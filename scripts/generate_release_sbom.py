#!/usr/bin/env python3
"""CycloneDX 1.5 SBOMs for release artifacts — not ``mcp-audit sbom``.

Two documents, because they answer different questions:

* ``--binary``: packages whose modules are actually in the PyInstaller PYZ.
  That is what a GitHub Release binary runs. Versions come from the build
  environment that froze the archive (the same venv PyInstaller used).
* ``--from-environment``: every distribution installed in the current
  interpreter. Used for the PyPI wheel after installing that wheel into a
  clean venv — it describes the wheel, not a binary. Filename must say so.

Syft 1.38.2 against a frozen mcp-audit binary produced **zero** components:
PyInstaller does not ship ``.dist-info``, which is what Syft's Python
cataloger reads. ``cyclonedx-py`` would describe the venv, including
excluded extras (mcp, sigstore). Neither is (b). This script is.

Usage::

    uv run python scripts/generate_release_sbom.py \\
        --binary dist/mcp-audit-linux_x86_64 --target linux-x86_64 \\
        --output dist/mcp-audit-linux-x86_64.cdx.json \\
        --schema tests/fixtures/cyclonedx-1.5.schema.json

    python scripts/generate_release_sbom.py --from-environment \\
        --name mcp-audit-scanner --output mcp-audit-scanner-wheel.cdx.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import uuid
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from importlib import metadata
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent

CDX_SCHEMA_URL = "http://cyclonedx.org/schema/bom-1.5.schema.json"
SPEC_VERSION = "1.5"

# Build-machine path leak: same class as the v0.15.0 SARIF absolute-path fix.
_PATH_LEAK = re.compile(
    r"(?:/Users/|/home/|/opt/hostedtoolcache|/private/var/|"
    r"site-packages|[A-Za-z]:\\\\|D:\\\\a\\\\)",
    re.IGNORECASE,
)

_PEP503 = re.compile(r"[-_.]+")


def pep503(name: str) -> str:
    """Normalize a PyPI distribution name (PEP 503)."""
    return _PEP503.sub("-", name).lower()


def _now_utc() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def distributions_from_pyz(
    pyz_modules: set[str],
    module_to_dists: Mapping[str, list[str]],
    version_of: Callable[[str], str],
) -> dict[str, str]:
    """Map PYZ top-level import names to installed distribution versions.

    A distribution is included only if at least one of its import names is
    present in the archive. Packages sitting in the build venv but excluded
    from the spec (mcp, sigstore, cyclonedx) do not appear.
    """
    found: dict[str, str] = {}
    tops = {module.split(".")[0] for module in pyz_modules if module}
    for top in tops:
        for dist in module_to_dists.get(top, ()):
            key = pep503(dist)
            try:
                found[key] = version_of(dist)
            except metadata.PackageNotFoundError:
                continue
    return dict(sorted(found.items()))


def distributions_from_environment() -> dict[str, str]:
    """Every installed distribution in this interpreter (wheel/venv mode)."""
    found: dict[str, str] = {}
    for dist in metadata.distributions():
        raw = dist.metadata["Name"]
        if not raw:
            continue
        found[pep503(raw)] = dist.version
    return dict(sorted(found.items()))


def _purl(name: str, version: str) -> str:
    return f"pkg:pypi/{name}@{version}"


def build_bom(
    *,
    packages: dict[str, str],
    app_name: str,
    app_version: str,
    covers: str,
    timestamp: str | None = None,
) -> dict[str, Any]:
    """Return a CycloneDX 1.5 document. No filesystem paths in any field."""
    ts = timestamp or _now_utc()
    components: list[dict[str, Any]] = []
    for name, version in packages.items():
        purl = _purl(name, version)
        components.append(
            {
                "type": "library",
                "bom-ref": purl,
                "name": name,
                "version": version,
                "purl": purl,
            }
        )
    serial_basis = covers + app_name + "".join(c["purl"] for c in components)
    serial = uuid.uuid5(uuid.NAMESPACE_URL, serial_basis)
    return {
        "$schema": CDX_SCHEMA_URL,
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "timestamp": ts,
            "lifecycles": [
                {"phase": "post-build" if covers == "pyinstaller-pyz" else "build"}
            ],
            "component": {
                "type": "application",
                "bom-ref": app_name,
                "name": app_name,
                "version": app_version,
                "properties": [
                    {
                        "name": "mcp-audit:sbom-covers",
                        "value": covers,
                    }
                ],
            },
        },
        "components": components,
    }


def bom_json(doc: dict[str, Any]) -> str:
    """Stable JSON. ``sort_keys`` is for review diffs, not RFC 8785."""
    return json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def find_path_leaks(text: str) -> list[str]:
    return [m.group(0) for m in _PATH_LEAK.finditer(text)]


def require_packages(packages: dict[str, str], required: tuple[str, ...]) -> list[str]:
    missing = [name for name in required if pep503(name) not in packages]
    if missing:
        return [f"SBOM missing required package(s): {', '.join(missing)}"]
    return []


def validate_schema(doc: dict[str, Any], schema_path: Path) -> None:
    try:
        import jsonschema
    except ImportError as exc:
        raise SystemExit(
            "jsonschema is required for --schema. "
            "The binary composite already has it via uv sync --all-extras; "
            "or pass --schema only from an environment that has [dev]."
        ) from exc

    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    jsonschema.validate(doc, schema)


def _app_version() -> str:
    try:
        return metadata.version("mcp-audit-scanner")
    except metadata.PackageNotFoundError:
        return "0.0.0"


def _write_checked(
    doc: dict[str, Any],
    output: Path,
    *,
    schema: Path | None,
    required: tuple[str, ...],
    packages: dict[str, str],
) -> None:
    failures = require_packages(packages, required)
    text = bom_json(doc)
    leaks = find_path_leaks(text)
    if leaks:
        failures.append(f"build-machine path leaked: {sorted(set(leaks))}")
    if schema is not None:
        validate_schema(doc, schema)
    if failures:
        print("FAIL:", file=sys.stderr)
        for item in failures:
            print(f"  - {item}", file=sys.stderr)
        raise SystemExit(1)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(text, encoding="utf-8")
    covers = doc["metadata"]["component"]["properties"][0]["value"]
    print(f"wrote {output} ({len(packages)} components, covers={covers})")
    for name, version in list(packages.items())[:8]:
        print(f"  {name} {version}")
    if len(packages) > 8:
        print(f"  … +{len(packages) - 8} more")


def _parse_require(raw: str | None) -> tuple[str, ...]:
    if not raw:
        return ()
    return tuple(pep503(part) for part in raw.split(",") if part.strip())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group()
    source.add_argument(
        "--binary",
        type=Path,
        help="PyInstaller executable to inventory",
    )
    source.add_argument(
        "--from-environment",
        action="store_true",
        help="Inventory this interpreter (wheel venv). Filename must contain 'wheel'.",
    )
    source.add_argument(
        "--check",
        type=Path,
        help="Validate an existing CycloneDX JSON (schema, path leak, --require)",
    )
    parser.add_argument("--target", help="Release target label (e.g. linux-x86_64)")
    parser.add_argument("--name", help="Application name for --from-environment")
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--schema",
        type=Path,
        help="CycloneDX JSON schema to validate against",
    )
    parser.add_argument(
        "--require",
        default="",
        help="Comma-separated PEP 503 names that must appear (e.g. pillow,reportlab)",
    )
    args = parser.parse_args(argv)

    required = _parse_require(args.require)
    version = _app_version()

    if args.check is not None:
        if not args.schema:
            parser.error("--check requires --schema")
        doc = json.loads(args.check.read_text(encoding="utf-8"))
        packages = {
            pep503(str(c["name"])): str(c["version"])
            for c in doc.get("components", [])
            if c.get("name") and c.get("version")
        }
        validate_schema(doc, args.schema)
        failures = require_packages(packages, required)
        leaks = find_path_leaks(json.dumps(doc))
        if leaks:
            failures.append(f"build-machine path leaked: {sorted(set(leaks))}")
        if failures:
            print("FAIL:", file=sys.stderr)
            for item in failures:
                print(f"  - {item}", file=sys.stderr)
            return 1
        print(f"OK: {args.check} ({len(packages)} components)")
        return 0

    if args.binary is None and not args.from_environment:
        parser.error("one of --binary, --from-environment, --check is required")
    if args.output is None:
        parser.error("--output is required unless --check")

    if args.binary is not None:
        if not args.target:
            parser.error("--target is required with --binary")
        binary = args.binary.resolve()
        if not binary.is_file():
            print(f"ERROR: binary not found: {binary}", file=sys.stderr)
            return 2
        scripts_dir = str(ROOT / "scripts")
        if scripts_dir not in sys.path:
            sys.path.insert(0, scripts_dir)
        from inspect_frozen_binary import pyz_module_names

        pyz = pyz_module_names(binary)
        packages = distributions_from_pyz(
            pyz, metadata.packages_distributions(), metadata.version
        )
        if not required:
            required = ("pillow", "reportlab")
        doc = build_bom(
            packages=packages,
            app_name=f"mcp-audit-{args.target}",
            app_version=version,
            covers="pyinstaller-pyz",
        )
        _write_checked(
            doc, args.output, schema=args.schema, required=required, packages=packages
        )
        return 0

    if "wheel" not in args.output.name.lower():
        print(
            "ERROR: --from-environment output filename must contain 'wheel' "
            "so it cannot be mistaken for a binary SBOM",
            file=sys.stderr,
        )
        return 2
    packages = distributions_from_environment()
    doc = build_bom(
        packages=packages,
        app_name=args.name or "mcp-audit-scanner",
        app_version=version,
        covers="wheel-install",
    )
    _write_checked(
        doc, args.output, schema=args.schema, required=required, packages=packages
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
