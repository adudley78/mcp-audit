#!/usr/bin/env python3
"""Inspect a PyInstaller archive — the binary itself, not the spec.

Confirms that modules listed in the spec's ``excludes=`` (plus a small
always-absent set) are not in the PYZ, that PIL and cryptography still
are, and that ``--connect`` prints the frozen-binary install hint when
the MCP SDK was not frozen in.

Usage:
    uv run python scripts/inspect_frozen_binary.py \\
        dist/mcp-audit-linux-x86_64 mcp-audit-linux-x86_64.spec
"""

from __future__ import annotations

import argparse
import ast
import json
import subprocess
import sys
import tempfile
from pathlib import Path

# Attestation stack must never ship, even if someone deletes it from a spec.
ALWAYS_ABSENT = ("sigstore", "pyasn1")
# reportlab (PDF) and urllib3/pyOpenSSL (TLS) need these. A smoke test that
# never writes a PDF would not catch an over-broad exclude that drops them.
ALWAYS_PRESENT = ("PIL", "cryptography")

CONNECT_HINT = "MCP SDK is not bundled in the standalone binary"


def parse_spec_excludes(spec_path: Path) -> list[str]:
    """Return the string literals in ``Analysis(..., excludes=[...])``."""
    tree = ast.parse(spec_path.read_text(encoding="utf-8"), filename=str(spec_path))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", "")
        if name != "Analysis":
            continue
        for kw in node.keywords:
            if kw.arg != "excludes" or not isinstance(kw.value, ast.List):
                continue
            out: list[str] = []
            for elt in kw.value.elts:
                if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                    out.append(elt.value)
            if not out:
                raise SystemExit(f"{spec_path}: Analysis(excludes=) is empty")
            return out
    raise SystemExit(f"{spec_path}: no Analysis(excludes=) list found")


def is_package_member(module: str, package: str) -> bool:
    """True if ``module`` is ``package`` or a submodule. ``mcp`` ≠ ``mcp_audit``."""
    return module == package or module.startswith(package + ".")


def pyz_module_names(binary: Path) -> set[str]:
    """Module names stored in the frozen PYZ archive inside ``binary``."""
    try:
        from PyInstaller.archive.readers import CArchiveReader
    except ImportError as exc:
        raise SystemExit(
            "PyInstaller is required to inspect the archive. "
            "Run this script via `uv run python` after installing pyinstaller."
        ) from exc

    pkg = CArchiveReader(str(binary))
    pyz_entries = [name for name, info in pkg.toc.items() if info[-1] in ("z", "Z")]
    if not pyz_entries:
        raise SystemExit(f"{binary}: no PYZ archive in PKG TOC")
    pyz = pkg.open_embedded_archive(pyz_entries[0])
    return set(pyz.toc)


def members_of(names: set[str], package: str) -> list[str]:
    return sorted(n for n in names if is_package_member(n, package))


def _print_table(names: set[str], packages: list[str], heading: str) -> None:
    print(heading)
    for pkg in packages:
        hits = members_of(names, pkg)
        print(f"  {pkg:22} {len(hits)}")


def check_presence(
    names: set[str], packages: tuple[str, ...], *, must_exist: bool
) -> list[str]:
    failures: list[str] = []
    for pkg in packages:
        hits = members_of(names, pkg)
        if must_exist and not hits:
            failures.append(f"expected {pkg} in PYZ, found 0 modules")
        if not must_exist and hits:
            sample = ", ".join(hits[:5])
            extra = f" (+{len(hits) - 5} more)" if len(hits) > 5 else ""
            failures.append(
                f"expected {pkg} absent from PYZ, found {len(hits)}: {sample}{extra}"
            )
    return failures


def check_connect_hint(binary: Path) -> list[str]:
    """Run ``scan --connect``; require the install hint and no traceback."""
    failures: list[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        cfg = Path(tmp) / "mcp.json"
        cfg.write_text(
            json.dumps({"mcpServers": {"inspect": {"command": "false", "args": []}}}),
            encoding="utf-8",
        )
        result = subprocess.run(  # noqa: S603
            [str(binary), "scan", "--connect", "--path", str(cfg), "--format", "json"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
        )
    blob = (result.stdout or "") + "\n" + (result.stderr or "")
    if "Traceback (most recent call last)" in blob:
        failures.append("--connect printed a traceback instead of the install hint")
    if CONNECT_HINT not in blob:
        snippet = blob[-500:].replace("\n", " ")
        failures.append(
            "--connect did not print the frozen-binary install hint; "
            f"output tail: {snippet!r}"
        )
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path, help="Path to the frozen executable")
    parser.add_argument("spec", type=Path, help="Matching .spec file")
    args = parser.parse_args(argv)

    binary = args.binary.resolve()
    spec = args.spec.resolve()
    if not binary.is_file():
        print(f"ERROR: binary not found: {binary}", file=sys.stderr)
        return 2
    if not spec.is_file():
        print(f"ERROR: spec not found: {spec}", file=sys.stderr)
        return 2

    excludes = parse_spec_excludes(spec)
    names = pyz_module_names(binary)
    print(f"archive: {binary} ({binary.stat().st_size} bytes)")
    print(f"pyz modules: {len(names)}")
    _print_table(names, list(ALWAYS_PRESENT), "present (required):")
    absent_pkgs = list(dict.fromkeys([*ALWAYS_ABSENT, *excludes]))
    _print_table(names, absent_pkgs, "absent (spec excludes + always-absent):")

    failures: list[str] = []
    failures.extend(check_presence(names, ALWAYS_PRESENT, must_exist=True))
    failures.extend(check_presence(names, tuple(ALWAYS_ABSENT), must_exist=False))
    # Top-level packages only — excluding mcp_audit.attestation.sigstore_client
    # is a source-module omit, not a PYZ package root.
    top_level_excludes = tuple(e for e in excludes if "." not in e)
    failures.extend(check_presence(names, top_level_excludes, must_exist=False))

    mcp_frozen = bool(members_of(names, "mcp"))
    if mcp_frozen:
        print("--connect: skipped (MCP SDK is frozen in this binary)")
    else:
        print("--connect: expecting frozen-binary install hint")
        failures.extend(check_connect_hint(binary))

    if failures:
        print("FAIL:", file=sys.stderr)
        for item in failures:
            print(f"  - {item}", file=sys.stderr)
        return 1
    print("OK: archive matches spec excludes; PIL and cryptography present")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
