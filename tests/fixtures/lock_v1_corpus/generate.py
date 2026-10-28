"""Regenerate the lock_version 1 regression corpus (STORY-0116).

The files next to this script were written by **origin/main at add156c**
(the last commit that wrote ``lock_version`` 1), not by the code under test:

- ``mcp-lock.offline.json`` — ``mcp-audit lock --offline`` over ``project/``.
- ``mcp-lock.resolved.json`` — ``mcp-audit lock`` over ``project/`` with the
  registry mocked by :func:`patched_registry` (state ``"locked"``).
- ``expected.json`` — what that same code reported for ``lock --verify``,
  ``lock --verify --resolve`` (registry state ``"locked"`` and ``"drifted"``)
  and the scan/check auto-verify, normalised by :func:`normalise`.

``tests/test_lock_v2.py`` runs the current code over the same locks and
asserts it reports the same thing, so a change in how ``lock`` reads specs
can never again turn into a false LOCK-004 on an untouched config.

To regenerate (only if the corpus itself changes), run this file with the
old code first on ``sys.path``::

    git archive add156c src | tar -x -C /tmp/main_src
    PYTHONPATH=/tmp/main_src/src python tests/fixtures/lock_v1_corpus/generate.py

The mocks below are imported by the tests, so both sides see the same
registry.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import shutil
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
PROJECT = HERE / "project"

#: What the mocked registry says `latest` is, per state.
_LATEST: dict[str, dict[str, str]] = {
    "locked": {},
    "drifted": {"plain-mcp-server": "1.5.0", "mcp-server-fetch": "2025.2.0"},
}
_DEFAULT_LATEST = "1.4.0"
_DEPRECATED = {"deprecated-mcp": "Package no longer supported"}
#: Tarballs whose bytes "changed" in the drifted state (same version).
_REPUBLISHED = {"env-mcp-2.0.0.tgz"}


@contextlib.contextmanager
def patched_registry(state: str) -> Iterator[None]:
    """Replace every network call ``lock`` makes with a deterministic answer."""

    def latest_info(ecosystem: object, name: str) -> tuple[str, str | None]:
        version = _LATEST[state].get(name, _DEFAULT_LATEST)
        return version, _DEPRECATED.get(name)

    def tarball_hash(url: str) -> str:
        salt = (
            "republished"
            if (state == "drifted" and url.rsplit("/", 1)[-1] in _REPUBLISHED)
            else ""
        )
        return "sha256:" + hashlib.sha256((url + salt).encode()).hexdigest()

    with (
        patch(
            "mcp_audit.lock.resolve.resolve_latest_version_info",
            side_effect=latest_info,
        ),
        patch("mcp_audit.lock.resolve.compute_hash_from_url", side_effect=tarball_hash),
    ):
        yield


def normalise(result: object, root: Path) -> dict:
    """Reduce a ``VerifyResult`` to host-independent, comparable data."""
    prefix = str(root)

    def clean(text: object) -> object:
        # Windows paths: the root prefix, then separators, so outcomes recorded
        # on Linux compare on every OS.
        if not isinstance(text, str):
            return text
        return text.replace(prefix, "<root>").replace("\\", "/")

    findings = sorted(
        (
            {
                "id": f.id,
                "severity": f.severity.value,
                "client": f.client,
                "server": f.server,
                "title": clean(f.title),
                "evidence": clean(f.evidence),
                "finding_path": clean(f.finding_path),
            }
            for f in result.findings  # type: ignore[attr-defined]
        ),
        key=lambda d: json.dumps(d, sort_keys=True),
    )
    return {
        "exit_code": result.exit_code,  # type: ignore[attr-defined]
        "checked_servers": result.checked_servers,  # type: ignore[attr-defined]
        "unverified_sections": result.unverified_sections,  # type: ignore[attr-defined]
        "unresolved_entries": sorted(result.unresolved_entries),  # type: ignore[attr-defined]
        "unverified": sorted(
            [i.kind, i.name, i.reason]
            for i in result.unverified  # type: ignore[attr-defined]
        ),
        "outside_root": [clean(p) for p in result.outside_root],  # type: ignore[attr-defined]
        "tampered": result.tampered,  # type: ignore[attr-defined]
        "findings": findings,
    }


def copy_project(dest: Path) -> Path:
    """Copy ``project/`` into *dest* and return the copy's resolved root."""
    root = dest / "project"
    shutil.copytree(PROJECT, root)
    # A repository, so auto-verify finds the root lock from `.cursor/` too.
    (root / ".git").mkdir()
    return root.resolve()


def discover(root: Path) -> list:
    """Discover the corpus servers the way ``lock`` does."""
    from rich.console import Console

    from mcp_audit.cli.lock import _discover_lock_servers

    return _discover_lock_servers(root, False, Console(file=io.StringIO()))


def run_scenarios(root: Path, lock_name: str) -> dict:
    """Return every normalised verify outcome for the lock *lock_name*."""
    from mcp_audit.lock.auto_verify import auto_verify
    from mcp_audit.lock.verifier import verify

    shutil.copyfile(HERE / lock_name, root / "mcp-lock.json")
    servers = discover(root)
    lock_path = root / "mcp-lock.json"
    out: dict = {"verify": normalise(verify(lock_path, servers), root)}
    for state in ("locked", "drifted"):
        with patched_registry(state):
            out[f"resolve_{state}"] = normalise(
                verify(lock_path, servers, resolve=True), root
            )
    findings, status = auto_verify(servers)
    out["auto_verify"] = {
        "finding_ids": sorted(f.id for f in findings),
        "verified": status.verified,
        "checked_servers": status.checked_servers,
        "unresolved_entries": sorted(status.unresolved_entries),
        "unverified_sections": status.unverified_sections,
    }
    return out


def main() -> int:
    """Write the two v1 locks and the expected outcomes."""
    from mcp_audit.lock.model import LOCK_VERSION
    from mcp_audit.lock.writer import regenerate, serialize

    if LOCK_VERSION != 1:
        print(
            "run this with the lock_version 1 code first on sys.path", file=sys.stderr
        )
        return 2
    with tempfile.TemporaryDirectory() as tmp:
        root = copy_project(Path(tmp))
        servers = discover(root)
        offline = regenerate(None, servers, root, offline=True, registry=None)
        (HERE / "mcp-lock.offline.json").write_bytes(serialize(offline))
        with patched_registry("locked"):
            resolved = regenerate(None, servers, root, offline=False, registry=None)
        (HERE / "mcp-lock.resolved.json").write_bytes(serialize(resolved))
        expected = {
            "offline": run_scenarios(root, "mcp-lock.offline.json"),
            "resolved": run_scenarios(root, "mcp-lock.resolved.json"),
        }
    (HERE / "expected.json").write_text(
        json.dumps(expected, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
