"""Unit tests for scripts/inspect_frozen_binary.py (no frozen binary required)."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import inspect_frozen_binary as frozen  # noqa: E402


def test_mcp_does_not_match_mcp_audit() -> None:
    assert frozen.is_package_member("mcp", "mcp")
    assert frozen.is_package_member("mcp.client.session", "mcp")
    assert not frozen.is_package_member("mcp_audit", "mcp")
    assert not frozen.is_package_member("mcp_audit.mcp_client", "mcp")


def test_parse_spec_excludes_linux_spec() -> None:
    excludes = frozen.parse_spec_excludes(ROOT / "mcp-audit-linux-x86_64.spec")
    assert "sigstore" in excludes
    assert "cyclonedx" in excludes
    # Top-level package names only are used for PYZ checks.
    assert all(isinstance(name, str) and name for name in excludes)


def test_check_presence_reports_missing_and_leaked() -> None:
    names = {"PIL", "PIL.Image", "cryptography.hazmat"}
    assert frozen.check_presence(names, ("PIL", "cryptography"), must_exist=True) == []
    missing = frozen.check_presence(names, ("mcp",), must_exist=True)
    assert missing and "mcp" in missing[0]
    leaked = frozen.check_presence(
        names | {"starlette.requests"}, ("starlette",), must_exist=False
    )
    assert leaked and "starlette" in leaked[0]
