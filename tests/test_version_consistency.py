"""Verify version string consistency across the codebase."""

from __future__ import annotations

import re


def test_version_is_importable() -> None:
    from mcp_audit import __version__

    assert __version__ is not None
    assert isinstance(__version__, str)
    assert len(__version__) > 0


def test_version_is_valid_semver() -> None:
    from mcp_audit import __version__

    assert re.match(r"^\d+\.\d+\.\d+", __version__), (
        f"Version {__version__!r} is not a valid semver string"
    )


def test_scan_result_uses_central_version() -> None:
    from mcp_audit import __version__
    from mcp_audit.models import ScanResult

    result = ScanResult()
    assert result.version == __version__


def test_sarif_uses_central_version() -> None:
    from mcp_audit import __version__
    from mcp_audit.output.sarif import _TOOL_VERSION

    assert __version__ == _TOOL_VERSION


def test_baselines_uses_central_version() -> None:
    from mcp_audit import __version__
    from mcp_audit.baselines.manager import _SCANNER_VERSION

    assert __version__ == _SCANNER_VERSION


def test_fleet_uses_central_version() -> None:
    from mcp_audit import __version__
    from mcp_audit.fleet.merger import _SCANNER_VERSION

    assert __version__ == _SCANNER_VERSION
