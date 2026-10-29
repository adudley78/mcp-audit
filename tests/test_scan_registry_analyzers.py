"""Q-059: a registry override keeps the default analyzer set."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from mcp_audit.analyzers.config_hygiene import ConfigHygieneAnalyzer
from mcp_audit.cli import app
from mcp_audit.cli.scan import _build_custom_analyzers
from mcp_audit.scanner import get_default_analyzers

REPO = Path(__file__).resolve().parent.parent
REGISTRY = REPO / "registry" / "known-servers.json"
runner = CliRunner()


def test_custom_list_matches_default_types() -> None:
    custom = _build_custom_analyzers(REGISTRY, False)
    assert custom is not None
    assert [type(a) for a in custom] == [type(a) for a in get_default_analyzers()]
    assert any(isinstance(a, ConfigHygieneAnalyzer) for a in custom)


def test_offline_registry_also_keeps_hygiene() -> None:
    custom = _build_custom_analyzers(None, True)
    assert custom is not None
    assert any(isinstance(a, ConfigHygieneAnalyzer) for a in custom)


def _hygiene_ids(args: list[str]) -> set[str]:
    out = runner.invoke(
        app, ["scan", str(REPO / "demo" / "configs"), "-f", "json", *args]
    ).output
    doc = json.loads(out[out.index("{") :])
    return {f["id"] for f in doc["findings"] if f.get("analyzer") == "config_hygiene"}


def test_scan_with_registry_reports_the_same_hygiene_findings() -> None:
    default = _hygiene_ids([])
    assert default, "demo configs should produce config_hygiene findings"
    assert _hygiene_ids(["--registry", str(REGISTRY)]) == default
    assert _hygiene_ids(["--offline-registry"]) == default
