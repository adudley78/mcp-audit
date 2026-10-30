"""STORY-0130: reporters of the Anthropic Git MCP server CVEs are credited."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from mcp_audit.analyzers.supply_chain import SupplyChainAnalyzer, split_credit
from mcp_audit.cli import app
from mcp_audit.models import ServerConfig

REGISTRY = Path(__file__).resolve().parent.parent / "registry" / "known-servers.json"
CREDITED = ("CVE-2025-68143", "CVE-2025-68144", "CVE-2025-68145")
CREDIT = "Yarden Porat (Cyata)"


def _git_vulns() -> dict[str, dict]:
    data = json.loads(REGISTRY.read_text(encoding="utf-8"))
    entry = next(e for e in data["entries"] if e["name"] == "mcp-server-git")
    return {v["cve"]: v for v in entry["known_vulns"]}


def test_shipped_registry_credits_the_three_cves() -> None:
    vulns = _git_vulns()
    for cve in CREDITED:
        assert CREDIT in vulns[cve]["description"], cve
        assert split_credit(vulns[cve]["description"])[1] == CREDIT
    assert "CVE-2026-27735" in vulns
    assert "reported by" not in vulns["CVE-2026-27735"]["description"]
    assert "Cyata" not in vulns["CVE-2026-27735"]["description"]


def test_sc004_finding_for_vulnerable_pin_carries_the_credit() -> None:
    server = ServerConfig(
        name="git",
        command="uvx",
        args=["mcp-server-git==2025.9.24"],
        client="claude",
        config_path="/fake/mcp.json",
    )
    findings = [f for f in SupplyChainAnalyzer().analyze(server) if f.id == "SC-004"]
    assert len(findings) == 1
    assert CREDIT in findings[0].description
    for cve in CREDITED:
        assert cve in findings[0].description
    assert "CVE-2026-27735" not in findings[0].description.split("Reported by")[1]


def test_vet_shows_the_credit() -> None:
    result = CliRunner().invoke(app, ["vet", "mcp-server-git"])
    assert " ".join(result.output.split()).count(f"reported by {CREDIT}") == 3
