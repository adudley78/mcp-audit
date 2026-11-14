"""STORY-0154: this week's registry additions, through the real code paths.

Four OSV ``MAL-*`` packages are known-malicious to ``vet`` and to SC-008; the
MCP Inspector RCE (GHSA-q978-78c7-phqw) is reported by SC-004 on a pinned
version below 2.12.0 and not on 2.12.0; ``affected CVE-2026-88968`` answers for
Claude Code below 2.1.251.  No network.  The shipped files are read only
through the loaders and commands, never as bare JSON.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from typer.testing import CliRunner

from mcp_audit import harness_versions as hv
from mcp_audit.analyzers.supply_chain import SupplyChainAnalyzer
from mcp_audit.cli import app
from mcp_audit.models import ServerConfig
from mcp_audit.registry.loader import load_registry
from mcp_audit.registry.malicious import load_known_malicious

runner = CliRunner()

INSPECTOR = "@modelcontextprotocol/inspector"
GHSA_INSPECTOR = "GHSA-q978-78c7-phqw"
CLAUDE_CODE_CVE = "CVE-2026-88968"

MALICIOUS = [
    ("npm", "@rfewqa-fes/mnm-doc-mcp", "MAL-2026-19148"),
    ("npm", "@go-gost/mcp-darwin-x64", "MAL-2026-19159"),
    ("pypi", "my-mcp-server-driving-license-ocr", "MAL-2026-19204"),
    ("npm", "karma365-mcp", "MAL-2026-19235"),
]


def _scan_findings(command: str, args: list[str]) -> list[Any]:
    server = ServerConfig(
        name="s", command=command, args=args, client="claude", config_path="/x.json"
    )
    return SupplyChainAnalyzer(offline_registry=True).analyze(server)


@pytest.mark.parametrize(("eco", "name", "rid"), MALICIOUS)
def test_vet_reports_each_package_as_known_malicious(
    eco: str, name: str, rid: str
) -> None:
    args = ["vet", name, "--format", "json"]
    if eco == "pypi":
        args += ["--ecosystem", "pypi"]
    result = runner.invoke(app, args)
    verdict = json.loads(result.stdout)
    assert rid in [m["id"] for m in verdict["malicious"]]
    assert load_known_malicious().lookup(eco, name)


@pytest.mark.parametrize(
    ("command", "args", "rid"),
    [
        ("npx", ["-y", "@rfewqa-fes/mnm-doc-mcp@1.0.0"], "MAL-2026-19148"),
        ("npx", ["-y", "@go-gost/mcp-darwin-x64"], "MAL-2026-19159"),
        ("uvx", ["my-mcp-server-driving-license-ocr"], "MAL-2026-19204"),
        ("npx", ["-y", "karma365-mcp@2.1.0"], "MAL-2026-19235"),
    ],
)
def test_scan_reports_sc_008_for_a_launch(
    command: str, args: list[str], rid: str
) -> None:
    hits = [f for f in _scan_findings(command, args) if f.id == "SC-008"]
    assert hits
    assert rid in hits[0].description + hits[0].evidence


@pytest.mark.parametrize(
    ("version", "reported"),
    [("2.11.0", True), ("2.0.0", True), ("2.12.0", False), ("2.13.1", False)],
)
def test_scan_reports_the_inspector_rce_below_the_fix(
    version: str, reported: bool
) -> None:
    findings = _scan_findings("npx", ["-y", f"{INSPECTOR}@{version}"])
    cve_findings = [f for f in findings if f.id == "SC-004"]
    text = " ".join(f.description + f.evidence for f in cve_findings)
    assert (GHSA_INSPECTOR in text) is reported


def test_inspector_record_credits_pillar_and_names_the_open_package() -> None:
    entry = load_registry(offline=True).get_npm(INSPECTOR)
    assert entry is not None
    (record,) = [v for v in entry.known_vulns or [] if v["cve"] == GHSA_INSPECTOR]
    assert record["fixed_in"] == "2.12.0"
    assert "Eilon Cohen (Pillar Security)" in record["description"]
    assert "`open` package" in record["description"]
    findings = _scan_findings("npx", ["-y", f"{INSPECTOR}@2.11.0"])
    sc004 = next(f for f in findings if f.id == "SC-004")
    assert "Eilon Cohen" in sc004.description


def test_the_older_inspector_cves_are_unchanged() -> None:
    findings = _scan_findings("npx", ["-y", f"{INSPECTOR}@0.16.6"])
    # 0.16.6 fixes both older CVEs; only the new advisory can still apply.
    text = " ".join(f.description for f in findings if f.id == "SC-004")
    assert "CVE-2025-49596" not in text and "CVE-2025-58444" not in text


def _affected(version: str | None, monkeypatch: pytest.MonkeyPatch) -> Any:
    import mcp_audit.cli.affected as cli  # noqa: PLC0415

    installs = (
        [hv.HarnessInstall("claude-code", "Claude Code", version, "/fixture", "npm")]
        if version
        else []
    )
    monkeypatch.setattr(
        cli, "find_harness_versions", lambda: hv.HarnessScan(installs=installs)
    )
    result = runner.invoke(app, ["affected", CLAUDE_CODE_CVE, "-f", "json"])
    return result, json.loads(result.output)


@pytest.mark.parametrize(
    ("version", "status"),
    [
        ("2.1.250", "AFFECTED"),
        ("2.0.0", "AFFECTED"),
        ("2.1.251", "NOT AFFECTED"),
        ("2.1.300", "NOT AFFECTED"),
    ],
)
def test_affected_answers_for_claude_code(
    version: str, status: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    result, doc = _affected(version, monkeypatch)
    assert result.exit_code == (1 if status == "AFFECTED" else 0)
    (row,) = doc["results"]
    assert row["status"] == status
    assert row["fixed_in"] == "2.1.251"
    assert "Claude Code" in row["subject"]


def test_affected_without_an_install_says_it_could_not_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result, doc = _affected(None, monkeypatch)
    assert result.exit_code == 0
    assert [r["status"] for r in doc["results"]] == ["COULDN'T CHECK"]


def test_affected_resolves_by_ghsa_alias_too(monkeypatch: pytest.MonkeyPatch) -> None:
    import mcp_audit.cli.affected as cli  # noqa: PLC0415

    monkeypatch.setattr(cli, "find_harness_versions", lambda: hv.HarnessScan())
    result = runner.invoke(app, ["affected", "GHSA-5xjx-9qx6-jcrv", "-f", "json"])
    assert result.exit_code == 0
    assert json.loads(result.output)["results"]


def test_registry_dates_moved() -> None:
    assert load_registry(offline=True).last_updated >= "2026-11-14"
    assert load_known_malicious().last_updated >= "2026-11-14"
