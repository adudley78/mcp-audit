"""STORY-0140: archived reference servers (SC-010, `archived` registry field)."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from mcp_audit.analyzers.supply_chain import SupplyChainAnalyzer
from mcp_audit.cli import app
from mcp_audit.models import ServerConfig, Severity
from mcp_audit.registry.loader import KnownServerRegistry, RegistryEntry
from mcp_audit.verdict import build_verdict

REPO = Path(__file__).resolve().parent.parent
REGISTRY = REPO / "registry" / "known-servers.json"
runner = CliRunner()

# The archive's own src/ listing (github.com/modelcontextprotocol/servers-archived,
# read 2026-11-04) intersected with what the registry lists.
ARCHIVED = {
    "@modelcontextprotocol/server-github",
    "@modelcontextprotocol/server-gitlab",
    "@modelcontextprotocol/server-google-maps",
    "@modelcontextprotocol/server-slack",
    "@modelcontextprotocol/server-postgres",
    "@modelcontextprotocol/server-puppeteer",
    "@modelcontextprotocol/server-brave-search",
    "@modelcontextprotocol/server-everart",
    "@modelcontextprotocol/server-aws-kb-retrieval",
    "@modelcontextprotocol/server-gdrive",
    "@modelcontextprotocol/server-redis",
}
# Still in modelcontextprotocol/servers/src on the same date.
MAINTAINED = {
    "@modelcontextprotocol/server-filesystem",
    "@modelcontextprotocol/server-memory",
    "@modelcontextprotocol/server-everything",
    "@modelcontextprotocol/server-sequential-thinking",
}


def _entries() -> dict[str, dict]:
    data = json.loads(REGISTRY.read_text())
    return {e["name"]: e for e in data["entries"]}


def _server(package: str, *, pin: str = "") -> ServerConfig:
    return ServerConfig(
        name="srv",
        client="claude-desktop",
        config_path=Path("mcp.json"),
        command="npx",
        args=["-y", f"{package}{pin}"],
    )


class TestRegistryData:
    def test_exactly_the_archived_reference_servers_are_marked(self) -> None:
        marked = {n for n, e in _entries().items() if e.get("archived")}
        assert marked == ARCHIVED

    def test_maintained_reference_servers_are_not_marked(self) -> None:
        entries = _entries()
        for name in MAINTAINED:
            assert not entries[name].get("archived", False), name

    def test_every_archived_entry_cites_its_notice(self) -> None:
        for name in ARCHIVED:
            e = _entries()[name]
            assert e["archive_notice"].startswith(
                "https://github.com/modelcontextprotocol/servers-archived/tree/main/src/"
            ), name
            assert (
                e["repo"] == "https://github.com/modelcontextprotocol/servers-archived"
            )

    def test_only_github_names_a_successor(self) -> None:
        successors = {
            n: e["successor"] for n, e in _entries().items() if e.get("archived")
        }
        assert successors.pop("@modelcontextprotocol/server-github") == (
            "github/github-mcp-server"
        )
        assert set(successors.values()) == {None}

    def test_model_defaults_keep_old_registries_loading(self) -> None:
        entry = RegistryEntry(
            name="x",
            source="npm",
            repo=None,
            maintainer="m",
            verified=True,
            last_verified="2026-01-01",
            known_versions=[],
            tags=[],
        )
        assert entry.archived is False
        assert entry.archive_notice is None
        assert entry.successor is None


class TestSc010:
    def setup_method(self) -> None:
        self.analyzer = SupplyChainAnalyzer(registry=KnownServerRegistry(REGISTRY))

    def test_archived_launch_gets_sc010_medium(self) -> None:
        findings = self.analyzer.analyze(_server("@modelcontextprotocol/server-slack"))
        sc010 = [f for f in findings if f.id == "SC-010"]
        assert len(sc010) == 1
        f = sc010[0]
        assert f.severity == Severity.MEDIUM
        assert f.owasp_mcp_top_10 == ["MCP04"]
        assert "servers-archived/tree/main/src/slack" in f.evidence
        assert "names no successor" in f.description

    def test_pinned_launch_still_matches(self) -> None:
        findings = self.analyzer.analyze(
            _server("@modelcontextprotocol/server-puppeteer", pin="@2025.5.12")
        )
        assert [f.id for f in findings if f.id == "SC-010"] == ["SC-010"]

    def test_successor_is_named_when_upstream_names_one(self) -> None:
        findings = self.analyzer.analyze(_server("@modelcontextprotocol/server-github"))
        f = next(f for f in findings if f.id == "SC-010")
        assert "github/github-mcp-server" in f.remediation

    def test_maintained_server_gets_no_sc010(self) -> None:
        findings = self.analyzer.analyze(
            _server("@modelcontextprotocol/server-sequential-thinking")
        )
        assert not [f for f in findings if f.id == "SC-010"]

    def test_archived_with_cves_reports_both(self) -> None:
        registry = KnownServerRegistry(REGISTRY)
        entry = registry.get_npm("@modelcontextprotocol/server-puppeteer")
        assert entry is not None
        entry.known_vulnerabilities = ["CVE-2099-0001"]
        analyzer = SupplyChainAnalyzer(registry=registry)
        ids = [f.id for f in analyzer.analyze(_server(entry.name))]
        assert "SC-004" in ids and "SC-010" in ids

    def test_sc010_is_not_an_advisory(self) -> None:
        from mcp_audit.advisory.classify import is_advisable

        assert is_advisable("SC-010") is False


class TestVet:
    def test_verdict_carries_archive_fields(self) -> None:
        registry = KnownServerRegistry(REGISTRY)
        entry = registry.get_npm("@modelcontextprotocol/server-github")
        verdict = build_verdict(entry.name, "npm", entry, None, registry)
        reg = verdict["registry"]
        assert reg["archived"] is True
        assert reg["successor"] == "github/github-mcp-server"
        assert reg["archive_notice"].endswith("/src/github")

    def test_unlisted_verdict_has_archive_keys(self) -> None:
        registry = KnownServerRegistry(REGISTRY)
        verdict = build_verdict("not-a-real-pkg-xyz", "npm", None, None, registry)
        assert verdict["registry"]["archived"] is False
        assert verdict["registry"]["successor"] is None

    def test_terminal_says_archived(self) -> None:
        result = runner.invoke(
            app,
            [
                "vet",
                "@modelcontextprotocol/server-brave-search",
                "--offline-registry",
            ],
        )
        assert result.exit_code == 0, result.output
        assert "Archived upstream" in result.output
        assert "servers-archived" in result.output
