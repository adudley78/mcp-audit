"""Tests for the ToxicFlowAnalyzer — cross-server capability combinations.

Test strategy:
- Unit tests for tag_server() covering known-package lookup, keyword matching,
  and tool-name matching (layer 3, runtime enumeration data).
- Integration tests for analyze_all() covering all TOXIC-001…TOXIC-007 rules,
  self-pair (single server with both capabilities), cross-pair (two separate
  servers), and negative cases (no dangerous combination).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mcp_audit.analyzers.toxic_flow import (
    KNOWN_SERVERS,
    TOXIC_PAIRS,
    Capability,
    ToxicFlowAnalyzer,
    ToxicPair,
    tag_server,
)
from mcp_audit.models import ServerConfig, Severity, TransportType
from mcp_audit.registry.loader import KnownServerRegistry, RegistryEntry

# ── Fixtures ──────────────────────────────────────────────────────────────────

_CFG = Path("/tmp/mcp.json")  # noqa: S108


def _server(
    name: str,
    command: str = "npx",
    args: list[str] | None = None,
    raw: dict | None = None,
    client: str = "cursor",
) -> ServerConfig:
    return ServerConfig(
        name=name,
        client=client,
        config_path=_CFG,
        transport=TransportType.STDIO,
        command=command,
        args=args or [],
        raw=raw or {},
    )


def _fs() -> ServerConfig:
    """Filesystem server — FILE_READ + FILE_WRITE."""
    return _server(
        "filesystem",
        args=["-y", "@modelcontextprotocol/server-filesystem", "/home"],
    )


def _fetch() -> ServerConfig:
    """Fetch server — NETWORK_OUT."""
    return _server("fetch", args=["-y", "@modelcontextprotocol/server-fetch"])


def _github() -> ServerConfig:
    """GitHub server — GIT + NETWORK_OUT."""
    return _server("github", args=["-y", "@modelcontextprotocol/server-github"])


def _postgres() -> ServerConfig:
    """Postgres server — DATABASE."""
    return _server("postgres", args=["-y", "@modelcontextprotocol/server-postgres"])


def _gmail() -> ServerConfig:
    """Gmail server — EMAIL + NETWORK_OUT."""
    return _server("gmail", args=["-y", "@modelcontextprotocol/server-gmail"])


def _puppeteer() -> ServerConfig:
    """Puppeteer server — BROWSER + NETWORK_OUT."""
    return _server("puppeteer", args=["-y", "@modelcontextprotocol/server-puppeteer"])


def _shell_server() -> ServerConfig:
    """Unknown server whose name implies SHELL_EXEC via keyword matching."""
    return _server("bash-runner", command="bash", args=["run.sh"])


def _vault_server() -> ServerConfig:
    """Unknown server whose name implies SECRETS via keyword matching."""
    return _server("vault-client", command="node", args=["vault-connector.js"])


def _memory() -> ServerConfig:
    """Memory server — no dangerous capabilities."""
    return _server("memory", args=["-y", "@modelcontextprotocol/server-memory"])


# ── tag_server — known-package lookup ────────────────────────────────────────


class TestTagServerKnownPackages:
    def test_filesystem_package_gives_file_caps(self) -> None:
        caps = tag_server(_fs())
        assert Capability.FILE_READ in caps
        assert Capability.FILE_WRITE in caps

    def test_fetch_package_gives_network_cap(self) -> None:
        caps = tag_server(_fetch())
        assert Capability.NETWORK_OUT in caps
        assert Capability.FILE_READ not in caps

    def test_github_package_gives_git_and_network(self) -> None:
        caps = tag_server(_github())
        assert Capability.GIT in caps
        assert Capability.NETWORK_OUT in caps

    def test_postgres_package_gives_database_cap(self) -> None:
        caps = tag_server(_postgres())
        assert Capability.DATABASE in caps

    def test_gmail_package_gives_email_and_network(self) -> None:
        caps = tag_server(_gmail())
        assert Capability.EMAIL in caps
        assert Capability.NETWORK_OUT in caps

    def test_puppeteer_package_gives_browser_and_network(self) -> None:
        caps = tag_server(_puppeteer())
        assert Capability.BROWSER in caps
        assert Capability.NETWORK_OUT in caps

    def test_memory_package_has_no_dangerous_caps(self) -> None:
        caps = tag_server(_memory())
        assert caps == frozenset()

    def test_all_known_servers_are_in_registry(self) -> None:
        # Verify the registry doesn't have typos by checking a few key entries.
        assert "@modelcontextprotocol/server-filesystem" in KNOWN_SERVERS
        assert "@modelcontextprotocol/server-fetch" in KNOWN_SERVERS
        assert "@modelcontextprotocol/server-github" in KNOWN_SERVERS

    def test_git_package_gives_git_and_file_read(self) -> None:
        server = _server("git", args=["-y", "@modelcontextprotocol/server-git"])
        caps = tag_server(server)
        assert Capability.GIT in caps
        assert Capability.FILE_READ in caps


# ── tag_server — keyword matching ────────────────────────────────────────────


class TestTagServerKeywords:
    def test_command_bash_implies_shell_exec(self) -> None:
        caps = tag_server(_shell_server())
        assert Capability.SHELL_EXEC in caps

    def test_arg_containing_postgres_implies_database(self) -> None:
        server = _server("db", command="node", args=["pg-server.js", "--database"])
        caps = tag_server(server)
        assert Capability.DATABASE in caps

    def test_arg_containing_vault_implies_secrets(self) -> None:
        caps = tag_server(_vault_server())
        assert Capability.SECRETS in caps

    def test_name_containing_fetch_implies_network(self) -> None:
        server = _server("my-fetch-server", command="node", args=["server.js"])
        caps = tag_server(server)
        assert Capability.NETWORK_OUT in caps

    def test_arg_http_implies_network(self) -> None:
        server = _server("api", command="python", args=["server.py", "--http"])
        caps = tag_server(server)
        assert Capability.NETWORK_OUT in caps

    def test_arg_sqlite_implies_database(self) -> None:
        server = _server("lite", command="python", args=["sqlite_server.py"])
        caps = tag_server(server)
        assert Capability.DATABASE in caps

    def test_arg_smtp_implies_email(self) -> None:
        server = _server("mailer", command="node", args=["smtp-relay.js"])
        caps = tag_server(server)
        assert Capability.EMAIL in caps

    def test_arg_playwright_implies_browser(self) -> None:
        server = _server("scraper", command="npx", args=["playwright", "serve"])
        caps = tag_server(server)
        assert Capability.BROWSER in caps

    def test_arg_github_implies_git(self) -> None:
        server = _server("vcs", command="node", args=["github-mcp.js"])
        caps = tag_server(server)
        assert Capability.GIT in caps

    def test_arg_curl_implies_network(self) -> None:
        server = _server("downloader", command="curl", args=["https://example.com"])
        caps = tag_server(server)
        assert Capability.NETWORK_OUT in caps

    def test_server_with_no_recognisable_keywords_has_no_caps(self) -> None:
        server = _server("unknown-thing", command="ruby", args=["my_gem.rb"])
        caps = tag_server(server)
        assert caps == frozenset()


# ── tag_server — layer 3: tool-name matching ──────────────────────────────────


class TestTagServerToolNames:
    def test_tool_named_read_file_implies_file_caps(self) -> None:
        server = _server(
            "enumerated",
            command="node",
            args=["server.js"],
            raw={
                "tools": [
                    {"name": "read_file", "description": "Reads a file from disk"},
                ]
            },
        )
        caps = tag_server(server)
        assert Capability.FILE_READ in caps

    def test_tool_description_mentioning_http_implies_network(self) -> None:
        server = _server(
            "enumerated",
            command="node",
            args=["server.js"],
            raw={
                "tools": [
                    {
                        "name": "do_thing",
                        "description": "Makes an http request to the given URL",
                    },
                ]
            },
        )
        caps = tag_server(server)
        assert Capability.NETWORK_OUT in caps

    def test_tool_names_augment_existing_caps(self) -> None:
        # Known package gives FILE_READ/WRITE; runtime tools add NETWORK_OUT.
        server = ServerConfig(
            name="filesystem",
            client="cursor",
            config_path=_CFG,
            transport=TransportType.STDIO,
            command="npx",
            args=["-y", "@modelcontextprotocol/server-filesystem", "/home"],
            raw={
                "tools": [
                    {"name": "fetch_remote", "description": "Fetches a URL"},
                ]
            },
        )
        caps = tag_server(server)
        assert Capability.FILE_READ in caps
        assert Capability.NETWORK_OUT in caps

    def test_non_dict_tools_entries_are_skipped(self) -> None:
        server = _server(
            "weird",
            raw={"tools": ["not-a-dict", None, 42]},
        )
        # Should not raise; just produce no extra caps.
        caps = tag_server(server)
        assert isinstance(caps, frozenset)


# ── analyze_all — negative cases ─────────────────────────────────────────────


class TestAnalyzeAllNegative:
    def test_no_servers_produces_no_findings(self) -> None:
        findings = ToxicFlowAnalyzer().analyze_all([])
        assert findings == []

    def test_single_server_with_only_file_caps_produces_no_findings(self) -> None:
        findings = ToxicFlowAnalyzer().analyze_all([_fs()])
        assert findings == []

    def test_two_filesystem_servers_produce_no_findings(self) -> None:
        """Same capabilities — no dangerous combination between them."""
        fs_a = _server("fs-a", args=["-y", "@modelcontextprotocol/server-filesystem"])
        fs_b = _server("fs-b", args=["-y", "@modelcontextprotocol/server-filesystem"])
        findings = ToxicFlowAnalyzer().analyze_all([fs_a, fs_b])
        assert findings == []

    def test_memory_server_alone_produces_no_findings(self) -> None:
        findings = ToxicFlowAnalyzer().analyze_all([_memory()])
        assert findings == []

    def test_two_memory_servers_produce_no_findings(self) -> None:
        findings = ToxicFlowAnalyzer().analyze_all([_memory(), _memory()])
        assert findings == []

    def test_analyze_single_server_is_always_empty(self) -> None:
        """Single-server analyze() is a no-op — toxic flow needs pairs."""
        assert ToxicFlowAnalyzer().analyze(_fs()) == []
        assert ToxicFlowAnalyzer().analyze(_fetch()) == []


# ── analyze_all — TOXIC-001: file read + network ──────────────────────────────


class TestToxic001:
    def test_filesystem_and_fetch_trigger_toxic001(self) -> None:
        findings = ToxicFlowAnalyzer().analyze_all([_fs(), _fetch()])
        ids = {f.id for f in findings}
        assert "TOXIC-001" in ids

    def test_finding_names_both_servers(self) -> None:
        findings = ToxicFlowAnalyzer().analyze_all([_fs(), _fetch()])
        toxic001 = next(f for f in findings if f.id == "TOXIC-001")
        # Both server names must appear somewhere in the finding.
        combined = f"{toxic001.server} {toxic001.evidence}"
        assert "filesystem" in combined
        assert "fetch" in combined

    def test_severity_is_high(self) -> None:
        findings = ToxicFlowAnalyzer().analyze_all([_fs(), _fetch()])
        toxic001 = next(f for f in findings if f.id == "TOXIC-001")
        assert toxic001.severity == Severity.HIGH

    def test_analyzer_field_is_toxic_flow(self) -> None:
        findings = ToxicFlowAnalyzer().analyze_all([_fs(), _fetch()])
        assert all(f.analyzer == "toxic_flow" for f in findings)

    def test_finding_path_is_set(self) -> None:
        findings = ToxicFlowAnalyzer().analyze_all([_fs(), _fetch()])
        toxic001 = next(f for f in findings if f.id == "TOXIC-001")
        assert toxic001.finding_path is not None

    def test_reverse_order_still_triggers_toxic001(self) -> None:
        """Pair detection should be symmetric — order in the list doesn't matter."""
        findings = ToxicFlowAnalyzer().analyze_all([_fetch(), _fs()])
        assert any(f.id == "TOXIC-001" for f in findings)

    def test_cwe_is_present(self) -> None:
        findings = ToxicFlowAnalyzer().analyze_all([_fs(), _fetch()])
        toxic001 = next(f for f in findings if f.id == "TOXIC-001")
        assert toxic001.cwe is not None


# ── analyze_all — TOXIC-002: file read + email ────────────────────────────────


class TestToxic002:
    def test_filesystem_and_gmail_trigger_toxic002(self) -> None:
        findings = ToxicFlowAnalyzer().analyze_all([_fs(), _gmail()])
        assert any(f.id == "TOXIC-002" for f in findings)

    def test_severity_is_high(self) -> None:
        findings = ToxicFlowAnalyzer().analyze_all([_fs(), _gmail()])
        f = next(x for x in findings if x.id == "TOXIC-002")
        assert f.severity == Severity.HIGH


# ── analyze_all — TOXIC-003: secrets + network ────────────────────────────────


class TestToxic003:
    def test_vault_and_fetch_trigger_toxic003(self) -> None:
        findings = ToxicFlowAnalyzer().analyze_all([_vault_server(), _fetch()])
        assert any(f.id == "TOXIC-003" for f in findings)

    def test_severity_is_critical(self) -> None:
        findings = ToxicFlowAnalyzer().analyze_all([_vault_server(), _fetch()])
        f = next(x for x in findings if x.id == "TOXIC-003")
        assert f.severity == Severity.CRITICAL

    def test_finding_names_both_servers(self) -> None:
        findings = ToxicFlowAnalyzer().analyze_all([_vault_server(), _fetch()])
        f = next(x for x in findings if x.id == "TOXIC-003")
        combined = f"{f.server} {f.evidence}"
        assert "vault-client" in combined
        assert "fetch" in combined


# ── analyze_all — TOXIC-004: file read + shell ────────────────────────────────


class TestToxic004:
    def test_filesystem_and_shell_trigger_toxic004(self) -> None:
        findings = ToxicFlowAnalyzer().analyze_all([_fs(), _shell_server()])
        assert any(f.id == "TOXIC-004" for f in findings)

    def test_severity_is_high(self) -> None:
        findings = ToxicFlowAnalyzer().analyze_all([_fs(), _shell_server()])
        f = next(x for x in findings if x.id == "TOXIC-004")
        assert f.severity == Severity.HIGH


# ── analyze_all — TOXIC-005: database + network ───────────────────────────────


class TestToxic005:
    def test_postgres_and_fetch_trigger_toxic005(self) -> None:
        findings = ToxicFlowAnalyzer().analyze_all([_postgres(), _fetch()])
        assert any(f.id == "TOXIC-005" for f in findings)

    def test_severity_is_high(self) -> None:
        findings = ToxicFlowAnalyzer().analyze_all([_postgres(), _fetch()])
        f = next(x for x in findings if x.id == "TOXIC-005")
        assert f.severity == Severity.HIGH


# ── analyze_all — TOXIC-006: shell + network ──────────────────────────────────


class TestToxic006:
    def test_shell_and_fetch_trigger_toxic006(self) -> None:
        findings = ToxicFlowAnalyzer().analyze_all([_shell_server(), _fetch()])
        assert any(f.id == "TOXIC-006" for f in findings)

    def test_severity_is_critical(self) -> None:
        findings = ToxicFlowAnalyzer().analyze_all([_shell_server(), _fetch()])
        f = next(x for x in findings if x.id == "TOXIC-006")
        assert f.severity == Severity.CRITICAL

    def test_finding_names_both_servers(self) -> None:
        findings = ToxicFlowAnalyzer().analyze_all([_shell_server(), _fetch()])
        f = next(x for x in findings if x.id == "TOXIC-006")
        combined = f"{f.server} {f.evidence}"
        assert "bash-runner" in combined
        assert "fetch" in combined


# ── analyze_all — TOXIC-007: git + network ────────────────────────────────────


class TestToxic007:
    def test_github_server_alone_triggers_toxic007_self_pair(self) -> None:
        """GitHub has both GIT and NETWORK_OUT — triggers TOXIC-007 as self-pair."""
        findings = ToxicFlowAnalyzer().analyze_all([_github()])
        assert any(f.id == "TOXIC-007" for f in findings)

    def test_git_server_and_fetch_trigger_toxic007(self) -> None:
        git = _server("git", args=["-y", "@modelcontextprotocol/server-git"])
        findings = ToxicFlowAnalyzer().analyze_all([git, _fetch()])
        assert any(f.id == "TOXIC-007" for f in findings)

    def test_severity_is_medium(self) -> None:
        git = _server("git", args=["-y", "@modelcontextprotocol/server-git"])
        findings = ToxicFlowAnalyzer().analyze_all([git, _fetch()])
        f = next(x for x in findings if x.id == "TOXIC-007")
        assert f.severity == Severity.MEDIUM


# ── Self-pair (single server with both capabilities) ──────────────────────────


class TestSelfPair:
    def test_github_self_pair_names_single_server(self) -> None:
        """GitHub alone provides GIT+NETWORK_OUT — self-pair finding."""
        findings = ToxicFlowAnalyzer().analyze_all([_github()])
        toxic007 = next((f for f in findings if f.id == "TOXIC-007"), None)
        assert toxic007 is not None
        # Self-pair: server label is just the server's own name.
        assert "+" not in toxic007.server
        assert "github" in toxic007.server

    def test_self_pair_evidence_mentions_both_capabilities(self) -> None:
        findings = ToxicFlowAnalyzer().analyze_all([_github()])
        toxic007 = next(f for f in findings if f.id == "TOXIC-007")
        assert "git" in toxic007.evidence
        assert "network_out" in toxic007.evidence

    def test_everything_server_triggers_multiple_self_pairs(self) -> None:
        """server-everything has FILE_READ, FILE_WRITE, NETWORK_OUT, SHELL_EXEC."""
        everything = _server(
            "everything",
            args=["-y", "@modelcontextprotocol/server-everything"],
        )
        findings = ToxicFlowAnalyzer().analyze_all([everything])
        finding_ids = {f.id for f in findings}
        # Should hit at least TOXIC-001 (file+network) and TOXIC-006 (shell+network).
        assert "TOXIC-001" in finding_ids
        assert "TOXIC-006" in finding_ids

    def test_server_with_only_sink_capability_no_self_pair(self) -> None:
        """NETWORK_OUT alone is not a source for any toxic rule."""
        findings = ToxicFlowAnalyzer().analyze_all([_fetch()])
        assert findings == []


# ── Cross-server findings — metadata checks ───────────────────────────────────


class TestCrossServerFindingMetadata:
    def test_cross_server_label_contains_plus(self) -> None:
        findings = ToxicFlowAnalyzer().analyze_all([_fs(), _fetch()])
        toxic001 = next(f for f in findings if f.id == "TOXIC-001")
        assert "+" in toxic001.server

    def test_same_client_preserved(self) -> None:
        findings = ToxicFlowAnalyzer().analyze_all([_fs(), _fetch()])
        toxic001 = next(f for f in findings if f.id == "TOXIC-001")
        assert toxic001.client == "cursor"

    def test_different_clients_labelled_multiple(self) -> None:
        fs = _server(
            "filesystem",
            args=["-y", "@modelcontextprotocol/server-filesystem"],
            client="cursor",
        )
        fetch = _server(
            "fetch",
            args=["-y", "@modelcontextprotocol/server-fetch"],
            client="vscode",
        )
        findings = ToxicFlowAnalyzer().analyze_all([fs, fetch])
        toxic001 = next(f for f in findings if f.id == "TOXIC-001")
        assert toxic001.client == "multiple"

    def test_finding_path_set_to_source_server_config(self) -> None:
        fs = _server(
            "filesystem",
            args=["-y", "@modelcontextprotocol/server-filesystem"],
        )
        findings = ToxicFlowAnalyzer().analyze_all([fs, _fetch()])
        toxic001 = next(f for f in findings if f.id == "TOXIC-001")
        assert toxic001.finding_path == str(_CFG)


# ── Multiple pairs in one scan ────────────────────────────────────────────────


class TestMultiplePairs:
    def test_three_servers_produce_multiple_findings(self) -> None:
        """filesystem + postgres + fetch: TOXIC-001 and TOXIC-005 should fire."""
        findings = ToxicFlowAnalyzer().analyze_all([_fs(), _postgres(), _fetch()])
        finding_ids = {f.id for f in findings}
        assert "TOXIC-001" in finding_ids
        assert "TOXIC-005" in finding_ids

    def test_no_duplicate_findings_for_same_pair_and_rule(self) -> None:
        """Each (server pair, rule) should emit at most one finding."""
        findings = ToxicFlowAnalyzer().analyze_all([_fs(), _fetch()])
        toxic001_count = sum(1 for f in findings if f.id == "TOXIC-001")
        assert toxic001_count == 1

    def test_four_servers_no_unexpected_cross_contamination(self) -> None:
        """Two inert servers added shouldn't create extra toxic findings."""
        findings_without = ToxicFlowAnalyzer().analyze_all([_fs(), _fetch()])
        findings_with = ToxicFlowAnalyzer().analyze_all(
            [_fs(), _fetch(), _memory(), _memory()]
        )
        ids_without = {f.id for f in findings_without}
        ids_with = {f.id for f in findings_with}
        assert ids_without == ids_with


# ── TOXIC_PAIRS list integrity ────────────────────────────────────────────────


class TestToxicPairsIntegrity:
    def test_all_seven_pairs_defined(self) -> None:
        ids = {tp.finding_id for tp in TOXIC_PAIRS}
        for n in range(1, 8):
            assert f"TOXIC-{n:03d}" in ids

    def test_no_duplicate_finding_ids(self) -> None:
        ids = [tp.finding_id for tp in TOXIC_PAIRS]
        assert len(ids) == len(set(ids))

    def test_each_pair_has_cwe(self) -> None:
        for tp in TOXIC_PAIRS:
            assert tp.cwe is not None, f"{tp.finding_id} is missing a CWE"

    @pytest.mark.parametrize("tp", TOXIC_PAIRS, ids=lambda tp: tp.finding_id)
    def test_each_pair_has_non_empty_remediation(self, tp: ToxicPair) -> None:
        assert tp.remediation.strip()

    @pytest.mark.parametrize("tp", TOXIC_PAIRS, ids=lambda tp: tp.finding_id)
    def test_each_pair_has_non_empty_description(self, tp: ToxicPair) -> None:
        assert tp.description.strip()

    @pytest.mark.parametrize("tp", TOXIC_PAIRS, ids=lambda tp: tp.finding_id)
    def test_critical_and_high_only_severities(self, tp: ToxicPair) -> None:
        from mcp_audit.models import Severity

        assert tp.severity in {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM}


# ── Registry-driven capability tagging ────────────────────────────────────────


def _stub_registry(entries: list[RegistryEntry]) -> KnownServerRegistry:
    """Build an in-memory KnownServerRegistry from explicit entries.

    Bypasses __init__ so the test doesn't touch the bundled JSON or the
    user-local cache.
    """
    reg = KnownServerRegistry.__new__(KnownServerRegistry)
    reg.schema_version = "test"
    reg.last_updated = "test"
    reg.entries = entries
    reg._name_index = {e.name.lower(): e for e in entries}  # noqa: SLF001
    return reg


def _npm_entry(name: str, capabilities: list[str] | None) -> RegistryEntry:
    """Construct a minimal RegistryEntry with the given capabilities."""
    return RegistryEntry(
        name=name,
        source="npm",
        repo=None,
        maintainer="test",
        verified=False,
        last_verified="2026-04-20",
        known_versions=[],
        tags=[],
        capabilities=capabilities,
    )


class TestTagServerWithRegistry:
    """Registry-backed capability lookup must take precedence over keywords."""

    def test_tag_server_uses_registry_capabilities(self) -> None:
        """Registry capability list is returned verbatim, skipping heuristics."""
        package = "@example/some-custom-server"
        reg = _stub_registry([_npm_entry(package, ["file_read"])])

        # "postgres" arg would normally trigger DATABASE via keyword matching.
        # Because the registry is authoritative, only FILE_READ is returned.
        server = _server(
            "some-custom",
            command="npx",
            args=["-y", package, "--postgres-uri", "..."],
        )

        caps = tag_server(server, registry=reg)
        assert caps == frozenset({Capability.FILE_READ})

    def test_tag_server_falls_back_when_no_capabilities(self) -> None:
        """Entry present but capabilities=None → keyword matching still runs."""
        reg = _stub_registry([_npm_entry("@modelcontextprotocol/server-fetch", None)])
        caps = tag_server(_fetch(), registry=reg)
        # KNOWN_SERVERS fallback + keyword matching both tag NETWORK_OUT.
        assert Capability.NETWORK_OUT in caps

    def test_tag_server_falls_back_when_no_registry(self) -> None:
        """No registry passed → behaviour matches the pre-migration code path."""
        caps_no_reg = tag_server(_fs(), registry=None)
        caps_default = tag_server(_fs())
        assert caps_no_reg == caps_default
        assert Capability.FILE_READ in caps_no_reg
        assert Capability.FILE_WRITE in caps_no_reg

    def test_tag_server_empty_registry_capabilities_suppresses_fallback(
        self,
    ) -> None:
        """capabilities=[] means 'no dangerous capabilities' — not a trigger."""
        package = "@example/inert-server"
        reg = _stub_registry([_npm_entry(package, [])])
        # Name contains 'fetch' which would keyword-match NETWORK_OUT — but
        # the registry says the package has no capabilities.
        server = _server("fetchy", command="npx", args=["-y", package])
        caps = tag_server(server, registry=reg)
        assert caps == frozenset()

    def test_analyzer_uses_injected_registry(self) -> None:
        """ToxicFlowAnalyzer threads the registry through to tag_server."""
        # Override filesystem to declare only NETWORK_OUT via the registry —
        # if the analyzer honours registry data, the normal filesystem+fetch
        # TOXIC-001 finding should NOT fire (both servers only have NETWORK_OUT).
        reg = _stub_registry(
            [
                _npm_entry("@modelcontextprotocol/server-filesystem", ["network_out"]),
                _npm_entry("@modelcontextprotocol/server-fetch", ["network_out"]),
            ]
        )
        analyzer = ToxicFlowAnalyzer(registry=reg)
        findings = analyzer.analyze_all([_fs(), _fetch()])
        assert not any(f.id == "TOXIC-001" for f in findings)


class TestRegistryEntryCapabilitiesField:
    """The new `capabilities` field must be backward-compatible."""

    def test_registry_entry_capabilities_field_optional(self) -> None:
        """Old JSON (pre-migration) without `capabilities` still deserialises."""
        entry = RegistryEntry.model_validate(
            {
                "name": "x",
                "source": "npm",
                "repo": None,
                "maintainer": "test",
                "verified": False,
                "last_verified": "2026-04-20",
                "known_versions": [],
                "tags": [],
            }
        )
        assert entry.capabilities is None

    def test_registry_entry_accepts_capabilities_list(self) -> None:
        entry = RegistryEntry.model_validate(
            {
                "name": "y",
                "source": "npm",
                "repo": None,
                "maintainer": "test",
                "verified": False,
                "last_verified": "2026-04-20",
                "known_versions": [],
                "tags": [],
                "capabilities": ["file_read", "network_out"],
            }
        )
        assert entry.capabilities == ["file_read", "network_out"]

    def test_bundled_registry_tags_known_servers(self) -> None:
        """The bundled registry must carry capability data for migrated entries."""
        from mcp_audit.registry.loader import load_registry  # noqa: PLC0415

        reg = load_registry()
        fs_entry = reg.get("@modelcontextprotocol/server-filesystem")
        assert fs_entry is not None
        assert fs_entry.capabilities is not None
        assert "file_read" in fs_entry.capabilities
        assert "file_write" in fs_entry.capabilities
