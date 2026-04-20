"""Tests for the supply-chain (typosquatting) analyzer."""

from __future__ import annotations

from pathlib import Path

import pytest

import mcp_audit.analyzers.supply_chain as _sc_module
from mcp_audit.analyzers.supply_chain import (  # noqa: I001
    SupplyChainAnalyzer,
    extract_npm_package,
    levenshtein,
)
from mcp_audit.models import ServerConfig, Severity, TransportType
from mcp_audit.registry import loader as _loader_module

# ── Levenshtein unit tests ─────────────────────────────────────────────────────


class TestLevenshtein:
    def test_identical_strings(self) -> None:
        assert levenshtein("abc", "abc") == 0

    def test_single_substitution(self) -> None:
        assert levenshtein("cat", "cut") == 1

    def test_single_insertion(self) -> None:
        assert levenshtein("cat", "cats") == 1

    def test_single_deletion(self) -> None:
        assert levenshtein("cats", "cat") == 1

    def test_empty_vs_nonempty(self) -> None:
        assert levenshtein("", "abc") == 3
        assert levenshtein("abc", "") == 3

    def test_both_empty(self) -> None:
        assert levenshtein("", "") == 0

    def test_completely_different(self) -> None:
        assert levenshtein("abc", "xyz") == 3

    def test_symmetric(self) -> None:
        assert levenshtein("kitten", "sitting") == levenshtein("sitting", "kitten")

    def test_scoped_package_one_char_diff(self) -> None:
        # "@modelcontextprotocol/server-filesyste" vs the real name — 1 deletion
        assert (
            levenshtein(
                "@modelcontextprotocol/server-filesystem",
                "@modelcontextprotocol/server-filesyste",
            )
            == 1
        )

    def test_longer_vs_shorter_direction(self) -> None:
        # Ensure the swap-to-keep-longer logic doesn't break correctness.
        assert levenshtein("a", "abcde") == 4
        assert levenshtein("abcde", "a") == 4


# ── extract_npm_package unit tests ────────────────────────────────────────────


class TestExtractNpmPackage:
    def test_simple_package(self) -> None:
        assert extract_npm_package(["my-package"]) == "my-package"

    def test_skips_leading_dash_y(self) -> None:
        assert extract_npm_package(["-y", "@modelcontextprotocol/server-github"]) == (
            "@modelcontextprotocol/server-github"
        )

    def test_skips_multiple_flags(self) -> None:
        result = extract_npm_package(["--yes", "--no-install", "my-pkg", "arg"])
        assert result == "my-pkg"

    def test_skips_p_flag_value(self) -> None:
        # -p ts-node consumes "ts-node" as the flag value; the next positional
        # "my-script.ts" is returned as-is (we cannot distinguish a script from a
        # package without network lookups, but it won't match any known package).
        assert extract_npm_package(["-p", "ts-node", "my-script.ts"]) == "my-script.ts"

    def test_only_flags_no_package(self) -> None:
        # When -p consumes the only remaining token there is no positional arg.
        assert extract_npm_package(["-p", "ts-node"]) is None

    def test_local_path_ignored(self) -> None:
        assert extract_npm_package(["./local-script.js"]) is None
        assert extract_npm_package(["/absolute/path"]) is None

    def test_url_ignored(self) -> None:
        assert extract_npm_package(["https://example.com/pkg"]) is None

    def test_scoped_package(self) -> None:
        assert extract_npm_package(["-y", "@scope/my-pkg"]) == "@scope/my-pkg"

    def test_empty_args(self) -> None:
        assert extract_npm_package([]) is None

    def test_lowercase_normalisation(self) -> None:
        assert extract_npm_package(["My-Package"]) == "my-package"

    def test_file_uri_ignored(self) -> None:
        assert extract_npm_package(["file:../local"]) is None


# ── SupplyChainAnalyzer integration tests ─────────────────────────────────────


def _make_server(
    name: str = "test-server",
    command: str = "npx",
    args: list[str] | None = None,
) -> ServerConfig:
    return ServerConfig(
        name=name,
        client="claude",
        config_path=Path("/tmp/mcp.json"),  # noqa: S108
        transport=TransportType.STDIO,
        command=command,
        args=args or [],
    )


class TestSupplyChainAnalyzer:
    def setup_method(self) -> None:
        self.analyzer = SupplyChainAnalyzer()

    # ── Basic properties ───────────────────────────────────────────────────────

    def test_name(self) -> None:
        assert self.analyzer.name == "supply_chain"

    def test_description_non_empty(self) -> None:
        assert len(self.analyzer.description) > 0

    # ── Legitimate packages → no findings ─────────────────────────────────────

    def test_exact_match_no_finding(self) -> None:
        pkg = "@modelcontextprotocol/server-filesystem"
        server = _make_server(args=["-y", pkg, "/home"])
        assert self.analyzer.analyze(server) == []

    def test_exact_match_github(self) -> None:
        server = _make_server(args=["-y", "@modelcontextprotocol/server-github"])
        assert self.analyzer.analyze(server) == []

    def test_exact_match_memory(self) -> None:
        server = _make_server(args=["-y", "@modelcontextprotocol/server-memory"])
        assert self.analyzer.analyze(server) == []

    # ── Distance 1 → CRITICAL ─────────────────────────────────────────────────

    def test_distance_1_critical(self) -> None:
        # Drop one char from the end: "server-filesyste" instead of "server-filesystem"
        server = _make_server(args=["-y", "@modelcontextprotocol/server-filesyste"])
        findings = self.analyzer.analyze(server)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].id == "SC-001"
        assert findings[0].analyzer == "supply_chain"
        assert findings[0].cwe == "CWE-829"

    def test_distance_1_substitution(self) -> None:
        # Replace 'g' with 'q' in 'server-github'
        server = _make_server(args=["-y", "@modelcontextprotocol/server-qithub"])
        findings = self.analyzer.analyze(server)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_distance_1_insertion(self) -> None:
        # Add an extra 's' at the end of 'server-slack'
        server = _make_server(args=["-y", "@modelcontextprotocol/server-slacks"])
        findings = self.analyzer.analyze(server)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    # ── Distance 2 → HIGH ─────────────────────────────────────────────────────

    def test_distance_2_high(self) -> None:
        # "server-postgrx" drops the 'e' and 's' from "server-postgres" → distance 2.
        server = _make_server(args=["-y", "@modelcontextprotocol/server-postgrx"])
        findings = self.analyzer.analyze(server)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert findings[0].id == "SC-002"

    # ── Distance 3 → MEDIUM ───────────────────────────────────────────────────

    def test_distance_3_medium(self) -> None:
        # "server-memoryyyy" appends three extra 'y' chars → distance 3.
        server = _make_server(args=["-y", "@modelcontextprotocol/server-memoryyyy"])
        findings = self.analyzer.analyze(server)
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM
        assert findings[0].id == "SC-003"

    # ── Distance > 3 → no finding ─────────────────────────────────────────────

    def test_unrelated_package_no_finding(self) -> None:
        server = _make_server(args=["-y", "totally-unrelated-tool-xyz"])
        assert self.analyzer.analyze(server) == []

    def test_clearly_different_scoped_package(self) -> None:
        server = _make_server(args=["-y", "@acme/some-completely-different-server"])
        assert self.analyzer.analyze(server) == []

    # ── Non-npx commands → no findings ───────────────────────────────────────

    def test_non_npx_command_skipped(self) -> None:
        server = _make_server(command="node", args=["server.js"])
        assert self.analyzer.analyze(server) == []

    def test_python_command_skipped(self) -> None:
        server = _make_server(command="python", args=["-m", "my_mcp_server"])
        assert self.analyzer.analyze(server) == []

    def test_uvx_command_checked(self) -> None:
        """uvx is not in _NPX_LIKE so it should be ignored (stdio Python runtime)."""
        server = _make_server(command="uvx", args=["mcp-server-git"])
        assert self.analyzer.analyze(server) == []

    def test_bunx_triggers_check(self) -> None:
        typo = "@modelcontextprotocol/server-filesyste"
        server = _make_server(command="bunx", args=["-y", typo])
        findings = self.analyzer.analyze(server)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    # ── No package in args → no findings ─────────────────────────────────────

    def test_no_package_arg(self) -> None:
        server = _make_server(command="npx", args=["-y"])
        assert self.analyzer.analyze(server) == []

    def test_only_local_path_args(self) -> None:
        server = _make_server(command="npx", args=["./local.js"])
        assert self.analyzer.analyze(server) == []

    # ── Finding fields ─────────────────────────────────────────────────────────

    def test_finding_references_server_and_client(self) -> None:
        server = _make_server(
            name="evil-fs",
            command="npx",
            args=["-y", "@modelcontextprotocol/server-filesyste"],
        )
        finding = self.analyzer.analyze(server)[0]
        assert finding.server == "evil-fs"
        assert finding.client == "claude"

    def test_finding_evidence_contains_command(self) -> None:
        server = _make_server(args=["-y", "@modelcontextprotocol/server-filesyste"])
        finding = self.analyzer.analyze(server)[0]
        assert "npx" in finding.evidence

    def test_finding_remediation_mentions_closest(self) -> None:
        server = _make_server(args=["-y", "@modelcontextprotocol/server-filesyste"])
        finding = self.analyzer.analyze(server)[0]
        assert "@modelcontextprotocol/server-filesystem" in finding.remediation

    def test_finding_title_contains_package(self) -> None:
        server = _make_server(args=["-y", "@modelcontextprotocol/server-filesyste"])
        finding = self.analyzer.analyze(server)[0]
        assert "@modelcontextprotocol/server-filesyste" in finding.title

    # ── Edge cases ─────────────────────────────────────────────────────────────

    def test_no_command_field(self) -> None:
        server = ServerConfig(
            name="headless",
            client="cursor",
            config_path=Path("/tmp/mcp.json"),  # noqa: S108
            transport=TransportType.SSE,
            url="https://example.com/mcp",
        )
        assert self.analyzer.analyze(server) == []

    @pytest.mark.parametrize(
        "typo,expected_severity",
        [
            # one-char deletions
            ("@modelcontextprotocol/server-githu", Severity.CRITICAL),
            # one-char addition
            ("@modelcontextprotocol/server-githubs", Severity.CRITICAL),
            # two insertions: "gitthuub" vs "github" → distance 2
            ("@modelcontextprotocol/server-gitthuub", Severity.HIGH),
        ],
    )
    def test_parametrized_typosquats(
        self, typo: str, expected_severity: Severity
    ) -> None:
        server = _make_server(args=["-y", typo])
        findings = self.analyzer.analyze(server)
        assert len(findings) == 1
        assert findings[0].severity == expected_severity


# ── Deduplication guard ────────────────────────────────────────────────────────


class TestLevenshteinDeduplication:
    """Verify supply_chain re-uses the registry.loader implementation.

    supply_chain.py must not define its own levenshtein function — it should
    import and re-export the one from registry/loader.py.  This test locks
    that contract so a future refactor cannot silently re-introduce a copy.
    """

    def test_supply_chain_uses_registry_levenshtein(self) -> None:
        """supply_chain.levenshtein IS registry.loader.levenshtein (same object)."""
        assert _sc_module.levenshtein is _loader_module.levenshtein, (
            "supply_chain.levenshtein must be the registry.loader implementation, "
            "not a locally defined copy"
        )

    def test_no_local_levenshtein_definition_in_supply_chain(self) -> None:
        """No 'def levenshtein' exists in supply_chain module source."""
        import inspect

        source = inspect.getsource(_sc_module)
        # The module may reference 'levenshtein' as an import or usage,
        # but must NOT define a new function named 'levenshtein'.
        assert "def levenshtein" not in source, (
            "supply_chain.py must not define its own levenshtein — "
            "import it from registry.loader instead"
        )
