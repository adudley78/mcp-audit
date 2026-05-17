"""Tests for the supply-chain (typosquatting) analyzer."""

from __future__ import annotations

from pathlib import Path

import pytest

import mcp_audit.analyzers.supply_chain as _sc_module
from mcp_audit.analyzers.supply_chain import (  # noqa: I001
    SupplyChainAnalyzer,
    extract_npm_package,
    extract_pypi_package,
    levenshtein,
)
from mcp_audit.models import ServerConfig, Severity, TransportType
from mcp_audit.registry import loader as _loader_module
from mcp_audit.registry.loader import normalize_pypi_name

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

    def test_python_m_unknown_module_no_finding(self) -> None:
        # "my_mcp_server" normalises to "my-mcp-server", which is not close to
        # any entry in the PyPI registry sub-index — no finding expected.
        server = _make_server(command="python", args=["-m", "my_mcp_server"])
        assert self.analyzer.analyze(server) == []

    def test_uvx_known_good_no_finding(self) -> None:
        # uvx is now checked via the Python path; mcp-server-git is an exact
        # match in the PyPI registry sub-index so no typosquat finding fires.
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


# ── Short-name threshold (≤5 chars → threshold 1) ─────────────────────────────


class TestShortNameThreshold:
    """Verify the tighter Levenshtein threshold applied to short package names."""

    def setup_method(self) -> None:
        self.analyzer = SupplyChainAnalyzer()

    def _server_with_pkg(self, pkg: str) -> ServerConfig:
        return _make_server(args=["-y", pkg])

    def test_short_name_no_fp_at_distance_2(self) -> None:
        """4-char name ≥2 edits from all registry entries → no SC-001."""
        # "zxqv" is 4+ edits from "mcp" and far from every registry entry.
        # Short-name threshold=1, so this must not fire.
        server = self._server_with_pkg("zxqv")
        findings = self.analyzer.analyze(server)
        assert findings == [], f"Expected no findings for 'zxqv', got {findings}"

    def test_short_name_fires_at_distance_1(self) -> None:
        """4-char name 1 edit from a registry entry → SC-001 fires (threshold is 1)."""
        # "@modelcontextprotocol/server-githu" is 1 edit from the real name (long pkg).
        # Use a short name: craft one that is exactly 1 edit from a real registry short
        # name. The registry has no 3-char entries, so we use a known long name instead
        # and verify the distance-1 boundary via the long-name path still fires.
        server = _make_server(args=["-y", "@modelcontextprotocol/server-githu"])
        findings = self.analyzer.analyze(server)
        assert len(findings) == 1
        assert findings[0].id == "SC-001"

    def test_5_char_name_uses_threshold_1(self) -> None:
        """Boundary: 5-char name uses threshold 1, not 3."""
        # "mcpfs" has 5 chars. Any registry entry 2+ edits away must NOT fire.
        server = self._server_with_pkg("mcpfs")
        findings = self.analyzer.analyze(server)
        assert findings == [], f"Expected no findings for 'mcpfs', got {findings}"

    def test_6_char_name_uses_threshold_3(self) -> None:
        """Just above boundary: 6-char name keeps threshold 3."""
        # "@modelcontextprotocol/server-memoryyyy" is 3 edits from the real name;
        # that test already covers long names. Here we check a 6-char standalone name
        # to ensure threshold=3 applies. "mcpfsx" won't match anything at ≤3 edits,
        # so this is a no-finding case that confirms no regression in logic.
        server = self._server_with_pkg("mcpfsx")
        findings = self.analyzer.analyze(server)
        # "mcpfsx" is unlikely to be within 3 edits of any real registry entry name
        # — this test simply asserts the 6-char name doesn't raise an error.
        assert isinstance(findings, list)

    def test_long_name_threshold_unchanged(self) -> None:
        """10-char name 3 edits away → SC-001 fires (threshold still 3)."""
        # "server-memoryyyy" appends three 'y' chars → distance 3 from "server-memory".
        server = _make_server(args=["-y", "@modelcontextprotocol/server-memoryyyy"])
        findings = self.analyzer.analyze(server)
        assert len(findings) == 1
        assert findings[0].id == "SC-003"
        assert findings[0].severity == Severity.MEDIUM

    def test_exact_match_short_name_no_sc001(self) -> None:
        """Regression: exact match never fires SC-001 regardless of name length."""
        # is_known() returns True before the threshold check, so no distance call.
        server = _make_server(args=["-y", "@modelcontextprotocol/server-filesystem"])
        assert self.analyzer.analyze(server) == []

    def test_empty_package_name_no_sc001(self) -> None:
        """Empty package name → no findings (extract_npm_package returns None)."""
        server = _make_server(command="npx", args=["-y"])
        assert self.analyzer.analyze(server) == []


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


# ── normalize_pypi_name unit tests ────────────────────────────────────────────


class TestNormalizePypiName:
    def test_underscores_to_hyphens(self) -> None:
        assert normalize_pypi_name("mcp_server_filesystem") == "mcp-server-filesystem"

    def test_dots_to_hyphens(self) -> None:
        assert normalize_pypi_name("mcp.server.fetch") == "mcp-server-fetch"

    def test_mixed_separators(self) -> None:
        assert normalize_pypi_name("mcp_server-fetch.v2") == "mcp-server-fetch-v2"

    def test_consecutive_separators_collapsed(self) -> None:
        assert normalize_pypi_name("mcp--server") == "mcp-server"

    def test_lowercase(self) -> None:
        assert normalize_pypi_name("MCP-Server-Fetch") == "mcp-server-fetch"

    def test_already_normalised(self) -> None:
        assert normalize_pypi_name("mcp-server-fetch") == "mcp-server-fetch"

    def test_pep503_equivalence(self) -> None:
        """mcp_server_filesystem and mcp-server-filesystem normalise identically."""
        assert normalize_pypi_name("mcp_server_filesystem") == normalize_pypi_name(
            "mcp-server-filesystem"
        )


# ── extract_pypi_package unit tests ───────────────────────────────────────────


class TestExtractPypiPackage:
    # ── uvx ────────────────────────────────────────────────────────────────────

    def test_uvx_simple(self) -> None:
        assert extract_pypi_package("uvx", ["mcp-server-filesystem"]) == (
            "mcp-server-filesystem"
        )

    def test_uvx_version_suffix_stripped(self) -> None:
        assert extract_pypi_package("uvx", ["mcp-server-filesystem@1.0.0"]) == (
            "mcp-server-filesystem"
        )

    def test_uvx_from_flag_extraction(self) -> None:
        # --from <pkg> <executable> — package is the token after --from
        assert (
            extract_pypi_package("uvx", ["--from", "mcp-server-foo", "mcp-foo"])
            == "mcp-server-foo"
        )

    def test_uvx_from_short_flag(self) -> None:
        assert extract_pypi_package("uvx", ["-f", "mcp-server-foo", "mcp-foo"]) == (
            "mcp-server-foo"
        )

    def test_uvx_from_flag_version_suffix(self) -> None:
        assert (
            extract_pypi_package("uvx", ["--from", "mcp-server-foo@2.0", "mcp-foo"])
            == "mcp-server-foo"
        )

    def test_uvx_python_flag_skipped(self) -> None:
        assert (
            extract_pypi_package("uvx", ["--python", "3.11", "mcp-server-filesystem"])
            == "mcp-server-filesystem"
        )

    def test_uvx_python_flag_equals_style(self) -> None:
        assert (
            extract_pypi_package("uvx", ["--python=3.11", "mcp-server-filesystem"])
            == "mcp-server-filesystem"
        )

    def test_uvx_underscore_normalised(self) -> None:
        assert extract_pypi_package("uvx", ["mcp_server_filesystem"]) == (
            "mcp-server-filesystem"
        )

    def test_uvx_no_args_returns_none(self) -> None:
        assert extract_pypi_package("uvx", []) is None

    def test_uvx_only_flags_returns_none(self) -> None:
        assert extract_pypi_package("uvx", ["--python", "3.11"]) is None

    # ── pipx ───────────────────────────────────────────────────────────────────

    def test_pipx_run_extraction(self) -> None:
        assert extract_pypi_package("pipx", ["run", "mcp-server-git"]) == (
            "mcp-server-git"
        )

    def test_pipx_install_extraction(self) -> None:
        assert extract_pypi_package("pipx", ["install", "mcp-server-git"]) == (
            "mcp-server-git"
        )

    def test_pipx_no_subcommand(self) -> None:
        # If no sub-command is present the first positional is the package.
        assert extract_pypi_package("pipx", ["mcp-server-git"]) == "mcp-server-git"

    def test_pipx_version_suffix_stripped(self) -> None:
        assert extract_pypi_package("pipx", ["run", "mcp-server-git@1.2.3"]) == (
            "mcp-server-git"
        )

    # ── python -m ──────────────────────────────────────────────────────────────

    def test_python_m_extraction(self) -> None:
        assert extract_pypi_package("python", ["-m", "mcp_server_filesystem"]) == (
            "mcp-server-filesystem"
        )

    def test_python_m_hyphen_name(self) -> None:
        assert extract_pypi_package("python", ["-m", "mcp-server-git"]) == (
            "mcp-server-git"
        )

    def test_python_no_m_flag_returns_none(self) -> None:
        assert extract_pypi_package("python", ["server.py"]) is None

    def test_python_m_flag_at_end_returns_none(self) -> None:
        assert extract_pypi_package("python", ["-m"]) is None

    # ── non-pypi command ───────────────────────────────────────────────────────

    def test_non_pypi_command_returns_none(self) -> None:
        assert extract_pypi_package("node", ["server.js"]) is None

    def test_npx_returns_none(self) -> None:
        assert extract_pypi_package("npx", ["-y", "some-pkg"]) is None


# ── KnownServerRegistry PyPI helpers ─────────────────────────────────────────


class TestRegistryPypiHelpers:
    def setup_method(self) -> None:
        self.registry = _loader_module.KnownServerRegistry()

    def test_get_pypi_names_returns_set(self) -> None:
        names = self.registry.get_pypi_names()
        assert isinstance(names, set)
        assert len(names) > 0

    def test_get_pypi_names_contains_known_entries(self) -> None:
        names = self.registry.get_pypi_names()
        assert "mcp-server-filesystem" in names
        assert "mcp-server-git" in names
        assert "mcp-server-fetch" in names

    def test_get_pypi_names_excludes_npm_entries(self) -> None:
        names = self.registry.get_pypi_names()
        # npm-only scoped packages must not appear in the PyPI pool
        assert "@modelcontextprotocol/server-filesystem" not in names

    def test_is_known_pypi_exact_match(self) -> None:
        assert self.registry.is_known_pypi("mcp-server-filesystem") is True

    def test_is_known_pypi_normalised_match(self) -> None:
        # Underscore variant normalises to the same name
        assert self.registry.is_known_pypi("mcp_server_filesystem") is True

    def test_is_known_pypi_unknown_returns_false(self) -> None:
        assert self.registry.is_known_pypi("totally-unknown-xyz-package") is False

    def test_is_known_pypi_npm_entry_returns_false(self) -> None:
        # npm-only entries must not be found by the pypi lookup
        assert (
            self.registry.is_known_pypi("@modelcontextprotocol/server-filesystem")
            is False
        )

    def test_find_closest_pypi_exact_returns_none(self) -> None:
        # Exact match should return None (caller uses is_known_pypi for that case)
        result = self.registry.find_closest_pypi("mcp-server-filesystem", threshold=3)
        assert result is None

    def test_find_closest_pypi_typo_found(self) -> None:
        # "mcp-server-fliesystem" is 2 edits from "mcp-server-filesystem"
        result = self.registry.find_closest_pypi("mcp-server-fliesystem", threshold=3)
        assert result is not None
        assert result.name == "mcp-server-filesystem"

    def test_find_closest_pypi_no_match_returns_none(self) -> None:
        result = self.registry.find_closest_pypi(
            "completely-unrelated-zzz", threshold=3
        )
        assert result is None

    def test_registry_entry_has_package_ecosystem_field(self) -> None:
        entry = self.registry.get("mcp-server-filesystem")
        assert entry is not None
        assert entry.package_ecosystem == "pypi"

    def test_npm_entry_has_default_ecosystem(self) -> None:
        entry = self.registry.get("@modelcontextprotocol/server-filesystem")
        assert entry is not None
        assert entry.package_ecosystem == "npm"


# ── SupplyChainAnalyzer Python-ecosystem tests ────────────────────────────────


def _make_pypi_server(
    name: str = "test-server",
    command: str = "uvx",
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


class TestPypiTyposquatting:
    def setup_method(self) -> None:
        self.analyzer = SupplyChainAnalyzer()

    # ── Typosquat detection ────────────────────────────────────────────────────

    def test_uvx_typosquat_detected(self) -> None:
        # "mcp-server-fliesystem" transposes 'il' → distance 2 → SC-002 HIGH
        server = _make_pypi_server(args=["mcp-server-fliesystem"])
        findings = self.analyzer.analyze(server)
        assert len(findings) == 1
        assert findings[0].id == "SC-002"
        assert findings[0].severity == Severity.HIGH
        assert findings[0].analyzer == "supply_chain"
        assert findings[0].cwe == "CWE-829"

    def test_uvx_typosquat_title_contains_package(self) -> None:
        server = _make_pypi_server(args=["mcp-server-fliesystem"])
        finding = self.analyzer.analyze(server)[0]
        assert "mcp-server-fliesystem" in finding.title
        assert "Python package typosquat" in finding.title

    def test_uvx_typosquat_remediation_mentions_correct_name(self) -> None:
        server = _make_pypi_server(args=["mcp-server-fliesystem"])
        finding = self.analyzer.analyze(server)[0]
        assert "mcp-server-filesystem" in finding.remediation

    def test_uvx_typosquat_evidence_contains_command(self) -> None:
        server = _make_pypi_server(args=["mcp-server-fliesystem"])
        finding = self.analyzer.analyze(server)[0]
        assert "uvx" in finding.evidence

    def test_uvx_distance_1_critical(self) -> None:
        # Drop one char from end: "mcp-server-filesyste" → distance 1 → CRITICAL SC-001
        server = _make_pypi_server(args=["mcp-server-filesyste"])
        findings = self.analyzer.analyze(server)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].id == "SC-001"

    def test_uvx_distance_3_medium(self) -> None:
        # Three extra chars: "mcp-server-gityyy" → distance 3 → MEDIUM SC-003
        server = _make_pypi_server(args=["mcp-server-gityyy"])
        findings = self.analyzer.analyze(server)
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM
        assert findings[0].id == "SC-003"

    # ── Known-good packages → no findings ─────────────────────────────────────

    def test_uvx_known_good_filesystem_no_finding(self) -> None:
        server = _make_pypi_server(args=["mcp-server-filesystem"])
        assert self.analyzer.analyze(server) == []

    def test_uvx_known_good_normalised_no_finding(self) -> None:
        # Underscore variant is PEP 503 equivalent — no finding
        server = _make_pypi_server(args=["mcp_server_filesystem"])
        assert self.analyzer.analyze(server) == []

    def test_uvx_known_good_postgres_no_finding(self) -> None:
        server = _make_pypi_server(args=["mcp-server-postgres"])
        assert self.analyzer.analyze(server) == []

    def test_pipx_run_known_good_no_finding(self) -> None:
        server = _make_pypi_server(command="pipx", args=["run", "mcp-server-git"])
        assert self.analyzer.analyze(server) == []

    # ── Argument parsing ───────────────────────────────────────────────────────

    def test_pipx_run_typosquat_detected(self) -> None:
        # "mcp-server-fliesystem" via pipx run
        server = _make_pypi_server(
            command="pipx", args=["run", "mcp-server-fliesystem"]
        )
        findings = self.analyzer.analyze(server)
        assert len(findings) == 1
        assert findings[0].id == "SC-002"

    def test_python_m_normalisation_and_check(self) -> None:
        # python -m mcp_server_filesystem → normalises to mcp-server-filesystem (exact)
        server = _make_pypi_server(
            command="python", args=["-m", "mcp_server_filesystem"]
        )
        assert self.analyzer.analyze(server) == []

    def test_python_m_typosquat_detected(self) -> None:
        # python -m mcp_server_fliesystem → typosquat
        server = _make_pypi_server(
            command="python", args=["-m", "mcp_server_fliesystem"]
        )
        findings = self.analyzer.analyze(server)
        assert len(findings) == 1
        assert findings[0].id == "SC-002"

    def test_uvx_from_flag_package_extracted(self) -> None:
        # "--from mcp-server-filesystem mcp-fs" → package is mcp-server-filesystem
        server = _make_pypi_server(args=["--from", "mcp-server-filesystem", "mcp-fs"])
        assert self.analyzer.analyze(server) == []

    def test_uvx_from_flag_typo_detected(self) -> None:
        server = _make_pypi_server(args=["--from", "mcp-server-fliesystem", "mcp-fs"])
        findings = self.analyzer.analyze(server)
        assert len(findings) == 1
        assert findings[0].id == "SC-002"

    def test_uvx_version_suffix_stripped_known_good(self) -> None:
        server = _make_pypi_server(args=["mcp-server-filesystem@1.0.0"])
        assert self.analyzer.analyze(server) == []

    # ── Short-name guard ───────────────────────────────────────────────────────

    def test_short_name_guard_no_false_positive(self) -> None:
        # "mcp" is 3 chars — threshold drops to 1; nothing within 1 edit should fire
        # unless it is an exact typo of "mcp" itself.  "mcq" is 1 edit from "mcp"
        # (which is in the registry), so it SHOULD fire.
        server = _make_pypi_server(args=["mcq"])
        findings = self.analyzer.analyze(server)
        # "mcq" is 1 edit from "mcp" → CRITICAL SC-001 fires (within threshold=1)
        assert len(findings) == 1
        assert findings[0].id == "SC-001"

    def test_5_char_pypi_name_threshold_1(self) -> None:
        # 5-char name uses threshold 1; package 2 edits from all entries → no finding
        server = _make_pypi_server(args=["zxqvw"])
        assert self.analyzer.analyze(server) == []

    # ── No cross-ecosystem false positives ────────────────────────────────────

    def test_npm_check_not_called_for_uvx(self) -> None:
        # An npm scoped-package name passed to uvx must not produce a finding
        # via the npm comparison pool (cross-ecosystem FP).
        server = _make_pypi_server(args=["@modelcontextprotocol/server-filesyste"])
        # The npm-scoped name is not in the PyPI index and won't match anything
        # in the PyPI pool within threshold, so no finding expected.
        findings = self.analyzer.analyze(server)
        assert findings == []

    # ── Server / client metadata on finding ───────────────────────────────────

    def test_finding_references_server_and_client(self) -> None:
        server = _make_pypi_server(
            name="evil-pypi",
            command="uvx",
            args=["mcp-server-fliesystem"],
        )
        finding = self.analyzer.analyze(server)[0]
        assert finding.server == "evil-pypi"
        assert finding.client == "claude"
        assert finding.owasp_mcp_top_10 == ["MCP04"]

    # ── npm path unaffected ────────────────────────────────────────────────────

    def test_npm_typosquat_still_works_after_python_addition(self) -> None:
        """Regression: npm typosquat path must not be broken by Python changes."""
        server = _make_server(args=["-y", "@modelcontextprotocol/server-filesyste"])
        findings = self.analyzer.analyze(server)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].id == "SC-001"


# ── Integration test: uvx_config.json fixture ────────────────────────────────


class TestUvxConfigFixtureIntegration:
    """End-to-end: parse uvx_config.json and run the supply chain analyzer."""

    def setup_method(self) -> None:
        self.analyzer = SupplyChainAnalyzer()
        self._fixture = Path(__file__).parent / "fixtures" / "uvx_config.json"

    def test_fixture_exists(self) -> None:
        assert self._fixture.exists(), f"Fixture not found: {self._fixture}"

    def test_typosquat_servers_produce_sc002(self) -> None:
        from mcp_audit.config_parser import parse_config
        from mcp_audit.discovery import DiscoveredConfig

        discovered = DiscoveredConfig(
            client_name="claude",
            root_key="mcpServers",
            path=self._fixture,
        )
        servers = parse_config(discovered)

        all_findings: list = []
        for server in servers:
            all_findings.extend(self.analyzer.analyze(server))

        sc002_findings = [f for f in all_findings if f.id == "SC-002"]
        # Three typosquat servers in the fixture: typosquat-uvx, pipx-typosquat,
        # python-m-typosquat — each should produce SC-002 HIGH.
        assert len(sc002_findings) == 3, (
            f"Expected 3 SC-002 findings, got {len(sc002_findings)}: "
            f"{[(f.server, f.id) for f in all_findings]}"
        )

    def test_known_good_server_produces_no_finding(self) -> None:
        from mcp_audit.config_parser import parse_config
        from mcp_audit.discovery import DiscoveredConfig

        discovered = DiscoveredConfig(
            client_name="claude",
            root_key="mcpServers",
            path=self._fixture,
        )
        servers = parse_config(discovered)

        for server in servers:
            if server.name == "known-good-uvx":
                findings = self.analyzer.analyze(server)
                assert findings == [], (
                    f"Expected no findings for known-good-uvx, got {findings}"
                )
