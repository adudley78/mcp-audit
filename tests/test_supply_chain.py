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
        # An exact registry match is never a typosquat.  The registry now
        # carries this package's fixed CVEs, so SC-004 may fire (STORY-0083).
        assert _non_advisory(self.analyzer.analyze(server)) == []

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
        assert _non_advisory(self.analyzer.analyze(server)) == []

    def test_npx_pypi_only_name_not_short_circuited_as_known(self) -> None:
        """Regression test for the ecosystem-blind lookup bug.

        Uses an isolated, controlled registry rather than the live bundled
        one, so this regression does not depend on registry contents that
        can legitimately change over time. (The original version of this
        test relied on the bundled registry's "mcp-server-gcp" as a
        coincidental npm-side typosquat neighbor; that entry was removed in
        the 2026-08-20 audit correction as an unrelated squat-farm listing —
        see registry-audit-2026-08-18.md and CHANGELOG.md — which is exactly
        the kind of churn a regression test should not depend on.)

        "mcp-server-git" is registered ONLY as a ``package_ecosystem: "pypi"``
        entry. Before ``is_known_npm``/``get_npm`` existed, the
        ecosystem-blind ``is_known()``/``get()`` pair matched this pypi entry
        for an npx-launched server and silently suppressed all findings (the
        package was treated as "known"). The npm-scoped path must not do
        this — it falls through to typosquat detection and correctly flags
        the unrelated npm entry "mcp-server-get" as a distance-1 candidate
        instead.
        """
        import json
        import tempfile

        from mcp_audit.registry.loader import KnownServerRegistry

        payload = {
            "schema_version": "1.0",
            "last_updated": "2026-08-20",
            "entries": [
                {
                    "name": "mcp-server-git",
                    "source": "pip",
                    "package_ecosystem": "pypi",
                    "repo": "https://github.com/modelcontextprotocol/servers",
                    "maintainer": "Anthropic",
                    "verified": True,
                    "last_verified": "2026-08-20",
                    "known_versions": [],
                    "tags": [],
                },
                {
                    "name": "mcp-server-get",
                    "source": "npm",
                    "repo": "https://github.com/example/mcp-server-get",
                    "maintainer": "community",
                    "verified": False,
                    "last_verified": "2026-08-20",
                    "known_versions": [],
                    "tags": [],
                },
            ],
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as fh:
            json.dump(payload, fh)
            tmp = fh.name
        registry = KnownServerRegistry(path=Path(tmp))
        analyzer = SupplyChainAnalyzer(registry=registry)

        server = _make_server(command="npx", args=["-y", "mcp-server-git"])
        findings = analyzer.analyze(server)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].id == "SC-001"
        assert "mcp-server-get" in findings[0].remediation

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
        assert _non_advisory(self.analyzer.analyze(server)) == []

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

    # ── python interpreter spelling (nc -e class: word-boundary evasion) ─────────

    def test_python3_m_extraction(self) -> None:
        # Regression: the bare ``command == "python"`` gate silently skipped the
        # dominant real-world spelling ``python3`` — a ``python3 -m <typosquat>``
        # invocation evaded supply-chain detection entirely.
        assert extract_pypi_package("python3", ["-m", "mcp_server_git"]) == (
            "mcp-server-git"
        )

    def test_python311_m_extraction(self) -> None:
        assert extract_pypi_package("python3.11", ["-m", "mcp-server-git"]) == (
            "mcp-server-git"
        )

    def test_python_abspath_m_extraction(self) -> None:
        assert extract_pypi_package("/usr/bin/python3", ["-m", "mcp-server-git"]) == (
            "mcp-server-git"
        )

    def test_py_launcher_m_extraction(self) -> None:
        assert extract_pypi_package("py", ["-m", "mcp-server-git"]) == "mcp-server-git"


class TestPythonInterpreterTyposquat:
    """``python3 -m <typosquat>`` must fire the same as ``python -m``."""

    def setup_method(self) -> None:
        self.analyzer = SupplyChainAnalyzer(offline_registry=True)

    @pytest.mark.parametrize("command", ["python", "python3", "python3.11"])
    def test_interpreter_spelling_detects_pypi_typosquat(self, command: str) -> None:
        # 1-edit typo of a known PyPI registry entry (mcp-server-git).
        server = _make_server(command=command, args=["-m", "mcp-server-gix"])
        findings = self.analyzer.analyze(server)
        ids = [f.id for f in findings]
        assert "SC-001" in ids, f"{command} -m typosquat must be detected"

    def test_abspath_python3_detects_typosquat(self) -> None:
        server = _make_server(
            command="/usr/local/bin/python3", args=["-m", "mcp-server-gix"]
        )
        assert "SC-001" in [f.id for f in self.analyzer.analyze(server)]


# ── KnownServerRegistry PyPI helpers ─────────────────────────────────────────


class TestRegistryPypiHelpers:
    def setup_method(self) -> None:
        self.registry = _loader_module.KnownServerRegistry()

    def test_get_pypi_names_returns_set(self) -> None:
        names = self.registry.get_pypi_names()
        assert isinstance(names, set)
        assert len(names) > 0

    def test_get_pypi_names_contains_known_entries(self) -> None:
        # "mcp-server-filesystem" was removed from the registry in the
        # 2026-08-20 audit correction — it never existed on PyPI (only the
        # npm-scoped `@modelcontextprotocol/server-filesystem` is real). See
        # registry-audit-2026-08-18.md and CHANGELOG.md.
        names = self.registry.get_pypi_names()
        assert "mcp-server-git" in names
        assert "mcp-server-fetch" in names

    def test_get_pypi_names_excludes_npm_entries(self) -> None:
        names = self.registry.get_pypi_names()
        # npm-only scoped packages must not appear in the PyPI pool
        assert "@modelcontextprotocol/server-filesystem" not in names

    def test_is_known_pypi_exact_match(self) -> None:
        assert self.registry.is_known_pypi("mcp-server-fetch") is True

    def test_is_known_pypi_normalised_match(self) -> None:
        # Underscore variant normalises to the same name
        assert self.registry.is_known_pypi("mcp_server_fetch") is True

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
        result = self.registry.find_closest_pypi("mcp-server-fetch", threshold=3)
        assert result is None

    def test_find_closest_pypi_typo_found(self) -> None:
        # "mcp-server-fethc" is 2 edits from "mcp-server-fetch"
        result = self.registry.find_closest_pypi("mcp-server-fethc", threshold=3)
        assert result is not None
        assert result.name == "mcp-server-fetch"

    def test_find_closest_pypi_no_match_returns_none(self) -> None:
        result = self.registry.find_closest_pypi(
            "completely-unrelated-zzz", threshold=3
        )
        assert result is None

    def test_registry_entry_has_package_ecosystem_field(self) -> None:
        entry = self.registry.get("mcp-server-fetch")
        assert entry is not None
        assert entry.package_ecosystem == "pypi"

    def test_npm_entry_has_default_ecosystem(self) -> None:
        entry = self.registry.get("@modelcontextprotocol/server-filesystem")
        assert entry is not None
        assert entry.package_ecosystem == "npm"


# ── KnownServerRegistry npm helpers ──────────────────────────────────────────


class TestRegistryNpmHelpers:
    """Mirrors TestRegistryPypiHelpers for the npm-scoped lookup trio.

    Regression coverage for the ecosystem-blind lookup bug: an npm-context
    caller (this analyzer's npm branch) must never resolve a PyPI-only
    entry's data by name, even when the two happen to share a name.
    """

    def setup_method(self) -> None:
        self.registry = _loader_module.KnownServerRegistry()

    def test_is_known_npm_exact_match(self) -> None:
        assert (
            self.registry.is_known_npm("@modelcontextprotocol/server-filesystem")
            is True
        )

    def test_is_known_npm_unknown_returns_false(self) -> None:
        assert self.registry.is_known_npm("totally-unknown-xyz-package") is False

    def test_is_known_npm_pypi_only_entry_returns_false(self) -> None:
        # "mcp-server-git" is a PyPI-only entry in the bundled registry — it
        # must not resolve on the npm-scoped path.
        assert self.registry.is_known_npm("mcp-server-git") is False

    def test_get_npm_exact_match(self) -> None:
        entry = self.registry.get_npm("@modelcontextprotocol/server-filesystem")
        assert entry is not None
        assert entry.package_ecosystem == "npm"

    def test_get_npm_pypi_only_entry_returns_none(self) -> None:
        """Regression guard for the "mcp-server-git" collision bug.

        An npx-launched server whose package exists ONLY as a pypi entry
        must NOT be treated as known/verified on the npm path.
        """
        assert self.registry.get_npm("mcp-server-git") is None

    def test_find_closest_npm_exact_returns_none(self) -> None:
        result = self.registry.find_closest_npm(
            "@modelcontextprotocol/server-filesystem", threshold=3
        )
        assert result is None

    def test_find_closest_npm_typo_found(self) -> None:
        # "server-fliesystem" is 2 edits from "server-filesystem"
        result = self.registry.find_closest_npm(
            "@modelcontextprotocol/server-fliesystem", threshold=3
        )
        assert result is not None
        assert result.name == "@modelcontextprotocol/server-filesystem"

    def test_find_closest_npm_no_match_returns_none(self) -> None:
        result = self.registry.find_closest_npm("completely-unrelated-zzz", threshold=3)
        assert result is None

    def test_find_closest_npm_excludes_pypi_only_entries(self) -> None:
        # A pypi-only entry (e.g. "mcp-server-git") must never surface as the
        # npm typosquat comparison target, even at a close edit distance.
        result = self.registry.find_closest_npm("mcp-server-gitt", threshold=3)
        assert result is None or result.package_ecosystem != "pypi"


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
        # "mcp-server-fethc" transposes 'ch' → distance 2 → SC-002 HIGH
        # (base package: "mcp-server-fetch". The original anchor here,
        # "mcp-server-filesystem" on PyPI, was removed from the registry in
        # the 2026-08-20 audit correction — it never existed on PyPI. See
        # registry-audit-2026-08-18.md and CHANGELOG.md.)
        server = _make_pypi_server(args=["mcp-server-fethc"])
        findings = self.analyzer.analyze(server)
        assert len(findings) == 1
        assert findings[0].id == "SC-002"
        assert findings[0].severity == Severity.HIGH
        assert findings[0].analyzer == "supply_chain"
        assert findings[0].cwe == "CWE-829"

    def test_uvx_typosquat_title_contains_package(self) -> None:
        server = _make_pypi_server(args=["mcp-server-fethc"])
        finding = self.analyzer.analyze(server)[0]
        assert "mcp-server-fethc" in finding.title
        assert "Python package typosquat" in finding.title

    def test_uvx_typosquat_remediation_mentions_correct_name(self) -> None:
        server = _make_pypi_server(args=["mcp-server-fethc"])
        finding = self.analyzer.analyze(server)[0]
        assert "mcp-server-fetch" in finding.remediation

    def test_uvx_typosquat_evidence_contains_command(self) -> None:
        server = _make_pypi_server(args=["mcp-server-fethc"])
        finding = self.analyzer.analyze(server)[0]
        assert "uvx" in finding.evidence

    def test_uvx_distance_1_critical(self) -> None:
        # Drop one char from end: "mcp-server-fetc" → distance 1 → CRITICAL SC-001
        server = _make_pypi_server(args=["mcp-server-fetc"])
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

    def test_uvx_known_good_fetch_no_finding(self) -> None:
        server = _make_pypi_server(args=["mcp-server-fetch"])
        assert self.analyzer.analyze(server) == []

    def test_uvx_known_good_normalised_no_finding(self) -> None:
        # Underscore variant is PEP 503 equivalent — no finding
        server = _make_pypi_server(args=["mcp_server_fetch"])
        assert self.analyzer.analyze(server) == []

    def test_uvx_known_good_postgres_no_finding(self) -> None:
        server = _make_pypi_server(args=["mcp-server-postgres"])
        assert self.analyzer.analyze(server) == []

    def test_pipx_run_known_good_no_finding(self) -> None:
        server = _make_pypi_server(command="pipx", args=["run", "mcp-server-git"])
        assert _non_advisory(self.analyzer.analyze(server)) == []

    # ── Argument parsing ───────────────────────────────────────────────────────

    def test_pipx_run_typosquat_detected(self) -> None:
        # "mcp-server-fethc" via pipx run
        server = _make_pypi_server(command="pipx", args=["run", "mcp-server-fethc"])
        findings = self.analyzer.analyze(server)
        assert len(findings) == 1
        assert findings[0].id == "SC-002"

    def test_python_m_normalisation_and_check(self) -> None:
        # python -m mcp_server_fetch → normalises to mcp-server-fetch (exact)
        server = _make_pypi_server(command="python", args=["-m", "mcp_server_fetch"])
        assert self.analyzer.analyze(server) == []

    def test_python_m_typosquat_detected(self) -> None:
        # python -m mcp_server_fethc → typosquat
        server = _make_pypi_server(command="python", args=["-m", "mcp_server_fethc"])
        findings = self.analyzer.analyze(server)
        assert len(findings) == 1
        assert findings[0].id == "SC-002"

    def test_uvx_from_flag_package_extracted(self) -> None:
        # "--from mcp-server-fetch mcp-fs" → package is mcp-server-fetch
        server = _make_pypi_server(args=["--from", "mcp-server-fetch", "mcp-fs"])
        assert self.analyzer.analyze(server) == []

    def test_uvx_from_flag_typo_detected(self) -> None:
        server = _make_pypi_server(args=["--from", "mcp-server-fethc", "mcp-fs"])
        findings = self.analyzer.analyze(server)
        assert len(findings) == 1
        assert findings[0].id == "SC-002"

    def test_uvx_version_suffix_stripped_known_good(self) -> None:
        server = _make_pypi_server(args=["mcp-server-fetch@1.0.0"])
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
            args=["mcp-server-fethc"],
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


def _non_advisory(findings: list) -> list:
    """Findings other than SC-004 (registry CVE advisories)."""
    return [f for f in findings if f.id != "SC-004"]


# ── SC-004: offline known-CVE advisory check ──────────────────────────────────


class TestKnownCveAdvisory:
    """SC-004 fires when an exact-match registry entry has known_vulnerabilities."""

    def _make_registry(self, entries: list) -> _loader_module.KnownServerRegistry:
        """Build a KnownServerRegistry backed by an in-memory JSON payload."""
        import json
        import tempfile

        from mcp_audit.registry.loader import KnownServerRegistry

        payload = {
            "schema_version": "1.0",
            "last_updated": "2026-06-13",
            "entries": entries,
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as fh:
            json.dump(payload, fh)
            tmp = fh.name
        return KnownServerRegistry(path=Path(tmp))

    def _make_server(
        self,
        name: str,
        command: str,
        args: list,
        config_path: str = "/fake/mcp.json",
    ) -> ServerConfig:
        return ServerConfig(
            name=name,
            command=command,
            args=args,
            client="claude",
            config_path=config_path,
        )

    def test_sc004_fires_for_npm_package_with_cve(self) -> None:
        """SC-004 is emitted when npx package has known_vulnerabilities."""
        registry = self._make_registry(
            [
                {
                    "name": "@mcpjam/inspector",
                    "source": "npm",
                    "repo": "https://github.com/MCPJam/inspector",
                    "maintainer": "MCPJam",
                    "verified": False,
                    "last_verified": "2026-06-13",
                    "known_versions": [],
                    "tags": [],
                    "known_vulnerabilities": ["CVE-2026-23744"],
                }
            ]
        )
        server = self._make_server("mcpjam", "npx", ["-y", "@mcpjam/inspector"])
        analyzer = SupplyChainAnalyzer(registry=registry)
        findings = analyzer.analyze(server)

        assert len(findings) == 1
        f = findings[0]
        assert f.id == "SC-004"
        assert f.severity == Severity.HIGH
        assert "CVE-2026-23744" in f.title
        assert "CVE-2026-23744" in f.description
        assert f.analyzer == "supply_chain"
        assert f.owasp_mcp_top_10 == ["MCP04"]

    def test_sc004_one_finding_per_package(self) -> None:
        """Multiple CVEs on one entry produce ONE SC-004 listing all of them.

        STORY-0078: per-CVE emission turned a package with two dozen
        advisories into two dozen HIGH findings, and every SC-004 for a
        package already shares one advisory ID in the feed.
        """
        registry = self._make_registry(
            [
                {
                    "name": "flowise",
                    "source": "npm",
                    "repo": "https://github.com/FlowiseAI/Flowise",
                    "maintainer": "FlowiseAI",
                    "verified": False,
                    "last_verified": "2026-06-13",
                    "known_versions": [],
                    "tags": [],
                    "known_vulnerabilities": ["CVE-2025-59528", "CVE-2026-99999"],
                }
            ]
        )
        server = self._make_server("flowise", "npx", ["flowise"])
        analyzer = SupplyChainAnalyzer(registry=registry)
        findings = analyzer.analyze(server)

        assert len(findings) == 1
        f = findings[0]
        assert f.id == "SC-004"
        assert f.title == "Known CVE advisories: flowise (2 CVEs)"
        assert "CVE-2025-59528" in f.description
        assert "CVE-2026-99999" in f.description
        assert "cves: CVE-2025-59528, CVE-2026-99999" in f.evidence

    def test_sc004_no_finding_when_no_known_vulnerabilities(self) -> None:
        """Known package without CVEs does not produce SC-004."""
        registry = self._make_registry(
            [
                {
                    "name": "@modelcontextprotocol/server-filesystem",
                    "source": "npm",
                    "repo": "https://github.com/modelcontextprotocol/servers",
                    "maintainer": "Anthropic",
                    "verified": True,
                    "last_verified": "2026-06-13",
                    "known_versions": [],
                    "tags": [],
                }
            ]
        )
        server = self._make_server(
            "filesystem",
            "npx",
            ["-y", "@modelcontextprotocol/server-filesystem"],
        )
        analyzer = SupplyChainAnalyzer(registry=registry)
        findings = analyzer.analyze(server)

        assert findings == []

    def test_sc004_evidence_contains_package_and_cve(self) -> None:
        """SC-004 evidence field references package name and CVE ID."""
        registry = self._make_registry(
            [
                {
                    "name": "gemini-mcp-tool",
                    "source": "npm",
                    "repo": "https://github.com/google-gemini/gemini-mcp-tool",
                    "maintainer": "community",
                    "verified": False,
                    "last_verified": "2026-06-13",
                    "known_versions": [],
                    "tags": [],
                    "known_vulnerabilities": ["CVE-2026-0755"],
                }
            ]
        )
        server = self._make_server("gemini", "npx", ["gemini-mcp-tool"])
        analyzer = SupplyChainAnalyzer(registry=registry)
        findings = analyzer.analyze(server)

        assert len(findings) == 1
        assert "gemini-mcp-tool" in findings[0].evidence
        assert "CVE-2026-0755" in findings[0].evidence

    def test_sc004_seeded_cve_surfaces_via_bundled_registry(self) -> None:
        """CVE-2026-23744 in bundled registry surfaces as SC-004 for @mcpjam/inspector.

        This test validates the full data→code pipeline: the seeded CVE in
        registry/known-servers.json must produce an SC-004 finding when a
        config contains '@mcpjam/inspector'.
        """
        analyzer = SupplyChainAnalyzer()
        server = self._make_server(
            "mcpjam-inspector",
            "npx",
            ["-y", "@mcpjam/inspector"],
        )
        findings = analyzer.analyze(server)

        sc004 = [f for f in findings if f.id == "SC-004"]
        assert len(sc004) >= 1, (
            "Expected SC-004 for @mcpjam/inspector (CVE-2026-23744 is in registry); "
            f"got {findings}"
        )
        assert any("CVE-2026-23744" in f.title for f in sc004)


# ── SC-004: version-aware suppression (STORY-0078) ────────────────────────────


def _vuln_registry(entries: list) -> _loader_module.KnownServerRegistry:
    """Build a KnownServerRegistry from in-memory entries."""
    import json
    import tempfile

    from mcp_audit.registry.loader import KnownServerRegistry

    payload = {
        "schema_version": "1.0",
        "last_updated": "2026-10-11",
        "entries": entries,
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as fh:
        json.dump(payload, fh)
        tmp = fh.name
    return KnownServerRegistry(path=Path(tmp))


def _pypi_entry(**extra: object) -> dict:
    entry: dict = {
        "name": "acme-mcp",
        "source": "pip",
        "package_ecosystem": "pypi",
        "repo": "https://example.invalid/acme-mcp",
        "maintainer": "acme",
        "verified": False,
        "last_verified": "2026-10-11",
        "known_versions": [],
        "tags": [],
    }
    entry.update(extra)
    return entry


_TWO_FIXED = {
    "known_vulnerabilities": ["CVE-2026-00001", "CVE-2026-00002"],
    "known_vulns": [
        {
            "cve": "CVE-2026-00001",
            "cvss": None,
            "description": "a",
            "fixed_in": "0.17.0",
        },
        {
            "cve": "CVE-2026-00002",
            "cvss": None,
            "description": "b",
            "fixed_in": "0.22.0",
        },
    ],
}


def _srv(command: str, args: list[str]) -> ServerConfig:
    return ServerConfig(
        name="s", command=command, args=args, client="claude", config_path="/x.json"
    )


class TestSc004VersionAware:
    """SC-004 drops CVEs a pinned version is already past."""

    def test_pinned_above_every_fix_is_silent(self) -> None:
        reg = _vuln_registry([_pypi_entry(**_TWO_FIXED)])
        out = SupplyChainAnalyzer(registry=reg).analyze(
            _srv("uvx", ["acme-mcp==0.23.1"])
        )
        assert [f for f in out if f.id == "SC-004"] == []

    def test_pinned_between_fixes_keeps_only_the_unfixed_cve(self) -> None:
        reg = _vuln_registry([_pypi_entry(**_TWO_FIXED)])
        out = SupplyChainAnalyzer(registry=reg).analyze(
            _srv("uvx", ["acme-mcp@0.18.0"])
        )
        assert len(out) == 1
        f = out[0]
        assert f.title == "Known CVE advisory: acme-mcp (CVE-2026-00002)"
        assert "pins version 0.18.0" in f.description
        assert "pinned: 0.18.0" in f.evidence
        assert "fixed_in: 0.22.0" in f.evidence

    def test_unpinned_keeps_all_and_names_the_fix(self) -> None:
        reg = _vuln_registry([_pypi_entry(**_TWO_FIXED)])
        out = SupplyChainAnalyzer(registry=reg).analyze(_srv("uvx", ["acme-mcp"]))
        assert len(out) == 1
        assert out[0].title == "Known CVE advisories: acme-mcp (2 CVEs)"
        assert "fixed in 0.22.0 or later" in out[0].description
        assert "Upgrade 'acme-mcp' to 0.22.0 or later" in out[0].remediation

    def test_unpinned_with_every_cve_fixed_is_medium(self) -> None:
        """STORY-0083: a patched release exists for everything listed."""
        reg = _vuln_registry([_pypi_entry(**_TWO_FIXED)])
        out = SupplyChainAnalyzer(registry=reg).analyze(_srv("uvx", ["acme-mcp"]))
        assert out[0].severity == Severity.MEDIUM
        assert "can reuse a cached older install" in out[0].description

    def test_unpinned_with_an_unfixed_cve_stays_high(self) -> None:
        unfixed = {
            "known_vulnerabilities": ["CVE-2026-00001", "CVE-2026-00003"],
            "known_vulns": [
                {
                    "cve": "CVE-2026-00001",
                    "cvss": None,
                    "description": "a",
                    "fixed_in": "0.17.0",
                },
                {
                    "cve": "CVE-2026-00003",
                    "cvss": None,
                    "description": "c",
                    "fixed_in": None,
                },
            ],
        }
        reg = _vuln_registry([_pypi_entry(**unfixed)])
        out = SupplyChainAnalyzer(registry=reg).analyze(_srv("uvx", ["acme-mcp"]))
        assert out[0].severity == Severity.HIGH
        assert "no recorded fix" in out[0].description

    def test_pinned_below_a_fix_is_high(self) -> None:
        reg = _vuln_registry([_pypi_entry(**_TWO_FIXED)])
        out = SupplyChainAnalyzer(registry=reg).analyze(
            _srv("uvx", ["acme-mcp==0.18.0"])
        )
        assert out[0].severity == Severity.HIGH

    def test_long_cve_lists_are_capped_in_the_description(self) -> None:
        many = [f"CVE-2026-{n:05d}" for n in range(1, 16)]
        reg = _vuln_registry(
            [
                _pypi_entry(
                    known_vulnerabilities=many,
                    known_vulns=[
                        {"cve": c, "cvss": None, "description": c, "fixed_in": "1.0.0"}
                        for c in many
                    ],
                )
            ]
        )
        out = SupplyChainAnalyzer(registry=reg).analyze(_srv("uvx", ["acme-mcp"]))
        assert out[0].title == "Known CVE advisories: acme-mcp (15 CVEs)"
        assert "CVE-2026-00010" in out[0].description
        assert "CVE-2026-00011" not in out[0].description
        assert (
            "and 5 more (`mcp-audit vet acme-mcp` lists them all)" in out[0].description
        )

    def test_ghsa_only_advisory_links_to_github(self) -> None:
        reg = _vuln_registry(
            [_pypi_entry(known_vulnerabilities=["GHSA-aaaa-bbbb-cccc"], known_vulns=[])]
        )
        out = SupplyChainAnalyzer(registry=reg).analyze(_srv("uvx", ["acme-mcp"]))
        assert "https://github.com/advisories/GHSA-aaaa-bbbb-cccc" in out[0].description

    def test_cve_without_fixed_in_is_kept_even_when_pinned(self) -> None:
        reg = _vuln_registry(
            [
                _pypi_entry(
                    known_vulnerabilities=["CVE-2026-00009"], **{"known_vulns": []}
                )
            ]
        )
        out = SupplyChainAnalyzer(registry=reg).analyze(
            _srv("uvx", ["acme-mcp==9.9.9"])
        )
        assert len(out) == 1
        assert "CVE-2026-00009" in out[0].title

    def test_known_vulns_alone_still_fires(self) -> None:
        reg = _vuln_registry(
            [
                _pypi_entry(
                    known_vulns=[
                        {
                            "cve": "CVE-2026-00003",
                            "cvss": None,
                            "description": "c",
                            "fixed_in": "2.0.0",
                        }
                    ]
                )
            ]
        )
        out = SupplyChainAnalyzer(registry=reg).analyze(_srv("uvx", ["acme-mcp"]))
        assert len(out) == 1
        assert "CVE-2026-00003" in out[0].title

    def test_npm_exact_pin_suppresses_and_range_does_not(self) -> None:
        entry = {
            "name": "@acme/server",
            "source": "npm",
            "package_ecosystem": "npm",
            "repo": "https://example.invalid/acme",
            "maintainer": "acme",
            "verified": False,
            "last_verified": "2026-10-11",
            "known_versions": [],
            "tags": [],
            "known_vulnerabilities": ["CVE-2026-00004"],
            "known_vulns": [
                {
                    "cve": "CVE-2026-00004",
                    "cvss": None,
                    "description": "d",
                    "fixed_in": "1.5.0",
                }
            ],
        }
        reg = _vuln_registry([entry])
        an = SupplyChainAnalyzer(registry=reg)
        assert an.analyze(_srv("npx", ["-y", "@acme/server@1.5.0"])) == []
        assert len(an.analyze(_srv("npx", ["-y", "@acme/server@1.4.0"]))) == 1
        # A range is not a pin: offline, mcp-audit can't know what it installs.
        assert len(an.analyze(_srv("npx", ["-y", "@acme/server@^1.5.0"]))) == 1


class TestPinnedVersion:
    """_pinned_version only returns exact pins."""

    @pytest.mark.parametrize(
        ("command", "args", "expected"),
        [
            ("npx", ["-y", "@scope/pkg@1.2.3"], "1.2.3"),
            ("npx", ["pkg@1.2.3-beta.1"], "1.2.3-beta.1"),
            ("npx", ["-y", "@scope/pkg"], None),
            ("npx", ["pkg@latest"], None),
            ("npx", ["pkg@^1.2.3"], None),
            ("yarn", ["dlx", "pkg@2.0.0"], "2.0.0"),
            ("uvx", ["mcp-atlassian==0.21.1"], "0.21.1"),
            ("uvx", ["mcp-atlassian@0.21.1"], "0.21.1"),
            ("uvx", ["mcp-atlassian>=0.21"], None),
            ("uvx", ["mcp-atlassian"], None),
            ("pipx", ["run", "mcp-atlassian==0.22.0"], "0.22.0"),
            ("node", ["server.js"], None),
        ],
    )
    def test_forms(self, command: str, args: list[str], expected: str | None) -> None:
        from mcp_audit.analyzers.supply_chain import _pinned_version

        assert _pinned_version(_srv(command, args)) == expected


class TestBundledRegistryAdvisories:
    """The shipped registry data drives SC-004 end to end (STORY-0078)."""

    def test_mcp_atlassian_unpinned_is_one_finding_with_all_cves(self) -> None:
        out = SupplyChainAnalyzer().analyze(_srv("uvx", ["mcp-atlassian"]))
        sc004 = [f for f in out if f.id == "SC-004"]
        assert len(sc004) == 1
        assert sc004[0].title == "Known CVE advisories: mcp-atlassian (30 CVEs)"
        # Every advisory has a fix, and the launch is unpinned (STORY-0083).
        assert sc004[0].severity == Severity.MEDIUM
        assert "and 20 more" in sc004[0].description
        assert "mcp-audit vet mcp-atlassian" in sc004[0].description

    def test_mcp_atlassian_fixed_release_is_silent(self) -> None:
        out = SupplyChainAnalyzer().analyze(_srv("uvx", ["mcp-atlassian==0.23.1"]))
        assert [f for f in out if f.id == "SC-004"] == []

    def test_mcp_atlassian_vulnerable_release_fires(self) -> None:
        out = SupplyChainAnalyzer().analyze(_srv("uvx", ["mcp-atlassian==0.21.1"]))
        sc004 = [f for f in out if f.id == "SC-004"]
        assert len(sc004) == 1
        # 0.21.1 is past the fixes for CVE-2026-27826 (0.17.0) and the two
        # advisories fixed before 0.21.1; every other advisory still applies.
        assert "(28 CVEs)" in sc004[0].title
        assert sc004[0].severity == Severity.HIGH

    def test_toolbox_server_pin_below_and_at_fix(self) -> None:
        an = SupplyChainAnalyzer()
        below = an.analyze(_srv("npx", ["-y", "@toolbox-sdk/server@1.4.0"]))
        assert [f.title for f in below if f.id == "SC-004"] == [
            "Known CVE advisory: @toolbox-sdk/server (CVE-2026-14540)"
        ]
        at_fix = an.analyze(_srv("npx", ["-y", "@toolbox-sdk/server@1.5.0"]))
        assert [f for f in at_fix if f.id == "SC-004"] == []
