# Final scanner.py coverage after this module: 89%
# (only lines 215-240 remain uncovered: live --connect MCP enumeration,
#  which requires a running MCP server and the optional mcp SDK)
"""Tests for mcp_audit.scanner — orchestration logic."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from mcp_audit.analyzers.base import BaseAnalyzer
from mcp_audit.analyzers.supply_chain import SupplyChainAnalyzer
from mcp_audit.cli import app
from mcp_audit.models import (
    Finding,
    RegistryStats,
    ScanResult,
    ServerConfig,
    Severity,
    TransportType,
)
from mcp_audit.scanner import (
    _run_rules_engine,
    _run_static_pipeline,
    run_scan,
    run_scan_async,
)


def _make_server(name: str = "test-server") -> ServerConfig:
    return ServerConfig(
        name=name,
        client="test",
        config_path=Path("/tmp/test.json"),  # noqa: S108
        transport=TransportType.STDIO,
        command="node",
        args=["server.js"],
        raw={"command": "node", "args": ["server.js"]},
    )


def _patch_no_known_clients():
    """Patch discovery so only extra_paths configs are found."""
    return patch("mcp_audit.discovery._get_client_specs", return_value=[])


class TestOfflineConnectConflict:
    """V-03: --offline --connect must raise, not silently proceed."""

    def test_offline_and_connect_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="Cannot use --connect with --offline"):
            run_scan(offline=True, connect=True)

    def test_offline_without_connect_succeeds(self, tmp_path: Path) -> None:
        config_file = tmp_path / "empty.json"
        config_file.write_text('{"mcpServers": {}}')
        with _patch_no_known_clients():
            result = run_scan(
                extra_paths=[config_file],
                offline=True,
                connect=False,
                skip_rug_pull=True,
            )
        assert result is not None


class TestAnalyzerCrashFinding:
    """V-04: a crashing analyzer must produce a HIGH finding."""

    def test_crashing_analyzer_emits_finding(self, tmp_path: Path) -> None:
        config_file = tmp_path / "test.json"
        config_file.write_text(
            '{"mcpServers": {"srv": {"command": "node", "args": ["s.js"]}}}'
        )

        class CrashingAnalyzer(BaseAnalyzer):
            @property
            def name(self) -> str:
                return "crasher"

            @property
            def description(self) -> str:
                return "Always crashes"

            def analyze(self, server: ServerConfig) -> list[Finding]:
                raise RuntimeError("simulated crash")

        with _patch_no_known_clients():
            result = run_scan(
                extra_paths=[config_file],
                analyzers=[CrashingAnalyzer()],
                skip_rug_pull=True,
            )

        crash_findings = [f for f in result.findings if f.id == "SCAN-ERR"]
        assert len(crash_findings) == 1
        assert crash_findings[0].severity == Severity.HIGH
        assert "crasher" in crash_findings[0].title
        assert "simulated crash" in crash_findings[0].evidence

    def test_crashing_analyzer_does_not_suppress_other_findings(
        self, tmp_path: Path
    ) -> None:
        config_file = tmp_path / "test.json"
        config_file.write_text(
            '{"mcpServers": {"srv": {"command": "node", "args": ["s.js"]}}}'
        )

        class CrashingAnalyzer(BaseAnalyzer):
            @property
            def name(self) -> str:
                return "crasher"

            @property
            def description(self) -> str:
                return "Always crashes"

            def analyze(self, server: ServerConfig) -> list[Finding]:
                raise RuntimeError("boom")

        class GoodAnalyzer(BaseAnalyzer):
            @property
            def name(self) -> str:
                return "good"

            @property
            def description(self) -> str:
                return "Always finds something"

            def analyze(self, server: ServerConfig) -> list[Finding]:
                return [
                    Finding(
                        id="GOOD-001",
                        severity=Severity.LOW,
                        analyzer="good",
                        client=server.client,
                        server=server.name,
                        title="Found something",
                        description="A real finding",
                        evidence="evidence",
                        remediation="fix it",
                    )
                ]

        with _patch_no_known_clients():
            result = run_scan(
                extra_paths=[config_file],
                analyzers=[CrashingAnalyzer(), GoodAnalyzer()],
                skip_rug_pull=True,
            )

        assert any(f.id == "GOOD-001" for f in result.findings)
        assert any(f.id == "SCAN-ERR" for f in result.findings)


# ── Registry stats populated by scanner ───────────────────────────────────────


class TestRegistryStatsInScanResult:
    """run_scan must populate ScanResult.registry_stats from the SupplyChainAnalyzer."""

    def test_registry_stats_populated_by_default(self, tmp_path: Path) -> None:
        config_file = tmp_path / "mcp.json"
        config_file.write_text('{"mcpServers": {}}')
        with _patch_no_known_clients():
            result = run_scan(
                extra_paths=[config_file],
                skip_rug_pull=True,
            )
        assert result.registry_stats is not None
        assert isinstance(result.registry_stats, RegistryStats)
        assert result.registry_stats.entry_count > 0

    def test_registry_stats_uses_live_entry_count(self, tmp_path: Path) -> None:
        """entry_count must reflect len(registry.entries), not the stored field."""

        from mcp_audit.registry.loader import KnownServerRegistry  # noqa: PLC0415

        mock_reg = MagicMock(spec=KnownServerRegistry)
        mock_reg.entries = []  # 0 live entries
        mock_reg.schema_version = "1.0"
        mock_reg.last_updated = "2026-04-15"
        mock_reg.is_known.return_value = True

        config_file = tmp_path / "mcp.json"
        config_file.write_text('{"mcpServers": {}}')
        with _patch_no_known_clients():
            result = run_scan(
                extra_paths=[config_file],
                analyzers=[SupplyChainAnalyzer(registry=mock_reg)],
                skip_rug_pull=True,
            )
        assert result.registry_stats is not None
        assert result.registry_stats.entry_count == 0

    def test_registry_stats_none_when_no_supply_chain_analyzer(
        self, tmp_path: Path
    ) -> None:
        """No SupplyChainAnalyzer in the list → registry_stats must be None."""
        config_file = tmp_path / "mcp.json"
        config_file.write_text('{"mcpServers": {}}')
        with _patch_no_known_clients():
            result = run_scan(
                extra_paths=[config_file],
                analyzers=[],
                skip_rug_pull=True,
            )
        assert result.registry_stats is None


# ── Nonexistent --path handling ───────────────────────────────────────────────


class TestNonexistentPathHandling:
    """CLI must exit 2 with a clear error when --path points to a missing file."""

    def test_scan_nonexistent_path_exits_2(self, tmp_path: Path) -> None:
        missing = tmp_path / "does-not-exist-mcp.json"
        runner = CliRunner()
        with _patch_no_known_clients():
            result = runner.invoke(app, ["scan", "--path", str(missing)])
        assert result.exit_code == 2, (
            f"scan with nonexistent --path must exit 2 (error), got {result.exit_code}"
        )

    def test_scan_nonexistent_path_shows_error_message(self, tmp_path: Path) -> None:
        missing = tmp_path / "does-not-exist-mcp.json"
        runner = CliRunner()
        with _patch_no_known_clients():
            result = runner.invoke(app, ["scan", "--path", str(missing)])
        output_lower = result.output.lower()
        assert "not found" in output_lower or "does not exist" in output_lower, (
            "Expected 'not found' or 'does not exist' in output, "
            f"got: {result.output!r}"
        )

    def test_scan_positional_nonexistent_path_exits_2(self, tmp_path: Path) -> None:
        missing = tmp_path / "does-not-exist-mcp.json"
        runner = CliRunner()
        with _patch_no_known_clients():
            result = runner.invoke(app, ["scan", str(missing)])
        assert result.exit_code == 2

    def test_pin_nonexistent_path_exits_2(self, tmp_path: Path) -> None:
        missing = tmp_path / "does-not-exist-mcp.json"
        runner = CliRunner()
        with _patch_no_known_clients():
            result = runner.invoke(app, ["pin", "--path", str(missing)])
        assert result.exit_code == 2

    def test_diff_nonexistent_path_exits_2(self, tmp_path: Path) -> None:
        missing = tmp_path / "does-not-exist-mcp.json"
        runner = CliRunner()
        with _patch_no_known_clients():
            result = runner.invoke(app, ["diff", "--path", str(missing)])
        assert result.exit_code == 2


# ── Positional path argument ───────────────────────────────────────────────────


class TestPositionalPathArgument:
    """scan / pin / diff must accept a bare positional path in addition to --path."""

    def test_scan_accepts_positional_path(self, tmp_path: Path) -> None:
        """mcp-audit scan config.json (no --path flag) must not exit 2."""
        config = tmp_path / "config.json"
        config.write_text('{"mcpServers": {}}')
        runner = CliRunner()
        with _patch_no_known_clients():
            result = runner.invoke(app, ["scan", str(config)])
        assert result.exit_code != 2, (
            "scan with positional path must not produce an argument error (exit 2); "
            f"got exit_code={result.exit_code}, output={result.output!r}"
        )

    def test_scan_positional_path_runs_scan(self, tmp_path: Path) -> None:
        """Positional path triggers a real scan; exit 0 or 1, not an error."""
        config = tmp_path / "config.json"
        config.write_text('{"mcpServers": {}}')
        runner = CliRunner()
        with _patch_no_known_clients():
            result = runner.invoke(app, ["scan", str(config)])
        assert result.exit_code in (0, 1), (
            f"Expected exit 0 or 1, got {result.exit_code}; output={result.output!r}"
        )

    def test_positional_overrides_path_flag(self, tmp_path: Path) -> None:
        """When both positional and --path are supplied, positional takes precedence."""
        positional = tmp_path / "positional.json"
        positional.write_text('{"mcpServers": {}}')
        option_path = tmp_path / "option.json"
        option_path.write_text(
            '{"mcpServers": {"opt": {"command": "node", "args": []}}}'
        )
        runner = CliRunner()
        with _patch_no_known_clients():
            result = runner.invoke(
                app, ["scan", str(positional), "--path", str(option_path)]
            )
        assert result.exit_code in (0, 1)

    def test_pin_accepts_positional_path(self, tmp_path: Path) -> None:
        config = tmp_path / "config.json"
        config.write_text('{"mcpServers": {}}')
        runner = CliRunner()
        with _patch_no_known_clients():
            result = runner.invoke(app, ["pin", str(config)])
        assert result.exit_code != 2, (
            f"pin with positional path must not produce argument error; "
            f"got {result.exit_code}"
        )

    def test_diff_accepts_positional_path(self, tmp_path: Path) -> None:
        config = tmp_path / "config.json"
        config.write_text('{"mcpServers": {}}')
        runner = CliRunner()
        with _patch_no_known_clients():
            result = runner.invoke(app, ["diff", str(config)])
        # diff exits 2 when no baseline exists — that's expected, not an argument error
        # The key assertion: output must not contain Typer's "unexpected extra argument"
        assert "unexpected extra argument" not in result.output.lower(), (
            f"diff rejected positional path as an argument error: {result.output!r}"
        )

    def test_scan_multiple_positional_paths_shows_friendly_error(
        self, tmp_path: Path
    ) -> None:
        """mcp-audit scan FILE1 FILE2 must exit 2 with a user-friendly message."""
        file1 = tmp_path / "config1.json"
        file2 = tmp_path / "config2.json"
        file1.write_text('{"mcpServers": {}}')
        file2.write_text('{"mcpServers": {}}')
        runner = CliRunner()
        with _patch_no_known_clients():
            result = runner.invoke(app, ["scan", str(file1), str(file2)])
        assert result.exit_code == 2, (
            f"Expected exit 2 for multiple positional paths, got {result.exit_code}; "
            f"output={result.output!r}"
        )
        assert "single config path" in result.output, (
            f"Expected friendly error message, got: {result.output!r}"
        )
        assert "unexpected extra argument" not in result.output.lower(), (
            f"Must not surface raw Typer error; got: {result.output!r}"
        )


# ── Invalid JSON path handling ─────────────────────────────────────────────────


class TestInvalidJsonPathHandling:
    """CLI must exit 2 with a clear error when a user-specified --path has invalid JSON.

    This tests the fix in cli.py that surfaces parse failures for explicit
    user-supplied paths, distinguishing them from auto-discovered configs which
    record errors silently and continue.
    """

    def _invoke_with_bad_json(self, bad_json: Path) -> object:
        runner = CliRunner()
        with _patch_no_known_clients():
            return runner.invoke(app, ["scan", "--path", str(bad_json)])

    def test_invalid_json_path_exits_2(self, tmp_path: Path) -> None:
        """A user-specified file with invalid JSON must produce exit code 2."""
        bad_json = tmp_path / "bad.json"
        bad_json.write_text("{not valid json}")
        result = self._invoke_with_bad_json(bad_json)
        assert result.exit_code == 2

    def test_invalid_json_path_shows_error_message(self, tmp_path: Path) -> None:
        """Output must mention the filename so the user knows which file failed."""
        bad_json = tmp_path / "bad.json"
        bad_json.write_text("{not valid json}")
        result = self._invoke_with_bad_json(bad_json)
        assert "bad.json" in result.output

    def test_valid_json_path_does_not_exit_2(self, tmp_path: Path) -> None:
        """A user-specified file with valid (but server-free) JSON must not exit 2."""
        good_json = tmp_path / "good.json"
        good_json.write_text('{"mcpServers": {}}')
        runner = CliRunner()
        with _patch_no_known_clients():
            result = runner.invoke(app, ["scan", "--path", str(good_json)])
        # 0 = clean, 1 = findings; both are acceptable — just not 2
        assert result.exit_code != 2

    def test_auto_discovered_bad_json_does_not_exit_2(self, tmp_path: Path) -> None:
        """Auto-discovered configs with invalid JSON must NOT cause exit 2.

        Only user-specified paths (via --path) should trigger the hard failure.
        Auto-discovered bad configs are silently recorded in result.errors.
        """
        bad_config = tmp_path / "claude_desktop_config.json"
        bad_config.write_text("{not valid json}")

        from mcp_audit.discovery import ClientSpec  # noqa: PLC0415

        fake_spec = ClientSpec(
            name="claude-desktop",
            root_key="mcpServers",
            config_paths=[bad_config],
        )
        runner = CliRunner()
        with patch("mcp_audit.discovery._get_client_specs", return_value=[fake_spec]):
            # No --path flag — this is auto-discovered, not user-specified
            result = runner.invoke(app, ["scan"])
        assert result.exit_code != 2


# ── Happy path scenarios ────────────────────────────────────────────────────────


class TestHappyPathCleanConfig:
    """Scanning a minimal valid config with no servers produces a perfect score."""

    def test_no_findings_grade_a(self, tmp_path: Path) -> None:
        config = tmp_path / "mcp.json"
        config.write_text('{"mcpServers": {}}')
        with _patch_no_known_clients():
            result = run_scan(extra_paths=[config], skip_rug_pull=True)
        assert result.findings == []
        assert result.score is not None
        assert result.score.grade == "A"
        assert result.score.numeric_score == 100

    def test_zero_servers_found(self, tmp_path: Path) -> None:
        config = tmp_path / "mcp.json"
        config.write_text('{"mcpServers": {}}')
        with _patch_no_known_clients():
            result = run_scan(extra_paths=[config], skip_rug_pull=True)
        assert result.servers_found == 0

    def test_cli_exits_zero_for_clean_config(self, tmp_path: Path) -> None:
        config = tmp_path / "mcp.json"
        config.write_text('{"mcpServers": {}}')
        runner = CliRunner()
        with _patch_no_known_clients():
            result = runner.invoke(app, ["scan", "--path", str(config)])
        assert result.exit_code == 0


class TestHappyPathWithFindings:
    """Scanning a config with a plaintext HTTP server produces findings."""

    def test_http_server_produces_findings(self, tmp_path: Path) -> None:
        config = tmp_path / "mcp.json"
        config.write_text(
            '{"mcpServers": {"remote": {"url": "http://example.com/mcp"}}}'
        )
        with _patch_no_known_clients():
            result = run_scan(extra_paths=[config], skip_rug_pull=True)
        assert len(result.findings) > 0

    def test_http_server_score_has_deductions(self, tmp_path: Path) -> None:
        # Use a credential-exposure config to force findings that produce
        # deductions in the scan score.  sk- + 20 chars matches the OpenAI
        # key pattern (minimum length required by the regex).
        config = tmp_path / "mcp.json"
        import json as _json  # noqa: PLC0415

        cfg = {
            "mcpServers": {
                "srv": {
                    "command": "node",
                    "args": ["s.js"],
                    "env": {"OPENAI_API_KEY": "sk-" + "a" * 20},
                }
            }
        }
        config.write_text(_json.dumps(cfg))
        with _patch_no_known_clients():
            result = run_scan(extra_paths=[config], skip_rug_pull=True)
        assert result.score is not None
        # Deductions list must be non-empty (at least one finding contributed).
        assert len(result.score.deductions) > 0

    def test_cli_exits_one_when_findings_exist(self, tmp_path: Path) -> None:
        config = tmp_path / "mcp.json"
        config.write_text(
            '{"mcpServers": {"remote": {"url": "http://example.com/mcp"}}}'
        )
        runner = CliRunner()
        with _patch_no_known_clients():
            result = runner.invoke(app, ["scan", "--path", str(config)])
        assert result.exit_code == 1


# ── --baseline flag ─────────────────────────────────────────────────────────────


class TestBaselineFlag:
    """--baseline latest injects drift findings when the server list changes."""

    def test_baseline_latest_detects_added_server(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        storage = tmp_path / "baselines"
        monkeypatch.setattr("mcp_audit.baselines.manager._DEFAULT_STORAGE_DIR", storage)

        config = tmp_path / "mcp.json"
        config.write_text(
            '{"mcpServers": {"srv": {"command": "node", "args": ["s.js"]}}}'
        )

        runner = CliRunner()
        with _patch_no_known_clients():
            save_result = runner.invoke(
                app, ["baseline", "save", "--path", str(config)]
            )
        assert save_result.exit_code == 0, save_result.output

        # Add a new server — this should appear as drift.
        config.write_text(
            '{"mcpServers": {'
            '"srv": {"command": "node", "args": ["s.js"]},'
            '"new-srv": {"command": "python", "args": ["srv.py"]}'
            "}}"
        )

        with _patch_no_known_clients():
            scan_result = runner.invoke(
                app,
                [
                    "scan",
                    "--path",
                    str(config),
                    "--baseline",
                    "latest",
                    "--format",
                    "json",
                ],
            )

        assert scan_result.exit_code in (0, 1), scan_result.output
        data = json.loads(scan_result.output)
        drift_findings = [f for f in data["findings"] if f["analyzer"] == "baseline"]
        assert len(drift_findings) > 0


# ── --verify-hashes flag ────────────────────────────────────────────────────────


class TestVerifyHashesFlag:
    """verify_server_hashes is called iff --verify-hashes is set."""

    def _config_with_server(self, tmp_path: Path) -> Path:
        config = tmp_path / "mcp.json"
        config.write_text(
            '{"mcpServers": {"srv": {"command": "node", "args": ["s.js"]}}}'
        )
        return config

    def test_verify_hashes_called_when_flag_set(self, tmp_path: Path) -> None:
        config = self._config_with_server(tmp_path)
        runner = CliRunner()
        with (
            _patch_no_known_clients(),
            patch(
                "mcp_audit.attestation.verifier.verify_server_hashes",
                return_value=[],
            ) as mock_verify,
        ):
            runner.invoke(app, ["scan", "--path", str(config), "--verify-hashes"])
        mock_verify.assert_called_once()

    def test_verify_hashes_not_called_when_absent(self, tmp_path: Path) -> None:
        config = self._config_with_server(tmp_path)
        runner = CliRunner()
        with (
            _patch_no_known_clients(),
            patch(
                "mcp_audit.attestation.verifier.verify_server_hashes",
                return_value=[],
            ) as mock_verify,
        ):
            runner.invoke(app, ["scan", "--path", str(config)])
        mock_verify.assert_not_called()

    def test_scan_offline_and_verify_hashes_exits_2(self, tmp_path: Path) -> None:
        """--offline and --verify-hashes are mutually exclusive; must exit 2."""
        config = self._config_with_server(tmp_path)
        result = CliRunner().invoke(
            app,
            ["scan", "--path", str(config), "--offline", "--verify-hashes"],
        )
        assert result.exit_code == 2
        out = result.output.lower()
        assert "verify-hashes" in out or "offline" in out


# ── --sast flag ──────────────────────────────────────────────────────────────────


@dataclass
class _FakeSastResult:
    findings: list = field(default_factory=list)
    rules_run: int = 0
    files_scanned: int = 3
    semgrep_version: str | None = "1.0.0"
    error: str | None = None


class TestSastFlag:
    """run_semgrep is called iff --sast is passed and Pro is available."""

    def test_sast_called_when_flag_set_and_pro_available(self, tmp_path: Path) -> None:
        config = tmp_path / "mcp.json"
        config.write_text('{"mcpServers": {}}')
        src_dir = tmp_path / "src"
        src_dir.mkdir()

        runner = CliRunner()
        with (
            _patch_no_known_clients(),
            patch(
                "mcp_audit.sast.runner.run_semgrep",
                return_value=_FakeSastResult(),
            ) as mock_sast,
        ):
            runner.invoke(
                app,
                ["scan", "--path", str(config), "--sast", str(src_dir)],
            )
        mock_sast.assert_called_once()

    def test_sast_not_called_when_absent(self, tmp_path: Path) -> None:
        config = tmp_path / "mcp.json"
        config.write_text('{"mcpServers": {}}')
        runner = CliRunner()
        with (
            _patch_no_known_clients(),
            patch(
                "mcp_audit.sast.runner.run_semgrep",
                return_value=_FakeSastResult(),
            ) as mock_sast,
        ):
            runner.invoke(app, ["scan", "--path", str(config)])
        mock_sast.assert_not_called()

    def test_sast_findings_included_in_result(self, tmp_path: Path) -> None:
        config = tmp_path / "mcp.json"
        config.write_text('{"mcpServers": {}}')
        src_dir = tmp_path / "src"
        src_dir.mkdir()

        sast_finding = Finding(
            id="SAST-001",
            severity=Severity.HIGH,
            analyzer="sast",
            client="test",
            server="test-srv",
            title="Injection risk",
            description="desc",
            evidence="ev",
            remediation="fix",
        )
        runner = CliRunner()
        with (
            _patch_no_known_clients(),
            patch(
                "mcp_audit.sast.runner.run_semgrep",
                return_value=_FakeSastResult(findings=[sast_finding]),
            ),
            patch("mcp_audit.scanner._USER_RULES_DIR", tmp_path / "no-user-rules"),
        ):
            result = runner.invoke(
                app,
                [
                    "scan",
                    "--path",
                    str(config),
                    "--sast",
                    str(src_dir),
                    "--format",
                    "json",
                ],
            )
        assert result.exit_code in (0, 1), result.output
        # Console progress lines precede the JSON block — skip to the first '{'.
        json_start = result.output.index("{")
        data = json.loads(result.output[json_start:])
        sast_findings = [f for f in data["findings"] if f["analyzer"] == "sast"]
        assert len(sast_findings) == 1


# ── --include-extensions flag ───────────────────────────────────────────────────


class TestIncludeExtensionsFlag:
    """Extension analyzer is called iff --include-extensions is set and Pro."""

    def test_extensions_called_when_flag_set_and_pro_available(
        self, tmp_path: Path
    ) -> None:
        config = tmp_path / "mcp.json"
        config.write_text('{"mcpServers": {}}')
        runner = CliRunner()
        with (
            _patch_no_known_clients(),
            patch(
                "mcp_audit.extensions.discovery.discover_extensions",
                return_value=[],
            ) as mock_discover,
            patch(
                "mcp_audit.extensions.analyzer.analyze_extensions",
                return_value=[],
            ) as mock_analyze,
        ):
            runner.invoke(
                app,
                ["scan", "--path", str(config), "--include-extensions"],
            )
        mock_discover.assert_called_once()
        mock_analyze.assert_called_once()

    def test_extensions_not_called_when_absent(self, tmp_path: Path) -> None:
        config = tmp_path / "mcp.json"
        config.write_text('{"mcpServers": {}}')
        runner = CliRunner()
        with (
            _patch_no_known_clients(),
            patch(
                "mcp_audit.extensions.discovery.discover_extensions",
                return_value=[],
            ) as mock_discover,
        ):
            runner.invoke(app, ["scan", "--path", str(config)])
        mock_discover.assert_not_called()


# ── --policy flag ───────────────────────────────────────────────────────────────


class TestPolicyFlag:
    """Governance findings appear in the result when --policy is set."""

    def test_governance_findings_appear(self, tmp_path: Path) -> None:
        # Config with one server not on the approved allowlist.
        config = tmp_path / "mcp.json"
        config.write_text(
            '{"mcpServers": {"unapproved-srv": {"command": "node", "args": ["s.js"]}}}'
        )

        # Policy that only allows servers named "approved-srv".
        policy_file = tmp_path / "policy.yml"
        policy_file.write_text(
            "version: 1\n"
            "name: test-policy\n"
            "approved_servers:\n"
            "  mode: allowlist\n"
            "  entries:\n"
            "    - name: approved-srv\n"
            "  violation_severity: high\n"
        )

        runner = CliRunner()
        with _patch_no_known_clients():
            result = runner.invoke(
                app,
                [
                    "scan",
                    "--path",
                    str(config),
                    "--policy",
                    str(policy_file),
                    "--format",
                    "json",
                ],
            )

        assert result.exit_code in (0, 1), result.output
        data = json.loads(result.output)
        gov_findings = [f for f in data["findings"] if f["analyzer"] == "governance"]
        assert len(gov_findings) > 0


# ── --no-score flag ─────────────────────────────────────────────────────────────


class TestNoScoreFlag:
    """--no-score nulls the score field before any formatter sees it."""

    def test_no_score_suppresses_score_in_json_output(self, tmp_path: Path) -> None:
        config = tmp_path / "mcp.json"
        config.write_text('{"mcpServers": {}}')
        runner = CliRunner()
        with _patch_no_known_clients():
            result = runner.invoke(
                app,
                ["scan", "--path", str(config), "--no-score", "--format", "json"],
            )
        data = json.loads(result.output)
        assert data["score"] is None

    def test_score_present_without_flag(self, tmp_path: Path) -> None:
        config = tmp_path / "mcp.json"
        config.write_text('{"mcpServers": {}}')
        runner = CliRunner()
        with _patch_no_known_clients():
            result = runner.invoke(
                app,
                ["scan", "--path", str(config), "--format", "json"],
            )
        data = json.loads(result.output)
        assert data["score"] is not None
        assert data["score"]["grade"] == "A"


# ── --severity-threshold flag ───────────────────────────────────────────────────


class TestSeverityThresholdFlag:
    """Only findings at or above the threshold appear in filtered output."""

    def test_threshold_high_filters_out_medium_and_low(self, tmp_path: Path) -> None:
        config = tmp_path / "mcp.json"
        config.write_text(
            '{"mcpServers": {"srv": {"command": "node", "args": ["s.js"]}}}'
        )

        # Inject findings at three different severity levels via a custom analyzer.
        class MultiSeverityAnalyzer(BaseAnalyzer):
            @property
            def name(self) -> str:
                return "multi"

            @property
            def description(self) -> str:
                return "Produces findings at multiple severities"

            def analyze(self, server: ServerConfig) -> list[Finding]:
                return [
                    Finding(
                        id=f"TST-{sev.value}",
                        severity=sev,
                        analyzer="multi",
                        client=server.client,
                        server=server.name,
                        title=f"{sev.value} issue",
                        description="desc",
                        evidence="ev",
                        remediation="fix",
                    )
                    for sev in (Severity.HIGH, Severity.MEDIUM, Severity.LOW)
                ]

        with _patch_no_known_clients():
            result = run_scan(
                extra_paths=[config],
                analyzers=[MultiSeverityAnalyzer()],
                skip_rug_pull=True,
            )

        # Verify unfiltered scan has all three severities.
        severities = {f.severity for f in result.findings}
        assert Severity.HIGH in severities
        assert Severity.MEDIUM in severities
        assert Severity.LOW in severities

        # Apply threshold via CLI and check JSON output.
        runner = CliRunner()

        class _PatchedAnalyzer(MultiSeverityAnalyzer):
            pass

        with (
            _patch_no_known_clients(),
            patch(
                "mcp_audit.scanner.get_default_analyzers",
                return_value=[_PatchedAnalyzer()],
            ),
        ):
            cli_result = runner.invoke(
                app,
                [
                    "scan",
                    "--path",
                    str(config),
                    "--severity-threshold",
                    "HIGH",
                    "--format",
                    "json",
                ],
            )
        data = json.loads(cli_result.output)
        returned_severities = {f["severity"] for f in data["findings"]}
        assert "MEDIUM" not in returned_severities
        assert "LOW" not in returned_severities


# ── --path skips auto-discovery ───────────────────────────────────────────────


class TestExplicitPathSkipsAutoDiscovery:
    """scan --path <file> must scan only that file (clients_scanned == 1)."""

    def test_explicit_path_does_not_include_auto_discovery(
        self, tmp_path: Path
    ) -> None:
        """JSON output must report clients_scanned == 1, not 2+."""
        config = tmp_path / "mcp.json"
        config.write_text('{"mcpServers": {}}')
        runner = CliRunner()
        # Do NOT patch _get_client_specs — auto-discovery must be skipped by
        # the fix itself, not by removing system clients from the spec list.
        result = runner.invoke(
            app,
            ["scan", "--path", str(config), "--format", "json"],
        )
        assert result.exit_code in (0, 1), (
            f"unexpected exit code {result.exit_code}: {result.output!r}"
        )
        data = json.loads(result.output)
        assert data["clients_scanned"] == 1, (
            f"Expected clients_scanned=1, got {data['clients_scanned']}. "
            "Auto-discovery should be skipped when --path is explicit."
        )

    def test_no_path_still_runs_auto_discovery(self, tmp_path: Path) -> None:
        """Without --path, auto-discovery still runs (existing behaviour)."""
        config = tmp_path / "mcp.json"
        config.write_text('{"mcpServers": {}}')
        with _patch_no_known_clients():
            result = run_scan(skip_rug_pull=True)
        # With no known clients patched out, result has 0 clients (no system configs).
        assert result.clients_scanned == 0


# ── --offline-registry flag ─────────────────────────────────────────────────────


class TestOfflineRegistryFlag:
    """--offline-registry constructs SupplyChainAnalyzer with offline_registry=True."""

    def test_offline_registry_creates_offline_supply_chain_analyzer(
        self, tmp_path: Path
    ) -> None:
        config = tmp_path / "mcp.json"
        config.write_text('{"mcpServers": {}}')

        captured: list[dict] = []

        original_init = SupplyChainAnalyzer.__init__

        def _capturing_init(self: SupplyChainAnalyzer, **kwargs: object) -> None:
            captured.append(dict(kwargs))
            original_init(self, **kwargs)  # type: ignore[arg-type]

        runner = CliRunner()
        with (
            _patch_no_known_clients(),
            patch.object(SupplyChainAnalyzer, "__init__", _capturing_init),
        ):
            runner.invoke(
                app,
                ["scan", "--path", str(config), "--offline-registry"],
            )

        # At least one SupplyChainAnalyzer must have been created with offline=True.
        assert any(kw.get("offline_registry") is True for kw in captured)


# ── Empty config directory ──────────────────────────────────────────────────────


class TestEmptyConfigDirectory:
    """Scanning when discovery finds no configs exits cleanly with zero findings."""

    def test_no_configs_found_zero_findings(self, tmp_path: Path) -> None:
        config = tmp_path / "mcp.json"
        config.write_text('{"mcpServers": {}}')
        # Override discovery so nothing is returned.
        with (
            patch("mcp_audit.discovery._get_client_specs", return_value=[]),
            patch("mcp_audit.scanner.discover_configs", return_value=[]),
        ):
            result = run_scan(skip_rug_pull=True)
        assert result.findings == []
        assert result.servers_found == 0
        assert result.score is not None
        assert result.score.grade == "A"

    def test_cli_exits_zero_when_no_configs_found(self) -> None:
        runner = CliRunner()
        with patch("mcp_audit.discovery._get_client_specs", return_value=[]):
            result = runner.invoke(app, ["scan"])
        assert result.exit_code == 0


# ── --rules-dir flag ────────────────────────────────────────────────────────────


class TestRulesDirFlag:
    """Custom rules from --rules-dir are loaded and their findings appear in output."""

    def _write_custom_rule(self, rules_dir: Path) -> None:
        rule = (
            "id: CUSTOM-001\n"
            "name: Test custom rule\n"
            "description: Flags servers named 'flagged-server'\n"
            "severity: HIGH\n"
            "category: test\n"
            "match:\n"
            "  field: server_name\n"
            "  pattern: '^flagged-server$'\n"
            "  type: regex\n"
            "message: \"Custom rule matched server '{server_name}'\"\n"
            "tags:\n"
            "  - test\n"
            "enabled: true\n"
        )
        (rules_dir / "custom.yml").write_text(rule)

    def test_custom_rule_finding_appears_in_result(self, tmp_path: Path) -> None:
        config = tmp_path / "mcp.json"
        config.write_text(
            '{"mcpServers": {"flagged-server": {"command": "node", "args": ["s.js"]}}}'
        )
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        self._write_custom_rule(rules_dir)

        with _patch_no_known_clients():
            result = run_scan(
                extra_paths=[config],
                extra_rules_dirs=[rules_dir],
                skip_rug_pull=True,
            )

        custom_findings = [f for f in result.findings if f.id == "CUSTOM-001"]
        assert len(custom_findings) >= 1

    def test_rules_dir_cli_loads_rules_when_pro(self, tmp_path: Path) -> None:
        """--rules-dir loads rules and their findings appear in JSON output."""
        config = tmp_path / "mcp.json"
        config.write_text(
            '{"mcpServers": {"flagged-server": {"command": "node", "args": ["s.js"]}}}'
        )
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        self._write_custom_rule(rules_dir)

        runner = CliRunner()
        with (
            _patch_no_known_clients(),
            patch("mcp_audit.scanner._USER_RULES_DIR", tmp_path / "no-rules"),
        ):
            result = runner.invoke(
                app,
                [
                    "scan",
                    "--path",
                    str(config),
                    "--rules-dir",
                    str(rules_dir),
                    "--format",
                    "json",
                ],
            )
        data = json.loads(result.output)
        custom_findings = [f for f in data["findings"] if f["id"] == "CUSTOM-001"]
        assert len(custom_findings) >= 1


# ── Scan pipeline order ─────────────────────────────────────────────────────────


class TestScanPipelineOrder:
    """Analyzers run before rule engine; rule engine runs before scoring."""

    def test_analyzers_run_before_rule_engine(self, tmp_path: Path) -> None:
        config = tmp_path / "mcp.json"
        config.write_text(
            '{"mcpServers": {"srv": {"command": "node", "args": ["s.js"]}}}'
        )

        call_log: list[str] = []

        class LoggingAnalyzer(BaseAnalyzer):
            @property
            def name(self) -> str:
                return "logger"

            @property
            def description(self) -> str:
                return "Records call order"

            def analyze(self, server: ServerConfig) -> list[Finding]:
                call_log.append("analyzer")
                return []

        original_run_rules = _run_rules_engine

        def _logging_rules(
            servers: list,
            extra: list | None,
            analyzers: list | None = None,
        ) -> list[Finding]:
            call_log.append("rules_engine")
            return original_run_rules(servers, extra, analyzers=analyzers)

        with (
            _patch_no_known_clients(),
            patch(
                "mcp_audit.scanner._run_rules_engine",
                side_effect=_logging_rules,
            ),
        ):
            run_scan(
                extra_paths=[config],
                analyzers=[LoggingAnalyzer()],
                skip_rug_pull=True,
            )

        assert "analyzer" in call_log
        assert "rules_engine" in call_log
        # Analyzer must appear before rule engine in the log.
        assert call_log.index("analyzer") < call_log.index("rules_engine")

    def test_scoring_attaches_after_rule_engine(self, tmp_path: Path) -> None:
        """result.score is populated (scoring ran) after the full pipeline."""
        config = tmp_path / "mcp.json"
        config.write_text('{"mcpServers": {}}')
        with _patch_no_known_clients():
            result = run_scan(extra_paths=[config], skip_rug_pull=True)
        assert result.score is not None


# ── --asset-prefix flag ─────────────────────────────────────────────────────────


class TestAssetPrefixFlag:
    """--asset-prefix is forwarded to SARIF and nucleus formatters."""

    def test_asset_prefix_appears_in_sarif_output(self, tmp_path: Path) -> None:
        config = tmp_path / "mcp.json"
        config.write_text('{"mcpServers": {}}')

        runner = CliRunner()
        with _patch_no_known_clients():
            result = runner.invoke(
                app,
                [
                    "scan",
                    "--path",
                    str(config),
                    "--format",
                    "sarif",
                    "--asset-prefix",
                    "prod-001",
                ],
            )

        assert "prod-001" in result.output

    def test_asset_prefix_appears_in_json_machine_info(self, tmp_path: Path) -> None:
        """--asset-prefix sets machine_info.asset_id in JSON output (F2)."""
        import json as _json  # noqa: PLC0415

        config = tmp_path / "mcp.json"
        config.write_text('{"mcpServers": {}}')

        runner = CliRunner()
        with _patch_no_known_clients():
            result = runner.invoke(
                app,
                [
                    "scan",
                    "--path",
                    str(config),
                    "--format",
                    "json",
                    "--asset-prefix",
                    "fleet-01",
                ],
            )

        assert result.exit_code == 0, result.output
        data = _json.loads(result.output)
        assert data["machine_info"]["asset_id"] == "fleet-01", (
            "machine_info.asset_id must equal --asset-prefix value"
        )

    def test_json_output_uses_machine_info_key(self, tmp_path: Path) -> None:
        """JSON output top-level key must be 'machine_info', not 'machine' (F7)."""
        import json as _json  # noqa: PLC0415

        config = tmp_path / "mcp.json"
        config.write_text('{"mcpServers": {}}')

        runner = CliRunner()
        with _patch_no_known_clients():
            result = runner.invoke(
                app,
                ["scan", "--path", str(config), "--format", "json"],
            )

        assert result.exit_code == 0, result.output
        data = _json.loads(result.output)
        assert "machine_info" in data, (
            "top-level 'machine_info' key missing from JSON output"
        )
        assert "machine" not in data, (
            "legacy 'machine' key must not appear in JSON output"
        )

    def test_json_output_score_uses_numeric_key(self, tmp_path: Path) -> None:
        """JSON output score key must be 'numeric', not 'numeric_score' (F7)."""
        import json as _json  # noqa: PLC0415

        config = tmp_path / "mcp.json"
        config.write_text('{"mcpServers": {"srv": {"command": "node", "args": []}}}')

        runner = CliRunner()
        with _patch_no_known_clients():
            result = runner.invoke(
                app,
                ["scan", "--path", str(config), "--format", "json"],
            )

        assert result.exit_code in (0, 1), result.output
        data = _json.loads(result.output)
        assert "score" in data
        assert "numeric" in data["score"], "score.numeric key missing from JSON output"
        assert "numeric_score" not in data["score"], (
            "legacy score.numeric_score key must not appear in JSON output"
        )


# ── run_scan_async (async code path) ───────────────────────────────────────────


class TestRunScanAsync:
    """run_scan_async exercises the same pipeline as run_scan via asyncio."""

    async def test_basic_async_scan_returns_result(self, tmp_path: Path) -> None:
        config = tmp_path / "mcp.json"
        config.write_text('{"mcpServers": {}}')
        with _patch_no_known_clients():
            result = await run_scan_async(
                extra_paths=[config],
                skip_rug_pull=True,
            )
        assert isinstance(result, ScanResult)
        assert result.score is not None
        assert result.score.grade == "A"

    async def test_async_scan_with_server_runs_analyzers(self, tmp_path: Path) -> None:
        """Per-server analyzer loop in run_scan_async executes when servers exist."""
        config = tmp_path / "mcp.json"
        config.write_text(
            '{"mcpServers": {"srv": {"command": "node", "args": ["s.js"]}}}'
        )
        with _patch_no_known_clients():
            result = await run_scan_async(
                extra_paths=[config],
                skip_rug_pull=True,
            )
        assert result.servers_found == 1
        assert result.score is not None

    async def test_async_scan_with_rug_pull(self, tmp_path: Path) -> None:
        """Rug-pull block executes when skip_rug_pull=False."""
        config = tmp_path / "mcp.json"
        config.write_text(
            '{"mcpServers": {"srv": {"command": "node", "args": ["s.js"]}}}'
        )
        state = tmp_path / "state.json"
        with _patch_no_known_clients():
            result = await run_scan_async(
                extra_paths=[config],
                state_path=state,
                skip_rug_pull=False,
            )
        assert isinstance(result, ScanResult)

    async def test_async_scan_parse_error_recorded(self, tmp_path: Path) -> None:
        """ValueError from parse_config is recorded in result.errors (not raised)."""
        config = tmp_path / "mcp.json"
        config.write_text('{"mcpServers": {}}')
        with (
            _patch_no_known_clients(),
            patch(
                "mcp_audit.scanner.parse_config",
                side_effect=ValueError("bad config"),
            ),
        ):
            result = await run_scan_async(
                extra_paths=[config],
                skip_rug_pull=True,
            )
        assert any("bad config" in e for e in result.errors)

    async def test_async_toxic_flow_exception_recorded(self, tmp_path: Path) -> None:
        config = tmp_path / "mcp.json"
        config.write_text('{"mcpServers": {}}')
        with (
            _patch_no_known_clients(),
            patch(
                "mcp_audit.analyzers.toxic_flow.ToxicFlowAnalyzer.analyze_all",
                side_effect=RuntimeError("toxic async boom"),
            ),
        ):
            result = await run_scan_async(
                extra_paths=[config],
                analyzers=[],
                skip_rug_pull=True,
            )
        assert any("toxic_flow" in e for e in result.errors)

    async def test_async_attack_paths_exception_recorded(self, tmp_path: Path) -> None:
        config = tmp_path / "mcp.json"
        config.write_text('{"mcpServers": {}}')
        with (
            _patch_no_known_clients(),
            patch(
                "mcp_audit.scanner.summarize_attack_paths",
                side_effect=RuntimeError("attack async boom"),
            ),
        ):
            result = await run_scan_async(
                extra_paths=[config],
                analyzers=[],
                skip_rug_pull=True,
            )
        assert any("attack_paths" in e for e in result.errors)

    async def test_async_rules_engine_exception_recorded(self, tmp_path: Path) -> None:
        config = tmp_path / "mcp.json"
        config.write_text('{"mcpServers": {}}')
        with (
            _patch_no_known_clients(),
            patch(
                "mcp_audit.scanner._run_rules_engine",
                side_effect=RuntimeError("rules async boom"),
            ),
        ):
            result = await run_scan_async(
                extra_paths=[config],
                analyzers=[],
                skip_rug_pull=True,
            )
        assert any("rules_engine" in e for e in result.errors)

    async def test_async_scan_with_finding_sets_finding_path(
        self, tmp_path: Path
    ) -> None:
        """Findings produced in run_scan_async have finding_path set (line 206)."""
        import json as _json  # noqa: PLC0415

        config = tmp_path / "mcp.json"
        cfg = {
            "mcpServers": {
                "srv": {
                    "command": "node",
                    "args": ["s.js"],
                    "env": {"OPENAI_API_KEY": "sk-" + "a" * 20},
                }
            }
        }
        config.write_text(_json.dumps(cfg))
        with _patch_no_known_clients():
            result = await run_scan_async(
                extra_paths=[config],
                skip_rug_pull=True,
            )
        path_set_findings = [f for f in result.findings if f.finding_path is not None]
        assert len(path_set_findings) > 0

    async def test_async_analyzer_crash_produces_finding(self, tmp_path: Path) -> None:
        """Analyzer crash in run_scan_async emits SCAN-ERR finding (lines 208-209)."""
        config = tmp_path / "mcp.json"
        config.write_text(
            '{"mcpServers": {"srv": {"command": "node", "args": ["s.js"]}}}'
        )

        class CrashingAnalyzer(BaseAnalyzer):
            @property
            def name(self) -> str:
                return "async-crasher"

            @property
            def description(self) -> str:
                return "Always crashes"

            def analyze(self, server: ServerConfig) -> list[Finding]:
                raise RuntimeError("async crash")

        with _patch_no_known_clients():
            result = await run_scan_async(
                extra_paths=[config],
                analyzers=[CrashingAnalyzer()],
                skip_rug_pull=True,
            )
        crash_findings = [f for f in result.findings if f.id == "SCAN-ERR"]
        assert len(crash_findings) == 1

    async def test_async_rug_pull_exception_recorded(self, tmp_path: Path) -> None:
        """rug-pull exception handler in run_scan_async appends to errors."""
        config = tmp_path / "mcp.json"
        config.write_text('{"mcpServers": {}}')
        with (
            _patch_no_known_clients(),
            patch(
                "mcp_audit.analyzers.rug_pull.RugPullAnalyzer.analyze_all",
                side_effect=RuntimeError("async rug_pull boom"),
            ),
        ):
            result = await run_scan_async(
                extra_paths=[config],
                analyzers=[],
                skip_rug_pull=False,
                state_path=tmp_path / "state.json",
            )
        assert any("rug_pull" in e for e in result.errors)

    async def test_async_offline_connect_raises(self) -> None:
        with pytest.raises(ValueError, match="Cannot use --connect with --offline"):
            await run_scan_async(offline=True, connect=True)

    def test_run_scan_connect_delegates_to_asyncio_run(self, tmp_path: Path) -> None:
        """run_scan(connect=True) calls asyncio.run(run_scan_async(...))."""
        config = tmp_path / "mcp.json"
        config.write_text('{"mcpServers": {}}')

        fake_result = ScanResult()
        fake_result.score = None  # will be set after scan

        async def _fake_async(**_kwargs: object) -> ScanResult:
            return fake_result

        with (
            _patch_no_known_clients(),
            patch("mcp_audit.scanner.run_scan_async", side_effect=_fake_async),
        ):
            result = run_scan(
                connect=True,
                extra_paths=[config],
                skip_rug_pull=True,
            )

        assert result is fake_result


# ── Exception handlers in run_scan ─────────────────────────────────────────────


class TestRunScanExceptionHandlers:
    """Exceptions from sub-analyzers are recorded in result.errors, not re-raised."""

    def test_rug_pull_exception_recorded_in_errors(self, tmp_path: Path) -> None:
        config = tmp_path / "mcp.json"
        config.write_text(
            '{"mcpServers": {"srv": {"command": "node", "args": ["s.js"]}}}'
        )
        with (
            _patch_no_known_clients(),
            patch(
                "mcp_audit.analyzers.rug_pull.RugPullAnalyzer.analyze_all",
                side_effect=RuntimeError("rug_pull exploded"),
            ),
        ):
            result = run_scan(extra_paths=[config], analyzers=[])
        assert any("rug_pull" in e for e in result.errors)
        assert any("rug_pull exploded" in e for e in result.errors)

    def test_toxic_flow_exception_recorded_in_errors(self, tmp_path: Path) -> None:
        config = tmp_path / "mcp.json"
        config.write_text(
            '{"mcpServers": {"srv": {"command": "node", "args": ["s.js"]}}}'
        )
        with (
            _patch_no_known_clients(),
            patch(
                "mcp_audit.analyzers.toxic_flow.ToxicFlowAnalyzer.analyze_all",
                side_effect=RuntimeError("toxic_flow exploded"),
            ),
        ):
            result = run_scan(extra_paths=[config], analyzers=[], skip_rug_pull=True)
        assert any("toxic_flow" in e for e in result.errors)

    def test_attack_paths_exception_recorded_in_errors(self, tmp_path: Path) -> None:
        config = tmp_path / "mcp.json"
        config.write_text(
            '{"mcpServers": {"srv": {"command": "node", "args": ["s.js"]}}}'
        )
        with (
            _patch_no_known_clients(),
            patch(
                "mcp_audit.scanner.summarize_attack_paths",
                side_effect=RuntimeError("attack_paths exploded"),
            ),
        ):
            result = run_scan(extra_paths=[config], analyzers=[], skip_rug_pull=True)
        assert any("attack_paths" in e for e in result.errors)

    def test_rules_engine_exception_recorded_in_errors(self, tmp_path: Path) -> None:
        config = tmp_path / "mcp.json"
        config.write_text(
            '{"mcpServers": {"srv": {"command": "node", "args": ["s.js"]}}}'
        )
        with (
            _patch_no_known_clients(),
            patch(
                "mcp_audit.scanner._run_rules_engine",
                side_effect=RuntimeError("rules_engine exploded"),
            ),
        ):
            result = run_scan(extra_paths=[config], analyzers=[], skip_rug_pull=True)
        assert any("rules_engine" in e for e in result.errors)


# ── _run_rules_engine with extra_rules_dirs ─────────────────────────────────────


class TestRunRulesEngineWithExtraDir:
    """_run_rules_engine merges custom rules with community rules."""

    def test_custom_rule_in_extra_dir_produces_finding(self, tmp_path: Path) -> None:
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "custom.yml").write_text(
            "id: CUSTOM-EXTRA-001\n"
            "name: Extra rule test\n"
            "description: Flags any server with command 'evil'\n"
            "severity: HIGH\n"
            "category: test\n"
            "match:\n"
            "  field: server_name\n"
            "  pattern: '^evil-srv$'\n"
            "  type: regex\n"
            "message: \"Evil server detected: '{server_name}'\"\n"
            "tags: []\n"
            "enabled: true\n"
        )

        server = ServerConfig(
            name="evil-srv",
            client="test",
            config_path=tmp_path / "mcp.json",
            transport=TransportType.STDIO,
            command="evil",
            args=[],
            raw={"command": "evil"},
        )

        findings = _run_rules_engine([server], extra_rules_dirs=[rules_dir])
        custom = [f for f in findings if f.id == "CUSTOM-EXTRA-001"]
        assert len(custom) >= 1

    def test_no_extra_dirs_only_community_rules_run(self, tmp_path: Path) -> None:
        """With extra_rules_dirs=None only community rules execute."""
        server = ServerConfig(
            name="safe-srv",
            client="test",
            config_path=tmp_path / "mcp.json",
            transport=TransportType.STDIO,
            command="node",
            args=["server.js"],
            raw={"command": "node"},
        )
        findings = _run_rules_engine([server], extra_rules_dirs=None)
        # Community rules run — check no CUSTOM-EXTRA finding appears.
        custom = [f for f in findings if f.id.startswith("CUSTOM-EXTRA")]
        assert custom == []


# ── _run_static_pipeline (canonical pipeline helper) ───────────────────────────


class _CountingAnalyzer(BaseAnalyzer):
    """Test analyzer that emits exactly one MEDIUM finding per server."""

    @property
    def name(self) -> str:
        return "counting"

    @property
    def description(self) -> str:
        return "emits one finding per server for pipeline tests"

    def analyze(self, server: ServerConfig) -> list[Finding]:
        return [
            Finding(
                id="COUNT-001",
                severity=Severity.MEDIUM,
                analyzer=self.name,
                client=server.client,
                server=server.name,
                title=f"counted {server.name}",
                description="pipeline ordering test finding",
                evidence="n/a",
                remediation="n/a",
            )
        ]


class TestRunStaticPipeline:
    """_run_static_pipeline is the canonical pipeline — both scan paths delegate."""

    def test_static_pipeline_documents_order(self, tmp_path: Path) -> None:
        """Pipeline runs analyzers, skips rug-pull, and populates score.

        Confirms the documented pipeline order with a minimal fixture:
        two servers × one analyzer = two COUNT-001 findings, plus a populated
        ``score`` field proving ``calculate_score`` ran, plus an
        ``attack_path_summary`` proving ``summarize_attack_paths`` ran.
        Passing ``analyzers=[_CountingAnalyzer()]`` exercises the loop without
        pulling in registry-backed analyzers.
        """
        server_a = _make_server("srv-a")
        server_b = _make_server("srv-b")

        result = ScanResult()
        result.servers_found = 2
        result.servers = [server_a, server_b]

        returned = _run_static_pipeline(
            result=result,
            all_servers=[server_a, server_b],
            configs=[],
            analyzers=[_CountingAnalyzer()],
            skip_rug_pull=True,
            state_path=tmp_path / "state.json",
            extra_rules_dirs=None,
        )

        assert returned is result
        count_findings = [f for f in result.findings if f.id == "COUNT-001"]
        assert len(count_findings) == 2
        for f in count_findings:
            assert f.finding_path == str(server_a.config_path)
        assert result.score is not None
        assert result.attack_path_summary is not None
        # No SupplyChainAnalyzer in the list → no registry_stats to attach.
        assert result.registry_stats is None

    def test_run_scan_delegates_to_static_pipeline(self, tmp_path: Path) -> None:
        """run_scan must pass its discovered servers/configs through the helper."""
        config = tmp_path / "mcp.json"
        config.write_text(
            '{"mcpServers": {"delegate-srv": {"command": "node", "args": ["s.js"]}}}'
        )

        sentinel = ScanResult()
        sentinel.score = None

        def _fake_pipeline(
            *,
            result: ScanResult,
            all_servers: list[ServerConfig],
            configs: list,  # noqa: ARG001
            analyzers: list[BaseAnalyzer],
            skip_rug_pull: bool,  # noqa: ARG001
            state_path: Path | None,  # noqa: ARG001
            extra_rules_dirs: list[Path] | None,  # noqa: ARG001
            scoring_weights=None,  # noqa: ARG001
            scoring_weights_source: str = "default",  # noqa: ARG001
        ) -> ScanResult:
            sentinel.servers = all_servers
            # Stash the analyzer list on the sentinel so the test can assert.
            sentinel.errors.append(f"analyzers={len(analyzers)}")
            sentinel.errors.append(f"servers={[s.name for s in all_servers]}")
            return sentinel

        with (
            _patch_no_known_clients(),
            patch("mcp_audit.scanner._run_static_pipeline", side_effect=_fake_pipeline),
        ):
            result = run_scan(extra_paths=[config], skip_rug_pull=True)

        assert result is sentinel
        assert any(e == "servers=['delegate-srv']" for e in sentinel.errors), (
            f"run_scan did not delegate with parsed servers: {sentinel.errors}"
        )
        # Default analyzer list = 5 (poisoning, credentials, transport, supply,
        # config_hygiene).
        assert any(e == "analyzers=5" for e in sentinel.errors)

    async def test_run_scan_async_delegates_to_static_pipeline(
        self, tmp_path: Path
    ) -> None:
        """run_scan_async must also funnel through _run_static_pipeline.

        Additionally verifies that _run_static_pipeline runs *after* any live
        enumeration (connect=False here, so the call is unconditional) and that
        the result it returns is the same object returned by run_scan_async.
        """
        config = tmp_path / "mcp.json"
        config.write_text(
            '{"mcpServers": {"async-srv": {"command": "node", "args": ["s.js"]}}}'
        )

        sentinel = ScanResult()

        def _fake_pipeline(
            *,
            result: ScanResult,  # noqa: ARG001
            all_servers: list[ServerConfig],
            configs: list,  # noqa: ARG001
            analyzers: list[BaseAnalyzer],  # noqa: ARG001
            skip_rug_pull: bool,  # noqa: ARG001
            state_path: Path | None,  # noqa: ARG001
            extra_rules_dirs: list[Path] | None,  # noqa: ARG001
            scoring_weights=None,  # noqa: ARG001
            scoring_weights_source: str = "default",  # noqa: ARG001
        ) -> ScanResult:
            sentinel.errors.append(f"servers={[s.name for s in all_servers]}")
            return sentinel

        with (
            _patch_no_known_clients(),
            patch("mcp_audit.scanner._run_static_pipeline", side_effect=_fake_pipeline),
        ):
            result = await run_scan_async(extra_paths=[config], skip_rug_pull=True)

        assert result is sentinel
        assert any(e == "servers=['async-srv']" for e in sentinel.errors)


# ── TestCustomScoringWeightsPipeline ──────────────────────────────────────────


class TestCustomScoringWeightsPipeline:
    """Scoring weights are threaded from run_scan into _run_static_pipeline."""

    def test_custom_weights_wired_through_pipeline(self, tmp_path: Path) -> None:
        """Pipeline with custom weights produces the correct weights_source."""
        from mcp_audit.governance.models import ScoringDeductions, ScoringWeights
        from mcp_audit.scanner import _run_static_pipeline

        server = _make_server("weights-test")
        result = ScanResult()
        result.servers = [server]
        result.servers_found = 1

        weights = ScoringWeights(deductions=ScoringDeductions(CRITICAL=-40))

        returned = _run_static_pipeline(
            result=result,
            all_servers=[server],
            configs=[],
            analyzers=[],
            skip_rug_pull=True,
            state_path=tmp_path / "state.json",
            extra_rules_dirs=None,
            scoring_weights=weights,
            scoring_weights_source="policy:/tmp/test-policy.yml",
        )

        assert returned.score is not None
        assert returned.score.weights_source == "policy:/tmp/test-policy.yml"

    def test_custom_critical_weight_lowers_score(self, tmp_path: Path) -> None:
        """A heavier CRITICAL deduction must produce a strictly lower numeric score."""
        from mcp_audit.analyzers.base import BaseAnalyzer
        from mcp_audit.governance.models import ScoringDeductions, ScoringWeights
        from mcp_audit.scanner import _run_static_pipeline

        class _CriticalFindingAnalyzer(BaseAnalyzer):
            name = "test-crit"
            description = "Injects one CRITICAL finding for testing."

            def analyze(self, server: ServerConfig) -> list[Finding]:
                return [
                    Finding(
                        id="CRIT-TEST",
                        severity=Severity.CRITICAL,
                        analyzer=self.name,
                        client=server.client,
                        server=server.name,
                        title="Critical test",
                        description="desc",
                        evidence="ev",
                        remediation="fix",
                    )
                ]

        server = _make_server("crit-server")

        def _run(weights=None, source="default") -> ScanResult:
            r = ScanResult()
            r.servers = [server]
            r.servers_found = 1
            return _run_static_pipeline(
                result=r,
                all_servers=[server],
                configs=[],
                analyzers=[_CriticalFindingAnalyzer()],
                skip_rug_pull=True,
                state_path=tmp_path / "state.json",
                extra_rules_dirs=None,
                scoring_weights=weights,
                scoring_weights_source=source,
            )

        default_result = _run()
        custom_result = _run(
            weights=ScoringWeights(deductions=ScoringDeductions(CRITICAL=-40)),
            source="policy:/tmp/p.yml",
        )

        assert default_result.score is not None
        assert custom_result.score is not None
        assert custom_result.score.numeric_score < default_result.score.numeric_score
        assert custom_result.score.weights_source == "policy:/tmp/p.yml"

    def test_default_weights_source_is_default(self, tmp_path: Path) -> None:
        """Without custom weights, weights_source must be 'default'."""
        from mcp_audit.scanner import _run_static_pipeline

        server = _make_server("default-weights")
        result = ScanResult()
        result.servers = [server]

        returned = _run_static_pipeline(
            result=result,
            all_servers=[server],
            configs=[],
            analyzers=[],
            skip_rug_pull=True,
            state_path=tmp_path / "state.json",
            extra_rules_dirs=None,
        )

        assert returned.score is not None
        assert returned.score.weights_source == "default"
