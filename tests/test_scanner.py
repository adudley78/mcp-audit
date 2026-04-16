"""Tests for mcp_audit.scanner — orchestration logic."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from mcp_audit.analyzers.base import BaseAnalyzer
from mcp_audit.analyzers.supply_chain import SupplyChainAnalyzer
from mcp_audit.models import (
    Finding,
    RegistryStats,
    ServerConfig,
    Severity,
    TransportType,
)
from mcp_audit.scanner import run_scan


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
        from unittest.mock import MagicMock  # noqa: PLC0415

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
