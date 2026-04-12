"""Tests for mcp_audit.scanner — orchestration logic."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from mcp_audit.analyzers.base import BaseAnalyzer
from mcp_audit.models import Finding, ServerConfig, Severity, TransportType
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
    return patch(
        "mcp_audit.discovery._get_client_specs", return_value=[]
    )


class TestOfflineConnectConflict:
    """V-03: --offline --connect must raise, not silently proceed."""

    def test_offline_and_connect_raises_value_error(self) -> None:
        with pytest.raises(
            ValueError, match="Cannot use --connect with --offline"
        ):
            run_scan(offline=True, connect=True)

    def test_offline_without_connect_succeeds(
        self, tmp_path: Path
    ) -> None:
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

    def test_crashing_analyzer_emits_finding(
        self, tmp_path: Path
    ) -> None:
        config_file = tmp_path / "test.json"
        config_file.write_text(
            '{"mcpServers": {"srv": {"command": "node",'
            ' "args": ["s.js"]}}}'
        )

        class CrashingAnalyzer(BaseAnalyzer):
            @property
            def name(self) -> str:
                return "crasher"

            @property
            def description(self) -> str:
                return "Always crashes"

            def analyze(
                self, server: ServerConfig
            ) -> list[Finding]:
                raise RuntimeError("simulated crash")

        with _patch_no_known_clients():
            result = run_scan(
                extra_paths=[config_file],
                analyzers=[CrashingAnalyzer()],
                skip_rug_pull=True,
            )

        crash_findings = [
            f for f in result.findings if f.id == "SCAN-ERR"
        ]
        assert len(crash_findings) == 1
        assert crash_findings[0].severity == Severity.HIGH
        assert "crasher" in crash_findings[0].title
        assert "simulated crash" in crash_findings[0].evidence

    def test_crashing_analyzer_does_not_suppress_other_findings(
        self, tmp_path: Path
    ) -> None:
        config_file = tmp_path / "test.json"
        config_file.write_text(
            '{"mcpServers": {"srv": {"command": "node",'
            ' "args": ["s.js"]}}}'
        )

        class CrashingAnalyzer(BaseAnalyzer):
            @property
            def name(self) -> str:
                return "crasher"

            @property
            def description(self) -> str:
                return "Always crashes"

            def analyze(
                self, server: ServerConfig
            ) -> list[Finding]:
                raise RuntimeError("boom")

        class GoodAnalyzer(BaseAnalyzer):
            @property
            def name(self) -> str:
                return "good"

            @property
            def description(self) -> str:
                return "Always finds something"

            def analyze(
                self, server: ServerConfig
            ) -> list[Finding]:
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
