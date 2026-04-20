"""Tests for BaseAnalyzer.analyze_all() default implementation."""

from __future__ import annotations

from pathlib import Path

from mcp_audit.analyzers.base import BaseAnalyzer
from mcp_audit.analyzers.rug_pull import RugPullAnalyzer
from mcp_audit.models import (
    Finding,
    ServerConfig,
    Severity,
)

# ── Minimal concrete subclass for testing ─────────────────────────────────────


class _CountingAnalyzer(BaseAnalyzer):
    """Analyzer that counts analyze() calls and emits one finding per server."""

    def __init__(self) -> None:
        self.call_count = 0

    @property
    def name(self) -> str:
        return "counting"

    @property
    def description(self) -> str:
        return "Counts analyze() invocations"

    def analyze(self, server: ServerConfig) -> list[Finding]:
        self.call_count += 1
        return [
            Finding(
                id="TEST-001",
                severity=Severity.INFO,
                analyzer=self.name,
                client=server.client,
                server=server.name,
                title=f"test finding for {server.name}",
                description="test",
                evidence="test",
                remediation="test",
            )
        ]


def _make_server(name: str, config_path: Path | None = None) -> ServerConfig:
    return ServerConfig(
        name=name,
        client="test-client",
        config_path=config_path or Path("/tmp/mcp.json"),  # noqa: S108
        command="node",
        args=[],
        env={},
    )


# ── Tests ─────────────────────────────────────────────────────────────────────


def test_analyze_all_default_calls_analyze_per_server() -> None:
    """analyze_all() calls analyze() once per server and unions results."""
    analyzer = _CountingAnalyzer()
    servers = [_make_server("srv-a"), _make_server("srv-b"), _make_server("srv-c")]

    results = analyzer.analyze_all(servers)

    assert analyzer.call_count == 3
    assert len(results) == 3
    titles = {f.title for f in results}
    assert titles == {
        "test finding for srv-a",
        "test finding for srv-b",
        "test finding for srv-c",
    }


def test_analyze_all_empty_server_list() -> None:
    """analyze_all() with no servers returns an empty list."""
    analyzer = _CountingAnalyzer()
    results = analyzer.analyze_all([])
    assert results == []
    assert analyzer.call_count == 0


def test_analyze_all_override_not_affected(tmp_path: Path) -> None:
    """RugPullAnalyzer.analyze_all() override is not broken by the base default.

    RugPullAnalyzer overrides analyze_all() — verify it still runs its own
    implementation and does not delegate to the base class loop.
    """
    state_path = tmp_path / "state.json"
    rp = RugPullAnalyzer(state_path=state_path)

    servers = [_make_server("srv-x")]
    findings = rp.analyze_all(servers)

    # First scan: rug-pull emits RUGPULL-000 INFO for every server.
    assert any(f.id == "RUGPULL-000" for f in findings), (
        "RugPullAnalyzer.analyze_all() should emit RUGPULL-000 on first scan"
    )
    # The no-op analyze() on a single server should NOT appear in results.
    assert not any(f.analyzer == "counting" for f in findings)
