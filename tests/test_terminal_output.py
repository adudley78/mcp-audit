"""Tests for the Rich terminal output renderer."""

from __future__ import annotations

from io import StringIO

from rich.console import Console

from mcp_audit.models import RegistryStats, ScanResult
from mcp_audit.output.terminal import _format_registry_stats, print_results


def _make_result(**kwargs) -> ScanResult:
    return ScanResult(clients_scanned=1, servers_found=0, **kwargs)


def _capture(result: ScanResult, show_score: bool = True) -> str:
    buf = StringIO()
    con = Console(file=buf, highlight=False, markup=True)
    print_results(result, console=con, show_score=show_score)
    return buf.getvalue()


# ── _format_registry_stats ────────────────────────────────────────────────────


class TestFormatRegistryStats:
    def test_contains_entry_count(self) -> None:
        stats = RegistryStats(
            entry_count=57, schema_version="1.0", last_updated="2026-04-15"
        )
        text = _format_registry_stats(stats)
        assert "57" in text

    def test_contains_schema_version(self) -> None:
        stats = RegistryStats(
            entry_count=57, schema_version="1.0", last_updated="2026-04-15"
        )
        text = _format_registry_stats(stats)
        assert "1.0" in text

    def test_contains_last_updated(self) -> None:
        stats = RegistryStats(
            entry_count=57, schema_version="1.0", last_updated="2026-04-15"
        )
        text = _format_registry_stats(stats)
        assert "2026-04-15" in text


# ── Registry stats line in print_results ──────────────────────────────────────


class TestRegistryStatsInTerminalOutput:
    def test_stats_line_present_when_registry_stats_set(self) -> None:
        result = _make_result(
            registry_stats=RegistryStats(
                entry_count=57, schema_version="1.0", last_updated="2026-04-15"
            )
        )
        output = _capture(result)
        assert "57" in output
        assert "2026-04-15" in output

    def test_stats_line_absent_when_registry_stats_none(self) -> None:
        result = _make_result(registry_stats=None)
        output = _capture(result)
        assert "Registry:" not in output

    def test_stats_shown_with_no_score(self) -> None:
        """Registry stats appear even when show_score=False — they are independent."""
        result = _make_result(
            registry_stats=RegistryStats(
                entry_count=57, schema_version="1.0", last_updated="2026-04-15"
            )
        )
        output = _capture(result, show_score=False)
        assert "57" in output
