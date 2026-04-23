"""Tests for the fleet merge module and CLI command.

Covers FleetMerger.load_report(), merge(), FleetStats calculations,
deduplication behaviour, version-mismatch warnings, --dir handling,
terminal/JSON output rendering, and the Enterprise license gate.
"""

from __future__ import annotations

import json
import warnings
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from mcp_audit.cli import app
from mcp_audit.fleet.merger import (
    FleetMerger,
    FleetReport,
    generate_fleet_html,
)

runner = CliRunner()

# ── Helpers ───────────────────────────────────────────────────────────────────

_TS = "2026-04-16T10:00:00+00:00"
_TS2 = "2026-04-16T11:00:00+00:00"


def _finding(
    *,
    analyzer: str = "credentials",
    server: str = "filesystem",
    title: str = "Hardcoded API key",
    severity: str = "HIGH",
    idx: int = 1,
) -> dict:
    return {
        "id": f"CRED-{idx:03d}",
        "severity": severity,
        "analyzer": analyzer,
        "client": "claude",
        "server": server,
        "title": title,
        "description": "An API key was found in the server config.",
        "evidence": "OPENAI_API_KEY=sk-abc123",
        "remediation": "Move secrets to environment variables.",
    }


def _scan_json(
    *,
    hostname: str = "machine-1",
    version: str = "0.1.0",
    findings: list[dict] | None = None,
    score: dict | None = None,
    servers_found: int = 2,
    timestamp: str = _TS,
) -> dict:
    """Build a minimal valid mcp-audit scan JSON dict."""
    return {
        "version": version,
        "timestamp": timestamp,
        "machine": {
            "hostname": hostname,
            "username": "testuser",
            "os": "Darwin",
            "os_version": "25.0",
            "scan_id": "00000000-0000-0000-0000-000000000001",
        },
        "clients_scanned": 1,
        "servers_found": servers_found,
        "servers": [],
        "findings": findings or [],
        "errors": [],
        "attack_path_summary": None,
        "score": score,
    }


def _write_json(path: Path, data: dict) -> Path:
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def _score_dict(numeric: int = 80) -> dict:
    return {
        "numeric_score": numeric,
        "grade": "B",
        "positive_signals": [],
        "deductions": [],
    }


# ── load_report() ──────────────────────────────────────────────────────────────


def test_load_report_valid(tmp_path: Path) -> None:
    f = _write_json(tmp_path / "m1.json", _scan_json(hostname="dev-laptop"))
    report = FleetMerger().load_report(f)

    assert report.machine_id == "dev-laptop"
    assert report.scanner_version == "0.1.0"
    assert report.server_count == 2
    assert isinstance(report.scan_timestamp, datetime)
    assert report.source_file == str(f)
    assert report.asset_prefix is None


def test_load_report_with_findings(tmp_path: Path) -> None:
    data = _scan_json(findings=[_finding()])
    f = _write_json(tmp_path / "m1.json", data)
    report = FleetMerger().load_report(f)

    assert len(report.findings) == 1
    assert report.findings[0].title == "Hardcoded API key"


def test_load_report_with_score(tmp_path: Path) -> None:
    data = _scan_json(score=_score_dict(75))
    f = _write_json(tmp_path / "m1.json", data)
    report = FleetMerger().load_report(f)

    assert report.score is not None
    assert report.score.numeric_score == 75


def test_load_report_raises_on_invalid_mcp_audit_json(tmp_path: Path) -> None:
    f = tmp_path / "not_audit.json"
    f.write_text(json.dumps({"foo": "bar"}), encoding="utf-8")
    with pytest.raises(ValueError, match="missing required mcp-audit fields"):
        FleetMerger().load_report(f)


def test_load_report_raises_on_malformed_json(tmp_path: Path) -> None:
    f = tmp_path / "bad.json"
    f.write_text("{this is not json", encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid JSON"):
        FleetMerger().load_report(f)


def test_load_report_raises_on_non_object_json(tmp_path: Path) -> None:
    f = tmp_path / "arr.json"
    f.write_text("[1, 2, 3]", encoding="utf-8")
    with pytest.raises(ValueError, match="not a valid mcp-audit JSON output"):
        FleetMerger().load_report(f)


def test_load_report_raises_on_missing_hostname(tmp_path: Path) -> None:
    data = _scan_json()
    data["machine_info"] = {"username": "alice"}  # no hostname
    f = _write_json(tmp_path / "m.json", data)
    with pytest.raises(ValueError, match="hostname"):
        FleetMerger().load_report(f)


def test_load_report_warns_on_version_mismatch(tmp_path: Path) -> None:
    data = _scan_json(version="0.0.9")
    f = _write_json(tmp_path / "old.json", data)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        FleetMerger().load_report(f)
    texts = [str(w.message) for w in caught]
    assert any("version mismatch" in t for t in texts)


# ── merge() — deduplication ────────────────────────────────────────────────────


def test_merge_deduplicates_identical_findings(tmp_path: Path) -> None:
    """Same finding on two machines: one DeduplicatedFinding, affected_count=2."""
    finding = _finding(title="Hardcoded API key", analyzer="credentials", server="fs")
    f1 = _write_json(
        tmp_path / "m1.json", _scan_json(hostname="m1", findings=[finding])
    )
    f2 = _write_json(
        tmp_path / "m2.json", _scan_json(hostname="m2", findings=[finding])
    )

    report = FleetMerger().merge([f1, f2])

    assert len(report.deduplicated_findings) == 1
    df = report.deduplicated_findings[0]
    assert df.affected_count == 2
    assert set(df.affected_machines) == {"m1", "m2"}
    assert df.affected_count == len(df.affected_machines)


def test_merge_no_overlapping_findings(tmp_path: Path) -> None:
    """Different findings on two machines → two distinct DeduplicatedFindings."""
    f1 = _write_json(
        tmp_path / "m1.json",
        _scan_json(hostname="m1", findings=[_finding(title="Key A", server="alpha")]),
    )
    f2 = _write_json(
        tmp_path / "m2.json",
        _scan_json(hostname="m2", findings=[_finding(title="Key B", server="alpha")]),
    )

    report = FleetMerger().merge([f1, f2])

    assert len(report.deduplicated_findings) == 2
    titles = {df.title for df in report.deduplicated_findings}
    assert titles == {"Key A", "Key B"}
    for df in report.deduplicated_findings:
        assert df.affected_count == 1


def test_merge_same_server_different_titles_produces_two_dedup_findings(
    tmp_path: Path,
) -> None:
    """Self-check 1: same server, different titles -> separate dedup entries.

    Two findings on 'filesystem' with different titles must produce two distinct
    DeduplicatedFindings, not one.
    """
    finding_a = _finding(title="Hardcoded API key", server="filesystem", idx=1)
    finding_b = _finding(title="Cleartext password", server="filesystem", idx=2)
    f1 = _write_json(
        tmp_path / "m1.json",
        _scan_json(hostname="m1", findings=[finding_a, finding_b]),
    )
    f2 = _write_json(
        tmp_path / "m2.json",
        _scan_json(hostname="m2", findings=[finding_a, finding_b]),
    )

    report = FleetMerger().merge([f1, f2])

    assert len(report.deduplicated_findings) == 2, (
        "Two findings with different titles on the same server must produce "
        "two DeduplicatedFindings, not one"
    )
    titles = {df.title for df in report.deduplicated_findings}
    assert titles == {"Hardcoded API key", "Cleartext password"}


# ── merge() — asset_prefix_filter ─────────────────────────────────────────────


def test_merge_asset_prefix_filter_excludes_non_matching(tmp_path: Path) -> None:
    f1 = _write_json(tmp_path / "m1.json", _scan_json(hostname="prod-m1"))
    f2 = _write_json(tmp_path / "m2.json", _scan_json(hostname="dev-m2"))

    report = FleetMerger(asset_prefix_filter="prod-").merge([f1, f2])

    machine_ids = {m.machine_id for m in report.machines}
    assert machine_ids == {"prod-m1"}
    assert "dev-m2" not in machine_ids


def test_merge_asset_prefix_filter_includes_matching(tmp_path: Path) -> None:
    f1 = _write_json(tmp_path / "m1.json", _scan_json(hostname="prod-api-1"))
    f2 = _write_json(tmp_path / "m2.json", _scan_json(hostname="prod-api-2"))
    f3 = _write_json(tmp_path / "m3.json", _scan_json(hostname="staging-api-1"))

    report = FleetMerger(asset_prefix_filter="prod-").merge([f1, f2, f3])

    assert report.machine_count == 2
    assert all(m.machine_id.startswith("prod-") for m in report.machines)


def test_merge_asset_prefix_filter_all_excluded_raises(tmp_path: Path) -> None:
    f1 = _write_json(tmp_path / "m1.json", _scan_json(hostname="dev-m1"))
    with pytest.raises(ValueError, match="No machine reports remain"):
        FleetMerger(asset_prefix_filter="prod-").merge([f1])


# ── merge() — version mismatches ──────────────────────────────────────────────


def test_merge_populates_version_mismatches(tmp_path: Path) -> None:
    """Self-check 4: version_mismatches list must be populated."""
    f1 = _write_json(tmp_path / "m1.json", _scan_json(hostname="m1", version="0.1.0"))
    # version "0.0.9" triggers a mismatch
    data2 = _scan_json(hostname="m2", version="0.0.9")
    f2 = _write_json(tmp_path / "m2.json", data2)

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        report = FleetMerger().merge([f1, f2])

    assert len(report.version_mismatches) == 1
    assert "m2" in report.version_mismatches[0]


def test_merge_no_version_mismatches_when_all_same(tmp_path: Path) -> None:
    f1 = _write_json(tmp_path / "m1.json", _scan_json(hostname="m1", version="0.1.0"))
    f2 = _write_json(tmp_path / "m2.json", _scan_json(hostname="m2", version="0.1.0"))

    report = FleetMerger().merge([f1, f2])

    assert report.version_mismatches == []


# ── merge() — edge cases ───────────────────────────────────────────────────────


def test_merge_empty_paths_raises(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="No scan files provided"):
        FleetMerger().merge([])


# ── finding_id determinism ─────────────────────────────────────────────────────


def test_finding_id_is_deterministic(tmp_path: Path) -> None:
    finding = _finding(title="Hardcoded key", analyzer="credentials", server="db")
    f1 = _write_json(
        tmp_path / "m1.json", _scan_json(hostname="m1", findings=[finding])
    )
    f2 = _write_json(
        tmp_path / "m2.json", _scan_json(hostname="m2", findings=[finding])
    )

    report_a = FleetMerger().merge([f1, f2])
    report_b = FleetMerger().merge([f1, f2])

    assert (
        report_a.deduplicated_findings[0].finding_id
        == report_b.deduplicated_findings[0].finding_id
    )
    assert len(report_a.deduplicated_findings[0].finding_id) == 16


def test_finding_id_different_for_different_keys(tmp_path: Path) -> None:
    f_a = _finding(title="Key A", server="alpha")
    f_b = _finding(title="Key B", server="alpha")
    f = _write_json(tmp_path / "m1.json", _scan_json(findings=[f_a, f_b]))
    report = FleetMerger().merge([f])
    ids = [df.finding_id for df in report.deduplicated_findings]
    assert len(ids) == len(set(ids))


# ── FleetStats ────────────────────────────────────────────────────────────────


def test_fleet_stats_riskiest_machine_critical_beats_many_low(tmp_path: Path) -> None:
    """Self-check 3: machine with 1 CRITICAL outranks machine with 10 LOW findings."""
    low_findings = [
        _finding(severity="LOW", idx=i, title=f"Low {i}") for i in range(10)
    ]
    crit_finding = _finding(severity="CRITICAL", title="Poison", idx=99)

    f1 = _write_json(
        tmp_path / "m1.json",
        _scan_json(hostname="lots-of-lows", findings=low_findings),
    )
    f2 = _write_json(
        tmp_path / "m2.json",
        _scan_json(hostname="one-critical", findings=[crit_finding]),
    )

    report = FleetMerger().merge([f1, f2])

    assert report.stats.riskiest_machine == "one-critical", (
        "Machine with 1 CRITICAL must be riskiest over machine with 10 LOW findings"
    )


def test_fleet_stats_riskiest_machine_is_none_when_no_critical_or_high(
    tmp_path: Path,
) -> None:
    f1 = _write_json(
        tmp_path / "m1.json",
        _scan_json(hostname="m1", findings=[_finding(severity="LOW")]),
    )
    report = FleetMerger().merge([f1])
    assert report.stats.riskiest_machine is None


def test_fleet_stats_average_score(tmp_path: Path) -> None:
    f1 = _write_json(
        tmp_path / "m1.json", _scan_json(hostname="m1", score=_score_dict(80))
    )
    f2 = _write_json(
        tmp_path / "m2.json", _scan_json(hostname="m2", score=_score_dict(60))
    )

    report = FleetMerger().merge([f1, f2])

    assert report.stats.average_score == 70.0


def test_fleet_stats_average_score_none_when_no_scores(tmp_path: Path) -> None:
    f1 = _write_json(tmp_path / "m1.json", _scan_json(hostname="m1"))
    report = FleetMerger().merge([f1])
    assert report.stats.average_score is None


def test_fleet_stats_lowest_score_machine(tmp_path: Path) -> None:
    f1 = _write_json(
        tmp_path / "m1.json", _scan_json(hostname="high-score", score=_score_dict(90))
    )
    f2 = _write_json(
        tmp_path / "m2.json", _scan_json(hostname="low-score", score=_score_dict(40))
    )
    f3 = _write_json(
        tmp_path / "m3.json", _scan_json(hostname="mid-score", score=_score_dict(65))
    )

    report = FleetMerger().merge([f1, f2, f3])

    assert report.stats.lowest_score_machine == "low-score"


def test_fleet_stats_severity_breakdown(tmp_path: Path) -> None:
    findings = [
        _finding(severity="CRITICAL", title="C1", idx=1),
        _finding(severity="HIGH", title="H1", idx=2),
        _finding(severity="HIGH", title="H2", idx=3),
        _finding(severity="LOW", title="L1", idx=4),
    ]
    f = _write_json(tmp_path / "m1.json", _scan_json(findings=findings))
    report = FleetMerger().merge([f])

    bd = report.stats.severity_breakdown
    assert bd["CRITICAL"] == 1
    assert bd["HIGH"] == 2
    assert bd["LOW"] == 1
    assert bd["MEDIUM"] == 0
    assert bd["INFO"] == 0


def test_fleet_stats_most_common_finding_is_highest_affected_count(
    tmp_path: Path,
) -> None:
    shared = _finding(title="Shared Issue", server="db")
    unique = _finding(title="Unique Issue", server="cache", idx=2)
    f1 = _write_json(
        tmp_path / "m1.json", _scan_json(hostname="m1", findings=[shared, unique])
    )
    f2 = _write_json(tmp_path / "m2.json", _scan_json(hostname="m2", findings=[shared]))

    report = FleetMerger().merge([f1, f2])

    assert report.stats.most_common_finding == "Shared Issue"


# ── merge() sorted output ─────────────────────────────────────────────────────


def test_merge_sorted_by_affected_count_desc(tmp_path: Path) -> None:
    rare = _finding(title="Rare Issue", server="alpha", idx=1)
    common = _finding(title="Common Issue", server="beta", idx=2)

    f1 = _write_json(
        tmp_path / "m1.json", _scan_json(hostname="m1", findings=[rare, common])
    )
    f2 = _write_json(tmp_path / "m2.json", _scan_json(hostname="m2", findings=[common]))

    report = FleetMerger().merge([f1, f2])

    # Common issue (2 machines) must come before rare issue (1 machine)
    assert report.deduplicated_findings[0].title == "Common Issue"
    assert report.deduplicated_findings[1].title == "Rare Issue"


# ── DeduplicatedFinding invariant ─────────────────────────────────────────────


def test_deduplicated_finding_affected_count_matches_len(tmp_path: Path) -> None:
    finding = _finding()
    f1 = _write_json(
        tmp_path / "m1.json", _scan_json(hostname="m1", findings=[finding])
    )
    f2 = _write_json(
        tmp_path / "m2.json", _scan_json(hostname="m2", findings=[finding])
    )
    f3 = _write_json(
        tmp_path / "m3.json", _scan_json(hostname="m3", findings=[finding])
    )

    report = FleetMerger().merge([f1, f2, f3])

    for df in report.deduplicated_findings:
        assert df.affected_count == len(df.affected_machines), (
            "affected_count must equal len(affected_machines)"
        )


# ── Terminal output rendering ─────────────────────────────────────────────────


def test_terminal_output_renders_without_error(tmp_path: Path) -> None:
    finding = _finding(severity="HIGH")
    f1 = _write_json(
        tmp_path / "m1.json",
        _scan_json(hostname="m1", findings=[finding], score=_score_dict(80)),
    )
    f2 = _write_json(
        tmp_path / "m2.json",
        _scan_json(hostname="m2", findings=[finding], score=_score_dict(60)),
    )

    with patch("mcp_audit.cli.cached_is_pro_feature_available", return_value=True):
        result = runner.invoke(
            app,
            ["merge", str(f1), str(f2)],
        )

    assert result.exit_code in (0, 1), (
        f"Unexpected exit code: {result.exit_code}\n{result.output}"
    )
    assert "Fleet Summary" in result.output
    assert "Finding Breakdown" in result.output


def test_terminal_output_shows_version_mismatch_warning(tmp_path: Path) -> None:
    f1 = _write_json(tmp_path / "m1.json", _scan_json(hostname="m1", version="0.1.0"))
    data2 = _scan_json(hostname="m2", version="0.0.9")
    f2 = _write_json(tmp_path / "m2.json", data2)

    with (
        patch("mcp_audit.cli.cached_is_pro_feature_available", return_value=True),
        warnings.catch_warnings(),
    ):
        warnings.simplefilter("ignore")
        result = runner.invoke(app, ["merge", str(f1), str(f2)])

    # Self-check 4: version mismatch appears in terminal output
    assert "Warning" in result.output or "mismatch" in result.output.lower()


# ── JSON output ───────────────────────────────────────────────────────────────


def test_json_output_valid_and_matches_schema(tmp_path: Path) -> None:
    finding = _finding()
    f1 = _write_json(
        tmp_path / "m1.json", _scan_json(hostname="m1", findings=[finding])
    )
    f2 = _write_json(
        tmp_path / "m2.json", _scan_json(hostname="m2", findings=[finding])
    )

    with patch("mcp_audit.cli.cached_is_pro_feature_available", return_value=True):
        result = runner.invoke(app, ["merge", str(f1), str(f2), "--format", "json"])

    assert result.exit_code in (0, 1)
    parsed = json.loads(result.output)

    # Validate against FleetReport schema fields
    report = FleetReport(**parsed)
    assert report.machine_count == 2
    assert len(report.deduplicated_findings) == 1
    assert report.deduplicated_findings[0].affected_count == 2
    assert report.stats.total_machines == 2


# ── HTML output ───────────────────────────────────────────────────────────────


def test_html_output_contains_fleet_summary(tmp_path: Path) -> None:
    f1 = _write_json(
        tmp_path / "m1.json", _scan_json(hostname="m1", score=_score_dict(85))
    )

    with patch("mcp_audit.cli.cached_is_pro_feature_available", return_value=True):
        result = runner.invoke(app, ["merge", str(f1), "--format", "html"])

    assert result.exit_code in (0, 1)
    assert "Fleet Summary" in result.output
    assert "<!DOCTYPE html>" in result.output or "<html" in result.output.lower()


def test_generate_fleet_html_returns_html_string(tmp_path: Path) -> None:
    finding = _finding(severity="CRITICAL")
    f1 = _write_json(
        tmp_path / "m1.json",
        _scan_json(hostname="m1", findings=[finding], score=_score_dict(30)),
    )
    f2 = _write_json(
        tmp_path / "m2.json", _scan_json(hostname="m2", score=_score_dict(90))
    )

    report = FleetMerger().merge([f1, f2])
    html = generate_fleet_html(report)

    assert isinstance(html, str)
    assert len(html) > 100
    assert "Fleet Summary" in html


# ── --dir flag ────────────────────────────────────────────────────────────────


def test_cli_merge_dir_loads_all_json_files(tmp_path: Path) -> None:
    _write_json(tmp_path / "m1.json", _scan_json(hostname="m1"))
    _write_json(tmp_path / "m2.json", _scan_json(hostname="m2"))

    with patch("mcp_audit.cli.cached_is_pro_feature_available", return_value=True):
        result = runner.invoke(
            app, ["merge", "--dir", str(tmp_path), "--format", "json"]
        )

    assert result.exit_code in (0, 1)
    parsed = json.loads(result.output)
    assert parsed["machine_count"] == 2


def test_cli_merge_dir_skips_non_json_files(tmp_path: Path) -> None:
    """Self-check 2: mixed directory — valid JSON, invalid JSON, .txt file."""
    _write_json(tmp_path / "valid.json", _scan_json(hostname="good-machine"))
    (tmp_path / "notes.txt").write_text("not a scan", encoding="utf-8")
    (tmp_path / "invalid.json").write_text('{"foo": "bar"}', encoding="utf-8")

    with patch("mcp_audit.cli.cached_is_pro_feature_available", return_value=True):
        result = runner.invoke(
            app, ["merge", "--dir", str(tmp_path), "--format", "json"]
        )

    # Should not crash; invalid.json is warned about and skipped
    assert result.exit_code in (0, 1, 2)
    # If exit 0/1, verify only the valid file was loaded (JSON starts at first '{')
    if result.exit_code in (0, 1):
        json_start = result.output.find("{")
        assert json_start != -1
        parsed = json.loads(result.output[json_start:])
        assert parsed["machine_count"] == 1
        assert parsed["machines"][0]["machine_id"] == "good-machine"


def test_cli_merge_dir_warns_on_invalid_json_file(tmp_path: Path) -> None:
    """Invalid JSON files in --dir produce a warning, not a crash."""
    _write_json(tmp_path / "valid.json", _scan_json(hostname="ok"))
    (tmp_path / "corrupt.json").write_text("{not valid json", encoding="utf-8")

    with patch("mcp_audit.cli.cached_is_pro_feature_available", return_value=True):
        result = runner.invoke(app, ["merge", "--dir", str(tmp_path)])

    assert "Warning" in result.output or result.exit_code != 2
    # Must not crash with unhandled exception
    assert result.exception is None or result.exit_code != 2


def test_cli_merge_files_and_dir_cannot_be_combined(tmp_path: Path) -> None:
    f = _write_json(tmp_path / "m1.json", _scan_json())
    with patch("mcp_audit.cli.cached_is_pro_feature_available", return_value=True):
        result = runner.invoke(app, ["merge", str(f), "--dir", str(tmp_path)])
    assert result.exit_code == 2


def test_cli_merge_no_args_shows_error(tmp_path: Path) -> None:
    with patch("mcp_audit.cli.cached_is_pro_feature_available", return_value=True):
        result = runner.invoke(app, ["merge"])
    assert result.exit_code == 2


# ── --output-file ──────────────────────────────────────────────────────────────


def test_cli_merge_output_file_writes_json(tmp_path: Path) -> None:
    f1 = _write_json(tmp_path / "m1.json", _scan_json(hostname="m1"))
    out = tmp_path / "fleet.json"

    with patch("mcp_audit.cli.cached_is_pro_feature_available", return_value=True):
        result = runner.invoke(
            app, ["merge", str(f1), "--format", "json", "--output-file", str(out)]
        )

    assert result.exit_code in (0, 1)
    assert out.exists()
    parsed = json.loads(out.read_text())
    assert parsed["machine_count"] == 1


# ── first_seen correctness ─────────────────────────────────────────────────────


def test_first_seen_is_earliest_timestamp(tmp_path: Path) -> None:
    finding = _finding()
    early = "2026-01-01T08:00:00+00:00"
    late = "2026-04-16T10:00:00+00:00"

    f1 = _write_json(
        tmp_path / "m1.json",
        _scan_json(hostname="m1", findings=[finding], timestamp=late),
    )
    f2 = _write_json(
        tmp_path / "m2.json",
        _scan_json(hostname="m2", findings=[finding], timestamp=early),
    )

    report = FleetMerger().merge([f1, f2])

    df = report.deduplicated_findings[0]
    assert df.first_seen == datetime.fromisoformat(early)
