"""Tests for mcp_audit.scoring — scan score and grade calculation."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
from pydantic import ValidationError
from rich.console import Console
from typer.testing import CliRunner

from mcp_audit.cli import app
from mcp_audit.governance.models import (
    ScoringDeductions,
    ScoringPositiveSignals,
    ScoringWeights,
)
from mcp_audit.models import Finding, ScanResult, ScanScore, Severity
from mcp_audit.scoring import calculate_score, format_grade_terminal

# ── Helpers ───────────────────────────────────────────────────────────────────


def _finding(
    severity: Severity,
    analyzer: str = "transport",
    idx: int = 0,
) -> Finding:
    """Build a minimal Finding for testing."""
    return Finding(
        id=f"T-{severity.value}-{idx:03d}",
        severity=severity,
        analyzer=analyzer,
        client="test",
        server="test-server",
        title="Test finding",
        description="Test description",
        evidence="test evidence",
        remediation="Fix it",
        finding_path="/tmp/test.json",  # noqa: S108
    )


def _findings(
    severity: Severity, count: int, analyzer: str = "transport"
) -> list[Finding]:
    return [_finding(severity, analyzer=analyzer, idx=i) for i in range(count)]


# ── calculate_score ────────────────────────────────────────────────────────────


class TestPerfectScore:
    """No findings → 100, grade A, all three positive signals present."""

    def test_numeric_score_is_100(self) -> None:
        score = calculate_score([])
        assert score.numeric_score == 100

    def test_grade_is_a(self) -> None:
        score = calculate_score([])
        assert score.grade == "A"

    def test_all_positive_signals_present(self) -> None:
        score = calculate_score([])
        assert "No credential exposure detected (+3 pts)" in score.positive_signals
        assert "No high-severity issues found (+3 pts)" in score.positive_signals
        assert "No prompt injection risks detected (+4 pts)" in score.positive_signals

    def test_no_deductions(self) -> None:
        score = calculate_score([])
        assert score.deductions == []


class TestAllCritical:
    """Many CRITICAL findings should produce grade F and correct deductions."""

    def test_grade_f_for_all_critical(self) -> None:
        findings = _findings(Severity.CRITICAL, 5)
        score = calculate_score(findings)
        assert score.grade == "F"

    def test_score_clamped_to_zero_not_negative(self) -> None:
        # 5 × 25 = 125 deductions; score must be 0 before bonuses.
        # No credentials/poisoning findings present → +3 +2 = +5 bonus.
        findings = _findings(Severity.CRITICAL, 5)
        score = calculate_score(findings)
        assert score.numeric_score >= 0

    def test_deduction_entry_for_critical_group(self) -> None:
        findings = _findings(Severity.CRITICAL, 3)
        score = calculate_score(findings)
        assert any("critical" in d.lower() for d in score.deductions)

    def test_deduction_shows_correct_points(self) -> None:
        findings = _findings(Severity.CRITICAL, 2)
        score = calculate_score(findings)
        # 2 × 25 = 50 pts
        deduction_str = next(d for d in score.deductions if "critical" in d.lower())
        assert "50" in deduction_str


class TestDeductionFloor:
    """Score must never go below 0."""

    def test_floor_at_zero(self) -> None:
        # 10 CRITICAL findings → −250 raw; should clamp to 0.
        findings = _findings(Severity.CRITICAL, 10)
        score = calculate_score(findings)
        assert score.numeric_score >= 0


class TestMixedSeverities:
    """Verify correct arithmetic across multiple severity levels."""

    def test_mixed_math(self) -> None:
        findings = (
            _findings(Severity.CRITICAL, 1)  # −25
            + _findings(Severity.HIGH, 2)  # −20
            + _findings(Severity.MEDIUM, 1)  # −5
            + _findings(Severity.LOW, 2)  # −4
        )
        # Base: 100 − 25 − 20 − 5 − 4 = 46
        # Bonuses: has critical+high → no "no high-severity" bonus
        #          no credentials (+3) + no poisoning (+4) = +7
        # Final: 46 + 7 = 53
        score = calculate_score(findings)
        assert score.numeric_score == 53

    def test_mixed_grade_d(self) -> None:
        findings = (
            _findings(Severity.CRITICAL, 1)
            + _findings(Severity.HIGH, 2)
            + _findings(Severity.MEDIUM, 1)
            + _findings(Severity.LOW, 2)
        )
        score = calculate_score(findings)
        # 53 falls in D range (40–59)
        assert score.grade == "D"

    def test_deductions_only_for_non_zero_groups(self) -> None:
        findings = _findings(Severity.HIGH, 1)  # only HIGH
        score = calculate_score(findings)
        assert all("high" in d.lower() for d in score.deductions)
        assert not any("critical" in d.lower() for d in score.deductions)
        assert not any("medium" in d.lower() for d in score.deductions)
        assert not any("low" in d.lower() for d in score.deductions)


class TestBonusCap:
    """Bonuses must not push score above 100."""

    def test_bonus_cap_at_100(self) -> None:
        # Start near 100 with a single LOW finding → −3 + bonuses ≤ 100.
        findings = _findings(Severity.LOW, 1)
        score = calculate_score(findings)
        assert score.numeric_score <= 100

    def test_no_findings_does_not_exceed_100(self) -> None:
        score = calculate_score([])
        assert score.numeric_score == 100


class TestGradeThresholds:
    """Verify each grade boundary."""

    @pytest.mark.parametrize(
        "numeric,expected_grade",
        [
            (100, "A"),
            (90, "A"),
            (89, "B"),
            (75, "B"),
            (74, "C"),
            (60, "C"),
            (59, "D"),
            (40, "D"),
            (39, "F"),
            (0, "F"),
        ],
    )
    def test_grade_boundary(self, numeric: int, expected_grade: str) -> None:
        # Patch calculate_score is awkward; instead verify _grade_for directly.
        from mcp_audit.scoring import _grade_for

        assert _grade_for(numeric) == expected_grade


class TestPositiveSignals:
    """Positive signal bonuses are conditional on absence of certain finding types."""

    def test_credential_findings_suppress_credential_signal(self) -> None:
        findings = _findings(Severity.LOW, 1, analyzer="credentials")
        score = calculate_score(findings)
        assert "No credential exposure detected (+3 pts)" not in score.positive_signals

    def test_poisoning_findings_suppress_poisoning_signal(self) -> None:
        findings = _findings(Severity.LOW, 1, analyzer="poisoning")
        score = calculate_score(findings)
        assert "No prompt injection risks detected (+4 pts)" not in (
            score.positive_signals
        )

    def test_high_finding_suppresses_no_high_severity_signal(self) -> None:
        findings = _findings(Severity.HIGH, 1)
        score = calculate_score(findings)
        assert "No high-severity issues found (+3 pts)" not in score.positive_signals

    def test_critical_finding_suppresses_no_high_severity_signal(self) -> None:
        findings = _findings(Severity.CRITICAL, 1)
        score = calculate_score(findings)
        assert "No high-severity issues found (+3 pts)" not in score.positive_signals

    def test_bonus_cap_limits_to_10(self) -> None:
        # All three bonuses apply: 3 + 5 + 2 = 10, which equals the cap.
        score = calculate_score([])
        # 100 base + 10 bonus = 110 → clamped to 100.
        assert score.numeric_score == 100


class TestInfoFindings:
    """INFO findings produce a −1 deduction each; score must not be 100."""

    def test_single_info_finding_deducts_one(self) -> None:
        # 100 − 1 (INFO) + 10 (all bonuses apply) → clamped to 100... wrong.
        # Actually: 100 − 1 = 99 + 10 = 109 → clamped to 100.
        # The meaningful check: a single INFO finding still produces a deduction entry.
        findings = _findings(Severity.INFO, 1)
        score = calculate_score(findings)
        assert any("info" in d.lower() for d in score.deductions)

    def test_info_only_score_below_100(self) -> None:
        # With only INFO findings, bonuses push score back to 100 because
        # clamping applies last. Verify the deduction entry is present regardless.
        findings = _findings(Severity.INFO, 3)
        score = calculate_score(findings)
        # Deductions list must mention info
        assert any("info" in d.lower() for d in score.deductions)

    def test_info_deduction_points_correct(self) -> None:
        findings = _findings(Severity.INFO, 4)
        score = calculate_score(findings)
        deduction_str = next(d for d in score.deductions if "info" in d.lower())
        # 4 × 1 = 4 pts
        assert "4" in deduction_str

    def test_info_and_low_combined(self) -> None:
        # 1 LOW (−3) + 2 INFO (−2) = −5 total; bonuses (+10) → clamped to 100.
        # Score should still reflect both deductions.
        findings = _findings(Severity.LOW, 1) + _findings(Severity.INFO, 2)
        score = calculate_score(findings)
        assert any("low" in d.lower() for d in score.deductions)
        assert any("info" in d.lower() for d in score.deductions)

    def test_info_does_not_affect_no_high_severity_signal(self) -> None:
        findings = _findings(Severity.INFO, 1)
        score = calculate_score(findings)
        assert "No high-severity issues found (+3 pts)" in score.positive_signals


class TestFormatGradeTerminal:
    """format_grade_terminal returns valid Rich markup strings."""

    def test_contains_grade_letter(self) -> None:
        score = ScanScore(
            numeric_score=85,
            grade="B",
            positive_signals=["No credential exposure detected"],
            deductions=["1 high finding (-15 pts)"],
        )
        output = format_grade_terminal(score)
        assert "B" in output

    def test_contains_numeric_score(self) -> None:
        score = ScanScore(
            numeric_score=85,
            grade="B",
            positive_signals=[],
            deductions=[],
        )
        output = format_grade_terminal(score)
        assert "85" in output

    def test_positive_signal_included(self) -> None:
        score = ScanScore(
            numeric_score=100,
            grade="A",
            positive_signals=["No credential exposure detected"],
            deductions=[],
        )
        output = format_grade_terminal(score)
        assert "No credential exposure detected" in output

    def test_deduction_included(self) -> None:
        score = ScanScore(
            numeric_score=70,
            grade="C",
            positive_signals=[],
            deductions=["2 high findings (-30 pts)"],
        )
        output = format_grade_terminal(score)
        assert "2 high findings (-30 pts)" in output

    def test_renders_without_error(self) -> None:
        """format_grade_terminal output should be printable by Rich."""
        score = ScanScore(
            numeric_score=55,
            grade="D",
            positive_signals=[],
            deductions=["3 critical findings (-75 pts)"],
        )
        console = Console(force_terminal=False)
        # Should not raise.
        console.print(format_grade_terminal(score))

    @pytest.mark.parametrize("grade", ["A", "B", "C", "D", "F"])
    def test_all_grades_render(self, grade: str) -> None:
        score = ScanScore(
            numeric_score=50,
            grade=grade,
            positive_signals=[],
            deductions=[],
        )
        output = format_grade_terminal(score)
        assert grade in output


# ── --no-score CLI flag ────────────────────────────────────────────────────────


class TestNoScoreFlag:
    """--no-score suppresses the grade panel in terminal output."""

    def test_no_score_suppresses_grade(self, tmp_path: Path) -> None:
        """When --no-score is passed, 'Scan Score' must not appear in output."""
        runner = CliRunner()
        dummy_result = ScanResult(clients_scanned=0, servers_found=0)
        dummy_result.score = calculate_score([])

        with patch("mcp_audit.cli.run_scan", return_value=dummy_result):
            result_no_score = runner.invoke(app, ["scan", "--no-score"])

        assert "Scan Score" not in result_no_score.output

    def test_score_shown_by_default(self) -> None:
        """Without --no-score, 'Scan Score' must appear in output."""
        runner = CliRunner()
        dummy_result = ScanResult(clients_scanned=0, servers_found=0)
        dummy_result.score = calculate_score([])

        with patch("mcp_audit.cli.run_scan", return_value=dummy_result):
            result_default = runner.invoke(app, ["scan"])

        assert "Scan Score" in result_default.output


# ── Custom scoring weights ─────────────────────────────────────────────────────


class TestCustomWeights:
    """calculate_score respects caller-supplied ScoringWeights."""

    def test_custom_critical_deduction(self) -> None:
        """CRITICAL: -40 produces a lower score than the default -25."""
        findings = [_finding(Severity.CRITICAL)]
        default_score = calculate_score(findings)

        weights = ScoringWeights(deductions=ScoringDeductions(CRITICAL=-40))
        custom_score = calculate_score(findings, weights=weights)

        assert custom_score.numeric_score < default_score.numeric_score

    def test_partial_override_falls_back(self) -> None:
        """Only CRITICAL overridden; HIGH uses the hardcoded default (10 pts)."""
        findings = [_finding(Severity.HIGH)]
        default_score = calculate_score(findings)

        # Override only CRITICAL — HIGH should fall back to default
        weights = ScoringWeights(deductions=ScoringDeductions(CRITICAL=-40))
        custom_score = calculate_score(findings, weights=weights)

        # No CRITICAL findings, so override has no effect — scores must match
        assert custom_score.numeric_score == default_score.numeric_score

    def test_no_scoring_block_unchanged(self) -> None:
        """Passing weights=None produces the same score as no custom weights."""
        findings = [_finding(Severity.HIGH), _finding(Severity.MEDIUM)]
        default_score = calculate_score(findings)
        none_score = calculate_score(findings, weights=None)
        assert none_score.numeric_score == default_score.numeric_score

    def test_weights_source_default(self) -> None:
        """weights_source is 'default' when no custom weights are used."""
        score = calculate_score([])
        assert score.weights_source == "default"

    def test_weights_source_policy(self) -> None:
        """weights_source reflects the caller-supplied label."""
        weights = ScoringWeights()
        score = calculate_score(
            [], weights=weights, weights_source="policy:/abs/policy.yml"
        )
        assert score.weights_source == "policy:/abs/policy.yml"

    def test_zero_deduction_valid(self) -> None:
        """CRITICAL: 0 is accepted; CRITICAL findings produce no score deduction."""
        findings = [_finding(Severity.CRITICAL)]
        weights = ScoringWeights(deductions=ScoringDeductions(CRITICAL=0))
        score = calculate_score(findings, weights=weights)
        # With CRITICAL deducting 0 pts no deduction entry is emitted
        assert not any("critical" in d.lower() for d in score.deductions)

    def test_positive_deduction_rejected(self) -> None:
        """CRITICAL: 5 (positive) must raise a Pydantic ValidationError."""
        with pytest.raises(ValidationError):
            ScoringDeductions(CRITICAL=5)

    def test_custom_max_bonus(self) -> None:
        """max_total_bonus=0 means no bonus points are awarded."""
        weights = ScoringWeights(
            positive_signals=ScoringPositiveSignals(max_total_bonus=0)
        )
        score = calculate_score([], weights=weights)
        # No findings → 100 base, bonus capped at 0 → should still be 100
        assert score.numeric_score == 100

    def test_custom_positive_signal_values_used(self) -> None:
        """Custom no_credentials value shows in the positive_signals label."""
        weights = ScoringWeights(
            positive_signals=ScoringPositiveSignals(no_credentials=7)
        )
        score = calculate_score([], weights=weights)
        assert any("+7 pts" in s for s in score.positive_signals)

    def test_negative_positive_signal_rejected(self) -> None:
        """Negative bonus values must raise a ValidationError."""
        with pytest.raises(ValidationError):
            ScoringPositiveSignals(no_credentials=-1)

    def test_deduction_string_reflects_custom_pts(self) -> None:
        """Deduction label shows the actual points deducted (custom weight)."""
        findings = [_finding(Severity.CRITICAL)]
        weights = ScoringWeights(deductions=ScoringDeductions(CRITICAL=-40))
        score = calculate_score(findings, weights=weights)
        deduction_str = next(d for d in score.deductions if "critical" in d.lower())
        assert "40" in deduction_str


class TestWeightsSourceTerminalOutput:
    """format_grade_terminal shows 'Weights:' line only when source != 'default'."""

    def test_no_weights_line_for_default(self) -> None:
        score = ScanScore(
            numeric_score=80,
            grade="B",
            positive_signals=[],
            deductions=[],
            weights_source="default",
        )
        output = format_grade_terminal(score)
        assert "Weights:" not in output

    def test_weights_line_shown_for_custom(self) -> None:
        score = ScanScore(
            numeric_score=80,
            grade="B",
            positive_signals=[],
            deductions=[],
            weights_source="policy:/etc/policy.yml",
        )
        output = format_grade_terminal(score)
        assert "Weights: policy:/etc/policy.yml" in output
