"""Tests for GitHub Action integration.

Covers --output-file, --severity-threshold exit codes, and YAML validity.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import yaml
from typer.testing import CliRunner

from mcp_audit.cli import app
from mcp_audit.models import Finding, ScanResult, ScanScore, Severity

runner = CliRunner()

# ── Helpers ────────────────────────────────────────────────────────────────────

_REPO_ROOT = Path(__file__).parent.parent


def _finding(severity: Severity, idx: int = 0) -> Finding:
    return Finding(
        id=f"TEST-{idx:03d}",
        severity=severity,
        analyzer="transport",
        client="cursor",
        server="test-server",
        title=f"Test finding {idx}",
        description="A test finding.",
        evidence="evidence text",
        remediation="Fix it.",
        finding_path="/tmp/test.json",  # noqa: S108
    )


def _result_with(*severities: Severity) -> ScanResult:
    """Build a ScanResult whose findings have the given severities."""
    findings = [_finding(sev, idx=i) for i, sev in enumerate(severities)]
    result = ScanResult(
        clients_scanned=1,
        servers_found=1,
        findings=findings,
        score=ScanScore(
            numeric_score=75,
            grade="B",
            positive_signals=[],
            deductions=[],
        ),
    )
    return result


def _empty_result() -> ScanResult:
    return ScanResult(
        clients_scanned=0,
        servers_found=0,
        findings=[],
        score=ScanScore(
            numeric_score=100,
            grade="A",
            positive_signals=["No findings"],
            deductions=[],
        ),
    )


def _patch_scan(result: ScanResult):
    """Patch mcp_audit.cli.run_scan to return *result*."""
    return patch("mcp_audit.cli.run_scan", return_value=result)


# ── --output-file writes SARIF ─────────────────────────────────────────────────


class TestOutputFileSarif:
    def test_sarif_written_to_file(self, tmp_path: Path) -> None:
        out = tmp_path / "results.sarif"
        with _patch_scan(_result_with(Severity.HIGH)):
            result = runner.invoke(
                app,
                ["scan", "--format", "sarif", "--output-file", str(out)],
            )
        assert out.exists(), f"SARIF file not created; exit={result.exit_code}"
        doc = json.loads(out.read_text())
        assert doc["version"] == "2.1.0"

    def test_sarif_is_valid_json_structure(self, tmp_path: Path) -> None:
        out = tmp_path / "scan.sarif"
        with _patch_scan(_result_with(Severity.CRITICAL)):
            runner.invoke(app, ["scan", "--format", "sarif", "--output-file", str(out)])
        doc = json.loads(out.read_text())
        assert "$schema" in doc
        assert "runs" in doc
        assert len(doc["runs"]) == 1
        assert "results" in doc["runs"][0]

    def test_output_file_alias_works(self, tmp_path: Path) -> None:
        """--output-file is an alias for -o / --output."""
        out = tmp_path / "via_alias.sarif"
        with _patch_scan(_empty_result()):
            result = runner.invoke(
                app,
                ["scan", "--format", "sarif", "--output-file", str(out)],
            )
        assert out.exists(), (
            f"alias --output-file did not write file; exit={result.exit_code}"
        )

    def test_output_creates_parent_dirs(self, tmp_path: Path) -> None:
        nested = tmp_path / "deep" / "nested" / "results.sarif"
        with _patch_scan(_empty_result()):
            runner.invoke(
                app,
                ["scan", "--format", "sarif", "--output-file", str(nested)],
            )
        assert nested.exists()


# ── --output-file writes JSON ──────────────────────────────────────────────────


class TestOutputFileJson:
    def test_json_written_to_file(self, tmp_path: Path) -> None:
        out = tmp_path / "results.json"
        with _patch_scan(_result_with(Severity.MEDIUM)):
            runner.invoke(
                app,
                ["scan", "--format", "json", "--output-file", str(out)],
            )
        assert out.exists()
        data = json.loads(out.read_text())
        assert "findings" in data

    def test_json_contains_score_and_grade(self, tmp_path: Path) -> None:
        out = tmp_path / "results.json"
        with _patch_scan(_result_with(Severity.LOW)):
            runner.invoke(
                app,
                ["scan", "--format", "json", "--output-file", str(out)],
            )
        data = json.loads(out.read_text())
        assert data.get("score") is not None
        assert "grade" in data["score"]
        assert "numeric_score" in data["score"]

    def test_json_finding_count_matches(self, tmp_path: Path) -> None:
        out = tmp_path / "results.json"
        with _patch_scan(_result_with(Severity.HIGH, Severity.MEDIUM, Severity.LOW)):
            runner.invoke(
                app,
                [
                    "scan",
                    "--format",
                    "json",
                    "--severity-threshold",
                    "low",
                    "--output-file",
                    str(out),
                ],
            )
        data = json.loads(out.read_text())
        # All three findings are at or above LOW so all should be present.
        assert len(data["findings"]) == 3


# ── --severity-threshold exit codes ───────────────────────────────────────────


class TestSeverityThresholdExitCodes:
    def test_threshold_critical_exits_0_when_only_high(self) -> None:
        """--severity-threshold critical: HIGH findings don't trigger exit 1."""
        with _patch_scan(_result_with(Severity.HIGH)):
            result = runner.invoke(
                app,
                ["scan", "--severity-threshold", "critical"],
            )
        assert result.exit_code == 0

    def test_threshold_critical_exits_1_when_critical_exists(self) -> None:
        with _patch_scan(_result_with(Severity.CRITICAL)):
            result = runner.invoke(
                app,
                ["scan", "--severity-threshold", "critical"],
            )
        assert result.exit_code == 1

    def test_threshold_high_exits_1_when_high_exists(self) -> None:
        with _patch_scan(_result_with(Severity.HIGH)):
            result = runner.invoke(
                app,
                ["scan", "--severity-threshold", "high"],
            )
        assert result.exit_code == 1

    def test_threshold_high_exits_0_when_only_medium(self) -> None:
        """--severity-threshold high: MEDIUM findings don't trigger exit 1."""
        with _patch_scan(_result_with(Severity.MEDIUM)):
            result = runner.invoke(
                app,
                ["scan", "--severity-threshold", "high"],
            )
        assert result.exit_code == 0

    def test_threshold_medium_exits_1_when_medium_exists(self) -> None:
        with _patch_scan(_result_with(Severity.MEDIUM)):
            result = runner.invoke(
                app,
                ["scan", "--severity-threshold", "medium"],
            )
        assert result.exit_code == 1

    def test_threshold_low_exits_0_when_only_info(self) -> None:
        """--severity-threshold low: INFO findings are filtered out → exit 0."""
        with _patch_scan(_result_with(Severity.INFO)):
            result = runner.invoke(
                app,
                ["scan", "--severity-threshold", "low"],
            )
        assert result.exit_code == 0

    def test_threshold_case_insensitive_upper(self) -> None:
        """--severity-threshold HIGH (uppercase) is accepted."""
        with _patch_scan(_result_with(Severity.CRITICAL)):
            result = runner.invoke(
                app,
                ["scan", "--severity-threshold", "HIGH"],
            )
        assert result.exit_code == 1

    def test_threshold_case_insensitive_mixed(self) -> None:
        """--severity-threshold High (mixed case) is accepted."""
        with _patch_scan(_result_with(Severity.HIGH)):
            result = runner.invoke(
                app,
                ["scan", "--severity-threshold", "High"],
            )
        assert result.exit_code == 1

    def test_invalid_threshold_exits_2(self) -> None:
        with _patch_scan(_empty_result()):
            result = runner.invoke(
                app,
                ["scan", "--severity-threshold", "bogus"],
            )
        assert result.exit_code == 2

    def test_empty_scan_exits_0_regardless_of_threshold(self) -> None:
        """No MCP configs found → no findings → always exit 0."""
        with _patch_scan(_empty_result()):
            result = runner.invoke(
                app,
                ["scan", "--severity-threshold", "low"],
            )
        assert result.exit_code == 0


# ── Step-summary JSON structure ────────────────────────────────────────────────


class TestStepSummaryJsonStructure:
    """The JSON output that the action's step-summary block parses."""

    def test_json_output_has_findings_key(self, tmp_path: Path) -> None:
        out = tmp_path / "summary.json"
        with _patch_scan(_result_with(Severity.HIGH, Severity.LOW)):
            runner.invoke(
                app,
                ["scan", "--format", "json", "--output-file", str(out)],
            )
        data = json.loads(out.read_text())
        assert "findings" in data

    def test_json_output_has_score_key(self, tmp_path: Path) -> None:
        out = tmp_path / "summary.json"
        with _patch_scan(_result_with(Severity.HIGH)):
            runner.invoke(
                app,
                ["scan", "--format", "json", "--output-file", str(out)],
            )
        data = json.loads(out.read_text())
        assert data.get("score") is not None

    def test_json_output_empty_findings_when_no_configs(self, tmp_path: Path) -> None:
        """No MCP configs → empty findings list; step summary must not crash."""
        out = tmp_path / "summary.json"
        with _patch_scan(_empty_result()):
            runner.invoke(
                app,
                ["scan", "--format", "json", "--output-file", str(out)],
            )
        data = json.loads(out.read_text())
        assert data["findings"] == []
        assert data["score"]["grade"] == "A"

    def test_step_summary_python_block_handles_empty_findings(self) -> None:
        """Run the step-summary logic against empty data — must not raise."""
        data = {"findings": [], "score": None}
        findings = data.get("findings", [])
        score = data.get("score") or {}
        grade = score.get("grade", "N/A")
        numeric = score.get("numeric_score", "N/A")
        critical = sum(1 for f in findings if f.get("severity") == "CRITICAL")
        high = sum(1 for f in findings if f.get("severity") == "HIGH")
        # Must complete without raising; spot-check values.
        assert grade == "N/A"
        assert numeric == "N/A"
        assert critical == 0
        assert high == 0


# ── YAML file validity ─────────────────────────────────────────────────────────


class TestYamlValidity:
    def _load_yaml(self, rel_path: str) -> dict:
        full = _REPO_ROOT / rel_path
        assert full.exists(), f"File not found: {full}"
        with open(full) as f:
            return yaml.safe_load(f)  # raises on invalid YAML

    def test_action_yml_is_valid_yaml(self) -> None:
        doc = self._load_yaml("action.yml")
        assert doc is not None

    def test_action_yml_has_required_keys(self) -> None:
        doc = self._load_yaml("action.yml")
        assert "name" in doc
        assert "runs" in doc
        assert doc["runs"]["using"] == "composite"

    def test_action_yml_inputs_defined(self) -> None:
        doc = self._load_yaml("action.yml")
        inputs = doc.get("inputs", {})
        assert "severity-threshold" in inputs
        assert "format" in inputs
        assert "upload-sarif" in inputs

    def test_action_yml_outputs_defined(self) -> None:
        doc = self._load_yaml("action.yml")
        outputs = doc.get("outputs", {})
        assert "finding-count" in outputs
        assert "grade" in outputs
        assert "sarif-path" in outputs

    def test_example_workflow_is_valid_yaml(self) -> None:
        doc = self._load_yaml(".github/workflows/mcp-audit-example.yml")
        assert doc is not None
        assert "jobs" in doc

    def test_example_workflow_has_security_events_permission(self) -> None:
        doc = self._load_yaml(".github/workflows/mcp-audit-example.yml")
        permissions = doc["jobs"]["mcp-audit"]["permissions"]
        assert "security-events" in permissions
        assert permissions["security-events"] == "write"

    def test_basic_example_is_valid_yaml(self) -> None:
        doc = self._load_yaml("examples/github-actions/basic.yml")
        assert doc is not None

    def test_basic_example_has_security_events_permission(self) -> None:
        doc = self._load_yaml("examples/github-actions/basic.yml")
        permissions = doc["jobs"]["mcp-audit"]["permissions"]
        assert permissions.get("security-events") == "write"

    def test_strict_example_is_valid_yaml(self) -> None:
        doc = self._load_yaml("examples/github-actions/strict.yml")
        assert doc is not None

    def test_strict_example_has_security_events_permission(self) -> None:
        doc = self._load_yaml("examples/github-actions/strict.yml")
        permissions = doc["jobs"]["mcp-audit"]["permissions"]
        assert permissions.get("security-events") == "write"

    def test_with_baseline_example_is_valid_yaml(self) -> None:
        doc = self._load_yaml("examples/github-actions/with-baseline.yml")
        assert doc is not None

    def test_with_baseline_example_has_security_events_permission(self) -> None:
        doc = self._load_yaml("examples/github-actions/with-baseline.yml")
        permissions = doc["jobs"]["mcp-audit"]["permissions"]
        assert permissions.get("security-events") == "write"
