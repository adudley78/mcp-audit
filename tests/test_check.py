"""Tests for `mcp-audit check` command and CheckFormatter."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from mcp_audit.cli import app
from mcp_audit.models import (
    AttackPath,
    AttackPathSummary,
    Finding,
    ScanResult,
    ScanScore,
    Severity,
)
from mcp_audit.output.check import _remediation_hint, print_check_results

runner = CliRunner()

# ── Helpers ───────────────────────────────────────────────────────────────────


def _make_finding(
    finding_id: str = "TEST-001",
    severity: Severity = Severity.MEDIUM,
    title: str = "Test finding",
    remediation: str = "Fix it manually.",
    analyzer: str = "test",
) -> Finding:
    return Finding(
        id=finding_id,
        severity=severity,
        analyzer=analyzer,
        client="claude-desktop",
        server="test-server",
        title=title,
        description="A test finding.",
        evidence="some evidence",
        remediation=remediation,
    )


def _make_score(numeric: int = 85, grade: str = "B") -> ScanScore:
    return ScanScore(
        numeric_score=numeric,
        grade=grade,
        positive_signals=[],
        deductions=[],
    )


def _clean_result() -> ScanResult:
    result = ScanResult()
    result.clients_scanned = 1
    result.servers_found = 1
    result.score = _make_score(100, "A")
    return result


def _findings_result(
    findings: list[Finding],
    numeric: int = 61,
    grade: str = "C",
) -> ScanResult:
    result = ScanResult()
    result.clients_scanned = 1
    result.servers_found = 1
    result.findings = findings
    result.score = _make_score(numeric, grade)
    return result


# ── Unit tests: _remediation_hint ─────────────────────────────────────────────


class TestRemediationHint:
    def test_autofixable_cred001(self) -> None:
        f = _make_finding(finding_id="CRED-001")
        assert "mcp-audit fix --apply" in _remediation_hint(f)

    def test_autofixable_cred002(self) -> None:
        f = _make_finding(finding_id="CRED-002")
        assert "mcp-audit fix --apply" in _remediation_hint(f)

    def test_autofixable_transport001(self) -> None:
        f = _make_finding(finding_id="TRANSPORT-001")
        assert "mcp-audit fix --apply" in _remediation_hint(f)

    def test_autofixable_sc001(self) -> None:
        f = _make_finding(finding_id="SC-001")
        assert "mcp-audit fix --apply" in _remediation_hint(f)

    def test_autofixable_sc002(self) -> None:
        f = _make_finding(finding_id="SC-002")
        assert "mcp-audit fix --apply" in _remediation_hint(f)

    def test_poison_finding_non_fixable(self) -> None:
        f = _make_finding(finding_id="POISON-001")
        hint = _remediation_hint(f)
        assert "mcp-audit fix --apply" not in hint
        assert len(hint) > 10

    def test_transport002_non_fixable(self) -> None:
        f = _make_finding(finding_id="TRANSPORT-002")
        hint = _remediation_hint(f)
        assert "127.0.0.1" in hint.lower() or "localhost" in hint.lower()

    def test_cfhyg001_pin_instruction(self) -> None:
        f = _make_finding(finding_id="CFHYG-001")
        hint = _remediation_hint(f)
        assert "pin" in hint.lower() or "version" in hint.lower()

    def test_unknown_id_falls_back_to_remediation_text(self) -> None:
        f = _make_finding(
            finding_id="UNKWN-999",
            remediation="Do something specific. And then something else.",
        )
        hint = _remediation_hint(f)
        assert "Do something specific" in hint

    def test_drift_prefix_match(self) -> None:
        f = _make_finding(finding_id="DRIFT-001")
        assert "baseline" in _remediation_hint(f).lower()

    def test_attest_prefix_match(self) -> None:
        f = _make_finding(finding_id="ATTEST-001")
        hint = _remediation_hint(f)
        assert "hash" in hint.lower() or "verified" in hint.lower()


# ── Unit tests: print_check_results ───────────────────────────────────────────


class TestPrintCheckResults:
    def test_grade_a_no_findings(self) -> None:
        from io import StringIO

        from rich.console import Console

        buf = StringIO()
        con = Console(file=buf, width=80)
        print_check_results(_clean_result(), console=con)
        out = buf.getvalue()
        assert "No issues found" in out
        assert "Grade: A" in out

    def test_grade_c_findings_shown(self) -> None:
        from io import StringIO

        from rich.console import Console

        findings = [
            _make_finding(
                finding_id="TRANSPORT-001",
                severity=Severity.HIGH,
                title="HTTP used",
            )
        ]
        result = _findings_result(findings, numeric=61, grade="C")
        buf = StringIO()
        con = Console(file=buf, width=80)
        print_check_results(result, console=con)
        out = buf.getvalue()
        assert "Grade: C" in out
        assert "HTTP used" in out

    def test_max_5_findings_shown(self) -> None:
        from io import StringIO

        from rich.console import Console

        findings = [
            _make_finding(finding_id=f"TEST-{i:03d}", title=f"Issue {i}")
            for i in range(10)
        ]
        result = _findings_result(findings, numeric=10, grade="F")
        buf = StringIO()
        con = Console(file=buf, width=80)
        print_check_results(result, console=con)
        out = buf.getvalue()
        assert "5 more" in out or "and 5 more" in out
        assert "\n  6." not in out

    def test_attack_path_line_grade_f(self) -> None:
        from io import StringIO

        from rich.console import Console

        findings = [_make_finding(finding_id="TOXIC-001", severity=Severity.CRITICAL)]
        result = _findings_result(findings, numeric=0, grade="F")
        result.attack_path_summary = AttackPathSummary(
            paths=[
                AttackPath(
                    id="PATH-001",
                    severity=Severity.CRITICAL,
                    title="File exfil via network",
                    description="Attacker can exfiltrate files.",
                    hops=["filesystem", "fetch"],
                    source_capability="file_read",
                    sink_capability="network_out",
                )
            ],
            hitting_set=["filesystem"],
        )
        buf = StringIO()
        con = Console(file=buf, width=80)
        print_check_results(result, console=con)
        assert "attack path" in buf.getvalue().lower()

    def test_attack_path_line_not_shown_for_grade_c(self) -> None:
        from io import StringIO

        from rich.console import Console

        findings = [_make_finding(finding_id="TOXIC-001", severity=Severity.HIGH)]
        result = _findings_result(findings, numeric=61, grade="C")
        result.attack_path_summary = AttackPathSummary(
            paths=[
                AttackPath(
                    id="PATH-001",
                    severity=Severity.HIGH,
                    title="Some path",
                    description="...",
                    hops=["a", "b"],
                    source_capability="x",
                    sink_capability="y",
                )
            ],
            hitting_set=["a"],
        )
        buf = StringIO()
        con = Console(file=buf, width=80)
        print_check_results(result, console=con)
        assert "⛔" not in buf.getvalue()

    def test_autofixable_summary_line(self) -> None:
        from io import StringIO

        from rich.console import Console

        findings = [
            _make_finding(
                finding_id="CRED-001",
                severity=Severity.CRITICAL,
                title="Exposed key",
            ),
            _make_finding(
                finding_id="TRANSPORT-001",
                severity=Severity.HIGH,
                title="No TLS",
            ),
        ]
        result = _findings_result(findings, numeric=40, grade="D")
        buf = StringIO()
        con = Console(file=buf, width=80)
        print_check_results(result, console=con)
        output = buf.getvalue()
        assert "mcp-audit fix --apply" in output
        # Both auto-fixable IDs must appear in the nudge line
        assert "CRED-001" in output
        assert "TRANSPORT-001" in output
        assert "auto-remediate" in output

    def test_no_autofix_summary_when_none_fixable(self) -> None:
        from io import StringIO

        from rich.console import Console

        findings = [_make_finding(finding_id="POISON-001", severity=Severity.HIGH)]
        result = _findings_result(findings, numeric=55, grade="C")
        buf = StringIO()
        con = Console(file=buf, width=80)
        print_check_results(result, console=con)
        assert "auto-remediate" not in buf.getvalue()

    def test_footer_shown(self) -> None:
        from io import StringIO

        from rich.console import Console

        findings = [_make_finding(finding_id="TEST-001", severity=Severity.MEDIUM)]
        result = _findings_result(findings)
        buf = StringIO()
        con = Console(file=buf, width=80)
        print_check_results(result, console=con)
        assert "mcp-audit scan" in buf.getvalue()

    def test_severity_sorted_critical_first(self) -> None:
        from io import StringIO

        from rich.console import Console

        findings = [
            _make_finding(
                finding_id="LOW-001",
                severity=Severity.LOW,
                title="Low finding",
            ),
            _make_finding(
                finding_id="CRIT-001",
                severity=Severity.CRITICAL,
                title="Critical finding",
            ),
            _make_finding(
                finding_id="MED-001",
                severity=Severity.MEDIUM,
                title="Medium finding",
            ),
        ]
        result = _findings_result(findings, numeric=10, grade="F")
        buf = StringIO()
        con = Console(file=buf, width=80)
        print_check_results(result, console=con)
        out = buf.getvalue()
        assert out.index("Critical finding") < out.index("Medium finding")
        assert out.index("Medium finding") < out.index("Low finding")


# ── CLI integration tests ──────────────────────────────────────────────────────


class TestCheckCommand:
    def _patch_run_scan(self, result: ScanResult):
        return patch("mcp_audit.cli.check.run_scan", return_value=result)

    def test_grade_a_exit_0(self) -> None:
        with self._patch_run_scan(_clean_result()):
            r = runner.invoke(app, ["check"])
        assert r.exit_code == 0
        assert "No issues found" in r.output

    def test_grade_c_exit_1(self) -> None:
        findings = [_make_finding(finding_id="TRANSPORT-001", severity=Severity.HIGH)]
        result = _findings_result(findings, numeric=61, grade="C")
        with self._patch_run_scan(result):
            r = runner.invoke(app, ["check"])
        assert r.exit_code == 1

    def test_critical_finding_exit_1_even_with_high_score(self) -> None:
        findings = [_make_finding(finding_id="CRED-001", severity=Severity.CRITICAL)]
        # Score is technically >=70 but CRITICAL present → exit 1
        result = _findings_result(findings, numeric=75, grade="B")
        with self._patch_run_scan(result):
            r = runner.invoke(app, ["check"])
        assert r.exit_code == 1

    def test_grade_b_no_critical_exit_0(self) -> None:
        findings = [_make_finding(finding_id="CFHYG-001", severity=Severity.MEDIUM)]
        result = _findings_result(findings, numeric=75, grade="B")
        with self._patch_run_scan(result):
            r = runner.invoke(app, ["check"])
        assert r.exit_code == 0

    def test_grade_f_attack_path_message(self) -> None:
        findings = [_make_finding(finding_id="TOXIC-001", severity=Severity.CRITICAL)]
        result = _findings_result(findings, numeric=0, grade="F")
        result.attack_path_summary = AttackPathSummary(
            paths=[
                AttackPath(
                    id="PATH-001",
                    severity=Severity.CRITICAL,
                    title="Exfil path",
                    description="...",
                    hops=["a", "b"],
                    source_capability="x",
                    sink_capability="y",
                )
            ],
            hitting_set=["a"],
        )
        with self._patch_run_scan(result):
            r = runner.invoke(app, ["check"])
        assert r.exit_code == 1
        assert "attack path" in r.output.lower()

    def test_max_5_findings_shown_cli(self) -> None:
        findings = [
            _make_finding(
                finding_id=f"TEST-{i:03d}",
                severity=Severity.MEDIUM,
                title=f"Issue {i}",
            )
            for i in range(10)
        ]
        result = _findings_result(findings, numeric=10, grade="F")
        with self._patch_run_scan(result):
            r = runner.invoke(app, ["check"])
        assert r.exit_code == 1
        assert "5 more" in r.output or "and 5 more" in r.output

    def test_autofixable_hint_in_output(self) -> None:
        findings = [
            _make_finding(
                finding_id="CRED-001",
                severity=Severity.CRITICAL,
                title="Exposed key",
            )
        ]
        result = _findings_result(findings, numeric=40, grade="D")
        with self._patch_run_scan(result):
            r = runner.invoke(app, ["check"])
        assert "mcp-audit fix --apply" in r.output

    def test_non_fixable_hint_specific(self) -> None:
        findings = [
            _make_finding(
                finding_id="POISON-001",
                severity=Severity.HIGH,
                title="Prompt injection in tool description",
            )
        ]
        result = _findings_result(findings, numeric=55, grade="C")
        with self._patch_run_scan(result):
            r = runner.invoke(app, ["check"])
        assert "mcp-audit fix --apply" not in r.output
        out_lower = r.output.lower()
        assert (
            "tool description" in out_lower
            or "sanitise" in out_lower
            or "remove" in out_lower
        )

    def test_no_configs_found_exit_0(self) -> None:
        empty = ScanResult()
        empty.clients_scanned = 0
        empty.servers_found = 0
        with self._patch_run_scan(empty):
            r = runner.invoke(app, ["check"])
        assert r.exit_code == 0
        assert "No MCP config files found" in r.output

    def test_verbose_flag_uses_full_output(self) -> None:
        findings = [_make_finding(finding_id="CRED-001", severity=Severity.HIGH)]
        result = _findings_result(findings, numeric=55, grade="C")
        with (
            self._patch_run_scan(result),
            patch("mcp_audit.cli.check.print_results") as mock_print,
            patch("mcp_audit.cli.check.print_check_results") as mock_check,
        ):
            runner.invoke(app, ["check", "--verbose"])
        mock_print.assert_called_once()
        mock_check.assert_not_called()

    def test_json_flag_outputs_json(self) -> None:
        with self._patch_run_scan(_clean_result()):
            r = runner.invoke(app, ["check", "--json"])
        assert r.exit_code == 0
        parsed = json.loads(r.output)
        assert "score" in parsed or "findings" in parsed

    def test_json_flag_no_rich_formatting(self) -> None:
        with self._patch_run_scan(_clean_result()):
            r = runner.invoke(app, ["check", "--json"])
        assert "Grade:" not in r.output
        assert "Security Check" not in r.output

    def test_path_flag_passed_to_run_scan(self, tmp_path: Path) -> None:
        config = tmp_path / "custom.json"
        config.write_text('{"mcpServers": {}}')
        with self._patch_run_scan(_clean_result()) as mock_scan:
            runner.invoke(app, ["check", "--path", str(config)])
        mock_scan.assert_called_once()
        call_kwargs = mock_scan.call_args
        extra = call_kwargs.kwargs.get("extra_paths")
        assert extra is not None
        assert config in extra or str(config) in [str(p) for p in extra]

    def test_positional_path_passed_to_run_scan(self, tmp_path: Path) -> None:
        """Positional config arg is forwarded to run_scan as extra_paths."""
        config = tmp_path / "custom.json"
        config.write_text('{"mcpServers": {}}')
        with self._patch_run_scan(_clean_result()) as mock_scan:
            runner.invoke(app, ["check", str(config)])
        mock_scan.assert_called_once()
        extra = mock_scan.call_args.kwargs.get("extra_paths")
        assert extra is not None
        assert config in extra or str(config) in [str(p) for p in extra]

    def test_positional_and_path_flag_both_given_exit_2(self, tmp_path: Path) -> None:
        """Supplying both a positional path and --path is an error."""
        config = tmp_path / "custom.json"
        config.write_text('{"mcpServers": {}}')
        r = runner.invoke(app, ["check", str(config), "--path", str(config)])
        assert r.exit_code == 2
        assert (
            "not both" in r.output
            or "positional" in r.output.lower()
            or "both" in r.output.lower()
        )

    def test_positional_invalid_path_exit_2(self) -> None:
        """A nonexistent positional path produces exit code 2."""
        r = runner.invoke(app, ["check", "/nonexistent/path/config.json"])
        assert r.exit_code == 2
        assert "not found" in r.output.lower()

    def test_invalid_path_exit_2(self) -> None:
        r = runner.invoke(app, ["check", "--path", "/nonexistent/path/config.json"])
        assert r.exit_code == 2
        assert "File not found" in r.output or "not found" in r.output.lower()

    def test_scan_exception_exit_2(self) -> None:
        with patch("mcp_audit.cli.check.run_scan", side_effect=RuntimeError("boom")):
            r = runner.invoke(app, ["check"])
        assert r.exit_code == 2
        assert "Scan error" in r.output

    def test_low_severity_findings_shown(self) -> None:
        """Low/INFO findings are shown — no severity floor."""
        findings = [
            _make_finding(
                finding_id="CFHYG-001",
                severity=Severity.LOW,
                title="Unpinned package",
            )
        ]
        result = _findings_result(findings, numeric=88, grade="B")
        with self._patch_run_scan(result):
            r = runner.invoke(app, ["check"])
        assert "Unpinned package" in r.output

    def test_remainder_footer_with_many_findings(self) -> None:
        findings = [
            _make_finding(
                finding_id=f"CFHYG-{i:03d}",
                severity=Severity.LOW,
                title=f"Issue {i}",
            )
            for i in range(8)
        ]
        result = _findings_result(findings, numeric=68, grade="C")
        with self._patch_run_scan(result):
            r = runner.invoke(app, ["check"])
        assert "3 more" in r.output or "and 3 more" in r.output

    def test_exactly_5_findings_no_remainder(self) -> None:
        findings = [
            _make_finding(
                finding_id=f"CFHYG-{i:03d}",
                severity=Severity.MEDIUM,
                title=f"Issue {i}",
            )
            for i in range(5)
        ]
        result = _findings_result(findings, numeric=70, grade="B")
        with self._patch_run_scan(result):
            r = runner.invoke(app, ["check"])
        assert "more" not in r.output or "mcp-audit scan" in r.output
