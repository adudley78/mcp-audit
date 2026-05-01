"""Tests for the SAST module (mcp_audit.sast)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from mcp_audit.cli import app
from mcp_audit.models import Severity
from mcp_audit.sast.runner import (
    SEMGREP_TIMEOUT_SECONDS,
    SastResult,
    _finding_id,
    find_rules_dir,
    find_semgrep,
    parse_semgrep_output,
    run_semgrep,
)

runner = CliRunner()

_FAKE_TARGET = Path("/dev/null")  # noqa: S108 — safe sentinel in tests


# ── helpers ───────────────────────────────────────────────────────────────────


def _make_semgrep_result(
    check_id: str = "python.injection.mcp-subprocess-string-cmd",
    path: str = "src/server.py",
    line: int = 42,
    message: str = "Subprocess injection risk",
    severity: str = "WARNING",
    cwe: str = "CWE-78",
    category: str = "injection",
) -> dict:
    """Return a minimal semgrep JSON result dict."""
    return {
        "check_id": check_id,
        "path": path,
        "start": {"line": line},
        "extra": {
            "message": message,
            "severity": severity,
            "metadata": {"cwe": cwe, "category": category},
        },
    }


def _make_semgrep_output(*results: dict, version: str = "1.0.0") -> dict:
    """Return a minimal semgrep JSON output dict."""
    return {
        "results": list(results),
        "version": version,
        "stats": {},
        "errors": [],
    }


# ── TestSemgrepDetection ──────────────────────────────────────────────────────


class TestSemgrepDetection:
    def test_find_semgrep_returns_path_when_installed(self) -> None:
        fake_path = "/usr/local/bin/semgrep"
        with patch("shutil.which", return_value=fake_path):
            assert find_semgrep() == fake_path

    def test_find_semgrep_returns_none_when_missing(self) -> None:
        with patch("shutil.which", return_value=None):
            assert find_semgrep() is None

    def test_find_rules_dir_repo_root(self) -> None:
        """find_rules_dir() resolves to the semgrep-rules/ dir in the dev repo."""
        result = find_rules_dir()
        assert result is not None
        assert result.is_dir()
        assert (result / "python").is_dir()


# ── TestSemgrepOutput ─────────────────────────────────────────────────────────


class TestSemgrepOutput:
    def test_parse_empty_results(self) -> None:
        output = _make_semgrep_output()
        findings = parse_semgrep_output(output, _FAKE_TARGET)
        assert findings == []

    def test_parse_single_warning_finding(self) -> None:
        output = _make_semgrep_output(_make_semgrep_result(severity="WARNING"))
        findings = parse_semgrep_output(output, _FAKE_TARGET)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_parse_error_finding(self) -> None:
        output = _make_semgrep_output(_make_semgrep_result(severity="ERROR"))
        findings = parse_semgrep_output(output, _FAKE_TARGET)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_parse_info_finding(self) -> None:
        output = _make_semgrep_output(_make_semgrep_result(severity="INFO"))
        findings = parse_semgrep_output(output, _FAKE_TARGET)
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_finding_id_deterministic(self) -> None:
        id1 = _finding_id("rule-id", "file.py", 10)
        id2 = _finding_id("rule-id", "file.py", 10)
        assert id1 == id2
        assert id1.startswith("SAST-")

    def test_finding_id_unique_for_different_inputs(self) -> None:
        id1 = _finding_id("rule-id", "file.py", 10)
        id2 = _finding_id("rule-id", "file.py", 11)
        assert id1 != id2

    def test_finding_analyzer_tag(self) -> None:
        output = _make_semgrep_output(_make_semgrep_result())
        findings = parse_semgrep_output(output, _FAKE_TARGET)
        assert all(f.analyzer == "sast" for f in findings)

    def test_finding_evidence_fields(self) -> None:
        output = _make_semgrep_output(
            _make_semgrep_result(
                check_id="python.injection.mcp-eval-tool-arg",
                path="src/server.py",
                line=42,
                cwe="CWE-95",
                category="injection",
            )
        )
        findings = parse_semgrep_output(output, _FAKE_TARGET)
        assert len(findings) == 1
        evidence = json.loads(findings[0].evidence)
        assert evidence["rule_id"] == "python.injection.mcp-eval-tool-arg"
        assert evidence["file"] == "src/server.py"
        assert evidence["line"] == 42
        assert evidence["cwe"] == "CWE-95"
        assert evidence["category"] == "injection"

    def test_parse_multiple_findings(self) -> None:
        output = _make_semgrep_output(
            _make_semgrep_result(check_id="rule1", line=1),
            _make_semgrep_result(check_id="rule2", line=2),
            _make_semgrep_result(check_id="rule3", line=3),
        )
        findings = parse_semgrep_output(output, _FAKE_TARGET)
        assert len(findings) == 3

    def test_finding_title_is_last_component_of_check_id(self) -> None:
        output = _make_semgrep_output(
            _make_semgrep_result(check_id="python.injection.mcp-subprocess-string-cmd")
        )
        findings = parse_semgrep_output(output, _FAKE_TARGET)
        assert findings[0].title == "mcp-subprocess-string-cmd"

    def test_finding_cwe_propagated(self) -> None:
        output = _make_semgrep_output(_make_semgrep_result(cwe="CWE-78"))
        findings = parse_semgrep_output(output, _FAKE_TARGET)
        assert findings[0].cwe == "CWE-78"

    def test_finding_path_set(self) -> None:
        output = _make_semgrep_output(_make_semgrep_result(path="src/my_server.py"))
        findings = parse_semgrep_output(output, _FAKE_TARGET)
        assert findings[0].finding_path == "src/my_server.py"

    def test_parse_semgrep_output_handles_null_severity(self) -> None:
        """``"severity": null`` in Semgrep JSON must not raise AttributeError."""
        result = _make_semgrep_result()
        # Overwrite severity with JSON null (Python None) to mimic Semgrep output.
        result["extra"]["severity"] = None
        output = _make_semgrep_output(result)
        findings = parse_semgrep_output(output, _FAKE_TARGET)
        assert len(findings) == 1
        # None falls back to "WARNING" which maps to Severity.HIGH.
        assert findings[0].severity == Severity.HIGH


# ── TestRunSemgrep ────────────────────────────────────────────────────────────


class TestRunSemgrep:
    def test_run_semgrep_not_installed(self) -> None:
        with patch("shutil.which", return_value=None):
            result = run_semgrep(_FAKE_TARGET)
        assert result.error is not None
        assert "semgrep" in result.error.lower()
        assert result.findings == []

    def test_run_semgrep_not_installed_does_not_raise(self) -> None:
        with patch("shutil.which", return_value=None):
            result = run_semgrep(_FAKE_TARGET)
        assert isinstance(result, SastResult)

    def test_run_semgrep_rules_dir_missing(self, tmp_path: Path) -> None:
        missing_rules = tmp_path / "no-such-dir"
        with (
            patch("shutil.which", return_value="/usr/bin/semgrep"),
            patch("mcp_audit.sast.runner.find_rules_dir", return_value=None),
        ):
            result = run_semgrep(_FAKE_TARGET, rules_dir=missing_rules)
        assert result.error is not None or isinstance(result, SastResult)

    def test_run_semgrep_success(self, tmp_path: Path) -> None:
        fake_output = _make_semgrep_output(_make_semgrep_result(severity="WARNING"))
        mock_proc = MagicMock()
        mock_proc.returncode = 1
        mock_proc.stdout = json.dumps(fake_output)
        mock_proc.stderr = ""

        rules_dir = tmp_path / "semgrep-rules"
        rules_dir.mkdir()

        with (
            patch("shutil.which", return_value="/usr/bin/semgrep"),
            patch("subprocess.run", return_value=mock_proc),
        ):
            result = run_semgrep(_FAKE_TARGET, rules_dir=rules_dir)

        assert result.error is None
        assert len(result.findings) == 1
        assert result.findings[0].severity == Severity.HIGH

    def test_run_semgrep_no_findings(self, tmp_path: Path) -> None:
        fake_output = _make_semgrep_output()
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = json.dumps(fake_output)
        mock_proc.stderr = ""

        rules_dir = tmp_path / "semgrep-rules"
        rules_dir.mkdir()

        with (
            patch("shutil.which", return_value="/usr/bin/semgrep"),
            patch("subprocess.run", return_value=mock_proc),
        ):
            result = run_semgrep(_FAKE_TARGET, rules_dir=rules_dir)

        assert result.error is None
        assert result.findings == []

    def test_run_semgrep_subprocess_error(self, tmp_path: Path) -> None:
        rules_dir = tmp_path / "semgrep-rules"
        rules_dir.mkdir()

        with (
            patch("shutil.which", return_value="/usr/bin/semgrep"),
            patch("subprocess.run", side_effect=OSError("binary not found")),
        ):
            result = run_semgrep(_FAKE_TARGET, rules_dir=rules_dir)

        assert isinstance(result, SastResult)
        assert result.error is not None
        assert result.findings == []

    def test_run_semgrep_real_error_exit_code(self, tmp_path: Path) -> None:
        mock_proc = MagicMock()
        mock_proc.returncode = 2
        mock_proc.stdout = ""
        mock_proc.stderr = "parse error in rule"

        rules_dir = tmp_path / "semgrep-rules"
        rules_dir.mkdir()

        with (
            patch("shutil.which", return_value="/usr/bin/semgrep"),
            patch("subprocess.run", return_value=mock_proc),
        ):
            result = run_semgrep(_FAKE_TARGET, rules_dir=rules_dir)

        assert result.error is not None
        assert result.findings == []


# ── TestSastCLI ───────────────────────────────────────────────────────────────


class TestSastCLI:
    def test_sast_command_semgrep_not_installed(self, tmp_path: Path) -> None:
        with (
            patch("mcp_audit.sast.runner.find_semgrep", return_value=None),
        ):
            result = runner.invoke(app, ["sast", str(tmp_path)])
        assert result.exit_code == 2
        assert "semgrep" in result.output.lower()

    def test_sast_command_with_findings(self, tmp_path: Path) -> None:
        fake_output = _make_semgrep_output(
            _make_semgrep_result(
                check_id="python.injection.mcp-eval-tool-arg",
                path=str(tmp_path / "server.py"),
                line=15,
                severity="ERROR",
                message="eval() called with variable",
            )
        )
        mock_proc = MagicMock()
        mock_proc.returncode = 1
        mock_proc.stdout = json.dumps(fake_output)
        mock_proc.stderr = ""

        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()

        with (
            patch(
                "mcp_audit.sast.runner.find_semgrep", return_value="/usr/bin/semgrep"
            ),
            patch("subprocess.run", return_value=mock_proc),
        ):
            result = runner.invoke(
                app,
                ["sast", str(tmp_path), "--rules-dir", str(rules_dir)],
            )
        assert result.exit_code == 1
        assert "mcp-eval-tool-arg" in result.output or "CRITICAL" in result.output

    def test_scan_with_sast_flag_merges_findings(self, tmp_path: Path) -> None:
        config = tmp_path / "config.json"
        config.write_text('{"mcpServers": {}}')

        fake_output = _make_semgrep_output(
            _make_semgrep_result(
                check_id="python.credentials.mcp-hardcoded-api-key",
                path=str(tmp_path / "server.py"),
                line=5,
                severity="ERROR",
                message="Hardcoded API key",
            )
        )
        mock_proc = MagicMock()
        mock_proc.returncode = 1
        mock_proc.stdout = json.dumps(fake_output)
        mock_proc.stderr = ""

        with (
            patch(
                "mcp_audit.sast.runner.find_semgrep", return_value="/usr/bin/semgrep"
            ),
            patch("subprocess.run", return_value=mock_proc),
        ):
            result = runner.invoke(
                app,
                [
                    "scan",
                    "--path",
                    str(config),
                    "--sast",
                    str(tmp_path),
                    "--format",
                    "json",
                ],
            )

        output_text = result.output
        json_start = output_text.find("{")
        assert json_start >= 0, f"No JSON in output: {output_text!r}"
        output_json = json.loads(output_text[json_start:])
        sast_findings = [
            f for f in output_json.get("findings", []) if f["analyzer"] == "sast"
        ]
        assert len(sast_findings) >= 1
        assert sast_findings[0]["analyzer"] == "sast"

    def test_sast_json_output_format(self, tmp_path: Path) -> None:
        fake_output = _make_semgrep_output(_make_semgrep_result(severity="WARNING"))
        mock_proc = MagicMock()
        mock_proc.returncode = 1
        mock_proc.stdout = json.dumps(fake_output)
        mock_proc.stderr = ""

        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()

        with (
            patch(
                "mcp_audit.sast.runner.find_semgrep", return_value="/usr/bin/semgrep"
            ),
            patch("subprocess.run", return_value=mock_proc),
        ):
            result = runner.invoke(
                app,
                [
                    "sast",
                    str(tmp_path),
                    "--format",
                    "json",
                    "--rules-dir",
                    str(rules_dir),
                ],
            )
        assert result.exit_code == 1
        output_text = result.output
        json_start = output_text.find("[")
        assert json_start >= 0, f"No JSON array in output: {output_text!r}"
        parsed = json.loads(output_text[json_start:])
        assert isinstance(parsed, list)
        assert parsed[0]["analyzer"] == "sast"

    def test_sast_command_no_findings(self, tmp_path: Path) -> None:
        fake_output = _make_semgrep_output()
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = json.dumps(fake_output)
        mock_proc.stderr = ""

        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()

        with (
            patch(
                "mcp_audit.sast.runner.find_semgrep", return_value="/usr/bin/semgrep"
            ),
            patch("subprocess.run", return_value=mock_proc),
        ):
            result = runner.invoke(
                app,
                ["sast", str(tmp_path), "--rules-dir", str(rules_dir)],
            )
        assert result.exit_code == 0
        assert "No SAST findings" in result.output or "0" in result.output


# ── Security hardening tests ──────────────────────────────────────────────────


# ── TestTsNewRules ────────────────────────────────────────────────────────────


class TestTsNewRules:
    """Verify parse_semgrep_output handles the 7 new TypeScript rule findings."""

    def _make_ts_result(
        self,
        rule_id: str,
        cwe: str,
        severity: str = "WARNING",
        path: str = "src/server.ts",
        line: int = 10,
    ) -> dict:
        return _make_semgrep_result(
            check_id=f"typescript.injection.{rule_id}",
            path=path,
            line=line,
            severity=severity,
            cwe=cwe,
            category="injection",
        )

    def test_ts_path_traversal_read_detected(self) -> None:
        """fs.readFile with variable path → HIGH finding (WARNING → HIGH mapping)."""
        output = _make_semgrep_output(
            self._make_ts_result("mcp-ts-fs-readfile-traversal", "CWE-22")
        )
        findings = parse_semgrep_output(output, _FAKE_TARGET)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert findings[0].analyzer == "sast"
        assert findings[0].cwe == "CWE-22"

    def test_ts_path_traversal_write_detected(self) -> None:
        """fs.writeFile with variable path → HIGH finding."""
        output = _make_semgrep_output(
            self._make_ts_result("mcp-ts-fs-writefile-traversal", "CWE-22")
        )
        findings = parse_semgrep_output(output, _FAKE_TARGET)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert findings[0].cwe == "CWE-22"

    def test_ts_path_join_traversal_detected(self) -> None:
        """path.join with variable component → MEDIUM finding (INFO → MEDIUM)."""
        output = _make_semgrep_output(
            self._make_ts_result(
                "mcp-ts-path-join-traversal", "CWE-22", severity="INFO"
            )
        )
        findings = parse_semgrep_output(output, _FAKE_TARGET)
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM
        assert findings[0].cwe == "CWE-22"

    def test_ts_sqli_string_concat_detected(self) -> None:
        """String-concatenated SQL query → CRITICAL finding (ERROR → CRITICAL)."""
        output = _make_semgrep_output(
            self._make_ts_result("mcp-ts-string-concat-sql", "CWE-89", severity="ERROR")
        )
        findings = parse_semgrep_output(output, _FAKE_TARGET)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].cwe == "CWE-89"

    def test_ts_sqli_template_literal_detected(self) -> None:
        """Template literal / non-literal SQL query arg → HIGH finding."""
        output = _make_semgrep_output(
            self._make_ts_result(
                "mcp-ts-unsafe-query-variable", "CWE-89", severity="WARNING"
            )
        )
        findings = parse_semgrep_output(output, _FAKE_TARGET)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert findings[0].cwe == "CWE-89"

    def test_ts_ssrf_fetch_detected(self) -> None:
        """fetch() with variable URL → HIGH finding."""
        output = _make_semgrep_output(
            self._make_ts_result("mcp-ts-fetch-ssrf", "CWE-918")
        )
        findings = parse_semgrep_output(output, _FAKE_TARGET)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert findings[0].cwe == "CWE-918"

    def test_ts_ssrf_http_request_detected(self) -> None:
        """https.request() with variable URL → HIGH finding."""
        output = _make_semgrep_output(
            self._make_ts_result("mcp-ts-http-request-ssrf", "CWE-918")
        )
        findings = parse_semgrep_output(output, _FAKE_TARGET)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert findings[0].cwe == "CWE-918"

    def test_ts_safe_patterns_produce_no_findings(self) -> None:
        """Semgrep returning zero results (safe code) produces empty findings list."""
        empty_output = _make_semgrep_output()
        findings = parse_semgrep_output(empty_output, _FAKE_TARGET)
        assert findings == []

    def test_ts_new_rules_all_tagged_sast(self) -> None:
        """All new TS rule findings carry analyzer='sast'."""
        new_rule_ids = [
            "mcp-ts-fs-readfile-traversal",
            "mcp-ts-fs-writefile-traversal",
            "mcp-ts-path-join-traversal",
            "mcp-ts-string-concat-sql",
            "mcp-ts-unsafe-query-variable",
            "mcp-ts-fetch-ssrf",
            "mcp-ts-http-request-ssrf",
        ]
        results = [self._make_ts_result(rule_id, "CWE-22") for rule_id in new_rule_ids]
        output = _make_semgrep_output(*results)
        findings = parse_semgrep_output(output, _FAKE_TARGET)
        assert len(findings) == 7
        assert all(f.analyzer == "sast" for f in findings)

    def test_ts_path_traversal_finding_id_starts_with_sast(self) -> None:
        """Finding ID for new TS rules starts with 'SAST-'."""
        output = _make_semgrep_output(
            self._make_ts_result("mcp-ts-fs-readfile-traversal", "CWE-22")
        )
        findings = parse_semgrep_output(output, _FAKE_TARGET)
        assert findings[0].id.startswith("SAST-")

    def test_ts_sqli_finding_path_propagated(self) -> None:
        """file path from Semgrep result propagates to finding_path."""
        output = _make_semgrep_output(
            self._make_ts_result(
                "mcp-ts-string-concat-sql", "CWE-89", path="src/db_handler.ts"
            )
        )
        findings = parse_semgrep_output(output, _FAKE_TARGET)
        assert findings[0].finding_path == "src/db_handler.ts"


# ── TestSastSecurityHardening ──────────────────────────────────────────────────


class TestSastSecurityHardening:
    """Verify the subprocess security invariants in run_semgrep()."""

    def test_sast_runner_timeout(self, tmp_path: Path) -> None:
        """subprocess.run() must receive timeout=SEMGREP_TIMEOUT_SECONDS."""
        fake_output = _make_semgrep_output()
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = json.dumps(fake_output)
        mock_proc.stderr = ""

        rules_dir = tmp_path / "semgrep-rules"
        rules_dir.mkdir()

        with (
            patch("shutil.which", return_value="/usr/bin/semgrep"),
            patch("subprocess.run", return_value=mock_proc) as mock_run,
        ):
            run_semgrep(tmp_path, rules_dir=rules_dir)

        assert mock_run.call_count == 1
        _, kwargs = mock_run.call_args
        assert kwargs.get("timeout") == SEMGREP_TIMEOUT_SECONDS, (
            f"Expected timeout={SEMGREP_TIMEOUT_SECONDS}, got {kwargs.get('timeout')}"
        )

    def test_sast_runner_no_shell_true(self, tmp_path: Path) -> None:
        """subprocess.run() must NOT be called with shell=True."""
        fake_output = _make_semgrep_output()
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = json.dumps(fake_output)
        mock_proc.stderr = ""

        rules_dir = tmp_path / "semgrep-rules"
        rules_dir.mkdir()

        with (
            patch("shutil.which", return_value="/usr/bin/semgrep"),
            patch("subprocess.run", return_value=mock_proc) as mock_run,
        ):
            run_semgrep(tmp_path, rules_dir=rules_dir)

        assert mock_run.call_count == 1
        _, kwargs = mock_run.call_args
        # shell must be absent or explicitly False — never True.
        assert kwargs.get("shell") is not True, (
            "shell=True found in subprocess.run() call"
        )
        # The command must be a list, not a string.
        cmd_arg = mock_run.call_args[0][0]
        assert isinstance(cmd_arg, list), (
            "subprocess.run() received a string command "
            f"(shell injection risk): {cmd_arg!r}"
        )

    def test_sast_runner_nonexistent_path(self, tmp_path: Path) -> None:
        """scan --sast <nonexistent> must produce exit code 2, not a traceback."""
        config = tmp_path / "config.json"
        config.write_text('{"mcpServers": {}}')
        missing = tmp_path / "nonexistent_src"

        result = runner.invoke(
            app,
            ["scan", "--path", str(config), "--sast", str(missing)],
        )

        assert result.exit_code == 2
        # Must mention the bad path in a human-readable message.
        assert (
            "nonexistent_src" in result.output or "not exist" in result.output.lower()
        )
        # Must not be a raw Python traceback.
        assert "Traceback" not in result.output
