"""Tests for the push-nucleus CLI command.

Covers: CLI registration, Enterprise gate, API key resolution, successful push,
job ERROR handling, poll timeout, --output-file, and severity threshold filtering.

All HTTP calls are mocked — no real network requests are made.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import typer
from typer.testing import CliRunner

from mcp_audit.cli import app
from mcp_audit.models import Finding, MachineInfo, ScanResult, Severity

runner = CliRunner()

# ── Fixtures ──────────────────────────────────────────────────────────────────

_NUCLEUS_URL = "https://nucleus.example.com"
_PROJECT_ID = "42"
_API_KEY = "test-api-key"


def _make_finding(severity: Severity = Severity.HIGH, idx: int = 1) -> Finding:
    """Build a minimal Finding for test use."""
    return Finding(
        id=f"TEST-{idx:03d}",
        severity=severity,
        analyzer="credentials",
        client="claude",
        server="test-server",
        title=f"Test finding {idx}",
        description="A test finding description.",
        evidence="evidence-string",
        remediation="Fix it.",
    )


def _make_result(findings: list[Finding] | None = None) -> ScanResult:
    """Build a minimal ScanResult for test use."""
    return ScanResult(
        version="0.1.0",
        timestamp=datetime.now(UTC),
        machine=MachineInfo(
            hostname="test-host",
            username="testuser",
            os="Darwin",
            os_version="25.0",
            scan_id="00000000-0000-0000-0000-000000000001",
        ),
        clients_scanned=0,
        servers_found=0,
        servers=[],
        findings=findings or [],
        errors=[],
    )


def _fake_nucleus_json(host: str = "test-host", findings: int = 0) -> str:
    """Build a minimal FlexConnect JSON string."""
    return json.dumps(
        {
            "nucleus_import_version": "1",
            "scan_tool": "mcp-audit",
            "scan_type": "Host",
            "scan_date": "2026-04-23 00:00:00",
            "assets": [{"host_name": host}],
            "findings": [{"id": f"F-{i}"} for i in range(findings)],
        }
    )


_BASE_ARGS = [
    "push-nucleus",
    "--url",
    _NUCLEUS_URL,
    "--project-id",
    _PROJECT_ID,
    "--api-key",
    _API_KEY,
]


# ── Test 1: command registration ──────────────────────────────────────────────


def test_push_nucleus_command_registered() -> None:
    """push-nucleus appears in the CLI help and is reachable."""
    result = runner.invoke(app, ["push-nucleus", "--help"])
    assert result.exit_code == 0
    assert "push-nucleus" in result.output or "Nucleus" in result.output


# ── Test 3: missing API key ───────────────────────────────────────────────────


def test_push_nucleus_missing_api_key_exits_2() -> None:
    """No --api-key and empty NUCLEUS_API_KEY env var → clean exit 2."""
    args = [
        "push-nucleus",
        "--url",
        _NUCLEUS_URL,
        "--project-id",
        _PROJECT_ID,
        # no --api-key
    ]
    with (
        patch("mcp_audit.cli.cached_is_pro_feature_available", return_value=True),
        patch.dict(os.environ, {"NUCLEUS_API_KEY": ""}, clear=False),
    ):
        # Remove the key entirely if it happens to be set in CI.
        env_backup = os.environ.pop("NUCLEUS_API_KEY", None)
        try:
            result = runner.invoke(app, args)
        finally:
            if env_backup is not None:
                os.environ["NUCLEUS_API_KEY"] = env_backup

    assert result.exit_code == 2
    assert "NUCLEUS_API_KEY" in result.output or "API key" in result.output


# ── Test 4: successful push ───────────────────────────────────────────────────


def test_push_nucleus_successful_push_exits_0() -> None:
    """Happy path: upload returns job_id, poll returns DONE → exit 0."""
    fake_json = _fake_nucleus_json(findings=2)

    with (
        patch("mcp_audit.cli.cached_is_pro_feature_available", return_value=True),
        patch("mcp_audit.cli.run_scan", return_value=_make_result()),
        patch("mcp_audit.cli.push_nucleus.format_nucleus", return_value=fake_json),
        patch(
            "mcp_audit.cli.push_nucleus._upload_scan",
            return_value={"job_id": 123, "success": True},
        ),
        patch(
            "mcp_audit.cli.push_nucleus._poll_job",
            return_value={"status": "DONE", "status_message": "Import complete"},
        ),
    ):
        result = runner.invoke(app, _BASE_ARGS)

    assert result.exit_code == 0


# ── Test 5: job ERROR status ──────────────────────────────────────────────────


def test_push_nucleus_job_error_exits_1() -> None:
    """Nucleus import job ending in ERROR → exit 1."""
    fake_json = _fake_nucleus_json()

    with (
        patch("mcp_audit.cli.cached_is_pro_feature_available", return_value=True),
        patch("mcp_audit.cli.run_scan", return_value=_make_result()),
        patch("mcp_audit.cli.push_nucleus.format_nucleus", return_value=fake_json),
        patch(
            "mcp_audit.cli.push_nucleus._upload_scan",
            return_value={"job_id": 456},
        ),
        patch(
            "mcp_audit.cli.push_nucleus._poll_job",
            return_value={
                "status": "ERROR",
                "status_message": "Invalid FlexConnect schema",
            },
        ),
    ):
        result = runner.invoke(app, _BASE_ARGS)

    assert result.exit_code == 1


# ── Test 6: poll timeout ──────────────────────────────────────────────────────


def test_push_nucleus_poll_timeout_exits_2() -> None:
    """_poll_job raising Exit(2) on timeout propagates as exit 2."""
    fake_json = _fake_nucleus_json()

    def _raise_timeout(*args, **kwargs):  # noqa: ANN002, ANN003
        raise typer.Exit(2)

    with (
        patch("mcp_audit.cli.cached_is_pro_feature_available", return_value=True),
        patch("mcp_audit.cli.run_scan", return_value=_make_result()),
        patch("mcp_audit.cli.push_nucleus.format_nucleus", return_value=fake_json),
        patch(
            "mcp_audit.cli.push_nucleus._upload_scan",
            return_value={"job_id": 789},
        ),
        patch("mcp_audit.cli.push_nucleus._poll_job", side_effect=_raise_timeout),
    ):
        result = runner.invoke(app, _BASE_ARGS)

    assert result.exit_code == 2


# ── Test 7: --output-file ─────────────────────────────────────────────────────


def test_push_nucleus_output_file_writes_flexconnect_json(tmp_path: Path) -> None:
    """--output-file writes the FlexConnect JSON payload to disk."""
    fake_json = _fake_nucleus_json(host="my-laptop", findings=3)
    out_path = tmp_path / "pushed-scan.json"

    with (
        patch("mcp_audit.cli.cached_is_pro_feature_available", return_value=True),
        patch("mcp_audit.cli.run_scan", return_value=_make_result()),
        patch("mcp_audit.cli.push_nucleus.format_nucleus", return_value=fake_json),
        patch(
            "mcp_audit.cli.push_nucleus._upload_scan",
            return_value={"job_id": 1},
        ),
        patch(
            "mcp_audit.cli.push_nucleus._poll_job",
            return_value={"status": "DONE"},
        ),
    ):
        result = runner.invoke(
            app,
            [*_BASE_ARGS, "--output-file", str(out_path)],
        )

    assert result.exit_code == 0
    assert out_path.exists(), "output file was not created"
    doc = json.loads(out_path.read_text(encoding="utf-8"))
    assert doc["nucleus_import_version"] == "1"
    assert len(doc["findings"]) == 3
    assert doc["assets"][0]["host_name"] == "my-laptop"


# ── Test 8: severity threshold filtering ─────────────────────────────────────


def test_push_nucleus_severity_threshold_filters_findings() -> None:
    """--severity-threshold HIGH excludes LOW findings from the pushed payload."""
    captured: list[ScanResult] = []

    def _capture_format(
        result: ScanResult,
        asset_prefix: str | None = None,
        console: object = None,
    ) -> str:
        captured.append(result)
        return json.dumps(
            {
                "nucleus_import_version": "1",
                "assets": [{"host_name": "test-host"}],
                "findings": [{"id": f.id} for f in result.findings],
            }
        )

    scan_result = _make_result(
        findings=[
            _make_finding(severity=Severity.CRITICAL, idx=1),
            _make_finding(severity=Severity.LOW, idx=2),
        ]
    )

    with (
        patch("mcp_audit.cli.cached_is_pro_feature_available", return_value=True),
        patch("mcp_audit.cli.run_scan", return_value=scan_result),
        patch(
            "mcp_audit.cli.push_nucleus.format_nucleus",
            side_effect=_capture_format,
        ),
        patch(
            "mcp_audit.cli.push_nucleus._upload_scan",
            return_value={"job_id": 99},
        ),
        patch(
            "mcp_audit.cli.push_nucleus._poll_job",
            return_value={"status": "DONE"},
        ),
    ):
        result = runner.invoke(
            app,
            [*_BASE_ARGS, "--severity-threshold", "HIGH"],
        )

    assert result.exit_code == 0
    assert len(captured) == 1, "format_nucleus should be called exactly once"
    pushed_findings = captured[0].findings
    # Only CRITICAL survives the HIGH threshold; LOW is below HIGH.
    assert len(pushed_findings) == 1
    assert pushed_findings[0].severity == Severity.CRITICAL


# ── Additional edge-case tests ────────────────────────────────────────────────


def test_push_nucleus_invalid_config_path_exits_2(tmp_path: Path) -> None:
    """A --config-paths value that does not exist → clean exit 2."""
    missing = tmp_path / "does-not-exist.json"
    with patch("mcp_audit.cli.cached_is_pro_feature_available", return_value=True):
        result = runner.invoke(
            app,
            [*_BASE_ARGS, "--config-paths", str(missing)],
        )
    assert result.exit_code == 2
    assert "not found" in result.output.lower() or "error" in result.output.lower()


def test_push_nucleus_descheduled_job_treated_as_error() -> None:
    """DESCHEDULED status is a non-DONE terminal state → exit 1."""
    fake_json = _fake_nucleus_json()

    with (
        patch("mcp_audit.cli.cached_is_pro_feature_available", return_value=True),
        patch("mcp_audit.cli.run_scan", return_value=_make_result()),
        patch("mcp_audit.cli.push_nucleus.format_nucleus", return_value=fake_json),
        patch(
            "mcp_audit.cli.push_nucleus._upload_scan",
            return_value={"job_id": 321},
        ),
        patch(
            "mcp_audit.cli.push_nucleus._poll_job",
            return_value={
                "status": "DESCHEDULED",
                "status_message": "Cancelled by admin",
            },
        ),
    ):
        result = runner.invoke(app, _BASE_ARGS)

    assert result.exit_code == 1


# ── SSRF scheme guard tests ───────────────────────────────────────────────────


def test_http_url_rejected() -> None:
    """push-nucleus must reject plain http:// URLs with exit code 2."""
    args = [
        "push-nucleus",
        "--url",
        "http://internal.corp/",
        "--project-id",
        _PROJECT_ID,
        "--api-key",
        _API_KEY,
    ]
    result = runner.invoke(app, args)
    assert result.exit_code == 2
    assert "https://" in result.output


def test_file_url_rejected() -> None:
    """push-nucleus must reject file:// URLs with exit code 2."""
    args = [
        "push-nucleus",
        "--url",
        "file:///etc/passwd",
        "--project-id",
        _PROJECT_ID,
        "--api-key",
        _API_KEY,
    ]
    result = runner.invoke(app, args)
    assert result.exit_code == 2
    assert "https://" in result.output


def test_ftp_url_rejected() -> None:
    """push-nucleus must reject ftp:// URLs with exit code 2."""
    args = [
        "push-nucleus",
        "--url",
        "ftp://evil.example.com/",
        "--project-id",
        _PROJECT_ID,
        "--api-key",
        _API_KEY,
    ]
    result = runner.invoke(app, args)
    assert result.exit_code == 2


def test_push_nucleus_api_key_from_env_var() -> None:
    """NUCLEUS_API_KEY env var is used when --api-key is omitted."""
    fake_json = _fake_nucleus_json()
    args_no_key = [
        "push-nucleus",
        "--url",
        _NUCLEUS_URL,
        "--project-id",
        _PROJECT_ID,
        # no --api-key
    ]

    with (
        patch("mcp_audit.cli.cached_is_pro_feature_available", return_value=True),
        patch.dict(os.environ, {"NUCLEUS_API_KEY": "env-key-value"}),
        patch("mcp_audit.cli.run_scan", return_value=_make_result()),
        patch("mcp_audit.cli.push_nucleus.format_nucleus", return_value=fake_json),
        patch(
            "mcp_audit.cli.push_nucleus._upload_scan",
            return_value={"job_id": 7},
        ),
        patch(
            "mcp_audit.cli.push_nucleus._poll_job",
            return_value={"status": "DONE"},
        ),
    ):
        result = runner.invoke(app, args_no_key)

    assert result.exit_code == 0
