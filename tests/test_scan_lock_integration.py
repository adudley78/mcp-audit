"""Integration tests for `mcp-audit scan`'s automatic mcp-lock.json
verification (STORY-0070) — the ``_apply_lock_verification`` pipeline stage
wired into ``cli/scan.py::scan()``.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from mcp_audit.cli import app
from mcp_audit.lock.writer import regenerate, write_lock
from mcp_audit.scanner import run_scan
from tests.conftest import split_runner, unwrapped

runner = CliRunner()


def _patch_no_known_clients():
    """Patch discovery so only the explicit --path config is found."""
    return patch("mcp_audit.discovery._get_client_specs", return_value=[])


def _write_config(tmp_path: Path, version: str = "1.0.0") -> Path:
    config = tmp_path / "mcp.json"
    payload = {
        "mcpServers": {"github": {"command": "npx", "args": ["-y", f"foo@{version}"]}}
    }
    config.write_text(json.dumps(payload))
    return config


def _write_matching_lock(tmp_path: Path, config: Path) -> None:
    """Discover the config's real ServerConfig list and lock exactly that."""
    with _patch_no_known_clients():
        result = run_scan(extra_paths=[config], skip_rug_pull=True)
    doc = regenerate(None, result.servers, tmp_path, offline=True, registry=None)
    write_lock(tmp_path / "mcp-lock.json", doc)


def _scan_json(config: Path, *extra_args: str) -> dict:
    with _patch_no_known_clients():
        r = runner.invoke(
            app, ["scan", "--path", str(config), "--format", "json", *extra_args]
        )
    json_start = r.output.find("{")
    return json.loads(r.output[json_start:])


class TestScanAutoVerifiesLock:
    def test_no_lock_file_scan_unchanged(self, tmp_path: Path) -> None:
        (tmp_path / ".git").mkdir()
        config = _write_config(tmp_path)
        with _patch_no_known_clients():
            r = runner.invoke(app, ["scan", "--path", str(config)])
        assert "Lock:" not in r.output

    def test_clean_lock_prints_verified_line(self, tmp_path: Path) -> None:
        (tmp_path / ".git").mkdir()
        config = _write_config(tmp_path)
        _write_matching_lock(tmp_path, config)
        with _patch_no_known_clients():
            r = runner.invoke(app, ["scan", "--path", str(config)])
        assert "Lock: verified (1 servers)" in unwrapped(r.output)

    def test_clean_lock_status_in_json(self, tmp_path: Path) -> None:
        (tmp_path / ".git").mkdir()
        config = _write_config(tmp_path)
        _write_matching_lock(tmp_path, config)
        parsed = _scan_json(config)
        assert parsed["lock_status"]["present"] is True
        assert parsed["lock_status"]["verified"] is True
        assert parsed["lock_status"]["findings"] == 0
        assert not any(f["id"].startswith("LOCK-") for f in parsed["findings"])

    def test_drifted_lock_adds_lock_001_and_lowers_score(self, tmp_path: Path) -> None:
        (tmp_path / ".git").mkdir()
        config = _write_config(tmp_path)
        _write_matching_lock(tmp_path, config)
        baseline = _scan_json(_write_config(tmp_path))  # same content, no drift yet
        baseline_score = baseline["score"]["numeric"]

        # Drift the config after locking it.
        _write_config(tmp_path, version="9.9.9")
        drifted = _scan_json(config)

        assert any(f["id"] == "LOCK-001" for f in drifted["findings"])
        assert drifted["lock_status"]["present"] is True
        assert drifted["lock_status"]["verified"] is False
        # LOCK-001 (HIGH, -10) must have been folded into the recomputed score.
        assert drifted["score"]["numeric"] < baseline_score

    def test_no_lock_flag_skips_verification(self, tmp_path: Path) -> None:
        (tmp_path / ".git").mkdir()
        config = _write_config(tmp_path)
        _write_matching_lock(tmp_path, config)
        _write_config(tmp_path, version="9.9.9")

        with _patch_no_known_clients():
            r = runner.invoke(app, ["scan", "--path", str(config), "--no-lock"])
        assert "Lock:" not in r.output

        parsed = _scan_json(config, "--no-lock")
        assert parsed["lock_status"]["present"] is False
        assert not any(f["id"].startswith("LOCK-") for f in parsed["findings"])


# ── Machine-readable stdout (STORY-0103) ──────────────────────────────────────

# Separate streams: ``r.stdout`` is only what a pipe consumer would read.
_split_runner = split_runner()

_WARN_STATUS_KW: dict = {
    "outside_root": ["/elsewhere/.mcp.json"],
    "not_covered": ["claude-code-agent/browser (/repo/.claude/agents/a.md)"],
    "unresolved_entries": ["claude-code/floating"],
}


def _patched_status(findings: list | None = None, **kwargs: object):
    """Patch scan's lock auto-verify to return a status with *kwargs* set."""
    from mcp_audit.models import LockStatus

    status = LockStatus(
        present=True,
        verified=not findings,
        findings=len(findings or []),
        checked_servers=1,
        lock_paths=["/repo/mcp-lock.json"],
        **kwargs,  # type: ignore[arg-type]
    )
    return patch(
        "mcp_audit.cli.scan._lock_auto_verify",
        return_value=(list(findings or []), status),
    )


def _lock_001() -> object:
    from mcp_audit.models import Finding, Severity

    return Finding(
        id="LOCK-001",
        severity=Severity.HIGH,
        analyzer="lock",
        client="claude-code",
        server="github",
        title="Locked server changed: 'github'",
        description="drifted",
        evidence="args changed",
        remediation="review",
    )


def _invoke_split(config: Path, *args: str):
    with _patch_no_known_clients():
        return _split_runner.invoke(app, ["scan", "--path", str(config), *args])


class TestLockLinesStayOffMachineReadableStdout:
    """`scan --format json|sarif|nucleus` stdout must parse as JSON with a lock
    present; the lock status lines move to stderr (STORY-0103)."""

    @pytest.mark.parametrize(
        "fmt_args",
        [
            ("--format", "json"),
            ("--json",),
            ("--format", "sarif"),
            ("--format", "nucleus"),
        ],
    )
    def test_verified_lock_line_goes_to_stderr(
        self, tmp_path: Path, fmt_args: tuple[str, ...]
    ) -> None:
        (tmp_path / ".git").mkdir()
        config = _write_config(tmp_path)
        _write_matching_lock(tmp_path, config)
        r = _invoke_split(config, *fmt_args)
        assert r.exit_code in (0, 1), r.stderr
        json.loads(r.stdout)  # the whole of stdout is one JSON document
        assert "Lock:" not in r.stdout
        assert "Lock: verified (1 servers)" in unwrapped(r.stderr)

    def test_json_still_carries_the_status(self, tmp_path: Path) -> None:
        (tmp_path / ".git").mkdir()
        config = _write_config(tmp_path)
        _write_matching_lock(tmp_path, config)
        parsed = json.loads(_invoke_split(config, "--format", "json").stdout)
        assert parsed["lock_status"]["present"] is True
        assert parsed["lock_status"]["verified"] is True

    @pytest.mark.parametrize("fmt", ["json", "sarif"])
    def test_warn_lines_go_to_stderr(self, tmp_path: Path, fmt: str) -> None:
        config = _write_config(tmp_path)
        with _patched_status(**_WARN_STATUS_KW):
            r = _invoke_split(config, "--format", fmt)
        doc = json.loads(r.stdout)
        err = unwrapped(r.stderr)
        assert "outside the lock root were skipped" in err
        assert "not covered by mcp-lock.json (AGENT-004)" in err
        assert "1 entry unresolved" in err
        assert "Lock: verified (1 servers)" in err
        for text in ("WARN", "Lock:"):
            assert text not in r.stdout
        if fmt == "json":
            assert doc["lock_status"]["outside_root"] == ["/elsewhere/.mcp.json"]
            assert len(doc["lock_status"]["not_covered"]) == 1

    def test_finding_summary_goes_to_stderr(self, tmp_path: Path) -> None:
        config = _write_config(tmp_path)
        with _patched_status(findings=[_lock_001()]):
            r = _invoke_split(config, "--format", "json")
        doc = json.loads(r.stdout)
        assert any(f["id"] == "LOCK-001" for f in doc["findings"])
        assert "Lock: 1 finding(s) across 1 locked server(s)" in unwrapped(r.stderr)

    def test_terminal_output_keeps_every_line_on_stdout(self, tmp_path: Path) -> None:
        config = _write_config(tmp_path)
        with _patched_status(**_WARN_STATUS_KW):
            r = _invoke_split(config)
        out = unwrapped(r.stdout)
        assert "outside the lock root were skipped" in out
        assert "not covered by mcp-lock.json (AGENT-004)" in out
        assert "1 entry unresolved" in out
        assert "Lock: verified (1 servers)" in out
        assert "Lock:" not in r.stderr

    @pytest.mark.parametrize("fmt", ["json", "sarif"])
    def test_other_stage_status_lines_go_to_stderr_too(
        self, tmp_path: Path, fmt: str
    ) -> None:
        """--project prints a summary line; with JSON or SARIF it is on stderr."""
        project = tmp_path / "repo"
        project.mkdir()
        (project / ".mcp.json").write_text(
            json.dumps({"mcpServers": {"x": {"command": "node", "args": ["s.js"]}}})
        )
        config = _write_config(tmp_path)
        r = _invoke_split(config, "--format", fmt, "--project", str(project))
        json.loads(r.stdout)
        assert "Project scan:" in unwrapped(r.stderr)
        assert "Project scan:" not in r.stdout

    def test_an_error_with_json_format_goes_to_stderr(self, tmp_path: Path) -> None:
        r = _split_runner.invoke(
            app,
            ["scan", "--format", "json", "--project", str(tmp_path / "missing")],
        )
        assert r.exit_code == 2
        assert r.stdout == ""
        assert "--project path not found" in unwrapped(r.stderr)
