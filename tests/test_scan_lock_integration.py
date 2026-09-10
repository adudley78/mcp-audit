"""Integration tests for `mcp-audit scan`'s automatic mcp-lock.json
verification (STORY-0070) — the ``_apply_lock_verification`` pipeline stage
wired into ``cli/scan.py::scan()``.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from mcp_audit.cli import app
from mcp_audit.lock.writer import regenerate, write_lock
from mcp_audit.scanner import run_scan

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
        assert "Lock: verified (1 servers)" in r.output

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
