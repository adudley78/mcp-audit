"""End-to-end tests for ``mcp-audit wrap`` / ``unwrap`` (EPIC-0009 Story 1.2)."""

from __future__ import annotations

import json
import subprocess
import sys
import sysconfig
from collections.abc import Iterator
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from mcp_audit.cli import app

runner = CliRunner()
PY = sys.executable
#: The console script installed with this interpreter's packages.
EXE = str(
    Path(sysconfig.get_path("scripts"))
    / ("mcp-audit.exe" if sys.platform == "win32" else "mcp-audit")
)
SERVER = {"command": PY, "args": ["-c", "import sys; sys.exit(7)"], "env": {"K": "v"}}
REMOTE = {"url": "https://mcp.example.com/mcp"}


@pytest.fixture
def repo(tmp_path: Path) -> Iterator[Path]:
    (tmp_path / ".git").mkdir()
    with patch("mcp_audit.discovery._get_client_specs", return_value=[]):
        yield tmp_path


def _config(root: Path, servers: dict) -> Path:
    path = root / ".mcp.json"
    path.write_text(json.dumps({"mcpServers": servers}, indent=2) + "\n")
    return path


def _cli(*args: str) -> str:
    result = runner.invoke(app, list(args))
    assert result.exit_code == 0, result.output
    return result.output


def _servers(path: Path) -> dict:
    return json.loads(path.read_text())["mcpServers"]


@pytest.fixture
def exe() -> str:
    if not Path(EXE).exists():
        pytest.skip("mcp-audit console script not installed next to this Python")
    return EXE


class TestWrap:
    def test_dry_run_changes_nothing(self, repo: Path, exe: str) -> None:
        config = _config(repo, {"srv": SERVER})
        before = config.read_text()
        out = _cli("wrap", "--path", str(config), "--exe", exe)
        assert config.read_text() == before
        assert "Would wrap 1 server(s)." in out
        assert "+" in out and "run" in out  # the diff is shown
        assert not list(repo.glob(".mcp.json.bak*"))

    def test_apply_writes_backup_and_launchable_entry(
        self, repo: Path, exe: str
    ) -> None:
        config = _config(repo, {"srv": SERVER, "remote": REMOTE})
        before = config.read_text()
        out = _cli("wrap", "--path", str(config), "--exe", exe, "--apply")
        assert "Wrapped 1 server(s)." in out
        assert "remote: skipped, remote server" in out
        assert (repo / ".mcp.json.bak").read_text() == before
        servers = _servers(config)
        assert servers["remote"] == REMOTE
        entry = servers["srv"]
        assert entry["command"] == exe
        assert entry["env"] == {"K": "v"}
        # What the client will now launch actually starts the server.
        launched = subprocess.run(  # noqa: S603
            [entry["command"], *entry["args"]],
            input=b"",
            capture_output=True,
            timeout=60,
        )
        assert launched.returncode == 7

    def test_dry_run_shows_the_gate_decision(self, repo: Path, exe: str) -> None:
        config = _config(repo, {"srv": SERVER})
        out = _cli("wrap", "--path", str(config), "--exe", exe, "--mode", "enforce")
        assert "gate: RUN-001" in out
        assert "enforce mode would refuse to start it" in out
        _cli("lock", str(repo), "--offline")
        out = _cli("wrap", "--path", str(config), "--exe", exe, "--mode", "enforce")
        assert "gate: approved in mcp-lock.json" in out
        assert "would refuse" not in out

    def test_second_wrap_is_a_no_op(self, repo: Path, exe: str) -> None:
        config = _config(repo, {"srv": SERVER})
        _cli("wrap", "--path", str(config), "--exe", exe, "--apply")
        after = config.read_text()
        out = _cli("wrap", "--path", str(config), "--exe", exe, "--apply")
        assert "srv: already wrapped" in out
        assert config.read_text() == after

    def test_server_filter(self, repo: Path, exe: str) -> None:
        config = _config(repo, {"a": SERVER, "b": SERVER})
        _cli("wrap", "--path", str(config), "--exe", exe, "--server", "b", "--apply")
        servers = _servers(config)
        assert servers["a"] == SERVER
        assert servers["b"]["command"] == exe

    def test_json_with_comments_is_skipped(self, repo: Path, exe: str) -> None:
        config = repo / ".mcp.json"
        config.write_text('{\n  // my servers\n  "mcpServers": {}\n}\n')
        out = _cli("wrap", "--path", str(config), "--exe", exe, "--apply")
        assert "not plain JSON" in out

    def test_relative_exe_rejected(self, repo: Path) -> None:
        config = _config(repo, {"srv": SERVER})
        result = runner.invoke(
            app, ["wrap", "--path", str(config), "--exe", "mcp-audit"]
        )
        assert result.exit_code == 2


class TestUnwrap:
    def test_round_trip_restores_the_original(self, repo: Path, exe: str) -> None:
        original = {"srv": SERVER, "bare": {"command": "my-server"}, "remote": REMOTE}
        config = _config(repo, original)
        _cli("wrap", "--path", str(config), "--exe", exe, "--apply")
        out = _cli("unwrap", "--path", str(config), "--apply")
        assert "Restored 2 server(s)." in out
        assert out.count("matches the original exactly") == 2
        assert _servers(config) == original

    def test_dry_run_changes_nothing(self, repo: Path, exe: str) -> None:
        config = _config(repo, {"srv": SERVER})
        _cli("wrap", "--path", str(config), "--exe", exe, "--apply")
        wrapped = config.read_text()
        out = _cli("unwrap", "--path", str(config))
        assert "Would restore 1 server(s)." in out
        assert config.read_text() == wrapped


class TestLockSeesThroughTheWrap:
    def test_lock_verify_is_clean_after_wrapping(self, repo: Path, exe: str) -> None:
        config = _config(repo, {"srv": SERVER})
        _cli("lock", str(repo), "--offline")
        _cli("wrap", "--path", str(config), "--exe", exe, "--apply")
        result = runner.invoke(app, ["lock", str(repo), "--verify"])
        assert result.exit_code == 0, result.output
        assert "LOCK-001" not in result.output

    def test_wrapped_enforced_server_starts_through_the_gate(
        self, repo: Path, exe: str
    ) -> None:
        config = _config(repo, {"srv": SERVER})
        _cli("lock", str(repo), "--offline")
        _cli(
            "wrap", "--path", str(config), "--exe", exe, "--mode", "enforce", "--apply"
        )
        entry = _servers(config)["srv"]
        launched = subprocess.run(  # noqa: S603
            [entry["command"], *entry["args"]],
            input=b"",
            capture_output=True,
            timeout=60,
        )
        assert launched.returncode == 7, launched.stderr

    def test_drift_after_wrapping_is_still_caught(self, repo: Path, exe: str) -> None:
        config = _config(repo, {"srv": SERVER})
        _cli("lock", str(repo), "--offline")
        _cli(
            "wrap", "--path", str(config), "--exe", exe, "--mode", "enforce", "--apply"
        )
        doc = json.loads(config.read_text())
        doc["mcpServers"]["srv"]["args"].append("--extra")
        config.write_text(json.dumps(doc))
        result = runner.invoke(app, ["lock", str(repo), "--verify"])
        assert "LOCK-001" in result.output
        entry = doc["mcpServers"]["srv"]
        launched = subprocess.run(  # noqa: S603
            [entry["command"], *entry["args"]],
            input=b"",
            capture_output=True,
            timeout=60,
        )
        assert launched.returncode == 78
        assert b"refused: LOCK-001" in launched.stderr


def test_check_reports_wrapped_servers(repo: Path, exe: str) -> None:
    config = _config(repo, {"a": SERVER, "b": SERVER})
    _cli("wrap", "--path", str(config), "--exe", exe, "--server", "a", "--apply")
    result = runner.invoke(app, ["check", "--path", str(config)])
    assert "Launch gate: 1 of 2 local servers wrapped (1 monitor)" in " ".join(
        result.output.split()
    )
