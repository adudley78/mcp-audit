"""Tests for the ``mcp-audit run`` launch gate (EPIC-0009 Story 1.3).

Every lock here is written by the real ``mcp-audit lock`` command, so the
gate is tested against the file format ``lock`` actually produces, not a
hand-built copy of it.
"""

from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from mcp_audit.cli import app
from mcp_audit.runtime.cli import EXIT_REFUSED
from mcp_audit.runtime.gate import check_launch

runner = CliRunner()
PY = sys.executable
#: A server that exits 7 at once, so a test can tell "started" from "refused".
SERVER = [PY, "-c", "import sys; sys.exit(7)"]


@pytest.fixture
def repo(tmp_path: Path) -> Iterator[Path]:
    """A git-rooted scratch repo (the lock walk is repo-bounded)."""
    (tmp_path / ".git").mkdir()
    with patch("mcp_audit.discovery._get_client_specs", return_value=[]):
        yield tmp_path


def _config(root: Path, servers: dict) -> Path:
    path = root / ".mcp.json"
    path.write_text(json.dumps({"mcpServers": servers}), encoding="utf-8")
    return path


def _lock(root: Path) -> Path:
    result = runner.invoke(app, ["lock", str(root), "--offline"])
    assert result.exit_code == 0, result.output
    lock = root / "mcp-lock.json"
    assert lock.exists()
    return lock


def _server(argv: list[str]) -> dict:
    return {"command": argv[0], "args": argv[1:]}


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        [PY, "-m", "mcp_audit._entry", "run", *args],
        input="",
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
    )


# ── check_launch ─────────────────────────────────────────────────────────────


class TestCheckLaunch:
    def test_locked_launch_is_allowed(self, repo: Path) -> None:
        config = _config(repo, {"srv": _server(SERVER)})
        _lock(repo)
        assert check_launch(SERVER, config_path=config, server_name="srv").ok

    def test_unlocked_server_is_lock_002(self, repo: Path) -> None:
        config = _config(repo, {"srv": _server(SERVER)})
        _lock(repo)
        _config(repo, {"srv": _server(SERVER), "other": _server(SERVER)})
        result = check_launch(SERVER, config_path=config, server_name="other")
        assert result.finding_id == "LOCK-002"
        assert "mcp-audit lock" in result.fix

    def test_changed_args_are_lock_001(self, repo: Path) -> None:
        config = _config(repo, {"srv": _server([PY, "-c", "print(1)"])})
        _lock(repo)
        result = check_launch(
            [PY, "-c", "print(2)"], config_path=config, server_name="srv"
        )
        assert result.finding_id == "LOCK-001"
        assert result.summary.endswith("its arguments changed")
        assert "print(2)" not in result.summary  # arguments are never quoted

    def test_added_arg_is_lock_001(self, repo: Path) -> None:
        config = _config(repo, {"srv": _server(SERVER)})
        _lock(repo)
        result = check_launch(
            [*SERVER, "--extra"], config_path=config, server_name="srv"
        )
        assert result.finding_id == "LOCK-001"
        assert "3 arguments; 2 were approved" in result.summary

    def test_changed_command_is_lock_001(self, repo: Path) -> None:
        config = _config(repo, {"srv": {"command": "npx", "args": ["-y", "pkg"]}})
        _lock(repo)
        result = check_launch(
            ["bunx", "-y", "pkg"], config_path=config, server_name="srv"
        )
        assert result.finding_id == "LOCK-001"
        assert "'npx' to 'bunx'" in result.summary

    def test_remote_entry_launched_locally_is_lock_001(self, repo: Path) -> None:
        config = _config(repo, {"srv": {"url": "https://mcp.example.com/mcp"}})
        _lock(repo)
        result = check_launch(SERVER, config_path=config, server_name="srv")
        assert result.finding_id == "LOCK-001"
        assert "remote server" in result.summary

    def test_no_lock_is_run_001(self, repo: Path) -> None:
        config = _config(repo, {"srv": _server(SERVER)})
        result = check_launch(SERVER, config_path=config, server_name="srv")
        assert result.finding_id == "RUN-001"

    def test_corrupt_lock_is_run_002(self, repo: Path) -> None:
        config = _config(repo, {"srv": _server(SERVER)})
        (repo / "mcp-lock.json").write_text("{ not json", encoding="utf-8")
        result = check_launch(SERVER, config_path=config, server_name="srv")
        assert result.finding_id == "RUN-002"

    def test_lock_without_servers_is_run_002(self, repo: Path) -> None:
        config = _config(repo, {"srv": _server(SERVER)})
        (repo / "mcp-lock.json").write_text('{"servers": []}', encoding="utf-8")
        result = check_launch(SERVER, config_path=config, server_name="srv")
        assert result.finding_id == "RUN-002"

    def test_newer_lock_version_is_run_002(self, repo: Path) -> None:
        config = _config(repo, {"srv": _server(SERVER)})
        lock = _lock(repo)
        doc = json.loads(lock.read_text())
        doc["lock_version"] = 99
        lock.write_text(json.dumps(doc))
        result = check_launch(SERVER, config_path=config, server_name="srv")
        assert result.finding_id == "RUN-002"
        assert "lock_version 99" in result.summary

    def test_explicit_lock_path(self, repo: Path, tmp_path_factory) -> None:
        config = _config(repo, {"srv": _server(SERVER)})
        lock = _lock(repo)
        elsewhere = tmp_path_factory.mktemp("cfg") / "mcp.json"
        elsewhere.write_text(config.read_text())
        # Outside the lock's root and home: out of scope, never a silent pass.
        result = check_launch(
            SERVER, config_path=elsewhere, server_name="srv", lock_path=lock
        )
        assert result.finding_id in {"RUN-001", "LOCK-002"}
        assert not result.ok


class TestTolerances:
    @pytest.mark.parametrize(
        "placeholder", ["${TOKEN}", "${TOKEN:-dflt}", "${env:TOKEN}"]
    )
    def test_client_placeholders_match_any_value(
        self, repo: Path, placeholder: str
    ) -> None:
        locked = [PY, "-c", "pass", f"--root={placeholder}/data"]
        config = _config(repo, {"srv": _server(locked)})
        _lock(repo)
        launched = [PY, "-c", "pass", "--root=/home/me/data"]
        assert check_launch(launched, config_path=config, server_name="srv").ok

    def test_placeholder_keeps_literal_parts(self, repo: Path) -> None:
        locked = [PY, "-c", "pass", "--root=${DIR}/data"]
        config = _config(repo, {"srv": _server(locked)})
        _lock(repo)
        launched = [PY, "-c", "pass", "--root=/home/me/other"]
        result = check_launch(launched, config_path=config, server_name="srv")
        assert result.finding_id == "LOCK-001"

    def test_placeholder_never_spans_arguments(self, repo: Path) -> None:
        locked = [PY, "-c", "pass", "${ARGS}"]
        config = _config(repo, {"srv": _server(locked)})
        _lock(repo)
        launched = [PY, "-c", "pass", "a", "b"]
        result = check_launch(launched, config_path=config, server_name="srv")
        assert result.finding_id == "LOCK-001"

    def test_redacted_credential_compares_like_verify(self, repo: Path) -> None:
        argv = [PY, "-c", "pass", "--api-key", "abc123secretvalue"]
        config = _config(repo, {"srv": _server(argv)})
        lock = _lock(repo)
        assert "abc123secretvalue" not in lock.read_text()  # lock redacted it
        assert check_launch(argv, config_path=config, server_name="srv").ok


# ── the CLI, end to end ──────────────────────────────────────────────────────


class TestCli:
    def test_enforce_starts_a_locked_server(self, repo: Path) -> None:
        config = _config(repo, {"srv": _server(SERVER)})
        _lock(repo)
        out = _run(
            "--config", str(config), "--server", "srv", "--mode", "enforce",
            "--", *SERVER,
        )  # fmt: skip
        assert out.returncode == 7
        assert out.stderr == ""

    @pytest.mark.parametrize(
        ("setup", "finding"),
        [("unlocked", "LOCK-002"), ("drifted", "LOCK-001"), ("nolock", "RUN-001")],
    )
    def test_enforce_refuses_and_monitor_starts(
        self, repo: Path, setup: str, finding: str
    ) -> None:
        config = _config(repo, {"srv": _server(SERVER)})
        if setup != "nolock":
            _lock(repo)
        name = "srv"
        argv = SERVER
        if setup == "unlocked":
            _config(repo, {"srv": _server(SERVER), "new": _server(SERVER)})
            name = "new"
        elif setup == "drifted":
            argv = [*SERVER, "--changed"]

        enforce = _run(
            "--config", str(config), "--server", name, "--mode", "enforce",
            "--", *argv,
        )  # fmt: skip
        assert enforce.returncode == EXIT_REFUSED
        lines = enforce.stderr.splitlines()
        assert len(lines) == 1
        assert lines[0].startswith(f"mcp-audit run: refused: {finding} ")
        assert "Fix: " in lines[0]

        monitor = _run("--config", str(config), "--server", name, "--", *argv)
        assert monitor.returncode == 7  # the server ran
        assert f"monitor: {finding} " in monitor.stderr
        assert "enforce mode would refuse" in monitor.stderr

    def test_corrupt_lock_fails_closed_in_enforce_open_in_monitor(
        self, repo: Path
    ) -> None:
        config = _config(repo, {"srv": _server(SERVER)})
        (repo / "mcp-lock.json").write_text("{ broken", encoding="utf-8")
        enforce = _run(
            "--config", str(config), "--server", "srv", "--mode", "enforce",
            "--", *SERVER,
        )  # fmt: skip
        assert enforce.returncode == EXIT_REFUSED
        assert "RUN-002" in enforce.stderr
        monitor = _run("--config", str(config), "--server", "srv", "--", *SERVER)
        assert monitor.returncode == 7
        assert "monitor: RUN-002" in monitor.stderr

    def test_enforce_without_server_identity_is_usage_error(self) -> None:
        out = _run("--mode", "enforce", "--", *SERVER)
        assert out.returncode == 2
        assert "needs --config and --server" in out.stderr

    def test_config_without_server_is_usage_error(self, repo: Path) -> None:
        config = _config(repo, {"srv": _server(SERVER)})
        out = _run("--config", str(config), "--", *SERVER)
        assert out.returncode == 2
        assert "go together" in out.stderr

    def test_plain_relay_unchanged_without_gate_flags(self) -> None:
        out = _run("--", *SERVER)
        assert out.returncode == 7
        assert out.stderr == ""

    def test_server_flags_after_dashdash_are_not_gate_flags(self, repo: Path) -> None:
        argv = [PY, "-c", "import sys; sys.exit(7)", "--mode", "enforce"]
        config = _config(repo, {"srv": _server(argv)})
        _lock(repo)
        out = _run("--config", str(config), "--server", "srv", "--", *argv)
        assert out.returncode == 7
        assert out.stderr == ""


def test_gate_fast_path_imports_nothing_heavy(repo: Path) -> None:
    config = _config(repo, {"srv": _server(SERVER)})
    _lock(repo)
    probe = (
        "import json, sys\n"
        "from pathlib import Path\n"
        "from mcp_audit.runtime.gate import check_launch\n"
        f"r = check_launch({SERVER!r}, config_path=Path({str(config)!r}),"
        " server_name='srv')\n"
        "assert r.ok, r\n"
        "print(json.dumps(sorted(sys.modules)))\n"
    )
    out = subprocess.run(  # noqa: S603
        [PY, "-c", probe], capture_output=True, text=True, timeout=60
    )
    assert out.returncode == 0, out.stderr
    loaded = json.loads(out.stdout.splitlines()[-1])
    heavy = ("mcp_audit.analyzers", "mcp_audit.scanner", "mcp_audit.cli", "pydantic")
    assert [m for m in loaded if m.startswith(heavy)] == []
