"""Tests for the `mcp-audit lock` CLI command."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from mcp_audit.cli import app
from tests.conftest import unwrapped

runner = CliRunner()

_CURSOR_CONFIG = {
    "mcpServers": {
        "github": {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-github@1.2.3"],
        }
    }
}


def _write_cursor_config(root: Path) -> Path:
    config_dir = root / ".cursor"
    config_dir.mkdir(parents=True, exist_ok=True)
    config_path = config_dir / "mcp.json"
    config_path.write_text(json.dumps(_CURSOR_CONFIG), encoding="utf-8")
    return config_path


class TestLockNoConfigs:
    def test_nothing_to_lock(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["lock", str(tmp_path), "--offline"])
        assert result.exit_code == 0
        assert "nothing to lock" in unwrapped(result.output)


class TestLockWrite:
    def test_writes_lock_file(self, tmp_path: Path) -> None:
        _write_cursor_config(tmp_path)
        result = runner.invoke(app, ["lock", str(tmp_path), "--offline"])
        assert result.exit_code == 0
        lock_path = tmp_path / "mcp-lock.json"
        assert lock_path.exists()
        doc = json.loads(lock_path.read_text(encoding="utf-8"))
        assert "cursor/github" in doc["servers"]
        assert doc["servers"]["cursor/github"]["package"]["resolved_version"] == "1.2.3"

    def test_output_flag_writes_to_custom_path(self, tmp_path: Path) -> None:
        _write_cursor_config(tmp_path)
        custom = tmp_path / "custom-lock.json"
        result = runner.invoke(
            app, ["lock", str(tmp_path), "--offline", "--output", str(custom)]
        )
        assert result.exit_code == 0
        assert custom.exists()
        assert not (tmp_path / "mcp-lock.json").exists()

    def test_invalid_path_exits_2(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["lock", str(tmp_path / "does-not-exist")])
        assert result.exit_code == 2


class TestLockVerify:
    def test_verify_without_lock_exits_2(self, tmp_path: Path) -> None:
        _write_cursor_config(tmp_path)
        result = runner.invoke(app, ["lock", str(tmp_path), "--verify"])
        assert result.exit_code == 2

    def test_verify_clean_exits_0(self, tmp_path: Path) -> None:
        _write_cursor_config(tmp_path)
        runner.invoke(app, ["lock", str(tmp_path), "--offline"])
        result = runner.invoke(app, ["lock", str(tmp_path), "--verify"])
        assert result.exit_code == 0
        assert "verified" in result.output

    def test_verify_json_format(self, tmp_path: Path) -> None:
        _write_cursor_config(tmp_path)
        runner.invoke(app, ["lock", str(tmp_path), "--offline"])
        result = runner.invoke(
            app, ["lock", str(tmp_path), "--verify", "--format", "json"]
        )
        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert payload["checked_servers"] == 1

    def test_verify_and_accept_mutually_exclusive(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["lock", str(tmp_path), "--verify", "--accept"])
        assert result.exit_code == 2


class TestLockVerifyIfPresent:
    """``--if-present`` (STORY-0070) — soft-adoption for Action/pre-commit."""

    def test_missing_lock_with_if_present_exits_0(self, tmp_path: Path) -> None:
        _write_cursor_config(tmp_path)
        result = runner.invoke(app, ["lock", str(tmp_path), "--verify", "--if-present"])
        assert result.exit_code == 0
        out_lower = result.output.lower()
        assert "skipping" in out_lower
        assert "--if-present" in out_lower

    def test_missing_lock_without_if_present_still_exits_2(
        self, tmp_path: Path
    ) -> None:
        """--if-present must not change behaviour when omitted."""
        _write_cursor_config(tmp_path)
        result = runner.invoke(app, ["lock", str(tmp_path), "--verify"])
        assert result.exit_code == 2

    def test_present_lock_with_if_present_still_verifies(self, tmp_path: Path) -> None:
        """--if-present only changes the missing-file case, not a real drift check."""
        _write_cursor_config(tmp_path)
        runner.invoke(app, ["lock", str(tmp_path), "--offline"])
        result = runner.invoke(app, ["lock", str(tmp_path), "--verify", "--if-present"])
        assert result.exit_code == 0
        assert "verified" in result.output

    def test_present_but_drifted_lock_with_if_present_still_fails(
        self, tmp_path: Path
    ) -> None:
        """--if-present never masks a genuine drift finding once a lock exists."""
        config_path = _write_cursor_config(tmp_path)
        runner.invoke(app, ["lock", str(tmp_path), "--offline"])
        config_path.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "github": {
                            "command": "npx",
                            "args": [
                                "-y",
                                "@modelcontextprotocol/server-github@9.9.9",
                            ],
                        }
                    }
                }
            ),
            encoding="utf-8",
        )
        result = runner.invoke(app, ["lock", str(tmp_path), "--verify", "--if-present"])
        assert result.exit_code == 1


class TestLockVerifyUnverifiedExitCode:
    """R56 Part 1: exit code now reflects unresolved/foreign-content state."""

    def _write_unresolved_lock(self, tmp_path: Path) -> None:
        """A floating spec locked --offline never resolves a version."""
        config_dir = tmp_path / ".cursor"
        config_dir.mkdir(parents=True, exist_ok=True)
        (config_dir / "mcp.json").write_text(
            json.dumps(
                {"mcpServers": {"github": {"command": "npx", "args": ["-y", "foo"]}}}
            ),
            encoding="utf-8",
        )
        runner.invoke(app, ["lock", str(tmp_path), "--offline"])

    def test_unresolved_entry_now_exits_1(self, tmp_path: Path) -> None:
        self._write_unresolved_lock(tmp_path)
        result = runner.invoke(app, ["lock", str(tmp_path), "--verify"])
        assert result.exit_code == 1
        assert "WARN" in result.output

    def test_allow_unverified_restores_exit_0_and_names_waived(
        self, tmp_path: Path
    ) -> None:
        self._write_unresolved_lock(tmp_path)
        result = runner.invoke(
            app, ["lock", str(tmp_path), "--verify", "--allow-unverified"]
        )
        assert result.exit_code == 0
        assert "WAIVED" in result.output
        assert "cursor/github" in result.output

    def test_allow_unverified_json_includes_waived_and_unverified_detail(
        self, tmp_path: Path
    ) -> None:
        self._write_unresolved_lock(tmp_path)
        result = runner.invoke(
            app,
            [
                "lock",
                str(tmp_path),
                "--verify",
                "--allow-unverified",
                "--format",
                "json",
            ],
        )
        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert payload["waived"] is True
        assert payload["exit_code"] == 0
        assert payload["unverified"][0]["name"] == "cursor/github"
        assert payload["unverified"][0]["kind"] == "entry"

    def test_clean_pinned_lock_still_exits_0_without_flag(self, tmp_path: Path) -> None:
        """Regression guard: the default (exact-pin) fixture is unaffected."""
        _write_cursor_config(tmp_path)
        runner.invoke(app, ["lock", str(tmp_path), "--offline"])
        result = runner.invoke(app, ["lock", str(tmp_path), "--verify"])
        assert result.exit_code == 0
        assert "WAIVED" not in result.output


class TestLockAccept:
    def test_accept_preserves_first_locked(self, tmp_path: Path) -> None:
        _write_cursor_config(tmp_path)
        runner.invoke(app, ["lock", str(tmp_path), "--offline"])
        lock_path = tmp_path / "mcp-lock.json"
        first_doc = json.loads(lock_path.read_text(encoding="utf-8"))
        first_locked = first_doc["servers"]["cursor/github"]["first_locked"]

        result = runner.invoke(app, ["lock", str(tmp_path), "--offline", "--accept"])
        assert result.exit_code == 0
        second_doc = json.loads(lock_path.read_text(encoding="utf-8"))
        assert second_doc["servers"]["cursor/github"]["first_locked"] == first_locked
