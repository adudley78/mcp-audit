"""STORY-0126: the Respond block and ``--policy-out``."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from mcp_audit.affected import respond
from mcp_audit.analyzers.managed_policy import PolicyEntry, entry_matches
from mcp_audit.cli import app
from mcp_audit.models import ServerConfig, TransportType

runner = CliRunner()
CVE = "CVE-2026-77244"


def _srv(name: str = "a", cfg: str = "mcp.json", **over: Any) -> ServerConfig:
    base: dict[str, Any] = {
        "name": name,
        "client": "custom",
        "config_path": Path(cfg),
        "transport": TransportType.STDIO,
        "command": "uvx",
        "args": ["mcp-atlassian==0.21.0"],
    }
    base.update(over)
    return ServerConfig(**base)


def _config(tmp_path: Path, servers: dict) -> Path:
    path = tmp_path / ".mcp.json"
    path.write_text(json.dumps({"mcpServers": servers}), encoding="utf-8")
    return path


HTTP = {
    "command": "uvx",
    "args": ["mcp-atlassian==0.21.0", "--transport", "sse"],
    "env": {"JIRA_TOKEN": "s3cr3t-value", "JIRA_URL": "https://x"},
}


class TestBuild:
    def test_names_only(self) -> None:
        a = _srv(
            env={"TOKEN": "v1"},
            headers={"Authorization": "Bearer v2"},
            args=["x", "--api-key=v3", "--verbose"],
        )
        item = respond.build(a, [a], [])
        assert item.names() == ["--api-key", "Authorization", "TOKEN"]
        assert (
            "v1" not in repr(item) and "v2" not in repr(item) and "v3" not in repr(item)
        )

    def test_shared_only_within_the_same_config_file(self) -> None:
        a = _srv("a", env={"TOKEN": "1", "ONLY_A": "1"})
        same = _srv("b", env={"TOKEN": "2"})
        other = _srv("c", cfg="other.json", env={"TOKEN": "3"})
        item = respond.build(a, [a, same, other], [])
        assert item.shared == {"custom/b": ["TOKEN"]}

    def test_credential_files_are_listed_by_stat_only(self, tmp_path: Path) -> None:
        (tmp_path / ".aws").mkdir()
        (tmp_path / ".aws" / "credentials").write_text("SECRET-CONTENT")
        (tmp_path / ".claude.json").write_text("{}")
        (tmp_path / ".netrc").write_text("")  # empty: not a credential store
        errors: list[str] = []
        found = respond.credential_files(tmp_path, tmp_path / "cwd-none", errors)
        paths = [p for p, _ in found]
        assert "~/.aws/credentials" in paths
        assert "~/.claude.json" in paths
        assert "~/.netrc" not in paths
        assert "SECRET-CONTENT" not in repr(found)

    def test_tool_text_is_counted_not_shown(self, tmp_path: Path) -> None:
        (tmp_path / "mcp-lock.json").write_text("{}")
        (tmp_path / "mcp-lock.tools.json").write_text(
            json.dumps(
                {
                    "_producer": "mcp-audit",
                    "_schema_version": 1,
                    "servers": {
                        "custom/a": {
                            "tools": {"t1": {"description": "SECRET TEXT"}, "t2": {}}
                        }
                    },
                }
            )
        )
        s = _srv(cfg=str(tmp_path / ".mcp.json"))
        item = respond.build(s, [s], [])
        assert item.tool_text == (2, "mcp-lock.tools.json")
        assert "SECRET TEXT" not in repr(item)

    def test_no_tool_text_when_absent_or_foreign(self, tmp_path: Path) -> None:
        (tmp_path / "mcp-lock.json").write_text("{}")
        (tmp_path / "mcp-lock.tools.json").write_text("[1]")
        s = _srv(cfg=str(tmp_path / ".mcp.json"))
        assert respond.build(s, [s], []).tool_text is None


class TestPolicyEntry:
    def test_command_entry_matches_the_server(self) -> None:
        s = _srv()
        entry, note = respond.policy_entry(s)
        assert entry == {"serverCommand": ["uvx", "mcp-atlassian==0.21.0"]}
        assert note is None

    def test_remote_server_gets_a_url_entry_without_secrets(self) -> None:
        s = _srv(
            command=None,
            args=[],
            transport=TransportType.SSE,
            url="https://mcp.example.com:8443/sse?api_key=abc123",
        )
        entry, _ = respond.policy_entry(s)
        assert entry == {"serverUrl": "https://mcp.example.com:8443/sse"}
        assert entry_matches(PolicyEntry("serverUrl", entry["serverUrl"], Path("x")), s)

    def test_url_with_userinfo_falls_back_to_name(self) -> None:
        s = _srv(
            command=None,
            args=[],
            transport=TransportType.SSE,
            url="https://user:pw@mcp.example.com/sse",
        )
        entry, note = respond.policy_entry(s)
        assert "pw" not in json.dumps(entry)
        assert note is not None

    @pytest.mark.parametrize(
        "args",
        [
            ["x", "--token=abc"],
            ["x", "--api-key", "abc"],
            ["x", "${HOME}/y"],
        ],
    )
    def test_secret_or_variable_commands_fall_back_to_name(self, args: list) -> None:
        s = _srv("named", args=args)
        entry, note = respond.policy_entry(s)
        assert entry == {"serverName": "named"}
        assert note is not None and "name only" in note
        assert "abc" not in json.dumps(entry)

    def test_document_deduplicates(self) -> None:
        doc, notes = respond.policy_document([_srv("a"), _srv("b")])
        assert doc == {
            "deniedMcpServers": [{"serverCommand": ["uvx", "mcp-atlassian==0.21.0"]}]
        }
        assert notes == []

    def test_every_written_entry_matches_its_server(self) -> None:
        servers = [_srv("a"), _srv("b", args=["--token=z"])]
        doc, _ = respond.policy_document(servers)
        for server, entry in zip(servers, doc["deniedMcpServers"], strict=False):
            ((kind, value),) = entry.items()
            value = tuple(value) if isinstance(value, list) else value
            assert entry_matches(PolicyEntry(kind, value, Path("x")), server) in (True,)  # type: ignore[arg-type]


class TestCli:
    def test_respond_block_and_no_values(self, tmp_path: Path) -> None:
        cfg = _config(
            tmp_path,
            {
                "a": HTTP,
                "b": {
                    "command": "npx",
                    "args": ["-y", "z"],
                    "env": {"JIRA_TOKEN": "x"},
                },
            },
        )
        res = runner.invoke(app, ["affected", CVE, "--path", str(cfg)])
        assert res.exit_code == 1
        assert "Respond" in res.output
        assert "JIRA_TOKEN" in res.output
        assert "also set on custom/b" in res.output
        assert "s3cr3t-value" not in res.output

    def test_json_has_respond_without_values(self, tmp_path: Path) -> None:
        cfg = _config(tmp_path, {"a": HTTP})
        res = runner.invoke(app, ["affected", CVE, "--path", str(cfg), "-f", "json"])
        doc = json.loads(res.output)
        assert doc["respond"][0]["could_read"] == ["JIRA_TOKEN", "JIRA_URL"]
        assert "s3cr3t-value" not in res.output

    def test_not_affected_servers_get_no_respond(self, tmp_path: Path) -> None:
        stdio = {"command": "uvx", "args": ["mcp-atlassian==0.21.0"], "env": {"T": "1"}}
        cfg = _config(tmp_path, {"a": stdio})
        res = runner.invoke(app, ["affected", CVE, "--path", str(cfg), "-f", "json"])
        assert json.loads(res.output)["respond"] == []

    def test_policy_out_writes_for_affected_only(self, tmp_path: Path) -> None:
        stdio = {"command": "uvx", "args": ["mcp-atlassian==0.21.0"]}
        cfg = _config(tmp_path, {"a": HTTP, "b": stdio})
        out = tmp_path / "p" / "policy.json"
        res = runner.invoke(
            app, ["affected", CVE, "--path", str(cfg), "--policy-out", str(out)]
        )
        assert res.exit_code == 1
        doc = json.loads(out.read_text())
        assert len(doc["deniedMcpServers"]) == 1
        assert "s3cr3t-value" not in out.read_text()

    def test_policy_out_with_nothing_affected_writes_nothing(
        self, tmp_path: Path
    ) -> None:
        cfg = _config(tmp_path, {"b": {"command": "npx", "args": ["-y", "left-pad"]}})
        out = tmp_path / "policy.json"
        res = runner.invoke(
            app, ["affected", CVE, "--path", str(cfg), "--policy-out", str(out)]
        )
        assert res.exit_code == 0
        assert not out.exists()

    def test_policy_out_refuses_the_managed_directory(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from mcp_audit.plugins import mods

        managed = tmp_path / "managed"
        managed.mkdir()
        monkeypatch.setattr(mods, "managed_settings_dir", lambda: managed)
        cfg = _config(tmp_path, {"a": HTTP})
        target = managed / "managed-settings.d" / "x.json"
        res = runner.invoke(
            app, ["affected", CVE, "--path", str(cfg), "--policy-out", str(target)]
        )
        assert res.exit_code == 2
        assert not target.exists()

    def test_policy_out_unwritable_is_exit_2(self, tmp_path: Path) -> None:
        cfg = _config(tmp_path, {"a": HTTP})
        res = runner.invoke(
            app, ["affected", CVE, "--path", str(cfg), "--policy-out", str(tmp_path)]
        )
        assert res.exit_code == 2
