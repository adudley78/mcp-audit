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
        entry, note = respond.policy_entry(_srv())
        assert entry == {"serverCommand": ["uvx", "mcp-atlassian==0.21.0"]}
        assert note is None

    def test_transport_words_and_yes_flag_are_allowed(self) -> None:
        s = _srv(
            command="npx", args=["-y", "mcp-atlassian@0.21.0", "--transport", "sse"]
        )
        entry, _ = respond.policy_entry(s)
        assert entry is not None

    @pytest.mark.parametrize(
        "args",
        [
            ["mcp-atlassian==0.21.0", "--token=abc"],
            ["mcp-atlassian==0.21.0", "--api-key", "abc"],
            ["mcp-atlassian==0.21.0", "${HOME}/y"],
            ["mcp-atlassian==0.21.0", "--bearer", "X"],
            ["mcp-atlassian==0.21.0", "--cookie", "session=X"],
            ["mcp-atlassian==0.21.0", "-u", "user:X"],
            ["mcp-atlassian==0.21.0", "SECRETPOSITIONAL123"],
            ["mcp-atlassian==0.21.0", "https://h.example/api/s/PATHSECRET/mcp"],
            ["other-pkg==1.0", "mcp-atlassian==0.21.0"],
        ],
    )
    def test_anything_that_might_be_a_secret_writes_no_entry(self, args: list) -> None:
        entry, note = respond.policy_entry(_srv("named", args=args))
        assert entry is None
        assert note is not None and "by hand" in note

    def test_no_name_entries_are_ever_written(self) -> None:
        doc, notes = respond.policy_document(
            [_srv("jira", args=["x", "--jira-token", "t"])]
        )
        assert doc == {"deniedMcpServers": []}
        assert notes

    def test_document_deduplicates(self) -> None:
        doc, notes = respond.policy_document([_srv("a"), _srv("b")])
        assert doc == {
            "deniedMcpServers": [{"serverCommand": ["uvx", "mcp-atlassian==0.21.0"]}]
        }
        assert notes == []

    def test_every_written_entry_matches_its_server(self) -> None:
        servers = [
            _srv("a"),
            _srv("b", command="pipx", args=["run", "mcp-atlassian==0.21.0"]),
        ]
        doc, _ = respond.policy_document(servers)
        assert len(doc["deniedMcpServers"]) == len(servers)
        for server, entry in zip(servers, doc["deniedMcpServers"], strict=True):
            value = tuple(entry["serverCommand"])
            assert (
                entry_matches(PolicyEntry("serverCommand", value, Path("x")), server)
                is True
            )


class TestFlagNames:
    @pytest.mark.parametrize(
        ("arg", "name"),
        [
            ("--api-key:sk-ant-api03-abcdef0123456789", "--api-key"),
            ("--token=abc", "--token"),
            ("-HAuthorization: Bearer ghp_aBcD1234567890", "-H"),
            ("--header=X-Key: v", "--header"),
        ],
    )
    def test_value_never_survives(self, arg: str, name: str) -> None:
        item = respond.build(_srv(args=[arg]), [_srv(args=[arg])], [])
        assert item.names() == [name]

    def test_json_names_are_scrubbed(self, tmp_path: Path) -> None:
        cfg = _config(
            tmp_path,
            {
                "a": {
                    "command": "uvx",
                    "args": [
                        "mcp-atlassian==0.21.0",
                        "--transport",
                        "sse",
                        "-HAuthorization: Bearer ghp_aBcD1234567890",
                        "--api-key:sk-ant-api03-zzzz",
                    ],
                }
            },
        )
        res = runner.invoke(app, ["affected", CVE, "--path", str(cfg), "-f", "json"])
        assert "ghp_" not in res.output and "sk-ant" not in res.output
        assert json.loads(res.output)["respond"][0]["could_read"] == ["--api-key", "-H"]


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


class TestPolicyFileSafety:
    def _cfg(self, tmp_path: Path) -> Path:
        return _config(
            tmp_path,
            {
                "a": {
                    "command": "uvx",
                    "args": ["mcp-atlassian==0.21.0", "--transport", "sse"],
                }
            },
        )

    def test_existing_file_is_never_overwritten(self, tmp_path: Path) -> None:
        out = tmp_path / "keep.json"
        out.write_text("precious")
        res = runner.invoke(
            app,
            [
                "affected",
                CVE,
                "--path",
                str(self._cfg(tmp_path)),
                "--policy-out",
                str(out),
            ],
        )
        assert res.exit_code == 2
        assert out.read_text() == "precious"

    def test_same_path_as_output_is_refused(self, tmp_path: Path) -> None:
        out = tmp_path / "same.json"
        res = runner.invoke(
            app,
            [
                "affected",
                CVE,
                "--path",
                str(self._cfg(tmp_path)),
                "-f",
                "json",
                "-o",
                str(out),
                "--policy-out",
                str(out),
            ],
        )
        assert res.exit_code == 2

    def test_note_reaches_stderr_for_machine_formats(self, tmp_path: Path) -> None:
        out = tmp_path / "p.json"
        res = runner.invoke(
            app,
            [
                "affected",
                CVE,
                "--path",
                str(self._cfg(tmp_path)),
                "-f",
                "sarif",
                "--policy-out",
                str(out),
            ],
        )
        assert "deniedMcpServers" in res.output
        assert json.loads(out.read_text())["deniedMcpServers"]

    def test_research_query_says_no_file(self, tmp_path: Path) -> None:
        out = tmp_path / "r.json"
        res = runner.invoke(
            app,
            [
                "affected",
                "x_MCPRS-4ad8c07d80d7",
                "--policy-out",
                str(out),
                "-f",
                "json",
            ],
        )
        assert not out.exists()
        assert "no servers" in res.output

    def test_managed_dir_check_ignores_case(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from mcp_audit.plugins import mods

        managed = tmp_path / "Managed"
        managed.mkdir()
        monkeypatch.setattr(mods, "managed_settings_dir", lambda: managed)
        assert respond.inside_managed_dir(tmp_path / "MANAGED" / "x.json")

    def test_deleted_cwd_does_not_crash(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def boom() -> Path:
            raise FileNotFoundError("cwd gone")

        monkeypatch.setattr(Path, "cwd", staticmethod(boom))
        res = runner.invoke(app, ["affected", CVE, "--path", str(self._cfg(tmp_path))])
        assert res.exit_code == 1
        assert "Traceback" not in res.output
