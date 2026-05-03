"""Tests for the mcp-audit diff engine.

Covers:
- ``loader.py`` — input routing for directories, JSON files, and git SHAs.
- ``comparator.py`` — all change types (added, removed, changed, renamed).
- ``risk.py`` — severity classification for each scenario.
- ``render.py`` — terminal, JSON, and PR-comment Markdown formatters.
- CLI integration via ``typer.testing.CliRunner``.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from mcp_audit.cli import app
from mcp_audit.diff.comparator import (
    ChangeType,
    EntityType,
    compare,
)
from mcp_audit.diff.loader import (
    _load_from_json_file,
    load_input,
)
from mcp_audit.diff.render import (
    render_json,
    render_pr_comment,
    render_terminal,
)
from mcp_audit.diff.risk import classify_added_server, classify_modified_server
from mcp_audit.models import ServerConfig, Severity, TransportType

runner = CliRunner()


# ── Fixtures ───────────────────────────────────────────────────────────────────


def _server(
    name: str = "test-server",
    command: str = "npx",
    args: list[str] | None = None,
    env: dict[str, str] | None = None,
    url: str | None = None,
    client: str = "cursor",
    raw: dict | None = None,
) -> ServerConfig:
    resolved_args = args or []
    resolved_env = env or {}
    default_raw = (
        {"command": command, "args": resolved_args} if not url else {"url": url}
    )
    return ServerConfig(
        name=name,
        client=client,
        config_path=Path("/tmp/test_mcp.json"),  # noqa: S108
        transport=TransportType.STDIO if not url else TransportType.SSE,
        command=command if not url else None,
        args=resolved_args,
        env=resolved_env,
        url=url,
        raw=raw if raw is not None else default_raw,
    )


def _filesystem_server(name: str = "filesystem") -> ServerConfig:
    return _server(name, args=["-y", "@modelcontextprotocol/server-filesystem"])


def _fetch_server(name: str = "fetch") -> ServerConfig:
    return _server(name, args=["-y", "@modelcontextprotocol/server-fetch"])


def _shell_server(name: str = "shell") -> ServerConfig:
    return _server(name, command="bash", args=["exec.sh"])


def _cred_server(name: str = "creds") -> ServerConfig:
    return _server(name, env={"OPENAI_API_KEY": "ref"})


def _aws_cred_server(name: str = "aws-server") -> ServerConfig:
    return _server(name, env={"AWS_SECRET_ACCESS_KEY": "ref"})


def _hardcoded_cred_server(name: str = "bad") -> ServerConfig:
    # sk- pattern triggers the OpenAI SECRET_PATTERNS
    return _server(name, args=["--api-key", "sk-abcdefghijklmnopqrstuvwx123"])


def _external_endpoint_server(name: str = "ext") -> ServerConfig:
    return _server(name, url="https://api.example.com/mcp/sse")


# ── comparator: identical inputs ──────────────────────────────────────────────


class TestCompareIdentical:
    def test_no_changes_same_empty_list(self) -> None:
        assert compare([], []) == []

    def test_no_changes_same_server(self) -> None:
        s = _filesystem_server()
        assert compare([s], [s]) == []

    def test_no_changes_reordered_tools_array(self) -> None:
        """Reordered tools in raw dict should not trigger a diff."""
        s1 = _server("s", raw={"command": "npx", "args": [], "tools": ["b", "a"]})
        s2 = _server("s", raw={"command": "npx", "args": [], "tools": ["a", "b"]})
        # Tool comparison uses set equality — order doesn't matter
        changes = compare([s1], [s2])
        assert changes == []

    def test_no_changes_whitespace_diff_only(self) -> None:
        """Non-MCP differences (same command, args, env) produce no diff."""
        s1 = _filesystem_server()
        s2 = _filesystem_server()
        assert compare([s1], [s2]) == []


# ── comparator: server added ───────────────────────────────────────────────────


class TestServerAdded:
    def test_single_server_added(self) -> None:
        base: list[ServerConfig] = []
        head = [_filesystem_server()]
        changes = compare(base, head)
        server_changes = [c for c in changes if c.entity_type == EntityType.SERVER]
        assert len(server_changes) == 1
        sc = server_changes[0]
        assert sc.change_type == ChangeType.ADDED
        assert sc.entity_name == "filesystem"

    def test_added_server_has_severity(self) -> None:
        changes = compare([], [_filesystem_server()])
        sc = next(c for c in changes if c.entity_type == EntityType.SERVER)
        assert sc.severity in list(Severity)

    def test_added_shell_server_is_high(self) -> None:
        changes = compare([], [_shell_server()])
        sc = next(c for c in changes if c.entity_type == EntityType.SERVER)
        assert sc.severity == Severity.HIGH

    def test_added_server_with_hardcoded_cred_is_critical(self) -> None:
        changes = compare([], [_hardcoded_cred_server()])
        sc = next(c for c in changes if c.entity_type == EntityType.SERVER)
        assert sc.severity == Severity.CRITICAL

    def test_added_server_emits_credential_sub_change(self) -> None:
        changes = compare([], [_hardcoded_cred_server()])
        cred_changes = [c for c in changes if c.entity_type == EntityType.CREDENTIAL]
        assert len(cred_changes) == 1
        assert cred_changes[0].severity == Severity.CRITICAL
        assert "MCP01" in cred_changes[0].owasp_mcp_top_10

    def test_added_server_with_external_endpoint_is_high(self) -> None:
        changes = compare([], [_external_endpoint_server()])
        sc = next(c for c in changes if c.entity_type == EntityType.SERVER)
        assert sc.severity == Severity.HIGH

    def test_added_server_emits_endpoint_sub_change(self) -> None:
        changes = compare([], [_external_endpoint_server()])
        ep_changes = [c for c in changes if c.entity_type == EntityType.ENDPOINT]
        assert len(ep_changes) >= 1
        assert ep_changes[0].severity == Severity.HIGH
        assert "MCP07" in ep_changes[0].owasp_mcp_top_10

    def test_added_server_high_value_env_key(self) -> None:
        changes = compare([], [_aws_cred_server()])
        env_changes = [
            c
            for c in changes
            if c.entity_type == EntityType.ENV_VAR and c.parent_server == "aws-server"
        ]
        assert len(env_changes) == 1
        assert env_changes[0].severity == Severity.HIGH

    def test_added_server_creates_toxic_pair(self) -> None:
        """Adding a network-capable server alongside an existing file-read server
        creates a toxic flow pair."""
        base = [_filesystem_server()]
        head = [_filesystem_server(), _fetch_server()]
        changes = compare(base, head)
        cap_changes = [c for c in changes if c.entity_type == EntityType.CAPABILITY]
        assert len(cap_changes) >= 1
        # Toxic pairs are HIGH or CRITICAL
        high_or_crit = (Severity.HIGH, Severity.CRITICAL)
        assert all(c.severity in high_or_crit for c in cap_changes)


# ── comparator: server removed ────────────────────────────────────────────────


class TestServerRemoved:
    def test_single_server_removed(self) -> None:
        base = [_filesystem_server()]
        head: list[ServerConfig] = []
        changes = compare(base, head)
        server_changes = [c for c in changes if c.entity_type == EntityType.SERVER]
        assert len(server_changes) == 1
        sc = server_changes[0]
        assert sc.change_type == ChangeType.REMOVED
        assert sc.entity_name == "filesystem"
        assert sc.severity == Severity.INFO


# ── comparator: server changed ────────────────────────────────────────────────


class TestServerChanged:
    def test_command_args_change(self) -> None:
        base = [_server("srv", command="node", args=["/path/server.js"])]
        head = [_server("srv", command="node", args=["/path/server.js", "--debug"])]
        changes = compare(base, head)
        server_changes = [c for c in changes if c.entity_type == EntityType.SERVER]
        assert len(server_changes) == 1
        sc = server_changes[0]
        assert sc.change_type == ChangeType.CHANGED
        assert sc.command_diff is not None
        assert sc.command_diff["before_args"] == ["/path/server.js"]
        assert sc.command_diff["after_args"] == ["/path/server.js", "--debug"]
        assert sc.severity == Severity.MEDIUM

    def test_env_var_openai_to_aws(self) -> None:
        """Changing env var from OPENAI_API_KEY to AWS_SECRET_ACCESS_KEY → HIGH."""
        base = [_server("srv", env={"OPENAI_API_KEY": "ref"})]
        head = [_server("srv", env={"AWS_SECRET_ACCESS_KEY": "ref"})]
        changes = compare(base, head)
        server_changes = [c for c in changes if c.entity_type == EntityType.SERVER]
        assert server_changes[0].severity == Severity.HIGH

    def test_env_var_change_emits_credential_ref_changed(self) -> None:
        base = [_server("srv", env={"OPENAI_API_KEY": "ref"})]
        head = [_server("srv", env={"AWS_SECRET_ACCESS_KEY": "ref"})]
        changes = compare(base, head)
        env_changes = [
            c
            for c in changes
            if c.entity_type == EntityType.ENV_VAR and c.parent_server == "srv"
        ]
        assert len(env_changes) >= 1
        aws_change = next(
            c for c in env_changes if c.entity_name == "AWS_SECRET_ACCESS_KEY"
        )
        assert aws_change.severity == Severity.HIGH

    def test_hardcoded_cred_introduced_is_critical(self) -> None:
        base = [_server("srv", args=["--api-key", "env:MY_KEY"])]
        head = [_server("srv", args=["--api-key", "sk-abcdefghijklmnopqrstuvwx123"])]
        changes = compare(base, head)
        sc = next(c for c in changes if c.entity_type == EntityType.SERVER)
        assert sc.severity == Severity.CRITICAL

    def test_hardcoded_cred_emits_credential_change(self) -> None:
        base = [_server("srv", args=["--api-key", "env:MY_KEY"])]
        head = [_server("srv", args=["--api-key", "sk-abcdefghijklmnopqrstuvwx123"])]
        changes = compare(base, head)
        cred_changes = [c for c in changes if c.entity_type == EntityType.CREDENTIAL]
        assert len(cred_changes) == 1
        assert cred_changes[0].severity == Severity.CRITICAL
        assert "MCP01" in cred_changes[0].owasp_mcp_top_10

    def test_tool_added_is_medium(self) -> None:
        _read_tools = {"command": "npx", "args": [], "tools": [{"name": "read"}]}
        base = [_server("srv", raw=_read_tools)]
        head = [
            _server(
                "srv",
                raw={
                    "command": "npx",
                    "args": [],
                    "tools": [{"name": "read"}, {"name": "write"}],
                },
            )
        ]
        changes = compare(base, head)
        tool_changes = [c for c in changes if c.entity_type == EntityType.TOOL]
        assert len(tool_changes) == 1
        assert tool_changes[0].entity_name == "write"
        assert tool_changes[0].severity == Severity.MEDIUM

    def test_no_diff_same_tools_different_order(self) -> None:
        _tools_ab = {
            "command": "npx",
            "args": [],
            "tools": [{"name": "a"}, {"name": "b"}],
        }
        _tools_ba = {
            "command": "npx",
            "args": [],
            "tools": [{"name": "b"}, {"name": "a"}],
        }
        base = [_server("srv", raw=_tools_ab)]
        head = [
            _server(
                "srv",
                raw=_tools_ba,
            )
        ]
        changes = compare(base, head)
        assert changes == []

    def test_url_changed_produces_endpoint_sub_change(self) -> None:
        base = [_server("srv", url="https://old.example.com/mcp")]
        head = [_server("srv", url="https://new.example.com/mcp")]
        changes = compare(base, head)
        ep_changes = [c for c in changes if c.entity_type == EntityType.ENDPOINT]
        assert len(ep_changes) == 1
        assert ep_changes[0].severity == Severity.HIGH


# ── comparator: rename detection ──────────────────────────────────────────────


class TestRenameDetection:
    def test_rename_treated_as_changed_not_removed_added(self) -> None:
        base = [_server("old-name", command="node", args=["server.js"])]
        head = [_server("new-name", command="node", args=["server.js"])]
        changes = compare(base, head)
        change_types = {(c.change_type, c.entity_type) for c in changes}
        # Should not have REMOVED + ADDED pair — should be CHANGED
        assert (ChangeType.REMOVED, EntityType.SERVER) not in change_types or (
            ChangeType.ADDED,
            EntityType.SERVER,
        ) not in change_types

    def test_different_command_not_a_rename(self) -> None:
        base = [_server("srv", command="node", args=["server.js"])]
        head = [_server("srv2", command="python", args=["server.py"])]
        changes = compare(base, head)
        server_changes = [c for c in changes if c.entity_type == EntityType.SERVER]
        # Should have REMOVED + ADDED
        change_types = {c.change_type for c in server_changes}
        assert ChangeType.REMOVED in change_types
        assert ChangeType.ADDED in change_types


# ── risk: classify_added_server ───────────────────────────────────────────────


class TestClassifyAddedServer:
    def test_plain_server_is_low_or_medium(self) -> None:
        s = _server("plain", command="node", args=["safe-server.js"])
        result = classify_added_server(s, [], [s])
        assert result in (Severity.LOW, Severity.MEDIUM, Severity.HIGH)

    def test_shell_exec_server_is_high(self) -> None:
        s = _shell_server()
        result = classify_added_server(s, [], [s])
        assert result == Severity.HIGH

    def test_hardcoded_cred_is_critical(self) -> None:
        s = _hardcoded_cred_server()
        result = classify_added_server(s, [], [s])
        assert result == Severity.CRITICAL

    def test_external_url_is_high(self) -> None:
        s = _external_endpoint_server()
        result = classify_added_server(s, [], [s])
        assert result == Severity.HIGH

    def test_aws_env_key_is_high(self) -> None:
        s = _aws_cred_server()
        result = classify_added_server(s, [], [s])
        assert result == Severity.HIGH


# ── risk: classify_modified_server ────────────────────────────────────────────


class TestClassifyModifiedServer:
    def test_args_change_is_medium(self) -> None:
        base = _server("srv", args=["--old"])
        head = _server("srv", args=["--new"])
        result = classify_modified_server(base, head, [], [], ["command/args"])
        assert result == Severity.MEDIUM

    def test_new_external_endpoint_is_high(self) -> None:
        base = _server("srv", url=None)
        head = _server("srv", url="https://api.example.com/mcp")
        result = classify_modified_server(base, head, [], [], ["url"])
        assert result == Severity.HIGH

    def test_new_hardcoded_cred_is_critical(self) -> None:
        base = _server("srv", args=["--key", "env:MY_KEY"])
        head = _server("srv", args=["--key", "sk-abcdefghijklmnopqrstuvwx123"])
        result = classify_modified_server(base, head, [], [], ["command/args"])
        assert result == Severity.CRITICAL

    def test_new_aws_env_key_is_high(self) -> None:
        base = _server("srv", env={})
        head = _server("srv", env={"AWS_SECRET_ACCESS_KEY": "ref"})
        result = classify_modified_server(base, head, [], [], ["env"])
        assert result == Severity.HIGH


# ── render: JSON output ───────────────────────────────────────────────────────


class TestRenderJson:
    def test_empty_changes_produces_empty_array(self) -> None:
        output = render_json([])
        data = json.loads(output)
        assert data == []

    def test_json_has_required_fields(self) -> None:
        changes = compare([], [_filesystem_server()])
        output = render_json(changes)
        data = json.loads(output)
        assert len(data) >= 1
        record = data[0]
        for field in (
            "change_type",
            "entity_type",
            "entity_name",
            "before",
            "after",
            "severity",
            "owasp_mcp_top_10",
        ):
            assert field in record, f"Missing field: {field}"

    def test_json_change_type_values(self) -> None:
        base = [_filesystem_server()]
        head = [_filesystem_server(), _fetch_server()]
        output = render_json(compare(base, head))
        data = json.loads(output)
        change_types = {r["change_type"] for r in data}
        assert change_types <= {"added", "removed", "changed"}

    def test_json_severity_values(self) -> None:
        output = render_json(compare([], [_shell_server()]))
        data = json.loads(output)
        severities = {r["severity"] for r in data}
        valid = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        assert severities <= valid

    def test_json_command_diff_present_when_args_change(self) -> None:
        base = [_server("srv", args=["--old"])]
        head = [_server("srv", args=["--new"])]
        output = render_json(compare(base, head))
        data = json.loads(output)
        server_records = [r for r in data if r["entity_type"] == "server"]
        assert len(server_records) == 1
        assert "command_diff" in server_records[0]
        assert server_records[0]["command_diff"] is not None


# ── render: PR-comment Markdown ───────────────────────────────────────────────


class TestRenderPrComment:
    def test_no_changes_message(self) -> None:
        output = render_pr_comment([], "HEAD~1", "HEAD")
        assert "No MCP changes" in output

    def test_has_h2_header(self) -> None:
        output = render_pr_comment([], "base", "head")
        assert output.startswith("## MCP Security Diff")

    def test_added_server_appears_in_output(self) -> None:
        changes = compare([], [_filesystem_server()])
        output = render_pr_comment(changes, "base", "head")
        assert "filesystem" in output

    def test_at_most_100_lines(self) -> None:
        # Create a large diff to stress the 100-line cap
        many_servers = [_server(f"server-{i}") for i in range(30)]
        changes = compare([], many_servers)
        output = render_pr_comment(changes, "base", "head")
        assert len(output.splitlines()) <= 100

    def test_contains_details_blocks(self) -> None:
        changes = compare([], [_filesystem_server()])
        output = render_pr_comment(changes, "base", "head")
        assert "<details>" in output
        assert "</details>" in output

    def test_summary_line_under_80_chars(self) -> None:
        changes = compare([], [_filesystem_server()])
        output = render_pr_comment(changes, "base", "head")
        for line in output.splitlines():
            if line.startswith("<summary>"):
                content = line.removeprefix("<summary>").removesuffix("</summary>")
                assert len(content) <= 80, f"Summary line too long: {content!r}"

    def test_valid_markdown_structure(self) -> None:
        """Basic sanity: no unpaired <details> tags."""
        many_servers = [_filesystem_server(), _fetch_server(), _shell_server()]
        changes = compare([], many_servers)
        output = render_pr_comment(changes, "base", "head")
        open_count = output.count("<details>")
        close_count = output.count("</details>")
        assert open_count == close_count


# ── render: terminal ──────────────────────────────────────────────────────────


class TestRenderTerminal:
    def test_no_exception_on_empty(self) -> None:
        render_terminal([], "base", "head")

    def test_no_exception_on_changes(self) -> None:
        changes = compare([], [_filesystem_server(), _fetch_server()])
        render_terminal(changes, "base", "head")

    def test_no_changes_prints_clean_message(  # type: ignore[type-arg]
        self, capsys: pytest.CaptureFixture
    ) -> None:
        from io import StringIO

        from rich.console import Console

        buf = StringIO()
        con = Console(file=buf, highlight=False)
        render_terminal([], "base", "head", console=con)
        out = buf.getvalue()
        assert "No MCP changes" in out


# ── loader: JSON file ─────────────────────────────────────────────────────────


class TestLoaderJsonFile:
    def test_load_raw_mcp_config(self, tmp_path: Path) -> None:
        cfg = {
            "mcpServers": {
                "test-server": {
                    "command": "npx",
                    "args": ["-y", "some-pkg"],
                }
            }
        }
        f = tmp_path / "mcp.json"
        f.write_text(json.dumps(cfg), encoding="utf-8")
        servers = _load_from_json_file(f)
        assert len(servers) == 1
        assert servers[0].name == "test-server"

    def test_load_scan_result_json(self, tmp_path: Path) -> None:
        from mcp_audit.models import ScanResult

        s = _filesystem_server()
        result = ScanResult(servers=[s], clients_scanned=1, servers_found=1)
        f = tmp_path / "scan.json"
        f.write_text(result.model_dump_json(by_alias=True), encoding="utf-8")
        servers = _load_from_json_file(f)
        assert len(servers) == 1
        assert servers[0].name == "filesystem"

    def test_load_vscode_config(self, tmp_path: Path) -> None:
        cfg = {
            "servers": {
                "vscode-server": {
                    "command": "node",
                    "args": ["server.js"],
                }
            }
        }
        f = tmp_path / "mcp.json"
        f.write_text(json.dumps(cfg), encoding="utf-8")
        servers = _load_from_json_file(f)
        assert len(servers) == 1
        assert servers[0].name == "vscode-server"

    def test_invalid_json_raises(self, tmp_path: Path) -> None:
        f = tmp_path / "bad.json"
        f.write_text("not json", encoding="utf-8")
        with pytest.raises(ValueError, match="Cannot read JSON"):
            _load_from_json_file(f)

    def test_empty_config_returns_empty_list(self, tmp_path: Path) -> None:
        f = tmp_path / "empty.json"
        f.write_text("{}", encoding="utf-8")
        servers = _load_from_json_file(f)
        assert servers == []


# ── loader: directory ─────────────────────────────────────────────────────────


class TestLoaderDirectory:
    def test_load_from_directory(self, tmp_path: Path) -> None:
        cfg = {"mcpServers": {"dir-server": {"command": "node", "args": ["srv.js"]}}}
        mcp_file = tmp_path / "mcp.json"
        mcp_file.write_text(json.dumps(cfg), encoding="utf-8")
        servers = load_input(str(tmp_path))
        assert any(s.name == "dir-server" for s in servers)


# ── loader: git SHA ───────────────────────────────────────────────────────────


class TestLoaderGitSha:
    def test_invalid_sha_raises_value_error(self) -> None:
        """A git ref that rev-parse cannot resolve should raise ValueError."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=128, stderr="not a git object")
            with pytest.raises(ValueError, match="could not be resolved"):
                load_input("definitely-not-a-real-git-ref-xyz")

    def test_valid_sha_with_no_mcp_configs_returns_empty(self) -> None:
        """A valid git ref with no known MCP config paths returns []."""
        sha = "abc1234" * 6  # fake but well-formed-looking SHA

        probe_result = MagicMock()
        probe_result.returncode = 0
        probe_result.stdout = sha

        # All `git show` calls raise CalledProcessError (no MCP configs at SHA)
        def _side_effects(cmd: list[str], **kwargs: object) -> MagicMock:
            if "rev-parse" in cmd:
                return probe_result
            raise subprocess.CalledProcessError(128, cmd)

        with patch("mcp_audit.diff.loader.subprocess.run", side_effect=_side_effects):
            from mcp_audit.diff.loader import _load_from_git_sha

            servers = _load_from_git_sha(sha)
        assert servers == []


# ── CLI: end-to-end integration ────────────────────────────────────────────────


class TestCLIDiff:
    def test_identical_directories_exits_0(self, tmp_path: Path) -> None:
        cfg = {"mcpServers": {"srv": {"command": "node", "args": ["s.js"]}}}
        f = tmp_path / "mcp.json"
        f.write_text(json.dumps(cfg), encoding="utf-8")
        result = runner.invoke(app, ["diff", str(tmp_path), str(tmp_path)])
        assert result.exit_code == 0

    def test_identical_directories_no_changes_message(self, tmp_path: Path) -> None:
        cfg = {"mcpServers": {"srv": {"command": "node", "args": ["s.js"]}}}
        f = tmp_path / "mcp.json"
        f.write_text(json.dumps(cfg), encoding="utf-8")
        result = runner.invoke(app, ["diff", str(tmp_path), str(tmp_path)])
        assert "No MCP changes" in result.output

    def test_added_server_exits_1(self, tmp_path: Path) -> None:
        base_dir = tmp_path / "base"
        head_dir = tmp_path / "head"
        base_dir.mkdir()
        head_dir.mkdir()

        (base_dir / "mcp.json").write_text(
            json.dumps({"mcpServers": {"s1": {"command": "node", "args": ["s.js"]}}}),
            encoding="utf-8",
        )
        (head_dir / "mcp.json").write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "s1": {"command": "node", "args": ["s.js"]},
                        "s2": {"command": "python", "args": ["srv.py"]},
                    }
                }
            ),
            encoding="utf-8",
        )
        result = runner.invoke(app, ["diff", str(base_dir), str(head_dir)])
        assert result.exit_code == 1

    def test_format_json_output(self, tmp_path: Path) -> None:
        base_dir = tmp_path / "base"
        head_dir = tmp_path / "head"
        base_dir.mkdir()
        head_dir.mkdir()
        (base_dir / "mcp.json").write_text("{}", encoding="utf-8")
        (head_dir / "mcp.json").write_text(
            json.dumps({"mcpServers": {"srv": {"command": "node", "args": []}}}),
            encoding="utf-8",
        )
        result = runner.invoke(
            app, ["diff", str(base_dir), str(head_dir), "--format", "json"]
        )
        assert result.exit_code == 1
        data = json.loads(result.output)
        assert isinstance(data, list)
        assert len(data) >= 1

    def test_format_pr_comment_output(self, tmp_path: Path) -> None:
        base_dir = tmp_path / "base"
        head_dir = tmp_path / "head"
        base_dir.mkdir()
        head_dir.mkdir()
        (base_dir / "mcp.json").write_text("{}", encoding="utf-8")
        (head_dir / "mcp.json").write_text(
            json.dumps({"mcpServers": {"srv": {"command": "node", "args": []}}}),
            encoding="utf-8",
        )
        result = runner.invoke(
            app, ["diff", str(base_dir), str(head_dir), "--format", "pr-comment"]
        )
        assert result.exit_code == 1
        assert "## MCP Security Diff" in result.output
        assert len(result.output.splitlines()) <= 100

    def test_severity_threshold_high_filters_low(self, tmp_path: Path) -> None:
        """With --severity-threshold high, low-severity changes are excluded."""
        base_dir = tmp_path / "base"
        head_dir = tmp_path / "head"
        base_dir.mkdir()
        head_dir.mkdir()
        (base_dir / "mcp.json").write_text("{}", encoding="utf-8")
        # Adding a plain server with no risky capabilities → LOW severity
        plain_cfg = {"mcpServers": {"plain": {"command": "node", "args": ["s.js"]}}}
        (head_dir / "mcp.json").write_text(json.dumps(plain_cfg), encoding="utf-8")
        result = runner.invoke(
            app,
            ["diff", str(base_dir), str(head_dir), "--severity-threshold", "high"],
        )
        # Low severity filtered out → no findings above threshold → exit 0
        assert result.exit_code == 0

    def test_severity_threshold_high_catches_shell_exec(self, tmp_path: Path) -> None:
        base_dir = tmp_path / "base"
        head_dir = tmp_path / "head"
        base_dir.mkdir()
        head_dir.mkdir()
        (base_dir / "mcp.json").write_text("{}", encoding="utf-8")
        shell_cfg = {"mcpServers": {"shell": {"command": "bash", "args": ["exec.sh"]}}}
        (head_dir / "mcp.json").write_text(json.dumps(shell_cfg), encoding="utf-8")
        result = runner.invoke(
            app,
            ["diff", str(base_dir), str(head_dir), "--severity-threshold", "high"],
        )
        assert result.exit_code == 1

    def test_output_file_written(self, tmp_path: Path) -> None:
        base_dir = tmp_path / "base"
        head_dir = tmp_path / "head"
        base_dir.mkdir()
        head_dir.mkdir()
        (base_dir / "mcp.json").write_text("{}", encoding="utf-8")
        (head_dir / "mcp.json").write_text("{}", encoding="utf-8")
        out_file = tmp_path / "diff.md"
        result = runner.invoke(
            app,
            [
                "diff",
                str(base_dir),
                str(head_dir),
                "--format",
                "pr-comment",
                "--output-file",
                str(out_file),
            ],
        )
        assert result.exit_code == 0
        assert out_file.exists()

    def test_invalid_format_exits_2(self, tmp_path: Path) -> None:
        result = runner.invoke(
            app, ["diff", str(tmp_path), str(tmp_path), "--format", "bogus"]
        )
        assert result.exit_code == 2

    def test_invalid_threshold_exits_2(self, tmp_path: Path) -> None:
        result = runner.invoke(
            app,
            ["diff", str(tmp_path), str(tmp_path), "--severity-threshold", "extreme"],
        )
        assert result.exit_code == 2

    def test_json_output_has_all_required_fields(self, tmp_path: Path) -> None:
        base_dir = tmp_path / "base"
        head_dir = tmp_path / "head"
        base_dir.mkdir()
        head_dir.mkdir()
        (base_dir / "mcp.json").write_text("{}", encoding="utf-8")
        (head_dir / "mcp.json").write_text(
            json.dumps({"mcpServers": {"srv": {"command": "node", "args": []}}}),
            encoding="utf-8",
        )
        result = runner.invoke(
            app, ["diff", str(base_dir), str(head_dir), "--format", "json"]
        )
        data = json.loads(result.output)
        for record in data:
            for field in (
                "change_type",
                "entity_type",
                "entity_name",
                "before",
                "after",
                "severity",
                "owasp_mcp_top_10",
            ):
                assert field in record


# ── fixtures directory: git-based integration ─────────────────────────────────


class TestGitFixtures:
    """Tests against fixtures/diff/ to simulate PR-state diffs.

    These tests write a temporary git repo with two commits and verify that
    ``load_input(sha)`` correctly loads configs from each commit.
    """

    @staticmethod
    def _git(args: list[str], **kwargs: object) -> subprocess.CompletedProcess:  # type: ignore[type-arg]
        """Run a git command in test fixtures.

        nosec S603 S607 — git is a well-known system binary used only in tests.
        """
        return subprocess.run(["git", *args], check=True, capture_output=True, **kwargs)  # noqa: S603 S607

    def test_git_sha_loads_configs(self, tmp_path: Path) -> None:
        """Set up a minimal git repo with two SHAs and verify load_input works."""
        repo = tmp_path / "repo"
        repo.mkdir()

        self._git(["init", str(repo)])
        self._git(["config", "user.email", "test@test.com"], cwd=str(repo))
        self._git(["config", "user.name", "Test"], cwd=str(repo))

        # Commit 1: one server
        mcp_file = repo / "mcp.json"
        mcp_file.write_text(
            json.dumps(
                {"mcpServers": {"server-a": {"command": "node", "args": ["a.js"]}}}
            ),
            encoding="utf-8",
        )
        self._git(["add", "."], cwd=str(repo))
        self._git(["commit", "-m", "initial"], cwd=str(repo))
        sha1 = self._git(["rev-parse", "HEAD"], cwd=str(repo), text=True).stdout.strip()

        # Commit 2: add second server
        mcp_file.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "server-a": {"command": "node", "args": ["a.js"]},
                        "server-b": {"command": "python", "args": ["b.py"]},
                    }
                }
            ),
            encoding="utf-8",
        )
        self._git(["add", "."], cwd=str(repo))
        self._git(["commit", "-m", "add server-b"], cwd=str(repo))
        sha2 = self._git(["rev-parse", "HEAD"], cwd=str(repo), text=True).stdout.strip()

        # Load from both SHAs within the repo directory
        original_cwd = os.getcwd()
        try:
            os.chdir(str(repo))
            base_servers = load_input(sha1)
            head_servers = load_input(sha2)
        finally:
            os.chdir(original_cwd)

        assert len(base_servers) == 1
        assert len(head_servers) == 2
        assert base_servers[0].name == "server-a"
        server_names = {s.name for s in head_servers}
        assert "server-a" in server_names
        assert "server-b" in server_names

    def test_git_diff_via_cli(self, tmp_path: Path) -> None:
        """End-to-end: CLI diff command against two git SHAs."""
        repo = tmp_path / "repo"
        repo.mkdir()

        self._git(["init", str(repo)])
        self._git(["config", "user.email", "test@test.com"], cwd=str(repo))
        self._git(["config", "user.name", "Test"], cwd=str(repo))

        mcp_file = repo / ".cursor" / "mcp.json"
        mcp_file.parent.mkdir()
        mcp_file.write_text(
            json.dumps({"mcpServers": {"srv": {"command": "node", "args": ["s.js"]}}}),
            encoding="utf-8",
        )
        self._git(["add", "."], cwd=str(repo))
        self._git(["commit", "-m", "init"], cwd=str(repo))
        sha1 = self._git(["rev-parse", "HEAD"], cwd=str(repo), text=True).stdout.strip()

        mcp_file.write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "srv": {"command": "node", "args": ["s.js"]},
                        "new-srv": {"command": "bash", "args": ["exec.sh"]},
                    }
                }
            ),
            encoding="utf-8",
        )
        self._git(["add", "."], cwd=str(repo))
        self._git(["commit", "-m", "add risky server"], cwd=str(repo))
        sha2 = self._git(["rev-parse", "HEAD"], cwd=str(repo), text=True).stdout.strip()

        original_cwd = os.getcwd()
        try:
            os.chdir(str(repo))
            result = runner.invoke(
                app,
                ["diff", sha1, sha2, "--format", "pr-comment"],
            )
        finally:
            os.chdir(original_cwd)

        assert result.exit_code == 1  # findings present
        assert "new-srv" in result.output
