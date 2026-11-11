"""Tests for wrapping MCP config entries in ``mcp-audit run`` (EPIC-0009 Story 1.2)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_audit.config_parser import parse_config
from mcp_audit.discovery import DiscoveredConfig
from mcp_audit.governance.evaluator import evaluate_governance
from mcp_audit.governance.models import GovernancePolicy
from mcp_audit.runtime.wrapping import (
    entry_digest,
    inner_launch,
    is_wrapper_command,
    unwrap_entry,
    wrap_entry,
    wrap_status,
    wrapper_options,
)

EXE = "/opt/venv/bin/mcp-audit"
ENTRY = {
    "type": "stdio",
    "command": "npx",
    "args": ["-y", "@modelcontextprotocol/server-memory@2.1.1"],
    "env": {"MEMORY_FILE": "/srv/m.json"},
    "cwd": "/srv",
}


def _wrap(entry: dict = ENTRY, mode: str = "monitor") -> dict:
    return wrap_entry(
        entry, exe=EXE, config_path="/p/.mcp.json", server="mem", mode=mode
    )


class TestWrapperCommand:
    @pytest.mark.parametrize(
        "command",
        [
            "mcp-audit",
            "mcp-audit.exe",
            "/usr/local/bin/mcp-audit",
            "/Users/a/.local/bin/mcp-audit",
            "C:\\Tools\\mcp-audit.exe",
            "/opt/mcp-audit-linux-x86_64",
            "/opt/mcp-audit-darwin-arm64",
        ],
    )
    def test_recognised(self, command: str) -> None:
        assert is_wrapper_command(command)

    @pytest.mark.parametrize(
        "command",
        [
            "./mcp-audit",
            "bin/mcp-audit",
            "mcp-auditor",
            "/x/mcp-audit-evil",
            "npx",
            "",
            None,
        ],
    )
    def test_not_recognised(self, command: object) -> None:
        # A relative path could be planted by a cloned repository.
        assert not is_wrapper_command(command)


class TestInnerLaunch:
    def test_wrapped(self) -> None:
        wrapped = _wrap()
        assert inner_launch(wrapped["command"], wrapped["args"]) == (
            "npx",
            ["-y", "@modelcontextprotocol/server-memory@2.1.1"],
        )

    @pytest.mark.parametrize(
        "args",
        [
            ["run", "--config", "x"],  # no --
            ["run", "--"],  # nothing after --
            ["scan", "--", "npx"],  # not run
            [],
            "run -- npx",
            ["run", "--", 3],
        ],
    )
    def test_not_wrapped(self, args: object) -> None:
        assert inner_launch("mcp-audit", args) is None

    def test_options(self) -> None:
        opts = wrapper_options(_wrap(mode="enforce")["args"])
        assert opts["mode"] == "enforce"
        assert opts["server"] == "mem"
        assert opts["config"] == "/p/.mcp.json"
        assert len(opts["original-sha256"]) == 64


class TestWrapUnwrap:
    def test_only_command_and_args_change_in_place(self) -> None:
        wrapped = _wrap()
        assert list(wrapped) == ["type", "command", "args", "env", "cwd"]
        assert wrapped["command"] == EXE
        assert {k: wrapped[k] for k in ("type", "env", "cwd")} == {
            k: ENTRY[k] for k in ("type", "env", "cwd")
        }
        assert wrapped["args"][-3:] == ["npx", *ENTRY["args"]]

    def test_round_trip_is_exact_and_verified(self) -> None:
        restored, verified = unwrap_entry(_wrap())
        assert verified
        assert restored == ENTRY
        assert list(restored) == list(ENTRY)
        assert entry_digest(restored) == entry_digest(ENTRY)

    def test_entry_without_args_key_round_trips(self) -> None:
        entry = {"command": "my-server"}
        restored, verified = unwrap_entry(_wrap(entry))
        assert verified
        assert restored == entry  # no "args": [] added

    def test_entry_with_empty_args_round_trips(self) -> None:
        entry = {"command": "my-server", "args": []}
        restored, verified = unwrap_entry(_wrap(entry))
        assert verified
        assert restored == entry

    def test_edited_after_wrap_is_restored_unverified(self) -> None:
        wrapped = _wrap()
        wrapped["env"] = {"NEW": "1"}
        restored, verified = unwrap_entry(wrapped)
        assert not verified
        assert restored["env"] == {"NEW": "1"}
        assert restored["command"] == "npx"

    def test_unwrap_of_plain_entry_is_none(self) -> None:
        assert unwrap_entry(ENTRY) is None

    @pytest.mark.parametrize(
        ("entry", "message"),
        [
            ({"url": "https://x.example/mcp"}, "no command"),
            ({"command": "npx", "args": "-y pkg"}, "not a list"),
        ],
    )
    def test_refuses_non_stdio(self, entry: dict, message: str) -> None:
        with pytest.raises(ValueError, match=message):
            _wrap(entry)

    def test_refuses_double_wrap(self) -> None:
        with pytest.raises(ValueError, match="already wrapped"):
            _wrap(_wrap())

    def test_refuses_unknown_mode(self) -> None:
        with pytest.raises(ValueError, match="mode"):
            _wrap(mode="audit")


def _parse(tmp_path: Path, servers: dict, client: str = "claude-code") -> list:
    path = tmp_path / ".mcp.json"
    path.write_text(json.dumps({"mcpServers": servers}))
    return parse_config(
        DiscoveredConfig(client_name=client, root_key="mcpServers", path=path)
    )


class TestParser:
    def test_wrapped_entry_is_analysed_as_the_inner_server(
        self, tmp_path: Path
    ) -> None:
        (server,) = _parse(tmp_path, {"mem": _wrap(mode="enforce")})
        assert server.command == "npx"
        assert server.args == ENTRY["args"]
        assert server.wrapped is True
        assert server.wrap_mode == "enforce"
        assert server.raw["command"] == EXE  # raw keeps what's written

    def test_plain_entry_unchanged(self, tmp_path: Path) -> None:
        (server,) = _parse(tmp_path, {"mem": ENTRY})
        assert server.command == "npx"
        assert server.wrapped is False
        assert server.wrap_mode is None

    def test_relative_wrapper_path_is_not_trusted(self, tmp_path: Path) -> None:
        planted = {"command": "./mcp-audit", "args": ["run", "--", "npx", "pkg"]}
        (server,) = _parse(tmp_path, {"x": planted})
        assert server.command == "./mcp-audit"
        assert server.wrapped is False


class TestStatusAndPolicy:
    def test_wrap_status(self, tmp_path: Path) -> None:
        servers = _parse(
            tmp_path,
            {
                "a": _wrap(),
                "b": _wrap(mode="enforce"),
                "c": ENTRY,
                "remote": {"url": "https://x.example/mcp"},
            },
        )
        assert wrap_status(servers) == (2, 3, {"monitor": 1, "enforce": 1})

    def test_require_wrap_reports_unwrapped_local_servers(self, tmp_path: Path) -> None:
        servers = _parse(
            tmp_path,
            {"a": _wrap(), "c": ENTRY, "remote": {"url": "https://x.example/mcp"}},
        )
        policy = GovernancePolicy.model_validate({"runtime": {"require_wrap": True}})
        findings = [
            f for f in evaluate_governance(servers, policy) if f.id == "WRAP-001"
        ]
        assert [f.server for f in findings] == ["c"]
        assert "mcp-audit wrap --server c" in findings[0].remediation

    def test_no_wrap_findings_without_the_policy(self, tmp_path: Path) -> None:
        servers = _parse(tmp_path, {"c": ENTRY})
        assert not [
            f
            for f in evaluate_governance(servers, GovernancePolicy())
            if f.id == "WRAP-001"
        ]

    def test_other_clients_are_out_of_scope(self, tmp_path: Path) -> None:
        servers = _parse(tmp_path, {"c": ENTRY}, client="claude-code-plugin")
        policy = GovernancePolicy.model_validate({"runtime": {"require_wrap": True}})
        assert not [
            f for f in evaluate_governance(servers, policy) if f.id == "WRAP-001"
        ]
