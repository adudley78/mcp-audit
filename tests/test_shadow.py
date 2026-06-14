"""Tests for mcp-audit shadow command modules.

Covers:
  - shadow/allowlist.py: loading, parsing, unmatched-entry detection
  - shadow/classifier.py: classify() — sanctioned vs shadow
  - shadow/risk.py: score_risk() — RiskLevel per capability combination
  - shadow/events.py: ShadowEvent models, serialisation, emit()
  - shadow/state.py: ShadowState persistence
  - cli/shadow.py: integration end-to-end (JSON output shape, allowlist effect)
"""

from __future__ import annotations

import json
import platform
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from mcp_audit.models import ServerConfig, TransportType
from mcp_audit.shadow.allowlist import (
    AllowlistServerEntry,
    ShadowAllowlist,
    find_unmatched_allowlist_entries,
    load_allowlist,
)
from mcp_audit.shadow.classifier import classify
from mcp_audit.shadow.events import (
    NewShadowServerEvent,
    ServerDriftEvent,
    ServerRemovedEvent,
    ShadowServerRecord,
    emit,
    records_to_json,
)
from mcp_audit.shadow.risk import RiskLevel, score_risk
from mcp_audit.shadow.state import ShadowState

# ── Fixtures ──────────────────────────────────────────────────────────────────


def _server(
    name: str = "filesystem",
    client: str = "claude-desktop",
    command: str | None = "npx",
    args: list[str] | None = None,
    env: dict[str, str] | None = None,
    raw: dict | None = None,
) -> ServerConfig:
    return ServerConfig(
        name=name,
        client=client,
        command=command,
        args=args or ["-y", "@modelcontextprotocol/server-filesystem", "/data"],  # noqa: S108
        env=env or {},
        config_path=Path("/fake/mcp.json"),
        transport=TransportType.STDIO,
        raw=raw or {},
    )


def _allowlist(servers: list[Any] | None = None) -> ShadowAllowlist:
    return ShadowAllowlist(sanctioned_servers=servers or [])


# ── shadow/classifier.py ──────────────────────────────────────────────────────


class TestClassify:
    def test_no_allowlist_returns_shadow(self) -> None:
        assert classify(_server(), None) == "shadow"

    def test_string_match_by_package_name_in_args(self) -> None:
        al = _allowlist(["@modelcontextprotocol/server-filesystem"])
        assert classify(_server(), al) == "sanctioned"

    def test_string_match_by_server_name(self) -> None:
        al = _allowlist(["filesystem"])
        assert classify(_server(name="filesystem"), al) == "sanctioned"

    def test_string_match_by_command(self) -> None:
        al = _allowlist(["/opt/internal/mcp/postgres-server"])
        server = _server(
            name="postgres",
            command="/opt/internal/mcp/postgres-server",
            args=[],
        )
        assert classify(server, al) == "sanctioned"

    def test_no_match_returns_shadow(self) -> None:
        al = _allowlist(["@modelcontextprotocol/server-github"])
        assert classify(_server(), al) == "shadow"

    def test_structured_entry_name_match(self) -> None:
        entry = AllowlistServerEntry(name="filesystem")
        al = _allowlist([entry])
        assert classify(_server(name="filesystem"), al) == "sanctioned"

    def test_structured_entry_command_match(self) -> None:
        entry = AllowlistServerEntry(command="/opt/internal/pg")
        server = _server(name="pg", command="/opt/internal/pg", args=[])
        al = _allowlist([entry])
        assert classify(server, al) == "sanctioned"

    def test_structured_entry_name_and_command_both_must_match(self) -> None:
        entry = AllowlistServerEntry(name="postgres", command="/opt/pg")
        wrong_name = _server(name="other", command="/opt/pg", args=[])
        al = _allowlist([entry])
        assert classify(wrong_name, al) == "shadow"

    def test_structured_entry_empty_fields_never_matches(self) -> None:
        entry = AllowlistServerEntry(name=None, command=None)
        al = _allowlist([entry])
        assert classify(_server(), al) == "shadow"

    def test_case_insensitive_string_match(self) -> None:
        al = _allowlist(["FILESYSTEM"])
        assert classify(_server(name="filesystem"), al) == "sanctioned"

    def test_empty_allowlist_returns_shadow(self) -> None:
        al = _allowlist([])
        assert classify(_server(), al) == "shadow"


# ── shadow/risk.py ────────────────────────────────────────────────────────────


class TestScoreRisk:
    def test_filesystem_server_returns_low(self) -> None:
        server = _server(
            name="filesystem",
            args=["-y", "@modelcontextprotocol/server-filesystem", "/data"],
        )
        risk, rationale = score_risk(server, registry=None)
        # filesystem alone: FILE_READ + FILE_WRITE but no toxic sink → LOW
        assert risk == RiskLevel.LOW
        assert "LOW" in rationale

    def test_database_plus_network_returns_high(self) -> None:
        # A server that has both DATABASE and NETWORK_OUT caps (e.g. a custom
        # server with both keywords in its name/args).
        server = ServerConfig(
            name="db-fetch",
            client="cursor",
            command="python",
            args=["postgres-fetch-server.py"],
            env={},
            config_path=Path("/fake/mcp.json"),
            transport=TransportType.STDIO,
            raw={},
        )
        # Patch tag_server to return the toxic combination directly.
        from mcp_audit.analyzers.toxic_flow import Capability

        with patch(
            "mcp_audit.shadow.risk.tag_server",
            return_value=frozenset({Capability.DATABASE, Capability.NETWORK_OUT}),
        ):
            risk, rationale = score_risk(server, registry=None)

        assert risk == RiskLevel.HIGH
        assert "database" in rationale.lower() or "toxic" in rationale.lower()

    def test_shell_plus_network_returns_critical(self) -> None:
        from mcp_audit.analyzers.toxic_flow import Capability

        server = _server(name="evil")
        with patch(
            "mcp_audit.shadow.risk.tag_server",
            return_value=frozenset({Capability.SHELL_EXEC, Capability.NETWORK_OUT}),
        ):
            risk, rationale = score_risk(server, registry=None)

        assert risk == RiskLevel.CRITICAL

    def test_secrets_plus_network_returns_critical(self) -> None:
        from mcp_audit.analyzers.toxic_flow import Capability

        server = _server(name="vault-fetch")
        with patch(
            "mcp_audit.shadow.risk.tag_server",
            return_value=frozenset({Capability.SECRETS, Capability.NETWORK_OUT}),
        ):
            risk, rationale = score_risk(server, registry=None)

        assert risk == RiskLevel.CRITICAL

    def test_no_capabilities_no_registry_returns_unknown(self) -> None:
        # A server with no recognizable keywords and no registry entry.
        server = ServerConfig(
            name="mystery-server",
            client="cursor",
            command="/usr/local/bin/mystery",
            args=[],
            env={},
            config_path=Path("/fake/mcp.json"),
            transport=TransportType.STDIO,
            raw={},
        )
        risk, rationale = score_risk(server, registry=None)
        assert risk == RiskLevel.UNKNOWN

    def test_registry_entry_with_null_capabilities_returns_unknown(self) -> None:
        from mcp_audit.registry.loader import KnownServerRegistry, RegistryEntry

        entry = RegistryEntry(
            name="@test/server",
            source="npm",
            repo=None,
            maintainer="test",
            verified=True,
            last_verified="2026-01-01",
            known_versions=["1.0.0"],
            tags=[],
            capabilities=None,  # explicit null
        )
        registry = MagicMock(spec=KnownServerRegistry)
        registry.get.side_effect = (
            lambda pkg: entry if pkg == "@test/server" else None  # noqa: S105
        )

        server = _server(
            name="test-server",
            args=["-y", "@test/server"],
        )
        risk, rationale = score_risk(server, registry=registry)
        assert risk == RiskLevel.UNKNOWN
        assert "capability tags missing" in rationale.lower()

    def test_registry_entry_with_empty_capabilities_returns_info(self) -> None:
        from mcp_audit.registry.loader import KnownServerRegistry, RegistryEntry

        entry = RegistryEntry(
            name="@modelcontextprotocol/server-memory",
            source="npm",
            repo=None,
            maintainer="Anthropic",
            verified=True,
            last_verified="2026-01-01",
            known_versions=["1.0.0"],
            tags=[],
            capabilities=[],  # explicitly empty — verified benign
        )
        registry = MagicMock(spec=KnownServerRegistry)
        registry.get.side_effect = lambda pkg: (
            entry
            if pkg == "@modelcontextprotocol/server-memory"  # noqa: S105
            else None
        )

        server = _server(
            name="memory",
            args=["-y", "@modelcontextprotocol/server-memory"],
        )

        with patch(
            "mcp_audit.shadow.risk.tag_server",
            return_value=frozenset(),
        ):
            risk, _ = score_risk(server, registry=registry)

        assert risk == RiskLevel.INFO


# ── shadow/events.py ──────────────────────────────────────────────────────────


class TestShadowEvents:
    def _base_kwargs(self) -> dict:
        now = datetime.now(UTC)
        return {
            "host": "test-host",
            "client": "claude-desktop",
            "server_name": "filesystem",
            "package_name": "@modelcontextprotocol/server-filesystem",
            "classification": "shadow",
            "risk_level": RiskLevel.LOW,
            "capability_tags": ["file_read", "file_write"],
            "first_seen": now,
            "last_seen": now,
        }

    def test_new_shadow_server_event_has_mcp09(self) -> None:
        ev = NewShadowServerEvent(**self._base_kwargs())
        assert ev.owasp_mcp_top_10 == ["MCP09"]

    def test_server_drift_event_has_mcp09(self) -> None:
        ev = ServerDriftEvent(**self._base_kwargs(), changed_fields=["args"])
        assert ev.owasp_mcp_top_10 == ["MCP09"]

    def test_server_removed_event_has_mcp09(self) -> None:
        ev = ServerRemovedEvent(**self._base_kwargs())
        assert ev.owasp_mcp_top_10 == ["MCP09"]

    def test_new_shadow_server_event_serialises_to_json(self) -> None:
        ev = NewShadowServerEvent(**self._base_kwargs())
        data = json.loads(ev.model_dump_json())
        assert data["event_type"] == "new_shadow_server"
        assert data["owasp_mcp_top_10"] == ["MCP09"]
        assert data["classification"] == "shadow"
        assert data["risk_level"] == "LOW"
        assert "first_seen" in data
        assert "last_seen" in data

    def test_server_drift_event_serialises_changed_fields(self) -> None:
        ev = ServerDriftEvent(**self._base_kwargs(), changed_fields=["command", "args"])
        data = json.loads(ev.model_dump_json())
        assert data["changed_fields"] == ["command", "args"]

    def test_emit_stdout_writes_json_line(self, capsys: pytest.CaptureFixture) -> None:
        ev = NewShadowServerEvent(**self._base_kwargs())
        emit(ev, sink="stdout", use_json=True)
        captured = capsys.readouterr()
        parsed = json.loads(captured.out.strip())
        assert parsed["event_type"] == "new_shadow_server"

    def test_emit_file_appends_json_line(self, tmp_path: Path) -> None:
        ev = NewShadowServerEvent(**self._base_kwargs())
        out_file = tmp_path / "events.jsonl"
        emit(ev, sink="file", file_path=out_file, use_json=True)
        emit(ev, sink="file", file_path=out_file, use_json=True)
        lines = out_file.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 2
        assert json.loads(lines[0])["event_type"] == "new_shadow_server"

    def test_emit_file_raises_without_path(self) -> None:
        ev = NewShadowServerEvent(**self._base_kwargs())
        with pytest.raises(ValueError, match="file_path must be set"):
            emit(ev, sink="file", file_path=None)

    def test_records_to_json_produces_list(self) -> None:
        now = datetime.now(UTC)
        rec = ShadowServerRecord(
            host="h",
            client="cursor",
            server_name="fs",
            classification="shadow",
            risk_level=RiskLevel.LOW,
            capability_tags=["file_read"],
            first_seen=now,
            last_seen=now,
        )
        output = records_to_json([rec])
        data = json.loads(output)
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["server_name"] == "fs"


# ── shadow/state.py ───────────────────────────────────────────────────────────


class TestShadowState:
    def test_touch_creates_new_entry(self, tmp_path: Path) -> None:
        state = ShadowState(state_dir=tmp_path)
        server = _server()
        now = datetime.now(UTC)
        entry = state.touch(server, now)
        assert entry.first_seen == now
        assert entry.last_seen == now

    def test_touch_updates_existing_entry(self, tmp_path: Path) -> None:
        state = ShadowState(state_dir=tmp_path)
        server = _server()
        t1 = datetime(2026, 1, 1, tzinfo=UTC)
        t2 = datetime(2026, 1, 2, tzinfo=UTC)
        state.touch(server, t1)
        entry = state.touch(server, t2)
        assert entry.first_seen == t1
        assert entry.last_seen == t2

    def test_save_and_reload(self, tmp_path: Path) -> None:
        state = ShadowState(state_dir=tmp_path)
        server = _server()
        now = datetime.now(UTC)
        state.touch(server, now)
        state.save()
        # Reload
        state2 = ShadowState(state_dir=tmp_path)
        entry = state2.get(server)
        assert entry is not None
        assert entry.server_name == server.name

    def test_state_file_has_secure_permissions(self, tmp_path: Path) -> None:
        import stat
        import sys

        if sys.platform == "win32":
            pytest.skip("POSIX file permissions not enforced on Windows")

        state = ShadowState(state_dir=tmp_path)
        state.touch(_server(), datetime.now(UTC))
        state.save()
        st = (tmp_path / "state.json").stat()
        mode = stat.S_IMODE(st.st_mode)
        assert mode == 0o600

    def test_reset_clears_all_entries(self, tmp_path: Path) -> None:
        state = ShadowState(state_dir=tmp_path)
        state.touch(_server(), datetime.now(UTC))
        state.save()
        state.reset()
        assert state.all_keys() == set()
        assert not (tmp_path / "state.json").exists()


# ── shadow/allowlist.py ───────────────────────────────────────────────────────


class TestLoadAllowlist:
    def test_load_explicit_path(self, tmp_path: Path) -> None:
        f = tmp_path / "allowlist.yml"
        f.write_text(
            "sanctioned_servers:\n  - '@modelcontextprotocol/server-filesystem'\n",
            encoding="utf-8",
        )
        al = load_allowlist(f)
        assert al is not None
        assert len(al.sanctioned_servers) == 1

    def test_missing_explicit_path_raises(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="not found"):
            load_allowlist(tmp_path / "nonexistent.yml")

    def test_no_allowlist_returns_none(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        # Ensure user config doesn't exist for this test by patching
        with patch(
            "mcp_audit.shadow.allowlist._USER_ALLOWLIST_PATH",
            tmp_path / "nope.yml",
        ):
            result = load_allowlist(None)
        assert result is None

    def test_invalid_yaml_raises(self, tmp_path: Path) -> None:
        f = tmp_path / "bad.yml"
        f.write_text(":\n  - [\n", encoding="utf-8")
        with pytest.raises(ValueError, match="YAML"):
            load_allowlist(f)

    def test_structured_entry_roundtrip(self, tmp_path: Path) -> None:
        f = tmp_path / "allowlist.yml"
        f.write_text(
            "sanctioned_servers:\n  - name: postgres\n    command: /opt/pg\n",
            encoding="utf-8",
        )
        al = load_allowlist(f)
        assert al is not None
        entry = al.sanctioned_servers[0]
        assert isinstance(entry, AllowlistServerEntry)
        assert entry.name == "postgres"
        assert entry.command == "/opt/pg"


class TestFindUnmatchedAllowlistEntries:
    def test_all_matched_returns_empty(self) -> None:
        al = _allowlist(["@modelcontextprotocol/server-filesystem"])
        servers = [_server()]
        assert find_unmatched_allowlist_entries(al, servers) == []

    def test_unmatched_string_reported(self) -> None:
        al = _allowlist(["@nonexistent/server"])
        servers = [_server()]
        unmatched = find_unmatched_allowlist_entries(al, servers)
        assert len(unmatched) == 1
        assert "@nonexistent/server" in unmatched[0]

    def test_empty_allowlist_returns_empty(self) -> None:
        al = _allowlist([])
        assert find_unmatched_allowlist_entries(al, [_server()]) == []


# ── cli/shadow.py integration tests ───────────────────────────────────────────


class TestShadowCommandIntegration:
    """End-to-end tests using a synthetic home directory and config files."""

    def _write_claude_config(self, tmp_path: Path, servers: dict) -> Path:
        cfg = tmp_path / "claude_desktop_config.json"
        cfg.write_text(json.dumps({"mcpServers": servers}), encoding="utf-8")
        return cfg

    def test_no_configs_returns_empty_json(self, tmp_path: Path) -> None:
        """When no MCP configs exist, JSON output is an empty list."""
        from typer.testing import CliRunner

        from mcp_audit.cli import app

        runner = CliRunner()
        result = runner.invoke(
            app,
            [
                "shadow",
                "--format",
                "json",
                "--path",
                str(tmp_path / "nonexistent.json"),
            ],
        )
        # Exit 0 when no configs; empty array on stdout
        assert result.exit_code == 0
        output = result.stdout.strip()
        assert output == "[]"

    def test_single_server_without_allowlist_is_shadow(self, tmp_path: Path) -> None:
        """A server with no allowlist configured is classified as shadow."""
        cfg = self._write_claude_config(
            tmp_path,
            {
                "filesystem": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/data"],
                }
            },
        )
        from typer.testing import CliRunner

        from mcp_audit.cli import app

        runner = CliRunner()
        result = runner.invoke(
            app,
            ["shadow", "--format", "json", "--path", str(cfg)],
        )
        assert result.exit_code == 1  # shadow server found → exit 1
        data = json.loads(result.stdout.strip())
        assert len(data) == 1
        assert data[0]["classification"] == "shadow"
        assert data[0]["owasp_mcp_top_10"] == ["MCP09"]
        assert "server_name" in data[0]
        assert "risk_level" in data[0]
        assert "capability_tags" in data[0]
        assert "first_seen" in data[0]
        assert "last_seen" in data[0]

    def test_server_in_allowlist_is_sanctioned(self, tmp_path: Path) -> None:
        """A server named in the allowlist is classified as sanctioned."""
        cfg = self._write_claude_config(
            tmp_path,
            {
                "filesystem": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/data"],
                }
            },
        )
        al_file = tmp_path / "allowlist.yml"
        al_file.write_text(
            "sanctioned_servers:\n  - '@modelcontextprotocol/server-filesystem'\n",
            encoding="utf-8",
        )
        from typer.testing import CliRunner

        from mcp_audit.cli import app

        runner = CliRunner()
        result = runner.invoke(
            app,
            [
                "shadow",
                "--format",
                "json",
                "--path",
                str(cfg),
                "--allowlist",
                str(al_file),
            ],
        )
        assert result.exit_code == 0  # all sanctioned → exit 0
        data = json.loads(result.stdout.strip())
        assert len(data) == 1
        assert data[0]["classification"] == "sanctioned"

    def test_two_servers_deduplication(self, tmp_path: Path) -> None:
        """Multiple servers in one config are all included, without duplication."""
        cfg = self._write_claude_config(
            tmp_path,
            {
                "filesystem": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/data"],
                },
                "github": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-github"],
                    "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_fake"},
                },
            },
        )
        from typer.testing import CliRunner

        from mcp_audit.cli import app

        runner = CliRunner()
        result = runner.invoke(
            app,
            ["shadow", "--format", "json", "--path", str(cfg)],
        )
        data = json.loads(result.stdout.strip())
        names = {r["server_name"] for r in data}
        assert "filesystem" in names
        assert "github" in names
        assert len(names) == 2  # no duplication

    def test_json_output_includes_host_field(self, tmp_path: Path) -> None:
        cfg = self._write_claude_config(
            tmp_path,
            {
                "filesystem": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/data"],
                }
            },
        )
        from typer.testing import CliRunner

        from mcp_audit.cli import app

        runner = CliRunner()
        result = runner.invoke(
            app,
            ["shadow", "--format", "json", "--path", str(cfg)],
        )
        data = json.loads(result.stdout.strip())
        assert data[0]["host"] == platform.node()

    def test_missing_allowlist_path_exits_2(self, tmp_path: Path) -> None:
        from typer.testing import CliRunner

        from mcp_audit.cli import app

        runner = CliRunner()
        result = runner.invoke(
            app,
            ["shadow", "--allowlist", str(tmp_path / "nonexistent.yml")],
        )
        assert result.exit_code == 2

    def test_terminal_text_output_distinguishes_shadow_and_sanctioned(
        self, tmp_path: Path
    ) -> None:
        """Default text output shows 'shadow' and 'sanctioned' classifications."""
        cfg = self._write_claude_config(
            tmp_path,
            {
                "filesystem": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/data"],
                },
                "github": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-github"],
                },
            },
        )
        al_file = tmp_path / "allowlist.yml"
        al_file.write_text(
            "sanctioned_servers:\n  - '@modelcontextprotocol/server-filesystem'\n",
            encoding="utf-8",
        )
        from typer.testing import CliRunner

        from mcp_audit.cli import app

        runner = CliRunner()
        result = runner.invoke(
            app,
            ["shadow", "--path", str(cfg), "--allowlist", str(al_file)],
        )
        # Exit 1 because github is shadow
        assert result.exit_code == 1
        assert (
            "shadow" in result.output.lower() or "sanctioned" in result.output.lower()
        )

    def test_terminal_text_output_no_servers(self, tmp_path: Path) -> None:
        """Text mode with no servers prints a message and exits 0."""
        from typer.testing import CliRunner

        from mcp_audit.cli import app

        runner = CliRunner()
        result = runner.invoke(
            app,
            ["shadow", "--path", str(tmp_path / "nonexistent_dir")],
        )
        assert result.exit_code == 0

    def test_json_output_to_file(self, tmp_path: Path) -> None:
        """--output-file writes JSON to disk instead of stdout."""
        cfg = self._write_claude_config(
            tmp_path,
            {
                "filesystem": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/data"],
                }
            },
        )
        out_file = tmp_path / "results" / "shadow.json"
        from typer.testing import CliRunner

        from mcp_audit.cli import app

        runner = CliRunner()
        result = runner.invoke(
            app,
            [
                "shadow",
                "--format",
                "json",
                "--path",
                str(cfg),
                "--output-file",
                str(out_file),
            ],
        )
        assert result.exit_code == 1  # shadow found
        assert out_file.exists()
        data = json.loads(out_file.read_text(encoding="utf-8"))
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["classification"] == "shadow"

    def test_empty_servers_in_non_empty_config_json_output(
        self, tmp_path: Path
    ) -> None:
        """Config file exists but has no servers → JSON output is empty list."""
        cfg = tmp_path / "empty_mcp.json"
        cfg.write_text('{"mcpServers": {}}', encoding="utf-8")
        from typer.testing import CliRunner

        from mcp_audit.cli import app

        runner = CliRunner()
        result = runner.invoke(
            app,
            ["shadow", "--format", "json", "--path", str(cfg)],
        )
        assert result.exit_code == 0
        assert result.stdout.strip() == "[]"

    def test_allowlist_invalid_yaml_exits_2(self, tmp_path: Path) -> None:
        """An allowlist file with invalid schema raises ValueError → exit 2."""
        al_file = tmp_path / "bad_schema.yml"
        # Valid YAML but wrong top-level type (not a mapping)
        al_file.write_text("- not a mapping\n", encoding="utf-8")
        cfg = self._write_claude_config(
            tmp_path,
            {"fs": {"command": "npx", "args": ["-y", "@fs/server"]}},
        )
        from typer.testing import CliRunner

        from mcp_audit.cli import app

        runner = CliRunner()
        result = runner.invoke(
            app,
            ["shadow", "--path", str(cfg), "--allowlist", str(al_file)],
        )
        assert result.exit_code == 2

    def test_load_registry_error_exits_2(self, tmp_path: Path) -> None:  # noqa: ARG002
        """When load_registry raises FileNotFoundError, exit code is 2."""
        from unittest.mock import patch

        from typer.testing import CliRunner

        from mcp_audit.cli import app

        with patch(
            "mcp_audit.cli.shadow.load_registry",
            side_effect=FileNotFoundError("registry not found"),
        ):
            runner = CliRunner()
            result = runner.invoke(app, ["shadow", "--format", "json"])
        assert result.exit_code == 2

    def test_unmatched_allowlist_warning_in_terminal_output(
        self, tmp_path: Path
    ) -> None:
        """An allowlist entry that matches nothing triggers a warning."""
        cfg = self._write_claude_config(
            tmp_path,
            {
                "filesystem": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/data"],
                }
            },
        )
        al_file = tmp_path / "allowlist.yml"
        al_file.write_text(
            "sanctioned_servers:\n  - '@nonexistent/package'\n",
            encoding="utf-8",
        )
        from typer.testing import CliRunner

        from mcp_audit.cli import app

        runner = CliRunner()
        result = runner.invoke(
            app,
            ["shadow", "--path", str(cfg), "--allowlist", str(al_file)],
        )
        # exit 1 — shadow server present
        assert result.exit_code == 1
        assert "shadow" in result.output.lower()


# ── cli/shadow.py — _emit_change_events ───────────────────────────────────────


class TestEmitChangeEvents:
    """Direct tests for _emit_change_events without running the full daemon."""

    def _server(
        self,
        name: str = "filesystem",
        client: str = "claude-desktop",
        command: str | None = "npx",
        args: list[str] | None = None,
        env: dict[str, str] | None = None,
        raw: dict | None = None,
    ) -> ServerConfig:
        return ServerConfig(
            name=name,
            client=client,
            command=command,
            args=args or ["-y", "@modelcontextprotocol/server-filesystem", "/data"],
            env=env or {},
            config_path=Path("/fake/mcp.json"),
            transport=TransportType.STDIO,
            raw=raw or {},
        )

    def test_new_server_emits_new_shadow_server_event(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        from datetime import UTC, datetime
        from unittest.mock import MagicMock

        from mcp_audit.cli.shadow import _emit_change_events
        from mcp_audit.registry.loader import KnownServerRegistry
        from mcp_audit.shadow.state import ShadowState

        state = ShadowState(state_dir=tmp_path)
        registry = MagicMock(spec=KnownServerRegistry)
        registry.get.return_value = None

        server = self._server()
        now = datetime.now(UTC)

        _emit_change_events(
            old_servers=[],
            new_servers=[server],
            allowlist=None,
            registry=registry,
            state=state,
            now=now,
            use_json=True,
            event_sink_path=None,
        )

        captured = capsys.readouterr()
        event = json.loads(captured.out.strip())
        assert event["event_type"] == "new_shadow_server"
        assert event["server_name"] == "filesystem"

    def test_removed_server_emits_removed_event(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        from datetime import UTC, datetime
        from unittest.mock import MagicMock

        from mcp_audit.cli.shadow import _emit_change_events
        from mcp_audit.registry.loader import KnownServerRegistry
        from mcp_audit.shadow.state import ShadowState

        state = ShadowState(state_dir=tmp_path)
        registry = MagicMock(spec=KnownServerRegistry)
        registry.get.return_value = None

        server = self._server()
        now = datetime.now(UTC)
        # seed state so the server shows as previously seen
        state.touch(server, now)

        _emit_change_events(
            old_servers=[server],
            new_servers=[],
            allowlist=None,
            registry=registry,
            state=state,
            now=now,
            use_json=True,
            event_sink_path=None,
        )

        captured = capsys.readouterr()
        event = json.loads(captured.out.strip())
        assert event["event_type"] == "server_removed"

    def test_changed_args_emits_drift_event(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        from datetime import UTC, datetime
        from unittest.mock import MagicMock

        from mcp_audit.cli.shadow import _emit_change_events
        from mcp_audit.registry.loader import KnownServerRegistry
        from mcp_audit.shadow.state import ShadowState

        state = ShadowState(state_dir=tmp_path)
        registry = MagicMock(spec=KnownServerRegistry)
        registry.get.return_value = None

        old_server = self._server(args=["-y", "@mcp/server", "/old"])
        new_server = self._server(args=["-y", "@mcp/server", "/new"])
        now = datetime.now(UTC)
        state.touch(old_server, now)

        _emit_change_events(
            old_servers=[old_server],
            new_servers=[new_server],
            allowlist=None,
            registry=registry,
            state=state,
            now=now,
            use_json=True,
            event_sink_path=None,
        )

        captured = capsys.readouterr()
        event = json.loads(captured.out.strip())
        assert event["event_type"] == "server_drift"
        assert "args" in event["changed_fields"]

    def test_unchanged_server_emits_no_event(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        from datetime import UTC, datetime
        from unittest.mock import MagicMock

        from mcp_audit.cli.shadow import _emit_change_events
        from mcp_audit.registry.loader import KnownServerRegistry
        from mcp_audit.shadow.state import ShadowState

        state = ShadowState(state_dir=tmp_path)
        registry = MagicMock(spec=KnownServerRegistry)
        registry.get.return_value = None

        server = self._server()
        now = datetime.now(UTC)
        state.touch(server, now)

        _emit_change_events(
            old_servers=[server],
            new_servers=[server],
            allowlist=None,
            registry=registry,
            state=state,
            now=now,
            use_json=True,
            event_sink_path=None,
        )

        captured = capsys.readouterr()
        # No drift events — identical server
        assert captured.out.strip() == ""

    def test_events_written_to_file_sink(self, tmp_path: Path) -> None:
        from datetime import UTC, datetime
        from unittest.mock import MagicMock

        from mcp_audit.cli.shadow import _emit_change_events
        from mcp_audit.registry.loader import KnownServerRegistry
        from mcp_audit.shadow.state import ShadowState

        state = ShadowState(state_dir=tmp_path)
        registry = MagicMock(spec=KnownServerRegistry)
        registry.get.return_value = None

        server = self._server()
        now = datetime.now(UTC)
        out_file = tmp_path / "events.jsonl"

        _emit_change_events(
            old_servers=[],
            new_servers=[server],
            allowlist=None,
            registry=registry,
            state=state,
            now=now,
            use_json=True,
            event_sink_path=out_file,
        )

        assert out_file.exists()
        event = json.loads(out_file.read_text(encoding="utf-8").strip())
        assert event["event_type"] == "new_shadow_server"


# ── cli/shadow.py — continuous mode ───────────────────────────────────────────


class TestShadowContinuousMode:
    """Test the --continuous daemon path via a mocked ConfigWatcher."""

    def _write_claude_config(self, tmp_path: Path, servers: dict) -> Path:
        cfg = tmp_path / "claude_desktop_config.json"
        cfg.write_text(json.dumps({"mcpServers": servers}), encoding="utf-8")
        return cfg

    def test_continuous_mode_starts_and_runs_initial_sweep(
        self, tmp_path: Path
    ) -> None:
        """--continuous completes an initial sweep and then calls ConfigWatcher."""
        cfg = self._write_claude_config(
            tmp_path,
            {
                "filesystem": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/data"],
                }
            },
        )
        import contextlib
        from unittest.mock import MagicMock, patch

        from typer.testing import CliRunner

        from mcp_audit.cli import app

        mock_watcher = MagicMock()
        mock_watcher.run_until_interrupt.side_effect = KeyboardInterrupt

        # ConfigWatcher is imported inside the function, so patch at the source module
        with patch("mcp_audit.watcher.ConfigWatcher", return_value=mock_watcher):
            runner = CliRunner()
            with contextlib.suppress(SystemExit, KeyboardInterrupt):
                runner.invoke(
                    app,
                    [
                        "shadow",
                        "--format",
                        "json",
                        "--continuous",
                        "--path",
                        str(cfg),
                    ],
                )

        # Watcher was instantiated and run was called
        assert mock_watcher.run_until_interrupt.called

    def test_continuous_mode_on_change_callback_emits_events(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        """The _on_change callback fires _emit_change_events correctly."""
        cfg = self._write_claude_config(
            tmp_path,
            {
                "filesystem": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/data"],
                }
            },
        )
        import contextlib
        from unittest.mock import patch

        from typer.testing import CliRunner

        from mcp_audit.cli import app

        captured_callback: list = []

        class FakeWatcher:
            def __init__(self, on_change_callback, extra_paths):  # noqa: ARG002
                captured_callback.append(on_change_callback)

            def run_until_interrupt(self) -> None:
                raise KeyboardInterrupt

        with patch("mcp_audit.watcher.ConfigWatcher", FakeWatcher):
            runner = CliRunner()
            with contextlib.suppress(SystemExit, KeyboardInterrupt):
                runner.invoke(
                    app,
                    [
                        "shadow",
                        "--format",
                        "json",
                        "--continuous",
                        "--path",
                        str(cfg),
                    ],
                )

        assert len(captured_callback) == 1
        callback = captured_callback[0]

        # Simulate a config change: a new server appears
        new_cfg = self._write_claude_config(
            tmp_path,
            {
                "filesystem": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/data"],
                },
                "github": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-github"],
                },
            },
        )

        with patch(
            "mcp_audit.cli.shadow._discover_all_servers",
            return_value=(
                [
                    ServerConfig(
                        name="github",
                        client="claude-desktop",
                        command="npx",
                        args=["-y", "@modelcontextprotocol/server-github"],
                        env={},
                        config_path=new_cfg,
                        transport=TransportType.STDIO,
                        raw={},
                    )
                ],
                1,
            ),
        ):
            callback(new_cfg, "modified")

        captured = capsys.readouterr()
        if captured.out.strip():
            event_types = set()
            for line in captured.out.strip().splitlines():
                if line.strip():
                    event = json.loads(line)
                    event_types.add(event["event_type"])
            assert event_types <= {
                "new_shadow_server",
                "server_drift",
                "server_removed",
            }
            assert len(event_types) > 0
