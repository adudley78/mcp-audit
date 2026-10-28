"""Servers behind an MCP gateway (STORY-0111): mcptoon, 1MCP, MCPHub."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest

from mcp_audit import gateways
from mcp_audit.analyzers.rug_pull import derive_state_path
from mcp_audit.analyzers.supply_chain import (
    FLAG_REDACTION_MARKER,
    REDACTION_MARKER,
    redact_env_values,
    redact_header_values,
)
from mcp_audit.config_parser import parse_config
from mcp_audit.diff.comparator import _has_hardcoded_cred
from mcp_audit.discovery import (
    DiscoveredConfig,
    discover_configs,
    discover_project_configs,
)
from mcp_audit.gateways import (
    GATEWAY_CONFIG_MAX_BYTES,
    MCPHUB_CLIENT,
    MCPTOON_CLIENT,
    ONEMCP_CLIENT,
    read_gateway_servers,
    user_gateway_config_paths,
)
from mcp_audit.lock.auto_verify import auto_verify
from mcp_audit.models import ServerConfig, TransportType
from mcp_audit.output.nucleus import format_nucleus
from mcp_audit.output.sarif import format_sarif
from mcp_audit.scanner import run_scan

# Synthetic secrets (never valid credentials).
GHP = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890"
PLAIN_KEY = "plainvalue12345zz"
DB_PASSWORD = "hunter2hunter2"  # noqa: S105 - synthetic


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _home(monkeypatch: pytest.MonkeyPatch, home: Path) -> None:
    monkeypatch.setattr("mcp_audit.gateways._gateway_home", lambda: home)
    # Keep the client configs (Claude, Cursor, …) out of these scans too.
    monkeypatch.setattr("mcp_audit.discovery._home", lambda: home / "client-home")


MCPTOON_JSON = {
    "servers": {
        "fs": {
            "transport": "stdio",
            "command": ["npx", "-y"],
            "args": ["@modelcontextprotocol/server-filesystem", "/srv/data"],
            "env": {"EXA_API_KEY": PLAIN_KEY},
        },
        "fetch": {"command": "uvx", "args": ["mcp-server-fetch"]},
        "gh": {
            "transport": "http",
            "url": "https://api.githubcopilot.com/mcp/",
            "headers": {"Authorization": f"Bearer {GHP}"},
        },
        # mcptoon drops both of these itself (fork-bomb guard).
        "mcptoon": {"command": ["mcptoon", "serve"]},
        "renamed-self": {"command": ["/usr/local/bin/mcptoon.exe"], "args": ["serve"]},
        "not-self": {"command": ["python", "-m", "mcptoon", "demo-server"]},
        "junk": ["not", "an", "object"],
    }
}


# ── Reading each gateway's format ────────────────────────────────────────────


class TestReadMcptoon:
    def test_json_entries_are_normalised(self, tmp_path: Path) -> None:
        path = _write(tmp_path / "config.json", json.dumps(MCPTOON_JSON))
        parsed = read_gateway_servers(path, MCPTOON_CLIENT)
        assert set(parsed.servers) == {"fs", "fetch", "gh", "not-self"}
        fs = parsed.servers["fs"]
        assert fs["command"] == "npx"
        assert fs["args"] == [
            "-y",
            "@modelcontextprotocol/server-filesystem",
            "/srv/data",
        ]
        assert fs["env"] == {"EXA_API_KEY": PLAIN_KEY}
        assert parsed.servers["fetch"]["command"] == "uvx"
        gh = parsed.servers["gh"]
        assert "command" not in gh and gh["url"].startswith("https://")
        assert parsed.transports["gh"] == "streamable-http"
        assert parsed.transports["fs"] == "stdio"

    def test_toml_config(self, tmp_path: Path) -> None:
        path = _write(
            tmp_path / "config.toml",
            '[servers.memory]\ntransport = "stdio"\ncommand = ["npx", "-y"]\n'
            'args = ["@modelcontextprotocol/server-memory"]\n'
            "[servers.memory.env]\nWHEN = 2026-10-28\n",
        )
        parsed = read_gateway_servers(path, MCPTOON_CLIENT)
        assert parsed.servers["memory"]["args"] == [
            "-y",
            "@modelcontextprotocol/server-memory",
        ]
        # TOML dates become text so raw stays JSON-serialisable.
        assert parsed.servers["memory"]["env"] == {"WHEN": "2026-10-28"}
        json.dumps(parsed.raw)

    def test_parse_config_builds_servers(self, tmp_path: Path) -> None:
        path = _write(tmp_path / "config.json", json.dumps(MCPTOON_JSON))
        config = DiscoveredConfig(MCPTOON_CLIENT, "servers", path)
        servers = {s.name: s for s in parse_config(config)}
        assert servers["fs"].client == MCPTOON_CLIENT
        assert servers["fs"].transport == TransportType.STDIO
        assert servers["gh"].transport == TransportType.STREAMABLE_HTTP
        assert servers["gh"].headers == {"Authorization": f"Bearer {GHP}"}
        assert config.raw == json.loads(json.dumps(MCPTOON_JSON))


class TestReadOneMcp:
    def test_defaults_env_array_templates_and_type(self, tmp_path: Path) -> None:
        doc = {
            "serverDefaults": {"env": {"SHARED": "x", "OVER": "default"}},
            "mcpServers": {
                "py": {
                    "command": "python",
                    "args": ["server.py"],
                    "env": ["PATH", "OVER=mine", "API_KEY=${SECRET_KEY}"],
                },
                "events": {"type": "sse", "url": "https://h.example/events"},
                "dup": {"command": "static-cmd"},
            },
            "mcpTemplates": {"dup": {"command": "template-cmd", "args": ["{{x}}"]}},
        }
        path = _write(tmp_path / "mcp.json", json.dumps(doc))
        parsed = read_gateway_servers(path, ONEMCP_CLIENT)
        assert parsed.servers["py"]["env"] == {
            "SHARED": "x",
            "OVER": "mine",
            "PATH": "${PATH}",
            "API_KEY": "${SECRET_KEY}",
        }
        assert parsed.transports["events"] == "sse"
        assert parsed.servers["dup"]["command"] == "template-cmd"


class TestReadMcphub:
    def test_servers_key_wins_over_mcpservers(self, tmp_path: Path) -> None:
        doc = {
            "servers": {"vscode-style": {"command": "a"}},
            "mcpServers": {"other": {"command": "b"}},
        }
        path = _write(tmp_path / "servers.json", json.dumps(doc))
        assert set(read_gateway_servers(path, MCPHUB_CLIENT).servers) == {
            "vscode-style"
        }

    def test_mcpservers_key(self, tmp_path: Path) -> None:
        doc = {"mcpServers": {"x": {"command": "a", "args": ["${cmd: op read z}"]}}}
        path = _write(tmp_path / "servers.json", json.dumps(doc))
        # Placeholders stay literal: nothing is executed or expanded.
        assert read_gateway_servers(path, MCPHUB_CLIENT).servers["x"]["args"] == [
            "${cmd: op read z}"
        ]


class TestBadFiles:
    @pytest.mark.parametrize(
        ("name", "content"),
        [
            ("config.json", "{not json"),
            ("config.toml", "[servers\n"),
            ("config.json", "[1, 2, 3]"),
        ],
    )
    def test_malformed_raises_value_error(
        self, tmp_path: Path, name: str, content: str
    ) -> None:
        path = _write(tmp_path / name, content)
        with pytest.raises(ValueError):
            read_gateway_servers(path, MCPTOON_CLIENT)

    def test_not_utf8(self, tmp_path: Path) -> None:
        path = tmp_path / "config.json"
        path.write_bytes(b'{"servers": "\xff\xfe"}')
        with pytest.raises(ValueError, match="UTF-8"):
            read_gateway_servers(path, MCPTOON_CLIENT)

    def test_oversize_is_not_read(self, tmp_path: Path) -> None:
        path = tmp_path / "config.json"
        path.write_bytes(b" " * (GATEWAY_CONFIG_MAX_BYTES + 1))
        with pytest.raises(ValueError, match="limit"):
            read_gateway_servers(path, MCPTOON_CLIENT)

    @pytest.mark.parametrize("name", ["config.json", "config.toml"])
    def test_deep_nesting_is_an_error_not_a_crash(
        self, tmp_path: Path, name: str
    ) -> None:
        depth = 200_000
        body = "[" * depth + "]" * depth
        text = body if name.endswith(".json") else f"x = {body}\n"
        path = _write(tmp_path / name, text)
        start = time.monotonic()
        with pytest.raises(ValueError):
            read_gateway_servers(path, MCPTOON_CLIENT)
        assert time.monotonic() - start < 10

    def test_server_cap_is_reported(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(gateways, "GATEWAY_MAX_SERVERS", 2)
        doc = {"servers": {f"s{i}": {"command": "x"} for i in range(5)}}
        path = _write(tmp_path / "config.json", json.dumps(doc))
        config = DiscoveredConfig(MCPTOON_CLIENT, "servers", path)
        assert len(parse_config(config)) == 2
        assert any("3 server(s)" in w for w in config.parse_warnings)

    def test_unreadable_file_is_a_scan_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _home(monkeypatch, tmp_path)
        path = _write(tmp_path / ".mcptoon" / "config.json", "{}")
        real_open = Path.open

        def deny(self: Path, *a: object, **k: object) -> object:
            if self == path:
                raise PermissionError(13, "Permission denied")
            return real_open(self, *a, **k)  # type: ignore[arg-type]

        monkeypatch.setattr(Path, "open", deny)
        monkeypatch.chdir(tmp_path / ".mcptoon")
        result = run_scan(skip_rug_pull=True)
        assert any("Cannot read" in e and "config.json" in e for e in result.errors)


# ── Where the files are ──────────────────────────────────────────────────────


class TestUserPaths:
    def test_defaults(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("mcp_audit.gateways._gateway_home", lambda: tmp_path)
        monkeypatch.setattr("mcp_audit.gateways.platform.system", lambda: "Linux")
        paths = user_gateway_config_paths()
        assert (MCPTOON_CLIENT, tmp_path / ".mcptoon" / "config.json") in paths
        assert (MCPTOON_CLIENT, tmp_path / ".mcptoon" / "config.toml") in paths
        assert (ONEMCP_CLIENT, tmp_path / ".config" / "1mcp" / "mcp.json") in paths
        assert (
            MCPHUB_CLIENT,
            tmp_path / ".config" / "mcphub" / "servers.json",
        ) in paths

    def test_windows_appdata(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("mcp_audit.gateways._gateway_home", lambda: tmp_path)
        monkeypatch.setattr("mcp_audit.gateways.platform.system", lambda: "Windows")
        appdata = tmp_path / "Roaming"
        monkeypatch.setattr(
            "mcp_audit.gateways._gateway_environ", lambda: {"APPDATA": str(appdata)}
        )
        assert (ONEMCP_CLIENT, appdata / "1mcp" / "mcp.json") in (
            user_gateway_config_paths()
        )

    def test_environment_overrides_absolute_only(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("mcp_audit.gateways._gateway_home", lambda: tmp_path)
        env = {
            "MCPTOON_HOME": str(tmp_path / "mh"),
            "XDG_CONFIG_HOME": str(tmp_path / "xdg"),
            "ONE_MCP_CONFIG_DIR": str(tmp_path / "od"),
            "ONE_MCP_CONFIG": "relative/mcp.json",
        }
        monkeypatch.setattr("mcp_audit.gateways._gateway_environ", lambda: env)
        paths = [p for _c, p in user_gateway_config_paths()]
        assert tmp_path / "mh" / "config.json" in paths
        assert tmp_path / "xdg" / "mcptoon" / "config.toml" in paths
        assert tmp_path / "od" / "mcp.json" in paths
        assert not any("relative" in str(p) for p in paths)


class TestDiscovery:
    def test_user_configs_join_default_discovery(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _home(monkeypatch, tmp_path)
        monkeypatch.chdir(_write(tmp_path / "cwd" / "x", "").parent)
        a = _write(tmp_path / ".mcptoon" / "config.json", json.dumps(MCPTOON_JSON))
        b = _write(tmp_path / ".config" / "mcphub" / "servers.json", "{}")
        found = {(c.client_name, c.path) for c in discover_configs()}
        assert (MCPTOON_CLIENT, a) in found
        assert (MCPHUB_CLIENT, b) in found
        assert not any(
            c.client_name in gateways.GATEWAY_UPSTREAM_CLIENTS
            for c in discover_configs(include_gateways=False)
        )
        # An explicit path never pulls them in.
        other = _write(tmp_path / "explicit.json", "{}")
        assert all(
            c.client_name == "custom"
            for c in discover_configs(extra_paths=[other], skip_auto_discovery=True)
        )

    def test_symlinked_user_config_is_info_shaped(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _home(monkeypatch, tmp_path)
        monkeypatch.chdir(_write(tmp_path / "cwd" / "x", "").parent)
        real = _write(tmp_path / "dotfiles" / "mcptoon.json", "{}")
        link = tmp_path / ".mcptoon" / "config.json"
        link.parent.mkdir()
        link.symlink_to(real)
        config = next(c for c in discover_configs() if c.path == link)
        assert config.is_symlink and config.symlink_root is None

    def test_cwd_project_files_are_project_scoped(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _home(monkeypatch, tmp_path / "home")
        repo = tmp_path / "repo"
        a = _write(repo / ".mcptoon.json", json.dumps(MCPTOON_JSON))
        b = _write(repo / ".mcphub" / "servers.json", "{}")
        monkeypatch.chdir(repo)
        found = {c.path: c for c in discover_configs()}
        assert found[a].is_project_scoped and not found[a].is_symlink
        assert found[b].client_name == MCPHUB_CLIENT

    def test_cwd_file_under_symlinked_parent_is_trust_002(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _home(monkeypatch, tmp_path / "home")
        elsewhere = tmp_path / "elsewhere"
        _write(elsewhere / "servers.json", json.dumps({"servers": {"x": {}}}))
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / ".mcphub").symlink_to(elsewhere, target_is_directory=True)
        monkeypatch.chdir(repo)
        result = run_scan(skip_rug_pull=True)
        trust = [f for f in result.findings if f.id == "TRUST-002"]
        assert trust and trust[0].severity.value == "HIGH"
        assert trust[0].client == MCPHUB_CLIENT

    def test_scan_from_home_does_not_double_count(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _home(monkeypatch, tmp_path)
        _write(tmp_path / ".mcptoon" / "config.json", json.dumps(MCPTOON_JSON))
        monkeypatch.chdir(tmp_path)
        configs = [
            c
            for c in discover_configs()
            if c.client_name in gateways.GATEWAY_UPSTREAM_CLIENTS
        ]
        assert len(configs) == len({c.path.resolve() for c in configs}) == 1

    def test_permission_error_probe_does_not_crash(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _home(monkeypatch, tmp_path)
        monkeypatch.chdir(_write(tmp_path / "cwd" / "x", "").parent)
        real_is_file = Path.is_file

        def deny(self: Path) -> bool:
            if ".mcptoon" in self.parts or "1mcp" in self.parts:
                raise PermissionError(13, "Permission denied")
            return real_is_file(self)

        monkeypatch.setattr(Path, "is_file", deny)
        discover_configs()  # must not raise

    def test_project_walk_includes_gateways_only_when_asked(
        self, tmp_path: Path
    ) -> None:
        nested = _write(tmp_path / "pkg" / ".mcptoon.toml", "")
        assert nested not in {c.path for c in discover_project_configs(tmp_path)}
        found = {
            c.path: c for c in discover_project_configs(tmp_path, include_gateways=True)
        }
        assert found[nested].client_name == MCPTOON_CLIENT
        assert found[nested].is_project_scoped


# ── Analysis: every analyzer sees the upstreams ──────────────────────────────


class TestScan:
    def test_upstreams_are_analysed_and_pair_in_toxic_flow(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _home(monkeypatch, tmp_path)
        monkeypatch.chdir(_write(tmp_path / "cwd" / "x", "").parent)
        _write(tmp_path / ".mcptoon" / "config.json", json.dumps(MCPTOON_JSON))
        result = run_scan(skip_rug_pull=True)
        names = {s.name for s in result.servers if s.client == MCPTOON_CLIENT}
        assert names == {"fs", "fetch", "gh", "not-self"}
        toxic = [f for f in result.findings if f.id.startswith("TOXIC-")]
        # filesystem (file read) behind the gateway + fetch (network out).
        assert any(f.client == MCPTOON_CLIENT for f in toxic)
        # The plaintext GitHub token in the upstream's header is reported.
        assert any(
            f.id.startswith("CRED-") and f.client == MCPTOON_CLIENT
            for f in result.findings
        )

    def test_demo_configs_have_no_gateway_servers(self) -> None:
        demo = Path(__file__).resolve().parent.parent / "demo" / "configs"
        result = run_scan(extra_paths=[demo], skip_rug_pull=True)
        assert not any(
            s.client in gateways.GATEWAY_UPSTREAM_CLIENTS for s in result.servers
        )

    def test_secrets_never_reach_any_output(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _home(monkeypatch, tmp_path)
        monkeypatch.chdir(_write(tmp_path / "cwd" / "x", "").parent)
        doc = {
            "mcpServers": {
                "db": {
                    "command": "npx",
                    "args": [
                        "-y",
                        "mcp-postgres",
                        f"postgresql://admin:{DB_PASSWORD}@db.example:5432/app",
                    ],
                    "env": {"API_KEY": PLAIN_KEY, "TOKEN": GHP, "REF": "${X}"},
                },
                "remote": {
                    "url": "https://h.example/mcp",
                    "headers": {"Authorization": f"Bearer {PLAIN_KEY}"},
                },
            }
        }
        _write(tmp_path / ".config" / "1mcp" / "mcp.json", json.dumps(doc))
        monkeypatch.setattr("mcp_audit.gateways.platform.system", lambda: "Linux")
        result = run_scan(skip_rug_pull=True)
        assert {s.name for s in result.servers if s.client == ONEMCP_CLIENT} == {
            "db",
            "remote",
        }
        outputs = {
            "json": result.model_dump_json(),
            "sarif": format_sarif(result),
            "nucleus": format_nucleus(result),
        }
        for kind, text in outputs.items():
            for secret in (PLAIN_KEY, GHP, DB_PASSWORD):
                assert secret not in text, (kind, secret)
        dumped = json.loads(outputs["json"])
        db = next(s for s in dumped["servers"] if s["name"] == "db")
        assert db["env"]["REF"] == "${X}"
        assert db["raw"]["env"]["TOKEN"] == REDACTION_MARKER

    def test_terminal_output_has_no_secret(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        from mcp_audit.output.terminal import print_results

        _home(monkeypatch, tmp_path)
        monkeypatch.chdir(_write(tmp_path / "cwd" / "x", "").parent)
        _write(tmp_path / ".mcptoon" / "config.json", json.dumps(MCPTOON_JSON))
        print_results(run_scan(skip_rug_pull=True))
        assert GHP not in capsys.readouterr().out

    def test_other_clients_serialisation_unchanged(self, tmp_path: Path) -> None:
        server = ServerConfig(
            name="x",
            client="cursor",
            config_path=tmp_path / "m.json",
            env={"API_KEY": PLAIN_KEY},
        )
        assert PLAIN_KEY in server.model_dump_json()


class TestRedactionHelpers:
    def test_env_values(self) -> None:
        out = redact_env_values(
            {
                "API_KEY": PLAIN_KEY,
                "GITHUB_TOKEN": GHP,
                "REF": "${GITHUB_TOKEN}",
                "NODE_ENV": "production",
                "KEY_FILE": "/etc/key.pem",
                "DATABASE_URL": f"postgresql://u:{DB_PASSWORD}@h/db",
                "N": 3,
            }
        )
        assert out["API_KEY"] == FLAG_REDACTION_MARKER
        assert out["GITHUB_TOKEN"] == REDACTION_MARKER
        assert out["REF"] == "${GITHUB_TOKEN}"
        assert out["NODE_ENV"] == "production"
        assert out["KEY_FILE"] == "/etc/key.pem"
        assert DB_PASSWORD not in out["DATABASE_URL"]
        assert out["N"] == 3

    def test_header_values(self) -> None:
        out = redact_header_values(
            {"Authorization": f"Bearer {PLAIN_KEY}", "X-Trace": "abc", "A": "${T}"}
        )
        assert out == {
            "Authorization": f"Bearer {REDACTION_MARKER}",
            "X-Trace": "abc",
            "A": "${T}",
        }

    def test_diff_reads_redacted_env_as_credential(self, tmp_path: Path) -> None:
        server = ServerConfig(
            name="x",
            client=MCPTOON_CLIENT,
            config_path=tmp_path / "c.json",
            env={"TOKEN": REDACTION_MARKER},
        )
        assert _has_hardcoded_cred(server)[0]


# ── Lock and rug-pull: unchanged for existing users ─────────────────────────


class TestLockAndRugPull:
    def test_user_gateway_config_not_in_state_key(self, tmp_path: Path) -> None:
        base = DiscoveredConfig("cursor", "mcpServers", tmp_path / "mcp.json")
        user_gw = DiscoveredConfig(MCPTOON_CLIENT, "servers", tmp_path / "c.json")
        project_gw = DiscoveredConfig(
            MCPTOON_CLIENT,
            "servers",
            tmp_path / ".mcptoon.json",
            is_project_scoped=True,
        )
        assert derive_state_path([base]) == derive_state_path([base, user_gw])
        assert derive_state_path([base]) != derive_state_path([base, project_gw])

    def test_lock_discovery_excludes_gateways(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from rich.console import Console  # noqa: PLC0415

        from mcp_audit.cli.lock import _discover_lock_servers  # noqa: PLC0415

        _home(monkeypatch, tmp_path)
        _write(tmp_path / ".mcptoon" / "config.json", json.dumps(MCPTOON_JSON))
        repo = tmp_path / "repo"
        _write(repo / ".mcptoon.json", json.dumps(MCPTOON_JSON))
        _write(repo / ".mcp.json", json.dumps({"mcpServers": {"a": {"command": "x"}}}))
        monkeypatch.chdir(repo)
        servers = _discover_lock_servers(repo, include_user=True, con=Console())
        assert {s.client for s in servers} <= {"claude-code", "claude-code-project"}

    def test_existing_lock_still_verifies_clean(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A lock written without gateway support keeps verifying."""
        from typer.testing import CliRunner  # noqa: PLC0415

        from mcp_audit.cli import app  # noqa: PLC0415

        _home(monkeypatch, tmp_path / "home")
        repo = tmp_path / "repo"
        _write(repo / ".mcp.json", json.dumps({"mcpServers": {"a": {"command": "x"}}}))
        monkeypatch.chdir(repo)
        runner = CliRunner()
        written = runner.invoke(app, ["lock", str(repo), "--offline"])
        assert written.exit_code == 0, written.output
        # A gateway project file appears after the lock was written.
        _write(repo / ".mcptoon.json", json.dumps(MCPTOON_JSON))
        verified = runner.invoke(app, ["lock", str(repo), "--verify"])
        assert verified.exit_code == 0, verified.output
        result = run_scan(skip_rug_pull=True)
        project_gateway = [
            s
            for s in result.servers
            if s.client == MCPTOON_CLIENT and s.is_project_scoped
        ]
        findings, status = auto_verify(result.servers)
        assert project_gateway
        assert not [f for f in findings if f.id.startswith("LOCK-")]
        assert any(MCPTOON_CLIENT in entry for entry in status.not_covered)


# ── scan --project ───────────────────────────────────────────────────────────


class TestProjectScan:
    def test_trust_001_names_the_gateway(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from typer.testing import CliRunner  # noqa: PLC0415

        from mcp_audit.cli import app  # noqa: PLC0415

        _home(monkeypatch, tmp_path / "home")
        repo = tmp_path / "repo"
        _write(repo / "sub" / ".mcptoon.json", json.dumps(MCPTOON_JSON))
        _write(
            repo / ".mcphub" / "servers.json",
            json.dumps({"servers": {"hub": {"command": "uvx", "args": ["x"]}}}),
        )
        monkeypatch.chdir(tmp_path)
        out = tmp_path / "out.json"
        CliRunner().invoke(
            app,
            [
                "scan",
                "--project",
                str(repo),
                "--format",
                "json",
                "--output-file",
                str(out),
                "--no-lock",
            ],
        )
        data = json.loads(out.read_text())
        trust = [f for f in data["findings"] if f["id"] == "TRUST-001"]
        by_server = {f["server"]: f for f in trust}
        assert "mcptoon serve" in by_server["fs"]["description"]
        assert "MCPHub.nvim" in by_server["hub"]["description"]
        assert by_server["fs"]["client"] == MCPTOON_CLIENT

    def test_cwd_project_file_analysed_once(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from typer.testing import CliRunner  # noqa: PLC0415

        from mcp_audit.cli import app  # noqa: PLC0415

        _home(monkeypatch, tmp_path / "home")
        repo = tmp_path / "repo"
        _write(repo / ".mcptoon.json", json.dumps(MCPTOON_JSON))
        monkeypatch.chdir(repo)
        out = tmp_path / "out.json"
        CliRunner().invoke(
            app,
            [
                "scan",
                "--project",
                ".",
                "--format",
                "json",
                "--output-file",
                str(out),
                "--no-lock",
            ],
        )
        data = json.loads(out.read_text())
        cred = [
            f
            for f in data["findings"]
            if f["id"].startswith("CRED-") and f["server"] == "gh"
        ]
        keys = {(f["id"], f["evidence"]) for f in cred}
        assert cred and len(keys) == len(cred)


def test_gateway_module_does_not_import_execution_apis() -> None:
    """The gateway reader parses text only: no subprocess, no network."""
    source = Path(gateways.__file__).read_text(encoding="utf-8")
    for banned in ("subprocess", "urllib", "socket", "os.system", "eval("):
        assert banned not in source


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_world_readable_gateway_config_gets_hygiene_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _home(monkeypatch, tmp_path)
    monkeypatch.chdir(_write(tmp_path / "cwd" / "x", "").parent)
    path = _write(tmp_path / ".mcptoon" / "config.json", json.dumps(MCPTOON_JSON))
    path.chmod(0o666)
    result = run_scan(skip_rug_pull=True)
    assert any(
        f.id == "CFHYG-001" and f.client == MCPTOON_CLIENT for f in result.findings
    )
