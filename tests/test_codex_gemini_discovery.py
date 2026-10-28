"""Codex and Gemini CLI MCP config discovery and parsing (STORY-0110).

Codex keeps MCP servers in ``[mcp_servers.<name>]`` tables of
``$CODEX_HOME/config.toml`` (default ``~/.codex``) and of a project's
``.codex/config.toml``; Gemini CLI keeps them in ``mcpServers`` of
``~/.gemini/settings.json`` and a project's ``.gemini/settings.json`` (JSON
with comments).  These tests drive discovery, the parser and the scan
pipeline with real files on disk.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from mcp_audit.cli import app
from mcp_audit.config_parser import (
    SETTINGS_MAX_BYTES,
    _strip_json_comments,
    config_dialect,
    parse_config,
)
from mcp_audit.discovery import (
    DiscoveredConfig,
    _get_client_specs,
    codex_user_config_path,
    discover_configs,
    discover_project_configs,
)
from mcp_audit.models import TransportType
from mcp_audit.scanner import run_scan

runner = CliRunner()

#: Synthetic, not a real token (same shape as the repo's other fixtures).
GH_TOKEN = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890"  # noqa: S105
DB_PASSWORD = "s3cretPassw0rd"  # noqa: S105
PG_URL = f"postgresql://admin:{DB_PASSWORD}@db.internal:5432/prod"

CODEX_TOML = f"""\
model = "o3"

[mcp_servers.github]
command = "npx"
args = ["-y", "@modelcontextprotocol/server-github"]
env = {{ GITHUB_TOKEN = "{GH_TOKEN}" }}

[mcp_servers.postgres]
command = "npx"
args = ["-y", "@modelcontextprotocol/server-postgres", "{PG_URL}"]

[mcp_servers.docs]
url = "https://docs.example.com/mcp"
bearer_token_env_var = "DOCS_TOKEN"
"""

GEMINI_JSON = """\
{
  // Gemini CLI allows comments in settings.json
  "theme": "Default",
  "mcpServers": {
    "fs": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/srv/data"]
    },
    /* a remote server */
    "remote": {
      "httpUrl": "https://api.example.com/mcp",
      "headers": {"Authorization": "Bearer $API_TOKEN"}
    }
  }
}
"""


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _codex(path: Path, client: str = "codex") -> DiscoveredConfig:
    return DiscoveredConfig(client_name=client, root_key="mcp_servers", path=path)


def _gemini(path: Path, client: str = "gemini-cli") -> DiscoveredConfig:
    return DiscoveredConfig(client_name=client, root_key="mcpServers", path=path)


@pytest.fixture()
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A fake home directory holding every user-level client path."""
    h = tmp_path / "home"
    h.mkdir()
    monkeypatch.setattr("mcp_audit.discovery._home", lambda: h)
    monkeypatch.delenv("CODEX_HOME", raising=False)
    monkeypatch.setattr(
        "mcp_audit.discovery.gemini_user_config_path",
        lambda: h / ".gemini" / "settings.json",
    )
    return h


def _symlink(link: Path, target: Path) -> None:
    link.parent.mkdir(parents=True, exist_ok=True)
    try:
        link.symlink_to(target, target_is_directory=target.is_dir())
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not available on this platform")


# ── Parser: Codex config.toml ─────────────────────────────────────────────────


class TestCodexParser:
    def test_stdio_and_http_servers(self, tmp_path: Path) -> None:
        path = _write(tmp_path / ".codex" / "config.toml", CODEX_TOML)
        servers = {s.name: s for s in parse_config(_codex(path))}
        assert set(servers) == {"github", "postgres", "docs"}
        gh = servers["github"]
        assert gh.transport == TransportType.STDIO
        assert gh.command == "npx"
        assert gh.args == ["-y", "@modelcontextprotocol/server-github"]
        assert gh.env == {"GITHUB_TOKEN": GH_TOKEN}
        assert gh.client == "codex"
        docs = servers["docs"]
        assert docs.transport == TransportType.STREAMABLE_HTTP
        assert docs.url == "https://docs.example.com/mcp"
        # The variable's *name* becomes a reference, never a value.
        assert docs.headers == {"Authorization": "Bearer ${DOCS_TOKEN}"}

    def test_codex_url_is_never_sse(self, tmp_path: Path) -> None:
        """Codex has no SSE transport: a /sse path is still streamable HTTP."""
        path = _write(
            tmp_path / "config.toml", '[mcp_servers.a]\nurl = "https://h/sse"\n'
        )
        [server] = parse_config(_codex(path))
        assert server.transport == TransportType.STREAMABLE_HTTP

    def test_env_http_headers_and_literal_headers(self, tmp_path: Path) -> None:
        path = _write(
            tmp_path / "config.toml",
            "[mcp_servers.a]\n"
            'url = "https://h/mcp"\n'
            'http_headers = { "X-Team" = "blue" }\n'
            'env_http_headers = { "X-Api-Key" = "A_KEY" }\n',
        )
        [server] = parse_config(_codex(path))
        assert server.headers == {"X-Team": "blue", "X-Api-Key": "${A_KEY}"}

    def test_retired_literal_bearer_token_is_kept(self, tmp_path: Path) -> None:
        """Codex refuses ``bearer_token`` now, but the secret is still on disk."""
        path = _write(
            tmp_path / "config.toml",
            f'[mcp_servers.a]\nurl = "https://h/mcp"\nbearer_token = "{GH_TOKEN}"\n',
        )
        [server] = parse_config(_codex(path))
        assert server.headers["Authorization"] == f"Bearer {GH_TOKEN}"

    def test_toml_values_become_json_safe(self, tmp_path: Path) -> None:
        path = _write(
            tmp_path / "config.toml",
            "[mcp_servers.a]\n"
            'command = "uvx"\n'
            'args = ["pkg", 8080, true]\n'
            "env = { PORT = 8080 }\n"
            "added = 1979-05-27T07:32:00Z\n",
        )
        [server] = parse_config(_codex(path))
        assert server.args == ["pkg", "8080", "true"]
        assert server.env == {"PORT": "8080"}
        assert server.raw["added"] == "1979-05-27T07:32:00+00:00"
        json.dumps(server.raw)  # rug-pull hashes raw with json.dumps
        json.loads(server.model_dump_json())

    def test_entry_codex_refuses_is_still_analysed(self, tmp_path: Path) -> None:
        """``command`` plus ``url`` is a Codex error; ``enabled = false`` is off.

        One edit makes either live, so both are parsed (stdio wins, as in
        Codex's own reader)."""
        path = _write(
            tmp_path / "config.toml",
            "[mcp_servers.both]\n"
            'command = "npx"\nargs = ["evil-pkg"]\nurl = "http://h/mcp"\n'
            "[mcp_servers.off]\n"
            'command = "npx"\nargs = ["other"]\nenabled = false\n',
        )
        servers = {s.name: s for s in parse_config(_codex(path))}
        assert servers["both"].transport == TransportType.STDIO
        assert servers["both"].command == "npx"
        assert servers["off"].args == ["other"]

    def test_dotted_server_name(self, tmp_path: Path) -> None:
        path = _write(
            tmp_path / "config.toml", '[mcp_servers."my.server"]\ncommand = "x"\n'
        )
        assert [s.name for s in parse_config(_codex(path))] == ["my.server"]

    @pytest.mark.parametrize(
        "text",
        [
            'model = "o3"\n',  # no MCP servers at all
            'mcp_servers = "nope"\n',  # wrong type
            "[mcp_servers]\nbad = 3\n",  # entry is not a table
        ],
    )
    def test_no_servers(self, tmp_path: Path, text: str) -> None:
        path = _write(tmp_path / "config.toml", text)
        assert parse_config(_codex(path)) == []

    def test_invalid_toml_raises_value_error(self, tmp_path: Path) -> None:
        path = _write(tmp_path / "config.toml", "[mcp_servers.a\ncommand=\n")
        with pytest.raises(ValueError, match="Invalid TOML"):
            parse_config(_codex(path))

    def test_bom_is_skipped(self, tmp_path: Path) -> None:
        path = tmp_path / "config.toml"
        path.write_bytes(b"\xef\xbb\xbf" + b'[mcp_servers.a]\ncommand = "x"\n')
        assert [s.name for s in parse_config(_codex(path))] == ["a"]

    def test_not_utf8_raises_value_error(self, tmp_path: Path) -> None:
        path = tmp_path / "config.toml"
        path.write_bytes(b'[mcp_servers.a]\ncommand = "\xff\xfe"\n')
        with pytest.raises(ValueError, match="not UTF-8"):
            parse_config(_codex(path))

    def test_oversized_file_is_reported_not_read(self, tmp_path: Path) -> None:
        path = tmp_path / "config.toml"
        path.write_bytes(b"#" * (SETTINGS_MAX_BYTES + 1))
        with pytest.raises(ValueError, match="limit"):
            parse_config(_codex(path))

    def test_unreadable_file_raises_value_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = _write(tmp_path / "config.toml", '[mcp_servers.a]\ncommand = "x"\n')

        def _denied(*_a: object, **_k: object) -> None:
            raise PermissionError(13, "Permission denied")

        monkeypatch.setattr("mcp_audit.config_parser.os.stat", _denied)
        with pytest.raises(ValueError, match="Cannot read"):
            parse_config(_codex(path))


# ── Parser: Gemini CLI settings.json ──────────────────────────────────────────


class TestGeminiParser:
    def test_comments_and_transports(self, tmp_path: Path) -> None:
        path = _write(tmp_path / ".gemini" / "settings.json", GEMINI_JSON)
        servers = {s.name: s for s in parse_config(_gemini(path))}
        assert servers["fs"].transport == TransportType.STDIO
        assert servers["fs"].args[-1] == "/srv/data"
        remote = servers["remote"]
        assert remote.transport == TransportType.STREAMABLE_HTTP
        assert remote.url == "https://api.example.com/mcp"
        assert remote.headers == {"Authorization": "Bearer $API_TOKEN"}

    def test_trailing_comma_is_rejected_like_gemini(self, tmp_path: Path) -> None:
        """Gemini CLI parses with JSON.parse after stripping comments only."""
        path = _write(
            tmp_path / ".gemini" / "settings.json",
            '{"mcpServers": {"a": {"command": "x",},}}',
        )
        with pytest.raises(ValueError, match="Invalid JSON"):
            parse_config(_gemini(path))

    @pytest.mark.parametrize(
        ("entry", "transport", "url"),
        [
            (
                {"httpUrl": "https://a/mcp", "url": "https://b/sse"},
                "streamable-http",
                "https://a/mcp",
            ),
            ({"url": "https://b/x", "type": "sse"}, "sse", "https://b/x"),
            (
                {"url": "https://b/sse", "type": "http"},
                "streamable-http",
                "https://b/sse",
            ),
            ({"url": "https://b/sse"}, "sse", "https://b/sse"),
            ({"url": "https://b/mcp"}, "streamable-http", "https://b/mcp"),
            ({"command": "npx"}, "stdio", None),
            ({"cwd": "/x"}, "unknown", None),
        ],
    )
    def test_transport_follows_gemini_order(
        self, tmp_path: Path, entry: dict, transport: str, url: str | None
    ) -> None:
        path = _write(
            tmp_path / ".gemini" / "settings.json",
            json.dumps({"mcpServers": {"s": entry}}),
        )
        [server] = parse_config(_gemini(path))
        assert server.transport.value == transport
        assert server.url == url

    def test_command_beside_url_is_still_analysed(self, tmp_path: Path) -> None:
        path = _write(
            tmp_path / ".gemini" / "settings.json",
            json.dumps(
                {"mcpServers": {"s": {"httpUrl": "https://a/mcp", "command": "npx"}}}
            ),
        )
        [server] = parse_config(_gemini(path))
        assert server.transport == TransportType.STREAMABLE_HTTP
        assert server.command == "npx"

    def test_non_object_root(self, tmp_path: Path) -> None:
        path = _write(tmp_path / ".gemini" / "settings.json", "[1, 2]")
        with pytest.raises(ValueError, match="Expected JSON object"):
            parse_config(_gemini(path))

    def test_comment_markers_inside_strings_survive(self) -> None:
        text = '{"u": "https://x//y/*z*/", "s": "a\\"//b"} // tail\n/* open'
        assert json.loads(_strip_json_comments(text)) == {
            "u": "https://x//y/*z*/",
            "s": 'a"//b',
        }

    def test_comment_stripper_is_linear(self) -> None:
        """Pathological input (many unterminated comment starts) stays fast."""
        text = '{"a": "' + "/*" * 200_000 + '"}' + "/*" * 200_000
        start = time.perf_counter()
        _strip_json_comments(text)
        assert time.perf_counter() - start < 2.0


# ── Which reader a path gets ──────────────────────────────────────────────────


class TestDialect:
    @pytest.mark.parametrize(
        ("rel", "dialect"),
        [
            ("config.toml", "codex"),
            (".codex/config.toml", "codex"),
            (".gemini/settings.json", "gemini"),
            (".claude/settings.json", None),
            ("settings.json", None),
            ("mcp.json", None),
        ],
    )
    def test_inferred_from_path(self, tmp_path: Path, rel: str, dialect: str) -> None:
        config = DiscoveredConfig("custom", "mcpServers", tmp_path / rel)
        assert config_dialect(config) == dialect

    def test_explicit_path_flag_reads_both(self, tmp_path: Path) -> None:
        codex = _write(tmp_path / "c" / "config.toml", CODEX_TOML)
        gemini = _write(tmp_path / "g" / ".gemini" / "settings.json", GEMINI_JSON)
        result = run_scan(extra_paths=[codex, gemini], skip_rug_pull=True)
        assert {s.name for s in result.servers} == {
            "github",
            "postgres",
            "docs",
            "fs",
            "remote",
        }
        assert not result.errors


# ── User-level discovery ──────────────────────────────────────────────────────


class TestUserDiscovery:
    def test_client_specs(self, home: Path) -> None:
        specs = {s.name: s for s in _get_client_specs()}
        assert specs["codex"].root_key == "mcp_servers"
        assert specs["codex"].config_paths == [home / ".codex" / "config.toml"]
        assert specs["gemini-cli"].config_paths == [home / ".gemini" / "settings.json"]

    def test_codex_home_override(
        self, home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        custom = tmp_path / "codex-state"
        custom.mkdir()
        monkeypatch.setenv("CODEX_HOME", str(custom))
        assert codex_user_config_path() == custom.resolve() / "config.toml"
        monkeypatch.setenv("CODEX_HOME", "  ")
        assert codex_user_config_path() == home / ".codex" / "config.toml"

    def test_default_scan_finds_user_files(
        self, home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _write(home / ".codex" / "config.toml", CODEX_TOML)
        _write(home / ".gemini" / "settings.json", GEMINI_JSON)
        work = tmp_path / "work"
        work.mkdir()
        monkeypatch.chdir(work)
        configs = discover_configs()
        labels = {(c.client_name, c.dialect) for c in configs}
        assert ("codex", "codex") in labels
        assert ("gemini-cli", "gemini") in labels
        result = run_scan(skip_rug_pull=True)
        by_client = {(s.client, s.name) for s in result.servers}
        assert ("codex", "github") in by_client
        assert ("gemini-cli", "remote") in by_client
        assert not any(s.is_project_scoped for s in result.servers)
        # The full per-server pipeline ran: the literal GitHub token is found.
        assert any(f.id == "CRED-001" and f.client == "codex" for f in result.findings)
        assert not any(f.id == "TRUST-001" for f in result.findings)

    def test_symlinked_user_file_is_trust_004(
        self, home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        real = _write(tmp_path / "dotfiles" / "settings.json", GEMINI_JSON)
        _symlink(home / ".gemini" / "settings.json", real)
        work = tmp_path / "work"
        work.mkdir()
        monkeypatch.chdir(work)
        result = run_scan(skip_rug_pull=True)
        assert any(
            f.id == "TRUST-004" and f.client == "gemini-cli" for f in result.findings
        )
        assert {"fs", "remote"} <= {s.name for s in result.servers}

    def test_parse_error_goes_to_errors(
        self, home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _write(home / ".codex" / "config.toml", "[mcp_servers.a\n")
        _write(home / ".gemini" / "settings.json", '{"mcpServers": {},}')
        work = tmp_path / "work"
        work.mkdir()
        monkeypatch.chdir(work)
        result = run_scan(skip_rug_pull=True)
        assert any("Invalid TOML" in e for e in result.errors)
        assert any("Invalid JSON" in e for e in result.errors)


# ── Project walk (scan --project, lock) ──────────────────────────────────────


class TestProjectWalk:
    def test_finds_nested_files(self, tmp_path: Path, home: Path) -> None:
        repo = tmp_path / "repo"
        _write(repo / ".codex" / "config.toml", CODEX_TOML)
        _write(repo / "pkg" / ".gemini" / "settings.json", GEMINI_JSON)
        found = {
            (c.client_name, c.path.relative_to(repo).as_posix())
            for c in discover_project_configs(repo)
        }
        assert found == {
            ("codex", ".codex/config.toml"),
            ("gemini-cli", "pkg/.gemini/settings.json"),
        }
        servers = [s for c in discover_project_configs(repo) for s in parse_config(c)]
        assert all(s.is_project_scoped for s in servers)

    def test_home_walk_skips_the_users_own_files(
        self, home: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _write(home / ".codex" / "config.toml", CODEX_TOML)
        _write(home / ".gemini" / "settings.json", GEMINI_JSON)
        _write(home / "repo" / ".codex" / "config.toml", CODEX_TOML)
        found = {
            c.path.relative_to(home).as_posix() for c in discover_project_configs(home)
        }
        assert found == {"repo/.codex/config.toml"}

    def test_home_walk_with_codex_home_elsewhere(
        self, home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """With CODEX_HOME elsewhere, ~/.codex is an ordinary project layer."""
        other = tmp_path / "codex-state"
        other.mkdir()
        monkeypatch.setenv("CODEX_HOME", str(other))
        _write(home / ".codex" / "config.toml", CODEX_TOML)
        found = {c.path for c in discover_project_configs(home)}
        assert home / ".codex" / "config.toml" in found

    def test_symlinked_file_is_trust_002_candidate(
        self, tmp_path: Path, home: Path
    ) -> None:
        outside = _write(tmp_path / "outside" / "config.toml", CODEX_TOML)
        repo = tmp_path / "repo"
        _symlink(repo / ".codex" / "config.toml", outside)
        [config] = discover_project_configs(repo)
        assert config.is_symlink and config.symlink_root == repo
        # The link's own name still selects the TOML reader.
        assert {s.name for s in parse_config(config)} == {"github", "postgres", "docs"}

    def test_scan_project_reports_trust_001_per_server(
        self, tmp_path: Path, home: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        repo = tmp_path / "repo"
        _write(repo / ".codex" / "config.toml", CODEX_TOML)
        _write(repo / ".gemini" / "settings.json", GEMINI_JSON)
        out = tmp_path / "out.json"
        outside = tmp_path / "elsewhere"
        outside.mkdir()
        monkeypatch.chdir(outside)
        with patch("mcp_audit.discovery._get_client_specs", return_value=[]):
            r = runner.invoke(
                app,
                ["scan", "--project", str(repo), "--format", "json", "-o", str(out)],
            )
        assert r.exit_code in (0, 1), r.output
        payload = json.loads(out.read_text(encoding="utf-8"))
        trust = {
            (f["client"], f["server"])
            for f in payload["findings"]
            if f["id"] == "TRUST-001"
        }
        assert trust == {
            ("codex", "github"),
            ("codex", "postgres"),
            ("codex", "docs"),
            ("gemini-cli", "fs"),
            ("gemini-cli", "remote"),
        }


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
def test_unreadable_codex_dir_does_not_crash_walk(tmp_path: Path, home: Path) -> None:
    repo = tmp_path / "repo"
    _write(repo / ".codex" / "config.toml", CODEX_TOML)
    locked = repo / "locked"
    locked.mkdir()
    os.chmod(locked, 0)
    try:
        found = discover_project_configs(repo)
    finally:
        os.chmod(locked, 0o700)
    assert [c.client_name for c in found] == ["codex"]


# ── Default scan from a checkout (cwd root) ──────────────────────────────────


class TestCwdDiscovery:
    def test_cwd_files_are_project_labelled(
        self, home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        repo = tmp_path / "repo"
        _write(repo / ".codex" / "config.toml", CODEX_TOML)
        _write(repo / ".gemini" / "settings.json", GEMINI_JSON)
        monkeypatch.chdir(repo)
        labels = {
            (c.client_name, c.dialect, c.is_symlink)
            for c in discover_configs()
            if c.path.is_relative_to(repo)
        }
        assert labels == {
            ("codex-project", "codex", False),
            ("gemini-cli-project", "gemini", False),
        }

    def test_same_name_as_user_server_keeps_separate_identity(
        self, home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """User ``github`` and repo ``github`` never share a rug-pull key."""
        _write(home / ".codex" / "config.toml", CODEX_TOML)
        repo = tmp_path / "repo"
        _write(repo / ".codex" / "config.toml", CODEX_TOML)
        monkeypatch.chdir(repo)
        result = run_scan(skip_rug_pull=True)
        keys = [f"{s.client}/{s.name}" for s in result.servers if s.name == "github"]
        assert sorted(keys) == ["codex-project/github", "codex/github"]

    def test_scan_from_home_reads_user_files_once(
        self, home: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _write(home / ".codex" / "config.toml", CODEX_TOML)
        _write(home / ".gemini" / "settings.json", GEMINI_JSON)
        monkeypatch.chdir(home)
        configs = [c for c in discover_configs() if c.dialect is not None]
        assert sorted(c.client_name for c in configs) == ["codex", "gemini-cli"]
        result = run_scan(skip_rug_pull=True)
        assert not any(f.id == "TRUST-002" for f in result.findings)
        names = [s.name for s in result.servers]
        assert len(names) == len(set(names)) == 5

    def test_scan_from_home_with_dotfile_symlinks_reads_once(
        self, home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        real = _write(tmp_path / "dotfiles" / "settings.json", GEMINI_JSON)
        _symlink(home / ".gemini" / "settings.json", real)
        monkeypatch.chdir(home)
        result = run_scan(skip_rug_pull=True)
        assert [f.id for f in result.findings if f.id.startswith("TRUST-00")] == [
            "TRUST-004"
        ]
        assert sorted(s.name for s in result.servers) == ["fs", "remote"]

    def test_symlinked_cwd_file_is_trust_002(
        self, home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        outside = _write(tmp_path / "outside" / "config.toml", CODEX_TOML)
        repo = tmp_path / "repo"
        _symlink(repo / ".codex" / "config.toml", outside)
        monkeypatch.chdir(repo)
        result = run_scan(skip_rug_pull=True)
        trust = [f for f in result.findings if f.id == "TRUST-002"]
        assert len(trust) == 1 and trust[0].severity.value == "HIGH"
        # Reported once, by the auto-run pass (TRUST-008's file) or discovery.
        assert trust[0].client in ("codex", "codex-project")

    def test_symlinked_parent_dir_is_trust_002(
        self, home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``.gemini -> /elsewhere`` makes its settings a TRUST-002 candidate."""
        elsewhere = tmp_path / "elsewhere"
        _write(elsewhere / "settings.json", GEMINI_JSON)
        repo = tmp_path / "repo"
        repo.mkdir()
        _symlink(repo / ".gemini", elsewhere)
        monkeypatch.chdir(repo)
        [config] = [c for c in discover_configs() if c.dialect == "gemini"]
        assert config.is_symlink and config.symlink_root == repo
        result = run_scan(skip_rug_pull=True)
        assert any(
            f.id == "TRUST-002" and f.severity.value == "HIGH" for f in result.findings
        )

    def test_repo_link_to_user_file_is_reported_not_reparsed(
        self, home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        user = _write(home / ".codex" / "config.toml", CODEX_TOML)
        repo = tmp_path / "repo"
        _symlink(repo / ".codex" / "config.toml", user)
        monkeypatch.chdir(repo)
        result = run_scan(skip_rug_pull=True)
        assert sorted(s.client for s in result.servers) == ["codex"] * 3
        assert any(f.id == "TRUST-002" for f in result.findings)

    def test_unreadable_probe_does_not_crash(
        self, home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        repo = tmp_path / "repo"
        _write(repo / ".codex" / "config.toml", CODEX_TOML)
        monkeypatch.chdir(repo)
        real_is_symlink = Path.is_symlink

        def _flaky(self: Path) -> bool:
            if self.name in (".codex", ".gemini") or self.parent.name in (
                ".codex",
                ".gemini",
            ):
                raise PermissionError(13, "Permission denied")
            return real_is_symlink(self)

        monkeypatch.setattr(Path, "is_symlink", _flaky)
        discover_configs()  # must not raise

    def test_read_error_goes_to_result_errors(
        self, home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        repo = tmp_path / "repo"
        _write(repo / ".gemini" / "settings.json", GEMINI_JSON)
        monkeypatch.chdir(repo)
        real_open = Path.open

        def _denied(self: Path, *a: object, **k: object):  # type: ignore[no-untyped-def]
            if self.name == "settings.json" and self.parent.name == ".gemini":
                raise PermissionError(13, "Permission denied")
            return real_open(self, *a, **k)

        monkeypatch.setattr(Path, "open", _denied)
        result = run_scan(skip_rug_pull=True)
        assert any("Cannot read" in e for e in result.errors)


# ── Secrets in every output format ────────────────────────────────────────────


class TestSecretsInOutput:
    """Launch-command secrets of Codex/Gemini servers never reach the output."""

    @pytest.fixture()
    def repo(self, home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
        repo = tmp_path / "repo"
        _write(repo / ".codex" / "config.toml", CODEX_TOML)
        _write(
            repo / ".gemini" / "settings.json",
            json.dumps(
                {
                    "mcpServers": {
                        "pg": {
                            "command": "npx",
                            "args": [
                                "-y",
                                "@modelcontextprotocol/server-postgres",
                                f"postgresql://admin:{DB_PASSWORD}@db/prod",
                            ],
                        }
                    }
                }
            ),
        )
        monkeypatch.chdir(repo)
        return repo

    @pytest.mark.parametrize("fmt", ["terminal", "json", "sarif"])
    def test_password_in_args_is_redacted(
        self, repo: Path, tmp_path: Path, fmt: str
    ) -> None:
        out = tmp_path / f"out.{fmt}"
        with patch("mcp_audit.discovery._get_client_specs", return_value=[]):
            r = runner.invoke(
                app, ["scan", "--format", fmt, "-o", str(out), "--no-score"]
            )
        assert r.exit_code in (0, 1), r.output
        text = r.output + (out.read_text(encoding="utf-8") if out.exists() else "")
        assert "postgres" in text  # the servers were scanned
        assert DB_PASSWORD not in text

    @pytest.mark.parametrize("fmt", ["terminal", "json", "sarif"])
    def test_literal_tokens_and_client_secrets_are_redacted(
        self, home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fmt: str
    ) -> None:
        """Codex ``bearer_token`` / ``oauth.client_secret`` / ``http_headers``
        and Gemini ``headers`` / ``oauth.clientSecret`` never reach the output,
        while CRED-003 still reports the literal token."""
        repo = tmp_path / "repo"
        _write(
            repo / ".codex" / "config.toml",
            "[mcp_servers.remote]\n"
            'url = "https://docs.example.com/mcp"\n'
            f'bearer_token = "{GH_TOKEN}"\n'
            'http_headers = { "X-Api-Key" = "codexHeaderSecret123" }\n'
            "[mcp_servers.remote.oauth]\n"
            'client_id = "app"\n'
            'client_secret = "codexClientSecret456"\n',
        )
        _write(
            repo / ".gemini" / "settings.json",
            json.dumps(
                {
                    "mcpServers": {
                        "g": {
                            "httpUrl": "https://g.example.com/mcp",
                            "headers": {"Authorization": "Bearer geminiHdrSecret789"},
                            "oauth": {"clientId": "a", "clientSecret": "gemOauth000"},
                        }
                    }
                }
            ),
        )
        monkeypatch.chdir(repo)
        out = tmp_path / f"out.{fmt}"
        with patch("mcp_audit.discovery._get_client_specs", return_value=[]):
            r = runner.invoke(
                app, ["scan", "--format", fmt, "-o", str(out), "--no-score"]
            )
        assert r.exit_code in (0, 1), r.output
        text = r.output + (out.read_text(encoding="utf-8") if out.exists() else "")
        for secret in (
            GH_TOKEN,
            "codexHeaderSecret123",
            "codexClientSecret456",
            "geminiHdrSecret789",
            "gemOauth000",
        ):
            assert secret not in text, (fmt, secret)
        if fmt == "json":
            payload = json.loads(out.read_text(encoding="utf-8"))
            assert any(f["id"] == "CRED-003" for f in payload["findings"])
            [remote] = [s for s in payload["servers"] if s["name"] == "remote"]
            assert remote["headers"]["Authorization"] == "Bearer [REDACTED]"
            assert remote["raw"]["bearer_token"] == "[REDACTED]"  # noqa: S105
            assert remote["raw"]["oauth"]["client_secret"] == "[REDACTED]"  # noqa: S105
            assert remote["raw"]["oauth"]["client_id"] == "app"

    def test_env_references_and_account_names_are_kept(self, tmp_path: Path) -> None:
        """References stay readable; ``git@`` is an account name, not a secret."""
        path = _write(
            tmp_path / "config.toml",
            "[mcp_servers.a]\n"
            'command = "npx"\n'
            'args = ["git+ssh://git@github.com/org/repo", "--token", "$TOK"]\n'
            "[mcp_servers.b]\n"
            'url = "https://h/mcp"\n'
            'bearer_token = "${LEGACY}"\n'
            'env_http_headers = { "X-Api-Key" = "KEYVAR" }\n',
        )
        dumped = {
            s.name: json.loads(s.model_dump_json()) for s in parse_config(_codex(path))
        }
        assert dumped["a"]["args"][0] == "git+ssh://git@github.com/org/repo"
        assert dumped["a"]["args"][2] == "$TOK"
        assert dumped["b"]["headers"]["X-Api-Key"] == "${KEYVAR}"
        assert dumped["b"]["raw"]["bearer_token"] == "${LEGACY}"  # noqa: S105


# ── lock, diff, rug-pull, fix, check ──────────────────────────────────────────


class TestLock:
    def test_lock_records_and_verifies_codex_and_gemini(
        self, home: Path, tmp_path: Path
    ) -> None:
        repo = tmp_path / "repo"
        _write(repo / ".codex" / "config.toml", CODEX_TOML)
        _write(repo / ".gemini" / "settings.json", GEMINI_JSON)
        r = runner.invoke(app, ["lock", str(repo), "--offline"])
        assert r.exit_code == 0, r.output
        doc = json.loads((repo / "mcp-lock.json").read_text(encoding="utf-8"))
        configs = {(e["config"], e["name"]) for e in doc["servers"].values()}
        assert (".codex/config.toml", "github") in configs
        assert (".gemini/settings.json", "remote") in configs
        r = runner.invoke(app, ["lock", str(repo), "--verify", "--allow-unverified"])
        assert r.exit_code == 0, r.output

    def test_new_server_after_lock_is_lock_002(
        self, home: Path, tmp_path: Path
    ) -> None:
        repo = tmp_path / "repo"
        path = _write(repo / ".codex" / "config.toml", CODEX_TOML)
        assert runner.invoke(app, ["lock", str(repo), "--offline"]).exit_code == 0
        path.write_text(
            CODEX_TOML + '\n[mcp_servers.extra]\ncommand = "bash"\nargs = ["x.sh"]\n',
            encoding="utf-8",
        )
        r = runner.invoke(app, ["lock", str(repo), "--verify"])
        assert r.exit_code == 1
        assert "LOCK-002" in r.output

    def test_changed_args_after_lock_is_lock_001(
        self, home: Path, tmp_path: Path
    ) -> None:
        repo = tmp_path / "repo"
        path = _write(repo / ".gemini" / "settings.json", GEMINI_JSON)
        assert runner.invoke(app, ["lock", str(repo), "--offline"]).exit_code == 0
        path.write_text(GEMINI_JSON.replace("/srv/data", "/"), encoding="utf-8")
        r = runner.invoke(app, ["lock", str(repo), "--verify"])
        assert r.exit_code == 1
        assert "LOCK-001" in r.output


class TestDiff:
    def test_toml_and_gemini_files_as_inputs(self, tmp_path: Path) -> None:
        from mcp_audit.diff.loader import load_input  # noqa: PLC0415

        base = _write(tmp_path / "a" / ".codex" / "config.toml", CODEX_TOML)
        head = _write(
            tmp_path / "b" / ".codex" / "config.toml",
            CODEX_TOML + '[mcp_servers.extra]\ncommand = "bash"\n',
        )
        assert {s.name for s in load_input(str(base))} == {"github", "postgres", "docs"}
        assert "extra" in {s.name for s in load_input(str(head))}
        gem = _write(tmp_path / "g" / ".gemini" / "settings.json", GEMINI_JSON)
        assert {s.name for s in load_input(str(gem))} == {"fs", "remote"}

    def test_git_ref_reads_codex_and_gemini_paths(self) -> None:
        from mcp_audit.diff import loader  # noqa: PLC0415

        paths = dict(loader._KNOWN_GIT_RELATIVE_PATHS)
        assert paths[".codex/config.toml"] == "mcp_servers"
        assert loader._GIT_PATH_DIALECT[".codex/config.toml"] == "codex"
        assert loader._GIT_PATH_DIALECT[".gemini/settings.json"] == "gemini"


class TestRugPull:
    def test_changed_codex_server_is_rugpull_001(
        self, home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = _write(home / ".codex" / "config.toml", CODEX_TOML)
        work = tmp_path / "work"
        work.mkdir()
        monkeypatch.chdir(work)
        state = tmp_path / "state.json"
        run_scan(state_path=state)
        path.write_text(
            CODEX_TOML.replace("server-github", "server-github-evil"), encoding="utf-8"
        )
        result = run_scan(state_path=state)
        changed = [f for f in result.findings if f.id == "RUGPULL-001"]
        assert [(f.client, f.server) for f in changed] == [("codex", "github")]


class TestFixAndCheck:
    def test_fix_refuses_toml_with_a_clear_message(self, tmp_path: Path) -> None:
        from mcp_audit.fixer.fixer import run_fix  # noqa: PLC0415

        path = _write(tmp_path / "config.toml", CODEX_TOML)
        with pytest.raises(ValueError, match="edits JSON MCP configs only"):
            run_fix([], path)
        assert path.read_text(encoding="utf-8") == CODEX_TOML

    def test_check_never_offers_fix_for_codex(self) -> None:
        from mcp_audit.models import Finding, Severity  # noqa: PLC0415
        from mcp_audit.output.check import _remediation_hint  # noqa: PLC0415

        finding = Finding(
            id="CRED-001",
            severity=Severity.HIGH,
            analyzer="credentials",
            client="codex",
            server="github",
            title="t",
            description="d",
            evidence="e",
            remediation="r.",
            finding_path="/home/u/.codex/config.toml",
        )
        assert "fix --apply" not in _remediation_hint(finding)

    def test_transport_fix_upgrades_gemini_http_url(self) -> None:
        from mcp_audit.fixer.strategies.transport import (  # noqa: PLC0415
            TransportFixStrategy,
        )
        from mcp_audit.models import Finding, Severity  # noqa: PLC0415

        config = {"mcpServers": {"r": {"httpUrl": "http://h/mcp", "url": "http://o"}}}
        finding = Finding(
            id="TRANSPORT-001",
            severity=Severity.HIGH,
            analyzer="transport",
            client="gemini-cli",
            server="r",
            title="t",
            description="d",
            evidence="e",
            remediation="r",
        )
        new, _ = TransportFixStrategy().apply(config, finding)
        assert new["mcpServers"]["r"]["httpUrl"] == "https://h/mcp"


def test_demo_configs_unchanged() -> None:
    """The demo directory has no Codex/Gemini files: no new clients appear."""
    demo = Path(__file__).resolve().parent.parent / "demo" / "configs"
    result = run_scan(extra_paths=[demo], skip_rug_pull=True)
    assert not {s.client for s in result.servers} & {
        "codex",
        "codex-project",
        "gemini-cli",
        "gemini-cli-project",
    }


def test_project_scan_symlinked_codex_dir_reported_once(
    tmp_path: Path, home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``.codex -> /elsewhere``: one TRUST-002 although the auto-run walk and
    the MCP-config walk both see ``.codex/config.toml``."""
    elsewhere = tmp_path / "elsewhere"
    _write(elsewhere / "config.toml", CODEX_TOML)
    repo = tmp_path / "repo"
    repo.mkdir()
    _symlink(repo / ".codex", elsewhere)
    out = tmp_path / "out.json"
    monkeypatch.chdir(tmp_path)
    with patch("mcp_audit.discovery._get_client_specs", return_value=[]):
        r = runner.invoke(
            app, ["scan", "--project", str(repo), "--format", "json", "-o", str(out)]
        )
    assert r.exit_code in (0, 1), r.output
    findings = json.loads(out.read_text(encoding="utf-8"))["findings"]
    trust = [f for f in findings if f["id"] == "TRUST-002"]
    assert len(trust) == 1 and trust[0]["severity"] == "HIGH"
