"""Tests for the managed MCP policy report (STORY-0112, MANAGED-001..005).

Every rule asserted here is quoted in ``analyzers/managed_policy.py`` from
https://code.claude.com/docs/en/managed-mcp and
https://code.claude.com/docs/en/managed-settings; the evaluation-table tests
reproduce the documented example tables row by row.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mcp_audit.analyzers import managed_policy as mp
from mcp_audit.analyzers.managed_policy import (
    analyze_managed_policy,
    managed_policy_findings,
    read_managed_policy,
    url_matches,
)
from mcp_audit.discovery import DiscoveredConfig
from mcp_audit.models import ServerConfig

_SECRET_URL = "https://alice:hunter2pass@mcp.evil.example/api"  # noqa: S105 — fixture
_SECRET_ARG = "postgresql://admin:s3cretPassw0rd@db.internal/prod"  # noqa: S105


def _write(path: Path, data: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data if isinstance(data, str) else json.dumps(data))
    return path


def _stdio(
    name: str,
    command: str,
    *args: str,
    client: str = "claude-code",
    path: Path = Path("/h/.claude.json"),
) -> ServerConfig:
    return ServerConfig(
        name=name, client=client, config_path=path, command=command, args=list(args)
    )


def _remote(
    name: str,
    url: str,
    client: str = "claude-code",
    path: Path = Path("/h/.claude.json"),
) -> ServerConfig:
    return ServerConfig(name=name, client=client, config_path=path, url=url)


def _policy(tmp_path: Path, settings: dict | None = None, mcp: object = None):
    managed = tmp_path / "managed"
    managed.mkdir(parents=True, exist_ok=True)
    if settings is not None:
        _write(managed / "managed-settings.json", settings)
    if mcp is not None:
        _write(managed / "managed-mcp.json", mcp)
    return read_managed_policy(managed, [])


def _run(policy, servers, configs=(), home=Path("/h"), root=None):
    return analyze_managed_policy(policy, list(servers), list(configs), home, root)


def _ids(findings) -> list[str]:
    return sorted(f.id for f in findings)


def _dead(findings) -> set[str]:
    return {f.server for f in findings if f.id == "MANAGED-002"}


# ── Reading the managed directory ─────────────────────────────────────────────


class TestRead:
    def test_absent_directory_produces_nothing(self, tmp_path: Path) -> None:
        policy = read_managed_policy(tmp_path / "missing", [])
        assert not policy.present
        assert _run(policy, [_stdio("a", "node")]) == []

    def test_dropins_merge_after_main_in_alphabetical_order(
        self, tmp_path: Path
    ) -> None:
        managed = tmp_path / "m"
        _write(
            managed / "managed-settings.json",
            {
                "allowManagedMcpServersOnly": True,
                "allowedMcpServers": [{"serverName": "one"}],
            },
        )
        _write(
            managed / "managed-settings.d" / "20-b.json",
            {"allowManagedMcpServersOnly": False},
        )
        _write(
            managed / "managed-settings.d" / "10-a.json",
            {
                "allowedMcpServers": [{"serverName": "two"}, {"serverName": "one"}],
                "deniedMcpServers": [{"serverName": "x"}],
            },
        )
        _write(
            managed / "managed-settings.d" / ".hidden.json",
            {"deniedMcpServers": [{"serverName": "hidden"}]},
        )
        _write(
            managed / "managed-settings.d" / "notes.txt",
            '{"deniedMcpServers": [{"serverName": "txt"}]}',
        )
        policy = read_managed_policy(managed, [])
        # Lists combine with duplicates removed; the later single value wins.
        assert [e.value for e in policy.allowed] == ["one", "two"]
        assert [e.value for e in policy.denied] == ["x"]
        assert policy.lock is False

    def test_invalid_json_is_reported_not_raised(self, tmp_path: Path) -> None:
        errors: list[str] = []
        managed = tmp_path / "m"
        _write(managed / "managed-settings.json", "{not json")
        policy = read_managed_policy(managed, errors)
        assert policy.present and policy.unparsable_files
        assert any("not valid JSON" in e for e in errors)
        (inv,) = [f for f in _run(policy, []) if f.id == "MANAGED-001"]
        assert "refuses to start" in inv.description

    def test_oversized_file_is_reported(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(mp, "MAX_FILE_BYTES", 10)
        errors: list[str] = []
        managed = tmp_path / "m"
        _write(managed / "managed-settings.json", {"deniedMcpServers": []})
        read_managed_policy(managed, errors)
        assert any("limit" in e for e in errors)

    def test_budget_exhaustion_is_reported(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(mp, "MAX_TOTAL_BYTES", 40)
        errors: list[str] = []
        managed = tmp_path / "m"
        for i in range(3):
            _write(managed / "managed-settings.d" / f"{i}.json", {"model": "x" * 10})
        read_managed_policy(managed, errors)
        assert any("budget" in e for e in errors)

    def test_permission_error_never_crashes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        managed = tmp_path / "m"
        _write(managed / "managed-settings.json", {"deniedMcpServers": []})
        real = Path.is_file

        def boom(self: Path) -> bool:
            if self.name == "managed-settings.json":
                raise PermissionError("denied")
            return real(self)

        monkeypatch.setattr(Path, "is_file", boom)
        errors: list[str] = []
        policy = read_managed_policy(managed, errors)
        assert any("PermissionError" in e for e in errors)
        assert not policy.settings_files

    def test_crash_goes_to_errors(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def boom(*_a: object, **_k: object) -> None:
            raise RuntimeError("bang")

        monkeypatch.setattr(mp, "read_managed_policy", boom)
        errors: list[str] = []
        assert managed_policy_findings([], [], None, errors) == []
        assert errors == ["managed policy check error: RuntimeError: bang"]

    def test_malformed_entries_are_stripped(self, tmp_path: Path) -> None:
        policy = _policy(
            tmp_path,
            {
                "allowedMcpServers": [
                    {"serverName": "has space"},  # allowlist names: [A-Za-z0-9_-]
                    {"serverName": "ok", "serverUrl": "https://x"},  # two keys
                    {"serverCommand": []},
                    {"serverName": "good"},
                ],
                "deniedMcpServers": [
                    {"serverName": "claude.ai Slack"},  # any string is fine here
                    {"serverName": " padded"},
                ],
            },
        )
        assert [e.value for e in policy.allowed] == ["good"]
        assert [e.value for e in policy.denied] == ["claude.ai Slack"]
        assert policy.stripped_entries == 4

    def test_non_list_allowlist_is_enforced_as_empty(self, tmp_path: Path) -> None:
        policy = _policy(tmp_path, {"allowedMcpServers": {"serverName": "a"}})
        assert policy.allowed == []
        assert _dead(_run(policy, [_stdio("a", "node")])) == {"a"}


# ── Matching rules (managed-mcp "How a server is evaluated") ─────────────────


class TestUrlMatching:
    @pytest.mark.parametrize(
        ("pattern", "url", "expected"),
        [
            ("https://mcp.example.com/*", "https://mcp.example.com/api", True),
            ("https://mcp.example.com", "https://mcp.example.com/any/path", True),
            ("https://*.example.com/*", "https://api.example.com/mcp", True),
            ("https://*.example.com/*", "https://example.org/mcp", False),
            ("http://localhost:*/*", "http://localhost:8080/mcp", True),
            ("*://mcp.example.com/*", "http://mcp.example.com/x", True),
            ("https://Mcp.Example.com/*", "https://mcp.example.com/api", True),
            ("https://mcp.example.com/*", "https://mcp.example.com./api", True),
            ("https://mcp.example.com/API", "https://mcp.example.com/api", False),
            ("https://mcp.example.com/*", "https://user:pw@mcp.example.com/a", True),
            ("https://mcp.example.com/api", "https://mcp.example.com/api?x=1", True),
        ],
    )
    def test_documented_rules(self, pattern: str, url: str, expected: bool) -> None:
        assert url_matches(pattern, url) is expected

    def test_var_references_are_undecidable(self) -> None:
        assert url_matches("https://${HOST}/*", "https://a/b") is None
        assert url_matches("https://a/*", "https://${HOST}/b") is None

    def test_pathological_pattern_is_fast(self) -> None:
        start = time.monotonic()
        assert (
            url_matches("https://a/" + "*a" * 1500 + "b", "https://a/" + "a" * 3000)
            is False
        )
        assert time.monotonic() - start < 1.0


class TestDocumentedTables:
    """Rows from the managed-mcp page's evaluation accordions."""

    def test_url_only_allowlist(self, tmp_path: Path) -> None:
        policy = _policy(
            tmp_path,
            {
                "allowManagedMcpServersOnly": True,
                "allowedMcpServers": [
                    {"serverUrl": "https://mcp.example.com/*"},
                    {"serverUrl": "https://*.internal.example.com/*"},
                ],
            },
        )
        servers = [
            _remote("a", "https://mcp.example.com/api"),
            _remote("b", "https://api.internal.example.com/mcp"),
            _remote("c", "https://external.example.com/mcp"),
            _stdio("d", "node", "x.js"),
        ]
        assert _dead(_run(policy, servers)) == {"c", "d"}

    def test_command_only_allowlist(self, tmp_path: Path) -> None:
        policy = _policy(
            tmp_path,
            {
                "allowManagedMcpServersOnly": True,
                "allowedMcpServers": [
                    {"serverCommand": ["npx", "-y", "approved-package"]}
                ],
            },
        )
        servers = [
            _stdio("a", "npx", "-y", "approved-package"),
            _stdio("b", "node", "server.js"),
            _stdio("c", "npx", "approved-package"),
            _stdio("e", "npx", "-y", "approved-package", "--flag"),
            _remote("my-api", "https://x.example/mcp"),
        ]
        assert _dead(_run(policy, servers)) == {"b", "c", "e", "my-api"}

    def test_mixed_name_and_command(self, tmp_path: Path) -> None:
        policy = _policy(
            tmp_path,
            {
                "allowManagedMcpServersOnly": True,
                "allowedMcpServers": [
                    {"serverName": "github"},
                    {"serverCommand": ["npx", "-y", "approved-package"]},
                ],
            },
        )
        servers = [
            _stdio("local-tool", "npx", "-y", "approved-package"),
            _stdio("local-tool2", "node", "server.js"),
            _stdio("github", "node", "server.js", path=Path("/h/p/.mcp.json")),
            _remote("github", "https://api.example/mcp"),
            _remote("other-api", "https://api.example/mcp"),
        ]
        dead = _run(policy, servers)
        names = sorted(
            (f.server, Path(f.finding_path).name) for f in dead if f.id == "MANAGED-002"
        )
        assert names == [
            ("github", ".mcp.json"),
            ("local-tool2", ".claude.json"),
            ("other-api", ".claude.json"),
        ]

    def test_name_only_allowlist(self, tmp_path: Path) -> None:
        policy = _policy(
            tmp_path,
            {
                "allowManagedMcpServersOnly": True,
                "allowedMcpServers": [
                    {"serverName": "github"},
                    {"serverName": "internal-tool"},
                ],
            },
        )
        servers = [
            _stdio("github", "anything"),
            _stdio("internal-tool", "anything"),
            _remote("other", "https://x.example/mcp"),
        ]
        findings = _run(policy, servers)
        assert _dead(findings) == {"other"}
        (weak,) = [f for f in findings if f.id == "MANAGED-005"]
        assert weak.severity.value == "LOW"
        assert "is not a security control" in weak.description
        assert "remote (HTTP/SSE) servers and stdio servers" in weak.description

    def test_denylist_overrides_allowlist(self, tmp_path: Path) -> None:
        policy = _policy(
            tmp_path,
            {
                "allowedMcpServers": [{"serverUrl": "https://*.example.com/*"}],
                "deniedMcpServers": [{"serverUrl": "https://staging.example.com/*"}],
            },
        )
        servers = [
            _remote("a", "https://mcp.example.com/api"),
            _remote("b", "https://staging.example.com/api"),
            _remote("c", "https://other.com/mcp"),
        ]
        findings = _run(policy, servers)
        reasons = {
            f.server: f.evidence.split("reason: ")[1].split(" |")[0]
            for f in findings
            if f.id == "MANAGED-002"
        }
        assert reasons == {"b": "denied", "c": "not-allowed"}

    def test_unset_allowlist_allows_everything(self, tmp_path: Path) -> None:
        policy = _policy(tmp_path, {"deniedMcpServers": [{"serverName": "bad"}]})
        assert _dead(_run(policy, [_stdio("good", "node"), _stdio("bad", "node")])) == {
            "bad"
        }

    def test_var_reference_never_claims_blocked(self, tmp_path: Path) -> None:
        policy = _policy(
            tmp_path,
            {
                "allowManagedMcpServersOnly": True,
                "allowedMcpServers": [{"serverCommand": ["${HOME}/bin/server"]}],
                "deniedMcpServers": [{"serverCommand": ["${HOME}/bin/bad"]}],
            },
        )
        assert _dead(_run(policy, [_stdio("x", "/home/u/bin/bad")])) == set()


# ── Exclusive control, provided servers ──────────────────────────────────────


class TestExclusiveAndProvided:
    def test_managed_mcp_json_blocks_user_project_and_plugin_servers(
        self, tmp_path: Path
    ) -> None:
        policy = _policy(tmp_path, mcp={"mcpServers": {"github": {"type": "http"}}})
        servers = [
            _stdio("user", "node"),
            _stdio(
                "proj", "node", client="claude-code-project", path=Path("/r/.mcp.json")
            ),
            _stdio(
                "plug", "node", client="claude-code-plugin", path=Path("/p/.mcp.json")
            ),
            _stdio("cur", "node", client="cursor", path=Path("/h/.cursor/mcp.json")),
            _stdio("agent", "node", client="claude-code-agent", path=Path("/r/a.md")),
            _stdio("desk", "node", client="claude-desktop", path=Path("/h/c.json")),
        ]
        findings = _run(policy, servers)
        assert _dead(findings) == {"user", "proj", "plug"}
        (inv,) = [f for f in findings if f.id == "MANAGED-001"]
        assert "exclusive control" in inv.description and "github" in inv.description
        assert "MANAGED-003" not in _ids(findings)

    def test_empty_server_map_disables_mcp(self, tmp_path: Path) -> None:
        policy = _policy(tmp_path, mcp={"mcpServers": {}})
        assert _dead(_run(policy, [_stdio("a", "node")])) == {"a"}

    def test_unparsable_managed_mcp_json_claims_nothing(self, tmp_path: Path) -> None:
        managed = tmp_path / "m"
        _write(managed / "managed-mcp.json", "[[[")
        policy = read_managed_policy(managed, [])
        findings = _run(policy, [_stdio("a", "node")])
        assert _dead(findings) == set()
        assert "could not be read or parsed" in findings[0].description

    def test_provided_server_shadows_same_name(self, tmp_path: Path) -> None:
        policy = _policy(
            tmp_path,
            {
                "managedMcpServers": {
                    "search": {"type": "http", "url": "https://search.example.com/mcp"},
                    "bad": {"type": "http", "url": "http://insecure.example/mcp"},
                }
            },
        )
        servers = [
            _stdio("search", "node"),
            _stdio("bad", "node"),
            _remote(
                "p",
                "https://search.example.com/mcp",
                client="claude-code-plugin",
                path=Path("/p/.mcp.json"),
            ),
        ]
        findings = _run(policy, servers)
        assert _dead(findings) == {"search", "p"}
        (inv,) = [f for f in findings if f.id == "MANAGED-001"]
        assert "https:// URL" in inv.description  # the dropped entry's reason


# ── MANAGED-003 / MANAGED-004 ─────────────────────────────────────────────────


class TestNoPolicy:
    def test_settings_without_mcp_keys(self, tmp_path: Path) -> None:
        policy = _policy(tmp_path, {"permissions": {"deny": ["Bash(rm *)"]}})
        findings = _run(policy, [])
        assert _ids(findings) == ["MANAGED-001", "MANAGED-003"]
        (f,) = [f for f in findings if f.id == "MANAGED-003"]
        assert f.severity.value == "LOW"

    @pytest.mark.parametrize(
        "settings",
        [
            {"deniedMcpServers": [{"serverName": "x"}]},
            {"allowedMcpServers": []},
            {"allowManagedMcpServersOnly": True},
            {"strictPluginOnlyCustomization": True},
            {"managedMcpServers": {}},
        ],
    )
    def test_any_mcp_key_suppresses(self, tmp_path: Path, settings: dict) -> None:
        settings = dict(settings)
        if settings.get("managedMcpServers") == {}:
            settings["managedMcpServers"] = {
                "s": {"type": "http", "url": "https://s.example/mcp"}
            }
        assert "MANAGED-003" not in _ids(_run(_policy(tmp_path, settings), []))


def _settings_config(path: Path, raw: dict, client: str) -> DiscoveredConfig:
    _write(path, raw)
    return DiscoveredConfig(
        client_name=client, root_key="mcpServers", path=path, raw=raw
    )


class TestBroadened:
    _MANAGED = {"allowedMcpServers": [{"serverUrl": "https://ok.example/*"}]}

    def test_project_file_broadening_is_medium(self, tmp_path: Path) -> None:
        repo = tmp_path / "repo"
        cfg = _settings_config(
            repo / ".claude" / "settings.json",
            {"allowedMcpServers": [{"serverUrl": _SECRET_URL}]},
            "claude-code-project",
        )
        findings = _run(
            _policy(tmp_path, self._MANAGED), [], [cfg], tmp_path / "h", repo
        )
        (f,) = [f for f in findings if f.id == "MANAGED-004"]
        assert f.severity.value == "MEDIUM"
        assert "hunter2pass" not in f.evidence and "[REDACTED]" in f.evidence

    def test_user_and_local_files_are_low(self, tmp_path: Path) -> None:
        home = tmp_path / "h"
        repo = tmp_path / "repo"
        configs = [
            _settings_config(
                home / ".claude" / "settings.json",
                {"allowedMcpServers": [{"serverName": "mine"}]},
                "claude-code",
            ),
            _settings_config(
                repo / ".claude" / "settings.local.json",
                {"allowedMcpServers": [{"serverName": "local"}]},
                "claude-code-project",
            ),
        ]
        findings = _run(_policy(tmp_path, self._MANAGED), [], configs, home, repo)
        assert sorted(f.severity.value for f in findings if f.id == "MANAGED-004") == [
            "LOW",
            "LOW",
        ]

    def test_locked_allowlist_is_not_broadened(self, tmp_path: Path) -> None:
        repo = tmp_path / "repo"
        cfg = _settings_config(
            repo / ".claude" / "settings.json",
            {"allowedMcpServers": [{"serverName": "x"}]},
            "claude-code-project",
        )
        managed = {**self._MANAGED, "allowManagedMcpServersOnly": True}
        assert "MANAGED-004" not in _ids(
            _run(_policy(tmp_path, managed), [], [cfg], tmp_path / "h", repo)
        )

    def test_same_entries_as_managed_are_silent(self, tmp_path: Path) -> None:
        repo = tmp_path / "repo"
        cfg = _settings_config(
            repo / ".claude" / "settings.json",
            {"allowedMcpServers": [{"serverUrl": "https://ok.example/*"}]},
            "claude-code-project",
        )
        assert "MANAGED-004" not in _ids(
            _run(_policy(tmp_path, self._MANAGED), [], [cfg], tmp_path / "h", repo)
        )

    def test_unlocked_project_allowlist_admits_the_server(self, tmp_path: Path) -> None:
        repo = tmp_path / "repo"
        cfg = _settings_config(
            repo / ".claude" / "settings.json",
            {"allowedMcpServers": [{"serverUrl": "https://extra.example/*"}]},
            "claude-code-project",
        )
        server = _remote("x", "https://extra.example/mcp")
        findings = _run(
            _policy(tmp_path, self._MANAGED), [server], [cfg], tmp_path / "h", repo
        )
        assert _dead(findings) == set()

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlinks only")
    def test_symlinked_claude_dir_is_not_attributed(self, tmp_path: Path) -> None:
        repo = tmp_path / "repo"
        elsewhere = tmp_path / "elsewhere"
        _write(
            elsewhere / "settings.json", {"allowedMcpServers": [{"serverName": "x"}]}
        )
        repo.mkdir()
        (repo / ".claude").symlink_to(elsewhere)
        cfg = DiscoveredConfig(
            client_name="claude-code-project",
            root_key="mcpServers",
            path=repo / ".claude" / "settings.json",
            raw={"allowedMcpServers": [{"serverName": "x"}]},
        )
        assert "MANAGED-004" not in _ids(
            _run(_policy(tmp_path, self._MANAGED), [], [cfg], tmp_path / "h", repo)
        )

    def test_home_as_project_root_counts_as_user_file(self, tmp_path: Path) -> None:
        cfg = _settings_config(
            tmp_path / ".claude" / "settings.json",
            {"allowedMcpServers": [{"serverName": "x"}]},
            "claude-code",
        )
        findings = _run(
            _policy(tmp_path / "m", self._MANAGED), [], [cfg, cfg], tmp_path, tmp_path
        )
        broadened = [f for f in findings if f.id == "MANAGED-004"]
        assert [f.severity.value for f in broadened] == ["LOW"]


# ── End to end: scan / check / --project and every output format ─────────────


@pytest.fixture
def machine(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Path]:
    """A home with one leaky server, a repo with one, and a managed denylist."""
    home = tmp_path / "home"
    repo = tmp_path / "repo"
    managed = tmp_path / "managed"
    _write(
        home / ".claude.json",
        {
            "mcpServers": {
                "db": {"command": "npx", "args": ["-y", "pg-mcp", _SECRET_ARG]}
            }
        },
    )
    _write(
        repo / ".mcp.json",
        {"mcpServers": {"remote": {"type": "http", "url": _SECRET_URL}}},
    )
    _write(
        managed / "managed-settings.json",
        {
            "allowManagedMcpServersOnly": True,
            "allowedMcpServers": [{"serverUrl": "https://approved.example/*"}],
        },
    )
    monkeypatch.setattr("mcp_audit.discovery._home", lambda: home)
    monkeypatch.setattr("mcp_audit.plugins.mods.managed_settings_dir", lambda: managed)
    monkeypatch.chdir(repo)
    return {"home": home, "repo": repo, "managed": managed}


class TestEndToEnd:
    def test_default_scan_reports_blocked_servers(
        self, machine: dict[str, Path]
    ) -> None:
        from mcp_audit.scanner import run_scan  # noqa: PLC0415

        result = run_scan(skip_rug_pull=True)
        managed = [f for f in result.findings if f.id.startswith("MANAGED-")]
        assert _ids(managed) == ["MANAGED-001", "MANAGED-002", "MANAGED-002"]
        assert _dead(managed) == {"db", "remote"}

    def test_outputs_redact_secrets(self, machine: dict[str, Path]) -> None:
        from mcp_audit.cli import app  # noqa: PLC0415

        runner = CliRunner()
        secrets = ("hunter2pass", "s3cretPassw0rd")

        res = runner.invoke(app, ["scan", "--format", "json", "--no-score"])
        data = json.loads(res.stdout[res.stdout.index("{") :])
        managed = [f for f in data["findings"] if f["id"].startswith("MANAGED-")]
        assert len(managed) == 3
        assert not any(s in json.dumps(managed) for s in secrets)

        res = runner.invoke(app, ["scan", "--format", "sarif", "--no-score"])
        sarif = json.loads(res.stdout[res.stdout.index("{") :])
        results = [
            r for r in sarif["runs"][0]["results"] if r["ruleId"].startswith("MANAGED-")
        ]
        rules = [
            r
            for r in sarif["runs"][0]["tool"]["driver"]["rules"]
            if r["id"].startswith("MANAGED-")
        ]
        assert len(results) == 3
        assert not any(s in json.dumps([results, rules]) for s in secrets)

        res = runner.invoke(app, ["scan", "--no-score"])
        blocks = [
            block for block in res.output.split("\n\n") if "managed_policy" in block
        ]
        assert len(blocks) == 3
        assert not any(s in "".join(blocks) for s in secrets)

    def test_finding_text_is_redacted(self, machine: dict[str, Path]) -> None:
        from mcp_audit.scanner import run_scan  # noqa: PLC0415

        result = run_scan(skip_rug_pull=True)
        for f in result.findings:
            if f.id.startswith("MANAGED-"):
                text = f.title + f.description + f.evidence + f.remediation
                assert "hunter2pass" not in text and "s3cretPassw0rd" not in text

    def test_project_scan_reports_each_server_once(
        self, machine: dict[str, Path]
    ) -> None:
        from mcp_audit.cli import app  # noqa: PLC0415

        res = CliRunner().invoke(
            app, ["scan", "--project", str(machine["repo"]), "--format", "json"]
        )
        data = json.loads(res.stdout[res.stdout.index("{") :])
        dead = [f for f in data["findings"] if f["id"] == "MANAGED-002"]
        assert sorted(f["server"] for f in dead) == ["db", "remote"]
        assert sum(f["id"] == "MANAGED-001" for f in data["findings"]) == 1

    def test_scan_from_home_does_not_double_count(
        self, machine: dict[str, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from mcp_audit.scanner import run_scan  # noqa: PLC0415

        monkeypatch.chdir(machine["home"])
        result = run_scan(skip_rug_pull=True)
        assert _dead(result.findings) == {"db"}
        assert sum(f.id == "MANAGED-002" for f in result.findings) == 1

    def test_explicit_path_skips_the_check(self, machine: dict[str, Path]) -> None:
        from mcp_audit.scanner import run_scan  # noqa: PLC0415

        result = run_scan(
            extra_paths=[machine["repo"] / ".mcp.json"], skip_rug_pull=True
        )
        assert not [f for f in result.findings if f.id.startswith("MANAGED-")]

    def test_no_managed_files_is_silent(
        self, machine: dict[str, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from mcp_audit.scanner import run_scan  # noqa: PLC0415

        monkeypatch.setattr(
            "mcp_audit.plugins.mods.managed_settings_dir",
            lambda: machine["managed"] / "nope",
        )
        result = run_scan(skip_rug_pull=True)
        assert not [f for f in result.findings if f.id.startswith("MANAGED-")]


def test_demo_configs_produce_no_managed_findings() -> None:
    from mcp_audit.scanner import run_scan  # noqa: PLC0415

    demo = Path(__file__).resolve().parent.parent / "demo" / "configs"
    result = run_scan(extra_paths=[demo], skip_rug_pull=True)
    assert not [f for f in result.findings if f.id.startswith("MANAGED-")]


def test_conftest_keeps_the_real_managed_directory_out() -> None:
    policy = read_managed_policy()
    assert not policy.present
