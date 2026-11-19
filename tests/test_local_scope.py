"""Claude Code local-scope servers (STORY-0175).

``claude mcp add`` writes to the local scope by default: the entry goes to
``projects.<project path>.mcpServers`` in ``~/.claude.json``.  A default scan
reads those entries for the working directory's project.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_audit import discovery
from mcp_audit.analyzers.rug_pull import RugPullAnalyzer, server_key
from mcp_audit.config_parser import parse_config
from mcp_audit.discovery import (
    LOCAL_SCOPE_CLIENT,
    ClientSpec,
    DiscoveredConfig,
    discover_configs,
    local_scope_dirs,
)
from mcp_audit.fixer.fixer import run_fix
from mcp_audit.lock.auto_verify import _NOT_LOCKED_CLIENTS
from mcp_audit.models import Finding, ServerConfig, Severity
from mcp_audit.output.check import _is_auto_fixable
from mcp_audit.scanner import run_scan

#: The real function; ``tests/conftest.py`` replaces the module attribute.
_REAL_LOCAL_SCOPE_DIRS = local_scope_dirs

_KEY = "sk-ant-" + "a1b2c3d4e5f60718" * 3


def _claude_json(home: Path, projects: dict, top: dict | None = None) -> Path:
    path = home / ".claude.json"
    doc: dict = {"projects": projects}
    if top is not None:
        doc["mcpServers"] = top
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


def _config(path: Path, *dirs: Path) -> DiscoveredConfig:
    return DiscoveredConfig(
        client_name="claude-code",
        root_key="mcpServers",
        path=path,
        local_project_dirs=tuple(dirs),
    )


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A home with only Claude Code's user file, and the real directory rule."""
    home = tmp_path / "home"
    home.mkdir()
    spec = ClientSpec(
        name="claude-code", root_key="mcpServers", config_paths=[home / ".claude.json"]
    )
    monkeypatch.setattr("mcp_audit.discovery._get_client_specs", lambda: [spec])
    monkeypatch.setattr("mcp_audit.discovery._home", lambda: home)
    monkeypatch.setattr("mcp_audit.discovery.local_scope_dirs", _REAL_LOCAL_SCOPE_DIRS)
    return home


class TestParse:
    def test_the_projects_entry_of_the_directory_is_read(self, tmp_path: Path) -> None:
        project = tmp_path / "proj"
        project.mkdir()
        path = _claude_json(
            tmp_path,
            {str(project): {"mcpServers": {"loc": {"command": "npx", "args": ["x"]}}}},
            top={"usr": {"command": "uvx", "args": ["y"]}},
        )
        servers = parse_config(_config(path, project))
        assert [(s.client, s.name) for s in servers] == [
            ("claude-code", "usr"),
            (LOCAL_SCOPE_CLIENT, "loc"),
        ]
        assert servers[1].local_project == str(project)
        assert servers[1].config_path == path
        assert servers[1].command == "npx"

    def test_without_directories_the_file_reads_as_before(self, tmp_path: Path) -> None:
        project = tmp_path / "proj"
        project.mkdir()
        path = _claude_json(
            tmp_path,
            {str(project): {"mcpServers": {"loc": {"command": "npx"}}}},
            top={"usr": {"command": "uvx"}},
        )
        servers = parse_config(_config(path))
        assert [(s.client, s.name) for s in servers] == [("claude-code", "usr")]

    def test_another_projects_servers_are_not_read(self, tmp_path: Path) -> None:
        mine, other = tmp_path / "mine", tmp_path / "other"
        mine.mkdir()
        other.mkdir()
        path = _claude_json(
            tmp_path, {str(other): {"mcpServers": {"loc": {"command": "npx"}}}}
        )
        assert parse_config(_config(path, mine)) == []

    def test_a_file_with_no_top_level_servers_still_gives_local_ones(
        self, tmp_path: Path
    ) -> None:
        project = tmp_path / "proj"
        project.mkdir()
        path = _claude_json(
            tmp_path, {str(project): {"mcpServers": {"loc": {"url": "https://a.test"}}}}
        )
        servers = parse_config(_config(path, project))
        assert [(s.client, s.name, s.url) for s in servers] == [
            (LOCAL_SCOPE_CLIENT, "loc", "https://a.test")
        ]

    def test_one_name_in_two_directories_keeps_both(self, tmp_path: Path) -> None:
        root = tmp_path / "repo"
        sub = root / "pkg"
        sub.mkdir(parents=True)
        path = _claude_json(
            tmp_path,
            {
                str(root): {"mcpServers": {"db": {"command": "root-cmd"}}},
                str(sub): {"mcpServers": {"db": {"command": "sub-cmd"}}},
            },
        )
        servers = parse_config(_config(path, sub, root))
        assert [(s.name, s.command, s.local_project) for s in servers] == [
            ("db", "sub-cmd", str(sub)),
            ("db#2", "root-cmd", str(root)),
        ]

    def test_a_key_with_a_trailing_separator_matches(self, tmp_path: Path) -> None:
        project = tmp_path / "proj"
        project.mkdir()
        path = _claude_json(
            tmp_path, {f"{project}/": {"mcpServers": {"loc": {"command": "npx"}}}}
        )
        assert [s.name for s in parse_config(_config(path, project))] == ["loc"]

    @pytest.mark.parametrize(
        "projects",
        [
            [],
            "text",
            {"": {"mcpServers": {"a": {"command": "x"}}}},
            {"\x00": {"mcpServers": {"a": {"command": "x"}}}},
        ],
    )
    def test_odd_shapes_give_no_server_and_no_error(
        self, tmp_path: Path, projects: object
    ) -> None:
        project = tmp_path / "proj"
        project.mkdir()
        path = tmp_path / ".claude.json"
        path.write_text(json.dumps({"projects": projects}), encoding="utf-8")
        assert parse_config(_config(path, project)) == []

    @pytest.mark.parametrize("entry", [None, [], "x", {"mcpServers": []}, {}])
    def test_an_odd_project_entry_gives_no_server(
        self, tmp_path: Path, entry: object
    ) -> None:
        project = tmp_path / "proj"
        project.mkdir()
        path = tmp_path / ".claude.json"
        path.write_text(json.dumps({"projects": {str(project): entry}}), "utf-8")
        assert parse_config(_config(path, project)) == []

    def test_too_many_projects_is_a_note_not_a_read(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("mcp_audit.config_parser._MAX_LOCAL_PROJECT_KEYS", 2)
        project = tmp_path / "proj"
        project.mkdir()
        projects = {f"/p{i}": {} for i in range(3)}
        projects[str(project)] = {"mcpServers": {"loc": {"command": "x"}}}
        path = _claude_json(tmp_path, projects)
        config = _config(path, project)
        assert parse_config(config) == []
        assert any("local-scope" in w for w in config.parse_warnings)


class TestDirectories:
    def test_outside_a_repository_only_the_directory_counts(
        self, tmp_path: Path
    ) -> None:
        folder = tmp_path / "a" / "b"
        folder.mkdir(parents=True)
        assert _REAL_LOCAL_SCOPE_DIRS(folder) == (folder.resolve(),)

    def test_in_a_repository_the_parents_up_to_the_root_count(
        self, tmp_path: Path
    ) -> None:
        root = tmp_path / "repo"
        folder = root / "a" / "b"
        folder.mkdir(parents=True)
        (root / ".git").mkdir()
        assert _REAL_LOCAL_SCOPE_DIRS(folder) == (
            folder.resolve(),
            (root / "a").resolve(),
            root.resolve(),
        )


class TestDiscovery:
    def test_the_user_file_carries_the_scan_directories(
        self, home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        project = tmp_path / "proj"
        project.mkdir()
        monkeypatch.chdir(project)
        _claude_json(home, {})
        found = discover_configs(include_plugins=False, include_agents=False)
        user = [c for c in found if c.path == home / ".claude.json"]
        assert len(user) == 1
        assert user[0].local_project_dirs == (project.resolve(),)

    def test_lock_and_wrap_discovery_opt_out(
        self, home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        project = tmp_path / "proj"
        project.mkdir()
        monkeypatch.chdir(project)
        _claude_json(home, {})
        found = discover_configs(
            include_plugins=False, include_agents=False, include_local_scope=False
        )
        assert all(c.local_project_dirs == () for c in found)

    def test_an_explicit_path_reads_no_local_servers(
        self, home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        project = tmp_path / "proj"
        project.mkdir()
        monkeypatch.chdir(project)
        path = _claude_json(
            home, {str(project): {"mcpServers": {"loc": {"command": "npx"}}}}
        )
        found = discover_configs(extra_paths=[path], skip_auto_discovery=True)
        assert all(c.local_project_dirs == () for c in found)

    def test_lock_and_wrap_call_sites_pass_the_opt_out(self) -> None:
        for name in ("lock.py", "wrap.py"):
            source = (Path(discovery.__file__).parent / "cli" / name).read_text(
                encoding="utf-8"
            )
            assert "include_local_scope=False" in source, name


class TestScan:
    def _scan(self, home: Path, project: Path, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.chdir(project)
        return run_scan(include_plugins=False, skip_rug_pull=True)

    def test_a_default_scan_checks_a_local_scope_server(
        self, home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        project = tmp_path / "proj"
        project.mkdir()
        _claude_json(
            home,
            {
                str(project): {
                    "mcpServers": {
                        "loc": {
                            "command": "npx",
                            "args": ["-y", "pkg"],
                            "env": {"ANTHROPIC_API_KEY": _KEY},
                        }
                    }
                }
            },
        )
        result = self._scan(home, project, monkeypatch)
        assert [(s.client, s.name) for s in result.servers] == [
            (LOCAL_SCOPE_CLIENT, "loc")
        ]
        cred = [f for f in result.findings if f.id.startswith("CRED-")]
        assert cred and all(f.client == LOCAL_SCOPE_CLIENT for f in cred)
        assert all(f.server == "loc" for f in cred)

    def test_a_scan_from_another_directory_does_not(
        self, home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        project, other = tmp_path / "proj", tmp_path / "other"
        project.mkdir()
        other.mkdir()
        _claude_json(home, {str(project): {"mcpServers": {"loc": {"command": "npx"}}}})
        result = self._scan(home, other, monkeypatch)
        assert result.servers == []

    def test_no_output_carries_the_project_directory(
        self, home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        project = tmp_path / "proj"
        project.mkdir()
        _claude_json(home, {str(project): {"mcpServers": {"loc": {"command": "npx"}}}})
        result = self._scan(home, project, monkeypatch)
        assert result.servers[0].local_project == str(project.resolve())
        assert "local_project" not in result.servers[0].model_dump()
        assert "local_project" not in result.model_dump_json()


def _local(name: str, project: str, command: str = "npx") -> ServerConfig:
    return ServerConfig(
        name=name,
        client=LOCAL_SCOPE_CLIENT,
        config_path=Path("/home/u/.claude.json"),
        command=command,
        raw={"command": command},
        local_project=project,
    )


class TestRugPull:
    def test_the_state_key_carries_the_project(self) -> None:
        assert server_key(_local("db", "/work/a")) == "claude-code-local/db @ /work/a"
        assert server_key(_local("db", "/work/a")) != server_key(
            _local("db", "/work/b")
        )

    def test_a_scan_somewhere_else_reports_nothing_removed(
        self, tmp_path: Path
    ) -> None:
        state = tmp_path / "state.json"
        RugPullAnalyzer(state_path=state).analyze_all([_local("db", "/work/a")])
        user = ServerConfig(
            name="usr",
            client="claude-code",
            config_path=Path("/home/u/.claude.json"),
            command="uvx",
        )
        findings = RugPullAnalyzer(state_path=state).analyze_all([user])
        assert [f.id for f in findings if f.id == "RUGPULL-003"] == []

    def test_a_scan_of_the_same_project_reports_the_removed_server(
        self, tmp_path: Path
    ) -> None:
        state = tmp_path / "state.json"
        RugPullAnalyzer(state_path=state).analyze_all(
            [_local("db", "/work/a"), _local("mem", "/work/a")]
        )
        findings = RugPullAnalyzer(state_path=state).analyze_all(
            [_local("mem", "/work/a")]
        )
        removed = [f for f in findings if f.id == "RUGPULL-003"]
        assert [f.server for f in removed] == ["db"]

    def test_a_changed_launch_is_reported_for_its_own_project_only(
        self, tmp_path: Path
    ) -> None:
        state = tmp_path / "state.json"
        RugPullAnalyzer(state_path=state).analyze_all(
            [_local("db", "/work/a"), _local("db", "/work/b")]
        )
        findings = RugPullAnalyzer(state_path=state).analyze_all(
            [_local("db", "/work/a", command="evil"), _local("db", "/work/b")]
        )
        changed = [f for f in findings if f.id == "RUGPULL-001"]
        assert len(changed) == 1


class TestOtherCommands:
    def test_lock_auto_verify_never_reports_a_local_server(self) -> None:
        assert LOCAL_SCOPE_CLIENT in _NOT_LOCKED_CLIENTS

    def test_check_offers_no_fix_for_a_local_server(self) -> None:
        finding = Finding(
            id="CRED-001",
            severity=Severity.HIGH,
            analyzer="credentials",
            client=LOCAL_SCOPE_CLIENT,
            server="loc",
            title="t",
            description="d",
            evidence="e",
            remediation="r",
            finding_path="/home/u/.claude.json",
        )
        assert _is_auto_fixable(finding) is False
        assert _is_auto_fixable(finding.model_copy(update={"client": "claude-code"}))

    def test_fix_never_edits_a_same_named_top_level_server(
        self, tmp_path: Path
    ) -> None:
        path = tmp_path / ".claude.json"
        doc = {
            "mcpServers": {"db": {"command": "npx", "env": {"API_KEY": "plain"}}},
            "projects": {
                "/work/a": {
                    "mcpServers": {"db": {"command": "npx", "env": {"API_KEY": _KEY}}}
                }
            },
        }
        text = json.dumps(doc, indent=2)
        path.write_text(text, encoding="utf-8")
        finding = Finding(
            id="CRED-001",
            severity=Severity.HIGH,
            analyzer="credentials",
            client=LOCAL_SCOPE_CLIENT,
            server="db",
            title="t",
            description="d",
            evidence="API_KEY",
            remediation="r",
            finding_path=str(path),
        )
        result = run_fix([finding], path, apply=True)
        assert path.read_text(encoding="utf-8") == text
        assert result.fixes_applied == []
        assert any("local-scope" in line for line in result.skipped)
