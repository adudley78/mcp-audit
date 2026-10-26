"""Tests for analyzers/sandbox.py: SANDBOX-001..005 (STORY-0093).

SANDBOX-001..004 are exercised through ``ConfigHygieneAnalyzer.analyze_config``
(the path a scan uses), SANDBOX-005 through ``analyze_settings_git_exposure``,
the scanner's step 0b and the CLI.  Each check has firing cases from
Anthropic's documentation, near misses that must stay silent, and the scope
rules (which file Claude Code reads a key from) it rests on.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from mcp_audit.analyzers import sandbox as sb
from mcp_audit.analyzers.config_hygiene import ConfigHygieneAnalyzer
from mcp_audit.cli import app
from mcp_audit.discovery import DiscoveredConfig
from mcp_audit.models import Finding, ScanResult, Severity
from mcp_audit.scanner import _run_static_pipeline, get_default_analyzers

runner = CliRunner()
TOKEN = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890"  # noqa: S105 - synthetic


# ── Helpers and fixtures ──────────────────────────────────────────────────────


def _sandbox(raw: object, path: Path) -> list[Finding]:
    findings = ConfigHygieneAnalyzer().analyze_config(raw, path, "claude-code")
    return [f for f in findings if f.id.startswith("SANDBOX-")]


def _ids(findings: list[Finding]) -> list[tuple[str, Severity]]:
    return [(f.id, f.severity) for f in findings]


def _box(**block: object) -> dict:
    return {"sandbox": block}


def _write(path: Path, data: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "home"
    path.mkdir()
    monkeypatch.setattr(Path, "home", lambda: path)
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    return path


@pytest.fixture
def project(tmp_path: Path, home: Path) -> Path:
    p = tmp_path / "repo" / ".claude" / "settings.json"
    p.parent.mkdir(parents=True)
    return p


@pytest.fixture
def local(project: Path) -> Path:
    return project.parent / "settings.local.json"


@pytest.fixture
def user(home: Path) -> Path:
    p = home / ".claude" / "settings.json"
    p.parent.mkdir(parents=True)
    return p


# ── SANDBOX-001 ───────────────────────────────────────────────────────────────

WEAKENING = [
    ("enableWeakerNestedSandbox", {"enableWeakerNestedSandbox": True}),
    ("enableWeakerNetworkIsolation", {"enableWeakerNetworkIsolation": True}),
    ("network.allowAllUnixSockets", {"network": {"allowAllUnixSockets": True}}),
    ("network.allowLocalBinding", {"network": {"allowLocalBinding": True}}),
]


class TestSandbox001:
    @pytest.mark.parametrize(("key", "block"), WEAKENING)
    @pytest.mark.parametrize("which", ["project", "local"])
    def test_weakening_key_from_a_repository_file_is_high(
        self, key: str, block: dict, which: str, project: Path, local: Path
    ) -> None:
        path = project if which == "project" else local
        out = _sandbox({"sandbox": block}, path)
        assert _ids(out) == [("SANDBOX-001", Severity.HIGH)]
        assert f"sandbox.{key} = true" in out[0].evidence
        assert "Each one weakens the sandbox" in out[0].description
        assert "admin-required" in out[0].description

    @pytest.mark.parametrize("value", [False, None, "true", 1, [], {}])
    def test_only_a_json_true_counts(self, value: object, project: Path) -> None:
        raw = _box(
            enableWeakerNestedSandbox=value,
            network={"allowLocalBinding": value, "allowAllUnixSockets": value},
        )
        assert not [f for f in _sandbox(raw, project) if f.id == "SANDBOX-001"]

    def test_enabled_false_in_shared_project_settings_is_high(
        self, project: Path, local: Path
    ) -> None:
        out = _sandbox(_box(enabled=False), project)
        assert _ids(out) == [("SANDBOX-001", Severity.HIGH)]
        assert "even when your ~/.claude/settings.json" in out[0].description
        # Claude Code's /sandbox panel writes `enabled` to the local file.
        assert _sandbox(_box(enabled=False), local) == []
        assert _sandbox(_box(enabled=True), project) == []

    def test_fail_if_unavailable_false_is_medium_in_project_only(
        self, project: Path, local: Path
    ) -> None:
        assert _ids(_sandbox(_box(failIfUnavailable=False), project)) == [
            ("SANDBOX-001", Severity.MEDIUM)
        ]
        assert _sandbox(_box(failIfUnavailable=False), local) == []
        assert _sandbox(_box(failIfUnavailable=True), project) == []

    @pytest.mark.parametrize("key", ["httpProxyPort", "socksProxyPort"])
    def test_proxy_port_is_medium(self, key: str, project: Path) -> None:
        out = _sandbox(_box(network={key: 8080}), project)
        assert _ids(out) == [("SANDBOX-001", Severity.MEDIUM)]
        assert "stops applying its domain lists" in out[0].description

    @pytest.mark.parametrize("port", [None, True, 0, 70000, "8080", 80.5])
    def test_invalid_or_null_ports_are_silent(
        self, port: object, project: Path
    ) -> None:
        raw = _box(network={"httpProxyPort": port, "socksProxyPort": port})
        assert _sandbox(raw, project) == []

    def test_one_finding_per_severity(self, project: Path) -> None:
        raw = _box(
            enabled=False,
            enableWeakerNestedSandbox=True,
            enableWeakerNetworkIsolation=True,
            failIfUnavailable=False,
            network={"allowAllUnixSockets": True, "httpProxyPort": 3128},
        )
        out = _sandbox(raw, project)
        assert _ids(out) == [
            ("SANDBOX-001", Severity.HIGH),
            ("SANDBOX-001", Severity.MEDIUM),
        ]
        assert out[0].evidence.count("sandbox.") == 4

    def test_user_settings_are_the_users_own_choice(self, user: Path) -> None:
        raw = _box(
            enabled=False,
            enableWeakerNestedSandbox=True,
            network={"allowLocalBinding": True, "httpProxyPort": 8080},
            excludedCommands=["docker *"],
        )
        assert _sandbox(raw, user) == []

    def test_local_file_in_the_home_directory_is_the_users_own(
        self, home: Path
    ) -> None:
        path = home / ".claude" / "settings.local.json"
        path.parent.mkdir(parents=True)
        assert _sandbox(_box(enableWeakerNestedSandbox=True), path) == []


# ── SANDBOX-002 ───────────────────────────────────────────────────────────────


class TestSandbox002:
    @pytest.mark.parametrize(
        "entry",
        [
            "python *",
            "python3 -c *",
            "python3.12 *",
            "/usr/bin/python3 *",
            "Python3.exe *",
            "bash *",
            "sh -c *",
            "zsh:*",
            "node *",
            "pwsh *",
            "osascript *",
            "npx *",
            "uvx *",
            "uv run *",
            "pnpm dlx *",
            "pipx run *",
            "bun x *",
            "python -m *",
            "direnv exec . *",
            "*.sh",
            "docker *",
            "docker compose *",
            "docker compose up *",
            "docker run *",
            "docker exec -it *",
            "podman *",
            "nerdctl run *",
            "docker-compose *",
            "*",
            "* --version",
        ],
    )
    def test_code_running_exclusions_fire(self, entry: str, project: Path) -> None:
        out = _sandbox(_box(excludedCommands=[entry]), project)
        assert _ids(out) == [("SANDBOX-002", Severity.HIGH)]
        assert "An excluded command runs with your full access" in out[0].description
        assert "Bash command (unsandboxed)" in out[0].description

    @pytest.mark.parametrize(
        "entry",
        [
            "python scripts/load_orders.py *",  # the doc's own narrowed example
            "uv run pytest *",
            "npm run build *",
            "docker",  # exact match, no arguments
            "python",
            "docker ps",
            "docker build *",
            "docker run myimage *",
            "gh *",
            "git push *",
            "git fetch *",
            "make *",
            "python3 -m pytest *",
            "direnv exec . npm test *",
            "bun run build *",
            "sudo *",  # calls starting with sudo stay sandboxed
            "",
            None,
            3,
        ],
    )
    def test_narrow_or_inert_exclusions_are_silent(
        self, entry: object, project: Path
    ) -> None:
        assert _sandbox(_box(excludedCommands=[entry]), project) == []

    @pytest.mark.parametrize(
        "socket",
        [
            "/var/run/docker.sock",
            "~/.docker/run/docker.sock",
            "/run/podman/podman.sock",
            "/run/containerd/containerd.sock",
        ],
    )
    def test_container_daemon_socket_fires(self, socket: str, project: Path) -> None:
        out = _sandbox(_box(network={"allowUnixSockets": [socket]}), project)
        assert _ids(out) == [("SANDBOX-002", Severity.HIGH)]
        assert "/var/run/docker.sock effectively grants access" in out[0].description

    def test_other_sockets_are_silent(self, project: Path) -> None:
        raw = _box(network={"allowUnixSockets": ["~/.ssh/agent-socket", 5]})
        assert _sandbox(raw, project) == []

    def test_malformed_lists_are_tolerated(self, project: Path) -> None:
        raw = _box(excludedCommands="docker *", network={"allowUnixSockets": "x"})
        assert _sandbox(raw, project) == []

    def test_entries_are_listed_in_one_finding(self, project: Path) -> None:
        raw = _box(
            excludedCommands=["docker *", "bash *", "npm ci"],
            network={"allowUnixSockets": ["/var/run/docker.sock"]},
        )
        out = _sandbox(raw, project)
        assert len(out) == 1
        assert out[0].evidence.count("contains") == 3


# ── SANDBOX-003 ───────────────────────────────────────────────────────────────


class TestSandbox003:
    @pytest.mark.parametrize(
        ("entry", "kind"),
        [
            ("github.com", "code host"),
            ("*.github.com", "code host"),
            ("gist.github.com", "code host"),
            ("api.github.com:443", "code host"),
            ("GitHub.COM.", "code host"),
            ("gitlab.com", "code host"),
            ("pastebin.com", "paste site"),
            ("hooks.slack.com", "webhook receiver"),
            ("webhook.site", "webhook receiver"),
            ("discord.com", "webhook receiver"),
            ("*", "every host"),
        ],
    )
    def test_publishable_hosts_fire(self, entry: str, kind: str, project: Path) -> None:
        out = _sandbox(_box(network={"allowedDomains": [entry]}), project)
        assert _ids(out) == [("SANDBOX-003", Severity.MEDIUM)]
        assert kind in out[0].description
        assert "Allowing broad domains such as github.com" in out[0].description

    @pytest.mark.parametrize(
        "entry",
        [
            "github.example.com",  # Anthropic's HIPAA example
            "registry.example.com",
            "registry.npmjs.org",
            "*.npmjs.org",
            "notgithub.com",
            "raw.githubusercontent.com",
            "[::1]:443",
            "localhost",
            "127.0.0.1:8080",
            "",
            None,
        ],
    )
    def test_other_hosts_are_silent(self, entry: object, project: Path) -> None:
        assert _sandbox(_box(network={"allowedDomains": [entry]}), project) == []

    def test_user_settings_are_silent(self, user: Path) -> None:
        assert _sandbox(_box(network={"allowedDomains": ["github.com"]}), user) == []


# ── SANDBOX-004 ───────────────────────────────────────────────────────────────


class TestSandbox004:
    @pytest.mark.parametrize(
        ("block", "key"),
        [
            ({"allowAppleEvents": True}, "allowAppleEvents"),
            ({"allowNestedUserNamespaces": True}, "allowNestedUserNamespaces"),
            ({"filesystem": {"disabled": True}}, "filesystem.disabled"),
            ({"network": {"strictAllowlist": True}}, "network.strictAllowlist"),
            ({"network": {"tlsTerminate": {}}}, "network.tlsTerminate"),
            ({"ripgrep": {"command": "/usr/local/bin/rg"}}, "ripgrep"),
            ({"bwrapPath": "/opt/bwrap"}, "bwrapPath"),
            ({"socatPath": "/opt/socat"}, "socatPath"),
            (
                {"filesystem": {"allowManagedReadPathsOnly": True}},
                "filesystem.allowManagedReadPathsOnly",
            ),
            (
                {"network": {"allowManagedDomainsOnly": True}},
                "network.allowManagedDomainsOnly",
            ),
            (
                {"credentials": {"allowPlaintextInject": True}},
                "credentials.allowPlaintextInject",
            ),
        ],
    )
    @pytest.mark.parametrize("which", ["project", "local"])
    def test_keys_a_repository_cant_set_are_info(
        self, block: dict, key: str, which: str, project: Path, local: Path
    ) -> None:
        path = project if which == "project" else local
        out = _sandbox({"sandbox": block}, path)
        assert _ids(out) == [("SANDBOX-004", Severity.INFO)]
        assert f"sandbox.{key}" in out[0].evidence

    def test_locks_are_named_as_giving_no_protection(self, project: Path) -> None:
        raw = _box(
            network={"strictAllowlist": True, "allowManagedDomainsOnly": True},
            allowAppleEvents=True,
        )
        out = _sandbox(raw, project)
        assert "give none from this file: sandbox.network.strictAllowlist" in (
            out[0].description
        )
        assert "allowManagedDomainsOnly" in out[0].description

    def test_mask_credential_entries_are_ignored_outside_user_settings(
        self, project: Path, user: Path
    ) -> None:
        raw = _box(
            credentials={
                "envVars": [
                    {"name": "GH_TOKEN", "mode": "mask"},
                    {"name": "AWS_SECRET_ACCESS_KEY", "mode": "deny"},
                ],
                "files": [{"path": "~/.npmrc", "mode": "mask"}],
            }
        )
        out = _sandbox(raw, project)
        assert _ids(out) == [("SANDBOX-004", Severity.INFO)]
        assert "'GH_TOKEN'" in out[0].evidence and "'~/.npmrc'" in out[0].evidence
        assert "AWS_SECRET" not in out[0].evidence  # deny entries apply anywhere
        assert _sandbox(raw, user) == []

    def test_user_settings_report_managed_only_keys(self, user: Path) -> None:
        raw = _box(
            bwrapPath="/opt/bwrap",
            allowAppleEvents=True,
            network={"strictAllowlist": True, "allowManagedDomainsOnly": True},
        )
        out = _sandbox(raw, user)
        assert _ids(out) == [("SANDBOX-004", Severity.INFO)]
        assert "bwrapPath" in out[0].evidence
        assert "allowManagedDomainsOnly" in out[0].evidence
        assert "strictAllowlist" not in out[0].evidence  # honoured in user settings
        assert "allowAppleEvents" not in out[0].evidence

    @pytest.mark.parametrize(
        "block",
        [
            {"allowAppleEvents": False},
            {"allowNestedUserNamespaces": False},  # "A false counts from any file"
            {"network": {"strictAllowlist": False, "tlsTerminate": None}},
            {"bwrapPath": ""},
            {"ripgrep": {}},
        ],
    )
    def test_default_values_are_silent(self, block: dict, project: Path) -> None:
        assert _sandbox({"sandbox": block}, project) == []

    def test_global_config_is_not_a_settings_file_for_sandbox(self, home: Path) -> None:
        path = home / ".claude.json"
        assert _sandbox(_box(allowAppleEvents=True, enabled=False), path) == []


# ── Whole-file behaviour and precision ────────────────────────────────────────

# Hand-written configs in the shapes Anthropic documents for ordinary use
# (strict, bash-sandbox, managed-style lockdown, a team file); Anthropic's own
# example files were measured locally and are not copied here.
ORDINARY = [
    {"sandbox": {"enabled": True}},
    {"sandbox": {"enabled": True, "autoAllowBashIfSandboxed": False}},
    {
        "sandbox": {
            "enabled": True,
            "autoAllowBashIfSandboxed": False,
            "allowUnsandboxedCommands": False,
            "excludedCommands": [],
            "enableWeakerNestedSandbox": False,
            "network": {
                "allowUnixSockets": [],
                "allowAllUnixSockets": False,
                "allowLocalBinding": False,
                "allowedDomains": [],
                "httpProxyPort": None,
                "socksProxyPort": None,
            },
        }
    },
    {
        "sandbox": {
            "enabled": True,
            "failIfUnavailable": True,
            "filesystem": {
                "allowWrite": ["./build", "~/.kube"],
                "denyRead": ["~/.aws/credentials"],
                "allowManagedReadPathsOnly": True,
            },
            "credentials": {"files": [{"path": "~/.ssh", "mode": "deny"}]},
            "network": {
                "allowedDomains": ["registry.npmjs.org", "github.example.com"],
                "deniedDomains": ["uploads.github.com"],
                "allowManagedDomainsOnly": True,
            },
        }
    },
    {
        "permissions": {"allow": ["Bash(npm run test *)"], "deny": ["Read(./.env)"]},
        "sandbox": {
            "enabled": True,
            "excludedCommands": ["python scripts/load_orders.py *", "gh pr view *"],
            "ignoreViolations": {"*": ["/etc/hosts"]},
        },
    },
]


class TestWholeFile:
    @pytest.mark.parametrize("raw", ORDINARY)
    @pytest.mark.parametrize("which", ["project", "local", "user"])
    def test_ordinary_configs_stay_at_info_or_below(
        self, raw: dict, which: str, project: Path, local: Path, user: Path
    ) -> None:
        path = {"project": project, "local": local, "user": user}[which]
        for finding in _sandbox(raw, path):
            assert finding.severity == Severity.INFO, finding.id

    @pytest.mark.parametrize("raw", [{}, [], "x", {"sandbox": None}, {"sandbox": []}])
    def test_malformed_input_is_silent(self, raw: object, project: Path) -> None:
        assert sb.analyze_sandbox_settings(raw, project, "claude-code") == []

    def test_not_a_claude_settings_file(self, tmp_path: Path) -> None:
        raw = _box(enableWeakerNestedSandbox=True)
        assert sb.analyze_sandbox_settings(raw, tmp_path / "mcp.json", "c") == []

    def test_findings_carry_the_settings_path_and_analyzer(self, project: Path) -> None:
        out = _sandbox(_box(enableWeakerNestedSandbox=True), project)
        assert out[0].finding_path == str(project)
        assert out[0].analyzer == "config_hygiene"
        assert out[0].server == "(config-level)"

    def test_huge_lists_stay_capped(self, project: Path) -> None:
        raw = _box(excludedCommands=["bash *"] * 5000)
        out = _sandbox(raw, project)
        assert "(+4980 more)" in out[0].evidence
        assert len(out[0].description) < 10_000

    def test_secrets_in_values_are_masked(self, project: Path) -> None:
        raw = _box(
            excludedCommands=[f"npx --registry=https://u:{TOKEN}@npm.example *"],
            ripgrep={"command": "/usr/bin/rg", "args": ["--token", TOKEN]},
        )
        out = _sandbox(raw, project)
        assert _ids(out) == [
            ("SANDBOX-002", Severity.HIGH),
            ("SANDBOX-004", Severity.INFO),
        ]
        for finding in out:
            text = finding.model_dump_json()
            assert TOKEN not in text
            assert "***" in finding.evidence

    def test_huge_values_are_quoted_quickly(self, project: Path) -> None:
        start = time.perf_counter()
        raw = _box(
            excludedCommands=["npx " + "-x " * 2_000_000 + "*"],
            ripgrep={"command": "rg", "args": ["a" * 5_000_000]},
        )
        out = _sandbox(raw, project)
        assert {f.id for f in out} == {"SANDBOX-002", "SANDBOX-004"}
        assert time.perf_counter() - start < 5
        assert all(len(f.evidence) < 2_000 for f in out)

    def test_long_values_are_truncated(self, project: Path) -> None:
        raw = _box(network={"allowedDomains": ["a" * 5000 + ".github.com"]})
        out = _sandbox(raw, project)
        assert len(out[0].evidence) < 400


# ── SANDBOX-005 ───────────────────────────────────────────────────────────────


def _config(path: Path, raw: object = None, **kwargs: object) -> DiscoveredConfig:
    return DiscoveredConfig(
        client_name="claude-code-project",
        root_key="mcpServers",
        path=path,
        raw=raw if raw is not None else {},
        **kwargs,
    )


@pytest.fixture
def repo(tmp_path: Path, home: Path) -> Path:
    root = tmp_path / "repo"
    (root / ".git" / "info").mkdir(parents=True)
    (root / ".claude").mkdir()
    return root


def _exposure(*configs: DiscoveredConfig) -> tuple[list[Finding], list[str]]:
    return sb.analyze_settings_git_exposure(configs)


class TestSandbox005Local:
    def test_unignored_local_settings_in_a_work_tree_is_medium(
        self, repo: Path
    ) -> None:
        path = _write(repo / ".claude" / "settings.local.json", {})
        raw = {"permissions": {"allow": ["Bash(ls *)"]}, "hooks": {"Stop": []}}
        findings, errors = _exposure(_config(path, raw))
        assert _ids(findings) == [("SANDBOX-005", Severity.MEDIUM)]
        assert errors == []
        text = findings[0].description
        assert "git work tree 'repo'" in text
        assert "~/.config/git/ignore" in text
        assert "1 permission rule(s)" in text
        assert "treats it as repository-supplied" in text

    @pytest.mark.parametrize(
        ("where", "text"),
        [
            (".gitignore", ".claude/settings.local.json"),
            (".gitignore", "**/.claude/settings.local.json"),
            (".gitignore", ".claude/"),
            (".claude/.gitignore", "settings.local.json"),
            (".git/info/exclude", "settings.local.json"),
            ("home:.config/git/ignore", "**/.claude/settings.local.json"),
        ],
    )
    def test_any_ignore_source_covers_it(
        self, where: str, text: str, repo: Path, home: Path
    ) -> None:
        path = _write(repo / ".claude" / "settings.local.json", {})
        target = home / where[5:] if where.startswith("home:") else repo / where
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text + "\n")
        assert _exposure(_config(path)) == ([], [])

    def test_core_excludes_file(self, repo: Path, home: Path) -> None:
        path = _write(repo / ".claude" / "settings.local.json", {})
        (home / ".gitconfig").write_text("[core]\n  excludesfile = ~/.gi\n")
        assert _ids(_exposure(_config(path))[0]) == [("SANDBOX-005", Severity.MEDIUM)]
        (home / ".gi").write_text("settings.local.json\n")
        assert _exposure(_config(path)) == ([], [])

    def test_outside_a_work_tree_nothing_is_reported(
        self, tmp_path: Path, home: Path
    ) -> None:
        path = _write(tmp_path / "plain" / ".claude" / "settings.local.json", {})
        if sb.find_work_tree_root(path.parent.parent) is not None:
            pytest.skip("the test directory itself sits in a git work tree")
        assert _exposure(_config(path)) == ([], [])

    def test_nested_project_uses_the_enclosing_work_tree(self, repo: Path) -> None:
        path = _write(repo / "pkg" / "app" / ".claude" / "settings.local.json", {})
        assert _ids(_exposure(_config(path))[0]) == [("SANDBOX-005", Severity.MEDIUM)]
        (repo / "pkg" / ".gitignore").write_text("app/.claude/settings.local.json\n")
        assert _exposure(_config(path)) == ([], [])

    def test_home_directory_local_file_is_skipped(self, home: Path) -> None:
        (home / ".git").mkdir()
        path = _write(home / ".claude" / "settings.local.json", {})
        assert _exposure(_config(path)) == ([], [])

    def test_shared_project_settings_alone_are_not_medium(self, repo: Path) -> None:
        path = _write(repo / ".claude" / "settings.json", {})
        assert _exposure(_config(path, {"permissions": {"allow": ["Read"]}})) == (
            [],
            [],
        )

    def test_each_file_once(self, repo: Path) -> None:
        path = _write(repo / ".claude" / "settings.local.json", {})
        findings, _ = _exposure(_config(path), _config(path))
        assert len(findings) == 1


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlinks")
class TestSandbox005Symlinks:
    def test_symlinked_settings_file_is_skipped(
        self, repo: Path, tmp_path: Path
    ) -> None:
        target = _write(tmp_path / "elsewhere.json", {})
        path = repo / ".claude" / "settings.local.json"
        path.symlink_to(target)
        assert _exposure(_config(path, is_symlink=True)) == ([], [])
        assert _exposure(_config(path)) == ([], [])  # checked even if not flagged

    def test_symlinked_claude_directory_is_skipped(
        self, tmp_path: Path, home: Path
    ) -> None:
        root = tmp_path / "repo2"
        (root / ".git").mkdir(parents=True)
        real = tmp_path / "outside" / ".claude"
        _write(real / "settings.local.json", {})
        (root / ".claude").symlink_to(real, target_is_directory=True)
        assert _exposure(_config(root / ".claude" / "settings.local.json")) == ([], [])

    def test_symlinked_gitignore_does_not_count(
        self, repo: Path, tmp_path: Path
    ) -> None:
        path = _write(repo / ".claude" / "settings.local.json", {})
        (tmp_path / "gi").write_text(".claude/\n")
        (repo / ".gitignore").symlink_to(tmp_path / "gi")
        assert _ids(_exposure(_config(path))[0]) == [("SANDBOX-005", Severity.MEDIUM)]


class TestSandbox005Errors:
    def test_unreadable_gitignore_is_an_error_not_a_finding(
        self, repo: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = _write(repo / ".claude" / "settings.local.json", {})
        (repo / ".gitignore").write_text("x\n")
        real_open = Path.open

        def deny(self: Path, *args: object, **kwargs: object):  # noqa: ANN202
            if self.name == ".gitignore":
                raise PermissionError(13, "Permission denied")
            return real_open(self, *args, **kwargs)

        monkeypatch.setattr(Path, "open", deny)
        findings, errors = _exposure(_config(path))
        assert findings == []
        assert errors == [
            "SANDBOX-005 skipped: could not read repo/.gitignore: Permission denied"
        ]
        assert str(repo) not in errors[0]  # never an absolute path (--path exit 2)

    def test_permission_error_on_is_symlink_is_contained(
        self, repo: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = _write(repo / ".claude" / "settings.local.json", {})
        real = Path.is_symlink

        def boom(self: Path) -> bool:
            if self.name == ".claude":
                raise PermissionError(13, "Permission denied")
            return real(self)

        monkeypatch.setattr(Path, "is_symlink", boom)
        findings, errors = _exposure(_config(path))
        assert findings == []
        assert errors and "Permission denied" in errors[0]
        assert str(repo) not in errors[0]

    def test_pipeline_records_errors_and_survives_a_crash(
        self, repo: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = _write(repo / ".claude" / "settings.local.json", {})
        raw = {"permissions": {"defaultMode": "bypassPermissions"}}
        config = _config(path, raw)
        result = _run_static_pipeline(
            ScanResult(), [], [config], get_default_analyzers(), skip_rug_pull=True
        )
        ids = {f.id for f in result.findings}
        assert {"SANDBOX-005", "HARNESS-001"} <= ids

        def explode(*_a: object, **_k: object) -> None:
            raise RuntimeError(f"bad {path}")

        monkeypatch.setattr("mcp_audit.scanner.analyze_settings_git_exposure", explode)
        result = _run_static_pipeline(
            ScanResult(), [], [config], get_default_analyzers(), skip_rug_pull=True
        )
        assert "sandbox error: RuntimeError" in result.errors
        assert "HARNESS-001" in {f.id for f in result.findings}
        assert not any(str(path) in e for e in result.errors)

    def test_step_runs_only_with_config_hygiene(self, repo: Path) -> None:
        path = _write(repo / ".claude" / "settings.local.json", {})
        result = _run_static_pipeline(
            ScanResult(), [], [_config(path)], [], skip_rug_pull=True
        )
        assert "SANDBOX-005" not in {f.id for f in result.findings}


class TestUsernamePaths:
    @pytest.mark.parametrize(
        ("value", "user"),
        [
            ("Read(//Users/alice/projects/**)", "alice"),
            ("Bash(/home/bob/bin/tool *)", "bob"),
            ("C:\\Users\\carol\\work", "carol"),
            ("C:/Users/dave/x", "dave"),
            ("/c/Users/erin/x", "erin"),
            ("file:///Users/frank/notes.txt", "frank"),
            ('cat "/home/gina/.npmrc"', "gina"),
            ("/Users/hal", "hal"),
        ],
    )
    def test_person_paths_are_found(self, value: str, user: str) -> None:
        found = sb.username_paths({"permissions": {"allow": [value]}})
        assert [u for _w, _p, u in found] == [user]
        assert found[0][0] == "permissions.allow[0]"

    @pytest.mark.parametrize(
        "value",
        [
            "/Users/you/x",
            "/home/runner/work/x",
            "/home/codespace/x",
            "C:\\Users\\Public\\x",
            "/Users/Shared/x",
            "/Users/$USER/x",
            "/home/${USER}/x",
            "C:\\Users\\%USERNAME%\\x",
            "/Users/<name>/x",
            "/Users/*/x",
            "/opt/home/x",
            "~/projects",
            "/Users/",
            "./home/x",
        ],
    )
    def test_placeholders_and_non_home_paths_are_skipped(self, value: str) -> None:
        assert sb.username_paths({"env": {"X": value}}) == []

    def test_keys_and_nested_values_are_searched(self) -> None:
        raw = {
            "sandbox": {
                "filesystem": {"allowWrite": ["/Users/ann/.kube"]},
                "ignoreViolations": {"/home/ben/bin/x": ["/etc/hosts"]},
            }
        }
        users = sorted(u for _w, _p, u in sb.username_paths(raw))
        assert users == ["ann", "ben"]

    def test_secrets_next_to_a_path_are_masked(self) -> None:
        raw = {"permissions": {"allow": [f"Bash(/home/ann/{TOKEN} *)"]}}
        (_where, path, _user) = sb.username_paths(raw)[0]
        assert TOKEN not in path

    def test_pathological_input_is_fast(self) -> None:
        start = time.perf_counter()
        raw = {"a": ["/" * 200_000, "/home/" * 20_000, "C:" + "\\" * 100_000]}
        sb.username_paths(raw)
        assert time.perf_counter() - start < 5

    def test_string_budget_is_reported(self, repo: Path) -> None:
        path = _write(repo / ".claude" / "settings.json", {})
        raw = {"env": {f"K{i}": "x" for i in range(sb._MAX_STRINGS)}}
        raw["z"] = "/Users/zed/x"
        findings, errors = _exposure(_config(path, raw))
        assert errors == [
            "SANDBOX-005 skipped: 'repo/.claude/settings.json' was searched for"
            " home-directory paths only up to 20000 strings, 16 KiB per string and"
            " depth 64"
        ]
        assert str(repo) not in errors[0]

    def test_huge_lists_are_walked_without_copying(self) -> None:
        start = time.perf_counter()
        budget = sb._Budget()
        found = sb._username_paths({"a": list(range(2_000_000))}, budget)
        assert found == [] and budget.truncated
        assert time.perf_counter() - start < 5

    def test_deep_nesting_is_bounded(self) -> None:
        raw: object = "/Users/deep/x"
        for _ in range(500):
            raw = [raw]
        budget = sb._Budget()
        assert sb._username_paths(raw, budget) == []
        assert budget.truncated

    def test_low_finding_for_committed_settings(self, repo: Path) -> None:
        path = _write(repo / ".claude" / "settings.json", {})
        raw = {"permissions": {"allow": ["Read(//Users/alice/x/**)"]}}
        findings, _ = _exposure(_config(path, raw))
        assert _ids(findings) == [("SANDBOX-005", Severity.LOW)]
        assert "(alice)" in findings[0].description
        assert "permissions.allow[0]: '//Users/alice/x/**'" in findings[0].evidence
        (repo / ".gitignore").write_text(".claude/settings.json\n")
        assert _exposure(_config(path, raw)) == ([], [])

    def test_local_file_gets_both(self, repo: Path) -> None:
        path = _write(repo / ".claude" / "settings.local.json", {})
        raw = {"permissions": {"allow": ["Read(//Users/alice/x/**)"]}}
        findings, _ = _exposure(_config(path, raw))
        assert _ids(findings) == [
            ("SANDBOX-005", Severity.MEDIUM),
            ("SANDBOX-005", Severity.LOW),
        ]


# ── CLI end to end ────────────────────────────────────────────────────────────


def _json_out(output: str) -> dict:
    return json.loads(output[output.index("{") :])


class TestCli:
    def _repo(self, root: Path) -> None:
        (root / ".git").mkdir(parents=True)
        _write(
            root / ".claude" / "settings.json",
            _box(
                enableWeakerNestedSandbox=True,
                excludedCommands=["docker *", f"npx --registry=https://u:{TOKEN}@r *"],
                network={"allowedDomains": ["github.com"]},
                allowAppleEvents=True,
            ),
        )
        _write(
            root / ".claude" / "settings.local.json",
            {"permissions": {"allow": [f"Bash(/home/ann/{TOKEN}/x *)"]}},
        )

    def test_default_scan_from_the_checkout(
        self, tmp_path: Path, home: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        repo = tmp_path / "repo"
        self._repo(repo)
        monkeypatch.chdir(repo)
        with patch("mcp_audit.discovery._get_client_specs", return_value=[]):
            result = runner.invoke(app, ["scan", "--format", "json"])
        found = {(f["id"], f["severity"]) for f in _json_out(result.output)["findings"]}
        assert {
            ("SANDBOX-001", "HIGH"),
            ("SANDBOX-002", "HIGH"),
            ("SANDBOX-003", "MEDIUM"),
            ("SANDBOX-004", "INFO"),
            ("SANDBOX-005", "MEDIUM"),
            ("SANDBOX-005", "LOW"),
        } <= found
        assert result.exit_code == 1

    def test_scan_project_and_check(
        self, tmp_path: Path, home: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        repo = tmp_path / "repo"
        self._repo(repo)
        monkeypatch.chdir(tmp_path)
        with patch("mcp_audit.discovery._get_client_specs", return_value=[]):
            result = runner.invoke(
                app, ["scan", "--project", str(repo), "--format", "json"]
            )
            ids = {f["id"] for f in _json_out(result.output)["findings"]}
            assert {"SANDBOX-001", "SANDBOX-002", "SANDBOX-005"} <= ids
            monkeypatch.chdir(repo)
            checked = runner.invoke(app, ["check", "--json"])
        assert checked.exit_code == 1
        ids = {f["id"] for f in _json_out(checked.output)["findings"]}
        assert {"SANDBOX-001", "SANDBOX-002", "SANDBOX-005"} <= ids

    @pytest.mark.parametrize("fmt", ["terminal", "json", "sarif"])
    def test_secrets_never_reach_output(
        self, fmt: str, tmp_path: Path, home: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        repo = tmp_path / "repo"
        self._repo(repo)
        monkeypatch.chdir(repo)
        with patch("mcp_audit.discovery._get_client_specs", return_value=[]):
            result = runner.invoke(
                app, ["scan", "--format", fmt], env={"COLUMNS": "400"}
            )
        shown = "Repository settings" if fmt == "terminal" else "SANDBOX-002"
        assert shown in result.output
        assert "--registry=https://***@r" in result.output or fmt == "terminal"
        assert TOKEN not in result.output

    def test_unreadable_gitignore_under_an_explicit_path_is_not_exit_2(
        self, tmp_path: Path, home: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        repo = tmp_path / "repo"
        (repo / ".git").mkdir(parents=True)
        path = _write(repo / ".claude" / "settings.local.json", {})
        (repo / ".gitignore").write_text("x\n")
        real_open = Path.open

        def deny(self: Path, *args: object, **kwargs: object):  # noqa: ANN202
            if self.name == ".gitignore":
                raise PermissionError(13, "Permission denied")
            return real_open(self, *args, **kwargs)

        monkeypatch.setattr(Path, "open", deny)
        result = runner.invoke(app, ["scan", "--path", str(path), "--format", "json"])
        assert result.exit_code != 2, result.output
        out = _json_out(result.output)
        assert any("SANDBOX-005 skipped" in e for e in out["errors"])

    def test_project_pipeline_errors_reach_the_output(
        self, tmp_path: Path, home: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        repo = tmp_path / "repo"
        (repo / ".git").mkdir(parents=True)
        _write(repo / ".claude" / "settings.local.json", {})
        (repo / ".gitignore").write_text("x\n")
        real_open = Path.open

        def deny(self: Path, *args: object, **kwargs: object):  # noqa: ANN202
            if self.name == ".gitignore":
                raise PermissionError(13, "Permission denied")
            return real_open(self, *args, **kwargs)

        monkeypatch.setattr(Path, "open", deny)
        monkeypatch.chdir(tmp_path)
        with patch("mcp_audit.discovery._get_client_specs", return_value=[]):
            result = runner.invoke(
                app, ["scan", "--project", str(repo), "--format", "json"]
            )
        errors = _json_out(result.output)["errors"]
        assert (
            errors.count(
                "SANDBOX-005 skipped: could not read repo/.gitignore: Permission denied"
            )
            == 1
        )


class TestDemoConfigs:
    def test_demo_configs_produce_no_sandbox_findings(self, home: Path) -> None:
        demo = Path(__file__).resolve().parents[1] / "demo" / "configs"
        result = runner.invoke(app, ["scan", "--path", str(demo), "--format", "json"])
        ids = {f["id"] for f in _json_out(result.output)["findings"]}
        assert not {i for i in ids if i.startswith("SANDBOX-")}


class TestReporting:
    @pytest.mark.parametrize("n", range(1, 6))
    def test_check_has_a_specific_hint(self, n: int) -> None:
        from mcp_audit.output.check import _HINTS, _remediation_hint  # noqa: PLC0415

        fid = f"SANDBOX-00{n}"
        finding = Finding(
            id=fid,
            severity=Severity.MEDIUM,
            analyzer="config_hygiene",
            client="claude-code",
            server="(config-level)",
            title="t",
            description="d",
            evidence="e",
            remediation="r",
        )
        assert _remediation_hint(finding) == _HINTS[fid]

    def test_advisory_classes(self) -> None:
        from mcp_audit.advisory.classify import (  # noqa: PLC0415
            finding_class_for,
            is_advisable,
        )

        assert finding_class_for("SANDBOX-001") == "sandbox-disabled"
        assert finding_class_for("SANDBOX-003") == "sandbox-disabled"
        assert finding_class_for("SANDBOX-005") == "config-hygiene"
        assert is_advisable("SANDBOX-002")
        assert not is_advisable("SANDBOX-004")
