"""Tests for analyzers/sandbox.py: SANDBOX-001..005 (STORY-0093).

SANDBOX-001..004 are exercised through ``analyze_sandbox_settings`` with an
explicit origin, and all five through ``analyze_sandbox_files`` (pipeline step
0b), the scanner and the CLI.  Each check has firing cases from Anthropic's
documentation, near misses that must stay silent, and the scope rules (which
file Claude Code reads a key from, and when a local file is the repository's)
it rests on.
"""

from __future__ import annotations

import json
import os
import re
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


LOCAL_IN_GIT = sb.ORIGIN_LOCAL_TRACKED


def _sandbox(
    raw: object,
    path: Path,
    origin: str | None = None,
    user: sb.UserSettingsLocks | None = None,
) -> list[Finding]:
    context = None
    if origin is not None or user is not None:
        context = sb.SandboxContext(
            origin or sb.ORIGIN_PROJECT, user or sb.UserSettingsLocks()
        )
    return sb.analyze_sandbox_settings(raw, path, "claude-code", context=context)


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
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
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
        path, origin = (project, None) if which == "project" else (local, LOCAL_IN_GIT)
        out = _sandbox({"sandbox": block}, path, origin)
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
        assert "even when your user settings" in out[0].description
        # Names both places Claude Code reads user settings from (STORY-0104).
        assert "$CLAUDE_CONFIG_DIR/settings.json" in out[0].description
        # Claude Code's /sandbox panel writes `enabled` to the local file.
        assert _sandbox(_box(enabled=False), local, LOCAL_IN_GIT) == []
        assert _sandbox(_box(enabled=True), project) == []

    def test_fail_if_unavailable_false_is_medium_in_project_only(
        self, project: Path, local: Path
    ) -> None:
        assert _ids(_sandbox(_box(failIfUnavailable=False), project)) == [
            ("SANDBOX-001", Severity.MEDIUM)
        ]
        assert _sandbox(_box(failIfUnavailable=False), local, LOCAL_IN_GIT) == []
        assert _sandbox(_box(failIfUnavailable=True), project) == []

    @pytest.mark.parametrize("key", ["httpProxyPort", "socksProxyPort"])
    def test_proxy_port_is_medium(self, key: str, project: Path) -> None:
        out = _sandbox(_box(network={key: 8080}), project)
        assert _ids(out) == [("SANDBOX-001", Severity.MEDIUM)]
        text = out[0].description
        assert "stops applying its domain lists" in text
        assert "Locks that apply without an admin-required sandbox" in text
        assert "network.deniedDomains" in text

    @pytest.mark.parametrize("key", ["httpProxyPort", "socksProxyPort"])
    def test_proxy_port_is_info_under_the_users_strict_allowlist(
        self, key: str, project: Path
    ) -> None:
        locks = sb.UserSettingsLocks(strict_allowlist=True)
        raw = _box(enableWeakerNestedSandbox=True, network={key: 8080})
        out = _sandbox(raw, project, user=locks)
        assert _ids(out) == [
            ("SANDBOX-001", Severity.HIGH),
            ("SANDBOX-001", Severity.INFO),
        ]
        assert "network.strictAllowlist: true" in out[1].description
        assert "ignores this repository entry" in out[1].description
        # strictAllowlist does not lock the weakening booleans.
        assert "enableWeakerNestedSandbox" in out[0].evidence

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

    def test_admin_required_note_is_not_attached_to_strict_allowlist_locks(
        self, project: Path
    ) -> None:
        out = _sandbox(_box(enableWeakerNestedSandbox=True), project)
        assert "admin-required" in out[0].description
        assert "strictAllowlist" not in out[0].description

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
            # wrappers that run whatever follows them
            "env *",
            "env -i *",
            "env FOO=1 *",
            "timeout 30 *",
            "timeout 5m *",
            "timeout *",
            "time *",
            "nohup *",
            "nice *",
            "nice -n 10 *",
            "stdbuf -oL *",
            "command *",
            "builtin *",
            "noglob *",
            "watch *",
            "setsid *",
            "ionice -c 3 *",
            "flock /tmp/lock *",
            "/usr/bin/env *",
        ],
    )
    def test_code_running_exclusions_are_medium_while_a_prompt_guards_them(
        self, entry: str, project: Path
    ) -> None:
        out = _sandbox(_box(excludedCommands=[entry]), project)
        assert _ids(out) == [("SANDBOX-002", Severity.MEDIUM)]
        text = out[0].description
        assert "An excluded command runs with your full access" in text
        assert "prompt still guards it" in text
        assert "Bash command (unsandboxed)" in text

    @pytest.mark.parametrize(
        ("allow", "entry"),
        [
            ("Bash(docker *)", "docker compose *"),
            ("Bash(docker compose up)", "docker compose *"),
            ("Bash(docker:*)", "docker *"),
            ("Bash(python scripts/x.py)", "python *"),
            ("Bash(timeout 30 make)", "timeout 30 *"),
            ("Bash", "bash *"),
            ("Bash(*)", "node *"),
            ("Bash(* --help)", "npx *"),
            ("Bash(npm test)", "*"),
            ("Bash(docker * up)", "docker compose *"),
        ],
    )
    def test_an_allow_rule_in_the_same_file_makes_it_high(
        self, allow: str, entry: str, project: Path
    ) -> None:
        raw = {"permissions": {"allow": [allow]}, **_box(excludedCommands=[entry])}
        out = _sandbox(raw, project)
        assert _ids(out) == [("SANDBOX-002", Severity.HIGH)]
        assert f"allow {allow!r} in this file approves it" in out[0].description

    @pytest.mark.parametrize(
        ("allow", "entry"),
        [
            ("Bash(npm test *)", "python *"),
            ("Bash(docker ps)", "docker compose *"),
            ("Bash(docker)", "docker compose *"),
            ("Bash(dock* compose up)", "docker compose *"),
            ("Read(./src/**)", "bash *"),
            ("WebFetch(domain:example.com)", "npx *"),
        ],
    )
    def test_an_unrelated_allow_rule_leaves_it_medium(
        self, allow: str, entry: str, project: Path
    ) -> None:
        raw = {"permissions": {"allow": [allow]}, **_box(excludedCommands=[entry])}
        assert _ids(_sandbox(raw, project)) == [("SANDBOX-002", Severity.MEDIUM)]

    @pytest.mark.parametrize(
        ("mode", "severity", "text"),
        [
            ("bypassPermissions", Severity.HIGH, "bypassPermissions mode"),
            ("auto", Severity.HIGH, "the classifier, not you"),
            ("dontAsk", Severity.MEDIUM, "prompt still guards it"),
            ("acceptEdits", Severity.MEDIUM, "prompt still guards it"),
            (None, Severity.MEDIUM, "prompt still guards it"),
        ],
    )
    def test_the_users_default_mode_decides_whether_anything_prompts(
        self, mode: str | None, severity: Severity, text: str, project: Path
    ) -> None:
        locks = sb.UserSettingsLocks(default_mode=mode)
        out = _sandbox(_box(excludedCommands=["python *"]), project, user=locks)
        assert _ids(out) == [("SANDBOX-002", severity)]
        assert text in out[0].description

    @pytest.mark.parametrize("mode", ["bypassPermissions", "auto"])
    def test_a_repository_default_mode_does_not_raise_it(
        self, mode: str, project: Path
    ) -> None:
        # Settings reference: "auto and bypassPermissions don't take effect from
        # project or local settings".
        raw = {
            "permissions": {"defaultMode": mode},
            **_box(excludedCommands=["python *"]),
        }
        assert _ids(_sandbox(raw, project)) == [("SANDBOX-002", Severity.MEDIUM)]

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
            "xargs *",  # ... and with xargs
            "eval *",
            "command -v *",  # the query form looks a command up
            "timeout 30 npm test *",
            "env FOO=1 npm test *",
            "nice make *",
            "flock /tmp/lock make *",
            "nohup",  # exact match, no arguments
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

    def test_entries_are_grouped_by_severity(self, project: Path) -> None:
        raw = _box(
            excludedCommands=["docker *", "bash *", "npm ci"],
            network={"allowUnixSockets": ["/var/run/docker.sock"]},
        )
        out = _sandbox(raw, project)
        assert _ids(out) == [
            ("SANDBOX-002", Severity.HIGH),
            ("SANDBOX-002", Severity.MEDIUM),
        ]
        assert out[0].evidence.count("contains") == 1
        assert out[1].evidence.count("contains") == 2


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

    def test_notes_name_the_locks_that_apply_without_admin_required(
        self, project: Path
    ) -> None:
        out = _sandbox(_box(network={"allowedDomains": ["github.com"]}), project)
        text = out[0].description
        assert "Locks that apply without an admin-required sandbox" in text
        assert "network.strictAllowlist" in text
        assert "admin-required" in text

    def test_info_under_the_users_strict_allowlist(self, project: Path) -> None:
        locks = sb.UserSettingsLocks(strict_allowlist=True)
        raw = _box(network={"allowedDomains": ["github.com", "pastebin.com"]})
        out = _sandbox(raw, project, user=locks)
        assert _ids(out) == [("SANDBOX-003", Severity.INFO)]
        assert "network.strictAllowlist: true" in out[0].description
        assert out[0].evidence.count("contains") == 2

    def test_remediation_example_hosts_are_not_flagged(self) -> None:
        hosts = re.findall(
            r"[a-z0-9.-]+\.(?:org|com|io|net)", sb._SANDBOX_003.remediation
        )
        assert hosts
        assert [h for h in hosts if sb.content_host(h)] == []


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
        for origin in (None, LOCAL_IN_GIT, sb.ORIGIN_OWN):
            out = _sandbox({"sandbox": block}, path, origin)
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
        origin = LOCAL_IN_GIT if which == "local" else None
        for finding in _sandbox(raw, path, origin):
            assert finding.severity == Severity.INFO, finding.id

    def test_analyze_config_no_longer_runs_sandbox_checks(self, project: Path) -> None:
        raw = _box(enableWeakerNestedSandbox=True, excludedCommands=["bash *"])
        out = ConfigHygieneAnalyzer().analyze_config(raw, project, "claude-code")
        assert not [f for f in out if f.id.startswith("SANDBOX-")]

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
            ("SANDBOX-002", Severity.MEDIUM),
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
    return sb.analyze_sandbox_files(configs)


UNKNOWN_SUMMARY = (
    "SANDBOX checks: git state unknown for 1 settings file(s): no SANDBOX-005"
    " for them, and SANDBOX-001..003 on a local file at MEDIUM at most"
)
LOUD = {
    "permissions": {"allow": ["Bash(python *)"]},
    "sandbox": {
        "enableWeakerNestedSandbox": True,
        "excludedCommands": ["python *"],
        "network": {"allowedDomains": ["github.com"]},
    },
}


class TestLocalFileOrigin:
    """A local settings file is the repository's only when git carries it."""

    def test_ignored_local_file_reports_nothing_medium_or_above(
        self, repo: Path
    ) -> None:
        (repo / ".gitignore").write_text(".claude/settings.local.json\n")
        path = _write(repo / ".claude" / "settings.local.json", LOUD)
        findings, errors = _exposure(_config(path, LOUD))
        assert findings == [] and errors == []

    def test_globally_ignored_local_file_is_the_users_own(
        self, repo: Path, home: Path
    ) -> None:
        # Claude Code writes this line to the global excludes file itself.
        (home / ".config" / "git").mkdir(parents=True)
        (home / ".config" / "git" / "ignore").write_text(
            "**/.claude/settings.local.json\n"
        )
        path = _write(repo / ".claude" / "settings.local.json", LOUD)
        assert _exposure(_config(path, LOUD)) == ([], [])

    def test_unignored_local_file_is_the_repositorys(self, repo: Path) -> None:
        path = _write(repo / ".claude" / "settings.local.json", LOUD)
        findings, errors = _exposure(_config(path, LOUD))
        assert _ids(findings) == [
            ("SANDBOX-001", Severity.HIGH),
            ("SANDBOX-002", Severity.HIGH),
            ("SANDBOX-003", Severity.MEDIUM),
            ("SANDBOX-005", Severity.MEDIUM),
        ]
        assert errors == []
        assert "no ignore file covers" in findings[0].description
        assert "treats it as repository-supplied" in findings[0].description

    @pytest.mark.skipif(os.name == "nt", reason="POSIX symlinks")
    def test_symlinked_claude_directory_is_the_repositorys(
        self, tmp_path: Path, home: Path
    ) -> None:
        root = tmp_path / "repo2"
        (root / ".git").mkdir(parents=True)
        (root / ".gitignore").write_text(".claude/\n")  # ignored, yet linked
        real = tmp_path / "outside" / ".claude"
        _write(real / "settings.local.json", LOUD)
        (root / ".claude").symlink_to(real, target_is_directory=True)
        findings, errors = _exposure(
            _config(root / ".claude" / "settings.local.json", LOUD)
        )
        assert ("SANDBOX-001", Severity.HIGH) in _ids(findings)
        assert "SANDBOX-005" not in {f.id for f in findings}
        assert "a symlink" in findings[0].description
        assert errors == []

    def test_unknown_git_state_is_reported_at_medium(
        self, repo: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = _write(repo / ".claude" / "settings.local.json", LOUD)
        (repo / ".gitignore").write_text("x\n")
        real_open = Path.open

        def deny(self: Path, *args: object, **kwargs: object):  # noqa: ANN202
            if self.name == ".gitignore":
                raise PermissionError(13, "Permission denied")
            return real_open(self, *args, **kwargs)

        monkeypatch.setattr(Path, "open", deny)
        findings, errors = _exposure(_config(path, LOUD))
        assert _ids(findings) == [
            ("SANDBOX-001", Severity.MEDIUM),
            ("SANDBOX-002", Severity.MEDIUM),
            ("SANDBOX-003", Severity.MEDIUM),
        ]
        assert "could not read (see the scan's errors)" in findings[0].description
        assert "MEDIUM at most because that is unknown" in findings[0].description
        assert errors == [
            "SANDBOX checks: could not read repo/.gitignore: Permission denied",
            UNKNOWN_SUMMARY,
        ]

    def test_local_file_outside_a_work_tree_is_the_users_own(
        self, tmp_path: Path, home: Path
    ) -> None:
        path = _write(tmp_path / "plain" / ".claude" / "settings.local.json", LOUD)
        if sb.find_work_tree_root(path.parent.parent) is not None:
            pytest.skip("the test directory itself sits in a git work tree")
        assert _exposure(_config(path, LOUD)) == ([], [])

    def test_shared_project_file_is_the_repositorys_even_if_ignored(
        self, repo: Path
    ) -> None:
        (repo / ".gitignore").write_text(".claude/\n")
        path = _write(repo / ".claude" / "settings.json", LOUD)
        findings, _ = _exposure(_config(path, LOUD))
        assert ("SANDBOX-001", Severity.HIGH) in _ids(findings)


class TestUserSettingsLocks:
    def _user_file(self, home: Path, data: object) -> Path:
        return _write(home / ".claude" / "settings.json", data)

    def test_strict_allowlist_in_user_settings_downgrades_hosts_and_ports(
        self, repo: Path, home: Path
    ) -> None:
        self._user_file(home, {"sandbox": {"network": {"strictAllowlist": True}}})
        raw = _box(network={"allowedDomains": ["github.com"], "httpProxyPort": 8080})
        path = _write(repo / ".claude" / "settings.json", raw)
        findings, errors = _exposure(_config(path, raw))
        assert _ids(findings) == [
            ("SANDBOX-001", Severity.INFO),
            ("SANDBOX-003", Severity.INFO),
        ]
        assert errors == []
        for finding in findings:
            assert "network.strictAllowlist: true" in finding.description

    def test_strict_allowlist_must_be_a_json_true(self, repo: Path, home: Path) -> None:
        self._user_file(home, {"sandbox": {"network": {"strictAllowlist": "true"}}})
        raw = _box(network={"allowedDomains": ["github.com"]})
        path = _write(repo / ".claude" / "settings.json", raw)
        assert _ids(_exposure(_config(path, raw))[0]) == [
            ("SANDBOX-003", Severity.MEDIUM)
        ]

    def test_user_default_mode_bypass_makes_exclusions_high(
        self, repo: Path, home: Path
    ) -> None:
        self._user_file(home, {"permissions": {"defaultMode": "bypassPermissions"}})
        raw = _box(excludedCommands=["bash *"])
        path = _write(repo / ".claude" / "settings.json", raw)
        assert _ids(_exposure(_config(path, raw))[0]) == [
            ("SANDBOX-002", Severity.HIGH)
        ]

    def test_claude_config_dir_is_honoured(
        self, repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        conf = tmp_path / "conf"
        _write(
            conf / "settings.json", {"sandbox": {"network": {"strictAllowlist": True}}}
        )
        monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(conf))
        raw = _box(network={"allowedDomains": ["github.com"]})
        path = _write(repo / ".claude" / "settings.json", raw)
        assert _ids(_exposure(_config(path, raw))[0]) == [
            ("SANDBOX-003", Severity.INFO)
        ]

    @pytest.mark.parametrize("inside_home", [True, False])
    def test_notes_name_the_claude_config_dir_file(
        self,
        inside_home: bool,
        repo: Path,
        home: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """With CLAUDE_CONFIG_DIR set, the notes name that file, not
        ~/.claude/settings.json, and never its absolute path (STORY-0103)."""
        conf = (home / ".config" / "claude") if inside_home else tmp_path / "conf"
        _write(
            conf / "settings.json",
            {
                "sandbox": {"network": {"strictAllowlist": True}},
                "permissions": {"defaultMode": "bypassPermissions"},
            },
        )
        monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(conf))
        raw = _box(
            network={"allowedDomains": ["github.com"], "httpProxyPort": 8080},
            excludedCommands=["bash *"],
        )
        path = _write(repo / ".claude" / "settings.json", raw)
        findings, errors = _exposure(_config(path, raw))
        assert errors == []
        label = (
            "~/.config/claude/settings.json"
            if inside_home
            else "$CLAUDE_CONFIG_DIR/settings.json"
        )
        texts = [f.description for f in findings]
        assert (
            sum(f"your {label} sets network.strictAllowlist" in t for t in texts) == 2
        )
        assert any(
            f"your {label} starts sessions in bypassPermissions" in t for t in texts
        )
        for text in texts:
            assert "your ~/.claude/settings.json" not in text
            assert str(conf) not in text

    def test_default_location_keeps_its_name(self, repo: Path, home: Path) -> None:
        self._user_file(home, {"permissions": {"defaultMode": "auto"}})
        raw = _box(excludedCommands=["bash *"])
        path = _write(repo / ".claude" / "settings.json", raw)
        [finding] = _exposure(_config(path, raw))[0]
        assert "your ~/.claude/settings.json starts sessions in auto mode" in (
            finding.description
        )

    def test_unreadable_claude_config_dir_file_error_names_it(
        self,
        repo: Path,
        home: Path,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        conf = tmp_path / "conf"
        user_file = _write(conf / "settings.json", {})
        monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(conf))
        real_open = Path.open

        def deny(self: Path, *args: object, **kwargs: object):  # noqa: ANN202
            if self == user_file:
                raise PermissionError(13, "Permission denied")
            return real_open(self, *args, **kwargs)

        monkeypatch.setattr(Path, "open", deny)
        path = _write(repo / ".claude" / "settings.json", {})
        _findings, errors = _exposure(_config(path, {}))
        assert errors == [
            "SANDBOX checks: could not read $CLAUDE_CONFIG_DIR/settings.json:"
            " Permission denied; SANDBOX-002/003 severities assume it sets nothing"
        ]

    @pytest.mark.parametrize("content", [b"{not json", b"[]", b"\xff\xfe"])
    def test_broken_user_settings_lock_nothing_and_are_not_errors(
        self, content: bytes, repo: Path, home: Path
    ) -> None:
        (home / ".claude").mkdir()
        (home / ".claude" / "settings.json").write_bytes(content)
        raw = _box(network={"allowedDomains": ["github.com"]})
        path = _write(repo / ".claude" / "settings.json", raw)
        findings, errors = _exposure(_config(path, raw))
        assert _ids(findings) == [("SANDBOX-003", Severity.MEDIUM)]
        assert errors == []

    def test_unreadable_user_settings_are_an_error(
        self, repo: Path, home: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        user_file = self._user_file(home, {})
        real_open = Path.open

        def deny(self: Path, *args: object, **kwargs: object):  # noqa: ANN202
            if self == user_file:
                raise PermissionError(13, "Permission denied")
            return real_open(self, *args, **kwargs)

        monkeypatch.setattr(Path, "open", deny)
        path = _write(repo / ".claude" / "settings.json", {})
        _findings, errors = _exposure(_config(path, {}))
        assert errors == [
            "SANDBOX checks: could not read ~/.claude/settings.json: Permission"
            " denied; SANDBOX-002/003 severities assume it sets nothing"
        ]

    def test_oversized_user_settings_are_not_read(
        self, repo: Path, home: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(sb, "_USER_SETTINGS_MAX_BYTES", 10)
        self._user_file(home, {"sandbox": {"network": {"strictAllowlist": True}}})
        _findings, errors = _exposure()
        assert errors and "larger than 4 MiB" in errors[0]


class TestCrashIsolation:
    def test_a_crash_on_one_file_keeps_the_others(
        self, repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        raw = _box(enableWeakerNestedSandbox=True)
        bad = _write(repo / "bad" / ".claude" / "settings.json", raw)
        good = _write(repo / ".claude" / "settings.json", raw)
        real = sb.analyze_sandbox_settings

        def flaky(raw_: object, path: Path, *args: object, **kwargs: object):  # noqa: ANN202
            if "bad" in path.parts:
                raise RuntimeError(f"boom {path}")
            return real(raw_, path, *args, **kwargs)

        monkeypatch.setattr(sb, "analyze_sandbox_settings", flaky)
        findings, errors = _exposure(_config(bad, raw), _config(good, raw))
        assert [f.finding_path for f in findings] == [str(good)]
        assert errors == [
            "SANDBOX checks: failed for '.claude/settings.json': RuntimeError"
        ]
        assert str(repo) not in errors[0]

    def test_pipeline_keeps_every_other_check_when_sandbox_crashes(
        self, repo: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        raw = {
            "permissions": {"defaultMode": "bypassPermissions", "allow": ["Bash"]},
            **_box(enableWeakerNestedSandbox=True),
        }
        path = _write(repo / ".claude" / "settings.json", raw)

        def explode(*_a: object, **_k: object) -> None:
            raise RuntimeError("check crashed")

        monkeypatch.setattr(sb, "_check_sandbox_001", explode)
        result = _run_static_pipeline(
            ScanResult(),
            [],
            [_config(path, raw)],
            get_default_analyzers(),
            skip_rug_pull=True,
        )
        ids = {f.id for f in result.findings}
        assert "HARNESS-001" in ids and not {i for i in ids if i.startswith("SANDBOX")}
        assert result.errors == [
            "SANDBOX checks: failed for '.claude/settings.json': RuntimeError"
        ]


class TestManySettingsFiles:
    def test_long_ignore_lines_and_many_files_stay_fast(self, repo: Path) -> None:
        line = "/" + "/".join(["a"] * 2000)
        lines = (1024 * 1024) // (len(line) + 1)
        (repo / ".gitignore").write_text("\n".join([line] * lines) + "\n")
        assert (repo / ".gitignore").stat().st_size <= 1024 * 1024
        configs = [
            _config(_write(repo / f"p{i}" / ".claude" / "settings.local.json", {}))
            for i in range(300)
        ]
        start = time.perf_counter()
        findings, errors = _exposure(*configs)
        assert time.perf_counter() - start < 10
        assert errors == []
        assert len(findings) == 300
        assert {f.id for f in findings} == {"SANDBOX-005"}

    def test_matching_budget_is_shared_and_reported(
        self, repo: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            sb, "IgnoreFileReader", lambda home=None: _small_budget_reader(home)
        )
        (repo / ".gitignore").write_text("\n".join(f"x{i}*" for i in range(200)))
        configs = [
            _config(
                _write(repo / f"p{i}" / ".claude" / "settings.local.json", LOUD), LOUD
            )
            for i in range(3)
        ]
        start = time.perf_counter()
        findings, errors = _exposure(*configs)
        assert time.perf_counter() - start < 5
        assert "SANDBOX-005" not in {f.id for f in findings}
        assert max(f.severity for f in findings) == Severity.MEDIUM
        assert errors[0].startswith(
            "SANDBOX checks: ignore-pattern matching budget reached"
        )
        assert errors[-1].startswith("SANDBOX checks: git state unknown for 3")


def _small_budget_reader(home: Path | None) -> object:
    from mcp_audit import _gitignore as gi  # noqa: PLC0415

    return gi.IgnoreFileReader(home=home, _meter=gi.MatchMeter(limit=100))


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
            "SANDBOX checks: could not read repo/.gitignore: Permission denied",
            UNKNOWN_SUMMARY,
        ]
        assert str(repo) not in " ".join(errors)  # never an absolute path (exit 2)

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

        monkeypatch.setattr("mcp_audit.scanner.analyze_sandbox_files", explode)
        result = _run_static_pipeline(
            ScanResult(), [], [config], get_default_analyzers(), skip_rug_pull=True
        )
        assert "SANDBOX checks failed: RuntimeError" in result.errors
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
            "/home/linuxbrew/.linuxbrew/bin/brew",  # Homebrew on Linux
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

    def test_a_secret_in_the_username_position_is_masked(self) -> None:
        raw = {"permissions": {"allow": [f"Bash(cat /home/{TOKEN}/notes.txt)"]}}
        [(_where, path, user)] = sb.username_paths(raw)
        assert user == "***"
        assert path == "/home/***/notes.txt"

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
            "SANDBOX checks: 'repo/.claude/settings.json' was searched for"
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
            {
                "permissions": {"allow": ["Bash(docker *)"]},
                **_box(
                    enableWeakerNestedSandbox=True,
                    excludedCommands=[
                        "docker *",
                        f"npx --registry=https://u:{TOKEN}@r *",
                    ],
                    network={"allowedDomains": ["github.com"]},
                    allowAppleEvents=True,
                ),
            },
        )
        _write(
            root / ".claude" / "settings.local.json",
            {
                "permissions": {
                    "allow": [
                        f"Bash(/home/ann/{TOKEN}/x *)",
                        f"Bash(cat /home/{TOKEN}/notes.txt)",
                    ]
                }
            },
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
            ("SANDBOX-002", "MEDIUM"),
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
        assert "SANDBOX-005" in result.output or fmt == "terminal"
        assert "home directory (***, ann)" in result.output or fmt == "terminal"
        assert TOKEN not in result.output
        assert TOKEN[:12] not in result.output

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
        assert any("SANDBOX checks: could not read" in e for e in out["errors"])

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
                "SANDBOX checks: could not read repo/.gitignore: Permission denied"
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
