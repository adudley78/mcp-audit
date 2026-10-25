"""Tests for analyzers/permissions.py: PERM-001..007 (STORY-0092).

Every check is exercised through the path a scan uses
(``ConfigHygieneAnalyzer.analyze_config`` for PERM-001..006, the scanner's
step 5b and the CLI for PERM-007), plus the public parsing helpers the sandbox
checks reuse.  Each check has firing cases, near misses that must stay silent,
and the documented Claude Code behaviour it rests on.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from mcp_audit.analyzers import permissions as perms
from mcp_audit.analyzers.config_hygiene import (
    ConfigHygieneAnalyzer,
    _is_broad_allow_rule,
)
from mcp_audit.cli import app
from mcp_audit.discovery import DiscoveredConfig
from mcp_audit.models import Finding, ScanResult, ServerConfig, Severity
from mcp_audit.scanner import _run_static_pipeline, get_default_analyzers

runner = CliRunner()


# ── Helpers ───────────────────────────────────────────────────────────────────


def _perm(raw: object, path: Path) -> list[Finding]:
    findings = ConfigHygieneAnalyzer().analyze_config(raw, path, "claude-code")
    return [f for f in findings if f.id.startswith("PERM-")]


def _ids(findings: list[Finding]) -> list[tuple[str, Severity]]:
    return [(f.id, f.severity) for f in findings]


def _rules(**lists: list[str]) -> dict:
    return {"permissions": dict(lists)}


@pytest.fixture
def project_settings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "home")
    (tmp_path / "home").mkdir()
    p = tmp_path / "repo" / ".claude" / "settings.json"
    p.parent.mkdir(parents=True)
    return p


@pytest.fixture
def user_settings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "home"
    monkeypatch.setattr(Path, "home", lambda: home)
    p = home / ".claude" / "settings.json"
    p.parent.mkdir(parents=True)
    return p


# ── Parsing layer (reused by STORY-0093) ──────────────────────────────────────


class TestParsing:
    @pytest.mark.parametrize(
        ("text", "tool", "spec"),
        [
            ("Bash", "Bash", None),
            ("  Bash(npm run *)  ", "Bash", "npm run *"),
            ("Edit(./Finance (2024)/**)", "Edit", "./Finance (2024)/**"),
            ("mcp__github__*", "mcp__github__*", None),
            ("Bash()", "Bash", ""),
        ],
    )
    def test_parse_rule(self, text: str, tool: str, spec: str | None) -> None:
        rule = perms.parse_permission_rule(text, "allow")
        assert rule is not None
        assert (rule.tool, rule.specifier, rule.list_name) == (tool, spec, "allow")
        assert rule.text == text.strip()

    @pytest.mark.parametrize("text", [None, 3, "", "   ", "Bash(oops", "(x)"])
    def test_unparseable_rules_are_none(self, text: object) -> None:
        assert perms.parse_permission_rule(text, "deny") is None

    def test_load_settings_tolerates_malformed_parts(self, tmp_path: Path) -> None:
        path = tmp_path / ".claude" / "settings.json"
        assert perms.load_claude_settings([], path) is None
        s = perms.load_claude_settings({"permissions": "x", "sandbox": ["y"]}, path)
        assert s is not None
        assert (s.permissions, s.sandbox, s.rules) == ({}, {}, ())
        s = perms.load_claude_settings(
            {"permissions": {"allow": "Bash", "deny": ["Read", 7, "Read"]}}, path
        )
        assert [r.text for r in s.rules] == ["Read"]  # duplicates kept once

    def test_sandbox_defaults(self, tmp_path: Path) -> None:
        path = tmp_path / ".claude" / "settings.json"
        s = perms.load_claude_settings({"sandbox": {"enabled": "true"}}, path)
        assert s.sandbox_enabled is False  # only the boolean true counts
        assert s.sandbox_auto_allow is True  # documented default
        s = perms.load_claude_settings(
            {"sandbox": {"enabled": True, "autoAllowBashIfSandboxed": False}}, path
        )
        assert s.sandbox_enabled is True
        assert s.sandbox_auto_allow is False

    def test_scope_and_anchor(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        home = tmp_path / "home"
        monkeypatch.setattr(Path, "home", lambda: home)
        user = home / ".claude" / "settings.json"
        project = tmp_path / "repo" / ".claude" / "settings.json"
        local = tmp_path / "repo" / ".claude" / "settings.local.json"
        for p in (user, project):
            p.parent.mkdir(parents=True, exist_ok=True)
        cases = {
            user: ("user", home / ".claude"),
            project: ("project", tmp_path / "repo"),
            local: ("local", tmp_path / "repo"),
            home / ".claude.json": ("global", None),
        }
        for path, (scope, anchor) in cases.items():
            s = perms.load_claude_settings({}, path)
            assert (s.scope, s.path_anchor) == (scope, anchor), path

    @pytest.mark.parametrize(
        ("path", "expected"),
        [
            ("a/.claude/settings.json", True),
            ("a/.claude/settings.local.json", True),
            ("a/.claude.json", True),
            ("a/.cursor/settings.json", False),
            ("a/settings.json", False),
            ("a/.claude/mcp.json", False),
        ],
    )
    def test_is_claude_code_settings_file(self, path: str, expected: bool) -> None:
        assert perms.is_claude_code_settings_file(Path(path)) is expected
        # config hygiene's hook/HARNESS gate is the same predicate
        assert ConfigHygieneAnalyzer._is_claude_code_config(Path(path)) is expected


# ── PERM-001: ignored or never-matching rules ─────────────────────────────────


class TestPerm001:
    @pytest.mark.parametrize(
        ("rule", "fix"),
        [
            ("Bash(command:rm *)", "Bash(rm *)"),
            ("Bash( command : rm -rf * )", "Bash(rm -rf *)"),
            ("PowerShell(command:Remove-Item *)", "PowerShell(Remove-Item *)"),
            ("Read(file_path:./.env)", "Read(./.env)"),
            ("Read(file_path:/etc/passwd)", "Read(//etc/passwd)"),
            ("Edit(file_path:src/**)", "Edit(src/**)"),
            ("Write(file_path:out/**)", "Edit(out/**)"),
            ("Glob(path:secrets/**)", "Read(secrets/**)"),
            ("Grep(path:secrets)", "Read(secrets)"),
            ("NotebookEdit(notebook_path:a.ipynb)", "Edit(a.ipynb)"),
            ("WebFetch(url:https://evil.example)", "WebFetch(domain:<host>)"),
        ],
    )
    def test_content_field_deny_is_high(
        self, project_settings: Path, rule: str, fix: str
    ) -> None:
        out = _perm(_rules(deny=[rule]), project_settings)
        assert _ids(out) == [("PERM-001", Severity.HIGH)]
        assert rule.strip() in out[0].description
        assert "primary content field" in out[0].description
        assert f"→ {fix}" in out[0].remediation
        assert out[0].finding_path == str(project_settings)
        assert out[0].owasp_mcp_top_10 == ["MCP07", "MCP02"]
        assert out[0].cwe == "CWE-693"

    def test_compound_command_reason_only_for_shell_tools(
        self, project_settings: Path
    ) -> None:
        bash = _perm(_rules(deny=["Bash(command:rm *)"]), project_settings)[0]
        read = _perm(_rules(deny=["Read(file_path:x)"]), project_settings)[0]
        assert "compound command" in bash.description
        assert "compound command" not in read.description

    def test_severity_follows_the_list(self, project_settings: Path) -> None:
        raw = _rules(
            deny=["Bash(command:rm *)"],
            ask=["Bash(command:git push *)"],
            allow=["Bash(command:ls *)"],
        )
        assert _ids(_perm(raw, project_settings)) == [
            ("PERM-001", Severity.HIGH),
            ("PERM-001", Severity.MEDIUM),
            ("PERM-001", Severity.INFO),
        ]

    def test_mcp_rule_with_parentheses_is_skipped(self, project_settings: Path) -> None:
        out = _perm(
            _rules(deny=["mcp__github__create_issue(repo:acme/x)"]), project_settings
        )
        assert _ids(out) == [("PERM-001", Severity.HIGH)]
        assert "skips any mcp__ rule that has parentheses" in out[0].description
        assert "--disallowedTools" in out[0].remediation

    @pytest.mark.parametrize(
        ("rule", "alternative"),
        [
            ("Write(./secrets/**)", "Edit(./secrets/**)"),
            ("NotebookEdit(docs/**)", "Edit(docs/**)"),
            ("MultiEdit(docs/**)", "Edit(docs/**)"),
            ("Glob(docs/**)", "Read(docs/**)"),
            ("Write(C:\\out\\**)", "Edit(C:\\out\\**)"),
        ],
    )
    def test_dead_path_rules(
        self, project_settings: Path, rule: str, alternative: str
    ) -> None:
        out = _perm(_rules(deny=[rule]), project_settings)
        assert _ids(out) == [("PERM-001", Severity.HIGH)]
        assert "never matches it" in out[0].description
        assert alternative in out[0].remediation

    def test_mid_pattern_colon_star(self, project_settings: Path) -> None:
        out = _perm(_rules(deny=["Bash(git:* push)"]), project_settings)
        assert _ids(out) == [("PERM-001", Severity.HIGH)]
        assert "literal character" in out[0].description
        assert "→ Bash(git push *)" in out[0].remediation

    @pytest.mark.parametrize("rule", ["*", "B*", "mcp__*", "mcp__git*__read", "*__x"])
    def test_unanchored_allow_glob_is_info(
        self, project_settings: Path, rule: str
    ) -> None:
        out = _perm(_rules(allow=[rule]), project_settings)
        assert _ids(out) == [("PERM-001", Severity.INFO)]
        assert "unanchored allow glob" in out[0].description

    @pytest.mark.parametrize(
        "rules",
        [
            # valid forms straight from the rule grammar
            {"deny": ["Bash(rm *)", "Read(./.env)", "Read(./secrets/**)"]},
            {"deny": ["Agent(model:opus)", "Bash(run_in_background:true)"]},
            {"deny": ["Agent(isolation:*)", "Skill(skill:deploy)"]},
            {"ask": ["Bash(command -v *)", "Bash(command:*)"]},
            {"deny": ["mcp__*", "*", "mcp__github", "mcp__github__delete_*"]},
            {"allow": ["mcp__github__*", "mcp__github__get_*", "mcp__puppeteer"]},
            {"deny": ["Write", "Glob", "NotebookEdit", "Write(*)"]},
            {"allow": ["Bash(scp host:* .)", "Bash(git push:*)", "Bash(ls:*)"]},
            {"allow": ["WebFetch(domain:example.com)", "Edit(docs/**)"]},
        ],
    )
    def test_valid_rules_are_silent(self, project_settings: Path, rules: dict) -> None:
        out = [
            f for f in _perm(_rules(**rules), project_settings) if f.id == "PERM-001"
        ]
        assert out == []

    def test_evidence_is_capped(self, project_settings: Path) -> None:
        many = [f"Bash(command:rm {i} *)" for i in range(25)]
        out = _perm(_rules(deny=many), project_settings)
        assert len(out) == 1
        assert "(+5 more)" in out[0].evidence
        assert "(+5 more)" in out[0].remediation


# ── PERM-002: single-slash paths ──────────────────────────────────────────────


class TestPerm002:
    @pytest.mark.parametrize(
        "rule",
        [
            "Read(/Users/alice/.ssh/**)",
            "Read(/home/alice/.aws/credentials)",
            "Edit(/etc/hosts)",
            "Read(/c/Users/alice/**)",
            "Read(/tmp/scratch/**)",
        ],
    )
    def test_project_deny_on_root_path_is_medium(
        self, project_settings: Path, rule: str
    ) -> None:
        out = _perm(_rules(deny=[rule]), project_settings)
        assert _ids(out) == [("PERM-002", Severity.MEDIUM)]
        spec = rule[rule.index("(") + 1 : -1]
        assert f"<project>{spec}" in out[0].description
        assert f"→ {rule.split('(')[0]}(/{spec})" in out[0].remediation
        assert "anchors at the settings source" in out[0].description

    def test_allow_is_info_and_ask_is_medium(self, project_settings: Path) -> None:
        raw = _rules(allow=["Read(/Users/alice/x/**)"], ask=["Edit(/etc/**)"])
        assert _ids(_perm(raw, project_settings)) == [
            ("PERM-002", Severity.MEDIUM),
            ("PERM-002", Severity.INFO),
        ]

    @pytest.mark.parametrize(
        "rule",
        [
            "Edit(/src/**/*.ts)",  # the doc's own project-root example
            "Read(/docs/**)",
            "Read(//Users/alice/x)",  # already absolute
            "Read(~/.zshrc)",
            "Read(./.env)",
            "Read(/**/secrets)",
            "Read(/)",
            "Bash(/usr/bin/env *)",  # not a path rule
        ],
    )
    def test_project_relative_rules_are_silent(
        self, project_settings: Path, rule: str
    ) -> None:
        assert _perm(_rules(deny=[rule]), project_settings) == []

    def test_existing_project_directory_is_trusted(
        self, project_settings: Path
    ) -> None:
        (project_settings.parent.parent / "etc").mkdir()
        assert _perm(_rules(deny=["Read(/etc/**)"]), project_settings) == []

    def test_user_settings_anchor_at_dot_claude(self, user_settings: Path) -> None:
        # The doc's own example: Read(/secrets/**) in user settings blocks
        # ~/.claude/secrets/**, not a project's secrets directory.
        out = _perm(_rules(deny=["Read(/secrets/**)"]), user_settings)
        assert _ids(out) == [("PERM-002", Severity.MEDIUM)]
        assert "~/.claude/secrets/**" in out[0].description
        assert "user settings" in out[0].description

    def test_user_settings_rule_for_a_real_dot_claude_dir(
        self, user_settings: Path
    ) -> None:
        (user_settings.parent / "agents").mkdir()
        assert _perm(_rules(deny=["Read(/agents/**)"]), user_settings) == []

    def test_global_config_is_not_checked(self, tmp_path: Path) -> None:
        path = tmp_path / ".claude.json"
        assert _perm(_rules(deny=["Read(/Users/x/**)"]), path) == []


# ── PERM-003: trailing * without a space ──────────────────────────────────────


class TestPerm003:
    @pytest.mark.parametrize(
        "rule", ["Bash(ls*)", "Bash(./scripts/test*)", "PowerShell(Get-Child*)"]
    )
    def test_fires_low(self, project_settings: Path, rule: str) -> None:
        out = _perm(_rules(allow=[rule]), project_settings)
        assert _ids(out) == [("PERM-003", Severity.LOW)]
        assert "lsof" in out[0].description  # the doc's example is quoted
        prefix = rule[rule.index("(") + 1 : -2]
        assert f"→ {rule.split('(')[0]}({prefix} *)" in out[0].remediation

    @pytest.mark.parametrize(
        "rule",
        [
            "Bash(ls *)",
            "Bash(ls:*)",
            "Bash(ls)",
            "Bash(npm run test*)",  # the * extends an argument, not the program
            "Bash(*)",
        ],
    )
    def test_silent(self, project_settings: Path, rule: str) -> None:
        assert _perm(_rules(allow=[rule]), project_settings) == []

    def test_broad_program_is_left_to_harness_005(self, project_settings: Path) -> None:
        raw = _rules(allow=["Bash(python*)"])
        all_ids = [
            f.id
            for f in ConfigHygieneAnalyzer().analyze_config(
                raw, project_settings, "claude-code"
            )
        ]
        assert all_ids == ["HARNESS-005"]

    def test_deny_is_silent(self, project_settings: Path) -> None:
        # A wider deny blocks more, not less.
        assert _perm(_rules(deny=["Bash(ls*)"]), project_settings) == []


# ── PERM-004: deny/ask is not a boundary without the sandbox ──────────────────


class TestPerm004:
    def test_deny_without_anything_approving_bypass_forms_is_info(
        self, project_settings: Path
    ) -> None:
        out = _perm(_rules(deny=["Bash(curl *)"]), project_settings)
        assert _ids(out) == [("PERM-004", Severity.INFO)]
        assert "/usr/bin/curl" in out[0].description
        assert "sh -c 'curl …'" in out[0].description
        assert "isn't a security boundary" in out[0].description
        assert out[0].cwe == "CWE-184"

    @pytest.mark.parametrize(
        "extra",
        [
            {"allow": ["Bash"]},
            {"allow": ["Bash(*)"]},
            {"allow": ["Bash(sh -c *)"]},
            {"allow": ["Bash(bash:*)"]},
            {"allow": ["Bash(env *)"]},
            {"allow": ["Bash(sudo -E *)"]},
            {"allow": ["Bash(* --version)"]},
            {"allow": ["Bash(/usr/bin/*)"]},
        ],
    )
    def test_medium_when_this_file_runs_bypass_forms(
        self, project_settings: Path, extra: dict
    ) -> None:
        raw = {"permissions": {"deny": ["Bash(rm -rf *)"], **extra}}
        out = [f for f in _perm(raw, project_settings) if f.id == "PERM-004"]
        assert _ids(out) == [("PERM-004", Severity.MEDIUM)]
        assert "approves those forms, so they run without a prompt" in (
            out[0].description
        )

    @pytest.mark.parametrize(
        ("mode", "phrase"),
        [
            ("bypassPermissions", "so those forms run without a prompt"),
            ("auto", "the auto-mode classifier, not you, decides"),
        ],
    )
    def test_user_settings_mode_counts(
        self, user_settings: Path, mode: str, phrase: str
    ) -> None:
        raw = {"permissions": {"deny": ["Bash(rm -rf *)"], "defaultMode": mode}}
        out = [f for f in _perm(raw, user_settings) if f.id == "PERM-004"]
        assert _ids(out) == [("PERM-004", Severity.MEDIUM)]
        assert phrase in out[0].description

    @pytest.mark.parametrize("mode", ["bypassPermissions", "auto"])
    @pytest.mark.parametrize("name", ["settings.json", "settings.local.json"])
    def test_project_or_local_mode_does_not_count(
        self, project_settings: Path, mode: str, name: str
    ) -> None:
        """Settings reference: auto and bypassPermissions "don't take effect from
        project or local settings"."""
        path = project_settings.with_name(name)
        raw = {"permissions": {"deny": ["Bash(rm -rf *)"], "defaultMode": mode}}
        out = [f for f in _perm(raw, path) if f.id == "PERM-004"]
        assert _ids(out) == [("PERM-004", Severity.INFO)]

    @pytest.mark.parametrize(
        "allow",
        [
            "Bash(./scripts/*)",
            "Bash(bin/*)",
            "Bash(./node_modules/.bin/*)",
            "Bash(bash scripts/test.sh *)",
            "Bash(sh ./gradlew *)",
            "Bash(sudo systemctl status *)",
            "Bash(env NODE_ENV=test npm test *)",
            "Bash(sh -c)",
        ],
    )
    def test_narrow_allows_do_not_approve_bypass_forms(
        self, project_settings: Path, allow: str
    ) -> None:
        raw = {"permissions": {"deny": ["Bash(curl *)"], "allow": [allow]}}
        out = [f for f in _perm(raw, project_settings) if f.id == "PERM-004"]
        assert _ids(out) == [("PERM-004", Severity.INFO)]

    @pytest.mark.parametrize(
        "extra",
        [
            {"defaultMode": "dontAsk"},
            {"defaultMode": "acceptEdits"},
            {"allow": ["Bash(npm run *)", "Bash(git commit *)", "PowerShell"]},
        ],
    )
    def test_info_when_bypass_forms_still_prompt(
        self, project_settings: Path, extra: dict
    ) -> None:
        raw = {"permissions": {"ask": ["Bash(wget *)"], **extra}}
        out = [f for f in _perm(raw, project_settings) if f.id == "PERM-004"]
        assert _ids(out) == [("PERM-004", Severity.INFO)]

    def test_git_push_names_the_documented_forms(self, project_settings: Path) -> None:
        out = _perm(_rules(deny=["Bash(git push *)"]), project_settings)
        assert _ids(out) == [("PERM-004", Severity.INFO)]
        for form in ("git -C . push", "git -c push.default=current push", "git 'push'"):
            assert form in out[0].description

    def test_sandbox_enabled_in_this_file_silences(
        self, project_settings: Path
    ) -> None:
        raw = {
            "permissions": {"deny": ["Bash(curl *)"], "defaultMode": "auto"},
            "sandbox": {"enabled": True},
        }
        assert _perm(raw, project_settings) == []

    @pytest.mark.parametrize(
        "rule",
        [
            "Bash(npm publish *)",
            "Bash(git commit *)",
            "Bash",
            "PowerShell(Remove-Item *)",
            "Read(./.env)",
            "WebFetch",
        ],
    )
    def test_other_programs_are_silent(self, project_settings: Path, rule: str) -> None:
        assert _perm(_rules(deny=[rule]), project_settings) == []


# ── PERM-005: WebFetch(domain:*) allow ────────────────────────────────────────


class TestPerm005:
    def test_high_when_this_file_enables_the_sandbox(
        self, project_settings: Path
    ) -> None:
        raw = {
            "permissions": {"allow": ["WebFetch(domain:*)"]},
            "sandbox": {"enabled": True},
        }
        out = _perm(raw, project_settings)
        assert _ids(out) == [("PERM-005", Severity.HIGH)]
        assert "sandboxed commands can reach any host" in out[0].description
        assert "→ WebFetch," in out[0].remediation

    @pytest.mark.parametrize("rule", ["WebFetch(domain:*)", "WebFetch( domain : * )"])
    def test_low_without_the_sandbox(self, project_settings: Path, rule: str) -> None:
        out = _perm(_rules(allow=[rule]), project_settings)
        assert _ids(out) == [("PERM-005", Severity.LOW)]

    @pytest.mark.parametrize(
        "raw",
        [
            {"permissions": {"allow": ["WebFetch"]}, "sandbox": {"enabled": True}},
            {"permissions": {"allow": ["WebFetch(domain:*.example.com)"]}},
            {"permissions": {"allow": ["WebFetch(domain:github.com)"]}},
            {"permissions": {"deny": ["WebFetch(domain:*)"]}},
        ],
    )
    def test_silent(self, project_settings: Path, raw: dict) -> None:
        assert _perm(raw, project_settings) == []


# ── PERM-006: bare Bash ask under sandbox auto-allow ──────────────────────────


class TestPerm006:
    @pytest.mark.parametrize("rule", ["Bash", "Bash(*)"])
    @pytest.mark.parametrize("auto", [None, True])
    def test_fires_medium(
        self, project_settings: Path, rule: str, auto: bool | None
    ) -> None:
        sandbox: dict = {"enabled": True}
        if auto is not None:
            sandbox["autoAllowBashIfSandboxed"] = auto
        out = _perm(
            {"permissions": {"ask": [rule]}, "sandbox": sandbox}, project_settings
        )
        assert _ids(out) == [("PERM-006", Severity.MEDIUM)]
        assert "is skipped for commands that run sandboxed" in out[0].description
        assert "sandbox.enabled = true" in out[0].evidence
        assert "autoAllowBashIfSandboxed: false" in out[0].remediation

    @pytest.mark.parametrize(
        "raw",
        [
            # Anthropic's strict example shape: auto-allow off
            {
                "permissions": {"ask": ["Bash"]},
                "sandbox": {"enabled": True, "autoAllowBashIfSandboxed": False},
            },
            {"permissions": {"ask": ["Bash"]}},  # no sandbox: the rule prompts
            {"permissions": {"ask": ["Bash"]}, "sandbox": {"enabled": False}},
            # "In plan mode, the rule isn't skipped"
            {
                "permissions": {"ask": ["Bash"], "defaultMode": "plan"},
                "sandbox": {"enabled": True},
            },
            # content-scoped ask rules still prompt for sandboxed commands
            {
                "permissions": {"ask": ["Bash(git push *)"]},
                "sandbox": {"enabled": True},
            },
            {"permissions": {"allow": ["Bash"]}, "sandbox": {"enabled": True}},
        ],
    )
    def test_silent(self, project_settings: Path, raw: dict) -> None:
        assert [f for f in _perm(raw, project_settings) if f.id == "PERM-006"] == []

    @pytest.mark.parametrize("mode", ["auto", "bypassPermissions", "acceptEdits"])
    def test_ask_rules_in_auto_or_bypass_mode_are_not_flagged(
        self, project_settings: Path, mode: str
    ) -> None:
        """Q-018's premise is contradicted by the current docs.

        "Claude Code doesn't auto-approve the following in any mode, including
        bypassPermissions: Tools matched by an explicit ask rule"
        (code.claude.com/docs/en/permission-modes).
        """
        raw = {
            "permissions": {"ask": ["Bash(git push *)", "Bash"], "defaultMode": mode}
        }
        assert [f for f in _perm(raw, project_settings) if f.id == "PERM-006"] == []


# ── Whole-file behaviour ──────────────────────────────────────────────────────


class TestWholeFile:
    def test_non_settings_files_are_ignored(self, tmp_path: Path) -> None:
        raw = _rules(deny=["Bash(command:rm *)"], allow=["WebFetch(domain:*)"])
        for name in (".cursor/settings.json", ".vscode/settings.json", "x.json"):
            path = tmp_path / name
            assert _perm(raw, path) == []

    @pytest.mark.parametrize(
        "raw", [{}, [], "x", {"permissions": None}, {"permissions": {"deny": "Bash"}}]
    )
    def test_empty_or_malformed_is_silent(
        self, project_settings: Path, raw: object
    ) -> None:
        assert perms.analyze_permission_rules(raw, project_settings, "c") == []

    def test_local_settings_are_checked_and_labelled(self, tmp_path: Path) -> None:
        local = tmp_path / "repo" / ".claude" / "settings.local.json"
        local.parent.mkdir(parents=True)
        out = _perm(_rules(deny=["Bash(command:rm *)"]), local)
        assert "local project settings" in out[0].description

    def test_ordinary_configs_stay_at_info_or_below(
        self, project_settings: Path
    ) -> None:
        """Realistic, correct settings in the shapes Anthropic documents.

        Written for this test (not copied): the rule forms the permissions,
        settings-reference and sandboxing pages show as correct.
        """
        configs = [
            {
                "permissions": {
                    "allow": ["Bash(npm run *)", "Bash(git commit *)"],
                    "deny": ["Bash(git push *)"],
                }
            },
            {
                "permissions": {
                    "allow": ["Bash(git diff *)", "Read(~/.zshrc)", "WebFetch"],
                    "deny": [
                        "Read(./.env)",
                        "Read(./.env.*)",
                        "Read(./secrets/**)",
                        "Read(./config/credentials.json)",
                        "Bash(curl *)",
                    ],
                    "ask": ["Bash(git push *)"],
                }
            },
            {
                "permissions": {
                    "allow": [
                        "PowerShell(Get-ChildItem *)",
                        "PowerShell(git commit *)",
                        "mcp__puppeteer__*",
                        "mcp__github__get_*",
                        "WebFetch(domain:github.com)",
                        "WebFetch(domain:*.example.com)",
                        "Edit(/src/**/*.ts)",
                        "Edit(./Finance (2024)/**)",
                    ],
                    "deny": [
                        "PowerShell(Remove-Item *)",
                        "Agent(Explore)",
                        "mcp__*",
                        "Read(//**/.env)",
                        "Read(*.env)",
                        "Read(!sample.env)",
                        "Agent(model:opus)",
                    ],
                }
            },
            {
                "permissions": {
                    "ask": ["Bash"],
                    "disableBypassPermissionsMode": "disable",
                },
                "sandbox": {"enabled": True, "autoAllowBashIfSandboxed": False},
            },
            {
                "permissions": {"deny": ["WebSearch", "WebFetch"], "ask": ["Bash"]},
                "sandbox": {"autoAllowBashIfSandboxed": False, "excludedCommands": []},
            },
            {
                "permissions": {
                    "deny": ["Bash(rm *)", "Read(~/.ssh/**)", "Edit(~/.aws/**)"],
                    "defaultMode": "acceptEdits",
                },
                "sandbox": {"enabled": True, "network": {"allowedDomains": ["x.y"]}},
            },
        ]
        for raw in configs:
            out = _perm(raw, project_settings)
            assert all(f.severity in (Severity.INFO,) for f in out), _ids(out)


# ── HARNESS-005 runner and PowerShell forms (STORY-0092) ──────────────────────


class TestHarness005RunnerForms:
    @pytest.mark.parametrize(
        "rule",
        [
            "Bash(devbox run *)",
            "Bash(devbox run:*)",
            "Bash(mise exec *)",
            "Bash(mise x *)",
            "Bash(mise exec node@20 -- *)",
            "Bash(direnv exec . *)",
            "Bash(docker exec app *)",
            "Bash(docker exec -it app *)",
            "Bash(docker run --rm *)",
            "Bash(podman run *)",
            "Bash(kubectl exec -it pod -- *)",
            "Bash(nix run *)",
            "Bash(npm exec *)",
            "Bash(pnpm dlx *)",
            "Bash(pnpm exec *)",
            "Bash(yarn dlx *)",
            "Bash(bun x *)",
            "Bash(pipx run *)",
            "Bash(uv run *)",
            "Bash(poetry run *)",
            "Bash(pdm run *)",
            "Bash(devbox run npm *)",
            "Bash(docker exec app bash *)",
            "PowerShell(iex *)",
            "PowerShell(Invoke-Expression *)",
            "PowerShell(Start-Process *)",
            "PowerShell(Invoke-WebRequest *)",
            "PowerShell(irm *)",
        ],
    )
    def test_runner_forms_are_broad(self, rule: str) -> None:
        assert _is_broad_allow_rule(rule) is True

    @pytest.mark.parametrize(
        "rule",
        [
            "Bash(devbox run npm test)",  # the doc's own recommended form
            "Bash(devbox run pytest *)",
            "Bash(uv run pytest *)",
            "Bash(docker exec app ls)",
            "Bash(docker exec app pytest *)",
            "Bash(pnpm dlx create-vite *)",
            "Bash(npm run *)",
            "Bash(mise exec node@20 -- node app.js)",
            "PowerShell(Get-ChildItem *)",
            "PowerShell(git commit *)",
        ],
    )
    def test_narrow_runner_forms_are_not(self, rule: str) -> None:
        assert _is_broad_allow_rule(rule) is False

    @pytest.mark.parametrize(
        "rule", ["Bash(git push origin main)", "Bash(gh api repos *)", "Bash(npx *)"]
    )
    def test_existing_broad_forms_unchanged(self, rule: str) -> None:
        assert _is_broad_allow_rule(rule) is True

    def test_runner_rule_reaches_harness_005_with_the_docs_fix(
        self, project_settings: Path
    ) -> None:
        out = ConfigHygieneAnalyzer().analyze_config(
            _rules(allow=["Bash(devbox run *)"]), project_settings, "claude-code"
        )
        assert _ids(out) == [("HARNESS-005", Severity.MEDIUM)]
        assert "Bash(devbox run npm test)" in out[0].remediation


# ── PERM-007: allow rules on servers with HIGH+ findings ─────────────────────


def _server(name: str, path: Path, client: str = "claude-code-project") -> ServerConfig:
    return ServerConfig(name=name, client=client, config_path=path, command="npx")


def _finding(
    server: ServerConfig,
    *,
    fid: str = "SC-001",
    severity: Severity = Severity.CRITICAL,
    analyzer: str = "supply_chain",
    server_label: str | None = None,
) -> Finding:
    return Finding(
        id=fid,
        severity=severity,
        analyzer=analyzer,
        client=server.client,
        server=server_label or server.name,
        title="t",
        description="d",
        evidence="e",
        remediation="r",
        finding_path=str(server.config_path),
    )


def _config(path: Path, raw: dict, client: str = "claude-code-project"):
    return DiscoveredConfig(
        client_name=client, root_key="mcpServers", path=path, raw=raw
    )


@pytest.fixture
def repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(Path, "home", lambda: tmp_path / "home")
    (tmp_path / "home" / ".claude").mkdir(parents=True)
    root = tmp_path / "repo"
    (root / ".claude").mkdir(parents=True)
    return root


class TestPerm007:
    def _run(self, repo: Path, allow: list[str], server: ServerConfig, **kw):
        settings = _config(repo / ".claude" / "settings.json", _rules(allow=allow))
        return perms.analyze_flagged_server_allows(
            [settings], [server], [_finding(server, **kw)]
        )

    @pytest.mark.parametrize("rule", ["mcp__github", "mcp__github__*"])
    def test_whole_server_allow_on_flagged_server(self, repo: Path, rule: str) -> None:
        server = _server("github", repo / ".mcp.json")
        out = self._run(repo, [rule], server)
        assert _ids(out) == [("PERM-007", Severity.HIGH)]
        f = out[0]
        assert f.server == "github"
        assert f.finding_path == str(repo / ".claude" / "settings.json")
        assert "SC-001" in f.description and "2.1.299" in f.description
        assert "1 CRITICAL or HIGH finding(s)" in f.description
        assert rule in f.evidence
        assert "mcp__github__<tool>" in f.remediation
        assert f.owasp_mcp_top_10 == ["MCP02", "MCP07"]

    @pytest.mark.parametrize(
        "rule",
        [
            "mcp__github__get_issue",  # one tool
            "mcp__github__get_*",  # a tool-prefix glob
            "mcp__gith*__*",  # skipped: glob in the server segment
            "mcp__*",  # skipped: unanchored
            "mcp__github(x)",  # skipped: parentheses
            "mcp__git",  # a different server since 2.1.299
        ],
    )
    def test_other_rule_shapes_do_not_fire(self, repo: Path, rule: str) -> None:
        server = _server("github", repo / ".mcp.json")
        assert self._run(repo, [rule], server) == []

    def test_2_1_299_whole_name_matching(self, repo: Path) -> None:
        """`mcp__a` no longer allows a server named `a__b` or `a_` (CHANGELOG)."""
        for name in ("a__b", "a_"):
            server = _server(name, repo / ".mcp.json")
            assert self._run(repo, ["mcp__a", "mcp__a__*"], server) == [], name
        # a name ending in _ needs the wildcard form with the whole name
        server = _server("a_", repo / ".mcp.json")
        assert self._run(repo, ["mcp__a_"], server) == []
        assert _ids(self._run(repo, ["mcp__a___*"], server)) == [
            ("PERM-007", Severity.HIGH)
        ]
        server = _server("reports__v2", repo / ".mcp.json")
        # bare form with __ is read as tool v2 of server reports: not whole-server
        assert self._run(repo, ["mcp__reports__v2"], server) == []
        out = self._run(repo, ["mcp__reports__v2__*"], server)
        assert _ids(out) == [("PERM-007", Severity.HIGH)]

    def test_name_is_normalized(self, repo: Path) -> None:
        server = _server("my.server name", repo / ".mcp.json")
        out = self._run(repo, ["mcp__my_server_name__*"], server)
        assert _ids(out) == [("PERM-007", Severity.HIGH)]
        assert "'my_server_name'" in out[0].description

    @pytest.mark.parametrize(
        ("analyzer", "fid", "fires"),
        [
            ("supply_chain", "SC-001", True),
            ("supply_chain", "SC-004", True),  # pinned: text names the version
            ("poisoning", "POISON-010", True),
            ("rug_pull", "RUGPULL-001", True),
            ("toxic_flow", "TOXIC-001", False),  # a capability mix, own severity
            ("toxic_flow", "INTEG-001", False),
            ("attestation", "ATTEST-001", False),  # added after the pipeline
            ("config_hygiene", "CFHYG-001", False),  # file mode, any 0644 file
            ("credentials", "CRED-001", False),
            ("rules", "COMM-013", False),  # every `npx -y` server
            ("transport", "TRANSPORT-001", False),
            ("trust", "TRUST-001", False),
            ("scanner", "SCAN-ERR", False),
        ],
    )
    def test_only_findings_about_the_server_itself_count(
        self, repo: Path, analyzer: str, fid: str, fires: bool
    ) -> None:
        server = _server("srv", repo / ".mcp.json")
        out = self._run(
            repo,
            ["mcp__srv__*"],
            server,
            fid=fid,
            analyzer=analyzer,
            severity=Severity.HIGH,
        )
        assert bool(out) is fires

    def test_sc004_counts_only_for_a_known_affected_version(self, repo: Path) -> None:
        """Real SC-004 output: unpinned says the version can't be told offline."""
        from mcp_audit.analyzers.supply_chain import (  # noqa: PLC0415
            SupplyChainAnalyzer,
        )

        analyzer = SupplyChainAnalyzer()
        settings = _config(
            repo / ".claude" / "settings.json", _rules(allow=["mcp__azure__*"])
        )
        for args, fires in (
            (["-y", "@azure/mcp", "server", "start"], False),
            (["-y", "@azure/mcp@0.0.1", "server", "start"], True),
        ):
            server = ServerConfig(
                name="azure",
                client="claude-code-project",
                config_path=repo / ".mcp.json",
                command="npx",
                args=args,
            )
            found = [
                f.model_copy(update={"finding_path": str(server.config_path)})
                for f in analyzer.analyze(server)
            ]
            sc004 = [f for f in found if f.id == "SC-004"]
            assert sc004 and sc004[0].severity is Severity.HIGH, args
            out = perms.analyze_flagged_server_allows([settings], [server], found)
            assert bool(out) is fires, args

    @pytest.mark.parametrize("severity", [Severity.MEDIUM, Severity.LOW, Severity.INFO])
    def test_below_high_does_not_count(self, repo: Path, severity: Severity) -> None:
        server = _server("srv", repo / ".mcp.json")
        assert self._run(repo, ["mcp__srv"], server, severity=severity) == []

    def test_cross_server_pair_does_not_count(self, repo: Path) -> None:
        server = _server("fs", repo / ".mcp.json")
        out = self._run(
            repo,
            ["mcp__fs__*"],
            server,
            fid="TOXIC-001",
            analyzer="toxic_flow",
            severity=Severity.HIGH,
            server_label="fs + fetch",
        )
        assert out == []

    def test_other_clients_are_not_claude_code_servers(self, repo: Path) -> None:
        server = _server("github", repo / ".cursor" / "mcp.json", client="cursor")
        assert self._run(repo, ["mcp__github__*"], server) == []

    def test_explicit_path_claude_file_counts(self, repo: Path) -> None:
        server = _server("github", repo / ".mcp.json", client="custom")
        assert _ids(self._run(repo, ["mcp__github__*"], server)) == [
            ("PERM-007", Severity.HIGH)
        ]
        other = _server("github", repo / "servers.json", client="custom")
        assert self._run(repo, ["mcp__github__*"], other) == []

    def test_project_rules_do_not_reach_another_project(
        self, repo: Path, tmp_path: Path
    ) -> None:
        elsewhere = _server("github", tmp_path / "other" / ".mcp.json")
        assert self._run(repo, ["mcp__github__*"], elsewhere) == []
        user_scope = _server(
            "github", tmp_path / "home" / ".claude.json", "claude-code"
        )
        assert self._run(repo, ["mcp__github__*"], user_scope) != []

    def test_user_settings_reach_every_project(
        self, repo: Path, tmp_path: Path
    ) -> None:
        server = _server("github", tmp_path / "other" / ".mcp.json")
        user = _config(
            tmp_path / "home" / ".claude" / "settings.json",
            _rules(allow=["mcp__github__*"]),
            client="claude-code",
        )
        out = perms.analyze_flagged_server_allows([user], [server], [_finding(server)])
        assert _ids(out) == [("PERM-007", Severity.HIGH)]
        assert "user settings" in out[0].description

    def test_one_finding_per_server_lists_every_rule(self, repo: Path) -> None:
        server = _server("github", repo / ".mcp.json")
        out = self._run(repo, ["mcp__github", "mcp__github__*"], server)
        assert len(out) == 1
        assert "'mcp__github', 'mcp__github__*'" in out[0].evidence

    def test_plugin_server_uses_the_plugin_scoped_name(self, tmp_path: Path) -> None:
        plugin_root = tmp_path / "plugins" / "db"
        (plugin_root / ".claude-plugin").mkdir(parents=True)
        (plugin_root / ".claude-plugin" / "plugin.json").write_text(
            json.dumps({"name": "my-plugin"}), encoding="utf-8"
        )
        server = _server(
            "database-tools", plugin_root / ".mcp.json", client="claude-code-plugin"
        )
        assert perms.claude_code_server_key(server) == (
            "plugin_my-plugin_database-tools"
        )
        settings = _config(
            tmp_path / "home" / ".claude" / "settings.json",
            _rules(allow=["mcp__database-tools__*"]),
        )
        assert (
            perms.analyze_flagged_server_allows(
                [settings], [server], [_finding(server)]
            )
            == []
        )  # the bare server key never matches a plugin server
        settings.raw = _rules(allow=["mcp__plugin_my-plugin_database-tools__*"])
        out = perms.analyze_flagged_server_allows(
            [settings], [server], [_finding(server)]
        )
        assert _ids(out) == [("PERM-007", Severity.HIGH)]

    def test_plugin_without_a_readable_name_is_skipped(self, tmp_path: Path) -> None:
        server = _server("x", tmp_path / "p" / ".mcp.json", client="claude-code-plugin")
        assert perms.claude_code_server_key(server) is None
        (tmp_path / "p" / ".claude-plugin").mkdir(parents=True)
        (tmp_path / "p" / ".claude-plugin" / "plugin.json").write_text("{not json")
        assert perms.claude_code_server_key(server) is None

    def test_no_flagged_servers_is_silent(self, repo: Path) -> None:
        server = _server("github", repo / ".mcp.json")
        settings = _config(
            repo / ".claude" / "settings.json", _rules(allow=["mcp__github"])
        )
        assert perms.analyze_flagged_server_allows([settings], [server], []) == []


class TestPerm007Pipeline:
    def _configs(self, repo: Path) -> tuple[list[DiscoveredConfig], list[ServerConfig]]:
        mcp = repo / ".mcp.json"
        settings = repo / ".claude" / "settings.json"
        server = _server("typo", mcp)
        return (
            [
                _config(mcp, {"mcpServers": {"typo": {"command": "npx"}}}),
                _config(settings, _rules(allow=["mcp__typo__*"])),
            ],
            [server],
        )

    def test_step_5b_runs_after_the_per_server_analyzers(self, repo: Path) -> None:
        configs, servers = self._configs(repo)
        flagged = _finding(servers[0])
        from mcp_audit import scanner  # noqa: PLC0415

        with (
            # a HIGH+ finding that exists only after step 5
            patch("mcp_audit.scanner._run_rules_engine", return_value=[flagged]),
            patch(
                "mcp_audit.scanner.calculate_score", wraps=scanner.calculate_score
            ) as score,
        ):
            result = _run_static_pipeline(
                ScanResult(),
                servers,
                configs,
                get_default_analyzers(),
                skip_rug_pull=True,
            )
        assert [f.id for f in result.findings if f.id == "PERM-007"] == ["PERM-007"]
        scored = score.call_args.args[0]
        assert "PERM-007" in {f.id for f in scored}  # counted in the grade

    def test_needs_the_config_hygiene_analyzer(self, repo: Path) -> None:
        configs, servers = self._configs(repo)
        analyzers = [
            a
            for a in get_default_analyzers()
            if not isinstance(a, ConfigHygieneAnalyzer)
        ]
        with patch(
            "mcp_audit.scanner._run_rules_engine",
            return_value=[_finding(servers[0])],
        ):
            result = _run_static_pipeline(
                ScanResult(), servers, configs, analyzers, skip_rug_pull=True
            )
        assert not [f for f in result.findings if f.id.startswith("PERM-")]

    def test_a_crash_is_reported_not_raised(self, repo: Path) -> None:
        configs, servers = self._configs(repo)
        with patch(
            "mcp_audit.scanner.analyze_flagged_server_allows",
            side_effect=RuntimeError("boom"),
        ):
            result = _run_static_pipeline(
                ScanResult(),
                servers,
                configs,
                get_default_analyzers(),
                skip_rug_pull=True,
            )
        assert "permissions error: boom" in result.errors


def _write(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


def _json_out(output: str) -> dict:
    return json.loads(output[output.index("{") :])


class TestCli:
    """The default path a user runs: no new flags."""

    def _repo(self, root: Path) -> None:
        # A typosquat of the official GitHub server (SC-001, CRITICAL) whose
        # tools the committed settings pre-approve.
        _write(
            root / ".mcp.json",
            {
                "mcpServers": {
                    "gh.tools": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-githb"],
                    },
                    "fs": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-filesystem", "."],
                    },
                }
            },
        )
        _write(
            root / ".claude" / "settings.json",
            {
                "permissions": {
                    "allow": ["mcp__gh_tools__*", "mcp__fs__*", "mcp__gh"],
                    "deny": ["Bash(command:rm *)"],
                }
            },
        )

    def test_scan_project(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(Path, "home", lambda: tmp_path / "home")
        repo = tmp_path / "repo"
        self._repo(repo)
        monkeypatch.chdir(tmp_path)
        with patch("mcp_audit.discovery._get_client_specs", return_value=[]):
            result = runner.invoke(
                app, ["scan", "--project", str(repo), "--format", "json"]
            )
        assert result.exit_code == 1
        found = {(f["id"], f["server"]) for f in _json_out(result.output)["findings"]}
        assert ("PERM-007", "gh.tools") in found
        assert ("PERM-007", "fs") not in found  # CFHYG/COMM findings don't count
        assert ("PERM-001", "(config-level)") in found

    def test_default_scan_from_the_repo(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """`mcp-audit scan` with no flags, run in the checkout (the Action's run)."""
        monkeypatch.setattr(Path, "home", lambda: tmp_path / "home")
        repo = tmp_path / "repo"
        self._repo(repo)
        monkeypatch.chdir(repo)
        with patch("mcp_audit.discovery._get_client_specs", return_value=[]):
            result = runner.invoke(app, ["scan", "--format", "json"])
        ids = [f["id"] for f in _json_out(result.output)["findings"]]
        assert ids.count("PERM-007") == 1
        assert "PERM-001" in ids


class TestReporting:
    @pytest.mark.parametrize("n", range(1, 8))
    def test_check_has_a_specific_hint(self, n: int) -> None:
        from mcp_audit.output.check import _HINTS, _remediation_hint  # noqa: PLC0415

        fid = f"PERM-00{n}"
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

    def test_advisory_class(self) -> None:
        from mcp_audit.advisory.classify import (  # noqa: PLC0415
            finding_class_for,
            is_advisable,
        )

        assert finding_class_for("PERM-004") == "excessive-scope"
        assert is_advisable("PERM-007")


class TestEdgeCases:
    @pytest.mark.skipif(
        not hasattr(__import__("os"), "symlink") or __import__("os").name == "nt",
        reason="POSIX symlinks",
    )
    def test_symlinked_settings_file_is_still_linted(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(Path, "home", lambda: tmp_path / "home")
        target = tmp_path / "elsewhere" / "settings.json"
        _write(target, _rules(deny=["Bash(command:rm *)"]))
        repo = tmp_path / "repo"
        (repo / ".claude").mkdir(parents=True)
        (repo / ".claude" / "settings.json").symlink_to(target)
        monkeypatch.chdir(tmp_path)
        with patch("mcp_audit.discovery._get_client_specs", return_value=[]):
            result = runner.invoke(
                app, ["scan", "--project", str(repo), "--format", "json"]
            )
        ids = {f["id"] for f in _json_out(result.output)["findings"]}
        assert {"PERM-001", "TRUST-002"} <= ids

    def test_oversized_plugin_manifest_is_not_read(self, tmp_path: Path) -> None:
        manifest = tmp_path / "p" / ".claude-plugin" / "plugin.json"
        manifest.parent.mkdir(parents=True)
        manifest.write_text(
            json.dumps({"name": "x", "pad": "a" * (1024 * 1024)}), encoding="utf-8"
        )
        server = _server("s", tmp_path / "p" / ".mcp.json", client="claude-code-plugin")
        assert perms.claude_code_server_key(server) is None

    def test_many_rules_stay_one_finding_per_severity(
        self, project_settings: Path
    ) -> None:
        deny = [f"Read(file_path:f{i})" for i in range(5000)]
        out = _perm(_rules(deny=deny), project_settings)
        assert _ids(out) == [("PERM-001", Severity.HIGH)]
        assert "(+4980 more)" in out[0].evidence
        assert len(out[0].description) < 10_000  # rule lists are capped everywhere


class TestPerm007AcrossScopes:
    """`scan --project`: a settings file from one scan, a server from the other."""

    _TYPOSQUAT = {
        "command": "npx",
        "args": ["-y", "@modelcontextprotocol/server-githb"],
    }

    def _run(self, home: Path, cwd: Path, project: Path, monkeypatch) -> list[dict]:
        from mcp_audit.discovery import ClientSpec  # noqa: PLC0415

        monkeypatch.setattr(Path, "home", lambda: home)
        monkeypatch.chdir(cwd)
        spec = ClientSpec(
            name="claude-code",
            root_key="mcpServers",
            config_paths=[home / ".claude.json", home / ".claude" / "settings.json"],
        )
        with patch("mcp_audit.discovery._get_client_specs", return_value=[spec]):
            result = runner.invoke(
                app, ["scan", "--project", str(project), "--format", "json"]
            )
        return [
            f for f in _json_out(result.output)["findings"] if f["id"] == "PERM-007"
        ]

    def test_user_settings_allow_on_a_repo_server(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        home, repo, cwd = tmp_path / "home", tmp_path / "repo", tmp_path / "cwd"
        _write(home / ".claude" / "settings.json", _rules(allow=["mcp__gh__*"]))
        _write(repo / ".mcp.json", {"mcpServers": {"gh": self._TYPOSQUAT}})
        cwd.mkdir()
        out = self._run(home, cwd, repo, monkeypatch)
        assert [(f["server"], f["finding_path"]) for f in out] == [
            ("gh", str(home / ".claude" / "settings.json"))
        ]
        assert "SC-001" in out[0]["description"]

    def test_repo_settings_allow_on_a_user_scope_server(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        home, repo, cwd = tmp_path / "home", tmp_path / "repo", tmp_path / "cwd"
        _write(home / ".claude.json", {"mcpServers": {"gh": self._TYPOSQUAT}})
        _write(repo / ".claude" / "settings.json", _rules(allow=["mcp__gh"]))
        cwd.mkdir()
        out = self._run(home, cwd, repo, monkeypatch)
        assert [f["finding_path"] for f in out] == [
            str((repo / ".claude" / "settings.json").resolve())
        ]

    def test_project_dot_adds_no_cross_scope_duplicate(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        home, repo = tmp_path / "home", tmp_path / "repo"
        (home / ".claude").mkdir(parents=True)
        _write(repo / ".mcp.json", {"mcpServers": {"gh": self._TYPOSQUAT}})
        _write(repo / ".claude" / "settings.json", _rules(allow=["mcp__gh__*"]))
        out = self._run(home, repo, repo, monkeypatch)
        # One from the default scan of the cwd and one from the project
        # pipeline (the existing `scan --project .` overlap); none added here.
        assert len(out) == 2

    def test_needs_the_config_hygiene_analyzer(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from mcp_audit.cli.scan import _apply_project_scan  # noqa: PLC0415

        home, repo = tmp_path / "home", tmp_path / "repo"
        _write(home / ".claude" / "settings.json", _rules(allow=["mcp__gh__*"]))
        _write(repo / ".mcp.json", {"mcpServers": {"gh": self._TYPOSQUAT}})
        monkeypatch.setattr(Path, "home", lambda: home)
        analyzers = [
            a
            for a in get_default_analyzers()
            if not isinstance(a, ConfigHygieneAnalyzer)
        ]
        from rich.console import Console  # noqa: PLC0415

        with patch("mcp_audit.discovery._get_client_specs", return_value=[]):
            out = _apply_project_scan(
                ScanResult(), repo.resolve(), analyzers, None, Console(quiet=True)
            )
        assert not [f for f in out.findings if f.id == "PERM-007"]
