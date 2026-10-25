"""Tests for AI agent steps in GitHub Actions workflows (WORKFLOW-001..003).

STORY-0091.  Every fixture is written into ``tmp_path`` so no workflow that
looks vulnerable is ever committed where a self-scan of this repository could
read it.

Covers:
- discovery: ``.github/workflows/*.y{a,}ml`` at the root, nested repository
  roots under ``--project``, skip dirs, symlinks, size cap;
- WORKFLOW-001 per agent action, and the near misses that must stay silent
  (vendor defaults, narrow allowlists, safe triggers, no secret, read-only);
- WORKFLOW-002 (deny list only), WORKFLOW-003 (version floor, workspace
  trust after a pull-request checkout);
- reusable workflows (``workflow_call``) and permission capping;
- malformed, hostile and huge YAML;
- wiring: default scan from the checkout, explicit path, ``scan --project``
  (once, not twice), ``check`` with no MCP config;
- a self-scan of this repository's own workflows.
"""

from __future__ import annotations

import json
import os
import textwrap
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mcp_audit.ci_workflows import discover_workflow_files, scan_workflows
from mcp_audit.ci_workflows import discovery as wf_discovery
from mcp_audit.ci_workflows.analyzer import (
    ATTACKER_TRIGGERS,
    Permissions,
    _cli_flags,
    _secret_refs,
    claude_code_action_posture,
    parse_permissions,
    parse_triggers,
    run_gemini_cli_posture,
)
from mcp_audit.cli import app
from mcp_audit.models import Severity

REPO_ROOT = Path(__file__).resolve().parent.parent
runner = CliRunner()


# ── Fixture helpers ──────────────────────────────────────────────────────────


def _write(root: Path, name: str, body: str) -> Path:
    path = root / ".github" / "workflows" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(body).lstrip(), encoding="utf-8")
    return path


def _ids(root: Path, *, walk: bool = False) -> list[str]:
    return [f.id for f in scan_workflows(root, walk=walk)]


def _claude(
    *,
    on: str = "issue_comment:\n  types: [created]",
    permissions: str | None = "permissions:\n  contents: write\n  issues: write",
    with_extra: str = "",
    auth_line: str = "anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}",
    action: str = "anthropics/claude-code-action@v1",
) -> str:
    """A claude-code-action workflow, indented so textwrap.dedent works."""
    perms = textwrap.indent(permissions, "") + "\n" if permissions else ""
    with_lines = "\n".join(
        "          " + line
        for line in (auth_line + "\n" + with_extra).splitlines()
        if line
    )
    return (
        "on:\n" + textwrap.indent(on, "  ") + "\n" + perms + "jobs:\n"
        "  agent:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        f"      - name: Run agent\n"
        f"        uses: {action}\n"
        "        with:\n" + with_lines + "\n"
    )


def _gemini(
    *,
    on: str = "issues:\n  types: [opened]",
    permissions: str | None = "permissions:\n  issues: write",
    settings: str | None = None,
    ref: str = "v0",
    extra_with: str = "",
    step_env: str = "",
    pre_steps: str = "      - uses: actions/checkout@v4\n",
) -> str:
    perms = permissions + "\n" if permissions else ""
    with_block = "          gemini_api_key: ${{ secrets.GEMINI_API_KEY }}\n"
    if settings is not None:
        with_block += (
            "          settings: |\n" + textwrap.indent(settings, " " * 12) + "\n"
        )
    with_block += extra_with
    env_block = ""
    if step_env:
        env_block = "        env:\n" + textwrap.indent(step_env, " " * 10) + "\n"
    return (
        "on:\n" + textwrap.indent(on, "  ") + "\n" + perms + "jobs:\n"
        "  triage:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        + pre_steps
        + f"      - uses: google-github-actions/run-gemini-cli@{ref}\n"
        + env_block
        + "        with:\n"
        + with_block
    )


_OPEN_BASH = "claude_args: --allowedTools Bash"


# ── Discovery ────────────────────────────────────────────────────────────────


class TestDiscovery:
    def test_finds_yml_and_yaml_only(self, tmp_path: Path) -> None:
        _write(tmp_path, "a.yml", "on: push\n")
        _write(tmp_path, "b.yaml", "on: push\n")
        _write(tmp_path, "notes.md", "# not a workflow\n")
        (tmp_path / ".github" / "workflows" / "sub").mkdir()
        _write(tmp_path / ".github" / "workflows" / "sub", "c.yml", "on: push\n")
        names = sorted(w.path.name for w in discover_workflow_files(tmp_path))
        assert names == ["a.yml", "b.yaml"]

    def test_missing_dir_and_non_dir_root(self, tmp_path: Path) -> None:
        assert discover_workflow_files(tmp_path) == []
        file_root = tmp_path / "file.txt"
        file_root.write_text("x", encoding="utf-8")
        assert discover_workflow_files(file_root) == []

    def test_paths_are_resolved_and_relative_path_is_posix(
        self, tmp_path: Path
    ) -> None:
        _write(tmp_path, "a.yml", "on: push\n")
        (wf,) = discover_workflow_files(tmp_path / "." / ".")
        assert wf.path.is_absolute()
        assert wf.rel_path == ".github/workflows/a.yml"

    def test_default_scan_does_not_walk_nested_repos(self, tmp_path: Path) -> None:
        nested = tmp_path / "other"
        (nested / ".git").mkdir(parents=True)
        _write(nested, "a.yml", "on: push\n")
        assert discover_workflow_files(tmp_path) == []
        assert [w.repo_root for w in discover_workflow_files(tmp_path, walk=True)] == [
            nested.resolve()
        ]

    def test_walk_reads_submodule_roots_but_not_vendored_copies(
        self, tmp_path: Path
    ) -> None:
        submodule = tmp_path / "libs" / "sub"
        submodule.mkdir(parents=True)
        (submodule / ".git").write_text("gitdir: ../../.git/modules/sub\n")
        _write(submodule, "sub.yml", "on: push\n")
        vendored = tmp_path / "third_party" / "copy"
        _write(vendored, "vendored.yml", "on: push\n")
        names = [w.path.name for w in discover_workflow_files(tmp_path, walk=True)]
        assert names == ["sub.yml"]

    def test_walk_skips_node_modules_and_symlinked_dirs(self, tmp_path: Path) -> None:
        nm = tmp_path / "node_modules" / "pkg"
        (nm / ".git").mkdir(parents=True)
        _write(nm, "a.yml", "on: push\n")
        real = tmp_path.parent / f"{tmp_path.name}-outside"
        (real / ".git").mkdir(parents=True)
        _write(real, "b.yml", "on: push\n")
        try:
            (tmp_path / "linked").symlink_to(real, target_is_directory=True)
        except (OSError, NotImplementedError):
            pytest.skip("symlinks not available")
        assert discover_workflow_files(tmp_path, walk=True) == []

    def test_symlinked_file_inside_root_is_read_outside_is_not(
        self, tmp_path: Path
    ) -> None:
        target_in = tmp_path / "shared" / "agent.yml"
        target_in.parent.mkdir()
        target_in.write_text("on: push\n", encoding="utf-8")
        outside = tmp_path.parent / f"{tmp_path.name}-x.yml"
        outside.write_text("on: push\n", encoding="utf-8")
        wf_dir = tmp_path / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        try:
            (wf_dir / "in.yml").symlink_to(target_in)
            (wf_dir / "out.yml").symlink_to(outside)
            (wf_dir / "broken.yml").symlink_to(tmp_path / "missing.yml")
        except (OSError, NotImplementedError):
            pytest.skip("symlinks not available")
        assert [w.path.name for w in discover_workflow_files(tmp_path)] == ["in.yml"]

    def test_oversized_file_is_skipped(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _write(tmp_path, "big.yml", "on: push\n" + "# pad\n" * 100)
        monkeypatch.setattr(wf_discovery, "MAX_WORKFLOW_BYTES", 64)
        assert discover_workflow_files(tmp_path) == []

    def test_unicode_and_spaces_in_path(self, tmp_path: Path) -> None:
        root = tmp_path / "my repo ü"
        _write(root, "claude.yml", _claude(with_extra=_OPEN_BASH))
        assert _ids(root) == ["WORKFLOW-001"]


# ── Parsing helpers ──────────────────────────────────────────────────────────


class TestParsing:
    def test_on_key_parsed_as_true_by_yaml_1_1(self) -> None:
        import yaml

        doc = yaml.safe_load("on:\n  issues: {}\n")
        assert True in doc
        assert parse_triggers(doc) == frozenset({"issues"})

    def test_trigger_shapes(self) -> None:
        assert parse_triggers({"on": "issues"}) == {"issues"}
        assert parse_triggers({"on": ["push", "issue_comment"]}) == {
            "push",
            "issue_comment",
        }
        assert parse_triggers({True: {"discussion": None}}) == {"discussion"}
        assert parse_triggers({"on": 3}) == frozenset()
        assert parse_triggers({}) == frozenset()

    def test_attacker_triggers_exclude_pull_request_and_push(self) -> None:
        assert "pull_request" not in ATTACKER_TRIGGERS
        assert "push" not in ATTACKER_TRIGGERS
        assert "pull_request_target" in ATTACKER_TRIGGERS

    def test_permissions(self) -> None:
        assert parse_permissions("write-all").can_write
        assert not parse_permissions("read-all").can_write
        assert not parse_permissions({}).can_write
        assert parse_permissions({"id-token": "write"}).write_scopes == ("id-token",)
        assert not parse_permissions({"contents": "read", "issues": "none"}).can_write
        assert Permissions(declared=False).can_write
        assert "may include write" in Permissions(declared=False).describe()

    def test_secret_refs(self) -> None:
        texts = [
            "${{ secrets.ANTHROPIC_API_KEY }}",
            "${{ secrets['MY-KEY'] }}",
            "${{ github.token }}",
            "${{ toJSON(secrets) }}",
            "Bearer ${{ secrets.GITHUB_TOKEN }} and plain secrets text",
            "${{ vars.NOT_A_SECRET }}",
        ]
        assert _secret_refs(texts) == {
            "ANTHROPIC_API_KEY",
            "MY-KEY",
            "github.token",
            "the whole secrets context",
            "GITHUB_TOKEN",
        }

    def test_cli_flags(self) -> None:
        flags = _cli_flags(
            '--max-turns 5 --allowedTools "Bash(git log:*)" Read,Edit '
            "--disallowed-tools=WebSearch --permission-mode bypassPermissions"
        )
        assert flags.allowed == ["Bash(git log:*)", "Read", "Edit"]
        assert flags.disallowed == ["WebSearch"]
        assert flags.bypass == ["--permission-mode bypassPermissions"]
        assert _cli_flags("--permission-mode=bypassPermissions").bypass
        assert _cli_flags("--dangerously-skip-permissions").bypass
        assert not _cli_flags("--permission-mode plan").bypass
        # Unbalanced quotes fall back to whitespace splitting, no exception.
        assert _cli_flags('--allowedTools "Bash').allowed == ["Bash"]

    def test_unquoted_rule_with_space_is_rejoined(self) -> None:
        assert _cli_flags("--allowedTools Bash(git log:*) Read").allowed == [
            "Bash(git log:*)",
            "Read",
        ]


# ── WORKFLOW-001: claude-code-action ─────────────────────────────────────────


class TestClaudeCodeAction:
    @pytest.mark.parametrize(
        "extra",
        [
            "claude_args: --allowedTools Bash",
            'claude_args: --allowedTools "Bash(*)"',
            "claude_args: --dangerously-skip-permissions",
            "claude_args: --permission-mode bypassPermissions",
            'claude_args: --allowed-tools "Bash(cat:*)"',
            'claude_args: --allowedTools "Bash(python3:*),Read"',
            'allowed_tools: "Bash(curl:*),View"',
            'settings: \'{"permissions": {"allow": ["Bash"]}}\'',
            'settings: \'{"permissions": {"defaultMode": "bypassPermissions"}}\'',
        ],
    )
    def test_opened_tools_fire(self, tmp_path: Path, extra: str) -> None:
        _write(tmp_path, "claude.yml", _claude(with_extra=extra))
        (finding,) = scan_workflows(tmp_path)
        assert finding.id == "WORKFLOW-001"
        assert finding.severity == Severity.HIGH
        assert finding.analyzer == "ci_workflow"
        assert finding.client == "github-actions"
        assert finding.server == "agent"
        assert finding.tool == "step 2 (Run agent)"
        assert finding.finding_path == str(
            (tmp_path / ".github/workflows/claude.yml").resolve()
        )
        assert "ANTHROPIC_API_KEY" in finding.description
        assert "contents: write" in finding.description
        assert finding.owasp_mcp_top_10 == ["MCP06", "MCP01"]

    @pytest.mark.parametrize(
        "extra",
        [
            "",  # the vendor default: no arbitrary Bash
            'claude_args: --allowedTools "Bash(gh issue view:*)" Read',
            "claude_args: --max-turns 5 --permission-mode plan",
            'claude_args: --disallowedTools "Bash(ps:*)"',
            "settings: ./ci/claude-settings.json",
        ],
    )
    def test_default_and_narrow_tools_stay_silent(
        self, tmp_path: Path, extra: str
    ) -> None:
        _write(tmp_path, "claude.yml", _claude(with_extra=extra))
        assert _ids(tmp_path) == []

    def test_allowed_non_write_users_is_named(self, tmp_path: Path) -> None:
        _write(
            tmp_path,
            "claude.yml",
            _claude(with_extra=_OPEN_BASH + '\nallowed_non_write_users: "*"'),
        )
        (finding,) = scan_workflows(tmp_path)
        assert "allowed_non_write_users is set (*)" in finding.description

    def test_absent_permissions_count_as_possibly_write(self, tmp_path: Path) -> None:
        _write(
            tmp_path,
            "claude.yml",
            _claude(permissions=None, with_extra="claude_args: --allowedTools Bash"),
        )
        (finding,) = scan_workflows(tmp_path)
        assert "may include write" in finding.description
        assert "none declared" in finding.evidence

    def test_subdirectory_action_does_not_match(self, tmp_path: Path) -> None:
        _write(
            tmp_path,
            "claude.yml",
            _claude(
                action="anthropics/claude-code-action/other@v1",
                with_extra="claude_args: --allowedTools Bash",
            ),
        )
        assert _ids(tmp_path) == []

    def test_owner_repo_match_is_case_insensitive(self, tmp_path: Path) -> None:
        _write(
            tmp_path,
            "claude.yml",
            _claude(
                action="Anthropics/Claude-Code-Action@v1",
                with_extra="claude_args: --allowedTools Bash",
            ),
        )
        assert _ids(tmp_path) == ["WORKFLOW-001"]

    def test_posture_function_reports_default_as_allowlist(self) -> None:
        assert claude_code_action_posture({}).kind == "allowlist"


# ── Conditions shared by every agent ─────────────────────────────────────────


class TestConditions:
    _OPEN = _OPEN_BASH

    @pytest.mark.parametrize(
        "on",
        [
            "issues:\n  types: [opened]",
            "issue_comment: {}",
            "pull_request_target:\n  types: [opened]",
            "pull_request_review: {}",
            "pull_request_review_comment: {}",
            "discussion: {}",
            "discussion_comment: {}",
        ],
    )
    def test_attacker_triggers_fire(self, tmp_path: Path, on: str) -> None:
        _write(tmp_path, "w.yml", _claude(on=on, with_extra=self._OPEN))
        assert _ids(tmp_path) == ["WORKFLOW-001"]

    @pytest.mark.parametrize(
        "on",
        [
            "push: {}",
            "pull_request: {}",
            "workflow_dispatch: {}",
            "schedule:\n  - cron: '0 0 * * *'",
        ],
    )
    def test_other_triggers_stay_silent(self, tmp_path: Path, on: str) -> None:
        _write(tmp_path, "w.yml", _claude(on=on, with_extra=self._OPEN))
        assert _ids(tmp_path) == []

    def test_review_trigger_text_notes_fork_secret_rule(self, tmp_path: Path) -> None:
        _write(
            tmp_path,
            "w.yml",
            _claude(on="pull_request_review_comment: {}", with_extra=self._OPEN),
        )
        (finding,) = scan_workflows(tmp_path)
        assert "withholds secrets for pull requests from forks" in finding.description

    def test_no_secret_stays_silent(self, tmp_path: Path) -> None:
        _write(
            tmp_path,
            "w.yml",
            _claude(auth_line="use_bedrock: 'true'", with_extra=self._OPEN),
        )
        assert _ids(tmp_path) == []

    def test_github_token_counts_as_a_secret(self, tmp_path: Path) -> None:
        _write(
            tmp_path,
            "w.yml",
            _claude(
                auth_line="github_token: ${{ github.token }}", with_extra=self._OPEN
            ),
        )
        (finding,) = scan_workflows(tmp_path)
        assert "github.token" in finding.description

    def test_secret_in_job_or_workflow_env_counts(self, tmp_path: Path) -> None:
        body = """
            on: issues
            permissions: write-all
            env:
              ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
            jobs:
              agent:
                runs-on: ubuntu-latest
                env:
                  GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
                steps:
                  - uses: anthropics/claude-code-action@v1
                    with:
                      claude_args: --dangerously-skip-permissions
        """
        _write(tmp_path, "w.yml", body)
        (finding,) = scan_workflows(tmp_path)
        assert "ANTHROPIC_API_KEY, GITHUB_TOKEN" in finding.description
        assert "permissions: write-all" in finding.description

    def test_secret_only_in_another_step_stays_silent(self, tmp_path: Path) -> None:
        body = """
            on: issues
            permissions: write-all
            jobs:
              agent:
                runs-on: ubuntu-latest
                steps:
                  - run: echo hi
                    env:
                      TOKEN: ${{ secrets.DEPLOY_TOKEN }}
                  - uses: anthropics/claude-code-action@v1
                    with:
                      claude_args: --dangerously-skip-permissions
        """
        _write(tmp_path, "w.yml", body)
        assert _ids(tmp_path) == []

    @pytest.mark.parametrize(
        ("permissions", "fires"),
        [
            ("permissions: read-all", False),
            ("permissions: {}", False),
            ("permissions:\n  contents: read\n  issues: read", False),
            ("permissions: write-all", True),
            ("permissions:\n  id-token: write", True),
        ],
    )
    def test_permission_shapes(
        self, tmp_path: Path, permissions: str, fires: bool
    ) -> None:
        _write(
            tmp_path, "w.yml", _claude(permissions=permissions, with_extra=self._OPEN)
        )
        assert _ids(tmp_path) == (["WORKFLOW-001"] if fires else [])

    def test_job_permissions_override_workflow_permissions(
        self, tmp_path: Path
    ) -> None:
        body = """
            on: issues
            permissions: write-all
            jobs:
              agent:
                runs-on: ubuntu-latest
                permissions:
                  contents: read
                steps:
                  - uses: anthropics/claude-code-action@v1
                    with:
                      anthropic_api_key: ${{ secrets.KEY }}
                      claude_args: --dangerously-skip-permissions
        """
        _write(tmp_path, "w.yml", body)
        assert _ids(tmp_path) == []


# ── WORKFLOW-001: the other two actions ──────────────────────────────────────


class TestSecurityReviewAndGemini:
    def test_security_review_on_pull_request_target_fires(self, tmp_path: Path) -> None:
        body = """
            on:
              pull_request_target:
            permissions:
              pull-requests: write
              contents: read
            jobs:
              security:
                runs-on: ubuntu-latest
                steps:
                  - uses: anthropics/claude-code-security-review@main
                    with:
                      claude-api-key: ${{ secrets.CLAUDE_API_KEY }}
        """
        _write(tmp_path, "sec.yml", body)
        (finding,) = scan_workflows(tmp_path)
        assert finding.id == "WORKFLOW-001"
        assert "not hardened against prompt injection" in finding.description
        assert "pull_request," in finding.remediation

    def test_security_review_on_pull_request_stays_silent(self, tmp_path: Path) -> None:
        body = """
            on:
              pull_request:
            permissions:
              pull-requests: write
            jobs:
              security:
                runs-on: ubuntu-latest
                steps:
                  - uses: anthropics/claude-code-security-review@main
                    with:
                      claude-api-key: ${{ secrets.CLAUDE_API_KEY }}
        """
        _write(tmp_path, "sec.yml", body)
        assert _ids(tmp_path) == []

    def test_gemini_without_settings_fires(self, tmp_path: Path) -> None:
        _write(tmp_path, "g.yml", _gemini())
        (finding,) = scan_workflows(tmp_path)
        assert finding.id == "WORKFLOW-001"
        assert "gemini --yolo" in finding.description

    @pytest.mark.parametrize(
        "settings",
        [
            '{"tools": {"core": []}}',
            '{"tools": {"core": ["run_shell_command(gh issue view)", "read_file"]}}',
            '{"coreTools": ["run_shell_command(echo)"]}',
            '{"security": {"disableYoloMode": true}}',
            '{"model": {"maxSessionTurns": ${{ vars.TURNS }}}, "tools": {"core": []}}',
            "not json at all",
        ],
    )
    def test_gemini_allowlists_and_unreadable_settings_stay_silent(
        self, tmp_path: Path, settings: str
    ) -> None:
        _write(tmp_path, "g.yml", _gemini(settings=settings))
        assert _ids(tmp_path) == []

    @pytest.mark.parametrize(
        "core", ['["run_shell_command"]', '["run_shell_command(cat)"]', '["ShellTool"]']
    )
    def test_gemini_broad_shell_in_core_fires(self, tmp_path: Path, core: str) -> None:
        _write(tmp_path, "g.yml", _gemini(settings='{"tools": {"core": ' + core + "}}"))
        assert _ids(tmp_path) == ["WORKFLOW-001"]

    def test_gemini_posture_unknown_for_non_json(self) -> None:
        assert run_gemini_cli_posture({"settings": "./settings.json"}).kind == "unknown"


# ── WORKFLOW-002 ─────────────────────────────────────────────────────────────


class TestBlocklistOnly:
    def test_claude_deny_list_on_open_shell(self, tmp_path: Path) -> None:
        _write(
            tmp_path,
            "w.yml",
            _claude(with_extra=_OPEN_BASH + ' --disallowedTools "Bash(ps:*)"'),
        )
        (finding,) = scan_workflows(tmp_path)
        assert finding.id == "WORKFLOW-002"
        assert finding.severity == Severity.MEDIUM
        assert "Bash(ps:*)" in finding.description
        assert "/proc/*/environ" in finding.description

    def test_gemini_exclude_only(self, tmp_path: Path) -> None:
        _write(
            tmp_path,
            "g.yml",
            _gemini(settings='{"tools": {"exclude": ["run_shell_command(ps)"]}}'),
        )
        assert _ids(tmp_path) == ["WORKFLOW-002"]

    def test_gemini_allowlist_plus_exclude_stays_silent(self, tmp_path: Path) -> None:
        _write(
            tmp_path,
            "g.yml",
            _gemini(settings='{"tools": {"core": [], "exclude": ["web_fetch"]}}'),
        )
        assert _ids(tmp_path) == []


# ── WORKFLOW-003 ─────────────────────────────────────────────────────────────

_SAFE_SETTINGS = '{"tools": {"core": []}}'


class TestGeminiFloorAndTrust:
    @pytest.mark.parametrize("ref", ["v0.1.21", "0.1.9", "v0.0.5"])
    def test_action_below_floor_fires(self, tmp_path: Path, ref: str) -> None:
        _write(tmp_path, "g.yml", _gemini(settings=_SAFE_SETTINGS, ref=ref))
        (finding,) = scan_workflows(tmp_path)
        assert finding.id == "WORKFLOW-003"
        assert finding.severity == Severity.HIGH
        assert finding.cwe == "CWE-1395"
        assert ref in finding.description

    @pytest.mark.parametrize(
        "ref", ["v0.1.22", "v0.2.0", "v0", "v0.1", "main", "a" * 40]
    )
    def test_fixed_floating_or_sha_refs_stay_silent(
        self, tmp_path: Path, ref: str
    ) -> None:
        _write(tmp_path, "g.yml", _gemini(settings=_SAFE_SETTINGS, ref=ref))
        assert _ids(tmp_path) == []

    @pytest.mark.parametrize(
        ("version", "fires"),
        [
            ("0.39.0", True),
            ("0.38.2", True),
            ("0.40.0-preview.2", True),
            ("0.39.1", False),
            ("0.40.0-preview.3", False),
            ("0.40.0", False),
            ("latest", False),
            ("${{ vars.GEMINI_CLI_VERSION }}", False),
        ],
    )
    def test_cli_version_floor(self, tmp_path: Path, version: str, fires: bool) -> None:
        _write(
            tmp_path,
            "g.yml",
            _gemini(
                settings=_SAFE_SETTINGS,
                extra_with=f"          gemini_cli_version: '{version}'\n",
            ),
        )
        assert _ids(tmp_path) == (["WORKFLOW-003"] if fires else [])

    def test_trust_after_pr_head_checkout_fires(self, tmp_path: Path) -> None:
        pre = (
            "      - uses: actions/checkout@v4\n"
            "        with:\n"
            "          ref: ${{ github.event.pull_request.head.sha }}\n"
        )
        _write(
            tmp_path,
            "g.yml",
            _gemini(
                on="pull_request_target: {}",
                settings=_SAFE_SETTINGS,
                step_env="GEMINI_CLI_TRUST_WORKSPACE: 'true'",
                pre_steps=pre,
            ),
        )
        (finding,) = scan_workflows(tmp_path)
        assert finding.id == "WORKFLOW-003"
        assert finding.cwe == "CWE-829"
        assert "GEMINI_CLI_TRUST_WORKSPACE=true (step env)" in finding.description

    def test_trust_with_gh_pr_checkout_and_legacy_name_fires(
        self, tmp_path: Path
    ) -> None:
        pre = (
            "      - uses: actions/checkout@v4\n"
            "      - run: gh pr checkout ${{ github.event.issue.number }}\n"
        )
        body = _gemini(on="issue_comment: {}", settings=_SAFE_SETTINGS, pre_steps=pre)
        job_env = "    env:\n      GEMINI_TRUST_WORKSPACE: true\n"
        body = body.replace("jobs:\n  triage:\n", "jobs:\n  triage:\n" + job_env)
        _write(tmp_path, "g.yml", body)
        (finding,) = scan_workflows(tmp_path)
        assert "GEMINI_TRUST_WORKSPACE=true (job env)" in finding.description

    def test_trust_on_default_branch_checkout_stays_silent(
        self, tmp_path: Path
    ) -> None:
        """Google's own triage/review examples trust a default-branch workspace."""
        _write(
            tmp_path,
            "g.yml",
            _gemini(
                settings=_SAFE_SETTINGS,
                step_env="GEMINI_CLI_TRUST_WORKSPACE: 'true'\nGITHUB_TOKEN: ''",
            ),
        )
        assert _ids(tmp_path) == []

    def test_old_version_on_push_stays_silent(self, tmp_path: Path) -> None:
        _write(tmp_path, "g.yml", _gemini(on="push: {}", ref="v0.1.10"))
        assert _ids(tmp_path) == []

    def test_old_version_and_no_allowlist_report_both(self, tmp_path: Path) -> None:
        _write(tmp_path, "g.yml", _gemini(ref="v0.1.21"))
        assert _ids(tmp_path) == ["WORKFLOW-001", "WORKFLOW-003"]


# ── Reusable workflows ───────────────────────────────────────────────────────

_CALLEE = """
    on:
      workflow_call:
    jobs:
      run:
        runs-on: ubuntu-latest
        steps:
          - uses: anthropics/claude-code-action@v1
            with:
              anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
              claude_args: --allowedTools Bash
"""


class TestReusableWorkflows:
    def test_callee_takes_caller_triggers(self, tmp_path: Path) -> None:
        _write(tmp_path, "agent.yml", _CALLEE)
        _write(
            tmp_path,
            "dispatch.yml",
            """
            on:
              issue_comment:
            jobs:
              call:
                permissions:
                  contents: write
                uses: ./.github/workflows/agent.yml
                secrets: inherit
            """,
        )
        (finding,) = scan_workflows(tmp_path)
        assert finding.id == "WORKFLOW-001"
        assert finding.finding_path.endswith("agent.yml")
        assert "called through workflow_call from .github/workflows/dispatch.yml" in (
            finding.description
        )
        assert "contents: write" in finding.description

    def test_chain_of_calls_keeps_outer_trigger(self, tmp_path: Path) -> None:
        _write(tmp_path, "agent.yml", _CALLEE)
        _write(
            tmp_path,
            "middle.yml",
            """
            on: workflow_call
            jobs:
              call:
                uses: ./.github/workflows/agent.yml
            """,
        )
        _write(
            tmp_path,
            "outer.yml",
            """
            on: issues
            jobs:
              call:
                uses: ./.github/workflows/middle.yml
            """,
        )
        assert _ids(tmp_path) == ["WORKFLOW-001"]

    def test_callee_with_no_local_caller_stays_silent(self, tmp_path: Path) -> None:
        _write(tmp_path, "agent.yml", _CALLEE)
        assert _ids(tmp_path) == []

    def test_caller_on_push_stays_silent(self, tmp_path: Path) -> None:
        _write(tmp_path, "agent.yml", _CALLEE)
        _write(
            tmp_path,
            "dispatch.yml",
            """
            on: push
            jobs:
              call:
                uses: ./.github/workflows/agent.yml
            """,
        )
        assert _ids(tmp_path) == []

    def test_callee_write_capped_by_read_only_caller(self, tmp_path: Path) -> None:
        perms = "        permissions:\n          issues: write\n"
        callee = _CALLEE.replace("      run:\n", "      run:\n" + perms)
        _write(tmp_path, "agent.yml", callee)
        _write(
            tmp_path,
            "dispatch.yml",
            """
            on: issues
            jobs:
              call:
                permissions:
                  contents: read
                uses: ./.github/workflows/agent.yml
            """,
        )
        assert _ids(tmp_path) == []


# ── Malformed and hostile input ──────────────────────────────────────────────


class TestHostileInput:
    def test_malformed_yaml_is_skipped(self, tmp_path: Path) -> None:
        _write(tmp_path, "bad.yml", "on: [issues\njobs: {\n")
        _write(tmp_path, "list.yml", "- just\n- a list\n")
        _write(tmp_path, "empty.yml", "")
        _write(tmp_path, "claude.yml", _claude(with_extra=_OPEN_BASH))
        assert _ids(tmp_path) == ["WORKFLOW-001"]

    def test_python_tags_are_never_constructed(self, tmp_path: Path) -> None:
        marker = tmp_path / "pwned"
        _write(
            tmp_path,
            "evil.yml",
            f"on: !!python/object/apply:os.system ['touch {marker}']\n",
        )
        assert _ids(tmp_path) == []
        assert not marker.exists()

    def test_deep_nesting_does_not_crash(self, tmp_path: Path) -> None:
        _write(tmp_path, "deep.yml", "on: " + "[" * 5000 + "]" * 5000 + "\n")
        assert _ids(tmp_path) == []

    def test_alias_bomb_is_bounded(self, tmp_path: Path) -> None:
        lines = ['a0: &a0 ["x", "x", "x", "x", "x", "x", "x", "x"]']
        for i in range(1, 12):
            prev = f"*a{i - 1}"
            lines.append(f"a{i}: &a{i} [{', '.join([prev] * 8)}]")
        lines.append("on: issues")
        lines.append("jobs:\n  j:\n    steps: *a11")
        _write(tmp_path, "bomb.yml", "\n".join(lines) + "\n")
        assert _ids(tmp_path) == []

    def test_non_utf8_file_is_skipped(self, tmp_path: Path) -> None:
        path = tmp_path / ".github" / "workflows" / "latin1.yml"
        path.parent.mkdir(parents=True)
        path.write_bytes(b"on: issues\nname: caf\xe9\n")
        assert _ids(tmp_path) == []

    def test_one_failing_file_does_not_hide_another(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from mcp_audit.ci_workflows import analyzer

        _write(tmp_path, "a.yml", _claude(with_extra=_OPEN_BASH))
        _write(tmp_path, "b.yml", _claude(with_extra=_OPEN_BASH))
        real = analyzer._analyze_step

        def flaky(ctx):  # type: ignore[no-untyped-def]
            if ctx.workflow.file.path.name == "a.yml":
                raise RuntimeError("boom")
            return real(ctx)

        monkeypatch.setattr(analyzer, "_analyze_step", flaky)
        findings = scan_workflows(tmp_path)
        assert [Path(f.finding_path).name for f in findings] == ["b.yml"]

    def test_file_grown_past_cap_after_discovery_is_not_parsed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from mcp_audit.ci_workflows import analyze_workflow_files

        _write(tmp_path, "a.yml", _claude(with_extra=_OPEN_BASH))
        files = discover_workflow_files(tmp_path)
        monkeypatch.setattr(wf_discovery, "MAX_WORKFLOW_BYTES", 16)
        assert analyze_workflow_files(files) == []

    def test_odd_shapes_do_not_crash(self, tmp_path: Path) -> None:
        body = """
            on: issues
            permissions: 7
            jobs:
              a: just-a-string
              b:
                steps: not-a-list
              c:
                steps:
                  - 42
                  - uses: 99
                  - uses: anthropics/claude-code-action@v1
                    with: a-string
                    env: [1, 2]
        """
        _write(tmp_path, "odd.yml", body)
        assert _ids(tmp_path) == []


# ── Wiring ───────────────────────────────────────────────────────────────────


def _vulnerable_repo(root: Path) -> Path:
    return _write(root, "claude.yml", _claude(with_extra=_OPEN_BASH))


class TestWiring:
    @pytest.fixture(autouse=True)
    def _no_client_configs_or_state(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No machine MCP configs, and rug-pull state kept under tmp_path."""
        monkeypatch.setattr("mcp_audit.discovery._get_client_specs", lambda: [])
        monkeypatch.setattr(
            "mcp_audit.scanner.derive_state_path",
            lambda _configs: tmp_path / "rug-pull-state.json",
        )

    def test_default_scan_from_checkout_reports_workflow(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from mcp_audit.scanner import run_scan

        _vulnerable_repo(tmp_path)
        monkeypatch.chdir(tmp_path)
        result = run_scan(skip_rug_pull=True, include_plugins=False)
        assert [f.id for f in result.findings] == ["WORKFLOW-001"]
        # The finding is in the scored set, like plugin findings.
        assert any("high" in d for d in result.score.deductions)

    def test_explicit_path_does_not_read_cwd_workflows(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from mcp_audit.scanner import run_scan

        _vulnerable_repo(tmp_path)
        config = tmp_path / "mcp.json"
        config.write_text(json.dumps({"mcpServers": {}}), encoding="utf-8")
        monkeypatch.chdir(tmp_path)
        result = run_scan(extra_paths=[config], skip_rug_pull=True)
        assert not [f for f in result.findings if f.id.startswith("WORKFLOW-")]

    def test_scan_project_reports_once_when_cwd_is_project(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _vulnerable_repo(tmp_path)
        monkeypatch.chdir(tmp_path)
        r = runner.invoke(
            app,
            [
                "scan",
                "--project",
                str(tmp_path),
                "--format",
                "json",
                "--no-plugins",
            ],
        )
        assert r.exit_code == 1, r.output
        data = json.loads(r.output[r.output.index("{") :])
        ids = [f["id"] for f in data["findings"]]
        assert ids.count("WORKFLOW-001") == 1

    def test_scan_project_reads_nested_repo(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        project = tmp_path / "work"
        nested = project / "service"
        (nested / ".git").mkdir(parents=True)
        _vulnerable_repo(nested)
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        monkeypatch.chdir(elsewhere)
        r = runner.invoke(
            app,
            ["scan", "--project", str(project), "--format", "json", "--no-plugins"],
        )
        data = json.loads(r.output[r.output.index("{") :])
        assert [f["id"] for f in data["findings"]] == ["WORKFLOW-001"]

    def test_check_with_no_mcp_config_still_reports_workflow(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _vulnerable_repo(tmp_path)
        monkeypatch.chdir(tmp_path)
        r = runner.invoke(app, ["check"])
        assert r.exit_code == 1, r.output
        assert "No MCP config files found" not in r.output
        assert "CI agent runs on text a stranger can write" in r.output

    def test_sarif_output_includes_workflow_rule(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _vulnerable_repo(tmp_path)
        monkeypatch.chdir(tmp_path)
        out = tmp_path / "out.sarif"
        r = runner.invoke(
            app, ["scan", "--format", "sarif", "-o", str(out), "--no-plugins"]
        )
        assert r.exit_code == 1, r.output
        sarif = json.loads(out.read_text(encoding="utf-8"))
        rule_ids = [rule["id"] for rule in sarif["runs"][0]["tool"]["driver"]["rules"]]
        assert "WORKFLOW-001" in rule_ids

    def test_changed_file_is_re_read(self, tmp_path: Path) -> None:
        path = _vulnerable_repo(tmp_path)
        assert _ids(tmp_path) == ["WORKFLOW-001"]
        text = path.read_text(encoding="utf-8")
        path.write_text(text.replace("issue_comment", "push"), encoding="utf-8")
        stat = path.stat()
        os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns + 1_000_000_000))
        assert _ids(tmp_path) == []


# ── This repository ──────────────────────────────────────────────────────────


def test_own_workflows_produce_no_workflow_findings() -> None:
    """mcp-audit's own CI runs no agent action; a self-scan must stay quiet."""
    assert discover_workflow_files(REPO_ROOT)  # the directory is really read
    assert scan_workflows(REPO_ROOT, walk=True) == []
