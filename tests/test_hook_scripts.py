"""HOOK-003: hook commands that run a file the repository ships (STORY-0138)."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from mcp_audit.analyzers.config_hygiene import ConfigHygieneAnalyzer
from mcp_audit.analyzers.hook_scripts import find_project_script, split_simple_commands
from mcp_audit.models import Severity

# ── The matcher ───────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        # The two research shapes (JFrog testmetest, SafeDep Miasma variant).
        ("node .github/init.js", ".github/init.js"),
        ("node .vscode/setup.mjs", ".vscode/setup.mjs"),
        # Relative paths, direct and through interpreters.
        ("./scripts/x.sh", "./scripts/x.sh"),
        ("scripts/x.sh --flag", "scripts/x.sh"),
        ("bash ./scripts/x.sh", "./scripts/x.sh"),
        ("sh scripts/x.sh", "scripts/x.sh"),
        ("zsh -x scripts/a.sh", "scripts/a.sh"),
        ("bash -e ./a.sh", "./a.sh"),
        ("python3 tools/a.py", "tools/a.py"),
        ("python3.11 init.py", "init.py"),
        ("ruby bin/setup.rb", "bin/setup.rb"),
        ("perl hooks/a.pl", "hooks/a.pl"),
        ("bun run scripts/a.ts", "scripts/a.ts"),
        ("deno run --allow-all ./a.ts", "./a.ts"),
        ("pwsh -NoProfile -File .\\a.ps1", ".\\a.ps1"),
        ("powershell -ExecutionPolicy Bypass -File scripts\\a.ps1", "scripts\\a.ps1"),
        ("node .github\\init.js", ".github\\init.js"),
        # $CLAUDE_PROJECT_DIR in every spelling and quoting.
        (
            'python "$CLAUDE_PROJECT_DIR/.claude/hooks/a.py"',
            "$CLAUDE_PROJECT_DIR/.claude/hooks/a.py",
        ),
        (
            "${CLAUDE_PROJECT_DIR}/.claude/hooks/check-style.sh",
            "${CLAUDE_PROJECT_DIR}/.claude/hooks/check-style.sh",
        ),
        (
            '"${CLAUDE_PROJECT_DIR}"/.claude/hooks/a.sh',
            "${CLAUDE_PROJECT_DIR}/.claude/hooks/a.sh",
        ),
        (
            "bash '$CLAUDE_PROJECT_DIR/.claude/hooks/a.sh'",
            "$CLAUDE_PROJECT_DIR/.claude/hooks/a.sh",
        ),
        ("node %CLAUDE_PROJECT_DIR%\\a.js", "%CLAUDE_PROJECT_DIR%\\a.js"),
        # Wrappers, launchers, assignments, preloads, nested shells, chains.
        ("FOO=1 node init.js", "init.js"),
        ("env NODE_ENV=x node init.js", "init.js"),
        ("npx tsx scripts/x.ts", "scripts/x.ts"),
        ("npx -y ts-node scripts/x.ts", "scripts/x.ts"),
        ("npx ./local.js", "./local.js"),
        ("uv run python tools/a.py", "tools/a.py"),
        ("node -r ./pre.js /usr/lib/a.js", "./pre.js"),
        ("node --require=./pre.js /usr/lib/a.js", "./pre.js"),
        ('bash -c "node .github/init.js"', ".github/init.js"),
        ('sh -lc "./a.sh"', "./a.sh"),
        ("echo start && node .vscode/setup.mjs", ".vscode/setup.mjs"),
        ("echo hi; python3 a.py | tee out", "a.py"),
        ("source ./env.sh", "./env.sh"),
    ],
)
def test_project_script_is_found(command: str, expected: str) -> None:
    assert find_project_script(command) == expected


@pytest.mark.parametrize(
    "command",
    [
        "/usr/bin/say hello",
        "afplay /System/Library/Sounds/Glass.aiff",
        "npx prettier --write .",
        "npx -y @scope/pkg --flag",
        "echo hello",
        "git status",
        "git diff --name-only",
        "cat ./README.md",
        "prettier --write $CLAUDE_PROJECT_DIR/src",
        "jq . ./package.json",
        "notify-send done",
        "",
        "   ",
        "python3 ~/bin/a.py",
        "node /opt/tools/a.js",
        "node $HOME/a.js",
        "node -e \"require('./x')\"",
        "python -m pytest tests/",
        "python -c 'print(1)'",
        "bash -c 'echo hi'",
        "bun run build",
        "node ../outside.js",
        "node https://example.com/a.js",
        "deno run https://example.com/a.ts",
        "echo ./not-run.sh",
        "./",
        "bash",
        "pwsh -Command Get-Date",
        # Found in a real settings file: a redirection after a subshell.
        "echo $(git diff --name-only) 2>/dev/null",
        # Found in a real settings file: a case pattern, not a command.
        'case "$CMD" in *grep*|*rg\\ *|*find\\ *) echo hit ;; esac',
    ],
)
def test_other_commands_are_not_found(command: str) -> None:
    assert find_project_script(command) is None


def test_quoted_separators_do_not_split() -> None:
    assert split_simple_commands("echo 'a; b' && node x.js") == [
        ["echo", "a; b"],
        ["node", "x.js"],
    ]
    assert find_project_script("echo 'a && node .github/init.js'") is None


def test_unclosed_quote_does_not_raise() -> None:
    assert find_project_script("node 'scripts/a.js") == "scripts/a.js"


def test_nesting_depth_is_bounded() -> None:
    cmd = "node .github/init.js"
    for _ in range(5):
        cmd = f"bash -c '{cmd}'"
    assert find_project_script(cmd) is None
    assert find_project_script("bash -c 'bash -c \"node .github/init.js\"'") is not None


def test_matcher_is_linear_and_padding_cannot_hide_a_hit() -> None:
    pad = "a " * 200_000
    start = time.monotonic()
    assert find_project_script(f"echo {pad}; node .github/init.js") == ".github/init.js"
    assert find_project_script("'" + "x" * 500_000) is None
    assert find_project_script("node " + "-" * 500_000) is None
    assert time.monotonic() - start < 3


# ── The finding ───────────────────────────────────────────────────────────────


def _settings(command: str, event: str = "SessionStart") -> dict:
    return {"hooks": {event: [{"hooks": [{"type": "command", "command": command}]}]}}


def _run(path: Path, raw: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(raw))
    return ConfigHygieneAnalyzer().analyze_config(
        raw=raw, config_path=path, client="claude-code"
    )


def _ids(findings) -> list[str]:
    return [f.id for f in findings]


@pytest.fixture(autouse=True)
def _home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    return home


def test_project_settings_hook_is_high(tmp_path: Path) -> None:
    findings = _run(
        tmp_path / "repo" / ".claude" / "settings.json",
        _settings("node .github/init.js"),
    )
    f = next(f for f in findings if f.id == "HOOK-003")
    assert f.severity == Severity.HIGH
    assert f.cwe == "CWE-829"
    assert f.owasp_mcp_top_10 == ["MCP05", "MCP09"]
    assert "SessionStart" in f.evidence
    assert ".github/init.js" in f.evidence
    # CFHYG-005 (hooks section present) still fires beside it.
    assert "CFHYG-005" in _ids(findings)


def test_local_settings_hook_is_high(tmp_path: Path) -> None:
    findings = _run(
        tmp_path / "repo" / ".claude" / "settings.local.json",
        _settings('python "$CLAUDE_PROJECT_DIR/.claude/hooks/a.py"', "PreToolUse"),
    )
    assert "HOOK-003" in _ids(findings)


def test_user_settings_hook_does_not_fire(_home: Path) -> None:
    findings = _run(
        _home / ".claude" / "settings.json", _settings("node .github/init.js")
    )
    assert "HOOK-003" not in _ids(findings)
    assert "CFHYG-005" in _ids(findings)


def test_claude_config_dir_settings_do_not_fire(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = tmp_path / "cfgdir"
    cfg.mkdir()
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(cfg))
    findings = _run(cfg / "settings.json", _settings("./hook.sh"))
    assert "HOOK-003" not in _ids(findings)


def test_global_claude_json_does_not_fire(_home: Path) -> None:
    findings = _run(_home / ".claude.json", _settings("node .github/init.js"))
    assert "HOOK-003" not in _ids(findings)


@pytest.mark.parametrize(
    "command",
    ["/usr/bin/say done", "npx prettier --write .", "echo hi", "git status"],
)
def test_benign_project_hooks_do_not_fire(tmp_path: Path, command: str) -> None:
    findings = _run(tmp_path / "repo" / ".claude" / "settings.json", _settings(command))
    assert "HOOK-003" not in _ids(findings)


def test_one_finding_per_file_counts_the_rest(tmp_path: Path) -> None:
    raw = {
        "hooks": {
            "SessionStart": [
                {
                    "hooks": [
                        {"type": "command", "command": "node .github/init.js"},
                        {"type": "command", "command": "bash ./b.sh"},
                    ]
                }
            ],
            "Stop": [{"hooks": [{"type": "command", "command": "./c.sh"}]}],
        }
    }
    findings = _run(tmp_path / "repo" / ".claude" / "settings.json", raw)
    hits = [f for f in findings if f.id == "HOOK-003"]
    assert len(hits) == 1
    assert "+2 more" in hits[0].evidence


def test_evidence_is_redacted(tmp_path: Path) -> None:
    secret = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890"  # noqa: S105
    findings = _run(
        tmp_path / "repo" / ".claude" / "settings.json",
        _settings(f"node .github/init.js --token {secret}"),
    )
    f = next(f for f in findings if f.id == "HOOK-003")
    assert secret not in f.evidence


def test_non_command_hook_types_are_ignored(tmp_path: Path) -> None:
    raw = {
        "hooks": {
            "Stop": [{"hooks": [{"type": "prompt", "command": "node .github/init.js"}]}]
        }
    }
    findings = _run(tmp_path / "repo" / ".claude" / "settings.json", raw)
    assert "HOOK-003" not in _ids(findings)


def test_homoglyph_interpreter_cannot_hide_the_script(tmp_path: Path) -> None:
    # Fullwidth "node" folds to ASCII before matching, like HOOK-001.
    findings = _run(
        tmp_path / "repo" / ".claude" / "settings.json",
        _settings("ｎｏｄｅ .github/init.js"),
    )
    assert "HOOK-003" in _ids(findings)


def test_project_scan_reports_hook003_for_the_keyv_layout() -> None:
    fixture = Path(__file__).parent / "fixtures" / "project_autoexec" / "keyv_layout"
    path = fixture / ".claude" / "settings.json"
    raw = json.loads(path.read_text())
    findings = ConfigHygieneAnalyzer().analyze_config(
        raw=raw, config_path=path, client="claude-code"
    )
    assert "HOOK-003" in _ids(findings)
