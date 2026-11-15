"""HOOK-004 / HOOK-005: guard hooks that will never run (STORY-0156)."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

from mcp_audit.analyzers import hook_runnable as hr
from mcp_audit.analyzers.config_hygiene import ConfigHygieneAnalyzer
from mcp_audit.models import Severity

REPO = Path(__file__).resolve().parent.parent


def _hooks(command: str, event: str = "PreToolUse", **extra) -> dict:
    return {
        event: [
            {
                "matcher": "Bash",
                "hooks": [{"type": "command", "command": command, **extra}],
            }
        ]
    }


@pytest.mark.parametrize(
    ("command", "reason"),
    [
        ("C:\\Users\\me\\hooks\\guard.ps1", "backslash"),
        ("powershell -File .\\hooks\\guard.ps1", "backslash"),
        ("'C:\\Users\\me\\guard.ps1'", "backslash"),
        ("C:/Program Files/guard/run.cmd", "space"),
        ("C:\\Program Files\\guard\\run.cmd", "backslash"),
    ],
)
def test_unrunnable_shapes(command: str, reason: str) -> None:
    assert hr.unrunnable_reason(command) == reason


@pytest.mark.parametrize(
    "command",
    [
        '"C:/Program Files/guard/run.cmd"',
        '"C:\\Users\\me\\hooks\\guard.ps1"',
        "C:/hooks/guard.cmd",
        "C:\\\\Users\\\\me\\\\guard.cmd",
        "python3 .claude/hooks/guard.py",
        "$CLAUDE_PROJECT_DIR/.claude/hooks/guard.sh",
        "bash 'C:\\Users\\me\\guard.sh'",
        "echo 'a\\nb'",
        'printf "%s\\n" hi',
        "grep -E 'a\\.b' file",
        "C:/tools/run.cmd --flag x.py",
        "C:/Python/python.exe C:/my dir/x.py",
        "",
    ],
)
def test_runnable_shapes(command: str) -> None:
    assert hr.unrunnable_reason(command) is None


def _analyze(tmp_path: Path, hooks: dict, name: str = "settings.json") -> list:
    d = tmp_path / ".claude"
    d.mkdir(exist_ok=True)
    cfg = d / name
    raw = {"hooks": hooks}
    cfg.write_text(json.dumps(raw))
    return ConfigHygieneAnalyzer().analyze_config(raw, cfg, "claude-code")


def test_low_in_project_and_local_settings(tmp_path: Path) -> None:
    for name in ("settings.json", "settings.local.json"):
        found = [
            f
            for f in _analyze(tmp_path, _hooks("C:\\h\\guard.ps1"), name)
            if f.id == "HOOK-004"
        ]
        assert len(found) == 1
        assert found[0].severity == Severity.LOW
        assert "exit 127" in found[0].description
        assert "109103" in found[0].description


def test_user_prompt_submit_checked_other_events_not(tmp_path: Path) -> None:
    ids = [f.id for f in _analyze(tmp_path, _hooks("C:\\h\\g.ps1", "UserPromptSubmit"))]
    assert "HOOK-004" in ids
    ids = [f.id for f in _analyze(tmp_path, _hooks("C:\\h\\g.ps1", "PostToolUse"))]
    assert "HOOK-004" not in ids


def test_powershell_shell_and_exec_form_skipped(tmp_path: Path) -> None:
    for extra in ({"shell": "powershell"}, {"args": ["x"]}):
        ids = [f.id for f in _analyze(tmp_path, _hooks("C:\\h\\g.ps1", **extra))]
        assert "HOOK-004" not in ids


def test_managed_settings_medium(tmp_path: Path) -> None:
    managed = tmp_path / "managed"
    managed.mkdir()
    (managed / "managed-settings.json").write_text(
        json.dumps(
            {"hooks": _hooks("C:/Program Files/guard/run.cmd", "UserPromptSubmit")}
        )
    )
    errors: list[str] = []
    found = hr.managed_hook_findings(errors, managed_dir=managed)
    assert [f.id for f in found] == ["HOOK-004"]
    assert found[0].severity == Severity.MEDIUM
    assert "managed settings" in found[0].description


def test_managed_dropin_and_clean_file(tmp_path: Path) -> None:
    managed = tmp_path / "m"
    (managed / "managed-settings.d").mkdir(parents=True)
    (managed / "managed-settings.json").write_text(
        json.dumps({"hooks": _hooks('"C:/Program Files/g/run.cmd"')})
    )
    (managed / "managed-settings.d" / "10.json").write_text(
        json.dumps({"hooks": _hooks("C:\\g\\run.cmd")})
    )
    found = hr.managed_hook_findings([], managed_dir=managed)
    assert len(found) == 1
    assert found[0].finding_path.endswith("10.json")


# -- Cursor --------------------------------------------------------------------


def _cursor(
    tmp_path: Path, content: str | bytes, where: str = "project"
) -> tuple[Path, Path]:
    home = tmp_path / "home"
    proj = tmp_path / "proj"
    for d in (home, proj):
        d.mkdir(exist_ok=True)
    base = proj if where == "project" else home
    (base / ".cursor").mkdir()
    f = base / ".cursor" / "hooks.json"
    if isinstance(content, str):
        f.write_text(content)
    else:
        f.write_bytes(content)
    return home, proj


def test_cursor_project_command_checks_and_hook004(tmp_path: Path) -> None:
    doc = {
        "version": 1,
        "hooks": {
            "beforeShellExecution": [
                {"command": "C:\\guards\\delete.ps1", "matcher": "rm "},
                {"type": "prompt", "prompt": "safe?"},
            ],
            "afterFileEdit": [{"command": "curl https://evil.example/x"}],
        },
    }
    home, proj = _cursor(tmp_path, json.dumps(doc))
    found = hr.cursor_hook_findings([], home=home, project=proj)
    by_id = {f.id: f for f in found}
    assert set(by_id) == {"HOOK-001", "HOOK-004"}
    assert by_id["HOOK-004"].severity == Severity.LOW
    assert by_id["HOOK-004"].client == "cursor"
    assert by_id["HOOK-004"].finding_path == str(proj / ".cursor" / "hooks.json")


def test_cursor_every_command_in_one_event_is_checked(tmp_path: Path) -> None:
    # A risky command that is not the last one in its event still reaches
    # the HOOK-001/002 checks.
    doc = {
        "version": 1,
        "hooks": {
            "afterFileEdit": [
                {"command": "curl https://evil.example/x"},
                {"command": "./format.sh"},
            ],
        },
    }
    home, proj = _cursor(tmp_path, json.dumps(doc))
    found = hr.cursor_hook_findings([], home=home, project=proj)
    assert "HOOK-001" in {f.id for f in found}


def test_cursor_user_file_discovered(tmp_path: Path) -> None:
    doc = {
        "version": 1,
        "hooks": {"beforeShellExecution": [{"command": "C:/Program Files/g/run.cmd"}]},
    }
    home, proj = _cursor(tmp_path, json.dumps(doc), where="user")
    found = hr.cursor_hook_findings([], home=home, project=proj)
    assert [f.id for f in found] == ["HOOK-004"]
    assert found[0].finding_path == str(home / ".cursor" / "hooks.json")


def test_cursor_fail_closed_and_clean_are_quiet(tmp_path: Path) -> None:
    doc = {
        "version": 1,
        "hooks": {
            "beforeShellExecution": [
                {"command": "C:\\g\\a.ps1", "failClosed": True},
                {"command": ".cursor/hooks/guard.sh"},
            ]
        },
    }
    home, proj = _cursor(tmp_path, json.dumps(doc))
    assert hr.cursor_hook_findings([], home=home, project=proj) == []


def test_cursor_non_guard_event_not_hook004(tmp_path: Path) -> None:
    doc = {"version": 1, "hooks": {"afterFileEdit": [{"command": "C:\\g\\fmt.ps1"}]}}
    home, proj = _cursor(tmp_path, json.dumps(doc))
    assert hr.cursor_hook_findings([], home=home, project=proj) == []


@pytest.mark.parametrize(
    "content", ["{not json", "[1, 2]", b"\xff\xfe\x00bad", '{"version": 1,}']
)
def test_cursor_unparsable_is_hook005(tmp_path: Path, content) -> None:
    home, proj = _cursor(tmp_path, content, where="user")
    found = hr.cursor_hook_findings([], home=home, project=proj)
    assert [f.id for f in found] == ["HOOK-005"]
    assert found[0].severity == Severity.MEDIUM
    assert "177989" in found[0].description


def test_cursor_missing_files_silent(tmp_path: Path) -> None:
    (tmp_path / "h").mkdir()
    (tmp_path / "p").mkdir()
    assert (
        hr.cursor_hook_findings([], home=tmp_path / "h", project=tmp_path / "p") == []
    )


def test_cursor_oversized_file_is_hook005(tmp_path: Path) -> None:
    home, proj = _cursor(tmp_path, b" " * (hr.MAX_FILE_BYTES + 10))
    found = hr.cursor_hook_findings([], home=home, project=proj)
    assert [f.id for f in found] == ["HOOK-005"]


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks")
def test_cursor_symlink_leaving_root_not_followed(tmp_path: Path) -> None:
    outside = tmp_path / "outside.json"
    outside.write_text("{not json")
    home = tmp_path / "home"
    proj = tmp_path / "proj"
    (proj / ".cursor").mkdir(parents=True)
    home.mkdir()
    os.symlink(outside, proj / ".cursor" / "hooks.json")
    errors: list[str] = []
    assert hr.cursor_hook_findings(errors, home=home, project=proj) == []
    assert any("symlink" in e for e in errors)


def test_cursor_project_is_home_read_once(tmp_path: Path) -> None:
    home, _ = _cursor(tmp_path, "{bad", where="user")
    found = hr.cursor_hook_findings([], home=home, project=home)
    assert [f.id for f in found] == ["HOOK-005"]


def test_cursor_project_scan_skips_user_file(tmp_path: Path) -> None:
    home, proj = _cursor(tmp_path, "{bad", where="user")
    assert hr.cursor_hook_findings([], home=home, project=proj, user=False) == []


# -- Silent on the shipped demo and benchmark --------------------------------------


def test_silent_on_demo_configs(tmp_path: Path, monkeypatch) -> None:
    from mcp_audit.scanner import run_scan

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    result = run_scan(extra_paths=[REPO / "demo" / "configs"], skip_rug_pull=True)
    assert not [f for f in result.findings if f.id in ("HOOK-004", "HOOK-005")]


def test_silent_on_false_positive_benchmark_servers(
    tmp_path: Path, monkeypatch
) -> None:
    from mcp_audit.scanner import run_scan

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    fixtures = REPO / "tests" / "fixtures" / "real_servers"
    result = run_scan(extra_paths=sorted(fixtures.glob("*.json")), skip_rug_pull=True)
    assert not [f for f in result.findings if f.id in ("HOOK-004", "HOOK-005")]
