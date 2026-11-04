"""Regression tests for the PR #266 review (STORY-0143): B1-B4, N1-N7."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mcp_audit import guardrails as g
from mcp_audit import scanner
from mcp_audit.advisory.canonical import canonicalize
from mcp_audit.cli import app
from mcp_audit.lock import guardrail_section as gs
from mcp_audit.lock import section_digests
from mcp_audit.models import Finding, Severity

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX only")
runner = CliRunner()

GH = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890"  # noqa: S105
ANT = "sk-ant-api03-" + "A" * 90 + "AA"  # noqa: S105
BEARER = "eyJhbGciOiJIUzI1NiJ9.zzzzsecretbearerQQQQ"  # noqa: S105
OPAQUE = "Zq9TotallyOpaqueTok3nXYZ"  # noqa: S105
TOKENS = {"GH": GH, "ANT": ANT, "BEARER": BEARER, "OPAQUE": OPAQUE}


@pytest.fixture()
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    h = tmp_path / "home"
    h.mkdir()
    monkeypatch.setattr(g, "_home", lambda: h)
    monkeypatch.setattr("mcp_audit.discovery._home", lambda: h)
    monkeypatch.setattr(
        "mcp_audit.discovery.gemini_user_config_path",
        lambda: h / ".gemini" / "settings.json",
    )
    monkeypatch.setenv("CODEX_HOME", str(h / ".codex"))
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    return h


@pytest.fixture()
def repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    r = tmp_path / "repo"
    r.mkdir()
    monkeypatch.chdir(r)
    return r


@pytest.fixture()
def state(tmp_path: Path) -> Path:
    return tmp_path / "state" / "guardrails.json"


def _w(path: Path, data: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data if isinstance(data, str) else json.dumps(data))
    return path


def _scan(cwd: Path, state: Path) -> tuple[list[Finding], list[str]]:
    errors: list[str] = []
    files = g.guardrail_files(cwd, errors)
    return g.guardrail_drift_findings(files, state, errors), errors


# ── B1: secrets ──────────────────────────────────────────────────────────────


def _before_after() -> tuple[dict, dict]:
    before = {"permissions": {"allow": ["Read"], "deny": ["Read(~/.ssh/**)"]}}
    after = {
        "permissions": {
            "allow": [
                "Read",
                f'Bash(curl -H "Authorization: Bearer {BEARER}" https://api)',
                f"Bash(GH_TOKEN={GH} gh pr list)",
                f"WebFetch(domain:user:{OPAQUE}@evil.example)",
                f"Bash(export ANTHROPIC_API_KEY={ANT})",
                f"Bash(curl -u admin:{OPAQUE} https://h)",
                f"Bash(curl https://h/?token={OPAQUE})",
            ],
            "additionalDirectories": [f"https://bob:{OPAQUE}@host/x", f"/srv/{GH}"],
        },
        "sandbox": {
            "network": {
                "allowedDomains": [
                    f"{OPAQUE}.tok.example",
                    f"https://u:{OPAQUE}@d.example",
                ]
            },
            "excludedCommands": [f"curl -H 'X-Api-Key: {OPAQUE}'"],
        },
    }
    return before, after


def test_secret_shapes_never_reach_state_evidence_or_lock(
    home: Path, repo: Path, state: Path
) -> None:
    before, after = _before_after()
    settings = _w(repo / ".claude" / "settings.json", before)
    gemini = _w(repo / ".gemini" / "settings.json", {"tools": {"allowed": ["x"]}})
    assert _scan(repo, state)[0] == []
    settings.write_text(json.dumps(after))
    gemini.write_text(
        json.dumps({"tools": {"allowed": ["x", f"run_shell_command(TOKEN={OPAQUE})"]}})
    )
    findings, errors = _scan(repo, state)
    assert findings and findings[0].severity == Severity.HIGH
    assert runner.invoke(app, ["lock", str(repo), "--offline"]).exit_code == 0
    blobs = {
        "state": state.read_bytes().decode(),
        "findings": "\n".join(f.model_dump_json() for f in findings),
        "errors": "\n".join(errors),
        "lock": (repo / "mcp-lock.json").read_text(),
    }
    for where, blob in blobs.items():
        for name, token in TOKENS.items():
            assert token not in blob, f"{name} leaked into {where}"


def test_redaction_is_stable_so_it_never_looks_like_a_change(
    home: Path, repo: Path, state: Path
) -> None:
    settings = _w(
        repo / ".claude" / "settings.json",
        {"permissions": {"allow": [f"Bash(curl -u admin:{OPAQUE} https://h)"]}},
    )
    assert _scan(repo, state)[0] == []
    assert _scan(repo, state)[0] == []
    # the same rule with a rotated secret masks to the same text: no change
    settings.write_text(
        json.dumps(
            {
                "permissions": {
                    "allow": ["Bash(curl -u admin:OtherSecret99xx https://h)"]
                }
            }
        )
    )
    assert _scan(repo, state)[0] == []


# ── B2: a newly created loosened file ────────────────────────────────────────


def test_new_loosened_files_are_reported(home: Path, repo: Path, state: Path) -> None:
    _w(repo / ".claude" / "settings.json", {"permissions": {"deny": ["Read(.env)"]}})
    assert _scan(repo, state)[0] == []
    _w(
        repo / ".claude" / "settings.local.json",
        {"permissions": {"defaultMode": "bypassPermissions", "allow": ["Bash(*)"]}},
    )
    _w(
        home / ".codex" / "config.toml",
        'approval_policy = "never"\nsandbox_mode = "danger-full-access"\n',
    )
    findings, _ = _scan(repo, state)
    by_file = {f.server: f for f in findings}
    assert set(by_file) == {".claude/settings.local.json", "~/.codex/config.toml"}
    assert all(f.severity == Severity.HIGH for f in findings)
    assert _scan(repo, state)[0] == []  # once


def test_new_file_after_a_scan_that_saw_no_files_is_reported(
    home: Path, repo: Path, state: Path
) -> None:
    assert _scan(repo, state) == ([], [])  # nothing exists; first scan silent
    assert state.exists()  # ... but it remembered what was absent
    _w(
        repo / ".claude" / "settings.json",
        {"permissions": {"defaultMode": "bypassPermissions"}},
    )
    findings, _ = _scan(repo, state)
    assert [f.severity for f in findings] == [Severity.HIGH]


def test_first_scan_stays_silent_even_with_a_loose_file(
    home: Path, repo: Path, state: Path
) -> None:
    _w(repo / ".claude" / "settings.json", {"permissions": {"allow": ["Bash(*)"]}})
    assert _scan(repo, state)[0] == []


# ── B3: LOCK-014 fails closed ────────────────────────────────────────────────


def _lock(repo: Path, *flags: str) -> object:
    return runner.invoke(app, ["lock", str(repo), "--offline", *flags])


def _json(out: str) -> dict:
    return json.loads(out[out.index("{") :])


def _verify(repo: Path, *flags: str) -> tuple[int, dict]:
    res = runner.invoke(
        app, ["lock", str(repo), "--verify", "--offline", "--format", "json", *flags]
    )
    return res.exit_code, _json(res.stdout)


@pytest.fixture()
def locked(repo: Path) -> Path:
    (repo / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"fs": {"command": "node", "args": ["x.js"]}}})
    )
    _w(
        repo / ".claude" / "settings.json",
        {"permissions": {"deny": ["Read(~/.ssh/**)"], "allow": ["Bash(ls)"]}},
    )
    assert _lock(repo).exit_code == 0  # type: ignore[attr-defined]
    assert _verify(repo)[0] == 0
    return repo


def _unverified(data: dict) -> list[tuple[str, str]]:
    return [(u["kind"], u["name"]) for u in data["unverified"]]


def test_padded_file_is_unverified_not_passed(locked: Path) -> None:
    body = json.dumps({"permissions": {"defaultMode": "bypassPermissions"}})
    (locked / ".claude" / "settings.json").write_text(
        body + " " * (4 * 1024 * 1024 + 10)
    )
    code, data = _verify(locked)
    assert code == 1
    assert ("guardrail-file", ".claude/settings.json") in _unverified(data)
    assert _verify(locked, "--allow-unverified")[0] == 0  # R56 waiver


@posix_only
def test_symlinked_file_is_unverified(locked: Path, tmp_path: Path) -> None:
    evil = _w(
        tmp_path / "evil.json", {"permissions": {"defaultMode": "bypassPermissions"}}
    )
    path = locked / ".claude" / "settings.json"
    path.unlink()
    path.symlink_to(evil)
    code, data = _verify(locked)
    assert code == 1
    assert ("guardrail-file", ".claude/settings.json") in _unverified(data)


def test_invalid_json_is_unverified(locked: Path) -> None:
    (locked / ".claude" / "settings.json").write_text('{"permissions":{"deny":[]},,}')
    code, data = _verify(locked)
    assert code == 1
    assert ("guardrail-file", ".claude/settings.json") in _unverified(data)


def test_new_guardrail_file_not_in_the_lock_is_compared_with_empty(
    locked: Path,
) -> None:
    _w(locked / ".codex" / "config.toml", 'approval_policy = "never"\n')
    code, data = _verify(locked)
    assert code == 1
    finding = [f for f in data["findings"] if f["id"] == "LOCK-014"][0]
    assert ".codex/config.toml" in finding["evidence"]
    assert "not in the lock" in finding["description"]
    # accepting records it; a tightening-only new file is silent
    assert _lock(locked, "--accept").exit_code == 0  # type: ignore[attr-defined]
    assert _verify(locked)[0] == 0
    _w(locked / ".gemini" / "settings.json", {"tools": {"exclude": ["web_fetch"]}})
    assert _verify(locked)[0] == 0


def test_new_unreadable_file_not_in_the_lock_is_unverified(locked: Path) -> None:
    _w(locked / ".gemini" / "settings.json", "{ nope")
    code, data = _verify(locked)
    assert code == 1
    assert ("guardrail-file", ".gemini/settings.json") in _unverified(data)


def test_no_section_is_written_for_a_repo_without_guardrail_files(repo: Path) -> None:
    (repo / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"fs": {"command": "node", "args": ["x.js"]}}})
    )
    assert _lock(repo).exit_code == 0  # type: ignore[attr-defined]
    assert "guardrails" not in json.loads((repo / "mcp-lock.json").read_text())
    _w(repo / ".claude" / "settings.json", {"permissions": {"allow": ["Bash(*)"]}})
    assert _verify(repo)[0] == 0  # no section: not looked at (documented limit)


# ── B4: malformed records ────────────────────────────────────────────────────

BAD_RECORDS = [
    {"agent": "claude-code", "facts": ["boom"], "hooks": []},
    {"agent": "claude-code", "facts": {}, "hooks": [[["x"], "y", "z"]]},
    {"agent": "claude-code", "facts": {}, "hooks": "abc"},
    {"agent": "nobody", "facts": {}, "hooks": []},
    {"agent": "claude-code", "facts": {}, "hooks": [], "digests": {"k": 1}},
]


@pytest.mark.parametrize("bad", BAD_RECORDS)
def test_compare_refuses_malformed_records(bad: dict) -> None:
    assert not g.valid_record(bad)
    with pytest.raises(ValueError):
        g.compare(bad, g.empty_record(g.CLAUDE), g.CLAUDE)
    with pytest.raises(ValueError):
        g.vanished_diff(bad, g.CLAUDE)


def _forge(repo: Path, rel: str, entry: dict) -> None:
    path = repo / "mcp-lock.json"
    doc = json.loads(path.read_text())
    files = doc["guardrails"]["files"]
    files[rel] = entry
    doc["guardrails"] = gs.build_section(files)
    doc["section_digests"] = section_digests.merge(doc.get("section_digests"), doc)
    path.write_bytes(canonicalize(doc))


@pytest.mark.parametrize("bad", BAD_RECORDS)
def test_malformed_lock_record_is_unverified_not_a_crash(
    locked: Path, bad: dict
) -> None:
    _forge(
        locked,
        ".claude/settings.json",
        {"digest": gs.entry(bad)["digest"], "record": bad},
    )
    code, data = _verify(locked)
    assert code == 1
    assert ("guardrail-file", ".claude/settings.json") in _unverified(data)


def test_malformed_lock_record_does_not_break_scan_or_check(
    home: Path, locked: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _forge(locked, ".claude/settings.json", {"digest": "x", "record": BAD_RECORDS[0]})
    monkeypatch.chdir(locked)
    assert runner.invoke(app, ["check", "--json"]).exit_code in (0, 1)
    assert runner.invoke(app, ["scan", "--format", "json"]).exit_code in (0, 1)


@pytest.mark.parametrize("bad", BAD_RECORDS)
def test_bad_state_record_heals_and_does_not_disable_the_step(
    home: Path, repo: Path, state: Path, bad: dict
) -> None:
    settings = _w(
        repo / ".claude" / "settings.json", {"permissions": {"deny": ["Read(x)"]}}
    )
    _scan(repo, state)
    data = json.loads(state.read_text())
    key = next(k for k in data["files"] if k.endswith("repo/.claude/settings.json"))
    data["files"][key]["record"] = bad
    other = str(home / ".claude" / "settings.json")
    _w(home / ".claude" / "settings.json", {})
    data["files"][other] = {"agent": "claude-code", "record": bad, "absent": False}
    state.write_text(json.dumps(data))
    findings, errors = _scan(repo, state)  # must not raise; poisoned = no history
    assert findings == []
    assert not any("failed" in e for e in errors), errors
    assert g.valid_record(json.loads(state.read_text())["files"][key]["record"])
    settings.write_text(json.dumps({"permissions": {"deny": []}}))
    assert [f.id for f in _scan(repo, state)[0]] == ["GUARD-001"]  # healed


# ── N1: lock paths ───────────────────────────────────────────────────────────


@posix_only
def test_lock_cannot_make_verify_read_outside_the_repository(
    locked: Path, tmp_path: Path
) -> None:
    fake = tmp_path / "fake"
    _w(
        fake / ".claude" / "settings.json",
        {"permissions": {"allow": ["Bash(SECRET-FROM-OUTSIDE)"]}},
    )
    (locked / "evil").symlink_to(fake)
    (locked / "evil2").symlink_to("/etc")
    empty = g.empty_record(g.CLAUDE)
    _forge(locked, "evil/.claude/settings.json", gs.entry(empty))
    _forge(locked, "evil2/passwd", gs.entry(empty))
    _forge(locked, "../outside/.claude/settings.json", gs.entry(empty))
    res = runner.invoke(
        app, ["lock", str(locked), "--verify", "--offline", "--format", "json"]
    )
    data = _json(res.stdout)
    assert res.exit_code == 1
    names = [u["name"] for u in data["unverified"]]
    for bad in (
        "evil/.claude/settings.json",
        "evil2/passwd",
        "../outside/.claude/settings.json",
    ):
        assert bad in names
    assert "SECRET-FROM-OUTSIDE" not in res.stdout
    assert [f for f in data["findings"] if f["id"] == "LOCK-014"] == []


# ── N3: limits do not hide changes ───────────────────────────────────────────


def _rec(allow: list[str], key: str = "allow") -> dict:
    return g.build_record(
        g.CLAUDE, {"permissions": {key: allow}}, Path("/r/.claude/settings.json"), []
    )


def test_changes_past_the_entry_cap_are_reported_not_judged() -> None:
    filler = [f"Read(/a/{i:05d})" for i in range(g.MAX_ENTRIES + 500)]
    before = _rec(filler)
    after = _rec([*filler, "zzz-last-sorted"])  # sorts past the cap: not shown
    assert before["facts"]["permissions.allow"] == after["facts"]["permissions.allow"]
    diff = g.compare(before, after, g.CLAUDE)
    assert [i.key for i in diff.loosened] == ["permissions.allow"]
    assert "direction not judged" in diff.loosened[0].line
    assert g.compare(before, before, g.CLAUDE).loosened == []


def test_pad_then_add_two_step_is_caught() -> None:
    small = _rec(["Read"])
    padded = _rec([f"Read(/a/{i:05d})" for i in range(g.MAX_ENTRIES + 10)])
    assert g.compare(small, padded, g.CLAUDE).loosened  # the pad itself gains
    added = _rec(
        [*(f"Read(/a/{i:05d})" for i in range(g.MAX_ENTRIES + 10)), "~Bash(*)"]
    )
    assert g.compare(padded, added, g.CLAUDE).loosened


def test_entries_differing_only_past_512_chars_are_caught() -> None:
    a = _rec(["Bash(" + "a" * 600 + "x)"], "deny")
    b = _rec(["Bash(" + "a" * 600 + "y)"], "deny")
    assert a["facts"] == b["facts"]
    diff = g.compare(a, b, g.CLAUDE)
    assert [i.key for i in diff.loosened] == ["permissions.deny"]
    assert not diff.high


def test_small_lists_carry_no_digest() -> None:
    assert "digests" not in _rec(["Read"])


# ── N4: a deleted nested file under scan --project ───────────────────────────


def test_deleted_nested_file_is_noticed_by_the_project_walk(
    home: Path, repo: Path, state: Path
) -> None:
    nested = _w(
        repo / "sub" / ".claude" / "settings.json",
        {"permissions": {"deny": ["Read(~/.ssh/**)"]}},
    )
    errors: list[str] = []
    files = g.project_guardrail_files(repo, errors, state)
    assert g.guardrail_drift_findings(files, state, errors) == []
    nested.unlink()
    files = g.project_guardrail_files(repo, errors, state)
    assert [f.display for f in files] == ["sub/.claude/settings.json"]
    out = g.guardrail_drift_findings(files, state, errors)
    assert [f.id for f in out] == ["GUARD-001"] and out[0].severity == Severity.HIGH
    assert (
        g.guardrail_drift_findings(
            g.project_guardrail_files(repo, errors, state), state, errors
        )
        == []
    )


def test_project_walk_lists_nothing_extra_without_state(
    home: Path, repo: Path, state: Path
) -> None:
    assert g.project_guardrail_files(repo, [], state) == []


# ── N5: never raises ─────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "target",
    [
        "mcp_audit.guardrails._home",
        "mcp_audit.guardrails.managed_files",
        "mcp_audit.guardrails.read_record",
        "mcp_audit.guardrails.compare",
        "mcp_audit.guardrails._claude_user_dir",
    ],
)
def test_injected_failures_never_raise(
    target: str, home: Path, repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _w(repo / ".claude" / "settings.json", {"permissions": {"deny": ["Read(x)"]}})
    rug = tmp_path / "st" / "state.json"
    scanner.run_scan(state_path=rug, guardrail_drift=True)
    _w(repo / ".claude" / "settings.json", {})

    def boom(*a: object, **k: object) -> None:
        raise RuntimeError("injected")

    monkeypatch.setattr(target, boom)
    result = scanner.run_scan(state_path=rug, guardrail_drift=True)
    assert any("guardrail drift" in e for e in result.errors) or target.endswith(
        "compare"
    )


def test_default_file_lister_is_guarded(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*a: object, **k: object) -> None:
        raise RuntimeError("injected")

    monkeypatch.setattr(g, "guardrail_files", boom)
    errors: list[str] = []
    assert scanner._default_guardrail_files(None, False, errors) is None
    assert any("guardrail drift failed" in e for e in errors)


def test_project_lister_is_guarded(
    home: Path, repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*a: object, **k: object) -> None:
        raise RuntimeError("injected")

    monkeypatch.setattr(g, "_home", boom)
    errors: list[str] = []
    assert g.project_guardrail_files(repo, errors) == []
    assert errors


# ── N7: only commands that show findings run the step ────────────────────────


def test_a_command_that_discards_findings_does_not_consume_a_loosening(
    home: Path, repo: Path, tmp_path: Path
) -> None:
    rug = tmp_path / "st" / "state.json"
    settings = _w(
        repo / ".claude" / "settings.json", {"permissions": {"deny": ["Read(x)"]}}
    )
    scanner.run_scan(state_path=rug, guardrail_drift=True)
    settings.write_text("{}")
    discarded = scanner.run_scan(state_path=rug)  # default: not run
    assert not [f for f in discarded.findings if f.id.startswith("GUARD-")]
    shown = scanner.run_scan(state_path=rug, guardrail_drift=True)
    assert [f.id for f in shown.findings if f.id.startswith("GUARD-")] == ["GUARD-001"]


def test_killchain_then_scan_still_reports(home: Path, repo: Path) -> None:
    settings = _w(
        repo / ".claude" / "settings.json", {"permissions": {"deny": ["Read(x)"]}}
    )
    first = runner.invoke(app, ["scan", "--format", "json"])
    assert "GUARD-001" not in first.stdout
    settings.write_text("{}")
    runner.invoke(app, ["killchain"])
    second = runner.invoke(app, ["scan", "--format", "json"])
    assert "GUARD-001" in second.stdout


# ── N6: older verifiers ──────────────────────────────────────────────────────


def test_upgrade_note_is_documented() -> None:
    root = Path(__file__).resolve().parent.parent
    for name in ("docs/lock.md", "CHANGELOG.md"):
        text = (root / name).read_text()
        assert "older mcp-audit" in text.lower() and "guardrails" in text, name
