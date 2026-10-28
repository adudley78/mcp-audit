"""REACH-001..003: credential files a Claude Code session can read (STORY-0114)."""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path, PurePosixPath

import pytest

from mcp_audit.analyzers import secret_reach as sr
from mcp_audit.models import Severity


def _layout(tmp_path: Path) -> tuple[Path, Path, Path]:
    home = tmp_path / "home"
    cwd = home / "proj"
    config = home / ".claude"
    for d in (home, cwd, config):
        d.mkdir(parents=True, exist_ok=True)
    return home, cwd, config


def _write(path: Path, text: str = "secret-value-never-read\n") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def _settings(path: Path, data: dict) -> None:
    _write(path, json.dumps(data))


def _run(
    tmp_path: Path,
    home: Path,
    cwd: Path,
    config: Path,
    errors: list[str] | None = None,
    managed: Path | None = None,
):
    return sr.secret_reach_findings(
        errors if errors is not None else [],
        cwd=cwd,
        home=home,
        config_dir=config,
        managed_dir=managed if managed is not None else tmp_path / "no-managed",
    )


def _ids(findings) -> list[str]:
    return [f.id for f in findings]


def _reach1(findings):
    return next(f for f in findings if f.id == "REACH-001")


# ── Gate ──────────────────────────────────────────────────────────────────────


def test_silent_without_a_claude_config_dir(tmp_path: Path) -> None:
    home, cwd, config = _layout(tmp_path)
    config.rmdir()
    _write(home / ".aws" / "credentials")
    _write(cwd / ".env")
    assert _run(tmp_path, home, cwd, config) == []


# ── REACH-001 ─────────────────────────────────────────────────────────────────


def test_reach_001_lists_uncovered_stores(tmp_path: Path) -> None:
    home, cwd, config = _layout(tmp_path)
    _write(home / ".ssh" / "id_ed25519")
    _write(home / ".aws" / "credentials")
    _write(home / ".kube" / "config")
    findings = _run(tmp_path, home, cwd, config)
    f = _reach1(findings)
    assert f.severity == Severity.LOW
    assert f.owasp_mcp_top_10 == ["MCP01"]
    assert "~/.ssh/id_ed25519 (SSH private key)" in f.evidence
    assert "~/.aws/credentials" in f.evidence
    assert "~/.kube/config (kubeconfig (may hold" in f.evidence
    assert f.title.startswith("3 credential file(s)")
    for text in (f.title, f.description, f.evidence, f.remediation):
        assert str(home) not in text


def test_reach_001_silent_with_no_stores(tmp_path: Path) -> None:
    home, cwd, config = _layout(tmp_path)
    assert "REACH-001" not in _ids(_run(tmp_path, home, cwd, config))


def test_empty_file_and_directory_are_not_stores(tmp_path: Path) -> None:
    home, cwd, config = _layout(tmp_path)
    _write(home / ".aws" / "credentials", "")
    (home / ".netrc").mkdir()
    assert "REACH-001" not in _ids(_run(tmp_path, home, cwd, config))


def test_store_list_has_no_unlisted_paths(tmp_path: Path) -> None:
    home, cwd, config = _layout(tmp_path)
    _write(home / ".ssh" / "my_custom_key")
    _write(home / ".ssh" / "id_ed25519.pub")
    assert "REACH-001" not in _ids(_run(tmp_path, home, cwd, config))


@pytest.mark.parametrize(
    "rule",
    [
        "Read(~/.aws/credentials)",
        "Read(~/.aws/**)",
        "Read(~/.aws)",
        "Read(~/.*/credentials)",
        "Read(~/**/credentials)",
        "Read",
        "*",
        "Read(//**)",
    ],
)
def test_user_read_deny_rule_covers(tmp_path: Path, rule: str) -> None:
    home, cwd, config = _layout(tmp_path)
    _write(home / ".aws" / "credentials")
    _settings(config / "settings.json", {"permissions": {"deny": [rule]}})
    assert "REACH-001" not in _ids(_run(tmp_path, home, cwd, config))


def test_absolute_double_slash_rule_covers(tmp_path: Path) -> None:
    home, cwd, config = _layout(tmp_path)
    store = _write(home / ".aws" / "credentials")
    _settings(
        config / "settings.json",
        # Permissions doc: "//path" from the filesystem root; on Windows the
        # path is in POSIX form ("C:\\Users\\alice" becomes "/c/Users/alice").
        {"permissions": {"deny": [f"Read(/{sr._posix(store)})"]}},
    )
    assert "REACH-001" not in _ids(_run(tmp_path, home, cwd, config))


@pytest.mark.parametrize(
    "rule",
    [
        "Read(~/.ssh/**)",  # other store
        "Edit(~/.aws/credentials)",  # Edit does not stop reads
        "Bash(cat ~/.aws/credentials)",  # Bash rule is not a Read rule
        "Read(.aws/credentials)",  # relative to cwd, not home
        "Read(~/.aws/cred)",  # partial name
        "Read(*)",  # relative: everything under the cwd, not home
        "Read(**)",
    ],
)
def test_rules_that_do_not_cover(tmp_path: Path, rule: str) -> None:
    home, cwd, config = _layout(tmp_path)
    _write(home / ".aws" / "credentials")
    _settings(config / "settings.json", {"permissions": {"deny": [rule]}})
    assert "~/.aws/credentials" in _reach1(_run(tmp_path, home, cwd, config)).evidence


def test_allow_rule_does_not_cover(tmp_path: Path) -> None:
    home, cwd, config = _layout(tmp_path)
    _write(home / ".aws" / "credentials")
    _settings(
        config / "settings.json",
        {"permissions": {"allow": ["Read(~/.aws/**)"], "ask": ["Read(~/.aws/**)"]}},
    )
    assert "REACH-001" in _ids(_run(tmp_path, home, cwd, config))


def test_single_slash_anchors_at_user_settings_dir(tmp_path: Path) -> None:
    """Permissions doc: ``/path`` in user settings resolves to ``~/.claude/path``."""
    home, cwd, config = _layout(tmp_path)
    _write(config / ".credentials.json")
    _settings(
        config / "settings.json",
        {"permissions": {"deny": ["Read(/.credentials.json)"]}},
    )
    assert "REACH-001" not in _ids(_run(tmp_path, home, cwd, config))


def test_single_slash_in_project_settings_anchors_at_cwd(tmp_path: Path) -> None:
    home, cwd, config = _layout(tmp_path)
    _write(config / ".credentials.json")
    _settings(
        cwd / ".claude" / "settings.json",
        {"permissions": {"deny": ["Read(/.credentials.json)"]}},
    )
    assert "REACH-001" in _ids(_run(tmp_path, home, cwd, config))


def test_project_and_local_settings_count(tmp_path: Path) -> None:
    home, cwd, config = _layout(tmp_path)
    _write(home / ".aws" / "credentials")
    _write(home / ".netrc")
    _settings(
        cwd / ".claude" / "settings.json",
        {"permissions": {"deny": ["Read(~/.aws/**)"]}},
    )
    _settings(
        cwd / ".claude" / "settings.local.json",
        {"permissions": {"deny": ["Read(~/.netrc)"]}},
    )
    assert "REACH-001" not in _ids(_run(tmp_path, home, cwd, config))


def test_managed_settings_and_dropins_count(tmp_path: Path) -> None:
    home, cwd, config = _layout(tmp_path)
    managed = tmp_path / "managed"
    _write(home / ".aws" / "credentials")
    _write(home / ".netrc")
    _settings(
        managed / "managed-settings.json",
        {"permissions": {"deny": ["Read(~/.aws/credentials)"]}},
    )
    _settings(
        managed / "managed-settings.d" / "10-netrc.json",
        {"permissions": {"deny": ["Read(~/.netrc)"]}},
    )
    findings = _run(tmp_path, home, cwd, config, managed=managed)
    assert "REACH-001" not in _ids(findings)


def test_block_reads_outside_working_directories_covers(tmp_path: Path) -> None:
    home, cwd, config = _layout(tmp_path)
    _write(home / ".aws" / "credentials")
    _settings(
        config / "settings.json",
        {"permissions": {"blockReadsOutsideWorkingDirectories": True}},
    )
    assert "REACH-001" not in _ids(_run(tmp_path, home, cwd, config))


def test_block_does_not_cover_when_cwd_is_home(tmp_path: Path) -> None:
    """The block fences paths outside the working directories; home is inside."""
    home, _cwd, config = _layout(tmp_path)
    _write(home / ".aws" / "credentials")
    _settings(
        config / "settings.json",
        {"permissions": {"blockReadsOutsideWorkingDirectories": True}},
    )
    findings = _run(tmp_path, home, home, config)
    assert "REACH-001" in _ids(findings)


@pytest.mark.parametrize(
    ("sandbox", "covered"),
    [
        ({"enabled": True, "filesystem": {"denyRead": ["~/.aws"]}}, True),
        ({"enabled": True, "filesystem": {"denyRead": ["~/.aws/"]}}, True),
        ({"enabled": True, "filesystem": {"denyRead": ["~/**/credentials"]}}, True),
        (
            {
                "enabled": True,
                "credentials": {
                    "files": [{"path": "~/.aws/credentials", "mode": "deny"}]
                },
            },
            True,
        ),
        ({"filesystem": {"denyRead": ["~/.aws"]}}, False),  # sandbox off
        (
            {
                "enabled": True,
                "filesystem": {"denyRead": ["~/.aws"], "disabled": True},
            },
            False,
        ),
        (
            {
                "enabled": True,
                "credentials": {
                    "files": [{"path": "~/.aws/credentials", "mode": "mask"}]
                },
            },
            False,
        ),
    ],
)
def test_sandbox_coverage(tmp_path: Path, sandbox: dict, covered: bool) -> None:
    home, cwd, config = _layout(tmp_path)
    _write(home / ".aws" / "credentials")
    _settings(config / "settings.json", {"sandbox": sandbox})
    assert ("REACH-001" not in _ids(_run(tmp_path, home, cwd, config))) is covered


def test_sandbox_absolute_path(tmp_path: Path) -> None:
    home, cwd, config = _layout(tmp_path)
    store = _write(home / ".aws" / "credentials")
    _settings(
        config / "settings.json",
        {
            "sandbox": {
                "enabled": True,
                "filesystem": {"denyRead": [str(sr._posix(store))]},
            }
        },
    )
    assert "REACH-001" not in _ids(_run(tmp_path, home, cwd, config))


@pytest.mark.skipif(sys.platform.startswith("win"), reason="symlinks need privileges")
def test_symlinked_store_covered_by_rule_on_its_target(tmp_path: Path) -> None:
    """Permissions doc: deny rules apply to the requested path or its target."""
    home, cwd, config = _layout(tmp_path)
    real = _write(home / "dotfiles" / "aws-credentials")
    (home / ".aws").mkdir()
    (home / ".aws" / "credentials").symlink_to(real)
    _settings(
        config / "settings.json", {"permissions": {"deny": ["Read(~/dotfiles/**)"]}}
    )
    assert "REACH-001" not in _ids(_run(tmp_path, home, cwd, config))


@pytest.mark.skipif(sys.platform.startswith("win"), reason="symlinks need privileges")
def test_dangling_symlink_is_not_a_store(tmp_path: Path) -> None:
    home, cwd, config = _layout(tmp_path)
    (home / ".aws").mkdir()
    (home / ".aws" / "credentials").symlink_to(home / "nowhere")
    assert "REACH-001" not in _ids(_run(tmp_path, home, cwd, config))


def test_claude_config_dir_login_store_follows_config_dir(tmp_path: Path) -> None:
    home, cwd, _config = _layout(tmp_path)
    other = tmp_path / "elsewhere" / "claude"
    _write(other / ".credentials.json")
    findings = _run(tmp_path, home, cwd, other)
    assert "Claude Code login" in _reach1(findings).evidence


# ── REACH-003 ─────────────────────────────────────────────────────────────────


def test_reach_003_env_files(tmp_path: Path) -> None:
    home, cwd, config = _layout(tmp_path)
    _write(cwd / ".env")
    _write(cwd / ".env.local")
    _write(cwd / ".env.example")
    _write(cwd / ".env.sample")
    _write(cwd / ".env.production.template")
    _write(cwd / ".envrc")
    _write(cwd / "sub" / ".env")  # root only
    f = next(x for x in _run(tmp_path, home, cwd, config) if x.id == "REACH-003")
    assert f.severity == Severity.LOW
    assert f.evidence == ".env, .env.local"
    assert str(home) not in f.description + f.evidence + f.remediation


def test_reach_003_empty_env_is_ignored(tmp_path: Path) -> None:
    home, cwd, config = _layout(tmp_path)
    _write(cwd / ".env", "")
    assert "REACH-003" not in _ids(_run(tmp_path, home, cwd, config))


@pytest.mark.parametrize(
    "rules",
    [
        ["Read(./.env)", "Read(./.env.*)"],
        ["Read(.env*)"],
        ["Read(**/.env*)"],
        ["Read(*.local)", "Read(.env)"],
    ],
)
def test_reach_003_covered(tmp_path: Path, rules: list[str]) -> None:
    home, cwd, config = _layout(tmp_path)
    _write(cwd / ".env")
    _write(cwd / ".env.local")
    _settings(cwd / ".claude" / "settings.json", {"permissions": {"deny": rules}})
    assert "REACH-003" not in _ids(_run(tmp_path, home, cwd, config))


def test_reach_003_user_rule_with_global_pattern_covers(tmp_path: Path) -> None:
    home, cwd, config = _layout(tmp_path)
    _write(cwd / ".env")
    _settings(config / "settings.json", {"permissions": {"deny": ["Read(//**/.env)"]}})
    assert "REACH-003" not in _ids(_run(tmp_path, home, cwd, config))


def test_reach_003_carve_out_reopens(tmp_path: Path) -> None:
    home, cwd, config = _layout(tmp_path)
    _write(cwd / ".env")
    _write(cwd / ".env.local")
    _settings(
        cwd / ".claude" / "settings.json",
        {"permissions": {"deny": ["Read(.env*)", "Read(!.env.local)"]}},
    )
    f = next(x for x in _run(tmp_path, home, cwd, config) if x.id == "REACH-003")
    assert f.evidence == ".env.local"


def test_carve_out_cannot_reach_home_anchored_rule(tmp_path: Path) -> None:
    """Permissions doc: a ``!~/`` pattern carves nothing from ``~/`` rules."""
    home, cwd, config = _layout(tmp_path)
    _write(home / ".aws" / "credentials")
    _settings(
        config / "settings.json",
        {"permissions": {"deny": ["Read(~/.aws/**)", "Read(!~/.aws/credentials)"]}},
    )
    assert "REACH-001" not in _ids(_run(tmp_path, home, cwd, config))


def test_reach_003_skipped_when_cwd_is_home(tmp_path: Path) -> None:
    home, _cwd, config = _layout(tmp_path)
    _write(home / ".env")
    assert "REACH-003" not in _ids(_run(tmp_path, home, home, config))


def test_settings_read_once_when_cwd_is_home(tmp_path: Path) -> None:
    home, _cwd, config = _layout(tmp_path)
    _settings(config / "settings.json", {})
    sources = sr.load_settings_sources(home, home, config, None, [])
    assert [s.scope for s in sources] == ["user"]


# ── REACH-002 ─────────────────────────────────────────────────────────────────


@pytest.mark.skipif(sys.platform.startswith("win"), reason="POSIX mode bits")
@pytest.mark.parametrize(("mode", "fires"), [(0o644, True), (0o600, False)])
def test_reach_002_world_readable_login(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: int, fires: bool
) -> None:
    home, cwd, config = _layout(tmp_path)
    store = _write(config / ".credentials.json")
    store.chmod(mode)
    monkeypatch.setattr(sr, "_dir_mode", lambda _p: 0o40755)
    findings = _run(tmp_path, home, cwd, config)
    assert ("REACH-002" in _ids(findings)) is fires
    if fires:
        f = next(x for x in findings if x.id == "REACH-002")
        assert f.severity == Severity.MEDIUM
        assert "0644" in f.evidence
        assert str(home) not in f.description + f.evidence + f.remediation


@pytest.mark.skipif(sys.platform.startswith("win"), reason="POSIX mode bits")
def test_reach_002_silent_when_a_parent_blocks_search(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home, cwd, config = _layout(tmp_path)
    store = _write(config / ".credentials.json")
    store.chmod(0o644)
    monkeypatch.setattr(sr, "_dir_mode", lambda p: 0o40700 if p == config else 0o40755)
    assert "REACH-002" not in _ids(_run(tmp_path, home, cwd, config))


@pytest.mark.skipif(sys.platform.startswith("win"), reason="POSIX mode bits")
def test_reach_002_group_readable_private_group_is_silent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import grp
    import pwd

    home, cwd, config = _layout(tmp_path)
    store = _write(config / ".credentials.json")
    store.chmod(0o640)
    st = store.stat()
    monkeypatch.setattr(sr, "_dir_mode", lambda _p: 0o40755)
    owner = pwd.getpwuid(st.st_uid).pw_name
    group = grp.getgrgid(st.st_gid).gr_name
    findings = _run(tmp_path, home, cwd, config)
    assert ("REACH-002" in _ids(findings)) is (group != owner)


def test_reach_002_skipped_on_windows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home, cwd, config = _layout(tmp_path)
    store = _write(config / ".credentials.json")
    store.chmod(0o644)
    monkeypatch.setattr(sr, "_ON_WINDOWS", True)
    assert "REACH-002" not in _ids(_run(tmp_path, home, cwd, config))


# ── Robustness and privacy ────────────────────────────────────────────────────


def test_malformed_and_oversized_settings(tmp_path: Path) -> None:
    home, cwd, config = _layout(tmp_path)
    _write(home / ".aws" / "credentials")
    _write(config / "settings.json", "{not json")
    _write(cwd / ".claude" / "settings.json", " " * (sr.MAX_FILE_BYTES + 10))
    errors: list[str] = []
    findings = _run(tmp_path, home, cwd, config, errors)
    assert "REACH-001" in _ids(findings)
    assert any("over the read limit" in e for e in errors)
    assert all(str(home) not in e for e in errors)


def test_non_string_and_garbage_entries_are_ignored(tmp_path: Path) -> None:
    home, cwd, config = _layout(tmp_path)
    _write(home / ".aws" / "credentials")
    _settings(
        config / "settings.json",
        {
            "permissions": {"deny": [1, None, {"a": 1}, "Read(", "Read()"]},
            "sandbox": {"enabled": True, "filesystem": {"denyRead": [3, ""]}},
        },
    )
    assert "REACH-001" in _ids(_run(tmp_path, home, cwd, config))


def test_read_error_goes_to_errors_and_never_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home, cwd, config = _layout(tmp_path)

    def boom(*_a, **_k):
        raise PermissionError("denied")

    monkeypatch.setattr(sr, "_uncovered_home_stores", boom)
    errors: list[str] = []
    assert _run(tmp_path, home, cwd, config, errors) == []
    assert errors == ["secret reach: check failed: PermissionError"]


def test_unreadable_settings_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home, cwd, config = _layout(tmp_path)
    settings = config / "settings.json"
    _settings(settings, {})
    real_open = Path.open

    def guarded(self: Path, *a, **k):
        if self == settings:
            raise PermissionError(13, "Permission denied")
        return real_open(self, *a, **k)

    monkeypatch.setattr(Path, "open", guarded)
    errors: list[str] = []
    _run(tmp_path, home, cwd, config, errors)
    assert errors == [
        "secret reach: cannot read ~/.claude/settings.json: Permission denied"
    ]


def test_credential_stores_are_never_opened(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home, cwd, config = _layout(tmp_path)
    stores = [
        _write(home / ".ssh" / "id_rsa"),
        _write(home / ".aws" / "credentials"),
        _write(config / ".credentials.json"),
        _write(cwd / ".env"),
    ]
    _settings(config / "settings.json", {})
    opened: list[str] = []
    real_path_open = Path.open
    real_os_open = os.open

    def path_open(self: Path, *a, **k):
        opened.append(str(self))
        return real_path_open(self, *a, **k)

    def os_open(path, *a, **k):
        opened.append(str(path))
        return real_os_open(path, *a, **k)

    monkeypatch.setattr(Path, "open", path_open)
    monkeypatch.setattr(os, "open", os_open)
    findings = _run(tmp_path, home, cwd, config)
    assert {"REACH-001", "REACH-003"} <= set(_ids(findings))
    assert not set(opened) & {str(s) for s in stores}


def test_pathological_patterns_are_fast(tmp_path: Path) -> None:
    home, cwd, config = _layout(tmp_path)
    _write(home / ".aws" / "credentials")
    _write(cwd / ".env")
    hostile = "Read(~/" + "/".join(["**", "*a*a*a*a*a*a*b"] * 60) + ")"
    long_name = "Read(~/" + "*" * 400 + "x)"
    _settings(
        config / "settings.json",
        {"permissions": {"deny": [hostile, long_name] * 200}},
    )
    start = time.monotonic()
    findings = _run(tmp_path, home, cwd, config)
    assert time.monotonic() - start < 5
    assert "REACH-001" in _ids(findings)


def test_windows_paths_are_normalised() -> None:
    assert sr._posix(Path("C:\\Users\\alice")) == PurePosixPath("/c/Users/alice")


def test_match_segments() -> None:
    m = sr._match_segments
    assert m(["**", ".env"], (".env",))
    assert m(["**", ".env"], ("a", "b", ".env"))
    assert not m([".env"], ("a", ".env"))
    assert m([".aws", "**"], (".aws", "credentials"))
    assert m(["*"], ("x",))
    assert not m(["*"], ("x", "y"))


def test_results_deduplicated(tmp_path: Path) -> None:
    home, cwd, config = _layout(tmp_path)
    _write(home / ".aws" / "credentials")
    findings = _run(tmp_path, home, cwd, config)
    keys = [(f.id, f.finding_path) for f in findings]
    assert len(keys) == len(set(keys))


# ── Pipeline ──────────────────────────────────────────────────────────────────


def _isolated_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home, cwd, config = _layout(tmp_path)
    _write(home / ".aws" / "credentials")
    _write(cwd / ".env")
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(config))
    monkeypatch.chdir(cwd)
    return home


def test_default_scan_reports_and_explicit_path_does_not(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from mcp_audit.scanner import run_scan

    home = _isolated_home(tmp_path, monkeypatch)
    state = tmp_path / "state.json"
    result = run_scan(state_path=state)
    ids = {f.id for f in result.findings}
    assert {"REACH-001", "REACH-003"} <= ids
    reach = [f for f in result.findings if f.id.startswith("REACH-")]
    assert len(reach) == len({(f.id, f.finding_path) for f in reach})
    assert result.servers == []  # nothing joins the server list, lock or rug-pull

    config = tmp_path / "explicit.json"
    config.write_text(json.dumps({"mcpServers": {}}))
    explicit = run_scan(extra_paths=[config], state_path=state)
    assert not any(f.id.startswith("REACH-") for f in explicit.findings)
    assert str(home) not in "".join(e for e in result.errors)


def test_sarif_and_finding_text_do_not_leak_home(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from mcp_audit.output.sarif import format_sarif
    from mcp_audit.scanner import run_scan

    home = _isolated_home(tmp_path, monkeypatch)
    result = run_scan(state_path=tmp_path / "state.json")
    result.findings = [f for f in result.findings if f.id.startswith("REACH-")]
    assert result.findings
    sarif = format_sarif(result)
    assert str(home) not in sarif
    for f in result.findings:
        assert str(home) not in f.title + f.description + f.evidence + f.remediation


def test_demo_configs_are_silent() -> None:
    from mcp_audit.scanner import run_scan

    demo = Path(__file__).resolve().parent.parent / "demo" / "configs"
    result = run_scan(extra_paths=[demo], skip_rug_pull=True)
    assert not any(f.id.startswith("REACH-") for f in result.findings)


def test_non_advisory() -> None:
    from mcp_audit.advisory.classify import NON_ADVISORY_IDS

    assert {"REACH-001", "REACH-002", "REACH-003"} <= NON_ADVISORY_IDS


def test_check_hints_exist() -> None:
    from mcp_audit.output.check import _HINTS

    assert {"REACH-001", "REACH-002", "REACH-003"} <= set(_HINTS)


# ── Review fixes: precedence, platform, managed locks, allowRead ──────────────


def _ssh_store(tmp_path: Path) -> tuple[Path, Path, Path]:
    home, cwd, config = _layout(tmp_path)
    _write(home / ".ssh" / "id_rsa")
    return home, cwd, config


_SB_SSH = {"enabled": True, "filesystem": {"denyRead": ["~/.ssh"]}}


@pytest.mark.parametrize(
    ("user", "project", "local", "covered"),
    [
        (_SB_SSH, None, {"sandbox": {"enabled": False}}, False),  # /sandbox off
        (
            {"filesystem": {"denyRead": ["~/.ssh"]}},
            None,
            {"sandbox": {"enabled": True}},
            True,
        ),
        (_SB_SSH, {"sandbox": {"enabled": False}}, None, False),
        (
            _SB_SSH,
            {"sandbox": {"enabled": False}},
            {"sandbox": {"enabled": True}},
            True,
        ),
        (_SB_SSH, None, {"sandbox": {"filesystem": {"disabled": True}}}, False),
    ],
)
def test_sandbox_enabled_follows_precedence(
    tmp_path: Path, user: dict, project: dict | None, local: dict | None, covered: bool
) -> None:
    """Settings doc: the highest-precedence file wins (local > project > user)."""
    home, cwd, config = _ssh_store(tmp_path)
    _settings(config / "settings.json", {"sandbox": user})
    if project is not None:
        _settings(cwd / ".claude" / "settings.json", project)
    if local is not None:
        _settings(cwd / ".claude" / "settings.local.json", local)
    assert ("REACH-001" not in _ids(_run(tmp_path, home, cwd, config))) is covered


def test_managed_sandbox_value_wins(tmp_path: Path) -> None:
    home, cwd, config = _ssh_store(tmp_path)
    managed = tmp_path / "managed"
    _settings(managed / "managed-settings.json", {"sandbox": {"enabled": False}})
    _settings(cwd / ".claude" / "settings.local.json", {"sandbox": _SB_SSH})
    assert "REACH-001" in _ids(_run(tmp_path, home, cwd, config, managed=managed))
    _settings(
        managed / "managed-settings.d" / "50-on.json", {"sandbox": {"enabled": True}}
    )
    assert "REACH-001" not in _ids(_run(tmp_path, home, cwd, config, managed=managed))


def test_sandbox_never_covers_on_native_windows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Sandboxing doc: the sandbox runs on macOS, Linux and WSL2."""
    home, cwd, config = _ssh_store(tmp_path)
    _settings(config / "settings.json", {"sandbox": _SB_SSH})
    monkeypatch.setattr(sr, "_ON_WINDOWS", True)
    assert "REACH-001" in _ids(_run(tmp_path, home, cwd, config))


def test_bypass_mode_voids_sandbox_coverage(tmp_path: Path) -> None:
    """denyRead doesn't stop the Read tool, which needs no approval in bypass mode."""
    home, cwd, config = _ssh_store(tmp_path)
    _settings(
        config / "settings.json",
        {"sandbox": _SB_SSH, "permissions": {"defaultMode": "bypassPermissions"}},
    )
    assert "REACH-001" in _ids(_run(tmp_path, home, cwd, config))


def test_project_bypass_mode_is_ignored(tmp_path: Path) -> None:
    """Settings reference: bypassPermissions doesn't take effect from project files."""
    home, cwd, config = _ssh_store(tmp_path)
    _settings(config / "settings.json", {"sandbox": _SB_SSH})
    _settings(
        cwd / ".claude" / "settings.json",
        {"permissions": {"defaultMode": "bypassPermissions"}},
    )
    assert "REACH-001" not in _ids(_run(tmp_path, home, cwd, config))


@pytest.mark.parametrize("nested", [False, True])
def test_allow_managed_permission_rules_only_drops_user_rules(
    tmp_path: Path, nested: bool
) -> None:
    home, cwd, config = _ssh_store(tmp_path)
    managed = tmp_path / "managed"
    lock = {"allowManagedPermissionRulesOnly": True}
    _settings(
        managed / "managed-settings.json", {"permissions": lock} if nested else lock
    )
    _settings(config / "settings.json", {"permissions": {"deny": ["Read(~/.ssh/**)"]}})
    assert "REACH-001" in _ids(_run(tmp_path, home, cwd, config, managed=managed))
    _settings(
        managed / "managed-settings.d" / "deny.json",
        {"permissions": {"deny": ["Read(~/.ssh/**)"]}},
    )
    assert "REACH-001" not in _ids(_run(tmp_path, home, cwd, config, managed=managed))


@pytest.mark.parametrize(
    ("filesystem", "covered"),
    [
        # The sandboxing doc's overlap table.
        ({"denyRead": ["~/"], "allowRead": ["~/.ssh"]}, False),
        ({"denyRead": ["~/"], "allowRead": ["~/projects"]}, True),
        ({"allowRead": ["~/"], "denyRead": ["~/.ssh/id_rsa"]}, True),
        ({"allowRead": ["~/"], "denyRead": ["~/**/id_rsa"]}, True),
        ({"denyRead": ["~/.ssh"], "allowRead": ["~/.ssh/id_rsa"]}, False),
        ({"denyRead": ["~/.ssh"], "allowRead": ["~/.ssh"]}, False),  # tie: not counted
    ],
)
def test_allow_read_overlap(tmp_path: Path, filesystem: dict, covered: bool) -> None:
    home, cwd, config = _ssh_store(tmp_path)
    _settings(
        config / "settings.json",
        {"sandbox": {"enabled": True, "filesystem": filesystem}},
    )
    assert ("REACH-001" not in _ids(_run(tmp_path, home, cwd, config))) is covered


def test_allow_managed_read_paths_only_ignores_user_allow(tmp_path: Path) -> None:
    home, cwd, config = _ssh_store(tmp_path)
    managed = tmp_path / "managed"
    _settings(
        managed / "managed-settings.json",
        {
            "sandbox": {
                "enabled": True,
                "filesystem": {"denyRead": ["~/"], "allowManagedReadPathsOnly": True},
            }
        },
    )
    _settings(
        config / "settings.json", {"sandbox": {"filesystem": {"allowRead": ["~/.ssh"]}}}
    )
    assert "REACH-001" not in _ids(_run(tmp_path, home, cwd, config, managed=managed))


@pytest.mark.skipif(sys.platform.startswith("win"), reason="symlinks need privileges")
def test_file_symlink_needs_its_target_covered(tmp_path: Path) -> None:
    """A rule on the link name leaves the target readable by its own path."""
    home, cwd, config = _layout(tmp_path)
    vault = _write(tmp_path / "vault" / "key")
    (home / ".ssh").mkdir()
    (home / ".ssh" / "id_ecdsa").symlink_to(vault)
    _settings(config / "settings.json", {"permissions": {"deny": ["Read(~/.ssh/**)"]}})
    assert "~/.ssh/id_ecdsa" in _reach1(_run(tmp_path, home, cwd, config)).evidence


@pytest.mark.skipif(sys.platform.startswith("win"), reason="symlinks need privileges")
def test_symlinked_directory_either_path_covers(tmp_path: Path) -> None:
    home, cwd, config = _layout(tmp_path)
    _write(home / "dotfiles" / "ssh" / "id_rsa")
    (home / ".ssh").symlink_to(home / "dotfiles" / "ssh")
    _settings(config / "settings.json", {"permissions": {"deny": ["Read(~/.ssh/**)"]}})
    assert "REACH-001" not in _ids(_run(tmp_path, home, cwd, config))


def test_padded_specifier_is_not_counted(tmp_path: Path) -> None:
    home, cwd, config = _ssh_store(tmp_path)
    _settings(
        config / "settings.json", {"permissions": {"deny": ["Read( ~/.ssh/** )"]}}
    )
    assert "REACH-001" in _ids(_run(tmp_path, home, cwd, config))


def test_reach_001_points_at_a_store(tmp_path: Path) -> None:
    home, cwd, config = _ssh_store(tmp_path)
    f = _reach1(_run(tmp_path, home, cwd, config))
    assert f.finding_path == str(home / ".ssh" / "id_rsa")
