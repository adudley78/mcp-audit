"""Editor extension allowlist policy (STORY-0144, EXTPOL-001..003).

Locations are the vendors' documented ones (VS Code, Cursor, Windsurf / Devin
Desktop policy pages, quoted in ``extensions/policy.py``).  Everything is
injected: a temp home, a temp policy file and a fake registry.
"""

from __future__ import annotations

import json
from pathlib import Path

from mcp_audit.extensions import policy as ep
from mcp_audit.policy_sources import NOT_FOUND, PlatformSources, RegistryRead


def _env(
    tmp_path: Path,
    platform: str = "linux",
    registry=None,
) -> ep.Environment:
    appdata = str(tmp_path / "AppData") if platform == "win32" else None
    return ep.Environment(
        home=tmp_path / "home",
        platform=platform,
        appdata=appdata,
        userprofile=str(tmp_path / "home") if platform == "win32" else None,
        sources=PlatformSources(platform, registry, tmp_path / "prefs", None),
        linux_policy_file=tmp_path / "etc" / "vscode" / "policy.json",
    )


def _install(env: ep.Environment, editor: str) -> None:
    (env.home / f".{editor}" / "extensions").mkdir(parents=True, exist_ok=True)
    if editor == "windsurf":
        return


def _settings(env: ep.Environment, editor: str, text: str) -> Path:
    path = ep._user_settings_path(editor, env)
    assert path is not None
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def _policy_file(env: ep.Environment, doc: object) -> None:
    env.linux_policy_file.parent.mkdir(parents=True, exist_ok=True)
    env.linux_policy_file.write_text(json.dumps(doc))


def _run(env: ep.Environment):
    errors: list[str] = []
    findings = ep.extension_policy_findings(errors, env)
    return findings, errors


def _by(findings, fid: str, editor: str = "vscode"):
    return [f for f in findings if f.id == fid and f.client == editor]


class TestVSCodeLinux:
    def test_policy_file_is_enforced(self, tmp_path: Path) -> None:
        env = _env(tmp_path)
        _install(env, "vscode")
        _policy_file(
            env,
            {
                "AllowedExtensions": {
                    "microsoft": True,
                    "github": True,
                    "esbenp.prettier-vscode": True,
                    "ms-python.python": ["2025.1.0", "stable"],
                }
            },
        )
        findings, errors = _run(env)
        (f,) = _by(findings, "EXTPOL-001")
        assert f.severity.value == "INFO"
        assert "enforced (Linux policy file)" in f.title
        assert "2 publishers, 2 specific extension IDs, 1 with version lists" in (
            f.description
        )
        assert [x.id for x in findings] == ["EXTPOL-001"]
        assert errors == []

    def test_policy_value_may_be_a_json_string(self, tmp_path: Path) -> None:
        env = _env(tmp_path)
        _install(env, "vscode")
        _policy_file(env, {"AllowedExtensions": json.dumps({"microsoft": True})})
        (f,) = _by(_run(env)[0], "EXTPOL-001")
        assert "1 entry: 1 publisher" in f.description

    def test_user_settings_only_is_extpol_002(self, tmp_path: Path) -> None:
        env = _env(tmp_path)
        _install(env, "vscode")
        _settings(
            env,
            "vscode",
            '{\n // allow only these\n "extensions.allowed": {"microsoft": true,},\n}',
        )
        findings, _ = _run(env)
        assert not _by(findings, "EXTPOL-001")  # inventory is for enforced only
        (f,) = _by(findings, "EXTPOL-002")
        assert f.severity.value == "LOW"
        assert "not enforced" in f.description
        assert not _by(findings, "EXTPOL-003")

    def test_policy_beats_the_user_setting(self, tmp_path: Path) -> None:
        env = _env(tmp_path)
        _install(env, "vscode")
        _policy_file(env, {"AllowedExtensions": {"microsoft": True}})
        _settings(env, "vscode", '{"extensions.allowed": {"*": true}}')
        findings, _ = _run(env)
        assert [f.id for f in _by(findings, "EXTPOL-001")] == ["EXTPOL-001"]
        assert not _by(findings, "EXTPOL-002")
        assert "enforced" in _by(findings, "EXTPOL-001")[0].title

    def test_wildcard_policy_is_extpol_003(self, tmp_path: Path) -> None:
        env = _env(tmp_path)
        _install(env, "vscode")
        _policy_file(env, {"AllowedExtensions": {"*": True}})
        findings, _ = _run(env)
        (f,) = _by(findings, "EXTPOL-003")
        assert f.severity.value == "LOW"
        assert "restricts nothing" in f.description

    def test_wildcard_false_is_not_allow_all(self, tmp_path: Path) -> None:
        env = _env(tmp_path)
        _install(env, "vscode")
        _policy_file(env, {"AllowedExtensions": {"*": False, "microsoft": True}})
        assert not _by(_run(env)[0], "EXTPOL-003")

    def test_no_allowlist_anywhere_is_silent(self, tmp_path: Path) -> None:
        env = _env(tmp_path)
        _install(env, "vscode")
        _settings(env, "vscode", '{"editor.fontSize": 14}')
        assert _run(env) == ([], [])

    def test_policy_json_without_the_key_is_silent(self, tmp_path: Path) -> None:
        env = _env(tmp_path)
        _install(env, "vscode")
        _policy_file(env, {"ChatToolsAutoApprove": False})
        assert _run(env)[0] == []

    def test_bad_policy_file_is_reported_not_raised(self, tmp_path: Path) -> None:
        env = _env(tmp_path)
        _install(env, "vscode")
        env.linux_policy_file.parent.mkdir(parents=True)
        env.linux_policy_file.write_text("{nope")
        findings, errors = _run(env)
        assert any("not valid JSON" in e for e in errors)
        assert findings == []


class TestCursor:
    def test_linux_is_not_supported(self, tmp_path: Path) -> None:
        env = _env(tmp_path)
        _install(env, "cursor")
        _policy_file(env, {"AllowedExtensions": {"*": True}})  # not read for Cursor
        findings, _ = _run(env)
        assert findings == []  # nothing enforced, nothing set: no finding
        assert not _by(findings, "EXTPOL-003", "cursor")

    def test_user_setting_on_linux_is_extpol_002(self, tmp_path: Path) -> None:
        env = _env(tmp_path)
        _install(env, "cursor")
        _settings(env, "cursor", '{"extensions.allowed": {"anysphere": true}}')
        findings, _ = _run(env)
        (f,) = _by(findings, "EXTPOL-002", "cursor")
        assert "Linux policy not supported (Cursor docs)" in f.description

    def test_windows_registry_is_not_read(self, tmp_path: Path) -> None:
        def reader(hive, key, name):
            raise AssertionError("Cursor's registry path is not documented")

        env = _env(tmp_path, "win32", reader)
        (env.home / ".cursor" / "extensions").mkdir(parents=True)
        assert _run(env)[0] == []


class TestMacOS:
    def test_every_editor_is_silent_without_a_setting(self, tmp_path: Path) -> None:
        env = _env(tmp_path, "darwin")
        for editor in ("vscode", "cursor", "windsurf"):
            _install(env, editor)
        assert _run(env)[0] == []  # never "absent", never a finding

    def test_user_setting_gets_a_caveat(self, tmp_path: Path) -> None:
        env = _env(tmp_path, "darwin")
        _install(env, "vscode")
        _settings(env, "vscode", '{"extensions.allowed": {"microsoft": true}}')
        (f,) = _by(_run(env)[0], "EXTPOL-002")
        assert "would not be seen" in f.description


class TestWindows:
    def _reg(self, values: dict[tuple[str, str], str]):
        seen: list[tuple[str, str, str]] = []

        def read(hive: str, key: str, name: str) -> RegistryRead:
            seen.append((hive, key, name))
            text = values.get((hive, key))
            return RegistryRead(True, text) if text is not None else NOT_FOUND

        read.seen = seen  # type: ignore[attr-defined]
        return read

    def test_vscode_computer_policy_wins_over_user(self, tmp_path: Path) -> None:
        key = "Software\\Policies\\Microsoft\\VSCode"
        reg = self._reg(
            {
                ("HKLM", key): json.dumps({"microsoft": True}),
                ("HKCU", key): json.dumps({"*": True}),
            }
        )
        env = _env(tmp_path, "win32", reg)
        (env.home / ".vscode" / "extensions").mkdir(parents=True)
        findings, _ = _run(env)
        (f,) = _by(findings, "EXTPOL-001")
        assert "HKLM, computer configuration" in f.title
        assert not _by(findings, "EXTPOL-003")
        assert all(name == "AllowedExtensions" for _, _, name in reg.seen)

    def test_vscode_user_configuration_policy(self, tmp_path: Path) -> None:
        key = "Software\\Policies\\Microsoft\\VSCode"
        reg = self._reg({("HKCU", key): json.dumps({"*": True})})
        env = _env(tmp_path, "win32", reg)
        (env.home / ".vscode" / "extensions").mkdir(parents=True)
        findings, _ = _run(env)
        assert "HKCU, user configuration" in _by(findings, "EXTPOL-001")[0].title
        assert _by(findings, "EXTPOL-003")

    def test_windsurf_uses_its_documented_key(self, tmp_path: Path) -> None:
        reg = self._reg(
            {("HKLM", "Software\\Policies\\Windsurf\\Devin"): '{"windsurf": true}'}
        )
        env = _env(tmp_path, "win32", reg)
        (env.home / ".windsurf" / "extensions").mkdir(parents=True)
        findings, _ = _run(env)
        assert "enforced" in _by(findings, "EXTPOL-001", "windsurf")[0].title
        assert {k for _, k, _ in reg.seen} == {"Software\\Policies\\Windsurf\\Devin"}

    def test_unreadable_registry_value_is_reported(self, tmp_path: Path) -> None:
        def read(hive: str, key: str, name: str) -> RegistryRead:
            return RegistryRead(True, None, "value is not REG_SZ or REG_EXPAND_SZ")

        env = _env(tmp_path, "win32", read)
        (env.home / ".vscode" / "extensions").mkdir(parents=True)
        findings, errors = _run(env)
        assert any("REG_SZ" in e for e in errors)
        assert findings == []


class TestInstalledEditors:
    def test_nothing_installed_is_silent(self, tmp_path: Path) -> None:
        env = _env(tmp_path)
        _policy_file(env, {"AllowedExtensions": {"*": True}})
        assert _run(env) == ([], [])

    def test_windsurf_shares_the_linux_policy_file(self, tmp_path: Path) -> None:
        env = _env(tmp_path)
        _install(env, "windsurf")
        _policy_file(env, {"AllowedExtensions": {"windsurf": True}})
        (f,) = _by(_run(env)[0], "EXTPOL-001", "windsurf")
        assert "enforced (Linux policy file)" in f.title

    def test_settings_dir_alone_counts_as_installed(self, tmp_path: Path) -> None:
        env = _env(tmp_path)
        _settings(env, "vscode", '{"extensions.allowed": {"a": true}}')
        assert _by(_run(env)[0], "EXTPOL-002")

    def test_oversize_settings_not_read(self, tmp_path: Path) -> None:
        env = _env(tmp_path)
        _install(env, "vscode")
        _settings(env, "vscode", " " * (2 * 1024 * 1024))
        findings, errors = _run(env)
        assert any("limit" in e for e in errors)
        assert findings == []

    def test_shape_counts(self) -> None:
        shape = ep.allowlist_shape(
            {"*": False, "a": True, "b": False, "c.d": ["1.0.0"], "e.f": True}
        )
        assert (shape.entries, shape.publishers, shape.extension_ids) == (5, 2, 2)
        assert (shape.version_lists, shape.false_entries) == (1, 2)


def test_default_scan_includes_extension_policy(tmp_path: Path, monkeypatch) -> None:
    from mcp_audit.scanner import run_scan  # noqa: PLC0415

    env = _env(tmp_path)
    _install(env, "vscode")
    _settings(env, "vscode", '{"extensions.allowed": {"microsoft": true}}')
    monkeypatch.setattr("mcp_audit.extensions.policy.default_environment", lambda: env)
    monkeypatch.setattr("mcp_audit.discovery._home", lambda: tmp_path / "h")
    monkeypatch.chdir(tmp_path)
    result = run_scan(skip_rug_pull=True)
    ids = sorted(f.id for f in result.findings if f.id.startswith("EXTPOL-"))
    assert ids == ["EXTPOL-002"]
    explicit = run_scan(extra_paths=[tmp_path], skip_rug_pull=True)
    assert not [f for f in explicit.findings if f.id.startswith("EXTPOL-")]


class TestEditorsDoNotChangeTheVerdict:
    """Editors installed with no allowlist must change nothing; an enforced
    allowlist (EXTPOL-001, inventory) must not change score, grade or check."""

    def _scan(self, env, monkeypatch, tmp_path: Path):
        from mcp_audit.scanner import run_scan  # noqa: PLC0415

        monkeypatch.setattr(
            "mcp_audit.extensions.policy.default_environment", lambda: env
        )
        monkeypatch.setattr("mcp_audit.discovery._home", lambda: tmp_path / "h")
        (tmp_path / "h").mkdir(parents=True, exist_ok=True)
        monkeypatch.chdir(tmp_path)
        return run_scan(skip_rug_pull=True)

    def _check(self, env, monkeypatch, tmp_path: Path):
        from typer.testing import CliRunner  # noqa: PLC0415

        from mcp_audit.cli import app  # noqa: PLC0415

        monkeypatch.setattr(
            "mcp_audit.extensions.policy.default_environment", lambda: env
        )
        monkeypatch.setattr("mcp_audit.discovery._home", lambda: tmp_path / "h")
        (tmp_path / "h").mkdir(parents=True, exist_ok=True)
        monkeypatch.chdir(tmp_path)
        res = CliRunner().invoke(app, ["check"], env={"COLUMNS": "100"})
        return res.exit_code, res.output

    def _editors(self, env) -> None:
        for editor in ("vscode", "cursor", "windsurf"):
            _install(env, editor)
            _settings(env, editor, '{"editor.fontSize": 14}')

    def test_no_allowlist_changes_nothing(self, tmp_path: Path, monkeypatch) -> None:
        bare = _env(tmp_path / "bare")
        base = self._scan(bare, monkeypatch, tmp_path / "bare")
        base_check = self._check(bare, monkeypatch, tmp_path / "bare")

        with_editors = _env(tmp_path / "ed")
        self._editors(with_editors)
        got = self._scan(with_editors, monkeypatch, tmp_path / "ed")
        got_check = self._check(with_editors, monkeypatch, tmp_path / "ed")

        assert [f.id for f in got.findings] == [f.id for f in base.findings]
        assert got.score == base.score
        assert got_check == base_check
        assert "No MCP config files found" in got_check[1]

    def test_enforced_allowlist_is_not_scored_and_not_in_check(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        bare = _env(tmp_path / "bare")
        base = self._scan(bare, monkeypatch, tmp_path / "bare")
        base_check = self._check(bare, monkeypatch, tmp_path / "bare")

        enforced = _env(tmp_path / "enf")
        self._editors(enforced)
        _policy_file(enforced, {"AllowedExtensions": {"microsoft": True}})
        got = self._scan(enforced, monkeypatch, tmp_path / "enf")
        got_check = self._check(enforced, monkeypatch, tmp_path / "enf")

        assert [f.id for f in got.findings if f.id == "EXTPOL-001"]  # in scan
        assert got.score == base.score
        assert got.score is not None and base.score is not None
        assert got.score.numeric_score == base.score.numeric_score
        assert got_check == base_check

    def test_calculate_score_skips_inventory_only_ids(self) -> None:
        from mcp_audit.models import Finding, Severity  # noqa: PLC0415
        from mcp_audit.scoring import (  # noqa: PLC0415
            INVENTORY_ONLY_IDS,
            calculate_score,
        )

        assert "EXTPOL-001" in INVENTORY_ONLY_IDS
        f = Finding(
            id="EXTPOL-001",
            severity=Severity.INFO,
            analyzer="extension_policy",
            client="vscode",
            server="extension-policy",
            title="t",
            description="d",
            evidence="e",
            remediation="r",
        )
        assert calculate_score([f]).numeric_score == calculate_score([]).numeric_score
