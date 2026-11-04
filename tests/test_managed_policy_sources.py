"""Claude Code policy sources beyond files (STORY-0144, MANAGED-006/007).

Sources and ranking: https://code.claude.com/docs/en/managed-settings.  Every
platform reader is injected, so none of this touches a real registry, plist
root or policy location, and it runs on Linux CI.
"""

from __future__ import annotations

import json
import os
import plistlib
import sys
import types
from pathlib import Path

import pytest

from mcp_audit.analyzers import managed_policy as mp
from mcp_audit.models import ServerConfig
from mcp_audit.policy_sources import (
    NOT_FOUND,
    PlatformSources,
    RegistryRead,
    read_plist,
    winreg_reader,
)

_DENY_EVIL = {"deniedMcpServers": [{"serverName": "evil"}]}


def _server(name: str = "evil") -> ServerConfig:
    return ServerConfig(
        name=name,
        client="claude-code",
        config_path=Path("/h/.claude.json"),
        command=f"{name}-mcp",
    )


def _remote(name: str, url: str) -> ServerConfig:
    return ServerConfig(
        name=name, client="claude-code", config_path=Path("/h/.claude.json"), url=url
    )


def _registry(**values: dict | str | None):
    """Fake registry reader: ``HKLM=...``/``HKCU=...`` value (dict or raw text)."""

    def read(hive: str, subkey: str, name: str) -> RegistryRead:
        assert subkey == "SOFTWARE\\Policies\\ClaudeCode" and name == "Settings"
        value = values.get(hive)
        if value is None:
            return NOT_FOUND
        text = value if isinstance(value, str) else json.dumps(value)
        return RegistryRead(True, text)

    return read


def _win(**values: dict | str | None) -> PlatformSources:
    return PlatformSources("win32", _registry(**values), Path("/none"), None)


def _mac(root: Path, user: str | None = "alice") -> PlatformSources:
    return PlatformSources("darwin", None, root, user)


def _plist(root: Path, data: object, user: str | None = None) -> Path:
    folder = root / user if user else root
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / "com.anthropic.claudecode.plist"
    path.write_bytes(plistlib.dumps(data))
    return path


def _files(tmp_path: Path, settings: dict | None) -> Path:
    managed = tmp_path / "managed"
    managed.mkdir(exist_ok=True)
    if settings is not None:
        (managed / "managed-settings.json").write_text(json.dumps(settings))
    return managed


def _ids(findings) -> list[str]:
    return sorted(f.id for f in findings)


def _run(policy, servers=(), probe=None):
    return mp.analyze_managed_policy(
        policy, list(servers), [], Path("/h"), None, probe=probe
    )


class TestRegistry:
    def test_hkcu_only_is_set_not_enforced(self, tmp_path: Path) -> None:
        policy = mp.read_effective_policy(
            _files(tmp_path, None), [], _win(HKCU=_DENY_EVIL)
        )
        assert policy.source_label == "HKCU registry (user-writable)"
        findings = _run(policy, [_server()])
        assert _ids(findings) == ["MANAGED-001", "MANAGED-002", "MANAGED-006"]
        (f006,) = [f for f in findings if f.id == "MANAGED-006"]
        assert f006.severity.value == "MEDIUM"
        assert f006.title == "Claude Code policy is set, not enforced"
        assert "deniedMcpServers" in f006.evidence
        assert "HKCU registry (user-writable)" in f006.evidence
        (dead,) = [f for f in findings if f.id == "MANAGED-002"]
        assert "source: HKCU registry (user-writable)" in dead.evidence
        assert "denied" in dead.evidence

    def test_hklm_outranks_hkcu(self, tmp_path: Path) -> None:
        policy = mp.read_effective_policy(
            _files(tmp_path, None),
            [],
            _win(HKLM={"deniedMcpServers": [{"serverName": "x"}]}, HKCU=_DENY_EVIL),
        )
        assert policy.source_label == "HKLM registry"
        findings = _run(policy, [_server("evil")])
        assert "MANAGED-006" not in _ids(findings)
        assert "MANAGED-002" not in _ids(findings)  # HKCU's denylist is ignored
        (inv,) = [f for f in findings if f.id == "MANAGED-001"]
        assert "source: HKLM registry" in inv.evidence
        assert "HKCU registry (user-writable): ignored" in inv.description

    def test_hkcu_ignored_when_a_file_is_present(self, tmp_path: Path) -> None:
        policy = mp.read_effective_policy(
            _files(tmp_path, {"model": "opus"}), [], _win(HKCU=_DENY_EVIL)
        )
        assert policy.source_kind == "files"
        assert "MANAGED-006" not in _ids(_run(policy, [_server()]))

    def test_hklm_beats_the_files(self, tmp_path: Path) -> None:
        policy = mp.read_effective_policy(
            _files(tmp_path, {"deniedMcpServers": [{"serverName": "other"}]}),
            [],
            _win(HKLM=_DENY_EVIL),
        )
        # first-wins: the file's allowlist is ignored, but its denylist is
        # still read from every admin source.
        assert policy.source_label == "HKLM registry"
        assert {e.value for e in policy.denied} == {"evil", "other"}

    def test_malformed_hklm_is_manage_007_and_scan_continues(
        self, tmp_path: Path
    ) -> None:
        errors: list[str] = []
        findings = mp.managed_policy_findings(
            [_server()],
            [],
            None,
            errors,
            directory=_files(tmp_path, _DENY_EVIL),
            sources=_win(HKLM="[1, 2]"),
        )
        assert _ids(findings) == ["MANAGED-001", "MANAGED-007"]
        (f,) = [f for f in findings if f.id == "MANAGED-007"]
        assert f.severity.value == "INFO"
        assert "refuses to start" in f.description
        assert any("not a JSON object" in e for e in errors)

    def test_malformed_hkcu_is_ignored(self, tmp_path: Path) -> None:
        policy = mp.read_effective_policy(
            _files(tmp_path, None), [], _win(HKCU="{nope")
        )
        assert _ids(_run(policy)) == []

    def test_oversize_value_is_reported_not_parsed(self, tmp_path: Path) -> None:
        big = json.dumps({"x": "a" * (mp.MAX_FILE_BYTES + 10)})
        errors: list[str] = []
        policy = mp.read_effective_policy(
            _files(tmp_path, None), errors, _win(HKLM=big)
        )
        assert policy.malformed_sources[0].problem == "over the 1048576-byte limit"

    def test_no_registry_off_windows(self, tmp_path: Path) -> None:
        sources = PlatformSources(
            "linux", _registry(HKLM=_DENY_EVIL), Path("/none"), None
        )
        policy = mp.read_effective_policy(_files(tmp_path, None), [], sources)
        assert not policy.present


class TestPlist:
    def test_plist_outranks_the_file_first_wins(self, tmp_path: Path) -> None:
        root = tmp_path / "prefs"
        _plist(
            root,
            {
                "allowManagedMcpServersOnly": True,
                "allowedMcpServers": [{"serverName": "mine"}],
            },
        )
        managed = _files(
            tmp_path, {"allowedMcpServers": [{"serverUrl": "https://f.example/*"}]}
        )
        policy = mp.read_effective_policy(managed, [], _mac(root))
        assert policy.source_label == "macOS configuration profile (device)"
        assert policy.lock is True
        assert [str(e.value) for e in policy.allowed or []] == ["mine"]
        findings = _run(policy, [_server("evil")])
        (dead,) = [f for f in findings if f.id == "MANAGED-002"]
        assert "source: macOS configuration profile (device)" in dead.evidence
        assert "not-allowed" in dead.evidence

    def test_file_without_the_key_does_not_override_the_lock(
        self, tmp_path: Path
    ) -> None:
        root = tmp_path / "prefs"
        _plist(root, {"allowManagedMcpServersOnly": True})
        managed = _files(tmp_path, {"deniedMcpServers": [{"serverName": "evil"}]})
        policy = mp.read_effective_policy(managed, [], _mac(root))
        assert policy.lock is True
        assert {e.value for e in policy.denied} == {"evil"}

    def test_merge_unions_denylists(self, tmp_path: Path) -> None:
        root = tmp_path / "prefs"
        _plist(
            root,
            {
                "managedSourcesBehavior": "merge",
                "deniedMcpServers": [{"serverName": "from-plist"}],
                "allowedMcpServers": [{"serverName": "p"}],
            },
        )
        managed = _files(
            tmp_path,
            {
                "deniedMcpServers": [{"serverName": "from-file"}],
                "allowedMcpServers": [{"serverName": "f"}],
                "allowManagedMcpServersOnly": True,
            },
        )
        policy = mp.read_effective_policy(managed, [], _mac(root))
        assert policy.source_kind == "merged"
        assert {e.value for e in policy.denied} == {"from-plist", "from-file"}
        # allowedMcpServers is taken whole from the highest-ranked source that
        # sets it; lower sources' entries are NOT added.
        assert {str(e.value) for e in policy.allowed or []} == {"p"}
        assert policy.lock is True  # strictest wins
        (inv,) = [f for f in _run(policy) if f.id == "MANAGED-001"]
        assert 'managedSourcesBehavior "merge"' in inv.description

    def test_merge_higher_source_wins_a_provided_server(self, tmp_path: Path) -> None:
        root = tmp_path / "prefs"
        hi = {"type": "http", "url": "https://hi.example/mcp"}
        lo = {"type": "http", "url": "https://lo.example/mcp"}
        _plist(
            root, {"managedSourcesBehavior": "merge", "managedMcpServers": {"s": hi}}
        )
        managed = _files(tmp_path, {"managedMcpServers": {"s": lo}})
        policy = mp.read_effective_policy(managed, [], _mac(root))
        assert policy.provided["s"]["url"] == "https://hi.example/mcp"

    def test_user_scoped_plist_ranks_after_device(self, tmp_path: Path) -> None:
        root = tmp_path / "prefs"
        _plist(root, {"deniedMcpServers": [{"serverName": "dev"}]})
        _plist(root, {"deniedMcpServers": [{"serverName": "usr"}]}, user="alice")
        policy = mp.read_effective_policy(_files(tmp_path, None), [], _mac(root))
        assert policy.source_label == "macOS configuration profile (device)"
        assert {e.value for e in policy.denied} == {"dev", "usr"}

    def test_malformed_plist_is_manage_007(self, tmp_path: Path) -> None:
        root = tmp_path / "prefs"
        root.mkdir()
        (root / "com.anthropic.claudecode.plist").write_text("not a plist")
        errors: list[str] = []
        findings = mp.managed_policy_findings(
            [_server()],
            [],
            None,
            errors,
            directory=_files(tmp_path, _DENY_EVIL),
            sources=_mac(root),
        )
        assert _ids(findings) == ["MANAGED-001", "MANAGED-007"]
        assert any("not a valid plist" in e for e in errors)

    def test_plist_whose_top_level_is_a_list_is_malformed(self, tmp_path: Path) -> None:
        root = tmp_path / "prefs"
        _plist(root, ["a"])
        policy = mp.read_effective_policy(_files(tmp_path, None), [], _mac(root))
        assert policy.malformed_sources
        assert _ids(_run(policy)) == ["MANAGED-001", "MANAGED-007"]

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlinks only")
    def test_symlink_out_of_the_root_is_not_followed(self, tmp_path: Path) -> None:
        root = tmp_path / "prefs"
        root.mkdir()
        outside = tmp_path / "outside.plist"
        outside.write_bytes(plistlib.dumps(_DENY_EVIL))
        (root / "com.anthropic.claudecode.plist").symlink_to(outside)
        got = read_plist(root / "com.anthropic.claudecode.plist", root)
        assert got.found and got.data is None
        assert "outside" in (got.problem or "")

    def test_plist_over_the_cap_is_not_parsed(self, tmp_path: Path) -> None:
        root = tmp_path / "prefs"
        _plist(root, {"x": "a" * (2 * 1024 * 1024)})
        got = read_plist(root / "com.anthropic.claudecode.plist", root)
        assert got.data is None and "limit" in (got.problem or "")

    def test_plist_bytes_and_dates_become_json_shapes(self, tmp_path: Path) -> None:
        import datetime  # noqa: PLC0415

        root = tmp_path / "prefs"
        _plist(
            root,
            {"blob": b"\x01", "when": datetime.datetime(2026, 1, 1), "k": [1]},
        )
        got = read_plist(root / "com.anthropic.claudecode.plist", root)
        assert got.data == {"blob": "01", "when": "2026-01-01T00:00:00", "k": [1]}

    def test_not_darwin_reads_no_plist(self, tmp_path: Path) -> None:
        root = tmp_path / "prefs"
        _plist(root, _DENY_EVIL)
        sources = PlatformSources("linux", None, root, "alice")
        assert not mp.read_effective_policy(_files(tmp_path, None), [], sources).present


class _Stat:
    def __init__(self, uid: int) -> None:
        self.st_uid = uid


def _probe(*, owner: int, writable: bool, uid: int = 1000, wsl: bool = False):
    return mp.FsProbe(
        uid=uid,
        stat=lambda p: _Stat(owner),  # type: ignore[return-value]
        access=lambda p, m: writable,
        wsl=wsl,
    )


class TestFileWritability:
    def test_user_writable_file_is_not_enforced(self, tmp_path: Path) -> None:
        policy = mp.read_effective_policy(
            _files(tmp_path, _DENY_EVIL), [], _mac(tmp_path / "none")
        )
        findings = _run(policy, probe=_probe(owner=1000, writable=True))
        (f,) = [f for f in findings if f.id == "MANAGED-006"]
        assert f.severity.value == "MEDIUM"
        assert "deniedMcpServers" in f.evidence
        assert "managed-settings.json" in f.evidence

    def test_owner_alone_is_enough(self, tmp_path: Path) -> None:
        policy = mp.read_effective_policy(_files(tmp_path, _DENY_EVIL), [])
        findings = _run(policy, probe=_probe(owner=1000, writable=False))
        assert "MANAGED-006" in _ids(findings)

    def test_root_owned_is_enforced(self, tmp_path: Path) -> None:
        policy = mp.read_effective_policy(_files(tmp_path, _DENY_EVIL), [])
        findings = _run(policy, probe=_probe(owner=0, writable=False))
        assert "MANAGED-006" not in _ids(findings)

    def test_running_as_root_or_on_windows_skips(self, tmp_path: Path) -> None:
        policy = mp.read_effective_policy(_files(tmp_path, _DENY_EVIL), [])
        for uid in (0, None):
            probe = _probe(owner=1000, writable=True, uid=uid)  # type: ignore[arg-type]
            assert "MANAGED-006" not in _ids(_run(policy, probe=probe))

    def test_writable_directory_alone_counts(self, tmp_path: Path) -> None:
        policy = mp.read_effective_policy(_files(tmp_path, _DENY_EVIL), [])
        managed = policy.directory

        probe = mp.FsProbe(
            uid=1000,
            stat=lambda p: _Stat(0),  # type: ignore[return-value]
            access=lambda p, m: p == managed,
        )
        (f,) = [f for f in _run(policy, probe=probe) if f.id == "MANAGED-006"]
        assert str(managed) in f.evidence

    def test_wsl_is_noted(self, tmp_path: Path) -> None:
        import dataclasses  # noqa: PLC0415

        policy = mp.read_effective_policy(_files(tmp_path, _DENY_EVIL), [])
        policy = dataclasses.replace(policy, directory=Path("/etc/claude-code"))
        # Root-owned and not writable by permission bits: only the documented
        # WSL fact makes /etc/claude-code user-writable.
        (f,) = [
            f
            for f in _run(policy, probe=_probe(owner=0, writable=False, wsl=True))
            if f.id == "MANAGED-006"
        ]
        assert "On WSL, /etc/claude-code is user-writable" in f.description
        assert "WSL: Anthropic notes" in f.evidence

    def test_real_tmp_file_is_writable_by_this_user(self, tmp_path: Path) -> None:
        if not hasattr(os, "geteuid") or os.geteuid() == 0:
            pytest.skip("needs a non-root POSIX user")
        policy = mp.read_effective_policy(_files(tmp_path, _DENY_EVIL), [])
        # The conftest replaces mp.default_fs_probe with a root fake; build the
        # real probe from os directly.
        real = mp.FsProbe(os.geteuid(), lambda p: p.stat(), os.access)
        assert "MANAGED-006" in _ids(_run(policy, probe=real))

    def test_plist_in_force_means_files_are_not_probed(self, tmp_path: Path) -> None:
        root = tmp_path / "prefs"
        _plist(root, _DENY_EVIL)
        policy = mp.read_effective_policy(
            _files(tmp_path, {"model": "x"}), [], _mac(root)
        )
        findings = _run(policy, probe=_probe(owner=1000, writable=True))
        assert "MANAGED-006" not in _ids(findings)


class TestFileOnlyIsUnchanged:
    def test_no_platform_source_returns_the_file_policy(self, tmp_path: Path) -> None:
        managed = _files(tmp_path, _DENY_EVIL)
        plain = mp.read_managed_policy(managed, [])
        eff = mp.read_effective_policy(managed, [], _mac(tmp_path / "empty"))
        assert eff.source_label is None and eff.denied == plain.denied
        assert eff is not None and eff.platform_sources_read is False

    def test_linux_keeps_the_pre_story_caveat(self, tmp_path: Path) -> None:
        sources = PlatformSources("linux", None, Path("/none"), None)
        policy = mp.read_effective_policy(_files(tmp_path, _DENY_EVIL), [], sources)
        (inv,) = [f for f in _run(policy) if f.id == "MANAGED-001"]
        assert "An MDM profile, an HKLM registry policy" in inv.description


class TestNothingIsWritten:
    def test_registry_reader_calls_only_read_apis(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls: list[str] = []

        def boom(name: str):
            def _raise(*a, **k):
                raise AssertionError(f"winreg.{name} must never be called")

            return _raise

        class _Key:
            def __enter__(self):
                return self

            def __exit__(self, *a) -> None:
                return None

        fake = types.SimpleNamespace(
            HKEY_LOCAL_MACHINE=1,
            HKEY_CURRENT_USER=2,
            KEY_READ=0x20019,
            REG_SZ=1,
            REG_EXPAND_SZ=2,
            OpenKey=lambda root, sub, res, access: (
                calls.append(f"open:{access:#x}") or _Key()
            ),
            QueryValueEx=lambda key, name: (json.dumps(_DENY_EVIL), 1),
            **{
                n: boom(n)
                for n in (
                    "CreateKey",
                    "CreateKeyEx",
                    "SetValue",
                    "SetValueEx",
                    "DeleteKey",
                    "DeleteKeyEx",
                    "DeleteValue",
                    "SaveKey",
                    "LoadKey",
                )
            },
        )
        monkeypatch.setitem(sys.modules, "winreg", fake)
        monkeypatch.setattr(sys, "platform", "win32")
        for hive in ("HKLM", "HKCU"):
            got = winreg_reader(hive, "SOFTWARE\\Policies\\ClaudeCode", "Settings")
            assert got.found and got.text == json.dumps(_DENY_EVIL)
        assert calls == ["open:0x20019", "open:0x20019"]  # KEY_READ only

    def test_wrong_value_type_is_a_problem(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class _Key:
            def __enter__(self):
                return self

            def __exit__(self, *a) -> None:
                return None

        fake = types.SimpleNamespace(
            HKEY_LOCAL_MACHINE=1,
            HKEY_CURRENT_USER=2,
            KEY_READ=1,
            REG_SZ=1,
            REG_EXPAND_SZ=2,
            OpenKey=lambda *a: _Key(),
            QueryValueEx=lambda key, name: (5, 4),
        )
        monkeypatch.setitem(sys.modules, "winreg", fake)
        monkeypatch.setattr(sys, "platform", "win32")
        got = winreg_reader("HKLM", "x", "Settings")
        assert got.found and got.text is None and "REG_SZ" in (got.problem or "")

    def test_reader_is_inert_off_windows(self) -> None:
        if sys.platform.startswith("win"):
            pytest.skip("real registry")
        assert winreg_reader("HKLM", "x", "Settings") == NOT_FOUND

    def test_the_module_never_names_a_write_api(self) -> None:
        src = (
            Path(mp.__file__).read_text()
            + Path(sys.modules["mcp_audit.policy_sources"].__file__ or "").read_text()
        )
        for name in ("SetValue", "CreateKey", "DeleteKey", "DeleteValue", "KEY_WRITE"):
            assert name not in src.replace("must never", "")


class TestEndToEnd:
    def test_default_scan_uses_injected_sources(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from mcp_audit.scanner import run_scan  # noqa: PLC0415

        home = tmp_path / "home"
        home.mkdir()
        monkeypatch.setattr("mcp_audit.discovery._home", lambda: home)
        monkeypatch.setattr(
            "mcp_audit.plugins.mods.managed_settings_dir",
            lambda: tmp_path / "no-files",
        )
        monkeypatch.setattr(
            "mcp_audit.analyzers.managed_policy.default_platform_sources",
            lambda: _win(HKCU=_DENY_EVIL),
        )
        monkeypatch.chdir(tmp_path)
        result = run_scan(skip_rug_pull=True)
        ids = [f.id for f in result.findings if f.id.startswith("MANAGED-")]
        assert "MANAGED-006" in ids
        assert result.errors == [] or all("managed" not in e for e in result.errors)


# ── Review fixes (PR #267) ────────────────────────────────────────────────────


def _desc(findings, fid: str) -> str:
    return " ".join(f.description + f.evidence for f in findings if f.id == fid)


class TestPolicyKeys:
    """Docs: a policy key is any key but the two control keys; a source with
    none (or only null values) doesn't count and isn't 'present'."""

    FILE_ALLOW = {"allowedMcpServers": [{"serverUrl": "https://ok.example/*"}]}

    def test_control_key_only_hklm_does_not_outrank_the_file(
        self, tmp_path: Path
    ) -> None:
        policy = mp.read_effective_policy(
            _files(tmp_path, self.FILE_ALLOW),
            [],
            _win(HKLM={"wslInheritsWindowsSettings": True}),
        )
        assert policy.source_label is None  # files alone, output unchanged
        assert [str(e.value) for e in policy.allowed or []] == ["https://ok.example/*"]

    @pytest.mark.parametrize(
        "hklm",
        [{}, {"allowedMcpServers": None}, {"managedSourcesBehavior": "first-wins"}],
    )
    def test_empty_or_null_hklm_is_not_an_admin_document(
        self, tmp_path: Path, hklm: dict
    ) -> None:
        policy = mp.read_effective_policy(
            _files(tmp_path, None), [], _win(HKLM=hklm, HKCU=_DENY_EVIL)
        )
        assert policy.source_kind == "hkcu"
        findings = _run(policy, [_server()])
        assert "MANAGED-006" in _ids(findings)
        assert "MANAGED-002" in _ids(findings)  # the HKCU denylist is evaluated

    @pytest.mark.parametrize("settings", [{}, {"wslInheritsWindowsSettings": True}])
    def test_empty_or_control_only_file_leaves_hkcu_in_force(
        self, tmp_path: Path, settings: dict
    ) -> None:
        policy = mp.read_effective_policy(
            _files(tmp_path, settings), [], _win(HKCU=_DENY_EVIL)
        )
        assert policy.source_kind == "hkcu"
        assert "MANAGED-006" in _ids(_run(policy, [_server()]))

    def test_empty_managed_settings_file_text_is_an_empty_object(
        self, tmp_path: Path
    ) -> None:
        managed = tmp_path / "managed"
        managed.mkdir()
        (managed / "managed-settings.json").write_text("")
        policy = mp.read_effective_policy(managed, [], _win(HKCU=_DENY_EVIL))
        assert policy.source_kind == "hkcu"

    @pytest.mark.parametrize("hkcu", [{}, {"managedSourcesBehavior": "merge"}, None])
    def test_hkcu_without_a_policy_key_is_silent(
        self, tmp_path: Path, hkcu: dict | None
    ) -> None:
        policy = mp.read_effective_policy(_files(tmp_path, None), [], _win(HKCU=hkcu))
        assert "MANAGED-006" not in _ids(_run(policy))
        assert not policy.present

    def test_unparsable_file_blocks_hkcu(self, tmp_path: Path) -> None:
        managed = tmp_path / "managed"
        managed.mkdir()
        (managed / "managed-settings.json").write_text("{nope")
        policy = mp.read_effective_policy(managed, [], _win(HKCU=_DENY_EVIL))
        assert policy.source_kind != "hkcu"
        assert "MANAGED-006" not in _ids(_run(policy))

    def test_merge_key_read_from_the_highest_source_carrying_it(
        self, tmp_path: Path
    ) -> None:
        # HKLM carries only managedSourcesBehavior: "merge" and no policy key,
        # yet it is the highest-ranked source carrying the key, so it merges.
        files = {
            "deniedMcpServers": [{"serverName": "from-file"}],
            "allowedMcpServers": [{"serverName": "f"}],
        }
        policy = mp.read_effective_policy(
            _files(tmp_path, files),
            [],
            _win(HKLM={"managedSourcesBehavior": "merge"}),
        )
        # Only one source delivers policy, so there is nothing to compose.
        assert {e.value for e in policy.denied} == {"from-file"}
        root = tmp_path / "prefs"
        _plist(root, {"managedSourcesBehavior": "merge", "model": "x"})
        policy = mp.read_effective_policy(_files(tmp_path, files), [], _mac(root))
        assert policy.source_kind == "merged"

    def test_hklm_control_only_does_not_hide_the_unlocked_file_allowlist(
        self, tmp_path: Path
    ) -> None:
        policy = mp.read_effective_policy(
            _files(tmp_path, self.FILE_ALLOW),
            [],
            _win(HKLM={"wslInheritsWindowsSettings": True}),
        )
        findings = _run(policy, [_remote("rogue", "https://rogue.example/mcp")])
        assert "MANAGED-002" in _ids(findings)


class TestCrossSourceKeys:
    def test_lock_in_hklm_takes_the_file_allowlist(self, tmp_path: Path) -> None:
        """Docs: while the lock is on, the managed allowedMcpServers list comes
        from the highest-ranked admin source that sets one."""
        policy = mp.read_effective_policy(
            _files(
                tmp_path,
                {"allowedMcpServers": [{"serverUrl": "https://ok.example/*"}]},
            ),
            [],
            _win(
                HKLM={
                    "allowManagedMcpServersOnly": True,
                    "deniedMcpServers": [{"serverName": "evil"}],
                }
            ),
        )
        assert policy.source_label == "HKLM registry"
        findings = _run(policy, [_remote("rogue", "https://rogue.example/mcp")])
        (dead,) = [f for f in findings if f.id == "MANAGED-002"]
        assert "not-allowed" in dead.evidence
        ok = _run(policy, [_remote("fine", "https://ok.example/mcp")])
        assert "MANAGED-002" not in _ids(ok)

    def test_without_the_lock_the_file_allowlist_is_ignored(
        self, tmp_path: Path
    ) -> None:
        policy = mp.read_effective_policy(
            _files(
                tmp_path,
                {"allowedMcpServers": [{"serverUrl": "https://ok.example/*"}]},
            ),
            [],
            _win(HKLM={"deniedMcpServers": [{"serverName": "evil"}]}),
        )
        assert policy.allowed is None

    def test_higher_source_list_wins_under_the_lock(self, tmp_path: Path) -> None:
        root = tmp_path / "prefs"
        _plist(
            root,
            {
                "allowManagedMcpServersOnly": True,
                "allowedMcpServers": [{"serverName": "p"}],
            },
        )
        policy = mp.read_effective_policy(
            _files(tmp_path, {"allowedMcpServers": [{"serverName": "f"}]}),
            [],
            _mac(root),
        )
        assert [str(e.value) for e in policy.allowed or []] == ["p"]

    def test_merge_takes_the_allowlist_whole(self, tmp_path: Path) -> None:
        root = tmp_path / "prefs"
        _plist(root, {"managedSourcesBehavior": "merge", "model": "x"})
        policy = mp.read_effective_policy(
            _files(
                tmp_path,
                {
                    "allowedMcpServers": [{"serverName": "f"}],
                    "deniedMcpServers": [{"serverName": "d"}],
                },
            ),
            [],
            _mac(root),
        )
        assert [str(e.value) for e in policy.allowed or []] == ["f"]
        assert {e.value for e in policy.denied} == {"d"}

    def test_merge_invalid_value_comes_from_the_setter_only(
        self, tmp_path: Path
    ) -> None:
        root = tmp_path / "prefs"
        _plist(
            root,
            {"managedSourcesBehavior": "merge", "allowedMcpServers": "oops"},
        )
        policy = mp.read_effective_policy(
            _files(tmp_path, {"allowedMcpServers": [{"serverName": "f"}]}),
            [],
            _mac(root),
        )
        assert policy.allowed == [] and policy.allowed_invalid_value


class TestPlistHardening:
    def test_shared_reference_plist_is_bounded(self, tmp_path: Path) -> None:
        import time  # noqa: PLC0415

        obj: object = "x"
        for _ in range(40):
            obj = [obj, obj]
        root = tmp_path / "prefs"
        root.mkdir()
        (root / "com.anthropic.claudecode.plist").write_bytes(
            plistlib.dumps({"deniedMcpServers": obj}, fmt=plistlib.FMT_BINARY)
        )
        start = time.monotonic()
        got = read_plist(root / "com.anthropic.claudecode.plist", root)
        assert time.monotonic() - start < 2
        assert got.data is None and got.problem == "plist too complex"

    def test_shared_references_within_budget_are_reused(self, tmp_path: Path) -> None:
        shared = [{"serverName": "a"}]
        root = tmp_path / "prefs"
        _plist(root, {"deniedMcpServers": shared + shared})
        got = read_plist(root / "com.anthropic.claudecode.plist", root)
        assert got.data == {"deniedMcpServers": [{"serverName": "a"}] * 2}

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlinks only")
    def test_symlink_loop_does_not_raise_and_files_survive(
        self, tmp_path: Path
    ) -> None:
        root = tmp_path / "prefs"
        root.mkdir()
        loop = root / "com.anthropic.claudecode.plist"
        os.symlink(loop, loop)
        got = read_plist(loop, root)
        assert got.found and got.data is None
        errors: list[str] = []
        findings = mp.managed_policy_findings(
            [_server()],
            [],
            None,
            errors,
            directory=_files(tmp_path, _DENY_EVIL),
            sources=_mac(root),
        )
        assert "MANAGED-001" in _ids(findings)
        assert "MANAGED-007" not in _ids(findings)  # not "malformed"

    def test_a_crashing_reader_costs_only_its_source(self, tmp_path: Path) -> None:
        def boom(hive, key, name):
            raise RuntimeError("registry exploded")

        errors: list[str] = []
        findings = mp.managed_policy_findings(
            [_server()],
            [],
            None,
            errors,
            directory=_files(tmp_path, _DENY_EVIL),
            sources=PlatformSources("win32", boom, Path("/none"), None),
        )
        assert _ids(findings) == ["MANAGED-001", "MANAGED-002"]
        assert any("registry exploded" in e for e in errors)

    @pytest.mark.parametrize("user", ["../../etc", "alice/../bob", "..", "a\\b"])
    def test_unsafe_user_name_reads_no_user_plist(
        self, tmp_path: Path, user: str
    ) -> None:
        root = tmp_path / "prefs"
        _plist(root, {"deniedMcpServers": [{"serverName": "x"}]}, user="alice")
        (tmp_path / "etc").mkdir(exist_ok=True)
        policy = mp.read_effective_policy(
            _files(tmp_path, None), [], _mac(root, user=user)
        )
        assert policy.source_label is None and not policy.malformed_sources

    def test_default_user_comes_from_the_password_database(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        if not hasattr(os, "geteuid"):
            pytest.skip("POSIX only")
        import pwd  # noqa: PLC0415

        from mcp_audit import policy_sources  # noqa: PLC0415

        monkeypatch.setenv("LOGNAME", "../../evil")
        monkeypatch.setenv("USER", "../../evil")
        assert policy_sources._current_user() == pwd.getpwuid(os.geteuid()).pw_name


class TestReadFailureKinds:
    def test_access_denied_is_not_manage_007(self, tmp_path: Path) -> None:
        def denied(hive, key, name):
            return RegistryRead(True, None, "access denied: PermissionError", "denied")

        errors: list[str] = []
        findings = mp.managed_policy_findings(
            [_server()],
            [],
            None,
            errors,
            directory=_files(tmp_path, _DENY_EVIL),
            sources=PlatformSources("win32", denied, Path("/none"), None),
        )
        assert _ids(findings) == ["MANAGED-001"]  # no 007, no verdicts
        (inv,) = findings
        assert "starts without that source's policies" in inv.description
        assert "refuses to start" not in inv.description
        # The withheld-verdicts sentence blames the platform source, not files.
        withheld = inv.description.split("verdicts withheld")[1].split(",")[0]
        assert "macOS profile or registry value" in withheld
        assert "managed settings file" not in withheld

    def test_other_read_failure_is_not_manage_007(self, tmp_path: Path) -> None:
        def broken(hive, key, name):
            return RegistryRead(True, None, "cannot read: OSError", "unreadable")

        findings = mp.managed_policy_findings(
            [],
            [],
            None,
            [],
            directory=_files(tmp_path, _DENY_EVIL),
            sources=PlatformSources("win32", broken, Path("/none"), None),
        )
        assert "MANAGED-007" not in _ids(findings)

    def test_hklm_empty_string_is_malformed(self, tmp_path: Path) -> None:
        findings = mp.managed_policy_findings(
            [],
            [],
            None,
            [],
            directory=_files(tmp_path, _DENY_EVIL),
            sources=_win(HKLM=""),
        )
        assert "MANAGED-007" in _ids(findings)

    def test_unreadable_plist_kinds(self, tmp_path: Path) -> None:
        if not hasattr(os, "geteuid") or os.geteuid() == 0:
            pytest.skip("needs a non-root POSIX user")
        root = tmp_path / "prefs"
        path = _plist(root, _DENY_EVIL)
        path.chmod(0)
        try:
            got = read_plist(path, root)
        finally:
            path.chmod(0o600)
        assert got.problem_kind == "denied"


class TestProbeGaps:
    def test_empty_user_writable_dropin_dir_counts(self, tmp_path: Path) -> None:
        managed = _files(tmp_path, _DENY_EVIL)
        (managed / "managed-settings.d").mkdir()
        policy = mp.read_effective_policy(managed, [], None)
        dropins = managed / "managed-settings.d"

        probe = mp.FsProbe(
            uid=1000,
            stat=lambda p: _Stat(0 if p != dropins else 1000),  # type: ignore[return-value]
            access=lambda p, m: False,
        )
        (f,) = [f for f in _run(policy, probe=probe) if f.id == "MANAGED-006"]
        assert str(dropins) in f.evidence
        assert "owned by the current user" in f.evidence

    def test_managed_mcp_json_is_probed(self, tmp_path: Path) -> None:
        managed = tmp_path / "managed"
        managed.mkdir()
        (managed / "managed-mcp.json").write_text('{"mcpServers": {"corp": {}}}')
        policy = mp.read_effective_policy(managed, [], None)
        mcp_file = managed / "managed-mcp.json"
        probe = mp.FsProbe(
            uid=1000,
            stat=lambda p: _Stat(0),  # type: ignore[return-value]
            access=lambda p, m: p == mcp_file,
        )
        (f,) = [f for f in _run(policy, probe=probe) if f.id == "MANAGED-006"]
        assert "managed-mcp.json" in f.evidence

    def test_group_write_is_labelled(self, tmp_path: Path) -> None:
        policy = mp.read_effective_policy(_files(tmp_path, _DENY_EVIL), [], None)
        (f,) = [
            f
            for f in _run(policy, probe=_probe(owner=0, writable=True))
            if f.id == "MANAGED-006"
        ]
        assert "group or other permission bits or an ACL" in f.evidence
        assert "owned by the current user" not in f.evidence

    def test_key_names_are_capped(self, tmp_path: Path) -> None:
        policy = mp.read_effective_policy(_files(tmp_path, {"k" * 500: 1}), [], None)
        (f,) = [
            f
            for f in _run(policy, probe=_probe(owner=1000, writable=True))
            if f.id == "MANAGED-006"
        ]
        assert "k" * 500 not in f.evidence + f.description
        assert "k" * 64 in f.evidence

    def test_managed_004_text_is_platform_accurate(self, tmp_path: Path) -> None:
        from mcp_audit.discovery import DiscoveredConfig  # noqa: PLC0415

        root = tmp_path / "prefs"
        _plist(root, {"allowedMcpServers": [{"serverUrl": "https://ok.example/*"}]})
        repo = tmp_path / "repo"
        path = repo / ".claude" / "settings.json"
        path.parent.mkdir(parents=True)
        raw = {"allowedMcpServers": [{"serverName": "x"}]}
        path.write_text(json.dumps(raw))
        cfg = DiscoveredConfig(
            client_name="claude-code-project",
            root_key="mcpServers",
            path=path,
            raw=raw,
        )
        policy = mp.read_effective_policy(_files(tmp_path, None), [], _mac(root))
        findings = mp.analyze_managed_policy(policy, [], [cfg], tmp_path / "h", repo)
        (f,) = [f for f in findings if f.id == "MANAGED-004"]
        assert "reads only the managed files" not in f.description
        assert "this platform's MDM/registry sources" in f.description
