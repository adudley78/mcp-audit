"""Tests for harness_versions.py and its use by ``affected`` (STORY-0132)."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

import pytest

from mcp_audit import harness_versions as hv
from mcp_audit.affected import match as m
from mcp_audit.affected.match import Status
from mcp_audit.harness_versions import HarnessScan, find_harness_versions
from mcp_audit.registry.research import load_research_records

PLUGIN4SHELL = "x_MCPRS-4ad8c07d80d7"
PKG = {
    "claude-code": "@anthropic-ai/claude-code",
    "codex": "@openai/codex",
    "gemini-cli": "@google/gemini-cli",
}


@pytest.fixture(autouse=True)
def _no_subprocess(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*a: Any, **k: Any) -> None:
        raise AssertionError("subprocess must not be used")

    for name in ("run", "Popen", "check_output", "call", "check_call"):
        monkeypatch.setattr(subprocess, name, boom)
    monkeypatch.setattr(os, "system", boom)


def _pkg(root: Path, key: str, version: Any, name: str | None = None) -> Path:
    d = root / PKG[key]
    d.mkdir(parents=True, exist_ok=True)
    (d / "package.json").write_text(
        json.dumps({"name": name or PKG[key], "version": version})
    )
    return d / "package.json"


def _scan(home: Path, env: dict[str, str] | None = None) -> HarnessScan:
    return find_harness_versions(home, env or {})


def test_module_does_not_import_subprocess() -> None:
    src = Path(hv.__file__).read_text()
    assert "subprocess" not in src and "os.system" not in src


class TestLayouts:
    def test_npm_prefix_env(self, tmp_path: Path) -> None:
        prefix = tmp_path / "pfx"
        _pkg(prefix / "lib" / "node_modules", "claude-code", "2.1.100")
        _pkg(prefix / "lib" / "node_modules", "codex", "0.146.0")
        _pkg(prefix / "lib" / "node_modules", "gemini-cli", "0.9.1")
        scan = _scan(tmp_path / "home", {"npm_config_prefix": str(prefix)})
        got = {(i.harness, i.version, i.kind) for i in scan.installs}
        assert got == {
            ("claude-code", "2.1.100", "npm"),
            ("codex", "0.146.0", "npm"),
            ("gemini-cli", "0.9.1", "npm"),
        }
        assert all("package.json" in i.source for i in scan.installs)

    def test_nvm_versions(self, tmp_path: Path) -> None:
        for node, ver in (("v20.1.0", "2.1.50"), ("v22.2.0", "2.1.200")):
            _pkg(
                tmp_path / ".nvm/versions/node" / node / "lib/node_modules",
                "claude-code",
                ver,
            )
        scan = _scan(tmp_path)
        assert sorted(i.version for i in scan.installs) == ["2.1.200", "2.1.50"]

    def test_windows_appdata_layout(self, tmp_path: Path) -> None:
        appdata = tmp_path / "AppData" / "Roaming"
        _pkg(appdata / "npm" / "node_modules", "codex", "0.150.0")
        scan = _scan(tmp_path / "home", {"APPDATA": str(appdata)})
        assert [(i.harness, i.version) for i in scan.installs] == [("codex", "0.150.0")]

    def test_native_versions_and_launcher_target(self, tmp_path: Path) -> None:
        vdir = tmp_path / ".local/share/claude/versions"
        vdir.mkdir(parents=True)
        (vdir / "2.1.100").write_text("bin")
        (vdir / "2.1.200").write_text("bin")
        (vdir / "notes.txt").write_text("x")
        bindir = tmp_path / ".local/bin"
        bindir.mkdir(parents=True)
        (bindir / "claude").symlink_to(vdir / "2.1.200")
        scan = _scan(tmp_path)
        by = {i.version: i for i in scan.installs}
        assert set(by) == {"2.1.100", "2.1.200"}
        assert by["2.1.200"].launcher_target and not by["2.1.100"].launcher_target
        assert all(i.kind == "native" for i in scan.installs)

    def test_nothing_installed(self, tmp_path: Path) -> None:
        scan = _scan(tmp_path)
        assert scan.installs == [] or all(
            str(tmp_path) not in i.source for i in scan.installs
        )

    def test_same_package_via_two_prefixes_listed_once(self, tmp_path: Path) -> None:
        real = tmp_path / "real"
        _pkg(real / "lib" / "node_modules", "codex", "0.146.0")
        link = tmp_path / "link"
        link.symlink_to(real)
        env = {"npm_config_prefix": str(real), "NPM_CONFIG_PREFIX": str(link)}
        scan = _scan(tmp_path / "home", env)
        assert [
            i.version for i in scan.installs if i.source.startswith(str(tmp_path))
        ] == ["0.146.0"]


class TestHostile:
    def _env(self, tmp_path: Path) -> tuple[Path, dict[str, str]]:
        prefix = tmp_path / "pfx"
        return prefix / "lib" / "node_modules", {"npm_config_prefix": str(prefix)}

    def _mine(self, scan: HarnessScan, tmp_path: Path) -> list[Any]:
        return [i for i in scan.installs if i.source.startswith(str(tmp_path))]

    def test_huge_file_skipped(self, tmp_path: Path) -> None:
        root, env = self._env(tmp_path)
        pj = _pkg(root, "codex", "1.0.0")
        pj.write_text(
            '{"name": "@openai/codex", "version": "1.0.0", "x": "'
            + "a" * (hv.MAX_PACKAGE_JSON_BYTES + 10)
            + '"}'
        )
        scan = _scan(tmp_path / "h", env)
        assert not self._mine(scan, tmp_path)
        assert any("over" in s for s in scan.skipped)

    @pytest.mark.parametrize(
        "body",
        [
            "not json{",
            "[1,2]",
            '{"name": "@openai/codex", "version": 7}',
            '{"name": "@openai/codex", "version": ["1.0.0"]}',
            '{"name": "@openai/codex", "version": "banana"}',
            '{"name": "other", "version": "1.0.0"}',
            "[" * 100000,
            "\xff\xfe",
        ],
    )
    def test_malformed_skipped_and_reported(self, tmp_path: Path, body: str) -> None:
        root, env = self._env(tmp_path)
        pj = _pkg(root, "codex", "1.0.0")
        pj.write_bytes(body.encode("latin-1"))
        scan = _scan(tmp_path / "h", env)
        assert not self._mine(scan, tmp_path)
        assert any(str(pj) in s for s in scan.skipped)

    def test_symlink_loop_skipped(self, tmp_path: Path) -> None:
        root, env = self._env(tmp_path)
        d = root / PKG["codex"]
        d.mkdir(parents=True)
        (d / "package.json").symlink_to(d / "package.json")
        scan = _scan(tmp_path / "h", env)
        assert not self._mine(scan, tmp_path)
        assert any("package.json" in s for s in scan.skipped)

    def test_directory_named_package_json(self, tmp_path: Path) -> None:
        root, env = self._env(tmp_path)
        (root / PKG["codex"] / "package.json").mkdir(parents=True)
        scan = _scan(tmp_path / "h", env)
        assert not self._mine(scan, tmp_path)

    @pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no FIFOs on Windows")
    def test_fifo_is_not_read(self, tmp_path: Path) -> None:
        root, env = self._env(tmp_path)
        d = root / PKG["codex"]
        d.mkdir(parents=True)
        os.mkfifo(d / "package.json")
        scan = _scan(tmp_path / "h", env)
        assert not self._mine(scan, tmp_path)
        assert any("not a regular file" in s for s in scan.skipped)

    def test_native_dir_with_junk_names(self, tmp_path: Path) -> None:
        vdir = tmp_path / ".local/share/claude/versions"
        vdir.mkdir(parents=True)
        for n in ("..bad", "latest", "9" * 200, "2.1.7"):
            (vdir / n).write_text("x")
        scan = _scan(tmp_path)
        assert [i.version for i in scan.installs if i.kind == "native"] == ["2.1.7"]

    def test_looping_launcher_symlink(self, tmp_path: Path) -> None:
        b = tmp_path / ".local/bin"
        b.mkdir(parents=True)
        (b / "claude").symlink_to(b / "claude")
        _scan(tmp_path)  # no traceback


class TestAffectedRows:
    def _rows(self, tmp_path: Path, version: str) -> list[m.Row]:
        rec = load_research_records().lookup(PLUGIN4SHELL)
        assert rec is not None
        root = tmp_path / "pfx" / "lib" / "node_modules"
        _pkg(root, "claude-code", version)
        scan = _scan(tmp_path / "h", {"npm_config_prefix": str(tmp_path / "pfx")})
        notes: list[str] = []
        return m.research_rows(rec, lambda: [], notes, scan)

    def _claude(self, rows: list[m.Row]) -> list[m.Row]:
        return [r for r in rows if r.package == "Claude Code"]

    def test_old_claude_code_is_affected_with_path(self, tmp_path: Path) -> None:
        rows = self._claude(self._rows(tmp_path, "2.1.100"))
        assert [r.status for r in rows] == [Status.AFFECTED]
        assert rows[0].version == "2.1.100"
        assert "package.json" in (rows[0].version_source or "")
        assert "2.1.179" in rows[0].evidence

    def test_new_claude_code_is_not_affected(self, tmp_path: Path) -> None:
        rows = self._claude(self._rows(tmp_path, "2.1.200"))
        assert [r.status for r in rows] == [Status.NOT_AFFECTED]

    def test_exactly_fixed_version_is_not_affected(self, tmp_path: Path) -> None:
        rows = self._claude(self._rows(tmp_path, "2.1.179"))
        assert [r.status for r in rows] == [Status.NOT_AFFECTED]

    def test_other_products_stay_couldnt_check(self, tmp_path: Path) -> None:
        rows = self._rows(tmp_path, "2.1.100")
        others = [r for r in rows if r.package != "Claude Code" and r.reason]
        assert len(others) == 3
        assert {r.status for r in others} == {Status.COULDNT_CHECK}

    def test_none_found_is_unchanged(self, tmp_path: Path) -> None:
        rec = load_research_records().lookup(PLUGIN4SHELL)
        assert rec is not None
        rows = m.research_rows(rec, lambda: [], [], HarnessScan())
        assert {r.status for r in rows} == {Status.COULDNT_CHECK}
        assert len(rows) == 4

    def test_two_installs_listed_with_path_note(self, tmp_path: Path) -> None:
        rec = load_research_records().lookup(PLUGIN4SHELL)
        assert rec is not None
        scan = HarnessScan(
            installs=[
                hv.HarnessInstall("claude-code", "Claude Code", "2.1.100", "/a", "npm"),
                hv.HarnessInstall(
                    "claude-code", "Claude Code", "2.1.200", "/b", "native"
                ),
            ]
        )
        notes: list[str] = []
        rows = [r for r in m.research_rows(rec, lambda: [], notes, scan) if r.package]
        assert [r.status for r in rows] == [Status.AFFECTED, Status.NOT_AFFECTED]
        assert any("PATH" in n for n in notes)


def test_cli_end_to_end(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from typer.testing import CliRunner

    from mcp_audit.cli import app

    pfx = tmp_path / "pfx"
    _pkg(pfx / "lib" / "node_modules", "claude-code", "2.1.100")
    monkeypatch.setenv("npm_config_prefix", str(pfx))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()
    res = CliRunner().invoke(app, ["affected", PLUGIN4SHELL, "--format", "json"])
    assert res.exit_code == 1, res.output
    data = json.loads(res.output[res.output.index("{") :])
    rows = [r for r in data["results"] if r.get("version") == "2.1.100"]
    assert rows and rows[0]["status"] == "AFFECTED"
