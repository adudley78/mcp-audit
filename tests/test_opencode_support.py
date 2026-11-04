"""OpenCode research record and config support (STORY-0142).

Covers the optional ``introduced`` / ``platforms`` record fields, the host
platform helper, the OpenCode record and its ``affected`` answers, OpenCode
version reading (npm and the installer), and OpenCode MCP config discovery and
parsing (JSONC).
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from mcp_audit import harness_versions as hv
from mcp_audit.affected import match as m
from mcp_audit.affected.match import Status
from mcp_audit.cli import app
from mcp_audit.config_parser import (
    _strip_json_comments,
    _strip_trailing_commas,
    config_dialect,
    parse_config,
)
from mcp_audit.discovery import (
    DiscoveredConfig,
    _get_client_specs,
    discover_configs,
    discover_project_configs,
    opencode_user_config_paths,
)
from mcp_audit.harness_versions import HarnessScan, find_harness_versions
from mcp_audit.host_platform import PLATFORMS, detect_host_platform
from mcp_audit.models import TransportType
from mcp_audit.registry.research import load_research_records, research_id
from mcp_audit.scanner import run_scan

runner = CliRunner()

PILLAR = (
    "https://www.pillar.security/blog/"
    "open-and-shut-remote-code-execution-in-opencode-via-mcp-oauth"
)
OPENCODE = research_id(PILLAR, ["OpenCode"])
GH_TOKEN = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890"  # noqa: S105
REPO = Path(__file__).resolve().parent.parent


@pytest.fixture(autouse=True)
def _no_subprocess(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*a: Any, **k: Any) -> None:
        raise AssertionError("subprocess must not be used")

    for name in ("run", "Popen", "check_output", "call", "check_call"):
        monkeypatch.setattr(subprocess, name, boom)


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


# ── Host platform helper ──────────────────────────────────────────────────────


class TestHostPlatform:
    def test_known_platforms(self) -> None:
        assert detect_host_platform("win32") == "windows"
        assert detect_host_platform("cygwin") == "windows"
        assert detect_host_platform("darwin") == "macos"

    def test_linux_is_wsl_when_the_kernel_says_microsoft(self) -> None:
        def read(path: str) -> str | None:
            if path.endswith("osrelease"):
                return "5.15.153.1-Microsoft-standard-WSL2\n"
            return None

        assert detect_host_platform("linux", read) == "wsl"

    def test_wsl_detected_from_proc_version_alone_any_case(self) -> None:
        def read(path: str) -> str | None:
            return "Linux version 4.4.0-19041-MICROSOFT" if "version" in path else None

        assert detect_host_platform("linux", read) == "wsl"

    def test_plain_linux(self) -> None:
        assert detect_host_platform("linux", lambda p: "6.1.0-generic") == "linux"

    def test_linux_with_unreadable_proc_is_undeterminable(self) -> None:
        assert detect_host_platform("linux", lambda p: None) is None

    def test_unknown_os_is_undeterminable(self) -> None:
        assert detect_host_platform("freebsd14") is None

    def test_proc_read_is_capped(self, tmp_path: Path) -> None:
        from mcp_audit import host_platform  # noqa: PLC0415

        big = tmp_path / "osrelease"
        big.write_text("x" * (host_platform.MAX_PROC_BYTES + 10) + " microsoft")
        text = host_platform._read_capped(str(big))
        assert text is not None and len(text) == host_platform.MAX_PROC_BYTES
        assert detect_host_platform("linux", lambda p: text) == "linux"

    def test_missing_proc_file_reads_as_none(self, tmp_path: Path) -> None:
        from mcp_audit import host_platform  # noqa: PLC0415

        assert host_platform._read_capped(str(tmp_path / "absent")) is None

    def test_module_has_no_subprocess(self) -> None:
        from mcp_audit import host_platform  # noqa: PLC0415

        src = Path(host_platform.__file__).read_text()
        assert "subprocess" not in src and "os.system" not in src


# ── Record fields and loader ──────────────────────────────────────────────────


def _record_file(tmp_path: Path, **product: Any) -> Path:
    prod = {
        "product": "Thing",
        "vendor": "V",
        "status": "fixed",
        "fixed_in": "2.0",
        **product,
    }
    entry = {
        "id": research_id("https://example.com/x", ["Thing"]),
        "summary": "s",
        "details": "d",
        "database_specific": {
            "mcp_audit": {"kind": "research", "products": [prod], "checks": []}
        },
    }
    path = tmp_path / "records.json"
    path.write_text(json.dumps({"schema_version": 1, "entries": [entry]}))
    return path


class TestRecordFields:
    def test_shipped_record_carries_both_fields(self) -> None:
        rec = load_research_records().lookup(OPENCODE)
        assert rec is not None
        [p] = rec.products
        assert (p.product, p.vendor, p.status) == (
            "OpenCode",
            "opencode project",
            "fixed",
        )
        assert (p.fixed_in, p.introduced) == ("1.18.33", "1.0.137")
        assert p.platforms == ("windows", "wsl")
        assert rec.checks == ()
        assert [(c.name, c.type) for c in rec.credits] == [
            ("Eilon Cohen (Pillar Security)", "FINDER")
        ]
        assert rec.source_url == PILLAR
        assert "no check" in rec.details.lower() or "`checks` is empty" in rec.details

    def test_id_is_the_deterministic_one(self) -> None:
        assert OPENCODE == "x_MCPRS-3a7e475c087d"

    def test_existing_records_have_neither_field(self) -> None:
        index = load_research_records()
        for rid, rec in index.records.items():
            if rid == OPENCODE:
                continue
            assert all(p.introduced is None and p.platforms == () for p in rec.products)

    def test_valid_fields_load(self, tmp_path: Path) -> None:
        index = load_research_records(
            _record_file(tmp_path, introduced="1.0.0", platforms=["macos", "linux"])
        )
        assert index.skipped == [] and len(index) == 1
        [p] = next(iter(index.records.values())).products
        assert p.introduced == "1.0.0" and p.platforms == ("macos", "linux")

    @pytest.mark.parametrize(
        "bad",
        [
            {"platforms": ["beos"]},
            {"platforms": ["windows", "beos"]},
            {"platforms": "windows"},
            {"platforms": []},
            {"platforms": [1]},
            {"introduced": "not a version"},
            {"introduced": 1},
        ],
    )
    def test_bad_value_skips_the_record_and_reports(
        self, tmp_path: Path, bad: dict[str, Any]
    ) -> None:
        index = load_research_records(_record_file(tmp_path, **bad))
        assert len(index) == 0
        assert len(index.skipped) == 1 and "malformed" in index.skipped[0]

    def test_platform_vocabulary(self) -> None:
        assert set(PLATFORMS) == {"windows", "wsl", "macos", "linux"}


# ── affected rows ─────────────────────────────────────────────────────────────


def _npm(root: Path, version: str) -> None:
    d = root / "opencode-ai"
    d.mkdir(parents=True, exist_ok=True)
    (d / "package.json").write_text(
        json.dumps({"name": "opencode-ai", "version": version})
    )


def _rows(tmp_path: Path, version: str | None, host: str | None) -> list[m.Row]:
    rec = load_research_records().lookup(OPENCODE)
    assert rec is not None
    pfx = tmp_path / "pfx"
    if version is not None:
        _npm(pfx / "lib" / "node_modules", version)
    scan = find_harness_versions(tmp_path / "home", {"npm_config_prefix": str(pfx)})
    return m.research_rows(rec, None, [], scan, lambda: host)


@pytest.mark.parametrize("host", ["windows", "wsl"])
class TestOpenCodeAffected:
    def test_last_affected_version(self, tmp_path: Path, host: str) -> None:
        [row] = _rows(tmp_path, "1.18.32", host)
        assert row.status is Status.AFFECTED
        assert row.version == "1.18.32" and row.fixed_in == "1.18.33"
        assert "package.json" in (row.version_source or "")

    def test_fixed_version(self, tmp_path: Path, host: str) -> None:
        [row] = _rows(tmp_path, "1.18.33", host)
        assert row.status is Status.NOT_AFFECTED and row.reason is None

    def test_first_affected_version(self, tmp_path: Path, host: str) -> None:
        [row] = _rows(tmp_path, "1.0.137", host)
        assert row.status is Status.AFFECTED

    def test_below_introduced(self, tmp_path: Path, host: str) -> None:
        [row] = _rows(tmp_path, "1.0.136", host)
        assert row.status is Status.NOT_AFFECTED
        assert row.reason == m.VERSION_OUTSIDE
        assert "below the first affected version 1.0.137" in row.evidence


class TestOpenCodePlatformAndInstaller:
    @pytest.mark.parametrize("host", ["macos", "linux"])
    def test_other_platforms_are_not_affected(self, tmp_path: Path, host: str) -> None:
        [row] = _rows(tmp_path, "1.18.32", host)
        assert row.status is Status.NOT_AFFECTED
        assert row.reason == m.PLATFORM_OUTSIDE
        assert f"not affected on {host}" in row.evidence

    def test_undeterminable_platform_is_couldnt_check(self, tmp_path: Path) -> None:
        [row] = _rows(tmp_path, "1.18.32", None)
        assert row.status is Status.COULDNT_CHECK
        assert row.reason == m.PLATFORM_UNKNOWN

    def test_nothing_installed_is_unchanged_wording(self, tmp_path: Path) -> None:
        [row] = _rows(tmp_path, None, "windows")
        assert row.status is Status.COULDNT_CHECK
        assert row.reason == m.HARNESS_VERSION
        assert row.evidence.startswith(
            "mcp-audit does not read which OpenCode version is installed; per the "
            "write-up: fixed in 1.18.33"
        )

    @pytest.mark.parametrize("name", ["opencode", "opencode.exe"])
    def test_installer_only_is_couldnt_check(self, tmp_path: Path, name: str) -> None:
        rec = load_research_records().lookup(OPENCODE)
        assert rec is not None
        _write(tmp_path / "home" / ".opencode" / "bin" / name, "\x7fELF")
        scan = find_harness_versions(tmp_path / "home", {})
        [row] = m.research_rows(rec, None, [], scan, lambda: "windows")
        assert row.status is Status.COULDNT_CHECK
        assert row.reason == m.HARNESS_VERSION
        assert row.version is None
        assert "installed by the OpenCode installer at ~/.opencode/bin" in row.evidence
        assert str(tmp_path) not in row.evidence
        assert "keeps no version file" in row.evidence

    def test_installer_on_macos_is_not_affected(self, tmp_path: Path) -> None:
        rec = load_research_records().lookup(OPENCODE)
        assert rec is not None
        _write(tmp_path / "home" / ".opencode" / "bin" / "opencode", "x")
        scan = find_harness_versions(tmp_path / "home", {})
        [row] = m.research_rows(rec, None, [], scan, lambda: "macos")
        assert row.status is Status.NOT_AFFECTED

    def test_host_is_only_read_for_platform_limited_products(
        self, tmp_path: Path
    ) -> None:
        rec = load_research_records().lookup("x_MCPRS-4ad8c07d80d7")
        assert rec is not None

        def boom() -> str | None:
            raise AssertionError("platform must not be read")

        scan = HarnessScan(
            installs=[
                hv.HarnessInstall("claude-code", "Claude Code", "2.1.1", "/p", "npm")
            ]
        )
        m.research_rows(rec, lambda: [], [], scan, boom)


# ── Harness versions ──────────────────────────────────────────────────────────


class TestOpenCodeVersions:
    def test_registered(self) -> None:
        assert hv.HARNESSES["opencode"] == ("OpenCode", "opencode-ai")

    def test_npm_global_install_is_read(self, tmp_path: Path) -> None:
        _npm(tmp_path / "pfx" / "lib" / "node_modules", "1.18.32")
        scan = find_harness_versions(
            tmp_path / "h", {"npm_config_prefix": str(tmp_path / "pfx")}
        )
        [inst] = scan.for_product("OpenCode")
        assert (inst.version, inst.kind, inst.harness) == ("1.18.32", "npm", "opencode")

    def test_wrong_package_name_is_skipped(self, tmp_path: Path) -> None:
        d = tmp_path / "pfx" / "lib" / "node_modules" / "opencode-ai"
        _write(d / "package.json", json.dumps({"name": "evil", "version": "1.0.0"}))
        scan = find_harness_versions(
            tmp_path / "h", {"npm_config_prefix": str(tmp_path / "pfx")}
        )
        assert scan.for_product("OpenCode") == []
        assert any("name is not opencode-ai" in s for s in scan.skipped)

    def test_installer_reports_no_version(self, tmp_path: Path) -> None:
        bin_file = _write(tmp_path / "h" / ".opencode" / "bin" / "opencode", "bin")
        scan = find_harness_versions(tmp_path / "h", {})
        [inst] = scan.for_product("OpenCode")
        assert inst.version is None and inst.kind == "installer"
        assert inst.source == str(bin_file)

    def test_installer_is_stat_only(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import builtins  # noqa: PLC0415
        import io  # noqa: PLC0415

        _write(tmp_path / "h" / ".opencode" / "bin" / "opencode", "bin")
        seen: list[str] = []

        def wrap(real: Any) -> Any:
            def spy(*a: Any, **k: Any) -> Any:
                seen.append(" ".join(str(x) for x in a))
                return real(*a, **k)

            return spy

        monkeypatch.setattr(os, "open", wrap(os.open))
        monkeypatch.setattr(builtins, "open", wrap(builtins.open))
        monkeypatch.setattr(io, "open", wrap(io.open))
        monkeypatch.setattr(Path, "open", wrap(Path.open))
        monkeypatch.setattr(Path, "read_bytes", wrap(Path.read_bytes))
        monkeypatch.setattr(Path, "read_text", wrap(Path.read_text))
        [inst] = find_harness_versions(tmp_path / "h", {}).for_product("OpenCode")
        assert inst.kind == "installer"
        assert not any(".opencode" in x for x in seen)

    def test_directory_named_opencode_is_skipped(self, tmp_path: Path) -> None:
        (tmp_path / "h" / ".opencode" / "bin" / "opencode").mkdir(parents=True)
        scan = find_harness_versions(tmp_path / "h", {})
        assert scan.for_product("OpenCode") == []
        assert any("not a regular file" in s for s in scan.skipped)

    def test_none_version_never_crashes_a_fixed_or_unfixed_row(self) -> None:
        # Plugin4Shell has an unfixed product: an installer-style install of it
        # must not raise (version=None) and is described, not ordered.
        rec = load_research_records().lookup("x_MCPRS-4ad8c07d80d7")
        assert rec is not None
        scan = HarnessScan(
            installs=[
                hv.HarnessInstall(
                    "claude-code", "Claude Code", None, "/p", "installer"
                ),
                hv.HarnessInstall("gemini-cli", "Gemini CLI", None, "/g", "installer"),
            ]
        )
        rows = m.research_rows(rec, lambda: [], [], scan)
        cc = [r for r in rows if r.package == "Claude Code"]
        gem = [r for r in rows if r.subject.startswith("Gemini CLI")]
        assert [r.status for r in cc] == [Status.COULDNT_CHECK]
        assert cc[0].version is None
        assert "(version unknown)" in gem[0].evidence


# ── CLI end to end ────────────────────────────────────────────────────────────


class TestCli:
    def _run(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        host: str,
        version: str | None = None,
        installer: bool = False,
    ) -> dict[str, Any]:
        home = tmp_path / "home"
        home.mkdir(exist_ok=True)
        pfx = tmp_path / "pfx"
        if version:
            _npm(pfx / "lib" / "node_modules", version)
        if installer:
            _write(home / ".opencode" / "bin" / "opencode", "bin")
        monkeypatch.setenv("HOME", str(home))
        monkeypatch.setenv("USERPROFILE", str(home))
        monkeypatch.setenv("npm_config_prefix", str(pfx))
        monkeypatch.setattr(m, "detect_host_platform", lambda: host)
        res = runner.invoke(app, ["affected", OPENCODE, "--format", "json"])
        assert res.exit_code in (0, 1), res.output
        doc = json.loads(res.output[res.output.index("{") :])
        return {
            "code": res.exit_code,
            "rows": [r for r in doc["results"] if r["subject"].startswith("OpenCode")],
        }

    def test_affected_on_windows(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        out = self._run(tmp_path, monkeypatch, "windows", "1.18.32")
        assert out["code"] == 1
        assert [r["status"] for r in out["rows"]] == ["AFFECTED"]

    def test_fixed_and_below_introduced(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fixed = self._run(tmp_path, monkeypatch, "wsl", "1.18.33")
        assert [r["status"] for r in fixed["rows"]] == ["NOT AFFECTED"]

    def test_below_introduced_via_cli(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        old = self._run(tmp_path, monkeypatch, "windows", "1.0.136")
        assert [r["status"] for r in old["rows"]] == ["NOT AFFECTED"]
        assert old["rows"][0]["reason"] == "version-outside"
        assert old["code"] == 0

    def test_macos_not_affected(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        out = self._run(tmp_path, monkeypatch, "macos", "1.18.32")
        assert [r["status"] for r in out["rows"]] == ["NOT AFFECTED"]
        assert out["rows"][0]["reason"] == "platform-outside"

    def test_installer_only(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        out = self._run(tmp_path, monkeypatch, "windows", installer=True)
        [row] = out["rows"]
        assert row["status"] == "COULDN'T CHECK" and row["reason"] == "harness-version"
        assert row["version"] is None
        assert "keeps no version file" in row["evidence"]
        assert str(tmp_path) not in json.dumps(row)  # home path is redacted

    def test_nothing_installed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        out = self._run(tmp_path, monkeypatch, "windows")
        [row] = out["rows"]
        assert row["status"] == "COULDN'T CHECK"
        assert "does not read which OpenCode version is installed" in row["evidence"]


# ── Parser: OpenCode JSONC ────────────────────────────────────────────────────

OPENCODE_JSONC = f"""\
{{
  // OpenCode allows comments
  "$schema": "https://opencode.ai/config.json",
  "mcp": {{
    "files": {{
      "type": "local",
      "command": ["npx", "-y", "@modelcontextprotocol/server-filesystem", "/srv/data",],
      "environment": {{ "GITHUB_TOKEN": "{GH_TOKEN}", }},
    }},
    /* a remote server over plain http */
    "remote": {{
      "type": "remote",
      "url": "http://api.example.com/mcp",
      "headers": {{ "Authorization": "Bearer abc", }},
    }},
  }},
}}
"""


def _oc(path: Path, client: str = "opencode") -> DiscoveredConfig:
    return DiscoveredConfig(
        client_name=client, root_key="mcp", path=path, dialect="opencode"
    )


class TestJsonc:
    def test_trailing_commas_are_dropped_only_outside_strings(self) -> None:
        text = '{"a": "x,]", "b": [1, 2, ], "c": {"d": 1, }, }'
        assert json.loads(_strip_trailing_commas(text)) == {
            "a": "x,]",
            "b": [1, 2],
            "c": {"d": 1},
        }

    def test_comma_between_values_is_kept(self) -> None:
        assert json.loads(_strip_trailing_commas("[1, 2,\n 3]")) == [1, 2, 3]

    def test_escaped_quote_does_not_end_the_string(self) -> None:
        text = '{"a": "q\\", ]", }'
        assert json.loads(_strip_trailing_commas(text)) == {"a": 'q", ]'}

    def test_comment_between_comma_and_closer(self) -> None:
        text = _strip_json_comments('{"a": 1, // last\n}')
        assert json.loads(_strip_trailing_commas(text)) == {"a": 1}

    def test_nested_and_comment_markers_in_strings(self, tmp_path: Path) -> None:
        text = (
            '{"mcp": {"s": {"type": "remote", "url": "https://x.example/a//b/*c*/",\n'
            ' "headers": {"X": "v", },},},}'
        )
        [s] = parse_config(_oc(_write(tmp_path / "opencode.jsonc", text)))
        assert s.url == "https://x.example/a//b/*c*/"

    def test_stripper_is_linear(self) -> None:
        import time  # noqa: PLC0415

        text = "[" + "1," * 200_000 + " " * 200_000 + "]"
        start = time.perf_counter()
        _strip_trailing_commas(text)
        assert time.perf_counter() - start < 5


class TestParser:
    def test_local_and_remote_mapping(self, tmp_path: Path) -> None:
        cfg = _oc(_write(tmp_path / "opencode.jsonc", OPENCODE_JSONC))
        servers = {s.name: s for s in parse_config(cfg)}
        local, remote = servers["files"], servers["remote"]
        assert local.transport is TransportType.STDIO
        assert local.command == "npx"
        assert local.args == [
            "-y",
            "@modelcontextprotocol/server-filesystem",
            "/srv/data",
        ]
        assert local.env == {"GITHUB_TOKEN": GH_TOKEN}
        assert remote.url == "http://api.example.com/mcp"
        assert remote.headers == {"Authorization": "Bearer abc"}
        assert remote.transport is TransportType.STREAMABLE_HTTP
        assert cfg.raw["mcp"]["files"]["type"] == "local"
        assert cfg.parse_warnings == []

    def test_disabled_server_is_still_parsed(self, tmp_path: Path) -> None:
        text = '{"mcp": {"x": {"type": "local", "command": ["a"], "enabled": false}}}'
        [s] = parse_config(_oc(_write(tmp_path / "opencode.json", text)))
        assert s.name == "x" and s.command == "a" and s.args == []

    @pytest.mark.parametrize(
        "entry",
        [
            '{"type": "carrier-pigeon"}',
            '{"command": ["a"]}',
            '{"type": "local"}',
            '{"type": "local", "command": []}',
            '{"type": "local", "command": "npx -y x"}',
            '{"type": "local", "command": [["a"]]}',
            '{"type": "remote"}',
            '"just a string"',
            "7",
        ],
    )
    def test_malformed_entry_is_skipped_and_reported(
        self, tmp_path: Path, entry: str
    ) -> None:
        text = (
            '{"mcp": {"bad": ' + entry + ', "ok": {"type": "local", "command": ["a"]}}}'
        )
        cfg = _oc(_write(tmp_path / "opencode.json", text))
        servers = parse_config(cfg)
        assert [s.name for s in servers] == ["ok"]
        assert len(cfg.parse_warnings) == 1 and "'bad'" in cfg.parse_warnings[0]
        parse_config(cfg)  # parsing twice does not duplicate the warning
        assert len(cfg.parse_warnings) == 1

    @pytest.mark.parametrize("text", ["{}", '{"mcp": []}', '{"mcp": null}'])
    def test_no_servers(self, tmp_path: Path, text: str) -> None:
        assert parse_config(_oc(_write(tmp_path / "opencode.json", text))) == []

    def test_invalid_json_raises_value_error(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="Invalid JSON"):
            parse_config(_oc(_write(tmp_path / "opencode.json", "{ nope")))

    def test_array_root_raises_value_error(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="Expected JSON object"):
            parse_config(_oc(_write(tmp_path / "opencode.json", "[]")))

    def test_oversized_file_is_reported_not_read(self, tmp_path: Path) -> None:
        path = tmp_path / "opencode.json"
        path.write_text("{" + " " * (4 * 1024 * 1024 + 1) + "}")
        with pytest.raises(ValueError, match="limit"):
            parse_config(_oc(path))

    @pytest.mark.parametrize("name", ["opencode.json", "opencode.jsonc"])
    def test_dialect_inferred_for_explicit_paths(
        self, tmp_path: Path, name: str
    ) -> None:
        cfg = DiscoveredConfig("custom", "mcpServers", tmp_path / name)
        assert config_dialect(cfg) == "opencode"

    def test_other_json_is_not_opencode(self, tmp_path: Path) -> None:
        cfg = DiscoveredConfig("custom", "mcpServers", tmp_path / "mcp.json")
        assert config_dialect(cfg) is None


# ── Discovery ─────────────────────────────────────────────────────────────────


@pytest.fixture()
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    h = tmp_path / "home"
    h.mkdir()
    monkeypatch.setattr("mcp_audit.discovery._home", lambda: h)
    monkeypatch.delenv("CODEX_HOME", raising=False)
    monkeypatch.delenv("OPENCODE_CONFIG", raising=False)
    return h


class TestDiscovery:
    def test_client_spec(self, home: Path) -> None:
        spec = {s.name: s for s in _get_client_specs()}["opencode"]
        assert spec.root_key == "mcp"
        assert spec.config_paths == [
            home / ".config" / "opencode" / "opencode.json",
            home / ".config" / "opencode" / "opencode.jsonc",
        ]

    def test_global_config_found_by_plain_scan(
        self, home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _write(home / ".config" / "opencode" / "opencode.jsonc", OPENCODE_JSONC)
        work = tmp_path / "work"
        work.mkdir()
        monkeypatch.chdir(work)
        assert ("opencode", "opencode") in {
            (c.client_name, c.dialect) for c in discover_configs()
        }
        result = run_scan(skip_rug_pull=True)
        by_name = {s.name: s for s in result.servers if s.client == "opencode"}
        assert set(by_name) == {"files", "remote"}
        assert by_name["remote"].url == "http://api.example.com/mcp"
        assert not any(s.is_project_scoped for s in result.servers)
        assert any(
            f.id == "CRED-001" and f.client == "opencode" for f in result.findings
        )
        assert any(
            f.id == "TRANSPORT-001" and f.server == "remote" for f in result.findings
        )
        assert not any(f.id == "TRUST-001" for f in result.findings)

    def test_opencode_config_env_file_is_discovered(
        self, home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        custom = _write(tmp_path / "elsewhere" / "oc.jsonc", OPENCODE_JSONC)
        monkeypatch.setenv("OPENCODE_CONFIG", str(custom))
        assert opencode_user_config_paths()[-1] == custom
        work = tmp_path / "work"
        work.mkdir()
        monkeypatch.chdir(work)
        found = [c for c in discover_configs() if c.path == custom]
        assert [(c.client_name, c.dialect) for c in found] == [("opencode", "opencode")]
        assert {s.name for s in parse_config(found[0])} == {"files", "remote"}

    def test_opencode_config_missing_path_is_ignored_silently(
        self, home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("OPENCODE_CONFIG", str(tmp_path / "nope.json"))
        work = tmp_path / "work"
        work.mkdir()
        monkeypatch.chdir(work)
        errors: list[str] = []
        configs = discover_configs(errors=errors)
        assert not any(c.client_name.startswith("opencode") for c in configs)
        assert errors == []
        result = run_scan(skip_rug_pull=True)
        assert not any("opencode" in e.lower() for e in result.errors)

    def test_blank_opencode_config_is_ignored(
        self, home: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("OPENCODE_CONFIG", "  ")
        assert len(opencode_user_config_paths()) == 2

    def test_cwd_root_file_is_project_labelled(
        self, home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        repo = tmp_path / "repo"
        _write(repo / "opencode.jsonc", OPENCODE_JSONC)
        _write(repo / "sub" / "opencode.json", OPENCODE_JSONC)  # not the cwd root
        monkeypatch.chdir(repo)
        labels = {
            (c.client_name, c.dialect, c.path.name)
            for c in discover_configs()
            if c.path.is_relative_to(repo)
        }
        assert labels == {("opencode-project", "opencode", "opencode.jsonc")}
        result = run_scan(skip_rug_pull=True)
        assert {s.client for s in result.servers} >= {"opencode-project"}

    def test_cwd_is_home_skips_project_files(
        self, home: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _write(home / "opencode.json", OPENCODE_JSONC)
        _write(home / ".config" / "opencode" / "opencode.json", OPENCODE_JSONC)
        monkeypatch.chdir(home)
        clients = [c.client_name for c in discover_configs()]
        assert clients.count("opencode") == 1
        assert "opencode-project" not in clients

    def test_project_label_keeps_identity_apart_from_user(
        self, home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _write(home / ".config" / "opencode" / "opencode.json", OPENCODE_JSONC)
        repo = tmp_path / "repo"
        _write(repo / "opencode.json", OPENCODE_JSONC)
        monkeypatch.chdir(repo)
        result = run_scan(skip_rug_pull=True)
        keys = sorted(
            f"{s.client}/{s.name}" for s in result.servers if s.name == "files"
        )
        assert keys == ["opencode-project/files", "opencode/files"]

    def test_project_walk_finds_nested_files(self, tmp_path: Path, home: Path) -> None:
        repo = tmp_path / "repo"
        _write(repo / "opencode.jsonc", OPENCODE_JSONC)
        _write(repo / "pkg" / "opencode.json", OPENCODE_JSONC)
        found = {
            (c.client_name, c.path.relative_to(repo).as_posix(), c.dialect)
            for c in discover_project_configs(repo)
        }
        assert found == {
            ("opencode", "opencode.jsonc", "opencode"),
            ("opencode", "pkg/opencode.json", "opencode"),
        }
        servers = [s for c in discover_project_configs(repo) for s in parse_config(c)]
        assert servers and all(s.is_project_scoped for s in servers)

    def test_home_walk_skips_the_users_own_files(self, home: Path) -> None:
        _write(home / ".config" / "opencode" / "opencode.json", OPENCODE_JSONC)
        _write(home / ".config" / "opencode" / "opencode.jsonc", OPENCODE_JSONC)
        _write(home / "repo" / "opencode.jsonc", OPENCODE_JSONC)
        found = {
            c.path.relative_to(home).as_posix() for c in discover_project_configs(home)
        }
        assert found == {"repo/opencode.jsonc"}

    def test_home_walk_skips_the_opencode_config_file(
        self, home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        custom = _write(tmp_path / "cfg" / "opencode.json", OPENCODE_JSONC)
        monkeypatch.setenv("OPENCODE_CONFIG", str(custom))
        assert discover_project_configs(tmp_path / "cfg") == []

    def test_scan_project_reports_trust_001(
        self, tmp_path: Path, home: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        repo = tmp_path / "repo"
        _write(repo / "opencode.jsonc", OPENCODE_JSONC)
        out = tmp_path / "out.json"
        outside = tmp_path / "elsewhere"
        outside.mkdir()
        monkeypatch.chdir(outside)
        r = runner.invoke(
            app, ["scan", "--project", str(repo), "--format", "json", "-o", str(out)]
        )
        assert r.exit_code in (0, 1), r.output
        payload = json.loads(out.read_text(encoding="utf-8"))
        trust = {
            (f["client"], f["server"])
            for f in payload["findings"]
            if f["id"] == "TRUST-001"
        }
        assert {("opencode", "files"), ("opencode", "remote")} <= trust

    def test_parse_warning_reaches_scan_errors(
        self, home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _write(
            home / ".config" / "opencode" / "opencode.json",
            '{"mcp": {"weird": {"type": "pigeon"}}}',
        )
        work = tmp_path / "work"
        work.mkdir()
        monkeypatch.chdir(work)
        result = run_scan(skip_rug_pull=True)
        assert any("'weird' was skipped" in e for e in result.errors)

    def test_diff_reads_opencode_from_a_git_path_table(self) -> None:
        from mcp_audit.diff import loader  # noqa: PLC0415

        paths = {p for p, _ in loader._KNOWN_GIT_RELATIVE_PATHS}
        assert {"opencode.json", "opencode.jsonc"} <= paths
        assert loader._GIT_PATH_DIALECT["opencode.jsonc"] == "opencode"


# ── Review fixes: unknown platform, unfixed products, loader, dedupe ──────────


def _product(**over: Any) -> Any:
    from mcp_audit.registry.research import AffectedProduct  # noqa: PLC0415

    base: dict[str, Any] = {
        "product": "Thing",
        "vendor": "V",
        "status": "fixed",
        "fixed_in": "2.0",
        "introduced": "1.0",
        "platforms": ("windows",),
    }
    base.update(over)
    return AffectedProduct(**base)


def _record_for(p: Any) -> Any:
    from mcp_audit.registry.research import ResearchRecord  # noqa: PLC0415

    return ResearchRecord(
        id="x_MCPRS-000000000000",
        summary="s",
        details="d",
        published=None,
        modified=None,
        products=(p,),
    )


def _one(version: str | None, p: Any, host: str | None) -> m.Row:
    kind = "npm" if version else "installer"
    scan = HarnessScan(
        installs=[hv.HarnessInstall("x", p.product, version, "/p/package.json", kind)]
    )
    [row] = m.research_rows(_record_for(p), None, [], scan, lambda: host)
    return row


class TestUnknownHost:
    @pytest.mark.parametrize(
        ("version", "status", "reason"),
        [
            ("2.0", Status.NOT_AFFECTED, None),  # at the fix: the version decides
            ("2.5", Status.NOT_AFFECTED, None),
            ("0.9", Status.NOT_AFFECTED, m.VERSION_OUTSIDE),  # below introduced
            ("1.5", Status.COULDNT_CHECK, m.PLATFORM_UNKNOWN),  # in range
            (None, Status.COULDNT_CHECK, m.PLATFORM_UNKNOWN),
        ],
    )
    def test_version_decides_before_platform(
        self, version: str | None, status: Status, reason: str | None
    ) -> None:
        row = _one(version, _product(), None)
        assert (row.status, row.reason) == (status, reason)

    def test_known_host_in_range_is_affected(self) -> None:
        assert _one("1.5", _product(), "windows").status is Status.AFFECTED

    def test_known_outside_host_beats_everything(self) -> None:
        row = _one("1.5", _product(), "macos")
        assert (row.status, row.reason) == (Status.NOT_AFFECTED, m.PLATFORM_OUTSIDE)
        assert _one(None, _product(), "macos").reason == m.PLATFORM_OUTSIDE


class TestUnfixedPlatformLimited:
    def _unfixed(self) -> Any:
        return _product(status="unfixed", fixed_in=None, introduced=None)

    def test_other_platform_is_not_affected(self) -> None:
        row = _one("1.5", self._unfixed(), "macos")
        assert (row.status, row.reason) == (Status.NOT_AFFECTED, m.PLATFORM_OUTSIDE)

    @pytest.mark.parametrize("host", ["windows", None])
    def test_covered_or_unknown_host_stays_couldnt_check(
        self, host: str | None
    ) -> None:
        row = _one("1.5", self._unfixed(), host)
        assert row.status is Status.COULDNT_CHECK
        assert row.reason == m.HARNESS_VERSION

    def test_unlimited_unfixed_product_never_reads_the_host(self) -> None:
        def boom() -> str | None:
            raise AssertionError("platform must not be read")

        p = _product(status="unfixed", fixed_in=None, introduced=None, platforms=())
        scan = HarnessScan(installs=[hv.HarnessInstall("x", "Thing", "1", "/p", "npm")])
        m.research_rows(_record_for(p), None, [], scan, boom)


class TestLoaderOrdering:
    @pytest.mark.parametrize(
        ("introduced", "fixed_in", "ok"),
        [("2.0", "2.0", False), ("3.0", "2.0", False), ("1.0", "2.0", True)],
    )
    def test_introduced_must_be_below_fixed_in(
        self, tmp_path: Path, introduced: str, fixed_in: str, ok: bool
    ) -> None:
        index = load_research_records(
            _record_file(tmp_path, introduced=introduced, fixed_in=fixed_in)
        )
        assert (len(index) == 1) is ok
        if not ok:
            assert len(index.skipped) == 1

    def test_introduced_alone_on_an_unfixed_product_loads(self, tmp_path: Path) -> None:
        index = load_research_records(
            _record_file(tmp_path, status="unfixed", fixed_in=None, introduced="1.0")
        )
        assert len(index) == 1


class TestDedupe:
    def test_opencode_config_naming_the_global_file_scans_once(
        self, home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        g = _write(home / ".config" / "opencode" / "opencode.json", OPENCODE_JSONC)
        monkeypatch.setenv("OPENCODE_CONFIG", str(g))
        work = tmp_path / "work"
        work.mkdir()
        monkeypatch.chdir(work)
        found = [c for c in discover_configs() if c.client_name == "opencode"]
        assert len(found) == 1
        result = run_scan(skip_rug_pull=True)
        names = [s.name for s in result.servers if s.client == "opencode"]
        assert sorted(names) == ["files", "remote"]

    def test_symlink_to_the_global_file_scans_once(
        self, home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        g = _write(home / ".config" / "opencode" / "opencode.json", OPENCODE_JSONC)
        link = tmp_path / "link.json"
        try:
            link.symlink_to(g)
        except (OSError, NotImplementedError):
            pytest.skip("symlinks not available")
        monkeypatch.setenv("OPENCODE_CONFIG", str(link))
        work = tmp_path / "work"
        work.mkdir()
        monkeypatch.chdir(work)
        assert len([c for c in discover_configs() if c.client_name == "opencode"]) == 1


# ── Secrets in output, and fix/check refusals ─────────────────────────────────

SECRET_JSONC = """{
  "mcp": {
    "files": {
      "type": "local",
      "command": ["npx", "-y", "srv", "--api-key",
                  "sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAA",
                  "postgres://u:hunter2pass@db/x"],
      "environment": {"GITHUB_TOKEN": "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890"},
    },
    "remote": {
      "type": "remote",
      "url": "https://u:hunter2pass@api.example.com/mcp?api_key=zzzzzzzzzzzz",
      "headers": {"Authorization": "Bearer sk-ant-api03-BBBBBBBBBBBBBBBBBBBBBBBB"},
    },
  },
}
"""  # noqa: S105
LEAKS = ("ghp_aBcDe", "sk-ant-api03-AAAA", "sk-ant-api03-BBBB", "hunter2pass")


class TestSecretsInOutput:
    @pytest.fixture()
    def repo(self, home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
        _write(home / ".config" / "opencode" / "opencode.jsonc", SECRET_JSONC)
        work = tmp_path / "work"
        work.mkdir()
        monkeypatch.chdir(work)
        return work

    def test_model_dump_json_has_no_secret(self, repo: Path) -> None:
        result = run_scan(skip_rug_pull=True)
        assert any(s.client == "opencode" for s in result.servers)
        out = result.model_dump_json()
        for leak in LEAKS:
            assert leak not in out, leak

    def test_scan_json_has_no_secret(self, repo: Path) -> None:
        res = runner.invoke(app, ["scan", "--format", "json"])
        assert res.exit_code in (0, 1), res.output
        assert "opencode" in res.output
        for leak in LEAKS:
            assert leak not in res.output, leak

    def test_check_json_has_no_secret(self, repo: Path) -> None:
        res = runner.invoke(app, ["check", "--json"])
        assert res.exit_code in (0, 1), res.output
        for leak in LEAKS:
            assert leak not in res.output, leak

    def test_in_memory_object_is_unchanged(self, repo: Path) -> None:
        result = run_scan(skip_rug_pull=True)
        files = next(s for s in result.servers if s.name == "files")
        assert files.env["GITHUB_TOKEN"].startswith("ghp_")
        assert files.raw["environment"]["GITHUB_TOKEN"].startswith("ghp_")


class TestFixRefusesOpenCode:
    def test_check_never_offers_fix_for_opencode(self) -> None:
        from mcp_audit.models import Finding, Severity  # noqa: PLC0415
        from mcp_audit.output.check import (  # noqa: PLC0415
            _is_auto_fixable,
            _remediation_hint,
        )

        for client, name in (
            ("opencode", "opencode.jsonc"),
            ("opencode-project", "opencode.json"),
        ):
            finding = Finding(
                id="CRED-001",
                severity=Severity.HIGH,
                analyzer="credentials",
                client=client,
                server="files",
                title="t",
                description="d",
                evidence="e",
                remediation="r.",
                finding_path=f"/home/u/{name}",
            )
            assert not _is_auto_fixable(finding)
            assert "fix --apply" not in _remediation_hint(finding)

    @pytest.mark.parametrize("name", ["opencode.json", "opencode.jsonc"])
    def test_run_fix_and_run_pins_refuse_and_write_nothing(
        self, tmp_path: Path, name: str
    ) -> None:
        from mcp_audit.fixer.fixer import run_fix, run_pins  # noqa: PLC0415

        path = _write(tmp_path / name, SECRET_JSONC)
        with pytest.raises(ValueError, match="OpenCode"):
            run_fix([], path, apply=True)
        with pytest.raises(ValueError, match="OpenCode"):
            run_pins(path, [("files", "srv", "1.0.0")], apply=True)
        assert path.read_text(encoding="utf-8") == SECRET_JSONC
        assert sorted(p.name for p in tmp_path.iterdir()) == [name]

    def test_fix_cli_apply_changes_nothing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = _write(tmp_path / "opencode.jsonc", SECRET_JSONC)
        res = runner.invoke(app, ["fix", "--path", str(path), "--apply"])
        assert res.exit_code == 2, res.output
        assert path.read_text(encoding="utf-8") == SECRET_JSONC
        assert sorted(p.name for p in tmp_path.iterdir()) == ["opencode.jsonc"]
        assert "Config updated" not in res.output
