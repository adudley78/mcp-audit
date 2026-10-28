"""Hostile-input robustness (STORY-0117, R1-R7).

A repository can plant files that parse but break later code: JSON nested
hundreds of levels deep, a lone UTF-16 surrogate in a key name, an empty
managed settings file.  None of these may crash ``scan``/``check``.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mcp_audit.analyzers.managed_policy import read_managed_policy
from mcp_audit.analyzers.permissions import settings_scope
from mcp_audit.cli import app
from mcp_audit.config_parser import MAX_CONFIG_DEPTH, parse_config
from mcp_audit.discovery import DiscoveredConfig, is_lock_file
from mcp_audit.lock.auto_verify import auto_verify
from mcp_audit.lock.writer import regenerate
from mcp_audit.models import LockStatus, ServerConfig
from mcp_audit.plugins.mods import read_guard_state
from mcp_audit.verdict import split_package_spec

runner = CliRunner()


def _deep_json(levels: int, leaf: str = "1") -> str:
    return '{"a":' * levels + leaf + "}" * levels


# ── R1: nesting depth ─────────────────────────────────────────────────────────


class TestNestingDepth:
    def _config(self, tmp_path: Path, name: str, client: str, key: str):
        path = tmp_path / name
        return path, DiscoveredConfig(client_name=client, root_key=key, path=path)

    def test_deep_mcp_json_is_refused_with_an_error(self, tmp_path: Path) -> None:
        path, cfg = self._config(tmp_path, ".mcp.json", "claude-code", "mcpServers")
        path.write_text(
            '{"mcpServers":{"x":{"command":"npx","deep":' + _deep_json(300) + "}}}"
        )
        with pytest.raises(ValueError, match="nested more than"):
            parse_config(cfg)

    def test_depth_at_the_limit_still_parses(self, tmp_path: Path) -> None:
        path, cfg = self._config(tmp_path, ".mcp.json", "claude-code", "mcpServers")
        # mcpServers -> x -> deep -> a... ; stay within MAX_CONFIG_DEPTH overall.
        path.write_text(
            '{"mcpServers":{"x":{"command":"npx","deep":'
            + _deep_json(MAX_CONFIG_DEPTH - 4)
            + "}}}"
        )
        assert [s.name for s in parse_config(cfg)] == ["x"]

    def test_hundred_thousand_brackets_is_an_error_not_a_crash(
        self, tmp_path: Path
    ) -> None:
        path, cfg = self._config(tmp_path, ".mcp.json", "claude-code", "mcpServers")
        path.write_text("[" * 200_000)
        with pytest.raises(ValueError):
            parse_config(cfg)

    def test_deep_codex_toml_is_refused(self, tmp_path: Path) -> None:
        path, cfg = self._config(tmp_path, "config.toml", "codex", "mcp_servers")
        path.write_text('[mcp_servers.x]\ncommand = "a"\nx = ' + "[" * 300 + "]" * 300)
        with pytest.raises(ValueError):
            parse_config(cfg)

    def test_deep_gemini_settings_is_refused(self, tmp_path: Path) -> None:
        path, cfg = self._config(tmp_path, "settings.json", "gemini-cli", "mcpServers")
        path.write_text(
            '{"mcpServers":{"x":{"command":"a","deep":' + _deep_json(300) + "}}}"
        )
        with pytest.raises(ValueError):
            parse_config(cfg)

    @pytest.mark.parametrize(
        "args", [["scan", "--format", "json"], ["check", "--json"]]
    )
    def test_scan_and_check_report_it_in_errors(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, args: list[str]
    ) -> None:
        (tmp_path / ".git").mkdir()
        (tmp_path / ".mcp.json").write_text(
            '{"mcpServers":{"x":{"command":"npx","deep":' + _deep_json(300) + "}}}"
        )
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, args)
        assert "Traceback" not in result.output
        assert not (
            result.exception and not isinstance(result.exception, SystemExit)
        ), result.exception
        document = json.loads(result.output[result.output.index("{") :])
        assert any("nested more than" in e for e in document["errors"])

    def test_deep_lock_file_does_not_crash_discovery_or_lock(
        self, tmp_path: Path
    ) -> None:
        lock = tmp_path / "mcp-lock.json"
        lock.write_text("[" * 200_000)
        assert is_lock_file(lock) is True
        other = tmp_path / "x.json"
        other.write_text("[" * 200_000)
        assert is_lock_file(other) is False  # no crash on RecursionError


# ── R2: managed drop-in ───────────────────────────────────────────────────────


class TestGuardStateReads:
    @pytest.mark.parametrize(
        "content",
        [
            pytest.param("[" * 200_000, id="brackets"),
            pytest.param(_deep_json(300), id="objects"),
        ],
    )
    def test_deep_dropin_is_ignored(self, tmp_path: Path, content: str) -> None:
        dropins = tmp_path / "managed-settings.d"
        dropins.mkdir()
        (dropins / "a.json").write_text(content)
        state = read_guard_state(tmp_path)
        assert not state.allow_override_deny_rules
        assert not state.allow_managed_mods_only

    def test_oversized_main_file_is_not_read(self, tmp_path: Path) -> None:
        main = tmp_path / "managed-settings.json"
        main.write_text('{"pad": "' + "x" * (3 * 1024 * 1024) + '"}')
        assert not read_guard_state(tmp_path).allow_managed_mods_only


# ── R3: lone surrogate in a lock key ──────────────────────────────────────────


class TestSurrogateLockKey:
    def _project(self, tmp_path: Path) -> None:
        (tmp_path / ".git").mkdir()
        (tmp_path / ".cursor").mkdir()
        server = ServerConfig(
            name="github",
            client="cursor",
            config_path=tmp_path / ".cursor" / "mcp.json",
            command="npx",
            args=["-y", "foo@1.0.0"],
        )
        (tmp_path / ".cursor" / "mcp.json").write_text(
            json.dumps(
                {
                    "mcpServers": {
                        "github": {"command": "npx", "args": ["-y", "foo@1.0.0"]}
                    }
                }
            )
        )
        doc = regenerate(None, [server], tmp_path, offline=True, registry=None)
        doc["x\ud800y"] = {"foo": 1}
        (tmp_path / "mcp-lock.json").write_text(json.dumps(doc, ensure_ascii=True))

    def test_lock_status_escapes_the_name(self) -> None:
        status = LockStatus(unverified_sections=["x\ud800y"], outside_root=["a\udcffb"])
        text = status.model_dump_json()
        assert "\\\\ud800" in text and "\\\\udcff" in text

    def test_auto_verify_names_the_section(self, tmp_path: Path) -> None:
        self._project(tmp_path)
        server = ServerConfig(
            name="github",
            client="cursor",
            config_path=tmp_path / ".cursor" / "mcp.json",
            command="npx",
            args=["-y", "foo@1.0.0"],
        )
        _findings, status = auto_verify([server])
        assert "x\\ud800y" in status.unverified_sections

    @pytest.mark.parametrize(
        "args", [["scan", "--format", "json"], ["check", "--json"]]
    )
    def test_scan_and_check_json_do_not_crash(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, args: list[str]
    ) -> None:
        self._project(tmp_path)
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, args)
        assert "Traceback" not in result.output
        assert not (
            result.exception and not isinstance(result.exception, SystemExit)
        ), result.exception
        json.loads(result.output[result.output.index("{") :])


# ── R4: empty managed settings file ───────────────────────────────────────────


class TestEmptyManagedSettings:
    def test_zero_byte_settings_file_is_an_empty_object(self, tmp_path: Path) -> None:
        managed = tmp_path / "m"
        managed.mkdir()
        (managed / "managed-settings.json").write_bytes(b"")
        errors: list[str] = []
        policy = read_managed_policy(managed, errors)
        assert policy.unparsable_files == []
        assert policy.settings_files == [managed / "managed-settings.json"]
        assert not any("not valid JSON" in e for e in errors)

    def test_zero_byte_dropin_is_an_empty_object(self, tmp_path: Path) -> None:
        managed = tmp_path / "m"
        (managed / "managed-settings.d").mkdir(parents=True)
        (managed / "managed-settings.json").write_text('{"allowedMcpServers": []}')
        (managed / "managed-settings.d" / "10.json").write_bytes(b"")
        errors: list[str] = []
        policy = read_managed_policy(managed, errors)
        assert policy.unparsable_files == []
        assert errors == []

    def test_whitespace_only_is_still_invalid(self, tmp_path: Path) -> None:
        managed = tmp_path / "m"
        managed.mkdir()
        (managed / "managed-settings.json").write_text("  \n")
        policy = read_managed_policy(managed, [])
        assert policy.unparsable_files

    def test_empty_managed_mcp_json_is_not_given_that_treatment(
        self, tmp_path: Path
    ) -> None:
        managed = tmp_path / "m"
        managed.mkdir()
        (managed / "managed-mcp.json").write_bytes(b"")
        errors: list[str] = []
        read_managed_policy(managed, errors)
        assert any("not valid JSON" in e for e in errors)


# ── R5: TRUST-005 reported once ───────────────────────────────────────────────


class TestSymlinkedDirectoryFindingOnce:
    @pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")
    @pytest.mark.parametrize("args", [["scan", "--project", "."], ["scan"]])
    def test_trust_005_is_not_duplicated(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, args: list[str]
    ) -> None:
        real = tmp_path / "real"
        real.mkdir()
        repo = tmp_path / "repo"
        for sub in (".claude/skills/s1", "nested/.git"):
            (repo / sub).mkdir(parents=True)
        (repo / ".mcp.json").write_text(
            json.dumps({"mcpServers": {"a": {"command": "npx", "args": ["x"]}}})
        )
        (repo / ".claude/skills/s1/SKILL.md").write_text("# s\n")
        for link in (
            "linkdir",
            "nested/l3",
            ".claude/skills/s1/sub",
            ".claude/commands",
        ):
            (repo / link).symlink_to(real, target_is_directory=True)
        monkeypatch.chdir(repo)
        result = runner.invoke(
            app, [*args, "--format", "json", "--include-agent-files"]
        )
        document = json.loads(result.output[result.output.index("{") :])
        keys = [
            (f["id"], f.get("server"), f["description"][:60])
            for f in document["findings"]
            if f["id"] == "TRUST-005"
        ]
        assert len(keys) == len(set(keys))


# ── R6: CLAUDE_CONFIG_DIR ─────────────────────────────────────────────────────


class TestUserScopeHonoursConfigDir:
    def test_settings_in_config_dir_are_user_scope(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        config_dir = tmp_path / "cfg"
        config_dir.mkdir()
        monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(config_dir))
        assert settings_scope(config_dir / "settings.json") == "user"

    def test_home_dot_claude_is_still_user_scope_when_overridden(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        home = tmp_path / "home"
        (home / ".claude").mkdir(parents=True)
        monkeypatch.setattr(Path, "home", lambda: home)
        monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path / "elsewhere"))
        assert settings_scope(home / ".claude" / "settings.json") == "user"

    def test_project_settings_stay_project(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path / "cfg"))
        project = tmp_path / "repo" / ".claude"
        project.mkdir(parents=True)
        assert settings_scope(project / "settings.json") == "project"


# ── R7: vet name@version ──────────────────────────────────────────────────────


class TestVetPinnedVersion:
    @pytest.mark.parametrize(
        ("spec", "expected"),
        [
            ("flowise", ("flowise", None)),
            ("flowise@3.0.4", ("flowise", "3.0.4")),
            ("flowise@v3.0.4", ("flowise", "3.0.4")),
            ("@scope/pkg", ("@scope/pkg", None)),
            ("@scope/pkg@1.2.3", ("@scope/pkg", "1.2.3")),
            ("@scope/pkg@latest", ("@scope/pkg", None)),
            ("pkg@^1.2.3", ("pkg", None)),
            ("pkg==1.2.3", ("pkg", "1.2.3")),
            ("pkg@1.0.0-beta.1", ("pkg", "1.0.0-beta.1")),
        ],
    )
    def test_split(self, spec: str, expected: tuple[str, str | None]) -> None:
        assert split_package_spec(spec) == expected

    def _vet(self, spec: str) -> tuple[int, dict]:
        result = runner.invoke(
            app, ["vet", spec, "--format", "json", "--offline-registry"]
        )
        return result.exit_code, json.loads(result.output)

    def test_scoped_with_version_resolves_the_registry_entry(self) -> None:
        code, verdict = self._vet("@modelcontextprotocol/server-filesystem@0.6.2")
        assert verdict["registry"]["listed"] is True
        assert verdict["package"]["name"] == "@modelcontextprotocol/server-filesystem"
        assert verdict["package"]["version"] == "0.6.2"
        assert {v["status"] for v in verdict["known_vulnerabilities"]} == {"affected"}
        assert code == 1

    def test_calendar_fix_and_semantic_pin_after_the_switch_is_not_affected(
        self,
    ) -> None:
        code, verdict = self._vet("@modelcontextprotocol/server-filesystem@2.0.0")
        assert {v["status"] for v in verdict["known_vulnerabilities"]} == {"fixed"}
        assert code == 0

    def test_unscoped_with_version_reports_per_cve_status(self) -> None:
        _code, old = self._vet("mcp-remote@0.1.30")
        _code, new = self._vet("mcp-remote@0.1.40")
        assert old["registry"]["listed"] is True
        old_affected = [
            v for v in old["known_vulnerabilities"] if v["status"] == "affected"
        ]
        new_affected = [
            v for v in new["known_vulnerabilities"] if v["status"] == "affected"
        ]
        assert len(old_affected) > len(new_affected)
        assert all(v["fixed_in"] is None for v in new_affected)

    def test_no_version_leaves_the_document_unchanged(self) -> None:
        _code, verdict = self._vet("mcp-remote")
        assert "version" not in verdict["package"]
        assert all("status" not in v for v in verdict["known_vulnerabilities"])

    def test_undecidable_pin_is_not_a_clean_exit(self) -> None:
        for flags in ([], ["--strict"]):
            result = runner.invoke(
                app,
                [
                    "vet",
                    "mcp-server-git@1.2.0",
                    "--ecosystem",
                    "pypi",
                    *flags,
                    "--format",
                    "json",
                    "--offline-registry",
                ],
            )
            statuses = {
                v["status"] for v in json.loads(result.output)["known_vulnerabilities"]
            }
            assert "undecidable" in statuses
            assert result.exit_code == 1

    def test_dropped_spec_is_announced_on_stderr_not_in_json(self) -> None:
        result = (
            CliRunner(mix_stderr=False).invoke(
                app,
                ["vet", "mcp-remote@next", "--format", "json", "--offline-registry"],
            )
            if "mix_stderr" in CliRunner.__init__.__code__.co_varnames
            else None
        )
        if result is None:
            pytest.skip("CliRunner cannot separate stderr")
        json.loads(result.stdout)
        assert "No version applied" in result.stderr


class TestDeepBaseline:
    def test_compare_exits_2_not_a_traceback(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from mcp_audit.baselines import manager as manager_mod

        monkeypatch.setattr(manager_mod, "_DEFAULT_STORAGE_DIR", tmp_path)
        (tmp_path / "t.json").write_text(
            '{"version":1,"servers":' + "[" * 200_000 + "]" * 200_000 + "}"
        )
        result = runner.invoke(app, ["baseline", "compare", "t"])
        assert result.exit_code == 2
        assert "Traceback" not in result.output
        assert not isinstance(result.exception, RecursionError)
