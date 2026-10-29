"""STORY-0127: ``affected --fix`` pins to the advisory's fixed version."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mcp_audit.affected.fixplan import candidates, choose, crosses_major
from mcp_audit.cli import app
from mcp_audit.fixer.fixer import run_pins
from mcp_audit.fixer.strategies.pinning import pin_exact

runner = CliRunner()
CVE = "CVE-2026-77244"


def _cfg(tmp_path: Path, servers: dict) -> Path:
    path = tmp_path / ".mcp.json"
    path.write_text(json.dumps({"mcpServers": servers}), encoding="utf-8")
    return path


SSE = ["mcp-atlassian==0.21.0", "--transport", "sse"]


class TestChoose:
    def test_lowest_fix_above_current(self) -> None:
        assert choose("1.20.0", ("2.2.0", "1.30.0")) == ("1.30.0", "")

    def test_current_major_two_takes_the_newer(self) -> None:
        assert choose("2.0.0", ("2.2.0", "1.30.0")) == ("2.2.0", "")

    def test_fix_below_current_is_ignored(self) -> None:
        assert choose("1.6.0", ("1.5.9", "2.2.0")) == ("2.2.0", "")

    def test_prerelease_fix_is_not_chosen_when_a_release_exists(self) -> None:
        assert choose("1.0.0", ("1.1.0rc1", "1.2.0")) == ("1.2.0", "")

    def test_nothing_above_current(self) -> None:
        version, why = choose("3.0.0", ("1.0.0",))
        assert version is None and "no fixed version is above" in why

    def test_no_fix_recorded(self) -> None:
        assert choose("1.0.0", ())[0] is None

    def test_unknown_current_needs_a_single_fix(self) -> None:
        assert choose(None, ("1.2.0",)) == ("1.2.0", "")
        assert choose(None, ("1.2.0", "2.0.0"))[0] is None

    def test_unparseable_current_or_fix_is_skipped(self) -> None:
        assert choose("not-a-version", ("1.2.0",))[0] is None
        assert choose("1.0.0", ("nope",))[0] is None

    def test_calendar_versus_semantic_is_skipped(self) -> None:
        version, why = choose("1.0.0", ("2025.7.1",))
        assert version is None and "numbering scheme" in why


class TestPinExact:
    def _c(self, command: str, args: list[str]) -> dict:
        return {"mcpServers": {"s": {"command": command, "args": args}}}

    def test_pypi_keeps_the_equals_style_and_extras(self) -> None:
        new, msg = pin_exact(self._c("uvx", ["pkg[x]==1.0"]), "s", "pkg", "1.1")
        assert new["mcpServers"]["s"]["args"] == ["pkg[x]==1.1"]
        assert "Replaced" in msg

    def test_pypi_at_style_is_kept(self) -> None:
        new, _ = pin_exact(self._c("uvx", ["pkg@1.0"]), "s", "pkg", "1.1")
        assert new["mcpServers"]["s"]["args"] == ["pkg@1.1"]

    def test_unpinned_pypi_gets_equals(self) -> None:
        new, _ = pin_exact(self._c("uvx", ["pkg", "--x"]), "s", "pkg", "1.1")
        assert new["mcpServers"]["s"]["args"] == ["pkg==1.1", "--x"]

    def test_scoped_npm(self) -> None:
        new, _ = pin_exact(
            self._c("npx", ["-y", "@scope/pkg@1.0.0", "/data"]),
            "s",
            "@scope/pkg",
            "1.2.0",
        )
        assert new["mcpServers"]["s"]["args"] == ["-y", "@scope/pkg@1.2.0", "/data"]

    def test_idempotent(self) -> None:
        cfg = self._c("uvx", ["pkg==1.1"])
        new, msg = pin_exact(cfg, "s", "pkg", "1.1")
        assert new == cfg and "already fixed" in msg

    def test_does_not_mutate_the_input(self) -> None:
        cfg = self._c("uvx", ["pkg==1.0"])
        pin_exact(cfg, "s", "pkg", "1.1")
        assert cfg["mcpServers"]["s"]["args"] == ["pkg==1.0"]

    @pytest.mark.parametrize(
        ("command", "args", "package"),
        [
            ("uvx", ["--from", "pkg==1.0", "tool"], "pkg"),
            ("uvx", ["other==1.0"], "pkg"),
            ("python", ["-m", "pkg"], "pkg"),
            ("uvx", ["--with", "x", "pkg==1"], "pkg"),
            ("uvx", [], "pkg"),
        ],
    )
    def test_launches_it_will_not_rewrite(
        self, command: str, args: list[str], package: str
    ) -> None:
        with pytest.raises(ValueError):
            pin_exact(self._c(command, args), "s", package, "2.0")

    def test_missing_server(self) -> None:
        with pytest.raises(ValueError):
            pin_exact({"mcpServers": {}}, "s", "pkg", "2.0")

    def test_vscode_servers_root(self) -> None:
        cfg = {"servers": {"s": {"command": "uvx", "args": ["pkg==1.0"]}}}
        new, _ = pin_exact(cfg, "s", "pkg", "1.1")
        assert new["servers"]["s"]["args"] == ["pkg==1.1"]


class TestRunPins:
    def test_dry_run_writes_nothing(self, tmp_path: Path) -> None:
        path = _cfg(tmp_path, {"s": {"command": "uvx", "args": ["pkg==1.0"]}})
        before = path.read_text()
        result = run_pins(path, [("s", "pkg", "1.1")])
        assert path.read_text() == before
        assert "pkg==1.1" in result.diff

    def test_apply_writes_with_backup(self, tmp_path: Path) -> None:
        path = _cfg(tmp_path, {"s": {"command": "uvx", "args": ["pkg==1.0"]}})
        before = path.read_text()
        result = run_pins(path, [("s", "pkg", "1.1")], apply=True)
        assert json.loads(path.read_text())["mcpServers"]["s"]["args"] == ["pkg==1.1"]
        assert result.backup_path is not None
        assert result.backup_path.read_text() == before
        assert not path.with_suffix(".json.tmp").exists()

    def test_a_skipped_pin_does_not_block_the_others(self, tmp_path: Path) -> None:
        path = _cfg(
            tmp_path,
            {
                "a": {"command": "uvx", "args": ["--from", "pkg==1.0", "t"]},
                "b": {"command": "uvx", "args": ["pkg==1.0"]},
            },
        )
        result = run_pins(path, [("a", "pkg", "1.1"), ("b", "pkg", "1.1")], apply=True)
        doc = json.loads(path.read_text())["mcpServers"]
        assert doc["a"]["args"] == ["--from", "pkg==1.0", "t"]
        assert doc["b"]["args"] == ["pkg==1.1"]
        assert len(result.skipped) == 1

    def test_toml_is_refused(self, tmp_path: Path) -> None:
        path = tmp_path / "config.toml"
        path.write_text("x = 1")
        with pytest.raises(ValueError, match="TOML"):
            run_pins(path, [("s", "pkg", "1.1")])

    def test_existing_fix_flow_unchanged(self, tmp_path: Path) -> None:
        # run_fix shares the write path; a no-finding call still reports it.
        from mcp_audit.fixer.fixer import run_fix

        path = _cfg(tmp_path, {"s": {"command": "uvx", "args": ["pkg"]}})
        assert run_fix([], path).no_fixable


class TestCli:
    def test_dry_run_shows_the_pin_and_changes_nothing(self, tmp_path: Path) -> None:
        cfg = _cfg(tmp_path, {"a": {"command": "uvx", "args": SSE}})
        before = cfg.read_text()
        res = runner.invoke(app, ["affected", CVE, "--path", str(cfg), "--fix"])
        assert res.exit_code == 1  # still affected: nothing was written
        assert "mcp-atlassian==0.22.0" in res.output
        assert "Dry run" in res.output
        assert cfg.read_text() == before

    def test_apply_then_rerun_is_clear(self, tmp_path: Path) -> None:
        cfg = _cfg(tmp_path, {"a": {"command": "uvx", "args": SSE}})
        res = runner.invoke(
            app, ["affected", CVE, "--path", str(cfg), "--fix", "--apply"]
        )
        assert res.exit_code == 1
        assert (tmp_path / ".mcp.json.bak").exists()
        again = runner.invoke(app, ["affected", CVE, "--path", str(cfg)])
        assert again.exit_code == 0
        assert "0 affected" in again.output

    def test_apply_needs_fix(self, tmp_path: Path) -> None:
        cfg = _cfg(tmp_path, {"a": {"command": "uvx", "args": SSE}})
        res = runner.invoke(app, ["affected", CVE, "--path", str(cfg), "--apply"])
        assert res.exit_code == 2

    def test_fix_needs_terminal_format(self, tmp_path: Path) -> None:
        cfg = _cfg(tmp_path, {"a": {"command": "uvx", "args": SSE}})
        res = runner.invoke(
            app, ["affected", CVE, "--path", str(cfg), "--fix", "-f", "json"]
        )
        assert res.exit_code == 2

    def test_unrewritable_launch_is_reported_not_changed(self, tmp_path: Path) -> None:
        launch = {
            "command": "uvx",
            "args": ["--from", "mcp-atlassian==0.21.0", "t", "--transport", "sse"],
        }
        cfg = _cfg(tmp_path, {"a": launch})
        before = cfg.read_text()
        res = runner.invoke(
            app, ["affected", CVE, "--path", str(cfg), "--fix", "--apply"]
        )
        assert cfg.read_text() == before
        assert "skipped" in res.output or "not pinned" in res.output

    def test_nothing_affected_says_so(self, tmp_path: Path) -> None:
        cfg = _cfg(tmp_path, {"a": {"command": "npx", "args": ["-y", "left-pad"]}})
        res = runner.invoke(app, ["affected", CVE, "--path", str(cfg), "--fix"])
        assert res.exit_code == 0
        assert "no AFFECTED server" in res.output

    def test_toml_config_does_not_stop_the_others(self, tmp_path: Path) -> None:
        good = tmp_path / "a"
        good.mkdir()
        cfg = _cfg(good, {"a": {"command": "uvx", "args": SSE}})
        toml = tmp_path / "config.toml"
        toml.write_text(
            '[mcp_servers.a]\ncommand = "uvx"\n'
            'args = ["mcp-atlassian==0.21.0", "--transport", "sse"]\n'
        )
        res = runner.invoke(
            app,
            [
                "affected",
                CVE,
                "--path",
                str(toml),
                "--path",
                str(cfg),
                "--fix",
                "--apply",
            ],
        )
        assert res.exit_code == 1
        assert "mcp-atlassian==0.22.0" in cfg.read_text()
        assert "TOML" in res.output

    def test_record_rule_fixes_come_from_ranges_even_for_listed_versions(self) -> None:
        from mcp_audit.affected.match import Launch, RecordRule, Status
        from mcp_audit.registry.malicious import MaliciousRecord

        rec = MaliciousRecord(
            id="GHSA-x",
            ecosystem="npm",
            name="left-pad",
            versions=("1.0.0", "1.1.0", "1.2.0"),
            ranges=((("introduced", "0"), ("fixed", "1.3.0")),),
        )
        d = RecordRule(rec, curated=False).decide(
            Launch("npm", "left-pad", "1.2.0", "config pin", None)
        )
        assert d.status is Status.AFFECTED
        assert d.fixes == ("1.3.0",)

    def test_union_of_fixes_across_overlapping_ranges(self) -> None:
        # [1.0.0 -> fixed 1.5.0] and [0 -> fixed 1.3.0]; current 1.2.0
        assert candidates("1.2.0", ("1.3.0", "1.5.0"))[0] == ["1.3.0", "1.5.0"]

    def test_cross_major_is_flagged(self) -> None:
        assert crosses_major("1.20.0", "2.2.0")
        assert not crosses_major("1.20.0", "1.30.0")

    def test_cross_major_pin_prints_a_note(self, tmp_path: Path) -> None:
        cfg = _cfg(
            tmp_path,
            {"a": {"command": "uvx", "args": ["mcp==1.20.0", "--transport", "http"]}},
        )
        res = runner.invoke(
            app, ["affected", "CVE-2026-59951", "--path", str(cfg), "--fix"]
        )
        assert "major-version change" in res.output


class TestWritePath:
    def test_permissions_are_kept_on_file_and_backup(self, tmp_path: Path) -> None:
        path = _cfg(tmp_path, {"s": {"command": "uvx", "args": ["pkg==1.0"]}})
        path.chmod(0o600)
        result = run_pins(path, [("s", "pkg", "1.1")], apply=True)
        assert (path.stat().st_mode & 0o777) == 0o600
        assert result.backup_path is not None
        assert (result.backup_path.stat().st_mode & 0o777) == 0o600

    def test_symlinked_config_is_edited_where_it_lives(self, tmp_path: Path) -> None:
        real = _cfg(tmp_path, {"s": {"command": "uvx", "args": ["pkg==1.0"]}})
        link = tmp_path / "link.json"
        link.symlink_to(real)
        run_pins(link, [("s", "pkg", "1.1")], apply=True)
        assert link.is_symlink()
        assert "pkg==1.1" in real.read_text()

    def test_first_backup_is_never_overwritten(self, tmp_path: Path) -> None:
        path = _cfg(tmp_path, {"s": {"command": "uvx", "args": ["pkg==1.0"]}})
        original = path.read_text()
        first = run_pins(path, [("s", "pkg", "1.1")], apply=True)
        second = run_pins(path, [("s", "pkg", "1.2")], apply=True)
        assert first.backup_path is not None and second.backup_path is not None
        assert first.backup_path != second.backup_path
        assert first.backup_path.read_text() == original


class TestLaunchForms:
    def _c(self, command: str, args: list[str]) -> dict:
        return {"mcpServers": {"s": {"command": command, "args": args}}}

    def test_pipx_run(self) -> None:
        new, _ = pin_exact(self._c("pipx", ["run", "pkg==1.0"]), "s", "pkg", "1.1")
        assert new["mcpServers"]["s"]["args"] == ["run", "pkg==1.1"]

    def test_absolute_path_launcher(self) -> None:
        new, _ = pin_exact(
            self._c("/usr/local/bin/uvx", ["pkg==1.0"]), "s", "pkg", "1.1"
        )
        assert new["mcpServers"]["s"]["args"] == ["pkg==1.1"]

    def test_cmd_c_wrapper_keeps_the_prefix(self) -> None:
        new, _ = pin_exact(
            self._c("cmd", ["/c", "npx", "-y", "pkg@1.0.0"]), "s", "pkg", "1.1.0"
        )
        assert new["mcpServers"]["s"]["args"] == ["/c", "npx", "-y", "pkg@1.1.0"]

    def test_with_equals_form_is_refused(self) -> None:
        with pytest.raises(ValueError):
            pin_exact(self._c("uvx", ["--with=httpx", "pkg==1.0"]), "s", "pkg", "1.1")

    def test_name_under_both_root_keys_is_refused(self) -> None:
        cfg = {
            "servers": {"s": {"command": "uvx", "args": ["pkg==1.0"]}},
            "mcpServers": {"s": {"command": "uvx", "args": ["pkg==1.2"]}},
        }
        with pytest.raises(ValueError, match="both"):
            pin_exact(cfg, "s", "pkg", "1.3")
