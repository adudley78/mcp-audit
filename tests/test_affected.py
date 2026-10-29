"""STORY-0121: ``mcp-audit affected``."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest
from packaging.specifiers import SpecifierSet
from typer.testing import CliRunner

from mcp_audit.affected import match as m
from mcp_audit.affected.match import (
    Launch,
    LockIndex,
    RangeRule,
    RecordRule,
    RegistryRule,
    Status,
)
from mcp_audit.affected.query import QueryError, parse_query
from mcp_audit.cli import app
from mcp_audit.models import Finding, ServerConfig, Severity
from mcp_audit.registry.loader import RegistryEntry
from mcp_audit.registry.malicious import MaliciousRecord
from mcp_audit.registry.research import load_research_records

REPO = Path(__file__).resolve().parent.parent
runner = CliRunner()
FS = "@modelcontextprotocol/server-filesystem"
PLUGIN4SHELL = "x_MCPRS-4ad8c07d80d7"
CONTEXTCRUSH = "x_MCPRS-32fc646f6f96"


def _entry(**over: Any) -> RegistryEntry:
    base: dict[str, Any] = {
        "name": FS,
        "source": "npm",
        "repo": None,
        "maintainer": "x",
        "verified": True,
        "last_verified": "2026-01-01",
        "known_versions": [],
        "tags": [],
        "semver_resumed_at": "1.0.0",
    }
    base.update(over)
    return RegistryEntry(**base)


def _launch(version: str | None, entry: RegistryEntry | None = None) -> Launch:
    return Launch(
        "npm", FS, version, "config pin" if version else None, entry or _entry()
    )


def _config(tmp_path: Path, servers: dict[str, Any], name: str = "mcp.json") -> Path:
    path = tmp_path / name
    path.write_text(json.dumps({"mcpServers": servers}), encoding="utf-8")
    return path


def _npx(spec: str) -> dict[str, Any]:
    return {"command": "npx", "args": ["-y", spec, "/srv/data"]}


def _run(*args: str) -> Any:
    return runner.invoke(app, ["affected", *args])


# ── Query ──────────────────────────────────────────────────────────────────────


class TestQuery:
    @pytest.mark.parametrize(
        "text", ["CVE-2025-53109", "GHSA-xxxx-yyyy-zzzz", "MAL-2026-4068", PLUGIN4SHELL]
    )
    def test_advisory_ids(self, text: str) -> None:
        q = parse_query(text)
        assert q.kind == "advisory" and q.advisory_id == text

    def test_range_with_scoped_name(self) -> None:
        q = parse_query(f"{FS}@<2025.7.1")
        assert q.kind == "range" and q.package == FS
        assert q.specifier is not None and "2025.1.1" in q.specifier

    def test_bare_version_means_equals(self) -> None:
        q = parse_query("litellm@1.107.0")
        assert q.specifier is not None and "1.107.0" in q.specifier
        assert "1.107.1" not in q.specifier

    @pytest.mark.parametrize(
        "text", ["", "   ", "x" * 300, "@scope/pkg", "pkg@", "@@1", "pkg@^1.2", "p@~1"]
    )
    def test_rejects(self, text: str) -> None:
        with pytest.raises(QueryError):
            parse_query(text)

    def test_tilde_equals_is_pep440_and_allowed(self) -> None:
        assert parse_query("pkg@~=1.4").kind == "range"

    def test_nonsense_range(self) -> None:
        with pytest.raises(QueryError, match="not a version range"):
            parse_query("pkg@banana")


# ── Rules ──────────────────────────────────────────────────────────────────────


class TestRegistryRule:
    rule = RegistryRule(FS, "CVE-2025-53109", "2025.7.1")

    def test_below_fix_is_affected(self) -> None:
        d = self.rule.decide(_launch("2025.1.14"))
        assert d.status is Status.AFFECTED and d.fixed_in == "2025.7.1"

    def test_at_or_above_fix_is_not_affected(self) -> None:
        assert self.rule.decide(_launch("2025.7.1")).status is Status.NOT_AFFECTED
        assert self.rule.decide(_launch("2025.8.21")).status is Status.NOT_AFFECTED

    def test_unpinned_is_couldnt_check_never_not_affected(self) -> None:
        d = self.rule.decide(_launch(None))
        assert d.status is Status.COULDNT_CHECK and d.reason == m.VERSION_UNKNOWN

    def test_semantic_pin_after_the_calendar_run_is_fixed_via_resumed_at(self) -> None:
        assert self.rule.decide(_launch("1.0.0")).status is Status.NOT_AFFECTED

    def test_semantic_pin_before_the_calendar_run_is_affected(self) -> None:
        assert self.rule.decide(_launch("0.6.2")).status is Status.AFFECTED

    def test_calendar_vs_semantic_without_resumed_at_is_undecidable(self) -> None:
        d = self.rule.decide(_launch("1.0.0", _entry(semver_resumed_at=None)))
        assert d.status is Status.COULDNT_CHECK and d.reason == m.UNDECIDABLE

    def test_unparsable_version_is_couldnt_check(self) -> None:
        d = self.rule.decide(_launch("not-a-version"))
        assert d.status is Status.COULDNT_CHECK

    def test_no_recorded_fix_is_affected_at_any_pinned_version(self) -> None:
        d = RegistryRule(FS, "CVE-1", None).decide(_launch("3.0.0"))
        assert d.status is Status.AFFECTED and "no fixed version" in d.evidence


def _rec(**over: Any) -> MaliciousRecord:
    base: dict[str, Any] = {
        "id": "MAL-1",
        "ecosystem": "npm",
        "name": "pkg",
        "versions": ("1.0.0",),
    }
    base.update(over)
    return MaliciousRecord(**base)


def _plain(version: str | None) -> Launch:
    return Launch("npm", "pkg", version, "config pin", None)


class TestRecordRule:
    def test_listed_version(self) -> None:
        assert RecordRule(_rec(), False).decide(_plain("1.0.0")).status is (
            Status.AFFECTED
        )

    def test_other_version_is_not_affected(self) -> None:
        assert RecordRule(_rec(), False).decide(_plain("2.0.0")).status is (
            Status.NOT_AFFECTED
        )

    def test_range_covers_and_excludes(self) -> None:
        rec = _rec(versions=(), ranges=((("introduced", "1.0.0"), ("fixed", "1.5.0")),))
        rule = RecordRule(rec, False)
        assert rule.decide(_plain("1.2.0")).status is Status.AFFECTED
        assert rule.decide(_plain("1.5.0")).status is Status.NOT_AFFECTED

    def test_unpinned_with_open_ended_range_is_affected(self) -> None:
        rec = _rec(versions=(), ranges=((("introduced", "0"),),))
        assert RecordRule(rec, False).decide(_plain(None)).status is Status.AFFECTED

    def test_unpinned_with_only_listed_versions_is_couldnt_check(self) -> None:
        assert RecordRule(_rec(), False).decide(_plain(None)).status is (
            Status.COULDNT_CHECK
        )

    def test_unparsable_range_bound_is_couldnt_check(self) -> None:
        rec = _rec(versions=(), ranges=((("introduced", "zzz"), ("fixed", "2")),))
        d = RecordRule(rec, False).decide(_plain("1.0.0"))
        assert d.status is Status.COULDNT_CHECK and d.reason == m.UNEVALUABLE

    def test_curated_package_ignores_a_blanket_range(self) -> None:
        rec = _rec(ranges=((("introduced", "0"),),))
        assert RecordRule(rec, True).decide(_plain("3.0.0")).status is (
            Status.NOT_AFFECTED
        )
        assert RecordRule(rec, False).decide(_plain("3.0.0")).status is (
            Status.AFFECTED
        )

    def test_matches_only_the_same_ecosystem(self) -> None:
        rule = RecordRule(_rec(), False)
        assert rule.matches(_plain("1.0.0"))
        assert not rule.matches(Launch("pypi", "pkg", "1.0.0", "x", None))


class TestRangeRule:
    def _rule(self, text: str) -> RangeRule:
        return RangeRule("pkg", SpecifierSet(text), f"pkg@{text}")

    def test_in_and_out(self) -> None:
        assert self._rule("<2").decide(_plain("1.5")).status is Status.AFFECTED
        assert self._rule("<2").decide(_plain("2.0")).status is Status.NOT_AFFECTED

    def test_comma_is_and(self) -> None:
        rule = self._rule(">=1,<2")
        assert rule.decide(_plain("1.5")).status is Status.AFFECTED
        assert rule.decide(_plain("0.5")).status is Status.NOT_AFFECTED

    def test_unpinned_is_couldnt_check(self) -> None:
        assert self._rule("<2").decide(_plain(None)).status is Status.COULDNT_CHECK

    def test_calendar_bound_against_semantic_pin_is_undecidable_without_help(
        self,
    ) -> None:
        # 1.0.0 sorts below 2025.7.1 but was published after it (Q-010)
        d = self._rule("<2025.7.1").decide(_plain("1.0.0"))
        assert d.status is Status.COULDNT_CHECK and d.reason == m.UNDECIDABLE

    def test_calendar_bound_uses_semver_resumed_at_when_the_registry_has_it(
        self,
    ) -> None:
        rule = RangeRule(FS, SpecifierSet("<2025.7.1"), "x")
        assert rule.decide(_launch("1.0.0")).status is Status.NOT_AFFECTED
        assert rule.decide(_launch("0.6.2")).status is Status.AFFECTED
        assert rule.decide(_launch("2025.1.14")).status is Status.AFFECTED

    def test_calendar_equals_against_semantic_pin_is_undecidable(self) -> None:
        d = self._rule("==2025.7.1").decide(_plain("1.0.0"))
        assert d.status is Status.COULDNT_CHECK

    def test_name_match_normalises_pypi(self) -> None:
        rule = RangeRule("My_Pkg", SpecifierSet("<2"), "x")
        assert rule.matches(Launch("pypi", "my-pkg", "1", "x", None))
        assert not rule.matches(Launch("npm", "my-pkg", "1", "x", None))


# ── Lock versions ──────────────────────────────────────────────────────────────


def _server(tmp_path: Path, **launch: Any) -> ServerConfig:
    return ServerConfig(
        name="filesystem",
        client="custom",
        config_path=tmp_path / "mcp.json",
        command="npx",
        args=launch.get("args", ["-y", FS, "/srv/data"]),
    )


def _lock(tmp_path: Path, version: str, name: str = FS) -> Path:
    path = tmp_path / "locks" / "mcp-lock.json"
    path.parent.mkdir(exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "servers": {
                    "custom/filesystem": {
                        "package": {"name": name, "resolved_version": version}
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    return path


class TestLockIndex:
    def test_explicit_lock_supplies_the_version(self, tmp_path: Path) -> None:
        locks = LockIndex([_lock(tmp_path, "2025.1.14")])
        version, source = m.server_version(_server(tmp_path), "npm", FS, locks)
        assert version == "2025.1.14" and "lock resolved_version" in (source or "")

    def test_config_pin_wins_over_the_lock(self, tmp_path: Path) -> None:
        locks = LockIndex([_lock(tmp_path, "1.0.0")])
        server = _server(tmp_path, args=["-y", f"{FS}@2025.8.21"])
        assert m.server_version(server, "npm", FS, locks) == (
            "2025.8.21",
            "config pin",
        )

    def test_a_lock_for_a_different_package_is_ignored(self, tmp_path: Path) -> None:
        locks = LockIndex([_lock(tmp_path, "9.9.9", name="other")])
        assert m.server_version(_server(tmp_path), "npm", FS, locks) == (None, None)

    def test_nearest_lock_beside_the_config_is_read(self, tmp_path: Path) -> None:
        lock = tmp_path / "mcp-lock.json"
        lock.write_text(
            json.dumps(
                {
                    "servers": {
                        "custom/filesystem": {
                            "package": {"name": FS, "resolved_version": "2025.2.2"}
                        }
                    }
                }
            ),
            encoding="utf-8",
        )
        version, _ = m.server_version(_server(tmp_path), "npm", FS, LockIndex([]))
        assert version == "2025.2.2"

    def test_unreadable_lock_is_reported_not_raised(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.json"
        bad.write_text("{nope", encoding="utf-8")
        errors: list[str] = []
        LockIndex([bad], errors)
        assert errors and "bad.json" in errors[0]


# ── Per-server rows ────────────────────────────────────────────────────────────


class TestDecideServer:
    def _reg(self) -> Any:
        from mcp_audit.registry.loader import load_registry  # noqa: PLC0415

        return load_registry(offline=True)

    def test_no_package_is_couldnt_check_with_its_own_reason(
        self, tmp_path: Path
    ) -> None:
        server = ServerConfig(
            name="r", client="c", config_path=tmp_path / "x", url="https://x.test/mcp"
        )
        row = m.decide_server(
            server,
            [RangeRule("pkg", SpecifierSet("<2"), "p")],
            self._reg(),
            LockIndex(),
            "q",
        )
        assert row.status is Status.COULDNT_CHECK and row.reason == m.NO_PACKAGE

    def test_other_package_is_not_affected_and_says_why(self, tmp_path: Path) -> None:
        row = m.decide_server(
            _server(tmp_path),
            [RangeRule("pkg", SpecifierSet("<2"), "p")],
            self._reg(),
            LockIndex(),
            "q",
        )
        assert row.status is Status.NOT_AFFECTED and row.reason == m.OTHER_PACKAGE
        assert "concerns pkg" in row.evidence

    def test_strongest_rule_wins(self, tmp_path: Path) -> None:
        rules = [
            RegistryRule(FS, "CVE-1", "2025.7.1"),
            RegistryRule(FS, "CVE-1", "2020.1.1"),
        ]
        server = _server(tmp_path, args=["-y", f"{FS}@2025.1.14"])
        row = m.decide_server(server, rules, self._reg(), LockIndex(), "CVE-1")
        assert row.status is Status.AFFECTED and row.fixed_in == "2025.7.1"


class TestOsvRecords:
    def test_npm_and_pypi_packages_become_records(self) -> None:
        osv = {
            "id": "GHSA-aaaa-bbbb-cccc",
            "aliases": ["CVE-2026-1"],
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": "litellm"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "0"}, {"fixed": "1.108.0"}],
                        },
                        {"type": "GIT", "events": [{"introduced": "abc"}]},
                    ],
                },
                {"package": {"ecosystem": "Go", "name": "x"}},
            ],
        }
        recs = m.records_from_osv(osv)
        assert [(r.ecosystem, r.name) for r in recs] == [("pypi", "litellm")]
        assert len(recs[0].ranges) == 1
        rule = RecordRule(recs[0], False)
        launch = Launch("pypi", "litellm", "1.107.0", "config pin", None)
        assert rule.decide(launch).status is Status.AFFECTED


# ── Research records ───────────────────────────────────────────────────────────


class TestResearchRows:
    def _record(self) -> Any:
        rec = load_research_records().lookup(PLUGIN4SHELL)
        assert rec is not None
        return rec

    def test_every_product_is_couldnt_check_never_not_affected(self) -> None:
        notes: list[str] = []
        rows = m.research_rows(self._record(), lambda: [], notes)
        assert {r.status for r in rows} == {Status.COULDNT_CHECK}
        assert len(rows) == 4 and notes

    def test_record_without_checks_has_its_own_note_and_row_text(self) -> None:
        rec = load_research_records().lookup(CONTEXTCRUSH)
        assert rec is not None
        notes: list[str] = []
        rows = m.research_rows(rec, None, notes)
        assert [r.status for r in rows] == [Status.COULDNT_CHECK]
        assert "no installed version shows exposure" in rows[0].evidence
        assert len(notes) == 1 and "No mcp-audit check tests" in notes[0]

    def test_high_check_result_is_affected(self) -> None:
        finding = Finding(
            id="PLUGIN-003",
            severity=Severity.CRITICAL,
            analyzer="plugins",
            client="claude-code-plugin",
            server="demo@market",
            title="Plugin checkout does not match its pin",
            description="d",
            evidence="e",
            remediation="r",
            finding_path="/x/y",
        )
        notes: list[str] = []
        rows = m.research_rows(self._record(), lambda: [finding], notes)
        assert rows[0].status is Status.AFFECTED and "PLUGIN-003" in rows[0].evidence
        assert notes == []

    def test_medium_posture_is_listed_but_not_affected(self) -> None:
        finding = Finding(
            id="PLUGIN-004",
            severity=Severity.MEDIUM,
            analyzer="plugins",
            client="claude-code-plugin",
            server="demo@market",
            title="Plugin updates from a moving branch",
            description="d",
            evidence="e",
            remediation="r",
        )
        rows = m.research_rows(self._record(), lambda: [finding], [])
        assert rows[0].status is Status.COULDNT_CHECK
        assert rows[0].reason == m.POSTURE_ONLY

    def test_unrelated_findings_are_ignored(self) -> None:
        finding = Finding(
            id="PLUGIN-001",
            severity=Severity.HIGH,
            analyzer="plugins",
            client="c",
            server="s",
            title="t",
            description="d",
            evidence="e",
            remediation="r",
        )
        rows = m.research_rows(self._record(), lambda: [finding], [])
        assert all("PLUGIN-001" not in r.evidence for r in rows)

    def test_checks_not_run_is_said(self) -> None:
        notes: list[str] = []
        m.research_rows(self._record(), None, notes)
        assert any("were not run" in n for n in notes)


# ── CLI ────────────────────────────────────────────────────────────────────────


class TestCli:
    def test_cve_below_fix_is_affected_exit_1(self, tmp_path: Path) -> None:
        cfg = _config(tmp_path, {"filesystem": _npx(f"{FS}@2025.1.14")})
        result = _run("CVE-2025-53109", "-p", str(cfg))
        assert result.exit_code == 1
        assert "AFFECTED" in result.output and "2025.7.1" in result.output

    def test_cve_at_fix_is_not_affected_exit_0(self, tmp_path: Path) -> None:
        cfg = _config(tmp_path, {"filesystem": _npx(f"{FS}@2025.8.21")})
        result = _run("CVE-2025-53109", "-p", str(cfg))
        assert result.exit_code == 0 and "NOT AFFECTED" in result.output

    def test_floating_npx_is_couldnt_check_and_exit_0_unless_asked(
        self, tmp_path: Path
    ) -> None:
        cfg = _config(tmp_path, {"filesystem": _npx(FS)})
        assert _run("CVE-2025-53109", "-p", str(cfg)).exit_code == 0
        strict = _run("CVE-2025-53109", "-p", str(cfg), "--fail-on-unknown")
        assert strict.exit_code == 1 and "COULDN'T CHECK" in strict.output

    def test_a_lock_settles_a_floating_launch(self, tmp_path: Path) -> None:
        cfg = _config(tmp_path, {"filesystem": _npx(FS)})
        lock = _lock(tmp_path, "2025.1.14")
        result = _run("CVE-2025-53109", "-p", str(cfg), "--lock", str(lock))
        assert result.exit_code == 1 and "lock resolved_version" in result.output

    def test_range_query_litellm(self, tmp_path: Path) -> None:
        cfg = _config(
            tmp_path, {"gw": {"command": "uvx", "args": ["litellm==1.107.0"]}}
        )
        result = _run("litellm@==1.107.0", "-p", str(cfg))
        assert result.exit_code == 1 and "AFFECTED" in result.output

    def test_remote_server_is_couldnt_check_and_trips_the_unknown_gate(
        self, tmp_path: Path
    ) -> None:
        cfg = _config(tmp_path, {"remote": {"url": "https://example.test/mcp"}})
        assert _run("litellm@<2", "-p", str(cfg)).exit_code == 0
        gated = _run("litellm@<2", "-p", str(cfg), "--fail-on-unknown")
        assert gated.exit_code == 1 and "launch no package" in gated.output

    def test_json_shape(self, tmp_path: Path) -> None:
        cfg = _config(tmp_path, {"filesystem": _npx(f"{FS}@2025.1.14")})
        result = _run("CVE-2025-53109", "-p", str(cfg), "-f", "json")
        doc = json.loads(result.output)
        assert doc["summary"] == {
            "checked": 1,
            "affected": 1,
            "not_affected": 0,
            "couldnt_check": 0,
        }
        row = doc["results"][0]
        assert row["status"] == "AFFECTED" and row["version_source"] == "config pin"
        assert row["fixed_in"] == "2025.7.1" and row["package"].startswith("npm:")

    def test_json_and_sarif_never_carry_the_home_directory(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        home = tmp_path / "home" / "someone"
        proj = home / "proj"
        proj.mkdir(parents=True)
        monkeypatch.setenv("HOME", str(home))
        monkeypatch.setenv("USERPROFILE", str(home))
        monkeypatch.chdir(proj)
        cfg = _config(proj, {"filesystem": _npx(f"{FS}@2025.1.14")})
        (proj / "broken.json").write_text("{nope", encoding="utf-8")
        for fmt in ("json", "sarif"):
            out = _run(
                "CVE-2025-53109",
                "-p",
                str(cfg),
                "-p",
                str(proj / "broken.json"),
                "-f",
                fmt,
            ).output
            assert "someone" not in out, fmt

    def test_sarif_is_valid_and_has_one_result_per_affected_server(
        self, tmp_path: Path
    ) -> None:
        jsonschema = pytest.importorskip("jsonschema")
        cfg = _config(
            tmp_path,
            {
                "a": _npx(f"{FS}@2025.1.14"),
                "b": _npx(f"{FS}@2025.8.21"),
            },
        )
        out = tmp_path / "r.sarif"
        result = _run("CVE-2025-53109", "-p", str(cfg), "-f", "sarif", "-o", str(out))
        assert result.exit_code == 1
        doc = json.loads(out.read_text(encoding="utf-8"))
        schema = json.loads(
            (REPO / "tests/fixtures/sarif-schema-2.1.0.json").read_text("utf-8")
        )
        jsonschema.validate(doc, schema)
        results = doc["runs"][0]["results"]
        assert len(results) == 1 and results[0]["ruleId"] == "CVE-2025-53109"

    def test_research_record_with_path_says_checks_not_run(
        self, tmp_path: Path
    ) -> None:
        cfg = _config(tmp_path, {"x": _npx("pkg@1.0.0")})
        result = _run(PLUGIN4SHELL, "-p", str(cfg))
        assert result.exit_code == 0
        assert "were not run" in result.output and "Claude Code" in result.output

    def test_record_without_checks_says_nothing_was_run(self, tmp_path: Path) -> None:
        cfg = _config(tmp_path, {"context7": _npx("@upstash/context7-mcp@4.4.4")})
        result = _run(CONTEXTCRUSH, "-p", str(cfg))
        assert result.exit_code == 0
        out = " ".join(result.output.split())
        assert "COULDN'T CHECK" in out and "Context7 MCP (Upstash)" in out
        assert "fixed in 2026-02-23 (server-side)" in out
        assert "No mcp-audit check tests this condition" in out
        # The plugin-directory wording belongs to Plugin4Shell only.
        assert "plugin" not in out.lower()
        assert "AFFECTED" not in out.replace("0 affected", "")

    def test_record_without_checks_json_has_one_couldnt_check_row(self) -> None:
        result = _run(CONTEXTCRUSH, "-f", "json")
        assert result.exit_code == 0
        doc = json.loads(result.output)
        assert [r["status"] for r in doc["results"]] == ["COULDN'T CHECK"]
        assert doc["results"][0]["fixed_in"] == "2026-02-23 (server-side)"

    def test_research_record_runs_the_plugin_checks(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import mcp_audit.cli.affected as cli  # noqa: PLC0415

        finding = Finding(
            id="PLUGIN-003",
            severity=Severity.CRITICAL,
            analyzer="plugins",
            client="claude-code-plugin",
            server="demo@market",
            title="Plugin checkout does not match its pin",
            description="d",
            evidence="e",
            remediation="r",
        )
        monkeypatch.setattr(cli, "_plugin_check_findings", lambda errors: [finding])
        result = _run(PLUGIN4SHELL)
        assert result.exit_code == 1 and "PLUGIN-003" in result.output

    def test_unknown_id_is_exit_2_with_the_live_hint(self) -> None:
        result = _run("CVE-2099-0001")
        assert result.exit_code == 2 and "--live" in result.output

    @pytest.mark.parametrize("arg", ["pkg@^1.2", "", "pkg@banana"])
    def test_bad_query_is_exit_2(self, arg: str) -> None:
        assert _run(arg).exit_code == 2

    def test_missing_path_and_lock_are_exit_2(self, tmp_path: Path) -> None:
        assert _run("CVE-2025-53109", "-p", str(tmp_path / "no.json")).exit_code == 2
        cfg = _config(tmp_path, {"x": _npx("pkg@1.0.0")})
        assert (
            _run(
                "CVE-2025-53109", "-p", str(cfg), "--lock", str(tmp_path / "n")
            ).exit_code
            == 2
        )

    def test_live_and_offline_conflict(self) -> None:
        result = _run("CVE-2099-0001", "--live", "--offline")
        assert result.exit_code == 2 and "--live" in result.output

    def test_output_needs_a_machine_format(self, tmp_path: Path) -> None:
        result = _run("litellm@<2", "-o", str(tmp_path / "x"))
        assert result.exit_code == 2

    def test_default_run_makes_no_network_call(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import socket  # noqa: PLC0415

        def boom(*a: Any, **k: Any) -> None:
            raise AssertionError("network used")

        monkeypatch.setattr(socket, "create_connection", boom)
        monkeypatch.setattr(socket.socket, "connect", boom)
        cfg = _config(tmp_path, {"filesystem": _npx(f"{FS}@2025.1.14")})
        assert _run("CVE-2025-53109", "-p", str(cfg)).exit_code == 1

    def test_live_fetches_an_unbundled_id(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import mcp_audit.vulnerability.osv as osv  # noqa: PLC0415

        osv_record = {
            "id": "GHSA-live-test-0001",
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": "somepkg"},
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "0"}, {"fixed": "2.0.0"}],
                        }
                    ],
                }
            ],
        }
        monkeypatch.setattr(
            osv,
            "fetch_vuln_details",
            lambda ids, **kw: ({"GHSA-live-test-0001": osv_record}, {}),
        )
        cfg = _config(tmp_path, {"s": {"command": "uvx", "args": ["somepkg==1.0.0"]}})
        result = _run("GHSA-live-test-0001", "-p", str(cfg), "--live")
        assert result.exit_code == 1 and "OSV.dev" in result.output

    def test_live_failure_is_exit_2(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import mcp_audit.vulnerability.osv as osv  # noqa: PLC0415

        monkeypatch.setattr(
            osv, "fetch_vuln_details", lambda ids, **kw: ({}, {ids[0]: "HTTP 404"})
        )
        result = _run("GHSA-live-test-0002", "--live")
        assert result.exit_code == 2 and "404" in result.output


# ── Review findings (PR #220) ──────────────────────────────────────────────────


class TestHostileInputs:
    def test_unparsable_config_is_a_couldnt_check_row_not_silence(
        self, tmp_path: Path
    ) -> None:
        cfg = _config(
            tmp_path,
            {
                "good": {"command": "uvx", "args": ["litellm==1.107.0"]},
                "bad": {"command": None, "args": "notalist"},
            },
        )
        result = _run("litellm@==1.107.0", "-p", str(cfg), "--fail-on-unknown")
        assert result.exit_code == 1
        assert "could not be parsed" in result.output

    def test_broken_json_config_trips_the_unknown_gate(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.json"
        bad.write_text("{nope", encoding="utf-8")
        result = _run("litellm@<2", "-p", str(bad), "--fail-on-unknown")
        assert result.exit_code == 1 and "COULDN'T CHECK" in result.output

    @pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX only")
    def test_a_fifo_lock_does_not_hang(self, tmp_path: Path) -> None:
        fifo = tmp_path / "mcp-lock.json"
        os.mkfifo(fifo)
        errors: list[str] = []
        assert m.read_lock_document(fifo, errors) is None
        assert errors and "not a regular file" in errors[0]

    @pytest.mark.skipif(not Path("/dev/zero").exists(), reason="POSIX only")
    def test_a_lock_that_is_a_symlink_to_dev_zero_is_refused(
        self, tmp_path: Path
    ) -> None:
        link = tmp_path / "mcp-lock.json"
        link.symlink_to("/dev/zero")
        errors: list[str] = []
        assert m.read_lock_document(link, errors) is None
        assert errors

    def test_oversized_lock_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(m, "MAX_LOCK_BYTES", 16)
        path = tmp_path / "mcp-lock.json"
        path.write_text(json.dumps({"servers": {"a": "x" * 100}}), encoding="utf-8")
        errors: list[str] = []
        assert m.read_lock_document(path, errors) is None
        assert "over" in errors[0]

    @pytest.mark.parametrize("raw", [b"\xff\xfe{", b"[]", b"[" * 100_000])
    def test_odd_lock_contents_are_reported_not_raised(
        self, tmp_path: Path, raw: bytes
    ) -> None:
        path = tmp_path / "mcp-lock.json"
        path.write_bytes(raw)
        errors: list[str] = []
        assert m.read_lock_document(path, errors) is None
        assert errors

    def test_a_control_character_version_in_a_lock_is_ignored(
        self, tmp_path: Path
    ) -> None:
        lock = _lock(tmp_path, "1.0.0\x1b[31m")
        locks = LockIndex([lock])
        assert m.server_version(_server(tmp_path), "npm", FS, locks) == (None, None)


class TestVersionEdges:
    def _rule(self, text: str) -> RangeRule:
        return RangeRule("pkg", SpecifierSet(text), f"pkg@{text}")

    @pytest.mark.parametrize("pre", ["2.0rc1", "2.0.0.dev1", "2.0a1"])
    def test_prereleases_of_the_bound_are_below_it(self, pre: str) -> None:
        assert self._rule("<2.0").decide(_plain(pre)).status is Status.AFFECTED
        assert self._rule("<=2.0").decide(_plain(pre)).status is Status.AFFECTED

    def test_wildcard_and_compatible_release_still_work(self) -> None:
        assert self._rule("==1.2.*").decide(_plain("1.2.7")).status is Status.AFFECTED
        assert self._rule("~=1.4").decide(_plain("1.9")).status is Status.AFFECTED
        assert self._rule("~=1.4").decide(_plain("2.0")).status is (Status.NOT_AFFECTED)

    def test_not_equal(self) -> None:
        assert self._rule("!=1.0").decide(_plain("1.1")).status is Status.AFFECTED

    def test_record_rule_orders_across_numbering_schemes_or_says_it_cannot(
        self,
    ) -> None:
        # fixed in a calendar version: a semantic pin cannot be ordered offline
        rec = _rec(versions=(), ranges=((("introduced", "0"), ("fixed", "2025.7.1")),))
        d = RecordRule(rec, False).decide(_plain("2.0.0"))
        assert d.status is Status.COULDNT_CHECK and d.reason == m.UNDECIDABLE
        # fixed in a semantic version: a calendar pin cannot be ordered either
        rec2 = _rec(versions=(), ranges=((("introduced", "0"), ("fixed", "1.5.0")),))
        assert RecordRule(rec2, False).decide(_plain("2025.8.1")).status is (
            Status.COULDNT_CHECK
        )

    def test_record_rule_same_scheme_still_decides(self) -> None:
        rec = _rec(versions=(), ranges=((("introduced", "0"), ("fixed", "2025.7.1")),))
        assert RecordRule(rec, False).decide(_plain("2025.1.1")).status is (
            Status.AFFECTED
        )
        assert RecordRule(rec, False).decide(_plain("2025.9.9")).status is (
            Status.NOT_AFFECTED
        )

    @pytest.mark.parametrize("text", ["x@===1.0", "x@<1,,", "x@,<1", "x@<1,"])
    def test_malformed_ranges_are_refused(self, text: str) -> None:
        with pytest.raises(QueryError):
            parse_query(text)


class TestLaunchForms:
    def _row(self, tmp_path: Path, command: str, args: list[str]) -> m.Row:
        from mcp_audit.registry.loader import load_registry  # noqa: PLC0415

        server = ServerConfig(
            name="s", client="c", config_path=tmp_path / "x", command=command, args=args
        )
        return m.decide_server(
            server,
            [RangeRule("litellm", SpecifierSet("==1.107.0"), "litellm@==1.107.0")],
            load_registry(offline=True),
            LockIndex(),
            "q",
        )

    @pytest.mark.parametrize(
        ("command", "args"),
        [
            ("uvx", ["--with", "litellm==1.107.0", "other-tool"]),
            ("uvx", ["--with=litellm==1.107.0", "other-tool"]),
            ("npx", ["-y", "-p", "litellm@1.107.0", "runner"]),
            ("npx", ["-y", "--package=litellm@1.107.0", "runner"]),
        ],
    )
    def test_extra_installed_packages_are_never_a_clean_bill(
        self, tmp_path: Path, command: str, args: list[str]
    ) -> None:
        row = self._row(tmp_path, command, args)
        assert row.status is Status.COULDNT_CHECK and row.reason == m.EXTRA_PACKAGES

    def test_a_server_flag_after_the_package_is_not_an_install_flag(
        self, tmp_path: Path
    ) -> None:
        row = self._row(tmp_path, "uvx", ["other-tool", "-p", "8080"])
        assert row.status is Status.NOT_AFFECTED

    def test_extras_in_a_pypi_pin_are_read(self, tmp_path: Path) -> None:
        row = self._row(tmp_path, "uvx", ["litellm[proxy]==1.107.0"])
        assert row.status is Status.AFFECTED and row.version == "1.107.0"

    def test_a_package_nobody_runs_gets_a_note(self, tmp_path: Path) -> None:
        cfg = _config(tmp_path, {"s": {"command": "uvx", "args": ["other==1.0"]}})
        result = _run("litlem@==1.0", "-p", str(cfg))
        assert result.exit_code == 0 and "No discovered server runs" in result.output


class TestDiscoveryWithoutPath:
    def test_servers_are_found_without_path(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        home = tmp_path / "home"
        (home / ".cursor").mkdir(parents=True)
        (home / ".cursor" / "mcp.json").write_text(
            json.dumps(
                {"mcpServers": {"gw": {"command": "uvx", "args": ["litellm==1.107.0"]}}}
            ),
            encoding="utf-8",
        )
        work = tmp_path / "work"
        work.mkdir()
        for var in ("HOME", "USERPROFILE"):
            monkeypatch.setenv(var, str(home))
        monkeypatch.chdir(work)
        result = _run("litellm@==1.107.0")
        assert result.exit_code == 1 and "cursor" in result.output.lower()


class TestNoNetworkByDefault:
    def test_nothing_resolves_or_opens_a_url(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import socket  # noqa: PLC0415
        import urllib.request  # noqa: PLC0415

        def boom(*a: Any, **k: Any) -> None:
            raise AssertionError("network used")

        for owner, name in (
            (socket, "getaddrinfo"),
            (socket, "create_connection"),
            (urllib.request, "urlopen"),
        ):
            monkeypatch.setattr(owner, name, boom)
        cfg = _config(tmp_path, {"filesystem": _npx(f"{FS}@2025.1.14")})
        for q in ("CVE-2025-53109", "litellm@<2", PLUGIN4SHELL):
            _run(q, "-p", str(cfg))
