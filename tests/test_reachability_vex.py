"""STORY-0125: transport reachability tags and OpenVEX output."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from mcp_audit.affected import vex
from mcp_audit.affected.match import (
    NOT_REACHABLE,
    VERSION_OUTSIDE,
    VERSION_UNKNOWN,
    Launch,
    RegistryRule,
    Row,
    Status,
)
from mcp_audit.analyzers.supply_chain import _emit_known_cve_findings
from mcp_audit.cli import app
from mcp_audit.models import ServerConfig, TransportType
from mcp_audit.registry import reachability as r
from mcp_audit.registry.loader import RegistryEntry, load_registry

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))
import audit_registry  # noqa: E402

runner = CliRunner()
CVE = "CVE-2026-77244"
VERIFIED = "Claude run, OSV.dev record text, 2026-10-29"


def _tag(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "cve": CVE,
        "fixed_in": "0.22.0",
        "affected_transports": ["http"],
        "verified_by": VERIFIED,
    }
    base.update(over)
    return base


def _server(*args: str, **over: Any) -> ServerConfig:
    base: dict[str, Any] = {
        "name": "atlassian",
        "client": "custom",
        "config_path": Path("mcp.json"),
        "transport": TransportType.STDIO,
        "command": "uvx",
        "args": ["mcp-atlassian", *args],
    }
    base.update(over)
    return ServerConfig(**base)


def _entry(*vulns: dict[str, Any]) -> RegistryEntry:
    return RegistryEntry(
        name="mcp-atlassian",
        source="pip",
        repo=None,
        maintainer="x",
        verified=True,
        last_verified="2026-01-01",
        known_versions=[],
        tags=[],
        known_vulns=list(vulns),
    )


class TestTags:
    def test_valid_tag(self) -> None:
        tags = r.tags_of(_tag(requires_auth=False))
        assert tags is not None
        assert tags.transports == {"http"}
        assert tags.requires_auth is False
        assert tags.verified_by == VERIFIED

    def test_untagged_record_has_no_tag(self) -> None:
        assert r.tags_of({"cve": CVE}) is None
        assert r.tag_problems({"cve": CVE}) == []

    @pytest.mark.parametrize(
        "over",
        [
            {"verified_by": ""},
            {"verified_by": None},
            {"affected_transports": []},
            {"affected_transports": ["websocket"]},
            {"affected_transports": "http"},
            {"requires_auth": "no"},
        ],
    )
    def test_invalid_tag_is_ignored_and_reported(self, over: dict) -> None:
        record = _tag(**over)
        assert r.tags_of(record) is None
        assert r.tag_problems(record)

    def test_requires_auth_without_transports_is_reported(self) -> None:
        assert r.tag_problems({"cve": CVE, "requires_auth": False})

    def test_excludes_stdio_only_when_stdio_is_absent(self) -> None:
        assert r.excludes_stdio(_tag()) is not None
        assert r.excludes_stdio(_tag(affected_transports=["stdio", "http"])) is None


class TestProvablyStdio:
    def test_plain_stdio_launch(self) -> None:
        assert r.provably_stdio(_server())

    @pytest.mark.parametrize(
        "args",
        [
            ("--transport", "streamable-http"),
            ("--transport=sse",),
            ("-t", "sse"),
            ("--port", "9000"),
            ("--host=0.0.0.0",),
            ("sse",),
            ("--streamable-http",),
        ],
    )
    def test_transport_arguments_defeat_the_proof(self, args: tuple) -> None:
        assert not r.provably_stdio(_server(*args))

    @pytest.mark.parametrize("name", ["TRANSPORT", "MCP_PORT", "SERVER_HOST"])
    def test_transport_env_defeats_the_proof(self, name: str) -> None:
        assert not r.provably_stdio(_server(env={name: "x"}))

    def test_remote_and_unknown_are_never_stdio(self) -> None:
        assert not r.provably_stdio(_server(url="https://x.example/mcp"))
        assert not r.provably_stdio(_server(transport=TransportType.UNKNOWN))
        assert not r.provably_stdio(_server(command=None))
        assert not r.provably_stdio(_server(transport=TransportType.SSE))

    def test_not_reachable_needs_tag_and_stdio(self) -> None:
        assert r.not_reachable(_tag(), _server()) is not None
        assert r.not_reachable(_tag(), _server("--transport", "sse")) is None
        assert r.not_reachable({"cve": CVE}, _server()) is None


class TestRegistryRule:
    def _rule(self, *, tagged: bool = True) -> RegistryRule:
        return RegistryRule(
            "mcp-atlassian",
            CVE,
            "0.22.0",
            r.excludes_stdio(_tag()) if tagged else None,
        )

    def _launch(self, *, stdio: bool, version: str | None = "0.21.0") -> Launch:
        return Launch("pypi", "mcp-atlassian", version, "config pin", None, stdio)

    def test_stdio_below_fix_is_not_affected(self) -> None:
        d = self._rule().decide(self._launch(stdio=True))
        assert d.status is Status.NOT_AFFECTED
        assert d.reason == NOT_REACHABLE
        assert VERIFIED in d.evidence

    def test_stdio_with_no_version_is_still_cleared(self) -> None:
        d = self._rule().decide(self._launch(stdio=True, version=None))
        assert d.reason == NOT_REACHABLE

    def test_non_stdio_below_fix_is_affected(self) -> None:
        d = self._rule().decide(self._launch(stdio=False))
        assert d.status is Status.AFFECTED

    def test_untagged_advisory_is_never_downgraded(self) -> None:
        d = self._rule(tagged=False).decide(self._launch(stdio=True))
        assert d.status is Status.AFFECTED


class TestSc004:
    def test_stdio_server_gets_no_finding_for_http_only_cve(self) -> None:
        assert _emit_known_cve_findings(_server(), _entry(_tag())) == []

    def test_http_server_keeps_the_finding(self) -> None:
        found = _emit_known_cve_findings(
            _server("--transport", "streamable-http"), _entry(_tag())
        )
        assert len(found) == 1
        assert CVE in found[0].description

    def test_untagged_cve_stays_and_cleared_one_is_named(self) -> None:
        other = {"cve": "CVE-2026-1", "fixed_in": "0.5.0"}
        found = _emit_known_cve_findings(_server(), _entry(_tag(), other))
        assert len(found) == 1
        assert "CVE-2026-1" in found[0].description
        assert f"Not counted: {CVE}" in found[0].description

    def test_flat_list_entry_does_not_resurrect_a_cleared_cve(self) -> None:
        entry = _entry(_tag())
        entry.known_vulnerabilities = [CVE]
        assert _emit_known_cve_findings(_server(), entry) == []


def _row(status: Status, reason: str | None, **over: Any) -> Row:
    base: dict[str, Any] = {
        "subject": "custom/a",
        "status": status,
        "evidence": "why",
        "config_path": "/home/me/.mcp.json",
        "package": "pypi:mcp-atlassian",
        "version": "0.21.0",
        "fixed_in": "0.22.0",
        "reason": reason,
    }
    base.update(over)
    return Row(**base)


class TestVexStatements:
    def test_purls(self) -> None:
        assert vex.purl("npm:@scope/pkg", "1.2.3") == "pkg:npm/%40scope/pkg@1.2.3"
        assert vex.purl("pypi:Foo_Bar", None) == "pkg:pypi/foo-bar"
        assert vex.purl("cargo:x", "1") is None

    def test_affected_carries_the_fix(self) -> None:
        s = vex.statement(CVE, _row(Status.AFFECTED, None))
        assert s is not None
        assert s["status"] == "affected"
        assert "0.22.0" in s["action_statement"]
        assert s["products"] == [{"@id": "pkg:pypi/mcp-atlassian@0.21.0"}]

    def test_affected_without_a_fix_still_has_an_action(self) -> None:
        s = vex.statement(CVE, _row(Status.AFFECTED, None, fixed_in=None))
        assert s is not None
        assert s["action_statement"]

    def test_not_reachable_is_not_affected_with_justification(self) -> None:
        s = vex.statement(CVE, _row(Status.NOT_AFFECTED, NOT_REACHABLE))
        assert s is not None
        assert s["status"] == "not_affected"
        assert s["justification"] == "vulnerable_code_not_in_execute_path"

    def test_version_outside_is_fixed(self) -> None:
        s = vex.statement(CVE, _row(Status.NOT_AFFECTED, VERSION_OUTSIDE))
        assert s is not None
        assert s["status"] == "fixed"

    def test_unknown_version_is_under_investigation(self) -> None:
        s = vex.statement(
            CVE, _row(Status.COULDNT_CHECK, VERSION_UNKNOWN, version=None)
        )
        assert s is not None
        assert s["status"] == "under_investigation"
        assert s["products"] == [{"@id": "pkg:pypi/mcp-atlassian"}]

    def test_other_package_and_no_package_say_nothing(self) -> None:
        assert vex.statement(CVE, _row(Status.NOT_AFFECTED, "other-package")) is None
        assert (
            vex.statement(CVE, _row(Status.COULDNT_CHECK, "no-package", package=None))
            is None
        )

    def test_nothing_local_leaks(self) -> None:
        doc = vex.render(vex.build([(CVE, _row(Status.AFFECTED, None))]))
        assert "/home/me" not in doc
        assert "custom/a" not in doc


class TestVexDocument:
    def test_shape_and_determinism(self) -> None:
        from datetime import UTC, datetime

        stamp = datetime(2026, 10, 29, 12, 0, 0, 5, tzinfo=UTC)
        pairs = [(CVE, _row(Status.AFFECTED, None))]
        a = vex.build(pairs, timestamp=stamp)
        b = vex.build(pairs, timestamp=stamp)
        assert a == b
        assert a["@context"] == "https://openvex.dev/ns/v0.2.0"
        assert a["@id"].startswith("urn:uuid:")
        assert a["timestamp"] == "2026-10-29T12:00:00Z"
        assert a["version"] == 1

    def test_most_cautious_status_wins_per_product(self) -> None:
        pairs = [
            (CVE, _row(Status.NOT_AFFECTED, NOT_REACHABLE)),
            (CVE, _row(Status.AFFECTED, None)),
            (CVE, _row(Status.AFFECTED, None, subject="custom/b")),
        ]
        doc = vex.build(pairs)
        assert [s["status"] for s in doc["statements"]] == ["affected"]


def _config(tmp_path: Path, servers: dict) -> Path:
    path = tmp_path / ".mcp.json"
    path.write_text(json.dumps({"mcpServers": servers}), encoding="utf-8")
    return path


ATLASSIAN = {"command": "uvx", "args": ["mcp-atlassian==0.21.0"]}
ATLASSIAN_HTTP = {
    "command": "uvx",
    "args": ["mcp-atlassian==0.21.0", "--transport", "streamable-http"],
}


class TestCli:
    def test_affected_openvex(self, tmp_path: Path) -> None:
        cfg = _config(tmp_path, {"a": ATLASSIAN})
        res = runner.invoke(app, ["affected", CVE, "--path", str(cfg), "-f", "openvex"])
        assert res.exit_code == 0, res.output
        doc = json.loads(res.output)
        assert doc["statements"][0]["status"] == "not_affected"

    def test_affected_terminal_shows_the_clearance(self, tmp_path: Path) -> None:
        cfg = _config(tmp_path, {"a": ATLASSIAN, "b": ATLASSIAN_HTTP})
        res = runner.invoke(app, ["affected", CVE, "--path", str(cfg)])
        assert res.exit_code == 1
        assert "AFFECTED (1)" in res.output
        assert "NOT AFFECTED" in res.output
        assert "stdio" in res.output

    def test_openvex_refuses_a_range(self, tmp_path: Path) -> None:
        cfg = _config(tmp_path, {"a": ATLASSIAN})
        res = runner.invoke(
            app,
            ["affected", "mcp-atlassian@<0.22.0", "--path", str(cfg), "-f", "openvex"],
        )
        assert res.exit_code == 2

    def test_openvex_with_nothing_to_state_is_an_error(self, tmp_path: Path) -> None:
        cfg = _config(tmp_path, {"x": {"command": "npx", "args": ["-y", "left-pad"]}})
        res = runner.invoke(app, ["affected", CVE, "--path", str(cfg), "-f", "openvex"])
        assert res.exit_code == 2

    def test_openvex_output_file(self, tmp_path: Path) -> None:
        cfg = _config(tmp_path, {"a": ATLASSIAN_HTTP})
        out = tmp_path / "x" / "v.json"
        res = runner.invoke(
            app,
            ["affected", CVE, "--path", str(cfg), "-f", "openvex", "-o", str(out)],
        )
        assert res.exit_code == 1
        assert json.loads(out.read_text())["statements"][0]["status"] == "affected"

    def test_scan_vex_writes_a_document(self, tmp_path: Path) -> None:
        cfg = _config(tmp_path, {"a": ATLASSIAN, "b": ATLASSIAN_HTTP})
        out = tmp_path / "scan.vex.json"
        runner.invoke(
            app,
            ["scan", "--path", str(cfg), "--offline", "--vex", str(out)],
        )
        doc = json.loads(out.read_text())
        by = {(s["vulnerability"]["name"], s["status"]) for s in doc["statements"]}
        assert (CVE, "affected") in by
        assert all(
            s["products"][0]["@id"].startswith("pkg:pypi/mcp-atlassian")
            for s in doc["statements"]
        )


class TestShippedRegistry:
    def test_every_tag_is_valid(self) -> None:
        entries = json.loads(
            (REPO / "registry" / "known-servers.json").read_text(encoding="utf-8")
        )["entries"]
        assert audit_registry.find_bad_reachability_tags(entries) == []

    def test_tagged_count_is_published(self) -> None:
        entries = json.loads(
            (REPO / "registry" / "known-servers.json").read_text(encoding="utf-8")
        )["entries"]
        assert audit_registry.count_tagged_advisories(entries) == 6

    def test_registry_loads_with_tagged_records(self) -> None:
        reg = load_registry()
        entry = next(e for e in reg.entries if e.name == "mcp-atlassian")
        assert any(r.tags_of(v) for v in entry.known_vulns)


class TestAuditCheck:
    def test_flags_unusable_tags(self) -> None:
        hits = audit_registry.find_bad_reachability_tags(
            [
                {"name": "p", "known_vulns": [_tag(verified_by=""), {"cve": "X"}]},
            ]
        )
        assert [h["cve"] for h in hits] == [CVE]
