"""Tests for the AdvisoryFormatter output formatter.

The formatter is the single-document face of the advisory subsystem. Its records must
be identical to the ones a published feed contains, or a consumer reading
``--format`` output and a consumer reading ``feed/osv/all.json`` would disagree about
the same vulnerability.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_audit.advisory.feed import build_advisories, write_feed
from mcp_audit.advisory.validate import validate_osv
from mcp_audit.models import Finding, ScanResult, ServerConfig, Severity
from mcp_audit.output.advisory import AdvisoryFormatter
from mcp_audit.output.base import BaseFormatter

FIXED_NOW = "2026-01-31T00:00:00Z"


def _finding(
    finding_id: str = "CRED-001",
    severity: Severity = Severity.CRITICAL,
    server: str = "github",
    **overrides,
) -> Finding:
    kwargs = {
        "id": finding_id,
        "severity": severity,
        "analyzer": "credentials",
        "client": "claude-desktop",
        "server": server,
        "title": "GitHub credential in environment",
        "description": "GitHub Token found in env var 'GITHUB_TOKEN'",
        "evidence": "env.GITHUB_TOKEN matches GitHub Token pattern",
        "remediation": "Use a credential manager or vault.",
        "cwe": "CWE-798",
        "owasp_mcp_top_10": ["MCP01"],
    }
    kwargs.update(overrides)
    return Finding(**kwargs)


def _result() -> ScanResult:
    servers = [
        ServerConfig(
            name="github",
            client="claude-desktop",
            command="npx",
            args=["-y", "mcp-audit-fixture-github-server@1.0.0"],
            config_path=Path("claude.json"),
        ),
        ServerConfig(
            name="local",
            client="claude-desktop",
            command="node",
            args=["./local-server.js"],
            config_path=Path("claude.json"),
        ),
    ]
    findings = [
        _finding(),
        _finding(
            finding_id="COMM-010",
            severity=Severity.LOW,
            analyzer="rules",
            title="npx used without pinned version",
            description="Unpinned npx invocation.",
            owasp_mcp_top_10=["MCP04"],
        ),
        # Runs from a local path, so it has no published package coordinate.
        _finding(server="local"),
    ]
    return ScanResult(servers=servers, findings=findings, servers_found=len(servers))


class TestAdvisoryFormatter:
    def test_is_a_base_formatter(self) -> None:
        assert issubclass(AdvisoryFormatter, BaseFormatter)
        assert isinstance(AdvisoryFormatter(now=FIXED_NOW), BaseFormatter)

    def test_emits_a_json_array_of_osv_records(self) -> None:
        records = json.loads(AdvisoryFormatter(now=FIXED_NOW).format(_result()))
        assert isinstance(records, list)
        assert records, "expected at least one advisory"
        for record in records:
            assert record["schema_version"] == "1.6.0"
            validate_osv(record)

    def test_records_are_ordered_by_advisory_id(self) -> None:
        records = json.loads(AdvisoryFormatter(now=FIXED_NOW).format(_result()))
        ids = [r["id"] for r in records]
        assert ids == sorted(ids)

    def test_servers_without_a_published_package_are_omitted(self) -> None:
        records = json.loads(AdvisoryFormatter(now=FIXED_NOW).format(_result()))
        names = {r["affected"][0]["package"]["name"] for r in records}
        assert names == {"mcp-audit-fixture-github-server"}

    def test_owasp_codes_are_the_bare_repo_wide_form(self) -> None:
        records = json.loads(AdvisoryFormatter(now=FIXED_NOW).format(_result()))
        codes = {
            code
            for record in records
            for code in record["affected"][0]["database_specific"]["owasp_mcp"]
        }
        assert codes, "expected mapped OWASP codes"
        assert all(":" not in code for code in codes), codes

    def test_severity_filter_is_applied(self) -> None:
        formatter = AdvisoryFormatter(now=FIXED_NOW, min_severity=Severity.HIGH)
        records = json.loads(formatter.format(_result()))
        rules = {
            r["affected"][0]["database_specific"]["mcp_audit_rule_id"] for r in records
        }
        assert "COMM-010" not in rules

    def test_output_matches_the_feeds_all_json_byte_for_byte(
        self, tmp_path: Path
    ) -> None:
        """A record must not depend on which door a consumer came in through."""
        result = _result()
        manifest = write_feed(
            build_advisories(result, now=FIXED_NOW).advisories, tmp_path / "feed"
        )
        from_feed = manifest.osv_json_path.read_text(encoding="utf-8")
        from_formatter = AdvisoryFormatter(now=FIXED_NOW).format(result)
        assert from_formatter == from_feed.rstrip("\n")

    def test_is_deterministic_for_a_fixed_timestamp(self) -> None:
        result = _result()
        first = AdvisoryFormatter(now=FIXED_NOW).format(result)
        second = AdvisoryFormatter(now=FIXED_NOW).format(result)
        assert first == second

    def test_compact_output_is_available(self) -> None:
        compact = AdvisoryFormatter(now=FIXED_NOW, indent=None).format(_result())
        assert "\n" not in compact
        assert json.loads(compact)

    def test_empty_scan_yields_an_empty_array(self) -> None:
        empty = ScanResult(servers=[], findings=[], servers_found=0)
        assert json.loads(AdvisoryFormatter(now=FIXED_NOW).format(empty)) == []

    def test_now_is_required_rather_than_defaulted_to_the_clock(self) -> None:
        """Wall-clock defaults would silently break feed reproducibility."""
        with pytest.raises(TypeError):
            AdvisoryFormatter()  # type: ignore[call-arg]
