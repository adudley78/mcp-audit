"""Tests for output/cyclonedx.py — CycloneDX 1.5 SBOM formatter.

Covers:
- format() with servers only (no findings)
- format() with VULN-* findings of all severities
- format() with non-VULN findings (standard security IDs) → not in vulnerabilities
- format() with VULN-UNPINNED → explicitly excluded
- format() with a ScanScore attached → formats without error
- ImportError path when cyclonedx is not installed
- specVersion is 1.5
- bomFormat is "CycloneDX"
"""

from __future__ import annotations

import importlib
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from mcp_audit.models import (
    Finding,
    ScanResult,
    ScanScore,
    ServerConfig,
    Severity,
    TransportType,
)

# ── Helpers ───────────────────────────────────────────────────────────────────

_CYCLONEDX_AVAILABLE = importlib.util.find_spec("cyclonedx") is not None

skip_no_cyclonedx = pytest.mark.skipif(
    not _CYCLONEDX_AVAILABLE,
    reason="cyclonedx-python-lib not installed",
)


def _server(name: str = "filesystem", client: str = "claude-desktop") -> ServerConfig:
    return ServerConfig(
        name=name,
        client=client,
        command="npx",
        args=["-y", f"@mcp/{name}", "/data"],
        env={},
        config_path=Path("/fake/mcp.json"),
        transport=TransportType.STDIO,
        raw={},
    )


def _finding(
    finding_id: str = "TEST-001",
    severity: Severity = Severity.MEDIUM,
) -> Finding:
    return Finding(
        id=finding_id,
        severity=severity,
        analyzer="test",
        client="claude-desktop",
        server="filesystem",
        title="Test finding",
        description="A test description.",
        evidence="some evidence",
        remediation="Fix it.",
    )


def _vuln_finding(
    vuln_id: str = "CVE-2024-1234",
    severity: Severity = Severity.HIGH,
) -> Finding:
    return Finding(
        id=f"VULN-{vuln_id}",
        severity=severity,
        analyzer="vulnerability",
        client="claude-desktop",
        server="filesystem",
        title=f"Vulnerability {vuln_id}",
        description=f"A known vulnerability: {vuln_id}.",
        evidence="deps.dev",
        remediation="Update the package.",
    )


def _result(
    servers: list[ServerConfig] | None = None,
    findings: list[Finding] | None = None,
    score: ScanScore | None = None,
) -> ScanResult:
    r = ScanResult(
        servers=servers or [],
        findings=findings or [],
        clients_scanned=1,
        configs_found=len(servers or []),
    )
    r.score = score
    return r


# ── Unit tests ────────────────────────────────────────────────────────────────


class TestCycloneDxFormatterImportError:
    def test_raises_import_error_when_library_missing(self) -> None:
        from mcp_audit.output.cyclonedx import CycloneDxFormatter

        with (
            patch("mcp_audit.output.cyclonedx._CYCLONEDX_AVAILABLE", False),
            pytest.raises(ImportError, match="sbom"),
        ):
            CycloneDxFormatter().format(_result())


@skip_no_cyclonedx
class TestCycloneDxFormatterWithLibrary:
    def _format(self, result: ScanResult) -> dict:
        from mcp_audit.output.cyclonedx import CycloneDxFormatter

        raw = CycloneDxFormatter().format(result)
        return json.loads(raw)

    def test_empty_scan_result_produces_valid_bom_structure(self) -> None:
        """Even with no servers/findings the BOM envelope fields are always present."""
        data = self._format(_result())
        assert data["bomFormat"] == "CycloneDX"
        assert data["specVersion"] == "1.5"
        assert "serialNumber" in data

    def test_spec_version_is_1_5(self) -> None:
        data = self._format(_result())
        assert data["specVersion"] == "1.5"

    def test_bom_format_field(self) -> None:
        data = self._format(_result())
        assert data["bomFormat"] == "CycloneDX"

    def test_serial_number_present(self) -> None:
        data = self._format(_result())
        assert "serialNumber" in data

    def test_two_servers_produce_two_components(self) -> None:
        servers = [_server("alpha"), _server("beta")]
        data = self._format(_result(servers=servers))
        assert "components" in data
        component_names = {c["name"] for c in data["components"]}
        assert "alpha" in component_names
        assert "beta" in component_names

    def test_no_findings_produces_no_vulnerabilities_block(self) -> None:
        """With no VULN-* findings the library omits the vulnerabilities key."""
        data = self._format(_result(servers=[_server()]))
        # cyclonedx-python-lib omits the key when the set is empty
        vulns = data.get("vulnerabilities", [])
        assert vulns == []

    def test_non_vuln_finding_not_in_vulnerabilities(self) -> None:
        """Standard security findings (CRED-001, etc.) are not included."""
        findings = [
            _finding("CRED-001", Severity.HIGH),
            _finding("POISON-001", Severity.CRITICAL),
        ]
        data = self._format(_result(servers=[_server()], findings=findings))
        vulns = data.get("vulnerabilities", [])
        assert vulns == []

    def test_vuln_finding_added_to_vulnerabilities(self) -> None:
        findings = [_vuln_finding("CVE-2024-1234", Severity.HIGH)]
        data = self._format(_result(servers=[_server()], findings=findings))
        assert "vulnerabilities" in data
        assert len(data["vulnerabilities"]) == 1
        vuln = data["vulnerabilities"][0]
        assert vuln["id"] == "CVE-2024-1234"

    def test_vuln_unpinned_excluded(self) -> None:
        """VULN-UNPINNED is explicitly excluded from the vulnerabilities block."""
        findings = [
            Finding(
                id="VULN-UNPINNED",
                severity=Severity.MEDIUM,
                analyzer="vulnerability",
                client="claude-desktop",
                server="fs",
                title="Unpinned dependency",
                description="Not pinned.",
                evidence="none",
                remediation="Pin it.",
            )
        ]
        data = self._format(_result(servers=[_server()], findings=findings))
        vulns = data.get("vulnerabilities", [])
        assert vulns == []

    def test_all_four_severities_map_correctly(self) -> None:
        """CRITICAL, HIGH, MEDIUM, LOW all map to CycloneDX severity strings."""
        findings = [
            _vuln_finding("CVE-CRIT-001", Severity.CRITICAL),
            _vuln_finding("CVE-HIGH-001", Severity.HIGH),
            _vuln_finding("CVE-MED-001", Severity.MEDIUM),
            _vuln_finding("CVE-LOW-001", Severity.LOW),
        ]
        data = self._format(_result(servers=[_server()], findings=findings))
        assert len(data["vulnerabilities"]) == 4

        severity_values = {
            v["id"]: v["ratings"][0]["severity"] for v in data["vulnerabilities"]
        }
        assert severity_values["CVE-CRIT-001"] == "critical"
        assert severity_values["CVE-HIGH-001"] == "high"
        assert severity_values["CVE-MED-001"] == "medium"
        assert severity_values["CVE-LOW-001"] == "low"

    def test_vuln_has_osv_source(self) -> None:
        findings = [_vuln_finding("CVE-2025-9999", Severity.CRITICAL)]
        data = self._format(_result(servers=[_server()], findings=findings))
        vuln = data["vulnerabilities"][0]
        assert vuln["source"]["name"] == "OSV"
        assert "osv.dev" in vuln["source"]["url"]

    def test_result_with_score_formats_without_error(self) -> None:
        """A ScanScore attached to the result should not break formatting."""
        score = ScanScore(
            numeric_score=85,
            grade="B",
            positive_signals=["No critical findings"],
            deductions=[],
        )
        data = self._format(_result(servers=[_server()], score=score))
        assert data["bomFormat"] == "CycloneDX"

    def test_tool_vendor_present_in_metadata(self) -> None:
        """mcp-audit appears in BOM metadata tools (any version of the lib)."""
        data = self._format(_result(servers=[_server()]))
        tools_section = data.get("metadata", {}).get("tools", {})
        raw = json.dumps(tools_section)
        assert "mcp-audit" in raw

    def test_multiple_vuln_findings_all_included(self) -> None:
        findings = [_vuln_finding(f"CVE-2024-{i:04d}", Severity.HIGH) for i in range(5)]
        data = self._format(_result(servers=[_server()], findings=findings))
        assert len(data["vulnerabilities"]) == 5

    def test_vuln_description_preserved(self) -> None:
        finding = _vuln_finding("CVE-2024-ABCD", Severity.MEDIUM)
        data = self._format(_result(servers=[_server()], findings=[finding]))
        vuln = data["vulnerabilities"][0]
        assert "CVE-2024-ABCD" in vuln.get("description", "")
