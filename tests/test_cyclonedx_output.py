"""Tests for the CycloneDX 1.5 SBOM formatter.

The formatter supports cyclonedx-python-lib 7.x AND 8.x-11.x — the two
major-version families differ in where ``Tool`` lives and in how
``Bom.metadata.tools`` exposes its underlying set. These tests therefore
assert shape-level invariants that hold across both APIs rather than
pinning to one major version.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_audit.models import Finding, ScanResult, ServerConfig, Severity

# The formatter module must import cleanly even when cyclonedx is absent.
# This line is the regression guard for the v8 breakage we saw in PR #5:
# a stray module-level reference to VulnerabilitySeverity caused NameError
# at import time on any cyclonedx version that moved ``Tool`` out of
# ``cyclonedx.model``.
from mcp_audit.output.cyclonedx import (  # noqa: E402
    _CYCLONEDX_AVAILABLE,
    CycloneDxFormatter,
)


def _make_server(name: str = "filesystem-server") -> ServerConfig:
    return ServerConfig(
        name=name,
        client="cursor",
        config_path=Path("/dev/null"),
        command="node",
        args=["server.js"],
    )


def _make_finding(
    *,
    finding_id: str = "VULN-CVE-2024-0001",
    severity: Severity = Severity.HIGH,
    description: str = "Known vulnerability in transitive dep.",
) -> Finding:
    return Finding(
        id=finding_id,
        severity=severity,
        analyzer="vulnerability",
        client="cursor",
        server="filesystem-server",
        title="Vulnerable dependency",
        description=description,
        evidence="pkg@1.2.3",
        remediation="Upgrade to >=1.2.4.",
    )


def _make_result(
    *,
    servers: list[ServerConfig] | None = None,
    findings: list[Finding] | None = None,
) -> ScanResult:
    return ScanResult(
        clients_scanned=1,
        servers_found=len(servers or []),
        servers=servers or [],
        findings=findings or [],
    )


class TestModuleImportWithoutExtra:
    """Guards against the v8 regression: the module must import cleanly
    even if ``cyclonedx-python-lib`` is not installed."""

    def test_module_imports_and_exposes_formatter(self) -> None:
        assert CycloneDxFormatter is not None
        assert isinstance(_CYCLONEDX_AVAILABLE, bool)

    def test_format_raises_helpful_error_when_extra_missing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("mcp_audit.output.cyclonedx._CYCLONEDX_AVAILABLE", False)
        with pytest.raises(ImportError, match=r"\[sbom\]"):
            CycloneDxFormatter().format(_make_result())


# Every test below requires the optional [sbom] extra.
pytestmark_sbom = pytest.mark.skipif(
    not _CYCLONEDX_AVAILABLE,
    reason="cyclonedx-python-lib not installed; install mcp-audit-scanner[sbom]",
)


@pytestmark_sbom
class TestFormatterOutput:
    def test_produces_valid_json_with_required_top_level_keys(self) -> None:
        output = CycloneDxFormatter().format(_make_result())
        doc = json.loads(output)

        assert doc["bomFormat"] == "CycloneDX"
        assert doc["specVersion"] == "1.5"
        assert doc["serialNumber"].startswith("urn:uuid:")
        assert "metadata" in doc
        assert "timestamp" in doc["metadata"]

    def test_records_mcp_audit_as_tool_in_metadata(self) -> None:
        # Regression: in v7 ``metadata.tools`` is a SortedSet that supports
        # ``.add()``; in v8+ it is a ``ToolRepository`` and the set lives at
        # ``.tools``. This assertion is version-agnostic — it works against
        # the serialised JSON, which normalises across both APIs.
        doc = json.loads(CycloneDxFormatter().format(_make_result()))
        tools = doc["metadata"]["tools"]
        # v7 emits a list of tools; v8+ emits an object with a "tools" list
        # depending on the schema variant. Normalise before asserting.
        tool_list = tools if isinstance(tools, list) else tools.get("tools", [])
        names = [t.get("name") for t in tool_list]
        assert "mcp-audit" in names

    def test_emits_one_component_per_server(self) -> None:
        servers = [_make_server("alpha"), _make_server("beta")]
        doc = json.loads(CycloneDxFormatter().format(_make_result(servers=servers)))
        component_names = {c["name"] for c in doc.get("components", [])}
        assert {"alpha", "beta"} <= component_names

    def test_vuln_findings_become_vulnerability_entries(self) -> None:
        findings = [
            _make_finding(finding_id="VULN-CVE-2024-0001", severity=Severity.HIGH),
            _make_finding(finding_id="VULN-CVE-2024-0002", severity=Severity.CRITICAL),
        ]
        doc = json.loads(CycloneDxFormatter().format(_make_result(findings=findings)))
        vuln_ids = {v["id"] for v in doc.get("vulnerabilities", [])}
        assert {"CVE-2024-0001", "CVE-2024-0002"} <= vuln_ids

    def test_non_vuln_findings_are_skipped(self) -> None:
        findings = [
            _make_finding(finding_id="POISON-001"),
            _make_finding(finding_id="CRED-002"),
            _make_finding(finding_id="VULN-UNPINNED"),  # explicit exclusion
            _make_finding(finding_id="VULN-CVE-2024-9999"),
        ]
        doc = json.loads(CycloneDxFormatter().format(_make_result(findings=findings)))
        vuln_ids = {v["id"] for v in doc.get("vulnerabilities", [])}
        assert vuln_ids == {"CVE-2024-9999"}

    def test_severity_mapping_preserves_level(self) -> None:
        findings = [
            _make_finding(finding_id="VULN-X-HIGH", severity=Severity.HIGH),
            _make_finding(finding_id="VULN-X-LOW", severity=Severity.LOW),
        ]
        doc = json.loads(CycloneDxFormatter().format(_make_result(findings=findings)))
        by_id = {v["id"]: v for v in doc["vulnerabilities"]}
        # CycloneDX stores severity under ratings[*].severity — case is
        # lowercased by the library. Compare case-insensitively so this
        # test survives future schema cosmetic tweaks.
        assert by_id["X-HIGH"]["ratings"][0]["severity"].lower() == "high"
        assert by_id["X-LOW"]["ratings"][0]["severity"].lower() == "low"

    def test_osv_source_url_embeds_finding_id(self) -> None:
        findings = [_make_finding(finding_id="VULN-CVE-2025-0001")]
        doc = json.loads(CycloneDxFormatter().format(_make_result(findings=findings)))
        vuln = doc["vulnerabilities"][0]
        assert vuln["source"]["name"] == "OSV"
        assert "CVE-2025-0001" in vuln["source"]["url"]
