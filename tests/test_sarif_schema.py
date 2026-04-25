"""Validate SARIF output against the official SARIF 2.1.0 JSON schema.

This test catches any format regressions that would cause GitHub's code-scanning
API to reject the uploaded file. It is the closest automated equivalent of
an actual upload test without requiring a live GitHub repo.
"""

from __future__ import annotations

import json
import urllib.request
from pathlib import Path

import pytest

from mcp_audit.models import Finding, ScanResult, Severity
from mcp_audit.output.sarif import format_sarif

# The official SARIF 2.1.0 JSON schema from OASIS.
_SARIF_SCHEMA_URL = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main"
    "/sarif-2.1/schema/sarif-schema-2.1.0.json"
)

# Cached locally so tests run offline after the first fetch.
_SCHEMA_CACHE = Path(__file__).parent / "fixtures" / "sarif-schema-2.1.0.json"


def _get_schema() -> dict:
    """Return the SARIF schema, fetching and caching it if needed."""
    if _SCHEMA_CACHE.exists():
        return json.loads(_SCHEMA_CACHE.read_text())
    try:
        with urllib.request.urlopen(_SARIF_SCHEMA_URL, timeout=10) as resp:  # noqa: S310
            schema = json.loads(resp.read())
        _SCHEMA_CACHE.parent.mkdir(parents=True, exist_ok=True)
        _SCHEMA_CACHE.write_text(json.dumps(schema, indent=2))
        return schema
    except Exception:
        pytest.skip("SARIF schema not available (network or cache missing)")


def _make_result(findings: list[Finding] | None = None) -> ScanResult:
    """Build a minimal ScanResult for SARIF formatting."""
    from mcp_audit.models import MachineInfo, ScanScore  # noqa: PLC0415

    return ScanResult(
        servers=[],
        findings=findings or [],
        clients_scanned=1,
        machine=MachineInfo(
            hostname="test-host",
            username="test-user",
            os="Linux",
            os_version="6.1",
            scan_id="00000000-0000-0000-0000-000000000001",
        ),
        score=ScanScore(
            numeric_score=72,
            grade="B",
            positive_signals=["No poisoning found"],
            deductions=["1 credential finding"],
        ),
    )


def _validate(sarif_str: str) -> None:
    """Validate a SARIF JSON string against the official schema."""
    try:
        import jsonschema  # noqa: PLC0415
    except ImportError:
        pytest.skip("jsonschema not installed (run: uv pip install jsonschema)")

    sarif = json.loads(sarif_str)
    schema = _get_schema()
    jsonschema.validate(instance=sarif, schema=schema)


class TestSarifSchemaCompliance:
    """SARIF output must conform to the SARIF 2.1.0 JSON schema."""

    def test_empty_findings_is_valid_sarif(self) -> None:
        """A scan with zero findings must produce schema-valid SARIF."""
        result = _make_result(findings=[])
        sarif_str = format_sarif(result)
        _validate(sarif_str)

    def test_single_finding_is_valid_sarif(self, tmp_path: Path) -> None:
        """A scan with one finding must produce schema-valid SARIF."""
        finding = Finding(
            id="POISON-001",
            severity=Severity.CRITICAL,
            analyzer="poisoning",
            client="claude_desktop",
            server="test-server",
            title="SSH key exfiltration",
            description="Tool description instructs the agent to read ~/.ssh/id_rsa",
            evidence="~/.ssh/id_rsa",
            remediation="Remove the server.",
            cwe="CWE-200",
            finding_path=str(tmp_path / "claude_desktop_config.json"),
        )
        result = _make_result(findings=[finding])
        sarif_str = format_sarif(result)
        _validate(sarif_str)

    def test_multiple_analyzers_is_valid_sarif(self, tmp_path: Path) -> None:
        """Findings from multiple analyzers must produce schema-valid SARIF."""
        findings = [
            Finding(
                id="POISON-001",
                severity=Severity.CRITICAL,
                analyzer="poisoning",
                client="claude_desktop",
                server="srv-a",
                title="SSH exfiltration",
                description="desc",
                evidence="ev",
                remediation="fix",
                finding_path=str(tmp_path / "a.json"),
            ),
            Finding(
                id="CRED-001",
                severity=Severity.HIGH,
                analyzer="credentials",
                client="claude_desktop",
                server="srv-b",
                title="API key exposed",
                description="desc",
                evidence="ev",
                remediation="fix",
                finding_path=str(tmp_path / "b.json"),
            ),
            Finding(
                id="GOV-001",
                severity=Severity.MEDIUM,
                analyzer="governance",
                client="claude_desktop",
                server="srv-c",
                title="Policy violation",
                description="desc",
                evidence="ev",
                remediation="fix",
            ),
        ]
        result = _make_result(findings=findings)
        sarif_str = format_sarif(result)
        _validate(sarif_str)

    def test_finding_with_no_path_is_valid_sarif(self) -> None:
        """A finding with no config path must produce schema-valid SARIF."""
        finding = Finding(
            id="TRANSPORT-001",
            severity=Severity.HIGH,
            analyzer="transport",
            client="cursor",
            server="srv",
            title="HTTP transport",
            description="desc",
            evidence="ev",
            remediation="fix",
            finding_path=None,  # No path — uses fallback URI
        )
        result = _make_result(findings=[finding])
        sarif_str = format_sarif(result)
        _validate(sarif_str)

    def test_sarif_contains_original_uri_base_ids(self) -> None:
        """SARIF run must define originalUriBaseIds for %SRCROOT%."""
        result = _make_result()
        sarif = json.loads(format_sarif(result))
        run = sarif["runs"][0]
        assert "originalUriBaseIds" in run, (
            "SARIF run must define originalUriBaseIds to satisfy the SARIF spec "
            "and allow GitHub to resolve %SRCROOT% to the repo root"
        )
        assert "%SRCROOT%" in run["originalUriBaseIds"]

    def test_sarif_contains_automation_details(self) -> None:
        """SARIF run must include automationDetails.id for GitHub deduplication."""
        result = _make_result()
        sarif = json.loads(format_sarif(result))
        run = sarif["runs"][0]
        assert "automationDetails" in run
        assert "id" in run["automationDetails"]

    def test_sarif_version_is_2_1_0(self) -> None:
        """SARIF document version must be exactly 2.1.0."""
        result = _make_result()
        sarif = json.loads(format_sarif(result))
        assert sarif["version"] == "2.1.0"

    def test_no_file_unknown_uri_in_results(self) -> None:
        """Results must not use file:///unknown — GitHub rejects it."""
        finding = Finding(
            id="POISON-001",
            severity=Severity.CRITICAL,
            analyzer="poisoning",
            client="test",
            server="srv",
            title="test",
            description="d",
            evidence="e",
            remediation="r",
            finding_path=None,
        )
        result = _make_result(findings=[finding])
        sarif_str = format_sarif(result)
        assert "file:///unknown" not in sarif_str, (
            "file:///unknown is not a valid SARIF artifact URI; "
            "use a relative path sentinel instead"
        )

    def test_automation_details_id_includes_hostname(self) -> None:
        """automationDetails.id should embed the machine hostname."""
        result = _make_result()
        sarif = json.loads(format_sarif(result))
        automation_id = sarif["runs"][0]["automationDetails"]["id"]
        assert "test-host" in automation_id

    def test_automation_details_id_fallback_when_no_hostname(self) -> None:
        """automationDetails.id must not be empty when hostname is absent."""
        result = _make_result()
        result.machine.hostname = None  # type: ignore[assignment]
        sarif = json.loads(format_sarif(result))
        automation_id = sarif["runs"][0]["automationDetails"]["id"]
        assert automation_id  # non-empty string
        assert "scan" in automation_id  # fallback token


class TestSarifOwaspMcpTaxonomy:
    """SARIF output must include the OWASP MCP Top 10 taxonomy block."""

    def _finding_with_owasp(self, codes: list[str]) -> Finding:
        return Finding(
            id="POISON-010",
            severity=Severity.HIGH,
            analyzer="poisoning",
            client="claude_desktop",
            server="test-srv",
            title="XML instruction injection",
            description="desc",
            evidence="ev",
            remediation="fix",
            owasp_mcp_top_10=codes,
        )

    def test_taxonomy_block_always_present(self) -> None:
        """runs[0].taxonomies must always contain the OWASP-MCP-Top-10 entry."""
        result = _make_result()
        sarif = json.loads(format_sarif(result))
        taxonomies = sarif["runs"][0].get("taxonomies", [])
        assert len(taxonomies) == 1
        assert taxonomies[0]["name"] == "OWASP-MCP-Top-10"

    def test_taxonomy_has_ten_taxa(self) -> None:
        """The taxonomy must declare all 10 OWASP MCP categories."""
        result = _make_result()
        sarif = json.loads(format_sarif(result))
        taxa = sarif["runs"][0]["taxonomies"][0]["taxa"]
        assert len(taxa) == 10
        ids = {t["id"] for t in taxa}
        assert ids == {f"MCP{i:02d}" for i in range(1, 11)}

    def test_rule_has_relationships_when_owasp_codes_set(self) -> None:
        """Rule must have relationships[] for findings with owasp_mcp_top_10."""
        finding = self._finding_with_owasp(["MCP03"])
        result = _make_result(findings=[finding])
        sarif = json.loads(format_sarif(result))
        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        assert "relationships" in rule
        assert rule["relationships"][0]["target"]["id"] == "MCP03"
        assert rule["relationships"][0]["target"]["toolComponent"]["name"] == (
            "OWASP-MCP-Top-10"
        )

    def test_rule_properties_owasp_codes(self) -> None:
        """Rule properties must include owasp-mcp-top-10 codes."""
        finding = self._finding_with_owasp(["MCP03"])
        result = _make_result(findings=[finding])
        sarif = json.loads(format_sarif(result))
        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule["properties"]["owasp-mcp-top-10"] == ["MCP03"]

    def test_rule_no_relationships_when_owasp_empty(self) -> None:
        """Rules for unmapped findings must not have relationships[]."""
        finding = self._finding_with_owasp([])
        result = _make_result(findings=[finding])
        sarif = json.loads(format_sarif(result))
        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        assert "relationships" not in rule
        assert "owasp-mcp-top-10" not in rule.get("properties", {})

    def test_taxonomy_block_is_schema_valid(self, tmp_path: Path) -> None:
        """A scan result with OWASP-coded findings must still be schema-valid SARIF."""
        finding = self._finding_with_owasp(["MCP03", "MCP06"])
        finding = finding.model_copy(
            update={"finding_path": str(tmp_path / "cfg.json")}
        )
        result = _make_result(findings=[finding])
        sarif_str = format_sarif(result)
        _validate(sarif_str)
        sarif = json.loads(sarif_str)
        assert sarif["runs"][0]["taxonomies"][0]["name"] == "OWASP-MCP-Top-10"
        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule["relationships"][0]["target"]["id"] == "MCP03"
        assert rule["properties"]["owasp-mcp-top-10"] == ["MCP03", "MCP06"]
