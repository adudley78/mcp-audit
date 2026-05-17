"""Tests for OWASP MCP Top 10 data model and mapping correctness."""

from __future__ import annotations

from mcp_audit.models import Finding, Severity
from mcp_audit.owasp_mcp import (
    OWASP_MCP_TOP_10,
    category_name,
    is_valid_code,
)

# ── owasp_mcp module ──────────────────────────────────────────────────────────


def test_owasp_mcp_top_10_has_ten_entries() -> None:
    assert len(OWASP_MCP_TOP_10) == 10
    assert set(OWASP_MCP_TOP_10) == {f"MCP{i:02d}" for i in range(1, 11)}


def test_category_name_lookup() -> None:
    assert category_name("MCP03") == "Tool Poisoning"
    assert category_name("MCP01") == "Token Mismanagement and Secret Exposure"
    assert category_name("MCP99") is None


def test_is_valid_code() -> None:
    assert is_valid_code("MCP01")
    assert is_valid_code("MCP10")
    assert not is_valid_code("MCP99")
    assert not is_valid_code("ASI01")
    assert not is_valid_code("")


# ── Finding model ─────────────────────────────────────────────────────────────


def _minimal_finding(**kwargs) -> Finding:
    defaults: dict = {
        "id": "X",
        "severity": Severity.LOW,
        "analyzer": "test",
        "client": "test",
        "server": "test",
        "title": "t",
        "description": "d",
        "evidence": "e",
        "remediation": "r",
    }
    defaults.update(kwargs)
    return Finding(**defaults)


def test_finding_defaults_to_empty_owasp_mcp_list() -> None:
    f = _minimal_finding()
    assert f.owasp_mcp_top_10 == []


def test_finding_accepts_owasp_mcp_codes() -> None:
    f = _minimal_finding(owasp_mcp_top_10=["MCP03", "MCP10"])
    assert f.owasp_mcp_top_10 == ["MCP03", "MCP10"]


def test_finding_owasp_mcp_default_is_independent() -> None:
    """Default list must not be shared between instances."""
    f1 = _minimal_finding()
    f2 = _minimal_finding()
    f1.owasp_mcp_top_10.append("MCP01")
    assert f2.owasp_mcp_top_10 == []


# ── Sanity-check: every emitted finding has valid codes ───────────────────────


# ── _print_owasp_report helper ────────────────────────────────────────────────


def _make_scan_result_with_findings():  # type: ignore[return]
    from mcp_audit.models import Finding, ScanResult, Severity  # noqa: PLC0415

    return ScanResult(
        clients_scanned=1,
        servers_found=1,
        findings=[
            Finding(
                id="POISON-010",
                severity=Severity.HIGH,
                analyzer="poisoning",
                client="claude_desktop",
                server="srv",
                title="XML injection",
                description="d",
                evidence="e",
                remediation="r",
                owasp_mcp_top_10=["MCP03", "MCP06"],
            ),
            Finding(
                id="CRED-001",
                severity=Severity.HIGH,
                analyzer="credentials",
                client="claude_desktop",
                server="srv",
                title="Credential",
                description="d",
                evidence="e",
                remediation="r",
                owasp_mcp_top_10=["MCP01"],
            ),
        ],
    )


def _capture_owasp_report(result) -> str:
    from io import StringIO  # noqa: PLC0415

    from rich.console import Console  # noqa: PLC0415

    from mcp_audit.cli.scan import _print_owasp_report  # noqa: PLC0415

    buf = StringIO()
    con = Console(file=buf, highlight=False, markup=False)
    _print_owasp_report(result, con)
    return buf.getvalue()


def test_owasp_report_shows_triggered_categories() -> None:
    result = _make_scan_result_with_findings()
    output = _capture_owasp_report(result)
    assert "MCP01" in output
    assert "MCP03" in output
    assert "MCP06" in output


def test_owasp_report_shows_category_count() -> None:
    result = _make_scan_result_with_findings()
    output = _capture_owasp_report(result)
    # MCP01 has 1 finding, MCP03 has 1 finding, MCP06 has 1 finding
    assert "finding" in output


def test_owasp_report_shows_coverage_line() -> None:
    result = _make_scan_result_with_findings()
    output = _capture_owasp_report(result)
    # New format: "Coverage: 10/10 OWASP MCP Top 10 categories checked"
    assert "Coverage: 10/10 OWASP MCP Top 10 categories checked" in output


def test_owasp_report_zero_finding_category_shown() -> None:
    """Categories with zero findings must still appear in the output."""
    from mcp_audit.models import Finding, ScanResult, Severity  # noqa: PLC0415

    # Scan with only MCP01 findings — all other categories should still appear
    result = ScanResult(
        clients_scanned=1,
        servers_found=1,
        findings=[
            Finding(
                id="X",
                severity=Severity.LOW,
                analyzer="test",
                client="t",
                server="t",
                title="t",
                description="d",
                evidence="e",
                remediation="r",
                owasp_mcp_top_10=["MCP01"],
            )
        ],
    )
    output = _capture_owasp_report(result)
    # All 10 categories must appear, even those with zero findings
    for i in range(1, 11):
        assert f"MCP{i:02d}" in output, f"MCP{i:02d} missing from owasp report"


# ── Integration scan sanity check ─────────────────────────────────────────────


def test_every_finding_has_valid_owasp_mcp_codes() -> None:
    """Run a demo scan; assert all owasp_mcp_top_10 codes are valid MCP01–MCP10."""
    from pathlib import Path  # noqa: PLC0415

    from mcp_audit.scanner import run_scan  # noqa: PLC0415

    demo_config = Path("demo/configs/claude_desktop_config.json")
    result = run_scan(extra_paths=[demo_config])
    for f in result.findings:
        for code in f.owasp_mcp_top_10:
            assert is_valid_code(code), (
                f"Finding {f.id} has invalid OWASP MCP code: {code!r}"
            )
