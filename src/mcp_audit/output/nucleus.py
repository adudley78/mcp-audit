"""Nucleus Security FlexConnect output formatter.

Produces a JSON document that conforms to the Nucleus FlexConnect universal
ingestion schema. Import this file into a Nucleus project via
Settings → Integrations → FlexConnect → Upload File.

Schema reference: https://nucleussec.com/flexconnect
"""

from __future__ import annotations

import json

from mcp_audit.models import Finding, ScanResult, Severity

# Maps our internal severity enum to Nucleus-accepted string values.
_SEVERITY_MAP: dict[Severity, str] = {
    Severity.CRITICAL: "Critical",
    Severity.HIGH: "High",
    Severity.MEDIUM: "Medium",
    Severity.LOW: "Low",
    Severity.INFO: "Informational",
}


def _finding_to_nucleus(finding: Finding) -> dict[str, str]:
    """Serialize a single Finding to a Nucleus FlexConnect finding object.

    Args:
        finding: The finding to serialize.

    Returns:
        Dict with all required Nucleus finding fields.
    """
    row: dict[str, str] = {
        "asset_name": f"{finding.client}/{finding.server}",
        "finding_number": finding.id,
        "finding_name": finding.title,
        "finding_severity": _SEVERITY_MAP[finding.severity],
        "finding_description": finding.description,
        "finding_solution": finding.remediation,
        "finding_output": finding.evidence,
        "finding_path": finding.finding_path or "",
        "finding_result": "Fail",
        "finding_type": "Vulnerability",
    }
    if finding.cwe:
        row["finding_cve"] = finding.cwe
    return row


def format_nucleus(result: ScanResult) -> str:
    """Format a ScanResult as a Nucleus FlexConnect JSON string.

    The returned string is a complete, self-contained JSON document ready
    for upload to the Nucleus platform. ``scan_date`` uses the space-separated
    format expected by FlexConnect (``YYYY-MM-DD HH:MM:SS``), derived from the
    UTC timestamp stored on the ScanResult.

    Args:
        result: The completed scan result to format.

    Returns:
        Pretty-printed JSON string conforming to the FlexConnect schema.
    """
    scan_date = result.timestamp.strftime("%Y-%m-%d %H:%M:%S")

    document: dict = {
        "nucleus_import_version": "1",
        "scan_tool": "mcp-audit",
        "scan_type": "Application",
        "scan_date": scan_date,
        "findings": [_finding_to_nucleus(f) for f in result.findings],
    }

    return json.dumps(document, indent=2)
