"""Nucleus Security FlexConnect output formatter.

Produces a JSON document that conforms to the Nucleus FlexConnect universal
ingestion schema. Import this file into a Nucleus project via
Settings → Integrations → FlexConnect → Upload File, or push directly with
``mcp-audit push-nucleus``.

Schema reference: https://help.nucleussec.com/docs/flexconnect-framework

Validated format (2026-04-23):
  - Top-level ``assets`` array defines the host asset.
  - Top-level ``findings`` array references the asset via ``host_name``.
  - ``scan_type`` must be ``"Host"`` for machine-level assets.
  - ``host_name`` inside each finding links back to the asset entry.
"""

from __future__ import annotations

import json

from rich.console import Console
from rich.panel import Panel

from mcp_audit.licensing import is_pro_feature_available
from mcp_audit.models import Finding, ScanResult, Severity

_console = Console()

# Maps our internal severity enum to Nucleus-accepted string values.
_SEVERITY_MAP: dict[Severity, str] = {
    Severity.CRITICAL: "Critical",
    Severity.HIGH: "High",
    Severity.MEDIUM: "Medium",
    Severity.LOW: "Low",
    Severity.INFO: "Informational",
}


def _finding_to_nucleus(finding: Finding, host_name: str) -> dict[str, str]:
    """Serialize a single Finding to a Nucleus FlexConnect finding object.

    Args:
        finding: The finding to serialize.
        host_name: The host_name that links this finding back to an entry in
            the top-level ``assets`` array.  Derived from the machine hostname
            or the user-supplied ``--asset-prefix`` override.

    Returns:
        Dict with all required Nucleus finding fields.
    """
    row: dict[str, str] = {
        "host_name": host_name,
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


def format_nucleus(
    result: ScanResult,
    asset_prefix: str | None = None,
    console: Console | None = None,
) -> str | None:
    """Format a ScanResult as a Nucleus FlexConnect JSON string.

    The returned string is a complete, self-contained JSON document ready
    for upload to the Nucleus platform. ``scan_date`` uses the space-separated
    format expected by FlexConnect (``YYYY-MM-DD HH:MM:SS``), derived from the
    UTC timestamp stored on the ScanResult.

    The document contains a top-level ``assets`` array (one entry for the
    scanned machine) and a top-level ``findings`` array.  Each finding's
    ``host_name`` field links it back to the asset entry.  The asset is
    identified by *asset_prefix* (or the machine hostname when not supplied);
    use ``--asset-prefix`` to override when the hostname is not meaningful
    (e.g. ``"MacBookAir"``) and the team prefers an asset tag or employee ID.

    Args:
        result: The completed scan result to format.
        asset_prefix: Override the hostname used as the asset identifier.

    Returns:
        Pretty-printed JSON string conforming to the FlexConnect schema, or
        ``None`` if the feature is not available under the current license.
    """
    _con = console or _console
    if not is_pro_feature_available("nucleus"):
        _con.print(
            Panel(
                "[bold]Nucleus FlexConnect output requires mcp-audit Enterprise.[/bold]\n\n"  # noqa: E501
                "Your scan completed successfully. Results are available in terminal, JSON, and SARIF formats.\n\n"  # noqa: E501
                "Upgrade to Enterprise: [link=https://mcp-audit.dev/pro]https://mcp-audit.dev/pro[/link]\n"
                "Already have a key? Run: [bold]mcp-audit activate <your-key>[/bold]",
                title="Enterprise Feature",
                border_style="yellow",
            )
        )
        return None

    scan_date = result.timestamp.strftime("%Y-%m-%d %H:%M:%S")
    host_name = asset_prefix if asset_prefix is not None else result.machine.hostname

    document: dict = {
        "nucleus_import_version": "1",
        "scan_tool": "mcp-audit",
        "scan_type": "Host",
        "scan_date": scan_date,
        "assets": [
            {
                "host_name": host_name,
                "operating_system_name": result.machine.os,
            }
        ],
        "findings": [_finding_to_nucleus(f, host_name) for f in result.findings],
    }

    return json.dumps(document, indent=2)
