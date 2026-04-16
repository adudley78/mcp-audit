"""Nucleus Security FlexConnect output formatter.

Produces a JSON document that conforms to the Nucleus FlexConnect universal
ingestion schema. Import this file into a Nucleus project via
Settings → Integrations → FlexConnect → Upload File.

Schema reference: https://nucleussec.com/flexconnect
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


def _finding_to_nucleus(finding: Finding, asset_prefix: str) -> dict[str, str]:
    """Serialize a single Finding to a Nucleus FlexConnect finding object.

    Args:
        finding: The finding to serialize.
        asset_prefix: Prefix prepended to the asset name (hostname or
            user-supplied override) so that assets from different machines
            remain distinct in Nucleus.

    Returns:
        Dict with all required Nucleus finding fields.
    """
    row: dict[str, str] = {
        "asset_name": f"{asset_prefix}/{finding.client}/{finding.server}",
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

    Each finding's ``asset_name`` is prefixed with *asset_prefix* (or the
    machine hostname when not supplied) so that findings from multiple machines
    are grouped under distinct assets in Nucleus.  Machine identity is also
    surfaced in the envelope via ``host_name`` and ``operating_system_name``.

    Args:
        result: The completed scan result to format.
        asset_prefix: Override the hostname prefix in ``asset_name``.  Useful
            when the hostname is not meaningful (e.g. "MacBookAir") and the
            team prefers an asset tag or employee ID.

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
    effective_prefix = (
        asset_prefix if asset_prefix is not None else result.machine.hostname
    )

    document: dict = {
        "nucleus_import_version": "1",
        "scan_tool": "mcp-audit",
        "scan_type": "Application",
        "scan_date": scan_date,
        "host_name": result.machine.hostname,
        "operating_system_name": result.machine.os,
        "findings": [_finding_to_nucleus(f, effective_prefix) for f in result.findings],
    }

    return json.dumps(document, indent=2)
