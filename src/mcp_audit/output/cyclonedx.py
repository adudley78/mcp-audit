"""CycloneDX 1.5 SBOM formatter for mcp-audit scan results."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

try:
    from cyclonedx.model import Tool, XsUri
    from cyclonedx.model.bom import Bom
    from cyclonedx.model.component import Component, ComponentType
    from cyclonedx.model.vulnerability import (
        Vulnerability,
        VulnerabilityRating,
        VulnerabilitySeverity,
        VulnerabilitySource,
    )
    from cyclonedx.output.json import JsonV1Dot5

    _CYCLONEDX_AVAILABLE = True
except ImportError:
    _CYCLONEDX_AVAILABLE = False

from mcp_audit.models import ScanResult
from mcp_audit.output.base import BaseFormatter

_SEVERITY_MAP: dict[str, VulnerabilitySeverity] = {
    "CRITICAL": VulnerabilitySeverity.CRITICAL,
    "HIGH": VulnerabilitySeverity.HIGH,
    "MEDIUM": VulnerabilitySeverity.MEDIUM,
    "LOW": VulnerabilitySeverity.LOW,
    "INFO": VulnerabilitySeverity.INFO,
    "UNKNOWN": VulnerabilitySeverity.UNKNOWN,
}


class CycloneDxFormatter(BaseFormatter):
    """Outputs a CycloneDX 1.5 JSON SBOM document."""

    def format(self, result: ScanResult) -> str:
        """Serialise a ScanResult to a CycloneDX 1.5 JSON SBOM string.

        Args:
            result: The completed scan result to format.

        Returns:
            CycloneDX 1.5 JSON string containing bomFormat, specVersion,
            serialNumber, metadata, components, and vulnerabilities.

        Raises:
            ImportError: When ``cyclonedx-python-lib`` is not installed.
                Install via ``pip install 'mcp-audit[sbom]'``.
        """
        if not _CYCLONEDX_AVAILABLE:
            raise ImportError(
                "The 'sbom' extra is required for CycloneDX output. "
                "Install it with: pip install 'mcp-audit[sbom]'"
            )

        from mcp_audit import __version__ as _ver  # noqa: PLC0415

        bom = Bom()
        bom.serial_number = uuid.uuid4()
        bom.metadata.timestamp = datetime.now(tz=UTC)

        # Tool entry for mcp-audit itself
        tool = Tool(vendor="mcp-audit", name="mcp-audit", version=_ver)
        bom.metadata.tools.add(tool)

        # One top-level component per scanned server
        for server in result.servers:
            comp = Component(
                name=server.name,
                type=ComponentType.APPLICATION,
                version="unknown",
            )
            bom.components.add(comp)

        # VULN-* findings → CycloneDX Vulnerability objects (skip VULN-UNPINNED)
        for finding in result.findings:
            if not finding.id.startswith("VULN-") or finding.id == "VULN-UNPINNED":
                continue

            osv_id = finding.id.removeprefix("VULN-")
            severity = _SEVERITY_MAP.get(
                finding.severity.value, VulnerabilitySeverity.UNKNOWN
            )

            vuln = Vulnerability(
                id=osv_id,
                source=VulnerabilitySource(
                    name="OSV",
                    url=XsUri(f"https://osv.dev/vulnerability/{osv_id}"),
                ),
                ratings=[VulnerabilityRating(severity=severity)],
                description=finding.description,
            )
            bom.vulnerabilities.add(vuln)

        serialiser = JsonV1Dot5(bom)
        return serialiser.output_as_string(indent=2)
