"""CycloneDX 1.5 SBOM formatter for mcp-audit scan results.

Supports cyclonedx-python-lib 7.x AND 8.x-11.x. The two major-version series
differ in two ways we care about:

* ``Tool`` lives at ``cyclonedx.model.Tool`` in v7; it was moved to
  ``cyclonedx.model.tool.Tool`` in v8.
* ``Bom.metadata.tools`` is a ``SortedSet`` in v7 (``.add(tool)`` works
  directly); in v8+ it is a ``ToolRepository`` whose underlying set is
  exposed as ``.tools`` (so you call ``.tools.add(tool)``).

All cyclonedx imports are deferred until format-time so the module always
imports cleanly regardless of whether the optional ``[sbom]`` extra is
installed.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from importlib.util import find_spec

from mcp_audit.models import ScanResult
from mcp_audit.output.base import BaseFormatter

_CYCLONEDX_AVAILABLE = find_spec("cyclonedx") is not None


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
                Install via ``pip install 'mcp-audit-scanner[sbom]'``.
        """
        if not _CYCLONEDX_AVAILABLE:
            raise ImportError(
                "The 'sbom' extra is required for CycloneDX output. "
                "Install it with: pip install 'mcp-audit-scanner[sbom]'"
            )

        from cyclonedx.model import XsUri  # noqa: PLC0415
        from cyclonedx.model.bom import Bom  # noqa: PLC0415
        from cyclonedx.model.component import (  # noqa: PLC0415
            Component,
            ComponentType,
        )
        from cyclonedx.model.vulnerability import (  # noqa: PLC0415
            Vulnerability,
            VulnerabilityRating,
            VulnerabilitySeverity,
            VulnerabilitySource,
        )
        from cyclonedx.output.json import JsonV1Dot5  # noqa: PLC0415

        try:
            from cyclonedx.model.tool import Tool  # noqa: PLC0415
        except ImportError:
            from cyclonedx.model import (  # noqa: PLC0415
                Tool,  # type: ignore[no-redef,attr-defined]
            )

        from mcp_audit import __version__ as _ver  # noqa: PLC0415

        severity_map: dict[str, VulnerabilitySeverity] = {
            "CRITICAL": VulnerabilitySeverity.CRITICAL,
            "HIGH": VulnerabilitySeverity.HIGH,
            "MEDIUM": VulnerabilitySeverity.MEDIUM,
            "LOW": VulnerabilitySeverity.LOW,
            "INFO": VulnerabilitySeverity.INFO,
            "UNKNOWN": VulnerabilitySeverity.UNKNOWN,
        }

        bom = Bom()
        bom.serial_number = uuid.uuid4()
        bom.metadata.timestamp = datetime.now(tz=UTC)

        tool = Tool(vendor="mcp-audit", name="mcp-audit", version=_ver)
        # v7: metadata.tools is a SortedSet exposing .add().
        # v8+: metadata.tools is a ToolRepository whose set is at .tools.
        tools_repo = bom.metadata.tools
        if hasattr(tools_repo, "tools"):
            tools_repo.tools.add(tool)
        else:
            tools_repo.add(tool)

        for server in result.servers:
            comp = Component(
                name=server.name,
                type=ComponentType.APPLICATION,
                version="unknown",
            )
            bom.components.add(comp)

        for finding in result.findings:
            if not finding.id.startswith("VULN-") or finding.id == "VULN-UNPINNED":
                continue

            osv_id = finding.id.removeprefix("VULN-")
            severity = severity_map.get(
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
