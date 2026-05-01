"""Core data models for mcp-audit."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from mcp_audit import __version__

# ── Machine identification ─────────────────────────────────────────────────────


class MachineInfo(BaseModel):
    """Identifies the machine that produced scan results."""

    hostname: str
    username: str
    os: str  # e.g., "Darwin", "Linux", "Windows"
    os_version: str
    scan_id: str  # UUID generated per scan run
    asset_id: str | None = None  # set by --asset-prefix in fleet deployments


def _collect_machine_info() -> MachineInfo:
    """Gather machine identification data at scan time.

    Falls back to :func:`getpass.getuser` when :func:`os.getlogin` is
    unavailable (e.g., inside CI containers or systemd services that lack a
    controlling terminal).
    """
    import getpass  # noqa: PLC0415
    import os as _os  # noqa: PLC0415
    import platform  # noqa: PLC0415
    import uuid  # noqa: PLC0415

    try:
        username = _os.getlogin()
    except OSError:
        username = getpass.getuser()

    return MachineInfo(
        hostname=platform.node(),
        username=username,
        os=platform.system(),
        os_version=platform.version(),
        scan_id=str(uuid.uuid4()),
    )


class Severity(StrEnum):
    """Finding severity levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class TransportType(StrEnum):
    """MCP server transport types."""

    STDIO = "stdio"
    SSE = "sse"
    STREAMABLE_HTTP = "streamable-http"
    UNKNOWN = "unknown"


class MCPClient(BaseModel):
    """A supported MCP client application."""

    name: str
    config_paths: list[Path]
    root_key: str = "mcpServers"  # VS Code uses "servers"


class ServerConfig(BaseModel):
    """A parsed MCP server configuration."""

    name: str
    client: str
    config_path: Path
    transport: TransportType = TransportType.UNKNOWN
    command: str | None = None
    args: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)
    url: str | None = None
    raw: dict = Field(default_factory=dict)


class ToolInfo(BaseModel):
    """A tool exposed by a live MCP server."""

    name: str
    description: str | None = None
    input_schema: dict = Field(default_factory=dict)


class ResourceInfo(BaseModel):
    """A resource exposed by a live MCP server."""

    uri: str
    name: str | None = None
    description: str | None = None


class PromptInfo(BaseModel):
    """A prompt template exposed by a live MCP server."""

    name: str
    description: str | None = None


class ServerEnumeration(BaseModel):
    """Live enumeration results from connecting to an MCP server.

    Populated by :func:`~mcp_audit.mcp_client.connect_and_enumerate`.
    When ``error`` is set, the other fields are empty.
    ``server_stderr`` carries any text the server process wrote to stderr
    during startup; ``None`` when no output was captured (e.g. SSE servers).
    """

    tools: list[ToolInfo] = Field(default_factory=list)
    resources: list[ResourceInfo] = Field(default_factory=list)
    prompts: list[PromptInfo] = Field(default_factory=list)
    error: str | None = None
    server_stderr: str | None = None


class Finding(BaseModel):
    """A security finding from an analyzer."""

    id: str
    severity: Severity
    analyzer: str
    client: str
    server: str
    tool: str | None = None
    title: str
    description: str
    evidence: str
    remediation: str
    cwe: str | None = None
    finding_path: str | None = None
    # OWASP MCP Top 10 category codes (e.g., ["MCP03", "MCP10"]).
    # A finding may map to multiple categories. Empty list = unmapped.
    owasp_mcp_top_10: list[str] = Field(default_factory=list)
    # CVE identifiers associated with this finding (e.g. ["CVE-2026-33032"]).
    # Empty list = no CVE cross-reference. Populated by analyzers and the rule
    # engine for findings that map to a named, public vulnerability.
    cve: list[str] = Field(default_factory=list)


class AttackPath(BaseModel):
    """A multi-hop attack path across MCP servers."""

    id: str  # e.g., "PATH-001"
    severity: Severity
    title: str  # e.g., "File exfiltration via network"
    description: str  # Plain-English narrative of the attack
    hops: list[str]  # Server names in order: ["filesystem", "fetch"]
    source_capability: str  # e.g., "file_read"
    sink_capability: str  # e.g., "network_out"


class AttackPathSummary(BaseModel):
    """Summary of all attack paths and recommended removal targets."""

    paths: list[AttackPath] = Field(default_factory=list)
    hitting_set: list[str] = Field(default_factory=list)  # Servers to remove
    # Maps every server that appears in a path to the path IDs it would break.
    paths_broken_by: dict[str, list[str]] = Field(default_factory=dict)


class ScanScore(BaseModel):
    """Score and letter grade for a completed scan."""

    model_config = ConfigDict(populate_by_name=True)

    # "numeric" is the JSON key; Python code uses .numeric_score throughout.
    numeric_score: int = Field(
        validation_alias="numeric",
        serialization_alias="numeric",
    )
    grade: str
    positive_signals: list[str]
    deductions: list[str]


class RegistryStats(BaseModel):
    """Metadata about the known-server registry used during a scan."""

    entry_count: int
    schema_version: str
    last_updated: str


class ScanResult(BaseModel):
    """Complete results from a scan run."""

    model_config = ConfigDict(populate_by_name=True)

    version: str = __version__
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    machine: MachineInfo = Field(
        default_factory=_collect_machine_info,
        serialization_alias="machine_info",
    )
    clients_scanned: int = 0
    servers_found: int = 0
    servers: list[ServerConfig] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    attack_path_summary: AttackPathSummary | None = None
    score: ScanScore | None = None
    registry_stats: RegistryStats | None = None
    findings_below_threshold: int = 0
    active_severity_threshold: str | None = None
    # Captured stderr from stdio MCP server subprocesses launched during --connect.
    # Populated only when --connect is used; empty for static-only scans.
    # Surfaced in terminal output via --verbose; always present in JSON output.
    server_logs: list[str] = Field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def has_findings(self) -> bool:
        return len(self.findings) > 0

    @property
    def max_severity(self) -> Severity | None:
        if not self.findings:
            return None
        order = [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFO,
        ]
        for sev in order:
            if any(f.severity == sev for f in self.findings):
                return sev
        return None
