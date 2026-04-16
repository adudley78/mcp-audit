"""Core data models for mcp-audit."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, Field

# ── Machine identification ─────────────────────────────────────────────────────


class MachineInfo(BaseModel):
    """Identifies the machine that produced scan results."""

    hostname: str
    username: str
    os: str  # e.g., "Darwin", "Linux", "Windows"
    os_version: str
    scan_id: str  # UUID generated per scan run


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
    """

    tools: list[ToolInfo] = Field(default_factory=list)
    resources: list[ResourceInfo] = Field(default_factory=list)
    prompts: list[PromptInfo] = Field(default_factory=list)
    error: str | None = None


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

    numeric_score: int
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

    version: str = "0.1.0"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    machine: MachineInfo = Field(default_factory=_collect_machine_info)
    clients_scanned: int = 0
    servers_found: int = 0
    servers: list[ServerConfig] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    attack_path_summary: AttackPathSummary | None = None
    score: ScanScore | None = None
    registry_stats: RegistryStats | None = None

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
