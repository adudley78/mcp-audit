"""Core data models for mcp-audit."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Finding severity levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class TransportType(str, Enum):
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


class ScanResult(BaseModel):
    """Complete results from a scan run."""

    version: str = "0.1.0"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    clients_scanned: int = 0
    servers_found: int = 0
    findings: list[Finding] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)

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
        order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        for sev in order:
            if any(f.severity == sev for f in self.findings):
                return sev
        return None
