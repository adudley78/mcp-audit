"""Assess transport-layer security of MCP server configurations."""

from __future__ import annotations

from urllib.parse import urlparse

from mcp_audit.analyzers.base import BaseAnalyzer
from mcp_audit.models import Finding, ServerConfig, Severity, TransportType


class TransportAnalyzer(BaseAnalyzer):
    """Check transport security: TLS, localhost binding, privilege escalation."""

    @property
    def name(self) -> str:
        return "transport"

    @property
    def description(self) -> str:
        return "Assess transport-layer security of server configurations"

    def analyze(self, server: ServerConfig) -> list[Finding]:
        findings: list[Finding] = []

        # Check HTTP/SSE without TLS
        if server.url:
            parsed = urlparse(server.url)
            is_remote_http = parsed.scheme == "http" and parsed.hostname not in (
                "localhost",
                "127.0.0.1",
                "::1",
            )
            if is_remote_http:
                findings.append(
                    Finding(
                        id="TRANSPORT-001",
                        severity=Severity.MEDIUM,
                        analyzer=self.name,
                        client=server.client,
                        server=server.name,
                        title="Unencrypted remote connection",
                        description=(
                            "SSE/HTTP server uses http:// to a non-localhost address"
                        ),
                        evidence=f"URL: {server.url}",
                        remediation="Use https:// or restrict to localhost",
                        cwe="CWE-319",
                    )
                )

        # Check stdio commands run with elevated privileges
        if (
            server.transport == TransportType.STDIO
            and server.command
            and (
                server.command in ("sudo", "doas")
                or server.command.startswith("/usr/sbin")
            )
        ):
            findings.append(
                Finding(
                    id="TRANSPORT-002",
                    severity=Severity.HIGH,
                    analyzer=self.name,
                    client=server.client,
                    server=server.name,
                    title="Elevated privilege execution",
                    description="MCP server runs with elevated privileges",
                    evidence=f"Command: {server.command}",
                    remediation="Run MCP servers with least-privilege user permissions",
                    cwe="CWE-250",
                )
            )

        # Check runtime package fetching (supply chain risk via transport)
        if server.command in ("npx", "uvx", "bunx"):
            findings.append(
                Finding(
                    id="TRANSPORT-003",
                    severity=Severity.MEDIUM,
                    analyzer=self.name,
                    client=server.client,
                    server=server.name,
                    title="Runtime package fetching",
                    description=(
                        f"Server uses {server.command}"
                        " which downloads packages at runtime"
                    ),
                    evidence=(f"Command: {server.command} {' '.join(server.args[:3])}"),
                    remediation=(
                        "Install packages locally and reference"
                        " the installed binary instead"
                    ),
                    cwe="CWE-829",
                )
            )

        return findings
