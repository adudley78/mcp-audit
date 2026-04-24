"""Assess transport-layer security of MCP server configurations."""

from __future__ import annotations

from urllib.parse import urlparse

from mcp_audit.analyzers.base import BaseAnalyzer
from mcp_audit.models import Finding, ServerConfig, Severity, TransportType
from mcp_audit.registry.loader import KnownServerRegistry

# Commands that fetch and execute a package at runtime.  Kept distinct from
# ``supply_chain._NPX_LIKE`` because ``uvx``/``pipx`` are pip-ecosystem
# launchers and are not relevant to npm typosquatting detection.
_RUNTIME_FETCH_COMMANDS: frozenset[str] = frozenset({"npx", "uvx", "bunx", "pipx"})

# Commands (and path-suffixes) that execute with elevated privileges.
_PRIV_ESC_NAMES: frozenset[str] = frozenset({"sudo", "doas", "pkexec", "su", "run0"})

# Wildcard bind addresses that expose a server on all network interfaces.
_WILDCARD_HOSTS: frozenset[str] = frozenset(
    {"0.0.0.0", "::"}  # noqa: S104
)


class TransportAnalyzer(BaseAnalyzer):
    """Check transport security: TLS, localhost binding, privilege escalation.

    When constructed with a :class:`KnownServerRegistry`, TRANSPORT-003
    (runtime package fetching) is tiered by registry membership:

    * Known and **verified** package → finding suppressed (COMM-010 still
      raises the pinning reminder at LOW).
    * Known but **unverified** package → LOW finding (recognised but not
      fully vetted).
    * Unknown package or no registry supplied → MEDIUM finding (historic
      behaviour; strong alarm for fully-unknown runtime fetches).

    The tiering exists to stop TRANSPORT-003 from firing at MEDIUM on every
    legitimate MCP server that launches via ``npx @modelcontextprotocol/*``.
    See GAPS.md → "TRANSPORT-003 rescoped" for rationale.
    """

    def __init__(self, registry: KnownServerRegistry | None = None) -> None:
        """Initialise the analyzer with an optional known-server registry.

        Args:
            registry: Pre-loaded registry used to tier TRANSPORT-003
                severity.  ``None`` preserves the historical
                "always MEDIUM" behaviour.
        """
        self._registry = registry

    @property
    def name(self) -> str:
        return "transport"

    @property
    def description(self) -> str:
        return "Assess transport-layer security of server configurations"

    def analyze(self, server: ServerConfig) -> list[Finding]:
        findings: list[Finding] = []

        # TRANSPORT-001: HTTP/SSE without TLS
        if server.url:
            parsed = urlparse(server.url)
            hostname = parsed.hostname or ""
            is_remote_http = parsed.scheme == "http" and hostname not in (
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

            # TRANSPORT-004: Wildcard interface binding (0.0.0.0 / [::])
            # Strip brackets from IPv6 addresses as urlparse returns them bare.
            bare_host = hostname.strip("[]")
            if bare_host in _WILDCARD_HOSTS:
                findings.append(
                    Finding(
                        id="TRANSPORT-004",
                        severity=Severity.HIGH,
                        analyzer=self.name,
                        client=server.client,
                        server=server.name,
                        title="Wildcard interface binding",
                        description=(
                            "MCP server binds to all network interfaces"
                            f" ({bare_host}), exposing it to the local network"
                            " and potentially the internet."
                        ),
                        evidence=f"URL: {server.url}",
                        remediation=(
                            "Bind to 127.0.0.1 (or ::1) to restrict access"
                            " to the local machine only."
                        ),
                        cwe="CWE-284",
                    )
                )

        # TRANSPORT-002: Elevated privilege execution
        if (
            server.transport == TransportType.STDIO
            and server.command
            and self._is_privilege_escalation(server)
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
                    remediation=(
                        "Run MCP servers with least-privilege user permissions"
                    ),
                    cwe="CWE-250",
                )
            )

        # TRANSPORT-003: Runtime package fetching (supply chain risk)
        is_runtime_fetch = server.command in _RUNTIME_FETCH_COMMANDS or (
            server.command == "yarn"
            and bool(server.args)
            and server.args[0] == "dlx"
        )
        if is_runtime_fetch:
            finding = self._build_runtime_fetch_finding(server)
            if finding is not None:
                findings.append(finding)

        return findings

    def _is_privilege_escalation(self, server: ServerConfig) -> bool:
        """Return True if the server command or its first argument escalates privileges.

        Matches bare names (``sudo``, ``pkexec`` …), any full path whose
        basename is a known escalation command (``/usr/bin/sudo``), the legacy
        ``/usr/sbin/*`` prefix, and the pattern of wrapping a command via
        ``sh``/``bash`` with ``sudo`` as the first argument.
        """
        cmd = server.command
        cmd_basename = cmd.rsplit("/", 1)[-1]

        if cmd_basename in _PRIV_ESC_NAMES:
            return True
        if cmd.startswith("/usr/sbin"):
            return True
        # sudo/doas passed as first arg to a shell wrapper (e.g. command="sh")
        return bool(server.args and server.args[0] in _PRIV_ESC_NAMES)

    def _build_runtime_fetch_finding(self, server: ServerConfig) -> Finding | None:
        """Construct a TRANSPORT-003 finding with registry-tiered severity.

        Returns ``None`` when the runtime-fetched package is a verified
        registry entry — such packages do not merit a MEDIUM alarm on every
        scan.  Callers that constructed this analyzer without a registry
        always get a MEDIUM finding (historic behaviour preserved).
        """
        # Imported lazily to avoid adding a top-level dependency between the
        # transport and supply_chain analyzer modules.
        from mcp_audit.analyzers.supply_chain import (  # noqa: PLC0415
            extract_npm_package,
        )

        # For `yarn dlx <pkg>`, skip the 'dlx' subcommand token.
        effective_args = (
            server.args[1:]
            if server.command == "yarn" and server.args and server.args[0] == "dlx"
            else server.args
        )
        package = extract_npm_package(effective_args)
        entry = (
            self._registry.get(package)
            if (self._registry is not None and package is not None)
            else None
        )

        if entry is not None and entry.verified:
            # Verified registry entry: suppress — the signal is covered by
            # COMM-010 (`npx used without pinned version`) at LOW.
            return None

        known_but_unverified = entry is not None and not entry.verified

        if known_but_unverified:
            severity = Severity.LOW
            title = "Runtime package fetching (unverified registry entry)"
            description = (
                f"Server uses {server.command} to fetch {package!r}, which is "
                "recognised in the known-server registry but not yet marked "
                "verified. Consider pinning the version and running "
                "`mcp-audit scan --verify-hashes` for integrity checks."
            )
        else:
            severity = Severity.MEDIUM
            title = "Runtime package fetching"
            description = (
                f"Server uses {server.command} which downloads packages at runtime"
            )

        return Finding(
            id="TRANSPORT-003",
            severity=severity,
            analyzer=self.name,
            client=server.client,
            server=server.name,
            title=title,
            description=description,
            evidence=f"Command: {server.command} {' '.join(server.args[:3])}",
            remediation=(
                "Install packages locally and reference the installed binary instead"
            ),
            cwe="CWE-829",
        )
