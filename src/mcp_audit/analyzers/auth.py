"""Authentication configuration checks for remote MCP servers.

AUTH-001 — Remote server without authentication
    Fires when a remote (HTTP/SSE/Streamable-HTTP) server carries no
    discernible authentication material in its configuration.  Severity is
    tiered by host visibility:

    • PUBLIC host  → HIGH  (anyone on the internet can call every tool)
    • PRIVATE host → MEDIUM (RFC 1918 / *.local — reachable within a network)
    • LOCALHOST    → no finding (local trust boundary; client and server share
                      the same machine)

    Research basis: arXiv 2605.22333 measured 40.55% of 7,973 live remote MCP
    servers as requiring no authentication; Censys counted 12,520 internet-exposed
    MCP services, the majority unauthenticated.  CWE-306 / OWASP MCP06.

No network calls are made.  DNS is never resolved.  Classification is
performed purely by string/IP analysis of the configured URL.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

from mcp_audit.analyzers.base import BaseAnalyzer
from mcp_audit.models import Finding, ServerConfig, Severity, TransportType

# ── AUTH-001: auth-signal detection constants ─────────────────────────────────

# Header names (case-insensitive) that carry authentication material.
_AUTH_HEADER_NAMES: frozenset[str] = frozenset(
    {
        "authorization",
        "x-api-key",
        "api-key",
        "x-auth-token",
        "x-access-token",
        "api_key",
        "token",
    }
)

# Top-level raw-config field names that indicate authentication configuration.
# Matched case-insensitively against the keys in the server's raw dict.
_AUTH_FIELD_NAMES: frozenset[str] = frozenset(
    {
        "token",
        "apikey",
        "api_key",
        "auth",
        "bearer",
        "authorization",
        "access_token",
        "secret",
    }
)

# Field names that indicate an OAuth configuration block.
_OAUTH_FIELD_NAMES: frozenset[str] = frozenset(
    {
        "oauth",
        "oauth2",
        "authorization_endpoint",
        "token_endpoint",
        "client_id",
    }
)

# ── Localhost / private-range helpers ─────────────────────────────────────────

_LOCALHOST_NAMES: frozenset[str] = frozenset({"localhost", "127.0.0.1", "::1", "[::1]"})

# RFC 1918 private ranges.
_PRIVATE_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv6Network("fc00::/7"),  # ULA
)

# Link-local ranges (169.254.x.x / fe80::/10) are treated as private for this
# check — they are not internet-routable.
_LINK_LOCAL_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
    ipaddress.IPv4Network("169.254.0.0/16"),
    ipaddress.IPv6Network("fe80::/10"),
)

# Loopback ranges beyond 127.0.0.1 (full 127.0.0.0/8 and ::1/128).
_LOOPBACK_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
    ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv6Network("::1/128"),
)


def _classify_host(hostname: str) -> str:
    """Return 'local', 'private', or 'public' for *hostname*.

    No DNS lookups are performed.  Classification relies entirely on the
    literal hostname string and, for IP addresses, RFC 1918 / loopback range
    membership.

    Returns:
        ``"local"``   — localhost names, loopback IP addresses.
        ``"private"`` — RFC 1918 / ULA / link-local IP addresses, *.local
                        mDNS hostnames.
        ``"public"``  — everything else (internet-routable).
    """
    if not hostname:
        return "public"

    # Strip IPv6 brackets for parsing.
    bare = hostname.strip("[]").lower()

    if bare in _LOCALHOST_NAMES:
        return "local"

    # *.local mDNS hostnames are private-scope.
    if bare.endswith(".local"):
        return "private"

    # Try parsing as an IP address.
    try:
        addr = ipaddress.ip_address(bare)
    except ValueError:
        # Not an IP literal — treat non-special hostnames as public.
        return "public"

    for net in _LOOPBACK_NETWORKS:
        if addr in net:
            return "local"

    for net in (*_PRIVATE_NETWORKS, *_LINK_LOCAL_NETWORKS):
        if addr in net:
            return "private"

    return "public"


# ── Auth-signal helpers ────────────────────────────────────────────────────────


def _has_auth_in_headers(server: ServerConfig) -> bool:
    """Return True if the server has at least one authentication header."""
    return any(key.lower() in _AUTH_HEADER_NAMES for key in server.headers)


def _has_auth_in_raw_fields(raw: dict) -> bool:
    """Return True if any top-level field in *raw* signals auth configuration.

    Checks field names only — values are never examined (security invariant:
    env values are never read or stored).
    """
    return any(key.lower() in _AUTH_FIELD_NAMES for key in raw)


def _has_oauth_in_raw(raw: dict) -> bool:
    """Return True if any top-level field in *raw* indicates an OAuth block."""
    return any(key.lower() in _OAUTH_FIELD_NAMES for key in raw)


def _has_auth_signal(server: ServerConfig) -> bool:
    """Return True if the server config contains any recognisable auth signal.

    Auth signals (any one suppresses AUTH-001):
    - An authentication header in ``server.headers``
    - A token/auth/key field in the raw server entry
    - An OAuth-related field in the raw server entry
    - URL userinfo (``https://user:pass@host``) — presence of a non-empty
      ``netloc`` with an ``@`` is treated as auth; the credentials analyzer
      will separately flag this as CRED-001.
    """
    if _has_auth_in_headers(server):
        return True
    if _has_auth_in_raw_fields(server.raw):
        return True
    if _has_oauth_in_raw(server.raw):
        return True
    # URL userinfo: https://user:pass@host or https://token@host
    if server.url:
        try:
            parsed = urlparse(server.url)
        except Exception:  # noqa: BLE001, S110
            return False
        if parsed.username:
            return True
    return False


def _is_remote_transport(server: ServerConfig) -> bool:
    """Return True if the server uses an HTTP-based (remote) transport."""
    return server.transport in (
        TransportType.SSE,
        TransportType.STREAMABLE_HTTP,
    ) or (
        # UNKNOWN transport with an explicit URL is also treated as remote.
        server.transport == TransportType.UNKNOWN and bool(server.url)
    )


# ── Analyzer ──────────────────────────────────────────────────────────────────


class AuthAnalyzer(BaseAnalyzer):
    """Check authentication configuration of remote MCP servers.

    Per-server checks:

    AUTH-001 — Remote server with no authentication material in config.
        Severity tiered by host visibility (HIGH for public, MEDIUM for
        private).  Localhost servers are exempt (local trust boundary).
        stdio servers never fire.
    """

    @property
    def name(self) -> str:
        return "auth"

    @property
    def description(self) -> str:
        return "Check authentication configuration of remote MCP servers"

    def analyze(self, server: ServerConfig) -> list[Finding]:
        findings: list[Finding] = []

        if _is_remote_transport(server):
            finding = self._check_auth001(server)
            if finding is not None:
                findings.append(finding)

        return findings

    # ── AUTH-001 ───────────────────────────────────────────────────────────────

    def _check_auth001(self, server: ServerConfig) -> Finding | None:
        """Emit AUTH-001 when a remote server has no authentication material."""
        if not server.url:
            return None

        if _has_auth_signal(server):
            return None

        try:
            parsed = urlparse(server.url)
            hostname = parsed.hostname or ""
        except Exception:  # noqa: BLE001
            return None

        host_class = _classify_host(hostname)

        if host_class == "local":
            return None

        if host_class == "private":
            severity = Severity.MEDIUM
            severity_rationale = (
                "The server is reachable within its network segment"
                " (RFC 1918 / *.local address). Any machine on the same"
                " network can call every tool it exposes."
            )
        else:
            severity = Severity.HIGH
            severity_rationale = (
                "The server is internet-routable. A measurement study"
                " (arXiv 2605.22333) found 40.55% of 7,973 live remote MCP"
                " servers require no authentication; Censys counted 12,520"
                " internet-exposed MCP services, the majority unauthenticated."
            )

        return Finding(
            id="AUTH-001",
            severity=severity,
            analyzer=self.name,
            client=server.client,
            server=server.name,
            title="Remote MCP server configured without authentication",
            description=(
                f"Server '{server.name}' uses a remote transport"
                f" ({server.url}) but its configuration carries no"
                " authentication material — no Authorization/x-api-key"
                " header, no token/apiKey/auth field, and no OAuth settings."
                f" {severity_rationale}"
                " Anyone who can reach the URL can invoke every tool this"
                " server exposes."
            ),
            evidence=(
                f"Server: {server.name} | Host: {hostname or server.url}"
                " | No authentication material found in config"
            ),
            remediation=(
                "Add an Authorization header (e.g."
                " 'Authorization: Bearer ${TOKEN}'), an x-api-key header,"
                " or configure OAuth settings in the server entry."
                " Consider IP-allowlisting or VPN for additional defence."
            ),
            cwe="CWE-306",
            owasp_mcp_top_10=["MCP06"],
        )
