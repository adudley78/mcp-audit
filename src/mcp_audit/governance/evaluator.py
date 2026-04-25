"""Evaluate discovered server configs against a governance policy.

Produces :class:`~mcp_audit.models.Finding` objects (``analyzer="governance"``)
for every policy violation found.  All standard output formatters consume
governance findings automatically because they are plain ``Finding`` objects.
"""

from __future__ import annotations

import fnmatch
import hashlib
from typing import TYPE_CHECKING

from mcp_audit.governance.models import (
    ApprovedServerEntry,
    ApprovedServers,
    ClientOverride,
    GovernancePolicy,
    PolicyMode,
    TransportPolicy,
)
from mcp_audit.models import Finding, ScanResult, Severity, TransportType

if TYPE_CHECKING:
    from mcp_audit.models import ServerConfig
    from mcp_audit.registry.loader import KnownServerRegistry

# ── Source detection helpers ───────────────────────────────────────────────────

_NPM_COMMANDS = frozenset({"npx", "node", "npm"})
_PIP_COMMANDS = frozenset({"python", "python3", "uvx", "uv", "pip", "pipx"})


def _infer_source(server: ServerConfig) -> str | None:
    """Infer the package ecosystem from the server's launch command.

    Args:
        server: Server configuration to inspect.

    Returns:
        ``"npm"``, ``"pip"``, or ``None`` when the source cannot be
        determined.
    """
    if not server.command:
        return None
    base = server.command.split("/")[-1].lower()
    if base in _NPM_COMMANDS:
        return "npm"
    if base in _PIP_COMMANDS:
        return "pip"
    return None


def _server_identifier(server: ServerConfig) -> str:
    """Return the primary identifier used to match a server against policy entries.

    Prefers the server name; falls back to the command basename.

    Args:
        server: Server configuration.

    Returns:
        A string to match against :attr:`ApprovedServerEntry.name`.
    """
    return server.name


def _is_http_unencrypted(server: ServerConfig) -> bool:
    """Return True when the server uses an unencrypted HTTP transport.

    Args:
        server: Server configuration to check.

    Returns:
        ``True`` when the server URL starts with ``http://`` (not ``https://``).
    """
    if server.transport not in (
        TransportType.STREAMABLE_HTTP,
        TransportType.SSE,
    ):
        return False
    if server.url and server.url.startswith("http://"):
        return True
    # SSE/HTTP servers without a URL are treated as potentially unencrypted.
    return server.transport == TransportType.STREAMABLE_HTTP and not server.url


# ── Entry matching ────────────────────────────────────────────────────────────


def _entry_matches(entry: ApprovedServerEntry, server: ServerConfig) -> bool:
    """Return True if *server* matches the policy *entry*.

    Matching rules:
    - ``entry.name`` may be an exact name or a ``fnmatch``-style glob.
    - When ``entry.source`` is set, the server's inferred source must match.

    Args:
        entry: Policy entry to match against.
        server: Server configuration to evaluate.

    Returns:
        ``True`` when the server satisfies all constraints in the entry.
    """
    identifier = _server_identifier(server)
    if not fnmatch.fnmatch(identifier, entry.name):
        return False
    if entry.source is not None:
        inferred = _infer_source(server)
        if inferred != entry.source:
            return False
    return True


# ── Finding construction helpers ──────────────────────────────────────────────


def _governance_finding_id(rule_type: str, server_name: str, client: str) -> str:
    """Produce a deterministic finding ID for a governance violation.

    Uses a short SHA-256 prefix so the ID is stable across runs for the same
    (rule_type, server_name, client) triple.

    Args:
        rule_type: e.g. ``"approved_servers"``, ``"transport"``.
        server_name: Name of the affected server.
        client: Client name (e.g. ``"cursor"``).

    Returns:
        A string of the form ``GOV-<8-char-hex>``.
    """
    digest = hashlib.sha256(f"{rule_type}:{server_name}:{client}".encode()).hexdigest()[
        :8
    ]
    return f"GOV-{digest}"


def _sev(severity_str: str) -> Severity:
    """Convert a policy severity string to a :class:`~mcp_audit.models.Severity`.

    Falls back to :attr:`~mcp_audit.models.Severity.MEDIUM` for unrecognised
    strings so that a misconfigured policy is never silently ignored.

    Args:
        severity_str: Case-insensitive severity label from the policy.

    Returns:
        Matching :class:`~mcp_audit.models.Severity` enum value.
    """
    try:
        return Severity(severity_str.upper())
    except ValueError:
        return Severity.MEDIUM


# ── Effective policy resolution ────────────────────────────────────────────────


def _effective_approved_servers(
    base: ApprovedServers | None,
    override: ClientOverride | None,
) -> ApprovedServers | None:
    """Merge base approved_servers with any client-level override.

    When the client override defines its own ``approved_servers``, that
    replaces the base policy for entries/mode.  Any ``additional`` entries
    from the override are appended to the effective entry list so that
    client-specific servers can be permitted without rebuilding the whole list.

    Args:
        base: Base ``approved_servers`` policy block.
        override: Client-level override; may be ``None``.

    Returns:
        The effective :class:`ApprovedServers` to apply for this client, or
        ``None`` when no approved-servers policy applies.
    """
    if override is None or override.approved_servers is None:
        return base
    client_ap = override.approved_servers
    # Merge: use client override as primary, extend with its additional list.
    merged_entries = list(client_ap.entries) + list(client_ap.additional)
    # Also append base entries if not fully overriding.
    # (The client override replaces the mode/entries but base entries remain
    # accessible via the explicit 'additional' field in the base.)
    return ApprovedServers(
        mode=client_ap.mode,
        entries=merged_entries,
        violation_severity=client_ap.violation_severity,
        message=client_ap.message,
    )


def _effective_transport(
    base: TransportPolicy | None,
    override: ClientOverride | None,
) -> TransportPolicy | None:
    """Return effective transport policy for a client, merging any override.

    Args:
        base: Base transport policy.
        override: Client-level override.

    Returns:
        Effective :class:`TransportPolicy` or ``None``.
    """
    if override is None or override.transport_policy is None:
        return base
    return override.transport_policy


# ── Per-check evaluators ──────────────────────────────────────────────────────


def _check_approved_servers(
    servers: list[ServerConfig],
    policy: ApprovedServers,
) -> list[Finding]:
    """Evaluate approved/denied server lists.

    Args:
        servers: Server configurations to check (all from one client).
        policy: Effective ``approved_servers`` policy to apply.

    Returns:
        List of governance findings for each violation.
    """
    findings: list[Finding] = []
    all_entries = list(policy.entries) + list(policy.additional)

    for server in servers:
        matched = any(_entry_matches(e, server) for e in all_entries)

        if policy.mode == PolicyMode.ALLOWLIST and not matched:
            msg = policy.message.format(server_name=server.name)
            findings.append(
                Finding(
                    id=_governance_finding_id(
                        "approved_servers", server.name, server.client
                    ),
                    severity=_sev(policy.violation_severity),
                    analyzer="governance",
                    client=server.client,
                    server=server.name,
                    title=f"Unapproved server: {server.name}",
                    description=msg,
                    evidence=(
                        f"rule=approved_servers mode=allowlist "
                        f"server={server.name} client={server.client}"
                    ),
                    remediation=(
                        "Add this server to the approved_servers list in your "
                        "governance policy, or remove it from the configuration."
                    ),
                    finding_path=str(server.config_path),
                )
            )

        elif policy.mode == PolicyMode.DENYLIST and matched:
            msg = policy.message.format(server_name=server.name)
            findings.append(
                Finding(
                    id=_governance_finding_id("denylist", server.name, server.client),
                    severity=_sev(policy.violation_severity),
                    analyzer="governance",
                    client=server.client,
                    server=server.name,
                    title=f"Denied server in use: {server.name}",
                    description=msg,
                    evidence=(
                        f"rule=approved_servers mode=denylist "
                        f"server={server.name} client={server.client}"
                    ),
                    remediation=(
                        "Remove this server from your configuration — it is "
                        "explicitly forbidden by the governance policy."
                    ),
                    finding_path=str(server.config_path),
                )
            )

    return findings


def _check_transport(
    servers: list[ServerConfig],
    policy: TransportPolicy,
) -> list[Finding]:
    """Evaluate transport-type constraints.

    Args:
        servers: Server configurations to check.
        policy: Effective transport policy.

    Returns:
        Governance findings for each transport violation.
    """
    findings: list[Finding] = []
    for server in servers:
        transport = server.transport

        if transport == TransportType.STDIO and not policy.allow_stdio:
            findings.append(
                Finding(
                    id=_governance_finding_id(
                        "transport_stdio", server.name, server.client
                    ),
                    severity=_sev(policy.violation_severity),
                    analyzer="governance",
                    client=server.client,
                    server=server.name,
                    title=f"Stdio transport not permitted: {server.name}",
                    description=(
                        f"Server '{server.name}' uses stdio transport, which "
                        "is not allowed by the governance policy."
                    ),
                    evidence=(
                        f"rule=transport transport=stdio "
                        f"server={server.name} client={server.client} "
                        "allow_stdio=false"
                    ),
                    remediation=(
                        "Migrate this server to a permitted transport type, or "
                        "update the governance policy to allow stdio."
                    ),
                    finding_path=str(server.config_path),
                )
            )

        if transport == TransportType.SSE and not policy.allow_sse:
            findings.append(
                Finding(
                    id=_governance_finding_id(
                        "transport_sse", server.name, server.client
                    ),
                    severity=_sev(policy.violation_severity),
                    analyzer="governance",
                    client=server.client,
                    server=server.name,
                    title=f"SSE transport not permitted: {server.name}",
                    description=(
                        f"Server '{server.name}' uses SSE transport, which "
                        "is not allowed by the governance policy."
                    ),
                    evidence=(
                        f"rule=transport transport=sse "
                        f"server={server.name} client={server.client} "
                        "allow_sse=false"
                    ),
                    remediation=(
                        "Migrate this server to a permitted transport type, or "
                        "update the governance policy to allow SSE."
                    ),
                    finding_path=str(server.config_path),
                )
            )

        if transport == TransportType.STREAMABLE_HTTP and not policy.allow_http:
            findings.append(
                Finding(
                    id=_governance_finding_id(
                        "transport_http_blocked", server.name, server.client
                    ),
                    severity=_sev(policy.violation_severity),
                    analyzer="governance",
                    client=server.client,
                    server=server.name,
                    title=f"HTTP transport not permitted: {server.name}",
                    description=(
                        f"Server '{server.name}' uses HTTP transport, which "
                        "is not allowed by the governance policy."
                    ),
                    evidence=(
                        f"rule=transport transport=http "
                        f"server={server.name} client={server.client} "
                        "allow_http=false"
                    ),
                    remediation=(
                        "Migrate this server to a permitted transport type or "
                        "update the governance policy."
                    ),
                    finding_path=str(server.config_path),
                )
            )

        # block_http: explicit flag; also triggered by require_tls on
        # unencrypted HTTP transports.
        if (policy.block_http or policy.require_tls) and _is_http_unencrypted(server):
            findings.append(
                Finding(
                    id=_governance_finding_id(
                        "transport_unencrypted_http", server.name, server.client
                    ),
                    severity=_sev(policy.violation_severity),
                    analyzer="governance",
                    client=server.client,
                    server=server.name,
                    title=f"Unencrypted HTTP transport: {server.name}",
                    description=(
                        f"Server '{server.name}' uses unencrypted HTTP. "
                        "The governance policy requires TLS / prohibits plain HTTP."
                    ),
                    evidence=(
                        f"rule=transport url={server.url or 'unknown'} "
                        f"server={server.name} client={server.client} "
                        f"block_http={policy.block_http} "
                        f"require_tls={policy.require_tls}"
                    ),
                    remediation=(
                        "Replace the server URL with an https:// endpoint, or "
                        "update the governance policy if HTTP is acceptable."
                    ),
                    finding_path=str(server.config_path),
                )
            )

    return findings


def _check_registry(
    servers: list[ServerConfig],
    policy_block: GovernancePolicy,
    registry: KnownServerRegistry,
) -> list[Finding]:
    """Evaluate Known-Server Registry membership requirements.

    Args:
        servers: Server configurations to check.
        policy_block: Root governance policy (provides registry_policy).
        registry: Populated :class:`~mcp_audit.registry.loader.KnownServerRegistry`.

    Returns:
        Governance findings for registry violations.
    """
    rp = policy_block.registry_policy
    if rp is None:
        return []

    findings: list[Finding] = []
    for server in servers:
        if rp.require_known and not registry.is_known(server.name):
            msg = rp.message.format(server_name=server.name)
            findings.append(
                Finding(
                    id=_governance_finding_id(
                        "registry_unknown", server.name, server.client
                    ),
                    severity=_sev(rp.violation_severity),
                    analyzer="governance",
                    client=server.client,
                    server=server.name,
                    title=f"Server not in Known-Server Registry: {server.name}",
                    description=msg,
                    evidence=(
                        f"rule=registry require_known=true "
                        f"server={server.name} in_registry=false"
                    ),
                    remediation=(
                        "Verify this server is legitimate and add it to your "
                        "registry, or update the governance policy."
                    ),
                    finding_path=str(server.config_path),
                )
            )
            # Can't be unverified if not known — skip require_verified check.
            continue

        if rp.require_verified and registry.is_known(server.name):
            # Look up the entry to check verified flag.
            entry = registry._name_index.get(server.name.lower())
            if entry is not None and not entry.verified:
                findings.append(
                    Finding(
                        id=_governance_finding_id(
                            "registry_unverified", server.name, server.client
                        ),
                        severity=_sev(rp.violation_severity),
                        analyzer="governance",
                        client=server.client,
                        server=server.name,
                        title=f"Server not verified in registry: {server.name}",
                        description=(
                            f"Server '{server.name}' is in the registry but "
                            "has not been verified."
                        ),
                        evidence=(
                            f"rule=registry require_verified=true "
                            f"server={server.name} verified=false"
                        ),
                        remediation=(
                            "Wait for the server to be verified, use a "
                            "verified alternative, or update the governance policy."
                        ),
                        finding_path=str(server.config_path),
                    )
                )

    return findings


def _check_score_threshold(
    servers: list[ServerConfig],
    policy_block: GovernancePolicy,
    client_name: str,
    override: ClientOverride | None,
    scan_result: ScanResult,
) -> list[Finding]:
    """Evaluate the minimum scan score threshold for a client group.

    Produces at most one finding per client — the score applies to the whole
    configuration, not per-server.

    Args:
        servers: Servers belonging to this client (used only for config_path).
        policy_block: Root governance policy.
        client_name: Client identifier string.
        override: Per-client override; may be ``None``.
        scan_result: Completed scan result containing the score.

    Returns:
        A list with zero or one :class:`~mcp_audit.models.Finding`.
    """
    if scan_result.score is None:
        return []

    threshold = None
    if override is not None and override.score_threshold is not None:
        threshold = override.score_threshold
    elif policy_block.score_threshold is not None:
        threshold = policy_block.score_threshold

    if threshold is None:
        return []

    actual = scan_result.score.numeric_score
    grade = scan_result.score.grade

    if actual >= threshold.minimum:
        return []

    msg = threshold.message.format(
        score=actual,
        grade=grade,
        minimum=threshold.minimum,
    )

    # Use the config_path from the first server in this client group.
    config_path = str(servers[0].config_path) if servers else None

    return [
        Finding(
            id=_governance_finding_id("score_threshold", client_name, client_name),
            severity=_sev(threshold.violation_severity),
            analyzer="governance",
            client=client_name,
            server="(all servers)",
            title=(
                f"Score below threshold for {client_name}: "
                f"{actual} < {threshold.minimum}"
            ),
            description=msg,
            evidence=(
                f"rule=score_threshold score={actual} grade={grade} "
                f"minimum={threshold.minimum} client={client_name}"
            ),
            remediation=(
                "Resolve the security findings in this configuration to "
                "raise the score above the governance threshold."
            ),
            finding_path=config_path,
        )
    ]


def _check_finding_policy(
    scan_result: ScanResult,
    policy_block: GovernancePolicy,
) -> list[Finding]:
    """Evaluate the finding count caps from ``finding_policy``.

    Counts findings by severity, excluding governance findings themselves
    (to avoid circular amplification).

    Args:
        scan_result: Completed scan result.
        policy_block: Root governance policy.

    Returns:
        Governance findings for each exceeded limit.
    """
    fp = policy_block.finding_policy
    if fp is None:
        return []

    non_gov = [f for f in scan_result.findings if f.analyzer != "governance"]

    counts = {
        Severity.CRITICAL: sum(1 for f in non_gov if f.severity == Severity.CRITICAL),
        Severity.HIGH: sum(1 for f in non_gov if f.severity == Severity.HIGH),
        Severity.MEDIUM: sum(1 for f in non_gov if f.severity == Severity.MEDIUM),
    }

    limits = {
        Severity.CRITICAL: fp.max_critical,
        Severity.HIGH: fp.max_high,
        Severity.MEDIUM: fp.max_medium,
    }

    findings: list[Finding] = []
    for sev, limit in limits.items():
        if limit is None:
            continue
        actual_count = counts[sev]
        if actual_count > limit:
            findings.append(
                Finding(
                    id=_governance_finding_id(
                        f"finding_policy_{sev.value.lower()}",
                        sev.value.lower(),
                        "fleet",
                    ),
                    severity=_sev(fp.violation_severity),
                    analyzer="governance",
                    client="(all clients)",
                    server="(all servers)",
                    title=(
                        f"Finding count exceeds policy limit: "
                        f"{actual_count} {sev.value.lower()} "
                        f"(max {limit})"
                    ),
                    description=(
                        f"The scan produced {actual_count} "
                        f"{sev.value.lower()} finding(s), exceeding the "
                        f"governance policy maximum of {limit}."
                    ),
                    evidence=(
                        f"rule=finding_policy severity={sev.value.lower()} "
                        f"actual={actual_count} limit={limit}"
                    ),
                    remediation=(
                        f"Resolve {sev.value.lower()} findings until the "
                        f"count is at or below {limit}, or adjust the policy "
                        "limit."
                    ),
                    finding_path=None,
                )
            )

    return findings


# ── Public entry point ─────────────────────────────────────────────────────────


def evaluate_governance(
    servers: list[ServerConfig],
    policy: GovernancePolicy,
    registry: KnownServerRegistry | None = None,
    scan_result: ScanResult | None = None,
) -> list[Finding]:
    """Evaluate all discovered server configs against the governance policy.

    Returns a flat list of :class:`~mcp_audit.models.Finding` objects, one
    per violation.

    Args:
        servers: All discovered server configurations (from all clients).
        policy: Validated governance policy to enforce.
        registry: Optional registry for registry membership checks.
        scan_result: Optional completed scan result; required for score
            threshold and finding policy checks.

    Returns:
        List of governance :class:`~mcp_audit.models.Finding` objects.
    """
    findings: list[Finding] = []

    # Group servers by client for per-client policy resolution.
    clients: dict[str, list[ServerConfig]] = {}
    for server in servers:
        clients.setdefault(server.client, []).append(server)

    for client_name, client_servers in clients.items():
        override = policy.client_overrides.get(client_name)

        # ── Approved servers ───────────────────────────────────────────────
        effective_ap = _effective_approved_servers(policy.approved_servers, override)
        if effective_ap is not None:
            findings.extend(_check_approved_servers(client_servers, effective_ap))

        # ── Transport policy ───────────────────────────────────────────────
        effective_tp = _effective_transport(policy.transport_policy, override)
        if effective_tp is not None:
            findings.extend(_check_transport(client_servers, effective_tp))

        # ── Score threshold ────────────────────────────────────────────────
        if scan_result is not None:
            findings.extend(
                _check_score_threshold(
                    client_servers,
                    policy,
                    client_name,
                    override,
                    scan_result,
                )
            )

    # ── Registry policy (cross-client, one check per server) ──────────────
    if registry is not None and policy.registry_policy is not None:
        findings.extend(_check_registry(servers, policy, registry))

    # ── Finding policy (aggregate, one check across all clients) ──────────
    if scan_result is not None and policy.finding_policy is not None:
        findings.extend(_check_finding_policy(scan_result, policy))

    # ── Propagate OWASP MCP Top 10 codes from the policy ──────────────────
    # When the policy declares owasp_mcp_top_10, attach those codes to every
    # governance finding so they flow through SARIF / JSON / terminal output.
    if policy.owasp_mcp_top_10:
        findings = [
            f.model_copy(update={"owasp_mcp_top_10": policy.owasp_mcp_top_10})
            for f in findings
        ]

    return findings
