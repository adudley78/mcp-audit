"""Risk scoring for shadow MCP servers.

Produces a :class:`RiskLevel` for a single server by:

1. Querying the registry for capability data.  If the registry entry exists
   but has ``capabilities=None`` (data not yet collected), returns
   :attr:`RiskLevel.UNKNOWN`.
2. Calling :func:`~mcp_audit.analyzers.toxic_flow.tag_server` to get
   capability tags.
3. Checking all :data:`~mcp_audit.analyzers.toxic_flow.TOXIC_PAIRS` for
   single-server self-pairs (a server that holds *both* the source and sink
   capability is at least as dangerous as a two-server combination).
4. Taking the highest matched toxic-pair severity as the risk level.
5. Defaulting to ``LOW`` when capability tags exist but no toxic pair fires,
   and ``INFO`` when the capability set is explicitly empty (registry entry
   with ``capabilities=[]`` — verified-benign server with no capabilities).

RiskLevel mirrors :class:`~mcp_audit.models.Severity` but adds ``UNKNOWN``
for the case where capability data is unavailable.
"""

from __future__ import annotations

from enum import StrEnum

from mcp_audit.analyzers.toxic_flow import TOXIC_PAIRS, tag_server
from mcp_audit.models import ServerConfig, Severity
from mcp_audit.registry.loader import KnownServerRegistry


class RiskLevel(StrEnum):
    """Risk level for a shadow server — mirrors Severity plus UNKNOWN."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    UNKNOWN = "UNKNOWN"


# Mapping Severity → RiskLevel for toxic-pair results.
_SEVERITY_TO_RISK: dict[Severity, RiskLevel] = {
    Severity.CRITICAL: RiskLevel.CRITICAL,
    Severity.HIGH: RiskLevel.HIGH,
    Severity.MEDIUM: RiskLevel.MEDIUM,
    Severity.LOW: RiskLevel.LOW,
    Severity.INFO: RiskLevel.INFO,
}

# Precedence order for merging (higher index = lower precedence).
_RISK_ORDER: list[RiskLevel] = [
    RiskLevel.CRITICAL,
    RiskLevel.HIGH,
    RiskLevel.MEDIUM,
    RiskLevel.LOW,
    RiskLevel.INFO,
    RiskLevel.UNKNOWN,
]


def score_risk(
    server: ServerConfig,
    registry: KnownServerRegistry | None,
) -> tuple[RiskLevel, str]:
    """Compute the risk level and a short human-readable rationale.

    The returned tuple is ``(risk_level, rationale)`` where *rationale* is a
    one-liner suitable for terminal display (e.g.
    ``"HIGH — toxic flow (database + network)"``).

    Args:
        server: The server to score.
        registry: Pre-loaded registry for capability lookups.  ``None``
            triggers pure heuristic mode.

    Returns:
        ``(RiskLevel, rationale_string)``
    """
    # ── Registry probe ────────────────────────────────────────────────────────
    # If the registry has an entry for this server but capabilities=None, we
    # cannot determine the risk — return UNKNOWN rather than guessing.
    if registry is not None:
        registry_entry_caps_null = False
        for token in [server.command or "", *server.args, server.name]:
            if not token:
                continue
            entry = registry.get(token)
            if entry is not None:
                if entry.capabilities is None:
                    registry_entry_caps_null = True
                break
        if registry_entry_caps_null:
            return (
                RiskLevel.UNKNOWN,
                "UNKNOWN — capability tags missing; "
                "file an issue at https://github.com/adudley78/mcp-audit "
                "to request registry enrichment",
            )

    # ── Capability tagging ────────────────────────────────────────────────────
    caps = tag_server(server, registry=registry)

    # If no capability data at all, we cannot score meaningfully.
    if not caps:
        # Distinguish between a verified-empty cap set (registry says []) and
        # genuinely unknown (no registry entry, no keyword hits).
        has_registry_entry = False
        if registry is not None:
            for token in [server.command or "", *server.args, server.name]:
                if not token:
                    continue
                if registry.get(token) is not None:
                    has_registry_entry = True
                    break
        if has_registry_entry:
            return RiskLevel.INFO, "INFO — no dangerous capabilities detected"
        return RiskLevel.UNKNOWN, "UNKNOWN — no capability data available"

    # ── Toxic pair check (single-server self-pairs) ───────────────────────────
    highest: RiskLevel | None = None
    highest_label = ""

    for tp in TOXIC_PAIRS:
        if tp.source in caps and tp.sink in caps:
            candidate = _SEVERITY_TO_RISK[tp.severity]
            is_higher = highest is None or _RISK_ORDER.index(
                candidate
            ) < _RISK_ORDER.index(highest)
            if is_higher:
                highest = candidate
                highest_label = (
                    f"{candidate.value} — toxic flow "
                    f"({tp.source.value.replace('_', '-')} + "
                    f"{tp.sink.value.replace('_', '-')})"
                )

    if highest is not None:
        return highest, highest_label

    # No toxic pair fired — non-empty cap set, no dangerous combination.
    cap_list = ", ".join(sorted(c.value.replace("_", "-") for c in caps))
    return RiskLevel.LOW, f"LOW — capabilities: {cap_list}"
