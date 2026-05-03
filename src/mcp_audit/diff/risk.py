"""Risk classification for MCP diff changes."""

from __future__ import annotations

from mcp_audit.analyzers.toxic_flow import Capability, tag_server
from mcp_audit.models import ServerConfig, Severity

# Capabilities that immediately elevate an added server to HIGH severity.
_HIGH_RISK_CAPS: frozenset[Capability] = frozenset(
    {Capability.SHELL_EXEC, Capability.FILE_WRITE}
)

# Capabilities that combine to produce CRITICAL-risk patterns.
_CRITICAL_CAP_PAIRS: frozenset[frozenset[Capability]] = frozenset(
    {
        frozenset({Capability.SHELL_EXEC, Capability.NETWORK_OUT}),
        frozenset({Capability.SECRETS, Capability.NETWORK_OUT}),
    }
)


def _has_external_url(server: ServerConfig) -> bool:
    """Return True if the server references a non-localhost URL."""
    from mcp_audit.diff.comparator import _extract_external_urls  # noqa: PLC0415

    return bool(_extract_external_urls(server))


def _has_high_value_env_key(server: ServerConfig) -> bool:
    """Return True if any env key references a high-value credential provider."""
    from mcp_audit.diff.comparator import _classify_env_key  # noqa: PLC0415

    return any(_classify_env_key(k)[0] for k in server.env)


def _has_hardcoded_cred(server: ServerConfig) -> bool:
    """Return True if a hardcoded credential appears in args/env values."""
    from mcp_audit.diff.comparator import _has_hardcoded_cred as _hc  # noqa: PLC0415

    return _hc(server)[0]


def classify_added_server(
    server: ServerConfig,
    base_servers: list[ServerConfig],  # noqa: ARG001
    head_servers: list[ServerConfig],  # noqa: ARG001
) -> Severity:
    """Classify the severity of a newly-added server.

    Severity ladder (highest wins):
    - CRITICAL: hardcoded credentials in args/env values.
    - HIGH: shell-exec or filesystem-write capability; external endpoint;
      high-value credential env-var reference (AWS, GCP, Azure, GitHub).
    - LOW: everything else (sanctioned capabilities, no creds, no externals).

    Args:
        server: The newly-added server.
        base_servers: Full list of servers at base state (unused at this level;
            toxic-pair detection runs separately in comparator.py).
        head_servers: Full list of servers at head state (same note).

    Returns:
        The highest applicable :class:`Severity` for this server addition.
    """
    if _has_hardcoded_cred(server):
        return Severity.CRITICAL

    caps = tag_server(server)

    if _HIGH_RISK_CAPS & caps:
        return Severity.HIGH

    if _has_external_url(server):
        return Severity.HIGH

    if _has_high_value_env_key(server):
        return Severity.HIGH

    # New server with expanded capability surface (any non-trivial capability)
    if caps:
        return Severity.MEDIUM

    return Severity.LOW


def classify_modified_server(
    base: ServerConfig,
    head: ServerConfig,
    base_servers: list[ServerConfig],  # noqa: ARG001
    head_servers: list[ServerConfig],  # noqa: ARG001
    field_changes: list[str],
) -> Severity:
    """Classify the severity of a modified server.

    Severity ladder (highest wins):
    - CRITICAL: a hardcoded credential is newly introduced in head.
    - HIGH: a new external endpoint appears; a new high-value env-var
      reference is introduced.
    - MEDIUM: command/args changed; env changed; tools changed.
    - INFO: only cosmetic changes (name-only rename handled by caller).

    Args:
        base: Server configuration before the change.
        head: Server configuration after the change.
        base_servers: Full server list at base state.
        head_servers: Full server list at head state.
        field_changes: List of field names that differ between base and head.

    Returns:
        The highest applicable :class:`Severity` for this server modification.
    """
    from mcp_audit.diff.comparator import (  # noqa: PLC0415
        _classify_env_key,
        _extract_external_urls,
    )

    # CRITICAL: hardcoded credential introduced
    base_hc = _has_hardcoded_cred(base)
    head_hc = _has_hardcoded_cred(head)
    if head_hc and not base_hc:
        return Severity.CRITICAL

    # HIGH: new external endpoint
    base_urls = set(_extract_external_urls(base))
    head_urls = set(_extract_external_urls(head))
    if head_urls - base_urls:
        return Severity.HIGH

    # HIGH: newly-added high-value env-var reference
    base_env = set(base.env.keys())
    head_env = set(head.env.keys())
    new_keys = head_env - base_env
    changed_keys = {k for k in base_env & head_env if base.env[k] != head.env[k]}
    for key in new_keys | changed_keys:
        is_hv, _ = _classify_env_key(key)
        if is_hv:
            return Severity.HIGH

    # MEDIUM: structural changes
    if field_changes:
        return Severity.MEDIUM

    return Severity.INFO
