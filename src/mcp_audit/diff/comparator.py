"""Compare two ServerConfig lists and produce a flat list of Change objects."""

from __future__ import annotations

import re
from enum import StrEnum
from urllib.parse import urlparse

from pydantic import BaseModel, Field

from mcp_audit.analyzers.credentials import SECRET_PATTERNS
from mcp_audit.models import ServerConfig, Severity


class ChangeType(StrEnum):
    """The kind of change detected."""

    ADDED = "added"
    REMOVED = "removed"
    CHANGED = "changed"


class EntityType(StrEnum):
    """The MCP entity that changed."""

    SERVER = "server"
    TOOL = "tool"
    CAPABILITY = "capability"
    ENV_VAR = "env_var"
    ENDPOINT = "endpoint"
    CREDENTIAL = "credential"


class Change(BaseModel):
    """A single MCP-aware change between base and head."""

    change_type: ChangeType
    entity_type: EntityType
    entity_name: str
    parent_server: str | None = None
    before: dict | str | None = None
    after: dict | str | None = None
    severity: Severity
    owasp_mcp_top_10: list[str] = Field(default_factory=list)
    # Populated for command/args changes on server entities.
    command_diff: dict | None = None


# ── Helpers ────────────────────────────────────────────────────────────────────

_URL_RE = re.compile(r"https?://[^\s\"'<>]+")

_HIGH_VALUE_ENV_PREFIXES: frozenset[str] = frozenset(
    {
        "AWS_",
        "AZURE_",
        "GOOGLE_",
        "GCP_",
        "GITHUB_",
        "GH_",
    }
)

_HIGH_VALUE_ENV_KEYWORDS: frozenset[str] = frozenset(
    {
        "AWS_ACCESS_KEY",
        "AWS_SECRET",
        "AWS_SESSION_TOKEN",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "AZURE_CLIENT_SECRET",
        "AZURE_STORAGE_KEY",
        "GITHUB_TOKEN",
        "GH_TOKEN",
    }
)

_HIGH_VALUE_PROVIDERS = {
    "AWS": frozenset({"AWS_"}),
    "GCP": frozenset({"GOOGLE_", "GCP_"}),
    "Azure": frozenset({"AZURE_"}),
    "GitHub": frozenset({"GITHUB_", "GH_"}),
}


def _classify_env_key(key: str) -> tuple[bool, str]:
    """Return ``(is_high_value, provider)`` for a given env-var key name."""
    ku = key.upper()
    for provider, prefixes in _HIGH_VALUE_PROVIDERS.items():
        for prefix in prefixes:
            if ku.startswith(prefix):
                return True, provider
    return False, ""


def _extract_external_urls(server: ServerConfig) -> list[str]:
    """Extract non-localhost HTTP/HTTPS URLs from a server's url and args."""
    urls: list[str] = []
    candidates: list[str] = []

    if server.url:
        candidates.append(server.url)
    candidates.extend(server.args)

    for candidate in candidates:
        for match in _URL_RE.findall(candidate):
            parsed = urlparse(match)
            host = (parsed.hostname or "").strip("[]")
            # nosec S104 — detection pattern, not a bind address
            if host and host not in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):  # noqa: S104
                urls.append(match)
    return urls


def _has_hardcoded_cred(server: ServerConfig) -> tuple[bool, str, str]:
    """Return ``(found, secret_name, provider)`` if hardcoded creds appear in args.

    Checks env values as well — we want CRITICAL when the actual secret value is
    present, not just a reference key name.
    """
    args_str = " ".join(server.args)
    env_vals = " ".join(server.env.values())
    text = args_str + " " + env_vals
    for secret_name, pattern, provider in SECRET_PATTERNS:
        if pattern.search(text):
            return True, secret_name, provider
    return False, "", ""


def _server_fingerprint(server: ServerConfig) -> tuple[str, str]:
    """Return a stable fingerprint used for rename detection."""
    # Use command + first non-flag arg (the package name / script path)
    first_arg = next(
        (a for a in server.args if not a.startswith("-")),
        "",
    )
    return (server.command or "", first_arg)


def _tools_set(server: ServerConfig) -> frozenset[str]:
    """Extract tool names from raw server data (populated by --connect)."""
    tools: list[dict] = server.raw.get("tools", []) if server.raw else []
    return frozenset(t.get("name", "") for t in tools if isinstance(t, dict))


def _server_summary(server: ServerConfig) -> dict:
    """Compact dict representation of a server for before/after fields."""
    return {
        "name": server.name,
        "command": server.command,
        "args": server.args,
        "env_keys": sorted(server.env.keys()),
        "url": server.url,
        "transport": str(server.transport),
    }


# ── Change factories ───────────────────────────────────────────────────────────


def _changes_for_added_server(
    server: ServerConfig,
    base_servers: list[ServerConfig],
    head_servers: list[ServerConfig],
) -> list[Change]:
    """Produce Change objects for a newly-added server.

    Always produces a SERVER/ADDED change.  Additional sub-changes are
    emitted for hardcoded credentials (CRITICAL), high-value env-var
    references (HIGH), external endpoints (HIGH), and newly-created
    toxic-flow pairs (CRITICAL/HIGH).
    """
    changes: list[Change] = []

    # ── Top-level server change ───────────────────────────────────────────
    from mcp_audit.diff.risk import classify_added_server  # noqa: PLC0415

    server_severity = classify_added_server(server, base_servers, head_servers)
    changes.append(
        Change(
            change_type=ChangeType.ADDED,
            entity_type=EntityType.SERVER,
            entity_name=server.name,
            before=None,
            after=_server_summary(server),
            severity=server_severity,
            owasp_mcp_top_10=_owasp_for_server(server, server_severity),
        )
    )

    # ── Hardcoded credential in args/env values ───────────────────────────
    found, secret_name, provider = _has_hardcoded_cred(server)
    if found:
        changes.append(
            Change(
                change_type=ChangeType.ADDED,
                entity_type=EntityType.CREDENTIAL,
                entity_name=secret_name,
                parent_server=server.name,
                before=None,
                after={"provider": provider, "location": "args/env-value"},
                severity=Severity.CRITICAL,
                owasp_mcp_top_10=["MCP01"],
            )
        )

    # ── High-value env-var key references ────────────────────────────────
    for key in server.env:
        is_hv, provider = _classify_env_key(key)
        if is_hv:
            changes.append(
                Change(
                    change_type=ChangeType.ADDED,
                    entity_type=EntityType.ENV_VAR,
                    entity_name=key,
                    parent_server=server.name,
                    before=None,
                    after={"provider": provider},
                    severity=Severity.HIGH,
                    owasp_mcp_top_10=["MCP01"],
                )
            )

    # ── External endpoints ────────────────────────────────────────────────
    for url in _extract_external_urls(server):
        changes.append(
            Change(
                change_type=ChangeType.ADDED,
                entity_type=EntityType.ENDPOINT,
                entity_name=urlparse(url).hostname or url,
                parent_server=server.name,
                before=None,
                after={"url": url},
                severity=Severity.HIGH,
                owasp_mcp_top_10=["MCP07"],
            )
        )

    # ── New toxic-flow pairs ──────────────────────────────────────────────
    changes.extend(_new_toxic_pair_changes(server, base_servers, head_servers))

    return changes


def _changes_for_removed_server(server: ServerConfig) -> list[Change]:
    """Produce a single Change for a removed server (always INFO)."""
    return [
        Change(
            change_type=ChangeType.REMOVED,
            entity_type=EntityType.SERVER,
            entity_name=server.name,
            before=_server_summary(server),
            after=None,
            severity=Severity.INFO,
            owasp_mcp_top_10=[],
        )
    ]


def _changes_for_modified_server(
    base: ServerConfig,
    head: ServerConfig,
    base_servers: list[ServerConfig],
    head_servers: list[ServerConfig],
) -> list[Change]:
    """Produce Change objects when a server exists in both base and head but differs.

    A SERVER/CHANGED change is always emitted when there are any differences.
    Sub-changes are produced for specific field mutations that carry security
    significance.
    """
    changes: list[Change] = []
    field_changes: list[str] = []

    # ── Command / args diff ───────────────────────────────────────────────
    cmd_diff: dict | None = None
    if base.command != head.command or base.args != head.args:
        cmd_diff = {
            "before_command": base.command,
            "after_command": head.command,
            "before_args": base.args,
            "after_args": head.args,
        }
        field_changes.append("command/args")

    if base.url != head.url:
        field_changes.append("url")

    # ── Env-var changes ───────────────────────────────────────────────────
    base_keys = set(base.env.keys())
    head_keys = set(head.env.keys())

    added_keys = head_keys - base_keys
    removed_keys = base_keys - head_keys
    # Changed values for keys present in both
    changed_keys = {k for k in base_keys & head_keys if base.env[k] != head.env[k]}

    if added_keys or removed_keys or changed_keys:
        field_changes.append("env")

    # ── Tool changes (from live enumeration data) ─────────────────────────
    base_tools = _tools_set(base)
    head_tools = _tools_set(head)
    added_tools = head_tools - base_tools
    removed_tools = base_tools - head_tools

    if added_tools or removed_tools:
        field_changes.append("tools")

    # Nothing changed — skip entirely (handles whitespace-only JSON edits too)
    if not field_changes:
        return []

    # ── Top-level server CHANGED change ──────────────────────────────────
    from mcp_audit.diff.risk import classify_modified_server  # noqa: PLC0415

    server_severity = classify_modified_server(
        base, head, base_servers, head_servers, field_changes
    )
    changes.append(
        Change(
            change_type=ChangeType.CHANGED,
            entity_type=EntityType.SERVER,
            entity_name=head.name,
            before=_server_summary(base),
            after=_server_summary(head),
            severity=server_severity,
            owasp_mcp_top_10=_owasp_for_modified(field_changes),
            command_diff=cmd_diff,
        )
    )

    # ── Sub-change: added env-var references ────────────────────────────
    for key in sorted(added_keys | changed_keys):
        is_hv, provider = _classify_env_key(key)
        sev = Severity.HIGH if is_hv else Severity.MEDIUM
        owasp = ["MCP01"] if is_hv else []
        change_type = ChangeType.ADDED if key in added_keys else ChangeType.CHANGED
        changes.append(
            Change(
                change_type=change_type,
                entity_type=EntityType.ENV_VAR,
                entity_name=key,
                parent_server=head.name,
                before=None if key in added_keys else {"key": key},
                after={"key": key, "provider": provider} if is_hv else {"key": key},
                severity=sev,
                owasp_mcp_top_10=owasp,
            )
        )

    # ── Sub-change: hardcoded credential introduced in head args/env ──────
    base_found, _, _ = _has_hardcoded_cred(base)
    head_found, secret_name, provider = _has_hardcoded_cred(head)
    if head_found and not base_found:
        changes.append(
            Change(
                change_type=ChangeType.ADDED,
                entity_type=EntityType.CREDENTIAL,
                entity_name=secret_name,
                parent_server=head.name,
                before=None,
                after={"provider": provider, "location": "args/env-value"},
                severity=Severity.CRITICAL,
                owasp_mcp_top_10=["MCP01"],
            )
        )

    # ── Sub-change: new external endpoint ────────────────────────────────
    base_endpoints = set(_extract_external_urls(base))
    head_endpoints = set(_extract_external_urls(head))
    for url in head_endpoints - base_endpoints:
        changes.append(
            Change(
                change_type=ChangeType.ADDED,
                entity_type=EntityType.ENDPOINT,
                entity_name=urlparse(url).hostname or url,
                parent_server=head.name,
                before=None,
                after={"url": url},
                severity=Severity.HIGH,
                owasp_mcp_top_10=["MCP07"],
            )
        )

    # ── Sub-change: added tools ───────────────────────────────────────────
    for tool_name in sorted(added_tools):
        changes.append(
            Change(
                change_type=ChangeType.ADDED,
                entity_type=EntityType.TOOL,
                entity_name=tool_name,
                parent_server=head.name,
                before=None,
                after={"tool": tool_name},
                severity=Severity.MEDIUM,
                owasp_mcp_top_10=[],
            )
        )

    return changes


def _new_toxic_pair_changes(
    new_server: ServerConfig,
    base_servers: list[ServerConfig],
    head_servers: list[ServerConfig],
) -> list[Change]:
    """Detect new toxic-flow pairs introduced by *new_server*.

    A pair is "new" if the partner server was already present in *base_servers*
    (so the pair couldn't have existed before *new_server* was added).
    """
    from mcp_audit.analyzers.toxic_flow import TOXIC_PAIRS, tag_server  # noqa: PLC0415

    new_caps = tag_server(new_server)
    if not new_caps:
        return []

    base_names = {s.name for s in base_servers}
    changes: list[Change] = []

    for existing in head_servers:
        if existing.name == new_server.name:
            continue
        if existing.name not in base_names and new_server.name > existing.name:
            # Both are new — pair wasn't possible before either way, report once
            # when the lexicographically-first server is processed.
            continue

        existing_caps = tag_server(existing)
        for pair in TOXIC_PAIRS:
            if (pair.source in new_caps and pair.sink in existing_caps) or (
                pair.source in existing_caps and pair.sink in new_caps
            ):
                changes.append(
                    Change(
                        change_type=ChangeType.ADDED,
                        entity_type=EntityType.CAPABILITY,
                        entity_name=f"{pair.finding_id}:{new_server.name}+{existing.name}",
                        parent_server=new_server.name,
                        before=None,
                        after={
                            "toxic_pair": pair.finding_id,
                            "source_server": new_server.name,
                            "sink_server": existing.name,
                            "title": pair.title,
                        },
                        severity=pair.severity,
                        owasp_mcp_top_10=list(pair.owasp_mcp_top_10),
                    )
                )
    return changes


def _owasp_for_server(server: ServerConfig, severity: Severity) -> list[str]:
    """Heuristic OWASP MCP Top 10 codes for an added server."""
    codes: list[str] = []
    if severity == Severity.CRITICAL:
        codes.append("MCP01")
    if server.url:
        codes.append("MCP07")
    return codes


def _owasp_for_modified(field_changes: list[str]) -> list[str]:
    codes: list[str] = []
    if "env" in field_changes:
        codes.append("MCP01")
    if "url" in field_changes:
        codes.append("MCP07")
    return codes


# ── Public API ─────────────────────────────────────────────────────────────────


def compare(
    base: list[ServerConfig],
    head: list[ServerConfig],
) -> list[Change]:
    """Compare two server lists and return a flat list of MCP-aware changes.

    Rename detection: if a server name changes but the command + first
    non-flag arg remain the same, the change is reported as CHANGED (not
    REMOVED + ADDED).

    Tool-order changes and non-MCP whitespace edits produce no diff.

    Args:
        base: Server configurations at the earlier state (PR base).
        head: Server configurations at the later state (PR head).

    Returns:
        Flat list of :class:`Change` objects, sorted by severity (CRITICAL
        first) then entity type.
    """
    base_by_name = {s.name: s for s in base}
    head_by_name = {s.name: s for s in head}

    base_names = set(base_by_name)
    head_names = set(head_by_name)

    added_names = head_names - base_names
    removed_names = base_names - head_names
    common_names = base_names & head_names

    # ── Rename detection ──────────────────────────────────────────────────
    renames: dict[str, str] = {}  # old_name → new_name
    unmatched_added = list(added_names)
    for old_name in list(removed_names):
        fp = _server_fingerprint(base_by_name[old_name])
        if fp == ("", ""):
            continue
        for new_name in unmatched_added:
            if _server_fingerprint(head_by_name[new_name]) == fp:
                renames[old_name] = new_name
                unmatched_added.remove(new_name)
                break

    renamed_old = set(renames.keys())
    renamed_new = set(renames.values())
    truly_added = added_names - renamed_new
    truly_removed = removed_names - renamed_old

    changes: list[Change] = []

    for name in sorted(truly_removed):
        changes.extend(_changes_for_removed_server(base_by_name[name]))

    for name in sorted(truly_added):
        changes.extend(_changes_for_added_server(head_by_name[name], base, head))

    for old_name, new_name in sorted(renames.items()):
        # Treat renamed servers as modified; surface the name change in before/after
        head_server = head_by_name[new_name]
        base_server = base_by_name[old_name]
        sub = _changes_for_modified_server(base_server, head_server, base, head)
        if sub:
            changes.extend(sub)
        else:
            # Only the name changed
            changes.append(
                Change(
                    change_type=ChangeType.CHANGED,
                    entity_type=EntityType.SERVER,
                    entity_name=new_name,
                    before=_server_summary(base_server),
                    after=_server_summary(head_server),
                    severity=Severity.INFO,
                    owasp_mcp_top_10=[],
                )
            )

    for name in sorted(common_names):
        changes.extend(
            _changes_for_modified_server(
                base_by_name[name], head_by_name[name], base, head
            )
        )

    # Sort by severity (CRITICAL first) then entity type
    _order = [
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
    ]
    changes.sort(key=lambda c: (_order.index(c.severity), c.entity_type))
    return changes
