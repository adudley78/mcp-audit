"""Automatic, offline ``mcp-lock.json`` verification for ``check`` and ``scan``.

Shared by both commands (STORY-0070) so the "nearest ancestor lock, grouped,
merged into one status object" logic is implemented once. Always offline —
neither ``check`` nor ``scan`` passes ``--resolve``-equivalent network
resolution here; that stays an explicit, opt-in flag on the standalone
``mcp-audit lock --verify --resolve`` command (ADR-0005 §8, and this story's
own "do not add --resolve to check by default" constraint).
"""

from __future__ import annotations

from pathlib import Path

from mcp_audit.discovery import AGENT_DEFINITION_CLIENT, agent_definition_scope
from mcp_audit.gateways import GATEWAY_UPSTREAM_CLIENTS
from mcp_audit.lock.discovery import find_lock_for
from mcp_audit.lock.identity import MatchKey, match_key
from mcp_audit.lock.verifier import _index_locked_entries
from mcp_audit.lock.verifier import verify as verify_lock
from mcp_audit.lock.writer import load_existing
from mcp_audit.models import Finding, LockStatus, ServerConfig

#: Clients ``mcp-audit lock`` never records (it discovers with
#: ``include_plugins=False``), so verifying them could only report every one
#: as unrecorded (LOCK-002) and fail locks that predate their discovery.
#: ``claude-code-plugin`` includes skills-directory plugin servers, which can
#: sit inside a locked repository (``.claude/skills/<name>/.mcp.json``,
#: STORY-0095).  ``lock``'s project walk does read that ``.mcp.json`` (as
#: ``claude-code``), so a repository's such server is verified against the
#: entry for its config path when the lock has one.
#: MCP gateway upstreams (``<gateway>-upstream``, STORY-0111) are never
#: recorded either; a project-scoped one under a lock root is listed in
#: ``status.not_covered``.
_NOT_LOCKED_CLIENTS = frozenset({"claude-code-plugin"}) | GATEWAY_UPSTREAM_CLIENTS

_DRIFT_IDS = frozenset(
    {
        "LOCK-001",
        "LOCK-002",
        "LOCK-004",
        "LOCK-005",
        "LOCK-006",
        "LOCK-007",
        "LOCK-008",
        "LOCK-011",
    }
)


def auto_verify(servers: list[ServerConfig]) -> tuple[list[Finding], LockStatus]:
    """Verify each server's nearest ancestor ``mcp-lock.json``, if any exists.

    Groups servers by their nearest lock file (monorepo-safe: a subtree with
    its own lock is verified against that lock, never a parent's) and merges
    every group's :class:`~mcp_audit.lock.verifier.VerifyResult` into one
    flat finding list plus a summary :class:`~mcp_audit.models.LockStatus`.

    Each group is verified against its own lock file's directory as the lock
    root, which is what makes the ``(config, name)`` match key (R61) resolve
    to the same pair ``mcp-audit lock`` recorded — the grouping key *is* the
    root, since :func:`~mcp_audit.lock.discovery.find_lock_for` walks up from
    the config file to find it.

    Args:
        servers: All servers discovered for this scan/check run.

    Returns:
        ``(findings, status)``. When no server has a discoverable lock file,
        ``status.present`` is ``False`` and *findings* is empty — the
        contract this story requires: a project with no ``mcp-lock.json``
        anywhere sees no behavior change at all.

    Servers declared inline in a Claude Code subagent definition (client
    ``claude-code-agent``, STORY-0094) are skipped: ``mcp-audit lock`` never
    records them, so verifying them would turn every existing lock in a repo
    with a ``.claude/agents/`` server into a LOCK-002 failure. A project-scope
    one under a lock root is listed in ``status.not_covered`` instead (and the
    status counts as present), so ``check``/``scan`` can say the lock does not
    cover it.

    Plugin servers (client ``claude-code-plugin``) are skipped the same way:
    the lock never records them.  A repository's skills-directory plugin
    (``.claude/skills/<name>``, ``is_project_scoped``, STORY-0095) under a lock
    root is the exception: ``lock``'s project walk records its ``.mcp.json``,
    so when the lock has an entry for the server's (config path, name) it is
    verified like any other (drift is LOCK-001).  One with no entry (an inline
    ``plugin.json`` server, or a lock written before the plugin was added) is
    listed in ``status.not_covered``.  Installed plugins and the user's own
    skills-directory plugins stay silent.
    """
    groups: dict[Path, list[ServerConfig]] = {}
    not_covered: list[str] = []
    not_covered_locks: set[Path] = set()
    recorded: dict[Path, set[MatchKey]] = {}

    def lock_records(lock: Path, server: ServerConfig) -> bool:
        """Whether *lock* has an entry for *server*'s (config path, name)."""
        if lock not in recorded:
            doc = load_existing(lock)
            servers = doc.get("servers") if isinstance(doc, dict) else None
            try:
                recorded[lock] = set(
                    _index_locked_entries(servers if isinstance(servers, dict) else {})
                )
            except (AttributeError, TypeError, ValueError):
                recorded[lock] = set()  # malformed; `lock --verify` reports it
        match = match_key(server.config_path, lock.parent, server.name)
        return match is not None and match in recorded[lock]

    def note_not_covered(server: ServerConfig) -> None:
        try:
            lock = find_lock_for(server.config_path)
        except (OSError, RuntimeError):
            lock = None
        if lock is not None:
            not_covered.append(f"{server.client}/{server.name} ({server.config_path})")
            not_covered_locks.add(lock)

    for server in servers:
        if server.client in _NOT_LOCKED_CLIENTS:
            if server.is_project_scoped:
                try:
                    lock = find_lock_for(server.config_path)
                except (OSError, RuntimeError):
                    lock = None
                if lock is not None and lock_records(lock, server):
                    groups.setdefault(lock, []).append(server)
                else:
                    note_not_covered(server)
            continue
        if server.client == AGENT_DEFINITION_CLIENT:
            if agent_definition_scope(server.config_path) == "project":
                note_not_covered(server)
            continue
        lock_path = find_lock_for(server.config_path)
        if lock_path is None:
            continue
        groups.setdefault(lock_path, []).append(server)

    if not groups:
        if not_covered:
            return [], LockStatus(
                present=True,
                verified=True,
                lock_paths=sorted(str(p) for p in not_covered_locks),
                not_covered=sorted(not_covered),
            )
        return [], LockStatus()

    all_findings: list[Finding] = []
    total_checked = 0
    unresolved: list[str] = []
    unverified_sections: set[str] = set()
    outside_root: list[str] = []
    tools_recorded = 0
    newer_locks = False
    for lock_path, group_servers in groups.items():
        result = verify_lock(lock_path, group_servers, root=lock_path.parent)
        if result.unsupported_version is not None:
            # Nothing in it was checked: say so instead of "verified".
            newer_locks = True
            unverified_sections.add(
                f"lock_version {result.unsupported_version} "
                "(newer than this mcp-audit; upgrade it)"
            )
        all_findings.extend(result.findings)
        total_checked += result.checked_servers
        unresolved.extend(result.unresolved_entries)
        unverified_sections.update(result.unverified_sections)
        outside_root.extend(result.outside_root)
        tools_recorded += result.tools_recorded

    verified = not newer_locks and not any(f.id in _DRIFT_IDS for f in all_findings)
    status = LockStatus(
        present=True,
        verified=verified,
        findings=len(all_findings),
        checked_servers=total_checked,
        lock_paths=sorted(str(p) for p in set(groups) | not_covered_locks),
        unresolved_entries=unresolved,
        unverified_sections=sorted(unverified_sections),
        outside_root=sorted(set(outside_root)),
        tools_recorded=tools_recorded,
        not_covered=sorted(not_covered),
    )
    return all_findings, status
