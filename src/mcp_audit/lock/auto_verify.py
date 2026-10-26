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
from mcp_audit.lock.discovery import find_lock_for
from mcp_audit.lock.verifier import verify as verify_lock
from mcp_audit.models import Finding, LockStatus, ServerConfig

_DRIFT_IDS = frozenset(
    {"LOCK-001", "LOCK-002", "LOCK-004", "LOCK-005", "LOCK-006", "LOCK-007", "LOCK-008"}
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
    """
    groups: dict[Path, list[ServerConfig]] = {}
    not_covered: list[str] = []
    not_covered_locks: set[Path] = set()
    for server in servers:
        if server.client == AGENT_DEFINITION_CLIENT:
            if agent_definition_scope(server.config_path) == "project":
                try:
                    agent_lock = find_lock_for(server.config_path)
                except (OSError, RuntimeError):
                    agent_lock = None
                if agent_lock is not None:
                    not_covered.append(
                        f"{server.client}/{server.name} ({server.config_path})"
                    )
                    not_covered_locks.add(agent_lock)
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
    for lock_path, group_servers in groups.items():
        result = verify_lock(lock_path, group_servers, root=lock_path.parent)
        all_findings.extend(result.findings)
        total_checked += result.checked_servers
        unresolved.extend(result.unresolved_entries)
        unverified_sections.update(result.unverified_sections)
        outside_root.extend(result.outside_root)
        tools_recorded += result.tools_recorded

    verified = not any(f.id in _DRIFT_IDS for f in all_findings)
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
