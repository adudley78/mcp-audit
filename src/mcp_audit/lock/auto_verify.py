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

from mcp_audit.lock.discovery import find_lock_for
from mcp_audit.lock.verifier import verify as verify_lock
from mcp_audit.models import Finding, LockStatus, ServerConfig

_DRIFT_IDS = frozenset({"LOCK-001", "LOCK-002", "LOCK-004", "LOCK-005"})


def auto_verify(servers: list[ServerConfig]) -> tuple[list[Finding], LockStatus]:
    """Verify each server's nearest ancestor ``mcp-lock.json``, if any exists.

    Groups servers by their nearest lock file (monorepo-safe: a subtree with
    its own lock is verified against that lock, never a parent's) and merges
    every group's :class:`~mcp_audit.lock.verifier.VerifyResult` into one
    flat finding list plus a summary :class:`~mcp_audit.models.LockStatus`.

    Args:
        servers: All servers discovered for this scan/check run.

    Returns:
        ``(findings, status)``. When no server has a discoverable lock file,
        ``status.present`` is ``False`` and *findings* is empty — the
        contract this story requires: a project with no ``mcp-lock.json``
        anywhere sees no behavior change at all.
    """
    groups: dict[Path, list[ServerConfig]] = {}
    for server in servers:
        lock_path = find_lock_for(server.config_path)
        if lock_path is None:
            continue
        groups.setdefault(lock_path, []).append(server)

    if not groups:
        return [], LockStatus()

    all_findings: list[Finding] = []
    total_checked = 0
    unresolved: list[str] = []
    unverified_sections: set[str] = set()
    for lock_path, group_servers in groups.items():
        result = verify_lock(lock_path, group_servers)
        all_findings.extend(result.findings)
        total_checked += result.checked_servers
        unresolved.extend(result.unresolved_entries)
        unverified_sections.update(result.unverified_sections)

    verified = not any(f.id in _DRIFT_IDS for f in all_findings)
    status = LockStatus(
        present=True,
        verified=verified,
        findings=len(all_findings),
        checked_servers=total_checked,
        lock_paths=sorted(str(p) for p in groups),
        unresolved_entries=unresolved,
        unverified_sections=sorted(unverified_sections),
    )
    return all_findings, status
