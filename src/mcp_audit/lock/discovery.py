"""Locate the nearest ``mcp-lock.json`` for a given MCP config file.

Used by `check`/`scan`'s automatic lock verification (STORY-0070) and by the
pinning fix strategy to source a ``resolved_version`` without re-hitting the
network. Resolution walks upward from the config file's own directory the way
cascading config resolution does elsewhere (``.eslintrc``, ``.gitignore``) —
nearest ancestor wins.

The walk is bounded by the enclosing git repository root: outside a git repo
only the config's own directory is checked (no upward walk), so a bare
``mcp-lock.json`` living in an unrelated ancestor directory (e.g. the user's
home directory) is never picked up by accident. This mirrors the boundary
``governance/loader.py`` already uses for policy-file discovery, applied to
a *bottom-up* (nearest match wins) walk instead of governance's *fixed-stop*
(cwd, then repo root) walk — the two need different shapes because a
monorepo can have more than one lock file at different subtree depths, and
each project config must be checked against its own nearest one, not a
single repo-wide file.
"""

from __future__ import annotations

from pathlib import Path

from mcp_audit.lock.model import LOCK_FILENAME


def _find_git_root(start: Path) -> Path | None:
    """Walk parent directories until a ``.git`` entry is found.

    Args:
        start: Directory to begin the search from (already resolved).

    Returns:
        The directory containing ``.git``, or ``None`` if not found.
    """
    current = start
    while True:
        if (current / ".git").exists():
            return current
        parent = current.parent
        if parent == current:
            return None
        current = parent


def find_lock_for(config_path: Path) -> Path | None:
    """Return the nearest ancestor ``mcp-lock.json`` for *config_path*, if any.

    Args:
        config_path: Path to an MCP config file (need not exist on disk —
            only its parent directory is walked).

    Returns:
        The resolved path to the nearest ``mcp-lock.json``, or ``None`` if
        none was found. Outside a git repository, only *config_path*'s own
        directory is checked — see module docstring for the boundary
        rationale.
    """
    start = config_path.resolve().parent
    git_root = _find_git_root(start)

    if git_root is None:
        candidate = start / LOCK_FILENAME
        return candidate if candidate.exists() else None

    current = start
    while True:
        candidate = current / LOCK_FILENAME
        if candidate.exists():
            return candidate
        if current == git_root:
            return None
        parent = current.parent
        if parent == current:
            return None
        current = parent
