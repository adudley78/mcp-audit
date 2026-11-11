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

from mcp_audit.lock.core import (  # noqa: F401 — re-exported; one implementation
    LOCK_FILENAME,
    _find_git_root,
    find_lock_for,
)
