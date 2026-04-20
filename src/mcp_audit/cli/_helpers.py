"""Shared helpers for ``mcp_audit.cli`` submodules.

Only truly cross-cutting utilities live here.  Per-command helpers stay in
their owning submodule.
"""

from __future__ import annotations

from pathlib import Path


def _write_output(path: Path, content: str) -> None:
    """Write *content* to *path*, creating parent directories as needed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
