"""Resolve the bundled semgrep-rules/ directory in all execution contexts.

Resolution order handled by :func:`get_bundled_rules_path`:

1. PyInstaller ``_MEIPASS`` — when running as a frozen one-file binary the
   rules directory is extracted alongside other bundled data.
2. importlib.resources — for pip-installed wheels the rules are packaged at
   ``mcp_audit/semgrep-rules`` and discovered via :mod:`importlib.resources`.

The dev-repo-root fallback (``semgrep-rules/`` adjacent to ``src/``) is handled
upstream by :func:`~mcp_audit.sast.runner.find_rules_dir` so that the bundled
path resolver stays narrowly scoped to non-dev installations.
"""

from __future__ import annotations

from pathlib import Path

from mcp_audit._paths import resolve_bundled_resource


def get_bundled_rules_path() -> Path | None:
    """Return the semgrep-rules/ directory for PyInstaller or pip-installed builds.

    Checks (in order):

    1. PyInstaller ``_MEIPASS`` (frozen binary).
    2. importlib.resources (pip-installed wheel at ``mcp_audit/semgrep-rules``).

    Returns ``None`` in a dev / editable-install context where
    ``semgrep-rules/`` has not been copied into ``src/mcp_audit/``.
    The dev-repo-root path is handled by
    :func:`~mcp_audit.sast.runner.find_rules_dir`.
    """
    return resolve_bundled_resource(
        package="mcp_audit",
        subdir="semgrep-rules",
        frozen_subpath="semgrep-rules",
    )
