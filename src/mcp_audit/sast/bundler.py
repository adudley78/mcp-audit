"""Resolve the bundled semgrep-rules/ directory for PyInstaller builds."""

from __future__ import annotations

import sys
from pathlib import Path


def get_bundled_rules_path() -> Path | None:
    """Return path to semgrep-rules/ for PyInstaller builds.

    Returns None if not running inside a frozen (PyInstaller) executable.
    """
    if not getattr(sys, "frozen", False):
        return None
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass is None:
        return None
    candidate = Path(meipass) / "semgrep-rules"
    return candidate if candidate.is_dir() else None
