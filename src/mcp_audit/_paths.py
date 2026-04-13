"""Resolve paths to bundled data files in both source and frozen (PyInstaller) modes.

When mcp-audit runs as a PyInstaller one-file binary, Python's ``__file__``
attributes point into a temporary extraction directory (``sys._MEIPASS``), not
the original source tree.  All modules that need to read from ``data/`` must
call :func:`data_dir` instead of constructing paths relative to ``__file__``.
"""

from __future__ import annotations

import sys
from pathlib import Path


def data_dir() -> Path:
    """Return the absolute path to the ``mcp_audit/data`` directory.

    Works correctly in three execution contexts:

    * **Normal source install** – returns ``<package_root>/data/``
    * **PyInstaller one-file binary** – returns the ``_MEIPASS`` extraction
      directory where ``--add-data`` places the bundled files.
    * **Editable / development install** – same as source install.

    Returns:
        Path pointing to the data directory.  The directory is guaranteed to
        exist when the package is properly installed or bundled.
    """
    if getattr(sys, "frozen", False):
        # PyInstaller sets sys.frozen = True and sys._MEIPASS to the temp dir.
        return Path(sys._MEIPASS) / "mcp_audit" / "data"  # type: ignore[attr-defined]
    return Path(__file__).parent / "data"
