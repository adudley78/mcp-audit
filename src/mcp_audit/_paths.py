"""Resolve paths to bundled data files in both source and frozen (PyInstaller) modes.

When mcp-audit runs as a PyInstaller one-file binary, Python's ``__file__``
attributes point into a temporary extraction directory (``sys._MEIPASS``), not
the original source tree.  All modules that need to read from ``data/`` must
call :func:`data_dir` instead of constructing paths relative to ``__file__``.

:func:`resolve_bundled_resource` is the shared 3-step resolver used by
``sast/bundler.py``, ``rules/engine.py``, ``registry/loader.py``, and
``extensions/analyzer.py`` to locate resources that ship inside the wheel but
live outside the package source tree during development.
"""

from __future__ import annotations

import importlib.resources
import sys
from pathlib import Path


def resolve_bundled_resource(
    package: str,
    subdir: str,
    frozen_subpath: str | None = None,
    dev_fallback: Path | None = None,
) -> Path | None:
    """Locate a bundled resource directory or file across all execution contexts.

    Resolution order (step 1 — explicit caller override — is the caller's
    responsibility):

    2. **PyInstaller _MEIPASS**: checked when ``sys.frozen`` is ``True``.
       The resource is expected at ``_MEIPASS / frozen_subpath`` (defaults to
       ``subdir`` when *frozen_subpath* is ``None``).
    3. **importlib.resources**: resolves ``subdir`` relative to *package* using
       :func:`importlib.resources.as_file` so the path is valid in both
       regular wheel installs and (hypothetical) zip-imported packages.
    4. **dev_fallback**: an absolute ``Path`` for editable / source-tree
       installs where the resource lives outside the Python package directory.
       Only tried when it is not ``None`` and it exists on disk.

    Args:
        package: Dotted package name for importlib lookup, e.g.
            ``"mcp_audit.rules"``.
        subdir: Resource path relative to the package, e.g. ``"community"``
            or ``"known-servers.json"``.
        frozen_subpath: Overrides the path used inside ``_MEIPASS`` when it
            differs from *subdir* (e.g. ``"rules/community"``).  Defaults to
            *subdir*.
        dev_fallback: Absolute ``Path`` for local-dev / editable installs
            (typically computed relative to ``__file__``).  Skipped when
            ``None`` or when the path does not exist.

    Returns:
        Resolved :class:`~pathlib.Path`, or ``None`` when no location is found.
    """
    _frozen_sub = frozen_subpath if frozen_subpath is not None else subdir

    # Step 2 — PyInstaller frozen binary
    if getattr(sys, "frozen", False):
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass is not None:
            candidate = Path(meipass) / _frozen_sub
            if candidate.exists():
                return candidate

    # Step 3 — importlib.resources (pip-installed wheel)
    # as_file() is always used instead of Path(str(ref)) so the path is valid
    # even in zip-import contexts.
    try:
        ref = importlib.resources.files(package).joinpath(subdir)
        with importlib.resources.as_file(ref) as path:
            if path.exists():
                return path
    except (TypeError, FileNotFoundError, ModuleNotFoundError):
        pass

    # Step 4 — dev / editable install fallback
    if dev_fallback is not None and dev_fallback.exists():
        return dev_fallback

    return None


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
