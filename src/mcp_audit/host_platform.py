"""Which kind of host this is: Windows, WSL, macOS or Linux (STORY-0142).

Used by ``affected`` for research records whose product is affected only on
some platforms.  Reads the standard library's ``sys.platform`` and, on Linux,
a size-capped read of ``/proc/sys/kernel/osrelease`` or ``/proc/version`` for
the word ``microsoft`` (how WSL kernels identify themselves).  Nothing is
executed and no other program is run.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from pathlib import Path

__all__ = ["PLATFORMS", "detect_host_platform"]

#: Values a research record's ``platforms`` list may hold.
PLATFORMS: tuple[str, ...] = ("windows", "wsl", "macos", "linux")

#: Most bytes read from a ``/proc`` file.
MAX_PROC_BYTES = 4096
_PROC_FILES = ("/proc/sys/kernel/osrelease", "/proc/version")


def _read_capped(path: str) -> str | None:
    try:
        with Path(path).open("rb") as fh:
            return fh.read(MAX_PROC_BYTES).decode("utf-8", errors="replace")
    except OSError:
        return None


def detect_host_platform(
    platform: str | None = None,
    read: Callable[[str], str | None] | None = None,
) -> str | None:
    """Return ``windows``, ``wsl``, ``macos`` or ``linux``; ``None`` if unknown.

    Args:
        platform: A ``sys.platform`` value (default: this host's).
        read: Reads a ``/proc`` file, returning ``None`` when absent (default:
            a capped file read).  Injected by tests.

    Returns:
        The platform name, or ``None`` when it cannot be determined (an
        unfamiliar OS, or a Linux host where neither ``/proc`` file could be
        read, since WSL cannot then be ruled out).
    """
    plat = sys.platform if platform is None else platform
    if plat in ("win32", "cygwin", "msys"):
        return "windows"
    if plat == "darwin":
        return "macos"
    if plat.startswith("linux"):
        reader = read or _read_capped
        texts = [t for t in (reader(p) for p in _PROC_FILES) if t is not None]
        if not texts:
            return None
        return "wsl" if any("microsoft" in t.casefold() for t in texts) else "linux"
    return None
