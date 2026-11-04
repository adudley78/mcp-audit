"""Where ``reach`` looks: the paths of one machine, and how they are shown.

Everything here is a path or a small file reader.  Nothing executes anything.
The defaults are the ones the default scan uses (``Path.home()``,
``Path.cwd()``, ``CLAUDE_CONFIG_DIR``, the OS's managed-settings directory,
``CODEX_HOME``); tests pass a temporary home explicitly.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass, field
from pathlib import Path

#: Largest settings file read (same cap as the other settings readers).
MAX_FILE_BYTES = 1024 * 1024


@dataclass
class Env:
    """The directories one ``reach`` run reads.

    Attributes:
        home: The user's home directory.
        cwd: The working directory (project settings, ``.mcp.json``).
        config_dir: Claude Code's config directory.
        managed_dir: Claude Code's managed-settings directory, or ``None``.
        codex_config: Codex's user ``config.toml``.
        gemini_config: Gemini CLI's user ``settings.json``.
        errors: Problems found while reading; shown in the report.
    """

    home: Path
    cwd: Path
    config_dir: Path
    managed_dir: Path | None
    codex_config: Path
    gemini_config: Path
    errors: list[str] = field(default_factory=list)
    #: Platform policy sources (macOS profile, Windows registry); ``None`` reads
    #: this machine's.  Injectable for tests.
    platform_sources: object | None = None

    def mask(self, path: Path | str) -> str:
        """*path* as shown in a report: ``~/...`` under home, never a username.

        Under the working directory (when that is outside home) a ``./`` path,
        under the managed directory its system path, anything else the bare
        file name.
        """
        p = Path(path)
        for root, prefix in self._roots():
            try:
                rel = p.relative_to(root).as_posix()
            except ValueError:
                continue
            return prefix if rel == "." else f"{prefix}/{rel}".replace("//", "/")
        return p.name

    def _roots(self) -> list[tuple[Path, str]]:
        roots: list[tuple[Path, str]] = [(self.home, "~")]
        if self.managed_dir is not None:
            roots.append((self.managed_dir, self.managed_dir.as_posix()))
        roots.append((self.cwd, "."))
        return roots

    def note(self, message: str) -> None:
        """Record a problem for the report's ``errors`` list."""
        if message not in self.errors:
            self.errors.append(message)


def default_env() -> Env:
    """The :class:`Env` for this machine and this working directory."""
    from mcp_audit.discovery import (  # noqa: PLC0415
        codex_user_config_path,
        gemini_user_config_path,
    )
    from mcp_audit.plugins import mods  # noqa: PLC0415

    home = Path.home()
    return Env(
        home=home,
        cwd=Path.cwd(),
        config_dir=mods.claude_config_dir(home),
        managed_dir=mods.managed_settings_dir(),
        codex_config=codex_user_config_path(),
        gemini_config=gemini_user_config_path(),
    )


def read_capped(
    path: Path, limit: int = MAX_FILE_BYTES
) -> tuple[bytes | None, str | None]:
    """Read at most *limit* (:data:`MAX_FILE_BYTES`) bytes of a regular file.

    Never blocks (non-blocking open, regular files only).

    Returns ``(bytes, None)``, ``(None, None)`` when the file does not exist,
    or ``(None, reason)`` when it exists but cannot be used (not a regular
    file, over the cap, unreadable).  Never raises.
    """
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        return None, None
    except OSError as exc:
        return None, f"cannot be read ({exc.strerror or type(exc).__name__})"
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None, "is not a regular file"
        with os.fdopen(fd, "rb", closefd=False) as handle:
            data = handle.read(limit + 1)
    except OSError as exc:
        return None, f"cannot be read ({exc.strerror or type(exc).__name__})"
    finally:
        os.close(fd)
    if len(data) > limit:
        return None, f"is over {limit} bytes"
    return data, None
