"""One way to write a file safely: a fresh temporary file, then one rename.

Every writer in mcp-audit that persists state or edits a file in place goes
through :func:`atomic_write`. Before 2026-11 there were eleven hand-rolled
copies, and they disagreed on three points that matter:

* **Symlinks.** ``lock`` and ``fix --apply`` wrote to a fixed
  ``<name>.tmp`` beside the target with ``O_CREAT | O_TRUNC``. In a cloned
  repository that name can be a planted symlink, so the write went through it
  into any file the user can write (``~/.bashrc``, ``~/.ssh/authorized_keys``).
  Here the temporary file has a random name and is created with ``O_EXCL``, so
  nothing already on disk is ever opened. The final ``os.replace`` replaces a
  symlink at the destination; it never writes through one.
* **Permissions.** ``os.open(..., O_CREAT | O_TRUNC, 0o600)`` applies the mode
  only when it *creates* the file. A state file left at 0o644 by an older
  release kept 0o644 forever. Here the mode is set on every write.
* **Partial writes.** In-place ``O_TRUNC`` writes left a truncated file after a
  crash or Ctrl-C (an empty ``seen.json`` silently resets feed rollback
  protection), and bare ``os.write`` calls can write fewer bytes than asked.
  Here the reader sees the old file or the new one, never part of either.
"""

from __future__ import annotations

import contextlib
import json
import os
import stat
import tempfile
from pathlib import Path

PRIVATE_FILE_MODE = 0o600
PRIVATE_DIR_MODE = 0o700


def atomic_write(
    path: Path | str,
    data: bytes | str,
    *,
    mode: int = PRIVATE_FILE_MODE,
    dir_mode: int | None = None,
) -> None:
    """Write *data* to *path* atomically with permission bits *mode*.

    Args:
        path: Destination file. Its parent directory must exist unless
            *dir_mode* is given.
        data: Bytes, or text (encoded as UTF-8).
        mode: Permission bits of the destination after the write. Defaults to
            owner read/write only.
        dir_mode: When set, create missing parent directories with this mode.

    Raises:
        OSError: The write failed. The destination is unchanged and the
            temporary file is removed.
    """
    target = Path(path)
    if dir_mode is not None:
        target.parent.mkdir(parents=True, exist_ok=True, mode=dir_mode)
    payload = data.encode("utf-8") if isinstance(data, str) else data

    # mkstemp: random name, O_CREAT | O_EXCL, mode 0o600. A pre-existing file
    # or symlink with that name is an error, never opened.
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{target.name}.", suffix=".tmp", dir=target.parent
    )
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)  # buffered write loops until done
            handle.flush()
            os.fsync(handle.fileno())
        if mode != PRIVATE_FILE_MODE:
            # mkstemp already made it 0o600, so a private file is never
            # chmodded and never briefly wider. chmod by name, not fchmod:
            # Windows has no os.fchmod before 3.13; the name is ours.
            os.chmod(tmp_name, mode)
        os.replace(tmp_name, target)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp_name)
        raise


def create_exclusive(path: Path | str, data: bytes | str, *, mode: int) -> None:
    """Create *path* with *data*; fail if any file or symlink is already there.

    For files that must never replace or follow anything, such as the first
    backup of a config before ``fix --apply`` edits it.

    Raises:
        FileExistsError: Something already exists at *path* (also a dangling
            symlink, which ``Path.exists()`` reports as absent).
    """
    payload = data.encode("utf-8") if isinstance(data, str) else data
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    fd = os.open(str(path), flags, mode)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(path)
        raise
    with contextlib.suppress(OSError):
        os.chmod(path, mode)  # O_CREAT applies the umask; set the exact bits


def read_untrusted_json(
    path: Path, *, max_bytes: int, what: str
) -> tuple[dict | None, str | None]:
    """Read one file from an untrusted directory as a JSON object.

    Returns ``(document, None)`` or ``(None, reason)`` and never raises. A
    symlink is not followed (it can name any file on this machine), a FIFO
    or device is not opened in a blocking way, and at most *max_bytes* are
    read. Shared by ``affected --fleet`` and ``reach --fleet``, which had one
    copy each (2026-11).

    Args:
        path: The file to read.
        max_bytes: Largest file read; a bigger one is refused, not cut.
        what: What the file should be, for the "not a JSON object" reason
            (``"an mcp-audit scan"``).
    """
    flags = (
        os.O_RDONLY
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    if os.path.islink(path):
        return None, "is a symbolic link (not followed)"
    # Checked before opening too: Windows refuses to open a directory with
    # "Permission denied", which would hide the real reason.
    try:
        if not stat.S_ISREG(os.lstat(path).st_mode):
            return None, "is not a regular file"
        fd = os.open(path, flags)
    except OSError as exc:
        return None, f"could not be read ({exc.strerror or type(exc).__name__})"
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None, "is not a regular file"
        with os.fdopen(fd, "rb", closefd=False) as handle:
            blob = handle.read(max_bytes + 1)
    except OSError as exc:
        return None, f"could not be read ({exc.strerror or type(exc).__name__})"
    finally:
        os.close(fd)
    if len(blob) > max_bytes:
        return None, f"is over {max_bytes} bytes; not read"
    try:
        doc = json.loads(blob.decode("utf-8"))
    except (ValueError, RecursionError, MemoryError):
        return None, "is not valid JSON"
    if not isinstance(doc, dict):
        return None, f"is not {what} (expected a JSON object)"
    return doc, None
