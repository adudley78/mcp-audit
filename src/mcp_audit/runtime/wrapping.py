"""Wrap and unwrap MCP config entries for ``credenzo run`` (EPIC-0009 Story 1.2).

A wrapped stdio entry launches Credenzo instead of the server::

    before: {"command": "npx", "args": ["-y", "pkg"], "env": {...}}
    after:  {"command": "/abs/path/mcp-audit",
             "args": ["run", "--config", "/abs/.mcp.json", "--server", "name",
                      "--mode", "monitor", "--original-sha256", "<hex>",
                      "--", "npx", "-y", "pkg"],
             "env": {...}}

Only ``command`` and ``args`` change; every other key (``env``, ``cwd``,
``type``, client-specific keys) stays as it was, in place. ``--original-sha256``
is the SHA-256 of the RFC 8785 form of the original entry, so
:func:`unwrap_entry` can prove it restored exactly what was there.

:func:`inner_launch` is what the config parser uses so every analyzer, the
lock and the launch gate see the server that actually runs, not the wrapper.
Stdlib-only (plus :mod:`mcp_audit._jcs`).
"""

from __future__ import annotations

import contextlib
import hashlib
import re
import shutil
import sys
from pathlib import Path, PurePath

from mcp_audit._jcs import canonicalize

#: The executable names a wrapper may have (pip/pipx/uv console script,
#: Windows launcher, PyInstaller release binaries).
#: ``credenzo`` is the command from 0.33.0; ``mcp-audit`` is the name every
#: config wrapped before that carries, so both are the wrapper.
_WRAPPER_NAME = re.compile(
    r"^(mcp-audit|credenzo)(-(darwin|linux|windows)-[a-z0-9_]+)?(\.exe)?$"
)

MODES = ("monitor", "enforce")

#: Clients whose JSON configs ``credenzo wrap`` rewrites (Story 1.2's first
#: batch plus the clients that share the format; ``custom`` is ``--path``).
WRAPPABLE_CLIENTS = frozenset(
    {
        "claude-code",
        "claude-code-project",
        "cursor",
        "claude-desktop",
        "vscode",
        "windsurf",
        "copilot-cli",
        "augment",
        "custom",
    }
)
ORIGINAL_DIGEST_FLAG = "--original-sha256"


def is_wrapper_command(command: object) -> bool:
    """Whether *command* names a Credenzo executable.

    A bare name (``credenzo``, resolved on PATH) or an absolute path whose
    file name is a Credenzo executable. A relative path (``./mcp-audit``)
    is never trusted as the wrapper: a cloned repository could plant one, so
    it is analysed as the command it is.
    """
    if not isinstance(command, str) or not command:
        return False
    name = PurePath(command.replace("\\", "/")).name
    if not _WRAPPER_NAME.match(name):
        return False
    is_bare = command == name
    is_absolute = command.startswith("/") or bool(re.match(r"^[A-Za-z]:[\\/]", command))
    return is_bare or is_absolute


def wrapper_digest(command: str) -> str:
    """Return ``"sha256:<hex>"`` of a wrapper's path as the config writes it.

    The lock records this, never the path: a lock holds no absolute path.
    """
    return "sha256:" + hashlib.sha256(command.encode("utf-8")).hexdigest()


def _this_install() -> list[Path]:
    """Paths of the Credenzo executables that belong to the running install."""
    found: list[Path] = []
    candidates = [Path(sys.argv[0])] if sys.argv and sys.argv[0] else []
    bin_dir = Path(sys.executable).parent if sys.executable else None
    if bin_dir is not None:
        candidates.append(Path(sys.executable))
        for name in ("credenzo", "mcp-audit", "credenzo.exe", "mcp-audit.exe"):
            candidates.append(bin_dir / name)
    for candidate in candidates:
        try:
            if _WRAPPER_NAME.match(candidate.name.lower()) and candidate.is_file():
                found.append(candidate.resolve())
        except OSError:
            continue
    return found


def _is_this_install(path: Path) -> bool:
    try:
        resolved = path.resolve()
    except OSError:
        return False
    return resolved in _this_install()


def _inside(path: Path, root: Path) -> bool:
    """Whether *path* is under *root*, as written or once links are resolved."""
    forms = [(path, root)]
    with contextlib.suppress(OSError):
        forms.append((path.resolve(), root.resolve()))
    for candidate, base in forms:
        try:
            candidate.relative_to(base)
        except ValueError:
            continue
        return True
    return False


def wrapper_trusted(command: object, *, root: Path | None, recorded: object) -> bool:
    """Whether a wrapped entry's wrapper may stand for the server it runs.

    ``lock --verify`` compares a wrapped entry by its
    inner launch.  That is only right when the wrapper is Credenzo.  A file
    that is merely *named* ``credenzo`` can be anything, and a repository can
    hold one at a path that is known in advance (a CI checkout, a dev
    container), so:

    - a wrapper inside the repository (the git root above *root*, or *root*
      itself when there is none) is trusted only when it is the running
      install or its digest is in the lock entry (``wrapper``, written by
      ``lock`` when a person locks the wrapped entry);
    - when the lock entry records a wrapper, any other wrapper path is not
      trusted unless it is the running install;
    - a bare name resolves on ``PATH``; it is trusted unless ``PATH`` leads to
      a file inside the repository that is not the running install.

    An absolute path outside the repository with nothing recorded stays
    trusted: a change to a repository cannot put a file there.  The recorded
    digest is of the path, not of the file: it says that a person approved
    that path.

    Args:
        command: The entry's ``command`` as written.
        root: The lock root, or ``None`` when there is none to compare with.
        recorded: The lock entry's ``wrapper`` value, if any.
    """
    if not is_wrapper_command(command):
        return False
    assert isinstance(command, str)  # noqa: S101 - is_wrapper_command checked it
    boundary = _repository_of(root)
    name = PurePath(command.replace("\\", "/")).name
    if command == name:
        if isinstance(recorded, str) and recorded == wrapper_digest(command):
            return True  # a person locked the entry with this bare name
        located = shutil.which(command)
        if located is None or boundary is None:
            return True
        path = Path(located)
        return _is_this_install(path) or not _inside(path, boundary)
    path = Path(command)
    if _is_this_install(path):
        return True
    if isinstance(recorded, str) and recorded:
        return recorded == wrapper_digest(command)
    return boundary is None or not _inside(path, boundary)


def _repository_of(root: Path | None) -> Path | None:
    """Return the directory a change to the repository can put a file under.

    The lock root can be a subdirectory (a monorepo with a lock per package).
    A commit can add a file anywhere in the repository, so the boundary is
    the git root above the lock root, or the lock root when there is none.
    """
    if root is None:
        return None
    from mcp_audit._paths import find_git_root

    try:
        found = find_git_root(root)
        # A `.git` *file* marks a submodule or a linked worktree.  The
        # superproject above a submodule can hold files too, so keep going
        # up to the first directory whose `.git` is a directory.
        boundary = found
        while found is not None and not (found / ".git").is_dir():
            if found.parent == found:
                break
            found = find_git_root(found.parent)
            if found is not None:
                boundary = found
        return boundary or root
    except OSError:
        return root


def inner_launch(command: object, args: object) -> tuple[str, list[str]] | None:
    """Return the wrapped server's ``(command, args)``, or ``None`` if not wrapped.

    Wrapped means: the command is a Credenzo executable
    (:func:`is_wrapper_command`), the first argument is ``run`` and a ``--``
    follows with at least the server's command after it.
    """
    if not is_wrapper_command(command):
        return None
    if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
        return None
    if not args or args[0] != "run" or "--" not in args:
        return None
    split = args.index("--")
    rest = args[split + 1 :]
    if not rest:
        return None
    return rest[0], rest[1:]


def wrapper_options(args: list[str]) -> dict[str, str]:
    """Return the ``--flag value`` pairs before ``--`` in a wrapped entry's args."""
    head = args[1 : args.index("--")] if "--" in args else args[1:]
    options: dict[str, str] = {}
    i = 0
    while i < len(head):
        flag = head[i]
        if flag.startswith("--") and i + 1 < len(head):
            options[flag[2:]] = head[i + 1]
            i += 2
        else:
            i += 1
    return options


def entry_digest(entry: dict) -> str:
    """SHA-256 hex of the RFC 8785 form of a config entry (key order ignored)."""
    return hashlib.sha256(canonicalize(entry)).hexdigest()


def wrap_entry(
    entry: dict,
    *,
    exe: str,
    config_path: str,
    server: str,
    mode: str = "monitor",
) -> dict:
    """Return *entry* rewritten to launch through ``credenzo run``.

    Raises:
        ValueError: The entry isn't a local (stdio) server, is already
            wrapped, or *mode* is unknown.
    """
    if mode not in MODES:
        raise ValueError(f"mode must be one of {', '.join(MODES)}")
    command = entry.get("command")
    if not isinstance(command, str) or not command:
        raise ValueError("not a local (stdio) server: it has no command")
    args = entry.get("args", [])
    if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
        raise ValueError("its args are not a list of strings")
    if inner_launch(command, args) is not None:
        raise ValueError("already wrapped")
    new_args = [
        "run",
        "--config", config_path,
        "--server", server,
        "--mode", mode,
        ORIGINAL_DIGEST_FLAG, entry_digest(entry),
        "--", command, *args,
    ]  # fmt: skip
    wrapped: dict = {}
    for key, value in entry.items():
        if key == "command":
            wrapped["command"] = exe
            wrapped["args"] = new_args
        elif key != "args":
            wrapped[key] = value
    return wrapped


def unwrap_entry(entry: dict) -> tuple[dict, bool] | None:
    """Return ``(original entry, verified)``, or ``None`` if *entry* isn't wrapped.

    ``verified`` is ``True`` when the restored entry's digest equals the
    ``--original-sha256`` recorded at wrap time. It is ``False`` when the
    entry was edited after wrapping (the restored entry is then the current
    inner launch with the other keys as they are now) or carries no digest.
    """
    command = entry.get("command")
    args = entry.get("args")
    inner = inner_launch(command, args)
    if inner is None:
        return None
    recorded = wrapper_options(args).get(ORIGINAL_DIGEST_FLAG[2:])  # type: ignore[arg-type]
    inner_command, inner_args = inner

    def _restore(with_args: bool) -> dict:
        restored: dict = {}
        for key, value in entry.items():
            if key == "command":
                restored["command"] = inner_command
                if with_args:
                    restored["args"] = list(inner_args)
            elif key != "args":
                restored[key] = value
        return restored

    candidates = [_restore(True)]
    if not inner_args:
        candidates.append(_restore(False))  # the original may have had no args key
    for candidate in candidates:
        if recorded is not None and entry_digest(candidate) == recorded:
            return candidate, True
    return candidates[0], False


def wrap_status(servers: list) -> tuple[int, int, dict[str, int]]:
    """Return ``(wrapped, local, {mode: count})`` over wrappable local servers.

    *servers* are parsed :class:`~mcp_audit.models.ServerConfig` objects;
    a local server is one with a command in a :data:`WRAPPABLE_CLIENTS`
    config.
    """
    wrapped = 0
    local = 0
    modes: dict[str, int] = {}
    for server in servers:
        if server.client not in WRAPPABLE_CLIENTS or not server.command:
            continue
        local += 1
        if server.wrapped:
            wrapped += 1
            mode = server.wrap_mode or "monitor"
            modes[mode] = modes.get(mode, 0) + 1
    return wrapped, local, modes
