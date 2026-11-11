"""Wrap and unwrap MCP config entries for ``mcp-audit run`` (EPIC-0009 Story 1.2).

A wrapped stdio entry launches mcp-audit instead of the server::

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

import hashlib
import re
from pathlib import PurePath

from mcp_audit._jcs import canonicalize

#: The executable names a wrapper may have (pip/pipx/uv console script,
#: Windows launcher, PyInstaller release binaries).
_WRAPPER_NAME = re.compile(r"^mcp-audit(-(darwin|linux|windows)-[a-z0-9_]+)?(\.exe)?$")

MODES = ("monitor", "enforce")

#: Clients whose JSON configs ``mcp-audit wrap`` rewrites (Story 1.2's first
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
    """Whether *command* names an mcp-audit executable.

    A bare name (``mcp-audit``, resolved on PATH) or an absolute path whose
    file name is an mcp-audit executable. A relative path (``./mcp-audit``)
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


def inner_launch(command: object, args: object) -> tuple[str, list[str]] | None:
    """Return the wrapped server's ``(command, args)``, or ``None`` if not wrapped.

    Wrapped means: the command is an mcp-audit executable
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
    """Return *entry* rewritten to launch through ``mcp-audit run``.

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
