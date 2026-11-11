"""Launch gate for ``mcp-audit run`` (EPIC-0009 Story 1.3).

Before the server starts, the gate checks the command about to run against
the server's entry in the nearest ``mcp-lock.json``:

=========  ==========================================================
ID         Meaning
=========  ==========================================================
LOCK-002   The server is not in the lock (never approved).
LOCK-001   The launch differs from the approved launch (drift).
RUN-001    No ``mcp-lock.json`` covers the server's config file.
RUN-002    The lock exists but can't be read, isn't valid, is a newer
           ``lock_version`` than this mcp-audit understands, or its
           ``tools`` section fails its own checksum.
=========  ==========================================================

It compares what is **actually being launched** (the argv after ``--``),
not what the config file says, so it also catches a client or tool that
rewrote the command. Two things are deliberately tolerated, each only within
a single argument, never across arguments:

* ``${VAR}``, ``${VAR:-default}`` and ``${env:VAR}`` placeholders in the
  locked arguments, which the client substitutes before launch.
* Credentials ``lock`` redacted (``[REDACTED]``), compared the way
  ``lock --verify`` compares them (both sides redacted).

Environment-variable and header *names*, which ``lock --verify`` also
compares, are not visible at launch and are not checked here.

Lean by design: the common path imports only :mod:`mcp_audit.lock.core`
(stdlib). The redaction code, which pulls in the supply-chain analyzer, is
imported only when the plain comparison fails.
"""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from mcp_audit.lock import tool_digests
from mcp_audit.lock.core import (
    find_lock_for,
    index_locked_entries,
    match_key,
    unsupported_version,
)

#: Matches the placeholder forms MCP clients substitute in launch arguments.
_PLACEHOLDER = re.compile(r"\$\{[^}]*\}")


@dataclass(frozen=True)
class GateResult:
    """Outcome of the launch gate for one server.

    Attributes:
        finding_id: ``None`` when the launch matches its lock entry; otherwise
            one of ``LOCK-001``, ``LOCK-002``, ``RUN-001``, ``RUN-002``.
        summary: One sentence naming the problem (no secrets, no full paths
            beyond the config and lock the user passed).
        fix: The command or action that resolves it.
    """

    finding_id: str | None
    summary: str = ""
    fix: str = ""
    #: The server's ``tools`` record from the lock (``{"tools": {...}}``), or
    #: ``None`` when the lock holds none for it (written without
    #: ``--connect``). Only set on an allowed launch.
    tools_record: dict | None = None

    @property
    def ok(self) -> bool:
        """True when the launch may proceed without a finding."""
        return self.finding_id is None


ALLOWED = GateResult(None)


def _arg_matches(locked: str, launched: str) -> bool:
    """Whether one launched argument satisfies one locked argument."""
    if locked == launched:
        return True
    if "${" not in locked:
        return False
    parts = _PLACEHOLDER.split(locked)
    pattern = ".*".join(re.escape(p) for p in parts)
    return re.fullmatch(pattern, launched, flags=re.DOTALL) is not None


def _argv_matches(locked: Sequence[str], launched: Sequence[str]) -> bool:
    return len(locked) == len(launched) and all(
        _arg_matches(lk, ln) for lk, ln in zip(locked, launched, strict=True)
    )


def _redacted(argv: Sequence[str]) -> list[str]:
    """Return *argv* redacted exactly as ``lock`` redacts a launch line."""
    from mcp_audit.lock.identity import redact_launch

    command, args = redact_launch(argv[0], list(argv[1:]))
    return [command, *args]


def launch_matches(identity: object, argv: Sequence[str]) -> bool:
    """Whether *argv* is the launch recorded in a lock entry's ``identity``."""
    if not isinstance(identity, dict) or "url" in identity:
        return False
    command = identity.get("command")
    args = identity.get("args", [])
    if not isinstance(command, str) or not isinstance(args, list):
        return False
    if not all(isinstance(a, str) for a in args):
        return False
    locked = [command, *args]
    launched = [str(a) for a in argv]
    if _argv_matches(locked, launched):
        return True
    # Slow path, as ``lock --verify`` compares: both sides redacted.
    return _argv_matches(_redacted(locked), _redacted(launched))


def _describe_change(identity: object, argv: Sequence[str]) -> str:
    """Say what changed without quoting arguments (they may hold secrets)."""
    if isinstance(identity, dict) and "url" in identity:
        return "it was approved as a remote server and is now launched locally"
    if not isinstance(identity, dict):
        return "its locked launch line is unreadable"
    command = identity.get("command")
    args = identity.get("args", [])
    if command != argv[0]:
        locked_cmd = _redacted([str(command)])[0]
        launched_cmd = _redacted([argv[0]])[0]
        return f"the command changed from {locked_cmd!r} to {launched_cmd!r}"
    if isinstance(args, list) and len(args) != len(argv) - 1:
        return f"it now has {len(argv) - 1} arguments; {len(args)} were approved"
    return "its arguments changed"


def check_launch(
    argv: Sequence[str],
    *,
    config_path: Path,
    server_name: str,
    lock_path: Path | None = None,
) -> GateResult:
    """Check the launch *argv* of *server_name* against its lock entry.

    Args:
        argv: The command about to be launched (program first).
        config_path: The MCP config file that declares the server.
        server_name: The server's name in that config file.
        lock_path: An explicit ``mcp-lock.json``; by default the nearest one
            above *config_path* (the same lookup ``check`` and ``scan`` use).

    Returns:
        :data:`ALLOWED`, or a :class:`GateResult` naming the finding.
    """
    lock = lock_path or find_lock_for(config_path)
    if lock is None:
        return GateResult(
            "RUN-001",
            f"no mcp-lock.json covers {config_path.name}",
            "run `mcp-audit lock` in the project, or pass --lock",
        )

    try:
        doc = json.loads(lock.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError):
        return GateResult(
            "RUN-002",
            f"{lock.name} can't be read or isn't valid JSON",
            "restore it from version control or run `mcp-audit lock`",
        )
    servers = doc.get("servers") if isinstance(doc, dict) else None
    if not isinstance(servers, dict) or not all(
        isinstance(e, dict) for e in servers.values()
    ):
        return GateResult(
            "RUN-002",
            f"{lock.name} has no valid servers section",
            "restore it from version control or run `mcp-audit lock`",
        )
    newer = unsupported_version(doc)
    if newer is not None:
        return GateResult(
            "RUN-002",
            f"{lock.name} is lock_version {newer}, newer than this mcp-audit reads",
            "upgrade mcp-audit",
        )

    key = match_key(config_path, lock.parent, server_name)
    if key is None:
        return GateResult(
            "RUN-001",
            f"{config_path.name} is outside the scope of {lock}",
            "run `mcp-audit lock` where the config lives, or pass --lock",
        )

    found = index_locked_entries(servers).get(key)
    if found is None:
        return GateResult(
            "LOCK-002",
            f"server {server_name!r} is not in mcp-lock.json",
            "review it, then run `mcp-audit lock` to approve it",
        )

    entry_key, entry = found
    identity = entry.get("identity")
    if launch_matches(identity, argv):
        section = doc.get(tool_digests.TOOLS_KEY)
        if not tool_digests.is_owned(section):
            return ALLOWED
        if not tool_digests.checksum_ok(section):
            return GateResult(
                "RUN-002",
                f"the tools section of {lock.name} fails its checksum "
                "(lock --verify reports this as LOCK-005)",
                "restore it from version control or run `mcp-audit lock --connect`",
            )
        record = section["servers"].get(entry_key)
        return GateResult(
            None, tools_record=record if isinstance(record, dict) else None
        )
    return GateResult(
        "LOCK-001",
        f"server {server_name!r} drifted from mcp-lock.json: "
        f"{_describe_change(identity, argv)}",
        "review the change; if approved, run `mcp-audit lock --accept`",
    )
