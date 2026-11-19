"""Tool-call guard for Claude Code: ``credenzo guard`` (STORY-0176).

``credenzo guard`` is a Claude Code ``PreToolUse`` hook.  Claude Code runs it
before each MCP tool call and gives it the call as JSON on stdin.  The guard
answers one question: **is this tool of this server approved in
mcp-lock.json?**  When it is not, the guard denies the call.  The agent does
not choose; the call does not happen.

What it protects against: an honest agent that picks a tool nobody approved
(a new server in the project's ``.mcp.json``, a tool a server added after it
was locked, a copy that ``lock`` did not record, a server whose launch
changed).  What it does not do: contain an agent that works against you.  An
agent that can run shell commands can change the lock file itself.

The decision, in order:

1. The call is not an MCP tool call: no decision.
2. The lock can describe the server only when Claude Code says it comes from
   the project's ``.mcp.json`` (source ``project``) or from the user's
   ``~/.claude.json`` (source ``user``).  Any other source (``local``,
   ``plugin``, ``claudeai``, ``managed``, ``agent``...) is **not covered**:
   no decision, or a denial with ``--strict``.
3. ``--allow-server`` (the exact name) and ``--allow-source`` are exceptions
   to that ``--strict`` denial.  They never apply to a project server: a
   repository chooses its own server names.
4. No ``mcp-lock.json`` above the project: not covered, as in 2.
5. The lock cannot be read or fails a checksum: denied (RUN-002).
6. The server is not in the lock: denied (LOCK-002).  A user-level server
   is not covered when the lock holds no user-level entry at all (it was
   written without ``--include-user``).
7. The server's config entry differs from the lock: denied (LOCK-001).
8. The lock holds no tool record for the server: denied (RUN-003), unless
   ``--allow-server`` names it (a locked server that ``lock --connect``
   cannot reach).
9. The tool is not in the record: denied (LOCK-006).

The guard never approves a call.  When it has no objection it prints nothing,
and Claude Code's own permission rules decide as before.

It compares **names** and the **config entry**.  It never sees a tool's
description or schema, so a server that changes an approved tool's text is
not stopped here: ``credenzo run --mode enforce`` does that for a local
server, ``lock --verify --connect`` reports it for any server.

Claude Code tells the hook where a server comes from in ``mcp_server``
(``name`` and ``source``; Claude Code 2.1.274 and later,
https://code.claude.com/docs/en/hooks; seen in a live session of 2.1.328 on
2026-11-19, where a ``.mcp.json`` server named ``my.files v2`` arrived as
``{"name": "my.files v2", "source": "project"}`` with the tool name
``mcp__my_files_v2__ping``).  Without that field the guard reads
the server from the tool name and looks in the project file, then the user
file; it cannot see a local-scope server of the same name.

Lean by design, like :mod:`mcp_audit.runtime.gate`: the common path imports
only the standard library and :mod:`mcp_audit.lock.core`.  The full config
parser is loaded only when the plain comparison of a config entry fails.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

from mcp_audit.lock import tool_digests
from mcp_audit.lock.core import (
    find_lock_for,
    index_locked_entries,
    match_key,
)
from mcp_audit.runtime.gate import read_lock
from mcp_audit.runtime.wrapping import inner_launch, wrapper_trusted

#: Hook input larger than this is not read (a tool call's arguments can be a
#: whole file, so the cap is generous).
MAX_INPUT_BYTES = 64 * 1024 * 1024
#: A config file larger than this is not read.  ``~/.claude.json`` also holds
#: session history and can be several MiB.
MAX_CONFIG_BYTES = 64 * 1024 * 1024

#: Sources whose servers a lock entry can describe, and the file each lives in.
PROJECT_SOURCE = "project"
USER_SOURCE = "user"
PROJECT_FILE = ".mcp.json"
USER_FILE = ".claude.json"

USAGE = (
    "credenzo guard [--mode enforce|monitor] [--strict] [--lock FILE] "
    "[--allow-server NAME]... [--allow-source SOURCE]... | --print-hook"
)

DESCRIPTION = (
    "Claude Code PreToolUse hook. Reads one tool call as JSON on stdin and "
    "denies an MCP tool call when the tool or its server is not approved in "
    "mcp-lock.json. It never approves a call: with no objection it prints "
    "nothing. By default it decides for servers of the project's .mcp.json "
    "and, when the lock holds user-level entries, of ~/.claude.json; "
    "--strict also denies servers the lock cannot describe."
)

_FIX_ADDED = "review the tool; if approved, run `credenzo lock --accept --connect`"
_FIX_LOCK = "review the server; if approved, run `credenzo lock --connect`"
_FIX_RESTORE = "restore it from version control or run `credenzo lock --connect`"


@dataclass(frozen=True)
class Decision:
    """The guard's answer for one tool call.

    Attributes:
        deny: The call must not happen.
        finding_id: ``LOCK-001``, ``LOCK-002``, ``LOCK-006``, ``RUN-001``,
            ``RUN-002`` or ``RUN-003`` when *deny*; else ``None``.
        summary: One sentence naming the problem.  It holds the server and
            tool names (cleaned by :func:`shown`), never tool text.
        fix: What a person does about it.
    """

    deny: bool
    finding_id: str | None = None
    summary: str = ""
    fix: str = ""


NO_DECISION = Decision(False)


def _deny(finding_id: str, summary: str, fix: str) -> Decision:
    return Decision(True, finding_id, summary, fix)


def shown(text: object, limit: int = 60) -> str:
    """Return *text* safe to put in a message: printable ASCII, capped.

    A server or tool name comes from a server.  Claude Code's docs call it
    untrusted text ("escape it before display"); the denial reason is read by
    the agent, so nothing but plain characters of the name goes into it.
    """
    cleaned = re.sub(r"[^A-Za-z0-9_.:@/ -]", "?", str(text))
    if len(cleaned) > limit:
        cleaned = cleaned[: limit - 3] + "..."
    return f"'{cleaned}'"


def claude_name(name: str) -> str:
    """Return *name* as Claude Code writes it inside a tool name.

    "Any character outside A-Z, a-z, 0-9, _ and - is replaced with _"
    (code.claude.com/docs/en/mcp, plugin-provided servers).  The docs state
    the rule for plugin servers only; the guard also accepts the name
    unchanged (:func:`_tool_of`).
    """
    return re.sub(r"[^A-Za-z0-9_-]", "_", name)


def _tool_of(tool_name: str, server: str) -> str | None:
    """Return the tool part of *tool_name* for *server*, or ``None``."""
    for form in (claude_name(server), server):
        prefix = f"mcp__{form}__"
        if tool_name.startswith(prefix) and len(tool_name) > len(prefix):
            return tool_name[len(prefix) :]
    return None


def _read_json(path: Path) -> dict | None:
    """Return the JSON object in *path*, or ``None`` (missing, large, not JSON)."""
    try:
        if not path.is_file() or path.stat().st_size > MAX_CONFIG_BYTES:
            return None
        doc = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, ValueError, RecursionError):
        return None
    return doc if isinstance(doc, dict) else None


def _servers_of(path: Path) -> dict:
    """Return the top-level ``mcpServers`` map of *path* (empty when none)."""
    doc = _read_json(path)
    servers = doc.get("mcpServers") if doc else None
    return servers if isinstance(servers, dict) else {}


def _project_dirs(event: dict, project_dir: Path | None) -> list[Path]:
    """Directories that can hold the session's ``.mcp.json``, nearest first.

    Claude Code sets ``CLAUDE_PROJECT_DIR`` for a hook command: that is the
    project root and the only candidate.  Without it, the hook's ``cwd`` and
    its parents up to the git root are tried.
    """
    if project_dir is not None:
        return [project_dir]
    cwd = event.get("cwd")
    try:
        start = Path(cwd).resolve() if isinstance(cwd, str) and cwd else Path.cwd()
    except (OSError, ValueError, RuntimeError):
        return []
    from mcp_audit._paths import find_git_root

    try:
        root = find_git_root(start)
    except OSError:
        root = None
    dirs = [start]
    if root is not None:
        current = start
        while current != root and current.parent != current:
            current = current.parent
            dirs.append(current)
    return dirs


def _entry_unchanged(
    entry_key: str, entry: dict, config: Path, name: str, root: Path
) -> bool:
    """Whether server *name* in *config* is still what the lock recorded.

    The plain comparison covers an entry written the usual way.  Anything
    else (a credential that ``lock`` redacted, a URL that ``lock`` wrote in
    canonical form, another shape) goes to the comparison ``lock --verify``
    itself uses, so the two never disagree.
    """
    raw = _servers_of(config).get(name)
    if not isinstance(raw, dict):
        return False
    identity = entry.get("identity")
    env = raw.get("env", {})
    headers = raw.get("headers", {})
    names_match = (
        isinstance(env, dict)
        and isinstance(headers, dict)
        and sorted(env) == entry.get("env_keys", [])
        and sorted(headers) == entry.get("header_keys", [])
    )
    if names_match and isinstance(identity, dict):
        url = raw.get("url")
        if url is not None and raw.get("command") is not None:
            # One entry with a URL and a command: the lock records the URL,
            # and a client may run the command.  Never "unchanged".
            return False
        if isinstance(url, str):
            if identity == {"url": url}:
                return True
        else:
            command, args = raw.get("command"), raw.get("args", [])
            inner = inner_launch(command, args)
            if inner is not None:
                if not wrapper_trusted(
                    command, root=root, recorded=entry.get("wrapper")
                ):
                    # A file named like Credenzo that the lock cannot vouch
                    # for: the entry is not the server it claims to wrap.
                    return False
                command, args = inner
            if identity == {"command": command, "args": args}:
                return True
    return _entry_unchanged_slow(entry_key, entry, config, name, root)


def _entry_unchanged_slow(
    entry_key: str, entry: dict, config: Path, name: str, root: Path
) -> bool:
    """The comparison ``lock --verify`` makes (LOCK-001), for one server."""
    from mcp_audit.config_parser import parse_config
    from mcp_audit.discovery import DiscoveredConfig
    from mcp_audit.lock.verifier import _check_drift

    client = entry_key.partition("/")[0] or "claude-code"
    try:
        servers = parse_config(
            DiscoveredConfig(client_name=client, root_key="mcpServers", path=config)
        )
    except ValueError:
        return False
    for server in servers:
        if server.name == name:
            return _check_drift(entry_key, server, entry, root) is None
    return False


@dataclass(frozen=True)
class _Target:
    """One reading of which server a call goes to."""

    name: str
    source: str
    config: Path


def _targets(
    event: dict, tool_name: str, dirs: list[Path], home: Path | None
) -> tuple[list[_Target], str | None, str | None]:
    """Return ``(targets, server name, source)`` for the call.

    With ``mcp_server`` the answer is exact: one target for a project or user
    server, none for another source.  Without it, each server of the project
    file, then of the user file, whose name opens the tool name is a target;
    a project server hides a user server of the same name (Claude Code's
    scope precedence).
    """
    provenance = event.get("mcp_server")
    if isinstance(provenance, dict):
        name, source = provenance.get("name"), provenance.get("source")
        if isinstance(name, str) and name and isinstance(source, str) and source:
            if source == PROJECT_SOURCE:
                for directory in dirs:
                    config = directory / PROJECT_FILE
                    if name in _servers_of(config):
                        return [_Target(name, source, config)], name, source
                # Claude Code says the server is the project's; the file that
                # declares it must be found, or nothing can be compared.
                config = (dirs[0] if dirs else Path.cwd()) / PROJECT_FILE
                return [_Target(name, source, config)], name, source
            if source == USER_SOURCE:
                if home is None:
                    return [], name, source
                return [_Target(name, source, home / USER_FILE)], name, source
            return [], name, source

    found: list[_Target] = []
    for directory in dirs:
        config = directory / PROJECT_FILE
        for name in _servers_of(config):
            if isinstance(name, str) and _tool_of(tool_name, name) is not None:
                found.append(_Target(name, PROJECT_SOURCE, config))
        if found:
            break
    taken = {claude_name(t.name) for t in found}
    if home is not None:
        user_config = home / USER_FILE
        for name in _servers_of(user_config):
            if (
                isinstance(name, str)
                and _tool_of(tool_name, name) is not None
                and claude_name(name) not in taken
            ):
                found.append(_Target(name, USER_SOURCE, user_config))
    guess = tool_name[len("mcp__") :].split("__", 1)[0]
    return found, (found[0].name if found else guess), None


def _has_user_entries(servers: dict) -> bool:
    return any(
        isinstance(e.get("config"), str) and e["config"].startswith("~/")
        for e in servers.values()
    )


def _check_target(target: _Target, tool_name: str, lock: Path, doc: dict) -> Decision:
    """Decide for one server reading against a lock that was read."""
    servers = doc["servers"]
    server = shown(target.name)
    key = match_key(target.config, lock.parent, target.name)
    found = index_locked_entries(servers).get(key) if key is not None else None
    if found is None:
        if target.source == USER_SOURCE and not _has_user_entries(servers):
            return Decision(False, "RUN-001")  # the lock holds no user-level entry
        return _deny(
            "LOCK-002", f"MCP server {server} is not in {lock.name}", _FIX_LOCK
        )
    entry_key, entry = found
    if not _entry_unchanged(entry_key, entry, target.config, target.name, lock.parent):
        return _deny(
            "LOCK-001",
            f"MCP server {server} changed in {target.config.name} since it was locked",
            "review the change; if approved, run `credenzo lock --accept --connect`",
        )
    section = doc.get(tool_digests.TOOLS_KEY)
    if tool_digests.is_owned(section) and not tool_digests.checksum_ok(section):
        return _deny(
            "RUN-002",
            f"the tools section of {lock.name} fails its checksum",
            _FIX_RESTORE,
        )
    record = (
        section["servers"].get(entry_key) if tool_digests.is_owned(section) else None
    )
    tools = record.get("tools") if isinstance(record, dict) else None
    if not isinstance(tools, dict):
        return _deny(
            "RUN-003",
            f"{lock.name} has no tool record for MCP server {server}",
            "run `credenzo lock --connect` to record its tools",
        )
    tool = _tool_of(tool_name, target.name)
    if tool is not None and any(
        tool in (recorded, claude_name(recorded))
        for recorded in tools
        if isinstance(recorded, str)
    ):
        return NO_DECISION
    return _deny(
        "LOCK-006",
        f"tool {shown(tool if tool is not None else tool_name)} of MCP server "
        f"{server} is not in {lock.name}",
        _FIX_ADDED,
    )


def decide(
    event: object,
    *,
    strict: bool = False,
    allow_servers: Iterable[str] = (),
    allow_sources: Iterable[str] = (),
    lock_path: Path | None = None,
    project_dir: Path | None = None,
    home: Path | None = None,
) -> Decision:
    """Decide one hook event.

    Args:
        event: The parsed hook input.
        strict: Also deny a server the lock cannot describe.
        allow_servers: Exact server names excepted from the ``strict`` denial
            and from RUN-003.  Never an unlocked project server.
        allow_sources: ``mcp_server.source`` values excepted from the
            ``strict`` denial.  Never ``project``.
        lock_path: An explicit ``mcp-lock.json`` (default: the nearest one
            above the project's ``.mcp.json``).
        project_dir: The project root (``CLAUDE_PROJECT_DIR``).
        home: The user's home directory (default: ``Path.home()``).

    Returns:
        :data:`NO_DECISION`, or a :class:`Decision` with ``deny=True``.
    """
    if not isinstance(event, dict):
        return NO_DECISION
    if event.get("hook_event_name", "PreToolUse") != "PreToolUse":
        return NO_DECISION
    tool_name = event.get("tool_name")
    provenance = event.get("mcp_server")
    if not isinstance(tool_name, str) or not (
        tool_name.startswith("mcp__") or isinstance(provenance, dict)
    ):
        return NO_DECISION

    if home is None:
        try:
            home = Path.home()
        except (RuntimeError, OSError):
            # No home directory can be determined (a stripped environment).
            # User-level servers are then not covered; project servers are
            # decided as usual.
            home = None
    dirs = _project_dirs(event, project_dir)
    targets, name, source = _targets(event, tool_name, dirs, home)

    allowed_names = set(allow_servers)
    allowed_sources = set(allow_sources)

    server = shown(name if name is not None else tool_name)
    origin = f" (source: {shown(source)})" if source is not None else ""

    def not_covered(why: str, *, project: bool = False) -> Decision:
        """Decide for a server the lock cannot describe.

        The exceptions never apply to a project server: its name is the
        repository's to choose, so a name on the allow list proves nothing.
        """
        if not strict:
            return NO_DECISION
        # Without ``mcp_server`` the name is only a guess from the tool name,
        # which a server chooses: it never matches the allow list.
        named = source is not None and name in allowed_names
        if not project and (named or source in allowed_sources):
            return NO_DECISION
        return _deny(
            "RUN-001",
            f"no mcp-lock.json covers MCP server {server}{origin}: {why}",
            "lock it with `credenzo lock --connect`"
            if project
            else "approve it with --allow-server or --allow-source in the hook "
            "command, or lock it",
        )

    in_project = any(t.source == PROJECT_SOURCE for t in targets)
    if not targets:
        return not_covered("the lock describes project and user servers only")

    lock = lock_path
    if lock is None:
        for directory in dirs:
            lock = find_lock_for(directory / PROJECT_FILE)
            if lock is not None:
                break
    if lock is None:
        return not_covered(
            "there is no mcp-lock.json above the project", project=in_project
        )

    doc, problem = read_lock(lock)
    if problem is not None:
        return _deny("RUN-002", problem.summary, problem.fix)

    for target in targets:
        decision = _check_target(target, tool_name, lock, doc)
        if decision.finding_id == "RUN-003" and target.name in allowed_names:
            # The server is in the lock and unchanged; only its tool record is
            # missing (`lock --connect` could not reach it).  The person named
            # it, by its exact name, as one to let through without a record.
            continue
        if decision.deny:
            return decision
        if decision.finding_id == "RUN-001":
            uncovered = not_covered(
                f"{lock.name} holds no user-level entry (lock --include-user)"
            )
            if uncovered.deny:
                return uncovered
    return NO_DECISION


# ── The hook command ──────────────────────────────────────────────────────────


def hook_settings(command: str, extra: Sequence[str] = ()) -> dict:
    """Return the Claude Code settings fragment that registers the guard.

    ``onFailure: block`` (Claude Code 2.1.295 and later) makes a guard that
    cannot start, or that times out, stop the call; without it Claude Code
    lets the call through.
    """
    return {
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": "mcp__.*",
                    "hooks": [
                        {
                            "type": "command",
                            "command": command,
                            "args": ["guard", *extra],
                            "timeout": 30,
                            "onFailure": "block",
                        }
                    ],
                }
            ]
        }
    }


def build_parser() -> argparse.ArgumentParser:
    """Return the parser for ``credenzo guard``."""
    parser = argparse.ArgumentParser(
        prog="credenzo guard", usage=USAGE, description=DESCRIPTION
    )
    parser.add_argument(
        "--mode",
        choices=("enforce", "monitor"),
        default="enforce",
        help="enforce (default): deny the call; monitor: only tell the user",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="also deny a server the lock cannot describe (no lock, or a "
        "source other than the project's .mcp.json and ~/.claude.json)",
    )
    parser.add_argument(
        "--lock", type=Path, help="mcp-lock.json to use (default: nearest above)"
    )
    parser.add_argument(
        "--allow-server",
        action="append",
        default=[],
        metavar="NAME",
        help="with --strict: let this server through when the lock cannot "
        "describe it, or when it is locked but has no tool record. The exact "
        "name; never applies to an unlocked project server (repeatable)",
    )
    parser.add_argument(
        "--allow-source",
        action="append",
        default=[],
        metavar="SOURCE",
        help="with --strict: let servers of this Claude Code source through, "
        "such as managed, claudeai or plugin. Never applies to project "
        "servers (repeatable)",
    )
    parser.add_argument(
        "--print-hook",
        action="store_true",
        help="print the Claude Code settings that register this hook, and exit",
    )
    return parser


def _read_event(stream: object) -> object:
    """Return the hook input parsed from *stream*; raise ``ValueError`` if not JSON."""
    buffer = getattr(stream, "buffer", stream)
    data = buffer.read(MAX_INPUT_BYTES + 1)
    if isinstance(data, str):
        data = data.encode("utf-8", errors="replace")
    if len(data) > MAX_INPUT_BYTES:
        raise ValueError("the hook input is larger than the guard reads")
    return json.loads(data.decode("utf-8-sig"))


def _message(decision: Decision) -> str:
    return f"Credenzo guard: {decision.finding_id} {decision.summary}."


def render(decision: Decision, *, enforce: bool) -> str:
    """Return the hook's stdout for *decision* (empty: nothing to say)."""
    if not decision.deny:
        return ""
    message = _message(decision)
    if not enforce:
        return json.dumps(
            {
                "systemMessage": f"{message} monitor mode: the call was not "
                f"stopped. Fix: {decision.fix}"
            }
        )
    return json.dumps(
        {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": (
                    f"{message} The call was not made. Do not try it again "
                    "and do not change mcp-lock.json. Tell the user that a "
                    "person must review this tool and approve it with "
                    "`credenzo lock`."
                ),
            },
            "systemMessage": f"{message} Fix: {decision.fix}",
        }
    )


def main(argv: Sequence[str] | None = None, stdin: object | None = None) -> int:
    """Run ``credenzo guard``; return the process exit status.

    Exit 0 with JSON on stdout carries a decision (or nothing).  Exit 2 is
    Claude Code's "blocking error": in enforce mode the guard uses it when
    it cannot read its input or fails, so a broken guard stops the call.
    """
    options = build_parser().parse_args(list(sys.argv[1:] if argv is None else argv))
    enforce = options.mode == "enforce"
    if options.print_hook:
        extra: list[str] = []
        if not enforce:
            extra += ["--mode", "monitor"]
        if options.strict:
            extra.append("--strict")
        for name in options.allow_server:
            extra += ["--allow-server", name]
        for source in options.allow_source:
            extra += ["--allow-source", source]
        command = _own_command()
        sys.stdout.write(json.dumps(hook_settings(command, extra), indent=2) + "\n")
        return 0

    source = stdin if stdin is not None else sys.stdin
    if stdin is None and sys.stdin is not None and sys.stdin.isatty():
        sys.stderr.write(
            f"usage: {USAGE}\n"
            "credenzo guard reads a Claude Code hook event on stdin. "
            "Run `credenzo guard --print-hook` for the settings that register it.\n"
        )
        return 2
    try:
        event = _read_event(source)
        project = os.environ.get("CLAUDE_PROJECT_DIR")
        decision = decide(
            event,
            strict=options.strict,
            allow_servers=options.allow_server,
            allow_sources=options.allow_source,
            lock_path=options.lock.expanduser().resolve() if options.lock else None,
            project_dir=Path(project).resolve() if project else None,
        )
        out = render(decision, enforce=enforce)
    except Exception as exc:  # noqa: BLE001 - a guard that fails must say so
        sys.stderr.write(
            f"Credenzo guard: could not decide ({type(exc).__name__}). "
            + ("The call was stopped.\n" if enforce else "The call was not stopped.\n")
        )
        return 2 if enforce else 0
    if out:
        try:
            sys.stdout.write(out + "\n")
            sys.stdout.flush()
        except (OSError, ValueError):
            # The decision did not reach Claude Code.  Exit 2 still stops the
            # call, with the reason on stderr.
            if enforce and decision.deny:
                sys.stderr.write(_message(decision) + "\n")
                return 2
    return 0


def _own_command() -> str:
    """Return the absolute path of this ``credenzo`` executable, or the bare name."""
    import shutil

    argv0 = sys.argv[0] if sys.argv and sys.argv[0] else ""
    for candidate in (argv0, shutil.which("credenzo") or ""):
        if candidate and Path(candidate).name.lower().startswith(
            ("credenzo", "mcp-audit")
        ):
            try:
                return str(Path(candidate).resolve())
            except OSError:
                continue
    return "credenzo"
