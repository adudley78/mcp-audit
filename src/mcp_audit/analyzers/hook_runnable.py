"""Guard hooks that will never run (HOOK-004, HOOK-005; STORY-0156).

A guard that never runs is worse than none: the user thinks they are protected.

**HOOK-004** - a ``PreToolUse`` or ``UserPromptSubmit`` hook in a Claude Code
settings file whose ``command`` Windows' Git Bash cannot start.  Claude Code runs
a hook ``command`` through Git Bash on Windows; when bash can't start it, the
hook exits 127, Claude Code treats that as a non-blocking error and the call goes
ahead, with the failure only in the ``--debug`` log
(anthropics/claude-code#109103, reported by ``daniels-zenity``).  Measured there:

* ``C:\\Windows\\Temp\\hook.cmd`` (unquoted backslashes): bash strips the
  backslashes, exit 127.
* ``C:/Windows/Temp/z space hook/hook.cmd`` (unquoted space): split at the
  space, exit 127.
* the same paths double-quoted, with doubled backslashes, or in forward-slash
  form without a space: run.  A single-quoted backslash path did not run.

LOW in user, project and local settings; MEDIUM in managed settings (the
organization deployed a control that silently does nothing).  The check reads the
command string only; it never runs a hook, and a command is flagged only when it
matches a shape measured above.  A hook with ``"shell": "powershell"`` or an
``args`` list (exec form) is not run through bash and is skipped.

**Cursor hooks.json** - ``~/.cursor/hooks.json`` and ``<project>/.cursor/hooks.json``
(https://cursor.com/docs/hooks: ``{"version": 1, "hooks": {<event>: [{"command":
..., "matcher": ..., "failClosed": ...}]}}``, entries are flat, not nested in a
``hooks`` list).  The existing HOOK-001/002 command checks and HOOK-004 run on
them.  A file that is unreadable, not valid JSON, or not an object is **HOOK-005**
(MEDIUM): Cursor skips such a file without a message (forum.cursor.com/t/177989,
confirmed by Cursor staff), so every guard in it is off.  Reads are capped at
1 MiB, regular files only, and a symlink whose target leaves the home directory
or the project root is not followed.

Nothing here runs a hook or touches the network.  Q-089's matcher half is
HARNESS-006's ``_guards_recursive_delete`` (a PreToolUse hook counts as a shell
guard only when its matcher is empty, ``*``, or names Bash/PowerShell).  Its
"script falls through to allow" half reads hook scripts and is not built.
"""

from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path

from mcp_audit.models import Finding, Severity

MAX_FILE_BYTES = 1024 * 1024


def read_capped(
    path: Path, limit: int = MAX_FILE_BYTES
) -> tuple[bytes | None, str | None]:
    """Read at most *limit* bytes of a regular file without blocking.

    ``(bytes, None)``; ``(None, None)`` when the file does not exist;
    ``(None, reason)`` when it exists but can't be used.  Never raises.  (The
    same contract as ``reach.context.read_capped``, which this module can't
    import without a cycle.)
    """
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        return None, None
    except OSError as exc:
        return None, f"can't be read ({exc.strerror or type(exc).__name__})"
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None, "is not a regular file"
        with os.fdopen(fd, "rb", closefd=False) as handle:
            data = handle.read(limit + 1)
    except OSError as exc:
        return None, f"can't be read ({exc.strerror or type(exc).__name__})"
    finally:
        os.close(fd)
    if len(data) > limit:
        return None, f"is over {limit} bytes"
    return data, None


#: Claude Code events whose hook can stop the action it guards.
CLAUDE_GUARD_EVENTS = ("PreToolUse", "UserPromptSubmit")

#: Cursor events that run before the action and can deny it.
CURSOR_GUARD_EVENTS = (
    "preToolUse",
    "beforeShellExecution",
    "beforeMCPExecution",
    "beforeReadFile",
    "beforeSubmitPrompt",
)

_DRIVE_RE = re.compile(r"^[A-Za-z]:[\\/]")
# A single backslash: not part of a doubled pair.
_SINGLE_BACKSLASH_RE = re.compile(r"(?<!\\)\\(?!\\)")
# A path made of single-backslash segments: drive, ./ ../, %VAR%, or a relative
# path whose last segment has an extension or that has two or more separators.
_BS_PATH_RE = re.compile(
    r"""^(?:
        [A-Za-z]:\\
      | \.{1,2}\\
      | %[A-Za-z_][\w]*%\\
      | \$env:[\w]+\\
      | [\w.-]+(?:\\[\w.-]+)*\\[\w.-]+\.\w{1,5}$
      | [\w.-]+\\[\w.-]+\\[\w.-]+
    )""",
    re.VERBOSE,
)
_EXEC_EXT_RE = re.compile(r"\.(?:cmd|bat|exe|ps1|sh|py|js|ts|vbs|com)(?=\s|$)", re.I)
_PATH_START_RE = re.compile(r"^(?:[/~.\-]|[A-Za-z]:)")


def _split_quotes(command: str) -> list[tuple[str, str]]:
    """Split *command* into ``(quote, text)`` runs: quote is ``""``, ``'`` or ``"``.

    A bash-style scan, enough for the shapes above: a backslash outside quotes
    escapes the next character, inside double quotes it escapes ``"``, ``\\``,
    ``$`` and a backtick, inside single quotes it is literal.
    """
    runs: list[tuple[str, str]] = []
    quote = ""
    buf: list[str] = []
    i = 0
    n = len(command)

    def flush() -> None:
        if buf:
            runs.append((quote, "".join(buf)))
            buf.clear()

    while i < n:
        ch = command[i]
        if quote == "'":
            if ch == "'":
                flush()
                quote = ""
            else:
                buf.append(ch)
        elif quote == '"':
            if ch == "\\" and i + 1 < n and command[i + 1] in '"\\$`':
                i += 1  # escaped char: not a path separator
            elif ch == '"':
                flush()
                quote = ""
            else:
                buf.append(ch)
        elif ch in "'\"":
            flush()
            quote = ch
        else:
            buf.append(ch)
        i += 1
    flush()
    return runs


def unrunnable_reason(command: str) -> str | None:
    """Why Git Bash on Windows can't start *command*, or ``None`` if no known shape.

    Returns ``"backslash"`` or ``"space"``.  Never runs anything.
    """
    text = command.strip()
    if not text:
        return None
    for index, (quote, run) in enumerate(_split_quotes(text)):
        if quote == '"':
            continue  # double-quoted paths run
        for token in run.split():
            if not _SINGLE_BACKSLASH_RE.search(token):
                continue
            # Unquoted: any path-shaped token.  Single-quoted: only the
            # command itself, as a drive path (the measured case: the whole
            # command single-quoted); a quoted script argument ("bash
            # 'C:\\x.sh'") is data bash passes on and is not flagged.
            if quote == "'":
                if index == 0 and _DRIVE_RE.match(token) and "\\" in token:
                    return "backslash"
                continue
            if _BS_PATH_RE.match(token):
                return "backslash"
    # Unquoted space: a drive-letter path whose first executable-looking token
    # ends after a space ("C:/Program Files/guard/run.cmd").
    if _DRIVE_RE.match(text):
        head = re.match(r"[^\"']*", text)
        head_text = head.group(0) if head else ""
        ext = _EXEC_EXT_RE.search(head_text)
        if ext is not None:
            prefix = head_text[: ext.start()]
            pieces = prefix.split()
            if len(pieces) > 1 and not any(_PATH_START_RE.match(p) for p in pieces[1:]):
                return "space"
    return None


def _evidence_command(command: str) -> str:
    return f"Command: {command.strip()[:120]!r}"


def _hook_004(
    *,
    event: str,
    command: str,
    reason: str,
    path: Path,
    client: str,
    managed: bool,
    cursor: bool = False,
) -> Finding:
    what = (
        "an unquoted path containing a space"
        if reason == "space"
        else "a path with single backslashes, outside double quotes"
    )
    if cursor:
        effect = (
            "If the command cannot start, Cursor treats the hook as failed and"
            " lets the action through, because failClosed is not true."
        )
    else:
        effect = (
            "On Windows this hook may exit 127 and allow every call: Claude Code"
            " runs the command through Git Bash, which cannot start it, and"
            " treats the failure as non-blocking, with nothing shown in the"
            " session (anthropics/claude-code#109103)."
        )
    return Finding(
        id="HOOK-004",
        severity=Severity.MEDIUM if managed else Severity.LOW,
        analyzer="config_hygiene",
        client=client,
        server="(hook)",
        title="Guard hook command may never run on Windows",
        description=(
            f"The {event} hook in '{path.name}' has {what}. {effect}"
            + (
                " This file is managed settings, so the control your"
                " organization deployed may be doing nothing."
                if managed
                else ""
            )
        ),
        evidence=_evidence_command(command),
        remediation=(
            "Use forward slashes, double-quote the path"
            ' ("C:/Program Files/guard/run.cmd"), or double the backslashes.'
            " Then test the hook on Windows with claude --debug and confirm it"
            " blocks a call it should block."
        ),
        cwe="CWE-754",
        owasp_mcp_top_10=["MCP02", "MCP07"],
        finding_path=str(path),
    )


def windows_unsafe_hook_findings(
    hooks: object, path: Path, client: str, *, managed: bool = False
) -> list[Finding]:
    """HOOK-004 for a Claude Code ``hooks`` section (one finding per event)."""
    findings: list[Finding] = []
    if not isinstance(hooks, dict):
        return findings
    for event in CLAUDE_GUARD_EVENTS:
        groups = hooks.get(event)
        if not isinstance(groups, list):
            continue
        done = False
        for group in groups:
            if done or not isinstance(group, dict):
                continue
            inner = group.get("hooks")
            for hook in inner if isinstance(inner, list) else []:
                if not isinstance(hook, dict) or hook.get("type") != "command":
                    continue
                if "args" in hook or str(hook.get("shell", "")).lower() == "powershell":
                    continue  # exec form / PowerShell: not a bash command line
                command = hook.get("command")
                if not isinstance(command, str):
                    continue
                reason = unrunnable_reason(command)
                if reason:
                    findings.append(
                        _hook_004(
                            event=event,
                            command=command,
                            reason=reason,
                            path=path,
                            client=client,
                            managed=managed,
                        )
                    )
                    done = True
                    break
    return findings


def managed_hook_findings(
    errors: list[str], *, managed_dir: Path | None = None
) -> list[Finding]:
    """HOOK-004 (MEDIUM) for hooks in the managed settings files.  Never raises."""
    try:
        from mcp_audit.analyzers.secret_reach import (  # noqa: PLC0415
            load_settings_sources,
        )
        from mcp_audit.plugins import mods as _mods  # noqa: PLC0415

        directory = (
            managed_dir if managed_dir is not None else _mods.managed_settings_dir()
        )
        home = Path.home()
        # Only the managed sources are used; user and project files are checked
        # by ConfigHygieneAnalyzer.analyze_config.
        sources = load_settings_sources(
            home, home, home / ".mcp-audit-none", directory, []
        )
        findings: list[Finding] = []
        for source in sources:
            if source.scope != "managed":
                continue
            findings.extend(
                windows_unsafe_hook_findings(
                    source.data.get("hooks"), source.path, "claude-code", managed=True
                )
            )
        return findings
    except Exception as exc:  # noqa: BLE001 - never fail the scan over a hook check
        errors.append(f"hook check error: {type(exc).__name__}: {exc}")
        return []


# -- Cursor hooks.json ---------------------------------------------------------


def cursor_hook_paths(home: Path, project: Path | None) -> list[tuple[Path, Path, str]]:
    """``(file, root it must stay inside, scope)`` for the Cursor hooks files."""
    paths = [(home / ".cursor" / "hooks.json", home, "user")]
    if project is not None:
        paths.append((project / ".cursor" / "hooks.json", project, "project"))
    return paths


def _cursor_commands(hooks: dict) -> list[tuple[str, dict]]:
    """``(event, entry)`` for every flat command entry in a Cursor ``hooks`` map."""
    out: list[tuple[str, dict]] = []
    for event, entries in hooks.items():
        if not isinstance(event, str) or not isinstance(entries, list):
            continue
        for entry in entries:
            if (
                isinstance(entry, dict)
                and entry.get("type", "command") == "command"
                and isinstance(entry.get("command"), str)
                and entry["command"].strip()
            ):
                out.append((event, entry))
    return out


def _problem_finding(path: Path, scope: str, reason: str) -> Finding:
    return Finding(
        id="HOOK-005",
        severity=Severity.MEDIUM,
        analyzer="config_hygiene",
        client="cursor",
        server="(hook)",
        title="Cursor hooks file can't be read, so its hooks never run",
        description=(
            f"The {scope} Cursor hooks file '{path.name}' {reason}. Cursor skips a"
            " hooks file it can't read or parse without showing a message"
            " (forum.cursor.com/t/177989, confirmed by Cursor staff), so every"
            " guard hook in it is off while it looks configured."
        ),
        evidence=f"{path}: {reason}",
        remediation=(
            "Fix the file so it is valid JSON of the form"
            ' {"version": 1, "hooks": {...}} and readable by your user, then'
            " check the Hooks tab in Cursor's settings shows your hooks."
        ),
        cwe="CWE-754",
        owasp_mcp_top_10=["MCP02", "MCP07"],
        finding_path=str(path),
    )


def cursor_hook_findings(
    errors: list[str],
    *,
    home: Path | None = None,
    project: Path | None = None,
    user: bool = True,
) -> list[Finding]:
    """Check ``~/.cursor/hooks.json`` and ``<project>/.cursor/hooks.json``.

    Read-only, capped, and never raises.  *project* defaults to the working
    directory (skipped when it is the home directory, where the two files are
    the same file).
    """
    try:
        home = home if home is not None else Path.home()
        if project is None:
            project = Path.cwd()
        try:
            if project.resolve() == home.resolve():
                project = None
        except OSError:
            pass
        findings: list[Finding] = []
        for path, root, scope in cursor_hook_paths(home, project):
            if scope == "user" and not user:
                continue
            findings.extend(_one_cursor_file(path, root, scope, errors))
        return findings
    except Exception as exc:  # noqa: BLE001
        errors.append(f"cursor hooks check error: {type(exc).__name__}: {exc}")
        return []


def _one_cursor_file(
    path: Path, root: Path, scope: str, errors: list[str]
) -> list[Finding]:
    try:
        is_link = path.is_symlink()
        if is_link:
            try:
                path.resolve().relative_to(root.resolve())
            except (ValueError, OSError):
                errors.append(
                    f"cursor hooks: {path} is a symlink that leaves {root}; not read"
                )
                return []
    except OSError:
        return []
    data, problem = read_capped(path, MAX_FILE_BYTES)
    if data is None and problem is None:
        return []  # no file
    if data is None:
        return [_problem_finding(path, scope, problem or "can't be read")]
    try:
        raw = json.loads(data.decode("utf-8-sig"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return [_problem_finding(path, scope, "is not valid JSON")]
    if not isinstance(raw, dict):
        return [_problem_finding(path, scope, "is not a JSON object")]
    hooks = raw.get("hooks")
    if not isinstance(hooks, dict) or not hooks:
        return []

    from mcp_audit.analyzers.config_hygiene import ConfigHygieneAnalyzer  # noqa: PLC0415

    entries = _cursor_commands(hooks)
    # One group per command, so every command reaches the HOOK-001/002 checks
    # (several commands can share an event).
    flat: dict[str, list] = {}
    for event, e in entries:
        flat.setdefault(event, []).append(
            {"hooks": [{"type": "command", "command": e["command"]}]}
        )
    findings = ConfigHygieneAnalyzer()._check_hook_commands(flat, path, "cursor")
    seen_events: set[str] = set()
    for event, entry in entries:
        if event not in CURSOR_GUARD_EVENTS or event in seen_events:
            continue
        if entry.get("failClosed") is True:
            continue
        reason = unrunnable_reason(entry["command"])
        if reason:
            seen_events.add(event)
            findings.append(
                _hook_004(
                    event=event,
                    command=entry["command"],
                    reason=reason,
                    path=path,
                    client="cursor",
                    managed=False,
                    cursor=True,
                )
            )
    for f in findings:
        f.finding_path = str(path)
    return findings
