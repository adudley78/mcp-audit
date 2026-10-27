"""Claude Code sandbox settings a repository can loosen (SANDBOX-001..005).

STORY-0093 (EPIC-0007).  Claude Code's Bash sandbox is configured by the
``sandbox`` block of any settings file, and Claude Code merges that block
across user, project and local settings.  Anthropic's sandboxing doc says a
repository's ``.claude/settings.json`` can turn on keys that "weaken the
sandbox" unless the organisation's managed settings make it "admin-required",
and that some keys "a repository can't turn on".  Every key name, which file
may set it, and what it does comes from Anthropic's documentation and is
quoted in the finding:

- code.claude.com/docs/en/sandboxing ("sandboxing doc")
- code.claude.com/docs/en/settings-reference ("settings reference"), whose
  index gives each key a scope: ``Any file``, ``User or managed`` or
  ``Managed``
- code.claude.com/docs/en/settings ("settings doc") for local settings and git
- code.claude.com/docs/en/permissions ("permissions doc") for when a local
  settings file counts as the repository's

Checks:

- **SANDBOX-001** (HIGH/MEDIUM, INFO for a proxy port under the user's
  ``strictAllowlist``): a repository settings file turns on a key that weakens
  the sandbox, turns the sandbox off, or points it at a proxy.
- **SANDBOX-002** (MEDIUM, HIGH when nothing prompts): it takes a shell,
  interpreter, wrapper, package runner, container runtime or every command
  out of the sandbox (``excludedCommands``); HIGH for opening the Docker or
  Podman socket (``allowUnixSockets``).
- **SANDBOX-003** (MEDIUM, INFO under the user's ``strictAllowlist``): it adds
  a host anyone can publish to, or every host, to ``allowedDomains``.
- **SANDBOX-004** (INFO): a key Claude Code ignores in this file ("dead
  config"), such as ``strictAllowlist`` or ``allowManagedDomainsOnly`` in a
  repository.
- **SANDBOX-005** (MEDIUM/LOW): a ``.claude/settings.local.json`` inside a git
  work tree that no ignore file covers, and home-directory paths with a
  username in a settings file headed for git.

All of them run in step 0b of :func:`mcp_audit.scanner._run_static_pipeline`
(:func:`analyze_sandbox_files`), not in ``analyze_config``: deciding whether a
local settings file is the repository's needs git's ignore files
(:mod:`mcp_audit._gitignore`), and SANDBOX-002/003's severity needs the user's
own ``~/.claude/settings.json``.  Each settings file is checked inside its own
``try``, and read failures and crashes go to ``result.errors``, so nothing
here can drop another check.  :func:`analyze_sandbox_settings` is the pure
per-file part.  Nothing is executed; ``git`` is never run.

Which files a repository controls:

- ``.claude/settings.json`` outside the home directory: always (it is the
  shared, committed file).
- ``.claude/settings.local.json``: the permissions doc calls it "normally your
  own file" and says "When the file is tracked in git, or ``.claude`` is a
  symlink, Claude Code treats it as repository-supplied".  It gets
  SANDBOX-001..003 when ``.claude`` is a symlink or no ignore file covers it
  (it is tracked, or will be), at MEDIUM at most when its ignore state can't
  be read, and not at all when git ignores it or it is outside a work tree.
- ``~/.claude/settings.json`` and ``~/.claude/settings.local.json``: the
  user's own; SANDBOX-004 only.

Each file is evaluated on its own, plus the two user-settings keys above;
managed settings and ``--settings`` (which can make the sandbox admin-required
or lock the allowlist) are not seen (GAPS.md).
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from mcp_audit._gitignore import (
    IgnoreFileReader,
    IgnoreStateUnknownError,
    find_work_tree_root,
)
from mcp_audit.analyzers.credentials import SECRET_PATTERNS
from mcp_audit.analyzers.permissions import (
    ClaudeSettings,
    is_claude_code_settings_file,
    load_claude_settings,
    settings_scope,
)
from mcp_audit.models import Finding, Severity

#: Analyzer label: the same family as PERM-* and HARNESS-*.
ANALYZER_NAME = "config_hygiene"
#: Start of every message this module adds to ``result.errors``.
ERROR_PREFIX = "SANDBOX checks: "

#: Items quoted in one finding before "(+N more)".
_LIST_CAP = 20
#: Longest value quoted in a finding.
_QUOTE_CHARS = 120
#: Text masked before a value is cut to :data:`_QUOTE_CHARS`.  Masking runs on
#: this much so a secret that starts inside the quoted part is masked whole.
_MASK_WINDOW = 64 * 1024
#: Largest user settings file read for ``strictAllowlist``/``defaultMode``.
_USER_SETTINGS_MAX_BYTES = 4 * 1024 * 1024

_REPO_SUPPLIED_QUOTE = (
    'the permissions doc: "When the file is tracked in git, or .claude is a'
    " symlink, Claude Code treats it as repository-supplied instead and holds"
    ' its rules until you trust the folder."'
)

#: Sandboxing doc, "Repository settings under an admin-required sandbox".
_ADMIN_REQUIRED_NOTE = (
    "Claude Code ignores these in a repository's files only while managed"
    " settings or --settings make the sandbox admin-required"
    " (allowUnsandboxedCommands false in managed settings or --settings, or"
    " allowManagedDomainsOnly true in managed settings; Claude Code 2.1.285 or"
    " later)."
)
#: Sandboxing doc, "Locks that apply without an admin-required sandbox":
#: network.strictAllowlist in managed settings, --settings or user settings
#: makes Claude Code ignore a repository's "proxy ports, allowedDomains, and
#: WebFetch(domain:...) allow rules"; network.deniedDomains or a
#: WebFetch(domain:...) deny rule in managed settings or --settings makes it
#: ignore "httpProxyPort and socksProxyPort".  "Requires Claude Code v2.1.285
#: or later."
_STRICT_ALLOWLIST_NOTE = (
    "It also ignores a repository's allowedDomains, proxy ports and"
    " WebFetch(domain:...) allow rules while managed settings, --settings or"
    ' your user settings set network.strictAllowlist (sandboxing doc, "Locks'
    ' that apply without an admin-required sandbox"; 2.1.285 or later).'
)
_DENIED_DOMAINS_NOTE = (
    "It ignores a repository's proxy ports while managed settings or"
    " --settings set network.deniedDomains or a WebFetch(domain:...) deny rule"
    " (same section)."
)
_PORT_NOTES = (_ADMIN_REQUIRED_NOTE, _STRICT_ALLOWLIST_NOTE, _DENIED_DOMAINS_NOTE)
_DOMAIN_NOTES = (_ADMIN_REQUIRED_NOTE, _STRICT_ALLOWLIST_NOTE)

# ── Shared helpers ────────────────────────────────────────────────────────────


def _mask(text: str) -> str:
    """Replace every SECRET_PATTERNS match and URL user info with ``***``."""
    for _name, pattern, _provider in SECRET_PATTERNS:
        text = pattern.sub("***", text)
    return re.sub(r"(?<=://)[^/@\s]+@", "***@", text)


def _quote(value: object) -> str:
    """A finding-safe rendering of a settings value: masked and length-capped."""
    try:
        text = value if isinstance(value, str) else json.dumps(value, default=str)
    except (TypeError, ValueError, RecursionError):
        text = type(value).__name__
    text = _mask(text[:_MASK_WINDOW])
    if len(text) > _QUOTE_CHARS:
        text = text[:_QUOTE_CHARS] + "…"
    return repr(text) if isinstance(value, str) else text


def _capped(items: list[str], sep: str = "; ") -> str:
    shown = sep.join(items[:_LIST_CAP])
    if len(items) > _LIST_CAP:
        shown += f"{sep}(+{len(items) - _LIST_CAP} more)"
    return shown


def _get(block: dict, dotted: str) -> tuple[bool, object]:
    """``(present, value)`` for a dotted key under the ``sandbox`` block."""
    current: object = block
    for part in dotted.split("."):
        if not isinstance(current, dict) or part not in current:
            return False, None
        current = current[part]
    return True, current


def _in_configuration_home(path: Path) -> bool:
    """True for ``~/.claude/settings*.json``: the user's own files, not a repository's.

    Permissions doc: in "your configuration home ... your home directory",
    Claude Code applies that folder's ``.claude/settings.local.json`` as the
    user's own.  Home that can't be resolved counts as not home (fail closed).
    """
    try:
        return path.parent.parent.resolve() == Path.home().resolve()
    except (OSError, RuntimeError):
        return False


# ── Context: which file this is, and what the user's own settings lock ───────


@dataclass(frozen=True)
class UserSettingsLocks:
    """What the user's ``~/.claude/settings.json`` sets that changes a severity.

    Attributes:
        strict_allowlist: ``sandbox.network.strictAllowlist`` is ``true``:
            Claude Code then ignores a repository's ``allowedDomains`` and
            proxy ports (2.1.285+), so SANDBOX-003 and proxy-port hits drop
            to INFO.
        default_mode: ``permissions.defaultMode``, when a string:
            ``bypassPermissions`` or ``auto`` there raise SANDBOX-002.
    """

    strict_allowlist: bool = False
    default_mode: str | None = None


#: Where a settings file's sandbox keys come from, for SANDBOX-001..003.
ORIGIN_PROJECT = "project"  # shared .claude/settings.json in a repository
ORIGIN_LOCAL_TRACKED = "local-in-git"  # local file no ignore file covers
ORIGIN_LOCAL_SYMLINK = "local-symlink"  # local file whose .claude is a link
ORIGIN_LOCAL_UNKNOWN = "local-unknown"  # local file, ignore state unreadable
ORIGIN_OWN = "own"  # the user's own file: SANDBOX-004 only


@dataclass(frozen=True)
class SandboxContext:
    """What :func:`analyze_sandbox_settings` needs beyond the file itself.

    Attributes:
        origin: One of the ``ORIGIN_*`` values.
        user: Locks from the user's own settings file.
    """

    origin: str = ORIGIN_OWN
    user: UserSettingsLocks = field(default_factory=UserSettingsLocks)


_ORIGIN_TEXT: dict[str, tuple[str, str]] = {
    ORIGIN_PROJECT: (
        "committed project settings (.claude/settings.json), which reach"
        " everyone who clones the repository",
        "A cloned repository chooses these for everyone who opens it.",
    ),
    ORIGIN_LOCAL_TRACKED: (
        "local project settings (.claude/settings.local.json) that no ignore"
        " file covers, so git tracks it or will",
        f"A tracked local file is the repository's: {_REPO_SUPPLIED_QUOTE}",
    ),
    ORIGIN_LOCAL_SYMLINK: (
        "local project settings (.claude/settings.local.json) in a .claude"
        " directory that is a symlink",
        f"So Claude Code treats it as the repository's: {_REPO_SUPPLIED_QUOTE}",
    ),
    ORIGIN_LOCAL_UNKNOWN: (
        "local project settings (.claude/settings.local.json) whose git state"
        " mcp-audit could not read (see the scan's errors)",
        "If git tracks it, it is the repository's ("
        + _REPO_SUPPLIED_QUOTE
        + "); reported at MEDIUM at most because that is unknown.",
    ),
}


def _default_context(settings: ClaudeSettings) -> SandboxContext:
    """A shared project file is the repository's; without context, nothing else is."""
    if settings.scope == "project" and not _in_configuration_home(settings.path):
        return SandboxContext(ORIGIN_PROJECT)
    return SandboxContext(ORIGIN_OWN)


@dataclass(frozen=True)
class _Hit:
    """One flagged key or entry: where it is, what it does here."""

    where: str  # e.g. "sandbox.excludedCommands contains 'python *'"
    why: str
    notes: tuple[str, ...] = ()


@dataclass(frozen=True)
class _Check:
    finding_id: str
    title: str
    remediation: str
    cwe: str
    owasp: tuple[str, ...]


def _build(
    check: _Check,
    severity: Severity,
    settings: ClaudeSettings,
    where_text: str,
    client: str,
    analyzer: str,
    summary: str,
    hits: list[_Hit],
) -> Finding:
    """One finding per check and severity in one settings file."""
    notes: list[str] = []
    for hit in hits:
        notes.extend(note for note in hit.notes if note not in notes)
    tail = " ".join([summary, *notes]).strip()
    return Finding(
        id=check.finding_id,
        severity=severity,
        analyzer=analyzer,
        client=client,
        server="(config-level)",
        title=check.title,
        description=(
            f"In {where_text}: "
            + _capped([f"{hit.where}: {hit.why}" for hit in hits])
            + f". {tail}"
        ),
        evidence=f"{settings.path}: " + _capped([hit.where for hit in hits]),
        remediation=check.remediation,
        cwe=check.cwe,
        owasp_mcp_top_10=list(check.owasp),
        finding_path=str(settings.path),
    )


_SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)
_RANK = {sev: rank for rank, sev in enumerate(reversed(_SEVERITY_ORDER))}


def _cap(severity: Severity, ceiling: Severity | None) -> Severity:
    if ceiling is not None and _RANK[severity] > _RANK[ceiling]:
        return ceiling
    return severity


def _grouped(
    graded: list[tuple[Severity, _Hit]],
) -> list[tuple[Severity, list[_Hit]]]:
    groups: dict[Severity, list[_Hit]] = {}
    for severity, hit in graded:
        groups.setdefault(severity, []).append(hit)
    return [(sev, groups[sev]) for sev in _SEVERITY_ORDER if sev in groups]


def _findings(
    check: _Check,
    graded: list[tuple[Severity, _Hit]],
    settings: ClaudeSettings,
    context: SandboxContext,
    client: str,
    analyzer: str,
    basis: str,
) -> list[Finding]:
    where_text, origin_tail = _ORIGIN_TEXT[context.origin]
    ceiling = Severity.MEDIUM if context.origin == ORIGIN_LOCAL_UNKNOWN else None
    capped = [(_cap(sev, ceiling), hit) for sev, hit in graded]
    return [
        _build(
            check,
            severity,
            settings,
            where_text,
            client,
            analyzer,
            f"{basis} {origin_tail}",
            hits,
        )
        for severity, hits in _grouped(capped)
    ]


_STRICT_ALLOWLIST_HIT = (
    "; your ~/.claude/settings.json sets network.strictAllowlist: true, so"
    " Claude Code 2.1.285 or later ignores this repository entry"
)

# ── SANDBOX-001: keys that weaken or switch off the sandbox ──────────────────


def _is_true(value: object) -> bool:
    """Only a JSON ``true``.

    A string such as ``"true"`` is an invalid value, and the settings doc says
    Claude Code "skips the broken file or values and continues with the
    rest", so it loosens nothing.
    """
    return value is True


def _is_false(value: object) -> bool:
    return value is False


def _is_port(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 < value < 65536


@dataclass(frozen=True)
class _Loosening:
    """A sandbox key a repository file can set that loosens the sandbox."""

    key: str
    applies: Callable[[object], bool]
    severity: Severity
    effect: str
    project_only: bool = False
    is_port: bool = False


#: Sandboxing doc, "Keep developers from widening the policy": "Unless managed
#: settings set them, a developer's user settings or --settings can turn on the
#: following keys. A repository's .claude/settings.json can too, unless the
#: sandbox is admin-required. Each one weakens the sandbox" (the four
#: booleans).  The same doc's admin-required table lists, among "the settings
#: that loosen it", ``enabled`` and ``failIfUnavailable`` ("false, when the
#: developer's ~/.claude/settings.json sets true") and the proxy ports.
_LOOSENING_KEYS: tuple[_Loosening, ...] = (
    _Loosening(
        "enableWeakerNestedSandbox",
        _is_true,
        Severity.HIGH,
        "on Linux and WSL2 the sandbox bind-mounts the existing /proc, which"
        ' "exposes process information that a fresh mount would hide"; the'
        ' sandboxing doc: "This option considerably weakens security"',
    ),
    _Loosening(
        "enableWeakerNetworkIsolation",
        _is_true,
        Severity.HIGH,
        "on macOS sandboxed commands can reach the system TLS trust service,"
        ' "opening a potential data exfiltration path through the trust service"',
    ),
    _Loosening(
        "network.allowAllUnixSockets",
        _is_true,
        Severity.HIGH,
        'sandboxed commands "can connect to every Unix socket", the Docker'
        " socket included (on WSL2 also the interop socket that launches Windows"
        " binaries such as cmd.exe)",
    ),
    _Loosening(
        "network.allowLocalBinding",
        _is_true,
        Severity.HIGH,
        "on macOS sandboxed commands can listen on ports and connect to any"
        " port on localhost: \"A localhost service that doesn't require"
        " authentication, such as a debugger, can then act for the command"
        ' outside the sandbox" (no effect on Linux and WSL2)',
    ),
    _Loosening(
        "enabled",
        _is_false,
        Severity.HIGH,
        "Bash commands run unsandboxed in this project even when your"
        " ~/.claude/settings.json turns the sandbox on (project settings take"
        " precedence over user settings)",
        project_only=True,
    ),
    _Loosening(
        "failIfUnavailable",
        _is_false,
        Severity.MEDIUM,
        "when the sandbox can't start, commands run unsandboxed instead of"
        " Claude Code refusing to start, even when your ~/.claude/settings.json"
        " sets true",
        project_only=True,
    ),
    _Loosening(
        "network.httpProxyPort",
        _is_port,
        Severity.MEDIUM,
        'sandboxed HTTP traffic goes to this local port: "Your proxy takes over'
        " filtering, and Claude Code stops applying its domain lists and network"
        ' prompts to traffic sent there"',
        is_port=True,
    ),
    _Loosening(
        "network.socksProxyPort",
        _is_port,
        Severity.MEDIUM,
        'sandboxed SOCKS traffic goes to this local port: "Your proxy takes'
        " over filtering, and Claude Code stops applying its domain lists and"
        ' network prompts to traffic sent there"',
        is_port=True,
    ),
)

_SANDBOX_001 = _Check(
    finding_id="SANDBOX-001",
    title="Repository settings weaken or switch off the Bash sandbox",
    remediation=(
        "Remove these keys from the repository's settings. If one machine needs"
        " one (for example enableWeakerNestedSandbox inside an unprivileged"
        " container), set it in that user's ~/.claude/settings.json. An"
        " organisation can stop repositories from setting them by making the"
        " sandbox admin-required in managed settings (allowUnsandboxedCommands:"
        " false) and setting each weakening key to false there."
    ),
    cwe="CWE-693",
    owasp=("MCP02", "MCP05"),
)
_SANDBOX_001_BASIS = (
    "Sandboxing doc: \"A repository's .claude/settings.json can too [turn these"
    " keys on], unless the sandbox is admin-required. Each one weakens the"
    ' sandbox."'
)


def _check_sandbox_001(
    settings: ClaudeSettings, context: SandboxContext, client: str, analyzer: str
) -> list[Finding]:
    graded: list[tuple[Severity, _Hit]] = []
    for item in _LOOSENING_KEYS:
        if item.project_only and settings.scope != "project":
            # Claude Code's /sandbox panel writes `enabled` to the local file,
            # so a false there is usually the user's own choice.
            continue
        present, value = _get(settings.sandbox, item.key)
        if not (present and item.applies(value)):
            continue
        where = f"sandbox.{item.key} = {_quote(value)}"
        if item.is_port and context.user.strict_allowlist:
            graded.append(
                (Severity.INFO, _Hit(where, item.effect + _STRICT_ALLOWLIST_HIT))
            )
        elif item.is_port:
            graded.append((item.severity, _Hit(where, item.effect, _PORT_NOTES)))
        else:
            graded.append(
                (item.severity, _Hit(where, item.effect, (_ADMIN_REQUIRED_NOTE,)))
            )
    return _findings(
        _SANDBOX_001, graded, settings, context, client, analyzer, _SANDBOX_001_BASIS
    )


# ── SANDBOX-002: commands taken out of the sandbox; container sockets ────────

_SHELLS_AND_INTERPRETERS: frozenset[str] = frozenset(
    {
        "sh", "bash", "zsh", "dash", "ksh", "fish", "csh", "tcsh",
        "pwsh", "powershell",
        "node", "nodejs", "deno", "bun", "ruby", "perl", "php", "lua",
        "osascript",
    }
)  # fmt: skip
_PYTHON_RE = re.compile(r"^(?:python|pypy)(?:\d+(?:\.\d+)*)?$")
#: Wrappers that run the command after them.  Permissions doc, "Wrappers":
#: "The stripped wrappers are timeout, time, nice, nohup, and stdbuf, plus the
#: shell builtins command and builtin, and zsh's noglob. Each runs its argument
#: as the actual command"; "Exec wrappers: such as watch, setsid, ionice, and
#: flock".  ``env`` runs the program it names.  Excluded-command entries are
#: matched against "the text of the call" (sandboxing doc), so ``timeout 30 *``
#: covers ``timeout 30 bash -c '...'``.  ``xargs`` is not here: the settings
#: reference says "Claude Code keeps a Bash call sandboxed" when it is "A
#: command starting with sudo, eval, or xargs".
_WRAPPERS: frozenset[str] = frozenset(
    {
        "env", "timeout", "time", "nice", "nohup", "stdbuf", "command",
        "builtin", "noglob", "watch", "setsid", "ionice", "flock",
    }
)  # fmt: skip
#: Wrapper arguments that are not the command: a duration, a number, an
#: environment assignment.
_WRAPPER_ARG_RE = re.compile(r"^(?:\d+(?:\.\d+)?[smhd]?|[A-Za-z_][A-Za-z0-9_]*=.*)$")
#: Package runners that execute whatever package or command follows them.
_PACKAGE_RUNNERS: frozenset[str] = frozenset({"npx", "bunx", "pnpx", "uvx"})
#: ``<program> <subcommand>`` pairs that run whatever follows (permissions doc,
#: "Wrappers": "Because these tools execute their arguments as a command").
_RUNNER_SUBCOMMANDS: frozenset[tuple[str, str]] = frozenset(
    {
        ("pipx", "run"), ("npm", "exec"), ("pnpm", "dlx"), ("pnpm", "exec"),
        ("yarn", "dlx"), ("yarn", "exec"), ("bun", "x"), ("uv", "run"),
        ("poetry", "run"), ("pdm", "run"), ("devbox", "run"), ("mise", "exec"),
        ("mise", "x"), ("direnv", "exec"), ("nix", "run"),
    }
)  # fmt: skip
_CONTAINER_PROGRAMS: frozenset[str] = frozenset({"docker", "podman", "nerdctl"})
#: Subcommands that start a container or act on a compose file.
_CONTAINER_RUN_SUBCOMMANDS: frozenset[str] = frozenset(
    {"run", "exec", "create", "container", "compose"}
)
_COMPOSE_PROGRAMS: frozenset[str] = frozenset({"docker-compose", "podman-compose"})
#: Container daemon sockets: "allowing access to /var/run/docker.sock
#: effectively grants access to the host system through the Docker socket".
_CONTAINER_SOCKETS: frozenset[str] = frozenset(
    {"docker.sock", "podman.sock", "containerd.sock"}
)


def _program(word: str) -> str:
    """Basename, lower-cased, ``.exe`` dropped (``/bin/Py3.exe`` → ``py3``)."""
    name = re.split(r"[\\/]", word)[-1].lower()
    return name[:-4] if name.endswith(".exe") else name


def _options_only(words: list[str]) -> bool:
    return all(word.startswith("-") for word in words)


def _pattern_words(pattern: str) -> tuple[list[str], bool]:
    """Words of a ``Bash(...)``-syntax pattern and whether it ends in a wildcard."""
    text = pattern.strip()
    for suffix in (":*", " *", "*"):
        if text.endswith(suffix):
            return text[: -len(suffix)].split(), True
    return text.split(), False


def runs_anything_outside_sandbox(entry: object) -> str | None:
    """Why an ``excludedCommands`` entry takes code-running commands out, if it does.

    Entries use ``Bash(...)`` rule syntax ("a pattern with no wildcard is an
    exact match"), so only an entry whose arguments are left open by a
    trailing wildcard is reported: ``python *``, ``bash -c *``, ``npx *``,
    ``uv run *``, ``env *``, ``timeout 30 *``, ``docker *``,
    ``docker compose *``, ``docker run *``, or a leading ``*`` (any program in
    front of the rest).  An entry narrowed to a script or subcommand
    (``python scripts/load.py *``, ``uv run pytest *``, ``docker ps``) is not.
    ``sudo``, ``eval`` and ``xargs`` entries are not reported: the settings
    reference says Claude Code keeps "A command starting with sudo, eval, or
    xargs" sandboxed.

    Returns:
        A short reason, or ``None``.
    """
    if not isinstance(entry, str):
        return None
    text = entry.strip()
    if not text:
        return None
    if text == "*":
        return "matches every command"
    if text.startswith("*"):
        # Permissions doc: Bash(* --version) matches bash -c 'echo hi' --version.
        return "a leading * matches any program in front of the rest"
    words, wildcard = _pattern_words(text)
    if not wildcard:
        return None
    if not words:
        return "matches every command"
    program, rest = _program(words[0]), words[1:]
    interpreter = program in _SHELLS_AND_INTERPRETERS or bool(_PYTHON_RE.match(program))
    if interpreter and _options_only(rest):
        return "a shell or interpreter with any arguments"
    if program in _WRAPPERS:
        if program == "command" and any(w in ("-v", "-V") for w in rest):
            return None  # the query form: "looks up a command rather than running one"
        positional = [w for w in rest if not w.startswith("-")]
        if program == "flock":  # flock <lockfile> <command>
            positional = positional[1:]
        if all(_WRAPPER_ARG_RE.match(w) for w in positional):
            return "a wrapper that runs whatever command follows it"
        return None
    if program in _PACKAGE_RUNNERS and _options_only(rest):
        return "a package runner with any package"
    if rest and (program, rest[0].lower()) in _RUNNER_SUBCOMMANDS:
        positional = [w for w in rest[1:] if not w.startswith("-")]
        if program == "direnv":  # direnv exec <dir> <command>
            positional = positional[1:]
        return None if positional else "an environment runner with any command"
    if program in _COMPOSE_PROGRAMS:
        return "runs the compose file, which Claude can edit"
    if program in _CONTAINER_PROGRAMS:
        positional = [w for w in rest if not w.startswith("-")]
        if not positional:
            return f"{program} with any arguments"
        sub = positional[0].lower()
        if sub == "compose":
            return f"{program} compose runs the compose file, which Claude can edit"
        if sub in _CONTAINER_RUN_SUBCOMMANDS and len(positional) == 1:
            return f"{program} {sub} with any image, mounts and command"
    return None


def allow_rule_overlapping(entry: str, settings: ClaudeSettings) -> str | None:
    """A Bash allow rule in *settings* that approves some command *entry* excludes.

    Sandboxing doc: "commands your allow rules cover run without a prompt",
    so such a command runs outside the sandbox and unprompted.  Patterns are
    compared word by word: a wildcard allow rule whose words start the
    excluded pattern's (``Bash(docker *)`` for ``docker compose *``), or an
    allow rule that starts with the excluded pattern's words
    (``Bash(docker compose up)``), overlaps.  A ``*`` word in the allow rule
    matches any word (``Bash(docker * up)``); other wildcards inside a word
    are compared literally.  A bare ``Bash``, ``Bash(*)`` or leading-``*``
    rule overlaps everything.
    """
    excluded_words, _ = _pattern_words(entry)
    every_command = entry.strip().startswith("*")
    for rule in settings.rules_in("allow"):
        if rule.tool != "Bash":
            continue
        spec = "*" if rule.specifier is None else rule.specifier.strip()
        if every_command or not spec or spec.startswith("*"):
            return rule.text
        allow_words, allow_wild = _pattern_words(spec)
        if not allow_words:
            return rule.text
        shared = min(len(allow_words), len(excluded_words))
        if any(
            a not in ("*", e)
            for a, e in zip(allow_words[:shared], excluded_words[:shared], strict=True)
        ):
            continue
        if allow_wild and len(allow_words) <= len(excluded_words):
            return rule.text
        if len(excluded_words) <= len(allow_words):
            return rule.text
    return None


def _socket_name(entry: object) -> str | None:
    if not isinstance(entry, str):
        return None
    name = re.split(r"[\\/]", entry.strip().rstrip("/"))[-1].lower()
    return name if name in _CONTAINER_SOCKETS else None


_SANDBOX_002 = _Check(
    finding_id="SANDBOX-002",
    title="Repository settings take code-running commands out of the sandbox",
    remediation=(
        "Remove these entries from the repository's settings. Keep a command"
        " sandboxed and give it the one directory or host it needs with"
        " sandbox.filesystem.allowWrite or sandbox.network.allowedDomains; if a"
        " tool must run unsandboxed, list the narrowest pattern (one script or"
        " subcommand) in your own ~/.claude/settings.json, and don't also allow"
        " it. Don't open the Docker or Podman socket to sandboxed commands."
    ),
    cwe="CWE-250",
    owasp=("MCP05", "MCP02"),
)
_SANDBOX_002_BASIS = (
    'Sandboxing doc: "An excluded command runs with your full access. A broad'
    " entry such as docker * covers everything that tool can do. If you write a"
    " pattern that covers an interpreter, a script inside your working"
    " directory, or a tool that acts on a file there, as docker compose does"
    " with its compose file, Claude can write that file and then run it outside"
    ' the sandbox"; "An excluded command goes through the regular permission'
    ' flow": commands an allow rule covers "run without a prompt", "In auto'
    ' mode, the classifier reviews other excluded commands", and "In'
    " bypassPermissions mode, an excluded command runs without a prompt unless"
    ' an ask rule matches it"; otherwise a "Bash command (unsandboxed)" prompt'
    ' appears. And "allowing access to /var/run/docker.sock effectively grants'
    ' access to the host system through the Docker socket" (allowUnixSockets'
    " applies on macOS only)."
)


def _exclusion_severity(
    entry: str, settings: ClaudeSettings, user: UserSettingsLocks
) -> tuple[Severity, str]:
    """MEDIUM while a prompt still guards the excluded command; HIGH when none does.

    A project or local file's own ``defaultMode`` is not counted: the settings
    reference says "auto and bypassPermissions don't take effect from project
    or local settings".  ``dontAsk`` does not raise it: in that mode "Claude
    Code auto-denies every tool call that would otherwise prompt you"
    (permission-modes doc).
    """
    allow = allow_rule_overlapping(entry, settings)
    if allow is not None:
        return (
            Severity.HIGH,
            f"; allow {allow!r} in this file approves it, so it runs outside the"
            " sandbox with no prompt",
        )
    if user.default_mode == "bypassPermissions":
        return (
            Severity.HIGH,
            "; your ~/.claude/settings.json starts sessions in bypassPermissions"
            " mode, where it runs with no prompt",
        )
    if user.default_mode == "auto":
        return (
            Severity.HIGH,
            "; your ~/.claude/settings.json starts sessions in auto mode, where"
            " the classifier, not you, decides whether it runs",
        )
    return (
        Severity.MEDIUM,
        '; a "Bash command (unsandboxed)" prompt still guards it in Manual and'
        " acceptEdits modes",
    )


def _check_sandbox_002(
    settings: ClaudeSettings, context: SandboxContext, client: str, analyzer: str
) -> list[Finding]:
    graded: list[tuple[Severity, _Hit]] = []
    notes = (_ADMIN_REQUIRED_NOTE,)
    present, excluded = _get(settings.sandbox, "excludedCommands")
    if present and isinstance(excluded, list):
        for entry in excluded:
            reason = runs_anything_outside_sandbox(entry)
            if not reason or not isinstance(entry, str):
                continue
            severity, why = _exclusion_severity(entry, settings, context.user)
            graded.append(
                (
                    severity,
                    _Hit(
                        f"sandbox.excludedCommands contains {_quote(entry)}",
                        reason + why,
                        notes,
                    ),
                )
            )
    present, sockets = _get(settings.sandbox, "network.allowUnixSockets")
    if present and isinstance(sockets, list):
        for entry in sockets:
            name = _socket_name(entry)
            if name:
                graded.append(
                    (
                        Severity.HIGH,
                        _Hit(
                            "sandbox.network.allowUnixSockets contains"
                            f" {_quote(entry)}",
                            f"the {name} socket controls the container daemon on the"
                            " host, and in the sandbox's default auto-allow mode a"
                            " sandboxed command runs without a prompt",
                            notes,
                        ),
                    )
                )
    return _findings(
        _SANDBOX_002, graded, settings, context, client, analyzer, _SANDBOX_002_BASIS
    )


# ── SANDBOX-003: hosts anyone can publish to in allowedDomains ───────────────

#: Hosts where anyone with a free account can receive data, by MITRE ATT&CK
#: sub-technique: T1567.001 Exfiltration to Code Repository ("Code
#: repositories are often accessible via an API (ex: https://api.github.com)"),
#: T1567.003 Exfiltration to Text Storage Sites ("such as pastebin[.]com"),
#: T1567.004 Exfiltration Over Webhook ("Discord, Slack, and webhook.site").
#: Sandboxing doc: "Allowing broad domains such as github.com can create paths
#: for data exfiltration."  A subdomain matches its parent entry.
_CONTENT_HOSTS: dict[str, str] = {
    "github.com": "a code host (T1567.001)",
    "gitlab.com": "a code host (T1567.001)",
    "bitbucket.org": "a code host (T1567.001)",
    "pastebin.com": "a paste site (T1567.003)",
    "paste.ee": "a paste site (T1567.003)",
    "hastebin.com": "a paste site (T1567.003)",
    "dpaste.com": "a paste site (T1567.003)",
    "dpaste.org": "a paste site (T1567.003)",
    "rentry.co": "a paste site (T1567.003)",
    "termbin.com": "a paste site (T1567.003)",
    "discord.com": "a webhook receiver (T1567.004)",
    "discordapp.com": "a webhook receiver (T1567.004)",
    "hooks.slack.com": "a webhook receiver (T1567.004)",
    "webhook.site": "a webhook receiver (T1567.004)",
}


def content_host(entry: object) -> str | None:
    """What kind of publish-anywhere host an ``allowedDomains`` entry admits, if any.

    The entry's port is dropped, a leading ``*.`` is dropped (it widens the
    entry to subdomains), and the host is compared with :data:`_CONTENT_HOSTS`
    and their subdomains: ``*.github.com`` and ``gist.github.com`` match,
    ``github.example.com`` does not.  A bare ``*`` is reported as every host:
    ``WebFetch(domain:...)`` allow rules feed the same allowlist, and the
    sandboxing doc says it honours "a bare *" there.
    """
    if not isinstance(entry, str):
        return None
    host = entry.strip().lower()
    if host == "*":
        return "every host"
    if host.startswith("["):  # IPv6 literal
        return None
    host = host.split(":", 1)[0].rstrip(".")
    if host.startswith("*."):
        host = host[2:]
    for domain, kind in _CONTENT_HOSTS.items():
        if host == domain or host.endswith("." + domain):
            return kind
    return None


_SANDBOX_003 = _Check(
    finding_id="SANDBOX-003",
    title=(
        "Repository settings let sandboxed commands reach hosts anyone can publish to"
    ),
    remediation=(
        "Remove these hosts from the repository's sandbox.network.allowedDomains"
        " and allow only the hosts a tool actually needs (for example"
        " registry.npmjs.org or pypi.org). Add sandbox.network.deniedDomains for"
        " upload hosts you never want reached. To stop any repository from"
        " widening the allowlist, set sandbox.network.strictAllowlist: true in"
        " your ~/.claude/settings.json."
    ),
    cwe="CWE-183",
    owasp=("MCP02", "MCP10"),
)
_SANDBOX_003_BASIS = (
    'Sandboxing doc: "Allowing broad domains such as github.com can create paths'
    " for data exfiltration. Because the proxy makes its allow decision from the"
    " client-supplied hostname without inspecting TLS, code running inside the"
    ' sandbox can potentially use domain fronting"; the settings reference:'
    ' "Claude Code merges the array sub-keys across settings scopes, so a'
    " project can add domains to your user list unless a repository lock"
    ' applies."'
)


def _check_sandbox_003(
    settings: ClaudeSettings, context: SandboxContext, client: str, analyzer: str
) -> list[Finding]:
    present, domains = _get(settings.sandbox, "network.allowedDomains")
    if not present or not isinstance(domains, list):
        return []
    graded: list[tuple[Severity, _Hit]] = []
    for entry in domains:
        kind = content_host(entry)
        if not kind:
            continue
        where = f"sandbox.network.allowedDomains contains {_quote(entry)}"
        if context.user.strict_allowlist:
            graded.append((Severity.INFO, _Hit(where, kind + _STRICT_ALLOWLIST_HIT)))
        else:
            graded.append((Severity.MEDIUM, _Hit(where, kind, _DOMAIN_NOTES)))
    return _findings(
        _SANDBOX_003, graded, settings, context, client, analyzer, _SANDBOX_003_BASIS
    )


# ── SANDBOX-004: keys Claude Code ignores in this file ───────────────────────


def _set(value: object) -> bool:
    """Set to something that would do something: true, or a non-empty value."""
    if value is None or value is False:
        return False
    if isinstance(value, (str, list, dict)):
        return bool(value)
    return True


def _set_or_empty_object(value: object) -> bool:
    """tlsTerminate: "Set {} to generate an ephemeral certificate authority"."""
    return isinstance(value, dict) or _set(value)


@dataclass(frozen=True)
class _IgnoredKey:
    key: str
    applies: Callable[[object], bool]
    managed_only: bool
    is_lock: bool
    quote: str


#: Settings reference index, Scope column: "User or managed" keys are not read
#: from project or local settings, "Managed" keys only from managed settings.
_USER_OR_MANAGED = "settings reference scope: User or managed"
_MANAGED = "settings reference scope: Managed"
_CREDENTIALS_QUOTE = (
    'settings reference: "Claude Code honors mask entries, allowPlaintextInject,'
    " awsPairs, and sigv4 only from user settings, managed settings, and the"
    ' --settings flag."'
)
_IGNORED_KEYS: tuple[_IgnoredKey, ...] = (
    _IgnoredKey(
        "allowAppleEvents",
        _is_true,
        managed_only=False,
        is_lock=False,
        quote='sandboxing doc: "It is only honored from user, managed, or CLI'
        ' settings. Project settings cannot enable it."',
    ),
    _IgnoredKey(
        "allowNestedUserNamespaces",
        _is_true,
        managed_only=False,
        is_lock=False,
        quote="settings reference: \"Claude Code ignores a true in a project's"
        ' .claude/settings.json or .claude/settings.local.json."',
    ),
    _IgnoredKey(
        "filesystem.disabled",
        _is_true,
        managed_only=False,
        is_lock=False,
        quote=_USER_OR_MANAGED,
    ),
    _IgnoredKey(
        "network.strictAllowlist",
        _is_true,
        managed_only=False,
        is_lock=True,
        quote="sandboxing doc: \"Setting it in a repository's .claude/settings.json"
        ' or .claude/settings.local.json has no effect."',
    ),
    _IgnoredKey(
        "network.tlsTerminate",
        _set_or_empty_object,
        managed_only=False,
        is_lock=False,
        quote="settings reference: \"A repository can't switch it on or supply a"
        ' certificate authority."',
    ),
    _IgnoredKey(
        "ripgrep", _set, managed_only=False, is_lock=False, quote=_USER_OR_MANAGED
    ),
    _IgnoredKey(
        "credentials.allowPlaintextInject",
        _is_true,
        managed_only=False,
        is_lock=False,
        quote=_CREDENTIALS_QUOTE,
    ),
    _IgnoredKey(
        "credentials.awsPairs",
        _set,
        managed_only=False,
        is_lock=False,
        quote=_CREDENTIALS_QUOTE,
    ),
    _IgnoredKey(
        "credentials.sigv4",
        _set,
        managed_only=False,
        is_lock=False,
        quote=_CREDENTIALS_QUOTE,
    ),
    _IgnoredKey(
        "bwrapPath",
        _set,
        managed_only=True,
        is_lock=False,
        quote='settings reference: "Claude Code reads it only from managed settings'
        " so that a user, project, or local file can't point the sandbox at a"
        ' different binary."',
    ),
    _IgnoredKey("socatPath", _set, managed_only=True, is_lock=False, quote=_MANAGED),
    _IgnoredKey(
        "filesystem.allowManagedReadPathsOnly",
        _is_true,
        managed_only=True,
        is_lock=True,
        quote=_MANAGED,
    ),
    _IgnoredKey(
        "network.allowManagedDomainsOnly",
        _is_true,
        managed_only=True,
        is_lock=True,
        quote=_MANAGED,
    ),
)

_SANDBOX_004 = _Check(
    finding_id="SANDBOX-004",
    title="Sandbox keys this settings file can't set (ignored by Claude Code)",
    remediation=(
        "Move each key to a file that can set it: managed settings for the"
        " managed-only keys, ~/.claude/settings.json (or managed settings) for"
        " the others, or delete it. Don't rely on a lock listed here while it"
        " sits in this file."
    ),
    cwe="CWE-693",
    owasp=("MCP02",),
)


def _mask_entries(sandbox: dict) -> list[str]:
    """``credentials.files``/``envVars`` entries with ``"mode": "mask"``."""
    found: list[str] = []
    for list_key, name_key in (("files", "path"), ("envVars", "name")):
        present, entries = _get(sandbox, f"credentials.{list_key}")
        if not present or not isinstance(entries, list):
            continue
        for entry in entries:
            if isinstance(entry, dict) and entry.get("mode") == "mask":
                found.append(
                    f"sandbox.credentials.{list_key} mask entry for"
                    f" {_quote(entry.get(name_key))}"
                )
    return found


def _check_sandbox_004(
    settings: ClaudeSettings, client: str, analyzer: str
) -> list[Finding]:
    if settings.scope == "user":
        candidates = [item for item in _IGNORED_KEYS if item.managed_only]
        where = "managed settings"
    elif settings.scope in ("project", "local"):
        candidates = list(_IGNORED_KEYS)
        where = "user or managed settings"
    else:
        return []
    hits: list[_Hit] = []
    locks: list[str] = []
    for item in candidates:
        present, value = _get(settings.sandbox, item.key)
        if not (present and item.applies(value)):
            continue
        honoured = "managed settings" if item.managed_only else where
        hits.append(
            _Hit(
                f"sandbox.{item.key} = {_quote(value)}",
                f"read only from {honoured} ({item.quote})",
            )
        )
        if item.is_lock:
            locks.append(f"sandbox.{item.key}")
    if settings.scope != "user":
        for entry in _mask_entries(settings.sandbox):
            hits.append(
                _Hit(
                    entry,
                    "mask entries are honoured only from user settings, managed"
                    " settings and --settings, so this credential is not masked",
                )
            )
            locks.append(entry)
    if not hits:
        return []
    if locks:
        summary = (
            "Claude Code ignores these here. These look like protections but"
            " give none from this file: " + _capped(locks, ", ") + "."
        )
    else:
        summary = (
            "Claude Code ignores these here, so they change nothing; a"
            " repository can't loosen the sandbox through them."
        )
    return [
        _build(
            _SANDBOX_004,
            Severity.INFO,
            settings,
            settings.scope_label,
            client,
            analyzer,
            summary,
            hits,
        )
    ]


# ── SANDBOX-001..004 for one file ─────────────────────────────────────────────


def analyze_sandbox_settings(
    raw: object,
    config_path: Path,
    client: str,
    *,
    analyzer: str = ANALYZER_NAME,
    context: SandboxContext | None = None,
) -> list[Finding]:
    """SANDBOX-001..004 for one Claude Code settings file.  Pure: reads nothing.

    Args:
        raw: Parsed JSON of the file.
        config_path: The file; anything that is not a Claude Code settings
            file yields nothing.
        client: Client name to attach to findings.
        analyzer: Analyzer label for findings.
        context: Where the file's keys come from and what the user's settings
            lock (:func:`analyze_sandbox_files` works this out).  Without it,
            a shared project ``.claude/settings.json`` is the repository's and
            any other file is the user's own (SANDBOX-004 only).

    Returns:
        Findings ordered by ID, most severe first within an ID.
    """
    if not is_claude_code_settings_file(config_path):
        return []
    settings = load_claude_settings(raw, config_path)
    if settings is None or not settings.sandbox:
        return []
    context = context if context is not None else _default_context(settings)
    findings: list[Finding] = []
    if context.origin != ORIGIN_OWN:
        findings.extend(_check_sandbox_001(settings, context, client, analyzer))
        findings.extend(_check_sandbox_002(settings, context, client, analyzer))
        findings.extend(_check_sandbox_003(settings, context, client, analyzer))
    findings.extend(_check_sandbox_004(settings, client, analyzer))
    return findings


# ── The user's own settings ───────────────────────────────────────────────────


def user_settings_path(home: Path | None = None) -> tuple[Path, str]:
    """``(path, label)`` of the user settings file.

    The settings doc: with ``CLAUDE_CONFIG_DIR`` set, "Claude Code then stores
    your settings ... there instead" of ``~/.claude``.  An explicit *home*
    (tests) ignores the variable.
    """
    config_dir = os.environ.get("CLAUDE_CONFIG_DIR") if home is None else None
    if config_dir:
        return Path(config_dir) / "settings.json", "$CLAUDE_CONFIG_DIR/settings.json"
    base = home if home is not None else Path.home()
    return base / ".claude" / "settings.json", "~/.claude/settings.json"


def read_user_settings_locks(
    home: Path | None = None,
) -> tuple[UserSettingsLocks, str | None]:
    """Read ``strictAllowlist`` and ``defaultMode`` from the user's settings file.

    Returns:
        The locks, and an error message (no absolute path) when the file
        exists but can't be read.  A file that is not valid JSON gives no
        locks and no error: the settings doc says Claude Code "skips the broken
        file", so it locks nothing either.
    """
    path, label = user_settings_path(home)
    try:
        if not path.is_file():
            return UserSettingsLocks(), None
        with path.open("rb") as handle:
            data = handle.read(_USER_SETTINGS_MAX_BYTES + 1)
    except OSError as exc:
        return UserSettingsLocks(), (
            f"could not read {label}: {exc.strerror or type(exc).__name__};"
            " SANDBOX-002/003 severities assume it sets nothing"
        )
    if len(data) > _USER_SETTINGS_MAX_BYTES:
        return UserSettingsLocks(), (
            f"{label} is larger than 4 MiB and was not read; SANDBOX-002/003"
            " severities assume it sets nothing"
        )
    try:
        raw = json.loads(data.decode("utf-8", errors="replace"))
    except (ValueError, RecursionError):
        return UserSettingsLocks(), None
    if not isinstance(raw, dict):
        return UserSettingsLocks(), None
    _present, strict = _get(raw, "sandbox.network.strictAllowlist")
    _present, mode = _get(raw, "permissions.defaultMode")
    return (
        UserSettingsLocks(
            strict_allowlist=strict is True,
            default_mode=mode if isinstance(mode, str) else None,
        ),
        None,
    )


# ── Git state of a settings file ──────────────────────────────────────────────

_GIT_NO_REPO = "no-repo"
_GIT_IGNORED = "ignored"
_GIT_TRACKED = "unignored"
_GIT_CLAUDE_LINK = "claude-symlink"
_GIT_UNKNOWN = "unknown"


@dataclass(frozen=True)
class _GitState:
    kind: str
    root: Path | None = None
    parts: tuple[str, ...] | None = None


def _relative_parts(path: Path, root: Path) -> tuple[str, ...] | None:
    try:
        return path.relative_to(root).parts
    except ValueError:
        return None


def _git_state(path: Path, reader: IgnoreFileReader) -> _GitState:
    """Whether git would carry *path*, from ignore files only; never runs git.

    Errors are recorded on *reader* (no absolute paths) and give ``unknown``.
    """
    label = f"{path.parent.name}/{path.name}"
    try:
        if path.parent.is_symlink():
            return _GitState(_GIT_CLAUDE_LINK)
    except OSError as exc:
        reader.errors.append(
            f"could not check {label}: {exc.strerror or type(exc).__name__}"
        )
        return _GitState(_GIT_UNKNOWN)
    root = find_work_tree_root(path.parent.parent)
    if root is None:
        return _GitState(_GIT_NO_REPO)
    parts = _relative_parts(path, root)
    if parts is None:
        return _GitState(_GIT_UNKNOWN)
    rel = "/".join((root.name, *parts))
    try:
        current = root
        for part in parts[:-1]:
            current = current / part
            if current.is_symlink():
                reader.errors.append(
                    f"'{rel}' is reached through a symlinked directory; whether"
                    " git tracks it is unknown"
                )
                return _GitState(_GIT_UNKNOWN, root, parts)
        ignored = reader.is_ignored(root, parts)
    except IgnoreStateUnknownError:
        return _GitState(_GIT_UNKNOWN, root, parts)
    except OSError as exc:
        reader.errors.append(
            f"could not check '{rel}': {exc.strerror or type(exc).__name__}"
        )
        return _GitState(_GIT_UNKNOWN, root, parts)
    return _GitState(_GIT_IGNORED if ignored else _GIT_TRACKED, root, parts)


_LOCAL_ORIGIN: dict[str, str] = {
    _GIT_CLAUDE_LINK: ORIGIN_LOCAL_SYMLINK,
    _GIT_TRACKED: ORIGIN_LOCAL_TRACKED,
    _GIT_UNKNOWN: ORIGIN_LOCAL_UNKNOWN,
}


# ── SANDBOX-005: settings headed for git ──────────────────────────────────────


class SettingsFileSource(Protocol):
    """What step 0b needs from a discovered config (``DiscoveredConfig`` fits)."""

    path: Path
    raw: dict
    client_name: str


#: Home-directory paths that name a user: ``/Users/<name>`` (macOS),
#: ``/home/<name>`` (Linux), ``C:\\Users\\<name>`` and ``/c/Users/<name>``
#: (Windows, Git Bash).  Leading slashes are one run so ``//Users/…`` (Claude
#: Code's absolute-path rule form) and ``file:///Users/…`` match; the
#: look-behind keeps a match from starting mid-path.  No nested quantifiers.
_USER_PATH_RE = re.compile(
    r"(?<![\w.~$%/\\-])"
    r"(?:[A-Za-z]:[\\/]+Users[\\/]+|/+(?:[A-Za-z]/)?Users/|/+home/)"
    r"(?P<user>[^\\/\s\"'`<>|;,()\[\]{}*?$%:=]+)"
)
_PATH_END_RE = re.compile(r"[\s\"'`<>|;,()]")
#: Placeholder and shared-account names that identify no person (docs
#: placeholders, OS shared folders, CI, dev-container and Homebrew accounts).
_NOT_A_PERSON: frozenset[str] = frozenset(
    {
        "you", "your", "yourname", "your-name", "your_name", "yourusername",
        "your-username", "your_username", "user", "username", "user-name",
        "user_name", "name", "me", "myself", "someone", "example", "shared",
        "public", "default", "default user", "all users", "guest", "runner",
        "ubuntu", "ec2-user", "vagrant", "node", "codespace", "vscode", "coder",
        "gitpod", "jovyan", "admin", "administrator", "root", "linuxbrew",
    }
)  # fmt: skip
#: Strings and characters examined per settings file.
_MAX_STRINGS = 20_000
_MAX_STRING_CHARS = 16_384
_MAX_DEPTH = 64
_MAX_NODES = 100_000


@dataclass
class _Budget:
    """Whether :func:`_strings` stopped early (reported, never silent)."""

    truncated: bool = False


def _strings(raw: object, budget: _Budget) -> Iterator[tuple[str, str]]:
    """``(json location, text)`` for every string key and value, within budget.

    Containers are walked through iterators, so a huge list is never copied;
    at most :data:`_MAX_NODES` values are visited.
    """
    emitted = 0
    visited = 0

    def clip(text: str) -> str:
        if len(text) > _MAX_STRING_CHARS:
            budget.truncated = True
        return text[:_MAX_STRING_CHARS]

    def children(where: str, node: object) -> Iterator[tuple[str, object, str | None]]:
        if isinstance(node, dict):
            for key, value in node.items():
                child = f"{where}.{key}" if where else str(key)
                yield child, value, key if isinstance(key, str) else None
        elif isinstance(node, list):
            for index, value in enumerate(node):
                yield f"{where}[{index}]", value, None

    if isinstance(raw, str):
        yield "(top level)", clip(raw)
        return
    stack: list[Iterator[tuple[str, object, str | None]]] = [children("", raw)]
    while stack:
        item = next(stack[-1], None)
        if item is None:
            stack.pop()
            continue
        where, value, key = item
        visited += 1
        if visited > _MAX_NODES or emitted >= _MAX_STRINGS:
            budget.truncated = True
            return
        if key is not None:
            emitted += 1
            yield f"{where} (key)", clip(key)
        if isinstance(value, str):
            emitted += 1
            yield where, clip(value)
        elif isinstance(value, (dict, list)):
            if len(stack) >= _MAX_DEPTH:
                budget.truncated = True
                continue
            stack.append(children(where, value))


def username_paths(raw: object) -> list[tuple[str, str, str]]:
    """``(json location, path, username)`` for each home path naming a person.

    Placeholders (``/Users/you``), shared folders (``C:\\Users\\Public``) and
    CI, container or Homebrew accounts (``/home/runner``,
    ``/home/linuxbrew``) are left out.  The path is cut at the first space,
    quote or shell separator, capped, and masked with SECRET_PATTERNS, and so
    is the username, so a secret on the same line is never quoted.  Only the
    first 20,000 strings, 16 KiB of each, at a depth up to 64 are searched.
    """
    return _username_paths(raw, _Budget())


def _username_paths(raw: object, budget: _Budget) -> list[tuple[str, str, str]]:
    found: list[tuple[str, str, str]] = []
    for where, text in _strings(raw, budget):
        for match in _USER_PATH_RE.finditer(text):
            user = match.group("user")
            if user.lower() in _NOT_A_PERSON:
                continue
            tail = text[match.start() : match.start() + 4 * _QUOTE_CHARS]
            end = _PATH_END_RE.search(tail)
            path = tail[: end.start()] if end else tail
            found.append(
                (where, _mask(path)[:_QUOTE_CHARS], _mask(user)[:_QUOTE_CHARS])
            )
    return found


_SANDBOX_005 = _Check(
    finding_id="SANDBOX-005",
    title="Local Claude Code settings are not ignored by git",
    remediation=(
        "Add .claude/settings.local.json (or **/.claude/settings.local.json) to"
        " .gitignore. If it is already committed, also remove it from the index"
        " (git rm --cached .claude/settings.local.json), review what it holds,"
        " and move anything the team should share into .claude/settings.json."
    ),
    cwe="CWE-538",
    owasp=("MCP10", "MCP02"),
)
_SANDBOX_005_PATHS_TITLE = (
    "Settings file headed for git contains home-directory paths with a username"
)
_SANDBOX_005_PATHS_REMEDIATION = (
    "Write paths that work on every machine: ~/ for your home directory (for"
    ' example Read(~/.npmrc) or "allowWrite": ["~/.kube"]), project-relative'
    " paths for the repository, and keep machine-specific entries in"
    " ~/.claude/settings.json or in a .claude/settings.local.json that git"
    " ignores."
)


def _headed_for_git_note(root: Path, reader: IgnoreFileReader) -> str:
    return (
        f"It is inside the git work tree '{root.name}' and no ignore file covers"
        " it (checked: the .gitignore files from the work-tree root down to its"
        " directory, .git/info/exclude, and the global excludes file,"
        f" {reader.global_label}), so it is committed already or will be by the"
        " next `git add -A`."
    )


def _local_settings_finding(
    config: SettingsFileSource, root: Path, reader: IgnoreFileReader, analyzer: str
) -> Finding:
    settings = load_claude_settings(config.raw, config.path)
    held = ""
    if settings is not None:
        parts = []
        if settings.rules:
            parts.append(f"{len(settings.rules)} permission rule(s)")
        if settings.sandbox:
            parts.append("a sandbox block")
        if isinstance(config.raw, dict) and config.raw.get("hooks"):
            parts.append("hooks")
        if parts:
            held = " It holds " + ", ".join(parts) + "."
    return Finding(
        id="SANDBOX-005",
        severity=Severity.MEDIUM,
        analyzer=analyzer,
        client=config.client_name,
        server="(config-level)",
        title=_SANDBOX_005.title,
        description=(
            f"'{config.path.parent.name}/{config.path.name}' is local project"
            " settings, which the settings doc describes as yours alone: Claude"
            ' Code "keeps it out of git when it creates the file; if you create'
            ' it by hand, add it to .gitignore yourself". '
            + _headed_for_git_note(root, reader)
            + held
            + " Committed, it reaches everyone who clones the repository, and"
            f" Claude Code then treats it as the repository's: {_REPO_SUPPLIED_QUOTE}"
            " UpGuard collected 18,470 of these files from public GitHub"
            " repositories."
        ),
        evidence=(
            f"{config.path}: in git work tree {root}; not matched by any ignore"
            " file read"
        ),
        remediation=_SANDBOX_005.remediation,
        cwe=_SANDBOX_005.cwe,
        owasp_mcp_top_10=list(_SANDBOX_005.owasp),
        finding_path=str(config.path),
    )


def _username_paths_finding(
    config: SettingsFileSource,
    root: Path,
    reader: IgnoreFileReader,
    paths: list[tuple[str, str, str]],
    analyzer: str,
) -> Finding:
    users = sorted({user for _where, _path, user in paths})
    return Finding(
        id="SANDBOX-005",
        severity=Severity.LOW,
        analyzer=analyzer,
        client=config.client_name,
        server="(config-level)",
        title=_SANDBOX_005_PATHS_TITLE,
        description=(
            f"'{config.path.parent.name}/{config.path.name}' contains"
            f" {len(paths)} absolute path(s) under a person's home directory"
            f" ({_capped(users, ', ')}). "
            + _headed_for_git_note(root, reader)
            + " Committed, these publish the username and name directories that"
            " don't exist on anyone else's machine. UpGuard found 8,341"
            " permission entries containing usernames in committed"
            " .claude/settings.local.json files."
        ),
        evidence=f"{config.path}: "
        + _capped([f"{where}: {path!r}" for where, path, _user in paths]),
        remediation=_SANDBOX_005_PATHS_REMEDIATION,
        cwe=_SANDBOX_005.cwe,
        owasp_mcp_top_10=list(_SANDBOX_005.owasp),
        finding_path=str(config.path),
    )


# ── Step 0b: every settings file in the scan ──────────────────────────────────


def _one_settings_file(
    config: SettingsFileSource,
    path: Path,
    reader: IgnoreFileReader,
    user: UserSettingsLocks,
    analyzer: str,
    unknown: list[str],
) -> list[Finding]:
    scope = settings_scope(path)
    state: _GitState | None = None
    if scope in ("project", "local") and not _in_configuration_home(path):
        state = _git_state(path, reader)
        if state.kind == _GIT_UNKNOWN:
            unknown.append(scope)
    if state is None:
        origin = ORIGIN_OWN
    elif scope == "project":
        origin = ORIGIN_PROJECT
    else:
        origin = _LOCAL_ORIGIN.get(state.kind, ORIGIN_OWN)
    findings = analyze_sandbox_settings(
        config.raw,
        config.path,
        config.client_name,
        analyzer=analyzer,
        context=SandboxContext(origin, user),
    )
    linked_file = getattr(config, "is_symlink", False) or path.is_symlink()
    if state is None or state.kind != _GIT_TRACKED or linked_file:
        return findings
    root = state.root
    if root is None or state.parts is None:
        return findings
    if scope == "local":
        findings.append(_local_settings_finding(config, root, reader, analyzer))
    budget = _Budget()
    paths = _username_paths(config.raw, budget)
    if budget.truncated:
        reader.errors.append(
            f"'{root.name}/{'/'.join(state.parts)}' was searched for home-directory"
            f" paths only up to {_MAX_STRINGS} strings, {_MAX_STRING_CHARS // 1024}"
            f" KiB per string and depth {_MAX_DEPTH}"
        )
    if paths:
        findings.append(_username_paths_finding(config, root, reader, paths, analyzer))
    return findings


def analyze_sandbox_files(
    configs: Iterable[SettingsFileSource],
    *,
    analyzer: str = ANALYZER_NAME,
    home: Path | None = None,
) -> tuple[list[Finding], list[str]]:
    """SANDBOX-001..005 over the scan's Claude Code settings files (step 0b).

    For each settings file: works out whether it is the repository's
    (:class:`SandboxContext`), runs :func:`analyze_sandbox_settings`, and,
    for a project or local file that sits in a git work tree and that no
    ignore file covers, SANDBOX-005 (MEDIUM for a local file; LOW for
    home-directory paths naming a person).  The user's
    ``~/.claude/settings.json`` is read once for ``strictAllowlist`` and
    ``defaultMode``.

    Each file is checked in its own ``try``: a crash on one file is recorded
    and the others still run.  A settings file that is a symlink, or reached
    through a symlinked ``.claude`` directory, gets no SANDBOX-005.  When a
    file's git state can't be read, the errors say so and what it changed:
    no SANDBOX-005 for it, and a local file's SANDBOX-001..003 at MEDIUM at
    most.

    Args:
        configs: The scan's discovered configs (``DiscoveredConfig`` objects).
        analyzer: Analyzer label for findings.
        home: Home directory for the user settings and global git config
            (tests); defaults to ``Path.home()``.

    Returns:
        ``(findings, errors)``; error messages carry no absolute paths.
    """
    reader = IgnoreFileReader(home=home)
    errors: list[str] = []
    user, user_error = read_user_settings_locks(home)
    if user_error:
        errors.append(f"{ERROR_PREFIX}{user_error}")
    findings: list[Finding] = []
    unknown: list[str] = []
    seen: set[str] = set()
    for config in configs:
        path = Path(os.path.abspath(config.path))
        if not is_claude_code_settings_file(path) or str(path) in seen:
            continue
        seen.add(str(path))
        try:
            findings.extend(
                _one_settings_file(config, path, reader, user, analyzer, unknown)
            )
        except Exception as exc:  # noqa: BLE001 - one file must not stop the rest
            errors.append(
                f"{ERROR_PREFIX}failed for '{path.parent.name}/{path.name}':"
                f" {type(exc).__name__}"
            )
    errors.extend(f"{ERROR_PREFIX}{message}" for message in reader.errors)
    if unknown:
        errors.append(
            f"{ERROR_PREFIX}git state unknown for {len(unknown)} settings file(s):"
            " no SANDBOX-005 for them, and SANDBOX-001..003 on a local file at"
            " MEDIUM at most"
        )
    return findings, errors
