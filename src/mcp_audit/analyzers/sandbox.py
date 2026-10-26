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

Checks:

- **SANDBOX-001** (HIGH/MEDIUM): a repository settings file turns on a key
  that weakens the sandbox, turns the sandbox off, or points it at a proxy.
- **SANDBOX-002** (HIGH): it takes a shell, interpreter, package runner,
  container runtime or every command out of the sandbox
  (``excludedCommands``), or opens the Docker or Podman socket
  (``allowUnixSockets``).
- **SANDBOX-003** (MEDIUM): it adds a host anyone can publish to (a code host,
  a paste site, a webhook receiver) or every host to ``allowedDomains``.
- **SANDBOX-004** (INFO): a key Claude Code ignores in this file ("dead
  config"), such as ``strictAllowlist`` or ``allowManagedDomainsOnly`` in a
  repository.
- **SANDBOX-005** (MEDIUM/LOW): a ``.claude/settings.local.json`` inside a git
  work tree that no ignore file covers, and home-directory paths with a
  username in a settings file headed for git.

SANDBOX-001..004 are pure functions of a settings file already parsed by the
scan (:func:`analyze_sandbox_settings`, called from
:meth:`~mcp_audit.analyzers.config_hygiene.ConfigHygieneAnalyzer.analyze_config`
beside PERM-001..006).  SANDBOX-005 reads ignore files
(:mod:`mcp_audit._gitignore`), so it runs as step 0b of
:func:`mcp_audit.scanner._run_static_pipeline`, where read failures go to
``result.errors`` (:func:`analyze_settings_git_exposure`).  Nothing is
executed; ``git`` is never run.

"Repository settings" means project (``.claude/settings.json``) and local
(``.claude/settings.local.json``) files outside the configuration home: the
sandboxing doc's own phrase is "a repository's ``.claude/settings.json`` and
``.claude/settings.local.json``".  The user's ``~/.claude/settings.json`` and
``~/.claude/settings.local.json`` are the user's own choice and get only
SANDBOX-004.  Each file is evaluated on its own; the merge across files and
managed settings (which can make the sandbox admin-required and so ignore a
repository's loosening keys) is not modelled (GAPS.md).
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
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

#: Analyzer label: emitted through config hygiene's per-file pass, like PERM-*.
ANALYZER_NAME = "config_hygiene"

#: Items quoted in one finding before "(+N more)".
_LIST_CAP = 20
#: Longest value quoted in a finding.
_QUOTE_CHARS = 120
#: Text masked before a value is cut to :data:`_QUOTE_CHARS`.  Masking runs on
#: this much so a secret that starts inside the quoted part is masked whole.
_MASK_WINDOW = 64 * 1024

_ADMIN_REQUIRED_NOTE = (
    " Claude Code ignores these in a repository's files only while managed"
    " settings or --settings make the sandbox admin-required"
    " (allowUnsandboxedCommands false or allowManagedDomainsOnly true; Claude"
    " Code 2.1.285 or later), which this scan can't see."
)

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


def is_repository_settings(settings: ClaudeSettings) -> bool:
    """True for project or local settings outside the configuration home."""
    return settings.scope in ("project", "local") and not _in_configuration_home(
        settings.path
    )


@dataclass(frozen=True)
class _Hit:
    """One flagged key or entry: where it is, what it does here."""

    where: str  # e.g. "sandbox.excludedCommands contains 'python *'"
    why: str


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
    client: str,
    analyzer: str,
    summary: str,
    hits: list[_Hit],
) -> Finding:
    """One finding per check and severity in one settings file."""
    return Finding(
        id=check.finding_id,
        severity=severity,
        analyzer=analyzer,
        client=client,
        server="(config-level)",
        title=check.title,
        description=(
            f"In {settings.scope_label}: "
            + _capped([f"{hit.where}: {hit.why}" for hit in hits])
            + f". {summary}"
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


def _grouped(
    graded: list[tuple[Severity, _Hit]],
) -> list[tuple[Severity, list[_Hit]]]:
    groups: dict[Severity, list[_Hit]] = {}
    for severity, hit in graded:
        groups.setdefault(severity, []).append(hit)
    return [(sev, groups[sev]) for sev in _SEVERITY_ORDER if sev in groups]


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
    ),
    _Loosening(
        "network.socksProxyPort",
        _is_port,
        Severity.MEDIUM,
        'sandboxed SOCKS traffic goes to this local port: "Your proxy takes'
        " over filtering, and Claude Code stops applying its domain lists and"
        ' network prompts to traffic sent there"',
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
    ' sandbox." A cloned repository chooses these for everyone who opens it.'
)


def _check_sandbox_001(
    settings: ClaudeSettings, client: str, analyzer: str
) -> list[Finding]:
    graded: list[tuple[Severity, _Hit]] = []
    for item in _LOOSENING_KEYS:
        if item.project_only and settings.scope != "project":
            # Claude Code's /sandbox panel writes `enabled` to the local file,
            # so a false there is usually the user's own choice.
            continue
        present, value = _get(settings.sandbox, item.key)
        if present and item.applies(value):
            graded.append(
                (
                    item.severity,
                    _Hit(f"sandbox.{item.key} = {_quote(value)}", item.effect),
                )
            )
    return [
        _build(
            _SANDBOX_001,
            severity,
            settings,
            client,
            analyzer,
            _SANDBOX_001_BASIS + _ADMIN_REQUIRED_NOTE,
            hits,
        )
        for severity, hits in _grouped(graded)
    ]


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


def runs_anything_outside_sandbox(entry: object) -> str | None:
    """Why an ``excludedCommands`` entry takes code-running commands out, if it does.

    Entries use ``Bash(...)`` rule syntax ("a pattern with no wildcard is an
    exact match"), so only an entry whose arguments are left open by a
    trailing wildcard is reported: ``python *``, ``bash -c *``, ``npx *``,
    ``uv run *``, ``docker *``, ``docker compose *``, ``docker run *``, or a
    leading ``*`` (any program in front of the rest).  An entry narrowed to a
    script or subcommand (``python scripts/load.py *``, ``uv run pytest *``,
    ``docker ps``) is not.  ``sudo``, ``eval`` and ``xargs`` entries are not
    reported: the settings reference says calls starting with them stay
    sandboxed.

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
    wildcard = False
    for suffix in (":*", " *", "*"):
        if text.endswith(suffix):
            text = text[: -len(suffix)].strip()
            wildcard = True
            break
    if not wildcard:
        return None
    words = text.split()
    if not words:
        return "matches every command"
    program, rest = _program(words[0]), words[1:]
    interpreter = program in _SHELLS_AND_INTERPRETERS or _PYTHON_RE.match(program)
    if interpreter and _options_only(rest):
        return "a shell or interpreter with any arguments"
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
        " subcommand) in your own ~/.claude/settings.json. Don't open the Docker"
        " or Podman socket to sandboxed commands."
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
    ' the sandbox"; and "allowing access to /var/run/docker.sock effectively'
    ' grants access to the host system through the Docker socket". An excluded'
    ' command still goes through the permission flow: a "Bash command'
    ' (unsandboxed)" prompt appears unless an allow rule covers it, and in'
    " bypassPermissions mode it runs without one. allowUnixSockets applies on"
    " macOS only."
)


def _check_sandbox_002(
    settings: ClaudeSettings, client: str, analyzer: str
) -> list[Finding]:
    hits: list[_Hit] = []
    present, excluded = _get(settings.sandbox, "excludedCommands")
    if present and isinstance(excluded, list):
        for entry in excluded:
            reason = runs_anything_outside_sandbox(entry)
            if reason:
                hits.append(
                    _Hit(f"sandbox.excludedCommands contains {_quote(entry)}", reason)
                )
    present, sockets = _get(settings.sandbox, "network.allowUnixSockets")
    if present and isinstance(sockets, list):
        for entry in sockets:
            name = _socket_name(entry)
            if name:
                hits.append(
                    _Hit(
                        f"sandbox.network.allowUnixSockets contains {_quote(entry)}",
                        f"the {name} socket controls the container daemon on the host",
                    )
                )
    if not hits:
        return []
    return [
        _build(
            _SANDBOX_002,
            Severity.HIGH,
            settings,
            client,
            analyzer,
            _SANDBOX_002_BASIS + _ADMIN_REQUIRED_NOTE,
            hits,
        )
    ]


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
        " and allow the narrow hosts a tool actually needs (for example"
        " registry.npmjs.org, or api.github.com only where a command must call"
        " it). Add sandbox.network.deniedDomains for upload hosts you never want"
        " reached, such as uploads.github.com."
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
    settings: ClaudeSettings, client: str, analyzer: str
) -> list[Finding]:
    present, domains = _get(settings.sandbox, "network.allowedDomains")
    if not present or not isinstance(domains, list):
        return []
    hits = [
        _Hit(f"sandbox.network.allowedDomains contains {_quote(entry)}", kind)
        for entry in domains
        if (kind := content_host(entry))
    ]
    if not hits:
        return []
    return [
        _build(
            _SANDBOX_003,
            Severity.MEDIUM,
            settings,
            client,
            analyzer,
            _SANDBOX_003_BASIS + _ADMIN_REQUIRED_NOTE,
            hits,
        )
    ]


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
        _build(_SANDBOX_004, Severity.INFO, settings, client, analyzer, summary, hits)
    ]


# ── SANDBOX-001..004 entry point ──────────────────────────────────────────────


def analyze_sandbox_settings(
    raw: object,
    config_path: Path,
    client: str,
    *,
    analyzer: str = ANALYZER_NAME,
) -> list[Finding]:
    """SANDBOX-001..004 for one Claude Code settings file.

    Args:
        raw: Parsed JSON of the file.
        config_path: The file; anything that is not a Claude Code settings
            file yields nothing.
        client: Client name to attach to findings.
        analyzer: Analyzer label for findings.

    Returns:
        Findings ordered by ID, most severe first within an ID.  SANDBOX-001..003
        only for repository settings (:func:`is_repository_settings`).
    """
    if not is_claude_code_settings_file(config_path):
        return []
    settings = load_claude_settings(raw, config_path)
    if settings is None or not settings.sandbox:
        return []
    findings: list[Finding] = []
    if is_repository_settings(settings):
        findings.extend(_check_sandbox_001(settings, client, analyzer))
        findings.extend(_check_sandbox_002(settings, client, analyzer))
        findings.extend(_check_sandbox_003(settings, client, analyzer))
    findings.extend(_check_sandbox_004(settings, client, analyzer))
    return findings


# ── SANDBOX-005: settings headed for git ──────────────────────────────────────


class GitExposureSource(Protocol):
    """What SANDBOX-005 needs from a discovered config (``DiscoveredConfig`` fits)."""

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
#: placeholders, OS shared folders, CI and dev-container accounts).
_NOT_A_PERSON: frozenset[str] = frozenset(
    {
        "you", "your", "yourname", "your-name", "your_name", "yourusername",
        "your-username", "your_username", "user", "username", "user-name",
        "user_name", "name", "me", "myself", "someone", "example", "shared",
        "public", "default", "default user", "all users", "guest", "runner",
        "ubuntu", "ec2-user", "vagrant", "node", "codespace", "vscode", "coder",
        "gitpod", "jovyan", "admin", "administrator", "root",
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
    CI or container accounts (``/home/runner``) are left out.  The path is
    cut at the first space, quote or shell separator, capped, and masked with
    SECRET_PATTERNS, so a secret on the same line is never quoted.  Only the
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
            found.append((where, _mask(path)[:_QUOTE_CHARS], user))
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
    config: GitExposureSource, root: Path, reader: IgnoreFileReader, analyzer: str
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
            " Claude Code then treats it as the repository's: \"When the file is"
            " tracked in git, or .claude is a symlink, Claude Code treats it as"
            " repository-supplied instead and holds its rules until you trust"
            ' the folder." UpGuard collected 18,470 of these files from public'
            " GitHub repositories."
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
    config: GitExposureSource,
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


def _relative_parts(path: Path, root: Path) -> tuple[str, ...] | None:
    try:
        return path.relative_to(root).parts
    except ValueError:
        return None


def _linked_component(root: Path, parts: tuple[str, ...]) -> bool:
    """True when any directory or the file between *root* and the file is a symlink.

    Git records a symlink as a link, not as the files behind it, so a
    settings file reached through one isn't in the work tree at that path.
    """
    current = root
    for part in parts:
        current = current / part
        if current.is_symlink():
            return True
    return False


def analyze_settings_git_exposure(
    configs: Iterable[GitExposureSource],
    *,
    analyzer: str = ANALYZER_NAME,
    home: Path | None = None,
) -> tuple[list[Finding], list[str]]:
    """SANDBOX-005 over the scan's Claude Code settings files.

    For each project or local settings file outside the configuration home
    that sits in a git work tree (a ``.git`` entry at or above the project
    directory) and that no ignore file covers:

    - MEDIUM for a ``.claude/settings.local.json``;
    - LOW when the file contains home-directory paths naming a person.

    A settings file that is a symlink, or is reached through a symlinked
    directory, is skipped (TRUST-002/TRUST-004 report the link).  A file
    whose ignore state can't be known (an ignore file unreadable or over the
    size cap, or the read budget spent) is skipped, and the reason is
    returned as an error.

    Args:
        configs: The scan's discovered configs (``DiscoveredConfig`` objects).
        analyzer: Analyzer label for findings.
        home: Home directory for the global git config (tests); defaults to
            ``Path.home()``.

    Returns:
        ``(findings, errors)``; error messages carry no absolute paths.
    """
    reader = IgnoreFileReader(home=home)
    findings: list[Finding] = []
    seen: set[str] = set()
    for config in configs:
        if getattr(config, "is_symlink", False):
            continue
        path = Path(os.path.abspath(config.path))
        if not is_claude_code_settings_file(path):
            continue
        scope = settings_scope(path)
        if scope not in ("project", "local") or _in_configuration_home(path):
            continue
        if str(path) in seen:
            continue
        seen.add(str(path))
        root = find_work_tree_root(path.parent.parent)
        if root is None:
            continue
        parts = _relative_parts(path, root)
        if parts is None:
            continue
        try:
            if _linked_component(root, parts):
                continue
            if reader.is_ignored(root, parts):
                continue
        except IgnoreStateUnknownError:
            continue
        except OSError as exc:
            reader.errors.append(
                f"could not check '{'/'.join(parts)}' in '{root.name}':"
                f" {exc.strerror or type(exc).__name__}"
            )
            continue
        if scope == "local":
            findings.append(_local_settings_finding(config, root, reader, analyzer))
        budget = _Budget()
        paths = _username_paths(config.raw, budget)
        if budget.truncated:
            reader.errors.append(
                f"'{root.name}/{'/'.join(parts)}' was searched for home-directory"
                f" paths only up to {_MAX_STRINGS} strings, {_MAX_STRING_CHARS // 1024}"
                f" KiB per string and depth {_MAX_DEPTH}"
            )
        if paths:
            findings.append(
                _username_paths_finding(config, root, reader, paths, analyzer)
            )
    errors = [f"SANDBOX-005 skipped: {message}" for message in reader.errors]
    return findings, errors
