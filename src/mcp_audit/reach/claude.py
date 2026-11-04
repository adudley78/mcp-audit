"""Claude Code: the five reach questions answered from its settings files.

Reads, never runs: the settings files a session in this directory loads
(managed ``managed-settings.json`` and ``managed-settings.d/*.json``, user
``settings.json``, project ``.claude/settings.json`` and
``.claude/settings.local.json``) through
:func:`mcp_audit.analyzers.secret_reach.load_settings_sources`, the same
reader REACH-001..003 use, and the findings the default scan already produced.

Vendor facts (fetched 2026-11-04):

- https://code.claude.com/docs/en/settings-reference : ``permissions.defaultMode``,
  ``permissions.disableBypassPermissionsMode``, ``sandbox.enabled`` and their
  scopes (managed > local > project > user; ``bypassPermissions`` does not take
  effect from project or local settings in 2.1.257 and later).
- https://code.claude.com/docs/en/sandboxing : with the sandbox on there is "no
  direct route out"; unlisted hosts prompt in the default modes, are refused
  with ``strictAllowlist`` (user, managed or ``--settings``) or
  ``allowManagedDomainsOnly`` (managed), and are allowed without a prompt under
  ``bypassPermissions`` unless one of those locks is on.
- https://code.claude.com/docs/en/monitoring-usage : telemetry needs
  ``CLAUDE_CODE_ENABLE_TELEMETRY=1``; ``OTEL_LOGS_EXPORTER`` selects the
  logs/events exporter (the tool_decision and tool_result events);
  ``OTEL_EXPORTER_OTLP_PROTOCOL`` has no default; "Claude Code ignores the
  OpenTelemetry exporter variables in a repository's .claude/settings.json and
  .claude/settings.local.json", but a repository "can still turn a signal off"
  by setting its exporter selector to ``none`` unless managed settings set that
  variable.

Only managed and user settings count toward "logging is on".  The process
environment and ``--settings`` files are not readable from here, so a value
they set is never assumed.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from mcp_audit.analyzers import secret_reach
from mcp_audit.analyzers.config_hygiene import (
    _network_primitive,
    _redirect_host,
)
from mcp_audit.analyzers.credentials import SECRET_PATTERNS
from mcp_audit.analyzers.managed_policy import (
    read_effective_policy,
    read_managed_policy,
)
from mcp_audit.analyzers.poisoning import normalize_for_detection
from mcp_audit.analyzers.secret_reach import SettingsSource
from mcp_audit.config_parser import _servers_from_dict
from mcp_audit.discovery import DiscoveredConfig
from mcp_audit.models import Finding, ServerConfig
from mcp_audit.reach.common import Assessment, network_status
from mcp_audit.reach.context import Env, read_capped
from mcp_audit.reach.models import Fact, Question, Reason, Status
from mcp_audit.reach.network import NetworkView
from mcp_audit.reach.surface import (
    COMMAND_KEYS,
    DESTINATION_UNKNOWN_NAMES,
    SANDBOX_EXECUTABLE_KEYS,
    SECRET_NAME_RE,
    Cmd,
    all_frontmatter_items,
    command_texts,
    frontmatter_items,
    hook_items,
    is_destination,
    plugin_hook_tables,
    settings_env_unsafe,
    unknown_settings_keys,
)

SETTINGS_DOC = "https://code.claude.com/docs/en/settings-reference"
SANDBOX_DOC = "https://code.claude.com/docs/en/sandboxing"
MONITORING_DOC = "https://code.claude.com/docs/en/monitoring-usage"

#: The sandbox runs on macOS, Linux and WSL2 only (sandboxing doc).
_SANDBOX_OS_SUPPORTED = not sys.platform.startswith("win")

#: On Linux and WSL2 the sandbox needs ``bubblewrap`` and ``socat``; without
#: them Claude Code "runs commands without sandboxing" unless
#: ``sandbox.failIfUnavailable`` is true (sandboxing doc).
_IS_LINUX = sys.platform.startswith("linux")
_LINUX_SANDBOX_TOOLS = ("bwrap", "socat")

#: Settings precedence, highest first (settings reference).
_PRECEDENCE = {"managed": 0, "local": 1, "project": 2, "user": 3}
_NOT_SET = "(not set)"

CLIENTS = frozenset(
    {"claude-code", "claude-code-project", "claude-code-plugin", "claude-code-agent"}
)


def _d(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def _list(value: object) -> list:
    return value if isinstance(value, list) else []


def resolve(
    sources: list[SettingsSource],
    getter: Callable[[dict], object],
    scopes: tuple[str, ...] | None = None,
) -> tuple[object, SettingsSource | None]:
    """The value and file from the highest-precedence source that sets it.

    Among managed files a later drop-in beats earlier ones and the main file.
    """
    ranked = sorted(
        enumerate(sources),
        key=lambda item: (_PRECEDENCE.get(item[1].scope, 9), -item[0]),
    )
    for _index, source in ranked:
        if scopes is not None and source.scope not in scopes:
            continue
        value = getter(source.data)
        if value is not None:
            return value, source
    return None, None


def _key(*path: str) -> Callable[[dict], object]:
    def get(data: dict) -> object:
        node: object = data
        for part in path:
            node = _d(node).get(part)
            if node is None:
                return None
        return node

    return get


# ── Settings files ────────────────────────────────────────────────────────────


@dataclass
class Settings:
    """The settings files read, and which of them could not be."""

    sources: list[SettingsSource] = field(default_factory=list)
    #: Existing files that were skipped (unparsable, over the cap, unreadable),
    #: as ``(scope, masked path)``.
    skipped: list[tuple[str, str]] = field(default_factory=list)

    @property
    def decisive_skipped(self) -> list[str]:
        """Every skipped settings file, whatever its scope.

        Any scope can set ``sandbox.enabled`` or ``permissions.defaultMode``
        (a repository file overrides the user's sandbox setting), so a file
        that was not read may hold what decides the answer.
        """
        return [p for _scope, p in self.skipped]


def _candidates(env: Env) -> list[tuple[str, Path]]:
    """Every settings file path a session in ``env.cwd`` would load."""
    from mcp_audit.analyzers.managed_policy import list_dropins  # noqa: PLC0415

    paths: list[tuple[str, Path]] = []
    if env.managed_dir is not None:
        paths.append(("managed", env.managed_dir / "managed-settings.json"))
        try:
            for p in list_dropins(env.managed_dir / "managed-settings.d")[
                : secret_reach.MAX_DROPINS
            ]:
                paths.append(("managed", p))
        except OSError:
            paths.append(("managed", env.managed_dir / "managed-settings.d"))
    paths.append(("user", env.config_dir / "settings.json"))
    paths.append(("project", env.cwd / ".claude" / "settings.json"))
    paths.append(("local", env.cwd / ".claude" / "settings.local.json"))
    return paths


def load_settings(env: Env) -> Settings:
    """Read the settings files; note, never raise on, the ones that fail."""
    errs: list[str] = []
    sources = secret_reach.load_settings_sources(
        env.cwd, env.home, env.config_dir, env.managed_dir, errs
    )
    for message in errs:
        env.note(message)
    read: set[str] = set()
    for source in sources:
        read.add(_ident(source.path))
    skipped: list[tuple[str, str]] = []
    for scope, path in _candidates(env):
        try:
            exists = path.exists()
        except OSError:
            exists = True
        if exists and _ident(path) not in read and not _is_dir(path):
            skipped.append((scope, env.mask(path)))
    return Settings(sources=sources, skipped=skipped)


def _ident(path: Path) -> str:
    try:
        return str(path.resolve())
    except (OSError, RuntimeError):
        return str(path)


def _is_dir(path: Path) -> bool:
    try:
        return path.is_dir()
    except OSError:
        return False


# ── Where it runs ─────────────────────────────────────────────────────────────


@dataclass
class RunFacts:
    """Sandbox and approval-mode facts."""

    sandbox_on: bool
    sandbox_known: bool
    sandbox_facts: list[Fact]
    bypass_active: bool
    bypass_requested_by_repo: bool
    approval_facts: list[Fact]
    refs_bypass: list[str]
    refs_repo_bypass: list[str]
    bypass_disabled: bool
    #: ``sandbox.enabled`` is true but on Linux/WSL the sandbox may silently
    #: fall back to running commands unsandboxed (no failIfUnavailable, and
    #: ``bwrap`` or ``socat`` not found).
    deps_unknown: bool = False
    #: Bash can run outside the sandbox without a prompt (see :func:`unsandboxed_bash`).
    unsandboxed_bash: bool = False
    unsandboxed_why: str = ""


def _src(source: SettingsSource | None, env: Env) -> str | None:
    return env.mask(source.path) if source is not None else None


def _finding_ref(findings: list[Finding], fid: str, path: Path | None) -> str | None:
    """*fid* when the scan reported it for *path* (same file), else ``None``."""
    if path is None:
        return None
    want = _ident(path)
    for f in findings:
        if f.id == fid and f.finding_path and _ident(Path(f.finding_path)) == want:
            return fid
    return None


def run_facts(settings: Settings, env: Env, findings: list[Finding]) -> RunFacts:
    """Sandbox and approval mode, each fact naming its source file."""
    src = settings.sources
    enabled, enabled_src = resolve(src, _key("sandbox", "enabled"))
    fs_off, fs_src = resolve(
        src, _key("sandbox", "filesystem", "disabled"), ("managed", "user")
    )
    sandbox_facts = [
        Fact(
            "sandbox.enabled",
            str(enabled).lower() if isinstance(enabled, bool) else _NOT_SET,
            _src(enabled_src, env),
        )
    ]
    if fs_off is True:
        sandbox_facts.append(
            Fact("sandbox.filesystem.disabled", "true", _src(fs_src, env))
        )
    sandbox_known = not settings.decisive_skipped
    sandbox_on = (
        enabled is True
        and fs_off is not True
        and _SANDBOX_OS_SUPPORTED
        and sandbox_known
    )
    fail_if, fail_src = resolve(
        src, _key("sandbox", "failIfUnavailable"), ("managed", "user")
    )
    deps_unknown = False
    if sandbox_on and _IS_LINUX:
        if fail_if is True:
            sandbox_facts.append(
                Fact("sandbox.failIfUnavailable", "true", _src(fail_src, env))
            )
        else:
            missing = [t for t in _LINUX_SANDBOX_TOOLS if shutil.which(t) is None]
            if missing:
                sandbox_on = False
                deps_unknown = True
                sandbox_facts.append(
                    Fact(
                        "sandbox dependencies not found",
                        ", ".join(missing),
                        SANDBOX_DOC,
                    )
                )
    if enabled is True and not _SANDBOX_OS_SUPPORTED:
        sandbox_facts.append(
            Fact("platform", "the sandbox runs on macOS, Linux and WSL2 only", None)
        )

    # Approval mode.  bypassPermissions counts from managed and user settings;
    # project and local files ask for it but Claude Code 2.1.257+ ignores them.
    mode_any, mode_any_src = resolve(src, _key("permissions", "defaultMode"))
    mode_honoured, mode_src = resolve(
        src, _key("permissions", "defaultMode"), ("managed", "user")
    )
    disable, disable_src = resolve(
        src,
        _key("permissions", "disableBypassPermissionsMode"),
        ("managed", "user"),
    )
    bypass_disabled = disable == "disable"
    repo_mode, repo_src = resolve(
        src, _key("permissions", "defaultMode"), ("project", "local")
    )
    approval_facts = [
        Fact(
            "permissions.defaultMode",
            str(mode_any) if mode_any is not None else _NOT_SET,
            _src(mode_any_src, env),
        ),
        Fact(
            "permissions.disableBypassPermissionsMode",
            str(disable) if disable is not None else _NOT_SET,
            _src(disable_src, env),
        ),
    ]
    bypass_active = mode_honoured == "bypassPermissions" and not bypass_disabled
    repo_bypass = repo_mode == "bypassPermissions" and not bypass_disabled
    refs_bypass: list[str] = []
    if bypass_active and mode_src is not None:
        refs_bypass.append(f"{env.mask(mode_src.path)}:permissions.defaultMode")
        fid = _finding_ref(findings, "HARNESS-001", mode_src.path)
        if fid:
            refs_bypass.insert(0, fid)
    refs_repo: list[str] = []
    if repo_bypass and repo_src is not None:
        refs_repo.append(f"{env.mask(repo_src.path)}:permissions.defaultMode")
        fid = _finding_ref(findings, "HARNESS-001", repo_src.path)
        if fid:
            refs_repo.insert(0, fid)
    bash_out, bash_why = unsandboxed_bash(settings)
    if bash_out and sandbox_on:
        approval_facts.append(Fact("Bash can run unsandboxed", bash_why, SANDBOX_DOC))
    return RunFacts(
        sandbox_on=sandbox_on,
        sandbox_known=sandbox_known,
        sandbox_facts=sandbox_facts,
        bypass_active=bypass_active,
        bypass_requested_by_repo=repo_bypass,
        approval_facts=approval_facts,
        refs_bypass=refs_bypass,
        refs_repo_bypass=refs_repo,
        bypass_disabled=bypass_disabled,
        deps_unknown=deps_unknown,
        unsandboxed_bash=bash_out and sandbox_on,
        unsandboxed_why=bash_why,
    )


# ── Permission rules and the sandbox escape hatches ─────────────────────────


def _rules(settings: Settings, kind: str) -> list[str]:
    """Every ``permissions.<kind>`` string in every settings file."""
    out: list[str] = []
    for source in settings.sources:
        for item in _list(_d(source.data.get("permissions")).get(kind)):
            if isinstance(item, str):
                out.append(item.strip())
    return out


def _bash_rules(rules: list[str]) -> list[str]:
    return [r for r in rules if r == "Bash" or r.startswith("Bash(")]


def _norm_command(text: str) -> str:
    return re.sub(r"[\s:]*\*$", "", text.strip())


def _rule_covers(rule: str, command: str) -> bool:
    """Does the ``Bash`` allow *rule* cover (or overlap) the excluded *command*?"""
    if rule == "Bash":
        return True
    a, b = _norm_command(rule[len("Bash(") : -1]), _norm_command(command)
    return a == "" or b.startswith(a) or a.startswith(b)


def unsandboxed_bash(settings: Settings) -> tuple[bool, str]:
    """Can a Bash command run outside the sandbox without a prompt?

    Sandboxing doc: ``sandbox.excludedCommands`` "run matching commands outside
    the sandbox, which means no filesystem restrictions and no network proxy";
    a command that fails in the sandbox can be retried unsandboxed unless
    ``sandbox.allowUnsandboxedCommands`` is false (user, managed or
    ``--settings``).  A Bash allow rule means no prompt for the command, so
    either route is silent.  The default of ``allowUnsandboxedCommands`` is not
    stated, so it is read as allowing the retry.
    """
    allows = _bash_rules(_rules(settings, "allow"))
    retry, _src_ = resolve(
        settings.sources,
        _key("sandbox", "allowUnsandboxedCommands"),
        ("managed", "user"),
    )
    if allows and retry is not False:
        return True, (
            "a Bash allow rule and the unsandboxed retry is not switched off"
            " (sandbox.allowUnsandboxedCommands is not false in user or managed"
            " settings)"
        )
    excluded: list[str] = []
    for source in settings.sources:
        for item in _list(_d(source.data.get("sandbox")).get("excludedCommands")):
            if isinstance(item, str):
                excluded.append(item)
    for command in excluded:
        if any(_rule_covers(rule, command) for rule in allows):
            return True, (
                "sandbox.excludedCommands runs a command outside the sandbox and"
                " a Bash allow rule covers it"
            )
    return False, ""


def _broad_domain(domain: str) -> bool:
    d = domain.strip().lower()
    return d in ("*", "*.*") or bool(re.fullmatch(r"\*\.[a-z0-9-]+", d))


def _webfetch(settings: Settings) -> tuple[list[str], bool]:
    """``(domains, any_host)`` from ``WebFetch`` allow rules."""
    domains: list[str] = []
    any_host = False
    for rule in _rules(settings, "allow"):
        if rule in ("WebFetch", "WebFetch(*)"):
            any_host = True
        elif rule.startswith("WebFetch(domain:") and rule.endswith(")"):
            domains.append(rule[len("WebFetch(domain:") : -1].strip())
    return domains, any_host


# ── Network ───────────────────────────────────────────────────────────────────


def _proxy_ports(settings: Settings, strict: object, managed_only: object) -> list[str]:
    """Names of the proxy ports that apply (sandboxing doc, "proxy ports").

    A port counts from any settings file, except that with
    ``allowManagedDomainsOnly`` only managed settings count and with a narrower
    network lock (``strictAllowlist``) only managed and user settings do.
    """
    scopes: tuple[str, ...] | None = None
    if managed_only is True:
        scopes = ("managed",)
    elif strict is True:
        scopes = ("managed", "user")
    names: list[str] = []
    for key in ("httpProxyPort", "socksProxyPort"):
        value, _s = resolve(settings.sources, _key("sandbox", "network", key), scopes)
        if value is not None:
            names.append(f"sandbox.network.{key}")
    return names


_RUNTIME_SOCKET_RE = re.compile(r"docker|podman|containerd|cri-o|crio", re.IGNORECASE)


def _unix_socket_reach(settings: Settings) -> str:
    """Why ``sandbox.network`` unix-socket settings open the network, or ``""``.

    A sandboxed command that can connect to a container runtime's socket asks
    the daemon (outside the sandbox) to run anything with any network, and
    ``allowAllUnixSockets`` allows every socket.
    """
    for source in settings.sources:
        net = _d(_d(source.data.get("sandbox")).get("network"))
        if net.get("allowAllUnixSockets") is True:
            return (
                "sandbox.network.allowAllUnixSockets lets sandboxed commands"
                " connect to every Unix socket, including a container runtime's"
            )
        for item in _list(net.get("allowUnixSockets")):
            if isinstance(item, str) and _RUNTIME_SOCKET_RE.search(item):
                return (
                    "sandbox.network.allowUnixSockets lists a container runtime"
                    " socket (docker, podman or containerd): a command that can"
                    " reach it can start a container with any network access"
                )
    return ""


_OFF_VALUES = frozenset({"false", "0", "no", "off"})


def connectors_possible(settings: Settings, env: Env) -> str:
    """Why claude.ai connectors may be loaded, or ``""`` when they are ruled out.

    With a claude.ai subscription login Claude Code fetches the account's
    connectors (remote MCP servers) at startup; they are in no local file.
    Documented ways they are not loaded (MCP doc, "Use MCP servers from
    claude.ai"; settings reference): ``disableClaudeAiConnectors``,
    ``ENABLE_CLAUDEAI_MCP_SERVERS`` set false, a ``managed-mcp.json`` without
    the managed ``allowAllClaudeAiMcps``, or an API-key login
    (``apiKeyHelper`` or ``ANTHROPIC_AUTH_TOKEN``).
    """
    src = settings.sources
    off, _s = resolve(src, _key("disableClaudeAiConnectors"))
    if off is True:
        return ""
    flag, _s = resolve(src, _key("env", "ENABLE_CLAUDEAI_MCP_SERVERS"))
    if flag is False or str(flag).strip().lower() in _OFF_VALUES:
        return ""
    if env.managed_dir is not None and os.path.lexists(
        env.managed_dir / "managed-mcp.json"
    ):
        allow, _s = resolve(src, _key("allowAllClaudeAiMcps"), ("managed",))
        if allow is not True:
            return ""
    helper, _s = resolve(src, _key("apiKeyHelper"))
    if isinstance(helper, str) and helper.strip():
        return ""
    # ANTHROPIC_API_KEY is not on this list: Claude Code asks once to approve
    # it in interactive mode, and a declined key falls back to the login.
    value, _s = resolve(src, _key("env", "ANTHROPIC_AUTH_TOKEN"))
    if isinstance(value, str) and value.strip():
        return ""
    return (
        "claude.ai connectors (remote MCP servers from the account) are loaded at"
        " startup with a subscription login and are in no local file; none of"
        " disableClaudeAiConnectors, ENABLE_CLAUDEAI_MCP_SERVERS=false, a"
        " managed-mcp.json or an API-key login rules them out"
    )


def _mcp_allowed_unbounded(
    settings: Settings, facts: RunFacts, net: NetworkView
) -> list[str]:
    """Local file-reading or shell servers the agent may call without a prompt.

    An ``mcp__<server>`` (or ``mcp__<server>__<tool>``) allow rule, or bypass
    mode, lets the server run unprompted, and MCP servers are not bound by
    ``Read`` deny rules.  Servers whose path arguments exclude home and every
    credential store are left out.
    """
    rules = [r for r in _rules(settings, "allow") if r.startswith("mcp__")]
    names: set[str] = set()
    for rule in rules:
        names.add(rule.split("__")[1] if rule.count("__") >= 1 else "")
    out: list[str] = []
    for v in [*net.reaching, *net.unclassified, *net.quiet]:
        if not v.local_reader or v.bounded:
            continue
        key = re.sub(r"[^A-Za-z0-9_-]", "_", v.name)
        if facts.bypass_active or "*" in names or key in names or v.name in names:
            out.append(v.name)
    return out


def sandbox_network(
    settings: Settings, env: Env, facts: RunFacts
) -> tuple[str, str, list[Fact]]:
    """The sandbox's network restriction: ``(state, text, facts)``.

    States: ``strict`` (unlisted hosts are refused), ``prompts`` (unlisted
    hosts prompt in the default modes), ``open`` (the sandbox is off, or
    ``bypassPermissions`` lets unlisted hosts through, or ``allowedDomains``
    has ``*``), ``unknown`` (a settings file that decides could not be read).
    Sandboxing doc, "Network isolation".
    """
    src = settings.sources
    strict, strict_src = resolve(
        src, _key("sandbox", "network", "strictAllowlist"), ("managed", "user")
    )
    managed_only, managed_src = resolve(
        src,
        _key("sandbox", "network", "allowManagedDomainsOnly"),
        ("managed",),
    )
    out: list[Fact] = []
    domains: list[str] = []
    for source in src:
        for item in _list(
            _d(_d(source.data.get("sandbox")).get("network")).get("allowedDomains")
        ):
            if isinstance(item, str):
                domains.append(item.strip())
    # "Paths and domains from both sandbox settings and permission rules are
    # merged into the final sandbox configuration" (sandboxing doc).
    fetch_domains, fetch_any = _webfetch(settings)
    domains += fetch_domains
    if strict is not None:
        out.append(
            Fact(
                "sandbox.network.strictAllowlist",
                str(strict).lower(),
                _src(strict_src, env),
            )
        )
    if managed_only is not None:
        out.append(
            Fact(
                "sandbox.network.allowManagedDomainsOnly",
                str(managed_only).lower(),
                _src(managed_src, env),
            )
        )
    out.append(
        Fact("sandbox.network.allowedDomains", f"{len(domains)} entr(ies)", None)
    )
    if not facts.sandbox_known:
        return "unknown", "a settings file that decides this could not be read", out
    if facts.deps_unknown:
        return (
            "unknown",
            "the sandbox may not be running: bubblewrap and socat were not both"
            " found and sandbox.failIfUnavailable is not true, so Claude Code"
            " would run commands without sandboxing",
            out,
        )
    if not facts.sandbox_on:
        return "open", "the sandbox is not on, so Bash has no network restriction", out
    if any(_broad_domain(d) for d in domains):
        return (
            "open",
            "an allowed domain is a wildcard (sandbox.network.allowedDomains or"
            " a WebFetch(domain:...) allow rule)",
            out,
        )
    if fetch_any:
        return "open", "a WebFetch allow rule lets any host through", out
    if facts.unsandboxed_bash:
        return "open", f"Bash can run outside the sandbox: {facts.unsandboxed_why}", out
    sock = _unix_socket_reach(settings)
    if sock:
        return "open", sock, out
    ports = _proxy_ports(settings, strict, managed_only)
    if ports:
        out.append(Fact("sandbox.network proxy port", ", ".join(ports), SANDBOX_DOC))
        return (
            "unknown",
            "a sandbox proxy port is set; the proxy filters everything sent to it"
            " and Claude Code's own network controls stop applying to that traffic",
            out,
        )
    locked = strict is True or managed_only is True
    if locked:
        return "strict", "unlisted hosts are refused (strict allowlist)", out
    if facts.bypass_active:
        return (
            "open",
            "bypassPermissions lets unlisted hosts through without a prompt",
            out,
        )
    return "prompts", "unlisted hosts prompt (no silent route out)", out


# ── Credentials ───────────────────────────────────────────────────────────────


def credential_question(
    findings: list[Finding],
    env: Env,
    ran: bool,
    errors: list[str],
    *,
    unsandboxed_bash: bool = False,
    env_secrets: list[Fact] | None = None,
    outside: list[Fact] | None = None,
    store_hits: list[Fact] | None = None,
    mcp_open: list[str] | None = None,
) -> tuple[Question, bool]:
    """Question 2 from REACH-001..003; the bool is "a store is readable".

    A scan that did not run the checks (no Claude Code config directory) or
    that reported a problem reading settings cannot say "none".

    ``unsandboxed_bash``: a deny rule is carried into the sandbox for Bash, so
    when Bash can run outside the sandbox the stores a deny rule "covers" are
    readable after all.  ``env_secrets``: secret-shaped variables in a settings
    ``env`` block, which every command and local MCP server inherits.
    """
    reach = [f for f in findings if f.id == "REACH-001" and f.client in CLIENTS]
    r002 = [f for f in findings if f.id == "REACH-002"]
    r003 = [f for f in findings if f.id == "REACH-003"]
    readable: list[str] = []
    for f in reach:
        for part in f.evidence.split("; "):
            if part.strip() and not part.startswith(
                "sandbox.allowNestedUserNamespaces"
            ):
                readable.append(part.strip())
    existing = secret_reach.existing_home_stores(env.home, env.config_dir)
    readable_labels = {p.split(" (")[0] for p in readable}
    covered = [
        f"{env.mask(p)} ({s.label})"
        for s, p in existing
        if env.mask(p) not in readable_labels
    ]
    facts = [Fact("readable without a prompt", f"{len(readable)}", None)]
    facts += [Fact("readable", r, None) for r in readable[:20]]
    facts.append(
        Fact("covered by a deny rule or sandbox entry", f"{len(covered)}", None)
    )
    facts += [Fact("covered", c, None) for c in covered[:20]]
    bypassed = covered if unsandboxed_bash else []
    if bypassed:
        facts.append(
            Fact(
                "covered only for sandboxed Bash",
                f"{len(bypassed)} (Bash can run unsandboxed, which skips the"
                " sandbox's file rules)",
                SANDBOX_DOC,
            )
        )
    secrets = env_secrets or []
    facts += secrets[:20]
    outside = outside or []
    hits = store_hits or []
    facts += hits[:20]
    mcp_open = mcp_open or []
    facts += outside[:20]
    facts += [
        Fact("MCP server reads files without a prompt", m, None) for m in mcp_open
    ]
    if r003:
        facts.append(
            Fact(
                "project .env files with no deny rule",
                r003[0].evidence,
                None,
            )
        )
    if r002:
        facts.append(Fact("login store mode", r002[0].evidence, None))
    refs = ["REACH-001"] if reach else []
    if reach or bypassed or secrets or hits:
        bits = []
        if hits:
            bits.append(
                f"{len(hits)} hook, apiKeyHelper or statusLine command(s) name a"
                " credential store path and run outside the sandbox"
            )
        if reach or bypassed:
            bits.append(
                f"{len(readable) + len(bypassed)} credential store(s) readable"
                f" without a prompt; {len(covered) - len(bypassed)} covered"
            )
        if secrets:
            bits.append(
                f"{len(secrets)} secret-shaped variable(s) in settings env, inherited"
                " by every command and local MCP server"
            )
        return (
            Question("credentials", Status.FAIL, "; ".join(bits), facts, refs),
            True,
        )
    problems = [
        e
        for e in errors
        if e.startswith("secret reach:") and "working directory" not in e
    ]
    if not ran or problems or outside or mcp_open:
        if not ran:
            why = (
                "Claude Code's config directory does not exist, so the credential"
                " checks (REACH-001..003) did not run"
            )
        elif problems:
            why = "the credential checks reported a problem reading settings"
        elif outside:
            why = (
                f"{len(outside)} hook, apiKeyHelper or statusLine command(s) run"
                " outside the sandbox and can read any file the user can; REACH-001"
                " and the deny rules do not apply to them"
            )
        else:
            why = (
                "an mcp__ allow rule (or bypass mode) lets a local MCP server that"
                " reads files run without a prompt, and MCP servers ignore Read"
                " deny rules: " + ", ".join(mcp_open[:5])
            )
        return (
            Question("credentials", Status.UNKNOWN, why, facts, []),
            False,
        )
    return (
        Question(
            "credentials",
            Status.PASS,
            f"no well-known credential store is readable without a prompt"
            f" ({len(covered)} covered)",
            facts,
            [],
        ),
        False,
    )


# ── Commands that run outside the sandbox, and secrets in env ──────────────────

_SECRET_NAME_RE = SECRET_NAME_RE
_MAX_LISTED = 20


_DEV_NET_RE = re.compile(r"/dev/(?:tcp|udp)\b", re.IGNORECASE)

#: Programs that, run bare, only print or report local state.  The list is
#: deliberately tiny.  ``git`` (``diff.external``, textconv, fsmonitor run
#: programs a repository configures) and ``sort`` (``--compress-program``) are
#: not on it, nor is anything that reads a file.
_LOCAL_WORDS = frozenset(
    {"echo", "printf", "true", "false", "date", "pwd", "whoami", "hostname", "uname"}
)
#: Any of these makes a command something other than one bare program:
#: substitution, redirection, pipes, lists, grouping, expansion, newlines.
_SHELL_SYNTAX_RE = re.compile(r"[|&;<>$`(){}\n\r\\]")


def _net_tool(command: str) -> str | None:
    """The network tool in *command*: HOOK-001's list plus ``/dev/tcp``/``/dev/udp``."""
    tool = _network_primitive([command])
    if tool:
        return tool
    match = _DEV_NET_RE.search(normalize_for_detection(command))
    return match.group(0) if match else None


def _known_local(command: str) -> bool:
    """True only when *command* is one bare, harmless, local printing program.

    No leading ``VAR=`` assignment (``LD_PRELOAD=...``, ``PATH=...``), no
    substitution, redirection, pipe or list, no path in the program name, and
    the program is on :data:`_LOCAL_WORDS`.
    """
    text = command.strip()
    if not text or _SHELL_SYNTAX_RE.search(text):
        return False
    first = text.split()[0]
    return first in _LOCAL_WORDS


def _host_of(value: object) -> str:
    """The host in a URL-ish value (no userinfo, path or query), else ``(set)``."""
    if not isinstance(value, str) or not value.strip():
        return "(set)"
    from urllib.parse import urlsplit  # noqa: PLC0415

    try:
        host = urlsplit(
            value.strip() if "://" in value else f"//{value.strip()}"
        ).hostname
    except ValueError:
        host = None
    return host or "(set)"


_PROXY_NAMES = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY")


def _destinations(
    scope: str, block: object, all_env: dict, ref: str
) -> tuple[list[Fact], list[Fact], list[Fact]]:
    """``(routes, unknown, facts)`` for the destination names in one ``env`` block.

    Project and local files are the repository's: a destination off the
    first-party list (CFHYG-007's predicate) is a route out, and names whose
    effect is not modelled are unknown.  User and managed files are the
    user's own choice: shown as facts.
    """
    routes: list[Fact] = []
    unknown: list[Fact] = []
    facts: list[Fact] = []
    if not isinstance(block, dict):
        return routes, unknown, facts
    repo = scope in ("project", "local")
    for name, value in block.items():
        text = str(name)
        upper = text.upper()
        if not is_destination(text):
            continue
        if not repo:
            shown = (
                "(set)"
                if upper in DESTINATION_UNKNOWN_NAMES
                else _host_of(value)
                if upper != "ANTHROPIC_FOUNDRY_RESOURCE"
                else str(value)[:64]
            )
            facts.append(Fact(f"API destination ({text})", shown, ref))
            continue
        if upper in DESTINATION_UNKNOWN_NAMES:
            if upper != "ANTHROPIC_VERTEX_PROJECT_ID" or _truthy(
                all_env.get("CLAUDE_CODE_USE_VERTEX")
            ):
                unknown.append(
                    Fact(f"repository env {text} (effect not modelled)", "", ref)
                )
            continue
        if not isinstance(value, str) or not value.strip():
            continue
        if upper == "ANTHROPIC_FOUNDRY_RESOURCE":
            label = "a resource the repository chose"
        else:
            # CFHYG-007 does not list ALL_PROXY (Node ignores it); reach asks
            # the same predicate under the HTTPS_PROXY name, the stricter reading.
            label = _redirect_host(
                "HTTPS_PROXY"
                if upper == "ALL_PROXY"
                else upper
                if upper in _PROXY_NAMES
                else text,
                value,
            )
        if label is not None:
            routes.append(
                Fact("repository env redirects API traffic", f"{text} -> {label}", ref)
            )
    return routes, unknown, facts


def _truthy(value: object) -> bool:
    return str(value).strip().lower() not in ("", "0", "false", "no", "off", "none")


@dataclass
class Collected:
    """Everything Claude Code runs outside the sandbox, and what is not understood.

    ``cmds``: hooks (settings, plugins, skills, agents, commands), command-valued
    keys, and one ``other`` item per settings key ``reach`` does not know.
    ``env_unsafe``: names in a settings ``env`` block that are not on the
    benign allowlist; any such name means no command counts as known local and
    no server counts as declared (they may load code).
    """

    cmds: list[Cmd] = field(default_factory=list)
    env_unsafe: list[tuple[str, str]] = field(default_factory=list)
    #: Repository env names that point API traffic off the first-party list.
    dest_routes: list[Fact] = field(default_factory=list)
    #: Repository env names whose network effect is not modelled.
    dest_unknown: list[Fact] = field(default_factory=list)
    #: The user's or admin's own destinations, shown as facts.
    dest_facts: list[Fact] = field(default_factory=list)
    #: Managed ``wslInheritsWindowsSettings`` is set: another policy chain.
    wsl_inherits: bool = False

    @property
    def code_loading(self) -> bool:
        """A settings ``env`` name might load code into a command or server."""
        return bool(self.env_unsafe)


def _item(what: str, text: str, ref: str) -> Cmd:
    return Cmd(what, text, ref, "other" if text == "?" else "command")


def collect(settings: Settings, env: Env) -> Collected:
    """Gather :class:`Collected` from every settings file, plugin and skill dir.

    The allowlist principle (docs/reach.md, "How reach decides"): a settings
    key that is neither understood nor known inert becomes an ``other`` item,
    so it can only ever make an answer COULDN'T CHECK.
    """
    out = Collected()
    for source in settings.sources:
        ref = env.mask(source.path)
        data = source.data
        if "hooks" in data:
            out.cmds += hook_items(data["hooks"], "hook", f"{ref}:hooks")
        for key in sorted(COMMAND_KEYS):
            if key in data:
                texts = command_texts(data[key]) or (
                    ["?"] if data[key] not in (None, "", False, {}, []) else []
                )
                out.cmds += [_item(key, t, f"{ref}:{key}") for t in texts]
        sandbox = _d(data.get("sandbox"))
        for key in SANDBOX_EXECUTABLE_KEYS:
            if key in sandbox:
                out.cmds += [
                    _item(f"sandbox.{key}", t, f"{ref}:sandbox.{key}")
                    for t in command_texts(sandbox[key]) or ["?"]
                ]
        for key in unknown_settings_keys(data):
            out.cmds.append(Cmd(f"setting {key}", "?", f"{ref}:{key}", "other"))
        out.env_unsafe += [
            (name, f"{ref}:env") for name in settings_env_unsafe(data.get("env"))
        ]
        merged = {
            k: v for s2 in settings.sources for k, v in _d(s2.data.get("env")).items()
        }
        r, u, f = _destinations(source.scope, data.get("env"), merged, f"{ref}:env")
        out.dest_routes += r
        out.dest_unknown += u
        out.dest_facts += f
        if "wslInheritsWindowsSettings" in data:
            if source.scope == "managed":
                out.wsl_inherits = True
            else:
                out.cmds.append(
                    Cmd(
                        "setting wslInheritsWindowsSettings",
                        "?",
                        f"{ref}:wslInheritsWindowsSettings",
                        "other",
                    )
                )
    out.cmds += plugin_commands(settings, env)
    out.cmds += all_frontmatter_items(env)
    return out


_PLUGIN_UNSURE = "plugin hook (not known to be enabled)"


def plugin_commands(settings: Settings, env: Env) -> list[Cmd]:
    """Hooks, skills, agents and commands of installed plugins.

    ``enabledPlugins`` false skips the plugin; true counts it; any other state
    is not known to be enabled, and everything it ships is not known local.
    """
    from mcp_audit.plugins.discovery import discover_installed_plugins  # noqa: PLC0415

    out: list[Cmd] = []
    try:
        plugins = discover_installed_plugins(env.config_dir / "plugins")
    except Exception:  # noqa: BLE001 — unreadable plugin state adds nothing
        return out
    for plugin in plugins:
        if plugin.install_path is None:
            continue
        flag, _src_ = resolve(
            settings.sources, _key("enabledPlugins", plugin.plugin_id)
        )
        if flag is False:
            continue
        what = "plugin hook" if flag is True else _PLUGIN_UNSURE
        install = Path(plugin.install_path)
        ref = f"{env.mask(install)}:hooks"
        try:
            for table in plugin_hook_tables(install):
                out += hook_items(table, what, ref)
            out += frontmatter_items(install, what, env)
        except Exception:  # noqa: BLE001 — an unreadable plugin is unknown
            out.append(Cmd(what, "?", ref, "other"))
    return out


def egress_commands(col: Collected, findings: list[Finding], env: Env) -> list[Fact]:
    """Commands and HTTP hooks that run outside the sandbox and reach the network.

    Hooks, helpers and status lines are not sandboxed (sandboxing doc:
    "Claude's file tools, MCP servers, and hooks run outside it").  A network
    tool (or a ``/dev/tcp`` redirect) in a command, or an ``http`` hook, is a
    route out in any file.  Only the tool name is reported, never the command.
    """
    out: list[Fact] = []
    seen: set[tuple[str, str]] = set()

    def add(what: str, tool: str, ref: str) -> None:
        if (what, ref) not in seen:
            seen.add((what, ref))
            out.append(Fact(f"{what} runs a network tool", tool, ref))

    for cmd in col.cmds:
        if cmd.kind == "http":
            add(cmd.what, "http hook", cmd.ref)
        elif cmd.kind == "command" and cmd.what != _PLUGIN_UNSURE:
            tool = _net_tool(cmd.text)
            if tool:
                add(cmd.what, tool.lower(), cmd.ref)
    for f in findings:
        if f.id == "HOOK-001" and f.client in CLIENTS:
            where = env.mask(f.finding_path) if f.finding_path else f.client
            add("hook", "HOOK-001", where)
    return out[:_MAX_LISTED]


def _store_path_re() -> re.Pattern[str]:
    names: set[str] = {".ssh", ".aws", ".gnupg"}
    names |= {st.rel for st in secret_reach.HOME_STORES}
    body = "|".join(
        re.escape(n).replace("/", r"[/\\]")
        for n in sorted(names, key=len, reverse=True)
    )
    return re.compile(rf"(?<![A-Za-z0-9_.-])(?:{body})(?![A-Za-z0-9_-])")


_STORE_PATH_RE = _store_path_re()


def store_commands(col: Collected) -> list[Fact]:
    """Commands that name a credential store path.

    These run outside the sandbox, so no deny rule applies to them; whatever
    their other behaviour, naming ``~/.ssh`` or ``~/.aws/credentials`` is a
    reach into REACH-001's list.  Names the event, never the command.
    """
    out: list[Fact] = []
    seen: set[tuple[str, str]] = set()
    for cmd in col.cmds:
        if cmd.kind != "command" or (cmd.what, cmd.ref) in seen:
            continue
        if _STORE_PATH_RE.search(cmd.text):
            seen.add((cmd.what, cmd.ref))
            out.append(Fact(f"{cmd.what} names a credential store path", "", cmd.ref))
    return out[:_MAX_LISTED]


def opaque_commands(col: Collected) -> list[Fact]:
    """Things that run outside the sandbox and are not known to be local.

    Known local means: a command of the one allowed shape, with no settings
    ``env`` name that could load code.  Everything else (an unclassifiable
    hook type, an unknown settings key, a script, an interpreter) is opaque.
    Names the event or key, never the command.
    """
    out: list[Fact] = []
    seen: set[tuple[str, str]] = set()
    for cmd in col.cmds:
        if cmd.kind == "http":
            continue
        if cmd.kind == "command" and cmd.what != _PLUGIN_UNSURE:
            if _net_tool(cmd.text):
                continue
            if _known_local(cmd.text) and not col.code_loading:
                continue
        if (cmd.what, cmd.ref) in seen:
            continue
        seen.add((cmd.what, cmd.ref))
        out.append(
            Fact(
                f"{cmd.what} runs something that is not known to be local", "", cmd.ref
            )
        )
    return out[:_MAX_LISTED]


def env_secrets(settings: Settings, env: Env) -> list[Fact]:
    """Secret-shaped variables in any settings file's ``env`` block (names only).

    The block sets the environment of every command Claude Code runs and of its
    local MCP servers.  A name that looks like a credential, or a value that
    matches a known credential format, counts; the value is never reported.
    """
    out: list[Fact] = []
    for source in settings.sources:
        block = source.data.get("env")
        if not isinstance(block, dict):
            continue
        for name, value in block.items():
            text = value if isinstance(value, str) else ""
            by_name = bool(text) and bool(_SECRET_NAME_RE.search(str(name)))
            by_value = any(p.search(text) for _n, p, _v in SECRET_PATTERNS)
            if by_name or by_value:
                out.append(
                    Fact(
                        "secret-shaped env variable (name only)",
                        str(name),
                        f"{env.mask(source.path)}:env",
                    )
                )
    return out[:_MAX_LISTED]


# ── MCP servers Claude Code reads that default discovery does not ───────────────

_CLAUDE_JSON_CAP = 8 * 1024 * 1024
MANAGED_CLIENT = "claude-code-managed"


def _servers_in(
    entries: object, client: str, path: Path, label: str | None = None
) -> list[ServerConfig]:
    if not isinstance(entries, dict):
        return []
    cfg = DiscoveredConfig(client_name=client, root_key="mcpServers", path=path)
    found = _servers_from_dict(entries, cfg)
    if label:
        for server in found:
            server.name = f"{server.name} [{label}]"
    return found


def extra_servers(env: Env) -> tuple[list[ServerConfig], bool, list[str]]:
    """Servers Claude Code loads that default discovery does not return.

    - ``~/.claude.json`` ``projects.<path>.mcpServers``: the per-project
      servers (all of them, as this is a machine view).
    - ``managed-mcp.json`` and the managed ``managedMcpServers`` setting
      (https://code.claude.com/docs/en/managed-mcp).  A readable
      ``managed-mcp.json`` takes exclusive control: only managed servers load.

    Returns ``(servers, exclusive, problems)``.  A file that exists but cannot
    be read is a problem (the network answer becomes COULDN'T CHECK); nothing
    here raises.
    """
    servers: list[ServerConfig] = []
    problems: list[str] = []
    exclusive = False

    path = env.home / ".claude.json"
    raw, why = read_capped(path, _CLAUDE_JSON_CAP)
    if why is not None:
        problems.append(f"{env.mask(path)} {why}")
    elif raw is not None:
        try:
            doc = json.loads(raw.decode("utf-8-sig", errors="replace"))
        except (ValueError, RecursionError):
            doc = None
            problems.append(f"{env.mask(path)} is not valid JSON")
        projects = _d(_d(doc).get("projects"))
        for key, entry in projects.items():
            label = env.mask(Path(str(key)))
            servers += _servers_in(
                _d(entry).get("mcpServers"), "claude-code", path, f"project {label}"
            )

    if env.managed_dir is not None:
        mpath = env.managed_dir / "managed-mcp.json"
        raw, why = read_capped(mpath)
        if why is not None:
            problems.append(f"{env.mask(mpath)} {why}")
        elif raw is not None:
            try:
                doc = json.loads(raw.decode("utf-8-sig", errors="replace"))
            except (ValueError, RecursionError):
                doc = None
                problems.append(f"{env.mask(mpath)} is not valid JSON")
            if isinstance(_d(doc).get("mcpServers"), dict):
                exclusive = True
                servers_managed = _servers_in(
                    _d(doc)["mcpServers"], MANAGED_CLIENT, mpath
                )
            else:
                servers_managed = []
                problems.append(f"{env.mask(mpath)} has no mcpServers object")
            servers += servers_managed
        try:
            policy = read_managed_policy(env.managed_dir, [])
        except Exception:  # noqa: BLE001 — reported by the policy question
            policy = None
        if policy is not None:
            spath = env.managed_dir / "managed-settings.json"
            servers += _servers_in(policy.provided, MANAGED_CLIENT, spath)
    return servers, exclusive, problems


# ── Policy ────────────────────────────────────────────────────────────────────


def classify_writer(uid: int, gid: int, mode: int) -> str:
    """Who can change a file: ``admin``, ``user`` or ``unknown``.

    Pure over ``st_uid``/``st_gid``/``st_mode`` so it does not depend on who
    runs the scan (``os.access`` answers yes for everything as root).  A file
    owned by a non-root account can be rewritten by that account; other-writable
    can be rewritten by anyone; group-writable depends on who is in the group,
    which is not read (``unknown``) unless the group is root's.
    """
    if uid != 0:
        return "user"
    if mode & stat.S_IWOTH:
        return "user"
    if mode & stat.S_IWGRP:
        return "admin" if gid == 0 else "unknown"
    return "admin"


def writer_of(path: Path) -> str:
    """:func:`classify_writer` of *path* and its directory; worst wins.

    ``unknown`` on Windows (ACLs are not read) and when the file cannot be
    examined.
    """
    if sys.platform.startswith("win") or not hasattr(os, "getuid"):
        return "unknown"
    rank = {"admin": 0, "unknown": 1, "user": 2}
    worst = "admin"
    for candidate in (path, path.parent):
        try:
            st = candidate.stat()
        except OSError:
            return "unknown"
        kind = classify_writer(st.st_uid, st.st_gid, st.st_mode)
        if rank[kind] > rank[worst]:
            worst = kind
    return worst


@dataclass
class PolicySource:
    """Which managed source is in force, and who can change it.

    This is the one adapter between ``reach`` and managed-policy source
    handling.  It reads the sources #267 ranks (``read_effective_policy``): the
    macOS managed-preferences profile, the Windows ``HKLM`` and ``HKCU``
    registry values and the managed files.  Server-managed settings are not
    read.  Only :func:`managed_policy_source` touches that reader.
    """

    present: bool
    files: list[Path] = field(default_factory=list)
    has_mcp_policy: bool = False
    incomplete: bool = False
    writer: str = "unknown"
    #: Label of the source in force (``HKLM registry``, ``managed settings
    #: files``, ...) and why it won; ``None`` for the managed files alone.
    label: str | None = None
    note: str | None = None
    #: Other sources that are present but not in force.
    ignored: list[str] = field(default_factory=list)
    #: ``managedMcpServers`` entries Claude Code drops (a command-type entry,
    #: a non-object value), shown as a fact only.
    dropped: list[str] = field(default_factory=list)


def managed_policy_source(env: Env) -> PolicySource:
    """Read the policy source in force (#267's ranking) and say who can change it.

    Never raises.  A policy that only ``HKCU`` delivers is user-writable
    without elevation, so its writer is ``user``, never ``admin``.
    """
    errs: list[str] = []
    try:
        policy = read_effective_policy(
            env.managed_dir,
            errs,
            env.platform_sources,  # type: ignore[arg-type]
        )
    except Exception as exc:  # noqa: BLE001 — a reader failure is reported
        env.note(f"managed policy: check failed: {type(exc).__name__}")
        return PolicySource(present=False, incomplete=True)
    for message in errs:
        env.note(message)
    files = list(policy.settings_files)
    if policy.mcp_file is not None:
        files.append(policy.mcp_file)
    rank = {"admin": 0, "unknown": 1, "user": 2}
    writer = "admin"
    if policy.source_kind == "hkcu":
        writer = "user"
    elif policy.source_kind in ("mdm", "hklm"):
        writer = "admin"
    else:
        for path in files + list(policy.unparsable_files):
            kind = writer_of(path)
            if rank[kind] > rank[writer]:
                writer = kind
        if not files and not policy.unparsable_files and not policy.sources_found:
            writer = "unknown"
    return PolicySource(
        present=policy.present,
        files=files,
        has_mcp_policy=policy.has_mcp_policy,
        incomplete=policy.incomplete or bool(policy.malformed_sources),
        writer=writer if policy.present else "unknown",
        label=policy.source_label,
        note=policy.selection_note,
        ignored=list(policy.ignored_sources),
        dropped=list(policy.provided_dropped),
    )


def policy_question(source: PolicySource, env: Env) -> Question:
    """Question 4 for Claude Code."""
    where = env.mask(env.managed_dir) if env.managed_dir is not None else "(none)"
    facts = [Fact("managed settings directory", where, None)]
    facts += [Fact("managed file", env.mask(p), None) for p in source.files[:20]]
    in_force = source.label or "managed settings files"
    facts.append(Fact("policy source in force", in_force, None))
    if source.note:
        facts.append(Fact("why this source", source.note, None))
    facts += [
        Fact("source present, not in force", i, None) for i in source.ignored[:10]
    ]
    facts += [
        Fact("managedMcpServers entry Claude Code drops", d, None)
        for d in source.dropped[:10]
    ]
    unread = (
        "server-managed settings are not read"
        " (https://code.claude.com/docs/en/managed-settings)"
    )
    if not source.present:
        return Question(
            "policy",
            Status.UNKNOWN,
            f"no managed settings file found in {where}; {unread}",
            facts,
        )
    if source.incomplete:
        return Question(
            "policy",
            Status.UNKNOWN,
            f"a managed settings file in {where} could not be read, so what it"
            " enforces is not known",
            facts,
        )
    what = "an MCP policy" if source.has_mcp_policy else "settings but no MCP policy"
    subject = in_force if source.label else f"managed files in {where}"
    if source.writer == "admin":
        return Question(
            "policy",
            Status.PASS,
            f"{subject} set {what}; only an administrator can change them. {unread}",
            facts + [Fact("who can change them", "administrator only", None)],
        )
    if source.writer == "user":
        return Question(
            "policy",
            Status.FAIL,
            f"{subject} set {what}, but a non-administrator can"
            " change them, so nothing is enforced against the person at this"
            " machine",
            facts + [Fact("who can change them", "a non-administrator account", None)],
        )
    return Question(
        "policy",
        Status.UNKNOWN,
        f"{subject} set {what}; who can change them could not be"
        f" determined (group membership or ACLs are not read). {unread}",
        facts,
    )


# ── Logging ───────────────────────────────────────────────────────────────────


def _env_value(
    sources: list[SettingsSource], name: str, scopes: tuple[str, ...]
) -> tuple[str | None, SettingsSource | None]:
    value, src = resolve(sources, lambda d: _d(d.get("env")).get(name), scopes)
    if value is None:
        return None, None
    return (value if isinstance(value, str) else str(value)).strip(), src


def logging_question(settings: Settings, env: Env) -> Question:
    """Question 5 for Claude Code: OpenTelemetry in managed or user settings.

    Monitoring doc: telemetry needs ``CLAUDE_CODE_ENABLE_TELEMETRY=1``; tool
    activity (``claude_code.tool_decision``, ``claude_code.tool_result``) is a
    logs/events record, selected by ``OTEL_LOGS_EXPORTER``; there is no default
    protocol.  Variables in a repository's settings files are ignored, except
    that a repository can set an exporter selector to ``none``.
    """
    src = settings.sources
    honoured = ("managed", "user")
    enable, enable_src = _env_value(src, "CLAUDE_CODE_ENABLE_TELEMETRY", honoured)
    exporter, exporter_src = _env_value(src, "OTEL_LOGS_EXPORTER", honoured)
    proto, proto_src = _env_value(src, "OTEL_EXPORTER_OTLP_PROTOCOL", honoured)
    logs_proto, logs_proto_src = _env_value(
        src, "OTEL_EXPORTER_OTLP_LOGS_PROTOCOL", honoured
    )
    endpoint, endpoint_src = _env_value(src, "OTEL_EXPORTER_OTLP_ENDPOINT", honoured)
    logs_endpoint, logs_endpoint_src = _env_value(
        src, "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT", honoured
    )
    repo_exporter, repo_src = _env_value(
        src, "OTEL_LOGS_EXPORTER", ("project", "local")
    )
    managed_exporter, _ = _env_value(src, "OTEL_LOGS_EXPORTER", ("managed",))

    facts = [
        Fact("CLAUDE_CODE_ENABLE_TELEMETRY", enable or _NOT_SET, _src(enable_src, env)),
        Fact("OTEL_LOGS_EXPORTER", exporter or _NOT_SET, _src(exporter_src, env)),
        Fact(
            "OTEL_EXPORTER_OTLP_PROTOCOL",
            (logs_proto or proto) or _NOT_SET,
            _src(logs_proto_src or proto_src, env),
        ),
        Fact(
            "OTLP endpoint (host)",
            _host_of(logs_endpoint or endpoint)
            if (logs_endpoint or endpoint)
            else _NOT_SET,
            _src(logs_endpoint_src or endpoint_src, env),
        ),
    ]
    for name in ("OTEL_LOG_USER_PROMPTS", "OTEL_LOG_TOOL_DETAILS"):
        value, value_src = _env_value(src, name, honoured)
        if value is not None:
            facts.append(Fact(name, value, _src(value_src, env)))
    facts.append(
        Fact(
            "read from",
            "managed and user settings only; the process environment and"
            " --settings are not readable here",
            MONITORING_DOC,
        )
    )
    if settings.decisive_skipped:
        return Question(
            "logging",
            Status.UNKNOWN,
            "a managed or user settings file could not be read, so telemetry"
            " settings are not known",
            facts,
        )
    if (
        repo_exporter is not None
        and repo_exporter.lower() == "none"
        and managed_exporter is None
    ):
        facts.append(
            Fact("OTEL_LOGS_EXPORTER (repository)", repo_exporter, _src(repo_src, env))
        )
        return Question(
            "logging",
            Status.FAIL,
            "a repository settings file sets OTEL_LOGS_EXPORTER to none and"
            " managed settings do not set it, so the logs/events signal is"
            " switched off",
            facts,
        )
    if enable is None or enable in ("", "0"):
        return Question(
            "logging",
            Status.FAIL,
            "telemetry is not enabled in managed or user settings"
            " (CLAUDE_CODE_ENABLE_TELEMETRY is not 1)",
            facts,
        )
    if enable != "1":
        return Question(
            "logging",
            Status.UNKNOWN,
            "CLAUDE_CODE_ENABLE_TELEMETRY has a value the monitoring doc does"
            " not define (it documents 1)",
            facts,
        )
    kinds = {k.strip().lower() for k in (exporter or "").split(",") if k.strip()}
    if "otlp" not in kinds:
        return Question(
            "logging",
            Status.FAIL,
            "telemetry is on but OTEL_LOGS_EXPORTER does not select otlp, so"
            " tool activity events are not sent anywhere durable",
            facts,
        )
    if not (logs_proto or proto):
        return Question(
            "logging",
            Status.FAIL,
            "OTEL_LOGS_EXPORTER is otlp but no OTLP protocol is set; Claude Code"
            " has no default protocol, so the exporter cannot send",
            facts,
        )
    if not (logs_endpoint or endpoint):
        return Question(
            "logging",
            Status.UNKNOWN,
            "the logs exporter is otlp with a protocol but no endpoint is set;"
            " Claude Code documents no default endpoint, so where it goes is"
            " not known",
            facts,
        )
    return Question(
        "logging",
        Status.PASS,
        "telemetry is on and the logs/events exporter is otlp with a protocol"
        " and endpoint set; tool decisions and results are exported",
        facts,
    )


# ── Assembly ──────────────────────────────────────────────────────────────────


def assess(
    *,
    env: Env,
    findings: list[Finding],
    net: NetworkView,
    scan_errors: list[str],
) -> Assessment:
    """Answer the five questions for Claude Code and collect verdict reasons."""
    settings = load_settings(env)
    facts = run_facts(settings, env, findings)
    reasons: list[Reason] = []
    col = collect(settings, env)

    # 1. Where it runs.
    where_facts = facts.sandbox_facts + facts.approval_facts
    if not facts.sandbox_known:
        sandbox_status = Status.UNKNOWN
        where_text = (
            "a settings file could not be read ("
            + ", ".join(settings.decisive_skipped)
            + "), so the sandbox state is not known (a file in any scope can"
            " switch the sandbox off or ask for bypass mode)"
        )
        reasons.append(Reason("unknown", where_text, []))
    elif facts.deps_unknown:
        sandbox_status = Status.UNKNOWN
        where_text = (
            "sandbox.enabled is true, but on Linux and WSL2 Claude Code runs"
            " commands unsandboxed when bubblewrap or socat is missing unless"
            " sandbox.failIfUnavailable is true, and neither is established"
        )
        reasons.append(
            Reason("unknown", where_text, [_ref_for(settings, env, "sandbox.enabled")])
        )
    elif facts.sandbox_on:
        sandbox_status = Status.PASS
        where_text = "the sandbox is on"
    else:
        sandbox_status = Status.FAIL
        where_text = "the sandbox is off (Claude Code's default)"
        reasons.append(
            Reason(
                "needs_work",
                "sandbox is not on: set sandbox.enabled to true in user or"
                " managed settings",
                [_ref_for(settings, env, "sandbox.enabled")],
            )
        )
    where_status = sandbox_status
    if facts.bypass_active:
        where_status = Status.FAIL
        where_text += "; bypassPermissions is the default mode (prompts skipped)"
        reasons.append(
            Reason(
                "not_safe",
                "bypassPermissions is the default mode and is not disabled:"
                " tool calls run without approval",
                facts.refs_bypass,
            )
        )
    elif facts.bypass_requested_by_repo:
        where_status = Status.FAIL
        where_text += (
            "; a repository settings file asks for bypassPermissions (ignored by"
            " Claude Code 2.1.257 and later; the installed version is not read)"
        )
        reasons.append(
            Reason(
                "needs_work",
                "a repository settings file sets bypassPermissions; Claude Code"
                " 2.1.257+ ignores it, older releases honour it",
                facts.refs_repo_bypass,
            )
        )
    if not facts.bypass_disabled:
        where_facts.append(
            Fact(
                "bypass mode",
                "can still be chosen for a session (not disabled)",
                None,
            )
        )
    if col.env_unsafe and where_status is Status.PASS:
        names = ", ".join(n for n, _r in col.env_unsafe[:5])
        where_status = Status.UNKNOWN
        where_text += (
            f"; settings env name(s) reach does not know ({names}) may change"
            " how commands are launched"
        )
        reasons.append(
            Reason(
                "unknown",
                f"settings env name(s) not on reach's lists: {names}",
                [r for _n, r in col.env_unsafe[:5]],
            )
        )
    if col.wsl_inherits and _on_wsl() and where_status is Status.PASS:
        where_status = Status.UNKNOWN
        where_text += "; WSL reads another policy chain (wslInheritsWindowsSettings)"
        reasons.append(
            Reason(
                "unknown", "WSL inherits the Windows policy chain, not read here", []
            )
        )
    where_q = Question(
        "where_it_runs",
        where_status,
        where_text,
        where_facts,
        facts.refs_bypass or facts.refs_repo_bypass,
    )

    # 2. Credentials.
    ran = env.config_dir.is_dir()
    secrets = env_secrets(settings, env)
    egress = egress_commands(col, findings, env)
    opaque = opaque_commands(col)
    store_hits = store_commands(col)
    if col.code_loading:
        # A settings env name may load code into any server: none is declared.
        net.unclassified += net.quiet
        net.quiet = []
    mcp_open = _mcp_allowed_unbounded(settings, facts, net)
    cred_q, creds_readable = credential_question(
        findings,
        env,
        ran,
        scan_errors,
        unsandboxed_bash=facts.unsandboxed_bash,
        env_secrets=secrets,
        outside=[*egress, *opaque],
        store_hits=store_hits,
        mcp_open=mcp_open,
    )
    if cred_q.status is Status.UNKNOWN:
        reasons.append(Reason("unknown", cred_q.summary, []))
    elif cred_q.status is Status.FAIL:
        why = []
        readable = ", ".join(f.value for f in cred_q.facts if f.key == "readable")
        if readable:
            why.append(
                "credential store(s) readable without a prompt (REACH-001): "
                + readable[:300]
            )
        if store_hits:
            why.append(
                "a hook, apiKeyHelper or statusLine command names a credential"
                " store path and runs outside the sandbox: "
                + ", ".join(
                    f"{f.key.split(' names')[0]} ({f.source})" for f in store_hits[:5]
                )
            )
        if facts.unsandboxed_bash:
            why.append(
                "Bash can run outside the sandbox, so deny rules do not hold for it"
            )
        if secrets:
            why.append(
                "secret-shaped variables in settings env, inherited by every"
                " command and local MCP server: "
                + ", ".join(f.value for f in secrets[:8])
            )
        reasons.append(
            Reason(
                "needs_work",
                "; ".join(why),
                ["REACH-001"] + [f.source for f in secrets[:5] if f.source],
            )
        )

    # 3. Network.
    state, state_text, net_facts = sandbox_network(settings, env, facts)
    net_facts += [
        Fact("network-capable server", v.describe(), v.ref) for v in net.reaching
    ]
    net_facts += [
        Fact("server with no declared capabilities", v.name, v.ref)
        for v in net.unclassified
    ]
    net_facts += [
        Fact(
            "settings env name not on the benign list (no server counts as declared)",
            n,
            r,
        )
        for n, r in col.env_unsafe[:5]
    ]
    net_facts += col.dest_facts
    unknown_routes = list(opaque) + list(col.dest_unknown)
    unknown_why: list[str] = []
    connectors = connectors_possible(settings, env)
    if connectors:
        unknown_why.append(connectors)
    if col.env_unsafe:
        names = ", ".join(n for n, _r in col.env_unsafe[:5])
        unknown_why.append(
            f"settings env name(s) reach does not know ({names}) may change"
            " where traffic goes"
        )
    chrome, chrome_why = chrome_default(env)
    if chrome is None:
        unknown_why.append(f"Claude in Chrome default not readable: {chrome_why}")
    elif chrome:
        unknown_why.append(
            "claudeInChromeDefaultEnabled is true in ~/.claude.json: the browser"
            " extension can act on the network outside the sandbox"
        )
    else:
        net_facts.append(
            Fact(
                "Claude in Chrome",
                "can be enabled per session (not on by default)",
                None,
            )
        )
    net_q, net_reasons = network_status(
        net,
        state,
        state_text,
        net_facts,
        egress + list(col.dest_routes),
        unknown_routes=unknown_routes,
        unknown_why=unknown_why,
    )
    reasons.extend(net_reasons)
    if creds_readable and (net.reaching or egress):
        routes = [v.describe() for v in net.reaching[:5]]
        routes += [f"{f.key} ({f.value})" for f in egress[:5]]
        reasons.insert(
            0,
            Reason(
                "not_safe",
                "a readable credential store plus a "
                + (
                    "network-capable server: "
                    if net.reaching
                    else "command that reaches the network: "
                )
                + ", ".join(routes),
                ["REACH-001"]
                + [v.ref for v in net.reaching[:5]]
                + [f.source for f in egress[:5] if f.source],
            ),
        )

    # 4. Policy.
    policy_q = policy_question(managed_policy_source(env), env)
    if col.wsl_inherits and policy_q.status is Status.PASS:
        policy_q = Question(
            "policy",
            Status.UNKNOWN,
            "wslInheritsWindowsSettings is set: on WSL the Windows policy chain"
            " also applies and is not read here; " + policy_q.summary,
            policy_q.facts,
        )
        reasons.append(Reason("unknown", "policy: " + policy_q.summary, []))

    # 5. Logging.
    log_q = logging_question(settings, env)
    if log_q.status is Status.FAIL:
        reasons.append(
            Reason("needs_work", "activity is not logged: " + log_q.summary, [])
        )
    elif log_q.status is Status.UNKNOWN:
        reasons.append(Reason("unknown", "logging: " + log_q.summary, []))

    return Assessment([where_q, cred_q, net_q, policy_q, log_q], reasons)


def _on_wsl() -> bool:
    """Is this host WSL (read from /proc, no subprocess)?"""
    from mcp_audit.host_platform import detect_host_platform

    return detect_host_platform() == "wsl"


def chrome_default(env: Env) -> tuple[bool | None, str]:
    """``claudeInChromeDefaultEnabled`` from ``~/.claude.json``.

    Returns ``(True, "")`` when Chrome is on by default, ``(False, "")`` when it
    is off or absent, and ``(None, reason)`` when the file cannot be read.
    """
    path = env.home / ".claude.json"
    raw, why = read_capped(path, _CLAUDE_JSON_CAP)
    if why is not None:
        return None, f"{env.mask(path)} {why}"
    if raw is None:
        return False, ""
    try:
        doc = json.loads(raw.decode("utf-8-sig", errors="replace"))
    except (ValueError, RecursionError):
        return None, f"{env.mask(path)} is not valid JSON"
    value = _d(doc).get("claudeInChromeDefaultEnabled")
    return (value is True or _truthy(value)), ""


def _ref_for(settings: Settings, env: Env, key: str) -> str:
    """``file:key`` for the file that sets *key* (the user file when none does)."""
    _value, source = resolve(settings.sources, _key(*key.split(".")))
    path = source.path if source is not None else env.config_dir / "settings.json"
    return f"{env.mask(path)}:{key}"


def detected_files(env: Env) -> list[str]:
    """Masked paths of the Claude Code files that exist (settings and config)."""
    paths = [p for _scope, p in _candidates(env)] + [env.home / ".claude.json"]
    out: list[str] = []
    for path in paths:
        try:
            if path.is_file():
                out.append(env.mask(path))
        except OSError:
            continue
    return out
