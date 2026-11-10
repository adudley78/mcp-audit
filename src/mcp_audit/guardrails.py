"""Guardrail drift: an agent's safety settings got weaker since the last scan.

mcp-audit tracks MCP servers (``pin``, ``baseline``, ``lock``) and instruction
files (INSTR-001/002) over time, but an agent's permission, sandbox, hook and
approval settings were only checked at a point in time.  An agent can write
its own settings (a prompt-injected agent that edits ``settings.json`` or
``config.toml`` is the incident shape of 2026), and a person can loosen them
by habit; either way the loosening is visible in the files alone.  STORY-0143,
Marcus queue Q-078.

What this module does (every scan with no explicit path, ``check`` and
``scan --project`` included, as pipeline step 5c2, right after instruction
drift):

* Reads the settings files of three agents, never executes anything:

  - Claude Code: ``~/.claude/settings.json`` (``$CLAUDE_CONFIG_DIR`` honoured),
    the working directory's ``.claude/settings.json`` and
    ``.claude/settings.local.json``.  Parsed with
    :func:`mcp_audit.analyzers.permissions.load_claude_settings`.
  - Codex: ``$CODEX_HOME/config.toml`` (default ``~/.codex/config.toml``,
    :func:`mcp_audit.discovery.codex_user_config_path`) and the project's
    ``.codex/config.toml``.
  - Gemini CLI: ``~/.gemini/settings.json`` and the project's
    ``.gemini/settings.json``.
  - Claude Code's managed settings files (``managed-settings.json``,
    ``managed-settings.d/*.json``, ``managed-mcp.json``): a SHA-256 each, no
    content.

* Keeps one normalised record per file (:func:`build_record`): *only*
  guardrail-relevant facts, sorted, never a secret.  Hook commands are stored
  as the SHA-256 of the command string plus the event and matcher; permission
  rules and other strings are masked with ``SECRET_PATTERNS`` and capped.
* Compares each record with the previous one for the same absolute path with
  :func:`compare`, which knows exactly the rows of :data:`LOOSENING_TABLE`.
  **A change that is not in the table is not a loosening.**

  - **GUARD-001** (MEDIUM, HIGH when a value is bypass-equivalent): the file
    loosened a guardrail.
  - **GUARD-002** (INFO): a managed settings file's bytes changed.

  A file seen for the first time is recorded silently.  A file that has
  disappeared is reported (GUARD-001) only when it held a deny rule or a hook
  that no other tracked file of the same agent still holds; otherwise silent.
  A scan never reports the same loosening twice: the record is updated after
  every scan.

Where the semantics come from.  Only keys quoted in this repository's own
analyzers (``analyzers/permissions.py``, ``analyzers/sandbox.py``,
``analyzers/config_hygiene.py``, ``docs/permission-rules.md``) or confirmed
against vendor documentation on 2026-11-04 are encoded; each row of
:data:`LOOSENING_TABLE` carries its citation.  What could not be confirmed is
left out and listed in GAPS.md.

* Claude Code: https://code.claude.com/docs/en/permissions,
  https://code.claude.com/docs/en/permission-modes,
  https://code.claude.com/docs/en/sandboxing,
  https://code.claude.com/docs/en/settings-reference
* Codex: https://learn.chatgpt.com/docs/config-file/config-reference (the page
  https://developers.openai.com/codex/config-reference redirects there) and
  https://learn.chatgpt.com/docs/sandboxing
* Gemini CLI:
  https://github.com/google-gemini/gemini-cli/blob/main/docs/reference/configuration.md

Safety: reads files only (bounded, through
:func:`mcp_audit.agent_files.drift.hash_file`: regular files, size-capped,
project symlinks refused); every filesystem or parse error becomes an entry in
``errors``, never an exception.  The record file (``<state dir>/guardrails.json``,
or beside an explicit rug-pull state path) follows the instruction-file rules
and shares their writer: 0o600, atomic temporary file + ``os.replace`` under a
lock after re-reading, an unreadable file is never overwritten, a non-record
file is kept as ``.corrupt``, the least recently seen records are dropped past
:data:`~mcp_audit.agent_files.drift.MAX_RECORDS`.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tomllib
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from platformdirs import user_config_dir

from mcp_audit.agent_files import drift as _drift
from mcp_audit.agent_files.discovery import _is_symlink
from mcp_audit.agent_files.imports import READ_CAP_BYTES
from mcp_audit.analyzers.credentials import SECRET_PATTERNS
from mcp_audit.analyzers.permissions import load_claude_settings
from mcp_audit.analyzers.rule_secrets import redact_rule
from mcp_audit.analyzers.supply_chain import redact_command_text
from mcp_audit.models import Finding, Severity

#: Where the per-file records live when the caller gives no rug-pull state path.
DEFAULT_STATE_PATH: Path = (
    Path(user_config_dir("mcp-audit")) / "state" / "guardrails.json"
)

#: Analyzer label on GUARD-* findings.
ANALYZER_NAME = "guardrails"
_LABEL = "guardrail drift"

CLAUDE = "claude-code"
CODEX = "codex"
GEMINI = "gemini-cli"
MANAGED = "claude-code-managed"

#: Largest settings file parsed (the instruction-file reader's read cap).
MAX_PARSE_BYTES: int = READ_CAP_BYTES
#: Entries kept per list, and characters kept per entry.  Past either, the
#: tail is dropped and the scan says so.
MAX_ENTRIES: int = 2000
MAX_ENTRY_CHARS: int = 512
#: Files per managed directory read.
MAX_MANAGED_FILES: int = 256
#: Entries quoted in one finding line before "(+N more)".
_QUOTE_ENTRIES = 5
_LINE_CHARS = 160


def _home() -> Path:
    """The home directory (patched in tests)."""
    return Path.home()


# ── Loosening table ───────────────────────────────────────────────────────────

#: Row kinds (what moving a fact in a given direction means).
ADDED = "added"  # a list gained an entry
REMOVED = "removed"  # a list lost an entry
GAINED = "gained"  # a scalar went from unset to set
ON = "on"  # a flag that is off by default turned on
OFF = "off"  # a flag that guards (default off) turned off / was removed
UNLOCKED = "unlocked"  # a flag whose explicit ``false`` is the guard was lifted
LOCKED_OFF = "locked_off"  # a default-on flag turned explicitly off
VALUE_REMOVED = "value_removed"  # a guarding string value was removed
RANKED = "ranked"  # an enum moved toward the permissive end
HOOKS = "hooks"  # a hook was removed or its command changed


@dataclass(frozen=True)
class Row:
    """One row of :data:`LOOSENING_TABLE`.

    Attributes:
        agent: ``claude-code``, ``codex`` or ``gemini-cli``.
        key: The fact name in the record (dotted, as in the settings file).
        kind: One of the kind constants above.
        cite: The documentation behind the row (URL and, where the repo
            already quotes it or it was read on 2026-11-04, the sentence).
        high: A change on this row is bypass-equivalent (GUARD-001 HIGH).
        order: For ``ranked``: values from most to least restrictive.
        absent_as: For ``ranked``: what an unset key means (``None``: unknown).
        top: For ``ranked``: the bypass-equivalent value (HIGH when moved to).
        aliases: For ``ranked``: spellings that mean another value.
    """

    agent: str
    key: str
    kind: str
    cite: str
    high: bool = False
    order: tuple[str, ...] = ()
    absent_as: str | None = None
    top: str | None = None
    aliases: tuple[tuple[str, str], ...] = ()


_PERM = "https://code.claude.com/docs/en/permissions"
_MODES = "https://code.claude.com/docs/en/permission-modes"
_SBX = "https://code.claude.com/docs/en/sandboxing"
_SETTINGS = "https://code.claude.com/docs/en/settings-reference"
_CODEX_CFG = "https://learn.chatgpt.com/docs/config-file/config-reference"
_CODEX_SBX = "https://learn.chatgpt.com/docs/sandboxing"
_GEMINI_CFG = (
    "https://github.com/google-gemini/gemini-cli/blob/main/docs/reference/"
    "configuration.md"
)
_SANDBOX_WEAKENS = (
    f"{_SETTINGS} (sandbox.*; analyzers/sandbox.py, docs/permission-rules.md:"
    ' "Each one weakens the sandbox")'
)

LOOSENING_TABLE: tuple[Row, ...] = (
    # ── Claude Code: permissions ─────────────────────────────────────────────
    Row(
        CLAUDE,
        "permissions.allow",
        ADDED,
        f'{_PERM}: "Rules are evaluated in order: deny, then ask, then allow."'
        " A new allow rule approves calls that would have prompted.",
    ),
    Row(
        CLAUDE,
        "permissions.deny",
        REMOVED,
        f'{_PERM}: "Rules are evaluated in order: deny, then ask, then allow.'
        ' The first match in that order determines the outcome." A lost deny'
        " rule lifts the first block.",
        high=True,
    ),
    Row(
        CLAUDE,
        "permissions.ask",
        REMOVED,
        f"{_PERM} (same evaluation order); {_MODES}: tools matched by an"
        " explicit ask rule are among the actions no mode auto-approves"
        " (docs/permission-rules.md).",
    ),
    Row(
        CLAUDE,
        "permissions.additionalDirectories",
        ADDED,
        f'{_SETTINGS}: "Give Claude file access to directories outside the'
        f' current one"; {_PERM}: acceptEdits accepts edits "for paths in the'
        ' working directory or additionalDirectories".',
    ),
    Row(
        CLAUDE,
        "permissions.defaultMode",
        RANKED,
        f'{_MODES}, what runs without asking: default "Reads only"; acceptEdits'
        ' "Reads, file edits, and common filesystem commands"; auto "Everything,'
        ' with background safety checks"; bypassPermissions "Everything".'
        " The page does not rank the modes; this order is that table's. plan"
        " is placed lowest (exploration; it edits nothing) and dontAsk is not"
        " ranked: a change to or from it is not judged (GAPS.md).",
        high=False,
        order=("plan", "default", "acceptEdits", "auto", "bypassPermissions"),
        absent_as="default",
        top="bypassPermissions",
        aliases=(("manual", "default"),),
    ),
    Row(
        CLAUDE,
        "permissions.disableBypassPermissionsMode",
        VALUE_REMOVED,
        f'{_SETTINGS}: "Prevent anyone from entering bypassPermissions mode";'
        f' {_MODES}: set to "disable".',
    ),
    # ── Claude Code: sandbox ─────────────────────────────────────────────────
    Row(
        CLAUDE,
        "sandbox.enabled",
        OFF,
        f'{_SBX}: "The sandbox is off by default. To turn it on, run /sandbox'
        ' ... or set sandbox.enabled to true".',
        high=True,
    ),
    Row(
        CLAUDE,
        "sandbox.failIfUnavailable",
        OFF,
        f"{_SBX}: \"if the sandbox can't start ... Claude Code runs commands"
        " without sandboxing. To make Claude Code exit at startup instead, set"
        ' sandbox.failIfUnavailable to true."',
    ),
    Row(
        CLAUDE,
        "sandbox.enableWeakerNestedSandbox",
        ON,
        _SANDBOX_WEAKENS,
    ),
    Row(
        CLAUDE,
        "sandbox.enableWeakerNetworkIsolation",
        ON,
        _SANDBOX_WEAKENS,
    ),
    Row(
        CLAUDE,
        "sandbox.network.allowAllUnixSockets",
        ON,
        _SANDBOX_WEAKENS,
    ),
    Row(
        CLAUDE,
        "sandbox.network.allowLocalBinding",
        ON,
        _SANDBOX_WEAKENS,
    ),
    Row(
        CLAUDE,
        "sandbox.autoAllowBashIfSandboxed",
        UNLOCKED,
        f'{_SBX}: "autoAllowBashIfSandboxed still defaults to true, so sandboxed'
        " commands keep running without prompts. Set it to false to prompt for"
        ' sandboxed commands." An explicit false lifted is a loosening.',
    ),
    Row(
        CLAUDE,
        "sandbox.allowUnsandboxedCommands",
        UNLOCKED,
        f'{_SBX}: setting it to false means "Claude Code ignores the'
        ' dangerouslyDisableSandbox parameter"; an explicit false lifted lets'
        " Claude retry a blocked command outside the sandbox.",
    ),
    Row(
        CLAUDE,
        "sandbox.network.allowedDomains",
        ADDED,
        f'{_SBX}: "Your allowed domains start empty."; {_SETTINGS}:'
        ' "Pre-allow domains so sandboxed commands don\'t prompt for them".',
    ),
    Row(
        CLAUDE,
        "sandbox.network.deniedDomains",
        REMOVED,
        f'{_SBX}: "A connection to a host in deniedDomains is refused in every'
        ' permission mode too."',
    ),
    Row(
        CLAUDE,
        "sandbox.network.allowUnixSockets",
        ADDED,
        f'{_SETTINGS}: "List Unix socket paths sandboxed commands can use on'
        ' macOS"; analyzers/sandbox.py quotes that allowing a Docker socket'
        ' "effectively grants access to the host system".',
    ),
    Row(
        CLAUDE,
        "sandbox.network.httpProxyPort",
        GAINED,
        f'{_SBX}: "Once either port applies, your proxy is responsible for'
        ' filtering everything sent to it."',
    ),
    Row(
        CLAUDE,
        "sandbox.network.socksProxyPort",
        GAINED,
        f'{_SBX}: "Once either port applies, your proxy is responsible for'
        ' filtering everything sent to it."',
    ),
    Row(
        CLAUDE,
        "sandbox.excludedCommands",
        ADDED,
        f'{_SBX}: "List a command pattern in sandbox.excludedCommands to run'
        " matching commands outside the sandbox, which means no filesystem"
        ' restrictions and no network proxy."',
    ),
    Row(
        CLAUDE,
        "sandbox.filesystem.allowWrite",
        ADDED,
        f'{_SBX}: "use sandbox.filesystem.allowWrite to grant access to'
        ' specific paths" outside the working directory.',
    ),
    Row(
        CLAUDE,
        "sandbox.filesystem.allowRead",
        ADDED,
        f'{_SBX}: allowRead "re-allows paths inside a denied region"'
        f' (denyRead); {_SETTINGS}: "Re-open reading inside a region denyRead'
        ' blocks".',
    ),
    Row(
        CLAUDE,
        "sandbox.filesystem.denyRead",
        REMOVED,
        f'{_SBX}: denyRead blocks reads ("read access to the entire computer,'
        ' except certain denied directories"); a lost entry re-opens the path.',
        high=True,
    ),
    Row(
        CLAUDE,
        "sandbox.filesystem.denyWrite",
        REMOVED,
        f'{_SETTINGS}: "Block sandboxed commands from writing to specific'
        ' paths"; a lost entry re-opens the path.',
    ),
    # ── Claude Code: hooks and MCP approval ──────────────────────────────────
    Row(
        CLAUDE,
        "hooks",
        HOOKS,
        f'{_PERM}: "A blocking hook also takes precedence over allow rules. A'
        " hook that exits with code 2 stops the tool call before permission"
        ' rules are evaluated"; a removed or replaced hook removes that stop'
        " until a person re-accepts it.",
    ),
    Row(
        CLAUDE,
        "disableAllHooks",
        ON,
        f'{_SETTINGS}: disableAllHooks "Turn off hooks, a custom status line,'
        ' and a custom @ file suggestion command at once" (scope: any file);'
        " every hook, including a blocking one that takes precedence over allow"
        f" rules ({_PERM}), stops running.",
        high=True,
    ),
    Row(
        CLAUDE,
        "enableAllProjectMcpServers",
        ON,
        f'{_SETTINGS}: "Approve every server in project .mcp.json files'
        ' without a prompt" (HARNESS-002).',
    ),
    Row(
        CLAUDE,
        "enabledMcpjsonServers",
        ADDED,
        f'{_SETTINGS}: "Approve specific servers from a project\'s .mcp.json"'
        " (HARNESS-007).",
    ),
    Row(
        CLAUDE,
        "disabledMcpjsonServers",
        REMOVED,
        f'{_SETTINGS}: "Reject specific servers from a project\'s .mcp.json".',
    ),
    # ── Codex ────────────────────────────────────────────────────────────────
    Row(
        CODEX,
        "approval_policy",
        RANKED,
        f'{_CODEX_CFG}: approval_policy "Controls when Codex pauses for approval'
        ' before executing commands"; never "The agent doesn\'t stop for approval'
        f' prompts" ({_CODEX_SBX}). The pages do not rank the values (on-failure'
        ' is "deprecated", untrusted "unsupported"); the order'
        " untrusted < on-request < on-failure < never is the story's"
        " (GAPS.md). A granular policy is not ranked.",
        order=("untrusted", "on-request", "on-failure", "never"),
        top="never",
    ),
    Row(
        CODEX,
        "sandbox_mode",
        RANKED,
        f'{_CODEX_CFG}: "read-only | workspace-write | danger-full-access";'
        f' {_CODEX_SBX}: danger-full-access "The agent runs without sandbox'
        ' restrictions"; read-only "can inspect files, but it can\'t edit files'
        ' or run commands without approval".',
        order=("read-only", "workspace-write", "danger-full-access"),
        top="danger-full-access",
    ),
    Row(
        CODEX,
        "sandbox_workspace_write.network_access",
        ON,
        f'{_CODEX_CFG}: "Allow outbound network access inside the'
        ' workspace-write sandbox."',
    ),
    Row(
        CODEX,
        "sandbox_workspace_write.writable_roots",
        ADDED,
        f'{_CODEX_CFG}: "Additional writable roots when sandbox_mode ='
        ' "workspace-write".',
    ),
    Row(
        CODEX,
        "hooks",
        HOOKS,
        f'{_CODEX_CFG}: "hooks (table): Lifecycle hooks configured inline in'
        ' config.toml"; a removed or replaced hook is a loosening until a'
        " person re-accepts it.",
    ),
    # ── Gemini CLI ───────────────────────────────────────────────────────────
    Row(
        GEMINI,
        "tools.allowed",
        ADDED,
        f'{_GEMINI_CFG}: tools.allowed "Tool names that skip the confirmation dialog".',
    ),
    Row(
        GEMINI,
        "tools.exclude",
        REMOVED,
        f'{_GEMINI_CFG}: tools.exclude "Tool names excluded from discovery."',
    ),
    Row(
        GEMINI,
        "tools.sandbox",
        OFF,
        f'{_GEMINI_CFG}: tools.sandbox "Legacy full-process sandbox. Accepts a'
        " boolean, a path to a sandbox profile, or a sandbox command such as"
        ' docker, podman, lxc, or windows-native."',
        high=True,
    ),
    Row(
        GEMINI,
        "security.toolSandboxing",
        OFF,
        f'{_GEMINI_CFG}: security.toolSandboxing "Isolates individual tools'
        ' rather than the whole CLI process."',
        high=True,
    ),
    Row(
        GEMINI,
        "general.defaultApprovalMode",
        RANKED,
        f'{_GEMINI_CFG}: general.defaultApprovalMode "default": prompts for'
        ' approval; "auto_edit": auto-approves edit tools; "plan": read-only'
        ' mode. "YOLO ... can only be enabled from the command line", so no'
        " settings value is YOLO-equivalent and none is HIGH (GAPS.md).",
        order=("plan", "default", "auto_edit"),
        absent_as="default",
    ),
    Row(
        GEMINI,
        "security.disableYoloMode",
        OFF,
        f'{_GEMINI_CFG}: security.disableYoloMode "Disables YOLO mode even when'
        ' a flag enables it."',
    ),
    Row(
        GEMINI,
        "security.disableAlwaysAllow",
        OFF,
        f'{_GEMINI_CFG}: security.disableAlwaysAllow "Removes \\"Always allow\\"'
        ' options from tool confirmation dialogs."',
    ),
    Row(
        GEMINI,
        "security.enablePermanentToolApproval",
        ON,
        f'{_GEMINI_CFG}: security.enablePermanentToolApproval "Shows an option'
        ' to allow a tool for all future sessions."',
    ),
    Row(
        GEMINI,
        "security.autoAddToPolicyByDefault",
        ON,
        f'{_GEMINI_CFG}: security.autoAddToPolicyByDefault "Makes the \\"all'
        ' future sessions\\" option the default for low-risk tools in trusted'
        ' workspaces."',
    ),
    Row(
        GEMINI,
        "security.folderTrust.enabled",
        LOCKED_OFF,
        f'{_GEMINI_CFG}: security.folderTrust.enabled (default true) "Tracks'
        ' whether folder trust is enabled."',
    ),
    Row(
        GEMINI,
        "hooksConfig.enabled",
        LOCKED_OFF,
        f'{_GEMINI_CFG}: hooksConfig.enabled "Canonical toggle for the hooks'
        ' system. When disabled, no hooks will be executed." (default true).',
    ),
    Row(
        GEMINI,
        "hooks",
        HOOKS,
        "analyzers/config_hygiene.py (TRUST-008): Gemini CLI fingerprints"
        " project hooks and warns before running a new or changed one; a"
        " removed or replaced hook is a loosening until a person re-accepts"
        " it.",
    ),
)

#: Rows by (agent, key).
_ROWS: dict[tuple[str, str], Row] = {(r.agent, r.key): r for r in LOOSENING_TABLE}


# ── Records ───────────────────────────────────────────────────────────────────


def _mask(text: str) -> str:
    """Replace every SECRET_PATTERNS match and URL user info with ``***``."""
    for _name, pattern, _provider in SECRET_PATTERNS:
        text = pattern.sub("***", text)
    text = re.sub(r"(?<=://)[^/@\s]+@", "***@", text)
    # user:secret@host written without a scheme (``domain:user:tok@host``)
    return re.sub(r"[^\s:/@()]+:[^\s/@()]+@(?=[A-Za-z0-9-]+\.[A-Za-z])", "***@", text)


def _redact(text: str) -> str:
    """Redact credentials in a settings string (STORY-0143 review B1).

    :func:`~mcp_audit.analyzers.supply_chain.redact_command_text` first (inline
    ``Bearer`` tokens, credential headers, ``curl -u user:pass``, ``password=``
    and ``TOKEN=`` pairs, ``?token=`` parameters, URL userinfo), then
    :func:`_mask`.  A pure function of the text, so the same value always
    gives the same string and redaction itself never looks like a change.
    """
    return _mask(redact_command_text(text))


#: Longest settings string redacted (and digested) in full.
_MAX_FULL_CHARS = 65536
_LABEL_RE = re.compile(r"[A-Za-z0-9_-]{16,}")


def _mask_labels(text: str) -> str:
    """Mask long mixed letter/digit runs in a host name (a token used as a label)."""

    def _one(match: re.Match[str]) -> str:
        word = match.group(0)
        digits = sum(c.isdigit() for c in word)
        has_case = word != word.lower() and word != word.upper()
        if digits and (has_case or digits >= 3) and any(c.isalpha() for c in word):
            return "***"
        return word

    return _LABEL_RE.sub(_one, text)


def _text(value: object) -> str | None:
    """A redacted, length-capped string for a settings value, or ``None``."""
    if not isinstance(value, str):
        return None
    return _redact(value.strip()[: MAX_ENTRY_CHARS * 8])[:MAX_ENTRY_CHARS]


def _set_digest(full: Iterable[str]) -> str:
    """SHA-256 of a whole set of (redacted, untruncated) strings."""
    body = json.dumps(sorted(set(full)), ensure_ascii=True).encode("ascii")
    return hashlib.sha256(body).hexdigest()


def _strings(
    value: object,
    notes: list[str],
    key: str,
    digests: dict[str, str],
    *,
    domains: bool = False,
) -> list[str]:
    """Sorted, unique, redacted strings from a list value (non-strings dropped).

    Entries are cut at :data:`MAX_ENTRY_CHARS` and the list at
    :data:`MAX_ENTRIES`.  When either cut hides anything, ``digests[key]`` gets
    the SHA-256 of the whole untruncated set, so a change past the cut is still
    noticed (review N3).
    """
    if not isinstance(value, list):
        return []
    full: set[str] = set()
    shown: set[str] = set()
    truncated = False
    for item in value:
        if not isinstance(item, str):
            continue
        text = _redact(item.strip()[:_MAX_FULL_CHARS])
        if domains:
            text = _mask_labels(text)
        if not text:
            continue
        full.add(text)
        if len(text) > MAX_ENTRY_CHARS:
            truncated = True
            text = text[:MAX_ENTRY_CHARS]
        shown.add(text)
    ordered = sorted(shown)
    if len(ordered) > MAX_ENTRIES:
        notes.append(f"{key}: {len(ordered)} entries; only {MAX_ENTRIES} recorded")
        ordered = ordered[:MAX_ENTRIES]
        truncated = True
    if truncated:
        digests[key] = _set_digest(full)
    return ordered


def _dig(block: object, dotted: str) -> object:
    current = block
    for part in dotted.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _put(facts: dict, key: str, value: object) -> None:
    """Record *value* under *key* unless it is empty (empty equals absent)."""
    if value is None or value == [] or value == "":
        return
    facts[key] = value


def _hook_entries(hooks: object) -> list[list[str]]:
    """``[event, matcher, sha256]`` for every hook handler, sorted and unique.

    The shape is the one Claude Code, Gemini CLI and Codex share: event name ->
    matcher groups, each ``{"matcher": ..., "hooks": [handler, ...]}``.  A
    ``command`` handler is the SHA-256 of its command string; any other handler
    is the SHA-256 of its canonical JSON.  The command itself is never kept.
    """
    out: set[tuple[str, str, str]] = set()
    if not isinstance(hooks, dict):
        return []
    for event, groups in hooks.items():
        if not isinstance(groups, list) or not isinstance(event, str):
            continue
        for group in groups:
            if not isinstance(group, dict):
                continue
            matcher = _text(group.get("matcher")) or ""
            handlers = group.get("hooks")
            if not isinstance(handlers, list):
                continue
            for handler in handlers:
                if not isinstance(handler, dict):
                    continue
                command = handler.get("command")
                if handler.get("type", "command") == "command" and isinstance(
                    command, str
                ):
                    payload = command
                else:
                    try:
                        payload = json.dumps(handler, sort_keys=True, default=str)
                    except (TypeError, ValueError, RecursionError):
                        payload = repr(sorted(handler))
                out.add(
                    (
                        (_text(event) or "")[:64],
                        matcher[:200],
                        hashlib.sha256(
                            payload.encode("utf-8", errors="surrogatepass")
                        ).hexdigest(),
                    )
                )
    return [list(item) for item in sorted(out)]


def _claude_facts(
    raw: dict, path: Path, notes: list[str], digests: dict[str, str]
) -> dict:
    facts: dict = {}
    settings = load_claude_settings(raw, path)
    if settings is None:
        return facts
    perms = settings.permissions
    for name in ("allow", "ask", "deny"):
        _put(
            facts,
            f"permissions.{name}",
            _strings(
                [r.text for r in settings.rules_in(name)],
                notes,
                f"permissions.{name}",
                digests,
            ),
        )
    _put(
        facts,
        "permissions.additionalDirectories",
        _strings(
            perms.get("additionalDirectories"),
            notes,
            "permissions.additionalDirectories",
            digests,
        ),
    )
    _put(facts, "permissions.defaultMode", _text(perms.get("defaultMode")))
    _put(
        facts,
        "permissions.disableBypassPermissionsMode",
        _text(perms.get("disableBypassPermissionsMode")),
    )
    sandbox = settings.sandbox
    for key in (
        "enabled",
        "failIfUnavailable",
        "enableWeakerNestedSandbox",
        "enableWeakerNetworkIsolation",
        "autoAllowBashIfSandboxed",
        "allowUnsandboxedCommands",
        "network.allowAllUnixSockets",
        "network.allowLocalBinding",
    ):
        value = _dig(sandbox, key)
        if isinstance(value, bool):
            facts[f"sandbox.{key}"] = value
    for key in ("network.httpProxyPort", "network.socksProxyPort"):
        value = _dig(sandbox, key)
        if isinstance(value, int) and not isinstance(value, bool):
            facts[f"sandbox.{key}"] = value
    for key in (
        "network.allowedDomains",
        "network.deniedDomains",
        "network.allowUnixSockets",
        "excludedCommands",
        "filesystem.allowWrite",
        "filesystem.allowRead",
        "filesystem.denyRead",
        "filesystem.denyWrite",
    ):
        _put(
            facts,
            f"sandbox.{key}",
            _strings(
                _dig(sandbox, key),
                notes,
                f"sandbox.{key}",
                digests,
                domains=key.endswith("Domains"),
            ),
        )
    for key in ("enableAllProjectMcpServers", "disableAllHooks"):
        if isinstance(raw.get(key), bool):
            facts[key] = raw[key]
    for key in ("enabledMcpjsonServers", "disabledMcpjsonServers"):
        _put(facts, key, _strings(raw.get(key), notes, key, digests))
    return facts


def _codex_facts(data: dict, notes: list[str], digests: dict[str, str]) -> dict:
    facts: dict = {}
    policy = data.get("approval_policy")
    if isinstance(policy, dict):
        facts["approval_policy"] = "granular"
    else:
        _put(facts, "approval_policy", _text(policy))
    _put(facts, "sandbox_mode", _text(data.get("sandbox_mode")))
    network = _dig(data, "sandbox_workspace_write.network_access")
    if isinstance(network, bool):
        facts["sandbox_workspace_write.network_access"] = network
    _put(
        facts,
        "sandbox_workspace_write.writable_roots",
        _strings(
            _dig(data, "sandbox_workspace_write.writable_roots"),
            notes,
            "sandbox_workspace_write.writable_roots",
            digests,
        ),
    )
    return facts


def _gemini_facts(data: dict, notes: list[str], digests: dict[str, str]) -> dict:
    facts: dict = {}
    _put(
        facts,
        "tools.allowed",
        _strings(_dig(data, "tools.allowed"), notes, "tools.allowed", digests),
    )
    _put(
        facts,
        "tools.exclude",
        _strings(_dig(data, "tools.exclude"), notes, "tools.exclude", digests),
    )
    sandbox = _dig(data, "tools.sandbox")
    if isinstance(sandbox, bool):
        facts["tools.sandbox"] = sandbox
    elif isinstance(sandbox, str):
        # A profile path or a command: only "on" is kept, never the text.
        facts["tools.sandbox"] = bool(sandbox.strip())
    for key in (
        "security.toolSandboxing",
        "security.disableYoloMode",
        "security.disableAlwaysAllow",
        "security.enablePermanentToolApproval",
        "security.autoAddToPolicyByDefault",
        "security.folderTrust.enabled",
        "hooksConfig.enabled",
    ):
        value = _dig(data, key)
        if isinstance(value, bool):
            facts[key] = value
    _put(
        facts,
        "general.defaultApprovalMode",
        _text(_dig(data, "general.defaultApprovalMode")),
    )
    return facts


def build_record(
    agent: str, parsed: dict, path: Path, notes: list[str] | None = None
) -> dict:
    """Return the normalised guardrail record of one parsed settings file.

    Args:
        agent: ``claude-code``, ``codex`` or ``gemini-cli``.
        parsed: The file's parsed JSON/TOML object.
        path: Where it was read (Claude Code scope decisions use it).
        notes: Receives "list truncated" notes.

    Returns:
        ``{"agent": ..., "facts": {...}, "hooks": [[event, matcher, sha256], ...]}``.
        Only guardrail-relevant facts; strings masked; hook commands hashed.
    """
    notes = notes if notes is not None else []
    digests: dict[str, str] = {}
    if agent == CLAUDE:
        facts = _claude_facts(parsed, path, notes, digests)
    elif agent == CODEX:
        facts = _codex_facts(parsed, notes, digests)
    else:
        facts = _gemini_facts(parsed, notes, digests)
    record: dict = {
        "agent": agent,
        "facts": facts,
        "hooks": _hook_entries(parsed.get("hooks")),
    }
    if digests:
        record["digests"] = dict(sorted(digests.items()))
    return record


def empty_record(agent: str) -> dict:
    """The record of a settings file that holds nothing."""
    return {"agent": agent, "facts": {}, "hooks": []}


_KNOWN_AGENTS = frozenset({CLAUDE, CODEX, GEMINI, MANAGED})


def valid_record(record: object, agent: str | None = None) -> bool:
    """Whether *record* has the shape :func:`build_record` writes.

    State files and lock files are data a person or a tool can edit; a record
    that is not of this shape (a list where ``facts`` should be an object, a
    hook that is not three strings) is never compared (review B4).
    """
    if not isinstance(record, dict):
        return False
    held = record.get("agent")
    if held not in _KNOWN_AGENTS or (agent is not None and held != agent):
        return False
    if not isinstance(record.get("facts"), dict):
        return False
    hooks = record.get("hooks")
    if not isinstance(hooks, list):
        return False
    for hook in hooks:
        if (
            not isinstance(hook, list)
            or len(hook) != 3
            or not all(isinstance(part, str) for part in hook)
        ):
            return False
    digests = record.get("digests")
    if digests is not None and not (
        isinstance(digests, dict)
        and all(isinstance(k, str) and isinstance(v, str) for k, v in digests.items())
    ):
        return False
    sha = record.get("sha256")
    return sha is None or isinstance(sha, str)


def _full_digest(record: dict, key: str) -> tuple[str | None, bool]:
    """``(digest of the whole set held under key, whether it was truncated)``."""
    held = (record.get("digests") or {}).get(key)
    if held is not None:
        return held, True
    value = (record.get("facts") or {}).get(key)
    if isinstance(value, list):
        return _set_digest(v for v in value if isinstance(v, str)), False
    return None, False


# ── Comparison ────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Loosening:
    """One loosened guardrail.

    Attributes:
        key: The fact name (a :data:`LOOSENING_TABLE` row key).
        line: Evidence text: old -> new, values masked and capped; hook
            commands never shown.
        high: The change is bypass-equivalent.
        lost: Deny entries or hooks (``("hooks", event, matcher, sha)``) that
            went missing; used for a vanished file's "only source" test.
    """

    key: str
    line: str
    high: bool = False
    lost: frozenset[tuple[str, ...]] = frozenset()


@dataclass
class Diff:
    """Result of :func:`compare`."""

    loosened: list[Loosening] = field(default_factory=list)
    #: Changes outside the table (an unrecognised mode value): reported beside
    #: a loosening, never a loosening themselves.
    unjudged: list[str] = field(default_factory=list)

    @property
    def high(self) -> bool:
        """True when any loosening is bypass-equivalent."""
        return any(item.high for item in self.loosened)


def _clip(text: str) -> str:
    return text if len(text) <= _LINE_CHARS else text[:_LINE_CHARS] + "…"


def _quote(items: Iterable[str]) -> str:
    ordered = sorted(items)
    # Display only: the stored (digested) strings keep their own redaction, so
    # a record written by an older version never reads as a change.
    shown = ", ".join(repr(_clip(redact_rule(i))) for i in ordered[:_QUOTE_ENTRIES])
    if len(ordered) > _QUOTE_ENTRIES:
        shown += f" (+{len(ordered) - _QUOTE_ENTRIES} more)"
    return shown


def _show(value: object) -> str:
    if value is None:
        return "(unset)"
    return _clip(str(value)) if not isinstance(value, bool) else str(value).lower()


def _list(facts: dict, key: str) -> set[str]:
    value = facts.get(key)
    return (
        {v for v in value if isinstance(v, str)} if isinstance(value, list) else set()
    )


def _normalise(row: Row, value: object) -> str | None:
    if not isinstance(value, str) or not value:
        return row.absent_as
    return dict(row.aliases).get(value, value)


def _ranked(row: Row, old: object, new: object) -> tuple[bool | None, bool, str | None]:
    """``(loosened, high, unjudged_note)`` for a ranked enum row."""
    before, after = _normalise(row, old), _normalise(row, new)
    if before == after:
        return False, False, None
    rank_b = row.order.index(before) if before in row.order else None
    rank_a = row.order.index(after) if after in row.order else None
    if rank_b is not None and rank_a is not None:
        loosened = rank_a > rank_b
        return loosened, loosened and after == row.top, None
    if after is not None and after == row.top:
        # Anything (unset or unknown) -> the bypass-equivalent value.
        return True, True, None
    if after is None:
        # Set -> unset where the default is unknown: tightening or neutral.
        return False, False, None
    return False, False, f"{row.key} {_show(old)} -> {_show(new)} (not ranked)"


def compare(old: dict | None, new: dict | None, agent: str | None = None) -> Diff:
    """Compare two records; return exactly the loosenings of the table.

    ``None`` means "the file holds nothing" (:func:`empty_record`).  A tightening
    (a deny rule gained, a mode moved down, a hook added) and every change that
    is not a row of :data:`LOOSENING_TABLE` return nothing.

    Args:
        old: The previous record.
        new: The current record.
        agent: Which agent's rows to apply (defaults to the records' own).
    """
    agent = agent or (new or old or {}).get("agent") or CLAUDE
    old = old or empty_record(agent)
    new = new or empty_record(agent)
    if not valid_record(old) or not valid_record(new):
        raise ValueError("malformed guardrail record")
    old_facts: dict = old.get("facts") or {}
    new_facts: dict = new.get("facts") or {}
    diff = Diff()
    for row in LOOSENING_TABLE:
        if row.agent != agent:
            continue
        before, after = old_facts.get(row.key), new_facts.get(row.key)
        if row.kind == HOOKS:
            _compare_hooks(row, old, new, diff)
        elif row.kind in (ADDED, REMOVED):
            was, now = _list(old_facts, row.key), _list(new_facts, row.key)
            _before = len(diff.loosened)
            if row.kind == ADDED and now - was:
                diff.loosened.append(
                    Loosening(
                        row.key, f"{row.key} gained {_quote(now - was)}", row.high
                    )
                )
            elif row.kind == REMOVED and was - now:
                lost = frozenset((row.key, entry) for entry in was - now)
                diff.loosened.append(
                    Loosening(
                        row.key,
                        f"{row.key} lost {_quote(was - now)}",
                        row.high,
                        lost,
                    )
                )
            if len(diff.loosened) == _before:
                # Past the recorded limits (list length, entry length) the
                # visible part may not move while the whole does (review N3).
                was_d, was_cut = _full_digest(old, row.key)
                now_d, now_cut = _full_digest(new, row.key)
                if (was_cut or now_cut) and was_d != now_d:
                    diff.loosened.append(
                        Loosening(
                            row.key,
                            f"{row.key} changed beyond the {MAX_ENTRIES} entries /"
                            f" {MAX_ENTRY_CHARS} characters each that are shown"
                            " (direction not judged)",
                            False,
                        )
                    )
        elif row.kind == GAINED:
            if before is None and after is not None:
                diff.loosened.append(
                    Loosening(row.key, f"{row.key} (unset) -> {_show(after)}", row.high)
                )
        elif row.kind == ON:
            if after is True and before is not True:
                diff.loosened.append(
                    Loosening(row.key, f"{row.key} {_show(before)} -> true", row.high)
                )
        elif row.kind == OFF:
            if before is True and after is not True:
                diff.loosened.append(
                    Loosening(row.key, f"{row.key} true -> {_show(after)}", row.high)
                )
        elif row.kind == UNLOCKED:
            if before is False and after is not False:
                diff.loosened.append(
                    Loosening(row.key, f"{row.key} false -> {_show(after)}", row.high)
                )
        elif row.kind == LOCKED_OFF:
            if after is False and before is not False:
                diff.loosened.append(
                    Loosening(row.key, f"{row.key} {_show(before)} -> false", row.high)
                )
        elif row.kind == VALUE_REMOVED:
            if before == "disable" and after != "disable":
                diff.loosened.append(
                    Loosening(
                        row.key, f"{row.key} 'disable' -> {_show(after)}", row.high
                    )
                )
        elif row.kind == RANKED:
            loosened, high, note = _ranked(row, before, after)
            if loosened:
                diff.loosened.append(
                    Loosening(
                        row.key,
                        f"{row.key} {_show(before)} -> {_show(after)}",
                        high or row.high,
                    )
                )
            elif note:
                diff.unjudged.append(note)
    return diff


def _compare_hooks(row: Row, old: dict, new: dict, diff: Diff) -> None:
    """A hook removed, or its command hash changed, is a loosening."""
    was = {tuple(h) for h in old.get("hooks") or [] if isinstance(h, list)}
    now = {tuple(h) for h in new.get("hooks") or [] if isinstance(h, list)}
    gone = was - now
    if not gone:
        return
    for event in sorted({h[0] for h in gone}):
        removed = [h for h in gone if h[0] == event]
        still = [h for h in now if h[0] == event and h[1] in {r[1] for r in removed}]
        verb = "changed" if still else "removed"
        diff.loosened.append(
            Loosening(
                "hooks",
                f"hook for {event} {verb}"
                + (f" ({len(removed)} handlers)" if len(removed) > 1 else ""),
                row.high,
                frozenset(("hooks", *h) for h in removed),
            )
        )


# ── Files ─────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class GuardrailFile:
    """One settings file to track.

    Attributes:
        path: Absolute path as the agent reads it.
        agent: ``claude-code``, ``codex``, ``gemini-cli`` or
            ``claude-code-managed``.
        scope: ``"user"``, ``"project"`` or ``"managed"``.
        display: Short name for titles (``~/.claude/settings.json``,
            ``.codex/config.toml``).
    """

    path: Path
    agent: str
    scope: str
    display: str


def _claude_user_dir() -> Path:
    override = os.environ.get("CLAUDE_CONFIG_DIR", "").strip()
    if override:
        return Path(override).expanduser()
    return _home() / ".claude"


def _display(path: Path, home: Path, root: Path | None) -> str:
    if root is not None:
        try:
            return path.relative_to(root).as_posix()
        except ValueError:
            pass
    try:
        return "~/" + path.relative_to(home).as_posix()
    except ValueError:
        return path.name


def _is_project_file(path: Path) -> str | None:
    """The agent that owns *path* as a project settings file, else ``None``."""
    parent = path.parent.name
    if parent == ".claude" and path.name in ("settings.json", "settings.local.json"):
        return CLAUDE
    if parent == ".codex" and path.name == "config.toml":
        return CODEX
    if parent == ".gemini" and path.name == "settings.json":
        return GEMINI
    return None


def managed_files(errors: list[str]) -> list[GuardrailFile]:
    """The managed settings files that exist (hashed, never read for content)."""
    from mcp_audit.analyzers import managed_policy as _managed  # noqa: PLC0415
    from mcp_audit.plugins import mods as _mods  # noqa: PLC0415

    out: list[GuardrailFile] = []
    try:
        directory = _mods.managed_settings_dir()
        candidates = [directory / "managed-settings.json"]
        dropins = directory / "managed-settings.d"
        try:
            candidates += _managed.list_dropins(dropins)[:MAX_MANAGED_FILES]
        except OSError as exc:
            errors.append(f"{_LABEL}: cannot list {dropins.name}: {type(exc).__name__}")
        candidates.append(directory / "managed-mcp.json")
        for path in candidates:
            if os.path.lexists(path):
                out.append(
                    GuardrailFile(
                        Path(os.path.abspath(path)),
                        MANAGED,
                        "managed",
                        f"{directory.name}/{path.name}",
                    )
                )
    except Exception as exc:  # noqa: BLE001 — never fail a scan over this
        errors.append(f"{_LABEL}: listing managed files failed: {type(exc).__name__}")
    return out


def guardrail_files(cwd: Path, errors: list[str]) -> list[GuardrailFile]:
    """List the settings files a default scan tracks.

    The user's Claude Code, Codex and Gemini CLI files, the managed settings
    files that exist, then the working directory's own ``.claude/settings.json``,
    ``.claude/settings.local.json``, ``.codex/config.toml`` and
    ``.gemini/settings.json`` (none when *cwd* is the home directory).  Listed
    whether or not they exist, except managed files, so a deleted file can be
    noticed.  A project file that is a symlink or resolves outside *cwd* is
    skipped (TRUST-002 elsewhere).  A file reached twice is listed once.
    Never raises (a failure is reported in *errors* and what was listed so far
    is returned).
    """
    out: list[GuardrailFile] = []
    try:
        _list_default_files(cwd, errors, out)
    except Exception as exc:  # noqa: BLE001 — a scan must never fail over this
        errors.append(f"{_LABEL}: listing files failed: {type(exc).__name__}")
    return out


def _list_default_files(cwd: Path, errors: list[str], out: list[GuardrailFile]) -> None:
    from mcp_audit import discovery as _discovery  # noqa: PLC0415

    seen: set[str] = set()
    home = _home()

    def _add(path: Path, agent: str, scope: str, root: Path | None) -> None:
        resolved = _drift._safe_resolve(path)
        key = os.path.normcase(str(resolved if resolved is not None else path))
        if key in seen:
            return
        seen.add(key)
        out.append(
            GuardrailFile(
                Path(os.path.abspath(path)),
                agent,
                scope,
                _display(Path(os.path.abspath(path)), home, root),
            )
        )

    try:
        _add(_claude_user_dir() / "settings.json", CLAUDE, "user", None)
        _add(_discovery.codex_user_config_path(), CODEX, "user", None)
        _add(_discovery.gemini_user_config_path(), GEMINI, "user", None)
    except Exception as exc:  # noqa: BLE001
        errors.append(f"{_LABEL}: listing user files failed: {type(exc).__name__}")
    for item in managed_files(errors):
        _add(item.path, item.agent, item.scope, None)

    root = _drift._safe_resolve(cwd)
    home_resolved = _drift._safe_resolve(home)
    if root is None or (home_resolved is not None and root == home_resolved):
        return
    try:
        for rel in (
            ".claude/settings.json",
            ".claude/settings.local.json",
            ".codex/config.toml",
            ".gemini/settings.json",
        ):
            path = root / rel
            agent = _is_project_file(path)
            if agent is None:
                continue
            if _is_symlink(path) or _is_symlink(path.parent):
                continue  # TRUST-002 elsewhere; not the repository's own
            resolved = _drift._safe_resolve(path)
            if resolved is not None and not resolved.is_relative_to(root):
                continue
            _add(path, agent, "project", root)
    except Exception as exc:  # noqa: BLE001
        errors.append(f"{_LABEL}: listing project files failed: {type(exc).__name__}")


def project_guardrail_files(
    project_dir: Path, errors: list[str], state_path: Path | None = None
) -> list[GuardrailFile]:
    """The settings files of a project tree (``scan --project``, ``lock``).

    The files the project walk (:func:`mcp_audit.discovery.discover_project_configs`)
    already visits: every ``.claude/settings.json``, ``.claude/settings.local.json``,
    ``.codex/config.toml`` and ``.gemini/settings.json`` under *project_dir*.
    Symlinked files and the user's own Codex/Gemini files are not included.
    With *state_path*, project files under *project_dir* that the record holds
    as present but that the walk no longer finds are listed too, so a deleted
    nested file is noticed (review N4).  Never raises.
    """
    out: list[GuardrailFile] = []
    try:
        _list_project_files(project_dir, errors, state_path, out)
    except Exception as exc:  # noqa: BLE001
        errors.append(f"{_LABEL}: listing project files failed: {type(exc).__name__}")
    return out


def _list_project_files(
    project_dir: Path,
    errors: list[str],
    state_path: Path | None,
    out: list[GuardrailFile],
) -> None:
    from mcp_audit import discovery as _discovery  # noqa: PLC0415

    seen: set[str] = set()
    root = _drift._safe_resolve(project_dir)
    if root is None:
        return
    home = _home()
    try:
        configs = _discovery.discover_project_configs(root)
    except Exception as exc:  # noqa: BLE001
        errors.append(f"{_LABEL}: project walk failed: {type(exc).__name__}")
        return
    for config in configs:
        agent = _is_project_file(config.path)
        if agent is None or config.is_symlink:
            continue
        resolved = _drift._safe_resolve(config.path)
        if resolved is None or not resolved.is_relative_to(root):
            continue
        key = os.path.normcase(str(resolved))
        if key in seen:
            continue
        seen.add(key)
        path = Path(os.path.abspath(config.path))
        out.append(GuardrailFile(path, agent, "project", _display(path, home, root)))
    if state_path is None:
        return
    status, records = _drift._read_state(state_path)
    if status != _drift._OK:
        return
    listed = {os.path.normcase(str(item.path)) for item in out}
    for key, record in records.items():
        if record.get("absent") is True or record.get("scope") != "project":
            continue
        path = Path(key)
        agent = _is_project_file(path)
        if agent is None or agent != record.get("agent") or key in listed:
            continue
        if not path.is_absolute() or not path.is_relative_to(root):
            continue
        if os.path.lexists(path):
            continue  # present but not walked (a symlink): not "deleted"
        out.append(GuardrailFile(path, agent, "project", _display(path, home, root)))


# ── Reading ───────────────────────────────────────────────────────────────────


def _parse(item: GuardrailFile, data: bytes) -> dict | str:
    """Parse a settings file; return the object, or a reason it cannot be read."""
    text = data.decode("utf-8-sig", errors="replace")
    if item.agent == CODEX:
        try:
            parsed: object = tomllib.loads(text)
        except (tomllib.TOMLDecodeError, RecursionError, ValueError):
            return "not valid TOML"
    else:
        try:
            parsed = json.loads(text)
        except (json.JSONDecodeError, RecursionError, ValueError):
            from mcp_audit.analyzers.config_hygiene import parse_jsonc  # noqa: PLC0415

            parsed = parse_jsonc(text)
            if parsed is None:
                return "not valid JSON"
    if not isinstance(parsed, dict):
        return "not an object"
    return parsed


def read_record(item: GuardrailFile, notes: list[str]) -> dict | None | str:
    """Read one settings file into its record.

    Returns:
        The record; ``None`` when the file does not exist; or a string saying
        why it could not be read (never a partial record).  Never raises.
    """
    if not os.path.lexists(item.path):
        return None
    head = bytearray()
    hashed = _drift.hash_file(item.path, follow_symlink=item.scope == "user", head=head)
    if isinstance(hashed, str):
        return hashed
    digest, size = hashed
    if item.agent == MANAGED:
        return {"agent": MANAGED, "facts": {}, "hooks": [], "sha256": digest}
    if size > len(head):
        return f"over {MAX_PARSE_BYTES} bytes; not read"
    parsed = _parse(item, bytes(head))
    if isinstance(parsed, str):
        return parsed
    try:
        return build_record(item.agent, parsed, item.path, notes)
    except Exception as exc:  # noqa: BLE001 — a weird file never fails a scan
        return f"cannot read: {type(exc).__name__}"


# ── State ─────────────────────────────────────────────────────────────────────


def state_path_for(rug_pull_state: Path | None) -> Path:
    """Return the guardrail record path for a scan.

    With an explicit rug-pull state path (tests, callers that pass one) the
    record sits beside it; otherwise the shared :data:`DEFAULT_STATE_PATH`.
    """
    if rug_pull_state is None:
        return DEFAULT_STATE_PATH
    return rug_pull_state.with_name(f"{rug_pull_state.stem}.guardrails.json")


def guardrail_drift_findings(
    tracked: list[GuardrailFile], state_path: Path, errors: list[str]
) -> list[Finding]:
    """Compare *tracked* files with their records; update the records.

    Args:
        tracked: Files from :func:`guardrail_files` or
            :func:`project_guardrail_files`.
        state_path: The record file (see :func:`state_path_for`).
        errors: Receives filesystem, parse and state problems.

    Returns:
        GUARD-001 / GUARD-002 findings.  Never raises.
    """
    try:
        return _drift_findings(tracked, state_path, errors)
    except Exception as exc:  # noqa: BLE001 — a scan must never fail over this
        errors.append(f"{_LABEL} failed: {type(exc).__name__}")
        return []


def _prior(previous: object, item: GuardrailFile) -> dict | None:
    """The previous valid record of *item*; ``None`` for none or a malformed one."""
    if not isinstance(previous, dict):
        return None
    old = previous.get("record")
    return old if valid_record(old, item.agent) else None


def _entry(
    item: GuardrailFile, record: dict, *, absent: bool, previous: object, now: str
) -> dict:
    first = previous.get("first_seen") if isinstance(previous, dict) else None
    return {
        "agent": item.agent,
        "scope": item.scope,
        "record": record,
        "absent": absent,
        "first_seen": first if isinstance(first, str) else now,
        "last_seen": now,
    }


def _drift_findings(
    tracked: list[GuardrailFile], state_path: Path, errors: list[str]
) -> list[Finding]:
    status, records = _drift._load(state_path, errors, _LABEL)
    now = datetime.now(UTC).isoformat()
    notes: list[str] = []
    current: dict[str, tuple[GuardrailFile, dict]] = {}
    missing: list[GuardrailFile] = []
    for item in tracked:
        result = read_record(item, notes)
        if isinstance(result, str):
            errors.append(f"{_LABEL}: {item.display}: {result}")
        elif result is None:
            missing.append(item)
        else:
            current[os.path.normcase(str(item.path))] = (item, result)
    errors.extend(dict.fromkeys(f"{_LABEL}: {n}" for n in notes))

    out: list[Finding] = []
    updates: dict[str, dict] = {}
    for key, (item, record) in current.items():
        previous = records.get(key)
        old = _prior(previous, item)
        try:
            if old is not None:
                if item.agent == MANAGED:
                    if old.get("sha256") != record.get("sha256"):
                        out.append(_managed_finding(item, old, record))
                else:
                    diff = compare(old, record, item.agent)
                    if diff.loosened:
                        out.append(_loosened_finding(item, diff))
        except Exception as exc:  # noqa: BLE001 — one file never stops the rest
            errors.append(
                f"{_LABEL}: {item.display}: compare failed: {type(exc).__name__}"
            )
        updates[key] = _entry(item, record, absent=False, previous=previous, now=now)
    for item in missing:
        key = os.path.normcase(str(item.path))
        previous = records.get(key)
        old = _prior(previous, item)
        if old is None:
            # Never seen (or a malformed record): remember that it is absent,
            # so the file appearing later, already loose, is reported
            # (review B2).  The scan that records it reports nothing.
            if item.agent != MANAGED:
                updates[key] = _entry(
                    item,
                    empty_record(item.agent),
                    absent=True,
                    previous=previous,
                    now=now,
                )
            continue
        if previous.get("absent") is True:  # type: ignore[union-attr]
            continue
        if item.agent != MANAGED:
            try:
                diff = vanished_diff(
                    old, item.agent, _held_by(item.agent, current.values())
                )
                if diff.loosened:
                    out.append(_loosened_finding(item, diff, vanished=True))
                    # Reported once: a file put back with the same content is
                    # not reported again.
                    old = _without_lost(old, diff)
            except Exception as exc:  # noqa: BLE001
                errors.append(
                    f"{_LABEL}: {item.display}: compare failed: {type(exc).__name__}"
                )
        # A tombstone keeps the last record, so a weaker file put back later is
        # still compared with what was there.
        updates[key] = _entry(item, old, absent=True, previous=previous, now=now)
    if status != _drift._UNREADABLE and updates:
        # Never write after a failed read: these updates were computed
        # without the history and would overwrite it.
        _drift._commit(updates, state_path, errors, _LABEL)
    return out


def _without_lost(record: dict, diff: Diff) -> dict:
    """*record* without the deny entries and hooks *diff* reported as lost."""
    lost: set[tuple[str, ...]] = set()
    for loosening in diff.loosened:
        lost |= loosening.lost
    facts = {}
    for key, value in (record.get("facts") or {}).items():
        if isinstance(value, list):
            value = [v for v in value if (key, v) not in lost]
        facts[key] = value
    hooks = [h for h in record.get("hooks") or [] if ("hooks", *h) not in lost]
    return {**record, "facts": facts, "hooks": hooks}


def _held_by(
    agent: str, current: Iterable[tuple[GuardrailFile, dict]]
) -> set[tuple[str, ...]]:
    """List entries and hooks the *current* records of *agent* still hold."""
    held: set[tuple[str, ...]] = set()
    for other, record in current:
        if other.agent != agent:
            continue
        for key, value in (record.get("facts") or {}).items():
            if isinstance(value, list):
                held |= {(key, v) for v in value if isinstance(v, str)}
        held |= {("hooks", *h) for h in record.get("hooks") or []}
    return held


def vanished_diff(
    old: dict, agent: str, held: set[tuple[str, ...]] | frozenset = frozenset()
) -> Diff:
    """What a vanished file held that nothing in *held* still holds.

    Only deny entries and hooks count: a removed guardrail file is a
    loosening only when it was the one source of a deny rule or a hook.
    """
    kept: list[Loosening] = []
    for loosening in compare(old, None, agent).loosened:
        if loosening.key != "hooks" and not _is_deny_key(loosening.key):
            continue
        still_lost = loosening.lost - held
        if still_lost:
            kept.append(
                Loosening(loosening.key, loosening.line, loosening.high, still_lost)
            )
    return Diff(loosened=kept)


def _is_deny_key(key: str) -> bool:
    return key in {
        "permissions.deny",
        "sandbox.filesystem.denyRead",
        "sandbox.filesystem.denyWrite",
        "sandbox.network.deniedDomains",
    }


# ── Findings ──────────────────────────────────────────────────────────────────

_AGENT_LABEL = {
    CLAUDE: "Claude Code",
    CODEX: "Codex",
    GEMINI: "Gemini CLI",
    MANAGED: "Claude Code (managed settings)",
}
_OWASP = ["MCP02"]


def _loosened_finding(
    item: GuardrailFile, diff: Diff, *, vanished: bool = False
) -> Finding:
    high = diff.high
    lines = [loosening.line for loosening in diff.loosened]
    if diff.unjudged:
        lines += [f"also changed, not judged: {note}" for note in diff.unjudged]
    where = (
        "every session of this user"
        if item.scope == "user"
        else "sessions started in this folder"
    )
    cause = (
        f"{item.display} is gone, and it held guardrails that no other tracked"
        " file still holds"
        if vanished
        else f"{item.display} now allows more than it did at the last scan"
    )
    return Finding(
        id="GUARD-001",
        severity=Severity.HIGH if high else Severity.MEDIUM,
        analyzer=ANALYZER_NAME,
        client=item.agent,
        server=item.display,
        title=f"Agent guardrail loosened since the last scan: {item.display}",
        description=(
            f"{_AGENT_LABEL.get(item.agent, item.agent)} reads {item.display} for"
            f" {where}. {cause}: a permission rule, approval or sandbox setting,"
            " hook or MCP approval is weaker. That is often a deliberate edit;"
            " it is reported because an agent, a skill or a sync tool can write"
            " these files too, and an agent that loosens its own settings has"
            " removed the check that would catch the next injected instruction."
            " mcp-audit compares normalised settings only (hook commands as"
            " hashes) and cannot show the file's other changes."
            + (
                " At least one change is equivalent to turning the guardrail off."
                if high
                else ""
            )
        ),
        evidence=f"{item.display}: " + "; ".join(lines),
        remediation=(
            "If you did not make this change, revert it (for a repository,"
            " `git diff` shows it) and find what wrote it. If it was intended,"
            " nothing more is needed: the next scan records this state as the"
            " baseline."
        ),
        cwe="CWE-693",
        finding_path=str(item.path),
        owasp_mcp_top_10=list(_OWASP),
    )


def _managed_finding(item: GuardrailFile, old: dict, new: dict) -> Finding:
    return Finding(
        id="GUARD-002",
        severity=Severity.INFO,
        analyzer=ANALYZER_NAME,
        client=item.agent,
        server=item.display,
        title=f"Managed settings file changed since the last scan: {item.display}",
        description=(
            f"{item.display} is a managed settings file: an administrator's"
            " policy for Claude Code on this machine. Its bytes changed since"
            " the last scan. mcp-audit keeps only a hash, so it cannot show what"
            " changed or whether the policy got weaker."
        ),
        evidence=(
            f"sha256 {_drift._short(old.get('sha256'))}… ->"
            f" {_drift._short(new.get('sha256'))}…"
        ),
        remediation=(
            "If your administrator or MDM did not change this file, ask them;"
            " an agent session with write access to the managed directory"
            " should not exist."
        ),
        cwe="CWE-693",
        finding_path=str(item.path),
        owasp_mcp_top_10=["MCP02"],
    )
