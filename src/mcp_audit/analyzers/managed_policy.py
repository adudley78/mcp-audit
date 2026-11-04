"""Managed MCP policy report: Claude Code organisation policy vs configured servers.

An organisation controls which MCP servers Claude Code loads through files it
deploys to a system directory (STORY-0112):

* ``managed-mcp.json`` — a fixed server set with *exclusive control*: no user,
  project or plugin server loads beside it.
* ``managed-settings.json`` and ``managed-settings.d/*.json`` — the keys
  ``allowedMcpServers``, ``deniedMcpServers``, ``allowManagedMcpServersOnly``
  and ``managedMcpServers``.

This module reads those files and, since STORY-0144, the other places Claude
Code reads administrator policy from (macOS managed preferences, Windows
``HKLM``/``HKCU`` registry; never server-managed settings, which have no local
copy), ranks them the way Claude Code does and compares the source in force with
the Claude Code servers the scan found:

* MANAGED-001 (INFO) — inventory of the managed MCP policy on this machine.
* MANAGED-002 (INFO) — a configured server the policy keeps from loading
  (dead config: it disappears from ``/mcp`` with no message).
* MANAGED-003 (LOW) — managed settings are deployed but set no MCP policy.
* MANAGED-004 (MEDIUM/LOW) — the managed allowlist isn't locked and a
  repository or user settings file adds entries to it.
* MANAGED-005 (LOW) — the managed allowlist admits a transport by
  ``serverName`` alone, which Anthropic says "is not a security control".
* MANAGED-006 (MEDIUM) — policy found only in a place the user can write
  (``HKCU`` with no admin document, or a managed file or directory the current
  user can write): a default, not enforcement.
* MANAGED-007 (INFO) — an admin source (plist or ``HKLM`` value) that is not a
  JSON object; Claude Code refuses to start on it.

Every rule is taken from Anthropic's documentation:
https://code.claude.com/docs/en/managed-mcp (matching rules, evaluation order,
exclusive control, provided servers), https://code.claude.com/docs/en/managed-settings
(file locations, drop-in merge order, invalid entries, source ranking and
``managedSourcesBehavior``, registry and macOS locations) and
https://code.claude.com/docs/en/settings-reference (key scopes).

Read-only and offline: the files are read as JSON with a per-file size cap and
a per-scan budget; nothing is executed and no URL is fetched.  Commands and
URLs that reach a finding go through :func:`_redact` (URL userinfo and
SECRET_PATTERNS).  ``${VAR}`` references are not expanded: a policy entry or a
server value that uses one is treated as undecidable and never produces a
"blocked" claim.
"""

from __future__ import annotations

import json
import os
import re
import sys
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Literal

from mcp_audit.analyzers.supply_chain import (
    redact_args,
    redact_assignment,
    redact_auth_scheme,
    redact_query_secrets,
)
from mcp_audit.models import Finding, ServerConfig, Severity
from mcp_audit.policy_sources import (
    MAX_VALUE_BYTES,
    PlatformSources,
    default_platform_sources,
    read_plist,
)

ANALYZER = "managed_policy"
CLIENT = "claude-code-managed"

# Per-file cap, drop-in count cap and total budget for one read of the managed
# directory.  Managed policy files are small JSON documents; anything beyond
# these is reported rather than read.
MAX_FILE_BYTES = 1024 * 1024
MAX_DROPINS = 256
MAX_TOTAL_BYTES = 8 * 1024 * 1024
# Longest URL / pattern the wildcard matcher accepts; longer is undecidable.
_MAX_MATCH_LEN = 4096

_DOCS = "https://code.claude.com/docs/en/managed-mcp"
_MANAGED_SETTINGS_DOCS = "https://code.claude.com/docs/en/managed-settings"

# Claude Code's documented name rules: allowlist names "letters, numbers,
# hyphens, and underscores"; managedMcpServers names the same.
_ALLOW_NAME = re.compile(r"[A-Za-z0-9_-]+")

# Settings keys that steer how sources combine and are not policy themselves
# (https://code.claude.com/docs/en/managed-settings: "Policy key: any settings
# key other than the two control keys ... A managed settings file or MDM policy
# that contains only those doesn't count").
CONTROL_KEYS = frozenset({"wslInheritsWindowsSettings", "managedSourcesBehavior"})

EntryKind = Literal["serverName", "serverCommand", "serverUrl"]
_ENTRY_KINDS: tuple[EntryKind, ...] = ("serverName", "serverCommand", "serverUrl")

# Discovered configs whose servers Claude Code itself loads and therefore the
# policy governs.  Subagent inline servers (claude-code-agent) are left out:
# the managed-mcp page does not say whether the lists apply to them.
_GOVERNED_FILE_NAMES = frozenset({".mcp.json", ".claude.json"})
_GOVERNED_CLIENTS = frozenset({"claude-code", "claude-code-project"})
_PLUGIN_CLIENT = "claude-code-plugin"


# ── Data model ────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class PolicyEntry:
    """One ``allowedMcpServers`` / ``deniedMcpServers`` entry.

    Attributes:
        kind: ``serverName``, ``serverCommand`` or ``serverUrl``.
        value: The name or URL, or the command as a tuple of strings.
        source: The file the entry was read from.
    """

    kind: EntryKind
    value: str | tuple[str, ...]
    source: Path

    def key(self) -> tuple[str, str | tuple[str, ...]]:
        """Identity used to de-duplicate entries across files."""
        return (self.kind, self.value)

    def shown(self) -> str:
        """The entry as text for findings, with secrets redacted."""
        if isinstance(self.value, tuple):
            return f"{self.kind} {_redact_parts(list(self.value))}"
        return f"{self.kind} {_redact(self.value)}"


@dataclass
class ManagedPolicy:
    """What the managed files in one directory say about MCP.

    ``allowed`` is ``None`` when no file sets ``allowedMcpServers`` (every
    server allowed) and a list (possibly empty) when one does.
    """

    directory: Path
    settings_files: list[Path] = field(default_factory=list)
    unparsable_files: list[Path] = field(default_factory=list)
    mcp_file: Path | None = None
    # Server names in a parsed managed-mcp.json; None when absent or unreadable.
    exclusive_servers: list[str] | None = None
    mcp_file_problem: str | None = None
    allowed: list[PolicyEntry] | None = None
    allowed_invalid_value: bool = False
    # A file set allowedMcpServers to null ("A null removes the key"); how that
    # combines with another file's list is not documented, so allowlist
    # verdicts are undecidable.
    allowed_null: bool = False
    denied: list[PolicyEntry] = field(default_factory=list)
    stripped_entries: int = 0
    lock: bool = False
    lock_invalid: bool = False
    provided: dict[str, dict] = field(default_factory=dict)
    provided_dropped: list[str] = field(default_factory=list)
    strict_plugin_only_mcp: bool = False
    # True only when the value certainly locks the MCP surface: true, an
    # array containing "mcp", or a value that is neither boolean nor array
    # (fail closed, Claude Code 2.1.282+).  Quoted booleans and objects only
    # mark an MCP policy as present.
    strict_plugin_only_blocks: bool = False
    # The drop-in directory exists but couldn't be listed.
    dropins_unlisted: bool = False
    other_mcp_keys: list[str] = field(default_factory=list)
    # ── STORY-0144: which source is in force ─────────────────────────────────
    # Top-level keys the settings documents carry (names only).
    doc_keys: list[str] = field(default_factory=list)
    # The document's own ``managedSourcesBehavior`` value (last file wins).
    sources_behavior: object = None
    # Label of the source the verdicts are evaluated against; ``None`` when the
    # managed files are the only source (the pre-STORY-0144 output, unchanged).
    source_label: str | None = None
    source_kind: Literal["files", "mdm", "hklm", "hkcu", "merged"] = "files"
    # Platform sources found beside the files: (label, location, keys).
    sources_found: list[SourceDoc] = field(default_factory=list)
    # Present but not in force, as text for MANAGED-001.
    ignored_sources: list[str] = field(default_factory=list)
    # Why this source won (first-wins) or "merged".
    selection_note: str | None = None
    # An admin source (plist / HKLM value) that is not a JSON object.
    malformed_sources: list[SourceDoc] = field(default_factory=list)
    # The managed files take part in the evaluated policy.
    files_in_force: bool = True
    # The scan could read this platform's MDM / registry sources.
    platform_sources_read: bool = False
    # Keys the managed files themselves carry (MANAGED-006 evidence).
    file_keys: list[str] = field(default_factory=list)
    # ``managed-settings.d`` exists (MANAGED-006 probes its writability).
    dropins_dir: Path | None = None
    # A document carried the ``managedSourcesBehavior`` key (its value is
    # ``sources_behavior``); Claude Code reads it from the highest-ranked source
    # carrying it or a policy key.
    behavior_key_present: bool = False

    @property
    def present(self) -> bool:
        """True when any managed settings file or ``managed-mcp.json`` exists."""
        return bool(
            self.settings_files
            or self.unparsable_files
            or self.dropins_unlisted
            or self.mcp_file is not None
            or self.sources_found
            or self.malformed_sources
        )

    @property
    def incomplete(self) -> bool:
        """True when a managed settings file or the drop-in list couldn't be read.

        Claude Code then drops the source or refuses to start, so verdicts
        built from the rest would be claims mcp-audit can't back.
        """
        return bool(
            self.unparsable_files or self.dropins_unlisted or self.malformed_sources
        )

    @property
    def exclusive(self) -> bool:
        """True when a readable ``managed-mcp.json`` takes exclusive control."""
        return self.exclusive_servers is not None

    @property
    def has_mcp_policy(self) -> bool:
        """True when the files set anything that restricts or provides servers."""
        return bool(
            self.mcp_file is not None
            or self.allowed is not None
            or self.allowed_null
            or self.denied
            or self.lock
            or self.provided
            or self.provided_dropped
            or self.strict_plugin_only_mcp
            or self.other_mcp_keys
        )


@dataclass(frozen=True)
class SourceDoc:
    """One policy document read from a platform source (plist or registry).

    Attributes:
        label: Name used in evidence (``HKLM registry``).
        kind: ``mdm`` (macOS profile), ``hklm`` or ``hkcu``.
        location: The path or registry key it came from.
        keys: Top-level policy keys it carries (names only).
        problem: Why it is not a usable JSON object, else ``None``.
        problem_kind: ``malformed`` (Claude Code refuses to start), ``denied``
            (the OS refused the read: Claude Code starts without the source) or
            ``unreadable`` (any other failure, or mcp-audit's own limits).
    """

    label: str
    kind: Literal["mdm", "hklm", "hkcu"]
    location: str
    keys: tuple[str, ...] = ()
    problem: str | None = None
    problem_kind: Literal["malformed", "denied", "unreadable"] = "malformed"


@dataclass(frozen=True)
class _Verdict:
    reason: Literal["exclusive", "denied", "plugin-only", "shadowed", "not-allowed"]
    detail: str


# ── Reading the managed directory ─────────────────────────────────────────────


def _redact_parts(parts: list[str]) -> str:
    """Join a command (or one URL) for finding text with secrets removed.

    Each part first has secret-named ``NAME=value`` assignments, header
    values after ``Authorization:``, ``Bearer `` or ``Basic `` (a part that is
    just ``Bearer`` or ``Basic`` hides the next part), and secret-named URL
    query and fragment parameters redacted; then
    ``supply_chain.redact_args`` (STORY-0108: URL userinfo, secret-named
    flag values, SECRET_PATTERNS) runs over the result, so the two redaction
    paths never diverge.  Capped at 300 characters after redacting.
    """
    pre: list[str] = []
    hide_next = False
    for part in parts:
        if hide_next:
            pre.append("[REDACTED]")
            hide_next = False
            continue
        if part.strip().lower() in ("bearer", "basic"):
            hide_next = True
            pre.append(part)
            continue
        pre.append(redact_auth_scheme(redact_assignment(redact_query_secrets(part))))
    cleaned = " ".join(p for p in redact_args(pre) if p)
    if len(cleaned) > 300:
        cleaned = cleaned[:300] + "…"
    return cleaned


def _redact(text: str) -> str:
    """Redact one value (a URL or a name) for finding text."""
    return _redact_parts([text])


class _Budget:
    """Byte budget shared by every file read in one call."""

    def __init__(self, total: int) -> None:
        self.remaining = total


def _read_json(
    path: Path, budget: _Budget, errors: list[str], *, empty_is_object: bool = False
) -> tuple[bool, object | None]:
    """Read *path* as JSON.  Returns ``(exists, parsed-or-None)``.

    At most ``MAX_FILE_BYTES + 1`` bytes are read, so a file that grows
    between checks can't exceed the cap.  ``parsed`` is ``None`` for a file
    that exists but can't be read, is over the size cap or the budget, or
    isn't valid JSON; the reason goes to *errors*.  With
    *empty_is_object* (managed settings files and drop-ins, not
    ``managed-mcp.json``) a zero-byte file is ``{}`` (Anthropic: "An empty
    managed settings file counts as {}").  Never raises.
    """
    try:
        if not path.is_file():
            return (False, None)
        with path.open("rb") as handle:
            data = handle.read(min(MAX_FILE_BYTES, budget.remaining) + 1)
    except OSError as exc:
        errors.append(f"managed policy: cannot read {path}: {type(exc).__name__}")
        return (True, None)
    if not data and empty_is_object:
        # "An empty managed settings file counts as {}" (managed-settings docs).
        return (True, {})
    if len(data) > MAX_FILE_BYTES:
        errors.append(
            f"managed policy: {path} is over the {MAX_FILE_BYTES}-byte limit; not read"
        )
        return (True, None)
    if len(data) > budget.remaining:
        errors.append(f"managed policy: read budget exhausted at {path}; not read")
        return (True, None)
    budget.remaining -= len(data)
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        errors.append(f"managed policy: cannot read {path}: {type(exc).__name__}")
        return (True, None)
    try:
        return (True, json.loads(text))
    except (json.JSONDecodeError, RecursionError) as exc:
        errors.append(f"managed policy: {path} is not valid JSON: {exc}")
        return (True, None)


def _parse_entry(raw: object, source: Path, *, allowlist: bool) -> PolicyEntry | None:
    """Return the entry *raw* describes, or ``None`` when Claude Code would strip it.

    An entry is an object with a single key (managed-mcp "Match servers by URL,
    command, or name").  ``serverName`` in an allowlist is limited to letters,
    numbers, hyphens and underscores; in a denylist it is any non-empty string
    without leading or trailing whitespace.
    """
    if not isinstance(raw, dict) or len(raw) != 1:
        return None
    ((kind, value),) = raw.items()
    if kind == "serverName":
        if not isinstance(value, str) or not value or value != value.strip():
            return None
        if allowlist and not _ALLOW_NAME.fullmatch(value):
            return None
        return PolicyEntry("serverName", value, source)
    if kind == "serverCommand":
        if (
            not isinstance(value, list)
            or not value
            or not all(isinstance(part, str) for part in value)
            or not value[0]
        ):
            return None
        return PolicyEntry("serverCommand", tuple(value), source)
    if kind == "serverUrl":
        if not isinstance(value, str) or not value.strip():
            return None
        return PolicyEntry("serverUrl", value, source)
    return None


def _provided_problem(name: str, entry: object) -> str | None:
    """Why Claude Code would drop a ``managedMcpServers`` entry (None = loads).

    The checks are the documented ones ("What an entry can contain").
    """
    if not _ALLOW_NAME.fullmatch(name):
        return "name has characters other than letters, numbers, - and _"
    if not isinstance(entry, dict):
        return "entry is not an object"
    if entry.get("type") not in ("http", "sse", "streamable-http"):
        return "type is not http or sse"
    url = entry.get("url")
    if not isinstance(url, str) or not url.lower().startswith("https://"):
        return "url is not an https:// URL"
    for member in ("command", "args", "env", "headersHelper"):
        if member in entry:
            return f"entry has a {member} member"
    if "${" in json.dumps(entry):
        return "a value contains a ${VAR} reference"
    if _has_hidden_chars(name) or _has_hidden_chars(entry):
        return "a key or value contains control or invisible formatting characters"
    return None


def _has_hidden_chars(obj: object, depth: int = 0) -> bool:
    """True when any string in *obj* has a control (Cc) or format (Cf) character."""
    if depth > 32:
        return True
    if isinstance(obj, str):
        return any(unicodedata.category(ch) in ("Cc", "Cf") for ch in obj)
    if isinstance(obj, dict):
        return any(
            _has_hidden_chars(k, depth + 1) or _has_hidden_chars(v, depth + 1)
            for k, v in obj.items()
        )
    if isinstance(obj, list):
        return any(_has_hidden_chars(v, depth + 1) for v in obj)
    return False


def _strict_plugin_only_mcp(value: object) -> tuple[bool, bool]:
    """Read ``strictPluginOnlyCustomization`` for the MCP surface.

    Returns ``(policy_present, blocks_user_and_project_servers)``.  ``true``
    or an array containing ``"mcp"`` locks the MCP surface ("Plugin servers
    only: Users can't add servers through ~/.claude.json or .mcp.json;
    plugin servers still load").  A value that is neither a boolean nor an
    array is "Treated as true, locking all four surfaces" (managed-settings,
    Keys that fail closed, Claude Code 2.1.282+), except two shapes whose
    reading is not documented for this key: a quoted boolean and an object.
    Those mark a policy as present but never support a "blocked" claim.
    ``null`` removes the key.
    """
    if value is None or value is False:
        return (False, False)
    if value is True:
        return (True, True)
    if isinstance(value, list):
        locked = "mcp" in value
        return (locked, locked)
    if isinstance(value, (str, dict)):
        return (True, False)
    return (True, True)


def _lock_value(value: object) -> tuple[bool, bool]:
    """Read ``allowManagedMcpServersOnly``: ``(locked, value_was_invalid)``.

    ``true`` or ``"true"`` locks and ``false`` or ``"false"`` doesn't (the
    quoted form "reads as that boolean"); any other value fails closed and
    "reads as" the restrictive value (managed-settings, Keys that fail
    closed).  ``null`` is handled by the caller (it removes the key).
    """
    if value is True or value == "true":
        return (True, False)
    if value is False or value == "false":
        return (False, False)
    return (True, True)


def list_dropins(dropins: Path) -> list[Path]:
    """Return the drop-in files Claude Code reads from *dropins*, in load order.

    Every ``*.json`` file in ``managed-settings.d/``, alphabetical, hidden files
    skipped (managed-settings "Split policy across drop-in files").  Shared by
    the managed-policy and secret-reach readers so they load the same files.

    Raises:
        OSError: when the directory cannot be listed.
    """
    if not dropins.is_dir():
        return []
    return sorted(
        p
        for p in dropins.iterdir()
        if p.name.endswith(".json") and not p.name.startswith(".")
    )


def policy_keys(doc: dict) -> list[str]:
    """The policy keys of a settings document, in document order.

    A policy key is any key other than the two control keys that is not
    ``null``; a document with none "doesn't count" as a source.
    """
    return [str(k) for k, v in doc.items() if k not in CONTROL_KEYS and v is not None]


@dataclass
class _Acc:
    """Running state while settings documents are applied in order."""

    allowed: dict[tuple, PolicyEntry] | None = None
    denied: dict[tuple, PolicyEntry] = field(default_factory=dict)
    strict: object = None


def _apply_document(
    policy: ManagedPolicy, acc: _Acc, path: Path, data: dict[str, object]
) -> None:
    """Fold one settings document (a file, plist or registry value) into *policy*.

    Documents are applied in load order: lists combine with duplicates removed,
    a single value replaces, a later ``managedMcpServers`` entry of the same
    name replaces the earlier one.
    """
    for key in policy_keys(data):
        if key not in policy.doc_keys:
            policy.doc_keys.append(key)
    if "managedSourcesBehavior" in data:
        policy.behavior_key_present = True
        policy.sources_behavior = data["managedSourcesBehavior"]
    if data.get("allowedMcpServers", 0) is None:
        policy.allowed_null = True
    elif "allowedMcpServers" in data:
        raw_allowed = data["allowedMcpServers"]
        acc.allowed = {} if acc.allowed is None else acc.allowed
        if isinstance(raw_allowed, list):
            for raw in raw_allowed:
                entry = _parse_entry(raw, path, allowlist=True)
                if entry is None:
                    policy.stripped_entries += 1
                else:
                    acc.allowed.setdefault(entry.key(), entry)
        else:
            # "Enforced as an empty allowlist until the value is fixed."
            policy.allowed_invalid_value = True
    raw_denied = data.get("deniedMcpServers")
    if isinstance(raw_denied, list):
        for raw in raw_denied:
            entry = _parse_entry(raw, path, allowlist=False)
            if entry is None:
                policy.stripped_entries += 1
            else:
                acc.denied.setdefault(entry.key(), entry)
    if "allowManagedMcpServersOnly" in data:
        raw_lock = data["allowManagedMcpServersOnly"]
        if raw_lock is None:
            policy.lock, policy.lock_invalid = (False, False)
        else:
            policy.lock, policy.lock_invalid = _lock_value(raw_lock)
    provided = data.get("managedMcpServers")
    if isinstance(provided, dict):
        for name, entry in provided.items():
            problem = _provided_problem(str(name), entry)
            policy.provided.pop(str(name), None)
            if problem is None and isinstance(entry, dict):
                policy.provided[str(name)] = entry
            else:
                policy.provided_dropped.append(f"{name} ({problem})")
    elif provided is not None:
        policy.provided_dropped.append("managedMcpServers (not an object)")
    if "strictPluginOnlyCustomization" in data:
        value = data["strictPluginOnlyCustomization"]
        # Drop-in rules: lists combine, a single value replaces.
        if isinstance(value, list) and isinstance(acc.strict, list):
            acc.strict = acc.strict + [v for v in value if v not in acc.strict]
        else:
            acc.strict = list(value) if isinstance(value, list) else value
    for key in ("allowAllClaudeAiMcps", "allowClaudeInChromeWithManagedMcp"):
        if key in data and key not in policy.other_mcp_keys:
            policy.other_mcp_keys.append(key)


def _finalize(policy: ManagedPolicy, acc: _Acc) -> None:
    """Derive the summary fields once every document has been applied."""
    policy.strict_plugin_only_mcp, policy.strict_plugin_only_blocks = (
        _strict_plugin_only_mcp(acc.strict)
    )
    if acc.allowed is not None:
        policy.allowed = (
            [] if policy.allowed_invalid_value else list(acc.allowed.values())
        )
    policy.denied = list(acc.denied.values())


def read_managed_policy(
    directory: Path | None = None, errors: list[str] | None = None
) -> ManagedPolicy:
    """Read the managed MCP policy files in *directory*.

    ``managed-settings.json`` is merged first, then every ``*.json`` file in
    ``managed-settings.d/`` in alphabetical order (hidden files skipped):
    lists combine with duplicates removed, single values are replaced by the
    later file, and a later ``managedMcpServers`` entry with the same name
    replaces the earlier one (managed-settings "Split policy across drop-in
    files").  ``managed-mcp.json`` is read alongside.

    Args:
        directory: The managed directory; Claude Code's system directory for
            this OS (``mcp_audit.plugins.mods.managed_settings_dir``) when
            omitted.
        errors: Receives unreadable/oversized/invalid-file notes.  Never raises.

    Returns:
        The merged policy.  ``present`` is False when no file exists.
    """
    from mcp_audit.plugins import mods as _mods  # noqa: PLC0415

    errs: list[str] = errors if errors is not None else []
    directory = directory if directory is not None else _mods.managed_settings_dir()
    policy = ManagedPolicy(directory=directory)
    budget = _Budget(MAX_TOTAL_BYTES)

    candidates: list[Path] = [directory / "managed-settings.json"]
    dropins = directory / "managed-settings.d"
    try:
        if dropins.is_dir():
            policy.dropins_dir = dropins
            names = list_dropins(dropins)
            if len(names) > MAX_DROPINS:
                errs.append(
                    f"managed policy: {dropins} has {len(names)} files; only the"
                    f" first {MAX_DROPINS} were read"
                )
            candidates += names[:MAX_DROPINS]
    except OSError as exc:
        errs.append(f"managed policy: cannot list {dropins}: {type(exc).__name__}")
        policy.dropins_unlisted = True

    acc = _Acc()
    for path in candidates:
        exists, data = _read_json(path, budget, errs, empty_is_object=True)
        if not exists:
            continue
        if not isinstance(data, dict):
            if data is not None:
                errs.append(f"managed policy: {path} is not a JSON object")
            policy.unparsable_files.append(path)
            continue
        policy.settings_files.append(path)
        _apply_document(policy, acc, path, data)
    _finalize(policy, acc)
    policy.file_keys = list(policy.doc_keys)

    mcp_path = directory / "managed-mcp.json"
    exists, data = _read_json(mcp_path, budget, errs)
    if exists:
        policy.mcp_file = mcp_path
        servers = data.get("mcpServers") if isinstance(data, dict) else None
        if isinstance(servers, dict):
            policy.exclusive_servers = sorted(str(k) for k in servers)
        else:
            policy.mcp_file_problem = (
                "could not be read or parsed"
                if data is None
                else "has no mcpServers object"
            )
    return policy


# ── Other sources and ranking (STORY-0144) ────────────────────────────────────
#
# Claude Code reads administrator policy from, highest first (managed-settings,
# https://code.claude.com/docs/en/managed-settings): (1) server-managed settings
# (no local copy: out of scope), (2) MDM/OS policy: a macOS configuration profile
# in the ``com.anthropic.claudecode`` managed-preferences domain or Windows
# ``HKLM\SOFTWARE\Policies\ClaudeCode`` value ``Settings``, (3) the managed
# settings files, (4) ``HKCU\SOFTWARE\Policies\ClaudeCode`` value ``Settings``.
# "Admin source: one of the first three sources... The HKCU registry is
# user-writable and isn't one."  Default ``managedSourcesBehavior`` is
# ``"first-wins"``; ``"merge"`` composes the admin sources.

MDM_DOMAIN = "com.anthropic.claudecode"
REGISTRY_SUBKEY = "SOFTWARE\\Policies\\ClaudeCode"
REGISTRY_VALUE = "Settings"
LABEL_FILES = "managed settings files"
LABEL_HKLM = "HKLM registry"
LABEL_HKCU = "HKCU registry (user-writable)"
_MDM_LABELS = {
    "device": "macOS configuration profile (device)",
    "user": "macOS configuration profile (user-scoped)",
}


@dataclass
class _PlatformDoc:
    info: SourceDoc
    data: dict | None
    path: Path
    policy: ManagedPolicy | None = None


def _bad_doc(
    label: str,
    kind: Literal["mdm", "hklm", "hkcu"],
    location: str,
    problem: str,
    problem_kind: str,
    path: Path,
    errors: list[str],
) -> _PlatformDoc:
    errors.append(f"managed policy: {location}: {problem}")
    kind_t: Literal["malformed", "denied", "unreadable"] = (
        "denied"
        if problem_kind == "denied"
        else "unreadable"
        if problem_kind == "unreadable"
        else "malformed"
    )
    return _PlatformDoc(
        SourceDoc(label, kind, location, (), problem, kind_t), None, path
    )


def _registry_doc(
    sources: PlatformSources,
    hive: str,
    label: str,
    kind: Literal["hklm", "hkcu"],
    errors: list[str],
) -> _PlatformDoc | None:
    """Read ``<hive>\\SOFTWARE\\Policies\\ClaudeCode`` value ``Settings``."""
    if sources.registry is None or not sources.platform.startswith("win"):
        return None
    read = sources.registry(hive, REGISTRY_SUBKEY, REGISTRY_VALUE)
    if not read.found:
        return None
    location = f"{hive}\\{REGISTRY_SUBKEY}\\{REGISTRY_VALUE}"
    path = Path(label)
    if read.problem is not None or read.text is None:
        return _bad_doc(
            label,
            kind,
            location,
            read.problem or "value could not be read",
            read.problem_kind,
            path,
            errors,
        )
    if len(read.text.encode("utf-8", "replace")) > MAX_VALUE_BYTES:
        return _bad_doc(
            label,
            kind,
            location,
            f"over the {MAX_VALUE_BYTES}-byte limit",
            "unreadable",
            path,
            errors,
        )
    try:
        parsed = json.loads(read.text.lstrip("\ufeff"))
    except (json.JSONDecodeError, RecursionError):
        return _bad_doc(
            label, kind, location, "value is not valid JSON", "malformed", path, errors
        )
    if not isinstance(parsed, dict):
        return _bad_doc(
            label,
            kind,
            location,
            "value is not a JSON object",
            "malformed",
            path,
            errors,
        )
    keys = tuple(sorted(policy_keys(parsed)))
    return _PlatformDoc(SourceDoc(label, kind, location, keys), parsed, path)


def _safe_user_dir(user: str | None) -> bool:
    """A user name that is one plain path component (never ``..`` or a path)."""
    if not user or user in (".", ".."):
        return False
    return not any(ch in user for ch in ("/", "\\", "\0"))


def _plist_docs(sources: PlatformSources, errors: list[str]) -> list[_PlatformDoc]:
    """Read the device and current-user ``com.anthropic.claudecode`` plists."""
    if sources.platform != "darwin":
        return []
    root = sources.plist_root
    candidates = [("device", root / f"{MDM_DOMAIN}.plist")]
    if _safe_user_dir(sources.user):
        candidates.append(("user", root / str(sources.user) / f"{MDM_DOMAIN}.plist"))
    out: list[_PlatformDoc] = []
    for scope, path in candidates:
        read = read_plist(path, root)
        if not read.found:
            continue
        label = _MDM_LABELS[scope]
        if read.data is None:
            out.append(
                _bad_doc(
                    label,
                    "mdm",
                    str(path),
                    read.problem or "cannot read",
                    read.problem_kind,
                    path,
                    errors,
                )
            )
            continue
        keys = tuple(sorted(policy_keys(read.data)))
        out.append(
            _PlatformDoc(SourceDoc(label, "mdm", str(path), keys), read.data, path)
        )
    return out


def _policy_for_doc(directory: Path, doc: _PlatformDoc) -> ManagedPolicy:
    assert doc.data is not None  # noqa: S101 — callers skip malformed docs
    policy = ManagedPolicy(directory=directory)
    acc = _Acc()
    _apply_document(policy, acc, doc.path, doc.data)
    _finalize(policy, acc)
    return policy


@dataclass
class _Ranked:
    label: str
    kind: Literal["files", "mdm", "hklm"]
    policy: ManagedPolicy


def _highest_allowlist(ranked: list[_Ranked]) -> ManagedPolicy | None:
    """The highest-ranked source that sets ``allowedMcpServers`` (``ranked`` is
    highest first)."""
    return next((r.policy for r in ranked if r.policy.allowed is not None), None)


def _merge_policies(directory: Path, ranked: list[_Ranked]) -> ManagedPolicy:
    """Compose admin sources the way ``managedSourcesBehavior: "merge"`` does.

    Per Anthropic's table (managed-settings, "Compose every managed source"):
    ``deniedMcpServers`` entries union; ``allowedMcpServers`` is a restriction
    allowlist, "taken whole from the highest-ranked source that sets it,
    without adding entries from lower sources"; locks take the strictest value;
    a ``managedMcpServers`` entry of the same name from a higher source wins.
    *ranked* is highest first.
    """
    merged = ManagedPolicy(directory=directory)
    denied: dict[tuple, PolicyEntry] = {}
    for item in ranked:
        for entry in item.policy.denied:
            denied.setdefault(entry.key(), entry)
    for item in reversed(ranked):  # lowest first, so a higher source overrides
        merged.provided.update(item.policy.provided)
    setter = _highest_allowlist(ranked)
    if setter is not None:
        merged.allowed = list(setter.allowed or [])
        merged.allowed_invalid_value = setter.allowed_invalid_value
    else:
        merged.allowed_null = ranked[0].policy.allowed_null
    for item in ranked:
        p = item.policy
        merged.lock |= p.lock
        merged.lock_invalid |= p.lock and p.lock_invalid
        merged.strict_plugin_only_mcp |= p.strict_plugin_only_mcp
        merged.strict_plugin_only_blocks |= p.strict_plugin_only_blocks
        merged.stripped_entries += p.stripped_entries
        merged.provided_dropped += p.provided_dropped
        for key in p.other_mcp_keys:
            if key not in merged.other_mcp_keys:
                merged.other_mcp_keys.append(key)
        for key in p.doc_keys:
            if key not in merged.doc_keys:
                merged.doc_keys.append(key)
    merged.denied = list(denied.values())
    merged.sources_behavior = "merge"
    return merged


def _read_platform_source(
    what: str, errors: list[str], read: Callable[[], object], default: object
) -> object:
    """Run one platform reader; a crash costs only that source (never the files)."""
    try:
        return read()
    except Exception as exc:  # noqa: BLE001 — isolate each source
        errors.append(f"managed policy: {what}: {type(exc).__name__}: {exc}")
        return default


def read_effective_policy(
    directory: Path | None = None,
    errors: list[str] | None = None,
    sources: PlatformSources | None = None,
) -> ManagedPolicy:
    """Read every Claude Code policy source and return the one in force.

    The managed files are read with :func:`read_managed_policy`; on macOS the
    ``com.anthropic.claudecode`` managed-preferences plists and on Windows the
    ``HKLM`` and ``HKCU`` ``Settings`` values are read through *sources*
    (injectable; read-only, 1 MiB cap).  Rules, all from
    https://code.claude.com/docs/en/managed-settings:

    * Ranking: plist / ``HKLM`` > managed files > ``HKCU``.  A *policy key* is
      any key other than ``wslInheritsWindowsSettings`` and
      ``managedSourcesBehavior`` with a non-null value; a source with none
      "doesn't count".  ``HKCU`` is used only when no admin document is
      present (one is present when it sets a policy key or exists but can't be
      read).
    * ``"first-wins"`` (default): the highest-ranked source that delivers a
      policy key is evaluated, except ``deniedMcpServers`` (union),
      ``allowManagedMcpServersOnly`` (a ``true`` anywhere turns it on) and, while
      that lock is on, ``allowedMcpServers`` (from the highest-ranked admin
      source that sets one), which come from every admin source.
    * ``"merge"``, read from the highest-ranked source carrying that key or a
      policy key: denylists union, ``allowedMcpServers`` is taken whole from
      the highest-ranked source that sets it, locks take the strictest value.

    With no platform source delivering policy the result is exactly
    :func:`read_managed_policy`.  Never raises on unreadable input; problems go
    to *errors*.
    """
    errs: list[str] = errors if errors is not None else []
    files = read_managed_policy(directory, errs)
    plat = sources if sources is not None else default_platform_sources()
    mdm: list[_PlatformDoc] = _read_platform_source(  # type: ignore[assignment]
        "macOS managed preferences", errs, lambda: _plist_docs(plat, errs), []
    )
    hklm: _PlatformDoc | None = _read_platform_source(  # type: ignore[assignment]
        "HKLM registry",
        errs,
        lambda: _registry_doc(plat, "HKLM", LABEL_HKLM, "hklm", errs),
        None,
    )
    hkcu: _PlatformDoc | None = _read_platform_source(  # type: ignore[assignment]
        "HKCU registry",
        errs,
        lambda: _registry_doc(plat, "HKCU", LABEL_HKCU, "hkcu", errs),
        None,
    )
    admin_docs = [*mdm, *([hklm] if hklm else [])]
    bad = [d.info for d in admin_docs if d.data is None]
    for d in admin_docs:
        if d.data is not None:
            d.policy = _policy_for_doc(files.directory, d)
    # Highest rank first: macOS profile(s) / HKLM, then the managed files.
    ranked_all = [
        _Ranked(d.info.label, d.info.kind, d.policy)  # type: ignore[arg-type]
        for d in admin_docs
        if d.policy is not None
    ]
    ranked_all.append(_Ranked(LABEL_FILES, "files", files))
    delivering = [r for r in ranked_all if r.policy.doc_keys]
    files_present = bool(files.unparsable_files or files.dropins_unlisted)
    hkcu_keys = policy_keys(hkcu.data) if hkcu is not None and hkcu.data else []

    def base(of: ManagedPolicy) -> ManagedPolicy:
        return replace(
            of,
            directory=files.directory,
            settings_files=list(files.settings_files),
            unparsable_files=list(files.unparsable_files),
            dropins_unlisted=files.dropins_unlisted,
            dropins_dir=files.dropins_dir,
            mcp_file=files.mcp_file,
            exclusive_servers=files.exclusive_servers,
            mcp_file_problem=files.mcp_file_problem,
            file_keys=list(files.file_keys),
            sources_found=[],
            malformed_sources=list(bad),
            platform_sources_read=True,
        )

    def with_docs(eff: ManagedPolicy) -> ManagedPolicy:
        infos = {d.info.label: d.info for d in admin_docs if d.data is not None}
        eff.sources_found = [infos[r.label] for r in delivering if r.label in infos]
        return eff

    if (
        not bad
        and len(delivering) == 1
        and delivering[0] is ranked_all[-1]
        and not hkcu_keys
    ):
        return files  # nothing beyond the managed files: output is unchanged
    if bad:
        # An admin source that can't be parsed or read: no verdict is built
        # (MANAGED-007 for a malformed one).
        return with_docs(base(files))
    if not delivering:
        if files_present or not hkcu_keys:
            return files
        # No admin document is present: Claude Code uses the HKCU value, which
        # the user can write without elevation.
        assert hkcu is not None and hkcu.data is not None  # noqa: S101
        eff = base(_policy_for_doc(files.directory, hkcu))
        eff.sources_found = [hkcu.info]
        eff.source_label = LABEL_HKCU
        eff.source_kind = "hkcu"
        eff.files_in_force = False
        eff.selection_note = (
            "no admin document is present, so Claude Code uses the HKCU value,"
            " which the user can write without elevation"
        )
        return eff

    decider = next(
        (r for r in ranked_all if r.policy.behavior_key_present or r.policy.doc_keys),
        None,
    )
    merge = (
        decider is not None
        and decider.policy.sources_behavior == "merge"
        and len(delivering) > 1
    )
    top = delivering[0]
    hkcu_ignored = (
        [f"{LABEL_HKCU}: ignored, an admin document is present"] if hkcu_keys else []
    )
    if merge:
        eff = with_docs(base(_merge_policies(files.directory, delivering)))
        eff.source_label = (
            "merged admin sources (" + " + ".join(r.label for r in delivering) + ")"
        )
        eff.source_kind = "merged"
        eff.selection_note = (
            f"{decider.label if decider else top.label} sets managedSourcesBehavior"  # type: ignore[union-attr]
            ' "merge", so Claude Code composes the admin sources: denylists'
            " union, allowedMcpServers is taken whole from the highest-ranked"
            " source that sets it, locks take the strictest value, and a higher"
            " source's managedMcpServers entry wins"
        )
        eff.files_in_force = any(r.kind == "files" for r in delivering)
        eff.ignored_sources = hkcu_ignored
        return eff

    eff = with_docs(base(top.policy))
    denied = {e.key(): e for e in top.policy.denied}
    for other in delivering[1:]:
        for entry in other.policy.denied:
            denied.setdefault(entry.key(), entry)
        eff.lock = eff.lock or other.policy.lock
        eff.lock_invalid = eff.lock_invalid or (
            other.policy.lock and other.policy.lock_invalid
        )
    eff.denied = list(denied.values())
    if eff.lock:
        # "While the lock is on, the managed allowedMcpServers list comes from
        # the highest-ranked admin source that sets one."
        setter = _highest_allowlist(delivering)
        if setter is not None and setter is not top.policy:
            eff.allowed = list(setter.allowed or [])
            eff.allowed_invalid_value = setter.allowed_invalid_value
            eff.allowed_null = False
    eff.source_label = top.label
    eff.source_kind = top.kind
    # The files matter when they are the selected source or still contribute a
    # key read from every admin source (denylist, lock, the locked allowlist).
    eff.files_in_force = (
        top.kind == "files"
        or bool(files.denied)
        or files.lock
        or (eff.lock and eff.allowed is not None and files.allowed == eff.allowed)
    )
    eff.selection_note = (
        f"{top.label} is the highest-ranked admin source that sets a policy"
        " key, so under the default managedSourcesBehavior (first-wins) Claude"
        " Code uses it and ignores the other sources' allowlists;"
        " deniedMcpServers and allowManagedMcpServersOnly (and, while that lock"
        " is on, allowedMcpServers) are still read from every admin source"
        if len(delivering) > 1
        else f"{top.label} is the admin source that sets policy keys"
    )
    eff.ignored_sources = [
        f"{r.label}: outranked by {top.label}" for r in delivering[1:]
    ] + hkcu_ignored
    return eff


# ── Matching (managed-mcp "How a server is evaluated") ───────────────────────


def _glob(pattern: str, text: str) -> bool:
    """``*``-only wildcard match.

    The pattern is split at ``*``: the first piece must be a prefix, the last
    a suffix, and each piece between is found left to right with
    ``str.find`` (leftmost placement is always safe when ``*`` is the only
    wildcard), so there is no backtracking.
    """
    pieces = pattern.split("*")
    if len(pieces) == 1:
        return pattern == text
    head, *middle, tail = pieces
    if not text.startswith(head):
        return False
    pos = len(head)
    end = len(text) - len(tail)
    if end < pos or not text.endswith(tail):
        return False
    for piece in middle:
        if not piece:
            continue
        found = text.find(piece, pos, end)
        if found == -1:
            return False
        pos = found + len(piece)
    return True


_DEFAULT_PORTS = {"https": "443", "http": "80"}


def _split_url(url: str) -> tuple[str, str, str | None, str] | None:
    """Split *url* into scheme, host, port and path.

    Scheme and host are lower-cased, userinfo is dropped and a trailing dot
    on the host removed (Claude Code's hostname match "is case-insensitive
    and ignores a trailing FQDN dot"; "Paths stay case-sensitive").  The
    port is ``None`` when the URL gives none.  Returns ``None`` without
    ``://`` or for a malformed bracketed (IPv6) host.
    """
    head, sep, rest = url.partition("://")
    if not sep:
        return None
    cut = len(rest)
    for ch in "/?#":
        idx = rest.find(ch)
        if idx != -1:
            cut = min(cut, idx)
    authority = rest[:cut].rpartition("@")[2].lower()
    path = rest[cut:]
    port: str | None
    if authority.startswith("["):
        close = authority.find("]")
        if close == -1:
            return None
        host, tail = authority[: close + 1], authority[close + 1 :]
        if tail and not tail.startswith(":"):
            return None
        port = tail[1:] if tail else None
    else:
        host, colon, port_text = authority.partition(":")
        port = port_text if colon else None
    return (head.lower(), host.rstrip("."), port or None, path)


def url_matches(pattern: str, url: str) -> bool | None:
    """Does a ``serverUrl`` *pattern* match a server *url*?

    Rules from managed-mcp "How serverUrl entries match": ``*`` matches
    anything anywhere, including the whole scheme; a pattern with no path
    matches any path.  Ports: a pattern port must match the server's port
    (the scheme's default, 443 for https and 80 for http, when the URL
    gives none), ``:*`` matching every port; with no port in the pattern, a
    hostname written out in full matches the default port only and a
    hostname with a ``*`` in it matches every port.  Returns ``None``
    (undecidable) when either side has a ``${VAR}`` reference, isn't a
    ``scheme://`` URL, is too long, has a non-numeric port, or the server's
    scheme has no default port mcp-audit knows when one is needed.
    """
    if "${" in pattern or "${" in url:
        return None
    if len(pattern) > _MAX_MATCH_LEN or len(url) > _MAX_MATCH_LEN:
        return None
    pat = _split_url(pattern)
    srv = _split_url(url)
    if pat is None or srv is None:
        return None
    p_scheme, p_host, p_port, p_path = pat
    s_scheme, s_host, s_port, s_path = srv
    if not _glob(p_scheme, s_scheme) or not _glob(p_host, s_host):
        return False
    if s_port is not None and not s_port.isdigit():
        return None
    default = _DEFAULT_PORTS.get(s_scheme)
    if p_port is None:
        if "*" not in p_host and s_port is not None:
            if default is None:
                return None
            if s_port.lstrip("0") != default:
                return False
    else:
        effective = (s_port.lstrip("0") or "0") if s_port is not None else default
        if effective is None:
            return None
        if not _glob(p_port, effective):
            return False
    if not p_path:
        return True
    paths = [s_path or "/"]
    for ch in "?#":
        if ch in s_path:
            paths.append(s_path.split(ch, 1)[0] or "/")
    return any(_glob(p_path, candidate) for candidate in paths)


def _server_command(server: ServerConfig) -> tuple[str, ...] | None:
    if not server.command:
        return None
    return (server.command, *server.args)


def entry_matches(entry: PolicyEntry, server: ServerConfig) -> bool | None:
    """Does *entry* match *server*?  ``None`` = undecidable (``${VAR}``)."""
    if entry.kind == "serverName":
        return entry.value == server.name
    if entry.kind == "serverCommand":
        command = _server_command(server)
        if command is None:
            return False
        assert isinstance(entry.value, tuple)  # noqa: S101 — set by _parse_entry
        if any("${" in part for part in (*entry.value, *command)):
            return None
        return entry.value == command
    if not server.url:
        return False
    return url_matches(str(entry.value), server.url)


def _allow_verdict(
    entries: list[PolicyEntry], server: ServerConfig
) -> Literal["allowed", "blocked", "unknown"]:
    """Apply the allowlist table: remote needs a serverUrl entry, stdio a
    serverCommand entry; a serverName match counts only when the list has no
    entry of that kind."""
    remote = bool(server.url)
    strong: EntryKind = "serverUrl" if remote else "serverCommand"
    relevant = [e for e in entries if e.kind == strong]
    if not relevant:
        relevant = [e for e in entries if e.kind == "serverName"]
    unknown = False
    for entry in relevant:
        result = entry_matches(entry, server)
        if result is True:
            return "allowed"
        if result is None:
            unknown = True
    return "unknown" if unknown else "blocked"


# ── Which servers and settings files the policy governs ──────────────────────


def is_governed(server: ServerConfig) -> bool:
    """True for a server Claude Code itself loads (user, project or plugin)."""
    if server.client == _PLUGIN_CLIENT:
        return True
    return (
        server.client in _GOVERNED_CLIENTS
        and server.config_path.name in _GOVERNED_FILE_NAMES
    )


def _has_symlink_between(root: Path, path: Path) -> bool:
    """True when *path* or any directory between *root* and it is a symlink.

    A path outside *root* counts as linked (it can't be attributed to the
    repository).  ``OSError`` reads as linked: never attribute what can't be
    checked.
    """
    try:
        rel = path.relative_to(root)
    except ValueError:
        return True
    current = root
    try:
        for part in rel.parts:
            current = current / part
            if current.is_symlink():
                return True
    except OSError:
        return True
    return False


@dataclass(frozen=True)
class SettingsAllowlist:
    """A non-managed settings file's ``allowedMcpServers`` entries."""

    path: Path
    scope: Literal["user", "project", "local"]
    entries: tuple[PolicyEntry, ...]


def settings_allowlists(
    configs: list, home: Path, root: Path | None
) -> list[SettingsAllowlist]:
    """Collect ``allowedMcpServers`` from discovered Claude Code settings files.

    Args:
        configs: Discovered configs (``DiscoveredConfig``) whose ``raw`` has
            been filled by ``parse_config``.
        home: The home directory; ``<home>/.claude/settings.json`` is the user
            file wherever it was discovered from (a ``--project`` walk of
            ``$HOME`` finds it too).
        root: Project root for project/local files.  A file under it reached
            through a symlinked component, or a symlinked file, is skipped:
            TRUST-002 reports it and it is never attributed to the repository.
    """
    user_file = home / ".claude" / "settings.json"
    out: list[SettingsAllowlist] = []
    seen: set[Path] = set()
    for config in configs:
        path: Path = config.path
        if path.name not in ("settings.json", "settings.local.json"):
            continue
        if path.parent.name != ".claude":
            continue
        raw = getattr(config, "raw", None)
        if not isinstance(raw, dict) or not isinstance(
            raw.get("allowedMcpServers"), list
        ):
            continue
        try:
            resolved = path.resolve()
        except OSError:
            continue
        if resolved in seen:
            continue
        if path == user_file or resolved == _safe_resolve(user_file):
            scope: Literal["user", "project", "local"] = "user"
        else:
            if getattr(config, "is_symlink", False):
                continue
            if root is not None and _has_symlink_between(root, path):
                continue
            scope = "local" if path.name == "settings.local.json" else "project"
        seen.add(resolved)
        entries = tuple(
            entry
            for raw_entry in raw["allowedMcpServers"]
            if (entry := _parse_entry(raw_entry, path, allowlist=True)) is not None
        )
        if entries:
            out.append(SettingsAllowlist(path, scope, entries))
    return out


def _safe_resolve(path: Path) -> Path | None:
    try:
        return path.resolve()
    except OSError:
        return None


# ── Findings ──────────────────────────────────────────────────────────────────


def _finding(
    fid: str,
    severity: Severity,
    server: str,
    title: str,
    description: str,
    evidence: str,
    remediation: str,
    path: Path | None,
    owasp: list[str],
    cwe: str,
    client: str = CLIENT,
) -> Finding:
    return Finding(
        id=fid,
        severity=severity,
        analyzer=ANALYZER,
        client=client,
        server=server,
        title=title,
        description=description,
        evidence=evidence,
        remediation=remediation,
        cwe=cwe,
        finding_path=str(path) if path is not None else None,
        owasp_mcp_top_10=owasp,
    )


_SOURCE_CAVEAT = (
    " mcp-audit reads only the managed files in the system directory. An MDM"
    " profile, an HKLM registry policy or server-managed settings from the"
    " claude.ai console rank above these files and are not visible to it; under"
    " Claude Code's default first-wins rule a higher source that delivers any"
    " policy key replaces the files' allowlist (deniedMcpServers and"
    " allowManagedMcpServersOnly are still read from every admin source,"
    " Claude Code 2.1.273 or later; managed-mcp.json always applies)."
)
_SOURCE_CAVEAT_READ = (
    " mcp-audit read the managed files and this platform's MDM / registry"
    " sources and ranks them as Claude Code does. Server-managed settings from"
    " the claude.ai console rank above all of them and have no local copy, so"
    " they are not visible; under Claude Code's default first-wins rule a higher"
    " source that delivers any policy key replaces the allowlist"
    " (deniedMcpServers and allowManagedMcpServersOnly are still read from every"
    " admin source, Claude Code 2.1.273 or later; managed-mcp.json always"
    " applies)."
)


def _source_caveat(policy: ManagedPolicy) -> str:
    return _SOURCE_CAVEAT_READ if policy.platform_sources_read else _SOURCE_CAVEAT


def _src(policy: ManagedPolicy) -> str:
    """Evidence prefix naming the source in force ('' for the files alone)."""
    return f"source: {policy.source_label} | " if policy.source_label else ""


def _inventory_lead(policy: ManagedPolicy) -> str:
    if policy.source_label is None and not policy.malformed_sources:
        return (
            f"Claude Code's managed files in {policy.directory} set this MCP policy: "
        )
    return (
        "Claude Code's managed policy"
        + (f" (source in force: {policy.source_label})" if policy.source_label else "")
        + " sets this MCP policy: "
    )


def _inventory_evidence(policy: ManagedPolicy, files: list[Path]) -> str:
    base = _src(policy) + "files: " + ", ".join(str(p) for p in files)
    extra = [
        f"{d.label}: {d.location}"
        for d in (*policy.sources_found, *policy.malformed_sources)
    ]
    return base + (" | " + "; ".join(extra) if extra else "")


def _inventory(policy: ManagedPolicy) -> Finding:
    parts: list[str] = []
    if policy.exclusive:
        assert policy.exclusive_servers is not None  # noqa: S101
        names = ", ".join(policy.exclusive_servers[:20]) or "none"
        parts.append(
            f"managed-mcp.json takes exclusive control with"
            f" {len(policy.exclusive_servers)} server(s) ({names}); no user,"
            " project or plugin server loads"
        )
    elif policy.mcp_file is not None:
        parts.append(f"managed-mcp.json {policy.mcp_file_problem}")
    if policy.provided:
        parts.append(
            "managedMcpServers provides " + ", ".join(sorted(policy.provided)[:20])
        )
    if policy.provided_dropped:
        parts.append(
            "managedMcpServers entries Claude Code drops: "
            + "; ".join(policy.provided_dropped[:10])
        )
    if policy.allowed is not None:
        if policy.allowed_invalid_value:
            parts.append(
                "allowedMcpServers is not a list, so Claude Code enforces an empty"
                " allowlist"
            )
        else:
            kinds = sorted({e.kind for e in policy.allowed})
            parts.append(
                f"allowedMcpServers has {len(policy.allowed)} entr"
                f"{'y' if len(policy.allowed) == 1 else 'ies'}"
                f" ({', '.join(kinds) or 'empty: no user-added server loads'}),"
                + (
                    " locked by allowManagedMcpServersOnly"
                    if policy.lock
                    else " not locked (other settings files can add to it)"
                )
            )
    elif policy.lock:
        parts.append(
            "allowManagedMcpServersOnly is true but no file sets"
            " allowedMcpServers, so every server that passes the denylist loads"
        )
    if policy.allowed_null:
        parts.append(
            "a file sets allowedMcpServers to null, which removes the key;"
            " allowlist verdicts are not reported"
        )
    if policy.lock_invalid:
        parts.append(
            "allowManagedMcpServersOnly has a value Claude Code can't read, so it"
            " reads as true (fails closed)"
        )
    if policy.denied:
        parts.append(f"deniedMcpServers has {len(policy.denied)} entries")
    if policy.stripped_entries:
        parts.append(
            f"{policy.stripped_entries} malformed allow/deny entr"
            f"{'y' if policy.stripped_entries == 1 else 'ies'} Claude Code strips"
        )
    if policy.strict_plugin_only_blocks:
        parts.append(
            "strictPluginOnlyCustomization locks MCP to plugin and managed sources"
        )
    elif policy.strict_plugin_only_mcp:
        parts.append(
            "strictPluginOnlyCustomization is set to a value whose effect on MCP"
            " mcp-audit can't decide (a quoted boolean or an object)"
        )
    if policy.incomplete:
        if not policy.malformed_sources:
            parts.append(
                "verdicts withheld (no MANAGED-002/003/004/005): a managed settings"
                " file or the managed-settings.d directory could not be read or"
                " parsed, so mcp-audit can't tell what Claude Code enforces (it"
                " drops a source it can't read and refuses to start on a document"
                " it can't parse)"
            )
        else:
            causes = []
            if policy.unparsable_files or policy.dropins_unlisted:
                causes.append(
                    "a managed settings file or the managed-settings.d directory"
                )
            causes.append("an admin policy source (macOS profile or registry value)")
            parts.append(
                "verdicts withheld (no MANAGED-002/003/004/005): "
                + " and ".join(causes)
                + " could not be read or parsed, so mcp-audit can't tell what"
                " Claude Code enforces"
            )
    if policy.unparsable_files:
        parts.append(
            "unreadable or invalid managed settings file(s) (Claude Code refuses"
            " to start on a managed document it can't parse): "
            + ", ".join(p.name for p in policy.unparsable_files)
        )
    if policy.selection_note:
        parts.append(policy.selection_note)
    if policy.ignored_sources:
        parts.append("not in force: " + "; ".join(policy.ignored_sources))
    for kind, text in (
        ("malformed", "an admin source Claude Code can't parse (it refuses to start)"),
        (
            "denied",
            "an admin source the operating system denied reading (Claude Code"
            " starts without that source's policies)",
        ),
        (
            "unreadable",
            "an admin source mcp-audit could not read (Claude Code may exit at"
            " startup, or mcp-audit's own limit applied)",
        ),
    ):
        group = [m for m in policy.malformed_sources if m.problem_kind == kind]
        if group:
            parts.append(
                text + ": " + "; ".join(f"{m.label} ({m.problem})" for m in group)
            )
    if not parts:
        parts.append("no MCP policy keys")
    files = [*policy.settings_files, *policy.unparsable_files]
    if policy.mcp_file is not None:
        files.append(policy.mcp_file)
    return _finding(
        "MANAGED-001",
        Severity.INFO,
        "managed-policy",
        "Managed MCP policy on this machine",
        _inventory_lead(policy) + "; ".join(parts) + "." + _source_caveat(policy),
        _inventory_evidence(policy, files),
        "Confirm the policy is the one your organization intends. Run `/status`"
        " in Claude Code to see which managed source is in force, and"
        " `claude mcp list` to see what actually loads. Reference: " + _DOCS,
        policy.directory,
        ["MCP09"],
        "CWE-1188",
    )


_VERDICT_CAVEAT = (
    " This holds when the managed settings files are the source Claude Code"
    " applies: an MDM profile or server-managed settings that deliver any policy"
    " key replace them, and mcp-audit can't read those."
)
_VERDICT_CAVEAT_READ = (
    " This holds when the source named in the evidence is the one Claude Code"
    " applies: server-managed settings from the claude.ai console rank above it,"
    " and mcp-audit can't read those."
)


def _verdict(
    policy: ManagedPolicy,
    server: ServerConfig,
    extra_allowed: list[SettingsAllowlist],
) -> _Verdict | None:
    """Why the managed policy keeps *server* from loading (None = it may load)."""
    if policy.exclusive:
        return _Verdict(
            "exclusive",
            "managed-mcp.json is deployed, and with it Claude Code loads only the"
            " servers that file defines, servers provided through"
            " managedMcpServers, and a few built-in ones. Users can't add,"
            " modify, or use any other MCP servers, including plugin-provided"
            " servers (Anthropic, managed-mcp: Exclusive control).",
        )
    for entry in policy.denied:
        if entry_matches(entry, server) is True:
            return _Verdict(
                "denied",
                f"it matches the managed denylist entry {entry.shown()} in"
                f" {entry.source.name}. A server that matches any denylist"
                " entry is blocked; nothing overrides a denylist match"
                " (Claude Code reads deniedMcpServers from every admin source,"
                " 2.1.273 or later).",
            )
    if policy.strict_plugin_only_blocks and server.client != _PLUGIN_CLIENT:
        return _Verdict(
            "plugin-only",
            "managed settings set strictPluginOnlyCustomization for MCP, so"
            " 'Users can't add servers through ~/.claude.json or .mcp.json;"
            " plugin servers still load' (Anthropic, managed-mcp: Choose a"
            " pattern; a value that is neither a boolean nor an array is treated"
            " as true, Claude Code 2.1.282 or later)."
            + (
                _VERDICT_CAVEAT_READ
                if policy.platform_sources_read
                else _VERDICT_CAVEAT
            ),
        )
    if policy.provided:
        for name, entry in policy.provided.items():
            same_name = server.client != _PLUGIN_CLIENT and name == server.name
            same_url = (
                server.client == _PLUGIN_CLIENT
                and bool(server.url)
                and isinstance(entry.get("url"), str)
                and server.url == entry["url"]
            )
            if same_name or same_url:
                how = "with the same name as" if same_name else "at the same URL as"
                return _Verdict(
                    "shadowed",
                    f"your organization provides a server {how}"
                    f" this one through managedMcpServers ({name}), and a"
                    " provided server takes precedence, so Claude Code connects"
                    " the organization's definition instead (Claude Code 2.1.259"
                    " or later)."
                    + (
                        _VERDICT_CAVEAT_READ
                        if policy.platform_sources_read
                        else _VERDICT_CAVEAT
                    ),
                )
    if policy.allowed is None or policy.allowed_null:
        return None
    entries = list(policy.allowed)
    extra_note = ""
    if not policy.lock:
        # Unlocked: allowlist entries from every settings scope merge into
        # one list, and the per-transport rule is applied to that list.
        seen = {e.key() for e in entries}
        for allowlist in extra_allowed:
            for entry in allowlist.entries:
                if entry.key() not in seen:
                    seen.add(entry.key())
                    entries.append(entry)
        extra_note = (
            " The allowlist isn't locked (allowManagedMcpServersOnly), so"
            " another project's settings file could still add this server;"
            " none mcp-audit read does."
        )
    if _allow_verdict(entries, server) != "blocked":
        return None
    if not entries:
        shown = "the managed allowlist is empty"
    elif server.url:
        shown = (
            "no managed allowlist entry matches it (a remote server must match a"
            " serverUrl entry once the list has one)"
        )
    else:
        shown = (
            "no managed allowlist entry matches it (a stdio server must match a"
            " serverCommand entry once the list has one)"
        )
    return _Verdict(
        "not-allowed",
        f"{shown}; commands must match exactly, every argument in order, and"
        " URLs by pattern and port (Anthropic, managed-mcp: How a server is"
        " evaluated)."
        + extra_note
        + (_VERDICT_CAVEAT_READ if policy.platform_sources_read else _VERDICT_CAVEAT),
    )


def _server_shown(server: ServerConfig) -> str:
    if server.url:
        return f"url {_redact(server.url)}"
    if server.command:
        return "command " + _redact_parts([server.command, *server.args])
    return "no command or url"


def _dead_config(
    server: ServerConfig, verdict: _Verdict, policy: ManagedPolicy
) -> Finding:
    return _finding(
        "MANAGED-002",
        Severity.INFO,
        server.name,
        "Configured MCP server that the managed policy keeps from loading",
        f"Claude Code server '{server.name}' in {server.config_path.name} does not"
        f" load under this machine's managed MCP policy: {verdict.detail} A"
        " server blocked this way disappears from /mcp and claude mcp list"
        " with no message saying policy is the reason.",
        f"server: {server.name} ({server.client}) | {_server_shown(server)} |"
        f" reason: {verdict.reason} | file: {server.config_path}"
        + (f" | source: {policy.source_label}" if policy.source_label else ""),
        "Remove the entry, or ask the policy owner to approve the server (add a"
        " serverUrl or serverCommand allowlist entry). Reference: " + _DOCS,
        server.config_path,
        ["MCP09"],
        "CWE-1188",
        client=server.client,
    )


def _broadened(policy: ManagedPolicy, allowlist: SettingsAllowlist) -> Finding | None:
    managed_keys = {e.key() for e in policy.allowed or []}
    extra = [e for e in allowlist.entries if e.key() not in managed_keys]
    if not extra:
        return None
    severity = Severity.MEDIUM if allowlist.scope == "project" else Severity.LOW
    who = {
        "project": "A repository's shared .claude/settings.json",
        "local": "A project's .claude/settings.local.json",
        "user": "Your user settings (~/.claude/settings.json)",
    }[allowlist.scope]
    shown = "; ".join(e.shown() for e in extra[:10])
    return _finding(
        "MANAGED-004",
        severity,
        "managed-policy",
        "Settings file adds servers to an unlocked managed MCP allowlist",
        f"{who} adds {len(extra)} entr{'y' if len(extra) == 1 else 'ies'} to"
        " allowedMcpServers that the managed allowlist doesn't have. The"
        " managed settings set allowedMcpServers without"
        " allowManagedMcpServersOnly, and Anthropic documents that then"
        " 'allowlists from every settings scope merge, including a user's own"
        " ~/.claude/settings.json, so a user can broaden what your allowlist"
        " permits'. allowedMcpServers can be set in any settings file, so a"
        " repository's committed settings broaden it for everyone who opens"
        " the repository. "
        + (
            "mcp-audit read the managed files and this platform's MDM/registry"
            " sources, but not server-managed settings"
            if policy.platform_sources_read
            else "mcp-audit reads only the managed files"
        )
        + ": Claude Code turns the lock on from a true in any admin source"
        " (2.1.273 or later), so "
        + (
            "server-managed settings"
            if policy.platform_sources_read
            else "an MDM profile or server-managed settings"
        )
        + " it can't read may already lock the list.",
        _src(policy) + f"file: {allowlist.path} | added: {shown}",
        "Administrators: set allowManagedMcpServersOnly to true next to"
        " allowedMcpServers in managed settings. Repository owners: remove"
        " allowedMcpServers from committed settings. Reference: " + _DOCS,
        allowlist.path,
        ["MCP02", "MCP09"],
        "CWE-284",
    )


def _name_only(policy: ManagedPolicy) -> Finding | None:
    if not policy.allowed:
        return None
    kinds = {e.kind for e in policy.allowed}
    if "serverName" not in kinds:
        return None
    weak: list[str] = []
    if "serverUrl" not in kinds:
        weak.append("remote (HTTP/SSE) servers")
    if "serverCommand" not in kinds:
        weak.append("stdio servers")
    if not weak:
        return None
    names = ", ".join(str(e.value) for e in policy.allowed if e.kind == "serverName")
    return _finding(
        "MANAGED-005",
        Severity.LOW,
        "managed-policy",
        "Managed MCP allowlist admits servers by name only",
        "The managed allowedMcpServers list admits "
        + " and ".join(weak)
        + " by serverName, because it has no "
        + (
            "serverUrl or serverCommand entries"
            if len(weak) == 2
            else (
                "serverUrl entries"
                if "serverUrl" not in kinds
                else "serverCommand entries"
            )
        )
        + ". Anthropic: 'A serverName entry, in either list, is not a security"
        " control. The name is the label a user assigns when running claude mcp"
        " add or editing a config file, not the underlying server, so a user can"
        " call any server github.'",
        _src(policy) + f"serverName entries: {_redact(names)}",
        "Add serverUrl entries for remote servers and serverCommand entries for"
        " stdio servers; once one exists, a name match no longer admits that"
        " transport. Reference: " + _DOCS,
        policy.directory,
        ["MCP09", "MCP07"],
        "CWE-284",
    )


def _no_policy(policy: ManagedPolicy) -> Finding:
    return _finding(
        "MANAGED-003",
        Severity.LOW,
        "managed-policy",
        "Managed settings are deployed but set no MCP policy",
        "This machine has Claude Code managed settings ("
        + (
            policy.source_label
            if policy.source_label and policy.source_kind != "files"
            else ", ".join(p.name for p in policy.settings_files)
            + f" in {policy.directory}"
        )
        + ") but they set none of allowedMcpServers,"
        " deniedMcpServers, allowManagedMcpServersOnly, managedMcpServers or"
        " strictPluginOnlyCustomization for MCP, and there is no"
        " managed-mcp.json. Anthropic: 'By default, anyone running Claude Code"
        " can connect any MCP server they choose', so the organization governs"
        " other settings here but not which MCP servers run." + _source_caveat(policy),
        _src(policy) + ("files: " + ", ".join(str(p) for p in policy.settings_files)),
        "If MCP servers should be governed, add deniedMcpServers, or"
        " allowedMcpServers with allowManagedMcpServersOnly, to managed settings,"
        " or deploy managed-mcp.json. Reference: " + _DOCS,
        policy.directory,
        ["MCP09"],
        "CWE-1188",
    )


@dataclass(frozen=True)
class FsProbe:
    """Injectable file-permission probe for MANAGED-006 (POSIX).

    Attributes:
        uid: The current user's effective uid; ``None`` on Windows (the file
            half of MANAGED-006 is skipped there).
        stat: ``Path -> os.stat_result``.
        access: ``(Path, mode) -> bool``, like ``os.access``.
        wsl: Running under WSL, where Anthropic notes ``/etc/claude-code`` is
            user-writable.
    """

    uid: int | None
    stat: Callable[[Path], os.stat_result]
    access: Callable[[Path, int], bool]
    wsl: bool = False


def default_fs_probe() -> FsProbe:
    """The real machine's probe (patched out in the test suite's conftest)."""
    uid = os.geteuid() if hasattr(os, "geteuid") else None
    wsl = False
    if sys.platform.startswith("linux"):
        try:
            wsl = "microsoft" in Path("/proc/version").read_text().lower()
        except OSError:
            wsl = False
    return FsProbe(uid, lambda p: p.stat(), lambda p, m: os.access(p, m), wsl)


_WSL_DIR = Path("/etc/claude-code")


def user_writable_paths(
    policy: ManagedPolicy, probe: FsProbe | None
) -> list[tuple[Path, str]]:
    """Managed paths the current user can write, each with the reason.

    Probed: the managed directory, ``managed-settings.d`` (even empty: a user
    can add a drop-in that overrides the files), each settings file that
    carries policy, and ``managed-mcp.json``.  A path counts when its owner is
    the current user (reason ``owned``) or ``access(W_OK)`` is true (reason
    ``group/other``: permission bits or an ACL).  On WSL, Anthropic: "On WSL,
    /etc/claude-code is user-writable", so that directory counts when policy
    files are there.  Root and Windows are skipped (``probe`` is ``None``,
    ``uid`` is ``None`` or 0): the finding is about a non-privileged user
    changing policy.
    """
    if probe is None or probe.uid is None or probe.uid == 0:
        return []
    files_part = policy.files_in_force and bool(policy.settings_files)
    mcp_part = policy.mcp_file is not None
    if not files_part and not mcp_part:
        return []
    targets: list[Path] = [policy.directory]
    if files_part:
        if policy.dropins_dir is not None:
            targets.append(policy.dropins_dir)
        targets.extend(policy.settings_files)
    if mcp_part and policy.mcp_file is not None:
        targets.append(policy.mcp_file)
    out: list[tuple[Path, str]] = []
    for path in dict.fromkeys(targets):
        try:
            if probe.stat(path).st_uid == probe.uid:
                out.append((path, "owned by the current user"))
            elif probe.access(path, os.W_OK):
                out.append(
                    (path, "writable through group or other permission bits or an ACL")
                )
        except OSError:
            continue
    if probe.wsl and policy.directory == _WSL_DIR and not out:
        out.append(
            (
                policy.directory,
                "WSL: Anthropic notes /etc/claude-code is user-writable",
            )
        )
    return out


def _keys_text(keys: list[str]) -> str:
    shown = ", ".join((k if len(k) <= 64 else k[:64] + "…") for k in sorted(keys)[:20])
    return shown + (f" (+{len(keys) - 20} more)" if len(keys) > 20 else "")


def _not_enforced(policy: ManagedPolicy, probe: FsProbe | None) -> Finding | None:
    """MANAGED-006: policy that exists only where the user can change it."""
    if policy.source_kind == "hkcu":
        keys = _keys_text(policy.doc_keys)
        return _finding(
            "MANAGED-006",
            Severity.MEDIUM,
            "managed-policy",
            "Claude Code policy is set, not enforced",
            "Claude Code policy is delivered only through the per-user registry"
            f" key {LABEL_HKCU}, and no admin source (macOS profile, HKLM value or"
            " managed settings file) is present. Anthropic: 'The HKCU registry is"
            " user-writable and isn't' an admin source; it is used only when no"
            " admin document is present above it. A user can change or delete the"
            " value without elevation, so this is a default, not enforcement."
            f" Keys it carries: {keys}.",
            f"source: {LABEL_HKCU} | keys: {keys} | location: "
            + ", ".join(d.location for d in policy.sources_found if d.kind == "hkcu"),
            "Deploy the policy through MDM, the HKLM registry key"
            " (HKLM\\SOFTWARE\\Policies\\ClaudeCode, value Settings) or a"
            " root/Administrator-owned managed settings file. Reference: "
            + _MANAGED_SETTINGS_DOCS,
            None,
            ["MCP09", "MCP07"],
            "CWE-284",
        )
    writable = user_writable_paths(policy, probe)
    if not writable:
        return None
    keys_list = list(policy.file_keys)
    if policy.mcp_file is not None:
        keys_list.append("managed-mcp.json (exclusive control)")
    keys = _keys_text(keys_list)
    shown = "; ".join(f"{p} ({why})" for p, why in writable[:10])
    return _finding(
        "MANAGED-006",
        Severity.MEDIUM,
        "managed-policy",
        "Claude Code policy is set, not enforced",
        "Claude Code's managed policy files are in a place the current non-root"
        " user can write, so the user can edit, replace or add to the policy and"
        f" it is a default, not enforcement. Keys the files carry: {keys}."
        + (
            " Anthropic: 'On WSL, /etc/claude-code is user-writable as well.'"
            if any("WSL" in why for _, why in writable)
            else ""
        ),
        _src(policy) + f"writable by the current user: {shown} | keys: {keys}",
        "Deploy the policy through MDM, the HKLM registry key or files owned by"
        " root (Windows: Administrator) in a directory only root can write."
        " Reference: " + _MANAGED_SETTINGS_DOCS,
        policy.directory,
        ["MCP09", "MCP07"],
        "CWE-732",
    )


def _malformed_finding(doc: SourceDoc) -> Finding:
    """MANAGED-007: an admin source that isn't a JSON object."""
    return _finding(
        "MANAGED-007",
        Severity.INFO,
        "managed-policy",
        "Claude Code admin policy source is not a valid settings object",
        f"The admin policy source {doc.label} ({doc.location}) could not be used:"
        f" {doc.problem}. Anthropic: Claude Code refuses to start on an admin"
        " managed document it can't parse, so developers on this machine see"
        " Claude Code fail to launch until the value is fixed. mcp-audit builds"
        " no allowlist or denylist verdict while an admin source is unreadable.",
        f"source: {doc.label} | location: {doc.location} | problem: {doc.problem}",
        "Fix the profile or registry value so it holds a JSON object of settings"
        " (the same shape as managed-settings.json). Reference: "
        + _MANAGED_SETTINGS_DOCS,
        None,
        ["MCP09"],
        "CWE-20",
    )


def analyze_managed_policy(
    policy: ManagedPolicy,
    servers: list[ServerConfig],
    configs: list,
    home: Path,
    root: Path | None,
    *,
    machine_findings: bool = True,
    probe: FsProbe | None = None,
) -> list[Finding]:
    """Compare *policy* with the configured servers and settings files.

    Args:
        policy: From :func:`read_managed_policy`.
        servers: Parsed servers; only those Claude Code loads are compared
            (:func:`is_governed`).
        configs: Discovered configs, already parsed (their ``raw`` is set).
        home: Home directory (identifies the user settings file).
        root: The scan's project root (cwd for a default scan, the
            ``--project`` directory otherwise).
        machine_findings: Emit MANAGED-001/003/005/006/007, which describe the
            machine rather than *servers*; ``scan --project`` passes False
            because the default scan already emitted them.

    Returns:
        MANAGED-001..007 findings; empty when no policy source exists.
    """
    if not policy.present:
        return []
    findings: list[Finding] = []
    if policy.incomplete:
        # A managed source Claude Code can't parse is dropped or stops it from
        # starting; nothing built from the remaining files can be backed.
        if not machine_findings:
            return []
        return [
            _inventory(policy),
            *(
                _malformed_finding(doc)
                for doc in policy.malformed_sources
                if doc.problem_kind == "malformed"
            ),
        ]
    if machine_findings:
        findings.append(_inventory(policy))
        not_enforced = _not_enforced(policy, probe)
        if not_enforced is not None:
            findings.append(not_enforced)
        if (
            not policy.has_mcp_policy
            and (policy.settings_files or policy.sources_found)
            and policy.source_kind != "hkcu"
        ):
            findings.append(_no_policy(policy))
        name_only = _name_only(policy)
        if name_only is not None:
            findings.append(name_only)

    allowlists = settings_allowlists(configs, home, root)
    if (
        policy.allowed is not None
        and not policy.allowed_null
        and not policy.lock
        and not policy.exclusive
    ):
        for allowlist in allowlists:
            broadened = _broadened(policy, allowlist)
            if broadened is not None:
                findings.append(broadened)

    seen: set[tuple[str, Path]] = set()
    for server in servers:
        if not is_governed(server):
            continue
        key = (server.name, _safe_resolve(server.config_path) or server.config_path)
        if key in seen:
            continue
        seen.add(key)
        verdict = _verdict(policy, server, allowlists)
        if verdict is not None:
            findings.append(_dead_config(server, verdict, policy))
    return findings


def finding_key(finding: Finding) -> tuple[str, str, str | None]:
    """De-duplication key across the default scan and ``scan --project``."""
    path = finding.finding_path
    if path is not None:
        resolved = _safe_resolve(Path(path))
        path = str(resolved) if resolved is not None else path
    return (finding.id, finding.server, path)


def managed_policy_findings(
    servers: list[ServerConfig],
    configs: list,
    root: Path | None,
    errors: list[str],
    *,
    machine_findings: bool = True,
    directory: Path | None = None,
    sources: PlatformSources | None = None,
    probe: FsProbe | None = None,
) -> list[Finding]:
    """Read every policy source and return MANAGED-001..007 findings.

    The entry point for ``scan`` / ``check`` (``scanner._discover_and_parse``)
    and ``scan --project`` (``cli/scan._apply_project_scan``).  Never raises:
    a crash is reported in *errors* and yields no findings, so the rest of the
    scan always runs.

    Args:
        servers: Parsed servers from discovery.
        configs: The discovered configs those servers came from.
        root: Project root (cwd for a default scan).
        errors: The scan's ``result.errors``.
        machine_findings: See :func:`analyze_managed_policy`.
        directory: Managed directory override (tests).
        sources: Platform readers (registry, plist root); the real machine's
            when omitted (tests inject fakes).
        probe: File-permission probe for MANAGED-006; the real one when
            omitted (tests inject fakes).
    """
    from mcp_audit.discovery import _home  # noqa: PLC0415

    try:
        policy = read_effective_policy(directory, errors, sources)
        return analyze_managed_policy(
            policy,
            servers,
            configs,
            _home(),
            root,
            machine_findings=machine_findings,
            probe=probe if probe is not None else default_fs_probe(),
        )
    except Exception as exc:  # noqa: BLE001 — never fail the scan over policy files
        errors.append(f"managed policy check error: {type(exc).__name__}: {exc}")
        return []
