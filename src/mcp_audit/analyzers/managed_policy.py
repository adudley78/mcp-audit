"""Managed MCP policy report: Claude Code organisation policy vs configured servers.

An organisation controls which MCP servers Claude Code loads through files it
deploys to a system directory (STORY-0112):

* ``managed-mcp.json`` — a fixed server set with *exclusive control*: no user,
  project or plugin server loads beside it.
* ``managed-settings.json`` and ``managed-settings.d/*.json`` — the keys
  ``allowedMcpServers``, ``deniedMcpServers``, ``allowManagedMcpServersOnly``
  and ``managedMcpServers``.

This module reads those files (never MDM profiles, the Windows registry or
server-managed settings, which have no file mcp-audit can read) and compares
them with the Claude Code servers the scan found:

* MANAGED-001 (INFO) — inventory of the managed MCP policy on this machine.
* MANAGED-002 (INFO) — a configured server the policy keeps from loading
  (dead config: it disappears from ``/mcp`` with no message).
* MANAGED-003 (LOW) — managed settings are deployed but set no MCP policy.
* MANAGED-004 (MEDIUM/LOW) — the managed allowlist isn't locked and a
  repository or user settings file adds entries to it.
* MANAGED-005 (LOW) — the managed allowlist admits a transport by
  ``serverName`` alone, which Anthropic says "is not a security control".

Every rule is taken from Anthropic's documentation:
https://code.claude.com/docs/en/managed-mcp (matching rules, evaluation order,
exclusive control, provided servers), https://code.claude.com/docs/en/managed-settings
(file locations, drop-in merge order, invalid entries) and
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
import re
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from mcp_audit.analyzers.supply_chain import redact_args
from mcp_audit.models import Finding, ServerConfig, Severity

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

# Claude Code's documented name rules: allowlist names "letters, numbers,
# hyphens, and underscores"; managedMcpServers names the same.
_ALLOW_NAME = re.compile(r"[A-Za-z0-9_-]+")

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

    @property
    def present(self) -> bool:
        """True when any managed settings file or ``managed-mcp.json`` exists."""
        return bool(
            self.settings_files
            or self.unparsable_files
            or self.dropins_unlisted
            or self.mcp_file is not None
        )

    @property
    def incomplete(self) -> bool:
        """True when a managed settings file or the drop-in list couldn't be read.

        Claude Code then drops the source or refuses to start, so verdicts
        built from the rest would be claims mcp-audit can't back.
        """
        return bool(self.unparsable_files or self.dropins_unlisted)

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
class _Verdict:
    reason: Literal["exclusive", "denied", "plugin-only", "shadowed", "not-allowed"]
    detail: str


# ── Reading the managed directory ─────────────────────────────────────────────


_SECRET_WORDS = (
    "key",
    "token",
    "secret",
    "password",
    "passwd",
    "pwd",
    "auth",
    "credential",
)
# Matched as whole name tokens only (``X-Amz-Signature``, ``sig``), so a name
# like ``DESIGN_DIR`` is not caught by ``sig``.
_SECRET_TOKENS = frozenset({"sig", "signature"})
_NAME_SPLIT = re.compile(r"[^A-Za-z0-9]+")
_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_SCHEME_WORDS = ("bearer ", "basic ")


def _is_secret_name(name: str) -> bool:
    """True when a parameter or variable *name* is named for a secret value."""
    lowered = name.lower()
    if any(word in lowered for word in _SECRET_WORDS):
        return True
    tokens = _NAME_SPLIT.split(_CAMEL.sub("-", name).lower())
    return any(token in _SECRET_TOKENS for token in tokens)


def _redact_pairs(text: str) -> str:
    """Redact the value of each secret-named ``name=value`` pair split on ``&``."""
    pairs: list[str] = []
    for pair in text.split("&"):
        name, eq, _value = pair.partition("=")
        pairs.append(f"{name}=[REDACTED]" if eq and _is_secret_name(name) else pair)
    return "&".join(pairs)


def _redact_query(text: str) -> str:
    """Redact secret-named parameters in a URL's query string and fragment.

    ``?sig=…``, ``X-Amz-Signature=…``, ``#access_token=…`` (the OAuth
    implicit-flow fragment).
    """
    head, hash_, fragment = text.partition("#")
    base, mark, query = head.partition("?")
    out = base + (mark + _redact_pairs(query) if mark else "")
    return out + (hash_ + _redact_pairs(fragment) if hash_ else "")


def _redact_assignment(part: str) -> str:
    """``NAME=value`` (``-e GITHUB_TOKEN=…``, ``--env=API_KEY=…``): redact value.

    The name is the text before the last ``=`` ahead of the value, without
    leading dashes; a part whose ``=`` follows a ``://`` URL is left to
    :func:`_redact_query`.
    """
    eq = part.find("=")
    if eq <= 0 or "://" in part[:eq]:
        return part
    name_end = eq
    # --env=API_KEY=value: the variable name is between the two '='.
    second = part.find("=", eq + 1)
    if part.startswith("-") and second != -1:
        name = part[eq + 1 : second]
        name_end = second
    else:
        name = part[:eq].lstrip("-")
    if _is_secret_name(name):
        return part[: name_end + 1] + "[REDACTED]"
    return part


def _redact_auth_schemes(part: str) -> str:
    """Redact what follows ``Authorization:``, ``Bearer `` or ``Basic ``."""
    lowered = part.lower()
    idx = lowered.find("authorization:")
    if idx != -1:
        return part[: idx + len("authorization:")] + " [REDACTED]"
    for word in _SCHEME_WORDS:
        idx = lowered.find(word)
        if idx != -1:
            return part[: idx + len(word)] + "[REDACTED]"
    return part


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
        pre.append(_redact_auth_schemes(_redact_assignment(_redact_query(part))))
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
    path: Path, budget: _Budget, errors: list[str]
) -> tuple[bool, object | None]:
    """Read *path* as JSON.  Returns ``(exists, parsed-or-None)``.

    At most ``MAX_FILE_BYTES + 1`` bytes are read, so a file that grows
    between checks can't exceed the cap.  ``parsed`` is ``None`` for a file
    that exists but can't be read, is over the size cap or the budget, or
    isn't valid JSON; the reason goes to *errors*.  Never raises.
    """
    try:
        if not path.is_file():
            return (False, None)
        with path.open("rb") as handle:
            data = handle.read(min(MAX_FILE_BYTES, budget.remaining) + 1)
    except OSError as exc:
        errors.append(f"managed policy: cannot read {path}: {type(exc).__name__}")
        return (True, None)
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
            names = sorted(
                p
                for p in dropins.iterdir()
                if p.name.endswith(".json") and not p.name.startswith(".")
            )
            if len(names) > MAX_DROPINS:
                errs.append(
                    f"managed policy: {dropins} has {len(names)} files; only the"
                    f" first {MAX_DROPINS} were read"
                )
            candidates += names[:MAX_DROPINS]
    except OSError as exc:
        errs.append(f"managed policy: cannot list {dropins}: {type(exc).__name__}")
        policy.dropins_unlisted = True

    allowed: dict[tuple, PolicyEntry] | None = None
    denied: dict[tuple, PolicyEntry] = {}
    strict: object = None
    for path in candidates:
        exists, data = _read_json(path, budget, errs)
        if not exists:
            continue
        if not isinstance(data, dict):
            if data is not None:
                errs.append(f"managed policy: {path} is not a JSON object")
            policy.unparsable_files.append(path)
            continue
        policy.settings_files.append(path)

        if data.get("allowedMcpServers", 0) is None:
            policy.allowed_null = True
        elif "allowedMcpServers" in data:
            raw_allowed = data["allowedMcpServers"]
            allowed = {} if allowed is None else allowed
            if isinstance(raw_allowed, list):
                for raw in raw_allowed:
                    entry = _parse_entry(raw, path, allowlist=True)
                    if entry is None:
                        policy.stripped_entries += 1
                    else:
                        allowed.setdefault(entry.key(), entry)
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
                    denied.setdefault(entry.key(), entry)
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
            if isinstance(value, list) and isinstance(strict, list):
                strict = strict + [v for v in value if v not in strict]
            else:
                strict = list(value) if isinstance(value, list) else value
        for key in ("allowAllClaudeAiMcps", "allowClaudeInChromeWithManagedMcp"):
            if key in data and key not in policy.other_mcp_keys:
                policy.other_mcp_keys.append(key)

    policy.strict_plugin_only_mcp, policy.strict_plugin_only_blocks = (
        _strict_plugin_only_mcp(strict)
    )
    if allowed is not None:
        policy.allowed = [] if policy.allowed_invalid_value else list(allowed.values())
    policy.denied = list(denied.values())

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
        parts.append(
            "verdicts withheld (no MANAGED-002/003/004/005): a managed settings"
            " file or the managed-settings.d directory could not be read or"
            " parsed, so mcp-audit can't tell what Claude Code enforces (it"
            " drops a source it can't read and refuses to start on a document"
            " it can't parse)"
        )
    if policy.unparsable_files:
        parts.append(
            "unreadable or invalid managed settings file(s) (Claude Code refuses"
            " to start on a managed document it can't parse): "
            + ", ".join(p.name for p in policy.unparsable_files)
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
        "Claude Code's managed files in "
        f"{policy.directory} set this MCP policy: "
        + "; ".join(parts)
        + "."
        + _SOURCE_CAVEAT,
        "files: " + ", ".join(str(p) for p in files),
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
            " as true, Claude Code 2.1.282 or later)." + _VERDICT_CAVEAT,
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
                    " or later)." + _VERDICT_CAVEAT,
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
        " evaluated)." + extra_note + _VERDICT_CAVEAT,
    )


def _server_shown(server: ServerConfig) -> str:
    if server.url:
        return f"url {_redact(server.url)}"
    if server.command:
        return "command " + _redact_parts([server.command, *server.args])
    return "no command or url"


def _dead_config(server: ServerConfig, verdict: _Verdict) -> Finding:
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
        f" reason: {verdict.reason} | file: {server.config_path}",
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
        " the repository. mcp-audit reads only the managed files: Claude Code"
        " turns the lock on from a true in any admin source (2.1.273 or"
        " later), so an MDM profile or server-managed settings it can't read"
        " may already lock the list.",
        f"file: {allowlist.path} | added: {shown}",
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
        f"serverName entries: {_redact(names)}",
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
        + ", ".join(p.name for p in policy.settings_files)
        + f" in {policy.directory}) but they set none of allowedMcpServers,"
        " deniedMcpServers, allowManagedMcpServersOnly, managedMcpServers or"
        " strictPluginOnlyCustomization for MCP, and there is no"
        " managed-mcp.json. Anthropic: 'By default, anyone running Claude Code"
        " can connect any MCP server they choose', so the organization governs"
        " other settings here but not which MCP servers run." + _SOURCE_CAVEAT,
        "files: " + ", ".join(str(p) for p in policy.settings_files),
        "If MCP servers should be governed, add deniedMcpServers, or"
        " allowedMcpServers with allowManagedMcpServersOnly, to managed settings,"
        " or deploy managed-mcp.json. Reference: " + _DOCS,
        policy.directory,
        ["MCP09"],
        "CWE-1188",
    )


def analyze_managed_policy(
    policy: ManagedPolicy,
    servers: list[ServerConfig],
    configs: list,
    home: Path,
    root: Path | None,
    *,
    machine_findings: bool = True,
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
        machine_findings: Emit MANAGED-001/003/005, which describe the
            machine rather than *servers*; ``scan --project`` passes False
            because the default scan already emitted them.

    Returns:
        MANAGED-001..005 findings; empty when no managed file exists.
    """
    if not policy.present:
        return []
    findings: list[Finding] = []
    if policy.incomplete:
        # A managed source Claude Code can't parse is dropped or stops it from
        # starting; nothing built from the remaining files can be backed.
        return [_inventory(policy)] if machine_findings else []
    if machine_findings:
        findings.append(_inventory(policy))
        if not policy.has_mcp_policy and policy.settings_files:
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
            findings.append(_dead_config(server, verdict))
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
) -> list[Finding]:
    """Read the managed directory and return MANAGED-001..005 findings.

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
    """
    from mcp_audit.discovery import _home  # noqa: PLC0415

    try:
        policy = read_managed_policy(directory, errors)
        return analyze_managed_policy(
            policy,
            servers,
            configs,
            _home(),
            root,
            machine_findings=machine_findings,
        )
    except Exception as exc:  # noqa: BLE001 — never fail the scan over policy files
        errors.append(f"managed policy check error: {type(exc).__name__}: {exc}")
        return []
