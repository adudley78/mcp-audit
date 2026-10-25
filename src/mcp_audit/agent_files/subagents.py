"""Claude Code subagent definitions as a config surface (STORY-0094).

A subagent definition is a Markdown file under ``.claude/agents/`` (project) or
``~/.claude/agents/`` (user), scanned recursively, whose YAML frontmatter can
change how Claude Code runs that subagent. Semantics below are from Anthropic's
sub-agents doc (https://code.claude.com/docs/en/sub-agents), the permissions doc
(https://code.claude.com/docs/en/permissions) and the Claude Code CHANGELOG,
read 2026-10-25:

* ``permissionMode``: ``default``, ``acceptEdits``, ``auto``, ``dontAsk``,
  ``bypassPermissions``, ``plan``, or ``manual`` (alias for ``default``). When
  the main session is in ``default`` or ``dontAsk`` mode the subagent runs in
  the mode it sets, except ``bypassPermissions`` (since v2.1.267 the subagent
  keeps the main session's mode) and ``auto`` when auto mode is unavailable.
  ``dontAsk`` auto-denies anything that would prompt, so it is stricter than
  ``default`` and is never flagged here.
* ``disallowedTools``: an entry with a specifier such as ``Bash(git push *)``
  still removes the whole tool, not only the matching commands.
* ``hooks``: run while the subagent is active. Since v2.1.218 a project
  subagent's frontmatter hooks run only after the folder holding the agent file
  is trusted; before that they ran from untrusted folders.
* ``mcpServers``: a list; each entry is a string naming an already-configured
  server or a one-key mapping ``{name: <.mcp.json-style server entry>}``.
  Inline servers start when the subagent starts. Since v2.1.153 they honour
  ``--strict-mcp-config``, ``--bare`` and managed MCP policy; since v2.1.238 a
  project agent file's inline servers load only after folder trust.
* Plugin subagents ignore ``permissionMode``, ``hooks`` and ``mcpServers``, so
  plugin ``agents/`` directories are not read by this module (GAPS.md).

mcp-audit never runs Claude Code, so it cannot tell which version is installed
(the epic's "harness version-floor table" is out of scope). Where the version
changes the risk, a finding uses the severity that holds on current versions and
states the older-version case in its text.

Parsing is read-only and bounded: at most :data:`MAX_AGENT_FILE_BYTES` are read,
the frontmatter block is capped at :data:`MAX_FRONTMATTER_CHARS`, YAML aliases
are refused (no expansion blow-up), and every value is converted to plain
JSON-compatible types before anything else sees it. Claude Code accepts
frontmatter that strict YAML rejects (an unquoted ``: `` in a description was
fixed to load in v2.1.69), so a document that fails to parse as a whole is
re-read one top-level key at a time; a security-relevant key that still cannot
be read is reported as a problem rather than silently dropped.
"""

from __future__ import annotations

import datetime as _dt
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from mcp_audit.discovery import AGENT_DEFINITION_CLIENT
from mcp_audit.models import Finding, Severity

# ── Limits ────────────────────────────────────────────────────────────────────

#: Bytes read from one agent definition file. The frontmatter sits at the top,
#: so a longer file only loses body text, which is truncated.
MAX_AGENT_FILE_BYTES: int = 1024 * 1024

#: Characters allowed in one frontmatter block before it is refused unparsed.
MAX_FRONTMATTER_CHARS: int = 256 * 1024

#: Nesting depth allowed in parsed frontmatter values.
_MAX_DEPTH: int = 32

#: Frontmatter keys whose values change what the subagent may do. A key in this
#: set that cannot be parsed is reported instead of being dropped.
SECURITY_KEYS: frozenset[str] = frozenset(
    {"permissionMode", "tools", "disallowedTools", "hooks", "mcpServers"}
)

#: Security keys whose value must be a list or mapping; the line-level string
#: fallback is never applied to them (a string there would hide the problem).
_STRUCTURED_KEYS: frozenset[str] = frozenset({"hooks", "mcpServers"})

#: A security key's fallback string that starts with YAML syntax (flow
#: collection, tag, alias, anchor, block scalar) is a parse failure, not a value.
_YAML_SYNTAX_START: tuple[str, ...] = ("[", "{", "!", "*", "&", "|", ">")

#: Version boundaries quoted in finding text (sub-agents doc and CHANGELOG).
BYPASS_FIX_VERSION = "2.1.267"
HOOK_TRUST_FIX_VERSION = "2.1.218"
INLINE_MCP_POLICY_FIX_VERSION = "2.1.153"
INLINE_MCP_TRUST_FIX_VERSION = "2.1.238"

_DOCS_URL = "https://code.claude.com/docs/en/sub-agents"


# ── Frontmatter parsing ───────────────────────────────────────────────────────


class _NoAliasSafeLoader(yaml.SafeLoader):
    """``yaml.SafeLoader`` that refuses aliases.

    Aliases are legal YAML but no real agent definition needs them, and a few
    nested aliases expand exponentially once anything walks or serialises the
    result (rug-pull hashing does). Refusing them keeps parsing linear in the
    input size; a refused block is reported like any other unreadable key.
    """

    def compose_node(self, parent: Any, index: Any) -> Any:  # noqa: ANN401
        """Compose the next node, raising on an alias event."""
        if self.check_event(yaml.AliasEvent):
            event = self.peek_event()
            raise yaml.composer.ComposerError(
                None, None, "YAML aliases are not accepted", event.start_mark
            )
        return super().compose_node(parent, index)


class _TooDeepError(ValueError):
    """Raised when parsed frontmatter nests deeper than :data:`_MAX_DEPTH`."""


def _jsonable(value: object, depth: int = 0) -> Any:  # noqa: ANN401
    """Convert a ``yaml.safe_load`` result to JSON-compatible types.

    Dates become ISO strings, sets become sorted lists, bytes are decoded, and
    mapping keys become strings, so downstream code (hashing, analyzers, JSON
    output) sees the same shapes a JSON config would give it.
    """
    if depth > _MAX_DEPTH:
        raise _TooDeepError("frontmatter nests too deeply")
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, (_dt.date, _dt.datetime)):
        return value.isoformat()
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, dict):
        return {str(k): _jsonable(v, depth + 1) for k, v in value.items()}
    if isinstance(value, (set, frozenset)):
        return sorted((_jsonable(v, depth + 1) for v in value), key=str)
    if isinstance(value, (list, tuple)):
        return [_jsonable(v, depth + 1) for v in value]
    return str(value)


def _load_yaml(text: str) -> Any:  # noqa: ANN401
    """Parse *text* with the alias-refusing safe loader and normalise it."""
    loader = _NoAliasSafeLoader(text)
    try:
        return _jsonable(loader.get_single_data())
    finally:
        loader.dispose()


@dataclass
class AgentFrontmatter:
    """Parsed frontmatter of one agent definition file.

    Attributes:
        data: JSON-compatible frontmatter mapping (empty when absent or unusable).
        body: Markdown after the closing ``---`` (the subagent's system prompt).
        present: ``True`` when the text opens with a frontmatter block.
        problems: Human-readable notes about content that could not be read;
            surfaced in a scan's ``errors`` so nothing is dropped silently.
    """

    data: dict[str, Any] = field(default_factory=dict)
    body: str = ""
    present: bool = False
    problems: list[str] = field(default_factory=list)


def _split_block(text: str) -> tuple[str | None, str]:
    """Return ``(frontmatter_text, body)``; ``frontmatter_text`` is ``None`` if absent.

    The file must open with a ``---`` line (a UTF-8 BOM is tolerated) and the
    block ends at the next line that is exactly ``---``.
    """
    if text.startswith("﻿"):
        text = text[1:]
    lines = text.splitlines(keepends=True)
    if not lines or lines[0].strip() != "---":
        return None, text
    for idx in range(1, len(lines)):
        if lines[idx].strip() == "---":
            return "".join(lines[1:idx]), "".join(lines[idx + 1 :])
    return None, text


_TOP_LEVEL_KEY_RE = re.compile(
    r"""^(?:"([^"]+)"|'([^']+)'|([^\s#'"][^:]*?))\s*:(?=\s|$)"""
)


def _top_level_blocks(block: str) -> list[tuple[str, str]]:
    """Split a frontmatter block into ``(key, text)`` pieces, one per top-level key.

    A top-level key starts at column 0; indented, blank and comment lines belong
    to the key above them.
    """
    pieces: list[tuple[str, list[str]]] = []
    for line in block.splitlines(keepends=True):
        match = _TOP_LEVEL_KEY_RE.match(line) if line[:1] not in (" ", "\t") else None
        if match:
            key = next(g for g in match.groups() if g is not None).strip()
            pieces.append((key, [line]))
        elif pieces:
            pieces[-1][1].append(line)
    return [(key, "".join(lines)) for key, lines in pieces]


def _lenient_scalar(piece: str) -> str | None:
    """Return the raw value of a one-line ``key: value`` piece, or ``None``.

    Mirrors the leniency Claude Code applies to unquoted scalars that contain
    ``: `` (CHANGELOG v2.1.69): the rest of the line is taken as a string.
    """
    content = [
        ln
        for ln in piece.splitlines()
        if ln.strip() and not ln.lstrip().startswith("#")
    ]
    if len(content) != 1:
        return None
    _, _, value = content[0].partition(":")
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        value = value[1:-1]
    return value or None


def parse_agent_frontmatter(text: str) -> AgentFrontmatter:
    """Parse the frontmatter of an agent definition. Never raises.

    Args:
        text: Full file content.

    Returns:
        An :class:`AgentFrontmatter`. ``data`` is empty when the file has no
        frontmatter, when the block is not a mapping, or when it exceeds the
        size cap; ``problems`` explains anything that could not be read.
    """
    block, body = _split_block(text)
    if block is None:
        return AgentFrontmatter(body=text)
    result = AgentFrontmatter(body=body, present=True)
    if len(block) > MAX_FRONTMATTER_CHARS:
        result.problems.append(
            f"frontmatter is larger than {MAX_FRONTMATTER_CHARS:,} characters and"
            " was not parsed"
        )
        return result

    try:
        parsed = _load_yaml(block)
    except (yaml.YAMLError, _TooDeepError):
        parsed = None
    else:
        if parsed is None:
            return result
        if isinstance(parsed, dict):
            result.data = parsed
            return result
        result.problems.append("frontmatter is not a mapping of keys to values")
        return result

    # The whole block failed: read it one top-level key at a time.
    for key, piece in _top_level_blocks(block):
        try:
            value = _load_yaml(piece)
        except (yaml.YAMLError, _TooDeepError) as exc:
            scalar = _lenient_scalar(piece)
            lenient_ok = scalar is not None and not (
                key in _STRUCTURED_KEYS
                or (key in SECURITY_KEYS and scalar.startswith(_YAML_SYNTAX_START))
            )
            if lenient_ok:
                result.data[key] = scalar
            elif key in SECURITY_KEYS:
                reason = str(exc).splitlines()[0] if str(exc) else type(exc).__name__
                result.problems.append(f"could not parse '{key}' ({reason})")
            continue
        if isinstance(value, dict):
            result.data.update(value)
    return result


def read_agent_text(path: Path) -> str:
    """Read at most :data:`MAX_AGENT_FILE_BYTES` of *path* as UTF-8 text.

    Raises:
        OSError: When the file cannot be opened or read.
    """
    with path.open("rb") as fh:
        raw = fh.read(MAX_AGENT_FILE_BYTES)
    return raw.decode("utf-8", errors="replace")


def read_agent_definition(path: Path) -> AgentFrontmatter:
    """Read and parse one agent definition file.

    Raises:
        OSError: When the file cannot be read.
    """
    return parse_agent_frontmatter(read_agent_text(path))


def has_frontmatter(path: Path) -> bool:
    """Return ``True`` when *path* opens with a ``---`` frontmatter line.

    Claude Code loads only Markdown files with frontmatter (``name`` and
    ``description`` are required) as subagents, so a README in an agents
    directory is not a definition. Never raises.
    """
    try:
        with path.open("rb") as fh:
            head = fh.read(8)
    except OSError:
        return False
    return head.removeprefix(b"\xef\xbb\xbf").startswith(b"---")


# ── Field helpers ─────────────────────────────────────────────────────────────


def _split_tool_list(value: object) -> list[str]:
    """Return the entries of a ``tools`` / ``disallowedTools`` value.

    Accepts a YAML list or a comma-separated string; commas inside ``(…)`` do
    not split (``Bash(git push *, git commit *)`` is one entry).
    """
    if isinstance(value, list):
        return [v.strip() for v in value if isinstance(v, str) and v.strip()]
    if not isinstance(value, str):
        return []
    entries: list[str] = []
    depth = 0
    current: list[str] = []
    for ch in value:
        if ch == "(":
            depth += 1
        elif ch == ")" and depth:
            depth -= 1
        if ch == "," and depth == 0:
            entries.append("".join(current))
            current = []
            continue
        current.append(ch)
    entries.append("".join(current))
    return [e.strip() for e in entries if e.strip()]


def inline_mcp_servers(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Return the inline MCP server definitions in a frontmatter mapping.

    ``mcpServers`` is a list. String entries reference servers configured
    elsewhere and are skipped; mapping entries are ``{name: server_entry}``.
    The first definition of a name wins. Any other shape yields nothing.
    """
    entries = data.get("mcpServers")
    if not isinstance(entries, list):
        return {}
    servers: dict[str, dict[str, Any]] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        for name, spec in entry.items():
            if isinstance(spec, dict) and name and name not in servers:
                servers[name] = spec
    return servers


def _scalar_str(value: object) -> str | None:
    """Render a YAML scalar the way a JSON config would spell it."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float, str)):
        return str(value)
    return None


def normalize_server_entry(spec: dict[str, Any]) -> dict[str, Any]:
    """Coerce a YAML server entry's string fields to strings.

    YAML reads ``PORT: 8080`` as an int and ``DEBUG: yes`` as a bool, while
    :class:`~mcp_audit.models.ServerConfig` expects strings. Scalars are
    rendered as text; nested values in ``args``/``env``/``headers`` are dropped.
    """
    out = dict(spec)
    for key in ("command", "url", "type"):
        if key in out:
            rendered = _scalar_str(out[key])
            if rendered is None:
                out.pop(key)
            else:
                out[key] = rendered
    if "args" in out:
        args = out["args"] if isinstance(out["args"], list) else []
        out["args"] = [s for s in (_scalar_str(a) for a in args) if s is not None]
    for key in ("env", "headers"):
        if key in out:
            mapping = out[key] if isinstance(out[key], dict) else {}
            out[key] = {
                str(k): s
                for k, s in ((k, _scalar_str(v)) for k, v in mapping.items())
                if s is not None
            }
    if "capabilities" in out and not isinstance(out["capabilities"], dict):
        out.pop("capabilities")
    return out


def _agent_name(data: dict[str, Any], path: Path) -> str:
    name = data.get("name")
    return name.strip() if isinstance(name, str) and name.strip() else path.stem


def _hook_events(hooks: object) -> list[str]:
    if not isinstance(hooks, dict):
        return []
    return sorted(str(k) for k, v in hooks.items() if v)


def _ambiguous_server_name(name: str) -> bool:
    """``__`` inside, or a trailing ``_``: Claude Code's permissions doc calls both
    out as names that ``mcp__<server>`` rules read as a different server."""
    return "__" in name or name.endswith("_")


# ── Findings ──────────────────────────────────────────────────────────────────


def _finding(
    *,
    finding_id: str,
    severity: Severity,
    path: Path,
    server: str,
    client: str,
    title: str,
    description: str,
    evidence: str,
    remediation: str,
    owasp: list[str],
    cwe: str | None,
) -> Finding:
    return Finding(
        id=finding_id,
        severity=severity,
        analyzer="agent_files",
        client=client,
        server=server,
        title=title,
        description=description,
        evidence=evidence,
        remediation=remediation,
        cwe=cwe,
        owasp_mcp_top_10=owasp,
        finding_path=str(path),
    )


def _check_permission_mode(
    data: dict[str, Any], path: Path, scope: str, client: str
) -> list[Finding]:
    """AGENT-001: a ``permissionMode`` that loosens the main session's prompts."""
    mode = data.get("permissionMode")
    if not isinstance(mode, str):
        return []
    mode = mode.strip()
    name = _agent_name(data, path)
    origin = (
        "a project file that reaches everyone who clones the repository"
        if scope == "project"
        else "your user-level agents directory"
    )
    if mode == "bypassPermissions":
        severity = Severity.MEDIUM if scope == "project" else Severity.LOW
        return [
            _finding(
                finding_id="AGENT-001",
                severity=severity,
                path=path,
                server=path.name,
                client=client,
                title="Subagent asks to skip every permission prompt",
                description=(
                    f"The subagent '{name}' in {path.name} ({origin}) sets"
                    " permissionMode: bypassPermissions. On Claude Code"
                    f" {BYPASS_FIX_VERSION} and later a subagent runs in"
                    " bypassPermissions only when your main session already does,"
                    " so from a default-mode session the setting is ignored. On"
                    f" earlier versions the subagent skipped every prompt even when"
                    " your session asked for them, which is HIGH. mcp-audit does not"
                    " run Claude Code and cannot see which version you have."
                ),
                evidence=f"{path}: permissionMode = bypassPermissions",
                remediation=(
                    "Remove permissionMode or set it to 'default'. Keep Claude Code"
                    f" at {BYPASS_FIX_VERSION} or later, and set"
                    ' permissions.disableBypassPermissionsMode to "disable" in user'
                    " or managed settings to refuse bypass everywhere."
                ),
                owasp=["MCP02", "MCP07"],
                cwe="CWE-862",
            )
        ]
    if scope == "project" and mode in ("acceptEdits", "auto"):
        effect = (
            "accepts file edits and common filesystem commands (mkdir, touch, mv,"
            " cp) in the working directory without asking"
            if mode == "acceptEdits"
            else "runs without routine prompts, with a background classifier"
            " deciding instead of you"
        )
        return [
            _finding(
                finding_id="AGENT-001",
                severity=Severity.MEDIUM,
                path=path,
                server=path.name,
                client=client,
                title=f"Project subagent loosens permission prompts ({mode})",
                description=(
                    f"The subagent '{name}' in {path.name} ({origin}) sets"
                    f" permissionMode: {mode}. When your main session is in default"
                    " (Manual) or dontAsk mode, Claude Code runs this subagent in"
                    f" {mode}: it {effect}. Any task Claude delegates to it gets"
                    " fewer prompts than the session you chose."
                ),
                evidence=f"{path}: permissionMode = {mode}",
                remediation=(
                    "Remove permissionMode from the project subagent so it inherits"
                    " your session's mode, or move the subagent to"
                    " ~/.claude/agents/ if you want it for yourself only."
                ),
                owasp=["MCP02", "MCP07"],
                cwe="CWE-862",
            )
        ]
    return []


def _check_disallowed_specifiers(
    data: dict[str, Any], path: Path, client: str
) -> list[Finding]:
    """AGENT-002 (INFO): a ``disallowedTools`` specifier removes the whole tool."""
    entries = [e for e in _split_tool_list(data.get("disallowedTools")) if "(" in e]
    if not entries:
        return []
    tools = sorted({e.split("(", 1)[0].strip() for e in entries})
    name = _agent_name(data, path)
    return [
        _finding(
            finding_id="AGENT-002",
            severity=Severity.INFO,
            path=path,
            server=path.name,
            client=client,
            title="disallowedTools specifier removes the whole tool",
            description=(
                f"The subagent '{name}' lists {', '.join(repr(e) for e in entries)}"
                " in disallowedTools. Claude Code ignores the part in parentheses:"
                f" the entry removes the whole tool ({', '.join(tools)}) from the"
                " subagent, not only the matching calls. If you meant to block only"
                " those calls, the subagent has lost more than you intended; if you"
                " later re-add the tool elsewhere, nothing blocks the calls."
            ),
            evidence=f"{path}: disallowedTools = {', '.join(entries)}",
            remediation=(
                "To block specific calls and keep the tool, add the same rule (for"
                " example Bash(git push *)) to permissions.deny in settings."
                " To remove the tool, list its bare name."
            ),
            owasp=["MCP02"],
            cwe=None,
        )
    ]


def _check_hooks_presence(
    data: dict[str, Any], path: Path, scope: str, client: str
) -> list[Finding]:
    """AGENT-003: the subagent defines frontmatter hooks."""
    events = _hook_events(data.get("hooks"))
    if not events:
        return []
    name = _agent_name(data, path)
    if scope == "project":
        severity = Severity.MEDIUM
        when = (
            f" Since Claude Code {HOOK_TRUST_FIX_VERSION} a project subagent's"
            " frontmatter hooks run only after the folder holding the agent file is"
            " trusted, and not in a `claude -p` run in an untrusted folder; before"
            f" {HOOK_TRUST_FIX_VERSION} they ran from folders you had not trusted,"
            " which is HIGH. After you trust the repository, these commands run"
            " with no further prompt."
        )
    else:
        severity = Severity.INFO
        when = " Hooks in your own ~/.claude/agents/ files run without a trust step."
    return [
        _finding(
            finding_id="AGENT-003",
            severity=severity,
            path=path,
            server=path.name,
            client=client,
            title="Subagent defines hooks that run shell commands",
            description=(
                f"The subagent '{name}' in {path.name} defines hooks for"
                f" {', '.join(events)}. Claude Code runs them while this subagent is"
                " active (a Stop hook becomes SubagentStop)." + when + " Each hook"
                " command is also checked by HOOK-001 (network egress) and HOOK-002"
                " (references to agent config files)."
            ),
            evidence=f"{path}: hooks = {', '.join(events)}",
            remediation=(
                "Read every hook command in this file before trusting the folder."
                " Remove hooks you did not add. To stop all hooks for one run, pass"
                " --settings '{\"disableAllHooks\": true}'."
            ),
            owasp=["MCP05", "MCP07"],
            cwe="CWE-78",
        )
    ]


def _check_inline_servers(
    data: dict[str, Any], path: Path, scope: str, client: str
) -> list[Finding]:
    """AGENT-004: inline MCP servers (INFO); LOW for a name ``mcp__`` rules misread."""
    findings: list[Finding] = []
    agent = _agent_name(data, path)
    trust = (
        f" Since {INLINE_MCP_TRUST_FIX_VERSION}, Claude Code starts a project agent"
        " file's inline servers only after that folder is trusted; earlier"
        " versions did not check."
        if scope == "project"
        else ""
    )
    for server_name in inline_mcp_servers(data):
        ambiguous = _ambiguous_server_name(server_name)
        description = (
            f"The subagent '{agent}' in {path.name} declares the MCP server"
            f" '{server_name}' inline. It is not in .mcp.json or a client config:"
            " Claude Code starts it when Claude delegates to this subagent and stops"
            " it when the subagent finishes. mcp-audit scans it as client"
            f" {AGENT_DEFINITION_CLIENT}, so its other findings appear under that"
            f" client. Claude Code {INLINE_MCP_POLICY_FIX_VERSION} and later apply"
            " --strict-mcp-config, --bare and managed MCP allow/deny policies to it;"
            " earlier versions did not." + trust
        )
        remediation = (
            "Check the server's command or URL the way you would a .mcp.json entry."
            " To share one connection with the main session instead, define the"
            " server once and list it here by name."
        )
        if ambiguous:
            short = server_name.split("__", 1)[0] if "__" in server_name else None
            short_note = (
                f" Claude Code reads 'mcp__{server_name}' and 'mcp__{short}' as rules"
                f" for a server named '{short}'."
                if short
                else ""
            )
            description += (
                " Its name contains '__' or ends in '_', which Claude Code's"
                " permissions doc calls out: permission rules that name it by its"
                " short form don't match its tools as allow rules, and as deny or ask"
                " rules they can also cover another server." + short_note
            )
            remediation = (
                f"Write rules for this server as mcp__{server_name}__* (the whole"
                " name plus the wildcard), or rename it without '__' or a trailing"
                " '_'. " + remediation
            )
        findings.append(
            _finding(
                finding_id="AGENT-004",
                severity=Severity.LOW if ambiguous else Severity.INFO,
                path=path,
                server=server_name,
                client=client,
                title=(
                    "Subagent MCP server name is ambiguous in mcp__ rules"
                    if ambiguous
                    else "Subagent declares its own MCP server"
                ),
                description=description,
                evidence=f"{path}: mcpServers -> {server_name}",
                remediation=remediation,
                owasp=["MCP09"],
                cwe=None,
            )
        )
    return findings


def analyze_agent_definition(
    data: dict[str, Any], path: Path, scope: str, client: str = AGENT_DEFINITION_CLIENT
) -> list[Finding]:
    """Return AGENT-001..004 for one subagent definition's frontmatter.

    HOOK-001/002 on the frontmatter's hook commands are not produced here; they
    belong to :class:`~mcp_audit.analyzers.config_hygiene.ConfigHygieneAnalyzer`
    (see its ``analyze_agent_definition``), which calls this function.

    Args:
        data: JSON-compatible frontmatter (from :func:`parse_agent_frontmatter`).
        path: The agent definition file.
        scope: ``"project"`` for a repository's ``.claude/agents/`` and
            ``"user"`` for ``~/.claude/agents/``.
        client: Client name for the findings.

    Returns:
        Findings in ID order. Empty when the frontmatter changes nothing.
    """
    if not isinstance(data, dict) or not data:
        return []
    return [
        *_check_permission_mode(data, path, scope, client),
        *_check_disallowed_specifiers(data, path, client),
        *_check_hooks_presence(data, path, scope, client),
        *_check_inline_servers(data, path, scope, client),
    ]


__all__ = [
    "AGENT_DEFINITION_CLIENT",
    "MAX_AGENT_FILE_BYTES",
    "MAX_FRONTMATTER_CHARS",
    "SECURITY_KEYS",
    "AgentFrontmatter",
    "analyze_agent_definition",
    "has_frontmatter",
    "inline_mcp_servers",
    "normalize_server_entry",
    "parse_agent_frontmatter",
    "read_agent_definition",
    "read_agent_text",
]
