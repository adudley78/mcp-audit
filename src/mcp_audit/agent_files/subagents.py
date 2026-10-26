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
  Claude Code starts every mapping entry, repeated names included. Since
  v2.1.153 they honour ``--strict-mcp-config``, ``--bare`` and managed MCP
  policy; since v2.1.238 a project agent file's inline servers load only after
  folder trust.
* Plugin subagents ignore ``permissionMode``, ``hooks`` and ``mcpServers``, so
  plugin ``agents/`` directories are not read by this module (GAPS.md).

mcp-audit never runs Claude Code, so it cannot tell which version is installed
(the epic's "harness version-floor table" is out of scope). Where the version
changes the risk, a finding uses the severity that holds on current versions and
states the older-version case in its text.

How the frontmatter is read follows Claude Code's own loader, described from
its behaviour (no code taken):

* Files over 1 MiB are skipped, as Claude Code skips them. A leading BOM is
  dropped. The frontmatter is the text between an opening ``---`` and the
  **first** ``---`` anywhere after it, even mid-line (``# ---`` ends it).
* The block is parsed as YAML; if that fails, one-line ``key: value`` entries
  whose value holds YAML syntax characters or ``": "`` are quoted, leading tabs
  become two spaces each, and the whole block is parsed again.

mcp-audit also reads the block ending at the first line that is exactly
``---`` (the conventional reading), and keeps the findings of both. A
security-relevant top-level key (``permissionMode``, ``tools``,
``disallowedTools``, ``hooks``, ``mcpServers``) that appears more than once is
reported, and every one of its values is checked. YAML aliases are resolved
under a value budget; nesting deeper than :data:`MAX_NESTING`, more than
:data:`MAX_YAML_NODES` nodes, or a block that cannot be parsed makes the
frontmatter unreadable, and every security-relevant key it names is reported
as present but unreadable rather than dropped.
"""

from __future__ import annotations

import datetime as _dt
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from mcp_audit.analyzers.credentials import SECRET_PATTERNS
from mcp_audit.discovery import AGENT_DEFINITION_CLIENT
from mcp_audit.models import Finding, Severity

# ── Limits ────────────────────────────────────────────────────────────────────

#: Largest agent definition Claude Code loads (its Markdown loader skips bigger
#: files); mcp-audit skips them too and says so in the scan's errors.
MAX_AGENT_FILE_BYTES: int = 1024 * 1024

#: Deepest nesting composed. PyYAML recurses per level and fails between 400
#: and 500 levels; anything deeper than this is reported as unreadable.
MAX_NESTING: int = 256

#: YAML nodes composed per file, across every reading of it. Keeps one hostile
#: file to well under a second; legitimate frontmatter has a few hundred.
MAX_YAML_NODES: int = 20_000

#: Values produced per reading once aliases are resolved (alias bomb guard).
MAX_EXPANDED_VALUES: int = 100_000

#: Per-scan (per discovery pass) budgets for subagent definitions.
MAX_AGENT_DEFINITIONS_PER_SCAN: int = 500
MAX_AGENT_BYTES_PER_SCAN: int = 16 * 1024 * 1024

#: Deepest value kept after construction.
_MAX_VALUE_DEPTH: int = 64

#: Frontmatter keys whose values change what the subagent may do.
SECURITY_KEYS: frozenset[str] = frozenset(
    {"permissionMode", "tools", "disallowedTools", "hooks", "mcpServers"}
)

#: Version boundaries quoted in finding text (sub-agents doc and CHANGELOG).
BYPASS_FIX_VERSION = "2.1.267"
HOOK_TRUST_FIX_VERSION = "2.1.218"
INLINE_MCP_POLICY_FIX_VERSION = "2.1.153"
INLINE_MCP_TRUST_FIX_VERSION = "2.1.238"

_REDACTED = "[REDACTED]"
_RECORD_KIND = "mcp-audit/subagent-definition"
_THIRD_PARTY_NOTE = (
    " Agent collections copied from other people into ~/.claude/agents/ run"
    " this way too, with no trust step."
)


def redact_secrets(text: str) -> str:
    """Replace anything matching a known credential pattern with ``[REDACTED]``."""
    for _label, pattern, _provider in SECRET_PATTERNS:
        text = pattern.sub(_REDACTED, text)
    return text


# ── YAML loading with budgets ─────────────────────────────────────────────────


class _LimitError(Exception):
    """An mcp-audit parsing limit was reached (not a YAML syntax error)."""


class _Budget:
    """A countdown that raises :class:`_LimitError` when spent."""

    def __init__(self, amount: int, what: str) -> None:
        self.amount = amount
        self.left = amount
        self.what = what

    def spend(self, n: int = 1) -> None:
        """Spend *n* units; raise when the budget goes negative."""
        self.left -= n
        if self.left < 0:
            raise _LimitError(f"more than {self.amount:,} {self.what}")


# YAML 1.1's "=" value tag makes PyYAML refuse a plain "=" scalar, and its
# timestamp tag turns dates into objects; Claude Code's YAML 1.2 parser reads
# both as strings, so both resolvers are dropped.
_DROPPED_TAGS = frozenset({"tag:yaml.org,2002:value", "tag:yaml.org,2002:timestamp"})


class _Loader(yaml.SafeLoader):
    """``SafeLoader`` that charges every composed node to a budget."""

    yaml_implicit_resolvers = {
        first: [(tag, rx) for tag, rx in resolvers if tag not in _DROPPED_TAGS]
        for first, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
    }

    def __init__(self, stream: str, budget: _Budget) -> None:
        super().__init__(stream)
        self._budget = budget

    def compose_node(self, parent: Any, index: Any) -> Any:  # noqa: ANN401
        """Compose the next node after charging it to the budget."""
        self._budget.spend()
        return super().compose_node(parent, index)


def _nesting_estimate(text: str) -> int:
    """Upper bound on the nesting depth of a YAML text, computed linearly.

    Per line: twice the indentation (compact sequences can nest without extra
    indentation), plus leading ``- ``/``? ``/``: `` indicators, plus open flow
    brackets carried across lines. Brackets inside quotes count too, which only
    ever overestimates.
    """
    best = 0
    flow = 0
    for line in text.split("\n"):
        i = 0
        n = len(line)
        while i < n and line[i] in " \t":
            i += 1
        depth = 2 * i
        while i < n and line[i] in "-?:" and (i + 1 == n or line[i + 1] in " \t"):
            depth += 1
            i += 1
            while i < n and line[i] in " \t":
                i += 1
        for ch in line[i:]:
            if ch in "[{":
                flow += 1
                best = max(best, depth + flow)
            elif ch in "]}" and flow:
                flow -= 1
        best = max(best, depth + flow)
    return best


def _jsonable(value: object, depth: int, budget: _Budget) -> Any:  # noqa: ANN401
    """Convert a constructed YAML value to JSON-compatible types under *budget*.

    Aliases were constructed as shared references; walking them here is where
    an alias bomb would expand, so every value is charged to *budget*.
    """
    budget.spend()
    if depth > _MAX_VALUE_DEPTH:
        raise _LimitError(f"values nested more than {_MAX_VALUE_DEPTH} levels deep")
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, (_dt.date, _dt.datetime)):
        return value.isoformat()
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, dict):
        return {str(k): _jsonable(v, depth + 1, budget) for k, v in value.items()}
    if isinstance(value, (set, frozenset)):
        return sorted((_jsonable(v, depth + 1, budget) for v in value), key=str)
    if isinstance(value, (list, tuple)):
        return [_jsonable(v, depth + 1, budget) for v in value]
    return str(value)


def _repeated_security_keys(node: Any) -> dict[str, list[Any]]:  # noqa: ANN401
    """Top-level security keys that appear more than once, with their value nodes."""
    if not isinstance(node, yaml.MappingNode):
        return {}
    seen: dict[str, list[Any]] = {}
    for key_node, value_node in node.value:
        if isinstance(key_node, yaml.ScalarNode) and key_node.value in SECURITY_KEYS:
            seen.setdefault(key_node.value, []).append(value_node)
    return {key: nodes for key, nodes in seen.items() if len(nodes) > 1}


def _load(text: str, budget: _Budget) -> tuple[Any, dict[str, list[Any]]]:
    """Parse *text*; return ``(value, {repeated_key: [values]})``.

    Raises:
        yaml.YAMLError: The text is not valid YAML.
        _LimitError: A nesting, node or value budget was exceeded.
    """
    if _nesting_estimate(text) > MAX_NESTING:
        raise _LimitError(f"nesting deeper than {MAX_NESTING} levels")
    loader = _Loader(text, budget)
    try:
        node = loader.get_single_node()
        if node is None:
            return None, {}
        repeated_nodes = _repeated_security_keys(node)
        expand = _Budget(MAX_EXPANDED_VALUES, "values after resolving aliases")
        value = _jsonable(loader.construct_document(node), 0, expand)
        repeats = {
            key: [_jsonable(loader.construct_document(v), 0, expand) for v in nodes]
            for key, nodes in repeated_nodes.items()
        }
    except RecursionError as exc:
        raise _LimitError("nesting too deep for the YAML parser") from exc
    finally:
        loader.dispose()
    return value, repeats


# Claude Code's lenient retry: a one-line `key: value` whose value holds YAML
# syntax characters (or ": ") is re-written as a double-quoted string.
_LOSSY_LINE = re.compile(r"([a-zA-Z_-]+):\s+(\S[^\r\n  ]*)")
_LOSSY_CHARS = re.compile(r"[{}\[\]*&#!|>%@`]|: ")


def _quote_lossy_values(text: str, budget: _Budget) -> str:
    """Quote one-line values the way Claude Code does before its second parse."""
    out: list[str] = []
    for line in text.split("\n"):
        match = _LOSSY_LINE.fullmatch(line)
        if match:
            key, value = match.group(1), match.group(2)
            quoted = value[0] == value[-1] and value[0] in "\"'"
            if not quoted and value.startswith("[") and value.endswith("]"):
                try:
                    quoted = isinstance(_load(value, budget)[0], list)
                except (yaml.YAMLError, _LimitError):
                    quoted = False
            if not quoted and _LOSSY_CHARS.search(value):
                escaped = value.replace("\\", "\\\\").replace('"', '\\"')
                line = f'{key}: "{escaped}"'
        out.append(line)
    return "\n".join(out)


def _tabs_to_spaces(text: str) -> str:
    """Replace each leading tab on every line with two spaces."""
    return re.sub(r"^\t+", lambda m: "  " * len(m.group(0)), text, flags=re.M)


def _yaml_reason(exc: yaml.YAMLError) -> str:
    """One short line describing a YAML error (no document excerpt)."""
    problem = getattr(exc, "problem", None) or str(exc).splitlines()[0]
    return redact_secrets(str(problem))[:160]


@dataclass
class _Block:
    """One parsed frontmatter block."""

    data: dict[str, Any] | None
    repeats: dict[str, list[Any]] = field(default_factory=dict)
    error: str | None = None
    not_mapping: bool = False


def _read_block(text: str, budget: _Budget) -> _Block:
    """Parse a frontmatter block, retrying the way Claude Code does on failure."""
    try:
        value, repeats = _load(text, budget)
    except _LimitError as exc:
        return _Block(None, error=str(exc))
    except yaml.YAMLError as first:
        error = _yaml_reason(first)
        # Claude Code's retry pattern does not match a line ending in "\r", so
        # a file checked out with CRLF endings (Windows) is not rescued, while
        # the same committed file checked out with LF endings is. Try both.
        for source in dict.fromkeys((text, text.replace("\r\n", "\n"))):
            retry = _tabs_to_spaces(_quote_lossy_values(source, budget))
            if retry == text:
                continue
            try:
                value, repeats = _load(retry, budget)
                break
            except _LimitError as exc:
                return _Block(None, error=str(exc))
            except yaml.YAMLError as exc:
                error = _yaml_reason(exc)
        else:
            return _Block(None, error=error)
    if value is None:
        return _Block({})
    if not isinstance(value, dict):
        return _Block(None, not_mapping=True)
    return _Block(value, repeats)


_SECURITY_KEY_TOKEN = re.compile(
    r"(?:^|[{,])[ \t]*(?:"
    r"\?[ \t]+[\"']?(permissionMode|tools|disallowedTools|hooks|mcpServers)"
    r"[\"']?[ \t]*\r?$"
    r"|[\"']?(permissionMode|tools|disallowedTools|hooks|mcpServers)[\"']?[ \t]*:)",
    re.M,
)


def _security_keys_named_in(text: str) -> list[str]:
    """Security keys that appear as a mapping key anywhere in *text*."""
    found = {m.group(1) or m.group(2) for m in _SECURITY_KEY_TOKEN.finditer(text)}
    return sorted(found)


# ── Splitting the frontmatter ─────────────────────────────────────────────────

# Claude Code's split: opening "---" at the very start, then everything up to
# the first "---" anywhere (mid-line included).
_CLAUDE_CODE_SPLIT = re.compile(r"---\s*\n([\s\S]*?)---\s*\n?")


def _split_claude_code(text: str) -> tuple[str | None, str]:
    """Return ``(block, body)`` as Claude Code splits them; no block -> None."""
    if text.find("---", 3) < 0:
        return None, text
    match = _CLAUDE_CODE_SPLIT.match(text)
    if match is None:
        return None, text
    return match.group(1), text[match.end() :]


def _is_delimiter_line(line: str) -> bool:
    return line.rstrip("\r").rstrip(" \t") == "---"


def _split_lines(text: str) -> str | None:
    """Return the block between an opening ``---`` line and the next ``---`` line."""
    lines = text.split("\n")
    if not _is_delimiter_line(lines[0]):
        return None
    for idx in range(1, len(lines)):
        if _is_delimiter_line(lines[idx]):
            return "\n".join(lines[1:idx])
    return None


# ── Parsed definition ─────────────────────────────────────────────────────────


@dataclass
class AgentFrontmatter:
    """Everything mcp-audit read from one agent definition's frontmatter.

    Attributes:
        readings: Distinct JSON-compatible frontmatter mappings: Claude Code's
            split first, then the line-delimited split when it differs, plus
            one variant per value of a repeated security key.
        body: Text after Claude Code's frontmatter (the subagent's prompt).
        present: ``True`` when the file opens with frontmatter as Claude Code
            reads it.
        unreadable_keys: Security keys the frontmatter names but mcp-audit
            could not read (Claude Code may still load them).
        unreadable_reason: Why the frontmatter could not be read.
        repeated_keys: Security key → how many times it appears.
        problems: Notes for the scan's ``errors``.
    """

    readings: list[dict[str, Any]] = field(default_factory=list)
    body: str = ""
    present: bool = False
    unreadable_keys: list[str] = field(default_factory=list)
    unreadable_reason: str | None = None
    repeated_keys: dict[str, int] = field(default_factory=dict)
    problems: list[str] = field(default_factory=list)

    @property
    def data(self) -> dict[str, Any]:
        """The reading Claude Code loads (empty when none)."""
        return self.readings[0] if self.readings else {}

    def to_record(self) -> dict[str, Any]:
        """JSON-compatible form carried in ``DiscoveredConfig.raw``."""
        return {
            "$kind": _RECORD_KIND,
            "readings": self.readings,
            "unreadable_keys": self.unreadable_keys,
            "unreadable_reason": self.unreadable_reason,
            "repeated_keys": self.repeated_keys,
        }

    @classmethod
    def from_record(cls, raw: object) -> AgentFrontmatter | None:
        """Rebuild from :meth:`to_record` output; ``None`` for anything else."""
        if not isinstance(raw, dict) or raw.get("$kind") != _RECORD_KIND:
            return None
        readings = [r for r in raw.get("readings") or [] if isinstance(r, dict)]
        unreadable = [k for k in raw.get("unreadable_keys") or [] if k in SECURITY_KEYS]
        repeated = raw.get("repeated_keys") or {}
        reason = raw.get("unreadable_reason")
        return cls(
            readings=readings,
            present=True,
            unreadable_keys=unreadable,
            unreadable_reason=reason if isinstance(reason, str) else None,
            repeated_keys={
                k: int(v)
                for k, v in repeated.items()
                if k in SECURITY_KEYS and isinstance(v, int)
            },
        )

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> AgentFrontmatter:
        """Wrap one already-parsed frontmatter mapping as a single reading."""
        return cls(readings=[data] if data else [], present=True)


def parse_agent_frontmatter(text: str) -> AgentFrontmatter:
    """Read an agent definition's frontmatter. Never raises.

    Args:
        text: Full file content.

    Returns:
        An :class:`AgentFrontmatter` (see the module docstring for the rules).
    """
    if text.startswith("﻿"):
        text = text[1:]
    cc_block, body = _split_claude_code(text)
    if cc_block is None:
        return AgentFrontmatter(body=text)
    result = AgentFrontmatter(body=body, present=True)
    budget = _Budget(MAX_YAML_NODES, "YAML nodes")
    seen: set[str] = set()

    def _add(reading: dict[str, Any]) -> None:
        key = json.dumps(reading, sort_keys=True)
        if key not in seen:
            seen.add(key)
            result.readings.append(reading)

    def _take(block: _Block) -> None:
        if block.data is None:
            return
        _add(block.data)
        for key, values in block.repeats.items():
            result.repeated_keys[key] = max(
                result.repeated_keys.get(key, 0), len(values)
            )
            for value in values:
                _add({**block.data, key: value})

    primary = _read_block(cc_block, budget)
    if primary.error is not None:
        result.unreadable_keys = _security_keys_named_in(cc_block)
        result.unreadable_reason = primary.error
        named = (
            f"; it names {', '.join(result.unreadable_keys)}"
            if result.unreadable_keys
            else ""
        )
        result.problems.append(
            f"the frontmatter could not be read ({primary.error}){named}"
        )
    elif primary.not_mapping:
        result.problems.append("the frontmatter is not a mapping of keys to values")
    else:
        _take(primary)

    line_block = _split_lines(text)
    if line_block is not None and line_block.strip() != cc_block.strip():
        secondary = _read_block(line_block, budget)
        if secondary.data is not None:
            _take(secondary)
    return result


def read_agent_text(path: Path) -> str | None:
    """Read *path* as UTF-8 text, or ``None`` when it is over the size cap.

    Raises:
        OSError: When the file cannot be opened or read.
    """
    with path.open("rb") as fh:
        raw = fh.read(MAX_AGENT_FILE_BYTES + 1)
    if len(raw) > MAX_AGENT_FILE_BYTES:
        return None
    return raw.decode("utf-8", errors="replace")


def _too_large(path: Path) -> str:
    return (
        f"Subagent definition {path} is larger than {MAX_AGENT_FILE_BYTES:,} bytes;"
        " Claude Code skips files this large, so mcp-audit did too."
    )


def read_agent_definition(path: Path) -> AgentFrontmatter:
    """Read and parse one agent definition file.

    Raises:
        OSError: When the file cannot be read.
    """
    text = read_agent_text(path)
    if text is None:
        return AgentFrontmatter(problems=[_too_large(path)])
    return parse_agent_frontmatter(text)


def has_frontmatter(path: Path) -> bool:
    """Return ``True`` when *path* opens with ``---`` (cheap pre-filter, no raise)."""
    try:
        with path.open("rb") as fh:
            head = fh.read(8)
    except OSError:
        return False
    return head.removeprefix(b"\xef\xbb\xbf").startswith(b"---")


def select_agent_definitions(
    paths: list[Path], errors: list[str] | None = None
) -> list[Path]:
    """Keep the candidates that are definitions, within the per-scan budgets.

    Drops files without frontmatter and files over 1 MiB (Claude Code skips
    them); stops after :data:`MAX_AGENT_DEFINITIONS_PER_SCAN` files or
    :data:`MAX_AGENT_BYTES_PER_SCAN` bytes. Every skip except "no frontmatter"
    is reported in *errors*. Never raises.
    """
    chosen: list[Path] = []
    total = 0
    report = errors.append if errors is not None else (lambda _msg: None)
    for index, path in enumerate(paths):
        try:
            size = path.stat().st_size
        except OSError as exc:
            report(f"Could not read subagent definition {path}: {exc}")
            continue
        if size > MAX_AGENT_FILE_BYTES:
            report(_too_large(path))
            continue
        if not has_frontmatter(path):
            continue
        if (
            len(chosen) >= MAX_AGENT_DEFINITIONS_PER_SCAN
            or total + size > MAX_AGENT_BYTES_PER_SCAN
        ):
            report(
                f"Stopped reading subagent definitions after {len(chosen)} files"
                f" ({total:,} bytes), the per-scan budget;"
                f" {len(paths) - index} more candidate(s) were not checked."
            )
            break
        chosen.append(path)
        total += size
    return chosen


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


def _mapping_entries(reading: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """The ``mcpServers`` items Claude Code starts: one-key mappings to a mapping."""
    entries = reading.get("mcpServers")
    if not isinstance(entries, list):
        return []
    out: list[tuple[str, dict[str, Any]]] = []
    for entry in entries:
        if isinstance(entry, dict) and len(entry) == 1:
            ((name, spec),) = entry.items()
            if name and isinstance(spec, dict):
                out.append((name, spec))
    return out


def agent_mcp_servers(
    definition: AgentFrontmatter | dict[str, Any],
) -> list[tuple[str, str, dict[str, Any]]]:
    """Every inline MCP server Claude Code would start, across all readings.

    One item per ``mcpServers`` mapping entry (string entries reference servers
    configured elsewhere). A repeated name keeps every item, renamed ``fs``,
    ``fs#2``, ``fs#3``…; the same item seen in two readings counts once.

    Returns:
        ``(display_name, declared_name, spec)`` tuples in order.
    """
    if isinstance(definition, dict):
        definition = AgentFrontmatter.from_mapping(definition)
    out: list[tuple[str, str, dict[str, Any]]] = []
    seen: set[tuple[str, str, int]] = set()
    used: set[str] = set()
    per_name: dict[str, int] = {}
    for reading in definition.readings:
        copies: dict[tuple[str, str], int] = {}
        for name, spec in _mapping_entries(reading):
            spec_key = json.dumps(spec, sort_keys=True)
            copies[(name, spec_key)] = copies.get((name, spec_key), 0) + 1
            identity = (name, spec_key, copies[(name, spec_key)])
            if identity in seen:
                continue
            seen.add(identity)
            display = name
            while display in used:
                per_name[name] = per_name.get(name, 1) + 1
                display = f"{name}#{per_name[name]}"
            used.add(display)
            out.append((display, name, spec))
    return out


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


def _agent_name(definition: AgentFrontmatter, path: Path) -> str:
    name = definition.data.get("name")
    return name.strip() if isinstance(name, str) and name.strip() else path.stem


def _hook_events(hooks: object) -> list[str]:
    if not isinstance(hooks, dict):
        return []
    return sorted(str(k) for k, v in hooks.items() if v)


def _ambiguous_server_name(name: str) -> bool:
    """``__`` inside, or a trailing ``_``: Claude Code's permissions doc calls both
    out as names that ``mcp__<server>`` rules read as a different server."""
    return "__" in name or name.endswith("_")


def lock_root_for(path: Path) -> Path | None:
    """The ``mcp-lock.json`` that would cover *path*, or ``None``. Never raises."""
    from mcp_audit.lock.discovery import find_lock_for  # noqa: PLC0415

    try:
        return find_lock_for(path)
    except (OSError, RuntimeError):
        return None


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
    reading: dict[str, Any], name: str, path: Path, scope: str, client: str
) -> list[Finding]:
    """AGENT-001: a ``permissionMode`` that loosens the main session's prompts."""
    mode = reading.get("permissionMode")
    if not isinstance(mode, str):
        return []
    mode = mode.strip()
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
                    " earlier versions the subagent skipped every prompt even when"
                    " your session asked for them, which is HIGH. mcp-audit does not"
                    " run Claude Code and cannot see which version you have."
                    + ("" if scope == "project" else _THIRD_PARTY_NOTE)
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
    reading: dict[str, Any], name: str, path: Path, client: str
) -> list[Finding]:
    """AGENT-002 (INFO): a ``disallowedTools`` specifier removes the whole tool."""
    entries = [e for e in _split_tool_list(reading.get("disallowedTools")) if "(" in e]
    if not entries:
        return []
    tools = sorted({e.split("(", 1)[0].strip() for e in entries})
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
    reading: dict[str, Any], name: str, path: Path, scope: str, client: str
) -> list[Finding]:
    """AGENT-003: the subagent defines frontmatter hooks."""
    events = _hook_events(reading.get("hooks"))
    if not events:
        return []
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
        when = (
            " Hooks in your own ~/.claude/agents/ files run without a trust step."
            + _THIRD_PARTY_NOTE
        )
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
    definition: AgentFrontmatter, name: str, path: Path, scope: str, client: str
) -> list[Finding]:
    """AGENT-004: inline MCP servers (INFO); LOW for a name ``mcp__`` rules
    misread; MEDIUM for a project server under an ``mcp-lock.json``."""
    servers = agent_mcp_servers(definition)
    if not servers:
        return []
    lock = lock_root_for(path) if scope == "project" else None
    findings: list[Finding] = []
    trust = (
        f" Since {INLINE_MCP_TRUST_FIX_VERSION}, Claude Code starts a project agent"
        " file's inline servers only after that folder is trusted; earlier"
        " versions did not check."
        if scope == "project"
        else ""
    )
    for display, declared, _spec in servers:
        ambiguous = _ambiguous_server_name(declared)
        repeat = (
            f" (another server in this file has the same name '{declared}'; Claude"
            " Code starts both, so mcp-audit scans this one as"
            f" '{display}')"
            if display != declared
            else ""
        )
        description = (
            f"The subagent '{name}' in {path.name} declares the MCP server"
            f" '{declared}' inline{repeat}. It is not in .mcp.json or a client"
            " config: Claude Code starts it when Claude delegates to this subagent"
            " and stops it when the subagent finishes. mcp-audit scans it as client"
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
        title = "Subagent declares its own MCP server"
        severity = Severity.INFO
        if ambiguous:
            short = declared.split("__", 1)[0] if "__" in declared else None
            short_note = (
                f" Claude Code reads 'mcp__{declared}' and 'mcp__{short}' as rules"
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
                f"Write rules for this server as mcp__{declared}__* (the whole"
                " name plus the wildcard), or rename it without '__' or a trailing"
                " '_'. " + remediation
            )
            title = "Subagent MCP server name is ambiguous in mcp__ rules"
            severity = Severity.LOW
        if lock is not None:
            description += (
                f" This repository has an mcp-lock.json ({lock}), but subagent"
                " servers are never recorded in it or verified against it, so this"
                " server is not covered by mcp-lock.json: a change to it passes the"
                " lock check."
            )
            remediation = (
                "Review this server in every change to the agent file; the lock does"
                " not cover it. " + remediation
            )
            title = "Subagent MCP server not covered by mcp-lock.json"
            severity = Severity.MEDIUM
        findings.append(
            _finding(
                finding_id="AGENT-004",
                severity=severity,
                path=path,
                server=display,
                client=client,
                title=title,
                description=description,
                evidence=f"{path}: mcpServers -> {declared}",
                remediation=remediation,
                owasp=["MCP09"],
                cwe=None,
            )
        )
    return findings


#: Which finding speaks for a security key that is repeated or unreadable.
_KEY_FINDING: dict[str, tuple[str, list[str], str | None]] = {
    "permissionMode": ("AGENT-001", ["MCP02", "MCP07"], "CWE-862"),
    "tools": ("AGENT-002", ["MCP02"], None),
    "disallowedTools": ("AGENT-002", ["MCP02"], None),
    "hooks": ("AGENT-003", ["MCP05", "MCP07"], "CWE-78"),
    "mcpServers": ("AGENT-004", ["MCP09"], None),
}


def _key_severity(key: str, scope: str, path: Path) -> Severity:
    """The scope severity of the finding that speaks for *key*."""
    if key == "permissionMode":
        return Severity.MEDIUM if scope == "project" else Severity.LOW
    if key == "hooks":
        return Severity.MEDIUM if scope == "project" else Severity.INFO
    if key == "mcpServers" and scope == "project" and lock_root_for(path):
        return Severity.MEDIUM
    return Severity.INFO


def _check_repeated_and_unreadable(
    definition: AgentFrontmatter, name: str, path: Path, scope: str, client: str
) -> list[Finding]:
    """A security key that appears more than once, or that mcp-audit cannot read."""
    findings: list[Finding] = []
    for key, count in sorted(definition.repeated_keys.items()):
        finding_id, owasp, cwe = _KEY_FINDING[key]
        findings.append(
            _finding(
                finding_id=finding_id,
                severity=_key_severity(key, scope, path),
                path=path,
                server=path.name,
                client=client,
                title=f"Subagent frontmatter repeats '{key}'",
                description=(
                    f"'{key}' appears {count} times in the frontmatter of the"
                    f" subagent '{name}' in {path.name}. YAML parsers disagree on"
                    " which value wins, so mcp-audit checked every value; whichever"
                    " Claude Code uses, a repeated security key is a way to show a"
                    " reviewer one value and run another."
                ),
                evidence=f"{path}: {key} x{count}",
                remediation=f"Keep one '{key}' entry and delete the others.",
                owasp=owasp,
                cwe=cwe,
            )
        )
    reason = definition.unreadable_reason or "it could not be parsed"
    for key in definition.unreadable_keys:
        finding_id, owasp, cwe = _KEY_FINDING[key]
        findings.append(
            _finding(
                finding_id=finding_id,
                severity=_key_severity(key, scope, path),
                path=path,
                server=path.name,
                client=client,
                title=f"Subagent '{key}' present but unreadable by mcp-audit",
                description=(
                    f"The frontmatter of {path.name} names '{key}', but mcp-audit"
                    f" could not read it ({reason}). The key is present but"
                    " unreadable by mcp-audit; Claude Code may load it, so its"
                    " effect was not checked."
                ),
                evidence=f"{path}: {key} (unreadable: {reason})",
                remediation=(
                    f"Read '{key}' in {path.name} by hand, and simplify the"
                    " frontmatter so it parses as plain YAML."
                ),
                owasp=owasp,
                cwe=cwe,
            )
        )
    return findings


def finalize_findings(findings: list[Finding]) -> list[Finding]:
    """Drop duplicates and redact credential-shaped text from every finding."""
    out: list[Finding] = []
    seen: set[tuple[str, str, str, str]] = set()
    for finding in findings:
        key = (finding.id, finding.server, finding.title, finding.evidence)
        if key in seen:
            continue
        seen.add(key)
        finding.title = redact_secrets(finding.title)
        finding.description = redact_secrets(finding.description)
        finding.evidence = redact_secrets(finding.evidence)
        finding.remediation = redact_secrets(finding.remediation)
        out.append(finding)
    return out


def analyze_agent_definition(
    definition: AgentFrontmatter | dict[str, Any],
    path: Path,
    scope: str,
    client: str = AGENT_DEFINITION_CLIENT,
) -> list[Finding]:
    """Return AGENT-001..004 for one subagent definition.

    Every reading is checked, so a value hidden from one way of reading the
    frontmatter is still reported. HOOK-001/002 on the hook commands are not
    produced here; :meth:`ConfigHygieneAnalyzer.analyze_agent_definition` adds
    them.

    Args:
        definition: An :class:`AgentFrontmatter`, or one parsed frontmatter
            mapping.
        path: The agent definition file.
        scope: ``"project"`` for a repository's ``.claude/agents/`` and
            ``"user"`` for ``~/.claude/agents/``.
        client: Client name for the findings.

    Returns:
        Findings, deduplicated, with credential-shaped text redacted.
    """
    if isinstance(definition, dict):
        definition = AgentFrontmatter.from_mapping(definition)
    name = _agent_name(definition, path)
    findings: list[Finding] = []
    for reading in definition.readings:
        findings += _check_permission_mode(reading, name, path, scope, client)
        findings += _check_disallowed_specifiers(reading, name, path, client)
        findings += _check_hooks_presence(reading, name, path, scope, client)
    findings += _check_inline_servers(definition, name, path, scope, client)
    findings += _check_repeated_and_unreadable(definition, name, path, scope, client)
    return finalize_findings(findings)


__all__ = [
    "AGENT_DEFINITION_CLIENT",
    "MAX_AGENT_BYTES_PER_SCAN",
    "MAX_AGENT_DEFINITIONS_PER_SCAN",
    "MAX_AGENT_FILE_BYTES",
    "MAX_EXPANDED_VALUES",
    "MAX_NESTING",
    "MAX_YAML_NODES",
    "SECURITY_KEYS",
    "AgentFrontmatter",
    "agent_mcp_servers",
    "analyze_agent_definition",
    "finalize_findings",
    "has_frontmatter",
    "lock_root_for",
    "normalize_server_entry",
    "parse_agent_frontmatter",
    "read_agent_definition",
    "read_agent_text",
    "redact_secrets",
    "select_agent_definitions",
]
