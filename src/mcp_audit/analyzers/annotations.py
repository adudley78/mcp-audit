"""Tool annotations that contradict the tool's own input schema (ANNOT-001, STORY-0136).

MCP tool annotations (``readOnlyHint``, ``destructiveHint``, ...) are hints a
server sends about its own tools. The MCP maintainers are explicit that they
are "a risk vocabulary, not enforcement": a client cannot trust a hint from a
server it does not trust, and a server can claim ``readOnlyHint`` and delete
files (https://blog.modelcontextprotocol.io/posts/2026-03-16-tool-annotations/).
actlint, which compares a server's labels with what its schema allows, found
4 of 31 servers whose labels the schema contradicted.

``ANNOT-001`` reads one structural contradiction in a tool definition:

* the tool says ``readOnlyHint: true`` and its input schema has a parameter
  that runs commands (``command``, ``script``, ``shell`` ...), runs SQL that
  writes, or writes/deletes (``overwrite``, ``delete``, a ``content`` to write
  beside a ``path``); or
* the tool says ``destructiveHint: false`` (and is not read-only) and the
  schema has a parameter that runs commands, runs destructive SQL, or deletes
  or overwrites. Additive writes are not counted there: the spec lets a
  non-destructive tool write.

A bare ``path`` or ``url`` is never enough: reading a file or a page is what a
read-only tool does. Annotations only ever *raise* a finding here; a server's
claim never suppresses anything else mcp-audit reports.

Where it runs: ``scan --connect`` (right after DELEG-*, over the tools each
server listed), and in a default scan over the saved tool text
``mcp-lock.tools.json`` in the working directory
(:mod:`mcp_audit.lock.tool_text`), which holds the same definitions. Nothing
connects to or starts a server here.

Severity is :data:`SHIPPED_SEVERITY`, set from the measurement in
``docs/annotations.md``.

Hardening: tool definitions are attacker-controlled. Text is tokenised once
with a linear regex and matched by set lookups (no backtracking patterns over
descriptions), the schema is walked iteratively with depth, node and
per-object property caps, non-boolean or malformed annotations are ignored,
and evidence is control-character-stripped, length-capped and redacted with
:func:`mcp_audit.analyzers.supply_chain.redact_command`.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from mcp_audit.analyzers.supply_chain import redact_command
from mcp_audit.models import Finding, ServerConfig, ServerEnumeration, Severity

ANALYZER_NAME: Final = "annotations"
FINDING_ID: Final = "ANNOT-001"
_CWE: Final = "CWE-451"
_OWASP: Final = ["MCP03", "MCP06"]

#: Severity of ANNOT-001. LOW until the measurement in docs/annotations.md
#: shows precision of at least 50% on at least 10 hits.
SHIPPED_SEVERITY: Final = Severity.LOW

# ── caps ────────────────────────────────────────────────────────────────────
MAX_DEPTH: Final = 8
MAX_NODES: Final = 5000
MAX_PROPS_PER_OBJECT: Final = 256
MAX_TEXT_CHARS: Final = 2000
MAX_NAME_CHARS: Final = 200
MAX_TOOLS: Final = 5000
MAX_PARAMS_SHOWN: Final = 3

# ── vocabulary ──────────────────────────────────────────────────────────────
_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_WORDS = re.compile(r"[a-z]+")

#: Parameter-name tokens that mean "this value is run".
_EXEC_NAME = frozenset(
    {"command", "cmd", "script", "shell", "exec", "execute", "bash", "powershell"}
)
#: A name that also carries one of these refers to a command or script, not
#: the command itself (``script_path``, ``command_name``).
_REFERENCE = frozenset(
    {
        "path",
        "file",
        "filename",
        "filepath",
        "dir",
        "directory",
        "id",
        "name",
        "url",
        "uri",
        "type",
        "lang",
        "language",
        "count",
        "format",
        "version",
        "timeout",
        "history",
    }
)
#: Parameter-name tokens for a write or delete switch.
_DESTRUCTIVE_NAME = frozenset({"overwrite", "delete", "drop", "truncate"})
_WRITE_NAME = frozenset({"write", "append"})
_SQL_NAME = frozenset({"sql", "statement", "stmt", "query"})
_CONTENT_NAME = frozenset({"content", "contents", "text", "data", "body"})
_PATH_NAME = frozenset(
    {"path", "file", "filename", "filepath", "destination", "target", "dest"}
)

_SQL_WRITE = frozenset({"insert", "update", "create", "grant"})
_SQL_DESTRUCTIVE = frozenset({"delete", "drop", "truncate", "alter"})
_WRITE_VERBS = frozenset({"write", "save", "overwrite", "append", "overwritten"})
_RUN_VERBS = frozenset({"run", "runs", "execute", "executed", "executes", "invoke"})
_RUN_OBJECTS = frozenset(
    {"command", "commands", "script", "shell", "bash", "program", "binary"}
)
#: Words that turn a mention into a prohibition ("read-only", "not allowed").
_NEGATORS = frozenset(
    {
        "not",
        "no",
        "cannot",
        "never",
        "only",
        "readonly",
        "without",
        "disallowed",
        "forbidden",
        "unsupported",
        "select",
    }
)

_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_NON_BOOL_TYPES: Final = frozenset({"boolean", "number", "integer", "null"})


def _words(text: object, limit: int = MAX_TEXT_CHARS) -> list[str]:
    """Return lowercase tokens of *text*, camelCase split, capped in length."""
    if not isinstance(text, str):
        return []
    return _WORDS.findall(_CAMEL.sub(" ", text[:limit]).lower())


@dataclass(frozen=True)
class Contradiction:
    """One parameter that contradicts a claimed annotation."""

    claim: str
    param: str
    reason: str


@dataclass
class _Param:
    name: str
    tokens: list[str]
    desc: list[str]
    type_name: str | None


def _param(name: str, node: object) -> _Param:
    desc: list[str] = []
    type_name: str | None = None
    if isinstance(node, dict):
        desc = _words(node.get("description"))
        t = node.get("type")
        if isinstance(t, str):
            type_name = t
    return _Param(name[:MAX_NAME_CHARS], _words(name[:MAX_NAME_CHARS]), desc, type_name)


def _property_groups(schema: object) -> list[list[_Param]]:
    """Return each ``properties`` object of *schema* as a list of parameters.

    Iterative, depth/node/property capped; ``$ref`` is not followed.
    """
    groups: list[list[_Param]] = []
    if not isinstance(schema, dict):
        return groups
    stack: list[tuple[object, int]] = [(schema, 0)]
    seen = 0
    while stack and seen < MAX_NODES:
        node, depth = stack.pop()
        seen += 1
        if not isinstance(node, dict) or depth > MAX_DEPTH:
            continue
        props = node.get("properties")
        if isinstance(props, dict):
            group: list[_Param] = []
            for i, (key, value) in enumerate(props.items()):
                if i >= MAX_PROPS_PER_OBJECT:
                    break
                if isinstance(key, str):
                    group.append(_param(key, value))
                    stack.append((value, depth + 1))
            groups.append(group)
        for key in ("items", "additionalProperties"):
            if isinstance(node.get(key), dict):
                stack.append((node[key], depth + 1))
        for key in ("anyOf", "oneOf", "allOf"):
            subs = node.get(key)
            if isinstance(subs, list):
                stack.extend((s, depth + 1) for s in subs[:MAX_PROPS_PER_OBJECT])
    return groups


def _runs_commands(p: _Param) -> str | None:
    toks = set(p.tokens)
    if (
        toks & _EXEC_NAME
        and not toks & _REFERENCE
        and p.type_name not in _NON_BOOL_TYPES
    ):
        return "runs commands"
    if p.desc and not set(p.desc) & _NEGATORS:
        d = p.desc
        for i, w in enumerate(d):
            if w in _RUN_VERBS and set(d[i + 1 : i + 5]) & _RUN_OBJECTS:
                return "runs commands"
            if w in _RUN_OBJECTS and set(d[i + 1 : i + 4]) & _RUN_VERBS:
                return "runs commands"
            if w in ("shell", "bash") and d[i + 1 : i + 2] in (
                ["command"],
                ["commands"],
                ["script"],
            ):
                return "runs commands"
    return None


def _sql(p: _Param, verbs: frozenset[str]) -> str | None:
    if set(p.tokens) & _SQL_NAME and p.type_name in (None, "string"):
        d = set(p.desc)
        if d & verbs and not d & _NEGATORS:
            return "runs SQL that writes"
    return None


def _destructive_switch(p: _Param) -> str | None:
    if set(p.tokens) & _DESTRUCTIVE_NAME:
        return "deletes or overwrites"
    return None


def _write_switch(p: _Param) -> str | None:
    if set(p.tokens) & _WRITE_NAME:
        return "writes"
    return None


def _content_to_path(group: list[_Param], p: _Param) -> str | None:
    if not set(p.tokens) & _CONTENT_NAME or p.type_name not in (None, "string"):
        return None
    d = set(p.desc)
    if not d & _WRITE_VERBS or d & _NEGATORS:
        return None
    for other in group:
        if other is not p and set(other.tokens) & _PATH_NAME:
            return "content to write beside a path"
    return None


def find_contradictions(
    annotations: object, input_schema: object
) -> list[Contradiction]:
    """Return the schema parameters that contradict the claimed annotations.

    Args:
        annotations: The tool's ``annotations`` object as the server sent it.
            Only a literal ``true`` ``readOnlyHint`` or a literal ``false``
            ``destructiveHint`` is read; anything else yields no result.
        input_schema: The tool's ``inputSchema``.

    Returns:
        Contradictions, empty when the claim is absent, malformed or unopposed.
        Never raises.
    """
    if not isinstance(annotations, dict):
        return []
    read_only = annotations.get("readOnlyHint") is True
    not_destructive = annotations.get("destructiveHint") is False
    if not read_only and not not_destructive:
        return []
    claim = "readOnlyHint=true" if read_only else "destructiveHint=false"
    found: list[Contradiction] = []
    try:
        groups = _property_groups(input_schema)
    except (RecursionError, TypeError, ValueError):
        return []
    for group in groups:
        for p in group:
            reason = (
                _runs_commands(p)
                or _sql(
                    p, _SQL_WRITE | _SQL_DESTRUCTIVE if read_only else _SQL_DESTRUCTIVE
                )
                or _destructive_switch(p)
                or (_write_switch(p) if read_only else None)
                or (_content_to_path(group, p) if read_only else None)
            )
            if reason:
                found.append(Contradiction(claim, p.name, reason))
    return found


def _clean(text: str, limit: int = MAX_NAME_CHARS) -> str:
    return _CONTROL.sub("", text)[:limit]


def _finding(
    *,
    client: str,
    server: str,
    tool: str,
    finding_path: str,
    contradictions: list[Contradiction],
) -> Finding:
    shown = contradictions[:MAX_PARAMS_SHOWN]
    parts = "; ".join(f"parameter '{_clean(c.param)}' {c.reason}" for c in shown)
    more = len(contradictions) - len(shown)
    if more > 0:
        parts += f"; {more} more"
    evidence = redact_command(None, [f"{shown[0].claim}: {parts}"])
    return Finding(
        id=FINDING_ID,
        severity=SHIPPED_SEVERITY,
        analyzer=ANALYZER_NAME,
        client=client,
        server=server,
        tool=_clean(tool),
        title="Tool annotation contradicts the tool's own input schema",
        description=(
            f"Tool '{_clean(tool)}' is annotated {shown[0].claim}, but its input "
            "schema has a parameter that says otherwise. MCP annotations are "
            "hints from the server, not enforcement: a client that auto-approves "
            "'read-only' tools on this label would approve a tool that can run "
            "commands or change data."
        ),
        evidence=evidence,
        remediation=(
            "Do not auto-approve this tool on its annotation. Read its input "
            "schema; if the parameter is real, the label is wrong, and the "
            "server should fix it or you should remove the server."
        ),
        cwe=_CWE,
        owasp_mcp_top_10=list(_OWASP),
        finding_path=finding_path,
    )


def analyze_definition(
    *,
    client: str,
    server: str,
    finding_path: str,
    name: object,
    annotations: object,
    input_schema: object,
) -> Finding | None:
    """Return ANNOT-001 for one tool definition, or ``None``. Never raises."""
    if not isinstance(name, str):
        return None
    hits = find_contradictions(annotations, input_schema)
    if not hits:
        return None
    return _finding(
        client=client,
        server=server,
        tool=name,
        finding_path=finding_path,
        contradictions=hits,
    )


def detect_annotation_contradictions(
    pairs: Iterable[tuple[ServerConfig, ServerEnumeration]],
) -> list[Finding]:
    """Run ANNOT-001 over every tool of every live-enumerated server.

    Called by :func:`~mcp_audit.scanner.run_scan_async` after DELEG-*, with the
    same ``(server, enumeration)`` pairs. Failed enumerations are skipped; the
    same logical server configured in several clients is analyzed once.
    """
    findings: list[Finding] = []
    seen: set[tuple] = set()
    for server, enumeration in pairs:
        if enumeration.error:
            continue
        identity = (
            server.name,
            server.command or "",
            tuple(server.args),
            server.url or "",
        )
        if identity in seen:
            continue
        seen.add(identity)
        for tool in enumeration.tools[:MAX_TOOLS]:
            f = analyze_definition(
                client=server.client,
                server=server.name,
                finding_path=str(server.config_path),
                name=tool.name,
                annotations=tool.annotations,
                input_schema=tool.input_schema,
            )
            if f is not None:
                findings.append(f)
    return findings


def findings_from_tool_text(doc: object, source: Path) -> list[Finding]:
    """Run ANNOT-001 over a loaded ``mcp-lock.tools.json`` document.

    The file is a companion to the lock and is not trusted for anything here:
    its text is only read, and a finding only ever raises. A server that lists
    two tools under one name stores a list of definitions; each is read.
    """
    findings: list[Finding] = []
    servers = doc.get("servers") if isinstance(doc, dict) else None
    if not isinstance(servers, dict):
        return findings
    count = 0
    for key, record in servers.items():
        tools = record.get("tools") if isinstance(record, dict) else None
        if not isinstance(tools, dict) or not isinstance(key, str):
            continue
        client, _, server = key.partition("/")
        for tool_name, stored in tools.items():
            defs = stored if isinstance(stored, list) else [stored]
            for definition in defs:
                count += 1
                if count > MAX_TOOLS:
                    return findings
                if not isinstance(definition, dict):
                    continue
                f = analyze_definition(
                    client=client if server else "lock",
                    server=server or client,
                    finding_path=str(source),
                    name=tool_name,
                    annotations=definition.get("annotations"),
                    input_schema=definition.get("inputSchema"),
                )
                if f is not None:
                    findings.append(f)
    return findings
