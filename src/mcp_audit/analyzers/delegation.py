"""Cross-tool delegation in live tool descriptions (DELEG-001..003, STORY-0100).

The tool-poisoning shape that works never runs itself. MCPTox (arXiv
2508.14925, AAAI 2026) built 1,312 poisoned descriptions on 45 real servers and
found that "the poisoned tool itself is never executed" (§3.1): its description
tells the agent that whenever it does X it must first call a *different*,
legitimate tool, or change that tool's arguments, and the legitimate tool does
the damage. The attacker "can register a malicious MCP server with tool
descriptions" (§2.2), so "an agent is connected to both a trusted MCP server
and a malicious one" (§3.4). Keyword rules miss most of it: on MCPTox's
unwrapped cases POISON-* flags about one in four, and parameter tampering
almost never (``docs/poisoning.md``).

Three structural checks, each over the text an agent reads about a tool (its
description, its title, and the ``description``/``title`` strings inside its
input schema):

``DELEG-001``
    The text names a tool that a **different server** in the same session
    exposes. A server documenting its own workflow ("call ``list_tables``
    first") names its own tools; a description that steers the agent to
    another server's tool crosses the boundary MCPTox's attacker relies on.
``DELEG-002``
    A conditional trigger ("before using …", "whenever …", "after …") plus a
    directive ("you must", "always", an imperative) to perform an action whose
    capability class (read, write, delete, send, execute) appears nowhere in
    the tool's own name or input-schema property names.
``DELEG-003``
    A directive to rewrite arguments ("modify the 'path' argument to …",
    "always set the recipient to …", "append to prompt …") scoped beyond this
    tool: to a named tool of another server, or to every call.

Where it runs: ``scan --connect`` (and ``dashboard --connect``), right after
COLLIDE-001, over every ``(server, tools/list)`` pair that enumerated. The
``tools`` section of ``mcp-lock.json`` records only names and SHA-256 digests
(:mod:`mcp_audit.lock.tool_digests`: "Only names and digests are written,
never the tool text"), so there is no offline copy of a description to read;
a default scan never connects to or starts a server.

Severities are not asserted, they are measured: :data:`SHIPPED_SEVERITY` is
set from the gate STORY-0100 defined (lift MCPTox implicit-trigger recall over
POISON-* and flag no more than 5 of its 353 clean real tools, on
``scripts/bench_poisoning.py delegation``). The measurement and the decision
are in ``docs/research/poisoning-benchmark/results.json`` under ``delegation``
and in ``docs/poisoning.md``; ``tests/test_delegation.py`` fails if this module
changes without a re-measure, or if the table here disagrees with it.

Hardening: every text is attacker-controlled. Matching is token-based (one
linear tokenizer regex, then set lookups), there are no backtracking
patterns over description text, schemas are walked iteratively with node and
depth caps, each tool's text is capped and the whole scan has a character
budget whose exhaustion is reported. Evidence is redacted with
``SECRET_PATTERNS`` (plus URL userinfo) over a bounded window around what is
shown (some of those patterns rescan to the end of their input), and stripped
of control characters; names in titles are reduced to a safe character set.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field

from mcp_audit.analyzers.credentials import SECRET_PATTERNS
from mcp_audit.models import (
    Finding,
    ServerConfig,
    ServerEnumeration,
    Severity,
    ToolInfo,
)

# ── Severity: decided by the measured gate, not asserted ──────────────────────

#: The severities the scope asked for if the gate passes.
STATED_SEVERITY: dict[str, Severity] = {
    "DELEG-001": Severity.MEDIUM,
    "DELEG-002": Severity.MEDIUM,
    "DELEG-003": Severity.HIGH,
}

#: What ships. Set from ``results.json["delegation"]["gate"]["shipped_severity"]``;
#: ``tests/test_delegation.py`` fails when the two disagree.
SHIPPED_SEVERITY: dict[str, Severity] = {
    "DELEG-001": Severity.MEDIUM,
    "DELEG-002": Severity.MEDIUM,
    "DELEG-003": Severity.HIGH,
}

ANALYZER_NAME = "delegation"
_CWE = "CWE-441"
_OWASP = ["MCP03", "MCP06"]

# ── Budgets ───────────────────────────────────────────────────────────────────

#: Characters of text read per tool (description + title + schema strings).
MAX_TOOL_TEXT_CHARS = 64 * 1024
#: Characters of tool text read per scan, across every server.
MAX_TOTAL_TEXT_CHARS = 8 * 1024 * 1024
#: Schema nodes visited per tool, and the deepest nesting followed.
MAX_SCHEMA_NODES = 5_000
MAX_SCHEMA_DEPTH = 64
#: Tools analyzed per scan.
MAX_TOOLS = 20_000
#: Characters of a sentence shown as evidence.
_EVIDENCE_CHARS = 200
#: Characters around what is shown that go through secret redaction. Some
#: ``SECRET_PATTERNS`` (``…://\w+:[^@]+@``) rescan to the end of the text
#: from every start, so redaction runs on this window, never a whole 64 KiB
#: field; a secret would have to be longer than the margin to reach the
#: shown part from outside it.
_REDACT_MARGIN = 1_000

# ── Vocabulary ────────────────────────────────────────────────────────────────


def _forms(*bases: str) -> frozenset[str]:
    """Return simple English inflections of each verb in *bases*.

    ``delete`` gives delete, deletes, deleted, deleting, deleter, deletion;
    good enough for a closed list of verbs, and it keeps the matching a set
    lookup rather than a pattern.
    """
    out: set[str] = set()
    for base in bases:
        out.add(base)
        stem = base[:-1] if base.endswith("e") else base
        if base.endswith(("s", "sh", "ch", "x", "z")):
            out.add(base + "es")
        elif base.endswith("y") and base[-2:-1] not in "aeiou":
            out.add(base[:-1] + "ies")
            out.add(base[:-1] + "ied")
        else:
            out.add(base + "s")
        out.update({stem + "ed", stem + "ing", stem + "er", stem + "ion"})
        if base.endswith("e"):
            out.add(base + "d")
        if (
            len(base) <= 4
            and base[-1] not in "aeiouwxy"
            and base[-2:-1] in ("a", "e", "i", "o", "u")
            and base[-3:-2] not in ("a", "e", "i", "o", "u", "")
        ):
            doubled = base + base[-1]
            out.update({doubled + "ing", doubled + "ed", doubled + "er"})
    return frozenset(out)


#: Capability classes of an action, as base verbs. Name/schema tokens and
#: directive verbs are both mapped through the inflected table below.
CAPABILITY_BASES: dict[str, tuple[str, ...]] = {
    "read": (
        "read",
        "fetch",
        "retrieve",
        "download",
        "export",
        "dump",
        "extract",
        "open",
        "access",
        "copy",
        "load",
        "get",
        "list",
        "search",
        "query",
        "find",
        "view",
        "collect",
        "gather",
        "browse",
        "lookup",
    ),
    "write": (
        "write",
        "create",
        "update",
        "modify",
        "edit",
        "overwrite",
        "append",
        "insert",
        "change",
        "replace",
        "rename",
        "move",
        "save",
        "store",
        "put",
        "patch",
        "commit",
        "merge",
        "mark",
        "label",
        "add",
        "inject",
        "set",
        "upsert",
        "schedule",
    ),
    "delete": (
        "delete",
        "remove",
        "erase",
        "wipe",
        "purge",
        "drop",
        "clear",
        "reset",
        "truncate",
        "trash",
        "destroy",
        "revoke",
        "cancel",
        "kill",
        "terminate",
        "uninstall",
        "unlink",
    ),
    "send": (
        "send",
        "post",
        "upload",
        "push",
        "email",
        "mail",
        "forward",
        "share",
        "publish",
        "transmit",
        "notify",
        "submit",
        "reply",
        "broadcast",
        "transfer",
        "invite",
        "comment",
        "pay",
    ),
    "execute": (
        "execute",
        "exec",
        "run",
        "eval",
        "evaluate",
        "spawn",
        "launch",
        "install",
    ),
}
CAPABILITY_VERBS: dict[str, frozenset[str]] = {
    cls: _forms(*bases) for cls, bases in CAPABILITY_BASES.items()
}
_VERB_CLASS: dict[str, str] = {
    word: cls for cls, words in CAPABILITY_VERBS.items() for word in words
}

#: Verbs that mean "call a tool" without saying what it does.
_INVOKE = _forms("use", "call", "invoke", "trigger", "perform", "proceed", "do")
#: Imperative heads: a sentence (or the clause after a trigger) starting with
#: one of these is addressed to the agent.
_IMPERATIVE = frozenset(
    {"use", "call", "invoke", "trigger"}
    | {base for bases in CAPABILITY_BASES.values() for base in bases}
)
#: Adverbs skipped before an imperative ("…, first call X", "…, always use Y").
_LEAD_ADVERBS = frozenset(
    {"first", "always", "also", "then", "please", "immediately", "automatically"}
)

#: Single-word trigger heads; "when"/"if" need a following action or subject.
_TRIGGER_HEADS = frozenset({"before", "after", "whenever", "upon", "anytime"})
_TRIGGER_TWO = frozenset(
    {("prior", "to"), ("every", "time"), ("each", "time"), ("any", "time")}
)
_SUBJECTS = frozenset({"you", "user", "agent", "assistant", "model", "llm"})

#: Words that make a sentence a directive to the agent.
_OBLIGATION = frozenset(
    {
        "must",
        "should",
        "shall",
        "need",
        "needs",
        "required",
        "requires",
        "require",
        "always",
        "mandatory",
        "necessary",
        "ensure",
        "automatically",
        "remember",
    }
)
_OBLIGATION_TWO = frozenset(
    {("make", "sure"), ("be", "sure"), ("have", "to"), ("has", "to")}
)

#: Verbs that rewrite what another call carries (base forms only: "always set",
#: not "it sets").
_REWRITE = frozenset(
    {
        "set",
        "change",
        "modify",
        "replace",
        "override",
        "overwrite",
        "rewrite",
        "substitute",
        "redirect",
        "reroute",
        "route",
        "append",
        "prepend",
        "inject",
        "insert",
        "add",
        "include",
        "attach",
        "cc",
        "bcc",
        "remove",
        "strip",
        "omit",
        "force",
        "hardcode",
        "swap",
        "alter",
        "pass",
    }
)
#: Nouns naming an argument.
_PARAM_NOUNS = frozenset(
    {
        "argument",
        "arguments",
        "parameter",
        "parameters",
        "param",
        "params",
        "field",
        "fields",
        "value",
        "values",
        "recipient",
        "recipients",
        "address",
        "path",
        "url",
        "query",
        "prompt",
        "header",
        "headers",
        "body",
        "cc",
        "bcc",
        "selector",
    }
)
#: "every/any/all/each <noun>" that scopes a directive to every call.
_UNIVERSAL_HEADS = frozenset({"every", "any", "all", "each"})
_UNIVERSAL_NOUNS = frozenset(
    {
        "tool",
        "tools",
        "call",
        "calls",
        "request",
        "requests",
        "invocation",
        "invocations",
        "function",
        "functions",
        "operation",
        "operations",
    }
)

_QUOTES = frozenset("'\"`\u2018\u2019\u201c\u201d")

#: A plain-word tool name ("search") is a reference only in tool context:
#: one of these among the two words before its opening quote …
_TOOL_CONTEXT_BEFORE = frozenset(_INVOKE) | {"run", "running", "runs"}
#: … or one of these as the word after its closing quote.
_TOOL_NOUNS = frozenset({"tool", "function", "command", "endpoint", "method"})
#: Words that make a directive about this tool itself ("use this", "call it").
_SELF_OBJECTS = frozenset({"this", "it", "me"})
#: Words after "this" that name the tool itself ("this tool must be called").
_SELF_NOUNS = _TOOL_NOUNS | {"action", "operation"}
#: How far (in words) a directive may sit from its trigger clause.
_DIRECTIVE_WINDOW = 25

# ── Linear tokenizers (no nested quantifiers, no lazy-dotall) ─────────────────

#: An MCP tool name as it can appear in prose (spec: letters, digits, ``_``,
#: ``-``, ``.``). Trailing ``.``/``-`` are trimmed by the caller.
_NAME_TOKEN = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.\-]*")
_VALID_NAME = re.compile(r"[A-Za-z0-9_](?:[A-Za-z0-9_.\-]{0,126}[A-Za-z0-9_])?")
_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_WORD_OR_COMMA = re.compile(r"[a-z]+|,")
_SENTENCE_END = re.compile(r"(?<=[.!?])\s+|\n+")
_USERINFO = re.compile(r"([A-Za-z][A-Za-z0-9+.\-]{0,20}://)[^\s/@]{1,256}@")
_IDENTIFIER_SHAPE = re.compile(r"[_.\-0-9]|[a-z][A-Z]")
#: ``key=value``, ``key:value`` and ``key: "value"`` assign a value; what
#: follows is not a tool reference. ``Note: read_file …`` (spaced colon, bare
#: name) is prose and still counts.
_VALUE_EQ = re.compile(r"\w[ \t]?=[ \t]?\Z")
_VALUE_COLON_TIGHT = re.compile(r"\w:\Z")
_VALUE_COLON_SPACED = re.compile(r"\w:[ \t]\Z")
_LEAD_WORD = re.compile(r"[a-z]+")
#: Longest ``mcp__<server>__<tool>`` token considered (tool names are at most
#: 128 characters by the MCP spec; server names are short).
_MAX_QUALIFIED_LEN = 320
_UNSAFE_NAME_CHARS = re.compile(r"[^A-Za-z0-9_.\-:/@ ]")


# ── Data ──────────────────────────────────────────────────────────────────────


@dataclass
class _Entry:
    server: ServerConfig
    identity: tuple
    tool: ToolInfo
    texts: list[tuple[str, str]] = field(default_factory=list)  # (field, text)


@dataclass
class _Budget:
    remaining: int
    truncated_tools: int = 0
    skipped_tools: int = 0
    schema_capped_tools: int = 0


def server_identity(server: ServerConfig) -> tuple:
    """Return the logical-server identity COLLIDE-001 uses (name, command, args, url).

    The same server configured in two clients is one server, not two.
    """
    return (server.name, server.command or "", tuple(server.args), server.url or "")


def is_identifier_shaped(name: str) -> bool:
    """Whether *name* reads as code rather than an English word.

    ``read_file``, ``moveEmail``, ``map-geocode`` and ``v2.search`` are
    identifier-shaped and count when they appear bare in prose; ``search`` or
    ``Fetch`` count only inside quotes or backticks, since the bare word is
    ordinary English.
    """
    return bool(_IDENTIFIER_SHAPE.search(name))


def split_words(text: str) -> list[str]:
    """Lowercase words of *text* with camelCase and snake/kebab case split."""
    return re.findall(r"[a-z]+", _CAMEL.sub(" ", text).lower())


def capability_classes(words: Iterable[str]) -> set[str]:
    """Return the capability classes (read/write/delete/send/execute) *words* name."""
    return {_VERB_CLASS[w] for w in words if w in _VERB_CLASS}


def _redact_tracking(text: str, offset: int = 0) -> tuple[str, int]:
    """Redact secrets in *text*; return it and where *offset* moved to.

    A match that covers *offset* moves it to the match's start, so a mention
    inside a secret is shown as ``[REDACTED]``.
    """
    passes: list[tuple[re.Pattern[str], str]] = [
        (pattern, "[REDACTED]") for _label, pattern, _provider in SECRET_PATTERNS
    ]
    passes.append((_USERINFO, r"\1[REDACTED]@"))
    for pattern, replacement in passes:
        pieces: list[str] = []
        last = 0
        new_offset = offset
        for m in pattern.finditer(text):
            repl = m.expand(replacement)
            pieces.append(text[last : m.start()])
            pieces.append(repl)
            if m.end() <= offset:
                new_offset += len(repl) - (m.end() - m.start())
            elif m.start() <= offset:
                new_offset = len("".join(pieces[:-1]))
            last = m.end()
        if pieces:
            pieces.append(text[last:])
            text = "".join(pieces)
            offset = new_offset
    return text, offset


def redact_evidence(text: str) -> str:
    """Make attacker-controlled text safe to put in a finding.

    Reads the first :data:`_EVIDENCE_CHARS` + :data:`_REDACT_MARGIN`
    characters, redacts ``SECRET_PATTERNS`` matches and URL userinfo, drops
    control and format characters (no terminal escape sequences), collapses
    whitespace and caps the length at :data:`_EVIDENCE_CHARS`.
    """
    text, _ = _redact_tracking(text[: _EVIDENCE_CHARS + _REDACT_MARGIN])
    text = "".join(ch if ch.isprintable() else " " for ch in text)
    text = " ".join(text.split())
    if len(text) > _EVIDENCE_CHARS:
        text = text[: _EVIDENCE_CHARS - 1] + "…"
    return text


def _clean_name(name: str) -> str:
    """A tool or server name as shown in a title or description.

    Names come from the scanned server (tool names) or a possibly
    repo-planted config (server names), and titles reach HTML and Rich
    output, so anything outside letters, digits and ``_ . - : / @`` and space
    becomes ``?``; secrets are redacted first; the result is capped.
    """
    name, _ = _redact_tracking(name[:256])
    shown = _UNSAFE_NAME_CHARS.sub("?", name)
    return shown if len(shown) <= 64 else shown[:63] + "\u2026"


def _excerpt(text: str, offset: int) -> str:
    """Evidence around the mention at *offset* in *text*.

    A window of :data:`_REDACT_MARGIN` characters either side is redacted
    before the cut, so a secret that straddles the shown part is never shown
    in part, and redaction never reads a whole field.
    """
    start = max(0, offset - _REDACT_MARGIN)
    window = text[start : offset + _REDACT_MARGIN]
    redacted, at = _redact_tracking(window, offset - start)
    return redact_evidence(redacted[max(0, at - 80) : at + 120])


# ── Reading a tool ────────────────────────────────────────────────────────────


def _schema_strings(
    schema: object, budget: _Budget
) -> tuple[list[tuple[str, str]], list[str]]:
    """Return ``(prose strings, property names)`` from an input schema.

    Prose is every ``description``/``title`` string; property names are the
    keys of every ``properties`` object. Iterative, with node and depth caps.
    """
    prose: list[tuple[str, str]] = []
    props: list[str] = []
    stack: list[tuple[object, int, str]] = [(schema, 0, "inputSchema")]
    nodes = 0
    capped = False
    while stack:
        node, depth, where = stack.pop()
        nodes += 1
        if nodes > MAX_SCHEMA_NODES or depth > MAX_SCHEMA_DEPTH:
            capped = True
            break
        if isinstance(node, dict):
            for key, value in node.items():
                if not isinstance(key, str):
                    continue
                if key in ("description", "title") and isinstance(value, str):
                    prose.append((f"{where}.{key}", value))
                elif key == "properties" and isinstance(value, dict):
                    props.extend(k for k in value if isinstance(k, str))
                    for pname, pval in value.items():
                        stack.append((pval, depth + 1, f"{where}.{pname}"))
                elif isinstance(value, dict | list):
                    stack.append((value, depth + 1, where))
        elif isinstance(node, list):
            stack.extend((item, depth + 1, where) for item in node)
    if capped:
        budget.schema_capped_tools += 1
    return prose, props


def _read_tool(entry: _Entry, budget: _Budget) -> list[str]:
    """Fill ``entry.texts`` within the budgets; return its schema property names."""
    tool = entry.tool
    candidates: list[tuple[str, str]] = []
    if tool.description:
        candidates.append(("description", tool.description))
    if tool.title:
        candidates.append(("title", tool.title))
    prose, props = _schema_strings(tool.input_schema or {}, budget)
    candidates.extend(prose)

    allowance = min(MAX_TOOL_TEXT_CHARS, budget.remaining)
    truncated = False
    for where, text in candidates:
        if allowance <= 0:
            truncated = True
            break
        if len(text) > allowance:
            # Cut at whitespace so a token (a secret, a tool name) is never split.
            cut = text.rfind(" ", 0, allowance)
            text = text[: cut if cut > allowance // 2 else allowance]
            truncated = True
        entry.texts.append((where, text))
        allowance -= len(text)
        budget.remaining -= len(text)
    if truncated:
        budget.truncated_tools += 1
    return props


# ── Matching ──────────────────────────────────────────────────────────────────


def _mentions(text: str, names: dict[str, set[tuple]]) -> list[tuple[str, int]]:
    """Return ``(name, offset)`` for each session tool name *text* mentions.

    A name counts when it is a whole token (``read_file`` does not match in
    ``read_file.txt`` or ``my_read_file``), case-sensitively, as MCP tool
    names are. Two shapes are not references: a value after ``key=``,
    ``key:`` or ``key: "…"`` (``action:"search_nodes"``, ``kind: "feedback"``;
    "Note: read_file …" is prose and counts), and a
    plain-word name ("search", "auth") unless it is quoted *and* in tool
    context ("use 'search'", "the `search` tool").
    """
    found: list[tuple[str, int]] = []
    for m in _NAME_TOKEN.finditer(text):
        token = m.group().rstrip(".-")
        if token not in names:
            qualified = _qualified_tool(token)
            if qualified is not None and qualified in names:
                # ``mcp__fs__read_file`` names read_file unambiguously.
                found.append((qualified, m.start()))
            continue
        start = m.start()
        end = start + len(token)
        opener = text[start - 1] if start > 0 else ""
        closer = text[end] if end < len(text) else ""
        quoted = opener in _QUOTES and closer in _QUOTES
        lead_end = start - 1 if quoted else start
        lead = text[max(0, lead_end - 40) : lead_end]
        if (
            _VALUE_EQ.search(lead)
            or _VALUE_COLON_TIGHT.search(lead)
            or (quoted and _VALUE_COLON_SPACED.search(lead))
        ):
            continue
        if not is_identifier_shaped(token):
            if not quoted:
                continue
            before = _LEAD_WORD.findall(lead.lower())[-2:]
            after = _LEAD_WORD.findall(text[end + 1 : end + 30].lower())[:1]
            if not (
                _TOOL_CONTEXT_BEFORE.intersection(before)
                or _TOOL_NOUNS.intersection(after)
            ):
                continue
        found.append((token, start))
    return found


def _qualified_tool(token: str) -> str | None:
    """The tool part of a client-qualified name, or ``None``.

    Claude Code calls an MCP tool ``mcp__<server>__<tool>`` (its permissions
    documentation writes rules as ``mcp__<server>__<tool>``), so a description
    aimed at Claude Code users can name a tool that way. Only the part after
    the server segment and the part after the last ``__`` are tried; tokens
    longer than an MCP name can be are not.
    """
    if "__" not in token or len(token) > _MAX_QUALIFIED_LEN:
        return None
    if token.startswith("mcp__"):
        parts = token.split("__", 2)
        if len(parts) == 3 and parts[2]:
            return parts[2]
    tail = token.rsplit("__", 1)[1]
    return tail or None


def _sentences(text: str) -> list[tuple[int, str]]:
    """Split *text* into ``(offset, sentence)`` on ``.!?`` + space and newlines."""
    out: list[tuple[int, str]] = []
    start = 0
    for m in _SENTENCE_END.finditer(text):
        if m.start() > start:
            out.append((start, text[start : m.start()]))
        start = m.end()
    if start < len(text):
        out.append((start, text[start:]))
    return out


def _tokens(sentence: str) -> list[str]:
    """Lowercase words and commas, camelCase and snake/kebab case split."""
    return _WORD_OR_COMMA.findall(_CAMEL.sub(" ", sentence).lower())


def _trigger_span(tokens: list[str]) -> tuple[int, int] | None:
    """Return ``(start, end)`` of a conditional-trigger clause, or ``None``.

    The clause runs from its head to the next comma (or at most 12 words).
    "when"/"if" count only when an action verb or a subject ("you", "the
    user") follows within three words.
    """
    n = len(tokens)
    for i, tok in enumerate(tokens):
        head = tok in _TRIGGER_HEADS
        if not head and i + 1 < n and (tok, tokens[i + 1]) in _TRIGGER_TWO:
            head = True
        if not head and tok in ("when", "if"):
            window = tokens[i + 1 : i + 4]
            head = any(
                w in _INVOKE or w in _VERB_CLASS or w in _SUBJECTS for w in window
            )
        if not head:
            continue
        end = i + 1
        while end < n and end - i <= 12 and tokens[end] != ",":
            end += 1
        return i, end
    return None


def _is_directive(words: list[str], *, imperative: bool) -> bool:
    """Whether *words* carry an obligation marker (or, if *imperative*, open with one).

    An imperative counts only in the clause after a trigger ("Before X,
    call Y"): a description's own first sentence is usually an imperative
    summary of the tool itself ("Set or reset a site setting after …").
    """
    if imperative:
        lead = 0
        while lead < len(words) and words[lead] in _LEAD_ADVERBS:
            lead += 1
        if lead < len(words) and words[lead] in _IMPERATIVE:
            return True
    for i, w in enumerate(words):
        if w in _OBLIGATION:
            return True
        if i + 1 < len(words) and (w, words[i + 1]) in _OBLIGATION_TWO:
            return True
    return False


_PASSIVE_BE = frozenset({"be", "is", "are", "being", "been"})


def _is_self_directed(before: list[str], after: list[str]) -> bool:
    """Whether the directive is about calling this tool itself.

    "Use when …" (a bare invoke verb opening the sentence), "use this to …",
    "call it after …", "you must always call this function", "This tool must
    be called before …": guidance on when to call the tool being described,
    which is what a description is for. Only an invoke verb whose object is
    the tool counts; "send the contents to this tool" does not.
    """
    if len(before) == 1 and before[0] in _INVOKE:
        return True
    for words in (before, after):
        for i, w in enumerate(words):
            if w in _INVOKE and _SELF_OBJECTS.intersection(words[i + 1 : i + 3]):
                return True
            if w == "this" and i + 1 < len(words) and words[i + 1] in _SELF_NOUNS:
                tail = words[i + 2 : i + 6]
                if _PASSIVE_BE.intersection(tail) and _INVOKE.intersection(tail):
                    return True
    return False


def _directed_classes(tokens: list[str], own: set[str]) -> list[tuple[str, str]]:
    """Return ``(verb, class)`` for each directed action outside the trigger clause.

    The directive must sit within :data:`_DIRECTIVE_WINDOW` words of the
    trigger and must not be about this tool itself. Only verbs whose class
    is absent from *own* (the tool's name and schema property names) are
    returned.
    """
    span = _trigger_span(tokens)
    if span is None:
        return []
    start, end = span
    window_start = max(0, start - _DIRECTIVE_WINDOW)
    before = [t for t in tokens[window_start:start] if t != ","]
    after = [t for t in tokens[end : end + _DIRECTIVE_WINDOW] if t != ","]
    if not (
        _is_directive(after, imperative=True) or _is_directive(before, imperative=False)
    ):
        return []
    if _is_self_directed(
        [t for t in tokens[:start] if t != ","], [t for t in tokens[end:] if t != ","]
    ):
        return []
    out: list[tuple[str, str]] = []
    for w in before + after:
        cls = _VERB_CLASS.get(w)
        if cls is not None and cls not in own and (w, cls) not in out:
            out.append((w, cls))
    return out


def _rewrite_directive(tokens: list[str]) -> str | None:
    """Return the rewrite verb of a directive to change arguments, or ``None``.

    Matches an obligation marker followed within four words by a base-form
    rewrite verb ("you MUST automatically modify", "always set"), or a clause
    that opens with one ("…, append to prompt").
    """
    words = tokens
    for i, w in enumerate(words):
        if w in _REWRITE and (i == 0 or words[i - 1] == ","):
            return w
        if w in _OBLIGATION or (
            i + 1 < len(words) and (w, words[i + 1]) in _OBLIGATION_TWO
        ):
            for nxt in words[i + 1 : i + 5]:
                if nxt in _REWRITE:
                    return nxt
    return None


def _universal_scope(tokens: list[str]) -> bool:
    """Whether the sentence scopes itself to every call ("any tool", "regardless")."""
    for i, w in enumerate(tokens):
        if w == "regardless":
            return True
        if w in _UNIVERSAL_HEADS and any(
            nxt in _UNIVERSAL_NOUNS for nxt in tokens[i + 1 : i + 3]
        ):
            return True
    return False


def _has_target(sentence: str, tokens: list[str]) -> bool:
    """Whether the sentence names an argument (a noun like "path", or a quote)."""
    if any(t in _PARAM_NOUNS for t in tokens):
        return True
    return any(ch in _QUOTES for ch in sentence)


# ── Findings ──────────────────────────────────────────────────────────────────


def _finding(
    fid: str,
    entry: _Entry,
    title: str,
    description: str,
    evidence: str,
    remediation: str,
) -> Finding:
    return Finding(
        id=fid,
        severity=SHIPPED_SEVERITY[fid],
        analyzer=ANALYZER_NAME,
        client=entry.server.client,
        server=entry.server.name,
        tool=entry.tool.name,
        title=title,
        description=description,
        evidence=evidence,
        remediation=remediation,
        cwe=_CWE,
        owasp_mcp_top_10=list(_OWASP),
        finding_path=str(entry.server.config_path),
    )


_REMEDIATION = (
    "Read this tool's full description as the agent will. A tool rarely needs "
    "to tell the agent what to do with other tools; if this server is not one "
    "you chose deliberately, remove it. Record the definitions you approved "
    "with `mcp-audit lock --connect`, so a later change to this text shows up "
    "as LOCK-008 on `lock --verify --connect`."
)


def _analyze_entry(
    entry: _Entry,
    own_props: list[str],
    names: dict[str, set[tuple]],
    servers_by_identity: dict[tuple, ServerConfig],
) -> list[Finding]:
    """Run DELEG-001..003 over one tool's text."""
    tool_name = _clean_name(entry.tool.name)
    own = capability_classes(split_words(entry.tool.name))
    for prop in own_props:
        own |= capability_classes(split_words(prop))

    other: dict[str, tuple[int, str, str, int]] = {}  # name -> first mention
    d002: tuple[str, str, list[tuple[str, str]]] | None = None
    d003: tuple[str, str, str] | None = None

    for index, (where, text) in enumerate(entry.texts):
        for name, offset in _mentions(text, names):
            owners = names[name]
            if name == entry.tool.name or entry.identity in owners:
                continue
            other.setdefault(name, (index, where, text, offset))
        for _offset, sentence in _sentences(text):
            tokens = _tokens(sentence)
            if not tokens:
                continue
            named = {n for n, _ in _mentions(sentence, names)}
            named_other = any(
                n != entry.tool.name and entry.identity not in names[n] for n in named
            )
            # A sentence naming only this server's own tools documents that
            # server's workflow: no server boundary is crossed.
            own_workflow = bool(named) and not named_other
            if d002 is None and not own_workflow:
                directed = _directed_classes(tokens, own)
                if directed:
                    d002 = (where, sentence, directed)
            if d003 is None and (named_other or _universal_scope(tokens)):
                verb = _rewrite_directive(tokens)
                if verb is not None and _has_target(sentence, tokens):
                    d003 = (where, sentence, verb)

    findings: list[Finding] = []
    if other:
        first_name, (_, where, text, offset) = min(
            other.items(), key=lambda kv: (kv[1][0], kv[1][3])
        )
        excerpt = _excerpt(text, offset)
        shown = sorted(other)[:10]
        owners = sorted(
            {
                _clean_name(servers_by_identity[i].name)
                for n in other
                for i in names[n]
                if i in servers_by_identity
            }
        )[:10]
        more = f" (+{len(other) - len(shown)} more)" if len(other) > len(shown) else ""
        findings.append(
            _finding(
                "DELEG-001",
                entry,
                title=(
                    f"Tool '{tool_name}' names another server's tool "
                    f"'{_clean_name(first_name)}'"
                ),
                description=(
                    f"The text of tool '{tool_name}' on server "
                    f"'{_clean_name(entry.server.name)}' names "
                    f"{', '.join(repr(n) for n in shown)}{more}, exposed by "
                    f"{', '.join(repr(o) for o in owners)}. A tool's description "
                    "is read by the agent as instructions; one that steers the "
                    "agent to another server's tools is how MCPTox's poisoned "
                    "tools work: the poisoned tool never runs, the legitimate "
                    "tool does the damage (arXiv 2508.14925). mcp-audit flags "
                    "the reference, not intent; a server that documents an "
                    "integration with another server also names its tools."
                ),
                evidence=f"{where}: {excerpt}",
                remediation=_REMEDIATION,
            )
        )
    if d002 is not None:
        where, sentence, directed = d002
        verbs = ", ".join(f"{v} ({c})" for v, c in directed[:5])
        findings.append(
            _finding(
                "DELEG-002",
                entry,
                title=(
                    f"Tool '{tool_name}' tells the agent to act when something "
                    "else happens"
                ),
                description=(
                    f"The text of tool '{tool_name}' states a trigger (before, "
                    "after, whenever another action happens) and directs the "
                    f"agent to {verbs}, an action this tool's own name and input "
                    "schema do not offer, so another tool would have to do it. "
                    "This is the implicit-trigger shape MCPTox measured (P2/P3, "
                    "arXiv 2508.14925). Capability classes are inferred from "
                    "words in the tool's name and schema property names, so a "
                    "tool whose name does not say what it does can trip this."
                ),
                evidence=f"{where}: {redact_evidence(sentence)}",
                remediation=_REMEDIATION,
            )
        )
    if d003 is not None:
        where, sentence, verb = d003
        findings.append(
            _finding(
                "DELEG-003",
                entry,
                title=(
                    f"Tool '{tool_name}' tells the agent to rewrite other "
                    "tools' arguments"
                ),
                description=(
                    f"The text of tool '{tool_name}' directs the agent to {verb} "
                    "an argument of calls this tool does not make: a named tool "
                    "of another server, or every call. That is MCPTox's "
                    "parameter-tampering paradigm (P3): the agent calls the "
                    "legitimate tool as asked, with the attacker's values "
                    "(arXiv 2508.14925)."
                ),
                evidence=f"{where}: {redact_evidence(sentence)}",
                remediation=_REMEDIATION,
            )
        )
    return findings


def detect_delegation(
    pairs: list[tuple[ServerConfig, ServerEnumeration]],
    errors: list[str] | None = None,
) -> list[Finding]:
    """Run DELEG-001..003 over every tool of every live-enumerated server.

    Called by :func:`~mcp_audit.scanner.run_scan_async` after COLLIDE-001,
    with the same ``(server, enumeration)`` pairs. Pairs whose enumeration
    failed are skipped; a partial tool list (``tools_error``) is analyzed as
    read. The same logical server configured in several clients is analyzed
    once. Never connects to anything and never executes anything: it reads
    the enumerated text.

    Args:
        pairs: ``(ServerConfig, ServerEnumeration)`` from the ``--connect`` loop.
        errors: When given, budget exhaustion is reported here (the scan's
            ``result.errors``) instead of passing silently.

    Returns:
        DELEG-* findings, at most one per ID per tool.
    """
    budget = _Budget(remaining=MAX_TOTAL_TEXT_CHARS)
    entries: list[tuple[_Entry, list[str]]] = []
    names: dict[str, set[tuple]] = {}
    servers_by_identity: dict[tuple, ServerConfig] = {}
    seen: set[tuple[tuple, str]] = set()

    for server, enumeration in pairs:
        if enumeration.error:
            continue
        identity = server_identity(server)
        servers_by_identity.setdefault(identity, server)
        for tool in enumeration.tools:
            if (identity, tool.name) in seen:
                continue
            seen.add((identity, tool.name))
            if _VALID_NAME.fullmatch(tool.name):
                names.setdefault(tool.name, set()).add(identity)
            if len(entries) >= MAX_TOOLS or budget.remaining <= 0:
                budget.skipped_tools += 1
                continue
            entry = _Entry(server=server, identity=identity, tool=tool)
            entries.append((entry, _read_tool(entry, budget)))

    findings: list[Finding] = []
    for entry, props in entries:
        findings.extend(_analyze_entry(entry, props, names, servers_by_identity))

    if errors is not None:
        if budget.skipped_tools:
            errors.append(
                f"[delegation] {budget.skipped_tools} tool(s) not checked: the "
                f"scan reached its budget ({MAX_TOOLS} tools, "
                f"{MAX_TOTAL_TEXT_CHARS} characters of tool text)"
            )
        if budget.truncated_tools:
            errors.append(
                f"[delegation] {budget.truncated_tools} tool(s) checked in part: "
                f"text beyond {MAX_TOOL_TEXT_CHARS} characters per tool (or the "
                "scan budget) was not read"
            )
        if budget.schema_capped_tools:
            errors.append(
                f"[delegation] {budget.schema_capped_tools} tool(s) have input "
                f"schemas larger than {MAX_SCHEMA_NODES} nodes or deeper than "
                f"{MAX_SCHEMA_DEPTH} levels; the rest was not read"
            )
    return findings
