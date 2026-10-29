"""Saved tool text: ``mcp-lock.tools.json``, the readable half of ``--connect``.

STORY-0123 (issue #215). ``lock --connect`` records only digests, so when
``lock --verify --connect`` reports LOCK-007 or LOCK-008 it can say *that* a
tool changed but not *what* changed. With ``--save-tool-text`` the lock also
writes the tool definitions themselves to a second file beside it, and verify
uses them to show the change.

The file is a **companion, not part of the lock**. ``mcp-lock.json`` is
byte-identical with or without it, its checksum does not cover it, and nothing
about a verdict depends on it: the digests in the lock decide pass or fail. The
file is only trusted for display, and only after each stored definition hashes
to the digest the lock holds for it. A file that does not match (edited by
hand, or from an older run) is reported as out of step and no diff is shown.

Each stored definition is the exact object :func:`tool_digests.tool_definition`
digests (name, title, description, inputSchema, outputSchema, annotations), so
no environment or header value can be in it: those belong to the server
config, which this module never sees.

Shape::

    {
      "_producer": "mcp-audit",
      "_schema_version": 1,
      "servers": {"<client>/<name>": {"tools": {"<tool>": {<definition>}}}}
    }

A server that lists two tools under one name stores a list of definitions for
that name, in the order the digest uses.
"""

from __future__ import annotations

import difflib
import json
import os
import stat
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from mcp_audit.advisory.canonical import CanonicalError, canonicalize
from mcp_audit.lock import tool_digests
from mcp_audit.models import ToolInfo

TOOL_TEXT_FILENAME = "mcp-lock.tools.json"
TOOL_TEXT_PRODUCER = "mcp-audit"
TOOL_TEXT_SCHEMA_VERSION = 1

#: Warn when the file passes this size (bytes) while writing.
WARN_BYTES = 1_000_000
#: Never read a file larger than this; it is not a tool-text file we wrote.
MAX_READ_BYTES = 64_000_000

#: Terminal limits per tool, so one noisy tool cannot bury the rest.
MAX_CHANGES_PER_TOOL = 8
MAX_VALUE_CHARS = 120
MAX_WORD_DIFF_CHARS = 700
_WORD_CONTEXT = 5
#: Largest changed stretch (words, old plus new) that is aligned word by word.
MAX_DIFF_WORDS = 1500
#: Longest before/after text shown in a pull-request comment.
MAX_COMMENT_TEXT = 4000


# ── storing ─────────────────────────────────────────────────────────────────


def tool_text_path(lock_path: Path, override: Path | None = None) -> Path:
    """Return where the tool-text file lives for *lock_path*."""
    return override if override is not None else lock_path.parent / TOOL_TEXT_FILENAME


def server_text(tools: list[ToolInfo]) -> dict:
    """Return one server's record: ``{"tools": {name: definition}}``."""
    grouped: dict[str, list[dict]] = {}
    for tool in tools:
        grouped.setdefault(tool.name, []).append(tool_digests.tool_definition(tool))
    stored: dict[str, object] = {}
    for name, definitions in grouped.items():
        stored[name] = (
            definitions[0]
            if len(definitions) == 1
            else sorted(definitions, key=canonicalize)
        )
    return {"tools": stored}


def build(servers: dict[str, dict]) -> dict:
    """Return a complete tool-text document for *servers*."""
    return {
        "_producer": TOOL_TEXT_PRODUCER,
        "_schema_version": TOOL_TEXT_SCHEMA_VERSION,
        "servers": {key: servers[key] for key in sorted(servers)},
    }


def merge(
    existing: dict | None, new_records: dict[str, dict], keep_keys: set[str]
) -> dict:
    """Merge this run's records into *existing*, like ``tool_digests.merge_section``.

    A server that could not be listed keeps its previous text; a server no
    longer in the lock is dropped.
    """
    servers: dict[str, dict] = {}
    if existing is not None:
        servers.update(existing.get("servers", {}))
    servers.update(new_records)
    return build({k: v for k, v in servers.items() if k in keep_keys})


def serialize(doc: dict) -> bytes:
    """Return *doc* as stable, reviewable bytes (sorted keys, 2-space indent)."""
    return (
        json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode()


def write(path: Path, doc: dict) -> int:
    """Write *doc* atomically to *path*; return the byte count.

    The temporary file is created with a random name and ``O_EXCL`` in the
    same directory, so a planted ``<name>.tmp`` symlink is never followed,
    and it is removed if anything fails.
    """
    data = serialize(doc)
    fd, tmp_name = tempfile.mkstemp(
        prefix=path.name + ".", suffix=".tmp", dir=path.parent
    )
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        os.chmod(tmp_name, 0o644)
        os.replace(tmp_name, path)
    except BaseException:
        Path(tmp_name).unlink(missing_ok=True)
        raise
    return len(data)


def load(path: Path) -> tuple[dict | None, str | None]:
    """Read a tool-text file; return ``(document, problem)``.

    ``(None, None)`` means there is no file. A file that is not a regular
    file, is too large, or is not a tool-text document returns
    ``(None, reason)``; nothing here raises on hostile input.
    """
    try:
        st = path.lstat()
    except FileNotFoundError:
        return None, None
    except OSError as exc:
        return None, f"cannot read {path.name}: {exc.strerror or exc}"
    if not stat.S_ISREG(st.st_mode):
        return None, f"{path.name} is not a regular file"
    if st.st_size > MAX_READ_BYTES:
        return None, f"{path.name} is larger than {MAX_READ_BYTES // 1_000_000} MB"
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError) as exc:
        return None, f"{path.name} is not readable JSON: {type(exc).__name__}"
    if (
        not isinstance(doc, dict)
        or doc.get("_producer") != TOOL_TEXT_PRODUCER
        or doc.get("_schema_version") != TOOL_TEXT_SCHEMA_VERSION
        or not isinstance(doc.get("servers"), dict)
    ):
        return None, f"{path.name} is not a tool-text file this mcp-audit can read"
    return doc, None


# ── checking against the lock ───────────────────────────────────────────────


def stored_definition(doc: dict | None, key: str, tool: str) -> object | None:
    """Return the stored definition (dict, or list for a name collision)."""
    if doc is None:
        return None
    server = doc.get("servers", {}).get(key)
    tools = server.get("tools") if isinstance(server, dict) else None
    return tools.get(tool) if isinstance(tools, dict) else None


def _definition_digest(stored: object) -> str | None:
    """Digest of a stored definition, or ``None`` if it cannot be digested.

    The file is untrusted: nesting past the canonical encoder's limit, a lone
    surrogate or an oversized value is "does not match", never an exception.
    """
    try:
        if isinstance(stored, dict):
            return tool_digests.digest(stored)
        if (
            isinstance(stored, list)
            and stored
            and all(isinstance(d, dict) for d in stored)
        ):
            return tool_digests.digest(sorted(stored, key=canonicalize))
    except (CanonicalError, TypeError, ValueError, RecursionError):
        return None
    return None


def trusted_definition(
    doc: dict | None, locked_server: dict | None, key: str, tool: str
) -> dict | None:
    """Return the stored definition for *tool* only if the lock vouches for it.

    The stored text must hash to the ``definition`` digest the lock holds for
    the tool. A name collision (stored as a list) cannot be shown as one
    definition, so it returns ``None``.
    """
    stored = stored_definition(doc, key, tool)
    if not isinstance(stored, dict):
        return None
    locked_tools = (locked_server or {}).get("tools")
    entry = locked_tools.get(tool) if isinstance(locked_tools, dict) else None
    if not isinstance(entry, dict):
        return None
    return stored if entry.get("definition") == _definition_digest(stored) else None


def out_of_step(doc: dict | None, locked_server: dict | None, key: str) -> list[str]:
    """Names of locked tools whose stored text does not match the lock.

    Empty when there is no file or no record for *key* (nothing to be out of
    step with), or when every stored definition hashes to the lock's digest.
    """
    if doc is None or key not in doc.get("servers", {}):
        return []
    locked_tools = (locked_server or {}).get("tools")
    if not isinstance(locked_tools, dict):
        return []
    bad: list[str] = []
    for tool, entry in sorted(locked_tools.items()):
        if not isinstance(entry, dict):
            continue
        stored = stored_definition(doc, key, tool)
        if stored is None or entry.get("definition") != _definition_digest(stored):
            bad.append(tool)
    return bad


# ── diffing ─────────────────────────────────────────────────────────────────


@dataclass
class FieldChange:
    """One changed path inside a tool's contract (schema or annotations)."""

    path: str
    old: str
    new: str


@dataclass
class ToolChange:
    """What changed in one tool, with the text to show for it."""

    tool: str
    fields: list[FieldChange] = field(default_factory=list)
    #: ``{"title": "...", "description": "..."}`` word diffs, ``[-old-] {+new+}``.
    words: dict[str, str] = field(default_factory=dict)
    #: Words that are new, per text field, used for the poisoning checks.
    added_text: str = ""
    #: POISON/concealment IDs that fire on ``added_text``.
    poison: list[str] = field(default_factory=list)
    before: dict | None = None
    after: dict | None = None

    def to_json(self) -> dict:
        """Return the full, uncapped diff for ``--format json``."""
        return {
            "tool": self.tool,
            "fields": [
                {"path": c.path, "old": redact(c.old), "new": redact(c.new)}
                for c in self.fields
            ],
            "words": {k: redact(v) for k, v in self.words.items()},
            "added_text": redact(self.added_text),
            "poison": self.poison,
            "before": _redacted(self.before),
            "after": _redacted(self.after),
        }


def _redacted(definition: dict | None) -> dict | None:
    if definition is None:
        return None
    return {
        k: redact(v) if k in tool_digests.TEXT_FIELDS and isinstance(v, str) else v
        for k, v in definition.items()
    }


def _show(value: object) -> str:
    if value is _ABSENT:
        return "(absent)"
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


_ABSENT = object()


def _walk(
    old: object, new: object, path: str, out: list[tuple[str, object, object]]
) -> None:
    if isinstance(old, dict) and isinstance(new, dict):
        for key in sorted(set(old) | set(new)):
            _walk(old.get(key, _ABSENT), new.get(key, _ABSENT), _join(path, key), out)
    elif isinstance(old, list) and isinstance(new, list) and len(old) == len(new):
        for i, (a, b) in enumerate(zip(old, new, strict=True)):
            _walk(a, b, f"{path}[{i}]", out)
    elif old != new:
        out.append((path, old, new))


def _join(path: str, key: str) -> str:
    return f"{path}.{key}" if path else key


def field_changes(old: dict, new: dict) -> list[FieldChange]:
    """Field-level changes between two definitions, excluding title/description."""
    a = {k: v for k, v in old.items() if k not in tool_digests.TEXT_FIELDS}
    b = {k: v for k, v in new.items() if k not in tool_digests.TEXT_FIELDS}
    raw: list[tuple[str, object, object]] = []
    _walk(a, b, "", raw)
    return [FieldChange(p, _show(o), _show(n)) for p, o, n in raw]


def word_diff(old: str, new: str) -> tuple[str, str]:
    """Return ``(rendered diff, added words)`` for two pieces of text.

    Removed words render as ``[-word-]``, added as ``{+word+}``; unchanged
    stretches are trimmed to a few words of context.
    """
    a, b = old.split(), new.split()
    # Trim the common head and tail, then refuse to align what is left if it
    # is large: SequenceMatcher is superlinear and the text is server-supplied.
    head = 0
    while head < min(len(a), len(b)) and a[head] == b[head]:
        head += 1
    tail = 0
    while (
        tail < min(len(a), len(b)) - head
        and a[len(a) - 1 - tail] == b[len(b) - 1 - tail]
    ):
        tail += 1
    mid_a, mid_b = a[head : len(a) - tail], b[head : len(b) - tail]
    if len(mid_a) + len(mid_b) > MAX_DIFF_WORDS:
        return (
            f"(changed: {len(mid_a)} words became {len(mid_b)} words; "
            "too long to align, full text in --format json)",
            " ".join(mid_b),
        )
    matcher = difflib.SequenceMatcher(a=a, b=b, autojunk=False)
    parts: list[str] = []
    added: list[str] = []
    for op, a0, a1, b0, b1 in matcher.get_opcodes():
        if op == "equal":
            run = a[a0:a1]
            if len(run) > 2 * _WORD_CONTEXT:
                head = run[:_WORD_CONTEXT] if parts else []
                tail = run[-_WORD_CONTEXT:]
                parts.extend(head)
                parts.append("…")
                parts.extend(tail)
            else:
                parts.extend(run)
            continue
        if a1 > a0:
            parts.append("[-" + " ".join(a[a0:a1]) + "-]")
        if b1 > b0:
            parts.append("{+" + " ".join(b[b0:b1]) + "+}")
            added.extend(b[b0:b1])
    return " ".join(parts), " ".join(added)


def poison_ids(text: str) -> list[str]:
    """IDs of the poisoning checks that fire on *text* (added words only)."""
    if not text.strip():
        return []
    # Imported here: the analyzer pulls in the whole pattern table, which a
    # plain `lock` write never needs.
    from mcp_audit.analyzers import poisoning  # noqa: PLC0415

    norm = poisoning.normalize_for_detection(text)
    ids = [
        p.id
        for p in poisoning.PATTERNS
        if not p.description_only and poisoning.matched_pattern(p, text, norm)
    ]
    for cm in poisoning.scan_concealed_channels(text):
        ids.append(poisoning.concealment_finding_id(cm))
    return sorted(set(ids))


def diff_tool(name: str, before: dict, after: dict) -> ToolChange:
    """Diff two definitions of one tool."""
    change = ToolChange(tool=name, before=before, after=after)
    change.fields = field_changes(before, after)
    added: list[str] = []
    for text_field in tool_digests.TEXT_FIELDS:
        old, new = before.get(text_field), after.get(text_field)
        if old == new:
            continue
        rendered, new_words = word_diff(old or "", new or "")
        change.words[text_field] = rendered
        added.append(new_words)
    change.added_text = " ".join(w for w in added if w)
    change.poison = poison_ids(change.added_text)
    return change


# ── rendering ───────────────────────────────────────────────────────────────


def redact(text: str) -> str:
    """Redact credentials in server-supplied *text* for display."""
    from mcp_audit.analyzers.poisoning import redact_evidence  # noqa: PLC0415

    return redact_evidence(text)


def secret_in(definitions: list[dict]) -> bool:
    """Whether any stored text looks like a credential (warn on save)."""
    from mcp_audit.analyzers.credentials import SECRET_PATTERNS  # noqa: PLC0415

    blob = json.dumps(definitions, ensure_ascii=False)
    return any(p.search(blob) for _l, p, _p in SECRET_PATTERNS)


def _clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def describe(change: ToolChange) -> list[str]:
    """Terminal lines for *change*, capped; the full diff is in JSON."""
    lines: list[str] = []
    shown = change.fields[:MAX_CHANGES_PER_TOOL]
    for c in shown:
        lines.append(
            f"{change.tool}: {c.path}: "
            f"{_clip(redact(c.old), MAX_VALUE_CHARS)} → "
            f"{_clip(redact(c.new), MAX_VALUE_CHARS)}"
        )
    if len(change.fields) > len(shown):
        lines.append(
            f"{change.tool}: … {len(change.fields) - len(shown)} more field "
            "change(s); the full diff is in --format json"
        )
    for text_field, rendered in change.words.items():
        clipped = _clip(redact(rendered), MAX_WORD_DIFF_CHARS)
        suffix = "" if clipped == rendered else " (clipped; full diff in --format json)"
        lines.append(f"{change.tool}: {text_field}: {clipped}{suffix}")
    if change.poison:
        lines.append(
            f"{change.tool}: the added text matches {', '.join(change.poison)}"
        )
    return lines


def describe_added(name: str, definition: dict) -> str:
    """One line showing a new tool's text."""
    text = (
        definition.get("description") or definition.get("title") or "(no description)"
    )
    return f"{name}: {_clip(redact(' '.join(str(text).split())), MAX_WORD_DIFF_CHARS)}"
