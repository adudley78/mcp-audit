"""Follow the files an instruction file pulls into the agent's context.

Two kinds of edge (STORY-0098):

**Claude Code ``@path`` imports** — documented at
https://code.claude.com/docs/en/memory#import-additional-files:

  "CLAUDE.md files can import additional files using ``@path/to/import``
  syntax. Imported files are expanded and loaded into context alongside the
  CLAUDE.md that references them."
  "Relative paths resolve relative to the file containing the import, not the
  working directory. Imported files can recursively import other files, with a
  maximum depth of four hops."
  "the path ends at the first space" (a backslash escapes a space); "A path
  wrapped in quotes isn't imported at all"; "Import parsing skips Markdown code
  spans and fenced code blocks."
  "An import in a project-level memory file is external when its path
  resolves outside your working directory ... it shows an approval dialog."
  Block-level HTML comments are stripped before the content is injected.

  Claude Code also expands imports inside the ``AGENTS.md`` it reads, in
  ``CLAUDE.local.md`` and in ``.claude/rules/`` files.  The published 2.1.100
  package agrees with the documentation: an ``@`` at the start of the text or
  after whitespace, the path running to the first unescaped whitespace, ``#``
  starting a fragment, and acceptance only of ``./``, ``~/``, ``/`` or a name
  starting ``[A-Za-z0-9._-]``.

  Where a Markdown parser and plain text read an ``@`` differently, this
  module takes the reading that follows more imports (``**@x**``, ``(@x)``,
  ``@x.`` with trailing punctuation, ``@x`` in an indented code block): every
  candidate must exist as a file before it counts, so an extra candidate costs
  a ``stat``, not a false finding.

**Prose references** — "read X before starting" sentences.  Bad Memory
(arXiv 2607.14611) put its payloads in files that CLAUDE.md/AGENTS.md told
the agent to read in words ("Read the files in ``knowledge/`` ... before
recommending anything", "See ``../core/behaviors.md``"), not ``@`` imports.
The agent opens these at its own discretion, so they are followed only inside
the scan root and never produce MEM-003.

Rules every edge follows:

- Nothing is executed and nothing is fetched; files are read with a size cap.
- A target outside the scan root is never read.  For a project file's import
  it becomes an ``"outside"`` edge (MEM-003); for a reference it is dropped.
- A symlink anywhere between the root and the target (the target itself or
  any directory on the way) stops the edge: TRUST-002 (project) or TRUST-004
  (user scope) names the link and the target is not read as the repo's own.
- Imports are followed four hops deep (the documented maximum); references
  share the same depth limit.  Each target is read at most once (cycle-safe).
- A per-scan budget caps followed files and bytes; reaching it is recorded in
  *notes*, never silent.
"""

from __future__ import annotations

import bisect
import os
import re
import stat
from collections import deque
from dataclasses import dataclass
from pathlib import Path

from mcp_audit.agent_files.gitignore import GitignoreIndex
from mcp_audit.agent_files.models import (
    MEMORY_SURFACES,
    AgentFile,
    ImportEdge,
)
from mcp_audit.discovery import (
    build_info_symlink_finding,
    build_project_symlink_finding,
)
from mcp_audit.models import Finding

# ── Limits ────────────────────────────────────────────────────────────────────

#: Import hops followed from a root instruction file (Claude Code: "a maximum
#: depth of four hops").
IMPORT_MAX_HOPS: int = 4
#: Bytes read from any one instruction or imported file.  Claude Code skips a
#: memory file over 4 MiB ("Claude Code skips a file over 4 MiB").
READ_CAP_BYTES: int = 4 * 1024 * 1024
#: Imported/referenced files read per scan pass.
MAX_FOLLOWED_FILES: int = 500
#: Bytes read from imported/referenced files per scan pass.
MAX_FOLLOWED_BYTES: int = 32 * 1024 * 1024
#: Import plus reference candidates considered per file.
MAX_EDGES_PER_FILE: int = 200
#: Reference verbs examined per file (bounds the reference scan).
MAX_REFERENCE_VERBS_PER_FILE: int = 2000
#: Characters after a reference verb searched for a path.
_REFERENCE_WINDOW: int = 200
#: Markdown files taken from one referenced directory.
MAX_DIRECTORY_REFERENCE_FILES: int = 20
#: Longest import path considered.
_MAX_IMPORT_CHARS: int = 4096

_CLIENT = "agent-files"


@dataclass
class ReadBudget:
    """Files and bytes still allowed to be read in one scan pass."""

    max_files: int = MAX_FOLLOWED_FILES
    max_bytes: int = MAX_FOLLOWED_BYTES
    files: int = 0
    bytes_read: int = 0
    exhausted: bool = False
    #: Set once the exhaustion has been reported.
    noted: bool = False

    def take(self, size: int) -> bool:
        """Reserve one file of *size* bytes; False when the budget is spent."""
        if self.files + 1 > self.max_files or self.bytes_read + size > self.max_bytes:
            self.exhausted = True
            return False
        self.files += 1
        self.bytes_read += size
        return True


def read_text_capped(path: Path, cap: int = READ_CAP_BYTES) -> tuple[str, bool]:
    """Read at most *cap* bytes of *path* as UTF-8 (errors replaced).

    Line endings are normalised to ``\n`` (``\r\n`` and lone ``\r``), as
    ``Path.read_text`` does in text mode, so CRLF files read the same on
    every platform.  Returns ``(text, truncated)``.  Raises ``OSError`` like
    ``open()``.
    """
    with path.open("rb") as fh:
        data = fh.read(cap + 1)
    truncated = len(data) > cap
    if truncated:
        data = data[:cap]
    text = data.decode("utf-8", errors="replace")
    return text.replace("\r\n", "\n").replace("\r", "\n"), truncated


def _key(path: Path) -> str:
    """Comparison key for a path (lexically normalised, case-folded on Windows)."""
    return os.path.normcase(os.path.normpath(str(path)))


def _within(path: Path, root: Path) -> bool:
    try:
        Path(os.path.normpath(str(path))).relative_to(root)
    except ValueError:
        return False
    return True


# ── Markdown masking ──────────────────────────────────────────────────────────

_FENCE_OPEN_RE = re.compile(r"^ {0,3}(`{3,}|~{3,})(.*)$")


def _blank(chars: list[str], start: int, end: int) -> None:
    for i in range(start, end):
        if chars[i] != "\n":
            chars[i] = " "


def _mask_fences(text: str) -> str:
    """Blank fenced code blocks (same length, so offsets and lines survive).

    An unclosed fence runs to the end of the document, as in CommonMark.
    """
    lines = text.split("\n")
    out: list[str] = []
    fence: str | None = None
    for line in lines:
        if fence is None:
            m = _FENCE_OPEN_RE.match(line)
            if m and not (m.group(1)[0] == "`" and "`" in m.group(2)):
                fence = m.group(1)
                out.append(" " * len(line))
                continue
            out.append(line)
            continue
        stripped = line.strip()
        if (
            len(line) - len(line.lstrip(" ")) <= 3
            and stripped
            and stripped[0] == fence[0]
            and set(stripped) == {fence[0]}
            and len(stripped) >= len(fence)
        ):
            fence = None
        out.append(" " * len(line))
    return "\n".join(out)


def _mask_html_comments(chars: list[str], text: str) -> None:
    """Blank every complete ``<!-- ... -->`` (two-pointer walk, linear)."""
    pos = 0
    while True:
        start = text.find("<!--", pos)
        if start == -1:
            return
        end = text.find("-->", start + 4)
        if end == -1:
            return
        _blank(chars, start, end + 3)
        pos = end + 3


def _mask_code_spans(chars: list[str], text: str) -> None:
    """Blank inline code spans, paragraph by paragraph.

    A run of N backticks opens a span closed by the next run of exactly N
    backticks in the same paragraph; an unmatched run is literal.  Runs are
    indexed once and matched with ``bisect``, so the pass is O(n log n).
    """
    para_start = 0
    n = len(text)
    while para_start < n:
        para_end = text.find("\n\n", para_start)
        if para_end == -1:
            para_end = n
        runs: list[tuple[int, int]] = []
        i = para_start
        while i < para_end:
            j = text.find("`", i, para_end)
            if j == -1:
                break
            k = j
            while k < para_end and text[k] == "`":
                k += 1
            escaped = j > 0 and text[j - 1] == "\\"
            runs.append((j + 1 if escaped else j, k - j - (1 if escaped else 0)))
            i = k
        by_len: dict[int, list[int]] = {}
        for idx, (_start, length) in enumerate(runs):
            if length > 0:
                by_len.setdefault(length, []).append(idx)
        consumed_until = -1
        for idx, (start, length) in enumerate(runs):
            if length <= 0 or start < consumed_until:
                continue
            same = by_len.get(length, [])
            pos = bisect.bisect_right(same, idx)
            while pos < len(same) and runs[same[pos]][0] < consumed_until:
                pos += 1
            if pos >= len(same):
                continue
            close_start, close_len = runs[same[pos]]
            _blank(chars, start, close_start + close_len)
            consumed_until = close_start + close_len
        para_start = para_end + 2


def mask_for_imports(text: str) -> str:
    """Text with code blocks, code spans and HTML comments blanked out.

    The result has the same length and line breaks as *text*, so offsets and
    line numbers still point at the original.  A blanked span becomes spaces,
    which keeps ``x``@y`` an import (Claude Code reads the text after a code
    span as a new text token).
    """
    fenced = _mask_fences(text)
    chars = list(fenced)
    _mask_code_spans(chars, fenced)
    masked = "".join(chars)
    chars = list(masked)
    _mask_html_comments(chars, masked)
    return "".join(chars)


def mask_for_references(text: str) -> str:
    """Text with fenced code blocks and HTML comments blanked (spans kept).

    Prose references are usually written in backticks ("Read ``docs/x.md``"),
    so code spans stay; a fenced block is code, not an instruction.
    """
    fenced = _mask_fences(text)
    chars = list(fenced)
    _mask_html_comments(chars, fenced)
    return "".join(chars)


# ── Import extraction ─────────────────────────────────────────────────────────

# An ``@`` at the start or after whitespace (Claude Code), or after Markdown
# emphasis/link/paren openers (the stricter reading), then a path that runs to
# the first unescaped whitespace.  Each character is consumed by exactly one
# branch, so the scan is linear.
_IMPORT_RE: re.Pattern[str] = re.compile(r"(?:^|(?<=[\s*_\[(]))@((?:[^\s\\]|\\ )+)")
_IMPORT_START_RE: re.Pattern[str] = re.compile(r"[A-Za-z0-9._-]")
_TRAILING_PUNCT = ".,;:!?)]*_~\"'"


@dataclass(frozen=True)
class ImportCandidate:
    """One ``@path`` occurrence: the text as written and the paths to try."""

    raw: str
    line: int
    variants: tuple[str, ...]


def _line_index(text: str) -> list[int]:
    starts = [0]
    pos = text.find("\n")
    while pos != -1:
        starts.append(pos + 1)
        pos = text.find("\n", pos + 1)
    return starts


def _accept(path: str) -> bool:
    if path.startswith(("./", "~/")):
        return True
    if path.startswith("/"):
        return path != "/"
    return not path.startswith("@") and bool(_IMPORT_START_RE.match(path))


def extract_imports(
    text: str, limit: int = MAX_EDGES_PER_FILE
) -> list[ImportCandidate]:
    """Return the ``@path`` imports in *text*, as Claude Code would read them.

    Args:
        text: The instruction file's content.
        limit: Maximum candidates returned.

    Returns:
        One :class:`ImportCandidate` per accepted ``@`` occurrence, in order.
    """
    masked = mask_for_imports(text)
    starts = _line_index(masked)
    out: list[ImportCandidate] = []
    for m in _IMPORT_RE.finditer(masked):
        path = m.group(1)
        hash_at = path.find("#")
        if hash_at != -1:
            path = path[:hash_at]
        path = path.replace("\\ ", " ")
        if not path or len(path) > _MAX_IMPORT_CHARS or not _accept(path):
            continue
        variants: list[str] = [path]
        trimmed = path.rstrip(_TRAILING_PUNCT)
        if trimmed and trimmed != path:
            variants.append(trimmed)
        link_at = path.find("](")
        if link_at > 0:
            variants.append(path[:link_at])
        strong_at = path.find("**")
        if strong_at > 0:
            variants.append(path[:strong_at])
        seen: list[str] = []
        for v in variants:
            if v and v not in seen and _accept(v):
                seen.append(v)
        if not seen:
            continue
        line = bisect.bisect_right(starts, m.start())
        out.append(ImportCandidate(raw=m.group(1), line=line, variants=tuple(seen)))
        if len(out) >= limit:
            break
    return out


# ── Prose-reference extraction ────────────────────────────────────────────────

_REF_VERB_RE: re.Pattern[str] = re.compile(
    r"\b(?:read|re-read|reread|load|follow|consult|review|study|obey)\b",
    re.IGNORECASE,
)
# What may precede the verb in its clause for the sentence to be an order
# ("Read X", "- Always read X", "Before starting any task, read X"); a
# cross-reference in the middle of a sentence ("... is described; read more
# in docs/x.md") is not followed.  Clause boundaries are . ! ? ; : and the
# line start.  Bounded (the prefix is at most 120 characters).
_REF_LEAD_RE: re.Pattern[str] = re.compile(
    r"^(?:always|first|then|also|please|now|next|finally|and|so|"
    r"you\s+must|you\s+should|make\s+sure\s+(?:to|you)|be\s+sure\s+to|"
    r"remember\s+to|(?:before|after|when|whenever|if|at\s+the\s+start\s+of)\b"
    r"[^.;:!?]{0,100},)?$",
    re.IGNORECASE,
)
_REF_BULLET_CHARS = "-*+>#`_ \t0123456789.)"
_REF_EXTENSIONS = (".md", ".mdc", ".markdown", ".txt")
_REF_STRIP = "()[]<>\"',;:*_!?"


@dataclass(frozen=True)
class ReferenceCandidate:
    """One "read X" reference: the path as written and whether it is a dir."""

    raw: str
    line: int
    is_dir: bool


def _sentence_window(line: str, start: int) -> str:
    window = line[start : start + _REFERENCE_WINDOW]
    stop = window.find(". ")
    return window if stop == -1 else window[:stop]


def _reference_tokens(window: str) -> list[tuple[str, bool]]:
    """Backticked spans and bare words in *window* (linear, no regex)."""
    tokens: list[tuple[str, bool]] = []
    pos = 0
    while True:
        open_at = window.find("`", pos)
        if open_at == -1:
            break
        close_at = window.find("`", open_at + 1)
        if close_at == -1:
            break
        tokens.append((window[open_at + 1 : close_at], True))
        pos = close_at + 1
    for word in window.split():
        if "`" in word:
            continue
        tokens.append((word.strip(_REF_STRIP).rstrip("."), False))
    return tokens


def _starts_clause(line: str, pos: int) -> bool:
    """True when the verb at *pos* begins an order in its clause."""
    start = max(line.rfind(c, 0, pos) for c in ".;:!?") + 1
    prefix = line[start:pos]
    if len(prefix) > 120:
        return False
    prefix = prefix.lstrip(_REF_BULLET_CHARS).strip().strip("*_").strip()
    return bool(_REF_LEAD_RE.match(prefix))


def extract_references(
    text: str, limit: int = MAX_EDGES_PER_FILE
) -> list[ReferenceCandidate]:
    """Return "read X" style references to Markdown/text files or directories.

    A reference is a path ending ``.md``/``.mdc``/``.markdown``/``.txt`` (or a
    backticked directory ending ``/``) within 200 characters after an order to
    read it — read / re-read / load / follow / consult / review / study / obey
    at the start of a clause, optionally after "always", "first", "you must",
    "before ...," and similar — in the same sentence, outside fenced code.
    URLs, ``@`` imports and absolute or home paths are not references (the
    latter are never read).
    """
    masked = mask_for_references(text)
    out: list[ReferenceCandidate] = []
    seen: set[str] = set()
    verbs = 0
    for line_no, line in enumerate(masked.split("\n"), start=1):
        for verb in _REF_VERB_RE.finditer(line):
            verbs += 1
            if verbs > MAX_REFERENCE_VERBS_PER_FILE or len(out) >= limit:
                return out
            if not _starts_clause(line, verb.start()):
                continue
            for token, backticked in _reference_tokens(
                _sentence_window(line, verb.end())
            ):
                if not token or "://" in token or token.startswith(("@", "~", "/")):
                    continue
                if any(c.isspace() for c in token) or len(token) > _MAX_IMPORT_CHARS:
                    continue
                is_dir = backticked and token.endswith("/")
                if not is_dir and not token.lower().endswith(_REF_EXTENSIONS):
                    continue
                if token in seen:
                    continue
                seen.add(token)
                out.append(ReferenceCandidate(raw=token, line=line_no, is_dir=is_dir))
                if len(out) >= limit:
                    return out
    return out


# ── Resolution ────────────────────────────────────────────────────────────────


def _win32_name(path: Path, windows: bool = os.name == "nt") -> Path:
    """Drop trailing dots and spaces from each component on Windows.

    Win32 strips them when it opens a file, so ``@docs/style.md.`` opens
    ``docs\\style.md`` there; naming the target the same way keeps
    deduplication and reporting consistent across platforms.
    """
    if not windows:
        return path
    parts = []
    for part in path.parts:
        trimmed = part.rstrip(". ")
        parts.append(part if part in (".", "..") or not trimmed else trimmed)
    return Path(*parts) if parts else path


def _resolve_import_path(raw: str, importing: Path, home: Path) -> Path:
    if raw.startswith("~/"):
        target = home / raw[2:]
    elif raw.startswith("/"):
        target = Path(raw)
    else:
        target = importing.parent / raw
    return _win32_name(Path(os.path.normpath(str(target))))


def _first_symlink(root: Path, target: Path) -> Path | None | bool:
    """Walk from *root* to *target* with ``lstat``.

    Returns the first path on the way that is a symlink, ``False`` when the
    target does not exist (or a component is not a directory), and ``None``
    when every component is real and the target is a regular file.
    """
    rel = target.relative_to(root)
    current = root
    parts = rel.parts
    for idx, part in enumerate(parts):
        current = current / part
        try:
            st = os.lstat(current)
        except OSError:
            return False
        if stat.S_ISLNK(st.st_mode):
            return current
        last = idx == len(parts) - 1
        if last and not stat.S_ISREG(st.st_mode):
            return False
        if not last and not stat.S_ISDIR(st.st_mode):
            return False
    return None


def _islink(path: Path) -> bool:
    try:
        return path.is_symlink()
    except OSError:
        return False


def _is_regular_file(path: Path) -> bool:
    try:
        return path.is_file()
    except OSError:
        return False


@dataclass
class _Resolved:
    target: Path
    status: str  # followed | outside | symlink
    link: Path | None = None


def _classify(target: Path, root: Path) -> _Resolved | None:
    """Classify an existing candidate; ``None`` when it does not exist."""
    if not _within(target, root):
        if _is_regular_file(target):
            return _Resolved(target, "outside")
        return None
    found = _first_symlink(root, target)
    if found is False:
        return None
    if isinstance(found, Path):
        return _Resolved(target, "symlink", link=found)
    return _Resolved(target, "followed")


def _resolve_import(
    cand: ImportCandidate, importing: Path, root: Path, home: Path
) -> _Resolved | None:
    for variant in cand.variants:
        target = _resolve_import_path(variant, importing, home)
        resolved = _classify(target, root)
        if resolved is not None:
            return resolved
    return None


def _resolve_reference(
    cand: ReferenceCandidate, importing: Path, root: Path
) -> list[_Resolved]:
    """Resolve a reference against the file's directory, then the root."""
    for base in (importing.parent, root):
        target = _win32_name(Path(os.path.normpath(str(base / cand.raw))))
        if not _within(target, root):
            continue
        if cand.is_dir:
            found = _first_symlink_dir(root, target)
            if isinstance(found, Path):
                return [_Resolved(target, "symlink", link=found)]
            if found is False:
                continue
            results: list[_Resolved] = []
            try:
                children = sorted(target.iterdir())
            except OSError:
                continue
            for child in children:
                if len(results) >= MAX_DIRECTORY_REFERENCE_FILES:
                    break
                if child.suffix.lower() != ".md":
                    continue
                resolved = _classify(child, root)
                if resolved is not None:
                    results.append(resolved)
            if results:
                return results
            continue
        resolved = _classify(target, root)
        if resolved is not None:
            return [resolved]
    return []


def _first_symlink_dir(root: Path, target: Path) -> Path | None | bool:
    """Like :func:`_first_symlink` but the target must be a real directory."""
    rel = target.relative_to(root)
    current = root
    for part in rel.parts:
        current = current / part
        try:
            st = os.lstat(current)
        except OSError:
            return False
        if stat.S_ISLNK(st.st_mode):
            return current
        if not stat.S_ISDIR(st.st_mode):
            return False
    return None


# ── Following ─────────────────────────────────────────────────────────────────


def _symlink_finding(link: Path, scope: str, root: Path) -> Finding:
    if scope == "project":
        return build_project_symlink_finding(link, _CLIENT, root)
    return build_info_symlink_finding(link, _CLIENT)


def _read_followed(
    target: Path,
    parent: AgentFile,
    kind: str,
    budget: ReadBudget,
    notes: list[str],
) -> AgentFile | None:
    try:
        size = os.stat(target).st_size
    except OSError as exc:
        notes.append(f"agent-file imports: cannot stat {target}: {exc}")
        return None
    if not budget.take(min(size, READ_CAP_BYTES)):
        return None
    try:
        text, truncated = read_text_capped(target)
    except OSError as exc:
        notes.append(f"agent-file imports: cannot read {target}: {exc}")
        return None
    if truncated:
        notes.append(
            f"agent-file imports: {target} is over {READ_CAP_BYTES} bytes;"
            " only the first part was scanned (Claude Code skips such a file)"
        )
    if "\x00" in text[:8192]:
        return None
    return AgentFile(
        path=target,
        surface=parent.surface,
        client=parent.client,
        scope=parent.scope,
        raw_content=text,
        body=text,
        follows_imports=kind == "import" and parent.follows_imports,
        imported_from=parent.path,
        truncated=truncated,
    )


def _body_line_offset(af: AgentFile) -> int:
    """Lines of frontmatter before :attr:`AgentFile.body` in the file."""
    raw, body = af.raw_content, af.body
    if body and raw.endswith(body) and len(raw) > len(body):
        return raw[: len(raw) - len(body)].count("\n")
    return 0


def follow_references(
    files: list[AgentFile],
    *,
    project_root: Path | None,
    home: Path | None = None,
    include_references: bool = True,
    budget: ReadBudget | None = None,
    skip_findings: list[Finding] | None = None,
    notes: list[str] | None = None,
) -> list[AgentFile]:
    """Follow imports and references out of *files*; return the new files.

    Each file in *files* (and each file reached) gets its :attr:`AgentFile.edges`
    filled in.  Files reached for the first time are returned with
    ``imported_from`` set; files already in *files* are never returned twice.

    Args:
        files: Discovered instruction files (any surface; only
            :data:`MEMORY_SURFACES` files are followed).
        project_root: Resolved scan root for ``scope="project"`` files.
            ``None`` when only user-scope files are present.
        home: The user's home directory (root for ``scope="user"`` files and
            the expansion of ``~/``); defaults to :meth:`Path.home`.
        include_references: Also follow "read X" prose references.
        budget: Shared read budget for the scan pass.
        skip_findings: Receives TRUST-002 (project) / TRUST-004 (user) for a
            symlink on the way to a target.
        notes: Receives one line per budget stop or read problem.

    Returns:
        Newly reached files, in breadth-first order.
    """
    home = home if home is not None else Path.home()
    budget = budget if budget is not None else ReadBudget()
    notes_out: list[str] = notes if notes is not None else []
    gitignore: GitignoreIndex | None = (
        GitignoreIndex(project_root, notes_out) if project_root is not None else None
    )
    visited: set[str] = {_key(f.path) for f in files}
    reported_links: set[str] = set()
    new_files: list[AgentFile] = []
    # A start file that is itself a symlink is not followed: its content is
    # not the scanned folder's own (it is reported as TRUST-002/004), and
    # Claude Code resolves its relative imports against the link's target.
    queue: deque[tuple[AgentFile, int]] = deque(
        (f, 0) for f in files if f.surface in MEMORY_SURFACES and not _islink(f.path)
    )
    while queue:
        af, depth = queue.popleft()
        if depth >= IMPORT_MAX_HOPS:
            continue
        root = project_root if af.scope == "project" else home
        if root is None:
            continue
        offset = _body_line_offset(af)
        work: list[tuple[str, _Resolved, str, int]] = []
        if af.follows_imports:
            for cand in extract_imports(af.body):
                resolved = _resolve_import(cand, af.path, root, home)
                if resolved is not None:
                    work.append(("import", resolved, cand.raw, cand.line + offset))
        if include_references:
            for ref in extract_references(af.body):
                for resolved in _resolve_reference(ref, af.path, root):
                    if resolved.status != "outside":
                        work.append(("reference", resolved, ref.raw, ref.line + offset))

        for kind, resolved, raw, line in work[:MAX_EDGES_PER_FILE]:
            status = resolved.status
            detail = ""
            if status == "outside" and af.scope != "project":
                # A user-scope file importing from outside $HOME: the user's
                # own configuration; nothing to read or report.
                continue
            if status == "symlink" and resolved.link is not None:
                link_key = _key(resolved.link)
                if skip_findings is not None and link_key not in reported_links:
                    reported_links.add(link_key)
                    skip_findings.append(
                        _symlink_finding(resolved.link, af.scope, root)
                    )
            if (
                status == "followed"
                and kind == "import"
                and af.scope == "project"
                and gitignore is not None
            ):
                ignored = gitignore.ignored_by(resolved.target)
                if ignored is not None:
                    status = "ignored"
                    detail = ignored
            if status in ("followed", "ignored"):
                tkey = _key(resolved.target)
                if tkey not in visited:
                    if budget.exhausted:
                        status = "skipped"
                    else:
                        visited.add(tkey)
                        reached = _read_followed(
                            resolved.target, af, kind, budget, notes_out
                        )
                        if reached is None and budget.exhausted:
                            status = "skipped"
                        elif reached is not None:
                            new_files.append(reached)
                            queue.append((reached, depth + 1))
                    if status == "skipped" and not budget.noted:
                        budget.noted = True
                        notes_out.append(
                            "agent-file imports: stopped after"
                            f" {budget.max_files} files / {budget.max_bytes} bytes;"
                            " later imports and references were not read"
                        )
            af.edges.append(
                ImportEdge(
                    raw=raw,
                    line=line,
                    target=resolved.target,
                    kind=kind,
                    status=status,
                    detail=detail,
                )
            )
    return new_files
