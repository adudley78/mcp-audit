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
from mcp_audit.agent_files.subagents import redact_secrets
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
#: Resolved imports plus references (targets that exist) followed per file.
MAX_EDGES_PER_FILE: int = 200
#: ``@`` tokens examined per file (most are not imports: emails, handles).
MAX_IMPORT_TOKENS: int = 10_000
#: Reference candidates (paths after a "read" verb) examined per file.
MAX_REFERENCE_CANDIDATES: int = 10_000
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
#
# Claude Code lexes an instruction file as Markdown and looks for ``@`` only in
# text: it skips code blocks and code spans, strips HTML comments from
# comment blocks (scanning what is left), and skips other HTML.  This module
# approximates that with a line pass and an inline pass, and wherever the
# approximation could differ it hides less, never more: a candidate it should
# not have seen costs a ``stat`` (every candidate must exist), a hidden one
# would be a missed import.
#
# - Fenced code blocks (backtick or tilde, up to three spaces of indent) are
#   blanked, line by line, until the closing fence.
# - A line starting with ``<!--`` (at a block start, or unindented) opens an
#   HTML comment block that runs to the first line containing ``-->``; inside
#   it only the ``<!-- ... -->`` parts are blanked (Claude Code scans the
#   rest as written), and a fence line inside it is not a fence.  The same
#   holds for a blockquote whose content opens with ``<!--``.  An unclosed
#   one is scanned as text.
# - The rest is split into blocks at blank or whitespace-only lines, ATX
#   headings, thematic breaks, list-item starts, lines that may open an HTML
#   block or a blockquote, and the blocks above.  Each block is read left to
#   right as Markdown inline text (backslash escapes, code spans, HTML
#   comments and tags).  A character is blanked only if that reading hides it
#   and so does the reading of the widest paragraph the lines could form
#   (split only where a paragraph certainly ends).  A comment runs over more
#   than one line only in a block that starts as a plain paragraph.
# - List items are read the same way, and an ``@`` that starts their raw
#   text or follows whitespace in it is kept as written: Claude Code also
#   scans a list item's text as written.
# - Indented code and other HTML blocks are scanned as text.

_FENCE_OPEN_RE = re.compile(r"^ {0,3}(`{3,}|~{3,})(.*)$")
_COMMENT_BLOCK_RE = re.compile(r"^ {0,3}<!--")
# A blockquote whose content opens with a comment: an HTML block inside it.
_QUOTE_COMMENT_RE = re.compile(r"^(?:[ \t]{0,3}>[ \t]?)+[ \t]{0,3}<!--")
_QUOTE_LINE_RE = re.compile(r"^[ \t]{0,3}>")
_QUOTE_PREFIX_RE = re.compile(r"^(?:[ \t]{0,3}>[ \t]?)+")
_HEADING_RE = re.compile(r"^ {0,3}#{1,6}(?:[ \t]|$)")
# A line that may start an HTML block or a blockquote, either of which ends
# the paragraph before it.
_BLOCK_START_RE = re.compile(r"^ {0,3}(?:<[A-Za-z/!?]|>)")
_HTML_START_RE = re.compile(r"^ {0,3}<[A-Za-z/!?]")
_LONE_TAG_RE = re.compile(r"^ {0,3}<[^\n>]+>$")
# A setext heading underline (or a thematic break made of dashes).
_SETEXT_RE = re.compile(r"^ {0,3}(?:=+|-+)[ \t]*$", re.MULTILINE)
_QUOTE_ANY_RE = re.compile(r"^[ \t]{0,3}>", re.MULTILINE)
_HTML_LINE_RE = re.compile(r"^ {0,3}<[A-Za-z/!?]", re.MULTILINE)
# A list item that ends any paragraph above it (one starting at 1, or a
# bullet, with text after the marker).
_LIST_INTERRUPT_RE = re.compile(
    r"^(?:[ \t]{0,3}>[ \t]?)*[ \t]{0,3}(?:[-*+]|1[.)])[ \t]"
)
# A line that may end a list item even when indented under it.
_ITEM_BREAK_RE = re.compile(r"^ {0,3}(?:#|```|~~~|<)")
_LIST_ITEM_RE = re.compile(
    r"^(?:[ \t]{0,3}>[ \t]?)*[ \t]{0,3}(?:[-*+]|\d{1,9}[.)])(?:[ \t]|$)"
)
# A thematic break or setext underline: either ends the paragraph above it.
_BREAK_RE = re.compile(
    r"^ {0,3}(?:(?:\*[ \t]*){3,}|(?:-[ \t]*){2,}|(?:_[ \t]*){3,}|=+[ \t]*)$"
)
# Inline: what can hide text, or stop a backtick from opening a code span.
_INLINE_STOP_RE = re.compile(r"\\|`|<|\[")
# An inline link or image: label (with any code spans in it), destination
# and title, whose backticks open nothing.  Possessive, so it never
# backtracks; matched on at most _LINK_MAX_CHARS characters.
_LINK_RE = re.compile(
    r"!?\[((?:\\.|`[^`]*+`|[^\[\]\\`]|\[(?:\\.|[^\[\]\\])*+\])*+)\]"
    r"\(\s*+(?:<(?:\\.|[^\n<>\\])*+>|[^\s()<>]*+(?:\([^\s()]*+\)[^\s()<>]*+)*+)"
    r"(?:\s++(?:\"(?:\\.|[^\"\\])*+\"|'(?:\\.|[^'\\])*+'|\((?:\\.|[^()\\])*+\)))?+"
    r"\s*+\)"
)
_LINK_MAX_CHARS = 4096
# An inline HTML tag or autolink, which may hold a backtick that therefore
# opens no code span.  Matched on at most _TAG_MAX_CHARS characters.
_TAG_RE = re.compile(
    r"</?[A-Za-z][A-Za-z0-9-]*"
    r"(?:\s+[A-Za-z_:][A-Za-z0-9_.:-]*"
    r"(?:\s*=\s*(?:[^\s\"'=<>`]+|'[^']*'|\"[^\"]*\"))?)*\s*/?>"
    r"|<[A-Za-z][A-Za-z0-9+.-]{1,31}:[^\s<>\x00-\x1f]*>"
)
_TAG_MAX_CHARS = 1024
# Other inline HTML that runs to a fixed closer: CDATA, a processing
# instruction, a declaration.
_HTML_OTHER: tuple[tuple[str, str], ...] = (
    ("<![CDATA[", "]]>"),
    ("<?", "?>"),
    ("<!", ">"),
)
_ASCII_PUNCT = frozenset("!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~")


def _indent(line: str) -> int:
    """Leading whitespace in columns, a tab reaching the next multiple of 4."""
    col = 0
    for ch in line:
        if ch == " ":
            col += 1
        elif ch == "\t":
            col += 4 - col % 4
        else:
            break
    return col


def _blank(chars: list[str], start: int, end: int) -> None:
    for i in range(start, end):
        if chars[i] != "\n":
            chars[i] = " "


def _closes_fence(line: str, fence: str) -> bool:
    stripped = line.strip()
    return (
        len(line) - len(line.lstrip(" ")) <= 3
        and bool(stripped)
        and set(stripped) == {fence[0]}
        and len(stripped) >= len(fence)
    )


@dataclass
class _Blocks:
    """Result of the line pass over one document."""

    masked: list[tuple[int, int]]  # fences and comment-block comments
    # Inline-content blocks: (start, end, paragraph).  Only in a block that
    # starts as a plain paragraph may a comment run over more than one line.
    inline: list[tuple[int, int, bool]]
    lists: list[tuple[int, int]]  # list items: inline, plus their raw text
    # The widest paragraphs the lines could form: split only where a
    # paragraph certainly ends (blank line, fence, comment block, heading,
    # break, HTML block).  Text is hidden only if it is hidden here too.
    wide: list[tuple[int, int]]


_SPECIAL_FIRST = frozenset("`~<>#*-_=+0123456789")


def _quote_run_ends(lines: list[str]) -> list[int]:
    """For each line, the last line of the run of blockquote lines it starts
    (one before it if it is not a blockquote line), plus a sentinel."""
    n = len(lines)
    ends = [n - 1] * (n + 1)
    for k in range(n - 1, -1, -1):
        if _QUOTE_LINE_RE.match(lines[k]):
            ends[k] = ends[k + 1] if k + 1 < n and ends[k + 1] >= k + 1 else k
        else:
            ends[k] = k - 1
    return ends


def _comment_ranges(text: str, start: int, end: int) -> list[tuple[int, int]]:
    """Every complete ``<!-- ... -->`` in ``text[start:end]`` (linear walk)."""
    out: list[tuple[int, int]] = []
    pos = start
    while True:
        open_at = text.find("<!--", pos, end)
        if open_at == -1:
            return out
        close_at = text.find("-->", open_at + 4, end)
        if close_at == -1:
            return out
        out.append((open_at, close_at + 3))
        pos = close_at + 3


def _scan_blocks(
    text: str,
    *,
    greedy_lists: bool = False,
    html_blocks: bool = False,
    setext: bool = False,
    quote_lazy: bool = False,
) -> _Blocks:
    """One pass over the lines of *text* (see the section comment above).

    With *greedy_lists*, a list item's text runs to the next blank line
    whatever the following lines look like (the second reading).  With
    *html_blocks*, a line starting with a tag starts an HTML block that runs
    to the next blank line and is scanned as written, fence-like lines
    included (the third reading).  With *setext*, a line starting with
    ``<!--`` or a tag (other than a lone tag) does not end a paragraph, as
    inside a setext heading's text (the fourth reading).  With *quote_lazy*,
    a comment block over several lines after a blockquote line (with no
    blank line between) is not one, as some readers keep such lines in the
    blockquote, whose end then cuts the comment short (the fifth reading).
    """
    lines = text.split("\n")
    starts: list[int] = []
    pos = 0
    for line in lines:
        starts.append(pos)
        pos += len(line) + 1
    masked: list[tuple[int, int]] = []
    inline: list[tuple[int, int, bool]] = []
    lists: list[tuple[int, int]] = []
    wide: list[tuple[int, int]] = []
    block_start: int | None = None
    block_is_list = False
    block_is_paragraph = False
    # A list item's lazy line: where its paragraph starts is uncertain, so it
    # is scanned as written.
    block_is_lazy = False
    # A blockquote since the last blank line: a container whose end (which
    # some readers place after lazy lines) may cut a comment block short.
    quote_seen = False
    wide_start: int | None = None
    wide_quoted = False  # the current widest paragraph holds a blockquote line

    def _close(end: int) -> None:
        nonlocal block_start
        if block_start is not None and end > block_start and not block_is_lazy:
            if block_is_list:
                lists.append((block_start, end))
            else:
                inline.append((block_start, end, block_is_paragraph))
        block_start = None

    def _close_wide(end: int) -> None:
        nonlocal wide_start, wide_quoted
        if wide_start is not None and end > wide_start:
            wide.append((wide_start, end))
        wide_start = None
        wide_quoted = False

    i = 0
    n = len(lines)
    # next_close[k]: first line at or after k containing "-->" (n if none),
    # so finding a comment block's end never rescans (linear overall).
    next_close = [n] * (n + 1)
    for k in range(n - 1, -1, -1):
        next_close[k] = k if "-->" in lines[k] else next_close[k + 1]
    quote_run_end: list[int] | None = None
    fence: str | None = None
    while i < n:
        line = lines[i]
        line_start = starts[i]
        line_end = line_start + len(line)
        if fence is not None:
            masked.append((line_start, line_end))
            if _closes_fence(line, fence):
                fence = None
            i += 1
            continue
        # After a list item, a line may still be the item's (lazy) text.
        list_context = block_is_list and block_start is not None
        in_greedy_list = greedy_lists and list_context
        # Every block-level construct below starts with one of a few
        # characters; a line starting otherwise skips their patterns.
        first = line.lstrip(" \t")[:1]
        special = first in _SPECIAL_FIRST
        m = _FENCE_OPEN_RE.match(line) if first in ("`", "~") else None
        if m and not (m.group(1)[0] == "`" and "`" in m.group(2)):
            _close(line_start)
            _close_wide(line_start)
            fence = m.group(1)
            masked.append((line_start, line_end))
            i += 1
            continue
        # Inside a paragraph that may be a setext heading's text (fourth
        # reading), HTML-looking lines are that text.
        in_setext = setext and block_start is not None and not block_is_list
        # A comment block starts a block; inside a paragraph or list item only
        # an unindented one interrupts it (otherwise it is that block's text).
        if (
            first == "<"
            and _COMMENT_BLOCK_RE.match(line)
            and (
                block_start is None
                or (line.startswith("<!--") and not in_greedy_list and not in_setext)
            )
        ):
            open_at = line.index("<!--")
            # "<!-->" and "<!--->" are whole comments (the block ends here).
            closes_here = line.startswith((">", "->"), open_at + 4) or (
                line.find("-->", open_at + 4) != -1
            )
            j = i if closes_here else next_close[i + 1]
            if j < n and not (quote_lazy and quote_seen and j > i):
                _close(line_start)
                _close_wide(line_start)
                block_end = starts[j] + len(lines[j])
                masked.extend(_comment_ranges(text, line_start, block_end))
                i = j + 1
                continue
            # Unclosed: scanned as ordinary text (Claude Code skips it).
        if first == ">" and not list_context and _QUOTE_COMMENT_RE.match(line):
            # Runs over the blockquote's lines to the first with "-->" and is
            # then read like a comment block.  A line without ">" ends it (an
            # HTML block has no lazy continuation).  Unclosed, its first line
            # is scanned as written and the rest read as usual.  After a
            # blockquote paragraph it may be that paragraph's text instead,
            # so the widest reading runs on through it.
            _close(line_start)
            if not wide_quoted:
                _close_wide(line_start)
            open_at = line.index("<!--")
            j = i
            closed = line.startswith((">", "->"), open_at + 4) or (
                "-->" in line[open_at + 4 :]
            )
            if not closed and i + 1 < n:
                if quote_run_end is None:
                    quote_run_end = _quote_run_ends(lines)
                j = next_close[i + 1]
                closed = j <= quote_run_end[i + 1]
            if closed:
                masked.extend(
                    _comment_ranges(text, line_start, starts[j] + len(lines[j]))
                )
                i = j + 1
            else:
                i += 1
            quote_seen = True
            continue
        quote = _QUOTE_PREFIX_RE.match(line) if first == ">" else None
        quote_seen = quote_seen or quote is not None
        if list_context and quote and not _LIST_ITEM_RE.match(line):
            # A blockquote line after a list item: a block of its own, and
            # the item's text after it is read apart from the text before.
            _close(line_start)
            _close_wide(line_start)
            wide.append((line_start, line_end))
            block_start = line_start
            block_is_lazy = True
            i += 1
            continue
        content = line[quote.end() :] if quote else line
        if not content.strip():
            # A blank line, or a blank line inside a blockquote: either ends
            # a paragraph (one holding a tab may not, so the widest reading
            # runs on through it).
            _close(line_start)
            if "\t" not in line:
                _close_wide(line_start)
            if not quote:
                quote_seen = False
            i += 1
            continue
        fm = _FENCE_OPEN_RE.match(content) if quote else None
        if fm and not (fm.group(1)[0] == "`" and "`" in fm.group(2)):
            # A fence inside a blockquote: code over the quote's lines to its
            # closing fence.  Scanned as written, and apart from what follows.
            _close(line_start)
            _close_wide(line_start)
            j = i
            while j + 1 < n:
                nxt = _QUOTE_PREFIX_RE.match(lines[j + 1])
                if nxt is None:
                    break
                j += 1
                if _closes_fence(lines[j][nxt.end() :], fm.group(1)):
                    break
            i = j + 1
            continue
        if html_blocks and first == "<" and _HTML_START_RE.match(line):
            _close(line_start)
            _close_wide(line_start)
            j = i
            while j + 1 < n and lines[j + 1].strip():
                j += 1
            i = j + 1
            continue
        # A heading or break, also inside a blockquote, is a block of its own;
        # so is a blockquote line opening HTML or indented code, which takes
        # no lazy lines after it.
        heading = special and bool(
            _HEADING_RE.match(content)
            or _BREAK_RE.match(content)
            or (quote and (_HTML_START_RE.match(content) or _indent(content) >= 4))
        )
        if heading:
            _close_wide(line_start)
            wide.append((line_start, line_end))
        elif (special and _LIST_INTERRUPT_RE.match(line)) or (
            quote and not wide_quoted
        ):
            # A list item, or a blockquote after plain lines, ends the
            # paragraph above it.
            _close_wide(line_start)
            wide_start = line_start
        elif wide_start is None:
            wide_start = line_start
        wide_quoted = (wide_quoted and wide_start is not None) or (
            quote is not None and wide_start is not None
        )
        if in_greedy_list:
            pass
        elif heading:
            _close(line_start)
            inline.append((line_start, line_end, False))
        elif special and _LIST_ITEM_RE.match(line):
            _close(line_start)
            block_start = line_start
            block_is_list = True
            block_is_lazy = False
        elif list_context and (
            _indent(line) < 2 or (special and _ITEM_BREAK_RE.match(line))
        ):
            # A lazy or barely indented line after a list item: it may be the
            # item's text or start a new block, and which line a new
            # paragraph would start at is not certain, so it is scanned as
            # written.
            _close(line_start)
            block_start = line_start
            block_is_lazy = True
        elif (
            first in ("<", ">")
            and _BLOCK_START_RE.match(line)
            and not (
                in_setext
                and _HTML_START_RE.match(line)
                and not _LONE_TAG_RE.match(line)
            )
        ):
            # A blockquote or HTML block: what follows it may be a new
            # paragraph, so a comment is hidden only within one line.
            _close(line_start)
            block_start = line_start
            block_is_list = False
            block_is_paragraph = False
            block_is_lazy = False
        elif block_start is None and _indent(line) >= 4:
            # Indented code, or a list item's text (kept as written where
            # its raw text would be): read on its own.
            lists.append((line_start, line_end))
        elif block_start is None:
            block_start = line_start
            # An indented block may be a list item's continuation.
            block_is_list = _indent(line) >= 2
            block_is_paragraph = True
            block_is_lazy = False
        i += 1
    _close(len(text))
    _close_wide(len(text))
    return _Blocks(masked=masked, inline=inline, lists=lists, wide=wide)


class _Index:
    """Positions in one text that every reading looks up: backtick runs by
    length, inline stop characters, and the closers of comments and other
    inline HTML.  Built once (linear), searched by bisection, and holding the
    inline reading of each block so that readings sharing a block share it.
    """

    def __init__(self, text: str) -> None:
        self.text = text
        self.runs: dict[int, list[int]] = {}
        for m in _BACKTICK_RUN_RE.finditer(text):
            self.runs.setdefault(m.end() - m.start(), []).append(m.start())
        self.stops = [m.start() for m in _INLINE_STOP_RE.finditer(text)]
        self._needles: dict[str, list[int]] = {}
        self.cache: dict[
            tuple[int, int, bool, bool, bool],
            tuple[list[tuple[int, int]], list[tuple[int, int]]],
        ] = {}

    def has_stop(self, start: int, end: int) -> bool:
        at = bisect.bisect_left(self.stops, start)
        return at < len(self.stops) and self.stops[at] < end

    def next_run(self, length: int, frm: int, end: int) -> int:
        """Start of the first maximal run of exactly *length* backticks in
        ``[frm, end)``, or -1."""
        same = self.runs.get(length)
        if not same:
            return -1
        at = bisect.bisect_left(same, frm)
        return same[at] if at < len(same) and same[at] < end else -1

    def find(self, needle: str, frm: int, end: int) -> int:
        """First *needle* starting in ``[frm, end - len(needle)]``, or -1."""
        found = self._needles.get(needle)
        if found is None:
            found = []
            pos = self.text.find(needle)
            while pos != -1:
                found.append(pos)
                pos = self.text.find(needle, pos + 1)
            self._needles[needle] = found
        at = bisect.bisect_left(found, frm)
        if at < len(found) and found[at] + len(needle) <= end:
            return found[at]
        return -1


_BACKTICK_RUN_RE = re.compile(r"`+")
_NOTHING: tuple[list[tuple[int, int]], list[tuple[int, int]]] = ([], [])


def _inline_hidden(
    index: _Index,
    start: int,
    end: int,
    *,
    multiline_comments: bool,
    tags: bool,
    links: bool = True,
) -> tuple[list[tuple[int, int]], list[tuple[int, int]]]:
    """Code spans and HTML comments in ``text[start:end]``, read left to right
    as Markdown inline text: a backslash escapes the punctuation after it, a
    run of N backticks opens a span closed by the next run of exactly N, and
    ``<!--`` opens a comment closed by the next ``-->``.  With *tags*, other
    inline HTML, autolinks and (with *links*) a link's destination and title
    are passed over whole, so a backtick inside them opens nothing; a link's
    label is read on its own.  One binary search per stop character, and
    bounded matches.
    """
    if not index.has_stop(start, end):
        return _NOTHING
    # Flags that cannot change the result are dropped from the cache key, so
    # readings and passes that see the same block share one scan.
    if index.find("\n", start, end) == -1:
        multiline_comments = True
    if tags and index.find("<", start, end) == -1 and index.find("[", start, end) == -1:
        tags = False
    if not tags:
        links = True
    key = (start, end, multiline_comments, tags, links)
    cached = index.cache.get(key)
    if cached is not None:
        return cached
    text = index.text
    spans: list[tuple[int, int]] = []
    comments: list[tuple[int, int]] = []
    result = (spans, comments)
    index.cache[key] = result
    p = start
    while p < end:
        m = _INLINE_STOP_RE.search(text, p, end)
        if m is None:
            break
        q = m.start()
        ch = text[q]
        if ch == "\\":
            p = q + 2 if q + 1 < end and text[q + 1] in _ASCII_PUNCT else q + 1
            continue
        if ch in "![":
            link = (
                _LINK_RE.match(text, q, min(end, q + _LINK_MAX_CHARS))
                if tags and links
                else None
            )
            if link is None:
                p = q + 1
                continue
            label_spans, label_comments = _inline_hidden(
                index,
                link.start(1),
                link.end(1),
                multiline_comments=multiline_comments,
                tags=True,
                links=False,
            )
            spans.extend(label_spans)
            comments.extend(label_comments)
            p = link.end()
            continue
        if ch == "<":
            if text.startswith("<!--", q):
                if text.startswith((">", "->"), q + 4):
                    stop = q + 5 if text[q + 4] == ">" else q + 6
                else:
                    close = index.find("-->", q + 4, end)
                    if close == -1:
                        p = q + 4
                        continue
                    stop = close + 3
                if not multiline_comments and index.find("\n", q, stop) != -1:
                    p = q + 4
                    continue
                comments.append((q, stop))
                p = stop
                continue
            if tags:
                stop = -1
                for opener, closer in _HTML_OTHER:
                    if text.startswith(opener, q):
                        close = index.find(closer, q + len(opener), end)
                        stop = close + len(closer) if close != -1 else -1
                        break
                else:
                    t = _TAG_RE.match(text, q, min(end, q + _TAG_MAX_CHARS))
                    stop = t.end() if t is not None else -1
                if stop != -1:
                    p = stop
                    continue
            p = q + 1
            continue
        k = q
        while k < end and text[k] == "`":
            k += 1
        close = index.next_run(k - q, k, end)
        if close != -1:
            spans.append((q, close + (k - q)))
            p = close + (k - q)
        else:
            p = k
    return result


def _mark(flags: bytearray, ranges: list[tuple[int, int]]) -> None:
    for a, b in ranges:
        flags[a:b] = b"\x01" * (b - a)


def _hidden(index: _Index, blocks: _Blocks, *, spans: bool) -> bytearray:
    """One flag per character of the text: 1 where this reading hides it."""
    text = index.text
    n = len(text)
    # The widest paragraphs, read once taking tags and links into account
    # and once not (in case one is not what it seems).
    wide_plain = bytearray(n)
    wide_tagged = bytearray(n)
    for a, b in blocks.wide:
        for flags, tags in ((wide_plain, False), (wide_tagged, True)):
            wide_spans, wide_comments = _inline_hidden(
                index, a, b, multiline_comments=True, tags=tags
            )
            _mark(flags, wide_spans)
            _mark(flags, wide_comments)
    narrow = bytearray(n)
    inline = list(blocks.inline) + [(a, b, False) for a, b in blocks.lists]
    for a, b, paragraph in inline:
        block_spans, block_comments = _inline_hidden(
            index, a, b, multiline_comments=paragraph, tags=True
        )
        if spans:
            _mark(narrow, block_spans)
        _mark(narrow, block_comments)
    masked = bytearray(n)
    _mark(masked, blocks.masked)
    hidden = bytearray(
        (
            int.from_bytes(masked, "big")
            | (
                int.from_bytes(narrow, "big")
                & int.from_bytes(wide_plain, "big")
                & int.from_bytes(wide_tagged, "big")
            )
        ).to_bytes(n, "big")
    )
    # Claude Code also scans a list item's text as written, where an "@"
    # counts only at the start or after whitespace: put those tokens back.
    for block_start, block_end in blocks.lists:
        at = text.find("@", block_start, block_end)
        while at != -1:
            stop = at + 1
            if at == block_start or text[at - 1].isspace():
                token = _TOKEN_RE.match(text, at)
                stop = min(token.end(), block_end) if token else at + 1
                hidden[at:stop] = bytes(stop - at)
            at = text.find("@", stop, block_end)
    return hidden


def _render(text: str, hidden: bytearray) -> str:
    """*text* with every hidden character but a newline turned into a space."""
    out: list[str] = []
    prev = 0
    for run in re.finditer(rb"\x01+", hidden):
        a, b = run.span()
        out.append(text[prev:a])
        out.append("\n".join(" " * len(part) for part in text[a:b].split("\n")))
        prev = b
    out.append(text[prev:])
    return "".join(out)


def _mask(
    text: str,
    *,
    spans: bool,
    greedy_lists: bool = False,
    html_blocks: bool = False,
    setext: bool = False,
    quote_lazy: bool = False,
    index: _Index | None = None,
) -> str:
    """Blank what Claude Code would not read as text (see the section comment)."""
    blocks = _scan_blocks(
        text,
        greedy_lists=greedy_lists,
        html_blocks=html_blocks,
        setext=setext,
        quote_lazy=quote_lazy,
    )
    return _render(text, _hidden(index or _Index(text), blocks, spans=spans))


def mask_for_imports(text: str) -> str:
    """Text with code blocks, code spans and HTML comments blanked out.

    The result has the same length and line breaks as *text*, so offsets and
    line numbers still point at the original.  A blanked span becomes spaces,
    which keeps ``x``@y`` an import (Claude Code reads the text after a code
    span as a new text token).
    """
    return _mask(text, spans=True)


def mask_readings_for_imports(text: str) -> tuple[str, ...]:
    """The readings :func:`extract_imports` unions: the default one; one where
    a list item's text runs to the next blank line (Claude Code scans
    list-item text as written, and where a list item ends is where the line
    pass is least sure); one where a line starting with a tag opens an HTML
    block, inside which a fence-like line opens no fence; when the text has
    a setext underline, one where HTML-looking lines inside a paragraph are
    its text; and, when it has a blockquote, one where a comment block right
    after it may be cut short by its end.  A reading whose blocks match an
    earlier one's is not repeated."""
    options: list[dict[str, bool]] = [{}, {"greedy_lists": True}]
    if _HTML_LINE_RE.search(text):
        options.append({"html_blocks": True})
    if _SETEXT_RE.search(text):
        options.append({"setext": True})
    if _QUOTE_ANY_RE.search(text):
        options.append({"quote_lazy": True})
    index = _Index(text)
    seen: list[_Blocks] = []
    readings: list[str] = []
    for option in options:
        blocks = _scan_blocks(text, **option)
        if blocks in seen:
            continue
        seen.append(blocks)
        readings.append(_render(text, _hidden(index, blocks, spans=True)))
    return tuple(readings)


def mask_for_references(text: str) -> str:
    """Text with fenced code blocks and HTML comments blanked (spans kept).

    Prose references are usually written in backticks ("Read ``docs/x.md``"),
    so code spans stay; a fenced block is code, not an instruction.
    """
    return _mask(text, spans=False)


# ── Import extraction ─────────────────────────────────────────────────────────

# An ``@`` at the start or after whitespace (Claude Code), or after a Markdown
# emphasis or link opener or a backtick, any of which can end the token before
# it in Claude Code's lexer so that the ``@`` starts a new text token
# (``**@x**``, ``[@x](...)``, `` `span`@x ``); not after "(", which does not.
# The path runs to the first unescaped whitespace.  Each character is
# consumed by exactly one branch, so the scan is linear.
_IMPORT_RE: re.Pattern[str] = re.compile(r"(?:^|(?<=[\s*_\[`]))@((?:[^\s\\]|\\ )+)")
_IMPORT_START_RE: re.Pattern[str] = re.compile(r"[A-Za-z0-9._-]")
_TRAILING_PUNCT = ".,;:!?)]*_~\"'`"


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
    if "\x00" in path:
        return False
    if path.startswith(("./", "~/")):
        return True
    if path.startswith("/"):
        return path != "/"
    return not path.startswith("@") and bool(_IMPORT_START_RE.match(path))


def _variants(token: str) -> list[str]:
    """The paths one ``@`` token may name: as written, without trailing
    punctuation, and without a Markdown link or emphasis tail."""
    path = token
    hash_at = path.find("#")
    if hash_at != -1:
        path = path[:hash_at]
    path = path.replace("\\ ", " ")
    if not path or len(path) > _MAX_IMPORT_CHARS or not _accept(path):
        return []
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
    return [v for v in variants if v and _accept(v)]


# The token as written, run on the original text from an ``@`` the masked
# reading found: a blanked character (a backtick the reading took for a code
# span's end) may be part of the path in Claude Code's reading.
_TOKEN_RE: re.Pattern[str] = re.compile(r"@((?:[^\s\\]|\\ )+)")


def extract_imports(
    text: str,
    limit: int = MAX_IMPORT_TOKENS,
    notes: list[str] | None = None,
    source: str = "",
) -> list[ImportCandidate]:
    """Return the ``@path`` imports in *text*, as Claude Code would read them.

    The union over :func:`mask_readings_for_imports`, so where the readings
    differ the extra candidate is kept (each must later exist as a file).

    Args:
        text: The instruction file's content.
        limit: Maximum ``@`` tokens examined per reading; reaching it is
            noted in *notes*.
        notes: Receives a line when *limit* is reached.
        source: The file's name, for that note.

    Returns:
        One :class:`ImportCandidate` per accepted ``@`` occurrence, in order.
    """
    found: dict[int, tuple[str, list[str]]] = {}
    capped = False
    for masked in mask_readings_for_imports(text):
        for examined, m in enumerate(_IMPORT_RE.finditer(masked), start=1):
            if examined > limit:
                capped = True
                break
            tokens = [m.group(1)]
            whole = _TOKEN_RE.match(text, m.start())
            if whole is not None and whole.group(1) != m.group(1):
                tokens.append(whole.group(1))
            raw, variants = found.get(m.start(), (m.group(1), []))
            for token in tokens:
                for v in _variants(token):
                    if v not in variants:
                        variants.append(v)
            found[m.start()] = (raw, variants)
    if capped and notes is not None:
        notes.append(
            f"agent-file imports: {source or 'a file'} has more than {limit} '@'"
            " tokens; the rest were not examined"
        )
    starts = _line_index(text)
    return [
        ImportCandidate(
            raw=raw,
            line=bisect.bisect_right(starts, offset),
            variants=tuple(variants),
        )
        for offset, (raw, variants) in sorted(found.items())
        if variants
    ]


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
    text: str,
    limit: int = MAX_REFERENCE_CANDIDATES,
    notes: list[str] | None = None,
    source: str = "",
) -> list[ReferenceCandidate]:
    """Return "read X" style references to Markdown/text files or directories.

    A reference is a path ending ``.md``/``.mdc``/``.markdown``/``.txt`` (or a
    backticked directory ending ``/``) within 200 characters after an order to
    read it — read / re-read / load / follow / consult / review / study / obey
    at the start of a clause, optionally after "always", "first", "you must",
    "before ...," and similar — in the same sentence, outside fenced code.
    URLs, ``@`` imports and absolute or home paths are not references (the
    latter are never read).  Reaching *limit* candidates or
    :data:`MAX_REFERENCE_VERBS_PER_FILE` verbs is noted in *notes*.
    """
    masked = mask_for_references(text)
    out: list[ReferenceCandidate] = []
    seen: set[str] = set()
    verbs = 0
    name = source or "a file"
    for line_no, line in enumerate(masked.split("\n"), start=1):
        for verb in _REF_VERB_RE.finditer(line):
            verbs += 1
            if verbs > MAX_REFERENCE_VERBS_PER_FILE:
                if notes is not None:
                    notes.append(
                        f"agent-file references: {name} has more than"
                        f" {MAX_REFERENCE_VERBS_PER_FILE} 'read'-style verbs; the"
                        " rest were not examined"
                    )
                return out
            if not _starts_clause(line, verb.start()):
                continue
            for token, backticked in _reference_tokens(
                _sentence_window(line, verb.end())
            ):
                if (
                    not token
                    or "\x00" in token
                    or "://" in token
                    or token.startswith(("@", "~", "/", "\\"))
                ):
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
                    if notes is not None:
                        notes.append(
                            f"agent-file references: {name} has more than {limit}"
                            " references; the rest were not examined"
                        )
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


#: Prefixes of paths that can reach the network when merely stat-ed: a UNC or
#: device path (``\\\\host\\share``, ``//host/share``, ``\\\\?\\``,
#: ``\\\\.\\``) makes Windows open an SMB session (and send the user's NTLM
#: hash); ``/net/<host>`` and ``/Network/`` trigger macOS / autofs mounts.
_NETWORK_PREFIXES = ("//", "\\\\", "/\\", "\\/")
_NETWORK_DIRS = ("/net/", "/network/")


def is_network_path(raw: str, target: Path | None = None) -> bool:
    """True when *raw* (as written) or *target* (resolved) is a path that a
    ``stat`` could send over the network.  Checked on the text only, so it
    makes no filesystem call itself."""
    if raw.startswith(_NETWORK_PREFIXES):
        return True
    if raw.replace("\\", "/").lower().startswith(_NETWORK_DIRS):
        return True
    if target is None:
        return False
    text = os.fspath(target)
    if text.startswith(_NETWORK_PREFIXES):
        return True
    lowered = text.replace("\\", "/").lower() + "/"
    return lowered.startswith(_NETWORK_DIRS)


def _first_symlink(root: Path, target: Path) -> Path | None | bool:
    """Walk from *root* to *target* with ``lstat``.

    Returns the first path on the way that is a symlink, ``False`` when the
    target does not exist (or a component is not a directory, or the path
    cannot be examined), and ``None`` when every component is real and the
    target is a regular file.
    """
    rel = target.relative_to(root)
    current = root
    parts = rel.parts
    for idx, part in enumerate(parts):
        current = current / part
        try:
            st = os.lstat(current)
        except (OSError, ValueError):
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
    except (OSError, ValueError):
        return False


def _is_regular_file(path: Path) -> bool:
    try:
        return path.is_file()
    except (OSError, ValueError):
        return False


@dataclass
class _Resolved:
    target: Path
    status: str  # followed | outside | symlink
    link: Path | None = None
    detail: str = ""


def _classify(
    target: Path, root: Path, *, check_outside: bool = True
) -> _Resolved | None:
    """Classify an existing candidate; ``None`` when it does not exist.

    A target outside *root* is only checked (one ``stat``) when
    *check_outside* is set; the caller has already refused network paths.
    """
    if not _within(target, root):
        if check_outside and _is_regular_file(target):
            return _Resolved(target, "outside")
        return None
    found = _first_symlink(root, target)
    if found is False:
        return None
    if isinstance(found, Path):
        return _Resolved(target, "symlink", link=found)
    return _Resolved(target, "followed")


def _resolve_import(
    cand: ImportCandidate, importing: Path, root: Path, home: Path, scope: str
) -> _Resolved | None:
    """The first variant of *cand* that exists, classified.

    A variant naming a network path is never examined: from a project file
    it is reported as an outside import by its text alone; from a user file
    (whose outside imports are the user's own) it is dropped.  Outside
    targets of user files are not examined either.
    """
    for variant in cand.variants:
        target = _resolve_import_path(variant, importing, home)
        if is_network_path(variant, target):
            if scope == "project":
                return _Resolved(
                    target, "outside", detail="network path; not checked or read"
                )
            return None
        resolved = _classify(target, root, check_outside=scope == "project")
        if resolved is not None:
            return resolved
    return None


def _resolve_reference(
    cand: ReferenceCandidate,
    importing: Path,
    root: Path,
    notes: list[str] | None = None,
) -> list[_Resolved]:
    """Resolve a reference against the file's directory, then the root."""
    for base in (importing.parent, root):
        target = _win32_name(Path(os.path.normpath(str(base / cand.raw))))
        if is_network_path(cand.raw, target) or not _within(target, root):
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
            except (OSError, ValueError):
                continue
            for child in children:
                if len(results) >= MAX_DIRECTORY_REFERENCE_FILES:
                    if notes is not None:
                        notes.append(
                            f"agent-file references: {target} has more than"
                            f" {MAX_DIRECTORY_REFERENCE_FILES} Markdown files;"
                            " only the first were followed"
                        )
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
        except (OSError, ValueError):
            return False
        if stat.S_ISLNK(st.st_mode):
            return current
        if not stat.S_ISDIR(st.st_mode):
            return False
    return None


# ── Following ─────────────────────────────────────────────────────────────────


def _symlink_finding(link: Path, scope: str, root: Path) -> Finding:
    if scope == "project":
        finding = build_project_symlink_finding(link, _CLIENT, root)
    else:
        finding = build_info_symlink_finding(link, _CLIENT)
    # The link's path is text from the scanned files; scrub it like any other.
    return finding.model_copy(
        update={
            "title": redact_secrets(finding.title),
            "server": redact_secrets(finding.server),
            "description": redact_secrets(finding.description),
            "evidence": redact_secrets(finding.evidence),
            "remediation": redact_secrets(finding.remediation),
        }
    )


def _read_followed(
    target: Path,
    parent: AgentFile,
    kind: str,
    budget: ReadBudget,
    notes: list[str],
) -> AgentFile | None:
    try:
        size = os.stat(target).st_size
    except (OSError, ValueError) as exc:
        notes.append(f"agent-file imports: cannot stat {target}: {exc}")
        return None
    if not budget.take(min(size, READ_CAP_BYTES)):
        return None
    try:
        text, truncated = read_text_capped(target)
    except (OSError, ValueError) as exc:
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
    # Notes carry paths and error text from the scanned files: collected
    # here and scrubbed of secrets before they reach the caller.
    notes_out: list[str] = []
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
        source = str(af.path)
        work: list[tuple[str, _Resolved, str, int]] = []
        if af.follows_imports:
            for cand in extract_imports(af.body, notes=notes_out, source=source):
                resolved = _resolve_import(cand, af.path, root, home, af.scope)
                if resolved is not None:
                    work.append(("import", resolved, cand.raw, cand.line + offset))
        if include_references:
            for ref in extract_references(af.body, notes=notes_out, source=source):
                for resolved in _resolve_reference(ref, af.path, root, notes_out):
                    if resolved.status != "outside":
                        work.append(("reference", resolved, ref.raw, ref.line + offset))
        if len(work) > MAX_EDGES_PER_FILE:
            notes_out.append(
                f"agent-file imports: {source} has more than {MAX_EDGES_PER_FILE}"
                " imports and references that exist; only the first were followed"
            )
        # An ignored file's own imports are not "from an ignored location"
        # in any new sense (Claude Code's worktrees live in an ignored
        # directory, and every import in one would be flagged).
        importer_ignored = (
            af.scope == "project"
            and gitignore is not None
            and gitignore.ignored_by(af.path) is not None
        )

        for kind, resolved, raw, line in work[:MAX_EDGES_PER_FILE]:
            status = resolved.status
            detail = resolved.detail
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
                and not importer_ignored
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
    if notes is not None:
        notes.extend(redact_secrets(note) for note in notes_out)
    return new_files
