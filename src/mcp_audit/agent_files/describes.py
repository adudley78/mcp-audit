"""Tell text that *describes* a risky action from text that *directs* it.

A security-review checklist that lists "reads ``~/.ssh/id_rsa``" as something
to flag contains the same words as a skill that tells the agent to read that
file, and a scanner that treats them alike is the scanner whose findings
nobody reads.  :func:`describe_match` decides, for one regex match in a
skill's text, whether the surrounding text only describes it (STORY-0141).

A match is *described* when any of five rules holds:

(a) its line is a Markdown task-list item (``- [ ]``, ``- [x]``, ``* [ ]``);
(b) its line is a blockquote (``>``);
(c) the matched text sits inside inline backticks or a quotation on its line
    and that line has a describing cue ("for example", "flag", "pattern");
(d) its line is a list item and the nearest heading above it, or the lead-in
    line of its list, has a review cue ("red flags", "check", "detect");
(e) the sentence holding the match has a negation before it ("never",
    "do not", "avoid") that is not itself followed by a word that turns it
    back into an order ("never forget to ...").  Rule (e) is not offered for
    the directive patterns POISON-070..076, whose own meaning includes the
    negation.

Text inside a fenced code block is never described: code a skill tells the
agent to run is directed whatever the heading above it says.  Whether to
apply the gate at all (it is off for a file with a concealment finding) is
the caller's decision.

Pure functions over a string; no I/O.  Every scan here is bounded by line or
paragraph length, so a hostile file costs one pass over its lines.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

__all__ = ["Described", "TextContext", "describe_match"]

#: Longest stretch of a paragraph read back for rule (e), in characters.
_SENTENCE_LOOKBACK: int = 400
#: Most lines of a paragraph read back for rule (e).
_PARAGRAPH_LOOKBACK_LINES: int = 6
#: Most lines walked up from a list item to find its lead-in line.
_LEADIN_LOOKBACK_LINES: int = 400

_FENCE_RE = re.compile(r"^ {0,3}(`{3,}|~{3,})")
_HEADING_RE = re.compile(r"^ {0,3}#{1,6}(?:\s|$)")
_LIST_ITEM_RE = re.compile(r"^\s*(?:[-*+]|\d{1,9}[.)])\s+")
_TASK_ITEM_RE = re.compile(r"^\s*[-*+]\s+\[[ xX]\](?:\s|$)")
_BLOCKQUOTE_RE = re.compile(r"^ {0,3}>")

# Rule (c) cues: this line is talking about phrases, not issuing them.
_DESCRIBING_CUE_RE = re.compile(
    r"\be\.g\.|\bfor\s+example\b|\bsuch\s+as\b|\blike\b|\bflag|\bdetect"
    r"|\blook(?:s|ing)?\s+for\b|\bwatch(?:es|ing)?\s+for\b|\bpatterns?\b"
    r"|\bphrases?\b|\battack|\bexamples?\b",
    re.IGNORECASE,
)

# Rule (d) cues: this heading or lead-in introduces things to look out for.
_REVIEW_CUE_RE = re.compile(
    r"\bflag|\bcheck|\breview|\bdetect|\blook(?:s|ing)?\s+for\b"
    r"|\bwatch(?:es|ing)?\s+for\b|\bred\s+flag|\bwarning\s+signs?\b"
    r"|\banti-?patterns?\b|\bexamples?\s+of\b|\bindicators?\b|\bsigns?\s+of\b"
    r"|\bsuspicious\b|\bmalicious\b|\battack|\bthreat",
    re.IGNORECASE,
)

# Rule (e): a negation, and the words that undo it when they follow closely.
_NEGATION_RE = re.compile(
    r"\b(?:never|do\s+not|don['’]?t|must\s+not|should\s+not|shouldn['’]?t"
    r"|avoid|refuse\s+to|not\s+allowed\s+to|forbidden|prohibited)\b",
    re.IGNORECASE,
)
_UNDOES_NEGATION_RE = re.compile(
    r"^(?:forget|fail|hesitate|skip|omit|stop|neglect)", re.IGNORECASE
)
_SENTENCE_END_RE = re.compile(r"[.!?](?=\s)")

# Quoted spans on one line: backticks, double, curly double, and single quotes
# that open and close at word edges (so an apostrophe is not a quote).
_QUOTE_SPAN_RES: tuple[re.Pattern[str], ...] = (
    re.compile(r"`[^`\n]+`"),
    re.compile(r'"[^"\n]+"'),
    re.compile(r"“[^”\n]+”"),
    re.compile(r"(?<![\w'])'[^'\n]+'(?![\w'])"),
)


@dataclass(frozen=True)
class Described:
    """Why a match counts as described, not directed.

    Attributes:
        rule: ``"a"`` .. ``"e"``, the rule in the module docstring.
        reason: A short phrase for the finding's evidence.
    """

    rule: str
    reason: str


class TextContext:
    """Line structure of one text, computed once for every match in it.

    Splits on ``"\\n"`` only, so line numbers agree with an editor's and with
    the line counts the analyzers use.  Fenced code blocks are found by
    walking the lines once; an unterminated fence runs to the end.
    """

    def __init__(self, text: str) -> None:
        self.text = text
        self.lines: list[str] = text.split("\n")
        self.starts: list[int] = []
        pos = 0
        for line in self.lines:
            self.starts.append(pos)
            pos += len(line) + 1
        self.fenced: list[bool] = self._find_fenced()

    def _find_fenced(self) -> list[bool]:
        """Mark each line that is inside, or is a fence of, a code block."""
        fenced: list[bool] = []
        marker: str | None = None
        for line in self.lines:
            fence = _FENCE_RE.match(line)
            if marker is None:
                if fence:
                    marker = fence.group(1)
                    fenced.append(True)
                else:
                    fenced.append(False)
                continue
            fenced.append(True)
            if (
                fence
                and fence.group(1)[0] == marker[0]
                and len(fence.group(1)) >= len(marker)
                and not line.strip()[len(fence.group(1)) :].strip()
            ):
                marker = None
        return fenced

    def line_index(self, offset: int) -> int:
        """Return the 0-based index of the line holding *offset*."""
        lo, hi = 0, len(self.starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if self.starts[mid] <= offset:
                lo = mid
            else:
                hi = mid - 1
        return lo

    def _nearest_heading(self, idx: int) -> str | None:
        """Return the closest heading line above line *idx*, outside code."""
        for i in range(idx - 1, -1, -1):
            if not self.fenced[i] and _HEADING_RE.match(self.lines[i]):
                return self.lines[i]
        return None

    def _list_leadin(self, idx: int) -> str | None:
        """Return the line that introduces the list holding line *idx*.

        Walks up through list items, blank lines and indented continuation
        lines; the first other line is the lead-in when it ends with ``:``.
        """
        stop = max(-1, idx - _LEADIN_LOOKBACK_LINES)
        for i in range(idx - 1, stop, -1):
            line = self.lines[i]
            if self.fenced[i]:
                return None
            if not line.strip() or _LIST_ITEM_RE.match(line) or line[:1] in " \t":
                continue
            return line if line.rstrip().endswith(":") else None
        return None

    def _sentence_prefix(self, idx: int, offset: int) -> str:
        """Return the text of the match's sentence that comes before it."""
        first = idx
        for _ in range(_PARAGRAPH_LOOKBACK_LINES):
            if first == 0:
                break
            prev = self.lines[first - 1]
            if (
                not prev.strip()
                or self.fenced[first - 1]
                or _HEADING_RE.match(prev)
                or _LIST_ITEM_RE.match(self.lines[first])
                or _LIST_ITEM_RE.match(prev)
            ):
                break
            first -= 1
        lo = max(self.starts[first], offset - _SENTENCE_LOOKBACK)
        prefix = self.text[lo:offset]
        ends = list(_SENTENCE_END_RE.finditer(prefix))
        return prefix[ends[-1].end() :] if ends else prefix


def _in_quotes(line: str, start: int, end: int) -> bool:
    """Return True when ``line[start:end]`` lies inside one quoted span."""
    for span_re in _QUOTE_SPAN_RES:
        for m in span_re.finditer(line):
            if m.start() < start and end <= m.end():
                return True
    return False


def _negated(prefix: str) -> bool:
    """Return True when *prefix* holds a negation that still reads as one."""
    for neg in _NEGATION_RE.finditer(prefix):
        words = prefix[neg.end() :].split(None, 3)[:3]
        if not any(_UNDOES_NEGATION_RE.match(w) for w in words):
            return True
    return False


def describe_match(
    ctx: TextContext, start: int, end: int, *, allow_negation: bool = True
) -> Described | None:
    """Decide whether the match at ``text[start:end]`` is described, not directed.

    Args:
        ctx: The line structure of the text the match was found in.
        start: Offset where the match starts.
        end: Offset where the match ends.
        allow_negation: Apply rule (e).  ``False`` for the directive patterns
            POISON-070..076, whose meaning includes the negation.

    Returns:
        A :class:`Described` naming the first rule that holds, or ``None``
        when the match is directed (including every match in a code fence).
    """
    idx = ctx.line_index(start)
    if ctx.fenced[idx]:
        return None
    line = ctx.lines[idx]
    if _TASK_ITEM_RE.match(line):
        return Described("a", "a Markdown task-list item")
    if _BLOCKQUOTE_RE.match(line):
        return Described("b", "a blockquote")
    col = start - ctx.starts[idx]
    if _DESCRIBING_CUE_RE.search(line) and _in_quotes(
        line, col, min(end - ctx.starts[idx], len(line))
    ):
        return Described("c", "a quoted example in a line that describes patterns")
    if _LIST_ITEM_RE.match(line):
        heading = ctx._nearest_heading(idx)
        if heading is not None and _REVIEW_CUE_RE.search(heading):
            return Described("d", "a list item under a review heading")
        leadin = ctx._list_leadin(idx)
        if leadin is not None and _REVIEW_CUE_RE.search(leadin):
            return Described("d", "a list item under a review lead-in")
    if allow_negation and _negated(ctx._sentence_prefix(idx, start)):
        return Described("e", "a negated instruction (never / do not / avoid)")
    return None
