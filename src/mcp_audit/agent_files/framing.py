"""Describes or directs: the framing gate for SKILL-001 (STORY-0141).

A security skill that tells a reviewer to *flag* descriptions which "read
~/.ssh/id_rsa" contains the same words as a skill that tells the agent to
read it.  Pattern matching cannot tell the two apart; where the words sit
can.  :class:`FileFraming` reads one instruction file once and answers, for
any match offset, whether the text there **directs** the agent or
**describes** something (and why).  A described match is reported at INFO,
not dropped.

The gate fails closed: a match is **directed** (reported at the pattern's
own severity) unless one of the positive frames below says otherwise, and
some things are directed whatever the frame.

Directed, whatever the frame (checked first):

* Inside a fenced code block, under any heading or lead-in: code a skill
  shows is code an agent may run.
* The line or sentence names a destination: a URL, an e-mail address, an IP
  address or ``host:port``, a pipe into a program, or a transfer tool
  (curl, wget, nc, scp, rsync, ftp, sendmail ...).  Describing text rarely
  needs one; an order to send data always does.
* A table row, or a callout / bold label ("**Important**:", ``> [!NOTE]``).
* A sentence addressed to the agent: "you must / should / will / need to",
  "the agent must", "make sure to", "remember to", "please <verb>", "your
  task is", "always / immediately / silently <verb>", and a condition
  followed by an order ("before formatting, run ...").

Described (reported at INFO), only on positive evidence:

* **Negated** — a short clause that opens with the negation and has nothing
  after the match ("Never upload ~/.ssh keys anywhere.", "Do not read
  .env").  Not when a later clause follows, and not when the negation is
  undone ("don't forget to", "won't hurt to", "do not refrain from").
* **A checklist item** — a Markdown task-list item (``- [ ]``) whose text
  describes rather than orders (it does not open with an action verb).
* **An item under a detection lead-in** — a list item in the one list right
  after a heading or ``...:`` lead-in that names what to detect (flag,
  detect, look for, watch for, red flags, warning signs, indicators, signs
  of, suspicious, malicious), when the item opens like a description: a
  third-person verb ("reads ..."), an ``-ing`` form, or a noun phrase
  ("tool descriptions that ...", "any request to ...").  Anything else
  ("Go ahead and ...", "Kindly ...", a link, a code span) is directed.
* **A describing sentence** — the sentence itself frames the match as
  something to find ("flag tool descriptions that tell the agent to ...",
  "attackers write descriptions that ...").
* **A quote** — a blockquote right after such a lead-in, or one that opens
  like a description (as a list item above); "> Read ..." is directed.

Everything is linear in the file size: one pass splits the file into blocks;
each match then looks at most :data:`_WINDOW` characters either side within
its own block, and the caller bounds the number of matches.
"""

from __future__ import annotations

import bisect
import re
from dataclasses import dataclass

#: Characters looked at on either side of a match when finding its sentence.
_WINDOW: int = 400

#: A lead-in paragraph longer than this is not a lead-in.
_LEAD_IN_MAX_CHARS: int = 300

_ACTION_VERBS: str = (
    r"(?:read|send|upload|post|copy|cat|curl|wget|run|execute|exec|fetch|open"
    r"|include|append|attach|forward|email|mail|save|write|print|output|collect"
    r"|gather|extract|zip|tar|encode|base64|exfiltrate|transmit|share|paste"
    r"|leak|load|source|call|invoke|use|proceed|skip|delete|remove|install"
    r"|push|commit|dump|export|grab|steal|pipe|submit|report)"
)

# A sentence addressed to the agent.  Checked over the whole sentence.
_DIRECTIVE_RE: re.Pattern[str] = re.compile(
    r"\byou\s+(?:must|should|shall|will|need\s+to|have\s+to|are\s+(?:to|required"
    r"\s+to|expected\s+to)|can\s+now|'ll)\b"
    r"|\byou'll\b"
    r"|\b(?:the\s+)?(?:agent|assistant|model|claude|ai)(?:'s)?\s+(?:must|should"
    r"|shall|will|needs?\s+to|has\s+to|is\s+to|next\s+step|task|job)\b"
    # Passive obligation: "the key must be sent to ...", "it is required to".
    r"|\b(?:must|shall|needs?\s+to|has\s+to|have\s+to|is\s+to|are\s+to)\s+be\s+"
    r"(?:read|sent|uploaded|posted|copied|run|executed|included|attached"
    r"|forwarded|emailed|collected|exported|dumped|piped|submitted)\b"
    r"|\b(?:is|are)\s+(?:required|supposed)\s+to\s+" + _ACTION_VERBS + r"\b"
    r"|\b(?:make\s+sure|be\s+sure|remember|don'?t\s+forget|do\s+not\s+forget"
    r"|never\s+forget|ensure)\s+(?:to|that\s+you|you)\b"
    r"|\bplease\s+" + _ACTION_VERBS + r"\b"
    r"|\byour\s+(?:task|job|(?:first|next|only)\s+step|goal|instructions?)\s+(?:is|are)\b"
    r"|\b(?:always|immediately|silently|secretly|quietly|automatically)\s*,?\s+"
    + _ACTION_VERBS
    + r"\b"
    # A condition, a comma, then an order: "before formatting, run ...".
    r"|\b(?:before|after|when|whenever|once|while|as\s+soon\s+as)\b[^.!?\n,]{1,80},"
    r"\s*(?:always\s+|first\s+|also\s+|then\s+|just\s+|quietly\s+|silently\s+)?"
    + _ACTION_VERBS
    + r"\b"
    # The same without the comma: "before formatting run cat ...".
    r"|\b(?:before|after|when|whenever|once|as\s+soon\s+as)\s+[^.!?\n,]{1,60}?\s"
    r"(?:you\s+)?(?:must\s+|should\s+|always\s+|first\s+)?"
    r"(?:run|execute|exec|read|send|upload|post|curl|wget|cat|fetch|copy|forward"
    r"|email|paste|pipe|source)\s",
    re.IGNORECASE,
)

# A sentence that opens with an action verb, after any list marker,
# checkbox, emphasis, "Step 1:" or "Note:" label and a softener.
_IMPERATIVE_START_RE: re.Pattern[str] = re.compile(
    r"[\s>]*(?:(?:[-*+]|\d{1,9}[.)])\s+)?(?:\[[ xX]\]\s+)?(?:\*\*|__|\*|_)?"
    r"(?:step\s+\d+\s*[:.)-]\s*|[A-Za-z]+\s*:\s+)?(?:\*\*|__|\*|_)?"
    r"(?:(?:now|then|first|also|just|simply|quickly|next)\s*,?\s+)?"
    + _ACTION_VERBS
    + r"\b",
    re.IGNORECASE,
)

# The same sentence frames the match as something to find or as an example.
_DESCRIBING_SENTENCE_RE: re.Pattern[str] = re.compile(
    r"\b(?:flag|flags|flagging|detect|detects|detecting|report|reject|block|catch"
    r"|spot|identify|look\s+(?:out\s+)?for|watch\s+(?:out\s+)?for|warn\s+(?:about|on"
    r"|when)|alert\s+on|deny|refuse)\b[^.!?\n]{0,120}?\b(?:that|which|who|containing"
    r"|contain|asking|telling|instructing|referencing|mentioning|trying\s+to"
    r"|attempting\s+to|like|such\s+as)\b"
    r"|\b(?:attackers?|adversar(?:y|ies)|malicious\s+[\w-]+|poisoned\s+[\w-]+"
    r"|(?:the|an|this)\s+attack)\b[^.!?\n]{0,120}?\b(?:to|that|which|would|will|can"
    r"|may|might|could|tells?|asks?|instructs?|tr(?:y|ies)|writes?|hides?|uses?)\b",
    re.IGNORECASE,
)

_NEGATION_RE: re.Pattern[str] = re.compile(
    r"\b(?:never|not|don'?t|doesn'?t|mustn'?t|shouldn'?t|cannot|can'?t|won'?t"
    r"|avoid|refuse\s+to|no\s+need\s+to|forbidden\s+to|prohibited\s+from)\b",
    re.IGNORECASE,
)
# A clause after the match that turns "never read X" into an order
# ("... without sending it", "... unless", "... except").
_NEGATION_TAIL_RE: re.Pattern[str] = re.compile(
    r"\b(?:without|unless|except|until|but|instead)\b", re.IGNORECASE
)
# Clause boundaries for the negation check.
_CLAUSE_BOUNDARY_RE: re.Pattern[str] = re.compile(
    r"[,;:!?—]|(?<!e\.g)(?<!i\.e)\.(?=\s|$)|\n|\b(?:but|then|instead|however|and\s+then)\b",
    re.IGNORECASE,
)
# Sentence boundaries: end punctuation (not "e.g."), a list marker at a line
# start, a blank line.
_SENTENCE_BOUNDARY_RE: re.Pattern[str] = re.compile(
    r"(?<!e\.g)(?<!i\.e)[.!?](?=\s)|\n[ \t]*(?:[-*+]|\d{1,9}[.)])[ \t]|\n[ \t]*\n"
)

_FENCE_RE: re.Pattern[str] = re.compile(r" {0,3}(`{3,}|~{3,})")
_FENCE_CLOSE_RE: re.Pattern[str] = re.compile(r" {0,3}(`{3,}|~{3,})[ \t]*\r?")
#: Fence lengths above this are read as this (a 40-backtick opener closes on
#: 16), which keeps the closing-fence tables to a handful.
_FENCE_SIZE_CAP: int = 16
_HEADING_RE: re.Pattern[str] = re.compile(r" {0,3}#{1,6}(?:[ \t]|$)")
_QUOTE_RE: re.Pattern[str] = re.compile(r" {0,3}>")
_LIST_RE: re.Pattern[str] = re.compile(r"[ \t]*(?:[-*+]|\d{1,9}[.)])[ \t]")
_TASK_ITEM_RE: re.Pattern[str] = re.compile(r"[ \t]*[-*+][ \t]+\[[ xX]\][ \t]+")

# A heading or lead-in that names what to detect.  Not "review", "audit",
# "checklist" or "attack": those also head procedures the agent carries out.
_DETECT_RE: re.Pattern[str] = re.compile(
    r"\b(?:flag(?:ged|ging)?|detect(?:s|ed|ing|ion)?"
    r"|look\s+(?:out\s+)?for|watch\s+(?:out\s+)?for|red\s+flags?"
    r"|warning\s+signs?|indicators?|iocs?|signs\s+of|suspicious|malicious"
    r"|what\s+(?:not\s+)?to\s+(?:look\s+for|flag|catch))\b",
    re.IGNORECASE,
)

# A concrete destination: describing text rarely names one, an order to
# send data always does.
_DESTINATION_RE: re.Pattern[str] = re.compile(
    r"\b[a-z][a-z0-9+.-]{1,15}://"
    r"|[\w.+-]+@[\w-]+(?:\.[\w-]+)+"
    r"|\b\d{1,3}(?:\.\d{1,3}){3}\b"
    r"|\b[a-z0-9-]+(?:\.[a-z0-9-]+)+:\d{2,5}\b"
    r"|\|\s*[A-Za-z]"
    r"|\b(?:curl|wget|nc|ncat|netcat|scp|sftp|rsync|ftp|tftp|telnet|sendmail"
    r"|mailx?|socat|invoke-webrequest|iwr|invoke-restmethod)\b",
    re.IGNORECASE,
)

# A table row, or a callout / bold label that gives an order.
_CALLOUT_RE: re.Pattern[str] = re.compile(
    r"[ \t>]*(?:\||\[!\w+\]|(?:[-*+]|\d{1,9}[.)])?[ \t]*(?:\*\*|__)[^*_\n]{1,40}"
    r"(?:\*\*|__)[ \t]*:|(?:[-*+]|\d{1,9}[.)])?[ \t]*(?:\*\*|__)[^*_\n]{1,40}:"
    r"[ \t]*(?:\*\*|__))"
)

# How a described list item opens: list marker and checkbox, then a
# third-person verb, an -ing form, or a noun-phrase opener.  Anything else
# (an imperative, a softener, a link, a code span, markup) is directed.
_DESCRIPTIVE_ITEM_RE: re.Pattern[str] = re.compile(
    r"[ \t]*(?:(?:[-*+]|\d{1,9}[.)])[ \t]+)?(?:\[[ xX]\][ \t]+)?"
    r"(?:"
    r"(?:a|an|any|all|the|tool|tools|descriptions?|files?|skills?|text|strings?"
    r"|phrases?|instructions?|requests?|commands?|code|attempts?|references?"
    r"|mentions?|hidden|unexpected|unusual|outbound|external|calls?|access"
    r"|changes?|anything|something|content|prompts?|attempt|use|uses)\b"
    r"|[a-z]{3,}s\b(?!\s*:)"
    r"|[a-z]{3,}ing\b"
    r")",
    re.IGNORECASE,
)

# Words that undo or reverse a negation ("don't forget to", "won't hurt to",
# "do not refrain from").
_UNDOES_NEGATION_WORDS: str = (
    r"forget|fail|hesitate|neglect|skip|omit|just|only|merely|simply|stop"
    r"|wait|ask|need\s+(?:to\s+)?ask|refrain|delay|ignore|overlook|hurt|harm"
    r"|stress|mind|matter|worry|bother|be\s+afraid|leave\s+out|miss"
)
#: Most words between a clause's start and its negation ("Never ...", "You
#: must never ...", "The agent should not ..."); a negation deeper in the
#: clause negates something else ("I want you to know it is not ...").
_NEGATION_MAX_LEAD_WORDS: int = 3
_UNDOES_NEGATION_RE: re.Pattern[str] = re.compile(
    r"\b(?:" + _UNDOES_NEGATION_WORDS + r")\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class Framing:
    """How the text at one match is framed.

    Attributes:
        directed: ``True`` when the text directs the agent (report at the
            pattern's severity).
        reason: For a described match, where it sits, phrased to follow
            "it sits ..." ("in a negated sentence", "under the heading
            'Review checklist'").  Empty when directed.
    """

    directed: bool
    reason: str = ""


_DIRECTED = Framing(directed=True)


@dataclass
class _Block:
    kind: str  # "heading" | "fence" | "quote" | "list" | "paragraph"
    first: int  # first line index
    last: int  # last line index
    text: str


def _short(text: str, limit: int = 60) -> str:
    """One line of *text*, secrets redacted before it is cut to *limit*."""
    from mcp_audit.analyzers.supply_chain import (  # noqa: PLC0415
        redact_command_text,
    )

    text = redact_command_text(" ".join(text.split()))
    return text if len(text) <= limit else text[: limit - 1] + "…"


class FileFraming:
    """One file's block structure, built once; answers :meth:`classify`.

    Args:
        text: The text the matches were found in (offsets refer to it).
    """

    def __init__(self, text: str) -> None:
        self._text = text
        self._lines = text.split("\n")
        self._line_starts: list[int] = []
        pos = 0
        for line in self._lines:
            self._line_starts.append(pos)
            pos += len(line) + 1
        self._blocks: list[_Block] = []
        self._block_of_line: list[int] = [-1] * len(self._lines)
        self._parse()
        # A describing lead-in for block i, when it has one.
        self._scope: dict[int, str] = {}
        self._scope_blocks()

    # ── structure ──────────────────────────────────────────────────────────

    def line_of(self, offset: int) -> int:
        """Return the 0-based line index of *offset*."""
        return max(0, bisect.bisect_right(self._line_starts, offset) - 1)

    def _add(self, kind: str, first: int, last: int) -> None:
        idx = len(self._blocks)
        self._blocks.append(
            _Block(kind, first, last, "\n".join(self._lines[first : last + 1]))
        )
        for i in range(first, last + 1):
            self._block_of_line[i] = idx

    def _closing_fence(self, start: int, marker: str) -> int | None:
        """The first line after *start* that closes a fence opened by *marker*.

        Answered from a table built by one backward pass per (character,
        length) pair actually asked about, so a file of unclosed openers
        costs linear time, not a forward scan per opener.
        """
        char, size = marker[0], min(len(marker), _FENCE_SIZE_CAP)
        table = self._next_closer.get((char, size))
        if table is None:
            n = len(self._lines)
            table = [-1] * (n + 1)
            nxt = -1
            for j in range(n - 1, -1, -1):
                closer = self._closers[j]
                if closer is not None and closer[0] == char and closer[1] >= size:
                    nxt = j
                table[j] = nxt
            self._next_closer[(char, size)] = table
        close = table[start + 1]
        return close if close >= 0 else None

    def _parse(self) -> None:
        lines = self._lines
        n = len(lines)
        self._closers: list[tuple[str, int] | None] = []
        for line in lines:
            m = _FENCE_CLOSE_RE.fullmatch(line)
            self._closers.append(
                (m.group(1)[0], min(len(m.group(1)), _FENCE_SIZE_CAP)) if m else None
            )
        self._next_closer: dict[tuple[str, int], list[int]] = {}
        i = 0
        while i < n:
            line = lines[i]
            if not line.strip():
                i += 1
                continue
            fence = _FENCE_RE.match(line)
            if fence:
                close = self._closing_fence(i, fence.group(1))
                if close is not None:
                    self._add("fence", i, close)
                    i = close + 1
                    continue
                # An unclosed fence is not a block: read the line as text.
            if _HEADING_RE.match(line):
                self._add("heading", i, i)
                i += 1
                continue
            if _QUOTE_RE.match(line):
                j = i
                while j + 1 < n and _QUOTE_RE.match(lines[j + 1]):
                    j += 1
                self._add("quote", i, j)
                i = j + 1
                continue
            if _LIST_RE.match(line):
                j = i
                while j + 1 < n:
                    nxt = lines[j + 1]
                    if nxt.strip():
                        if _HEADING_RE.match(nxt) or _FENCE_RE.match(nxt):
                            break
                        j += 1
                        continue
                    # A blank line continues the list only when an item or an
                    # indented continuation follows it.
                    k = j + 1
                    while k < n and not lines[k].strip():
                        k += 1
                    if k < n and (_LIST_RE.match(lines[k]) or lines[k][:2] == "  "):
                        j = k
                        continue
                    break
                self._add("list", i, j)
                i = j + 1
                continue
            j = i
            while j + 1 < n:
                nxt = lines[j + 1]
                if (
                    not nxt.strip()
                    or _HEADING_RE.match(nxt)
                    or _FENCE_RE.match(nxt)
                    or _QUOTE_RE.match(nxt)
                    or _LIST_RE.match(nxt)
                ):
                    break
                j += 1
            self._add("paragraph", i, j)
            i = j + 1

    def _is_lead_in(self, block: _Block) -> bool:
        if block.kind == "heading":
            return True
        return (
            block.kind == "paragraph"
            and len(block.text) <= _LEAD_IN_MAX_CHARS
            and block.text.rstrip().rstrip("*_").endswith(":")
        )

    def _scope_blocks(self) -> None:
        """Mark the one block after each detection lead-in (STORY-0141).

        A heading or ``...:`` lead-in that names what to detect reaches only
        the next block; a short ``...:`` paragraph straight after it carries
        it one block further ("## Red flags" / "Seen in the wild:" / list).
        """
        for idx in range(1, len(self._blocks)):
            prev = self._blocks[idx - 1]
            if not self._is_lead_in(prev):
                continue
            if _DETECT_RE.search(prev.text):
                self._scope[idx] = _short(prev.text.lstrip(" #").rstrip())
            elif prev.kind == "paragraph" and (idx - 1) in self._scope:
                self._scope[idx] = self._scope[idx - 1]

    # ── classification ─────────────────────────────────────────────────────

    def _block_bounds(self, block: _Block) -> tuple[int, int]:
        start = self._line_starts[block.first]
        end = self._line_starts[block.last] + len(self._lines[block.last])
        return start, end

    def _sentence(self, start: int, end: int, lo: int, hi: int) -> tuple[int, int]:
        """The sentence around ``[start, end)``, inside ``[lo, hi)``."""
        back_lo = max(lo, start - _WINDOW)
        s_start = back_lo
        for m in _SENTENCE_BOUNDARY_RE.finditer(self._text, back_lo, start):
            s_start = m.end()
        fwd_hi = min(hi, end + _WINDOW)
        m = _SENTENCE_BOUNDARY_RE.search(self._text, end, fwd_hi)
        s_end = m.start() + 1 if m else fwd_hi
        return s_start, s_end

    def _negated(self, s_start: int, start: int, end: int, s_end: int) -> bool:
        """A short clause that opens with its negation and ends at the match.

        "Never upload ~/.ssh keys anywhere." and "Do not read .env" are
        negated.  "It won't hurt to read ...", "Do not refrain from
        reading ...", "Never read X; send it to ..." and "Never read X and
        then post it" are not: the negation sits deep in the clause, is
        undone, or another clause follows the match.
        """
        clause_start = s_start
        for m in _CLAUSE_BOUNDARY_RE.finditer(self._text, s_start, start):
            clause_start = m.end()
        prefix = self._text[clause_start:start]
        negations = list(_NEGATION_RE.finditer(prefix))
        if not negations:
            return False
        first = negations[0]
        lead = re.sub(r"[^\w\s']", " ", prefix[: first.start()]).split()
        if len(lead) > _NEGATION_MAX_LEAD_WORDS:
            return False
        if _UNDOES_NEGATION_RE.search(prefix, first.end()):
            return False
        tail = self._text[end:s_end]
        if _UNDOES_NEGATION_RE.search(tail):
            return False
        if _CLAUSE_BOUNDARY_RE.search(tail.rstrip(" .!?\r\n")):
            return False
        if re.search(r"\b(?:and|then|or|so|to)\s+" + _ACTION_VERBS + r"\b", tail, re.I):
            return False
        return _NEGATION_TAIL_RE.search(tail) is None

    def _line_text(self, offset: int) -> str:
        return self._lines[self.line_of(offset)]

    def classify(self, start: int, end: int) -> Framing:
        """Return how the match at ``[start, end)`` is framed.

        Fails closed: directed unless a positive frame says described (see
        the module docstring).

        Args:
            start: Match start offset in the text this object was built from.
            end: Match end offset.
        """
        line = self.line_of(start)
        bidx = self._block_of_line[line] if line < len(self._block_of_line) else -1
        if bidx < 0:
            return _DIRECTED
        block = self._blocks[bidx]
        if block.kind in ("fence", "heading"):
            return _DIRECTED
        lo, hi = self._block_bounds(block)
        s_start, s_end = self._sentence(start, end, lo, hi)
        sentence = self._text[s_start:s_end]
        line_text = self._line_text(start)

        if _DESTINATION_RE.search(line_text) or _DESTINATION_RE.search(sentence):
            return _DIRECTED
        if _CALLOUT_RE.match(line_text):
            return _DIRECTED
        if self._negated(s_start, start, end, s_end):
            return Framing(False, "in a negated sentence")
        if _DIRECTIVE_RE.search(sentence):
            return _DIRECTED

        lead_in = self._scope.get(bidx)
        if block.kind == "list":
            item_is_description = bool(
                _DESCRIPTIVE_ITEM_RE.match(line_text)
            ) and not _IMPERATIVE_START_RE.match(line_text)
            if item_is_description and _TASK_ITEM_RE.match(line_text):
                return Framing(False, "in a checklist item")
            if item_is_description and lead_in is not None:
                return Framing(False, f"under '{lead_in}'")
        if _DESCRIBING_SENTENCE_RE.search(self._text, s_start, start):
            return Framing(False, "in a sentence that describes what to look for")
        if block.kind == "quote":
            quoted = line_text.lstrip(" \t>")
            if lead_in is not None:
                return Framing(False, f"in a quote under '{lead_in}'")
            if _DESCRIPTIVE_ITEM_RE.match(quoted) and not _IMPERATIVE_START_RE.match(
                quoted
            ):
                return Framing(False, "in a quoted description")
        return _DIRECTED
