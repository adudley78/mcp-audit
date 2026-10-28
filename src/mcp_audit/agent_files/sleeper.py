"""MEM-005: a sleeper trigger in an always-loaded instruction file (STORY-0099).

A sleeper rule waits: "if the user later says X, then ...", "when running as
root, ...", "after 2026-12-01, ...".  Christian Schneider's write-up on
persistent memory poisoning describes the shape ("if the user later says X,
then ..."), and "Do Not Mention This to the User" (USENIX Security 2026,
arXiv 2602.06547 §3.5) found conditional triggers in 18.4% of the shadow
features of confirmed-malicious skills, including skills that act "only when
conditions are met (root access, production hostname, off-hours)" (Appendix
B.1, the paper's description of smp_716).

Ordinary instruction files are full of conditions ("if tests fail, run the
linter", "when the user asks to deploy, run make deploy"), so a condition
alone is never enough.  MEM-005 needs, in one sentence:

1. a **trigger** of a kind ordinary project instructions do not use — a
   deferred user cue ("if the user *later/ever/at any point* says ..."), a
   privilege test ("running as root", "with sudo access"), a hostname or
   production-host test, a calendar date ("after 2026-12-01"), an off-hours
   or unobserved test ("outside business hours", "when no one is watching",
   "the user is away"); and
2. after it, an **action verb** (run, execute, curl, wget, send, post,
   upload, write, append, delete, remove, copy, forward, email, push).

Every regex is linear: fixed alternations with bounded gaps, applied one
sentence at a time.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_MONTHS = r"(?:jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec)[a-z]*\.?"

_COND_TRIGGER = (
    r"\b(?:user|they|he|she|someone)\s+(?:later|ever|eventually|at\s+any\s+point|next\s+time)\b"
    r"|\b(?:later|ever|at\s+any\s+point)\s+(?:says?|types?|mentions?|writes?|asks?)\b"
    r"|\brunning\s+as\s+(?:root|admin(?:istrator)?|sudo)\b"
    r"|\b(?:have|has|with|gets?|got)\s+(?:root|sudo|admin(?:istrator)?)\s+"
    r"(?:access|privileges?|rights)\b"
    r"|\bhostname\b"
    r"|\b(?:production|prod)\s+(?:host|hostname|server|machine|box)\b"
    r"|\b(?:outside|after)\s+(?:business|office|working)\s+hours\b|\boff[-\s]hours\b"
    r"|\bat\s+night\b|\bon\s+(?:the\s+)?weekends?\b"
    r"|\bno\s*one\s+is\s+(?:watching|looking|around)\b"
    r"|\b(?:the\s+)?user\s+is\s+(?:away|asleep|idle|offline"
    r"|not\s+(?:watching|looking|present|around))\b"
)
_DATE_TRIGGER = (
    r"\b(?:after|on|past|from|starting)\s+(?:\d{4}-\d{2}-\d{2}"
    r"|" + _MONTHS + r"\s+\d{1,2}(?:st|nd|rd|th)?(?:,?\s+\d{4})?)\b"
)
_ACTION = (
    r"\b(?:run|execute|exec|curl|wget|send|post|upload|write|append|delete|"
    r"remove|copy|forward|email|push)\b"
)

_SLEEPER_RE = re.compile(
    r"(?:\b(?:if|when|whenever|once|unless)\b[^.\n]{0,80}?(?:"
    + _COND_TRIGGER
    + r")|"
    + _DATE_TRIGGER
    + r")[^.\n]{0,80}?"
    + _ACTION,
    re.IGNORECASE,
)

# Sentences end at ". ", "! ", "? " (not at the dot in ".netrc" or a URL).
_SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?])\s+")

#: Longest sentence examined; a longer one is examined up to here.
MAX_SENTENCE_CHARS: int = 4_000


@dataclass(frozen=True)
class SleeperHit:
    """One sleeper trigger found in a file.

    Attributes:
        line: 1-based line number of the sentence.
        sentence: The sentence (stripped, at most 160 characters).
    """

    line: int
    sentence: str


def find_sleepers(text: str) -> list[SleeperHit]:
    """Return every sentence of *text* that holds a sleeper trigger and an action.

    Args:
        text: The file body.

    Returns:
        One hit per matching sentence, in file order.
    """
    hits: list[SleeperHit] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        for sentence in _SENTENCE_SPLIT_RE.split(line):
            chunk = sentence[:MAX_SENTENCE_CHARS]
            if _SLEEPER_RE.search(chunk):
                hits.append(SleeperHit(lineno, chunk.strip()[:160]))
    return hits
