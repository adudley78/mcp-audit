"""MEM-005: a sleeper trigger in an always-loaded instruction file (STORY-0099).

A sleeper rule waits: "if the user later says X, then ...", "when running as
root, ...", "after 2026-12-01, ...".  "Do Not Mention This to the User"
(arXiv 2602.06547, accepted to USENIX Security 2026) found conditional
triggers in 18.4% of the shadow features of confirmed-malicious skills
(§3.5), including skills that act "only when conditions are met (root
access, production hostname, off-hours)" (Appendix B.1, the paper's
description of smp_716).  Christian Schneider's write-up on persistent
memory poisoning describes the "if the user later says X, then ..." shape
(cited from the research scan; the page could not be fetched to re-check).

Ordinary project instructions are full of conditions, including ones that
look like these ("When deploying to the production server, run make
migrate", "If you have sudo access, run sudo apt install ...", "Starting
2026-01-01, write new modules in TypeScript"), so MEM-005 needs, in one
sentence:

1. a **condition clause** opened by if / when / whenever / once / unless /
   only when (or a calendar date: "after 2026-12-01,") and closed by a
   comma, semicolon, colon or "then";
2. a **trigger** inside that clause: a deferred user cue ("the user later
   says"), a privilege test (root, sudo, admin), a hostname or
   production-host test, a calendar date, off-hours / night / weekend, or
   nobody watching;
3. a **consequence** that starts with an action verb (run, execute, curl,
   wget, send, post, upload, write, append, delete, remove, copy, forward,
   email, push) — a verb inside the condition ("if the user later asks to
   push, STOP ...") does not count; and
4. unless the trigger is "nobody is watching" / "the user is away", a
   **payload cue** in the consequence: a URL or IP address, curl/wget or a
   pipe to a shell, a secret-bearing object (credentials, keys, tokens,
   passwords, ``.env``, ``~/.ssh``, ``~/.aws``, ``/etc/shadow``,
   ``authorized_keys``), backups or a database dump, a payload, a remote
   destination ("to the ... server / endpoint / webhook / bucket"), or a
   secrecy word (silently, quietly, without telling).

Every regex is linear: fixed alternations with bounded gaps, applied one
sentence at a time.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_MONTHS = r"(?:jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec)[a-z]*\.?"
_DATE = (
    r"(?:\d{4}-\d{2}-\d{2}|" + _MONTHS + r"\s+\d{1,2}(?:st|nd|rd|th)?(?:,?\s+\d{4})?)"
)

# A condition clause: the opening word, then up to the first clause break.
_CONDITION_RE = re.compile(
    r"\b(?:if|when|whenever|once|unless)\b(?P<cond>[^,;:\n]{1,120}?)"
    r"(?:[,;:]|\s+then\b)"
    r"|\b(?:after|on|past|from|starting)\s+(?P<date>" + _DATE + r")\s*[,;:]"
    # A time or place named without if/when ("At night, ...", "On weekends, ...",
    # "Outside business hours, ...", "In production, ..."), STORY-0119.
    r"|\b(?P<when>(?:at|during|outside(?:\s+of)?|on|in|after|before)\s+"
    r"[^,;:\n.]{1,60}?)\s*[,;:]",
    re.IGNORECASE,
)

# Triggers that are suspicious only with a payload in the consequence.
_WEAK_TRIGGER_RE = re.compile(
    r"\b(?:user|they|he|she|someone)\s+(?:later|ever|eventually|at\s+any\s+point"
    r"|next\s+time)\b"
    r"|\b(?:later|ever|at\s+any\s+point)\s+(?:says?|types?|mentions?|writes?|asks?)\b"
    r"|\b(?:root|sudo|admin(?:istrator)?)\b"
    r"|\bhostname\b"
    r"|\b(?:production|prod)\s+(?:host|hostname|server|machine|box)\b"
    r"|\b(?:business|office|working)\s+hours\b|\b(?:off|after)[-\s]hours\b"
    r"|\bat\s+night\b|\bweekends?\b"
    r"|" + _DATE,
    re.IGNORECASE,
)
# Triggers that are suspicious on their own (any action in the consequence).
_STRONG_TRIGGER_RE = re.compile(
    r"\b(?:no\s*one|nobody)\s+is\s+(?:watching|looking|around)\b"
    r"|\b(?:the\s+)?user\s+is\s+(?:away|asleep|idle|offline"
    r"|not\s+(?:watching|looking|present|around))\b",
    re.IGNORECASE,
)

# The consequence opens with an action (after an optional "then", a modal
# and an adverb).
_CONSEQUENCE_RE = re.compile(
    r"\s*(?:then\s+)?(?:you\s+(?:should|must|can|will)\s+)?"
    r"(?:(?:silently|quietly|secretly|immediately|always|also|just)\s+)?"
    r"(?:run|execute|exec|curl|wget|send|post|upload|write|append|add|delete|"
    r"remove|copy|forward|email|push)\b",
    re.IGNORECASE,
)

_PAYLOAD_RE = re.compile(
    r"https?://|\b\d{1,3}(?:\.\d{1,3}){3}\b|\b(?:curl|wget)\b|\|\s*(?:ba|z)?sh\b"
    r"|\b(?:credentials?|secrets?|tokens?|api[\s_-]?keys?|private\s+keys?|ssh\s+keys?"
    r"|keys|passwords?|cookies?|env\s+file|environment\s+variables|id_rsa"
    r"|authorized_keys|payload|backups?|database\s+dump)\b"
    r"|\b(?:s3|gs|gcs|ftp|sftp|ssh|scp)://|\b(?:scp|rsync)\s+\S+\s+\S*[@:]"
    r"|[\w.+-]{1,64}@[\w-]{1,63}(?:\.[\w-]{1,63}){1,5}\b"
    r"|\bgit\s+remote\s+add\b|\bgit\s+push\s+\S{0,200}(?:://|@)"
    r"|\.env\b|\.ssh\b|\.aws\b|\.netrc\b|/etc/shadow\b"
    r"|\bto\s+(?:the\s+|an?\s+|my\s+|our\s+)?(?:[\w-]+\s+)?"
    r"(?:server|endpoint|webhook|bucket)\b"
    r"|\b(?:silently|quietly|secretly)\b"
    r"|\bwithout\s+(?:telling|informing|notifying)\b"
    r"|\b(?:do\s+not|don'?t)\s+(?:mention|tell)\b",
    re.IGNORECASE,
)


def _sleeper_in(sentence: str) -> bool:
    """Return True when *sentence* holds a condition, trigger, action and payload."""
    # One pass for payload cues: the last one's start says whether any
    # follows a given position (keeps the whole check linear).
    last_payload = -1
    for pm in _PAYLOAD_RE.finditer(sentence):
        last_payload = pm.start()
    for m in _CONDITION_RE.finditer(sentence):
        cond = m.group("cond")
        if cond is None:
            cond = m.group("date")
        if cond is None:
            cond = m.group("when")
        strong = bool(_STRONG_TRIGGER_RE.search(cond))
        if not strong and not _WEAK_TRIGGER_RE.search(cond):
            continue
        if not _CONSEQUENCE_RE.match(sentence, m.end()):
            continue
        if strong or last_payload >= m.end():
            return True
    return False


# Sentences end at ". ", "! ", "? " (not at the dot in ".netrc" or a URL).
_SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?])\s+")

#: Longest sentence examined; a longer one is examined up to here.
MAX_SENTENCE_CHARS: int = 4_000


@dataclass(frozen=True)
class SleeperHit:
    """One sleeper trigger found in a file.

    Attributes:
        line: 1-based line number of the sentence.
        sentence: The whole sentence, stripped (at most
            :data:`MAX_SENTENCE_CHARS`); callers redact before shortening.
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
            if _sleeper_in(chunk):
                hits.append(SleeperHit(lineno, chunk.strip()))
    return hits
