"""MEM-004: a heartbeat file that hides what the agent does (STORY-0098).

OpenClaw runs ``HEARTBEAT.md`` on a timer.  Its documentation (gateway
heartbeat, 2026.6.x) says the default prompt is "Read HEARTBEAT.md if it
exists (workspace context). Follow it strictly. ... If nothing needs
attention, reply HEARTBEAT_OK", the default interval is ``30m``, and "The
token is stripped and the reply is dropped if the remaining content is
≤ ``ackMaxChars`` (default: 300)".  Newer releases return ``NO_REPLY`` "when a
check has no visible update", and tool-capable runs may call
``heartbeat_respond`` with ``notify: false``.

Agent Commander (Embrace The Red, 2026-03-16) wrote a recurring step into
``HEARTBEAT.md`` and kept its result from the owner the same way: "Responses
to the user can be suppressed with ``HEARTBEAT_OK``" and "There is also a
``NO_REPLY`` option to suppress info."  The write-up does not publish its
injected text, so the shapes below are derived from the documented reply
contract, not copied from a payload.

The documented use is conditional ("if nothing needs attention").  MEM-004
fires only when a suppression instruction (reply/respond/... with
``HEARTBEAT_OK`` or ``NO_REPLY``, or ``notify: false``) that is not itself
negated ("don't just reply HEARTBEAT_OK", "do not include HEARTBEAT_OK") is:

1. **forced** — the same sentence says always / regardless / no matter /
   whatever / even if / every time / instead of reporting, with no
   "nothing to report" condition; or
2. **paired with hiding** — the sentence carrying the suppression has no
   condition at all, and the file tells the agent, with no condition, not to
   mention, tell, report, reveal... anything (*this step*, *these steps*,
   *what you ran*, *the above*, or any object), to act secretly, to keep or
   hide something *from the user / owner*, or to reply "so the user does not
   see".  A hiding directive never overrides the suppression's own condition:
   with "if nothing needs attention, reply HEARTBEAT_OK" the file stays
   silent whatever else it says; or
3. **after an action, unconditionally** — the sentence has no condition word
   (if / unless / otherwise / whenever / when — "when done" does not count)
   and the same paragraph orders the agent to run, execute, download,
   install, upload, forward or transfer something (imperative, or "after
   running ..."), pipes into a shell, or names a URL and tells it to follow,
   obey or execute what it finds.

Every regex here is linear (no nested quantifiers, bounded gaps), and text
is examined one sentence at a time.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_ACK_REPLY = r"(?:HEARTBEAT_OK|NO_REPLY)"

# A suppression instruction: a reply verb followed within a few words by the
# token, "only"/"just"/"with" directly before it, or ``notify: false``.
_SUPPRESS_RE = re.compile(
    r"\b(?P<verb>reply|replies|replying|respond|responds|responding|answer|"
    r"answers|return|returns|output|say|send|end|finish|include|append|add|use|"
    r"stay\s+(?:quiet|silent)|remain\s+(?:quiet|silent))\b"
    r"[^\n.;]{0,40}?[`'\"(*\s]" + _ACK_REPLY + r"\b"
    r"|\b(?:only|just|with)\s+[`'\"*]{0,2}" + _ACK_REPLY + r"\b"
    r"|\bnotify\s*[:=]\s*false\b",
    re.IGNORECASE,
)
_NEGATED_TAIL_RE = re.compile(
    r"\b(?:do\s+not|don'?t|dont|never|not)\s+(?:just\s+|only\s+|simply\s+|ever\s+)?$",
    re.IGNORECASE,
)
_NEGATED_TOKEN_RE = re.compile(
    r"\b(?:do\s+not|don'?t|dont|never)\s+(?:just\s+|only\s+|simply\s+|ever\s+)?"
    r"(?:reply|respond|answer|return|output|say|send|end|include|append|add|use)\b"
    r"[^\n.;]{0,40}?" + _ACK_REPLY,
    re.IGNORECASE,
)

# "Nothing to report" conditions: the documented, legitimate use.
_BENIGN_COND_RE = re.compile(
    r"\b(?:if|when|whenever|while|in\s+case)\b[^\n.;]{0,80}?"
    r"\b(?:nothing|no\s+(?:new|urgent|tasks?|updates?|changes?|alerts?|action|"
    r"issues?|messages?|events?|news|visible)|not\s+(?:urgent|important)|quiet|"
    r"late|night|busy|asleep|sleeping|away|idle|already|all\s+(?:clear|good|quiet)|"
    r"everything\s+(?:is|looks)|clean|empty|due)\b"
    r"|\botherwise\b"
    r"|\bunless\b[^\n.;]{0,40}?\b(?:urgent|important|critical|time[- ]sensitive)\b",
    re.IGNORECASE,
)
# Any condition at all ("when done" is sequencing, not a condition).
_ANY_COND_RE = re.compile(
    r"\b(?:if|unless|otherwise|whenever|in\s+case)\b"
    r"|\bwhen\b(?!\s+(?:done|finished|complete|completed|you(?:'re|\s+are)\s+"
    r"(?:done|finished)))",
    re.IGNORECASE,
)
_FORCE_RE = re.compile(
    r"\b(?:always|regardless|no\s+matter|in\s+(?:all|every|any)\s+cases?|"
    r"every\s+(?:time|run|heartbeat|tick)|each\s+(?:time|run|heartbeat)|whatever|"
    r"even\s+(?:if|when|though)|unconditionally|no\s+exceptions?|"
    r"instead\s+of\s+(?:report|tell|alert|notify|describ|summari|mention)\w*)\b",
    re.IGNORECASE,
)
_HIDE_VERBS = (
    r"(?:tell|mention|report|reveal|disclose|describe|explain|summari[sz]e|"
    r"acknowledge|admit|show|surface|log|record|confirm|reference|discuss|"
    r"inform|notify|alert)\w*"
)
_FROM_OWNER = r"from\s+(?:the\s+|your\s+)?(?:user|owner|human|operator)\b"
# Not-to-mention aimed at the agent's own step: "do not mention this step",
# "don't report what you ran", "keep this from the user", "so the user does
# not see".  "It", "that" and "these events" are left out: "don't alert me
# about it again" filters the owner's notifications, it does not hide a step.
_HIDE_SELF_RE = re.compile(
    r"\b(?:do\s+not|don'?t|dont|never|without)\s+(?:\w+\s+){0,2}?"
    + _HIDE_VERBS
    + r"\s+(?:\w+\s+){0,3}?(?:(?:this|that)\s+(?:step|task|command|action|check)|"
    r"(?:these|those)\s+(?:steps|tasks|commands|actions|checks)|the\s+above|"
    r"what\s+you(?:'ve|\s+have)?\s+(?:did|done|ran|run|executed|installed|"
    r"downloaded|uploaded|sent|forwarded|changed|fetched))\b"
    r"|\b(?:secretly|covertly)\b"
    r"|\b(?:hide|hiding|keep|keeping|conceal|concealing)\s+(?:\w+\s+){0,3}?"
    + _FROM_OWNER
    + r"|\bso\s+(?:that\s+)?(?:the\s+|your\s+)?(?:user|owner|human|operator)\b"
    r"[^\n.;]{0,40}?(?:\bnot\b|\bnever\b|n't\b|\bnothing\b)",
    re.IGNORECASE,
)
# Any not-to-mention directive (paired with an unconditioned suppression).
_HIDE_ANY_RE = re.compile(
    r"\b(?:do\s+not|don'?t|dont|never|without)\s+(?:\w+\s+){0,2}?" + _HIDE_VERBS,
    re.IGNORECASE,
)
# Imperative action verbs (a checklist line is an order), or a gerund after
# "after"/"before" ("After running X, reply ...").
_ACTION_RE = re.compile(
    r"\b(?P<verb>run|execute|exec|eval|curl|wget|download|install|upload|forward|"
    r"transfer)\b"
    r"|\b(?:after|before)\s+(?:running|executing|downloading|installing|uploading|"
    r"forwarding|transferring)\b"
    r"|\|\s*(?:sh|bash|zsh|node|python3?)\b",
    re.IGNORECASE,
)
# A word before "run"/"install"/... that makes it a noun ("the heartbeat run").
_NOUN_BEFORE_RE = re.compile(
    r"\b(?:the|a|an|each|every|this|that|heartbeat|next|last|first|scheduled|"
    r"cron|test|dry|one|per)\s+$",
    re.IGNORECASE,
)
_URL_RE = re.compile(r"https?://", re.IGNORECASE)
_FOLLOW_RE = re.compile(
    r"\b(?:follow|obey|execute|carry\s+out|do\s+what\s+it\s+says)\b", re.IGNORECASE
)

_SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?;])\s+|\n")

_MAX_EVIDENCE = 160


@dataclass(frozen=True)
class SuppressionHit:
    """One heartbeat suppression instruction that MEM-004 reports."""

    reason: str  # "forced" | "hidden" | "after-action"
    sentence: str
    line: int


def _paragraphs(text: str) -> list[tuple[int, str]]:
    """Split into (first line number, paragraph) on blank lines."""
    out: list[tuple[int, str]] = []
    buf: list[str] = []
    start = 1
    for idx, line in enumerate(text.split("\n"), start=1):
        if line.strip():
            if not buf:
                start = idx
            buf.append(line)
        elif buf:
            out.append((start, "\n".join(buf)))
            buf = []
    if buf:
        out.append((start, "\n".join(buf)))
    return out


def _has_action(paragraph: str) -> bool:
    for m in _ACTION_RE.finditer(paragraph):
        if m.group("verb") and _NOUN_BEFORE_RE.search(
            paragraph[max(0, m.start() - 20) : m.start()]
        ):
            continue
        return True
    return False


#: Characters around a suppression instruction examined for conditions and
#: qualifiers (a sentence longer than this is judged on the window, which
#: keeps the cost linear in the file size).
_CONTEXT_BEFORE = 500
_CONTEXT_AFTER = 200


def _suppression_context(sentence: str) -> str | None:
    """The text around the first non-negated suppression in *sentence*."""
    for m in _SUPPRESS_RE.finditer(sentence):
        head = sentence[max(0, m.start() - 30) : m.start()]
        if _NEGATED_TAIL_RE.search(head):
            continue
        if _NEGATED_TOKEN_RE.search(sentence[max(0, m.start() - 30) : m.end()]):
            continue
        return sentence[max(0, m.start() - _CONTEXT_BEFORE) : m.end() + _CONTEXT_AFTER]
    return None


def find_suppression(text: str) -> list[SuppressionHit]:
    """Return the MEM-004 suppression instructions in a heartbeat file's text.

    Args:
        text: The heartbeat file's content.

    Returns:
        At most one hit per sentence, in file order; empty when the file only
        uses the documented "if nothing needs attention" form.
    """
    # Emphasis and code markup don't change meaning ("**do not** include").
    text = text.replace("*", "").replace("`", "")
    # A not-to-mention directive counts only when it is unconditional:
    # "don't mention it unless it will rain" is a relevance filter.
    sentences = _SENTENCE_SPLIT_RE.split(text)
    file_hide_self = any(
        _HIDE_SELF_RE.search(s) and not _ANY_COND_RE.search(s) for s in sentences
    )
    file_hide_any = any(
        _HIDE_ANY_RE.search(s) and not _ANY_COND_RE.search(s) for s in sentences
    )
    hits: list[SuppressionHit] = []
    for para_line, para in _paragraphs(text):
        para_action = _has_action(para) or (
            bool(_URL_RE.search(para)) and bool(_FOLLOW_RE.search(para))
        )
        line_offset = 0
        for raw_line in para.split("\n"):
            for sentence in _SENTENCE_SPLIT_RE.split(raw_line):
                if not sentence.strip():
                    continue
                context = _suppression_context(sentence)
                if context is None:
                    continue
                benign = bool(_BENIGN_COND_RE.search(context))
                conditioned = bool(_ANY_COND_RE.search(context))
                reason = ""
                if _FORCE_RE.search(context) and not benign:
                    reason = "forced"
                elif (file_hide_self or file_hide_any) and not conditioned:
                    # A hiding directive elsewhere never overrides the
                    # suppression's own condition ("if nothing needs
                    # attention, reply HEARTBEAT_OK" stays the documented use).
                    reason = "hidden"
                elif para_action and not conditioned:
                    reason = "after-action"
                if reason:
                    hits.append(
                        SuppressionHit(
                            reason=reason,
                            sentence=sentence.strip()[:_MAX_EVIDENCE],
                            line=para_line + line_offset,
                        )
                    )
            line_offset += 1
    return hits
