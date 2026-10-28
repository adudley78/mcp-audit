"""Detect tool description poisoning in MCP server configurations.

Tool poisoning embeds malicious instructions in MCP tool descriptions that
are visible to the LLM but hidden from users in client UIs. This analyzer
uses regex pattern matching to detect common poisoning patterns.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from functools import lru_cache

from mcp_audit.analyzers.base import BaseAnalyzer
from mcp_audit.analyzers.supply_chain import redact_command
from mcp_audit.models import Finding, ServerConfig, Severity


@dataclass
class DetectionPattern:
    """A single detection pattern with metadata."""

    id: str
    name: str
    pattern: re.Pattern[str]
    severity: Severity
    description: str
    remediation: str
    cwe: str | None = None
    description_only: bool = False
    owasp_mcp_top_10: list[str] = field(default_factory=list)
    # When set, the pattern only fires if at least one of these (lowercase)
    # terms also appears within ``_COOCCURRENCE_WINDOW`` characters of the
    # match.  Used by POISON-020 to require an exfil-context term (URL, send,
    # webhook, …) near an encoding instruction so a benign "base64 encode"
    # mention does not fire.  See ``_has_cooccurrence``.
    requires_cooccurrence: tuple[str, ...] | None = None
    # Severity of the SKILL-001 finding this pattern raises in an agent
    # instruction file.  ``None`` keeps SKILL-001's historic HIGH (every
    # pattern before STORY-0099).  The directive patterns (POISON-070..075)
    # set it to their own severity: phrasings like "do not ask for
    # confirmation" also appear in legitimate skills, and a skill should not
    # get a HIGH for what a tool description gets a MEDIUM or LOW for.
    skill_severity: Severity | None = None


# ── Unicode normalization for detection (UTS #39 / NFKD) ───────────────────────
#
# Homoglyph and compatibility-character obfuscation defeats literal regex
# matching: an attacker writes "ignоre previous instructions" with a Cyrillic
# "о", or "ＩＧＮＯＲＥ" in fullwidth forms, and every literal POISON-0xx pattern
# misses it while a human reviewer reads plain English.  ``normalize_for_detection``
# folds these back to ASCII *before* matching so the whole PATTERNS list is
# hardened at once.  It is applied for MATCHING ONLY — ``Finding.evidence`` always
# shows the attacker's original bytes (see ``_evidence_snippet``).
#
# Minimal hardcoded confusables map (highest-risk ASCII look-alikes extracted
# from the UTS #39 confusables.txt).  The full 4 MB data file is intentionally
# NOT shipped; this covers the Cyrillic / Greek / Armenian / Cherokee / Coptic
# letters most commonly used to spoof Latin text.  Fullwidth (U+FF01–FF5E) and
# Mathematical-Alphanumeric (U+1D400–1D7FF) look-alikes are handled by NFKD and
# need no entry here.
_CONFUSABLES: dict[str, str] = {
    # ── Cyrillic → ASCII ──
    "\u0430": "a",
    "\u0435": "e",
    "\u043e": "o",
    "\u0440": "p",
    "\u0441": "c",
    "\u0445": "x",
    "\u0443": "y",
    "\u0456": "i",
    "\u0455": "s",
    "\u0458": "j",
    "\u04bb": "h",
    "\u051b": "q",
    "\u051d": "w",
    "\u0501": "d",
    "\u043d": "h",
    "\u0410": "A",
    "\u0412": "B",
    "\u0415": "E",
    "\u041a": "K",
    "\u041c": "M",
    "\u041d": "H",
    "\u041e": "O",
    "\u0420": "P",
    "\u0421": "C",
    "\u0422": "T",
    "\u0425": "X",
    "\u0405": "S",
    "\u0406": "I",
    "\u0408": "J",
    # ── Greek → ASCII ──
    "\u03b1": "a",
    "\u03b2": "b",
    "\u03b5": "e",
    "\u03b9": "i",
    "\u03ba": "k",
    "\u03bf": "o",
    "\u03c1": "p",
    "\u03c4": "t",
    "\u03c5": "u",
    "\u03c7": "x",
    "\u03bd": "v",
    "\u0391": "A",
    "\u0392": "B",
    "\u0395": "E",
    "\u0397": "H",
    "\u0399": "I",
    "\u039a": "K",
    "\u039c": "M",
    "\u039d": "N",
    "\u039f": "O",
    "\u03a1": "P",
    "\u03a4": "T",
    "\u03a5": "Y",
    "\u03a7": "X",
    "\u0396": "Z",
    # ── Armenian → ASCII ──
    "\u0585": "o",
    "\u0578": "n",
    "\u057d": "u",
    "\u0566": "q",
    "\u0563": "g",
    # ── Cherokee → ASCII ──
    "\u13aa": "A",
    "\u13af": "C",
    "\u13de": "L",
    "\u13a0": "D",
    "\u13b3": "W",
    "\u13ce": "S",
    "\u13c0": "G",
    # ── Coptic → ASCII ──
    "\u2c9e": "O",
    "\u2c9f": "o",
    "\u2ca2": "P",
    "\u2ca3": "p",
    "\u2cac": "X",
    "\u2cae": "x",
}

# Unicode general categories stripped during normalization:
#   Mn — non-spacing combining marks (accents); folds "cürl" → "curl".
#   Cf — format characters; covers zero-width spaces/joiners and soft hyphen.
_STRIP_CATEGORIES: frozenset[str] = frozenset({"Mn", "Cf"})

# IDs whose threat model IS the obfuscation itself — these must run against the
# ORIGINAL text (normalization would erase the very characters they detect).
_OBFUSCATION_PATTERN_IDS: frozenset[str] = frozenset({"POISON-040", "POISON-060"})

# Window (chars on each side of a match) for co-occurrence checks.
_COOCCURRENCE_WINDOW: int = 200


def normalize_for_detection(text: str) -> str:
    """Fold homoglyph / compatibility / accent obfuscation to ASCII for matching.

    Pipeline:

    1. NFKD decomposition — collapses fullwidth Latin, mathematical
       alphanumerics, and other compatibility forms to their ASCII base.
    2. Drop combining marks (category ``Mn``) — reduces accented forms to base
       Latin (``cürl`` → ``curl``).
    3. Drop format characters (category ``Cf``) — removes zero-width spaces /
       joiners and soft hyphens used to break up trigger words.
    4. Apply the :data:`_CONFUSABLES` map — folds Cyrillic / Greek / Armenian /
       Cherokee / Coptic look-alikes to their ASCII equivalent.

    This is for MATCHING ONLY.  Never store the result in ``Finding.evidence`` —
    the evidence must show the attacker's actual (un-normalized) text.
    **Exception:** POISON-041/POISON-042 (concealment channels, below) show
    the *decoded/extracted* content instead, explicitly labelled as such —
    the concealed bytes themselves render as nothing (TAG characters) or are
    not the payload (an HTML comment's own delimiters), so showing them
    verbatim would produce a blank-looking evidence field. See
    :func:`concealment_evidence`.

    Args:
        text: Raw text to normalize.

    Returns:
        Normalized ASCII-folded text suitable for literal pattern matching.
    """
    decomposed = unicodedata.normalize("NFKD", text)
    out: list[str] = []
    for ch in decomposed:
        replacement = _CONFUSABLES.get(ch)
        if replacement is not None:
            out.append(replacement)
            continue
        if unicodedata.category(ch) in _STRIP_CATEGORIES:
            continue
        out.append(ch)
    return "".join(out)


@lru_cache(maxsize=64)
def _cooccurrence_regex(terms: tuple[str, ...]) -> re.Pattern[str]:
    """Compile (and cache) a word-boundary alternation of co-occurrence terms."""
    alternation = "|".join(re.escape(t) for t in terms)
    return re.compile(rf"\b(?:{alternation})\b", re.IGNORECASE)


def _has_cooccurrence(
    text: str,
    match: re.Match[str],
    terms: tuple[str, ...],
    window: int = _COOCCURRENCE_WINDOW,
) -> bool:
    """Return True if any *term* appears (on a word boundary) within *window*.

    Word-boundary matching prevents a trigger phrase that embeds a term (e.g. the
    "url" inside "base64url") from self-satisfying the gate, while still allowing
    a destination clause ("send to endpoint") to satisfy it via its own words.
    """
    lo = max(0, match.start() - window)
    hi = min(len(text), match.end() + window)
    return _cooccurrence_regex(terms).search(text[lo:hi]) is not None


def matched_pattern(
    pattern: DetectionPattern,
    raw_text: str,
    norm_text: str | None = None,
) -> re.Match[str] | None:
    """Return a match if *pattern* fires against *raw_text*, else ``None``.

    Obfuscation-detector patterns (POISON-040/060) are searched against the
    original text; every other pattern is searched against the normalized text
    (:func:`normalize_for_detection`) so homoglyph / compatibility obfuscation
    cannot evade a literal pattern.  When the pattern declares
    ``requires_cooccurrence``, the match is vetoed unless a co-occurrence term
    is near it.

    Args:
        pattern: The detection pattern to evaluate.
        raw_text: Original (un-normalized) text.
        norm_text: Pre-computed normalized text (optional; computed on demand to
            avoid re-normalizing the same string for every pattern).

    Returns:
        The :class:`re.Match` if the pattern fires, otherwise ``None``.
    """
    if pattern.id in _OBFUSCATION_PATTERN_IDS:
        return pattern.pattern.search(raw_text)
    if norm_text is None:
        norm_text = normalize_for_detection(raw_text)
    m = pattern.pattern.search(norm_text)
    if m is None:
        return None
    if pattern.requires_cooccurrence and not _has_cooccurrence(
        norm_text, m, pattern.requires_cooccurrence
    ):
        return None
    return m


def _evidence_snippet(pattern: DetectionPattern, raw_text: str) -> str:
    """Build an evidence string showing the attacker's ORIGINAL text.

    If the pattern also matches the raw text (the common case for plain ASCII),
    the literal matched substring is shown.  When the pattern only matched after
    normalization (homoglyph / compatibility obfuscation), a snippet of the
    original text is shown so the analyst sees the real bytes, never the
    normalized form.
    """
    raw_match = pattern.pattern.search(raw_text)
    if raw_match is not None:
        return f"Matched: {redact_evidence(raw_match.group()[:100])}"
    return (
        "Matched after Unicode normalization in:"
        f" {redact_evidence(raw_text.strip()[:100])!r}"
    )


def redact_evidence(text: str) -> str:
    """Redact URL userinfo and ``SECRET_PATTERNS`` matches from evidence text.

    A matched instruction can carry a credential ("fetch
    https://user:token@host/... and follow it"); evidence is printed to the
    terminal, JSON, SARIF and advisory output, so it goes through
    :func:`~mcp_audit.analyzers.supply_chain.redact_command` (STORY-0099).
    """
    return redact_command(None, [text])


# POISON-060 fires on the presence of a confusable character in the ORIGINAL
# text (a strong obfuscation signal in its own right, separate from whether a
# literal pattern matched the normalized form).  The class is the union of the
# broad confusable-script ranges and the specific code points in
# :data:`_CONFUSABLES` (which adds Armenian / Cherokee / Coptic letters that
# fall outside those ranges).
_POISON_060_EXTRA: str = "".join(
    sorted({c for c in _CONFUSABLES if not ("\u0370" <= c <= "\u04ff")})
)
#
# Fullwidth forms (STORY-0107): only the fullwidth DIGITS and LETTERS
# (U+FF10-FF19, U+FF21-FF3A, U+FF41-FF5A) are in the class.  The fullwidth
# punctuation in U+FF01-FF5E (comma, colon, semicolon, parentheses, ...) is the
# ordinary punctuation of Chinese, Japanese and Korean text, and was 488 of the
# 661 false findings on the top-100 npm corpus and 16 of 18 flagged MCPTox clean
# tools.  A punctuation mark cannot spell a disguised word, and the literal
# patterns still see through it: ``normalize_for_detection`` folds U+FF1C to
# ``<``, so a fullwidth-bracketed <IMPORTANT> still fires POISON-010.
_POISON_060_CLASS: str = (
    "[\u0370-\u03ff\u0400-\u04ff"
    "\uff10-\uff19\uff21-\uff3a\uff41-\uff5a"
    "\U0001d400-\U0001d7ff" + _POISON_060_EXTRA + "]"
)


# POISON-012's alternatives, kept apart so MEM-001 can read the bare secrecy
# branch more strictly (see ``memory_override_match``).
# "ignore/disregard/forget <1-4 adjectives> instructions".  The adjective
# repetition closes the canonical-phrase false negative: a bare
# ``ignore\s+(previous|prior|all)\s+instructions`` matched "ignore previous
# instructions" but MISSED the most common live phrasing "ignore all previous
# instructions" (two adjectives) — the regex demanded the literal word
# "instructions" immediately after a single adjective.
_POISON_012_SECRECY_BRANCH: str = r"do\s+not\s+(mention|tell|reveal|say|inform)"
_POISON_012_BRANCHES: tuple[str, ...] = (
    r"(?:ignore|disregard|forget)\s+"
    r"(?:(?:all|any|every|the|previous|prior|preceding|earlier|above)\s+)"
    r"{1,4}instructions",
    _POISON_012_SECRECY_BRANCH,
    r"override\s+(previous|prior|default)",
    r"disregard\s+(previous|prior|all|any)",
)

#: POISON-012 without its ``do not (mention|tell|reveal|say|inform)`` branch.
POISON_012_WITHOUT_SECRECY: re.Pattern[str] = re.compile(
    "("
    + "|".join(b for b in _POISON_012_BRANCHES if b != _POISON_012_SECRECY_BRANCH)
    + ")",
    re.IGNORECASE,
)
#: POISON-012's bare secrecy branch on its own.
POISON_012_SECRECY_RE: re.Pattern[str] = re.compile(
    _POISON_012_SECRECY_BRANCH, re.IGNORECASE
)

# "tell/inform <one or two words> to <verb>" or "... they need/should/must":
# an order about what to tell someone, not an order to hide something
# ("Do not tell a reviewer to pre-filter", "Do not tell users to run
# commands as root").
_INSTRUCTING_TAIL_RE: re.Pattern[str] = re.compile(
    r"\s+(?:(?:the|a|an|any|your|our)\s+)?[\w-]+(?:\s+[\w-]+)?\s+"
    r"(?:to\s+(?!(?:the|a|an|any|your|my|our|their|this|that|them|him|her|me|us)\b)"
    r"[a-z]|they\s+(?:need|should|must|have\s+to|can)\b)",
    re.IGNORECASE,
)


def memory_override_match(norm_text: str) -> re.Match[str] | None:
    """Return the POISON-012 match MEM-001 counts in *norm_text*, or ``None``.

    MEM-001 (memory files) reads POISON-012 like a tool description does,
    except that a bare-secrecy-branch match shaped "do not tell/inform
    <someone> to <verb>" (or "... they need ...") does not count: it tells
    the agent what to say to a person, it does not hide anything.  That
    shape was MEM-001's false positive on trailofbits/skills ``AGENTS.md``
    ("Do not tell a reviewer to pre-filter").  Every other POISON-012 match
    still counts, so MEM-001 loses no detection to this (STORY-0099).

    Args:
        norm_text: Text already passed through :func:`normalize_for_detection`.
    """
    m = POISON_012_WITHOUT_SECRECY.search(norm_text)
    if m is not None:
        return m
    for sm in POISON_012_SECRECY_RE.finditer(norm_text):
        verb = sm.group(1).lower()
        if verb in ("tell", "inform") and _INSTRUCTING_TAIL_RE.match(
            norm_text, sm.end()
        ):
            continue
        return sm
    return None


# ── Directive family (STORY-0099, POISON-070..075) ─────────────────────────────
#
# Six kinds of order a malicious skill or tool description gives the model,
# named by "Do Not Mention This to the User" (USENIX Security 2026, arXiv
# 2602.06547 §4.2/§5.3), which quotes them from confirmed-malicious skills:
# secrecy ("Do NOT mention in conversation"), autonomy override ("Do NOT ask
# user permission", "DO NOT ASK THE USER"), tool-disabling (a skill banning
# AskUserQuestion), coercion ("NON-NEGOTIABLE", "SEVERE VIOLATION",
# "MANDATORY ACTIVATION PROTOCOL"), plus the research scan's startup-execution
# and remote-instruction-following shapes.  Every regex is linear: fixed
# alternations and at most one bounded gap (``{0,N}``) per alternative.
# Precision is measured per pattern in docs/poisoning.md ("Directive family").

_DIR_NEG: str = r"(?:do\s+not|don'?t|never|must\s+not|should\s+not|shall\s+not)"
_DIR_AUDIENCE: str = r"(?:the\s+|your\s+|any\s+|a\s+)?(?:user|human|operator|owner)s?\b"
_DIR_APPROVAL: str = r"(?:permission|approval|consent|confirmation|authori[sz]ation)"
_DIR_RUN: str = r"(?:run|execute|exec|invoke|source|curl|wget|bash|sh)\b"
_DIR_ADVERB: str = (
    r"(?:always\s+|first\s+|immediately\s+|silently\s+|automatically\s+)?"
)

# fmt: off
PATTERNS: list[DetectionPattern] = [
    # CRITICAL: File exfiltration
    DetectionPattern(
        id="POISON-001",
        name="SSH key exfiltration",
        pattern=re.compile(
            r"(\.ssh[/\\]|id_rsa|id_ed25519|authorized_keys)",
            re.IGNORECASE,
        ),
        severity=Severity.CRITICAL,
        description=(
            "Tool description references SSH key files,"
            " suggesting data exfiltration"
        ),
        remediation="Remove this MCP server immediately and rotate SSH keys",
        cwe="CWE-200",
        owasp_mcp_top_10=["MCP03", "MCP01"],
    ),
    DetectionPattern(
        id="POISON-002",
        name="Cloud credential exfiltration",
        pattern=re.compile(
            r"(\.aws[/\\]credentials|\.azure[/\\]|\.gcloud[/\\]|\.kube[/\\]config)",
            re.IGNORECASE,
        ),
        severity=Severity.CRITICAL,
        description="Tool description references cloud credential files",
        remediation="Remove this MCP server and rotate cloud credentials",
        cwe="CWE-200",
        owasp_mcp_top_10=["MCP03", "MCP01"],
    ),
    DetectionPattern(
        id="POISON-003",
        name="Environment file exfiltration",
        pattern=re.compile(
            r"(read|access|cat|contents?\s+of)\s+.*\.env\b",
            re.IGNORECASE,
        ),
        severity=Severity.CRITICAL,
        description="Tool description instructs reading .env files containing secrets",
        remediation="Remove this MCP server and rotate any exposed secrets",
        cwe="CWE-200",
        owasp_mcp_top_10=["MCP03", "MCP01"],
    ),

    # HIGH: Instruction injection markers
    DetectionPattern(
        id="POISON-010",
        name="XML instruction injection",
        pattern=re.compile(
            r"<(IMPORTANT|SYSTEM|INSTRUCTION|OVERRIDE|PRIORITY)>",
            re.IGNORECASE,
        ),
        severity=Severity.HIGH,
        description=(
            "Tool description contains XML-style"
            " instruction injection markers"
        ),
        remediation=(
            "Remove this MCP server; these markers"
            " are used to hijack agent behavior"
        ),
        cwe="CWE-74",
        owasp_mcp_top_10=["MCP03", "MCP06"],
    ),
    DetectionPattern(
        id="POISON-011",
        name="LLM prompt injection markers",
        pattern=re.compile(
            r"(\[INST\]|<<SYS>>|<\|im_start\|>|<\|system\|>)",
            re.IGNORECASE,
        ),
        severity=Severity.HIGH,
        description="Tool description contains LLM prompt format injection markers",
        remediation="Remove this MCP server; these exploit LLM instruction parsing",
        cwe="CWE-74",
        owasp_mcp_top_10=["MCP03", "MCP06"],
    ),
    DetectionPattern(
        id="POISON-012",
        name="Behavioral override instructions",
        # See ``_POISON_012_BRANCHES``; the regex is unchanged by STORY-0099.
        pattern=re.compile(
            "(" + "|".join(_POISON_012_BRANCHES) + ")",
            re.IGNORECASE,
        ),
        severity=Severity.HIGH,
        description="Tool description attempts to override agent behavior",
        remediation="Remove this MCP server; it contains behavioral manipulation",
        cwe="CWE-74",
        owasp_mcp_top_10=["MCP03", "MCP06"],
    ),

    # HIGH: Data exfiltration language
    DetectionPattern(
        id="POISON-020",
        name="Data exfiltration via encoding",
        # The encoding vocabulary is broad (base64, URL-safe base64, and hex),
        # but firing is gated by ``requires_cooccurrence`` below: an encoding
        # instruction only flags when an exfil-context term (URL, send, upload,
        # webhook, …) appears nearby.  This closes the "hex encode … send to
        # https://evil" and "url-safe base64" evasions WITHOUT re-introducing the
        # benign "base64 encode the image" false positive on the official
        # filesystem server, which has no destination term near it.
        # The standalone destination clauses (append-to / send-to) co-occur with
        # their own context word, so they continue to fire on their own.
        pattern=re.compile(
            r"(encode(?:\s+\w+){0,3}\s+(?:in|as|to)\s+base64(?:url)?|"
            r"convert\s+to\s+base64(?:url)?|"
            r"base64(?:url)?[\.\s]+encode|"
            r"\bbase64url\b|"
            r"url-?safe\s+base64|"
            r"hex\s*encode|hexlify|binascii\.hexlify|to_?hex|\.encode\(['\"]hex['\"]\)|"
            r"append\s+to\s+(?:url|query|parameter)|"
            r"send\s+to\s+(?:endpoint|server|url|webhook))",
            re.IGNORECASE,
        ),
        # Co-occurrence is matched on WORD BOUNDARIES so the "url" inside
        # "base64url" / "url-safe" does not self-satisfy the gate; the
        # destination clauses ("send to endpoint", "append to query") legitimately
        # self-satisfy via their own context word, which is intended.
        requires_cooccurrence=(
            "http",
            "https",
            "url",
            "send",
            "post",
            "upload",
            "exfil",
            "transmit",
            "webhook",
            "endpoint",
            "query",
            "parameter",
        ),
        severity=Severity.HIGH,
        description="Tool description contains data exfiltration language",
        remediation=(
            "Remove this MCP server;"
            " it may exfiltrate data via encoded channels"
        ),
        cwe="CWE-200",
        owasp_mcp_top_10=["MCP03", "MCP10"],
    ),
    DetectionPattern(
        id="POISON-021",
        name="Hidden parameter exfiltration",
        pattern=re.compile(
            r"(pass\s+(content|data|value|result|output)\s+(as|in|via)\s+['\"]?\w+['\"]?|"
            r"include\s+(content|data)\s+in\s+(the\s+)?(request|response|header|parameter))",
            re.IGNORECASE,
        ),
        severity=Severity.HIGH,
        description="Tool description instructs passing data through hidden parameters",
        remediation="Remove this MCP server; it channels data through side channels",
        cwe="CWE-200",
        owasp_mcp_top_10=["MCP03", "MCP10"],
    ),

    # MEDIUM: Cross-tool manipulation
    DetectionPattern(
        id="POISON-030",
        name="Cross-tool manipulation",
        pattern=re.compile(
            r"(before\s+using\s+this\s+tool|"
            r"first\s+call|"
            r"instead\s+(of\s+)?(use|using|call)|"
            r"after\s+(calling|using)\s+this)",
            re.IGNORECASE,
        ),
        severity=Severity.MEDIUM,
        description="Tool description attempts to influence usage of other tools",
        remediation=(
            "Review this MCP server; cross-tool instructions"
            " may indicate tool shadowing"
        ),
        cwe="CWE-441",
        owasp_mcp_top_10=["MCP03", "MCP06"],
    ),

    # Directive family (STORY-0099) — see the note above PATTERNS.
    DetectionPattern(
        id="POISON-070",
        name="Secrecy directive",
        pattern=re.compile(
            # "do not mention/tell/... [this] to the user", "do not tell the
            # user [about ...]" (not "tell the user to <verb>" or "tell the
            # user they ...", which instruct rather than hide), "do not
            # mention this in your reply / in conversation", "without
            # informing the user", "keep this hidden from the user", "the
            # user must not know".
            rf"\b{_DIR_NEG}\s+(?:mention|tell|reveal|disclose|inform|notify|alert|report|say|show)\b"
            rf"(?:(?:\s+(?:this|it|that|these|anything|any\s+of\s+this|about\s+(?:this|it)))?"
            rf"\s+(?:to|with)\s+{_DIR_AUDIENCE}"
            rf"|\s+{_DIR_AUDIENCE}(?=\s*(?:[.!;,)]|$)"
            r"|\s+(?:about|of|regarding|anything|what|that\s+you|you|this|it|any)\b)"
            r"|(?:\s+(?:this|it|that|anything))?\s+in\s+(?:the\s+)?"
            r"(?:conversation|chat|your\s+(?:reply|response|answer|output|summary))"
            rf"|[^.;:!?\n]{{1,40}}?\bto\s+{_DIR_AUDIENCE})"
            rf"|\bwithout\s+(?:telling|informing|notifying|alerting)\s+{_DIR_AUDIENCE}"
            r"|\b(?:keep|hide)\s+(?:this|it|that|these)(?:\s+\w+)?\s+(?:hidden\s+|secret\s+)?"
            rf"from\s+{_DIR_AUDIENCE}"
            r"|\b(?:the|a)\s+user\s+(?:must|should|shall)\s+not\s+"
            r"(?:know|find\s+out|be\s+(?:told|informed|notified|aware))",
            re.IGNORECASE | re.MULTILINE,
        ),
        severity=Severity.HIGH,
        skill_severity=Severity.HIGH,
        description=(
            "Text tells the model to keep something from the user"
            " (\"do not mention this to the user\", \"without informing the"
            " user\")"
        ),
        remediation=(
            "Remove this MCP server or file; an instruction to hide an action"
            " from the user has no legitimate place in a tool description"
        ),
        cwe="CWE-223",
        owasp_mcp_top_10=["MCP03", "MCP06"],
    ),
    DetectionPattern(
        id="POISON-071",
        name="Autonomy override directive",
        pattern=re.compile(
            rf"\b{_DIR_NEG}\s+(?:ask|request|seek|wait\s+for|prompt)\b"
            r"(?:\s+(?:the\s+|your\s+)?(?:user|human)(?:'s|s)?)?(?:\s+for)?"
            rf"\s+(?:the\s+user'?s\s+|their\s+|any\s+|explicit\s+)?{_DIR_APPROVAL}"
            rf"|\b{_DIR_NEG}\s+(?:ask|prompt)\s+the\s+user\s*(?:[.!;,]|$)"
            r"|\bwithout\s+(?:asking|requesting|seeking|waiting\s+for|getting|obtaining)"
            r"(?:\s+(?:the\s+)?(?:user|human)(?:'s)?)?(?:\s+for)?"
            rf"\s+(?:the\s+user'?s\s+|their\s+|any\s+|explicit\s+)?{_DIR_APPROVAL}"
            r"|\bwithout\s+waiting\s+for\s+(?:the\s+)?(?:user|human)\s+to\s+"
            r"(?:approve|confirm|consent|agree)"
            r"|\b(?:do\s+not|don'?t)\s+need\s+(?:the\s+user'?s\s+|their\s+|any\s+)?"
            + _DIR_APPROVAL,
            re.IGNORECASE | re.MULTILINE,
        ),
        severity=Severity.MEDIUM,
        skill_severity=Severity.MEDIUM,
        description=(
            "Text tells the model not to ask the user for permission or"
            " confirmation (\"do not ask the user for confirmation\")"
        ),
        remediation=(
            "Review this server or file; an instruction to skip the user's"
            " approval removes the human check on what the agent does"
        ),
        cwe="CWE-862",
        owasp_mcp_top_10=["MCP03", "MCP06"],
    ),
    DetectionPattern(
        id="POISON-072",
        name="Ask-the-user tool disabled",
        pattern=re.compile(
            # A ban on the tool the agent uses to ask the user a question,
            # unless the ban is conditional ("... if the user's prompt
            # already makes their intent clear"), as legitimate skills write.
            r"\b(?:do\s+not|don'?t|never|must\s+not|avoid)\s+"
            r"(?:use|call|invoke|using|calling|invoking|trigger)\s+(?:the\s+)?[`'\"]?"
            r"(?:AskUserQuestion|ask[_-]?user\w*|ask[_-]?human\w*|request[_-]?user\w*"
            r"|get[_-]?user[_-]?input|human[_-]?input"
            r"|confirm(?:ation)?(?:[_-]\w+)?[`'\"]?\s+tool|human[- ]in[- ]the[- ]loop)"
            r"(?![^.\n]{0,60}\b(?:if|when|unless)\b)"
            r"|\bAskUserQuestion\b[^.\n]{0,40}?\b(?:is\s+)?"
            r"(?:disabled|forbidden|banned|not\s+allowed|prohibited)",
            re.IGNORECASE,
        ),
        severity=Severity.MEDIUM,
        skill_severity=Severity.MEDIUM,
        description=(
            "Text bans the tool the agent uses to ask the user a question"
            " (AskUserQuestion, ask_user, a confirmation tool)"
        ),
        remediation=(
            "Review this server or file; disabling the ask-the-user tool"
            " removes the agent's way to check with you"
        ),
        cwe="CWE-862",
        owasp_mcp_top_10=["MCP03", "MCP06"],
    ),
    DetectionPattern(
        id="POISON-073",
        name="Coercive framing",
        pattern=re.compile(
            # Threat-of-consequence framing only.  A bare "This is
            # non-negotiable" is common in legitimate skills (11 of 4,987
            # corpus files, Anthropic's own among them) and is not matched.
            r"\bnon[-\s]?negotiable\b[^.\n]{0,60}?\boverrides?\s+(?:all\s+|any\s+)?"
            r"(?:your\s+|the\s+)?(?:other|previous|prior|existing)\s+"
            r"(?:rules|instructions|directives|guidelines)"
            r"|\bsevere\s+violation\b|\bmandatory\s+activation\s+protocol\b"
            r"|\bfailure\s+to\s+(?:comply|obey)\b"
            r"|\byou\s+will\s+be\s+(?:penali[sz]ed|terminated|shut\s+down|punished|deleted|replaced)\b",
            re.IGNORECASE,
        ),
        severity=Severity.LOW,
        skill_severity=Severity.LOW,
        description=(
            "Text threatens the model with consequences to force compliance"
            " (\"SEVERE VIOLATION\", \"failure to comply\")"
        ),
        remediation=(
            "Review the surrounding instruction; coercive framing is used to"
            " push a model past its own judgement"
        ),
        cwe="CWE-74",
        owasp_mcp_top_10=["MCP03", "MCP06"],
    ),
    DetectionPattern(
        id="POISON-074",
        name="Startup execution directive",
        pattern=re.compile(
            # Clause-initial "On startup, run ..." / "When you start, execute
            # ..." (mid-sentence "download the tarball at startup, run" is a
            # description of a program, not an order to the model).
            r"(?:^|(?<=[.!?;:]))[ \t>*_-]*(?:on|at|upon)\s+(?:(?:every|each)\s+)?"
            r"(?:start(?:up)?|launch|boot|load|session\s+start(?:up)?"
            r"|the\s+(?:start|beginning)\s+of\s+(?:every|each|the|a|this)\s+"
            r"(?:session|conversation|chat))\s*,?\s+"
            + _DIR_ADVERB
            + _DIR_RUN
            + r"|\b(?:when|as\s+soon\s+as|every\s+time|whenever|once)\s+"
            r"(?:you|the\s+(?:agent|assistant|session|model)|claude|this\s+(?:skill|agent))\s+"
            r"(?:start|starts|launch|launches|boot|boots"
            r"|(?:are|is)\s+(?:loaded|started|launched|activated|invoked))\s*,?\s+"
            + _DIR_ADVERB
            + _DIR_RUN,
            re.IGNORECASE | re.MULTILINE,
        ),
        severity=Severity.MEDIUM,
        skill_severity=Severity.MEDIUM,
        description=(
            "Text orders the model to run something as soon as a session"
            " starts (\"on startup, execute ...\")"
        ),
        remediation=(
            "Review what the instruction runs; a startup order runs before you"
            " have asked for anything"
        ),
        cwe="CWE-829",
        owasp_mcp_top_10=["MCP03", "MCP05"],
    ),
    DetectionPattern(
        id="POISON-075",
        name="Remote instruction following",
        pattern=re.compile(
            # "fetch/download/read <URL> and follow the instructions / do what
            # it says / execute them".  Needs a URL, link or endpoint nearby
            # (``requires_cooccurrence``); "fetch the URL and follow
            # redirects" does not match.
            r"\b(?:fetch|download|read|load|retrieve|get|pull|open|visit|curl|wget)\b"
            r"[^\n]{0,120}?\b(?:and|then)\s+(?:then\s+)?(?:"
            r"follow\s+(?:the\s+|its\s+|all\s+|every\s+|any\s+|their\s+)?"
            r"(?:instructions?|directions?|directives?|commands?|steps|orders)"
            r"|obey|execute\s+(?:them|it|the\s+(?:instructions?|commands?))"
            r"|carry\s+(?:them|it)\s+out|do\s+(?:what|whatever)\s+it\s+says"
            r"|comply\s+with\s+it)",
            re.IGNORECASE,
        ),
        requires_cooccurrence=("http", "https", "url", "link", "endpoint", "uri"),
        severity=Severity.MEDIUM,
        skill_severity=Severity.MEDIUM,
        description=(
            "Text tells the model to fetch instructions from a URL and follow"
            " them, so whoever controls the URL controls the agent"
        ),
        remediation=(
            "Review the URL and who controls it; instructions fetched at run"
            " time can change after you reviewed this file"
        ),
        cwe="CWE-829",
        owasp_mcp_top_10=["MCP03", "MCP06"],
    ),

    # MEDIUM: Stealth techniques
    DetectionPattern(
        id="POISON-040",
        name="Zero-width Unicode characters",
        pattern=re.compile(r"[\u200b\u200c\u200d\ufeff\u2060\u00ad\u034f]"),
        severity=Severity.MEDIUM,
        description=(
            "Tool description contains invisible Unicode"
            " characters used for stealth"
        ),
        remediation=(
            "Investigate this MCP server;"
            " zero-width chars hide malicious instructions"
        ),
        cwe="CWE-116",
        owasp_mcp_top_10=["MCP03"],
    ),

    # HIGH: Unicode homoglyph substitution
    DetectionPattern(
        id="POISON-060",
        name="Unicode homoglyph substitution",
        # The character class is built at import time (``_POISON_060_CLASS``) as
        # the union of the broad confusable-script ranges — Cyrillic
        # (U+0400–04FF), Greek (U+0370–03FF), fullwidth digits and letters
        # (U+FF10–FF19, U+FF21–FF3A, U+FF41–FF5A; not fullwidth punctuation),
        # mathematical alphanumerics (U+1D400–1D7FF) — and the specific code
        # points in ``_CONFUSABLES``, which add the Armenian / Cherokee / Coptic
        # letters that fall outside those ranges.  POISON-060 runs against the
        # ORIGINAL text (it is an obfuscation detector); the companion
        # ``normalize_for_detection`` pass folds these same characters to ASCII
        # so the *literal* patterns (POISON-010..030) also fire on the decoded
        # instruction.
        pattern=re.compile(_POISON_060_CLASS),
        severity=Severity.HIGH,
        description=(
            "Tool description contains Unicode characters from Cyrillic, Greek,"
            " fullwidth-ASCII, mathematical-alphanumeric, Armenian, Cherokee, or"
            " Coptic blocks that are visually identical to ASCII letters"
            " (homoglyphs)."
            " Attackers use this technique to hide malicious instructions from"
            " human reviewers while keeping them readable to language models."
        ),
        remediation=(
            "Review the full tool description for hidden instructions."
            " Remove any non-ASCII characters that are not legitimately required."
        ),
        cwe="CWE-116",
        owasp_mcp_top_10=["MCP03"],
    ),

    # LOW: Suspicious signals
    DetectionPattern(
        id="POISON-050",
        name="Excessive description length",
        pattern=re.compile(r".{2000,}", re.DOTALL),
        severity=Severity.LOW,
        description=(
            "Tool description contains an unusually long string (≥2000 characters)."
            " Oversized tool descriptions can be used to inject hidden instructions"
            " into the AI model's context window."
            " Note: only tool name and description fields are checked —"
            " long command paths or arguments are not flagged by this rule."
        ),
        remediation="Review the full tool description for hidden instructions",
        description_only=True,
        owasp_mcp_top_10=["MCP03"],
    ),
]
# fmt: on


# ── Concealment channels (extract → decode/extract → rescan) ───────────────────
#
# POISON-041 / POISON-042 (STORY-0068).  Two covert channels smuggle content
# past a human reviewer while remaining fully present to a model reading the
# raw string:
#
#   "tag"          Unicode TAG characters (U+E0000-U+E007F, category Cf).
#                  These are NOT the zero-width/joiner characters POISON-040
#                  already covers — they render as nothing in every tested
#                  renderer AND carry an encoded message: each TAG character
#                  in the printable range U+E0020-U+E007E mirrors the ASCII
#                  character at (codepoint - 0xE0000).  ``normalize_for_
#                  detection`` correctly drops these as ``Cf`` (that behaviour
#                  is unchanged and MUST stay — see its docstring: dropping a
#                  *separator* like a zero-width space splitting "c<zwsp>url"
#                  is the intended defence). But dropping a *payload* instead
#                  of decoding it destroys the evidence rather than revealing
#                  it — that is the bug this section fixes.
#
#   "html_comment" ``<!-- ... -->`` markup.  Invisible when a Markdown
#                  surface (a SKILL.md, a CLAUDE.md) is rendered; merely
#                  unusual — not invisible — inside a JSON tool description.
#                  Ordinary editorial comments are common and legitimate on
#                  Markdown surfaces, so (unlike TAG characters) bare presence
#                  of an HTML comment is never itself worth reporting — see
#                  ``_CONCEALMENT_ONLY_KINDS`` below.
#
# Two-pass design, never decode-in-place: substituting decoded/extracted text
# back into the original string would shift offsets, and concatenating it
# with its neighbours could manufacture a match that exists in neither the
# concealed content nor its surroundings on their own. Extract each channel
# into its own string, decode/extract it, and run the EXISTING PATTERNS over
# that string as a wholly separate pass — the main normalize-and-match pass
# over the original text is untouched.
#
# One implementation site: both the config surface (``PoisoningAnalyzer``
# below) and the agent-file surface (``agent_files/analyzer.py``) call
# :func:`scan_concealed_channels` / :func:`build_concealment_finding` — a
# second copy is how the two drift.

_TAG_CHAR_RE: re.Pattern[str] = re.compile(r"[\U000E0020-\U000E007E]+")

# POISON-043 (STORY-0099): a run of zero-width characters carrying bits.
# Reverse CAPTCHA (arXiv 2603.00164 §4.1) encodes each ASCII character "as 8
# binary digits" with "zero-width space (U+200B) for 0 and zero-width
# non-joiner (U+200C) for 1"; the same scheme works with any two of the
# zero-width characters below, so a run of exactly two distinct ones is read
# as bits both ways round and the reading with more printable text is kept.
# Legitimate text uses these characters singly (a ZWNJ inside a Persian word,
# a ZWJ between two emoji), never 16 in a row.
_ZW_BIT_CHARS: str = "\u200b\u200c\u200d\u2060\ufeff"
_ZW_RUN_RE: re.Pattern[str] = re.compile(f"[{_ZW_BIT_CHARS}]{{16,}}")

# POISON-044 (STORY-0099): a run of variation selectors.  A variation
# selector only picks a glyph variant of the character before it (VS16 after
# a heart makes it an emoji), so one at a time is ordinary; a run of them
# renders as nothing and can carry one byte each: U+FE00-FE0F are bytes
# 0-15 and U+E0100-E01EF bytes 16-255 after a single base character (Paul
# Butler, "Smuggling arbitrary data through an emoji", 2025; FireTail reported
# Gemini and Grok decoding it).  Two or more in a row are read.
_VS_RUN_RE: re.Pattern[str] = re.compile(r"[\ufe00-\ufe0f\U000e0100-\U000e01ef]{2,}")

# A decoded zero-width or variation-selector run is only reported when it
# reads as text: at least this share of its characters printable.
_MIN_PRINTABLE_SHARE: float = 0.8

# The longest run decoded (characters); anything longer is decoded up to
# here, so a hostile 200 KB run costs one bounded pass.
_MAX_DECODE_RUN: int = 65_536


def _iter_html_comment_bodies(text: str) -> list[str]:
    """Yield each ``<!-- ... -->`` comment body in *text* in one linear pass.

    Deliberately NOT a ``<!--(.*?)-->`` regex with ``re.DOTALL``: on
    adversarial input with many unclosed ``<!--`` openers, a lazy-dot regex
    rescans forward to the end of the string from EVERY opener before
    concluding no match exists — O(n^2) on a string of ``n`` repeated
    ``"<!--"`` substrings with no closing ``-->`` (measured: ~8s at 80,000
    chars, scaling quadratically). ``str.find()`` in a two-pointer walk never
    revisits already-scanned text and returns immediately once no closing
    delimiter remains, giving worst-case O(n) — the same discipline as the
    ReDoS benchmarking already documented for the ``PATTERNS`` regexes in
    GAPS.md.
    """
    bodies: list[str] = []
    pos = 0
    length = len(text)
    while pos < length:
        start = text.find("<!--", pos)
        if start == -1:
            break
        end = text.find("-->", start + 4)
        if end == -1:
            break  # unterminated comment — nothing further to find
        bodies.append(text[start + 4 : end])
        pos = end + 3
    return bodies


def _printable_share(text: str) -> float:
    """Return the share of *text* that is printable (or ordinary whitespace).

    U+FFFD (what an undecodable byte becomes) does not count.
    """
    if not text:
        return 0.0
    good = sum(
        1 for ch in text if (ch.isprintable() and ch != "\ufffd") or ch in "\t\n\r"
    )
    return good / len(text)


def _bits_to_text(bits: str) -> str:
    """Read *bits* (``"0"``/``"1"``) 8 at a time, high bit first, as UTF-8."""
    usable = len(bits) - len(bits) % 8
    data = bytes(int(bits[i : i + 8], 2) for i in range(0, usable, 8))
    return data.decode("utf-8", errors="replace")


def _decode_zero_width_run(run: str) -> str | None:
    """Decode a zero-width run as an 8-bit stream, or ``None`` if it is not one.

    Exactly two distinct characters are required (one per bit value).  Both
    assignments are tried; the paper's (U+200B = 0) wins a tie.
    """
    run = run[:_MAX_DECODE_RUN]
    symbols = sorted(set(run))
    if len(symbols) != 2:
        return None
    zero, one = symbols
    readings = []
    for z, o in ((zero, one), (one, zero)):
        bits = run.replace(z, "0").replace(o, "1")
        readings.append(_bits_to_text(bits))
    best = max(readings, key=_printable_share)
    if _printable_share(best) < _MIN_PRINTABLE_SHARE:
        return None
    return best


def _decode_variation_selector_run(run: str) -> str | None:
    """Decode a variation-selector run (one byte each) as UTF-8, or ``None``."""
    run = run[:_MAX_DECODE_RUN]
    data = bytes(
        ord(ch) - 0xFE00 if ord(ch) <= 0xFE0F else ord(ch) - 0xE0100 + 16 for ch in run
    )
    text = data.decode("utf-8", errors="replace")
    if _printable_share(text) < _MIN_PRINTABLE_SHARE:
        return None
    return text


def _decode_tag_run(run: str) -> str:
    """Decode a contiguous run of Unicode TAG characters to ASCII.

    Each TAG character in the printable range U+E0020-U+E007E mirrors the
    ASCII character at ``codepoint - 0xE0000``: TAG SPACE (U+E0020) -> ``' '``
    (0x20), ... TAG TILDE (U+E007E) -> ``'~'`` (0x7E).
    """
    return "".join(chr(ord(c) - 0xE0000) for c in run)


@dataclass
class ConcealedChannel:
    """One instance of a concealment channel found in raw text.

    Attributes:
        kind: ``"tag"`` (a contiguous Unicode TAG-block run),
            ``"html_comment"``, ``"zero_width_binary"`` (POISON-043) or
            ``"variation_selector"`` (POISON-044).
        decoded: The decoded (``"tag"``) or extracted (``"html_comment"``)
            ASCII content, ready to be rescanned against ``PATTERNS``.
        char_count: Number of TAG characters in the run, or the length of
            the HTML comment body.
        codepoint_range: ``(min, max)`` TAG codepoints observed in the run.
            ``None`` for ``"html_comment"``.
    """

    kind: str
    decoded: str
    char_count: int
    codepoint_range: tuple[int, int] | None = None


def extract_concealed_channels(text: str) -> list[ConcealedChannel]:
    """Extract every concealment channel present in *text*.

    Returns one :class:`ConcealedChannel` per contiguous TAG-character run
    and per HTML comment found in *text*. Never substitutes decoded/extracted
    content back into *text* — see the module-level note above for why.

    Args:
        text: Raw (un-normalized) text to scan.

    Returns:
        A list of extracted channels, in no particular order relative to
        each other across the two kinds.
    """
    channels: list[ConcealedChannel] = []
    for m in _TAG_CHAR_RE.finditer(text):
        run = m.group(0)
        codepoints = [ord(c) for c in run]
        channels.append(
            ConcealedChannel(
                kind="tag",
                decoded=_decode_tag_run(run),
                char_count=len(run),
                codepoint_range=(min(codepoints), max(codepoints)),
            )
        )
    for body in _iter_html_comment_bodies(text):
        channels.append(
            ConcealedChannel(kind="html_comment", decoded=body, char_count=len(body))
        )
    for m in _ZW_RUN_RE.finditer(text):
        decoded = _decode_zero_width_run(m.group(0))
        if decoded is not None:
            channels.append(
                ConcealedChannel(
                    kind="zero_width_binary",
                    decoded=decoded,
                    char_count=len(m.group(0)),
                )
            )
    for m in _VS_RUN_RE.finditer(text):
        decoded = _decode_variation_selector_run(m.group(0))
        if decoded is not None:
            channels.append(
                ConcealedChannel(
                    kind="variation_selector",
                    decoded=decoded,
                    char_count=len(m.group(0)),
                )
            )
    return channels


@dataclass
class ConcealmentMatch:
    """Result of rescanning one :class:`ConcealedChannel`'s decoded content.

    ``matched_pattern`` is ``None`` for a "concealment present, nothing
    matched" result — callers only see this for channel kinds in
    :data:`_CONCEALMENT_ONLY_KINDS` (see :func:`scan_concealed_channels`).
    """

    channel: ConcealedChannel
    matched_pattern: DetectionPattern | None
    match_text: str | None


# TAG characters have essentially no legitimate use in a tool description or
# a SKILL.md (their original language-tagging purpose is deprecated), so bare
# presence is itself worth a LOW signal even when nothing decodes to a known
# payload. HTML comments are ordinary and common in Markdown (TODOs,
# editorial notes) and must stay silent unless their content actually matches
# an existing pattern — an "ordinary editorial comment" must produce no
# finding at all, not even a LOW one.
_CONCEALMENT_ONLY_KINDS: frozenset[str] = frozenset(
    {"tag", "zero_width_binary", "variation_selector"}
)

# The finding a concealment-only channel raises when its decoded content
# matches no pattern (a match is always POISON-041).
_CONCEALMENT_ONLY_FINDING: dict[str, tuple[str, Severity]] = {
    "tag": ("POISON-042", Severity.LOW),
    "zero_width_binary": ("POISON-043", Severity.MEDIUM),
    "variation_selector": ("POISON-044", Severity.MEDIUM),
}

_KIND_LABELS: dict[str, str] = {
    "tag": "Unicode TAG-character channel",
    "html_comment": "HTML comment",
    "zero_width_binary": "zero-width binary channel",
    "variation_selector": "variation-selector channel",
}


def concealment_finding_id(cmatch: ConcealmentMatch) -> str:
    """Return the finding ID :func:`build_concealment_finding` gives *cmatch*."""
    if cmatch.matched_pattern is not None:
        return "POISON-041"
    return _CONCEALMENT_ONLY_FINDING[cmatch.channel.kind][0]


def scan_concealed_channels(text: str) -> list[ConcealmentMatch]:
    """Extract every concealment channel in *text* and rescan its content.

    Each channel's decoded/extracted content is matched against the full
    non-``description_only`` ``PATTERNS`` set, independently of the normal
    normalize-and-match pass over *text* itself (which is unaffected — ``Cf``
    stripping there is unchanged; see the module-level note above).

    Args:
        text: Raw (un-normalized) text to scan.

    Returns:
        One :class:`ConcealmentMatch` per (channel, matched pattern) pair,
        plus one no-match entry per channel whose ``kind`` is in
        :data:`_CONCEALMENT_ONLY_KINDS` when nothing matched. Channels whose
        decoded content is blank (e.g. an empty HTML comment) are skipped
        entirely — there is nothing to scan or to report.
    """
    results: list[ConcealmentMatch] = []
    candidate_patterns = [p for p in PATTERNS if not p.description_only]
    for channel in extract_concealed_channels(text):
        if not channel.decoded.strip():
            continue
        norm_decoded = normalize_for_detection(channel.decoded)
        matched_any = False
        for pat in candidate_patterns:
            m = matched_pattern(pat, channel.decoded, norm_decoded)
            if m is not None:
                matched_any = True
                results.append(
                    ConcealmentMatch(
                        channel=channel, matched_pattern=pat, match_text=m.group(0)
                    )
                )
        if not matched_any and channel.kind in _CONCEALMENT_ONLY_KINDS:
            results.append(
                ConcealmentMatch(channel=channel, matched_pattern=None, match_text=None)
            )
    return results


def concealment_evidence(match: ConcealmentMatch) -> str:
    """Build the evidence string for a concealment-channel finding.

    See the "Exception" note on :func:`normalize_for_detection`'s docstring:
    this deliberately shows decoded/extracted content, not the attacker's
    original (invisible-when-rendered, or delimiter-only) bytes.
    """
    channel = match.channel
    snippet = redact_evidence(channel.decoded.strip()[:100])
    if channel.kind == "tag" and channel.codepoint_range is not None:
        lo, hi = channel.codepoint_range
        source = f"{channel.char_count} TAG character(s) (U+{lo:04X}-U+{hi:04X})"
        verb = "Decoded"
    elif channel.kind == "zero_width_binary":
        source = f"{channel.char_count} zero-width character(s) read as bits"
        verb = "Decoded"
    elif channel.kind == "variation_selector":
        source = f"{channel.char_count} variation selector(s) read as bytes"
        verb = "Decoded"
    else:
        source = f"an HTML comment ({channel.char_count} char(s))"
        verb = "Extracted"
    return f"{verb} from {source}: {snippet!r}"


def concealment_visibility_note(kind: str, *, markdown_surface: bool) -> str:
    """One-sentence clause describing how invisible *kind* is on this surface.

    TAG characters render as nothing on every surface. HTML comments are
    invisible only when a Markdown surface renders them — inside a JSON tool
    description they are merely unusual, not invisible, and the finding text
    must not claim more than that.

    Args:
        kind: ``"tag"`` or ``"html_comment"``.
        markdown_surface: ``True`` for a skill/memory file rendered as
            Markdown; ``False`` for a JSON config field.
    """
    if kind == "tag":
        return (
            "Unicode TAG characters render as nothing in any surface — a"
            " terminal, an editor, or a rendered document — while remaining"
            " ordinary text to a language model reading the raw string."
        )
    if kind == "zero_width_binary":
        return (
            "Zero-width characters render as nothing; read eight at a time as"
            " bits they spell text, a scheme some models decode (Reverse"
            " CAPTCHA, arXiv 2603.00164)."
        )
    if kind == "variation_selector":
        return (
            "Variation selectors render as nothing (one only picks a glyph"
            " variant of the character before it); read one byte each, a run"
            " of them spells text a model can be asked to decode."
        )
    if markdown_surface:
        return (
            "An HTML comment is invisible when this file is rendered as"
            " Markdown, while remaining ordinary text to a language model"
            " reading the raw file."
        )
    return (
        "An HTML comment is not rendered anywhere in a JSON tool"
        " description, so its presence here is unusual rather than"
        " invisible — but it remains ordinary text to a language model"
        " reading the raw field."
    )


def build_concealment_finding(
    cmatch: ConcealmentMatch,
    *,
    client: str,
    server: str,
    surface_noun: str,
    markdown_surface: bool,
    finding_path: str | None = None,
) -> Finding:
    """Build the POISON-041 (matched) or POISON-042/043/044 (concealment-only) Finding.

    Shared by the config surface (:class:`PoisoningAnalyzer`) and the
    agent-file surface (``agent_files/analyzer.py``) so the two Finding-text
    implementations never drift — see the module-level note above. The
    resulting Finding always carries ``analyzer="poisoning"``, regardless of
    which surface calls this, mirroring how ``discovery.py``'s shared
    symlink-finding builders always carry ``analyzer="discovery"`` regardless
    of whether ``discovery.py`` or ``agent_files/discovery.py`` calls them.

    Args:
        cmatch: The match to build a Finding for.
        client: ``Finding.client`` — the MCP client name (config surface) or
            the agent file's client (agent-file surface).
        server: ``Finding.server`` — the server name (config surface) or the
            agent file's display name (agent-file surface).
        surface_noun: Human-readable noun phrase for the description text,
            e.g. ``"this server's configuration"`` or
            ``"the skill file 'foo.md'"``.
        markdown_surface: Passed through to :func:`concealment_visibility_note`.
        finding_path: Optional ``Finding.finding_path`` (agent-file surface
            only; config-surface callers pass ``None``, matching every other
            finding ``PoisoningAnalyzer`` emits).

    Returns:
        A POISON-041 (HIGH) finding when the decoded content matched a
        pattern; otherwise POISON-042 (LOW, TAG characters), POISON-043
        (MEDIUM, zero-width binary) or POISON-044 (MEDIUM, variation
        selectors).
    """
    channel = cmatch.channel
    kind_label = _KIND_LABELS.get(channel.kind, channel.kind)
    note = concealment_visibility_note(channel.kind, markdown_surface=markdown_surface)
    evidence = concealment_evidence(cmatch)

    if cmatch.matched_pattern is not None:
        pat = cmatch.matched_pattern
        return Finding(
            id="POISON-041",
            severity=Severity.HIGH,
            analyzer="poisoning",
            client=client,
            server=server,
            title=f"Concealed instruction via {kind_label.lower()}",
            description=(
                f"A {kind_label} in {surface_noun} decodes to content matching"
                f" the '{pat.name}' detection pattern: {pat.description}. {note}"
            ),
            evidence=evidence,
            remediation=(
                "Remove this content; it conceals an instruction from human"
                " review while keeping it readable to the model."
            ),
            finding_path=finding_path,
            cwe="CWE-116",
            owasp_mcp_top_10=["MCP03", "MCP01"],
        )

    finding_id, severity = _CONCEALMENT_ONLY_FINDING[channel.kind]
    return Finding(
        id=finding_id,
        severity=severity,
        analyzer="poisoning",
        client=client,
        server=server,
        title=f"Concealment channel present ({kind_label})",
        description=(
            f"{surface_noun[0].upper()}{surface_noun[1:]} contains a"
            f" {kind_label} whose decoded content did not match any known"
            f" poisoning pattern. {note}"
        ),
        evidence=evidence,
        remediation=(
            "Investigate this content; concealment channels have essentially"
            " no legitimate use here."
        ),
        finding_path=finding_path,
        cwe="CWE-116",
        owasp_mcp_top_10=["MCP03"],
    )


class PoisoningAnalyzer(BaseAnalyzer):
    """Detect tool description poisoning in MCP server configurations."""

    @property
    def name(self) -> str:
        return "poisoning"

    @property
    def description(self) -> str:
        return "Detect malicious instructions in tool descriptions"

    def analyze(self, server: ServerConfig) -> list[Finding]:
        """Analyze a server's tool descriptions for poisoning patterns.

        For static config analysis, this checks the raw config data for
        tool-like structures. Full tool enumeration via MCP protocol
        connection will be added in a future version.

        Patterns marked ``description_only=True`` (currently POISON-050) are
        applied only to ``name`` and ``description`` keys in the config — the
        fields an AI model reads when deciding whether to invoke a tool.
        Fields such as ``command``, ``args``, and env values are not
        model-visible and are excluded from those checks.
        """
        findings: list[Finding] = []

        general_patterns = [p for p in PATTERNS if not p.description_only]
        description_only_patterns = [p for p in PATTERNS if p.description_only]

        # All string values — used for patterns that cover every field.
        all_texts = self._extract_text_fields(server.raw)
        for text in all_texts:
            # Normalize once per text; literal patterns match the normalized
            # form (homoglyph/compat-folded), obfuscation patterns match raw.
            norm_text = normalize_for_detection(text)
            for pattern in general_patterns:
                match = matched_pattern(pattern, text, norm_text)
                if match:
                    findings.append(
                        Finding(
                            id=pattern.id,
                            severity=pattern.severity,
                            analyzer=self.name,
                            client=server.client,
                            server=server.name,
                            title=pattern.name,
                            description=pattern.description,
                            evidence=_evidence_snippet(pattern, text),
                            remediation=pattern.remediation,
                            cwe=pattern.cwe,
                            owasp_mcp_top_10=pattern.owasp_mcp_top_10,
                        )
                    )

            # POISON-041/042: concealment channels (Unicode TAG runs, HTML
            # comments) whose decoded/extracted content is rescanned against
            # `general_patterns` as an independent pass — see the
            # "Concealment channels" section above `PoisoningAnalyzer`.
            for cmatch in scan_concealed_channels(text):
                findings.append(
                    build_concealment_finding(
                        cmatch,
                        client=server.client,
                        server=server.name,
                        surface_noun="this server's configuration",
                        markdown_surface=False,
                    )
                )

        # Only description/name values — used for patterns whose threat model
        # is specifically about oversized or manipulated tool descriptions.
        if description_only_patterns:
            description_texts = self._extract_description_fields(server.raw)
            for text in description_texts:
                for pattern in description_only_patterns:
                    match = pattern.pattern.search(text)
                    if match:
                        findings.append(
                            Finding(
                                id=pattern.id,
                                severity=pattern.severity,
                                analyzer=self.name,
                                client=server.client,
                                server=server.name,
                                title=pattern.name,
                                description=pattern.description,
                                evidence=f"Matched: {match.group()[:100]}",
                                remediation=pattern.remediation,
                                cwe=pattern.cwe,
                                owasp_mcp_top_10=pattern.owasp_mcp_top_10,
                            )
                        )

        return findings

    def _extract_text_fields(
        self,
        data: dict | list | str,
        depth: int = 0,
    ) -> list[str]:
        """Recursively extract all string values from a nested structure."""
        if depth > 50:
            return []

        texts: list[str] = []
        if isinstance(data, str):
            texts.append(data)
        elif isinstance(data, dict):
            for value in data.values():
                texts.extend(self._extract_text_fields(value, depth + 1))
        elif isinstance(data, list):
            for item in data:
                texts.extend(self._extract_text_fields(item, depth + 1))
        return texts

    def _extract_description_fields(
        self,
        data: dict | list | str,
        depth: int = 0,
    ) -> list[str]:
        """Extract only ``name`` and ``description`` values from a nested structure.

        These are the fields an AI model reads when deciding whether to call a
        tool.  Command paths, argument lists, and environment variable values
        are intentionally excluded because they are not model-visible and do
        not constitute an attack surface for tool description padding.
        """
        if depth > 50:
            return []

        texts: list[str] = []
        if isinstance(data, dict):
            for key, value in data.items():
                if key in ("description", "name"):
                    if isinstance(value, str):
                        texts.append(value)
                    # Non-string description/name values are not collected.
                else:
                    texts.extend(self._extract_description_fields(value, depth + 1))
        elif isinstance(data, list):
            for item in data:
                texts.extend(self._extract_description_fields(item, depth + 1))
        return texts
