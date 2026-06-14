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
        return f"Matched: {raw_match.group()[:100]}"
    return f"Matched after Unicode normalization in: {raw_text.strip()[:100]!r}"


# POISON-060 fires on the presence of a confusable character in the ORIGINAL
# text (a strong obfuscation signal in its own right, separate from whether a
# literal pattern matched the normalized form).  The class is the union of the
# broad confusable-script ranges and the specific code points in
# :data:`_CONFUSABLES` (which adds Armenian / Cherokee / Coptic letters that
# fall outside those ranges).
_POISON_060_EXTRA: str = "".join(
    sorted({c for c in _CONFUSABLES if not ("\u0370" <= c <= "\u04ff")})
)
_POISON_060_CLASS: str = (
    "[\u0370-\u03ff\u0400-\u04ff\uff01-\uff5e\U0001d400-\U0001d7ff"
    + _POISON_060_EXTRA
    + "]"
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
        pattern=re.compile(
            # "ignore/disregard/forget <1-4 adjectives> instructions".  The
            # adjective repetition closes the canonical-phrase false negative:
            # a bare ``ignore\s+(previous|prior|all)\s+instructions`` matched
            # "ignore previous instructions" but MISSED the most common live
            # phrasing "ignore all previous instructions" (two adjectives) —
            # the regex demanded the literal word "instructions" immediately
            # after a single adjective.
            r"((?:ignore|disregard|forget)\s+"
            r"(?:(?:all|any|every|the|previous|prior|preceding|earlier|above)\s+)"
            r"{1,4}instructions|"
            r"do\s+not\s+(mention|tell|reveal|say|inform)|"
            r"override\s+(previous|prior|default)|"
            r"disregard\s+(previous|prior|all|any))",
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
        # (U+0400–04FF), Greek (U+0370–03FF), fullwidth ASCII (U+FF01–FF5E),
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
