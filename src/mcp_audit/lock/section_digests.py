"""Per-section digests for ``mcp-lock.json`` (``lock_version`` 2, STORY-0116).

ADR-0005's R59 addendum (a), agreed with the ``trees`` producer on #88:
canonical serialisation makes byte preservation *possible*; a per-section
digest makes a violation of it *detectable by the other tool*. A version-2
lock carries one top-level map::

    "section_digests": {"servers": "sha256:<hex>", "tools": "sha256:<hex>",
                        "trees": "sha256:<hex>"}

Each value is the SHA-256 of the RFC 8785 canonical bytes of that top-level
section's value. Each producer writes only the entries for the sections it
produced and copies every other entry through verbatim, so any tool can
recompute any entry and a mismatch means a section changed without its
producer updating its digest. mcp-audit writes ``servers`` always and
``tools`` when it owns that section; it never writes or recomputes ``trees``.

The map is outside mcp-audit's own ``checksum`` (which keeps covering
``{lock_version, generated_by, servers}``): another producer must be able to
add its own entry without tripping LOCK-005.

A digest over the canonical bytes of a *parsed* value cannot see a byte-level
reformat, so :func:`noncanonical_sections` also compares the file's bytes
with their canonical form (LOCK-012).
"""

from __future__ import annotations

from dataclasses import dataclass

from mcp_audit.advisory.canonical import CanonicalError, canonicalize
from mcp_audit.lock import tool_digests
from mcp_audit.lock.model import SECTION_DIGESTS_KEY, STRUCTURAL_KEYS

#: Top-level keys that are the envelope, not sections: never digested.
ENVELOPE_KEYS: frozenset[str] = STRUCTURAL_KEYS | {SECTION_DIGESTS_KEY}

_PREFIX = "sha256:"
_HEX = frozenset("0123456789abcdef")


def is_digest_string(value: object) -> bool:
    """Whether *value* is ``"sha256:"`` followed by 64 lowercase hex digits.

    Checked character by character (no regex), so any input is linear.
    """
    if not isinstance(value, str) or len(value) != len(_PREFIX) + 64:
        return False
    return value.startswith(_PREFIX) and all(c in _HEX for c in value[len(_PREFIX) :])


def section_digest(value: object) -> str:
    """Return ``"sha256:<hex>"`` of *value*'s RFC 8785 canonical bytes.

    Raises:
        CanonicalError: *value* is too large or too deep to canonicalize.
    """
    return tool_digests.digest(value)


def owned_sections(doc: dict) -> list[str]:
    """Return the sections whose digest mcp-audit writes for *doc*.

    ``servers`` always; ``tools`` only when it is mcp-audit's own populated
    section (``None`` holds nothing to digest, and another producer's
    ``tools`` is that producer's to digest).
    """
    names = ["servers"]
    if tool_digests.is_owned(doc.get(tool_digests.TOOLS_KEY)):
        names.append(tool_digests.TOOLS_KEY)
    return names


def merge(existing: object, doc: dict) -> dict[str, str]:
    """Return the ``section_digests`` map to write into *doc*.

    Entries for sections mcp-audit decides (``servers``, and ``tools`` when
    it is ``None`` or mcp-audit's own) are recomputed or dropped; every other
    entry from *existing* is copied verbatim, including a stale or malformed
    one: it belongs to another producer, and leaving it intact is what lets
    that producer detect a change. Entries naming an envelope key are
    dropped; they digest nothing a producer owns.

    Args:
        existing: The previous ``section_digests`` value, or ``None``.
        doc: The new document, with ``servers`` and ``tools`` already final.

    Raises:
        ValueError: *existing* is present but not an object.
        CanonicalError: An owned section is too large to canonicalize.
    """
    if existing is not None and not isinstance(existing, dict):
        raise ValueError(f"`{SECTION_DIGESTS_KEY}` is not an object")
    tools = doc.get(tool_digests.TOOLS_KEY)
    decided = {"servers"}
    if tools is None or tool_digests.is_owned(tools):
        decided.add(tool_digests.TOOLS_KEY)

    merged: dict[str, str] = {}
    for key, value in (existing or {}).items():
        if key in decided or key in ENVELOPE_KEYS:
            continue
        merged[key] = value
    for key in owned_sections(doc):
        merged[key] = section_digest(doc[key])
    return {key: merged[key] for key in sorted(merged)}


@dataclass
class DigestProblem:
    """One ``section_digests`` entry that does not hold (LOCK-011)."""

    section: str
    reason: str
    recorded: str | None = None
    computed: str | None = None


@dataclass
class DigestCheck:
    """Outcome of :func:`check`."""

    problems: list[DigestProblem]
    #: Sections whose digest could not be computed (canonicalization bound).
    too_large: list[str]
    #: Sections whose recorded digest matched.
    matched: list[str]


def check(doc: dict) -> DigestCheck:
    """Check every ``section_digests`` entry of a version-2 *doc*.

    A problem is: the map is missing or not an object; an entry mcp-audit
    always writes is missing (``servers``, and ``tools`` when mcp-audit owns
    it); an entry names an envelope key or a section the document does not
    have; a value is not ``sha256:`` + 64 hex; or a recorded digest does not
    match the section. A section that exceeds the canonicalization bound is
    reported in :attr:`DigestCheck.too_large` instead (not checked, not
    passed).
    """
    problems: list[DigestProblem] = []
    too_large: list[str] = []
    matched: list[str] = []
    digests = doc.get(SECTION_DIGESTS_KEY)
    if not isinstance(digests, dict):
        reason = "missing" if digests is None else "not an object"
        problems.append(
            DigestProblem(SECTION_DIGESTS_KEY, f"`{SECTION_DIGESTS_KEY}` is {reason}")
        )
        return DigestCheck(problems, too_large, matched)

    for name in owned_sections(doc):
        if name not in digests:
            problems.append(
                DigestProblem(name, "no digest recorded for a section mcp-audit wrote")
            )

    for name in sorted(digests):
        value = digests[name]
        shown = value if isinstance(value, str) else None
        if name in ENVELOPE_KEYS:
            problems.append(
                DigestProblem(name, "names part of the envelope, not a section", shown)
            )
            continue
        if not is_digest_string(value):
            problems.append(
                DigestProblem(name, "recorded value is not sha256: + 64 hex digits")
            )
            continue
        if name not in doc:
            problems.append(
                DigestProblem(
                    name, "a digest is recorded for a section that is gone", shown
                )
            )
            continue
        try:
            computed = section_digest(doc[name])
        except CanonicalError:
            too_large.append(name)
            continue
        if computed != value:
            problems.append(
                DigestProblem(
                    name,
                    "section content does not match the digest recorded for it",
                    shown,
                    computed,
                )
            )
        else:
            matched.append(name)
    return DigestCheck(problems, too_large, matched)


def noncanonical_sections(raw: bytes, doc: dict) -> list[str] | None:
    """Return which top-level members of *raw* are not in canonical form.

    ADR-0005 §2 makes the on-disk format the RFC 8785 encoding of the whole
    document. Returns ``[]`` when *raw* is exactly that; otherwise the keys
    whose canonical member text (``"key":<value>``) does not appear in
    *raw*, or ``["<layout>"]`` when every member does but the bytes between
    them differ (whitespace, order, a trailing newline). ``None`` when the
    document is too large to canonicalize (not checked).
    """
    try:
        if raw == canonicalize(doc):
            return []
        names = []
        for key in sorted(doc):
            member = canonicalize({key: doc[key]})[1:-1]
            if member not in raw:
                names.append(key)
    except CanonicalError:
        return None
    return names or ["<layout>"]
