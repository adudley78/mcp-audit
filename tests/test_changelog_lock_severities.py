"""Assert the CHANGELOG's LOCK-* severities match the code that assigns them.

R50 (2026-09-10): the ``[0.17.0]`` CHANGELOG section — spliced verbatim onto the
public GitHub Release page by ``scripts/compose_release_notes.py`` — described
LOCK-005 as an INFO note about an unresolved offline entry. The shipped
verifier's LOCK-005 is actually the CRITICAL tamper/hand-edit check that
short-circuits every other check with exit code 2. The CHANGELOG's other four
LOCK severities also disagreed with the code (LOCK-002/LOCK-004 were described
as lower than HIGH; LOCK-003 as LOW instead of MEDIUM; LOCK-004's CRITICAL
same-version-different-hash case was omitted entirely).
``scripts/validate_owasp_mapping.py`` did not, and could not, catch this: it
asserts that an id is *mapped*, never that *prose describing* the id is
accurate. Nothing else in this repo compares a CHANGELOG finding description
against the code.

FACTS-only, in the R26 sense: this test extracts only ``{id: {severities}}``
from both sources and compares those sets. It deliberately does NOT diff
wording, a finding's title, its trigger condition, or which mode
(offline/``--resolve``) it fires under — a reworded sentence must not fail
this test, only a severity word that disagrees with the code.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHANGELOG_PATH = ROOT / "CHANGELOG.md"
VERIFIER_PATH = ROOT / "src" / "mcp_audit" / "lock" / "verifier.py"

_SEVERITY_WORDS = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


def _code_severities(verifier_text: str) -> dict[str, set[str]]:
    """Extract ``{full_lock_id: {severity, ...}}`` from ``verifier.py``'s source.

    Every ``Finding(id="LOCK-NNN", severity=Severity.XXX, ...)`` construction in
    this module places ``id=`` immediately before ``severity=`` on the next
    line. This regex mirrors that literal layout rather than importing and
    exercising the module, so a silent layout change fails this test instead
    of passing on a coincidence.
    """
    pairs = re.findall(r'id="(LOCK-\d{3})",\s*severity=Severity\.(\w+),', verifier_text)
    assert pairs, (
        f'Found no `id="LOCK-NNN", severity=Severity.X` constructions in '
        f"{VERIFIER_PATH} — the source layout changed; update this regex."
    )
    result: dict[str, set[str]] = {}
    for lock_id, severity in pairs:
        result.setdefault(lock_id, set()).add(severity)
    return result


def _current_release_section(changelog_text: str) -> str:
    """Return the body of the CHANGELOG's most recent dated ``## [X.Y.Z]`` section."""
    pieces = re.split(r"\n## \[", changelog_text)
    dated = [f"[{piece}" for piece in pieces[1:]]
    dated = [section for section in dated if not section.startswith("[Unreleased]")]
    assert dated, (
        f"No dated (non-Unreleased) `## [X.Y.Z]` section found in {CHANGELOG_PATH}"
    )
    return dated[0]


def _changelog_severities(section: str) -> dict[str, set[str]]:
    """Extract ``{full_lock_id: {severity, ...}}`` named anywhere in *section*.

    For each ``**LOCK-NNN**`` mention, collects every all-caps severity word
    found before the next ``**LOCK-`` mention (or end of section) —
    tolerates a single id naming two severities in one sentence, which
    LOCK-004 does (HIGH for a version change, CRITICAL for a same-version
    hash change).

    Returns an empty dict when the section names no ``LOCK-NNN`` id at all —
    not every release touches `lock`/`verifier.py` (e.g. v0.18.1's SC-005-only
    section, STORY-0073/R58); this test's job is to catch a *named* LOCK id
    whose described severity disagrees with the code, not to require every
    release to discuss LOCK-* in the first place.
    """
    markers = list(re.finditer(r"\*\*(LOCK-\d{3})\*\*", section))
    result: dict[str, set[str]] = {}
    for index, marker in enumerate(markers):
        start = marker.end()
        end = markers[index + 1].start() if index + 1 < len(markers) else len(section)
        chunk = section[start:end]
        found = {word for word in _SEVERITY_WORDS if re.search(rf"\b{word}\b", chunk)}
        result.setdefault(marker.group(1), set()).update(found)
    return result


def test_changelog_severities_empty_when_section_names_no_lock_id() -> None:
    """A release section that never mentions LOCK-NNN (e.g. an SC-005-only
    release) yields an empty dict, not an assertion failure."""
    section = "### Added\n\n- Some unrelated change naming SC-005, not LOCK-*.\n"
    assert _changelog_severities(section) == {}


def test_changelog_lock_severities_match_verifier_code() -> None:
    """Every LOCK-* id named in the CHANGELOG's newest section carries the
    severity (or severities) the shipped code actually assigns it — not a
    stale description of what someone thought it meant."""
    code = _code_severities(VERIFIER_PATH.read_text(encoding="utf-8"))
    section = _current_release_section(CHANGELOG_PATH.read_text(encoding="utf-8"))
    changelog = _changelog_severities(section)

    for full_id, changelog_sevs in changelog.items():
        assert full_id in code, (
            f"{full_id} is named in the CHANGELOG's current release section but "
            f"is never constructed in {VERIFIER_PATH}. Check the id spelling in "
            "either place."
        )
        assert changelog_sevs, (
            f"{full_id} is named in the CHANGELOG's current release section but "
            "no severity word (CRITICAL/HIGH/MEDIUM/LOW/INFO) was found near it."
        )
        assert changelog_sevs == code[full_id], (
            f"{full_id}'s severity in the CHANGELOG's current release section "
            f"{sorted(changelog_sevs)} does not match what {VERIFIER_PATH} "
            f"actually assigns it {sorted(code[full_id])}.\n"
            "This test only checks the severity word(s), never wording — fix "
            "whichever side is now wrong."
        )
