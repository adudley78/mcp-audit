"""ClawHavoc (Koi Security, 2026) shapes against SKILL-005..008 (STORY-0133).

The fixtures under ``tests/fixtures/clawhavoc/`` are synthetic: they
reproduce the shapes the published reports describe, with RFC 5737 addresses
and defanged hosts.  Nothing is copied from a sample, and nothing here is run.
"""

from __future__ import annotations

import re
import shutil
from pathlib import Path

import pytest

from mcp_audit.agent_files import skill_package as sp
from mcp_audit.agent_files.install_steps import install_step_hits

FIXTURES = Path(__file__).parent / "fixtures" / "clawhavoc"

#: fixture -> SKILL ids expected (measured, see docs/agent-files.md).
MEASURED: dict[str, set[str]] = {
    "mac-b64-pipe-bash": {"SKILL-005"},
    "mac-second-stage-fetch": {"SKILL-005"},
    "mac-paste-site-prose": {"SKILL-005"},
    "win-protected-zip-prose": {"SKILL-005"},
    "win-protected-zip-cmd": {"SKILL-005"},
    "reverse-shell-in-code": {"SKILL-005", "SKILL-008"},
    # Known gap (GAPS.md): reading .env and posting it is not a narrow shape.
    "env-exfil-webhook": set(),
}


def _refang(text: str) -> str:
    return text.replace("hxxp", "http").replace("[.]", ".")


def _scan(tmp_path: Path, name: str) -> list:
    """Copy a fixture (refanged) under a skills dir and analyse it."""
    skills = tmp_path / "skills"
    dest = skills / name
    shutil.copytree(FIXTURES / name, dest)
    for f in dest.rglob("*"):
        if f.is_file():
            f.write_text(_refang(f.read_text()), encoding="utf-8")
    return sp.analyze_skill_packages([sp.SkillPackage(dest, "user", skills, False)])


@pytest.mark.parametrize("name", sorted(MEASURED))
def test_each_published_shape(tmp_path: Path, name: str) -> None:
    ids = {f.id for f in _scan(tmp_path, name)}
    assert ids == MEASURED[name]


def test_findings_credit_koi_and_are_high() -> None:
    text = _refang((FIXTURES / "mac-b64-pipe-bash" / "SKILL.md").read_text())
    hits = install_step_hits("SKILL.md", text)
    assert hits and hits[0].severity.value == "HIGH"
    skills = FIXTURES.parent  # any dir; finding text does not depend on it
    pkg = sp.SkillPackage(FIXTURES / "mac-b64-pipe-bash", "user", skills, False)
    desc = sp.analyze_skill_packages([pkg])[0].description
    assert "Koi Security" in desc and "ClawHavoc" in desc


@pytest.mark.parametrize(
    "text",
    [
        "Paste the output into Terminal.\n\n\n\nSee https://rentry.co/ for notes.\n",
        "Our archive is password protected; ask support for the key.\n",
        "Run the tests. Do not use pastebin.com for secrets.\n",
        "Use glot.io to share snippets; nothing to install.\n",
    ],
)
def test_ordinary_prose_is_not_flagged(text: str) -> None:
    reasons = [r for h in install_step_hits("SKILL.md", text) for r in h.reasons]
    assert not any("ClawHavoc" in r for r in reasons)


def test_benign_skill_fixtures_stay_clean() -> None:
    root = Path(__file__).parent / "fixtures" / "agent_files"
    for f in root.rglob("*.md"):
        reasons = [
            r for h in install_step_hits(f.name, f.read_text()) for r in h.reasons
        ]
        assert not any("ClawHavoc" in r for r in reasons), f


_LIVE = [
    re.compile(r"https?://(?!203\.0\.113\.)\d{1,3}(?:\.\d{1,3}){3}"),
    re.compile(r"(?<![\d.])(?!203\.0\.113\.)(?:\d{1,3}\.){3}\d{1,3}(?![\d.])"),
    re.compile(r"(?i)\b(?:https?://)(?:glot\.io|rentry\.co|pastebin\.com)"),
    re.compile(r"\b[0-9a-f]{32,64}\b"),
]


def test_fixtures_hold_no_live_indicator() -> None:
    for f in FIXTURES.rglob("*"):
        if not f.is_file():
            continue
        text = f.read_text()
        for rx in _LIVE:
            assert not rx.search(text), (f, rx.pattern)
