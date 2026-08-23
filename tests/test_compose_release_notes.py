"""Compose GitHub Release notes from the evergreen template + CHANGELOG."""

from __future__ import annotations

from pathlib import Path

import pytest
from scripts.compose_release_notes import (
    CHANGELOG_TOKEN,
    VERSION_TOKEN,
    ComposeError,
    compose,
    extract_changelog_section,
    leftover_tokens,
    main,
)

ROOT = Path(__file__).resolve().parent.parent
TEMPLATE = ROOT / ".github" / "release-notes-template.md"
CHANGELOG = ROOT / "CHANGELOG.md"
RELEASE_YML = ROOT / ".github" / "workflows" / "release.yml"


def test_extract_0150_has_security_not_unreleased() -> None:
    text = CHANGELOG.read_text(encoding="utf-8")
    section = extract_changelog_section(text, "v0.15.0")
    assert "### Security" in section
    assert "absolute config path" in section
    assert "mcp-audit advise" in section
    assert "Weekly read-only registry drift" not in section
    assert "## [0.15.0]" not in section
    assert "## [0.14.0]" not in section


def test_extract_0140_does_not_inherit_0150() -> None:
    text = CHANGELOG.read_text(encoding="utf-8")
    section = extract_changelog_section(text, "v0.14.0")
    assert "agent_files" in section
    assert "absolute config path" not in section
    assert "mcp-audit advise <target>" not in section


def test_missing_section_fails_loudly() -> None:
    with pytest.raises(ComposeError, match="no '## \\[9.9.9\\]' section"):
        extract_changelog_section("# Changelog\n\n## [0.1.0]\n\n- x\n", "v9.9.9")


def test_refuses_unreleased() -> None:
    with pytest.raises(ComposeError, match="Unreleased"):
        extract_changelog_section("## [Unreleased]\n\n- x\n", "Unreleased")


def test_empty_section_fails() -> None:
    with pytest.raises(ComposeError, match="empty"):
        extract_changelog_section("## [1.0.0]\n\n---\n\n## [0.9.0]\n\n- x\n", "v1.0.0")


def test_compose_substitutes_and_leaves_no_tokens() -> None:
    notes = compose(
        TEMPLATE.read_text(encoding="utf-8"),
        CHANGELOG.read_text(encoding="utf-8"),
        "v0.15.0",
    )
    assert leftover_tokens(notes) == []
    assert "{{VERSION}}" not in notes
    assert "{{CHANGELOG_SECTION}}" not in notes
    assert notes.startswith("<!--")
    assert "## mcp-audit v0.15.0" in notes
    assert "adudley78/mcp-audit@v0.15.0" in notes
    assert "### Security" in notes
    assert "### Install" in notes
    # Next tag must not be able to inherit this from the template.
    assert "What's new" not in TEMPLATE.read_text(encoding="utf-8")


def test_leftover_unknown_token_fails() -> None:
    template = f"## mcp-audit {VERSION_TOKEN}\n\n{CHANGELOG_TOKEN}\n\n{{{{EXTRA}}}}\n"
    changelog = "## [0.1.0]\n\n### Added\n\n- hello\n"
    with pytest.raises(ComposeError, match="EXTRA"):
        compose(template, changelog, "v0.1.0")


def test_template_is_evergreen() -> None:
    text = TEMPLATE.read_text(encoding="utf-8")
    body = text.split("-->", 1)[1]
    assert VERSION_TOKEN in text
    assert CHANGELOG_TOKEN in text
    for rotting in (
        "What's new",
        "What's fixed",
        "What changed",
        "### Highlights",
        "read this first",
        "Signed Advisory Feed (Experimental), Registry Cleanup",
    ):
        assert rotting not in body, rotting


def test_release_workflow_uses_the_composer() -> None:
    text = RELEASE_YML.read_text(encoding="utf-8")
    assert "scripts/compose_release_notes.py" in text
    assert 'sed "s|{{VERSION}}|' not in text


def test_main_writes_output(tmp_path: Path) -> None:
    out = tmp_path / "notes.md"
    assert (
        main(
            [
                "--tag",
                "v0.15.0",
                "--template",
                str(TEMPLATE),
                "--changelog",
                str(CHANGELOG),
                "--output",
                str(out),
            ]
        )
        == 0
    )
    body = out.read_text(encoding="utf-8")
    assert "## mcp-audit v0.15.0" in body
    assert leftover_tokens(body) == []
