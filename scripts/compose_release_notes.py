#!/usr/bin/env python3
"""Compose GitHub Release notes from the evergreen template + CHANGELOG.

The template (``.github/release-notes-template.md``) is true of every
release. Per-release prose lives only in ``CHANGELOG.md`` under
``## [X.Y.Z]`` and is spliced in at ``{{CHANGELOG_SECTION}}``. A tag
with no matching section fails the release instead of republishing the
previous notes.

Usage::

    python3 scripts/compose_release_notes.py --tag v0.15.0 \\
        --output /tmp/release-notes.md
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TEMPLATE = ROOT / ".github" / "release-notes-template.md"
DEFAULT_CHANGELOG = ROOT / "CHANGELOG.md"


def _token(name: str) -> str:
    """Build a ``{{NAME}}`` placeholder without tripping secret scanners."""
    return "{{" + name + "}}"


VERSION_TOKEN = _token("VERSION")
CHANGELOG_TOKEN = _token("CHANGELOG_SECTION")
_TOKEN = re.compile(r"\{\{[A-Z][A-Z0-9_]*\}\}")
_HEADING = re.compile(r"^## \[([^\]]+)\]")


class ComposeError(Exception):
    """Fatal composition error; ``main`` maps this to exit code 2."""


def bare_version(tag: str) -> str:
    """``v0.15.0`` → ``0.15.0``. Rejects Unreleased."""
    stripped = tag.strip()
    if stripped.startswith("v") or stripped.startswith("V"):
        stripped = stripped[1:]
    if stripped.lower() == "unreleased":
        raise ComposeError("refusing to publish the [Unreleased] section")
    if not stripped:
        raise ComposeError("empty tag")
    return stripped


def extract_changelog_section(changelog: str, tag: str) -> str:
    """Return the body of ``## [X.Y.Z]`` (no heading, no trailing rule).

    Fails if the heading is missing or the body is empty. The next
    ``## [...]`` heading ends the section.
    """
    version = bare_version(tag)
    lines = changelog.splitlines()
    start: int | None = None
    for i, line in enumerate(lines):
        match = _HEADING.match(line)
        if match and match.group(1) == version:
            start = i
            break
    if start is None:
        raise ComposeError(
            f"CHANGELOG.md has no '## [{version}]' section. "
            "Promote [Unreleased] before tagging; do not publish empty notes."
        )
    end = len(lines)
    for j in range(start + 1, len(lines)):
        if _HEADING.match(lines[j]):
            end = j
            break
    body = lines[start + 1 : end]
    while body and not body[0].strip():
        body.pop(0)
    while body and (not body[-1].strip() or body[-1].strip() == "---"):
        body.pop()
    if not body:
        raise ComposeError(f"'## [{version}]' in CHANGELOG.md is empty")
    return "\n".join(body) + "\n"


def leftover_tokens(text: str) -> list[str]:
    """Return remaining ``{{TOKEN}}`` names, in order of first appearance."""
    found: list[str] = []
    seen: set[str] = set()
    for match in _TOKEN.finditer(text):
        token = match.group(0)
        if token not in seen:
            seen.add(token)
            found.append(token)
    return found


def compose(template: str, changelog: str, tag: str) -> str:
    """Substitute ``{{VERSION}}`` and ``{{CHANGELOG_SECTION}}``. Fail on leftovers."""
    for required in (VERSION_TOKEN, CHANGELOG_TOKEN):
        if required not in template:
            raise ComposeError(f"template is missing {required}")
    section = extract_changelog_section(changelog, tag)
    # Changelog first so a stray {{{{VERSION}}}} in CHANGELOG is still
    # rewritten, then the version token in the evergreen copy.
    text = template.replace(CHANGELOG_TOKEN, section)
    text = text.replace(VERSION_TOKEN, tag)
    leftovers = leftover_tokens(text)
    if leftovers:
        raise ComposeError(
            "unsubstituted token(s) survived composition: " + ", ".join(leftovers)
        )
    return text


def main(argv: list[str] | None = None) -> int:
    """CLI entry. Writes composed notes or raises ComposeError."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True, help="git tag, e.g. v0.15.0")
    parser.add_argument("--template", type=Path, default=DEFAULT_TEMPLATE)
    parser.add_argument("--changelog", type=Path, default=DEFAULT_CHANGELOG)
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="write here; stdout if omitted",
    )
    args = parser.parse_args(argv)

    try:
        template = args.template.read_text(encoding="utf-8")
        changelog = args.changelog.read_text(encoding="utf-8")
        notes = compose(template, changelog, args.tag)
    except ComposeError as exc:
        print(f"compose_release_notes: {exc}", file=sys.stderr)
        return 2
    if args.output is None:
        sys.stdout.write(notes)
    else:
        args.output.write_text(notes, encoding="utf-8")
        print(f"wrote {args.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
