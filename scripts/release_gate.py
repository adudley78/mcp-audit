#!/usr/bin/env python3
"""Decide when a version bump becomes a release, and when a run may publish.

Two decisions, one module, so both read the version the same way:

``tag``
    Run by ``.github/workflows/release-on-version-bump.yml`` for one commit
    on ``main``. Creates no tag itself; it prints ``create``/``tag`` for the
    workflow. A tag is due only when that commit itself changed
    ``[project].version`` (compared with its parent), the new version has no
    ``vX.Y.Z`` tag yet, CHANGELOG.md has a ``## [X.Y.Z]`` section, and the
    version is higher than every existing release tag. A commit that leaves
    the version alone (a Dependabot edit to pyproject.toml) is a quiet
    no-op even while an older bump is still untagged, so a release always
    tags the commit that bumped it, never whatever happens to be HEAD.
    Already tagged is also a no-op. A bump with no changelog section, or one
    that goes backwards, is an error.

``publish``
    Run by ``.github/workflows/release.yml``'s ``gate`` job. Every job that
    creates a GitHub Release, publishes to PyPI, or moves a tag needs it.
    A run may publish only when its ref is a ``vX.Y.Z`` tag that names the
    version in pyproject.toml at that commit, and that commit is on
    ``main``. A tag push qualifies as before. A ``workflow_dispatch``
    qualifies only with ``publish: true`` on such a tag ref; without it the
    dispatch stays the build-only dry run it has always been.

Why the dispatch path exists: a tag pushed with the workflow's own
GITHUB_TOKEN does not start other workflows, but a dispatch does. That
lets a merged version bump release itself with no personal token.

A PyPI version can never be reused, so every refusal on the publish path
exits non-zero with the reason. A silent skip would look like a release.

Usage::

    python3 scripts/release_gate.py tag --tags "$(git tag -l 'v*.*.*')"
    python3 scripts/release_gate.py publish --event push \\
        --ref refs/tags/v0.22.0 --publish false --on-main true
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_PYPROJECT = ROOT / "pyproject.toml"
DEFAULT_CHANGELOG = ROOT / "CHANGELOG.md"

VERSION_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")
TAG_REF_RE = re.compile(r"^refs/tags/v(\d+\.\d+\.\d+)$")


class GateError(Exception):
    """A condition that must stop the workflow, with the reason to print."""


@dataclass(frozen=True)
class Decision:
    go: bool
    reason: str
    version: str = ""

    @property
    def tag(self) -> str:
        return f"v{self.version}" if self.version else ""


def parse_version(text: str) -> tuple[int, int, int]:
    match = VERSION_RE.match(text.strip())
    if not match:
        raise GateError(f"version {text!r} is not plain X.Y.Z")
    major, minor, patch = (int(part) for part in match.groups())
    return major, minor, patch


def read_version(pyproject: Path) -> str:
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    try:
        version = data["project"]["version"]
    except KeyError as exc:
        raise GateError(f"{pyproject} has no [project].version") from exc
    parse_version(version)
    return version


def release_tags(raw: str) -> list[tuple[int, int, int]]:
    """Plain ``vX.Y.Z`` tags only; floating ``v0``/``v1`` tags are ignored."""
    found = []
    for line in raw.split():
        if line.startswith("v") and VERSION_RE.match(line[1:]):
            found.append(parse_version(line[1:]))
    return found


def has_changelog_section(changelog: str, version: str) -> bool:
    pattern = rf"^## \[{re.escape(version)}\]"
    return re.search(pattern, changelog, flags=re.MULTILINE) is not None


def decide_tag(
    version: str, previous_version: str | None, changelog: str, existing_tags: str
) -> Decision:
    current = parse_version(version)
    if previous_version is not None and previous_version.strip() == version:
        return Decision(False, f"this commit did not change the version ({version})")
    tags = release_tags(existing_tags)
    if current in tags:
        return Decision(False, f"v{version} is already tagged; nothing to do")
    if not has_changelog_section(changelog, version):
        raise GateError(
            f"pyproject.toml says {version} but CHANGELOG.md has no "
            f"'## [{version}]' section; promote [Unreleased] first"
        )
    if tags and current < max(tags):
        highest = "v" + ".".join(str(n) for n in max(tags))
        raise GateError(f"v{version} is lower than the latest release tag {highest}")
    return Decision(
        True, f"v{version} is untagged and has a changelog section", version
    )


def decide_publish(
    event: str, ref: str, publish_input: str, version: str, on_main: bool
) -> Decision:
    if event == "workflow_dispatch" and publish_input.strip().lower() != "true":
        return Decision(False, "workflow_dispatch without publish: build-only dry run")
    if event not in ("push", "workflow_dispatch"):
        raise GateError(f"release.yml does not publish on {event!r} events")

    match = TAG_REF_RE.match(ref)
    if not match:
        raise GateError(f"publishing needs a vX.Y.Z tag ref, got {ref!r}")
    tag_version = match.group(1)
    if tag_version != version:
        raise GateError(
            f"tag v{tag_version} does not match pyproject.toml version {version} "
            "at that commit"
        )
    if not on_main:
        raise GateError(f"v{tag_version} points at a commit that is not on main")
    return Decision(
        True, f"v{tag_version} is on main and matches pyproject.toml", version
    )


def _write_outputs(values: dict[str, str]) -> None:
    lines = "".join(f"{key}={value}\n" for key, value in values.items())
    sys.stdout.write(lines)
    target = os.environ.get("GITHUB_OUTPUT")
    if target:
        with open(target, "a", encoding="utf-8") as handle:
            handle.write(lines)


def _flag(text: str) -> bool:
    value = text.strip().lower()
    if value not in ("true", "false"):
        raise GateError(f"expected true or false, got {text!r}")
    return value == "true"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)

    tag = sub.add_parser("tag", help="is a release tag due for this commit?")
    tag.add_argument("--pyproject", type=Path, default=DEFAULT_PYPROJECT)
    tag.add_argument(
        "--previous-pyproject",
        type=Path,
        default=None,
        help="pyproject.toml at the commit's parent; missing means a new version",
    )
    tag.add_argument("--changelog", type=Path, default=DEFAULT_CHANGELOG)
    tag.add_argument("--tags", default="", help="whitespace-separated tag names")

    pub = sub.add_parser("publish", help="may this release.yml run publish?")
    pub.add_argument("--pyproject", type=Path, default=DEFAULT_PYPROJECT)
    pub.add_argument("--event", required=True)
    pub.add_argument("--ref", required=True)
    pub.add_argument("--publish", default="false")
    pub.add_argument("--on-main", required=True)

    args = parser.parse_args(argv)
    try:
        version = read_version(args.pyproject)
        if args.command == "tag":
            previous = None
            if args.previous_pyproject and args.previous_pyproject.is_file():
                previous = read_version(args.previous_pyproject)
            decision = decide_tag(
                version, previous, args.changelog.read_text(encoding="utf-8"), args.tags
            )
            _write_outputs(
                {
                    "create": str(decision.go).lower(),
                    "tag": decision.tag or f"v{version}",
                }
            )
        else:
            decision = decide_publish(
                args.event, args.ref, args.publish, version, _flag(args.on_main)
            )
            _write_outputs({"publish": str(decision.go).lower()})
    except GateError as exc:
        print(f"::error::{exc}", file=sys.stderr)
        return 1
    print(decision.reason, file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
