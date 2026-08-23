#!/usr/bin/env python3
"""Summarise how a freshly built advisory feed differs from the published one.

R30 used this diff as a publish *gate*: skip the commit when nothing
changed. That was wrong (R31) — the feed is published on a TTL, so every
scheduled run must publish something even when the advisory content is
identical, or the freshness envelope (``expires``) freezes and the feed
starts hard-failing ``feed verify`` on its own expiry date. This script's
job now is narrower: describe *what kind* of publish this is, for the
commit message, never whether to publish.

``mcp_audit.advisory.feed.build_advisory`` stamps every advisory's ``published``
and ``modified`` fields with the run's wall-clock ``now`` (see
``cli/advise.py::_resolve_now``), so two runs over identical findings never
produce byte-identical advisory files — only byte-identical *content*. A naive
``diff -r`` between the old and new feed directories would therefore report a
change on every single run. This script strips the two volatile fields
(``published``, ``modified``) before comparing, so the verdict tracks the
advisories themselves — package, finding class, severity, references, and so
on — not the timestamp of the run that (re)built them.

Usage::

    python scripts/feed_diff.py --old previous_feed --new new_feed \\
        --github-output "$GITHUB_OUTPUT"

Exit code is 0 on success (informational only — never a gate) and 2 only if
``--new`` has no ``index.json`` (should not happen inside the workflow).
Writes ``changed``, ``changed_count``, ``snapshot_version``, ``count``, and
``commit_message`` to ``--github-output`` when given.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# Stamped fresh on every build (see module docstring); never meaningful to the
# "did the feed actually change" question.
_VOLATILE_ADVISORY_FIELDS = ("published", "modified")


def _strip_volatile(record: dict[str, Any]) -> dict[str, Any]:
    """Return *record* without fields that change on every run regardless of content."""
    return {k: v for k, v in record.items() if k not in _VOLATILE_ADVISORY_FIELDS}


def load_advisory_fingerprints(feed_dir: Path) -> dict[str, dict[str, Any]]:
    """Return ``{advisory_id: content}`` for every record under *feed_dir*/advisories.

    Missing directory (no prior feed, or a feed with zero advisories) returns an
    empty mapping rather than raising — the caller treats that as "everything is
    new".
    """
    advisories_dir = Path(feed_dir) / "advisories"
    if not advisories_dir.is_dir():
        return {}

    fingerprints: dict[str, dict[str, Any]] = {}
    for path in sorted(advisories_dir.glob("*.json")):
        record = json.loads(path.read_text(encoding="utf-8"))
        advisory_id = str(record.get("id") or path.stem)
        fingerprints[advisory_id] = _strip_volatile(record)
    return fingerprints


@dataclass(frozen=True)
class DiffSummary:
    """What changed between two feeds, ignoring published/modified timestamps."""

    added: int
    removed: int
    modified: int

    @property
    def changed_count(self) -> int:
        return self.added + self.removed + self.modified

    @property
    def changed(self) -> bool:
        return self.changed_count > 0


def diff_summary(old_dir: Path, new_dir: Path) -> DiffSummary:
    """Compare two feed directories' advisories, ignoring volatile timestamps.

    "Different" means an advisory ID is present on only one side, or a shared
    ID's content differs once ``published``/``modified`` are removed. A feed
    that republishes the exact same findings under a new timestamp has an
    empty (all-zero) summary.
    """
    old = load_advisory_fingerprints(old_dir)
    new = load_advisory_fingerprints(new_dir)
    old_ids, new_ids = set(old), set(new)
    added = len(new_ids - old_ids)
    removed = len(old_ids - new_ids)
    modified = sum(1 for aid in old_ids & new_ids if old[aid] != new[aid])
    return DiffSummary(added=added, removed=removed, modified=modified)


def feeds_changed(old_dir: Path, new_dir: Path) -> bool:
    """Return ``True`` iff *new_dir* carries different advisories than *old_dir*."""
    return diff_summary(old_dir, new_dir).changed


def read_index(feed_dir: Path) -> dict[str, Any]:
    """Read ``<feed_dir>/index.json``, or ``{}`` if it does not exist."""
    index_path = Path(feed_dir) / "index.json"
    if not index_path.is_file():
        return {}
    return json.loads(index_path.read_text(encoding="utf-8"))


def build_commit_message(
    *, snapshot_version: object, count: object, changed_count: int
) -> str:
    """Return the `feed` branch commit message for this publish.

    Every scheduled run publishes (R31) — this only decides which of the two
    honest descriptions the commit gets, so scrolling the branch history
    shows at a glance which weeks changed anything:

        feed: refresh expiry (snapshot 4, 23 advisories, no content change)
        feed: 2 advisories changed (snapshot 5, 25 advisories)
    """
    if changed_count == 0:
        return (
            f"feed: refresh expiry (snapshot {snapshot_version}, {count} "
            "advisories, no content change)"
        )
    return (
        f"feed: {changed_count} advisories changed "
        f"(snapshot {snapshot_version}, {count} advisories)"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--old",
        type=Path,
        required=True,
        help="Previously published feed directory (may not exist yet).",
    )
    parser.add_argument(
        "--new",
        type=Path,
        required=True,
        help="Freshly built candidate feed directory.",
    )
    parser.add_argument(
        "--github-output",
        type=Path,
        default=None,
        help="Append changed/changed_count/snapshot_version/count/commit_message "
        "as GitHub Actions step outputs.",
    )
    args = parser.parse_args(argv)

    new_index = read_index(args.new)
    if not new_index:
        print(f"ERROR: {args.new} has no index.json", file=sys.stderr)
        return 2

    summary = diff_summary(args.old, args.new)
    snapshot_version = new_index.get("snapshot_version")
    count = new_index.get("count")
    message = build_commit_message(
        snapshot_version=snapshot_version,
        count=count,
        changed_count=summary.changed_count,
    )

    verdict = "changed" if summary.changed else "unchanged"
    print(
        f"Feed {verdict}: {summary.added} added, {summary.removed} removed, "
        f"{summary.modified} modified; {count} advisory(ies) total, "
        f"snapshot_version={snapshot_version}.",
        file=sys.stderr,
    )
    print(f"Commit message: {message}", file=sys.stderr)

    if args.github_output is not None:
        with args.github_output.open("a", encoding="utf-8") as handle:
            handle.write(f"changed={'true' if summary.changed else 'false'}\n")
            handle.write(f"changed_count={summary.changed_count}\n")
            handle.write(f"snapshot_version={snapshot_version}\n")
            handle.write(f"count={count}\n")
            handle.write(f"commit_message={message}\n")

    print(message)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
