#!/usr/bin/env python3
"""Decide whether a freshly built advisory feed differs from the published one.

``mcp_audit.advisory.feed.build_advisory`` stamps every advisory's ``published``
and ``modified`` fields with the run's wall-clock ``now`` (see
``cli/advise.py::_resolve_now``), so two runs over identical findings never
produce byte-identical advisory files — only byte-identical *content*. A naive
``diff -r`` between the old and new feed directories would therefore report a
change on every single run, which is exactly the noise
``.github/workflows/advisory-feed-publish.yml`` must not produce.

This script strips the two volatile fields (``published``, ``modified``) from
every advisory record before comparing, so the verdict tracks the advisories
themselves — package, finding class, severity, references, and so on — not
the timestamp of the run that (re)built them.

Usage::

    python scripts/feed_diff.py --old previous_feed --new new_feed \\
        --github-output "$GITHUB_OUTPUT"

Exit code is always 0; the verdict is reported via ``changed=true|false`` on
stdout and, when ``--github-output`` is given, appended to that file so a
GitHub Actions step can read it as a job output.
"""

from __future__ import annotations

import argparse
import json
import sys
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


def feeds_changed(old_dir: Path, new_dir: Path) -> bool:
    """Return ``True`` iff *new_dir* carries different advisories than *old_dir*.

    "Different" means the set of advisory IDs differs, or any shared ID's
    content differs once ``published``/``modified`` are removed. A feed that
    republishes the exact same findings under a new timestamp is not different.
    """
    return load_advisory_fingerprints(old_dir) != load_advisory_fingerprints(new_dir)


def read_index(feed_dir: Path) -> dict[str, Any]:
    """Read ``<feed_dir>/index.json``, or ``{}`` if it does not exist."""
    index_path = Path(feed_dir) / "index.json"
    if not index_path.is_file():
        return {}
    return json.loads(index_path.read_text(encoding="utf-8"))


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
        help="Append changed/snapshot_version/count as GitHub Actions step outputs.",
    )
    args = parser.parse_args(argv)

    new_index = read_index(args.new)
    if not new_index:
        print(f"ERROR: {args.new} has no index.json", file=sys.stderr)
        return 2

    changed = feeds_changed(args.old, args.new)
    snapshot_version = new_index.get("snapshot_version")
    count = new_index.get("count")

    verdict = "changed" if changed else "unchanged"
    print(
        f"Feed {verdict}: {count} advisory(ies), candidate snapshot_version="
        f"{snapshot_version}.",
        file=sys.stderr,
    )
    if not changed:
        print(
            "No substantive difference from the published feed "
            "(published/modified timestamps excluded) — skipping publish.",
            file=sys.stderr,
        )

    if args.github_output is not None:
        with args.github_output.open("a", encoding="utf-8") as handle:
            handle.write(f"changed={'true' if changed else 'false'}\n")
            handle.write(f"snapshot_version={snapshot_version}\n")
            handle.write(f"count={count}\n")

    print("true" if changed else "false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
