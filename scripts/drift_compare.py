#!/usr/bin/env python3
"""Compare two drift snapshots: which MCP servers changed what they tell the agent.

A snapshot is the file ``scripts/drift_snapshot.py --summary`` writes: one row
per package with the version that was current that day and, when the server
started with no network and no credentials, the lock digests of its tools
(``lock/tool_digests.py``). This script compares two of them, an older and a
newer one, and writes the weekly index record.

A server is compared only when it connected with at least one tool in both
snapshots. For each such server:

- ``added`` / ``removed``: tool names in only one snapshot.
- ``definition_changed``: same name, different ``definition`` digest (any part
  of the tool changed, text included).
- ``calendar_only``: same name, different ``definition`` digest, and the only
  difference is that the dates in the text moved with the calendar (an example
  query for "today"). The snapshot holds, for a tool whose text has ISO dates,
  the digest of the text with the dates cut out (``undated``) and the dates
  themselves (``dates``). A tool is ``calendar_only`` when ``undated`` is the
  same in both snapshots and each date is the same, or moved by the number of
  days between the two snapshots, or is the first day of a month and moved by
  the number of months between them. A date that an author moved in another
  way is a change. These tools are not in ``definition_changed`` or
  ``contract_changed`` and do not make a server ``changed``; each one is
  listed by name. A snapshot from before 2026-11-20 has no ``undated``
  digests; a comparison with one counts such a tool as changed.
- ``bumped``: the version string differs.

Stdlib only, no network, no package code. Tool names are recorded; tool text
never is (the snapshots hold digests only).

Usage::

    python scripts/drift_compare.py OLDER.json NEWER.json --out index/DATE.json
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
_ISO_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")


def _connected_rows(snapshot: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    """Return ``{(type, package): row}`` for rows that connected with tools.

    A package listed twice (two versions under one label) keeps the row with
    the most tools, so a stale duplicate cannot hide the live one.
    """
    out: dict[tuple[str, str], dict[str, Any]] = {}
    for row in snapshot.get("rows", []):
        if not isinstance(row, dict):
            continue
        digests = row.get("digests")
        if not row.get("connected") or not isinstance(digests, dict) or not digests:
            continue
        key = (str(row.get("type")), str(row.get("package")))
        kept = out.get(key)
        if kept is None or len(digests) > len(kept["digests"]):
            out[key] = row
    return out


def _date(text: object) -> dt.date | None:
    """Return *text* as a date when it is exactly ``YYYY-MM-DD``."""
    if not isinstance(text, str) or not _ISO_DATE.fullmatch(text):
        return None
    try:
        return dt.date.fromisoformat(text)
    except ValueError:
        return None


def moved_with_calendar(
    old: dict[str, Any], new: dict[str, Any], day_old: dt.date, day_new: dt.date
) -> bool:
    """Whether a tool's only difference is that its dates followed the calendar.

    *old* and *new* are the tool's records in two snapshots made on *day_old*
    and *day_new*. True needs the same ``undated`` digest and, for each pair
    of dates in order, one of: the same date; a move by the days between the
    snapshots; two first days of a month, moved by the months between them.
    """
    undated = old.get("undated")
    if not isinstance(undated, str) or not undated or undated != new.get("undated"):
        return False
    dates_old, dates_new = old.get("dates"), new.get("dates")
    if not isinstance(dates_old, list) or not isinstance(dates_new, list):
        return False
    if not dates_old or len(dates_old) != len(dates_new):
        return False
    days = (day_new - day_old).days
    months = (day_new.year - day_old.year) * 12 + day_new.month - day_old.month
    for text_old, text_new in zip(dates_old, dates_new, strict=True):
        a, b = _date(text_old), _date(text_new)
        if a is None or b is None:
            return False
        if a == b or (b - a).days == days:
            continue
        if a.day == b.day == 1 and (b.year - a.year) * 12 + b.month - a.month == months:
            continue
        return False
    return True


def compare_row(
    old: dict[str, Any],
    new: dict[str, Any],
    day_old: dt.date | None = None,
    day_new: dt.date | None = None,
) -> dict[str, Any]:
    """Compare one server's tools in two snapshots.

    *day_old* and *day_new* are the dates of the two snapshots. With no dates
    no tool is ``calendar_only``.
    """
    d_old: dict[str, dict[str, str]] = old["digests"]
    d_new: dict[str, dict[str, str]] = new["digests"]
    added = sorted(set(d_new) - set(d_old))
    removed = sorted(set(d_old) - set(d_new))
    both = set(d_old) & set(d_new)
    differs = sorted(
        t for t in both if d_old[t].get("definition") != d_new[t].get("definition")
    )
    calendar_only = [
        t
        for t in differs
        if day_old is not None
        and day_new is not None
        and moved_with_calendar(d_old[t], d_new[t], day_old, day_new)
    ]
    definition_changed = [t for t in differs if t not in calendar_only]
    contract_changed = sorted(
        t
        for t in definition_changed
        if d_old[t].get("contract") != d_new[t].get("contract")
    )
    return {
        "type": new.get("type"),
        "package": new.get("package"),
        "version_from": old.get("version"),
        "version_to": new.get("version"),
        "bumped": old.get("version") != new.get("version"),
        "changed": bool(added or removed or definition_changed),
        "added": added,
        "removed": removed,
        "definition_changed": definition_changed,
        "contract_changed": contract_changed,
        "calendar_only": calendar_only,
    }


def _aggregate(rows: list[dict[str, Any]]) -> dict[str, Any]:
    changed = [r for r in rows if r["changed"]]
    compared = len(rows)
    return {
        "compared": compared,
        "changed": len(changed),
        "changed_pct": round(100 * len(changed) / compared, 1) if compared else None,
        "changed_with_bump": sum(r["bumped"] for r in changed),
        "changed_without_bump": sum(not r["bumped"] for r in changed),
        "bumped": sum(r["bumped"] for r in rows),
        "bumped_unchanged": sum(r["bumped"] and not r["changed"] for r in rows),
        "tool_added_or_removed": sum(bool(r["added"] or r["removed"]) for r in changed),
        "text_only": sum(
            not r["added"] and not r["removed"] and not r["contract_changed"]
            for r in changed
        ),
        "calendar_only": sum(
            bool(r["calendar_only"]) and not r["changed"] for r in rows
        ),
    }


def compare(older: dict[str, Any], newer: dict[str, Any]) -> dict[str, Any]:
    """Return the index record for the step from *older* to *newer*."""
    old_rows = _connected_rows(older)
    new_rows = _connected_rows(newer)
    day_old, day_new = _date(older.get("label")), _date(newer.get("label"))
    rows = [
        compare_row(old_rows[key], new_rows[key], day_old, day_new)
        for key in sorted(set(old_rows) & set(new_rows))
    ]
    by_type = {
        t: _aggregate([r for r in rows if r["type"] == t])
        for t in sorted({str(r["type"]) for r in rows})
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "from": older.get("label"),
        "to": newer.get("label"),
        "tool": newer.get("tool"),
        "packages_in_corpus": newer.get("pairs"),
        "connected_from": len(old_rows),
        "connected_to": len(new_rows),
        **_aggregate(rows),
        "by_type": by_type,
        "method": (
            "Each package is installed at the version current on the snapshot "
            "date and started with no network and no credentials. A server is "
            "compared when it listed tools on both dates. A change is a tool "
            "added, removed, or with a different definition digest. A tool "
            "whose only difference is that its dates moved with the calendar "
            "is not a change; calendar_only counts the servers whose tools "
            "differ only in that way."
        ),
        "rows": [r for r in rows if r["changed"] or r["bumped"] or r["calendar_only"]],
    }


def _load(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("rows"), list):
        raise ValueError(f"{path}: not a drift snapshot (no 'rows' list)")
    return data


def main(argv: list[str] | None = None) -> int:
    """Command-line entry point."""
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("older", type=Path)
    parser.add_argument("newer", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument(
        "--from-label",
        help="Label for the older snapshot when its file has none.",
    )
    parser.add_argument(
        "--to-label",
        help="Label for the newer snapshot when its file has none.",
    )
    parser.add_argument(
        "--min-compared",
        type=int,
        default=0,
        help="Exit 1 when fewer servers than this were compared (a broken run).",
    )
    args = parser.parse_args(argv)
    try:
        older, newer = _load(args.older), _load(args.newer)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.from_label and not older.get("label"):
        older["label"] = args.from_label
    if args.to_label and not newer.get("label"):
        newer["label"] = args.to_label
    result = compare(older, newer)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=1) + "\n", encoding="utf-8")
    summary = {
        k: v for k, v in result.items() if k not in ("rows", "method", "by_type")
    }
    print(json.dumps(summary, indent=1))
    if result["compared"] < args.min_compared:
        print(
            f"error: only {result['compared']} servers compared, "
            f"fewer than --min-compared {args.min_compared}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
