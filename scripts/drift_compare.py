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
- ``calendar_only``: same name, different ``definition`` digest, but the same
  ``undated`` digest in both snapshots. The tool writes a date into its text
  (an example query for "today"), so its digest is new each day with no change
  by its author. These tools are not in ``definition_changed`` and do not make
  a server ``changed``. A snapshot from before 2026-11-20 has no ``undated``
  digests; a comparison with one counts such a tool as changed, as before.
- ``contract_changed``: the subset whose ``contract`` digest changed too (name,
  input schema or annotations; not only prose).
- ``bumped``: the version string differs.

Stdlib only, no network, no package code. Tool names are recorded; tool text
never is (the snapshots hold digests only).

Usage::

    python scripts/drift_compare.py OLDER.json NEWER.json --out index/DATE.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1


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


def compare_row(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    """Compare one server's tools in two snapshots."""
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
        if d_old[t].get("undated")
        and d_old[t].get("undated") == d_new[t].get("undated")
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
    rows = [
        compare_row(old_rows[key], new_rows[key])
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
            "whose definition differs only in a calendar date is not a change; "
            "calendar_only counts the servers with only such tools."
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
