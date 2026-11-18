"""Run Credenzo's added-words poisoning checks on HISTOR's record of changes.

Dev tool, not part of the package and never run in CI.  It reads a local copy
of ``changes.jsonl.gz`` from a HISTOR snapshot (CC BY 4.0,
https://histor.modelmarket.dev/datasets/) and prints the counts that
``results.json`` pins.  The data file is not committed.

Usage::

    uv run python docs/research/histor-changes/measure.py PATH/changes.jsonl.gz
"""

from __future__ import annotations

import collections
import gzip
import hashlib
import json
import sys

from mcp_audit.analyzers import poisoning


def added_text(value: object) -> str:
    """Return the words a change added to one tool field.

    HISTOR writes a text field as ``[op, text]`` pairs (``+`` is added text)
    and a schema field as ``{path, old, new}`` records.
    """
    parts: list[str] = []
    if isinstance(value, list):
        for item in value:
            if isinstance(item, list) and len(item) == 2 and item[0] == "+":
                parts.append(str(item[1]))
            elif isinstance(item, dict) and item.get("new") is not None:
                new = item["new"]
                parts.append(new if isinstance(new, str) else json.dumps(new))
    elif isinstance(value, str):
        parts.append(value)
    return " ".join(parts)


def fired(text: str) -> list[tuple[str, str]]:
    """Return ``(check id, matched words)`` for every check that fires."""
    norm = poisoning.normalize_for_detection(text)
    out: list[tuple[str, str]] = []
    for pattern in poisoning.PATTERNS:
        if pattern.description_only:
            continue
        match = poisoning.matched_pattern(pattern, text, norm)
        if match:
            out.append((pattern.id, match.group(0)))
    for channel in poisoning.scan_concealed_channels(text):
        out.append((poisoning.concealment_finding_id(channel), ""))
    return out


def main(path: str) -> None:
    """Print the counts for the snapshot at *path*."""
    changes = with_modified = flagged = 0
    servers: set[str] = set()
    by_check: collections.Counter[str] = collections.Counter()
    distinct: set[tuple[str, str]] = set()
    with gzip.open(path, "rt", encoding="utf-8") as handle:
        for line in handle:
            record = json.loads(line)
            summary = json.loads(record["summaryJson"])
            changes += 1
            modified = summary.get("modified") or []
            with_modified += bool(modified)
            hit = False
            for tool in modified:
                for value in (tool.get("fields") or {}).values():
                    text = added_text(value)
                    if not text.strip():
                        continue
                    digest = hashlib.sha256(text.encode()).hexdigest()
                    for check, _words in fired(text):
                        hit = True
                        if (check, digest) not in distinct:
                            distinct.add((check, digest))
                            by_check[check] += 1
            if hit:
                flagged += 1
                servers.add(record["serverId"])
    print(
        json.dumps(
            {
                "changes": changes,
                "changes_with_modified_tool": with_modified,
                "changes_flagged_added_words": flagged,
                "servers_flagged": len(servers),
                "distinct_added_texts_by_check": dict(by_check.most_common()),
            },
            indent=1,
        )
    )


if __name__ == "__main__":
    main(sys.argv[1])
