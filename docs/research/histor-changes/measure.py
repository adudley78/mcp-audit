"""Run Credenzo's poisoning text checks on HISTOR's record of changes.

Dev tool, not part of the package and never run in CI.  It reads a local copy
of ``changes.jsonl.gz`` from a HISTOR snapshot
(https://histor.modelmarket.dev/datasets/) and prints the counts that
``results.json`` pins.  The data file is not committed.

Usage::

    uv run python docs/research/histor-changes/measure.py PATH/changes.jsonl.gz
    uv run python docs/research/histor-changes/measure.py PATH/changes.jsonl.gz \
        --rows rows.json --check-labels docs/research/histor-changes/labels.json

What is checked.  For a ``title`` or ``description`` field HISTOR gives a word
diff, and the script checks the added words: this is what
``credenzo lock --verify`` checks.  For a changed schema node HISTOR gives the
old and the new value, and the script checks the whole new value.
``lock --verify`` does not check schema text.
"""

from __future__ import annotations

import argparse
import collections
import gzip
import hashlib
import json
import random
from typing import Any

from mcp_audit.analyzers import poisoning
from mcp_audit.lock.tool_digests import TEXT_FIELDS
from mcp_audit.lock.tool_text import poison_ids

#: Characters kept each side of a match in a row's context.
CONTEXT = 110
#: Seed and sizes of the labelled sample (see README.md).
SAMPLE_SEED = 169
SAMPLED_CHECKS = {"POISON-030": 100, "POISON-060": 60}


def added_text(value: object) -> str:
    """Return the text of one changed tool field that the script checks.

    HISTOR writes a text field as ``[op, text]`` pairs (``+`` is added text)
    and a schema field as ``{path, old, new}`` records (the whole new value).
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


def contexts(text: str) -> list[tuple[str, str]]:
    """Return ``(check id, context)`` for every check that fires on *text*.

    The check IDs are those of ``lock/tool_text.poison_ids``; this function
    adds the words round each match, with the match inside ``[[ ]]``.
    """
    ids = poison_ids(text)
    if not ids:
        return []
    norm = poisoning.normalize_for_detection(text)
    out: list[tuple[str, str]] = []
    for pattern in poisoning.PATTERNS:
        if pattern.description_only:
            continue
        match = poisoning.matched_pattern(pattern, text, norm)
        if match:
            src = text if pattern.id in ("POISON-040", "POISON-060") else norm
            start, end = match.start(), match.end()
            out.append(
                (
                    pattern.id,
                    src[max(0, start - CONTEXT) : start]
                    + "[["
                    + src[start:end]
                    + "]]"
                    + src[end : end + CONTEXT],
                )
            )
    for channel in poisoning.scan_concealed_channels(text):
        out.append((poisoning.concealment_finding_id(channel), text[:60]))
    if sorted({check for check, _ in out}) != ids:
        raise SystemExit(f"contexts() and poison_ids() differ: {ids}")
    return out


def _script(char: str) -> str | None:
    code = ord(char)
    if 0x400 <= code <= 0x52F:
        return "Cyr"
    if 0x370 <= code <= 0x3FF or 0x1F00 <= code <= 0x1FFF:
        return "Grk"
    if char.isascii() and char.isalpha():
        return "Lat"
    if 0xFF10 <= code <= 0xFF5A:
        return "Full"
    if 0x1D400 <= code <= 0x1D7FF:
        return "Math"
    if char.isalpha():
        return "Oth"
    return None


def script_of_matched_word(context: str) -> str:
    """Return the scripts of the word at the POISON-060 match in *context*."""
    pos = context.find("[[")
    plain = context.replace("[[", "").replace("]]", "")
    start = end = pos
    while start > 0 and plain[start - 1].isalnum():
        start -= 1
    while end < len(plain) and plain[end].isalnum():
        end += 1
    scripts = {_script(char) for char in plain[start:end]} - {None}
    return "+".join(sorted(scripts))  # type: ignore[arg-type]


def measure(path: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Return the counts and the distinct flagged rows for the file at *path*."""
    changes = with_modified = 0
    flagged: dict[str, set[int]] = {"all": set(), "text": set()}
    servers: dict[str, set[str]] = {"all": set(), "text": set()}
    by_text: collections.Counter[str] = collections.Counter()
    seen_text: set[tuple[str, str]] = set()
    seen_row: set[tuple[str, str]] = set()
    rows: list[dict[str, Any]] = []
    with gzip.open(path, "rt", encoding="utf-8") as handle:
        for line in handle:
            record = json.loads(line)
            summary = json.loads(record["summaryJson"])
            changes += 1
            modified = summary.get("modified") or []
            with_modified += bool(modified)
            for tool in modified:
                for field, value in (tool.get("fields") or {}).items():
                    text = added_text(value)
                    if not text.strip():
                        continue
                    found = contexts(text)
                    if not found:
                        continue
                    scopes = ["all"] + (["text"] if field in TEXT_FIELDS else [])
                    for scope in scopes:
                        flagged[scope].add(record["id"])
                        servers[scope].add(record["serverId"])
                    digest = hashlib.sha256(text.encode()).hexdigest()
                    for check, context in found:
                        if (check, digest) not in seen_text:
                            seen_text.add((check, digest))
                            by_text[check] += 1
                        key = (check, hashlib.sha256(context.encode()).hexdigest())
                        if key in seen_row:
                            continue
                        seen_row.add(key)
                        row = {
                            "change": record["id"],
                            "server": record["serverId"],
                            "tool": tool.get("tool"),
                            "field": field,
                            "check": check,
                            "snippet": " ".join(context.split()),
                            "text_sha256": digest,
                        }
                        if check == "POISON-060":
                            row["kind"] = script_of_matched_word(row["snippet"])
                        rows.append(row)
    by_row = collections.Counter(row["check"] for row in rows)
    kinds = collections.Counter(row.get("kind") for row in rows if "kind" in row)
    counts = {
        "changes": changes,
        "changes_with_modified_tool": with_modified,
        "changes_flagged": len(flagged["all"]),
        "servers_flagged": len(servers["all"]),
        "changes_flagged_in_title_or_description": len(flagged["text"]),
        "servers_flagged_in_title_or_description": len(servers["text"]),
        "distinct_rows": len(rows),
        "distinct_rows_by_check": dict(by_row.most_common()),
        "distinct_rows_in_schema_fields": sum(
            1 for row in rows if row["field"] not in TEXT_FIELDS
        ),
        "distinct_added_texts_by_check": dict(by_text.most_common()),
        "poison_060_rows_by_script_of_matched_word": dict(kinds.most_common()),
    }
    return counts, rows


def sample(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return the labelled sample: all rows of the small checks, then a draw."""
    rng = random.Random(SAMPLE_SEED)  # noqa: S311 - a sample, not a secret
    out = [row for row in rows if row["check"] not in SAMPLED_CHECKS]
    for check, size in SAMPLED_CHECKS.items():
        pool = [row for row in rows if row["check"] == check]
        rng.shuffle(pool)
        servers: set[str] = set()
        picked = 0
        for row in pool:
            if row["server"] in servers:
                continue
            servers.add(row["server"])
            out.append(row)
            picked += 1
            if picked >= size:
                break
    return out


def check_labels(rows: list[dict[str, Any]], labels_path: str) -> None:
    """Exit with an error unless ``labels.json`` holds exactly the sample."""
    with open(labels_path, encoding="utf-8") as handle:
        labels = json.load(handle)["rows"]
    want = [
        (r["change"], r["server"], r["tool"], r["field"], r["check"], r["text_sha256"])
        for r in sample(rows)
    ]
    have = [
        (
            r["change_id"],
            r["server_id"],
            r["tool"],
            r["field"],
            r["check"],
            r["added_text_sha256"],
        )
        for r in labels
    ]
    if want != have:
        raise SystemExit("labels.json does not hold the seed-169 sample")
    print(f"labels.json holds the sample: {len(have)} rows")


def main() -> None:
    """Print the counts; optionally write the rows and check the labels."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("changes", help="path of HISTOR's changes.jsonl.gz")
    parser.add_argument("--rows", help="write the distinct flagged rows here")
    parser.add_argument("--check-labels", help="path of labels.json to verify")
    args = parser.parse_args()
    counts, rows = measure(args.changes)
    print(json.dumps(counts, indent=1, ensure_ascii=False))
    if args.rows:
        with open(args.rows, "w", encoding="utf-8") as handle:
            json.dump(rows, handle, ensure_ascii=False)
    if args.check_labels:
        check_labels(rows, args.check_labels)


if __name__ == "__main__":
    main()
