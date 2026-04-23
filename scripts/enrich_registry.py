#!/usr/bin/env python3
"""Enrich registry/known-servers.json with npm/PyPI metadata.

Fetches first_published, weekly_downloads, and publisher_history for npm entries
and writes them back to the registry file. Run periodically to keep data fresh.

Usage:
    python scripts/enrich_registry.py [--dry-run]
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from pathlib import Path

REGISTRY_PATH = Path(__file__).parent.parent / "registry" / "known-servers.json"


def fetch_npm_metadata(package_name: str) -> dict:
    """Fetch metadata for an npm package from the npm registry API.

    Args:
        package_name: The npm package name (scoped or unscoped).

    Returns:
        Parsed JSON response dict, or an empty dict on failure.
    """
    encoded = package_name.replace("/", "%2F")
    url = f"https://registry.npmjs.org/{encoded}"
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:  # noqa: S310
            return json.loads(resp.read())
    except Exception as exc:
        print(f"  WARN: could not fetch {package_name}: {exc}", file=sys.stderr)
        return {}


def extract_npm_fields(data: dict) -> dict:
    """Extract first_published, publisher_history from npm registry response.

    Args:
        data: Parsed npm registry API response.

    Returns:
        Dict with any of ``first_published`` and ``publisher_history`` that
        could be extracted.  ``weekly_downloads`` is not returned here because
        it requires a separate call to the npm downloads API.
    """
    result: dict = {}

    time = data.get("time", {})
    created = time.get("created")
    if created:
        result["first_published"] = created[:10]  # YYYY-MM-DD

    # Collect unique maintainer names across all versions, most-recent first.
    versions = data.get("versions", {})
    seen: list[str] = []
    seen_set: set[str] = set()
    for _ver, vdata in reversed(list(versions.items())):
        for m in vdata.get("maintainers", []):
            name = m.get("name", "")
            if name and name not in seen_set:
                seen.append(name)
                seen_set.add(name)
    if seen:
        result["publisher_history"] = seen

    return result


def main() -> None:
    """Entry point: parse args, enrich each npm entry, write results."""
    parser = argparse.ArgumentParser(
        description="Enrich registry metadata from npm/PyPI"
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Print changes without writing"
    )
    args = parser.parse_args()

    data = json.loads(REGISTRY_PATH.read_text())
    changed = 0

    for entry in data["entries"]:
        if entry.get("source") != "npm":
            continue
        print(f"Fetching {entry['name']}...")
        meta = fetch_npm_metadata(entry["name"])
        if not meta:
            continue
        fields = extract_npm_fields(meta)
        for key, val in fields.items():
            if entry.get(key) != val:
                entry[key] = val
                changed += 1

    print(f"\n{changed} field(s) updated across {len(data['entries'])} entries.")

    if not args.dry_run:
        REGISTRY_PATH.write_text(json.dumps(data, indent=2) + "\n")
        print(f"Written to {REGISTRY_PATH}")
    else:
        print("Dry run — no changes written.")


if __name__ == "__main__":
    main()
