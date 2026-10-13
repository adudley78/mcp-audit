#!/usr/bin/env python3
"""Check (or update) the registry's CVE lists against OSV.

For every entry in ``registry/known-servers.json`` this queries OSV
(``POST https://api.osv.dev/v1/query``) by package name and ecosystem, and
compares the advisories it returns with the entry's ``known_vulnerabilities``
and ``known_vulns``.  SC-004 and ``vet`` read only those two fields, so an
advisory missing here is an advisory the default offline scan never reports
(STORY-0083: on 2026-10-13, 47 of 53 entries listed none).

Modes:

* ``--check`` (the default) changes nothing.  It prints what is missing and
  exits 1 when anything is, 0 when nothing is.  This is what the weekly
  ``registry-advisory-sync.yml`` workflow runs, mirroring
  ``registry-drift.yml``'s rule that automation never writes the registry.
* ``--write`` merges the missing advisories into the file.  A human (or the
  build loop, in a reviewed PR) runs this.

Merge rules, so a write can only add information:

* Existing IDs and records are never removed or rewritten.  A record that
  lacks ``fixed_in`` gets one filled in when OSV knows it.
* An advisory counts as present when any of its IDs (OSV id or aliases) is
  already listed, so a GHSA is not added beside the CVE it aliases.
* The recorded ID is the advisory's CVE alias when it has one, else its OSV
  id (GHSA-/PYSEC-).
* Withdrawn records and ``MAL-*`` malicious-package records are skipped:
  a malicious release is a different finding class from a CVE.
* ``fixed_in`` is the highest ``fixed`` version across the package's ranges,
  and is left unset when any range has no fix.  Taking the highest is
  conservative: a pinned version fixed on an older branch may still be
  reported, but no affected version is missed.

Known limit: unreviewed GitHub advisories carry no package data, so OSV does
not map them to a package until GitHub reviews them.  NVD-only CVEs are not
covered either.  Those still need adding by hand.

Usage:
    python scripts/sync_registry_advisories.py            # check
    python scripts/sync_registry_advisories.py --write    # update the file
    python scripts/sync_registry_advisories.py --summary "$GITHUB_STEP_SUMMARY"
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
REGISTRY_PATH = REPO_ROOT / "registry" / "known-servers.json"
OSV_QUERY_URL = "https://api.osv.dev/v1/query"
_ECOSYSTEMS = {"npm": "npm", "pip": "PyPI", "pypi": "PyPI"}
_DESCRIPTION_LIMIT = 200


# ── OSV access ─────────────────────────────────────────────────────────────────


def osv_ecosystem(entry: dict[str, Any]) -> str | None:
    """Return the OSV ecosystem name for a registry entry, or ``None``."""
    source = str(entry.get("package_ecosystem") or entry.get("source") or "")
    return _ECOSYSTEMS.get(source.lower())


def query_osv(name: str, ecosystem: str, timeout: int = 30) -> list[dict[str, Any]]:
    """Return every OSV record for ``name`` in ``ecosystem``, following pages.

    Raises:
        RuntimeError: when OSV cannot be reached or returns bad JSON.  The
            caller turns this into exit code 2, never a silent pass.
    """
    vulns: list[dict[str, Any]] = []
    page_token: str | None = None
    while True:
        body: dict[str, Any] = {"package": {"name": name, "ecosystem": ecosystem}}
        if page_token:
            body["page_token"] = page_token
        request = urllib.request.Request(  # noqa: S310 — constant https URL
            OSV_QUERY_URL,
            data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            # Constant https://api.osv.dev URL.
            with urllib.request.urlopen(request, timeout=timeout) as resp:  # noqa: S310  # nosec B310
                data = json.loads(resp.read())
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise RuntimeError(
                f"OSV query failed for {ecosystem}/{name}: {exc}"
            ) from exc
        vulns.extend(data.get("vulns") or [])
        page_token = data.get("next_page_token")
        if not page_token:
            return vulns


# ── Record shaping ─────────────────────────────────────────────────────────────


def _version_key(version: str) -> tuple:
    """Sort key for npm/PyPI version strings, tolerant of odd formats."""
    try:
        from packaging.version import Version  # noqa: PLC0415

        return (0, Version(version))
    except Exception:  # noqa: BLE001 — any unparsable version sorts by parts
        parts: list[int | str] = []
        for piece in version.replace("-", ".").split("."):
            parts.append(int(piece) if piece.isdigit() else piece)
        return (1, tuple(str(p).zfill(10) if isinstance(p, int) else p for p in parts))


def _same_package(affected: dict[str, Any], name: str, ecosystem: str) -> bool:
    pkg = affected.get("package") or {}
    if pkg.get("ecosystem") != ecosystem:
        return False
    if ecosystem == "PyPI":
        norm = lambda s: str(s).lower().replace("_", "-").replace(".", "-")  # noqa: E731
        return norm(pkg.get("name", "")) == norm(name)
    return pkg.get("name") == name


def fixed_version(vuln: dict[str, Any], name: str, ecosystem: str) -> str | None:
    """Highest ``fixed`` event for this package, or ``None`` when no fix is known.

    A range that ends in ``last_affected`` is bounded (an old version line
    that stopped, as with server-filesystem's 0.6.x), so it doesn't make the
    advisory unfixed.  A range with neither ``fixed`` nor ``last_affected``
    is open-ended, meaning the newest release may be affected, and returns
    ``None``.
    """
    fixes: list[str] = []
    for affected in vuln.get("affected") or []:
        if not _same_package(affected, name, ecosystem):
            continue
        for rng in affected.get("ranges") or []:
            if rng.get("type") not in ("ECOSYSTEM", "SEMVER"):
                continue
            events = rng.get("events") or []
            range_fixes = [e["fixed"] for e in events if e.get("fixed")]
            bounded = any(e.get("last_affected") for e in events)
            if not range_fixes and not bounded:
                return None
            fixes.extend(range_fixes)
    if not fixes:
        return None
    return max(fixes, key=_version_key)


def advisory_id(vuln: dict[str, Any]) -> str:
    """The ID to record: the CVE alias when there is one, else the OSV id."""
    for alias in vuln.get("aliases") or []:
        if str(alias).startswith("CVE-"):
            return str(alias)
    return str(vuln["id"])


def all_ids(vuln: dict[str, Any]) -> set[str]:
    return {str(vuln["id"]), *(str(a) for a in vuln.get("aliases") or [])}


def describe(vuln: dict[str, Any]) -> str:
    text = (vuln.get("summary") or vuln.get("details") or "").strip().split("\n")[0]
    if len(text) > _DESCRIPTION_LIMIT:
        text = text[: _DESCRIPTION_LIMIT - 1].rstrip() + "…"
    return text


def is_skipped(vuln: dict[str, Any]) -> bool:
    return bool(vuln.get("withdrawn")) or str(vuln.get("id", "")).startswith("MAL-")


# ── Diff and merge ─────────────────────────────────────────────────────────────


def missing_for_entry(
    entry: dict[str, Any], vulns: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    """Return (new records, fixed_in fills for existing records) for one entry."""
    name = str(entry["name"])
    ecosystem = osv_ecosystem(entry) or ""
    listed: set[str] = set(entry.get("known_vulnerabilities") or [])
    records = entry.get("known_vulns") or []
    listed |= {
        str(r.get("cve")) for r in records if isinstance(r, dict) and r.get("cve")
    }
    no_fix = {
        str(r["cve"])
        for r in records
        if isinstance(r, dict) and r.get("cve") and not r.get("fixed_in")
    }

    new: list[dict[str, Any]] = []
    fills: dict[str, str] = {}
    seen: set[str] = set()
    for vuln in sorted(vulns, key=lambda v: advisory_id(v)):
        if is_skipped(vuln):
            continue
        ids = all_ids(vuln)
        fix = fixed_version(vuln, name, ecosystem)
        present = ids & listed
        if present:
            for pid in present & no_fix:
                if fix:
                    fills[pid] = fix
            continue
        rec_id = advisory_id(vuln)
        if rec_id in seen:
            continue
        seen.add(rec_id)
        new.append(
            {
                "cve": rec_id,
                "cvss": None,
                "description": describe(vuln),
                "fixed_in": fix,
            }
        )
    return new, fills


def apply(
    entry: dict[str, Any], new: list[dict[str, Any]], fills: dict[str, str]
) -> None:
    """Merge ``new`` records and ``fills`` into ``entry`` in place (additive only)."""
    if new:
        ids = list(entry.get("known_vulnerabilities") or [])
        ids.extend(r["cve"] for r in new if r["cve"] not in ids)
        entry["known_vulnerabilities"] = ids
        records = list(entry.get("known_vulns") or [])
        records.extend(new)
        entry["known_vulns"] = records
    if fills:
        for record in entry.get("known_vulns") or []:
            if (
                isinstance(record, dict)
                and record.get("cve") in fills
                and not record.get("fixed_in")
            ):
                record["fixed_in"] = fills[record["cve"]]


def sync(
    registry: dict[str, Any],
    fetch: Any = None,
) -> dict[str, dict[str, Any]]:
    """Compute and apply missing advisories to ``registry`` in place.

    Args:
        registry: Parsed registry JSON.
        fetch: ``(name, ecosystem) -> list[osv record]``; injectable for tests.

    Returns:
        ``{package: {"added": [ids], "filled": {id: fixed_in}}}`` for every
        entry that changed.
    """
    fetch = fetch or query_osv
    changes: dict[str, dict[str, Any]] = {}
    for entry in registry.get("entries", []):
        ecosystem = osv_ecosystem(entry)
        if ecosystem is None:
            continue
        vulns = fetch(str(entry["name"]), ecosystem)
        new, fills = missing_for_entry(entry, vulns)
        if new or fills:
            apply(entry, new, fills)
            changes[str(entry["name"])] = {
                "added": [r["cve"] for r in new],
                "filled": fills,
            }
    return changes


def render_summary(changes: dict[str, dict[str, Any]]) -> str:
    """Markdown summary for humans and the GitHub job summary."""
    if not changes:
        return (
            "## Registry advisory sync\n\n"
            "No missing advisories. The registry matches OSV.\n"
        )
    added = sum(len(c["added"]) for c in changes.values())
    filled = sum(len(c["filled"]) for c in changes.values())
    lines = [
        "## Registry advisory sync",
        "",
        f"**{added} advisories missing and {filled} fixed versions to fill, "
        f"across {len(changes)} registry entries.** "
        "Run `python scripts/sync_registry_advisories.py --write` and open a PR.",
        "",
        "| Package | Missing | fixed_in to fill |",
        "|---|---|---|",
    ]
    for name in sorted(changes):
        c = changes[name]
        fills = ", ".join(f"{k}→{v}" for k, v in sorted(c["filled"].items())) or "—"
        lines.append(f"| `{name}` | {', '.join(c['added']) or '—'} | {fills} |")
    return "\n".join(lines) + "\n"


def write_registry(path: Path, registry: dict[str, Any], today: str) -> None:
    registry["last_updated"] = today
    registry["entry_count"] = len(registry.get("entries", []))
    path.write_text(
        json.dumps(registry, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )


# ── CLI ────────────────────────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="report only (default)")
    mode.add_argument("--write", action="store_true", help="merge missing advisories")
    parser.add_argument("--registry", type=Path, default=REGISTRY_PATH)
    parser.add_argument("--out", type=Path, help="write the proposed registry here")
    parser.add_argument("--summary", type=Path, help="append a markdown summary here")
    parser.add_argument("--today", default=dt.date.today().isoformat())
    args = parser.parse_args(argv)

    registry = json.loads(args.registry.read_text(encoding="utf-8"))
    try:
        changes = sync(registry)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    summary = render_summary(changes)
    print(summary)
    if args.summary:
        with args.summary.open("a", encoding="utf-8") as fh:
            fh.write(summary)
    if args.out and changes:
        write_registry(args.out, registry, args.today)
    if args.write:
        if changes:
            write_registry(args.registry, registry, args.today)
        return 0
    return 1 if changes else 0


if __name__ == "__main__":
    sys.exit(main())
