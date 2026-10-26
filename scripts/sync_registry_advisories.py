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
* Withdrawn records and ``MAL-*`` malicious-package records are skipped
  here: a malicious release is a different finding class from a CVE.  They
  go to ``registry/known-malicious.json`` instead (below).
* ``fixed_in`` is the highest ``fixed`` version across the package's ranges,
  and is left unset when any range has no fix.  Taking the highest is
  conservative: a pinned version fixed on an older branch may still be
  reported, but no affected version is missed.

Known-malicious packages (STORY-0097).  The same run mirrors OSV's ``MAL-*``
records into ``registry/known-malicious.json`` (next to ``--registry``, or
``--malicious``), which SC-008 and ``vet`` match offline by exact name.  OSV's
per-package query can't find a malicious package nobody has named yet, so
this part reads OSV's bulk export instead (``<ecosystem>/all.zip`` for npm and
PyPI, about 260 MB together, read once per run) and keeps every record that:

* has an ``MAL-`` ID and is not withdrawn, and
* names an npm or PyPI package whose name contains ``mcp`` (any case), or
  that ``known-servers.json`` lists.  The test is a plain substring on
  purpose: a match is by exact package name, so an extra record can never
  cause a false positive, and a token rule would drop real MCP names such as
  ``timemcp`` and ``livemcp``.

Unlike the CVE merge, this file is a mirror, not additive: a record OSV
withdraws or deletes is removed, because keeping it would keep accusing the
package.  Each entry keeps OSV's ``id``, ``aliases``, ``summary``,
``published``, ``versions`` and ``ranges`` as OSV states them (lists sorted
for a stable diff); ``modified`` is left out so a re-import that changes
nothing else does not churn the file.  ``NOTES`` adds mcp-audit's own context
to a few records, in a separate ``note`` field.

Known limit: unreviewed GitHub advisories carry no package data, so OSV does
not map them to a package until GitHub reviews them.  NVD-only CVEs are not
covered either.  Those still need adding by hand.

Usage:
    python scripts/sync_registry_advisories.py            # check
    python scripts/sync_registry_advisories.py --write    # update the files
    python scripts/sync_registry_advisories.py --summary "$GITHUB_STEP_SUMMARY"
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
import tempfile
import urllib.error
import urllib.request
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
REGISTRY_PATH = REPO_ROOT / "registry" / "known-servers.json"
OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_EXPORT_URL = "https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip"
MALICIOUS_FILENAME = "known-malicious.json"
MALICIOUS_ECOSYSTEMS = ("npm", "PyPI")
_ECOSYSTEMS = {"npm": "npm", "pip": "PyPI", "pypi": "PyPI"}
_DESCRIPTION_LIMIT = 200
_MAX_EXPORT_BYTES = 2 * 1024**3
_MAX_RECORD_BYTES = 5 * 1024**2

# mcp-audit's own context for specific MAL records, written to the record's
# ``note`` field.  Keep each note to facts with a source.
_CANARY_NOTE = (
    "All ten records MAL-2026-5476 to MAL-2026-5485 report the same "
    "install-time beacon host, npx-canary-log.vulnerable-live.workers.dev. "
    "Three of these npm packages (mcp-server-notion, mcp-server-redis, "
    "mcp-server-supabase), read on npm on 2026-08-18, named "
    "theinfosecguy/npx-canary as their repository and described themselves "
    "as a security research canary for an authorized bug bounty project "
    "(registry-audit-2026-08-18.md in the mcp-audit repository). That points "
    "to a researcher's canary rather than a criminal campaign; mcp-audit "
    "reports the record as OSV states it."
)
NOTES: dict[str, str] = {f"MAL-2026-{n}": _CANARY_NOTE for n in range(5476, 5486)}


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


# ── Known-malicious mirror (STORY-0097) ────────────────────────────────────────

Keep = Callable[[str, str], bool]


def _fold(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def package_selector(registry: dict[str, Any]) -> Keep:
    """Return ``keep(ecosystem, name)``: an MCP-named or registry-listed package.

    Args:
        registry: Parsed ``known-servers.json``.

    Returns:
        A predicate over an OSV ecosystem name (``npm``/``PyPI``) and package.
    """
    listed: set[tuple[str, str]] = set()
    for entry in registry.get("entries", []):
        eco = osv_ecosystem(entry)
        if eco:
            name = str(entry["name"])
            listed.add((eco, _fold(name) if eco == "PyPI" else name.lower()))

    def keep(ecosystem: str, name: str) -> bool:
        if "mcp" in name.lower():
            return True
        key = _fold(name) if ecosystem == "PyPI" else name.lower()
        return (ecosystem, key) in listed

    return keep


def _record_matches(record: dict[str, Any], ecosystem: str, keep: Keep) -> bool:
    for affected in record.get("affected") or []:
        pkg = affected.get("package") or {}
        if pkg.get("ecosystem") == ecosystem and keep(ecosystem, str(pkg.get("name", ""))):
            return True
    return False


def fetch_malicious_export(
    ecosystem: str, keep: Keep, timeout: int = 300
) -> list[dict[str, Any]]:
    """Download OSV's bulk export for *ecosystem* and return the kept MAL records.

    Raises:
        RuntimeError: when the export can't be downloaded or read.  The caller
            turns this into exit code 2, never a silent pass.
    """
    url = OSV_EXPORT_URL.format(ecosystem=ecosystem)
    kept: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "all.zip"
        try:
            # Constant https://osv-vulnerabilities.storage.googleapis.com URL.
            with (
                urllib.request.urlopen(url, timeout=timeout) as resp,  # noqa: S310  # nosec B310
                path.open("wb") as fh,
            ):
                total = 0
                while chunk := resp.read(1 << 20):
                    total += len(chunk)
                    if total > _MAX_EXPORT_BYTES:
                        raise RuntimeError(f"OSV export for {ecosystem} is too large")
                    fh.write(chunk)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise RuntimeError(f"OSV export download failed for {ecosystem}: {exc}") from exc
        try:
            with zipfile.ZipFile(path) as archive:
                for info in archive.infolist():
                    base = info.filename.rsplit("/", 1)[-1]
                    if not (base.startswith("MAL-") and base.endswith(".json")):
                        continue
                    if info.file_size > _MAX_RECORD_BYTES:
                        continue
                    record = json.loads(archive.read(info))
                    if _record_matches(record, ecosystem, keep):
                        kept.append(record)
        except (zipfile.BadZipFile, json.JSONDecodeError, KeyError, OSError) as exc:
            raise RuntimeError(f"OSV export for {ecosystem} is unreadable: {exc}") from exc
    return kept


def malicious_entries(
    records: list[dict[str, Any]], ecosystem: str, keep: Keep
) -> list[dict[str, Any]]:
    """Shape kept OSV records into ``known-malicious.json`` entries.

    One entry per (record, package); withdrawn and non-``MAL-`` records are
    dropped.  Lists are sorted so the file diffs cleanly.
    """
    entries: list[dict[str, Any]] = []
    for record in records:
        rid = str(record.get("id", ""))
        if not rid.startswith("MAL-") or record.get("withdrawn"):
            continue
        for affected in record.get("affected") or []:
            pkg = affected.get("package") or {}
            name = str(pkg.get("name", ""))
            if pkg.get("ecosystem") != ecosystem or not name or not keep(ecosystem, name):
                continue
            entry: dict[str, Any] = {
                "id": rid,
                "ecosystem": ecosystem,
                "name": name,
                "aliases": sorted(str(a) for a in record.get("aliases") or []),
                "summary": describe(record),
                "published": record.get("published"),
                "versions": sorted(
                    {str(v) for v in affected.get("versions") or []}, key=_version_key
                ),
                "ranges": [
                    {"type": rng.get("type"), "events": rng.get("events") or []}
                    for rng in affected.get("ranges") or []
                    if rng.get("type") in ("SEMVER", "ECOSYSTEM")
                ],
            }
            if rid in NOTES:
                entry["note"] = NOTES[rid]
            entries.append(entry)
    return entries


def _entry_key(entry: dict[str, Any]) -> tuple[str, str, str]:
    return (str(entry["ecosystem"]), str(entry["name"]).lower(), str(entry["id"]))


def sync_malicious(
    registry: dict[str, Any],
    existing: list[dict[str, Any]],
    fetch: Any = None,
) -> tuple[dict[str, list[str]], list[dict[str, Any]]]:
    """Compute the known-malicious mirror and how it differs from *existing*.

    Args:
        registry: Parsed ``known-servers.json`` (for the selection predicate).
        existing: ``entries`` of the current ``known-malicious.json``.
        fetch: ``(ecosystem, keep) -> list[osv record]``; injectable for tests.

    Returns:
        ``({"added": [...], "removed": [...], "changed": [...]}, entries)``,
        each list holding ``"<ID> <ecosystem>/<name>"`` labels; the dict is
        empty when nothing differs.
    """
    fetch = fetch or fetch_malicious_export
    keep = package_selector(registry)
    entries: list[dict[str, Any]] = []
    for ecosystem in MALICIOUS_ECOSYSTEMS:
        entries.extend(malicious_entries(fetch(ecosystem, keep), ecosystem, keep))
    entries.sort(key=_entry_key)

    def label(e: dict[str, Any]) -> str:
        return f"{e['id']} {e['ecosystem']}/{e['name']}"

    old = {_entry_key(e): e for e in existing if isinstance(e, dict) and "id" in e}
    new = {_entry_key(e): e for e in entries}
    diff = {
        "added": [label(new[k]) for k in sorted(new.keys() - old.keys())],
        "removed": [label(old[k]) for k in sorted(old.keys() - new.keys())],
        "changed": [
            label(new[k]) for k in sorted(new.keys() & old.keys()) if new[k] != old[k]
        ],
    }
    return ({k: v for k, v in diff.items() if v}, entries)


def load_malicious(path: Path) -> list[dict[str, Any]]:
    """Return the ``entries`` of an existing ``known-malicious.json`` (or ``[]``)."""
    if not path.is_file():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    return list(data.get("entries") or [])


def write_malicious(path: Path, entries: list[dict[str, Any]], today: str) -> None:
    """Write ``known-malicious.json`` with a header describing its source."""
    doc = {
        "schema_version": "1.0",
        "description": (
            "OSV malicious-package (MAL-*) records for npm and PyPI packages "
            "whose name contains 'mcp' or that registry/known-servers.json "
            "lists. Matched offline by exact name (SC-008, mcp-audit vet). "
            "Written by scripts/sync_registry_advisories.py --write; do not "
            "edit by hand."
        ),
        "source": "https://osv.dev (OpenSSF malicious-packages, via OSV's bulk export)",
        "last_updated": today,
        "entry_count": len(entries),
        "entries": entries,
    }
    path.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def render_malicious_summary(diff: dict[str, list[str]], total: int) -> str:
    """Markdown summary of the known-malicious mirror's drift."""
    if not diff:
        return (
            "## Known-malicious packages\n\n"
            f"No changes. `known-malicious.json` matches OSV ({total} records).\n"
        )
    lines = [
        "## Known-malicious packages",
        "",
        f"**{len(diff.get('added', []))} added, {len(diff.get('removed', []))} "
        f"removed, {len(diff.get('changed', []))} changed** "
        f"(OSV now has {total} matching records). "
        "Run `python scripts/sync_registry_advisories.py --write` and open a PR.",
        "",
    ]
    for kind in ("added", "removed", "changed"):
        items = diff.get(kind, [])
        if not items:
            continue
        lines.append(f"**{kind.capitalize()}:**")
        lines.extend(f"- `{item}`" for item in items[:50])
        if len(items) > 50:
            lines.append(f"- … and {len(items) - 50} more")
        lines.append("")
    return "\n".join(lines) + "\n"


# ── CLI ────────────────────────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="report only (default)")
    mode.add_argument("--write", action="store_true", help="merge missing advisories")
    parser.add_argument("--registry", type=Path, default=REGISTRY_PATH)
    parser.add_argument(
        "--malicious",
        type=Path,
        help=f"known-malicious file (default: {MALICIOUS_FILENAME} next to --registry)",
    )
    parser.add_argument("--out", type=Path, help="write the proposed registry here")
    parser.add_argument(
        "--malicious-out", type=Path, help="write the proposed known-malicious file here"
    )
    parser.add_argument("--summary", type=Path, help="append a markdown summary here")
    parser.add_argument("--today", default=dt.date.today().isoformat())
    args = parser.parse_args(argv)

    registry = json.loads(args.registry.read_text(encoding="utf-8"))
    malicious_path = args.malicious or args.registry.parent / MALICIOUS_FILENAME
    try:
        existing_malicious = load_malicious(malicious_path)
        changes = sync(registry)
        mal_diff, mal_entries = sync_malicious(registry, existing_malicious)
    except (RuntimeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    summary = render_summary(changes) + "\n" + render_malicious_summary(
        mal_diff, len(mal_entries)
    )
    print(summary)
    if args.summary:
        with args.summary.open("a", encoding="utf-8") as fh:
            fh.write(summary)
    if args.out and changes:
        write_registry(args.out, registry, args.today)
    if args.malicious_out and mal_diff:
        write_malicious(args.malicious_out, mal_entries, args.today)
    if args.write:
        if changes:
            write_registry(args.registry, registry, args.today)
        if mal_diff:
            write_malicious(malicious_path, mal_entries, args.today)
        return 0
    return 1 if changes or mal_diff else 0


if __name__ == "__main__":
    sys.exit(main())
