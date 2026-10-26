"""Known-malicious package names: OSV ``MAL-*`` records, matched offline (SC-008).

STORY-0097.  ``registry/known-malicious.json`` is a mirror of the OSV
malicious-package records (OpenSSF ``malicious-packages`` project, served by
OSV under ``MAL-*`` IDs) for npm and PyPI packages whose name contains
``mcp`` or that the known-server registry lists.  It is written by
``scripts/sync_registry_advisories.py --write`` and shipped inside the wheel
and the PyInstaller binaries, so a plain ``scan`` or ``vet`` matches it with
no network call.  Before this file, the only way to see these records was
``scan --check-vulns``.

Matching is by exact name in one ecosystem: npm names lowercased, PyPI names
PEP 503 normalised.  An npm record never matches a PyPI launch of the same
name (npm ``mcp-server-git`` is ``MAL-2026-5478``; Anthropic's PyPI
``mcp-server-git`` is the official server).

Versions follow OSV semantics (an explicit ``versions`` list, plus ``ranges``
evaluated in event order), with one documented exception: for a package the
known-server registry lists, a range that says *every* version
(``introduced: "0"`` and nothing else) is ignored when the record also lists
explicit versions.  GitHub's malware advisories use that blanket range even
for a single compromised release of a real package (``@browserbasehq/mcp``:
OSV ``MAL-2025-191195`` lists ``2.1.1`` beside a blanket range, while npm
still serves the clean ``3.0.0``).  The registry is mcp-audit's statement that
the package as a whole is legitimate, so the explicit list wins there.

The loader is tolerant: a missing or malformed file yields an empty index
(``load_error`` says why) instead of breaking every scan.  Tests pin that the
shipped file loads with records in it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from packaging.version import InvalidVersion, Version

from mcp_audit.registry.loader import normalize_pypi_name

Ecosystem = Literal["npm", "pypi"]

_OSV_ECOSYSTEMS: dict[str, Ecosystem] = {"npm": "npm", "pypi": "pypi"}

# Budgets.  The shipped file is ~90 KB and ~220 entries; these caps only
# matter for a corrupt or substituted file, and hitting one is reported in
# ``load_error`` (and from there in ``ScanResult.errors``), never silent.
MAX_FILE_BYTES = 32 * 1024 * 1024
MAX_ENTRIES = 50_000


def _resolve_bundled_path() -> Path:
    """Locate the bundled ``known-malicious.json`` in any execution context.

    Delegates to :func:`~mcp_audit._paths.resolve_bundled_resource`:
    PyInstaller ``_MEIPASS/registry/``, then the installed wheel
    (``mcp_audit/registry/known-malicious.json``), then the repo root.
    """
    from mcp_audit._paths import resolve_bundled_resource  # noqa: PLC0415

    dev_fallback = (
        Path(__file__).parent.parent.parent.parent / "registry" / "known-malicious.json"
    )
    found = resolve_bundled_resource(
        package="mcp_audit.registry",
        subdir="known-malicious.json",
        frozen_subpath="registry/known-malicious.json",
        dev_fallback=dev_fallback,
    )
    return found if found is not None else dev_fallback


def _key(ecosystem: Ecosystem, name: str) -> tuple[Ecosystem, str]:
    if ecosystem == "pypi":
        return ecosystem, normalize_pypi_name(name)
    return ecosystem, name.lower()


# ── Records ────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class MaliciousRecord:
    """One OSV ``MAL-*`` record for one package.

    Attributes:
        id: The OSV ID, e.g. ``MAL-2026-5479``.
        ecosystem: ``"npm"`` or ``"pypi"``.
        name: The package name as OSV gives it.
        aliases: Other IDs for the same record (``GHSA-…``).
        summary: OSV's one-line summary.
        published: OSV's ``published`` timestamp, if any.
        versions: Explicitly listed affected versions.
        ranges: Each range's events, as ``((kind, version), …)`` tuples in
            file order; ``kind`` is ``introduced``, ``fixed`` or
            ``last_affected``.
        note: mcp-audit's own context note, if the sync script added one.
    """

    id: str
    ecosystem: Ecosystem
    name: str
    aliases: tuple[str, ...] = ()
    summary: str = ""
    published: str | None = None
    versions: tuple[str, ...] = ()
    ranges: tuple[tuple[tuple[str, str], ...], ...] = ()
    note: str | None = None

    @property
    def link(self) -> str:
        """The record's public page on osv.dev."""
        return f"https://osv.dev/vulnerability/{self.id}"


def _parse_record(raw: dict[str, Any]) -> MaliciousRecord | None:
    """Build a record from one ``entries`` item, or ``None`` if unusable."""
    if not isinstance(raw, dict) or raw.get("withdrawn"):
        return None
    rid = raw.get("id")
    name = raw.get("name")
    eco = _OSV_ECOSYSTEMS.get(str(raw.get("ecosystem", "")).lower())
    if not isinstance(rid, str) or not isinstance(name, str) or eco is None:
        return None
    ranges: list[tuple[tuple[str, str], ...]] = []
    for rng in raw.get("ranges") or []:
        if not isinstance(rng, dict):
            continue
        events: list[tuple[str, str]] = []
        for event in rng.get("events") or []:
            if not isinstance(event, dict):
                continue
            for kind in ("introduced", "fixed", "last_affected"):
                if isinstance(event.get(kind), str):
                    events.append((kind, event[kind]))
        if events:
            ranges.append(tuple(events))
    return MaliciousRecord(
        id=rid,
        ecosystem=eco,
        name=name,
        aliases=tuple(str(a) for a in raw.get("aliases") or []),
        summary=str(raw.get("summary") or ""),
        published=raw.get("published")
        if isinstance(raw.get("published"), str)
        else None,
        versions=tuple(str(v) for v in raw.get("versions") or []),
        ranges=tuple(ranges),
        note=raw.get("note") if isinstance(raw.get("note"), str) else None,
    )


# ── Version assessment ─────────────────────────────────────────────────────────


def _is_blanket(events: tuple[tuple[str, str], ...]) -> bool:
    """A range that says every version: ``introduced: "0"`` and nothing else."""
    return events == (("introduced", "0"),)


def _is_open_ended(events: tuple[tuple[str, str], ...]) -> bool:
    """True when the newest release is inside the range (no fix after it)."""
    return not any(kind in ("fixed", "last_affected") for kind, _ in events)


def _version(value: str) -> Version | None:
    if value == "0":
        return Version("0")
    try:
        return Version(value)
    except InvalidVersion:
        return None


def _range_covers(events: tuple[tuple[str, str], ...], version: str) -> bool | None:
    """Evaluate one OSV range for *version*; ``None`` when a version won't parse.

    OSV's evaluation: walk the events in version order; ``introduced`` turns
    affected on at that version, ``fixed`` turns it off at that version, and
    ``last_affected`` turns it off just after.
    """
    if _is_blanket(events):
        return True
    target = _version(version)
    if target is None:
        return None
    parsed: list[tuple[Version, str]] = []
    for kind, value in events:
        bound = _version(value)
        if bound is None:
            return None
        parsed.append((bound, kind))
    affected = False
    for bound, kind in sorted(parsed, key=lambda item: item[0]):
        if kind == "introduced" and target >= bound:
            affected = True
        elif (kind == "fixed" and target >= bound) or (
            kind == "last_affected" and target > bound
        ):
            affected = False
    return affected


def _same_version(a: str, b: str) -> bool:
    if a == b:
        return True
    va, vb = _version(a), _version(b)
    return va is not None and vb is not None and va == vb


@dataclass(frozen=True)
class MaliciousMatch:
    """How one record applies to one configured launch.

    Attributes:
        record: The matched record.
        latest_affected: ``True`` when OSV marks every release, or every
            release from some version on, so an unpinned launch installs an
            affected one.
        pinned: The exact version the launch pins, or ``None``.
        blanket_range_ignored: ``True`` when the curated-package exception
            dropped a blanket range (see the module docstring).
    """

    record: MaliciousRecord
    latest_affected: bool
    pinned: str | None
    blanket_range_ignored: bool = False

    @property
    def affects_this_launch(self) -> bool:
        """``True`` when the configured launch installs a listed release."""
        return self.pinned is not None or self.latest_affected


def assess(
    record: MaliciousRecord,
    pinned: str | None,
    *,
    curated: bool,
) -> MaliciousMatch | None:
    """Decide how *record* applies to a launch that pins *pinned* (or nothing).

    Args:
        record: The OSV record for the configured package.
        pinned: The exact version the launch pins, or ``None`` when unpinned.
        curated: ``True`` when the known-server registry lists this package
            in the same ecosystem (enables the blanket-range exception).

    Returns:
        A :class:`MaliciousMatch`, or ``None`` when the launch pins a version
        the record does not cover.  A version that won't parse is treated as
        covered (conservative, like SC-004).
    """
    ranges = record.ranges
    ignored = False
    if curated and record.versions and any(_is_blanket(r) for r in ranges):
        ranges = tuple(r for r in ranges if not _is_blanket(r))
        ignored = True
    latest = any(_is_open_ended(r) for r in ranges)
    if pinned is None:
        if not latest and not record.versions and not ranges:
            return None
        return MaliciousMatch(record, latest, None, ignored)
    covered = any(_same_version(pinned, v) for v in record.versions) or any(
        _range_covers(r, pinned) is not False for r in ranges
    )
    if not covered:
        return None
    return MaliciousMatch(record, latest, pinned, ignored)


# ── Index ──────────────────────────────────────────────────────────────────────


@dataclass
class KnownMaliciousPackages:
    """In-memory index of ``known-malicious.json``.

    Attributes:
        records: Every usable record, in file order.
        last_updated: The file's ``last_updated`` date, or ``None``.
        source: Path the index was read from, or ``None`` when built in memory.
        load_error: Why the file could not be read, or ``None``.
    """

    records: list[MaliciousRecord] = field(default_factory=list)
    last_updated: str | None = None
    source: Path | None = None
    load_error: str | None = None

    def __post_init__(self) -> None:
        self._index: dict[tuple[Ecosystem, str], list[MaliciousRecord]] = {}
        for record in self.records:
            self._index.setdefault(_key(record.ecosystem, record.name), []).append(
                record
            )

    def lookup(self, ecosystem: Ecosystem, name: str) -> list[MaliciousRecord]:
        """Return every record for *name* in *ecosystem* (exact match).

        Args:
            ecosystem: ``"npm"`` or ``"pypi"``.
            name: Package name without a version suffix.

        Returns:
            Matching records, possibly empty.
        """
        if not name:
            return []
        return list(self._index.get(_key(ecosystem, name), []))

    def __len__(self) -> int:
        return len(self.records)


def load_known_malicious(path: Path | None = None) -> KnownMaliciousPackages:
    """Load ``known-malicious.json`` from *path* or the bundled location.

    Never raises: a missing or malformed file gives an empty index with
    ``load_error`` set.  Individual malformed or withdrawn entries are skipped.

    Args:
        path: Explicit file path (tests).  ``None`` uses the bundled file.

    Returns:
        A :class:`KnownMaliciousPackages` index.
    """
    resolved: Path | None = None
    try:
        resolved = path.resolve() if path is not None else _resolve_bundled_path()
        size = resolved.stat().st_size
        if size > MAX_FILE_BYTES:
            return KnownMaliciousPackages(
                source=resolved,
                load_error=f"file is {size} bytes, over the {MAX_FILE_BYTES}-byte cap",
            )
        data = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, ValueError, RuntimeError) as exc:
        # RuntimeError: Path.resolve() on a symlink loop (Python < 3.13).
        return KnownMaliciousPackages(source=resolved, load_error=str(exc))
    if not isinstance(data, dict) or not isinstance(data.get("entries"), list):
        return KnownMaliciousPackages(
            source=resolved, load_error="no 'entries' list in file"
        )
    raw_entries = data["entries"]
    error = None
    if len(raw_entries) > MAX_ENTRIES:
        error = (
            f"{len(raw_entries)} entries, over the {MAX_ENTRIES}-entry cap; "
            f"only the first {MAX_ENTRIES} were loaded"
        )
        raw_entries = raw_entries[:MAX_ENTRIES]
    records = [r for r in (_parse_record(e) for e in raw_entries) if r is not None]
    updated = data.get("last_updated")
    return KnownMaliciousPackages(
        records=records,
        last_updated=updated if isinstance(updated, str) else None,
        source=resolved,
        load_error=error,
    )
