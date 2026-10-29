"""The per-server decision for ``mcp-audit affected``.

Three outcomes, never collapsed: **AFFECTED**, **NOT AFFECTED** and
**COULDN'T CHECK**.  A server is NOT AFFECTED only when mcp-audit can show
why: it runs a different package than the advisory concerns, or it runs the
named package at a version the advisory does not cover.  Anything it cannot
order or evaluate (a floating ``npx -y pkg``, a calendar version against a
semantic fix, a range with an unparsable bound) is COULDN'T CHECK, with the
reason in the row.

Versions come from the launch command's exact pin, then from the nearest
``mcp-lock.json`` ``resolved_version`` (or one passed with ``--lock``).  No
semver range is resolved and no package manager is run.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

from packaging.version import InvalidVersion, Version

from mcp_audit.affected.query import Query
from mcp_audit.analyzers.supply_chain import (
    _fix_status,
    _pinned_version,
    _schemes_differ,
    launch_package,
    resolve_launch_entry,
)
from mcp_audit.lock.discovery import find_lock_for
from mcp_audit.lock.writer import load_existing as load_lock
from mcp_audit.models import Finding, ServerConfig, Severity
from mcp_audit.registry.loader import (
    KnownServerRegistry,
    RegistryEntry,
    normalize_pypi_name,
)
from mcp_audit.registry.malicious import (
    KnownMaliciousPackages,
    MaliciousRecord,
    _is_blanket,
    _is_open_ended,
    _parse_record,
    _range_covers,
    _same_version,
)
from mcp_audit.registry.research import ResearchRecord

MAX_LOCK_BYTES = 8 * 1024 * 1024


class Status(StrEnum):
    """The three outcomes."""

    AFFECTED = "AFFECTED"
    NOT_AFFECTED = "NOT AFFECTED"
    COULDNT_CHECK = "COULDN'T CHECK"


# Reasons a row is COULDN'T CHECK / NOT AFFECTED.  ``NO_PACKAGE`` is the one
# unknown that never fails ``--fail-on-unknown``: the launch names no package,
# so there is nothing to compare.
VERSION_UNKNOWN = "version-unknown"
UNDECIDABLE = "undecidable"
UNEVALUABLE = "unevaluable"
NO_PACKAGE = "no-package"
HARNESS_VERSION = "harness-version"
POSTURE_ONLY = "posture-only"
OTHER_PACKAGE = "other-package"
VERSION_OUTSIDE = "version-outside"


@dataclass(frozen=True)
class Row:
    """One answer: a server, or a harness or plugin for a research record."""

    subject: str
    status: Status
    evidence: str
    config_path: str | None = None
    package: str | None = None
    version: str | None = None
    version_source: str | None = None
    fixed_in: str | None = None
    reason: str | None = None


@dataclass(frozen=True)
class Decision:
    """A rule's verdict on one launch."""

    status: Status
    evidence: str
    reason: str | None = None
    fixed_in: str | None = None


@dataclass
class Report:
    """Everything one ``affected`` run produced."""

    query: Query
    rows: list[Row] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    live: bool = False

    def count(self, status: Status) -> int:
        """Rows with *status*."""
        return sum(1 for r in self.rows if r.status is status)

    def blocking_unknown(self) -> int:
        """COULDN'T CHECK rows where a package was identified (gate material)."""
        return sum(
            1
            for r in self.rows
            if r.status is Status.COULDNT_CHECK and r.reason != NO_PACKAGE
        )

    def needs_version(self) -> int:
        """COULDN'T CHECK rows that a pin or a lock would settle."""
        return sum(1 for r in self.rows if r.reason == VERSION_UNKNOWN)

    def exit_code(self, *, fail_on_unknown: bool = False) -> int:
        """0 nothing affected, 1 something affected (or unknown with the flag)."""
        if self.count(Status.AFFECTED):
            return 1
        if fail_on_unknown and self.blocking_unknown():
            return 1
        return 0


# ── Versions ───────────────────────────────────────────────────────────────────


def _parses(version: str) -> bool:
    try:
        Version(version)
    except InvalidVersion:
        return False
    return True


def _name_key(ecosystem: str, name: str) -> str:
    return normalize_pypi_name(name) if ecosystem == "pypi" else name.lower()


class LockIndex:
    """``resolved_version`` lookups: ``--lock`` files, then the nearest lock."""

    def __init__(self, explicit: Iterable[Path] = (), errors: list[str] | None = None):
        self._explicit: list[tuple[Path, dict]] = []
        self._by_config: dict[Path, tuple[Path, dict] | None] = {}
        self._errors = errors if errors is not None else []
        for path in explicit:
            doc = self._read(path)
            if doc is not None:
                self._explicit.append((path, doc))

    def _read(self, path: Path) -> dict | None:
        try:
            if path.stat().st_size > MAX_LOCK_BYTES:
                self._errors.append(f"lock {path.name} is over {MAX_LOCK_BYTES} bytes")
                return None
        except OSError as exc:
            self._errors.append(f"lock {path.name} could not be read: {exc.strerror}")
            return None
        doc = load_lock(path)
        if doc is None:
            self._errors.append(f"lock {path.name} is not a readable lock file")
        return doc

    def _nearest(self, config_path: Path) -> tuple[Path, dict] | None:
        if config_path not in self._by_config:
            found = find_lock_for(config_path)
            doc = self._read(found) if found is not None else None
            self._by_config[config_path] = (found, doc) if found and doc else None
        return self._by_config[config_path]

    def resolved(
        self, server: ServerConfig, ecosystem: str, package: str
    ) -> tuple[str, str] | None:
        """``(version, source)`` the lock recorded for this server, or ``None``."""
        key = f"{server.client}/{server.name}"
        sources = list(self._explicit)
        nearest = self._nearest(server.config_path)
        if nearest is not None:
            sources.append(nearest)
        for path, doc in sources:
            servers = doc.get("servers")
            entry = servers.get(key) if isinstance(servers, dict) else None
            pkg = entry.get("package") if isinstance(entry, dict) else None
            if not isinstance(pkg, dict):
                continue
            version = pkg.get("resolved_version")
            name = pkg.get("name")
            if not isinstance(version, str) or not version:
                continue
            if isinstance(name, str) and _name_key(ecosystem, name) != _name_key(
                ecosystem, package
            ):
                continue
            return version, f"lock resolved_version ({path.name})"
        return None


def server_version(
    server: ServerConfig, ecosystem: str, package: str, locks: LockIndex
) -> tuple[str | None, str | None]:
    """The version this launch installs, and where that came from."""
    pinned = _pinned_version(server)
    if pinned is not None:
        return pinned, "config pin"
    found = locks.resolved(server, ecosystem, package)
    return found if found is not None else (None, None)


# ── Rules ──────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Launch:
    """One server's launch facts handed to a rule."""

    ecosystem: str
    package: str
    version: str | None
    source: str | None
    entry: RegistryEntry | None


_NO_VERSION = Decision(
    Status.COULDNT_CHECK,
    "the launch pins no exact version and no lock records one; pin it or run "
    "`mcp-audit lock`",
    VERSION_UNKNOWN,
)


def _unorderable(version: str, other: str) -> Decision:
    return Decision(
        Status.COULDNT_CHECK,
        f"{version} and {other} cannot be ordered offline (one is not a version "
        "mcp-audit can parse, or they use calendar and semantic numbering)",
        UNDECIDABLE,
    )


@dataclass(frozen=True)
class RegistryRule:
    """A CVE recorded against a registry entry (``known_vulns``)."""

    entry_name: str
    advisory: str
    fixed_in: str | None

    def matches(self, launch: Launch) -> bool:
        """The launch resolves to this registry entry."""
        return launch.entry is not None and launch.entry.name == self.entry_name

    def describes(self) -> str:
        """The package this rule is about."""
        return self.entry_name

    def decide(self, launch: Launch) -> Decision:
        """AFFECTED below the recorded fix, NOT AFFECTED at or above it."""
        version = launch.version
        if version is None:
            return _NO_VERSION
        if not _parses(version):
            return _unorderable(version, self.fixed_in or "the fix")
        if self.fixed_in is None:
            return Decision(
                Status.AFFECTED,
                f"{version} ({launch.source}); the registry records "
                f"{self.advisory} against {self.entry_name} and no fixed version",
            )
        if not _parses(self.fixed_in):
            return _unorderable(version, self.fixed_in)
        resumed = launch.entry.semver_resumed_at if launch.entry else None
        status = _fix_status(version, self.fixed_in, resumed)
        if status == "undecidable":
            return _unorderable(version, self.fixed_in)
        if status == "affected":
            return Decision(
                Status.AFFECTED,
                f"{version} ({launch.source}) is below {self.advisory}'s fixed "
                f"version {self.fixed_in} (registry)",
                fixed_in=self.fixed_in,
            )
        return Decision(
            Status.NOT_AFFECTED,
            f"{version} ({launch.source}) is at or above {self.advisory}'s fixed "
            f"version {self.fixed_in} (registry)",
            VERSION_OUTSIDE,
            self.fixed_in,
        )


@dataclass(frozen=True)
class RecordRule:
    """An OSV package record: a ``MAL-*`` mirror entry or a live-fetched record."""

    record: MaliciousRecord
    curated: bool

    def matches(self, launch: Launch) -> bool:
        """Same ecosystem and package."""
        return launch.ecosystem == self.record.ecosystem and _name_key(
            launch.ecosystem, launch.package
        ) == _name_key(self.record.ecosystem, self.record.name)

    def describes(self) -> str:
        """The package this rule is about."""
        return f"{self.record.ecosystem}:{self.record.name}"

    def decide(self, launch: Launch) -> Decision:
        """Evaluate the record's explicit versions and ranges, OSV-style."""
        record = self.record
        ranges = record.ranges
        if self.curated and record.versions and any(_is_blanket(r) for r in ranges):
            ranges = tuple(r for r in ranges if not _is_blanket(r))
        version = launch.version
        if version is None:
            if any(_is_open_ended(r) for r in ranges):
                return Decision(
                    Status.AFFECTED,
                    f"{record.id} lists every release from some version on, so an "
                    "unpinned launch installs an affected one",
                )
            return _NO_VERSION
        if not _parses(version):
            return _unorderable(version, record.id)
        if any(_same_version(version, v) for v in record.versions):
            return Decision(
                Status.AFFECTED,
                f"{version} ({launch.source}) is a version {record.id} lists",
            )
        results = [_range_covers(r, version) for r in ranges]
        if any(r is True for r in results):
            return Decision(
                Status.AFFECTED,
                f"{version} ({launch.source}) is inside a range {record.id} lists",
            )
        if any(r is None for r in results):
            return Decision(
                Status.COULDNT_CHECK,
                f"{record.id} has a range with a version bound mcp-audit cannot parse",
                UNEVALUABLE,
            )
        return Decision(
            Status.NOT_AFFECTED,
            f"{version} ({launch.source}) is outside every version and range "
            f"{record.id} lists",
            VERSION_OUTSIDE,
        )


@dataclass(frozen=True)
class RangeRule:
    """The user's own ``package@range``."""

    package: str
    specifier: Any  # packaging.specifiers.SpecifierSet
    text: str

    def matches(self, launch: Launch) -> bool:
        """Same package name (npm lowercased, PyPI normalised)."""
        return _name_key(launch.ecosystem, launch.package) == _name_key(
            launch.ecosystem, self.package
        )

    def describes(self) -> str:
        """The package this rule is about."""
        return self.package

    def decide(self, launch: Launch) -> Decision:
        """Every comparator must hold; calendar against semantic is unknown."""
        version = launch.version
        if version is None:
            return _NO_VERSION
        if not _parses(version):
            return _unorderable(version, self.text)
        resumed = launch.entry.semver_resumed_at if launch.entry else None
        holds = True
        for spec in self.specifier:
            bound = spec.version
            if _parses(bound.replace(".*", "")) and _schemes_differ(
                version, bound.replace(".*", "")
            ):
                if spec.operator not in ("<", "<="):
                    return _unorderable(version, bound)
                status = _fix_status(version, bound, resumed)
                if status == "undecidable":
                    return _unorderable(version, bound)
                holds = holds and status == "affected"
            else:
                holds = holds and spec.contains(version, prereleases=True)
        if holds:
            return Decision(
                Status.AFFECTED,
                f"{version} ({launch.source}) satisfies {self.text}",
            )
        return Decision(
            Status.NOT_AFFECTED,
            f"{version} ({launch.source}) does not satisfy {self.text}",
            VERSION_OUTSIDE,
        )


Rule = RegistryRule | RecordRule | RangeRule


@dataclass
class RuleSet:
    """What an advisory ID resolved to in the bundled data."""

    rules: list[Rule] = field(default_factory=list)
    research: ResearchRecord | None = None
    sources: list[str] = field(default_factory=list)

    @property
    def found(self) -> bool:
        """The ID is known to at least one source."""
        return bool(self.rules) or self.research is not None


def rules_for_range(query: Query) -> RuleSet:
    """The single rule a ``pkg@range`` query makes."""
    assert query.package is not None and query.specifier is not None  # noqa: S101
    return RuleSet(rules=[RangeRule(query.package, query.specifier, query.text)])


def rules_for_advisory(
    advisory_id: str,
    registry: KnownServerRegistry,
    malicious: KnownMaliciousPackages,
    research: Any,
) -> RuleSet:
    """Resolve an ID against the registry, the malicious mirror and research records."""
    wanted = advisory_id.upper()
    out = RuleSet()
    record = research.lookup(advisory_id)
    if record is not None:
        out.research = record
        out.sources.append("research records")
    for entry in registry.entries:
        fixed: dict[str, str | None] = {}
        for item in entry.known_vulns or []:
            cve = item.get("cve") if isinstance(item, dict) else None
            if isinstance(cve, str) and cve.upper() == wanted:
                fx = item.get("fixed_in")
                fixed[cve] = str(fx) if fx else None
        for cve in entry.known_vulnerabilities or []:
            if isinstance(cve, str) and cve.upper() == wanted:
                fixed.setdefault(cve, None)
        for cve, fixed_in in fixed.items():
            out.rules.append(RegistryRule(entry.name, cve, fixed_in))
    if any(isinstance(r, RegistryRule) for r in out.rules):
        out.sources.append(f"registry (updated {registry.last_updated})")
    mal = [
        r
        for r in malicious.records
        if r.id.upper() == wanted or wanted in {a.upper() for a in r.aliases}
    ]
    for r in mal:
        curated = (
            registry.get_npm(r.name)
            if r.ecosystem == "npm"
            else registry.get_pypi(r.name)
        ) is not None
        out.rules.append(RecordRule(r, curated))
    if mal:
        out.sources.append("known-malicious mirror")
    return out


def records_from_osv(osv: dict[str, Any]) -> list[MaliciousRecord]:
    """Turn a fetched OSV record into one package record per npm / PyPI package.

    Only ``affected[]`` items with an npm or PyPI package and ``SEMVER`` or
    ``ECOSYSTEM`` ranges are used; ``GIT`` ranges name commits, which mcp-audit
    cannot order, and are skipped.
    """
    out: list[MaliciousRecord] = []
    rid = osv.get("id")
    if not isinstance(rid, str):
        return out
    for item in osv.get("affected") or []:
        pkg = item.get("package") if isinstance(item, dict) else None
        if not isinstance(pkg, dict):
            continue
        raw = {
            "id": rid,
            "name": pkg.get("name"),
            "ecosystem": pkg.get("ecosystem"),
            "aliases": osv.get("aliases") or [],
            "summary": osv.get("summary") or "",
            "published": osv.get("published"),
            "versions": item.get("versions") or [],
            "ranges": [
                r
                for r in item.get("ranges") or []
                if isinstance(r, dict) and r.get("type") in ("SEMVER", "ECOSYSTEM")
            ],
        }
        rec = _parse_record(raw)
        if rec is not None:
            out.append(rec)
    return out


# ── Servers ────────────────────────────────────────────────────────────────────

_RANK = {Status.AFFECTED: 0, Status.COULDNT_CHECK: 1, Status.NOT_AFFECTED: 2}


def decide_server(
    server: ServerConfig,
    rules: list[Rule],
    registry: KnownServerRegistry,
    locks: LockIndex,
    label: str,
) -> Row:
    """Answer for one server."""
    subject = f"{server.client}/{server.name}"
    where = str(server.config_path)
    found = launch_package(server)
    if found is None:
        how = (
            "a remote URL"
            if server.url and not server.command
            else f"'{Path(server.command or 'unknown').name}'"
        )
        return Row(
            subject,
            Status.COULDNT_CHECK,
            f"the launch ({how}) names no npm or PyPI package mcp-audit can read",
            config_path=where,
            reason=NO_PACKAGE,
        )
    ecosystem, package = found
    entry = resolve_launch_entry(server, registry)
    plain = Launch(ecosystem, package, None, None, entry)
    applicable = [r for r in rules if r.matches(plain)]
    pkg_id = f"{ecosystem}:{package}"
    if not applicable:
        concerns = ", ".join(sorted({r.describes() for r in rules})) or "other packages"
        return Row(
            subject,
            Status.NOT_AFFECTED,
            f"runs {pkg_id}; {label} concerns {concerns}",
            config_path=where,
            package=pkg_id,
            reason=OTHER_PACKAGE,
        )
    version, source = server_version(server, ecosystem, package, locks)
    launch = Launch(ecosystem, package, version, source, entry)
    decisions = sorted(
        (r.decide(launch) for r in applicable), key=lambda d: _RANK[d.status]
    )
    best = decisions[0]
    return Row(
        subject,
        best.status,
        best.evidence,
        config_path=where,
        package=pkg_id,
        version=version,
        version_source=source,
        fixed_in=best.fixed_in,
        reason=best.reason,
    )


def decide_servers(
    servers: Iterable[ServerConfig],
    ruleset: RuleSet,
    registry: KnownServerRegistry,
    locks: LockIndex,
    label: str,
) -> list[Row]:
    """One row per server, in discovery order."""
    return [decide_server(s, ruleset.rules, registry, locks, label) for s in servers]


# ── Research records ───────────────────────────────────────────────────────────

_PRODUCT_STATUS = {
    "fixed": "fixed in {fixed_in}",
    "unfixed": "not fixed at disclosure",
    "wontfix": "not going to be fixed (vendor statement)",
}


def research_rows(
    record: ResearchRecord,
    check_findings: Callable[[], list[Finding]] | None,
    notes: list[str],
) -> list[Row]:
    """Rows for a research record: check results, then one row per product.

    A record about harness versions cannot be answered per product, because
    mcp-audit does not read which Claude Code or Codex is installed (queued
    behind this epic), so every product row is COULDN'T CHECK.  The named
    checks run where they can; a HIGH-or-worse hit is AFFECTED, anything
    milder is listed as COULDN'T CHECK (posture only).  No check result ever
    produces NOT AFFECTED: the checks cover Claude Code's plugin directory
    only.
    """
    rows: list[Row] = []
    findings = check_findings() if check_findings is not None else []
    hits = [f for f in findings if f.id in record.checks]
    for f in hits:
        severe = f.severity in (Severity.CRITICAL, Severity.HIGH)
        rows.append(
            Row(
                f"{f.client}/{f.server}",
                Status.AFFECTED if severe else Status.COULDNT_CHECK,
                f"{f.id} {f.severity.value}: {f.title}",
                config_path=f.finding_path,
                reason=None if severe else POSTURE_ONLY,
            )
        )
    if check_findings is None:
        notes.append(
            f"The {'/'.join(record.checks) or 'record'} checks were not run "
            "(they read Claude Code's plugin directory; not run with --path)."
        )
    elif not any(r.status is Status.AFFECTED for r in rows):
        notes.append(
            f"No {'/'.join(record.checks) or 'check'} result shows the swap on "
            "Claude Code's plugin checkouts; that is not a clean bill for the "
            "other harnesses or for installs that kept no .git."
        )
    for p in record.products:
        state = _PRODUCT_STATUS[p.status].format(fixed_in=p.fixed_in)
        rows.append(
            Row(
                f"{p.product} ({p.vendor})",
                Status.COULDNT_CHECK,
                f"mcp-audit does not read which {p.product} version is "
                f"installed; per the write-up: {state}",
                reason=HARNESS_VERSION,
                fixed_in=p.fixed_in,
            )
        )
    return rows
