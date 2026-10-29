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

import json
import os
import re
import stat
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
from mcp_audit.registry.reachability import Tags, excludes_stdio, provably_stdio
from mcp_audit.registry.research import ResearchRecord

MAX_LOCK_BYTES = 8 * 1024 * 1024
# What a recorded version may look like; anything else (control characters,
# spaces, absurd length) is ignored rather than printed.
_VERSION_TEXT = re.compile(r"[0-9A-Za-z][0-9A-Za-z.+!_\-]{0,63}")
_PYPI_PIN_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._\-]*)(?:\[[^\]]*\])?==(?P<ver>[^=<>!~,;\s]+)$"
)


class Status(StrEnum):
    """The three outcomes."""

    AFFECTED = "AFFECTED"
    NOT_AFFECTED = "NOT AFFECTED"
    COULDNT_CHECK = "COULDN'T CHECK"


# Reasons a row is COULDN'T CHECK / NOT AFFECTED.  ``NO_PACKAGE`` rows are
# collapsed into a count in the terminal listing unless ``--all``.
VERSION_UNKNOWN = "version-unknown"
UNDECIDABLE = "undecidable"
UNEVALUABLE = "unevaluable"
NO_PACKAGE = "no-package"
HARNESS_VERSION = "harness-version"
POSTURE_ONLY = "posture-only"
OTHER_PACKAGE = "other-package"
VERSION_OUTSIDE = "version-outside"
UNREADABLE = "unreadable-config"
EXTRA_PACKAGES = "extra-packages"
NOT_REACHABLE = "not-reachable"
# A row with one of these reasons (or none) means a server really runs the
# advisory's package.
RAN_THE_PACKAGE = frozenset(
    {None, VERSION_OUTSIDE, VERSION_UNKNOWN, UNDECIDABLE, UNEVALUABLE, NOT_REACHABLE}
)


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
    #: Every version the advisory says fixes this, for ``affected --fix``.
    fixes: tuple[str, ...] = ()


@dataclass(frozen=True)
class Decision:
    """A rule's verdict on one launch."""

    status: Status
    evidence: str
    reason: str | None = None
    fixed_in: str | None = None
    fixes: tuple[str, ...] = ()


@dataclass
class Report:
    """Everything one ``affected`` run produced."""

    query: Query
    rows: list[Row] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    live: bool = False
    #: ``{"cve", "signals", "line"}`` when the query is a CVE (KEV/EPSS/PoC).
    exploit: dict | None = None
    #: A ``respond.Respond`` per AFFECTED server (STORY-0126).
    respond: list[Any] = field(default_factory=list)

    def count(self, status: Status) -> int:
        """Rows with *status*."""
        return sum(1 for r in self.rows if r.status is status)

    def blocking_unknown(self) -> int:
        """Every COULDN'T CHECK row (what ``--fail-on-unknown`` gates on)."""
        return self.count(Status.COULDNT_CHECK)

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


def read_lock_document(path: Path, errors: list[str]) -> dict | None:
    """Read a lock file defensively; problems go to *errors*, never raise.

    ``st_size`` cannot be trusted (``/dev/zero`` and a FIFO report 0), so the
    file is opened without blocking, must be a regular file, and at most
    ``MAX_LOCK_BYTES + 1`` bytes are read.
    """
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        errors.append(f"lock {path.name} could not be read: {exc.strerror}")
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            errors.append(f"lock {path.name} is not a regular file; skipped")
            return None
        with os.fdopen(fd, "rb", closefd=False) as handle:
            blob = handle.read(MAX_LOCK_BYTES + 1)
    except OSError as exc:
        errors.append(f"lock {path.name} could not be read: {exc.strerror}")
        return None
    finally:
        os.close(fd)
    if len(blob) > MAX_LOCK_BYTES:
        errors.append(f"lock {path.name} is over {MAX_LOCK_BYTES} bytes; skipped")
        return None
    try:
        doc = json.loads(blob.decode("utf-8"))
    except (ValueError, RecursionError, MemoryError):
        errors.append(f"lock {path.name} is not valid JSON; skipped")
        return None
    if not isinstance(doc, dict):
        errors.append(f"lock {path.name} is not a lock file; skipped")
        return None
    return doc


class LockIndex:
    """``resolved_version`` lookups: ``--lock`` files, then the nearest lock."""

    def __init__(
        self, explicit: Iterable[Path] = (), errors: list[str] | None = None
    ) -> None:
        self._explicit: list[tuple[Path, dict]] = []
        self._by_config: dict[Path, tuple[Path, dict] | None] = {}
        self._errors = errors if errors is not None else []
        for path in explicit:
            doc = self._read(path)
            if doc is not None:
                self._explicit.append((path, doc))

    def _read(self, path: Path) -> dict | None:
        """Read a lock without trusting it: regular file, bounded, never blocking."""
        doc = read_lock_document(path, self._errors)
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
            if not isinstance(version, str) or not _VERSION_TEXT.fullmatch(version):
                continue
            if isinstance(name, str) and _name_key(ecosystem, name) != _name_key(
                ecosystem, package
            ):
                continue
            return version, f"lock resolved_version ({path.name})"
        return None


def _pypi_pin_with_extras(server: ServerConfig, package: str) -> str | None:
    """``pkg[extra]==1.2.3``: a pin ``_pinned_version`` does not read."""
    for arg in server.args:
        hit = _PYPI_PIN_RE.match(arg)
        if (
            hit
            and normalize_pypi_name(hit["name"]) == normalize_pypi_name(package)
            and _VERSION_TEXT.fullmatch(hit["ver"])
            and _parses(hit["ver"])
        ):
            return hit["ver"]
    return None


def server_version(
    server: ServerConfig, ecosystem: str, package: str, locks: LockIndex
) -> tuple[str | None, str | None]:
    """The version this launch installs, and where that came from."""
    pinned = _pinned_version(server)
    if pinned is None and ecosystem == "pypi":
        pinned = _pypi_pin_with_extras(server, package)
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
    #: The launch is provably stdio (see ``registry.reachability``).
    stdio: bool = False


_COMPARE: dict[str, Callable[[Version, Version], bool]] = {
    "<": lambda a, b: a < b,
    "<=": lambda a, b: a <= b,
    ">": lambda a, b: a > b,
    ">=": lambda a, b: a >= b,
    "==": lambda a, b: a == b,
    "!=": lambda a, b: a != b,
}

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
    #: Set when a verified tag says the advisory does not reach stdio servers.
    off_stdio: Tags | None = None

    def matches(self, launch: Launch) -> bool:
        """The launch resolves to this registry entry."""
        return launch.entry is not None and launch.entry.name == self.entry_name

    def describes(self) -> str:
        """The package this rule is about."""
        return self.entry_name

    def decide(self, launch: Launch) -> Decision:
        """AFFECTED below the recorded fix, NOT AFFECTED at or above it.

        A verified transport tag clears a provably-stdio server unless the
        version already shows it fixed (that answer is the stronger one).
        """
        by_version = self._by_version(launch)
        if (
            launch.stdio
            and self.off_stdio is not None
            and by_version.status is not Status.NOT_AFFECTED
        ):
            return Decision(
                Status.NOT_AFFECTED,
                f"{self.advisory} is in {self.entry_name}'s "
                f"{'/'.join(sorted(self.off_stdio.transports))} transport code, "
                "and this server is launched over stdio with nothing selecting "
                f"another transport (tag verified by {self.off_stdio.verified_by})",
                NOT_REACHABLE,
                self.fixed_in,
            )
        return by_version

    def _by_version(self, launch: Launch) -> Decision:
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
                fixes=(self.fixed_in,),
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
                fixes=tuple(
                    dict.fromkeys(
                        value
                        for events in ranges
                        for kind, value in events
                        if kind == "fixed"
                    )
                ),
            )
        for _kind, bound in (e for r in ranges for e in r):
            if bound != "0" and _parses(bound) and _schemes_differ(version, bound):
                return _unorderable(version, bound)
        results = [_range_covers(r, version) for r in ranges]
        if any(r is True for r in results):
            fixes = tuple(
                dict.fromkeys(
                    value
                    for events, covers in zip(ranges, results, strict=True)
                    if covers is True
                    for kind, value in events
                    if kind == "fixed"
                )
            )
            return Decision(
                Status.AFFECTED,
                f"{version} ({launch.source}) is inside a range {record.id} lists",
                fixes=fixes,
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
            op, bound = spec.operator, spec.version
            wildcard = bound.endswith(".*")
            base = bound[:-2] if wildcard else bound
            if not _parses(base):
                return _unorderable(version, bound)
            if _schemes_differ(version, base):
                if op not in ("<", "<=") or wildcard:
                    return _unorderable(version, bound)
                status = _fix_status(version, base, resumed)
                if status == "undecidable":
                    return _unorderable(version, bound)
                holds = holds and status == "affected"
            elif op in _COMPARE and not wildcard:
                # Compared directly so `<2.0` includes 2.0rc1 (a pre-release
                # sorts below the release; SpecifierSet.contains skips it).
                holds = holds and _COMPARE[op](Version(version), Version(base))
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
        off: dict[str, Tags | None] = {}
        for item in entry.known_vulns or []:
            cve = item.get("cve") if isinstance(item, dict) else None
            if isinstance(cve, str) and cve.upper() == wanted:
                fx = item.get("fixed_in")
                fixed[cve] = str(fx) if fx else None
                off[cve] = excludes_stdio(item)
        for cve in entry.known_vulnerabilities or []:
            if isinstance(cve, str) and cve.upper() == wanted:
                fixed.setdefault(cve, None)
        for cve, fixed_in in fixed.items():
            out.rules.append(RegistryRule(entry.name, cve, fixed_in, off.get(cve)))
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


_EXTRA_PACKAGE_FLAGS = frozenset(
    {"--with", "--with-editable", "--with-requirements", "-p", "--package"}
)


def _installs_extra_packages(
    server: ServerConfig, ecosystem: str, package: str
) -> bool:
    """True when the launch installs more than the package it runs.

    ``uvx --with litellm==1.107.0 other-tool`` and ``npx -p litellm-js runner``
    install a second package that ``launch_package`` does not name.  Only the
    arguments before the named package are read, so a ``-p 8080`` that belongs
    to the server does not count.
    """
    args = list(server.args)
    wanted = _name_key(ecosystem, package)
    stop = len(args)
    for i, arg in enumerate(args):
        if arg.startswith("-"):
            continue
        bare = re.split(r"==|\[", arg, maxsplit=1)[0]
        if ecosystem == "npm":
            bare = bare.rsplit("@", 1)[0] if bare.rfind("@") > 0 else bare
        if _name_key(ecosystem, bare) == wanted:
            stop = i
            break
    for arg in args[:stop]:
        flag = arg.split("=", 1)[0]
        if flag in _EXTRA_PACKAGE_FLAGS:
            return True
    return False


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
    if not applicable and _installs_extra_packages(server, ecosystem, package):
        return Row(
            subject,
            Status.COULDNT_CHECK,
            f"runs {pkg_id} and also installs packages through --with / -p / "
            "--package, which mcp-audit does not read",
            config_path=where,
            package=pkg_id,
            reason=EXTRA_PACKAGES,
        )
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
    launch = Launch(ecosystem, package, version, source, entry, provably_stdio(server))
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
        fixes=tuple(
            dict.fromkeys(
                f for d in decisions if d.status is best.status for f in d.fixes
            )
        ),
    )


def would_close(
    server: ServerConfig,
    rules: list[Rule],
    registry: KnownServerRegistry,
    version: str,
) -> bool:
    """Would *server* pinned to *version* be clear of every rule? (``--fix`` check)

    True only when each rule that concerns the package says NOT AFFECTED; an
    AFFECTED or COULDN'T CHECK answer means the pin would not close the advisory.
    """
    found = launch_package(server)
    if found is None:
        return False
    ecosystem, package = found
    entry = resolve_launch_entry(server, registry)
    plain = Launch(ecosystem, package, None, None, entry)
    launch = Launch(
        ecosystem, package, version, "the fixed pin", entry, provably_stdio(server)
    )
    applicable = [r for r in rules if r.matches(plain)]
    return bool(applicable) and all(
        r.decide(launch).status is Status.NOT_AFFECTED for r in applicable
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
