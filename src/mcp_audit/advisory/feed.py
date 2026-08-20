"""Build advisory records from scan findings and publish them as a feed on disk.

Two public entry points:

``build_advisory(finding, server)``
    Deterministic mapping from a single mcp-audit finding to an :class:`Advisory`.

``write_feed(advisories, out_dir)``
    Materialises the feed: one JSON file per advisory under ``advisories/``, an
    ``index.json`` summarising all of them, and an ``osv/`` export that any
    osv-scanner-compatible tool can consume.

Every byte written here is reproducible. Given the same findings and the same
``now`` timestamp, two runs on two machines produce identical files — that is what
makes the detached signatures in :mod:`mcp_audit.advisory.sign` verifiable by a
third party who re-derives the feed themselves.

Advisories are only minted for servers that resolve to a real published package
(npm or PyPI). A server launched from a local path or reachable only at a URL has
no package coordinate, and OSV records are keyed by package — see
:func:`resolve_package`.
"""

from __future__ import annotations

import hashlib
import json
import os
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

from mcp_audit import __version__
from mcp_audit.analyzers.credentials import SECRET_PATTERNS
from mcp_audit.analyzers.supply_chain import (
    extract_npm_package,
    extract_pypi_package,
    normalize_pypi_name,
)
from mcp_audit.models import Finding, ScanResult, ServerConfig, Severity
from mcp_audit.owasp_mcp import OWASP_MCP_TOP_10_URI

from .canonical import canonicalize
from .classify import (
    cvss_for,
    extract_cves,
    finding_class_for,
    is_advisable,
    observation_for,
    owasp_codes_for,
)
from .schema import Advisory, Package, Reference
from .schema import Severity as AdvisorySeverity

__all__ = [
    "FEED_VERSION",
    "BuildReport",
    "FeedManifest",
    "PackageRef",
    "build_advisories",
    "build_advisory",
    "load_feed",
    "resolve_package",
    "write_feed",
]

FEED_VERSION = "1.0"

# Commands whose first non-flag argument names a package in a public registry.
_NPM_COMMANDS = frozenset({"npx", "bunx", "pnpx"})
_PYPI_COMMANDS = frozenset({"uvx", "pipx"})

_REDACTED = "[REDACTED]"

# Deterministic ZIP member timestamp. The DOS date format the ZIP spec uses cannot
# represent anything before 1980-01-01, which is the conventional epoch for
# reproducible archives.
_ZIP_EPOCH = (1980, 1, 1, 0, 0, 0)


# ── Package resolution ────────────────────────────────────────────────────────

# OSV's own spelling of the ecosystems we mint advisories for. Also the allowlist for
# the per-ecosystem directory names in the osv-scanner export.
_OSV_ECOSYSTEMS: Final[frozenset[str]] = frozenset({"npm", "PyPI"})


@dataclass(frozen=True)
class PackageRef:
    """A package coordinate in a public distribution registry."""

    ecosystem: str  # "npm" | "PyPI" — OSV's spelling, not lowercase
    name: str
    version: str | None = None


def resolve_package(server: ServerConfig) -> PackageRef | None:
    """Return the published package a server is launched from, or ``None``.

    ``None`` means the server has no coordinate in a public registry — it runs from
    a local path, a container, or a remote URL — and therefore cannot be the subject
    of an OSV record. Callers should skip such servers rather than inventing a name.
    """
    command = (server.command or "").strip()
    args = list(server.args or [])
    if not command:
        return None

    base = Path(command).name

    if base == "yarn" and args and args[0] == "dlx":
        return _npm_ref(extract_npm_package(args[1:]))

    if base in _NPM_COMMANDS:
        return _npm_ref(extract_npm_package(args))

    if base in _PYPI_COMMANDS:
        spec = extract_pypi_package(base, args)
        if not spec:
            return None
        # extract_pypi_package already strips any "@version" suffix, so recover the
        # pin from the raw argument list rather than from the normalised name.
        name, _ = _split_spec(spec)
        return PackageRef("PyPI", normalize_pypi_name(name), _pypi_version(args))

    return None


def _npm_ref(spec: str | None) -> PackageRef | None:
    if not spec:
        return None
    name, version = _split_spec(spec)
    return PackageRef("npm", name, version)


def _split_spec(spec: str) -> tuple[str, str | None]:
    """Split a package spec into ``(name, version)``.

    Handles the scoped npm form, where the leading ``@`` of ``@scope/pkg`` is part of
    the name and only an ``@`` appearing after the slash separates the version.
    """
    if spec.startswith("@"):
        scope, slash, rest = spec.partition("/")
        if not slash:
            return spec, None
        if "@" in rest:
            tail, _, version = rest.rpartition("@")
            return f"{scope}/{tail}", version or None
        return spec, None
    if "@" in spec:
        name, _, version = spec.rpartition("@")
        return name, version or None
    return spec, None


def _pypi_version(args: list[str]) -> str | None:
    """Return the version pinned on the first non-flag argument, if any."""
    for arg in args:
        if arg.startswith("-"):
            continue
        return _split_spec(arg)[1]
    return None


# ── Redaction ─────────────────────────────────────────────────────────────────


def redact(text: str) -> str:
    """Strip anything matching a known credential pattern from advisory prose.

    Analyzers already redact their own evidence, so this is a backstop: an advisory
    is a published artifact, and a secret that reaches it cannot be un-published.
    """
    cleaned = text
    for _label, pattern, _provider in SECRET_PATTERNS:
        cleaned = pattern.sub(_REDACTED, cleaned)
    return cleaned


#: Below this length a path string is too generic to redact safely — "/" itself is
#: one character, and blindly `str.replace("/", ...)` would rewrite every path
#: separator in the whole document, not just the scanned config's own path.
_MIN_SAFE_PATH_LENGTH = 3


def _redact_local_paths(text: str, config_path: Path) -> str:
    """Rewrite *config_path* and its ancestors in *text* to a cwd-relative form.

    ``config_hygiene.py`` (CFHYG-001/002/005) legitimately embeds the real, absolute
    scanned path in a finding's evidence/remediation — you need the actual path to
    run the ``chmod`` it suggests. But an advisory is copied from that finding
    verbatim into a document meant to be published to the world, and an absolute
    path there is the same defect class as the RFC 8785 float bug in a different
    shape: two hosts scanning the *same relative target* resolve it to two different
    absolute paths, so the same finding canonicalizes (and signs) differently
    depending on where the scanning machine happens to keep its checkout — on top of
    leaking the operator's home-directory username, which contradicts mcp-audit's
    own privacy-first premise in the one component designed to leave the machine.

    *config_path*, and each of its ancestors up to (but not including) ``$HOME``,
    is replaced by its path relative to the current working directory — not just
    the bare filename, which would make two same-named config files in different
    directories indistinguishable. Climbing stops at ``$HOME`` (or does not start
    at all when *config_path* is not under it) rather than continuing to the
    filesystem root: an ancestor that short — ``/`` is one character — would match,
    and get rewritten, everywhere a path separator appears in the rest of the text,
    not just in the scanned config's own path. ``$HOME`` itself becomes the
    conventional ``~``, since the directories above it carry no information a reader
    needs and only encode the local username.

    Cwd-relative is only safe when the working directory is itself under ``$HOME``:
    then the climb from cwd up to any shared ancestor never needs to go above
    ``$HOME``, so ``$HOME``'s own name is always climbed *past* (as an anonymous
    ``..``) and never descended back *through*. When the working directory has
    escaped ``$HOME`` entirely (e.g. a container mounting the repo outside the home
    volume), that guarantee doesn't hold — reaching a config file under ``$HOME``
    would require descending through ``$HOME``'s own directory entry from a shared
    ancestor above it, putting the username literally in the output. Ancestors
    under ``$HOME`` are rendered relative to ``$HOME`` (``~/...``) instead in that
    case: never a leak, at the cost of exact reproducibility across two hosts whose
    container mounts disagree — the same caveat any tool's relative-path output
    would carry there.
    """
    try:
        home: Path | None = Path.home()
    except RuntimeError:
        home = None
    under_home = home is not None and config_path.is_relative_to(home)
    cwd = Path.cwd()
    cwd_escaped_home = home is not None and not cwd.is_relative_to(home)

    ancestors: list[Path] = [config_path]
    if under_home:
        current = config_path
        while current != home:
            parent = current.parent
            if parent == home:
                break
            ancestors.append(parent)
            current = parent

    replacements: list[tuple[str, str]] = []
    for ancestor in ancestors:
        raw = str(ancestor)
        if len(raw) < _MIN_SAFE_PATH_LENGTH:
            continue
        if under_home and cwd_escaped_home:
            # cwd can't reach `ancestor` without passing through $HOME itself —
            # relpath would spell out $HOME's name. Anchor on $HOME instead.
            relative = f"~/{ancestor.relative_to(home)}" if ancestor != home else "~"
        else:
            try:
                relative = os.path.relpath(ancestor, cwd)
            except ValueError:
                relative = ancestor.name
        replacements.append((raw, relative))
    if home is not None and len(str(home)) >= _MIN_SAFE_PATH_LENGTH:
        replacements.append((str(home), "~"))

    # Longest string first: config_path's full string must be replaced before any
    # of its own ancestor directories, or a shorter ancestor's occurrence inside the
    # still-unreplaced longer string would be replaced first, leaving a malformed
    # hybrid path (part original, part rewritten) behind.
    by_length_desc = sorted(replacements, key=lambda pair: len(pair[0]), reverse=True)
    for raw, relative in by_length_desc:
        text = text.replace(raw, relative)
    return text


# ── Advisory construction ─────────────────────────────────────────────────────


def normalize_location(finding: Finding) -> str:
    """Return the package-relative location an advisory applies to.

    Only the MCP tool name qualifies. It is intrinsic to the package (the server
    declares it), identical on every host, and is exactly the granularity at which
    two findings in the same package are genuinely different vulnerabilities.

    Config file paths are deliberately excluded: they vary per machine, contain the
    operator's username, and would make advisory IDs unreproducible. An empty string
    means the advisory covers the package as a whole.
    """
    return (finding.tool or "").strip()


def build_advisory(
    finding: Finding,
    server: ServerConfig,
    *,
    now: str,
    package: PackageRef | None = None,
) -> Advisory | None:
    """Map a single finding to an :class:`Advisory`, or ``None`` if it has no package.

    The mapping is total and deterministic: the same ``(finding, server, now)`` always
    yields a byte-identical record, and the advisory ID depends only on the package
    coordinate and the vulnerability's identity — never on the scanning host.

    Args:
        finding: The finding to describe. This is the in-memory form of the SARIF
            result mcp-audit emits; ``result.ruleId`` is ``finding.id``.
        server: The server the finding was raised against, used for the package
            coordinate and transport.
        now: RFC 3339 UTC timestamp (``YYYY-MM-DDTHH:MM:SSZ``) for ``published`` and
            ``modified``. Required rather than defaulted so callers cannot
            accidentally produce a non-reproducible feed.
        package: Pre-resolved package coordinate. Resolved from *server* when omitted.

    Returns:
        The advisory, or ``None`` when the server resolves to no published package.
    """
    pkg = package if package is not None else resolve_package(server)
    if pkg is None:
        return None

    finding_class = finding_class_for(finding.id)
    cvss_vector, cvss_basis = cvss_for(finding_class, finding.severity)
    cwe_ids = [finding.cwe] if finding.cwe else []

    def _sanitize(text: str) -> str:
        return redact(_redact_local_paths(text, server.config_path))

    return Advisory(
        package=Package(ecosystem=pkg.ecosystem, name=pkg.name),
        summary=_sanitize(finding.title),
        details=_sanitize(_details_for(finding)),
        finding_class=finding_class,
        mcp_audit_rule_id=finding.id,
        introduced=pkg.version or "0",
        mcp_transport=_transport_for(server),
        owasp_mcp=owasp_codes_for(finding.owasp_mcp_top_10),
        severity=[AdvisorySeverity(score=cvss_vector)],
        references=_references_for(finding),
        published=now,
        modified=now,
        location=normalize_location(finding),
        observation=observation_for(finding.id),
        aliases=_aliases_for(finding),
        cwe_ids=cwe_ids,
        cvss_basis=cvss_basis,
    )


def _details_for(finding: Finding) -> str:
    """Compose the advisory ``details`` prose from a finding's own fields."""
    parts = [finding.description.strip()]
    if finding.evidence.strip():
        parts.append(f"Evidence: {finding.evidence.strip()}")
    if finding.remediation.strip():
        parts.append(f"Remediation: {finding.remediation.strip()}")
    parts.append(
        f"Detected by mcp-audit rule {finding.id} "
        f"({finding.analyzer} analyzer, severity {finding.severity.value})."
    )
    return " ".join(parts)


def _transport_for(server: ServerConfig) -> str | None:
    """Return the OSV-facing transport label, or ``None`` when it is unknown."""
    value = str(server.transport.value if server.transport else "").lower()
    return value if value in {"stdio", "sse", "http"} else None


def _aliases_for(finding: Finding) -> list[str]:
    """Return public vulnerability IDs this advisory is an alias of."""
    aliases = set(finding.cve)
    aliases.update(extract_cves(finding.description, finding.evidence, finding.title))
    return sorted(aliases)


def _references_for(finding: Finding) -> list[Reference]:
    """Return the reference list, ordered deterministically and de-duplicated."""
    refs = [Reference(url=OWASP_MCP_TOP_10_URI, type="WEB")]
    for cve in _aliases_for(finding):
        refs.append(
            Reference(url=f"https://nvd.nist.gov/vuln/detail/{cve}", type="ADVISORY")
        )
    seen: set[str] = set()
    unique: list[Reference] = []
    for ref in refs:
        if ref.url not in seen:
            seen.add(ref.url)
            unique.append(ref)
    return unique


# ── Whole-scan construction ───────────────────────────────────────────────────


@dataclass
class BuildReport:
    """Outcome of mapping a whole scan to advisories."""

    advisories: list[Advisory] = field(default_factory=list)
    #: Findings dropped because their server has no published package coordinate.
    skipped_no_package: int = 0
    #: Findings that collapsed onto an advisory another finding already produced.
    merged_duplicates: int = 0
    #: Findings whose server could not be located in the scan result.
    skipped_no_server: int = 0
    #: Findings that assert no vulnerability (positive signals, operational errors).
    skipped_non_advisory: int = 0


def build_advisories(
    result: ScanResult,
    *,
    now: str,
    min_severity: Severity | None = None,
    only_observation: str | None = None,
) -> BuildReport:
    """Map every eligible finding in a scan result to an advisory.

    Findings that map to the same advisory ID — the same vulnerability class in the
    same package — are collapsed into one record, because a feed keyed by package is
    describing the package, not each host that happens to run it.

    Args:
        result: A completed scan.
        now: RFC 3339 UTC timestamp applied to every advisory.
        min_severity: Drop findings below this severity when given.
        only_observation: Keep only ``"package-intrinsic"`` or ``"deployment"``
            records when given.

    Returns:
        A :class:`BuildReport` with the advisories sorted by ID and counts explaining
        every finding that did not become one.
    """
    servers = {(s.client, s.name): s for s in result.servers}
    report = BuildReport()
    by_id: dict[str, Advisory] = {}

    for finding in result.findings:
        if min_severity is not None and not _at_least(finding.severity, min_severity):
            continue
        if not is_advisable(finding.id):
            report.skipped_non_advisory += 1
            continue
        if (
            only_observation is not None
            and observation_for(finding.id) != only_observation
        ):
            continue

        server = servers.get((finding.client, finding.server))
        if server is None:
            report.skipped_no_server += 1
            continue

        advisory = build_advisory(finding, server, now=now)
        if advisory is None:
            report.skipped_no_package += 1
            continue

        assert advisory.id is not None  # set by Advisory.__post_init__
        if advisory.id in by_id:
            report.merged_duplicates += 1
            continue
        by_id[advisory.id] = advisory

    report.advisories = [by_id[key] for key in sorted(by_id)]
    return report


_SEVERITY_ORDER = [
    Severity.INFO,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
]


def _at_least(value: Severity, floor: Severity) -> bool:
    return _SEVERITY_ORDER.index(value) >= _SEVERITY_ORDER.index(floor)


# ── Feed materialisation ──────────────────────────────────────────────────────


@dataclass(frozen=True)
class FeedManifest:
    """Paths written by :func:`write_feed`."""

    out_dir: Path
    index_path: Path
    advisory_paths: list[Path]
    osv_json_path: Path
    osv_zip_path: Path
    ecosystem_zip_paths: list[Path] = field(default_factory=list)

    @property
    def signable_paths(self) -> list[Path]:
        """Files that :mod:`mcp_audit.advisory.sign` signs, in a stable order."""
        return [*self.advisory_paths, self.index_path]


def write_feed(advisories: list[Advisory], out_dir: Path) -> FeedManifest:
    """Write a complete feed to *out_dir* and return the paths written.

    Layout::

        out_dir/
          index.json               summary of every advisory
          advisories/<id>.json     one OSV record per advisory
          osv/all.json             every record as a single JSON array
          osv/all.zip              every record, zipped
          osv/osv-scanner/<ecosystem>/all.zip

    The ``osv/osv-scanner/`` subtree is the directory layout osv-scanner expects under
    ``OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY``: one archive per ecosystem, so it can be
    pointed at directly rather than rearranged by hand.

    Advisory files are pretty-printed for review. The bytes that get *signed* are the
    RFC 8785 canonicalization of the parsed document, which :mod:`sign` re-derives at
    verification time, so formatting the files for humans costs nothing.
    """
    out_dir = Path(out_dir)
    advisories_dir = out_dir / "advisories"
    osv_dir = out_dir / "osv"
    advisories_dir.mkdir(parents=True, exist_ok=True)
    osv_dir.mkdir(parents=True, exist_ok=True)

    ordered = sorted(advisories, key=lambda a: a.id or "")
    records = [advisory.to_osv() for advisory in ordered]

    advisory_paths: list[Path] = []
    for advisory, record in zip(ordered, records, strict=True):
        path = advisories_dir / f"{advisory.id}.json"
        _write_json(path, record)
        advisory_paths.append(path)

    index_path = out_dir / "index.json"
    _write_json(index_path, _build_index(ordered))

    osv_json_path = osv_dir / "all.json"
    _write_json(osv_json_path, records)

    osv_zip_path = osv_dir / "all.zip"
    _write_osv_zip(osv_zip_path, ordered, records)

    ecosystem_zip_paths = _write_osv_scanner_db(osv_dir, ordered, records)

    return FeedManifest(
        out_dir=out_dir,
        index_path=index_path,
        advisory_paths=advisory_paths,
        osv_json_path=osv_json_path,
        osv_zip_path=osv_zip_path,
        ecosystem_zip_paths=ecosystem_zip_paths,
    )


def _build_index(advisories: list[Advisory]) -> dict:
    """Build the feed index. ``updated`` is derived, never wall-clock.

    Each entry carries the SHA-256 of its advisory's canonical form. Because the index
    itself is signed, that digest binds every advisory to the index: swapping an
    advisory file for a re-signed forgery still fails, since its digest no longer
    matches the one the index signature covers.
    """
    entries = []
    for advisory in advisories:
        record = advisory.to_osv()
        entries.append(
            {
                "id": advisory.id,
                "modified": advisory.modified,
                "summary": advisory.summary,
                "severity": record.get("severity", []),
                "owasp_mcp": list(advisory.owasp_mcp),
                "affected": record["affected"],
                "path": f"advisories/{advisory.id}.json",
                "canonical_sha256": hashlib.sha256(canonicalize(record)).hexdigest(),
            }
        )
    return {
        "feed_version": FEED_VERSION,
        "generator": f"mcp-audit/{__version__}",
        "count": len(entries),
        "updated": max((a.modified for a in advisories), default=""),
        "advisories": entries,
    }


def _write_json(path: Path, payload: object) -> None:
    """Write *payload* as pretty, sorted-key JSON with a trailing newline."""
    text = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False)
    path.write_text(text + "\n", encoding="utf-8")


def _write_osv_zip(path: Path, advisories: list[Advisory], records: list[dict]) -> None:
    """Write the osv-scanner offline-database archive, byte-reproducibly.

    ``ZipFile.writestr`` stamps each member with the current time by default, which
    would make the archive differ between runs; an explicit ``ZipInfo`` with a fixed
    timestamp is what keeps the feed reproducible.
    """
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for advisory, record in zip(advisories, records, strict=True):
            info = zipfile.ZipInfo(filename=f"{advisory.id}.json", date_time=_ZIP_EPOCH)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, canonicalize(record))


def _write_osv_scanner_db(
    osv_dir: Path, advisories: list[Advisory], records: list[dict]
) -> list[Path]:
    """Write one archive per ecosystem in the layout osv-scanner looks for.

    osv-scanner resolves its offline database as
    ``{cache_dir}/osv-scanner/{ecosystem}/all.zip``, so emitting that subtree here means
    a consumer can set ``OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY`` to ``osv/`` and scan,
    with no manual file shuffling in between.

    Returns:
        The archive paths written, sorted by ecosystem.
    """
    by_ecosystem: dict[str, tuple[list[Advisory], list[dict]]] = {}
    for advisory, record in zip(advisories, records, strict=True):
        ecosystem = advisory.package.ecosystem
        # The ecosystem becomes a directory name, and only ever comes from
        # resolve_package(); refuse anything that could escape osv_dir.
        if ecosystem not in _OSV_ECOSYSTEMS:
            raise ValueError(f"unsupported OSV ecosystem for export: {ecosystem!r}")
        bucket = by_ecosystem.setdefault(ecosystem, ([], []))
        bucket[0].append(advisory)
        bucket[1].append(record)

    written: list[Path] = []
    for ecosystem in sorted(by_ecosystem):
        eco_advisories, eco_records = by_ecosystem[ecosystem]
        eco_dir = osv_dir / "osv-scanner" / ecosystem
        eco_dir.mkdir(parents=True, exist_ok=True)
        path = eco_dir / "all.zip"
        _write_osv_zip(path, eco_advisories, eco_records)
        written.append(path)
    return written


def load_feed(out_dir: Path) -> list[dict]:
    """Load every advisory record from a feed directory, ordered by file name."""
    advisories_dir = Path(out_dir) / "advisories"
    if not advisories_dir.is_dir():
        return []
    from .sign import advisory_json_paths  # noqa: PLC0415 — avoids an import cycle

    return [
        json.loads(path.read_text(encoding="utf-8"))
        for path in advisory_json_paths(advisories_dir)
    ]
