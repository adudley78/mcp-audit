"""Pure builder: package name + RegistryEntry → verdict document.

This module is the **single source of truth** for the verdict document shape
used by ``mcp-audit vet``.  It has no I/O and no network calls — the function
is deterministic given the same inputs and is therefore trivial to unit-test.

Consumers:
- ``mcp_audit.cli.vet`` (the ``mcp-audit vet`` CLI command)
- The mcp-audit.dev static-site generator (future)

Verdict schema: ``https://mcp-audit.dev/v1/schema.json`` (schema_version 1.0.0).
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from mcp_audit.registry.loader import KnownServerRegistry, RegistryEntry
from mcp_audit.registry.malicious import MaliciousMatch

# ── Constants ──────────────────────────────────────────────────────────────────

SCHEMA_VERSION = "1.0.0"

_VERDICT_BASE_URL = "https://mcp-audit.dev/v1/verdicts"
_BADGE_BASE_URL = "https://img.shields.io/endpoint?url=https://mcp-audit.dev/v1/badge"
_NVD_BASE_URL = "https://nvd.nist.gov/vuln/detail"


def advisory_link(advisory_id: str) -> str:
    """Public page for an advisory ID: NVD for CVEs, GitHub for GHSA, OSV otherwise."""
    if advisory_id.startswith("CVE-"):
        return f"{_NVD_BASE_URL}/{advisory_id}"
    if advisory_id.startswith("GHSA-"):
        return f"https://github.com/advisories/{advisory_id}"
    return f"https://osv.dev/vulnerability/{advisory_id}"


_REGISTRY_CONTRIBUTION_URL = "https://mcp-audit.dev/contribute"

# Matches @scope/name (npm scoped packages).
_SCOPED_RE = re.compile(r"^@([^/]+)/(.+)$")

# What counts as an exact version in `vet pkg@1.2.3` / `vet pkg==1.2.3`.
_PINNED_VERSION_RE = re.compile(r"^[vV]?(\d[0-9A-Za-z.+_!-]*)$")


def split_package_spec(spec: str) -> tuple[str, str | None]:
    """Split ``name@version`` / ``@scope/name@version`` / ``name==version``.

    Registry lookups use the bare name; the version is reported against the
    recorded CVE ranges.  Only an exact version (starts with a digit, optional
    ``v``) counts as a pin.  A dist-tag (``@latest``) or a range (``@^1.2``) is
    dropped without a pin: it names no single release.

    Args:
        spec: The package argument as typed.

    Returns:
        ``(name, version)``; *version* is ``None`` when none was given.
    """
    spec = spec.strip()
    if "==" in spec:
        name, _, rest = spec.partition("==")
        match = _PINNED_VERSION_RE.match(rest.strip())
        return name.strip(), match.group(1) if match else None
    at = spec.rfind("@")
    if at <= 0:
        return spec, None
    name, rest = spec[:at], spec[at + 1 :]
    match = _PINNED_VERSION_RE.match(rest)
    return name, match.group(1) if match else None


def with_pinned_version(
    verdict: dict[str, Any], version: str | None, semver_resumed_at: str | None
) -> dict[str, Any]:
    """Record a pinned *version* on *verdict* and judge each CVE against it.

    Adds ``package.version`` and, per ``known_vulnerabilities`` item, a
    ``status`` of ``affected`` (no recorded fix, or *version* is below it),
    ``fixed`` or ``undecidable`` (the fix uses a different numbering scheme,
    calendar versus semantic, and nothing offline orders them: the same rule
    as SC-004/SC-009).  A verdict without a version is returned unchanged.

    Args:
        verdict: A verdict document (modified in place and returned).
        version: The exact version asked about, or ``None``.
        semver_resumed_at: The registry entry's ``semver_resumed_at``, if any.

    Returns:
        *verdict*.
    """
    if version is None:
        return verdict
    from mcp_audit.analyzers.supply_chain import _fix_status  # noqa: PLC0415

    verdict["package"]["version"] = version
    for item in verdict.get("known_vulnerabilities") or []:
        if not isinstance(item, dict):
            continue
        fixed = item.get("fixed_in")
        item["status"] = (
            _fix_status(version, str(fixed), semver_resumed_at) if fixed else "affected"
        )
    return verdict


# ── Public helpers ─────────────────────────────────────────────────────────────


def name_to_slug(name: str) -> str:
    """Convert a package name to a URL-safe slug for badge/verdict URLs.

    Transformation rules (applied in order):
    1. Scoped npm names ``@scope/name`` become ``at-scope-name``.
    2. Lowercased.
    3. Underscores replaced with hyphens.

    Args:
        name: Package name (e.g. ``@scope/my_pkg`` or ``my_pkg``).

    Returns:
        URL-safe slug string.

    Examples::

        >>> name_to_slug("@modelcontextprotocol/server-filesystem")
        'at-modelcontextprotocol-server-filesystem'
        >>> name_to_slug("mcp_server_git")
        'mcp-server-git'
    """
    m = _SCOPED_RE.match(name)
    slug = f"at-{m.group(1)}-{m.group(2)}" if m else name
    return slug.lower().replace("_", "-")


def badge_url(ecosystem: str, name: str) -> str:
    """Return the Shields.io badge endpoint URL for a package.

    Args:
        ecosystem: ``"npm"`` or ``"pypi"``.
        name: Raw package name (slug conversion applied internally).

    Returns:
        Full Shields.io endpoint URL string.
    """
    slug = name_to_slug(name)
    return f"{_BADGE_BASE_URL}/{ecosystem}/{slug}.json"


def verdict_page_url(ecosystem: str, name: str) -> str:
    """Return the mcp-audit.dev verdict page URL for a package.

    Args:
        ecosystem: ``"npm"`` or ``"pypi"``.
        name: Raw package name (slug conversion applied internally).

    Returns:
        Full verdict page URL string.
    """
    slug = name_to_slug(name)
    return f"{_VERDICT_BASE_URL}/{ecosystem}/{slug}.json"


# ── Internal helpers ──────────────────────────────────────────────────────────


def _normalise_vulns(entry: RegistryEntry) -> list[dict[str, Any]]:
    """Merge ``known_vulns`` (rich dicts) and ``known_vulnerabilities`` (bare CVE IDs).

    ``known_vulns`` entries take precedence; bare CVE IDs from
    ``known_vulnerabilities`` that are not already present in ``known_vulns``
    are promoted to minimal rich dicts.  Deduplication is by CVE ID.

    Args:
        entry: A registry entry whose vulnerability fields should be merged.

    Returns:
        Deduplicated list of rich vulnerability dicts conforming to the
        ``known_vulnerabilities`` array item schema (cve, cvss, description,
        fixed_in, source, link).
    """
    seen: set[str] = set()
    result: list[dict[str, Any]] = []

    # Rich records first (preferred source — carry more metadata).
    for vuln in entry.known_vulns or []:
        cve = vuln.get("cve", "")
        if not cve or cve in seen:
            continue
        seen.add(cve)
        result.append(
            {
                "cve": cve,
                "cvss": vuln.get("cvss"),
                "description": vuln.get("description"),
                "fixed_in": vuln.get("fixed_in"),
                "source": "NVD",
                "link": advisory_link(cve),
            }
        )

    # Bare CVE strings that aren't already in the rich list.
    for cve_id in entry.known_vulnerabilities or []:
        if not cve_id or cve_id in seen:
            continue
        seen.add(cve_id)
        result.append(
            {
                "cve": cve_id,
                "cvss": None,
                "description": None,
                "fixed_in": None,
                "source": "NVD",
                "link": advisory_link(cve_id),
            }
        )

    return result


def malicious_item(match: MaliciousMatch) -> dict[str, Any]:
    """Shape one OSV ``MAL-*`` match for the verdict's ``malicious`` list.

    Args:
        match: An :func:`~mcp_audit.registry.malicious.assess` result.

    Returns:
        ``{id, ecosystem, aliases, summary, versions, ranges, latest_affected,
        blanket_range_ignored, link, note}``.  ``ranges`` keeps OSV's events
        (``[{"introduced": "0"}]`` means every version).  ``latest_affected``
        is ``True`` when OSV marks every release (or every release from some
        version on), so the latest release ``vet`` answers for is covered.
    """
    record = match.record
    return {
        "id": record.id,
        "ecosystem": record.ecosystem,
        "aliases": list(record.aliases),
        "summary": record.summary or None,
        "versions": list(record.versions),
        "ranges": [
            [{kind: value} for kind, value in events] for events in record.ranges
        ],
        "latest_affected": match.latest_affected,
        "blanket_range_ignored": match.blanket_range_ignored,
        "link": record.link,
        "note": record.note,
    }


# ── Public builder ────────────────────────────────────────────────────────────


def build_verdict(
    name: str,
    ecosystem: str,
    entry: RegistryEntry | None,
    typosquat_of: RegistryEntry | None,
    registry: KnownServerRegistry,
    *,
    typosquat_basis: str | None = None,
    malicious: list[dict[str, Any]] | None = None,
    other_ecosystem_malicious: list[dict[str, Any]] | None = None,
    pinned_version: str | None = None,
) -> dict[str, Any]:
    """Build a v1 verdict document from registry data.

    This is the **only** place that assembles the verdict document shape.
    All fields conform to ``https://mcp-audit.dev/v1/schema.json`` (which
    allows additional properties; ``typosquat_basis``, ``malicious`` and
    ``other_ecosystem_malicious`` were added by STORY-0097).

    Args:
        name: Package name exactly as supplied by the user.
        ecosystem: ``"npm"`` or ``"pypi"``.
        entry: Matching :class:`~mcp_audit.registry.loader.RegistryEntry` when
            the package is listed in the registry; ``None`` otherwise.
        typosquat_of: The registry entry that *name* closely resembles, when a
            typosquatting suspicion has been detected; ``None`` otherwise.
            ``typosquat_of`` is only meaningful when *entry* is ``None``.
        registry: The loaded :class:`~mcp_audit.registry.loader.KnownServerRegistry`
            instance, used for metadata (``last_updated``, entry count).
        typosquat_basis: Why *typosquat_of* was chosen: ``"edit-distance"``
            (SC-001..003 logic) or ``"unscoped-twin"`` (SC-007).  Defaults to
            ``"edit-distance"`` when *typosquat_of* is set.
        malicious: :func:`malicious_item` dicts for OSV ``MAL-*`` records on
            this package in this ecosystem (SC-008 data).
        other_ecosystem_malicious: The same, for a same-named package in the
            other registry (``vet mcp-server-git`` answers for the PyPI
            package; the npm package of that name is ``MAL-2026-5478``).

    Returns:
        Verdict ``dict`` ready for JSON serialisation.  Always includes every
        required schema key so callers can treat the document as complete.
    """
    now_iso = datetime.now(tz=UTC).isoformat()
    basis = None if typosquat_of is None else typosquat_basis or "edit-distance"

    if entry is not None:
        registry_block: dict[str, Any] = {
            "listed": True,
            "verified": entry.verified,
            "maintainer": entry.maintainer,
            "entry_updated": entry.last_verified,
            "registry_updated": registry.last_updated,
        }
        vulns = _normalise_vulns(entry)
        capabilities = entry.capabilities or []
        attestation_block: dict[str, Any] = {
            "hash_pins_available": bool(entry.known_hashes),
            "attestation_expected": entry.attestation_expected,
        }
        tags = entry.tags
        repo = entry.repo
    else:
        registry_block = {
            "listed": False,
            "verified": False,
            "maintainer": None,
            "entry_updated": None,
            "registry_updated": registry.last_updated,
        }
        vulns = []
        capabilities = []
        attestation_block = {
            "hash_pins_available": False,
            "attestation_expected": False,
        }
        tags = []
        repo = None

    document = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": now_iso,
        "package": {
            "ecosystem": ecosystem,
            "name": name,
        },
        "registry": registry_block,
        "known_vulnerabilities": vulns,
        "capabilities": capabilities,
        "attestation": attestation_block,
        "typosquat_of": typosquat_of.name if typosquat_of is not None else None,
        "typosquat_basis": basis,
        "malicious": list(malicious or []),
        "other_ecosystem_malicious": list(other_ecosystem_malicious or []),
        "tags": tags,
        "links": {
            "repo": repo,
            "verdict_page": verdict_page_url(ecosystem, name),
        },
    }
    return with_pinned_version(
        document, pinned_version, entry.semver_resumed_at if entry else None
    )
