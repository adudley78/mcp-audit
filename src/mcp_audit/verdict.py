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

# ── Constants ──────────────────────────────────────────────────────────────────

SCHEMA_VERSION = "1.0.0"

_VERDICT_BASE_URL = "https://mcp-audit.dev/v1/verdicts"
_BADGE_BASE_URL = "https://img.shields.io/endpoint?url=https://mcp-audit.dev/v1/badge"
_NVD_BASE_URL = "https://nvd.nist.gov/vuln/detail"
_REGISTRY_CONTRIBUTION_URL = "https://mcp-audit.dev/contribute"

# Matches @scope/name (npm scoped packages).
_SCOPED_RE = re.compile(r"^@([^/]+)/(.+)$")


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
                "link": f"{_NVD_BASE_URL}/{cve}",
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
                "link": f"{_NVD_BASE_URL}/{cve_id}",
            }
        )

    return result


# ── Public builder ────────────────────────────────────────────────────────────


def build_verdict(
    name: str,
    ecosystem: str,
    entry: RegistryEntry | None,
    typosquat_of: RegistryEntry | None,
    registry: KnownServerRegistry,
) -> dict[str, Any]:
    """Build a v1 verdict document from registry data.

    This is the **only** place that assembles the verdict document shape.
    All fields conform to ``https://mcp-audit.dev/v1/schema.json``.

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

    Returns:
        Verdict ``dict`` ready for JSON serialisation.  Always includes every
        required schema key so callers can treat the document as complete.
    """
    now_iso = datetime.now(tz=UTC).isoformat()

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

    return {
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
        "tags": tags,
        "links": {
            "repo": repo,
            "verdict_page": verdict_page_url(ecosystem, name),
        },
    }
