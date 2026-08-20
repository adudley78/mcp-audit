"""Advisory data model for mcp-audit.

Serializes to OSV schema_version 1.6.0 (https://ossf.github.io/osv-schema/) so that
any osv-scanner-compatible tool can consume our feed. All MCP-specific and OWASP
metadata lives under `affected[].database_specific`, which OSV permits.

Design invariants (enforce with tests — see rules):
  * Deterministic: the same finding always produces a byte-identical record. IDs are
    stable, keys are sorted on export.
  * Validatable: to_osv() output must pass the vendored OSV 1.6.0 JSON schema.
  * Signable: to_canonical_json() emits sorted-key, compact JSON ready for RFC 8785
    (JCS) canonicalization in sign.py before signing.

This module has no third-party dependencies on purpose.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field

from mcp_audit.owasp_mcp import is_valid_code

SCHEMA_VERSION = "1.6.0"
# OSV restricts `id` prefixes to a registered allowlist plus an `x_` experimental
# namespace. We use `x_MCPSA` so records validate today. Registering `MCP`/`MCPSA` as
# an OSV home-database prefix upstream is a standards move (own the identifier) —
# drop the `x_` once it lands.
ID_PREFIX = "x_MCPSA"  # MCP Security Advisory (OSV experimental namespace)

FindingClass = str  # one of FIXABLE_FINDING_CLASSES (for fixable findings)
Transport = str  # "stdio" | "sse" | "http"

# The three finding classes `mcp-audit fix` remediates, each with the OWASP MCP Top 10
# category it always maps to. Codes are the bare `MCP01`..`MCP10` form defined in
# mcp_audit.owasp_mcp — the repo's single source of truth for this taxonomy — so that a
# consumer can join advisory records to our SARIF output and to docs/owasp-mapping.json
# without translating between two spellings of the same code.
FINDING_CLASS_TO_OWASP: dict[str, str] = {
    "hardcoded-secret": "MCP01",
    "excessive-scope": "MCP02",
    "command-injection": "MCP05",
}

FIXABLE_FINDING_CLASSES = frozenset(FINDING_CLASS_TO_OWASP)


def owasp_for(finding_class: str) -> str:
    """Return the OWASP MCP Top 10 code for a fixable finding class.

    Args:
        finding_class: One of :data:`FIXABLE_FINDING_CLASSES`.

    Returns:
        A bare category code, e.g. ``"MCP01"``.

    Raises:
        ValueError: The class has no fixed mapping.
    """
    try:
        return FINDING_CLASS_TO_OWASP[finding_class]
    except KeyError as exc:
        raise ValueError(
            f"No OWASP MCP mapping for finding_class {finding_class!r}; "
            f"known: {sorted(FINDING_CLASS_TO_OWASP)}"
        ) from exc


# Whether the finding describes the published package itself or the way an operator
# deployed it.  Consumers of the feed use this to decide whether a record is a claim
# about upstream code (actionable by the maintainer) or about local configuration
# (actionable by the operator).  See docs/advisory-feed.md.
OBSERVATION_PACKAGE = "package-intrinsic"
OBSERVATION_DEPLOYMENT = "deployment"


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


@dataclass(frozen=True)
class Package:
    ecosystem: str  # real distribution ecosystem, e.g. "npm" or "PyPI"
    name: str

    @property
    def purl(self) -> str:
        eco = "pypi" if self.ecosystem.lower() == "pypi" else self.ecosystem.lower()
        return f"pkg:{eco}/{self.name}"


@dataclass(frozen=True)
class Severity:
    score: str  # CVSS v3.1 vector string
    type: str = "CVSS_V3"  # noqa: A003 — normative OSV field name


@dataclass(frozen=True)
class Reference:
    url: str
    type: str = "WEB"  # noqa: A003 — ADVISORY | REPORT | FIX | WEB ...


@dataclass(frozen=True)
class VerifiedPatch:
    """Populated by `mcp-audit fix` once a patch lands. Null-equivalent until then."""

    fixed_version: str | None = None
    pr_url: str | None = None
    cosign_bundle: str | None = None

    def as_dict(self) -> dict:
        return {
            "fixed_version": self.fixed_version,
            "pr_url": self.pr_url,
            "cosign_bundle": self.cosign_bundle,
        }

    @property
    def is_patched(self) -> bool:
        return self.fixed_version is not None


@dataclass
class Advisory:
    package: Package
    summary: str
    details: str
    finding_class: FindingClass
    mcp_audit_rule_id: str
    introduced: str = "0"  # OSV range: affected from this version
    fixed: str | None = None  # OSV range: fixed at this version, if known
    mcp_transport: Transport | None = None
    # Bare OWASP MCP Top 10 codes ("MCP01".."MCP10"), as defined in mcp_audit.owasp_mcp.
    owasp_mcp: list[str] = field(default_factory=list)
    severity: list[Severity] = field(default_factory=list)
    references: list[Reference] = field(default_factory=list)
    verified_patch: VerifiedPatch = field(default_factory=VerifiedPatch)
    # Required, keyword-only, and deliberately undefaulted: a wall-clock default here
    # would be a non-determinism landmine in a module whose output gets signed (see
    # module docstring). Every caller must say what "now" is; build_advisory() and
    # AdvisoryFormatter already do, via --published-at / SOURCE_DATE_EPOCH / clock in
    # that priority order (see cli/advise.py::_resolve_now).
    published: str = field(kw_only=True)
    modified: str = field(kw_only=True)
    id: str | None = None  # noqa: A003 — set in __post_init__ if not provided
    # Package-intrinsic sub-location the finding applies to (e.g. an MCP tool name).
    # Deliberately NEVER a filesystem path or anything else derived from the scanning
    # host — advisory IDs must be identical on every machine that observes the same
    # vulnerability, and mcp-audit is privacy-first. Empty string = whole package.
    location: str = ""
    # "package-intrinsic" | "deployment" — see module docstring constants.
    observation: str = OBSERVATION_DEPLOYMENT
    # Cross-references to public vulnerability identifiers (e.g. ["CVE-2026-1234"]).
    aliases: list[str] = field(default_factory=list)
    # CWE identifiers carried through from the originating finding (e.g. ["CWE-798"]).
    cwe_ids: list[str] = field(default_factory=list)
    # How the CVSS vector in `severity` was derived. See advisory/classify.py.
    cvss_basis: str | None = None

    def __post_init__(self) -> None:
        # If the finding class is a known fixable one, ensure its OWASP code is present.
        if self.finding_class in FIXABLE_FINDING_CLASSES and not self.owasp_mcp:
            self.owasp_mcp = [owasp_for(self.finding_class)]
        # A code that owasp_mcp.py does not recognise must never reach the feed: the
        # OWASP taxonomy has exactly one definition in this repo, and publishing a
        # code outside it would be inventing one.
        unknown = [code for code in self.owasp_mcp if not is_valid_code(code)]
        if unknown:
            raise ValueError(
                f"Unknown OWASP MCP Top 10 code(s) {unknown}; "
                f"valid codes are defined in mcp_audit.owasp_mcp"
            )
        if self.id is None:
            self.id = self.stable_id()

    def stable_id(self) -> str:
        """Deterministic ID: <prefix>-<12 hex of package+rule+class+introduced+loc>.

        The basis contains only package coordinates and vulnerability identity — never
        a timestamp — so two machines observing the same issue mint the same advisory
        ID regardless of when either one scanned, and a recurring issue keeps the same
        ID across a UTC year boundary. An earlier version embedded ``published[:4]``
        (the publication year) in the ID; that meant the same vulnerability advised on
        either side of midnight on Dec 31 minted two different IDs, breaking dedup for
        anyone trying to answer "have I seen this advisory?". ``location`` is appended
        only when non-empty, which keeps IDs stable for whole-package records.
        """
        basis_parts = [
            self.package.ecosystem,
            self.package.name,
            self.mcp_audit_rule_id,
            self.finding_class,
            self.introduced,
        ]
        if self.location:
            basis_parts.append(self.location)
        digest = hashlib.sha256("|".join(basis_parts).encode()).hexdigest()[:12]
        return f"{ID_PREFIX}-{digest}"

    def to_osv(self) -> dict:
        """Return an OSV 1.6.0 record. Keys are sorted by to_canonical_json()."""
        database_specific = {
            "owasp_mcp": list(self.owasp_mcp),
            "mcp_transport": self.mcp_transport,
            "finding_class": self.finding_class,
            "mcp_audit_rule_id": self.mcp_audit_rule_id,
            "verified_patch": self.verified_patch.as_dict(),
            "observation": self.observation,
        }
        if self.location:
            database_specific["mcp_location"] = self.location
        if self.cwe_ids:
            database_specific["cwe_ids"] = list(self.cwe_ids)
        if self.cvss_basis is not None:
            database_specific["cvss_basis"] = self.cvss_basis
        if not self.owasp_mcp:
            # OUT OF SCOPE rule: never invent an OWASP code. An empty list plus an
            # explicit TODO is the honest representation of "no clean mapping yet".
            database_specific["owasp_mcp_todo"] = (
                f"TODO: no published OWASP MCP Top 10 category maps cleanly to "
                f"{self.mcp_audit_rule_id}; see docs/owasp-mapping.json"
            )

        affected = {
            "package": {
                "ecosystem": self.package.ecosystem,
                "name": self.package.name,
                "purl": self.package.purl,
            },
            "ranges": [
                {
                    "type": "SEMVER",
                    "events": _range_events(self.introduced, self.fixed),
                }
            ],
            "database_specific": database_specific,
        }
        record = {
            "schema_version": SCHEMA_VERSION,
            "id": self.id,
            "modified": self.modified,
            "published": self.published,
            "summary": self.summary,
            "details": self.details,
            "affected": [affected],
        }
        if self.aliases:
            record["aliases"] = sorted(self.aliases)
        if self.severity:
            record["severity"] = [
                {"type": s.type, "score": s.score} for s in self.severity
            ]
        if self.references:
            record["references"] = [
                {"type": r.type, "url": r.url} for r in self.references
            ]
        return record

    def to_canonical_json(self) -> str:
        """Sorted-key, compact JSON. sign.py applies RFC 8785 before signing."""
        return json.dumps(self.to_osv(), sort_keys=True, separators=(",", ":"))


def _range_events(introduced: str, fixed: str | None) -> list[dict]:
    events = [{"introduced": introduced}]
    if fixed is not None:
        events.append({"fixed": fixed})
    return events
