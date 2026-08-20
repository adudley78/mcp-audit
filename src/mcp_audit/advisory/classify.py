"""Classification of mcp-audit findings into advisory taxonomy.

Three orthogonal questions are answered here, one function each:

``finding_class_for``
    Which vulnerability class does this finding belong to? The three classes that
    ``mcp-audit fix`` remediates (``hardcoded-secret``, ``excessive-scope``,
    ``command-injection``) are named in :mod:`mcp_audit.advisory.schema`; the rest
    of the taxonomy lives here because it exists only to label advisories.

``observation_for``
    Is this a statement about the *published package* or about the way an operator
    *deployed* it? A feed consumer needs to know whether to route a record to the
    upstream maintainer or to the operator, and publishing "package X is vulnerable"
    when the real defect is a local misconfiguration would be plainly wrong.

``cvss_for``
    Which CVSS 3.1 vector describes it? See :data:`CVSS_BY_CLASS` for how these are
    derived and why the derivation is recorded in each advisory.

OWASP MCP Top 10 codes are *not* derived here. They come from
``Finding.owasp_mcp_top_10``, which ``scripts/validate_owasp_mapping.py`` already
holds to ``docs/owasp-mapping.json``. :func:`owasp_codes_for` only validates them
against :mod:`mcp_audit.owasp_mcp`, the repo's single definition of the taxonomy.
"""

from __future__ import annotations

import re
from typing import Final

from mcp_audit.models import Severity
from mcp_audit.owasp_mcp import is_valid_code

from .schema import OBSERVATION_DEPLOYMENT, OBSERVATION_PACKAGE

__all__ = [
    "CVSS_BY_CLASS",
    "CVSS_BY_SEVERITY",
    "NON_ADVISORY_IDS",
    "cvss_base_score",
    "cvss_for",
    "finding_class_for",
    "is_advisable",
    "observation_for",
    "owasp_codes_for",
]

# Findings that assert no vulnerability and therefore must never become an advisory:
# positive signals, first-run bookkeeping, and operational errors. Publishing these
# would fill the feed with records that claim nothing and cannot be remediated.
# Most are entries in docs/owasp-mapping.json with an empty owasp_codes list;
# CFHYG-004 is the one exception (see its own comment below).
NON_ADVISORY_IDS: Final[frozenset[str]] = frozenset(
    {
        "RUGPULL-000",  # first scan — baseline recorded, no prior state to compare
        "RUGPULL-002",  # new server detected — recorded for future comparison, benign
        "RUGPULL-003",  # server removed — benign
        "ATTEST-010",  # Sigstore provenance verified — positive signal
        "ATTEST-015",  # verification error — operational, not a defect
        "CFHYG-004",  # env-var references used for credentials — positive signal;
        # carries owasp_codes: ["MCP01"] in docs/owasp-mapping.json (it is itself a
        # positive-signal *mapping*, not an empty one) — excluded here on its merits,
        # not because it is unmapped.
        "BL-001",  # malformed baseline file — operational error
        "COMM-000",  # community rule template stub — never matches real configs
    }
)

# DRIFT-* ids are minted per-event at scan time (see cli/scan.py::_drift_to_findings)
# and can't be enumerated into NON_ADVISORY_IDS above. A removed server is the
# drift-pipeline equivalent of RUGPULL-003 (benign bookkeeping, not a vulnerability),
# and is recognisable by a stable, literal id prefix rather than a hash — see
# _drift_to_findings's docstring for why the drift type is embedded unhashed.
_NON_ADVISORY_ID_PREFIXES: Final[tuple[str, ...]] = ("DRIFT-SERVER_REMOVED-",)


def is_advisable(finding_id: str) -> bool:
    """Return True if a finding asserts something an advisory can meaningfully claim."""
    if finding_id in NON_ADVISORY_IDS:
        return False
    return not finding_id.startswith(_NON_ADVISORY_ID_PREFIXES)


# ── Finding class ─────────────────────────────────────────────────────────────

# Exact finding IDs whose class is not implied by their prefix. Checked first.
_CLASS_BY_ID: Final[dict[str, str]] = {
    # The three classes `mcp-audit fix` remediates.
    "CRED-001": "hardcoded-secret",
    "CRED-002": "hardcoded-secret",
    "CFHYG-003": "hardcoded-secret",
    "COMM-008": "hardcoded-secret",
    "COMM-009": "hardcoded-secret",
    "COMM-021": "hardcoded-secret",
    "COMM-022": "hardcoded-secret",
    "COMM-023": "hardcoded-secret",
    "TRANSPORT-002": "excessive-scope",
    "COMM-011": "excessive-scope",
    "COMM-034": "excessive-scope",
    "COMM-001": "command-injection",
    "COMM-002": "command-injection",
    "COMM-004": "command-injection",
    "COMM-005": "command-injection",
    "COMM-006": "command-injection",
    "COMM-007": "command-injection",
    "COMM-015": "command-injection",
    # Everything else.
    "TRANSPORT-001": "unencrypted-transport",
    "TRANSPORT-003": "unpinned-dependency",
    "TRANSPORT-004": "network-exposure",
    "SC-004": "known-vulnerability",
    "COMM-003": "sandbox-disabled",
    "COMM-010": "unpinned-dependency",
    "COMM-012": "network-exposure",
    "COMM-013": "unpinned-dependency",
    "COMM-014": "excessive-scope",
    "COMM-024": "missing-authentication",
    "COMM-025": "missing-authentication",
    "COMM-026": "unencrypted-transport",
    "COMM-027": "unidentified-server",
    "COMM-028": "unpinned-dependency",
    "COMM-029": "unpinned-dependency",
    "COMM-030": "unidentified-server",
    "COMM-031": "missing-authentication",
    "COMM-033": "untrusted-config-origin",
    "COLLIDE-001": "tool-collision",
    "TRUST-001": "untrusted-config-origin",
    "CFHYG-005": "hook-execution",
}

# Prefix → class, applied when no exact ID match exists. Longest prefix wins.
_CLASS_BY_PREFIX: Final[dict[str, str]] = {
    "POISON-": "tool-poisoning",
    "SKILL-": "tool-poisoning",
    "MEM-": "tool-poisoning",
    "HOOK-": "hook-execution",
    "SC-": "typosquat",
    "CFHYG-": "config-hygiene",
    "TOXIC-": "toxic-flow",
    "RUGPULL-": "rug-pull",
    "AUTH-": "missing-authentication",
    "ATTEST-": "unverified-provenance",
    "ATT-": "unverified-provenance",
    "EXT-": "ide-extension",
    "SAST-": "source-vulnerability",
    "GOV-": "policy-violation",
    "DRIFT-": "configuration-drift",
    "BL-": "operational-error",
    "COMM-": "community-rule",
}

_FALLBACK_CLASS: Final[str] = "unclassified"


def finding_class_for(finding_id: str) -> str:
    """Return the advisory ``finding_class`` for an mcp-audit finding ID.

    Unknown IDs fall back to ``"unclassified"`` rather than raising: a new detection
    rule must never be able to crash advisory generation.
    """
    exact = _CLASS_BY_ID.get(finding_id)
    if exact is not None:
        return exact
    for prefix in sorted(_CLASS_BY_PREFIX, key=len, reverse=True):
        if finding_id.startswith(prefix):
            return _CLASS_BY_PREFIX[prefix]
    return _FALLBACK_CLASS


# ── Observation kind ──────────────────────────────────────────────────────────

# Prefixes whose findings describe the published artifact itself. Anything not listed
# here is treated as a deployment observation, which is the conservative default: it
# never asserts a defect in someone else's package on thin evidence.
_PACKAGE_INTRINSIC_PREFIXES: Final[tuple[str, ...]] = (
    "POISON-",
    "SC-",
    "ATTEST-",
    "ATT-",
    "SAST-",
    "EXT-",
    "COLLIDE-",
)


def observation_for(finding_id: str) -> str:
    """Return ``"package-intrinsic"`` or ``"deployment"`` for a finding ID."""
    if finding_id.startswith(_PACKAGE_INTRINSIC_PREFIXES):
        return OBSERVATION_PACKAGE
    return OBSERVATION_DEPLOYMENT


# ── OWASP codes ───────────────────────────────────────────────────────────────


def owasp_codes_for(codes: list[str]) -> list[str]:
    """Validate ``Finding.owasp_mcp_top_10`` entries for publication.

    The advisory feed publishes the same bare ``MCP01``..``MCP10`` codes that
    :mod:`mcp_audit.owasp_mcp` defines and that SARIF output and
    ``docs/owasp-mapping.json`` already use, so a consumer can join a record to the rest
    of mcp-audit's output without translating between spellings.

    A year-suffixed form (``"MCP01:2025"``) is accepted on input and normalised, because
    OWASP publishes the categories that way and a caller may pass one through.
    Unrecognised strings are dropped rather than passed along — the feed must never emit
    an invented code. Order is preserved and duplicates removed.
    """
    resolved: list[str] = []
    for raw in codes:
        bare = raw.split(":")[0].strip().upper()
        if is_valid_code(bare) and bare not in resolved:
            resolved.append(bare)
    return resolved


# ── CVSS ──────────────────────────────────────────────────────────────────────

# CVSS 3.1 vectors are *derived*, not independently assessed per record, and every
# advisory says which derivation produced it via `database_specific.cvss_basis`:
#
#   "finding-class-template"  the class has stable exploitation characteristics across
#                             every finding in it, so one vector describes them all
#   "severity-band"           no class template applies, or the template would have
#                             over-claimed (see `cvss_for`); the vector encodes
#                             mcp-audit's own severity rubric — see
#                             docs/severity-framework.md
#
# Consumers that need a rigorous per-instance score should treat these as a starting
# point. Recording the basis is what keeps that distinction visible downstream.
CVSS_BY_CLASS: Final[dict[str, str]] = {
    "hardcoded-secret": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
    "command-injection": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H",
    "excessive-scope": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N",
    "tool-poisoning": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
    "typosquat": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H",
    "known-vulnerability": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "unencrypted-transport": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "unpinned-dependency": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H",
    "missing-authentication": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "network-exposure": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    "toxic-flow": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N",
    "hook-execution": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
    "unverified-provenance": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H",
    "tool-collision": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
    "untrusted-config-origin": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H",
    "sandbox-disabled": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N",
}

CVSS_BY_SEVERITY: Final[dict[Severity, str]] = {
    Severity.CRITICAL: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    Severity.HIGH: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
    Severity.MEDIUM: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
    Severity.LOW: "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N",
    Severity.INFO: "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N",
}

CVSS_BASIS_CLASS: Final[str] = "finding-class-template"
CVSS_BASIS_SEVERITY: Final[str] = "severity-band"

# Highest CVSS 3.1 base score each mcp-audit severity is allowed to publish, using the
# standard qualitative bands (Low 0.1–3.9, Medium 4.0–6.9, High 7.0–8.9, Critical 9.0+).
_SEVERITY_CEILING: Final[dict[Severity, float]] = {
    Severity.CRITICAL: 10.0,
    Severity.HIGH: 8.9,
    Severity.MEDIUM: 6.9,
    Severity.LOW: 3.9,
    Severity.INFO: 0.0,
}


def cvss_for(finding_class: str, severity: Severity) -> tuple[str, str]:
    """Return ``(cvss_3_1_vector, basis)`` for a finding class and severity.

    A class template is used only when it does not over-claim: a template scoring
    higher than the finding's own severity band is discarded in favour of the
    severity-band vector. Without that check a LOW ``unpinned-dependency`` finding
    would publish a High CVSS score, and a feed that inflates its own records is worth
    less than no feed at all.

    ``basis`` is one of :data:`CVSS_BASIS_CLASS` or :data:`CVSS_BASIS_SEVERITY` and is
    written into the advisory so consumers can see how the score was arrived at.
    """
    template = CVSS_BY_CLASS.get(finding_class)
    if (
        template is not None
        and cvss_base_score(template) <= _SEVERITY_CEILING[severity]
    ):
        return template, CVSS_BASIS_CLASS
    return CVSS_BY_SEVERITY[severity], CVSS_BASIS_SEVERITY


# ── CVSS 3.1 base score ───────────────────────────────────────────────────────

# CVSS v3.1 specification section 7.1 (https://www.first.org/cvss/v3.1/specification-document).
_AV: Final[dict[str, float]] = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC: Final[dict[str, float]] = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED: Final[dict[str, float]] = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED: Final[dict[str, float]] = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI: Final[dict[str, float]] = {"N": 0.85, "R": 0.62}
_CIA: Final[dict[str, float]] = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(value: float) -> float:
    """Round up to one decimal place, per the CVSS 3.1 ``Roundup`` definition."""
    scaled = int(round(value * 100_000))
    if scaled % 10_000 == 0:
        return scaled / 100_000
    return (scaled // 10_000 + 1) / 10.0


def cvss_base_score(vector: str) -> float:
    """Return the CVSS 3.1 base score for a base-metric vector string.

    Args:
        vector: A ``CVSS:3.1/AV:.../A:...`` base vector.

    Returns:
        The base score, rounded up to one decimal place as the specification requires.

    Raises:
        ValueError: The vector is malformed or omits a base metric.
    """
    parts = vector.split("/")
    if not parts or parts[0] != "CVSS:3.1":
        raise ValueError(f"not a CVSS 3.1 vector: {vector!r}")
    metrics = dict(part.split(":", 1) for part in parts[1:] if ":" in part)
    try:
        scope_changed = metrics["S"] == "C"
        exploitability = (
            8.22
            * _AV[metrics["AV"]]
            * _AC[metrics["AC"]]
            * (_PR_CHANGED if scope_changed else _PR_UNCHANGED)[metrics["PR"]]
            * _UI[metrics["UI"]]
        )
        conf, integ, avail = (_CIA[metrics[m]] for m in ("C", "I", "A"))
    except KeyError as exc:
        raise ValueError(
            f"malformed CVSS 3.1 vector {vector!r}: missing {exc}"
        ) from exc

    iss = 1 - ((1 - conf) * (1 - integ) * (1 - avail))
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    if impact <= 0:
        return 0.0
    raw = (
        (1.08 * (impact + exploitability))
        if scope_changed
        else (impact + exploitability)
    )
    return _roundup(min(raw, 10.0))


# ── CVE extraction ────────────────────────────────────────────────────────────

_CVE_RE: Final[re.Pattern[str]] = re.compile(r"\bCVE-\d{4}-\d{4,}\b")


def extract_cves(*texts: str) -> list[str]:
    """Return sorted, de-duplicated CVE IDs found in the given text fragments."""
    found: set[str] = set()
    for text in texts:
        if text:
            found.update(_CVE_RE.findall(text))
    return sorted(found)
