"""Detect dangerous cross-server capability combinations (toxic flows).

Two MCP servers may each be safe in isolation, but together enable an
end-to-end attack path — for example, a file-reading server paired with a
network-capable server creates a file-exfiltration path that neither server
creates alone.

Detection strategy:
1. Tag each server with capability labels (FILE_READ, NETWORK_OUT, etc.) using
   three layers: known-package lookup → keyword matching on command/args →
   tool-name matching from live enumeration data.
2. Check every ordered server pair (including self-pairs) for dangerous
   capability combinations defined in TOXIC_AND_INTEGRITY_PAIRS.
3. Emit a finding naming both servers for each detected combination.

Two claim types, two ID prefixes, one mechanism (R37): TOXIC_PAIRS models
confidentiality ("does data leave?" — source produces data, sink exfiltrates,
finding IDs TOXIC-00x). INTEGRITY_PAIRS models a distinct axis, state
change/persistence ("can content written here be executed there?", finding
IDs INTEG-00x). Both lists share the same ToxicPair shape and are checked by
the same self-pair/cross-pair loop in ToxicFlowAnalyzer.analyze_all(), but
are kept as separate source lists (combined only via TOXIC_AND_INTEGRITY_PAIRS)
so a user filtering on one ID prefix never silently gets the other.

Research basis:
  "Compromising LLM-Integrated Applications with Indirect Prompt Injection"
  Greshake et al., arXiv 2023 §4 — multi-tool attack chaining
  https://arxiv.org/abs/2302.12173

  "LLM Tool Use and the New Attack Surface", Trail of Bits 2024
  https://blog.trailofbits.com/2024/09/12/llm-tool-use/
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from mcp_audit.analyzers.base import BaseAnalyzer
from mcp_audit.models import Finding, ServerConfig, Severity
from mcp_audit.registry.loader import KnownServerRegistry


class Capability(StrEnum):
    """Coarse-grained capability labels for MCP servers."""

    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    NETWORK_OUT = "network_out"
    SHELL_EXEC = "shell_exec"
    DATABASE = "database"
    EMAIL = "email"
    BROWSER = "browser"
    GIT = "git"
    SECRETS = "secrets"
    # Tag-only: recorded and inferable, but deliberately NOT wired into
    # TOXIC_PAIRS or attack_paths.CAPABILITY_FLOWS. Cloud resource access
    # (AWS/GCP/Azure API calls) is already, mechanically, a form of
    # NETWORK_OUT — every cloud SDK call is HTTPS — so it does not open a
    # new exfiltration primitive TOXIC_PAIRS doesn't already cover via
    # NETWORK_OUT. What it *does* add is a materially different blast
    # radius (IAM-scoped infrastructure control, not just "can fetch a
    # URL") that plausibly deserves its own severity/CWE-calibrated pairs
    # (e.g. FILE_READ+CLOUD, SECRETS+CLOUD) — but that calibration needs
    # its own research-and-measurement pass across real registry data, the
    # same standard this file's own conventions hold new TOXIC_PAIRS to
    # (see PROVENANCE.md). Added now so the registry-submission vocabulary
    # is complete and the capability is recorded and auditable; wiring is
    # deliberately deferred rather than guessed.
    CLOUD = "cloud"


@dataclass(frozen=True)
class ToxicPair:
    """A dangerous capability combination that should be flagged when detected."""

    source: Capability
    sink: Capability
    finding_id: str
    severity: Severity
    title: str
    description: str
    remediation: str
    cwe: str | None = None
    owasp_mcp_top_10: tuple[str, ...] = ()


@dataclass(frozen=True)
class KeywordRule:
    """Maps keywords found in server config strings to capability labels."""

    keywords: tuple[str, ...]
    capabilities: frozenset[Capability]


# ── Known server registry ─────────────────────────────────────────────────────

KNOWN_SERVERS: dict[str, frozenset[Capability]] = {
    "@modelcontextprotocol/server-filesystem": frozenset(
        {Capability.FILE_READ, Capability.FILE_WRITE}
    ),
    "@modelcontextprotocol/server-fetch": frozenset({Capability.NETWORK_OUT}),
    "@modelcontextprotocol/server-github": frozenset(
        {Capability.GIT, Capability.NETWORK_OUT}
    ),
    "@modelcontextprotocol/server-git": frozenset(
        {Capability.GIT, Capability.FILE_READ}
    ),
    "@modelcontextprotocol/server-postgres": frozenset({Capability.DATABASE}),
    "@modelcontextprotocol/server-sqlite": frozenset({Capability.DATABASE}),
    "@modelcontextprotocol/server-brave-search": frozenset({Capability.NETWORK_OUT}),
    "@modelcontextprotocol/server-puppeteer": frozenset(
        {Capability.BROWSER, Capability.NETWORK_OUT}
    ),
    "@modelcontextprotocol/server-slack": frozenset({Capability.NETWORK_OUT}),
    "@modelcontextprotocol/server-gdrive": frozenset(
        {Capability.FILE_READ, Capability.NETWORK_OUT}
    ),
    "@modelcontextprotocol/server-gmail": frozenset(
        {Capability.EMAIL, Capability.NETWORK_OUT}
    ),
    "@modelcontextprotocol/server-memory": frozenset(),
    "@modelcontextprotocol/server-sequentialthinking": frozenset(),
    "@modelcontextprotocol/server-everything": frozenset(
        {
            Capability.FILE_READ,
            Capability.FILE_WRITE,
            Capability.NETWORK_OUT,
            Capability.SHELL_EXEC,
        }
    ),
}

# ── Keyword matching rules ────────────────────────────────────────────────────
#
# These rules fire for any server whose command, args, or name contain a
# matching token — including third-party packages NOT in known-servers.json.
# This is intentional: TOXIC-005 (database + network) must fire for e.g.
# `mcp-server-postgres` (community package) just as it does for
# `@modelcontextprotocol/server-postgres` (registry entry).  The registry
# path returns capabilities verbatim for known entries; the keyword path
# provides the same result for unknown-but-recognisable packages via token
# scanning.  Both paths return identical DATABASE capability for any server
# whose package name or server name contains "postgres".  Verified 2026-04-23:
#   r.get("@modelcontextprotocol/server-postgres").capabilities == ["database"]
#   r.get("mcp-server-postgres") is None  →  keyword "postgres" fires instead

KEYWORD_RULES: list[KeywordRule] = [
    KeywordRule(
        keywords=("filesystem", "file-system", "file_system", "file", " fs "),
        capabilities=frozenset({Capability.FILE_READ, Capability.FILE_WRITE}),
    ),
    KeywordRule(
        keywords=("fetch", "http", "https", "request", "curl", "wget", "network"),
        capabilities=frozenset({Capability.NETWORK_OUT}),
    ),
    KeywordRule(
        keywords=("exec", "shell", "bash", " sh ", "terminal", "command", "spawn"),
        capabilities=frozenset({Capability.SHELL_EXEC}),
    ),
    KeywordRule(
        keywords=(
            "postgres",
            "postgresql",
            "mysql",
            "mariadb",
            "sqlite",
            "mongo",
            "mongodb",
            "database",
            " db ",
            "sql",
        ),
        capabilities=frozenset({Capability.DATABASE}),
    ),
    KeywordRule(
        keywords=("gmail", "email", " mail", "smtp", "sendgrid", "mailgun", " ses "),
        capabilities=frozenset({Capability.EMAIL}),
    ),
    KeywordRule(
        keywords=("browser", "puppeteer", "playwright", "selenium", "chrome", "webkit"),
        capabilities=frozenset({Capability.BROWSER}),
    ),
    KeywordRule(
        keywords=("github", "gitlab", "bitbucket", " git"),
        capabilities=frozenset({Capability.GIT}),
    ),
    KeywordRule(
        keywords=("vault", "secret", "credential", "keychain", "1password", "password"),
        capabilities=frozenset({Capability.SECRETS}),
    ),
    KeywordRule(
        keywords=(
            "aws",
            "gcp",
            "azure",
            "s3",
            "ec2",
            "lambda",
            "cloudformation",
            "kubernetes",
            "k8s",
            "gke",
            "eks",
            "boto3",
            "gcloud",
        ),
        capabilities=frozenset({Capability.CLOUD}),
    ),
]

# ── Toxic pair definitions ────────────────────────────────────────────────────

TOXIC_PAIRS: list[ToxicPair] = [
    # NOTE: every pair below is exfiltration-shaped (source "produces data",
    # sink "leaks it out" — see attack_paths._SOURCE_CAPS/_SINK_CAPS). This
    # models exactly one axis: confidentiality. Integrity (state change /
    # persistence) is a SEPARATE, narrower list — see INTEGRITY_PAIRS below.
    # Do not add a persistence-shaped pair here; it would silently change
    # what "TOXIC-*" means to anyone filtering on that ID prefix.
    ToxicPair(
        source=Capability.FILE_READ,
        sink=Capability.NETWORK_OUT,
        finding_id="TOXIC-001",
        severity=Severity.HIGH,
        title="File read + network exfiltration path",
        description=(
            "One server can read local files while another can make outbound "
            "network requests. An attacker or prompt injection could chain these "
            "to exfiltrate sensitive files."
        ),
        remediation=(
            "Review whether both servers are necessary. Consider restricting "
            "file access paths or network destinations."
        ),
        cwe="CWE-200",
        owasp_mcp_top_10=("MCP05", "MCP10"),
    ),
    ToxicPair(
        source=Capability.FILE_READ,
        sink=Capability.EMAIL,
        finding_id="TOXIC-002",
        severity=Severity.HIGH,
        title="File read + email exfiltration path",
        description=(
            "One server can read local files while another can send emails. "
            "Sensitive files could be exfiltrated via email."
        ),
        remediation=(
            "Review whether both servers need these capabilities. "
            "Restrict file access or email recipients."
        ),
        cwe="CWE-200",
        owasp_mcp_top_10=("MCP05", "MCP10"),
    ),
    ToxicPair(
        source=Capability.SECRETS,
        sink=Capability.NETWORK_OUT,
        finding_id="TOXIC-003",
        severity=Severity.CRITICAL,
        title="Secret access + network exfiltration path",
        description=(
            "One server can access credential stores while another can make "
            "outbound requests. Credentials could be exfiltrated."
        ),
        remediation=(
            "Isolate secret-accessing servers from any server with network "
            "capabilities."
        ),
        cwe="CWE-522",
        owasp_mcp_top_10=("MCP01", "MCP10"),
    ),
    ToxicPair(
        source=Capability.FILE_READ,
        sink=Capability.SHELL_EXEC,
        finding_id="TOXIC-004",
        severity=Severity.HIGH,
        title="File read + shell execution path",
        description=(
            "One server can read files while another can execute shell commands. "
            "Malicious content could be read from a file and executed."
        ),
        remediation=(
            "Review whether both servers are necessary. Restrict shell execution scope."
        ),
        cwe="CWE-78",
        owasp_mcp_top_10=("MCP10",),
    ),
    ToxicPair(
        source=Capability.DATABASE,
        sink=Capability.NETWORK_OUT,
        finding_id="TOXIC-005",
        severity=Severity.HIGH,
        title="Database access + network exfiltration path",
        description=(
            "One server can query databases while another can make outbound "
            "requests. Database contents could be exfiltrated."
        ),
        remediation=(
            "Review whether both servers need these capabilities. "
            "Restrict database queries or network destinations."
        ),
        cwe="CWE-200",
        owasp_mcp_top_10=("MCP05", "MCP10"),
    ),
    ToxicPair(
        source=Capability.SHELL_EXEC,
        sink=Capability.NETWORK_OUT,
        finding_id="TOXIC-006",
        severity=Severity.CRITICAL,
        title="Shell execution + network exfiltration path",
        description=(
            "One server can execute shell commands while another can make "
            "outbound requests. This combination enables arbitrary command "
            "execution with data exfiltration."
        ),
        remediation=(
            "This is a high-risk combination. Remove one server or implement "
            "strict sandboxing."
        ),
        cwe="CWE-78",
        owasp_mcp_top_10=("MCP05", "MCP10"),
    ),
    ToxicPair(
        source=Capability.GIT,
        sink=Capability.NETWORK_OUT,
        finding_id="TOXIC-007",
        severity=Severity.MEDIUM,
        title="Git access + network exfiltration path",
        description=(
            "One server can access git repositories while another can make "
            "outbound requests. Source code or commit history could be "
            "exfiltrated."
        ),
        remediation=(
            "Review whether both servers are necessary. Consider read-only git access."
        ),
        cwe="CWE-200",
        owasp_mcp_top_10=("MCP10",),
    ),
]


# ── Integrity pairs ────────────────────────────────────────────────────────
#
# R37 measured what FILE_WRITE participates in nowhere: TOXIC_PAIRS only
# models confidentiality (does data leave?). It never asks whether state can
# be changed, or whether a change persists and later re-executes. Adding
# FILE_WRITE to TOXIC_PAIRS was rejected for the general case — see the R37
# measurement recorded in GAPS.md — so this is a second, narrower list for
# a different claim: "content written by one server can be executed by
# another." Kept separate from TOXIC_PAIRS deliberately, with a distinct
# finding-ID prefix (INTEG-*, never TOXIC-*), so a user filtering on
# TOXIC-* for exfiltration risk does not silently also get integrity
# findings, and vice versa. ToxicFlowAnalyzer and shadow/risk.py both
# consume TOXIC_AND_INTEGRITY_PAIRS (defined below), not this list alone.
#
# Measurement (R37, 50-entry registry, 2026-09-08):
#   - FILE_WRITE + SHELL_EXEC: 1 self-pair (server-everything, a kitchen-sink
#     demo server that is SUPPOSED to trip every rule) and 11 cross-server
#     pairs across a mega-scan of all 50 registry entries combined (3
#     FILE_WRITE-capable entries x 4 SHELL_EXEC-capable entries, minus
#     self-overlaps). Small numbers, and the combinations are dominated by
#     servers already flagged elsewhere for unrelated CVEs (@mcpjam/inspector,
#     flowise, gemini-mcp-tool) rather than an "obviously benign, why did
#     this fire" server. Severity is calibrated against TOXIC-004
#     (FILE_READ + SHELL_EXEC) rather than borrowed from an exfiltration
#     pair: the shape is identical (attacker-controlled content reaches a
#     shell-exec sink), just via a write instead of a read, and SHELL_EXEC's
#     reach is not scoped by mcp-audit's capability model any more for a
#     write than for a read — so the write-target problem that blocks
#     FILE_WRITE + NETWORK_OUT (see below) does not apply here.
#   - FILE_WRITE + NETWORK_OUT was measured and explicitly REJECTED as a
#     general pair (self- or cross-server): 2 self-pair hits (docpull —
#     the exact motivating "fetch and persist" case — and server-everything)
#     but 60 cross-server pairs in the same mega-scan, almost entirely
#     `@modelcontextprotocol/server-filesystem` (a completely generic,
#     extremely common server whose entire stated purpose is file I/O)
#     paired against every one of the 21 NETWORK_OUT-capable registry
#     entries. Severity for this pair depends almost entirely on WHERE the
#     write lands — a scratch directory is nothing, `~/.claude/CLAUDE.md`
#     is critical — and mcp-audit's capability model has no notion of write
#     target (tag_server() never inspects a server's configured directory
#     argument). Shipping one severity for two situations that differ by
#     orders of magnitude was rejected as indefensible per this project's
#     own severity-framework conventions. Recorded as a known, MEASURED gap
#     in GAPS.md (not silently dropped, and not the same as CLOUD's
#     deliberate-deferral shape) pending a write-target model.
INTEGRITY_PAIRS: list[ToxicPair] = [
    ToxicPair(
        source=Capability.FILE_WRITE,
        sink=Capability.SHELL_EXEC,
        finding_id="INTEG-001",
        severity=Severity.HIGH,
        title="File write + shell execution path (plant-then-execute)",
        description=(
            "One server can write files while another can execute shell "
            "commands. An attacker or prompt injection could write a "
            "malicious script or payload via the file-writing server and "
            "have the shell-execution server run it — the same "
            "content-reaches-execution chain as reading a malicious file "
            "and executing it (TOXIC-004), but via a write instead of a "
            "read. This is an integrity finding (state change/persistence), "
            "not an exfiltration finding."
        ),
        remediation=(
            "Review whether both servers are necessary. Treat any location "
            "the file-writing server can reach as untrusted input to the "
            "shell-execution server, and restrict shell execution scope."
        ),
        cwe="CWE-78",
        owasp_mcp_top_10=("MCP05",),
    ),
]

# Combined pair list for pair-based detection. ToxicFlowAnalyzer.analyze_all()
# and shadow/risk.py::score_risk() both need every rule — TOXIC_PAIRS
# (confidentiality/exfiltration) plus INTEGRITY_PAIRS (integrity/persistence)
# — but the two source lists stay separate so a reader auditing "what counts
# as exfiltration" vs "what counts as integrity" can inspect each list on its
# own. Do not collapse them back into one list; import THIS constant instead
# of concatenating TOXIC_PAIRS + INTEGRITY_PAIRS at each call site.
TOXIC_AND_INTEGRITY_PAIRS: list[ToxicPair] = TOXIC_PAIRS + INTEGRITY_PAIRS


# ── Tag-only capabilities ───────────────────────────────────────────────────
#
# A Capability member that appears in no TOXIC_PAIRS entry (source or sink)
# and no attack_paths.CAPABILITY_FLOWS entry can be recorded on a server but
# can never contribute to a toxic-flow or attack-path finding — the same
# shape as the R34 "subprocess" defect (a capability that is recorded, looks
# meaningful, and does nothing), just arriving through deliberate design (or
# an unnoticed gap) instead of a typo. R35 added compute_dead_capabilities()
# / scripts/audit_registry.py's find_dead_capabilities() to compute this set
# at audit time and compare it against the explicit list below, so the next
# tag-only addition is a conscious act, not an accident silently inherited
# from adding an enum value without wiring it into either table. A capability
# found dead but NOT listed here fails that check loudly, in the same spirit
# as the duplicate-name guard in registry/loader.py — which fails loudly
# because a silent wrong answer had already shipped once.
#
# ``kind`` distinguishes WHY a member is here, because collapsing that
# distinction is exactly how "subprocess" sat inert for months: an allowlist
# that can't tell an accepted design decision from a known-but-unfixed gap
# launders the second into the first, and nobody looks at it again.
#   - DELIBERATE_DEFERRAL: wiring was consciously postponed pending its own
#     calibration pass; there is no known missing table row today.
#   - SUSPECTED_GAP: the capability is dead because the detection MODEL has
#     no axis to express it — not because someone chose to leave it out.
#     This is a known, unfixed gap, not a settled decision; do not read it
#     as one.
# ``reason`` is mandatory and non-empty (enforced in __post_init__) — no
# member may be added without saying, in prose, which of the two it is and
# why.


class TagOnlyKind(StrEnum):
    """Why a capability is listed in KNOWN_TAG_ONLY_CAPABILITIES."""

    DELIBERATE_DEFERRAL = "deliberate_deferral"
    SUSPECTED_GAP = "suspected_gap"


@dataclass(frozen=True)
class TagOnlyCapability:
    """One allowlisted tag-only capability, with a mandatory reason.

    Raises:
        ValueError: if ``reason`` is empty/whitespace-only. A tag-only entry
            with no stated reason is indistinguishable from an accident —
            the exact failure mode this allowlist exists to prevent.
    """

    capability: Capability
    kind: TagOnlyKind
    reason: str

    def __post_init__(self) -> None:
        if not self.reason.strip():
            raise ValueError(
                f"TagOnlyCapability({self.capability!r}) has an empty reason — "
                "every tag-only allowlist entry must say, in prose, why it is "
                "here and whether it is a deliberate deferral or a suspected gap."
            )


KNOWN_TAG_ONLY_CAPABILITIES: tuple[TagOnlyCapability, ...] = (
    TagOnlyCapability(
        capability=Capability.CLOUD,
        kind=TagOnlyKind.DELIBERATE_DEFERRAL,
        reason=(
            "Cloud SDK calls are already NETWORK_OUT mechanically, so CLOUD "
            "does not open a new exfiltration primitive TOXIC_PAIRS doesn't "
            "already cover. Calibrating dedicated pairs for its distinct "
            "blast radius (IAM-scoped infrastructure control) needs its own "
            "research-and-measurement pass (R34), not a guess made here."
        ),
    ),
    # R35 flagged FILE_WRITE here as a SUSPECTED_GAP (no axis in the model
    # for state change/persistence). R37 measured it (see INTEGRITY_PAIRS
    # above and GAPS.md's "Toxic flow analysis — FILE_WRITE integrity axis
    # (R37)" section) and added INTEG-001 (FILE_WRITE + SHELL_EXEC).
    # FILE_WRITE now participates in a real detection path via
    # TOXIC_AND_INTEGRITY_PAIRS, so it is no longer dead and this allowlist
    # entry is removed — do not re-add it without a fresh measurement.
    # FILE_WRITE + NETWORK_OUT remains a separate, still-open, MEASURED gap
    # (write-target severity problem) — tracked in GAPS.md, not here, since
    # FILE_WRITE as a capability is no longer tag-only.
)

_KNOWN_TAG_ONLY_CAP_SET: frozenset[Capability] = frozenset(
    t.capability for t in KNOWN_TAG_ONLY_CAPABILITIES
)


def compute_dead_capabilities() -> frozenset[Capability]:
    """Return Capability members that participate in no detection path.

    "Participate" means appearing as a source or sink in
    :data:`TOXIC_AND_INTEGRITY_PAIRS` (i.e. :data:`TOXIC_PAIRS` or
    :data:`INTEGRITY_PAIRS`), or as either element of an
    :data:`~mcp_audit.analyzers.attack_paths.CAPABILITY_FLOWS` edge. A
    capability outside both sets can be recorded on a server (and inferred
    by keyword heuristics, if a :data:`KEYWORD_RULES` entry exists for it)
    but can never cause a finding to fire.

    Imports ``attack_paths`` lazily: ``attack_paths.py`` imports ``Capability``
    and ``TOXIC_PAIRS`` FROM this module, so a top-level import here would be
    circular.

    Returns:
        Frozen set of dead :class:`Capability` members. Compare against
        :data:`KNOWN_TAG_ONLY_CAPABILITIES` (via ``_KNOWN_TAG_ONLY_CAP_SET``
        for membership, or the full tuple for each entry's ``kind``/
        ``reason``) to distinguish an accounted-for tag-only capability —
        deliberate or a known suspected gap — from an accidental one.
    """
    from mcp_audit.analyzers.attack_paths import CAPABILITY_FLOWS  # noqa: PLC0415

    used: set[Capability] = set()
    for tp in TOXIC_AND_INTEGRITY_PAIRS:
        used.add(tp.source)
        used.add(tp.sink)
    for source_cap, sink_cap in CAPABILITY_FLOWS:
        used.add(source_cap)
        used.add(sink_cap)
    return frozenset(Capability) - used


# ── Capability tagging ────────────────────────────────────────────────────────


_CAPABILITY_VALUES: frozenset[str] = frozenset(c.value for c in Capability)


def _is_known_cap(value: str) -> bool:
    """Return True if *value* matches a defined :class:`Capability` member.

    Unknown capability strings in registry data are dropped silently so a
    future-schema capability name in an updated registry does not crash
    older clients.
    """
    return value in _CAPABILITY_VALUES


def tag_server(
    server: ServerConfig,
    registry: KnownServerRegistry | None = None,
) -> frozenset[Capability]:
    """Assign capability labels to a server.

    When *registry* is supplied and contains a :class:`RegistryEntry` for
    this server's package name with ``capabilities`` explicitly set, those
    capability tags are returned verbatim — the registry is the single
    source of truth and no keyword or tool-name matching is performed.

    Otherwise falls back to a three-layer heuristic approach (used when
    *registry* is ``None``, when the package is not in the registry, or when
    the registry entry does not yet have capability data):

    1. **Known-package lookup** — exact match of any arg against
       :data:`KNOWN_SERVERS` (an in-module fallback table).
    2. **Keyword matching** — scan command name, server name, and all args for
       keywords defined in :data:`KEYWORD_RULES`.
    3. **Tool-name matching** — if the server's ``raw`` dict contains a
       ``"tools"`` key (populated by live ``--connect`` enumeration), apply the
       same keyword rules to tool names and descriptions.

    Args:
        server: The server configuration to tag.
        registry: Optional pre-loaded :class:`KnownServerRegistry` to consult
            for authoritative capability data.

    Returns:
        An immutable set of :class:`Capability` values.
    """
    # Registry-first path: if the server resolves to a registry entry with
    # capability data, return those capabilities directly without heuristics.
    # Security reviewed: "token" here is a CLI command/arg string, not a secret.
    if registry is not None:
        for token in [server.command or "", *server.args, server.name]:
            if not token:
                continue
            entry = registry.get(token)
            if entry is not None and entry.capabilities is not None:
                return frozenset(
                    Capability(c) for c in entry.capabilities if _is_known_cap(c)
                )

    caps: set[Capability] = set()

    # Layer 1 — known server registry (check all args for package names).
    for token in [server.command or "", *server.args, server.name]:
        if token in KNOWN_SERVERS:
            caps.update(KNOWN_SERVERS[token])

    # Layer 2 — keyword matching on the full token string.
    search_text = (
        " "
        + " ".join(
            t for t in [server.command or "", server.name, *server.args] if t
        ).lower()
        + " "
    )

    for rule in KEYWORD_RULES:
        for kw in rule.keywords:
            if kw in search_text:
                caps.update(rule.capabilities)
                break  # One keyword match per rule is enough.

    # Layer 3 — tool-name matching from live enumeration data.
    tools: list[dict] = server.raw.get("tools", []) if server.raw else []
    if tools:
        tool_text = (
            " "
            + " ".join(
                f"{t.get('name', '')} {t.get('description', '')}"
                for t in tools
                if isinstance(t, dict)
            ).lower()
            + " "
        )

        for rule in KEYWORD_RULES:
            for kw in rule.keywords:
                if kw in tool_text:
                    caps.update(rule.capabilities)
                    break

    return frozenset(caps)


# ── Analyzer ──────────────────────────────────────────────────────────────────


class ToxicFlowAnalyzer(BaseAnalyzer):
    """Detect dangerous cross-server capability combinations.

    Operates across all servers collectively — the single-server
    :meth:`analyze` always returns an empty list.  The orchestrator
    must call :meth:`analyze_all` instead.

    When a :class:`KnownServerRegistry` is passed to ``__init__``, its
    per-entry ``capabilities`` lists take precedence over keyword-based
    heuristics during server tagging.
    """

    def __init__(self, registry: KnownServerRegistry | None = None) -> None:
        """Initialise with an optional registry for capability lookups.

        Args:
            registry: Pre-loaded :class:`KnownServerRegistry` whose entries'
                ``capabilities`` fields override the in-module
                :data:`KNOWN_SERVERS` fallback.  When ``None`` the analyzer
                runs in pure heuristic mode — matching the behaviour from
                before the registry migration.
        """
        self._registry = registry

    @property
    def name(self) -> str:
        return "toxic_flow"

    @property
    def description(self) -> str:
        return "Detect dangerous capability combinations across MCP servers"

    def analyze(self, server: ServerConfig) -> list[Finding]:
        """No-op for single-server analysis — toxic flow is cross-server.

        The scanner calls :meth:`analyze_all` with the full server list.
        """
        return []

    def analyze_all(self, servers: list[ServerConfig]) -> list[Finding]:
        """Check all server pairs for dangerous capability combinations.

        Checks every rule in :data:`TOXIC_AND_INTEGRITY_PAIRS` — both the
        exfiltration-shaped :data:`TOXIC_PAIRS` and the integrity-shaped
        :data:`INTEGRITY_PAIRS` — so both claims are detected by the same
        pair-matching mechanism while keeping distinct finding-ID prefixes
        (``TOXIC-*`` vs ``INTEG-*``).

        Considers both cross-server pairs and single-server self-pairs (a
        server that alone has both the source and sink capability is at least
        as dangerous as a two-server combination).

        For each unordered pair ``{A, B}`` (including ``{A, A}``):
        - Cross-pair: emit a finding if A has the toxic-pair's source
          capability and B has the sink capability, *or* vice-versa.
          Only one finding is emitted per (pair, rule) combination.
        - Self-pair: emit a finding if the single server has both
          the source and sink capabilities.

        Args:
            servers: All MCP servers discovered in the current scan.

        Returns:
            List of :class:`~mcp_audit.models.Finding` objects, one per
            detected toxic pair.  Empty when no dangerous combinations exist.
        """
        findings: list[Finding] = []
        n = len(servers)
        # Cache tags so each server is only tagged once.
        caps: list[frozenset[Capability]] = [
            tag_server(s, registry=self._registry) for s in servers
        ]

        for i in range(n):
            for j in range(i, n):
                caps_a, caps_b = caps[i], caps[j]

                for tp in TOXIC_AND_INTEGRITY_PAIRS:
                    if i == j:
                        # Self-pair: one server holds both ends of the path.
                        if tp.source in caps_a and tp.sink in caps_a:
                            findings.append(
                                self._make_finding(tp, servers[i], servers[i])
                            )
                    else:
                        # Cross-pair: check forward direction first; fall back
                        # to reverse so only one finding is emitted per pair.
                        if tp.source in caps_a and tp.sink in caps_b:
                            findings.append(
                                self._make_finding(tp, servers[i], servers[j])
                            )
                        elif tp.source in caps_b and tp.sink in caps_a:
                            findings.append(
                                self._make_finding(tp, servers[j], servers[i])
                            )

        return findings

    @staticmethod
    def _make_finding(
        tp: ToxicPair,
        source_server: ServerConfig,
        sink_server: ServerConfig,
    ) -> Finding:
        """Build a :class:`~mcp_audit.models.Finding` for a detected toxic pair.

        Args:
            tp: The toxic pair rule that triggered.
            source_server: Server providing the source capability (or same as
                ``sink_server`` for self-pairs).
            sink_server: Server providing the sink capability.

        Returns:
            A fully populated :class:`~mcp_audit.models.Finding`.
        """
        is_self = source_server is sink_server

        if is_self:
            server_label = source_server.name
            client_label = source_server.client
            evidence = (
                f"{source_server.name!r} has both "
                f"'{tp.source}' and '{tp.sink}' capabilities"
            )
            config_path = str(source_server.config_path)
        else:
            server_label = f"{source_server.name} + {sink_server.name}"
            client_label = (
                source_server.client
                if source_server.client == sink_server.client
                else "multiple"
            )
            evidence = (
                f"{source_server.name!r} has '{tp.source}'; "
                f"{sink_server.name!r} has '{tp.sink}'"
            )
            config_path = str(source_server.config_path)

        return Finding(
            id=tp.finding_id,
            severity=tp.severity,
            analyzer="toxic_flow",
            client=client_label,
            server=server_label,
            title=tp.title,
            description=tp.description,
            evidence=evidence,
            remediation=tp.remediation,
            cwe=tp.cwe,
            finding_path=config_path,
            owasp_mcp_top_10=list(tp.owasp_mcp_top_10),
        )
