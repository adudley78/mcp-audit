"""Pydantic models for the governance policy schema."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, field_validator


class PolicyMode(StrEnum):
    """Controls whether the server list is an allowlist or denylist."""

    ALLOWLIST = "allowlist"
    DENYLIST = "denylist"


class ApprovedServerEntry(BaseModel):
    """A single entry in the approved (or denied) server list.

    ``name`` may be an exact server name or a glob pattern such as
    ``@modelcontextprotocol/*``.  ``source`` restricts the match to a specific
    package ecosystem (``"npm"``, ``"pip"``, ``"github"``); ``None`` means any.
    """

    name: str
    source: str | None = None
    max_version: str | None = None
    notes: str | None = None


class ApprovedServers(BaseModel):
    """Policy block controlling which servers are allowed or forbidden."""

    mode: PolicyMode = PolicyMode.ALLOWLIST
    entries: list[ApprovedServerEntry] = Field(default_factory=list)
    additional: list[ApprovedServerEntry] = Field(default_factory=list)
    violation_severity: str = "high"
    message: str = "Server {server_name} is not on the approved server list"


class ScoreThreshold(BaseModel):
    """Policy block enforcing a minimum scan score."""

    minimum: int = Field(ge=0, le=100)
    violation_severity: str = "medium"
    message: str = "Configuration scored {score} ({grade}), below minimum of {minimum}"


class TransportPolicy(BaseModel):
    """Policy block controlling which MCP transport types are permitted."""

    require_tls: bool = False
    allow_stdio: bool = True
    allow_sse: bool = True
    allow_http: bool = True
    block_http: bool = False
    violation_severity: str = "high"


class RegistryPolicy(BaseModel):
    """Policy block enforcing Known-Server Registry membership."""

    require_known: bool = False
    require_verified: bool = False
    violation_severity: str = "medium"
    message: str = "Server {server_name} is not in the Known-Server Registry"


class FindingPolicy(BaseModel):
    """Policy block capping the number of allowed findings per severity."""

    max_critical: int | None = None
    max_high: int | None = None
    max_medium: int | None = None
    violation_severity: str = "high"


class ClientOverride(BaseModel):
    """Per-client policy overrides that supplement or replace the base policy.

    The ``client`` key in :attr:`GovernancePolicy.client_overrides` must match
    the ``client`` field on :class:`~mcp_audit.models.ServerConfig` (e.g.
    ``"cursor"``, ``"claude-desktop"``).
    """

    approved_servers: ApprovedServers | None = None
    transport_policy: TransportPolicy | None = None
    score_threshold: ScoreThreshold | None = None


class ScoringDeductions(BaseModel):
    """Per-severity point deductions for the scan score.

    All values must be <= 0 (deductions reduce the score).  A value of 0
    means that severity is ignored in scoring.  Defaults match the hardcoded
    constants in :mod:`mcp_audit.scoring`.
    """

    model_config = ConfigDict(extra="ignore")

    CRITICAL: int = -25
    HIGH: int = -10
    MEDIUM: int = -5
    LOW: int = -2
    INFO: int = -1

    @field_validator("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", mode="before")
    @classmethod
    def must_be_non_positive(cls, v: object) -> object:
        """Reject positive deduction values — they would raise the score."""
        if isinstance(v, (int, float)) and v > 0:
            raise ValueError(
                f"Deduction value must be <= 0 (got {v}); "
                "positive deductions are nonsensical"
            )
        return v


class ScoringPositiveSignals(BaseModel):
    """Bonus point values for positive security signals.

    All values must be >= 0.  The sum of earned bonuses is capped at
    ``max_total_bonus``.  Defaults match the hardcoded bonus logic in
    :mod:`mcp_audit.scoring`.

    Field mapping to current scoring logic:

    - ``no_credentials``: bonus when no credential findings are present (+3).
    - ``all_pinned``: bonus when no CRITICAL or HIGH findings are present (+5).
    - ``registry_only``: bonus when no prompt-injection/poisoning findings are
      present (+2).
    """

    model_config = ConfigDict(extra="ignore")

    max_total_bonus: int = 10
    no_credentials: int = 3
    all_pinned: int = 3
    registry_only: int = 4

    @field_validator(
        "max_total_bonus",
        "no_credentials",
        "all_pinned",
        "registry_only",
        mode="before",
    )
    @classmethod
    def must_be_non_negative(cls, v: object) -> object:
        """Reject negative bonus values."""
        if isinstance(v, (int, float)) and v < 0:
            raise ValueError(f"Positive-signal value must be >= 0 (got {v})")
        return v


class ScoringWeights(BaseModel):
    """Root container for custom scoring weight configuration.

    Set ``extra='ignore'`` so unknown keys added in future policy versions
    are silently discarded (forward-compatible).
    """

    model_config = ConfigDict(extra="ignore")

    deductions: ScoringDeductions = Field(default_factory=ScoringDeductions)
    positive_signals: ScoringPositiveSignals = Field(
        default_factory=ScoringPositiveSignals
    )


class GovernancePolicy(BaseModel):
    """Root governance policy document.

    Loaded from ``.mcp-audit-policy.yml`` (or equivalent) via
    :func:`~mcp_audit.governance.loader.load_policy`.
    """

    version: int = 1
    name: str = "mcp-audit governance policy"
    approved_servers: ApprovedServers | None = None
    score_threshold: ScoreThreshold | None = None
    transport_policy: TransportPolicy | None = None
    registry_policy: RegistryPolicy | None = None
    finding_policy: FindingPolicy | None = None
    client_overrides: dict[str, ClientOverride] = Field(default_factory=dict)
    # OWASP MCP Top 10 category codes to attach to all findings emitted by this
    # policy. Policy authors can set this in their YAML to annotate governance
    # violations with the relevant MCP Top 10 categories.
    owasp_mcp_top_10: list[str] = Field(default_factory=list)
    # Custom scoring weights.  When ``None`` (the default), the hardcoded
    # constants in :mod:`mcp_audit.scoring` are used unchanged.  When present,
    # the nested ``deductions`` and ``positive_signals`` blocks override those
    # constants for this scan.  Absent sub-keys fall back to their defaults.
    scoring: ScoringWeights | None = None
