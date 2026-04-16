"""Pydantic models for the governance policy schema."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


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
