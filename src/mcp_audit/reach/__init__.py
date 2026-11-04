"""``mcp-audit reach``: what can the agents on this machine touch? (STORY-0145).

Static and offline: the engine reads settings files and a finished default
scan; it never executes an agent and never watches live calls.  ``engine`` is
pure (a :class:`~mcp_audit.models.ScanResult` in, a
:class:`~mcp_audit.reach.models.MachineReach` out); rendering lives in
``mcp_audit.output.reach*`` and the command in ``mcp_audit.cli.reach``, so a
fleet server or an identity-platform export can reuse the engine.

See ``docs/reach.md``.
"""

from __future__ import annotations

from mcp_audit.reach.engine import build_machine_reach, verdict_of
from mcp_audit.reach.models import (
    SCHEMA_VERSION,
    AgentReach,
    MachineReach,
    Verdict,
)

__all__ = [
    "SCHEMA_VERSION",
    "AgentReach",
    "MachineReach",
    "Verdict",
    "build_machine_reach",
    "verdict_of",
]
