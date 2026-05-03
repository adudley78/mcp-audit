"""Event models and emission for ``mcp-audit shadow``.

Three event types are emitted during continuous (daemon) mode:

* :class:`NewShadowServerEvent` — a server that was not seen before appeared.
* :class:`ServerDriftEvent` — a tracked server changed (command, args, env,
  or tool list).
* :class:`ServerRemovedEvent` — a tracked server disappeared from all configs.

All events carry ``owasp_mcp_top_10: ["MCP09"]`` and an ISO 8601 timestamp.

Emission sinks
--------------
* **stdout** (default) — one JSON object per line (``--format json``) or
  Rich-formatted text (terminal default).
* **syslog** — via :class:`logging.handlers.SysLogHandler`.  Uses
  ``/dev/log`` on Linux (where that socket exists), otherwise falls back to
  ``localhost:514`` (macOS / Windows).
* **file** — appends JSON lines to the given path.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, Field

from mcp_audit.shadow.risk import RiskLevel

_OWASP_MCP09: list[str] = ["MCP09"]

logger = logging.getLogger(__name__)


# ── Event models ──────────────────────────────────────────────────────────────


class _BaseEvent(BaseModel):
    """Common fields for all shadow events."""

    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    owasp_mcp_top_10: list[str] = Field(default=_OWASP_MCP09)
    host: str
    client: str
    server_name: str
    package_name: str | None = None
    classification: Literal["sanctioned", "shadow"]
    risk_level: RiskLevel
    capability_tags: list[str]
    finding_ids: list[str] = Field(default_factory=list)


class NewShadowServerEvent(_BaseEvent):
    """A new MCP server was discovered that was not in the prior state."""

    event_type: Literal["new_shadow_server"] = "new_shadow_server"
    first_seen: datetime
    last_seen: datetime


class ServerDriftEvent(_BaseEvent):
    """An existing tracked MCP server's configuration has changed."""

    event_type: Literal["server_drift"] = "server_drift"
    first_seen: datetime
    last_seen: datetime
    changed_fields: list[str] = Field(default_factory=list)


class ServerRemovedEvent(_BaseEvent):
    """A previously tracked MCP server is no longer present in any config."""

    event_type: Literal["server_removed"] = "server_removed"
    first_seen: datetime
    last_seen: datetime


ShadowEvent = Annotated[
    NewShadowServerEvent | ServerDriftEvent | ServerRemovedEvent,
    Field(discriminator="event_type"),
]


# ── Server record (JSON output for non-event full-scan output) ─────────────────


class ShadowServerRecord(BaseModel):
    """A single server entry in the JSON output of a full shadow sweep."""

    host: str
    client: str
    server_name: str
    package_name: str | None = None
    classification: Literal["sanctioned", "shadow"]
    risk_level: RiskLevel
    capability_tags: list[str]
    findings: list[str] = Field(default_factory=list)
    owasp_mcp_top_10: list[str] = Field(default=_OWASP_MCP09)
    first_seen: datetime
    last_seen: datetime


# ── Emission ──────────────────────────────────────────────────────────────────


def _get_syslog_address() -> str | tuple[str, int]:
    """Return the syslog socket/address for the current platform."""
    dev_log = Path("/dev/log")
    if dev_log.exists():
        return str(dev_log)
    return ("localhost", 514)


def emit(
    event: NewShadowServerEvent | ServerDriftEvent | ServerRemovedEvent,
    *,
    sink: Literal["stdout", "syslog", "file"] = "stdout",
    file_path: Path | None = None,
    use_json: bool = True,
) -> None:
    """Emit a shadow event to the configured sink.

    Args:
        event: The event to emit.
        sink: Destination — ``"stdout"``, ``"syslog"``, or ``"file"``.
        file_path: Required when *sink* is ``"file"``; path is created if
            it does not exist.
        use_json: When ``True`` (default), serialise as a compact JSON line.
            Ignored for ``"syslog"`` (always JSON there).

    Raises:
        ValueError: When *sink* is ``"file"`` and *file_path* is ``None``.
    """
    payload = event.model_dump_json()

    if sink == "stdout":
        if use_json:
            sys.stdout.write(payload + "\n")
            sys.stdout.flush()
        else:
            # Plain-text fallback for terminal mode.
            sys.stdout.write(
                f"[{event.event_type}] {event.client}:{event.server_name} "
                f"({event.risk_level})\n"
            )
            sys.stdout.flush()

    elif sink == "syslog":
        handler = logging.handlers.SysLogHandler(address=_get_syslog_address())
        handler.ident = "mcp-audit-shadow: "
        syslog_logger = logging.getLogger("mcp_audit.shadow.events.syslog")
        if not syslog_logger.handlers:
            syslog_logger.addHandler(handler)
            syslog_logger.setLevel(logging.INFO)
            syslog_logger.propagate = False
        syslog_logger.info("%s", payload)

    elif sink == "file":
        if file_path is None:
            raise ValueError("file_path must be set when sink='file'")
        file_path.parent.mkdir(parents=True, exist_ok=True)
        with file_path.open("a", encoding="utf-8") as fh:
            fh.write(payload + "\n")

    else:
        raise ValueError(f"Unknown sink: {sink!r}")


# ── JSON output helper ────────────────────────────────────────────────────────


def records_to_json(records: list[ShadowServerRecord]) -> str:
    """Serialise a list of server records to a pretty-printed JSON array."""
    data = [json.loads(r.model_dump_json()) for r in records]
    return json.dumps(data, indent=2, default=str)
