"""Persistent first_seen / last_seen state for shadow server tracking.

State is stored in ``<user-config-dir>/mcp-audit/shadow/state.json``
(resolved via ``platformdirs``) at ``0o700`` directory / ``0o600`` file
permissions — matching the baseline and rug-pull conventions.

State schema (JSON object):
::

    {
      "<client>:<server_name>": {
        "first_seen": "ISO 8601",
        "last_seen": "ISO 8601",
        "config_hash": "<sha256 hex>",
        "client": "<client name>",
        "server_name": "<server name>"
      }
    }
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import datetime
from pathlib import Path

from platformdirs import user_config_dir

from mcp_audit.models import ServerConfig

_DEFAULT_STATE_DIR = Path(user_config_dir("mcp-audit")) / "shadow"
logger = logging.getLogger(__name__)


def _state_key(server: ServerConfig) -> str:
    return f"{server.client}:{server.name}"


def _config_hash(server: ServerConfig) -> str:
    return hashlib.sha256(json.dumps(server.raw, sort_keys=True).encode()).hexdigest()


class ShadowStateEntry:
    """In-memory representation of a single server's shadow state."""

    __slots__ = ("first_seen", "last_seen", "config_hash", "client", "server_name")

    def __init__(
        self,
        first_seen: datetime,
        last_seen: datetime,
        config_hash: str,
        client: str,
        server_name: str,
    ) -> None:
        self.first_seen = first_seen
        self.last_seen = last_seen
        self.config_hash = config_hash
        self.client = client
        self.server_name = server_name

    def to_dict(self) -> dict:
        return {
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "config_hash": self.config_hash,
            "client": self.client,
            "server_name": self.server_name,
        }

    @classmethod
    def from_dict(cls, data: dict) -> ShadowStateEntry:
        return cls(
            first_seen=datetime.fromisoformat(data["first_seen"]),
            last_seen=datetime.fromisoformat(data["last_seen"]),
            config_hash=data["config_hash"],
            client=data["client"],
            server_name=data["server_name"],
        )


class ShadowState:
    """Manages persistent first_seen / last_seen tracking for shadow servers.

    Args:
        state_dir: Directory for state storage.  Defaults to
            ``<user-config-dir>/mcp-audit/shadow/``.
    """

    def __init__(self, state_dir: Path | None = None) -> None:
        self._dir = (state_dir or _DEFAULT_STATE_DIR).resolve()
        self._dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._path = self._dir / "state.json"
        self._entries: dict[str, ShadowStateEntry] = {}
        self._load()

    # ── I/O ───────────────────────────────────────────────────────────────────

    def _load(self) -> None:
        if not self._path.exists():
            return
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
            for key, val in raw.items():
                self._entries[key] = ShadowStateEntry.from_dict(val)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Shadow state file unreadable (%s); starting fresh.", exc)

    def save(self) -> None:
        """Persist current state to disk with 0o600 permissions."""
        payload = json.dumps(
            {k: v.to_dict() for k, v in self._entries.items()},
            indent=2,
        ).encode("utf-8")
        # Security: O_CREAT with mode 0o600 — owner read/write only.
        fd = os.open(str(self._path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(payload)

    # ── Queries ───────────────────────────────────────────────────────────────

    def get(self, server: ServerConfig) -> ShadowStateEntry | None:
        return self._entries.get(_state_key(server))

    def all_keys(self) -> set[str]:
        return set(self._entries.keys())

    # ── Mutation ──────────────────────────────────────────────────────────────

    def touch(self, server: ServerConfig, now: datetime) -> ShadowStateEntry:
        """Create or update the state entry for *server*.

        Returns:
            The entry (new or updated).
        """
        key = _state_key(server)
        h = _config_hash(server)
        existing = self._entries.get(key)
        if existing is None:
            entry = ShadowStateEntry(
                first_seen=now,
                last_seen=now,
                config_hash=h,
                client=server.client,
                server_name=server.name,
            )
            self._entries[key] = entry
        else:
            existing.last_seen = now
            existing.config_hash = h
            entry = existing
        return entry

    def get_hash(self, server: ServerConfig) -> str | None:
        e = self._entries.get(_state_key(server))
        return e.config_hash if e is not None else None

    def reset(self) -> None:
        """Clear all state (for ``--reset-state`` operations)."""
        self._entries.clear()
        if self._path.exists():
            self._path.unlink()
