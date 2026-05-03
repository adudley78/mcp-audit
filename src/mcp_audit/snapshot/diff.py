"""Delta between a historical snapshot and the current live state.

Answers "what changed since the snapshot was taken?" — servers added, removed,
or modified — suitable for incident response triage.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mcp_audit.models import ServerConfig
from mcp_audit.snapshot.rehydrate import (
    _detect_format,
    _servers_from_cyclonedx,
    _servers_from_native,
    load_snapshot,
)


@dataclass
class SnapshotDelta:
    """Delta between a historical snapshot and current live state.

    Attributes:
        snapshot_timestamp: ISO 8601 timestamp from the snapshot.
        added: Server names present in current state but absent in snapshot.
        removed: Server names present in snapshot but absent in current state.
        unchanged: Server names present in both states.
        added_count: Convenience count.
        removed_count: Convenience count.
    """

    snapshot_timestamp: str
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    unchanged: list[str] = field(default_factory=list)

    @property
    def added_count(self) -> int:
        """Number of servers added since the snapshot."""
        return len(self.added)

    @property
    def removed_count(self) -> int:
        """Number of servers removed since the snapshot."""
        return len(self.removed)

    def summary_line(self) -> str:
        """One-line human-readable summary of the delta.

        Returns:
            E.g. ``"3 servers added, 1 removed since 2026-05-01T12:00:00Z"``.
        """
        parts: list[str] = []
        if self.added_count:
            parts.append(f"{self.added_count} server(s) added")
        if self.removed_count:
            parts.append(f"{self.removed_count} server(s) removed")
        if not parts:
            parts.append("no changes")
        ts = self.snapshot_timestamp
        return ", ".join(parts) + f" since {ts}"


def _names_from_snapshot(raw: dict[str, Any]) -> set[str]:
    """Extract server names from a snapshot dict.

    Args:
        raw: Top-level snapshot dict (CycloneDX or native format).

    Returns:
        Set of server name strings.
    """
    fmt = _detect_format(raw)
    if fmt == "cyclonedx":
        records = _servers_from_cyclonedx(raw)
    else:
        records = _servers_from_native(raw)
    return {r.get("name") or "unknown" for r in records}


def diff_snapshot_against_current(
    snapshot_path: Path,
    current_servers: list[ServerConfig],
) -> SnapshotDelta:
    """Compute the delta between a saved snapshot and *current_servers*.

    Args:
        snapshot_path: Path to a previously saved ``.snapshot.json`` file.
        current_servers: Live server list from the current scan.

    Returns:
        :class:`SnapshotDelta` describing added/removed/unchanged servers.

    Raises:
        ValueError: If the snapshot file is corrupt or missing required fields.
    """
    raw = load_snapshot(snapshot_path)
    meta = raw.get("metadata") or {}
    ts_raw = meta.get("timestamp") or ""
    timestamp_str = ts_raw if isinstance(ts_raw, str) else str(ts_raw)

    snapshot_names = _names_from_snapshot(raw)
    current_names = {s.name for s in current_servers}

    added = sorted(current_names - snapshot_names)
    removed = sorted(snapshot_names - current_names)
    unchanged = sorted(snapshot_names & current_names)

    return SnapshotDelta(
        snapshot_timestamp=timestamp_str,
        added=added,
        removed=removed,
        unchanged=unchanged,
    )
