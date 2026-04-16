"""Baseline snapshot and drift detection manager.

Users can capture a point-in-time snapshot of their MCP configuration and
then compare future scans against it to detect drift: new servers, removed
servers, or configuration changes.

Baselines are architecturally separate from the rug-pull analyzer.  The
rug-pull analyzer tracks automatic per-scan hashes; baselines are explicit,
user-named snapshots stored in ``~/.config/mcp-audit/baselines/``.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import warnings
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, Field

from mcp_audit.models import ServerConfig, Severity

_SCANNER_VERSION = "0.1.0"
_DEFAULT_STORAGE_DIR = Path.home() / ".config" / "mcp-audit" / "baselines"

logger = logging.getLogger(__name__)

_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


# ── Data models ───────────────────────────────────────────────────────────────


class BaselineServer(BaseModel):
    """Snapshot of a single MCP server at the time of baseline capture.

    ``env`` stores only environment variable key names — never values — to
    avoid persisting secrets to disk.
    """

    name: str
    client: str
    command: str | None
    args: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)
    transport: str | None = None
    config_hash: str


class Baseline(BaseModel):
    """A complete named snapshot of MCP server state."""

    name: str
    created_at: datetime
    scanner_version: str
    servers: list[BaselineServer] = Field(default_factory=list)
    server_count: int
    config_paths: list[str] = Field(default_factory=list)


class DriftType(StrEnum):
    """Categories of configuration drift detected against a baseline."""

    SERVER_ADDED = "server_added"
    SERVER_REMOVED = "server_removed"
    COMMAND_CHANGED = "command_changed"
    ARGS_CHANGED = "args_changed"
    ENV_CHANGED = "env_changed"
    HASH_CHANGED = "hash_changed"


_DRIFT_SEVERITY: dict[DriftType, Severity] = {
    DriftType.SERVER_ADDED: Severity.MEDIUM,
    DriftType.SERVER_REMOVED: Severity.INFO,
    DriftType.COMMAND_CHANGED: Severity.HIGH,
    DriftType.ARGS_CHANGED: Severity.MEDIUM,
    DriftType.ENV_CHANGED: Severity.MEDIUM,
    DriftType.HASH_CHANGED: Severity.HIGH,
}


class DriftFinding(BaseModel):
    """A single detected drift item between a baseline and the current state."""

    drift_type: DriftType
    server_name: str
    client: str
    severity: Severity
    description: str
    baseline_value: str | None = None
    current_value: str | None = None


# ── Helpers ───────────────────────────────────────────────────────────────────


def _compute_config_hash(server: ServerConfig) -> str:
    """Return the SHA-256 digest of the server's raw config dict.

    Uses the same algorithm as the rug-pull analyzer's ``raw`` hash so that
    the two systems are directly comparable.
    """
    return hashlib.sha256(
        json.dumps(server.raw, sort_keys=True).encode()
    ).hexdigest()


def _server_to_baseline_server(server: ServerConfig) -> BaselineServer:
    """Convert a live ``ServerConfig`` into a ``BaselineServer`` snapshot.

    Env values are intentionally dropped; only key names are stored.
    """
    return BaselineServer(
        name=server.name,
        client=server.client,
        command=server.command,
        args=list(server.args),
        env=dict.fromkeys(server.env.keys(), ""),
        transport=server.transport.value if server.transport is not None else None,
        config_hash=_compute_config_hash(server),
    )


# ── BaselineManager ───────────────────────────────────────────────────────────


class BaselineManager:
    """Manages storage and comparison of MCP configuration baselines.

    Args:
        storage_dir: Directory in which baseline JSON files are stored.
            Defaults to ``~/.config/mcp-audit/baselines/``.
    """

    def __init__(self, storage_dir: Path | None = None) -> None:
        self._storage_dir = storage_dir or _DEFAULT_STORAGE_DIR
        self._storage_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    # ── persistence ───────────────────────────────────────────────────────────

    def save(
        self,
        servers: list[ServerConfig],
        config_paths: list[str],
        name: str | None = None,
    ) -> Baseline:
        """Capture a baseline snapshot of the provided servers and persist it.

        Args:
            servers: Live server configurations to snapshot.
            config_paths: Config file paths included in this snapshot.
            name: Human-readable label.  Auto-generated from timestamp if
                ``None``.

        Returns:
            The saved :class:`Baseline`.
        """
        if name is None:
            name = datetime.now(UTC).strftime("baseline-%Y%m%d-%H%M%S")

        baseline = Baseline(
            name=name,
            created_at=datetime.now(UTC),
            scanner_version=_SCANNER_VERSION,
            servers=[_server_to_baseline_server(s) for s in servers],
            server_count=len(servers),
            config_paths=config_paths,
        )

        path = self._storage_dir / f"{name}.json"
        content = baseline.model_dump_json(indent=2).encode("utf-8")
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(content)

        return baseline

    def list(self) -> list[Baseline]:
        """Return all saved baselines, newest first.

        Malformed or unreadable files are skipped with a warning.

        Returns:
            Baselines sorted by :attr:`Baseline.created_at` descending.
        """
        baselines: list[Baseline] = []
        for path in self._storage_dir.glob("*.json"):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                baselines.append(Baseline.model_validate(data))
            except Exception as exc:  # noqa: BLE001
                warnings.warn(
                    f"Skipping malformed baseline file {path.name}: {exc}",
                    stacklevel=2,
                )
        baselines.sort(key=lambda b: b.created_at, reverse=True)
        return baselines

    def load(self, name: str) -> Baseline:
        """Load a baseline by name.

        Args:
            name: Baseline label, with or without the ``.json`` extension.

        Returns:
            The loaded :class:`Baseline`.

        Raises:
            FileNotFoundError: If no baseline with that name exists.
        """
        stem = name.removesuffix(".json")
        path = self._storage_dir / f"{stem}.json"
        if not path.exists():
            raise FileNotFoundError(
                f"No baseline named {stem!r} found in {self._storage_dir}. "
                "Run 'mcp-audit baseline list' to see available baselines."
            )
        data = json.loads(path.read_text(encoding="utf-8"))
        return Baseline.model_validate(data)

    def load_latest(self) -> Baseline | None:
        """Return the most recently created baseline, or ``None`` if none exist.

        Returns:
            The newest :class:`Baseline` or ``None``.
        """
        baselines = self.list()
        return baselines[0] if baselines else None

    def delete(self, name: str) -> None:
        """Delete a baseline file.

        Confirmation prompting is handled at the CLI layer; this method
        performs the deletion unconditionally once called.

        Args:
            name: Baseline label, with or without the ``.json`` extension.

        Raises:
            ValueError: If no baseline with that name exists.
        """
        stem = name.removesuffix(".json")
        path = self._storage_dir / f"{stem}.json"
        if not path.exists():
            raise ValueError(
                f"No baseline named {stem!r} found in {self._storage_dir}."
            )
        path.unlink()

    def export(self, name: str) -> str:
        """Return the raw JSON content of a baseline for stdout piping.

        Args:
            name: Baseline label, with or without the ``.json`` extension.

        Returns:
            Raw JSON string (no Rich formatting).

        Raises:
            FileNotFoundError: If the baseline does not exist.
        """
        stem = name.removesuffix(".json")
        path = self._storage_dir / f"{stem}.json"
        if not path.exists():
            raise FileNotFoundError(
                f"No baseline named {stem!r} found in {self._storage_dir}."
            )
        return path.read_text(encoding="utf-8")

    # ── comparison ────────────────────────────────────────────────────────────

    def compare(
        self,
        baseline: Baseline,
        current_servers: list[ServerConfig],
    ) -> list[DriftFinding]:
        """Detect drift between a baseline snapshot and the current server state.

        Servers are matched by ``(client, name)`` pair so that two different
        AI clients can each have a server named "filesystem" without
        producing false positives.

        A single server can produce multiple :class:`DriftFinding` entries
        (e.g. both ``hash_changed`` and ``command_changed`` simultaneously).

        Args:
            baseline: The reference snapshot to compare against.
            current_servers: Live server configurations from the current scan.

        Returns:
            List of :class:`DriftFinding` sorted by severity descending
            (highest severity first).
        """
        findings: list[DriftFinding] = []

        baseline_map: dict[tuple[str, str], BaselineServer] = {
            (bs.client, bs.name): bs for bs in baseline.servers
        }
        current_map: dict[tuple[str, str], ServerConfig] = {
            (s.client, s.name): s for s in current_servers
        }

        # Detect added servers
        for key, server in current_map.items():
            if key not in baseline_map:
                findings.append(
                    DriftFinding(
                        drift_type=DriftType.SERVER_ADDED,
                        server_name=server.name,
                        client=server.client,
                        severity=_DRIFT_SEVERITY[DriftType.SERVER_ADDED],
                        description=(
                            f"Server '{server.name}' (client: {server.client}) "
                            "was not present in the baseline — it has been added "
                            "since the snapshot was taken."
                        ),
                        baseline_value=None,
                        current_value=(
                            f"{server.command} {' '.join(server.args)}".strip()
                        ),
                    )
                )

        # Detect removed servers
        for key, bs in baseline_map.items():
            if key not in current_map:
                findings.append(
                    DriftFinding(
                        drift_type=DriftType.SERVER_REMOVED,
                        server_name=bs.name,
                        client=bs.client,
                        severity=_DRIFT_SEVERITY[DriftType.SERVER_REMOVED],
                        description=(
                            f"Server '{bs.name}' (client: {bs.client}) "
                            "was present in the baseline but is no longer configured."
                        ),
                        baseline_value=f"{bs.command} {' '.join(bs.args)}".strip(),
                        current_value=None,
                    )
                )

        # Detect per-field drift for servers present in both
        for key in baseline_map.keys() & current_map.keys():
            bs = baseline_map[key]
            srv = current_map[key]
            current_hash = _compute_config_hash(srv)

            if current_hash != bs.config_hash:
                findings.append(
                    DriftFinding(
                        drift_type=DriftType.HASH_CHANGED,
                        server_name=srv.name,
                        client=srv.client,
                        severity=_DRIFT_SEVERITY[DriftType.HASH_CHANGED],
                        description=(
                            f"The full configuration of '{srv.name}' "
                            f"(client: {srv.client}) has changed since the baseline."
                        ),
                        baseline_value=bs.config_hash[:16] + "…",
                        current_value=current_hash[:16] + "…",
                    )
                )

            if srv.command != bs.command:
                findings.append(
                    DriftFinding(
                        drift_type=DriftType.COMMAND_CHANGED,
                        server_name=srv.name,
                        client=srv.client,
                        severity=_DRIFT_SEVERITY[DriftType.COMMAND_CHANGED],
                        description=(
                            f"The executable command for '{srv.name}' "
                            f"(client: {srv.client}) has changed since the baseline."
                        ),
                        baseline_value=bs.command,
                        current_value=srv.command,
                    )
                )

            if list(srv.args) != list(bs.args):
                findings.append(
                    DriftFinding(
                        drift_type=DriftType.ARGS_CHANGED,
                        server_name=srv.name,
                        client=srv.client,
                        severity=_DRIFT_SEVERITY[DriftType.ARGS_CHANGED],
                        description=(
                            f"The arguments for '{srv.name}' "
                            f"(client: {srv.client}) have changed since the baseline."
                        ),
                        baseline_value=json.dumps(list(bs.args)),
                        current_value=json.dumps(list(srv.args)),
                    )
                )

            current_env_keys = set(srv.env.keys())
            baseline_env_keys = set(bs.env.keys())
            if current_env_keys != baseline_env_keys:
                added = sorted(current_env_keys - baseline_env_keys)
                removed = sorted(baseline_env_keys - current_env_keys)
                parts = []
                if added:
                    parts.append(f"added: {added}")
                if removed:
                    parts.append(f"removed: {removed}")
                findings.append(
                    DriftFinding(
                        drift_type=DriftType.ENV_CHANGED,
                        server_name=srv.name,
                        client=srv.client,
                        severity=_DRIFT_SEVERITY[DriftType.ENV_CHANGED],
                        description=(
                            f"Environment variable keys for '{srv.name}' "
                            f"(client: {srv.client}) have changed since the baseline. "
                            + "; ".join(parts)
                        ),
                        baseline_value=json.dumps(sorted(baseline_env_keys)),
                        current_value=json.dumps(sorted(current_env_keys)),
                    )
                )

        findings.sort(key=lambda f: _SEVERITY_ORDER.get(f.severity, 99))
        return findings
