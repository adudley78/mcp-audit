"""Detect rug-pull attacks by tracking MCP server configuration hashes.

A rug-pull attack works as follows:
  1. Attacker publishes a clean MCP server that developers install and trust.
  2. After adoption, the attacker silently mutates tool descriptions to include
     malicious instructions (data exfiltration, behavioral overrides, etc.).
  3. The developer never sees the change; the AI agent reads poisoned descriptions
     on every subsequent invocation.

Detection strategy: hash each server's configuration on first scan and store the
hashes in a local state file.  On subsequent scans, re-hash and compare.  Any
deviation is flagged as a potential rug-pull.

Research basis: "Compromising LLM-Integrated Applications with Indirect Prompt
Injection" — Greshake et al., arXiv 2023 §4.2
  https://arxiv.org/abs/2302.12173
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

from mcp_audit.analyzers.base import BaseAnalyzer
from mcp_audit.discovery import DiscoveredConfig
from mcp_audit.models import Finding, ServerConfig, Severity

_STATE_DIR: Path = Path.home() / ".mcp-audit"
DEFAULT_STATE_PATH: Path = _STATE_DIR / "state.json"
_STATE_VERSION = 1


# ── Public helpers (used by cli.py pin/diff commands) ─────────────────────────


def derive_state_path(configs: list[DiscoveredConfig]) -> Path:
    """Return a scoped state file path derived from the set of config files.

    Different invocations that scan different config files produce different
    state paths, preventing cross-contamination between e.g. demo configs and
    real machine configs.

    The derivation is deterministic: sort the absolute config paths, join with
    newlines, SHA-256 hash, take the first 8 hex characters.

    Args:
        configs: Discovered config files for the current scan.

    Returns:
        A path like ``~/.mcp-audit/state_a1b2c3d4.json``.  Falls back to
        :data:`DEFAULT_STATE_PATH` when *configs* is empty so that there is
        always a valid path to write to.
    """
    if not configs:
        return DEFAULT_STATE_PATH
    paths_str = "\n".join(sorted(str(c.path) for c in configs))
    digest = hashlib.sha256(paths_str.encode()).hexdigest()[:8]
    return _STATE_DIR / f"state_{digest}.json"


def server_key(server: ServerConfig) -> str:
    """Return the canonical state-file key for a server: ``'{client}/{name}'``."""
    return f"{server.client}/{server.name}"


def compute_hashes(server: ServerConfig) -> dict[str, str]:
    """Return a dict of SHA-256 digests for the four tracked aspects of a server.

    Args:
        server: The server whose config to hash.

    Returns:
        Dict with keys ``command``, ``args``, ``env_keys``, and ``raw``.
    """
    def _h(value: str) -> str:
        return hashlib.sha256(value.encode()).hexdigest()

    return {
        "command": _h(server.command or ""),
        "args": _h(" ".join(server.args)),
        "env_keys": _h(json.dumps(sorted(server.env.keys()))),
        "raw": _h(json.dumps(server.raw, sort_keys=True)),
    }


def load_state(state_path: Path) -> dict:
    """Load the state file, returning an empty baseline if it does not exist.

    Args:
        state_path: Path to the state JSON file.

    Returns:
        Parsed state dict.  Always valid — never raises.
    """
    if not state_path.exists():
        return {"version": _STATE_VERSION, "servers": {}}
    try:
        data = json.loads(state_path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return {"version": _STATE_VERSION, "servers": {}}
        return data
    except (json.JSONDecodeError, OSError):
        return {"version": _STATE_VERSION, "servers": {}}


def save_state(state: dict, state_path: Path) -> None:
    """Persist the state dict to disk, creating parent directories as needed.

    Args:
        state: State dict to serialise.
        state_path: Destination path.
    """
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(json.dumps(state, indent=2), encoding="utf-8")


def build_state_entry(server: ServerConfig, first_seen: str | None = None) -> dict:
    """Build a state entry dict for a single server.

    Args:
        server: The server to record.
        first_seen: ISO timestamp to use as ``first_seen``.  Defaults to now.

    Returns:
        A dict ready to be stored under the server's key in the state file.
    """
    now = datetime.now(UTC).isoformat()
    return {
        "config_path": str(server.config_path),
        "first_seen": first_seen or now,
        "last_seen": now,
        "hashes": compute_hashes(server),
    }


# ── Analyzer ──────────────────────────────────────────────────────────────────


class RugPullAnalyzer(BaseAnalyzer):
    """Detect silent configuration changes across consecutive scans.

    The single-server :meth:`analyze` method is intentionally a no-op.  Call
    :meth:`analyze_all` with the complete list of servers after the per-server
    analysis loop.  The state file is updated on every :meth:`analyze_all` call.

    Args:
        state_path: Override the state file location.  Defaults to
            ``~/.mcp-audit/state.json``.  Pass a ``tmp_path`` in tests.
    """

    def __init__(self, state_path: Path | None = None) -> None:
        self._state_path = state_path or DEFAULT_STATE_PATH

    @property
    def name(self) -> str:
        return "rug_pull"

    @property
    def description(self) -> str:
        return "Detect silent MCP server configuration changes (rug-pull attacks)"

    def analyze(self, server: ServerConfig) -> list[Finding]:
        """No-op.  Rug-pull detection requires the full server list.

        Use :meth:`analyze_all` instead.
        """
        return []

    def analyze_all(self, servers: list[ServerConfig]) -> list[Finding]:
        """Compare current server configs against the stored baseline.

        Behaviour:

        * **First scan** (no state file present): records baseline and emits one
          ``RUGPULL-000`` INFO finding per server.
        * **Known server changed**: emits ``RUGPULL-001`` HIGH.
        * **New server** (not in prior baseline): emits ``RUGPULL-002`` INFO.
        * **Removed server** (in baseline, not in current scan): emits
          ``RUGPULL-003`` INFO.

        The state file is always written at the end, updating ``last_seen`` and
        current hashes for all present servers.

        Args:
            servers: All parsed server configurations from the current scan.

        Returns:
            List of :class:`~mcp_audit.models.Finding` objects.
        """
        findings: list[Finding] = []
        first_scan = not self._state_path.exists()
        state = load_state(self._state_path)
        stored: dict = state.setdefault("servers", {})

        current: dict[str, ServerConfig] = {server_key(s): s for s in servers}

        # ── Evaluate each current server ──────────────────────────────────────
        for key, srv in current.items():
            if key not in stored:
                if first_scan:
                    findings.append(self._baseline_finding(srv))
                else:
                    findings.append(self._new_server_finding(srv, key))
            else:
                stored_hashes = stored[key].get("hashes", {})
                current_hashes = compute_hashes(srv)
                if current_hashes["raw"] != stored_hashes.get("raw"):
                    changed = [
                        f for f in ("command", "args", "env_keys", "raw")
                        if current_hashes.get(f) != stored_hashes.get(f)
                    ]
                    findings.append(self._changed_finding(srv, key, changed))

        # ── Detect removed servers ─────────────────────────────────────────────
        for key, entry in stored.items():
            if key not in current:
                client, _, srv_name = key.partition("/")
                findings.append(self._removed_finding(client, srv_name, key, entry))

        # ── Persist updated state ─────────────────────────────────────────────
        now = datetime.now(UTC).isoformat()
        for key, srv in current.items():
            first_seen = stored.get(key, {}).get("first_seen", now)
            stored[key] = {
                "config_path": str(srv.config_path),
                "first_seen": first_seen,
                "last_seen": now,
                "hashes": compute_hashes(srv),
            }
        save_state(state, self._state_path)

        return findings

    # ── Private finding factories ──────────────────────────────────────────────

    def _baseline_finding(self, srv: ServerConfig) -> Finding:
        return Finding(
            id="RUGPULL-000",
            severity=Severity.INFO,
            analyzer=self.name,
            client=srv.client,
            server=srv.name,
            title=f"First scan — baseline recorded for {srv.name!r}",
            description=(
                "No previous baseline existed for this server. "
                "Configuration hashes have been recorded. "
                "Future scans will detect any changes."
            ),
            evidence=f"State file: {self._state_path}",
            remediation=(
                "No action required. "
                "Run 'mcp-audit scan' regularly to detect rug-pull attacks."
            ),
            finding_path=str(srv.config_path),
        )

    def _new_server_finding(self, srv: ServerConfig, key: str) -> Finding:
        return Finding(
            id="RUGPULL-002",
            severity=Severity.INFO,
            analyzer=self.name,
            client=srv.client,
            server=srv.name,
            title=f"New MCP server detected: {srv.name!r}",
            description=(
                f"Server {key!r} was not present in the previous baseline. "
                "Its configuration has been recorded for future comparison."
            ),
            evidence=f"config_path: {srv.config_path}",
            remediation=(
                "Verify this server was intentionally added to your configuration."
            ),
            finding_path=str(srv.config_path),
        )

    def _changed_finding(
        self, srv: ServerConfig, key: str, changed_fields: list[str]
    ) -> Finding:
        return Finding(
            id="RUGPULL-001",
            severity=Severity.HIGH,
            analyzer=self.name,
            client=srv.client,
            server=srv.name,
            title=f"Server configuration changed since last scan: {srv.name!r}",
            description=(
                f"The configuration of {key!r} has changed since the last recorded "
                "baseline. This pattern is consistent with a rug-pull attack where "
                "tool descriptions or parameters are silently modified after initial "
                "trust is established."
            ),
            evidence=f"Changed hash fields: {', '.join(changed_fields)}",
            remediation=(
                "Inspect the current tool descriptions for malicious instructions. "
                "If the change was intentional, run 'mcp-audit pin' to update the "
                "baseline."
            ),
            cwe="CWE-494",
            finding_path=str(srv.config_path),
        )

    def _removed_finding(
        self, client: str, srv_name: str, key: str, entry: dict
    ) -> Finding:
        last_seen = entry.get("last_seen", "unknown")
        return Finding(
            id="RUGPULL-003",
            severity=Severity.INFO,
            analyzer=self.name,
            client=client,
            server=srv_name,
            title=f"Previously tracked server no longer configured: {srv_name!r}",
            description=(
                f"Server {key!r} was present in the previous baseline but is "
                "no longer in the current configuration."
            ),
            evidence=f"Last seen: {last_seen}",
            remediation=(
                "If intentionally removed, this is expected. "
                "If unexpected, verify your MCP configuration was not tampered with."
            ),
            finding_path=entry.get("config_path", ""),
        )
