"""POISON-* checks on live tool text for ``mcp-audit run`` (EPIC-0009 Story 1.4).

Runs the same :class:`~mcp_audit.analyzers.poisoning.PoisoningAnalyzer`
``scan --connect`` runs, one tool at a time so each finding belongs to a
tool, over the definition the server sent in ``tools/list``. A tool whose
worst finding is at or above ``runtime.poison_threshold`` from the
governance policy (default ``critical``) is reported in monitor mode and
withheld in enforce mode, like a changed tool.

The analyzer, pydantic models and policy are heavy to import, and this sits
on a launch path, so :class:`PoisonCheck` loads them on a background thread
started at launch; the first ``tools/list`` answer waits for it if it isn't
ready yet.
"""

from __future__ import annotations

import sys
import threading
from pathlib import Path

#: Severity rank, most severe first (mirrors ``models.Severity``).
_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
DEFAULT_THRESHOLD = "critical"


def _say(message: str) -> None:
    try:
        sys.stderr.write(f"mcp-audit run: {message}\n")
        sys.stderr.flush()
    except (OSError, ValueError):
        pass


class PoisonCheck:
    """Background-loaded POISON-* check with a policy threshold.

    Args:
        server_name: For the synthetic server config the analyzer reads.
        config_path: The MCP config; its directory is where the policy is
            looked for (then its git root, then the user's policy).
        policy_path: An explicit policy file (``--policy``).
    """

    def __init__(
        self,
        server_name: str,
        config_path: Path,
        policy_path: Path | None = None,
    ) -> None:
        self.server_name = server_name
        self.config_path = config_path
        self.policy_path = policy_path
        self.threshold = DEFAULT_THRESHOLD
        self._ready = threading.Event()
        self._analyze = None
        self._thread = threading.Thread(target=self._load, daemon=True)

    def start(self) -> PoisonCheck:
        """Start loading in the background; returns ``self``."""
        self._thread.start()
        return self

    def _load(self) -> None:
        try:
            self.threshold = self._threshold()
            if self.threshold == "off":
                return
            from mcp_audit.analyzers.poisoning import PoisoningAnalyzer
            from mcp_audit.mcp_client import build_runtime_server_config
            from mcp_audit.models import (
                ServerConfig,
                ServerEnumeration,
                ToolInfo,
                TransportType,
            )

            analyzer = PoisoningAnalyzer()
            base = ServerConfig(
                name=self.server_name,
                client="mcp-audit-run",
                config_path=self.config_path,
                transport=TransportType.STDIO,
                command="",
                args=[],
            )

            def _analyze(definition: dict) -> list[tuple[str, str]]:
                tool = ToolInfo(
                    name=definition["name"],
                    title=definition.get("title"),
                    description=definition.get("description"),
                    input_schema=definition.get("inputSchema", {}),
                    output_schema=definition.get("outputSchema"),
                    annotations=definition.get("annotations"),
                )
                config = build_runtime_server_config(
                    base, ServerEnumeration(tools=[tool])
                )
                if config is None:
                    return []
                return [(f.id, str(f.severity)) for f in analyzer.analyze(config)]

            self._analyze = _analyze
        except Exception as exc:  # noqa: BLE001 — never break the session
            _say(f"poisoning check unavailable: {type(exc).__name__}: {exc}")
        finally:
            self._ready.set()

    def _threshold(self) -> str:
        from mcp_audit.governance.loader import load_policy

        try:
            policy = load_policy(self.policy_path, start=self.config_path.parent)
        except ValueError as exc:
            _say(
                f"policy not loaded ({exc}); poisoning threshold stays "
                f"{DEFAULT_THRESHOLD}"
            )
            return DEFAULT_THRESHOLD
        if policy is None or policy.runtime is None:
            return DEFAULT_THRESHOLD
        return policy.runtime.poison_threshold

    def over_threshold(self, definitions: list[dict]) -> dict[str, tuple[str, str]]:
        """Return ``{tool name: (finding ID, severity)}`` at or above threshold.

        The worst finding per tool is returned. Waits for the background load
        (at most 30 s) the first time.
        """
        self._ready.wait(timeout=30)
        if self._analyze is None or self.threshold == "off":
            return {}
        limit = _RANK[self.threshold.upper()]
        out: dict[str, tuple[str, str]] = {}
        for definition in definitions:
            try:
                hits = self._analyze(definition)
            except Exception:  # noqa: BLE001, S112 — one bad tool never stops the rest
                continue
            ranked = [
                (_RANK.get(sev.upper(), 9), fid, sev.upper())
                for fid, sev in hits
                if _RANK.get(sev.upper(), 9) <= limit
            ]
            if ranked:
                _, fid, sev = min(ranked)
                out[definition["name"]] = (fid, sev)
        return out
