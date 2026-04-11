"""Scanner orchestrator: discovery → parsing → analysis → results."""

from __future__ import annotations

from pathlib import Path

from mcp_audit.analyzers.base import BaseAnalyzer
from mcp_audit.analyzers.credentials import CredentialsAnalyzer
from mcp_audit.analyzers.poisoning import PoisoningAnalyzer
from mcp_audit.analyzers.rug_pull import RugPullAnalyzer
from mcp_audit.analyzers.supply_chain import SupplyChainAnalyzer
from mcp_audit.analyzers.transport import TransportAnalyzer
from mcp_audit.config_parser import parse_config
from mcp_audit.discovery import discover_configs
from mcp_audit.models import ScanResult, ServerConfig


def get_default_analyzers() -> list[BaseAnalyzer]:
    """Return the default set of per-server analyzers.

    Note: :class:`~mcp_audit.analyzers.rug_pull.RugPullAnalyzer` is intentionally
    excluded here — it operates across all servers collectively and is invoked
    separately via :func:`run_scan`.
    """
    return [
        PoisoningAnalyzer(),
        CredentialsAnalyzer(),
        TransportAnalyzer(),
        SupplyChainAnalyzer(),
    ]


def run_scan(
    extra_paths: list[Path] | None = None,
    analyzers: list[BaseAnalyzer] | None = None,
    state_path: Path | None = None,
    skip_rug_pull: bool = False,
) -> ScanResult:
    """Run a complete scan: discover configs, parse them, analyze, return results.

    All configs are parsed first so that the rug-pull analyzer receives the full
    server list in a single :meth:`analyze_all` call.

    Args:
        extra_paths: Additional config paths to scan.
        analyzers: Custom per-server analyzer list.  Uses defaults if ``None``.
        state_path: Override the rug-pull state file location.  Useful in tests.
        skip_rug_pull: When ``True``, skip rug-pull analysis entirely.  Used by
            the ``pin`` and ``diff`` CLI commands which manage state directly.

    Returns:
        :class:`~mcp_audit.models.ScanResult` with all findings.
    """
    if analyzers is None:
        analyzers = get_default_analyzers()

    result = ScanResult()

    # ── Discover configs ───────────────────────────────────────────────────────
    configs = discover_configs(extra_paths=extra_paths)
    result.clients_scanned = len({c.client_name for c in configs})

    # ── Parse all configs up-front ─────────────────────────────────────────────
    all_servers: list[ServerConfig] = []
    for config in configs:
        try:
            servers = parse_config(config)
            all_servers.extend(servers)
        except ValueError as e:
            result.errors.append(str(e))

    result.servers_found = len(all_servers)

    # ── Per-server analysis ────────────────────────────────────────────────────
    for server in all_servers:
        for analyzer in analyzers:
            try:
                findings = analyzer.analyze(server)
                for finding in findings:
                    finding.finding_path = str(server.config_path)
                result.findings.extend(findings)
            except Exception as e:  # noqa: BLE001
                result.errors.append(
                    f"{analyzer.name} error on {server.name}: {e}"
                )

    # ── Rug-pull analysis (cross-server, stateful) ────────────────────────────
    if not skip_rug_pull:
        rug_pull = RugPullAnalyzer(state_path=state_path)
        try:
            result.findings.extend(rug_pull.analyze_all(all_servers))
        except Exception as e:  # noqa: BLE001
            result.errors.append(f"rug_pull error: {e}")

    return result
