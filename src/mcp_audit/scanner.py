"""Scanner orchestrator: discovery → parsing → analysis → results."""

from __future__ import annotations

from pathlib import Path

from mcp_audit.analyzers.base import BaseAnalyzer
from mcp_audit.analyzers.credentials import CredentialsAnalyzer
from mcp_audit.analyzers.poisoning import PoisoningAnalyzer
from mcp_audit.analyzers.transport import TransportAnalyzer
from mcp_audit.config_parser import parse_config
from mcp_audit.discovery import discover_configs
from mcp_audit.models import ScanResult


def get_default_analyzers() -> list[BaseAnalyzer]:
    """Return the default set of analyzers."""
    return [
        PoisoningAnalyzer(),
        CredentialsAnalyzer(),
        TransportAnalyzer(),
    ]


def run_scan(
    extra_paths: list[Path] | None = None,
    analyzers: list[BaseAnalyzer] | None = None,
) -> ScanResult:
    """Run a complete scan: discover configs, parse them, analyze, return results.

    Args:
        extra_paths: Additional config paths to scan.
        analyzers: Custom analyzer list. Uses defaults if None.

    Returns:
        ScanResult with all findings.
    """
    if analyzers is None:
        analyzers = get_default_analyzers()

    result = ScanResult()

    # Discover
    configs = discover_configs(extra_paths=extra_paths)
    result.clients_scanned = len({c.client_name for c in configs})

    # Parse and analyze
    for config in configs:
        try:
            servers = parse_config(config)
        except ValueError as e:
            result.errors.append(str(e))
            continue

        result.servers_found += len(servers)

        for server in servers:
            for analyzer in analyzers:
                try:
                    findings = analyzer.analyze(server)
                    for finding in findings:
                        finding.finding_path = str(server.config_path)
                    result.findings.extend(findings)
                except Exception as e:
                    result.errors.append(f"{analyzer.name} error on {server.name}: {e}")

    return result
