"""What-if simulator for kill-chain recommendations.

Re-runs the attack-path summarization stage from the static analysis pipeline
against a modified server list (with target servers removed) to compute the
exact blast-radius reduction that applying a set of :class:`KillSwitch` objects
would achieve.

The math is identical to what ``mcp-audit scan`` produces when those servers
are absent from the config — :func:`summarize_attack_paths` is the same pure
function used in :func:`~mcp_audit.scanner._run_static_pipeline`.
"""

from __future__ import annotations

from mcp_audit.analyzers.attack_paths import summarize_attack_paths
from mcp_audit.killchain.recommender import KillSwitch
from mcp_audit.models import AttackPathSummary, Finding, ScanResult


def _finding_involves_server(finding: Finding, servers: set[str]) -> bool:
    """Return True if *finding* references any server in *servers*.

    Toxic-flow findings encode both parties in ``finding.server`` either as
    ``"source + sink"`` (cross-server) or just ``"server_name"`` (self-pair).
    """
    if " + " in finding.server:
        parts = [p.strip() for p in finding.server.split(" + ", 1)]
        return any(p in servers for p in parts)
    return finding.server in servers


def simulate(
    scan_result: ScanResult,
    changes: list[KillSwitch],
) -> AttackPathSummary:
    """Return the attack-path summary after applying the given kill switches.

    Removes each ``change.target_server`` from the server list and from the
    toxic-flow findings, then re-runs
    :func:`~mcp_audit.analyzers.attack_paths.summarize_attack_paths`
    — the same function used by the main pipeline.  The result is
    mathematically identical to what ``mcp-audit scan`` would produce if the
    recommended changes were actually applied to the configuration.

    Args:
        scan_result: The original scan result (not mutated).
        changes: Kill switches whose ``target_server`` values are to be
            removed from the simulation.

    Returns:
        :class:`~mcp_audit.models.AttackPathSummary` reflecting the state
        after the changes.  Returns an empty summary when *changes* is empty
        and there were no paths to begin with, or when all servers are removed.
    """
    if not changes:
        return scan_result.attack_path_summary or AttackPathSummary()

    removed: set[str] = {ks.target_server for ks in changes}
    remaining_servers = [s for s in scan_result.servers if s.name not in removed]

    toxic_findings: list[Finding] = [
        f
        for f in scan_result.findings
        if f.analyzer == "toxic_flow" and not _finding_involves_server(f, removed)
    ]

    return summarize_attack_paths(remaining_servers, toxic_findings)
