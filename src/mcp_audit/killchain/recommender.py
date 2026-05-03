"""Rank kill switches from the attack-path graph's hitting-set output.

Wraps the greedy hitting-set already computed by ``summarize_attack_paths`` in
:mod:`mcp_audit.analyzers.attack_paths` with human-readable metadata: which
capability to restrict, how many paths each change removes (incrementally), and
a one-line rationale.

The recommender does **not** re-implement the hitting-set algorithm — it
consumes the already-computed :class:`~mcp_audit.models.AttackPathSummary` and
adds the presentation layer.
"""

from __future__ import annotations

from collections import Counter

from pydantic import BaseModel, Field

from mcp_audit.analyzers.attack_paths import _CAP_LABELS, _SEVERITY_ORDER
from mcp_audit.models import AttackPath, AttackPathSummary, Severity


class KillSwitch(BaseModel):
    """A single recommended configuration change that reduces blast radius.

    Fields match the ``--format json`` output schema documented in
    the ``killchain`` command help text.
    """

    change_id: str  # "KS-001", "KS-002", …
    description: str  # "Remove or restrict `shell-exec` on `db-admin-mcp`"
    target_server: str
    target_tool: str | None = None
    capability: str  # human-readable capability label, e.g. "shell execution"
    paths_removed: int  # incremental paths broken at this greedy step
    path_ids_removed: list[str] = Field(default_factory=list)  # sorted PATH-NNN IDs
    paths_remaining: int  # paths still alive after this + all prior steps
    severity_reduction: str  # e.g. "removes 3 CRITICAL, 2 HIGH paths"
    rationale: str
    governance_patch: str | None = None


# ── Internal helpers ──────────────────────────────────────────────────────────


def _cap_label(cap_str: str) -> str:
    """Convert a raw capability string to a human-readable label."""
    try:
        from mcp_audit.analyzers.toxic_flow import Capability  # noqa: PLC0415

        cap_enum = Capability(cap_str)
        return _CAP_LABELS.get(cap_enum, cap_str.replace("_", " "))
    except ValueError:
        return cap_str.replace("_", " ")


def _infer_primary_capability(
    server: str,
    path_ids: set[str],
    paths: list[AttackPath],
) -> str:
    """Return the most prominent capability label for *server* across *path_ids*.

    Checks whether the server appears as source (hops[0]), sink (hops[-1]),
    or an intermediate hop in each path, weighting source/sink roles more
    heavily than intermediate appearances.  Returns the most frequent
    capability label, falling back to ``"unknown"`` when no path data is
    available.
    """
    cap_counter: Counter[str] = Counter()
    for path in paths:
        if path.id not in path_ids:
            continue
        hops = path.hops
        if not hops:
            continue
        if hops[0] == server:
            cap_counter[path.source_capability] += 2
        if hops[-1] == server:
            cap_counter[path.sink_capability] += 2
        if server in hops[1:-1]:
            cap_counter[path.source_capability] += 1
            cap_counter[path.sink_capability] += 1

    if not cap_counter:
        return "unknown"

    top_cap = cap_counter.most_common(1)[0][0]
    return _cap_label(top_cap)


def _severity_reduction_label(
    path_ids: set[str],
    paths: list[AttackPath],
) -> str:
    """Summarise the severity of the paths removed by this kill switch."""
    by_sev: dict[Severity, int] = {}
    for path in paths:
        if path.id in path_ids:
            by_sev[path.severity] = by_sev.get(path.severity, 0) + 1
    if not by_sev:
        return "no paths removed"
    parts = [
        f"{count} {sev}" for sev in _SEVERITY_ORDER if (count := by_sev.get(sev, 0)) > 0
    ]
    return "removes " + ", ".join(parts)


def _build_rationale(
    server: str,
    path_ids: set[str],
    all_paths: list[AttackPath],
    total_paths: int,
) -> str:
    """Generate a plain-English rationale sentence for targeting *server*."""
    n = len(path_ids)
    pct = int(100 * n / total_paths) if total_paths > 0 else 0

    source_count = sum(
        1 for p in all_paths if p.id in path_ids and p.hops and p.hops[0] == server
    )
    sink_count = sum(
        1 for p in all_paths if p.id in path_ids and p.hops and p.hops[-1] == server
    )

    if source_count > sink_count:
        role = "data-source node"
    elif sink_count > source_count:
        role = "exfiltration node"
    else:
        role = "key intermediate node"

    cap = _infer_primary_capability(server, path_ids, all_paths)
    return (
        f"`{server}` acts as a {role} in {n} of {total_paths} attack paths "
        f"({pct}%) via its {cap} capability. Removing or restricting this "
        "capability severs the shared edge across all affected paths."
    )


# ── Public API ────────────────────────────────────────────────────────────────


def recommend(
    summary: AttackPathSummary,
    top_n: int = 3,
) -> list[KillSwitch]:
    """Return the top-N kill switches ranked by blast-radius reduction.

    Follows the greedy hitting-set order already computed in *summary* —
    the highest-impact server first — then continues with additional servers
    from ``paths_broken_by`` (sorted by descending impact, then alphabetically
    for determinism) until *top_n* entries are produced or no more servers
    with path coverage remain.

    The result is fully deterministic: ties are broken by server name
    (alphabetical order), so repeated calls with the same input always
    produce identical output.

    Args:
        summary: Attack-path summary produced by ``summarize_attack_paths``.
        top_n: Maximum number of kill switches to return.  The result may be
            shorter when fewer independent changes are needed to cover all paths.

    Returns:
        List of :class:`KillSwitch` objects in priority order (highest
        blast-radius reduction first).
    """
    if not summary.paths:
        return []

    total_paths = len(summary.paths)
    server_to_path_ids: dict[str, set[str]] = {
        server: set(pids) for server, pids in summary.paths_broken_by.items()
    }
    remaining: set[str] = {p.id for p in summary.paths}
    result: list[KillSwitch] = []
    seen_servers: set[str] = set()

    # Primary order: the pre-computed hitting-set (greedy-optimal).
    # Secondary: additional servers from paths_broken_by sorted by
    # (descending impact, ascending name) for deterministic tie-breaking.
    hitting_set_order = list(summary.hitting_set)
    extra_servers = sorted(
        (s for s in server_to_path_ids if s not in set(hitting_set_order)),
        key=lambda s: (-len(server_to_path_ids[s]), s),
    )
    ordered = hitting_set_order + extra_servers

    for server in ordered:
        if len(result) >= top_n:
            break
        if server in seen_servers:
            continue
        seen_servers.add(server)

        newly_broken = server_to_path_ids.get(server, set()) & remaining
        if not newly_broken:
            # No incremental impact — all remaining candidates are redundant.
            break
        remaining -= newly_broken

        cap_label = _infer_primary_capability(server, newly_broken, summary.paths)
        sev_label = _severity_reduction_label(newly_broken, summary.paths)
        rationale = _build_rationale(server, newly_broken, summary.paths, total_paths)

        result.append(
            KillSwitch(
                change_id=f"KS-{len(result) + 1:03d}",
                description=(
                    f"Remove or restrict `{cap_label}` capability on server `{server}`"
                ),
                target_server=server,
                capability=cap_label,
                paths_removed=len(newly_broken),
                path_ids_removed=sorted(newly_broken),
                paths_remaining=len(remaining),
                severity_reduction=sev_label,
                rationale=rationale,
            )
        )

    return result
