"""Attack path summarization engine.

Builds directed multi-hop attack chains from toxic flow findings and the
full server capability graph, then computes a minimum hitting set — the
smallest collection of servers whose removal breaks every identified path.

Algorithm overview
------------------
1. **Path extraction** — parse toxic flow findings into 2-server (1-edge)
   AttackPath objects, then walk the capability graph with DFS (up to 4
   servers deep) to discover 3- and 4-server chains.
2. **Deduplication** — paths with identical ordered hop sequences are merged.
3. **Hitting set** — greedy set-cover approximation: repeatedly pick the
   server that appears in the most *remaining* unbroken paths until all paths
   are covered.  Runs in O(|paths| × |servers|) — acceptable for the scale of
   MCP configs encountered in practice.

Research basis:
  "Compromising LLM-Integrated Applications with Indirect Prompt Injection"
  Greshake et al., arXiv 2023 §4 — multi-tool attack chaining
  https://arxiv.org/abs/2302.12173
"""

from __future__ import annotations

from collections import defaultdict
from typing import NamedTuple

from mcp_audit.analyzers.toxic_flow import (
    TOXIC_PAIRS,
    Capability,
    tag_server,
)
from mcp_audit.models import (
    AttackPath,
    AttackPathSummary,
    Finding,
    ServerConfig,
    Severity,
)

# ── Capability flow graph ─────────────────────────────────────────────────────
# An edge (A, B) means "data produced by capability A can be consumed /
# forwarded by a server that has capability B" — enabling A-server → B-server
# chaining.  This is a superset of TOXIC_PAIRS (which only covers 2-server
# combinations); the extra edges allow intermediate hops to be discovered.

CAPABILITY_FLOWS: frozenset[tuple[Capability, Capability]] = frozenset(
    {
        (Capability.FILE_READ, Capability.NETWORK_OUT),
        (Capability.FILE_READ, Capability.EMAIL),
        (Capability.FILE_READ, Capability.SHELL_EXEC),
        (Capability.SECRETS, Capability.NETWORK_OUT),
        (Capability.SECRETS, Capability.EMAIL),
        (Capability.SECRETS, Capability.SHELL_EXEC),
        (Capability.DATABASE, Capability.NETWORK_OUT),
        (Capability.DATABASE, Capability.EMAIL),
        (Capability.DATABASE, Capability.SHELL_EXEC),
        (Capability.SHELL_EXEC, Capability.NETWORK_OUT),
        (Capability.SHELL_EXEC, Capability.EMAIL),
        (Capability.GIT, Capability.NETWORK_OUT),
        (Capability.BROWSER, Capability.NETWORK_OUT),
        (Capability.BROWSER, Capability.EMAIL),
    }
)

# Which capabilities are "source" (produce data) and which are "sink" (exfiltrate).
_SOURCE_CAPS: frozenset[Capability] = frozenset(
    {
        Capability.FILE_READ,
        Capability.DATABASE,
        Capability.SECRETS,
        Capability.GIT,
        Capability.BROWSER,
        Capability.SHELL_EXEC,  # shell output can be forwarded
    }
)

_SINK_CAPS: frozenset[Capability] = frozenset(
    {Capability.NETWORK_OUT, Capability.EMAIL}
)

# Severity mapping for (source_cap, sink_cap) pairs used in multi-hop paths.
_PAIR_SEVERITY: dict[tuple[Capability, Capability], Severity] = {
    tp: p.severity
    for p in TOXIC_PAIRS
    for tp in [(p.source, p.sink)]
}

_SEVERITY_ORDER: list[Severity] = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]

# Human-readable labels used in generated descriptions.
_CAP_LABELS: dict[Capability, str] = {
    Capability.FILE_READ: "file read",
    Capability.FILE_WRITE: "file write",
    Capability.NETWORK_OUT: "outbound network",
    Capability.SHELL_EXEC: "shell execution",
    Capability.DATABASE: "database access",
    Capability.EMAIL: "email sending",
    Capability.BROWSER: "browser automation",
    Capability.GIT: "git access",
    Capability.SECRETS: "secret/credential access",
}


# ── Internal helpers ──────────────────────────────────────────────────────────


class _PathCandidate(NamedTuple):
    hops: tuple[str, ...]
    source_cap: Capability
    sink_cap: Capability


def _max_severity(*severities: Severity) -> Severity:
    """Return the highest severity from an arbitrary number of Severity values."""
    for level in _SEVERITY_ORDER:
        if level in severities:
            return level
    return Severity.INFO


def _path_severity(source_cap: Capability, sink_cap: Capability) -> Severity:
    """Infer path severity from endpoint capabilities.

    Uses the pre-computed toxic pair severity table where available, then
    falls back to heuristics for combinations not covered by a toxic pair.
    """
    if (source_cap, sink_cap) in _PAIR_SEVERITY:
        return _PAIR_SEVERITY[(source_cap, sink_cap)]
    # Heuristic for combinations produced by multi-hop traversal.
    if source_cap in (Capability.SECRETS, Capability.SHELL_EXEC):
        return Severity.CRITICAL
    if sink_cap in (Capability.NETWORK_OUT, Capability.EMAIL):
        return Severity.HIGH
    return Severity.MEDIUM


def _path_title(source_cap: Capability, sink_cap: Capability, hop_count: int) -> str:
    """Generate a concise title for an attack path."""
    src_label = _CAP_LABELS.get(source_cap, str(source_cap))
    snk_label = _CAP_LABELS.get(sink_cap, str(sink_cap))
    suffix = f" ({hop_count}-server chain)" if hop_count > 2 else ""
    return f"{src_label.capitalize()} → {snk_label} exfiltration path{suffix}"


def _path_description(
    hops: tuple[str, ...],
    server_caps: dict[str, frozenset[Capability]],
    source_cap: Capability,
    sink_cap: Capability,
) -> str:
    """Generate a plain-English narrative for an attack path."""
    src_label = _CAP_LABELS.get(source_cap, str(source_cap))
    snk_label = _CAP_LABELS.get(sink_cap, str(sink_cap))

    if len(hops) == 1:
        return (
            f"The '{hops[0]}' server has both {src_label} and {snk_label} "
            "capabilities. An attacker or prompt injection can use a single "
            "server to both access sensitive data and exfiltrate it."
        )

    hop_parts = []
    for hop in hops:
        caps = server_caps.get(hop, frozenset())
        cap_labels = [_CAP_LABELS.get(c, str(c)) for c in sorted(caps, key=str)]
        cap_str = ", ".join(cap_labels) if cap_labels else "unknown"
        hop_parts.append(f"'{hop}' ({cap_str})")

    chain = " → ".join(hop_parts)
    return (
        f"An attacker can chain {chain} to progress from {src_label} through to "
        f"{snk_label}. Each hop in this {len(hops)}-server chain amplifies the "
        "attacker's reach — a prompt injection in any participating server is "
        "sufficient to trigger the full path."
    )


def _flows_between(
    caps_a: frozenset[Capability],
    caps_b: frozenset[Capability],
) -> tuple[Capability, Capability] | None:
    """Return the first (source_cap, sink_cap) flow edge between two cap sets.

    Returns ``None`` when no flow edge connects the two sets.
    """
    for ca in sorted(caps_a, key=str):
        for cb in sorted(caps_b, key=str):
            if (ca, cb) in CAPABILITY_FLOWS:
                return ca, cb
    return None


def _build_adjacency(
    servers: list[ServerConfig],
    server_caps: dict[str, frozenset[Capability]],
) -> dict[str, list[str]]:
    """Build directed adjacency list: server A → servers reachable from A.

    A → B exists when at least one capability flow edge connects a cap in A
    to a cap in B, and A ≠ B.
    """
    adj: dict[str, list[str]] = defaultdict(list)
    for a in servers:
        caps_a = server_caps.get(a.name, frozenset())
        if not caps_a:
            continue
        for b in servers:
            if a.name == b.name:
                continue
            caps_b = server_caps.get(b.name, frozenset())
            if _flows_between(caps_a, caps_b) is not None:
                adj[a.name].append(b.name)
    return dict(adj)


def _dfs_paths(
    start: str,
    adj: dict[str, list[str]],
    max_depth: int,
) -> list[tuple[str, ...]]:
    """DFS from *start*, returning all simple paths of length ≥ 2 servers.

    2-server paths are included so that graph-based detection still works when
    no toxic findings are supplied.  The caller deduplicates against paths
    already extracted from toxic findings.
    """
    results: list[tuple[str, ...]] = []

    def _dfs(path: list[str], visited: set[str]) -> None:
        if len(path) >= 2:
            results.append(tuple(path))
        if len(path) >= max_depth:
            return
        for nxt in adj.get(path[-1], []):
            if nxt not in visited:
                visited.add(nxt)
                path.append(nxt)
                _dfs(path, visited)
                path.pop()
                visited.remove(nxt)

    _dfs([start], {start})
    return results


def _candidates_from_toxic_findings(
    toxic_findings: list[Finding],
) -> list[_PathCandidate]:
    """Convert 2-server toxic flow findings into PathCandidates.

    Parses the finding's ``server`` field ("source + sink" or "name" for
    self-pairs) and resolves the source/sink capabilities from the finding ID.
    """
    finding_id_to_pair = {tp.finding_id: tp for tp in TOXIC_PAIRS}
    seen: set[tuple[str, ...]] = set()
    candidates: list[_PathCandidate] = []

    for f in toxic_findings:
        if f.analyzer != "toxic_flow":
            continue
        tp = finding_id_to_pair.get(f.id)
        if tp is None:
            continue

        if " + " in f.server:
            src_name, snk_name = f.server.split(" + ", 1)
            hops: tuple[str, ...] = (src_name, snk_name)
        else:
            hops = (f.server,)  # self-pair

        if hops in seen:
            continue
        seen.add(hops)
        candidates.append(_PathCandidate(hops, tp.source, tp.sink))

    return candidates


def _candidates_from_graph(
    servers: list[ServerConfig],
    server_caps: dict[str, frozenset[Capability]],
    existing_hop_tuples: set[tuple[str, ...]],
    max_depth: int = 4,
) -> list[_PathCandidate]:
    """Walk the capability graph to find multi-hop chains (≥ 3 servers).

    Skips paths whose hop sequence is already represented in
    *existing_hop_tuples* to avoid re-emitting toxic pair findings.
    """
    adj = _build_adjacency(servers, server_caps)
    seen: set[tuple[str, ...]] = set(existing_hop_tuples)
    candidates: list[_PathCandidate] = []

    for server in servers:
        for hops in _dfs_paths(server.name, adj, max_depth):
            if hops in seen:
                continue
            seen.add(hops)

            caps_src = server_caps.get(hops[0], frozenset())
            caps_snk = server_caps.get(hops[-1], frozenset())
            edge = _flows_between(caps_src, caps_snk)
            if edge is None:
                # Try using the actual traversal endpoint caps if direct
                # src→snk edge doesn't exist (valid for indirect paths).
                for ca in sorted(caps_src, key=str):
                    if ca in _SOURCE_CAPS:
                        for cb in sorted(caps_snk, key=str):
                            if cb in _SINK_CAPS:
                                edge = (ca, cb)
                                break
                    if edge:
                        break
            if edge is None:
                continue
            candidates.append(_PathCandidate(hops, edge[0], edge[1]))

    return candidates


# ── Hitting set ───────────────────────────────────────────────────────────────


def _compute_hitting_set(
    paths: list[AttackPath],
) -> tuple[list[str], dict[str, list[str]]]:
    """Greedy minimum hitting set approximation.

    Iteratively selects the server appearing in the most remaining unbroken
    paths until every path has been covered.  This is the standard greedy
    approximation for weighted set cover (ln(n)+1 factor guarantee).

    Args:
        paths: All attack paths to cover.

    Returns:
        A tuple of (hitting_set, paths_broken_by) where:

        * *hitting_set* is an ordered list of server names (highest impact
          first) whose removal would break every path.
        * *paths_broken_by* maps **every** server that appears in any path to
          the list of path IDs it would break — useful for "remove X to break
          N paths" recommendations.
    """
    if not paths:
        return [], {}

    # Build server → set of path IDs mapping for all servers.
    server_to_path_ids: dict[str, set[str]] = defaultdict(set)
    for path in paths:
        for hop in path.hops:
            server_to_path_ids[hop].add(path.id)

    # Greedy selection loop.
    remaining: set[str] = {p.id for p in paths}
    hitting_set: list[str] = []

    while remaining:
        # Pick the server that covers the most remaining paths.
        best = max(
            server_to_path_ids,
            key=lambda s: len(server_to_path_ids[s] & remaining),
        )
        covered = server_to_path_ids[best] & remaining
        if not covered:
            break  # Remaining paths have no servers — structural anomaly.
        hitting_set.append(best)
        remaining -= covered

    paths_broken_by = {s: sorted(pids) for s, pids in server_to_path_ids.items()}
    return hitting_set, paths_broken_by


# ── Public API ────────────────────────────────────────────────────────────────


def summarize_attack_paths(
    servers: list[ServerConfig],
    toxic_findings: list[Finding],
) -> AttackPathSummary:
    """Build an :class:`~mcp_audit.models.AttackPathSummary` from scan data.

    Steps:

    1. Tag every server with capability labels (re-uses the toxic flow tagger).
    2. Create :class:`~mcp_audit.models.AttackPath` objects for every 2-server
       toxic pair found in *toxic_findings*.
    3. Walk the capability graph (DFS, up to 4 servers) to discover multi-hop
       chains not already covered by step 2.
    4. Compute the greedy minimum hitting set and the per-server breaking power.

    Args:
        servers: All MCP servers discovered in the current scan.
        toxic_findings: Findings produced by
            :class:`~mcp_audit.analyzers.toxic_flow.ToxicFlowAnalyzer`.

    Returns:
        An :class:`~mcp_audit.models.AttackPathSummary` with paths, hitting
        set, and per-server impact data.  Returns an empty summary when no
        attack paths are found.
    """
    if not servers:
        return AttackPathSummary()

    # Step 1 — tag capabilities.
    server_caps: dict[str, frozenset[Capability]] = {
        s.name: tag_server(s) for s in servers
    }

    # Step 2 — candidates from toxic findings (2-server chains).
    from_findings = _candidates_from_toxic_findings(toxic_findings)
    existing_hops: set[tuple[str, ...]] = {c.hops for c in from_findings}

    # Step 3 — multi-hop candidates from graph traversal.
    from_graph = _candidates_from_graph(servers, server_caps, existing_hops)

    all_candidates = from_findings + from_graph

    if not all_candidates:
        return AttackPathSummary()

    # Build AttackPath objects.
    attack_paths: list[AttackPath] = []
    for idx, cand in enumerate(all_candidates, start=1):
        path_id = f"PATH-{idx:03d}"
        severity = _path_severity(cand.source_cap, cand.sink_cap)
        title = _path_title(cand.source_cap, cand.sink_cap, len(cand.hops))
        description = _path_description(
            cand.hops, server_caps, cand.source_cap, cand.sink_cap
        )
        attack_paths.append(
            AttackPath(
                id=path_id,
                severity=severity,
                title=title,
                description=description,
                hops=list(cand.hops),
                source_capability=str(cand.source_cap),
                sink_capability=str(cand.sink_cap),
            )
        )

    # Sort by severity so callers always see the worst paths first.
    attack_paths.sort(key=lambda p: _SEVERITY_ORDER.index(p.severity))

    # Step 4 — hitting set.
    hitting_set, paths_broken_by = _compute_hitting_set(attack_paths)

    return AttackPathSummary(
        paths=attack_paths,
        hitting_set=hitting_set,
        paths_broken_by=paths_broken_by,
    )
