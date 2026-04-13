"""Tests for the attack path summarization engine."""

from __future__ import annotations

from pathlib import Path

from mcp_audit.analyzers.attack_paths import (
    CAPABILITY_FLOWS,
    _build_adjacency,
    _candidates_from_toxic_findings,
    _compute_hitting_set,
    _max_severity,
    _path_severity,
    summarize_attack_paths,
)
from mcp_audit.analyzers.toxic_flow import Capability, ToxicFlowAnalyzer
from mcp_audit.models import (
    AttackPath,
    AttackPathSummary,
    Finding,
    ServerConfig,
    Severity,
    TransportType,
)

# ── Shared helpers ─────────────────────────────────────────────────────────────


def _server(
    name: str,
    command: str = "npx",
    args: list[str] | None = None,
    env: dict[str, str] | None = None,
    client: str = "cursor",
) -> ServerConfig:
    resolved_args = args or []
    return ServerConfig(
        name=name,
        client=client,
        config_path=Path("/tmp/test_mcp.json"),  # noqa: S108
        transport=TransportType.STDIO,
        command=command,
        args=resolved_args,
        env=env or {},
        raw={"command": command, "args": resolved_args},
    )


def _filesystem_server(name: str = "filesystem") -> ServerConfig:
    return _server(
        name,
        args=["-y", "@modelcontextprotocol/server-filesystem"],
    )


def _fetch_server(name: str = "fetch") -> ServerConfig:
    return _server(
        name,
        args=["-y", "@modelcontextprotocol/server-fetch"],
    )


def _shell_server(name: str = "shell") -> ServerConfig:
    """Server with shell execution capability."""
    return _server(name, command="bash", args=["exec-wrapper.sh"])


def _secrets_server(name: str = "vault") -> ServerConfig:
    return _server(name, args=["vault-mcp-server"])


def _toxic_finding(
    finding_id: str = "TOXIC-001",
    server: str = "filesystem + fetch",
    severity: Severity = Severity.HIGH,
    analyzer: str = "toxic_flow",
) -> Finding:
    return Finding(
        id=finding_id,
        severity=severity,
        analyzer=analyzer,
        client="cursor",
        server=server,
        title="Test toxic flow",
        description="Test description.",
        evidence="'filesystem' has 'file_read'; 'fetch' has 'network_out'",
        remediation="Remove one server.",
    )


# ── Path construction from toxic findings ──────────────────────────────────────


class TestCandidatesFromToxicFindings:
    def test_cross_server_pair_parsed(self) -> None:
        finding = _toxic_finding(
            finding_id="TOXIC-001", server="filesystem + fetch", severity=Severity.HIGH
        )
        candidates = _candidates_from_toxic_findings([finding])

        assert len(candidates) == 1
        assert candidates[0].hops == ("filesystem", "fetch")
        assert candidates[0].source_cap == Capability.FILE_READ
        assert candidates[0].sink_cap == Capability.NETWORK_OUT

    def test_self_pair_parsed(self) -> None:
        finding = _toxic_finding(
            finding_id="TOXIC-001", server="everything", severity=Severity.HIGH
        )
        candidates = _candidates_from_toxic_findings([finding])

        assert len(candidates) == 1
        assert candidates[0].hops == ("everything",)

    def test_non_toxic_findings_skipped(self) -> None:
        finding = Finding(
            id="POISON-001",
            severity=Severity.HIGH,
            analyzer="poisoning",
            client="cursor",
            server="server-a",
            title="Poisoning",
            description="desc",
            evidence="evidence",
            remediation="fix",
        )
        assert _candidates_from_toxic_findings([finding]) == []

    def test_unknown_finding_id_skipped(self) -> None:
        finding = _toxic_finding(finding_id="TOXIC-999", server="a + b")
        assert _candidates_from_toxic_findings([finding]) == []

    def test_duplicate_hops_deduplicated(self) -> None:
        f1 = _toxic_finding(finding_id="TOXIC-001", server="filesystem + fetch")
        f2 = _toxic_finding(finding_id="TOXIC-001", server="filesystem + fetch")
        candidates = _candidates_from_toxic_findings([f1, f2])
        assert len(candidates) == 1

    def test_multiple_findings_produce_multiple_candidates(self) -> None:
        f1 = _toxic_finding(finding_id="TOXIC-001", server="filesystem + fetch")
        f2 = _toxic_finding(
            finding_id="TOXIC-003",
            server="vault + fetch",
            severity=Severity.CRITICAL,
        )
        candidates = _candidates_from_toxic_findings([f1, f2])
        assert len(candidates) == 2
        hops_list = [c.hops for c in candidates]
        assert ("filesystem", "fetch") in hops_list
        assert ("vault", "fetch") in hops_list

    def test_empty_input_returns_empty(self) -> None:
        assert _candidates_from_toxic_findings([]) == []


# ── Multi-hop chain detection ──────────────────────────────────────────────────


class TestMultiHopDetection:
    def test_three_server_chain_detected(self) -> None:
        """filesystem (file_read) → shell (shell_exec) → fetch (network_out)."""
        servers = [_filesystem_server(), _shell_server(), _fetch_server()]
        summary = summarize_attack_paths(servers, [])

        three_hop_paths = [p for p in summary.paths if len(p.hops) == 3]
        assert len(three_hop_paths) >= 1

        hop_sequences = [tuple(p.hops) for p in three_hop_paths]
        assert ("filesystem", "shell", "fetch") in hop_sequences

    def test_two_server_chain_from_graph(self) -> None:
        """Direct FILE_READ → NETWORK_OUT chain with no prior toxic findings."""
        servers = [_filesystem_server(), _fetch_server()]
        summary = summarize_attack_paths(servers, [])

        two_hop_paths = [p for p in summary.paths if len(p.hops) == 2]
        assert len(two_hop_paths) >= 1

    def test_no_chain_when_no_dangerous_caps(self) -> None:
        safe_server = _server(
            "memory", args=["-y", "@modelcontextprotocol/server-memory"]
        )
        summary = summarize_attack_paths([safe_server], [])
        assert summary.paths == []

    def test_max_depth_respected(self) -> None:
        """Paths should not exceed 4 servers."""
        # Build a five-server linear chain.
        servers = [
            _filesystem_server("fs"),
            _shell_server("sh1"),
            _shell_server("sh2"),
            _shell_server("sh3"),
            _fetch_server("net"),
        ]
        summary = summarize_attack_paths(servers, [])
        for path in summary.paths:
            assert len(path.hops) <= 4, f"Path {path.id} exceeds 4 hops: {path.hops}"

    def test_path_ids_are_unique(self) -> None:
        servers = [_filesystem_server(), _shell_server(), _fetch_server()]
        summary = summarize_attack_paths(servers, [])
        ids = [p.id for p in summary.paths]
        assert len(ids) == len(set(ids))

    def test_path_ids_use_correct_format(self) -> None:
        servers = [_filesystem_server(), _fetch_server()]
        summary = summarize_attack_paths(servers, [])
        for path in summary.paths:
            assert path.id.startswith("PATH-")
            assert path.id[5:].isdigit()

    def test_severity_sorted_descending(self) -> None:
        servers = [_filesystem_server(), _fetch_server(), _secrets_server()]
        summary = summarize_attack_paths(servers, [])
        severities = [p.severity for p in summary.paths]
        from mcp_audit.analyzers.attack_paths import _SEVERITY_ORDER
        for i in range(len(severities) - 1):
            assert _SEVERITY_ORDER.index(severities[i]) <= _SEVERITY_ORDER.index(
                severities[i + 1]
            )

    def test_self_pair_server_in_hops(self) -> None:
        """A single server with both source and sink caps forms a 1-hop path."""
        everything = _server(
            "everything",
            args=["-y", "@modelcontextprotocol/server-everything"],
        )
        # Produce a self-pair toxic finding.
        finding = _toxic_finding(
            finding_id="TOXIC-001", server="everything", severity=Severity.HIGH
        )
        summary = summarize_attack_paths([everything], [finding])
        self_paths = [p for p in summary.paths if p.hops == ["everything"]]
        assert len(self_paths) == 1


# ── Hitting set computation ────────────────────────────────────────────────────


class TestHittingSet:
    def _make_path(
        self,
        path_id: str,
        hops: list[str],
        severity: Severity = Severity.HIGH,
    ) -> AttackPath:
        return AttackPath(
            id=path_id,
            severity=severity,
            title="Test path",
            description="Test",
            hops=hops,
            source_capability="file_read",
            sink_capability="network_out",
        )

    def test_single_path_single_shared_server(self) -> None:
        paths = [self._make_path("PATH-001", ["a", "b"])]
        hs, broken_by = _compute_hitting_set(paths)
        # Either 'a' or 'b' suffices; HS must have exactly 1 element.
        assert len(hs) == 1
        assert hs[0] in {"a", "b"}

    def test_server_covering_most_paths_chosen_first(self) -> None:
        """'fetch' appears in 3 paths; it should be the first selection."""
        paths = [
            self._make_path("PATH-001", ["filesystem", "fetch"]),
            self._make_path("PATH-002", ["vault", "fetch"]),
            self._make_path("PATH-003", ["db", "fetch"]),
            self._make_path("PATH-004", ["db", "email"]),
        ]
        hs, _ = _compute_hitting_set(paths)
        assert hs[0] == "fetch"

    def test_hitting_set_breaks_all_paths(self) -> None:
        paths = [
            self._make_path("PATH-001", ["a", "b"]),
            self._make_path("PATH-002", ["c", "d"]),
            self._make_path("PATH-003", ["a", "d"]),
        ]
        hs, broken_by = _compute_hitting_set(paths)

        # Verify every path is actually broken by at least one HS member.
        all_path_ids = {p.id for p in paths}
        covered = set()
        for s in hs:
            covered |= set(broken_by.get(s, []))
        assert covered >= all_path_ids

    def test_empty_paths_returns_empty_hitting_set(self) -> None:
        hs, broken_by = _compute_hitting_set([])
        assert hs == []
        assert broken_by == {}

    def test_paths_broken_by_populated_for_all_servers(self) -> None:
        paths = [
            self._make_path("PATH-001", ["a", "b"]),
            self._make_path("PATH-002", ["b", "c"]),
        ]
        _, broken_by = _compute_hitting_set(paths)
        assert "a" in broken_by
        assert "b" in broken_by
        assert "c" in broken_by
        assert broken_by["b"] == ["PATH-001", "PATH-002"]

    def test_greedy_prefers_highest_coverage(self) -> None:
        """Server 'b' covers all 3 paths; it must be the sole HS element."""
        paths = [
            self._make_path("PATH-001", ["a", "b"]),
            self._make_path("PATH-002", ["b", "c"]),
            self._make_path("PATH-003", ["d", "b"]),
        ]
        hs, broken_by = _compute_hitting_set(paths)
        assert hs == ["b"]
        assert set(broken_by["b"]) == {"PATH-001", "PATH-002", "PATH-003"}


# ── Removing hitting set actually breaks all paths ─────────────────────────────


class TestHittingSetSoundness:
    """Verify that removing hitting-set servers truly breaks every path."""

    def _paths_remaining_after_removal(
        self, summary: AttackPathSummary
    ) -> list[AttackPath]:
        """Return paths not broken by any hitting-set server."""
        hs_set = set(summary.hitting_set)
        return [p for p in summary.paths if not hs_set & set(p.hops)]

    def test_removal_breaks_all_paths_filesystem_fetch(self) -> None:
        servers = [_filesystem_server(), _fetch_server()]
        summary = summarize_attack_paths(servers, [])
        assert self._paths_remaining_after_removal(summary) == []

    def test_removal_breaks_all_paths_three_server_chain(self) -> None:
        servers = [_filesystem_server(), _shell_server(), _fetch_server()]
        summary = summarize_attack_paths(servers, [])
        assert self._paths_remaining_after_removal(summary) == []

    def test_removal_breaks_all_paths_complex_topology(self) -> None:
        servers = [
            _filesystem_server(),
            _fetch_server(),
            _secrets_server(),
            _shell_server(),
        ]
        summary = summarize_attack_paths(servers, [])
        assert self._paths_remaining_after_removal(summary) == []

    def test_removal_breaks_all_paths_from_toxic_findings(self) -> None:
        servers = [_filesystem_server(), _fetch_server(), _secrets_server()]
        toxic_findings = ToxicFlowAnalyzer().analyze_all(servers)
        summary = summarize_attack_paths(servers, toxic_findings)
        assert self._paths_remaining_after_removal(summary) == []


# ── Edge cases ─────────────────────────────────────────────────────────────────


class TestEdgeCases:
    def test_no_servers_returns_empty_summary(self) -> None:
        summary = summarize_attack_paths([], [])
        assert summary.paths == []
        assert summary.hitting_set == []
        assert summary.paths_broken_by == {}

    def test_single_safe_server_no_paths(self) -> None:
        server = _server("memory", args=["-y", "@modelcontextprotocol/server-memory"])
        summary = summarize_attack_paths([server], [])
        assert summary.paths == []
        assert summary.hitting_set == []

    def test_single_server_both_caps_produces_self_path(self) -> None:
        everything = _server(
            "everything",
            args=["-y", "@modelcontextprotocol/server-everything"],
        )
        finding = _toxic_finding(finding_id="TOXIC-001", server="everything")
        summary = summarize_attack_paths([everything], [finding])

        assert len(summary.paths) >= 1
        self_path = next(p for p in summary.paths if p.hops == ["everything"])
        assert self_path is not None
        assert summary.hitting_set == ["everything"]

    def test_no_toxic_findings_still_detects_from_graph(self) -> None:
        """Graph traversal must work without any toxic findings input."""
        servers = [_filesystem_server(), _fetch_server()]
        summary = summarize_attack_paths(servers, [])
        assert len(summary.paths) >= 1

    def test_attack_path_fields_populated(self) -> None:
        servers = [_filesystem_server(), _fetch_server()]
        summary = summarize_attack_paths(servers, [])
        path = summary.paths[0]

        assert path.id
        assert path.severity in list(Severity)
        assert path.title
        assert path.description
        assert len(path.hops) >= 1
        assert path.source_capability
        assert path.sink_capability

    def test_summary_model_fields_populated(self) -> None:
        servers = [_filesystem_server(), _fetch_server()]
        summary = summarize_attack_paths(servers, [])

        assert isinstance(summary.paths, list)
        assert isinstance(summary.hitting_set, list)
        assert isinstance(summary.paths_broken_by, dict)
        assert len(summary.hitting_set) >= 1

    def test_duplicate_toxic_findings_not_duplicated_in_paths(self) -> None:
        finding = _toxic_finding(finding_id="TOXIC-001", server="filesystem + fetch")
        servers = [_filesystem_server(), _fetch_server()]
        summary = summarize_attack_paths(servers, [finding, finding])
        # The (filesystem, fetch) 2-hop path should appear once.
        two_hop = [p for p in summary.paths if set(p.hops) == {"filesystem", "fetch"}]
        assert len(two_hop) == 1


# ── Utility function tests ─────────────────────────────────────────────────────


class TestUtilities:
    def test_max_severity_critical_wins(self) -> None:
        result = _max_severity(Severity.HIGH, Severity.CRITICAL, Severity.LOW)
        assert result == Severity.CRITICAL

    def test_max_severity_single(self) -> None:
        assert _max_severity(Severity.MEDIUM) == Severity.MEDIUM

    def test_path_severity_secrets_network_is_critical(self) -> None:
        sev = _path_severity(Capability.SECRETS, Capability.NETWORK_OUT)
        assert sev == Severity.CRITICAL

    def test_path_severity_file_network_is_high(self) -> None:
        sev = _path_severity(Capability.FILE_READ, Capability.NETWORK_OUT)
        assert sev == Severity.HIGH

    def test_capability_flows_contains_expected_edges(self) -> None:
        assert (Capability.FILE_READ, Capability.NETWORK_OUT) in CAPABILITY_FLOWS
        assert (Capability.SHELL_EXEC, Capability.NETWORK_OUT) in CAPABILITY_FLOWS
        assert (Capability.SECRETS, Capability.NETWORK_OUT) in CAPABILITY_FLOWS

    def test_build_adjacency_connects_file_to_network(self) -> None:
        servers = [_filesystem_server(), _fetch_server()]
        from mcp_audit.analyzers.toxic_flow import tag_server
        server_caps = {s.name: tag_server(s) for s in servers}
        adj = _build_adjacency(servers, server_caps)
        assert "fetch" in adj.get("filesystem", [])

    def test_build_adjacency_no_self_loops(self) -> None:
        servers = [_filesystem_server(), _fetch_server()]
        from mcp_audit.analyzers.toxic_flow import tag_server
        server_caps = {s.name: tag_server(s) for s in servers}
        adj = _build_adjacency(servers, server_caps)
        for src, targets in adj.items():
            assert src not in targets
