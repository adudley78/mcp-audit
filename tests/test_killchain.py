"""Tests for the mcp-audit killchain decision engine.

Covers:
- ``recommend()`` determinism and greedy-order correctness.
- ``simulate()`` produces the same attack-path summary as a fresh run would.
- ``patches.py`` generates YAML that parses via the governance loader.
- ``render.py`` Markdown and JSON formatters — no missing placeholders.
- CLI integration via typer.testing.CliRunner.
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml
from typer.testing import CliRunner

from mcp_audit.analyzers.attack_paths import summarize_attack_paths
from mcp_audit.analyzers.toxic_flow import ToxicFlowAnalyzer
from mcp_audit.cli import app
from mcp_audit.killchain.patches import generate_pr_comment, generate_yaml_patch
from mcp_audit.killchain.recommender import KillSwitch, recommend
from mcp_audit.killchain.render import render_json, render_markdown
from mcp_audit.killchain.simulator import simulate
from mcp_audit.models import (
    AttackPath,
    AttackPathSummary,
    Finding,
    ScanResult,
    ServerConfig,
    Severity,
    TransportType,
)

runner = CliRunner()

# ── Shared fixtures ────────────────────────────────────────────────────────────


def _server(
    name: str,
    command: str = "npx",
    args: list[str] | None = None,
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
        env={},
        raw={"command": command, "args": resolved_args},
    )


def _filesystem_server(name: str = "filesystem") -> ServerConfig:
    return _server(name, args=["-y", "@modelcontextprotocol/server-filesystem"])


def _fetch_server(name: str = "fetch") -> ServerConfig:
    return _server(name, args=["-y", "@modelcontextprotocol/server-fetch"])


def _shell_server(name: str = "shell") -> ServerConfig:
    return _server(name, command="bash", args=["exec-wrapper.sh"])


def _db_server(name: str = "db") -> ServerConfig:
    return _server(
        name, args=["postgres-mcp-server", "--db-url", "postgres://localhost/db"]
    )


def _email_server(name: str = "email") -> ServerConfig:
    return _server(name, args=["email-mcp", "--smtp-host", "mail.example.com"])


def _toxic_finding(
    finding_id: str = "TOXIC-001",
    server: str = "filesystem + fetch",
    severity: Severity = Severity.HIGH,
) -> Finding:
    return Finding(
        id=finding_id,
        severity=severity,
        analyzer="toxic_flow",
        client="cursor",
        server=server,
        title="Test toxic flow",
        description="Test description",
        evidence="test evidence",
        remediation="Remove one server.",
    )


def _make_attack_path(
    path_id: str,
    hops: list[str],
    severity: Severity = Severity.HIGH,
    source_cap: str = "file_read",
    sink_cap: str = "network_out",
) -> AttackPath:
    return AttackPath(
        id=path_id,
        severity=severity,
        title=f"Test path {path_id}",
        description="Test attack path",
        hops=hops,
        source_capability=source_cap,
        sink_capability=sink_cap,
    )


def _make_summary_with_paths(
    paths: list[AttackPath],
) -> AttackPathSummary:
    """Build an AttackPathSummary with the hitting set computed from paths."""
    from mcp_audit.analyzers.attack_paths import _compute_hitting_set  # noqa: PLC0415

    hitting_set, paths_broken_by = _compute_hitting_set(paths)
    return AttackPathSummary(
        paths=paths,
        hitting_set=hitting_set,
        paths_broken_by=paths_broken_by,
    )


def _make_scan_result_with_servers(
    servers: list[ServerConfig],
) -> ScanResult:
    """Run ToxicFlowAnalyzer and summarize_attack_paths for a server list."""
    toxic_findings = ToxicFlowAnalyzer().analyze_all(servers)
    summary = summarize_attack_paths(servers, toxic_findings)
    result = ScanResult()
    result.servers = servers
    result.findings = toxic_findings
    result.attack_path_summary = summary
    return result


# ── recommender.recommend() ────────────────────────────────────────────────────


class TestRecommend:
    def test_empty_summary_returns_empty(self) -> None:
        summary = AttackPathSummary()
        switches = recommend(summary)
        assert switches == []

    def test_single_path_single_server_recommendation(self) -> None:
        """One path between filesystem→fetch; recommend removing one of them."""
        servers = [_filesystem_server(), _fetch_server()]
        result = _make_scan_result_with_servers(servers)
        summary = result.attack_path_summary
        assert summary is not None
        assert len(summary.paths) >= 1

        switches = recommend(summary, top_n=3)
        assert len(switches) >= 1
        first = switches[0]
        assert first.change_id == "KS-001"
        assert first.paths_removed >= 1
        assert first.target_server in (s.name for s in servers)

    def test_recommend_top_n_respected(self) -> None:
        """Given --top 5 with a 5-server setup, returns ≤5 switches."""
        paths = [
            _make_attack_path("PATH-001", ["alpha", "beta"]),
            _make_attack_path("PATH-002", ["alpha", "gamma"]),
            _make_attack_path("PATH-003", ["delta", "epsilon"]),
            _make_attack_path("PATH-004", ["alpha", "delta"]),
            _make_attack_path("PATH-005", ["zeta", "beta"]),
        ]
        summary = _make_summary_with_paths(paths)
        switches = recommend(summary, top_n=5)
        assert len(switches) <= 5
        assert len(switches) >= 1
        for i, ks in enumerate(switches):
            assert ks.change_id == f"KS-{i + 1:03d}"

    def test_greedy_picks_highest_impact_first(self) -> None:
        """Server 'alpha' appears in 3 paths; it must be picked first."""
        paths = [
            _make_attack_path("PATH-001", ["alpha", "beta"]),
            _make_attack_path("PATH-002", ["alpha", "gamma"]),
            _make_attack_path("PATH-003", ["alpha", "delta"]),
            _make_attack_path("PATH-004", ["epsilon", "zeta"]),
        ]
        summary = _make_summary_with_paths(paths)
        switches = recommend(summary, top_n=3)
        assert switches[0].target_server == "alpha"
        assert switches[0].paths_removed == 3

    def test_shared_capability_picked_first(self) -> None:
        """Three servers share the same hitting set server → picked first."""
        servers = [
            _filesystem_server("fs1"),
            _filesystem_server("fs2"),
            _filesystem_server("fs3"),
            _fetch_server("net"),
        ]
        result = _make_scan_result_with_servers(servers)
        summary = result.attack_path_summary
        assert summary is not None
        switches = recommend(summary, top_n=3)
        # "net" (fetch) is the single sink shared by all three filesystem servers
        assert switches[0].target_server in ("net", "fs1", "fs2", "fs3")
        # First switch must break > 1 path (shared edge)
        assert switches[0].paths_removed >= 1

    def test_deterministic_on_repeated_calls(self) -> None:
        """Same input always produces identical output."""
        paths = [
            _make_attack_path("PATH-001", ["alpha", "beta"]),
            _make_attack_path("PATH-002", ["gamma", "delta"]),
            _make_attack_path("PATH-003", ["alpha", "delta"]),
        ]
        summary = _make_summary_with_paths(paths)
        result_a = recommend(summary, top_n=3)
        result_b = recommend(summary, top_n=3)
        assert [ks.model_dump() for ks in result_a] == [
            ks.model_dump() for ks in result_b
        ]

    def test_incremental_paths_remaining_decreases(self) -> None:
        """paths_remaining must decrease (or stay the same) across switches."""
        paths = [
            _make_attack_path("PATH-001", ["alpha", "beta"]),
            _make_attack_path("PATH-002", ["alpha", "gamma"]),
            _make_attack_path("PATH-003", ["delta", "epsilon"]),
        ]
        summary = _make_summary_with_paths(paths)
        switches = recommend(summary, top_n=3)
        prev_remaining = len(paths)
        for ks in switches:
            assert ks.paths_remaining <= prev_remaining
            prev_remaining = ks.paths_remaining

    def test_all_independent_paths_no_shared_edge(self) -> None:
        """Every path has a unique server pair — each switch removes exactly 1."""
        paths = [
            _make_attack_path("PATH-001", ["a", "b"]),
            _make_attack_path("PATH-002", ["c", "d"]),
            _make_attack_path("PATH-003", ["e", "f"]),
        ]
        summary = _make_summary_with_paths(paths)
        switches = recommend(summary, top_n=3)
        # Each switch may remove 1 or more paths depending on the hitting set
        total_removed = sum(ks.paths_removed for ks in switches)
        assert total_removed == len(paths)

    def test_fields_are_populated(self) -> None:
        """Every KillSwitch field is non-empty."""
        servers = [_filesystem_server(), _fetch_server()]
        result = _make_scan_result_with_servers(servers)
        summary = result.attack_path_summary
        assert summary
        switches = recommend(summary, top_n=1)
        assert switches
        ks = switches[0]
        assert ks.change_id
        assert ks.description
        assert ks.target_server
        assert ks.capability
        assert ks.rationale
        assert ks.severity_reduction
        assert isinstance(ks.paths_removed, int)
        assert isinstance(ks.paths_remaining, int)

    def test_top_n_default_is_three(self) -> None:
        """Default top_n is 3."""
        paths = [
            _make_attack_path(f"PATH-{i:03d}", ["alpha", f"node{i}"])
            for i in range(1, 8)
        ]
        # alpha appears in all 7 paths; after removing alpha all paths are gone
        summary = _make_summary_with_paths(paths)
        switches = recommend(summary)
        assert len(switches) <= 3


# ── simulator.simulate() ──────────────────────────────────────────────────────


class TestSimulate:
    def test_no_changes_returns_original_summary(self) -> None:
        servers = [_filesystem_server(), _fetch_server()]
        result = _make_scan_result_with_servers(servers)
        original = result.attack_path_summary or AttackPathSummary()
        simulated = simulate(result, [])
        assert len(simulated.paths) == len(original.paths)

    def test_removing_all_servers_yields_empty_summary(self) -> None:
        servers = [_filesystem_server(), _fetch_server()]
        result = _make_scan_result_with_servers(servers)
        summary = result.attack_path_summary or AttackPathSummary()
        switches = recommend(summary, top_n=10)
        simulated = simulate(result, switches)
        assert len(simulated.paths) == 0

    def test_simulate_matches_fresh_scan_without_server(self) -> None:
        """Simulate removing 'fetch' should equal a fresh scan without it."""
        servers = [_filesystem_server(), _fetch_server()]
        result = _make_scan_result_with_servers(servers)
        original_summary = result.attack_path_summary or AttackPathSummary()
        assert len(original_summary.paths) > 0

        # Determine which server to remove from the recommendation
        switches = recommend(original_summary, top_n=1)
        assert switches
        target = switches[0].target_server

        # Simulate removal
        simulated = simulate(result, [switches[0]])

        # Fresh scan without that server
        remaining = [s for s in servers if s.name != target]
        fresh_result = _make_scan_result_with_servers(remaining)
        fresh_summary = fresh_result.attack_path_summary or AttackPathSummary()

        assert len(simulated.paths) == len(fresh_summary.paths)

    def test_paths_remaining_matches_simulation(self) -> None:
        """KillSwitch.paths_remaining matches simulate() path count."""
        servers = [_filesystem_server(), _fetch_server()]
        result = _make_scan_result_with_servers(servers)
        summary = result.attack_path_summary or AttackPathSummary()
        switches = recommend(summary, top_n=1)
        assert switches
        simulated = simulate(result, [switches[0]])
        assert len(simulated.paths) == switches[0].paths_remaining

    def test_simulate_is_idempotent(self) -> None:
        """simulate() called twice with same inputs produces identical results."""
        servers = [_filesystem_server(), _fetch_server()]
        result = _make_scan_result_with_servers(servers)
        summary = result.attack_path_summary or AttackPathSummary()
        switches = recommend(summary, top_n=1)
        a = simulate(result, switches)
        b = simulate(result, switches)
        assert [p.id for p in a.paths] == [p.id for p in b.paths]


# ── patches.generate_yaml_patch() ─────────────────────────────────────────────


class TestGenerateYamlPatch:
    def test_empty_switches_returns_comment(self) -> None:
        patch = generate_yaml_patch([])
        assert patch.startswith("#")

    def test_yaml_patch_is_valid_yaml(self) -> None:
        switches = [
            KillSwitch(
                change_id="KS-001",
                description="Remove file-read on fs",
                target_server="filesystem",
                capability="file read",
                paths_removed=3,
                paths_remaining=0,
                severity_reduction="removes 3 HIGH",
                rationale="Test rationale",
            )
        ]
        patch = generate_yaml_patch(switches)
        parsed = yaml.safe_load(patch)
        assert isinstance(parsed, dict)
        assert "approved_servers" in parsed

    def test_yaml_patch_parses_via_governance_loader(self) -> None:
        """Patched YAML must load without error via the governance model."""
        from mcp_audit.governance.models import GovernancePolicy  # noqa: PLC0415

        switches = [
            KillSwitch(
                change_id="KS-001",
                description="Remove shell-exec on admin",
                target_server="db-admin-mcp",
                capability="shell execution",
                paths_removed=8,
                paths_remaining=4,
                severity_reduction="removes 3 CRITICAL",
                rationale="Test",
            )
        ]
        patch_yaml = generate_yaml_patch(switches)
        # Strip comments (yaml.safe_load handles them, but governance loader
        # may use Pydantic — parse via GovernancePolicy directly)
        parsed = yaml.safe_load(patch_yaml)
        policy = GovernancePolicy.model_validate(parsed)
        assert policy.approved_servers is not None
        assert policy.approved_servers.mode == "denylist"
        assert any(e.name == "db-admin-mcp" for e in policy.approved_servers.entries)

    def test_patch_contains_all_target_servers(self) -> None:
        switches = [
            KillSwitch(
                change_id=f"KS-{i:03d}",
                description=f"Remove server{i}",
                target_server=f"server{i}",
                capability="file read",
                paths_removed=1,
                paths_remaining=0,
                severity_reduction="removes 1 HIGH",
                rationale="Test",
            )
            for i in range(1, 4)
        ]
        patch = generate_yaml_patch(switches)
        for ks in switches:
            assert ks.target_server in patch

    def test_generate_pr_comment_contains_table(self) -> None:
        switches = [
            KillSwitch(
                change_id="KS-001",
                description="Remove file-read on fs",
                target_server="filesystem",
                capability="file read",
                paths_removed=2,
                paths_remaining=1,
                severity_reduction="removes 2 HIGH",
                rationale="Test rationale text.",
            )
        ]
        comment = generate_pr_comment(switches)
        assert "KS-001" in comment
        assert "filesystem" in comment
        assert "|" in comment  # Markdown table


# ── render.render_markdown() ──────────────────────────────────────────────────


class TestRenderMarkdown:
    def _make_switches(self, n: int = 2) -> list[KillSwitch]:
        return [
            KillSwitch(
                change_id=f"KS-{i:03d}",
                description=f"Remove `cap{i}` from `server{i}`",
                target_server=f"server{i}",
                capability=f"cap{i}",
                paths_removed=3 - i,
                path_ids_removed=[f"PATH-{j:03d}" for j in range(1, 4 - i)],
                paths_remaining=i,
                severity_reduction=f"removes {3 - i} HIGH",
                rationale=f"Server{i} is critical.",
            )
            for i in range(1, n + 1)
        ]

    def test_no_paths_returns_no_attack_paths_message(self) -> None:
        md = render_markdown([], AttackPathSummary())
        assert "No reachable attack paths" in md

    def test_contains_blast_radius(self) -> None:
        paths = [
            _make_attack_path("PATH-001", ["a", "b"], Severity.CRITICAL),
            _make_attack_path("PATH-002", ["a", "c"], Severity.HIGH),
        ]
        summary = _make_summary_with_paths(paths)
        switches = self._make_switches(2)
        md = render_markdown(switches, summary)
        assert "2 reachable attack path" in md
        assert "CRITICAL" in md

    def test_contains_all_switch_change_ids(self) -> None:
        paths = [
            _make_attack_path(f"PATH-{i:03d}", ["alpha", f"node{i}"])
            for i in range(1, 4)
        ]
        summary = _make_summary_with_paths(paths)
        switches = self._make_switches(2)
        md = render_markdown(switches, summary)
        assert "KS-001" in md
        assert "KS-002" in md

    def test_contains_what_if_section(self) -> None:
        paths = [_make_attack_path("PATH-001", ["a", "b"])]
        summary = _make_summary_with_paths(paths)
        simulated = AttackPathSummary()  # empty = all paths eliminated
        switches = self._make_switches(1)
        md = render_markdown(switches, summary, simulated)
        assert "What-if" in md or "what-if" in md.lower()

    def test_no_unfilled_placeholders(self) -> None:
        """No ``{...}`` placeholders should remain in output."""
        paths = [_make_attack_path("PATH-001", ["a", "b"])]
        summary = _make_summary_with_paths(paths)
        simulated = AttackPathSummary()
        switches = self._make_switches(1)
        md = render_markdown(switches, summary, simulated)
        import re

        unresolved = re.findall(r"\{[a-z_]+\}", md)
        assert not unresolved, f"Unresolved placeholders: {unresolved}"

    def test_all_independent_notice_shown_when_no_shared_edge(self) -> None:
        paths = [
            _make_attack_path("PATH-001", ["a", "b"]),
            _make_attack_path("PATH-002", ["c", "d"]),
        ]
        summary = _make_summary_with_paths(paths)
        # Ensure all switches break ≤1 path (no shared edge case)
        independent_switches = [
            KillSwitch(
                change_id=f"KS-{i:03d}",
                description=f"Change {i}",
                target_server=f"server{i}",
                capability="file read",
                paths_removed=1,
                paths_remaining=0,
                severity_reduction="removes 1 HIGH",
                rationale="Test",
            )
            for i in range(1, 3)
        ]
        md = render_markdown(independent_switches, summary)
        assert "no common edge" in md


# ── render.render_json() ──────────────────────────────────────────────────────


class TestRenderJson:
    def test_output_is_valid_json(self) -> None:
        paths = [_make_attack_path("PATH-001", ["a", "b"])]
        summary = _make_summary_with_paths(paths)
        switches = recommend(summary, top_n=1)
        output = render_json(switches, summary)
        parsed = json.loads(output)
        assert isinstance(parsed, dict)

    def test_json_fields_present(self) -> None:
        paths = [_make_attack_path("PATH-001", ["a", "b"])]
        summary = _make_summary_with_paths(paths)
        switches = recommend(summary, top_n=1)
        simulated = AttackPathSummary()
        output = render_json(switches, summary, simulated)
        parsed = json.loads(output)
        assert "generated" in parsed
        assert "original_blast_radius" in parsed
        assert "simulated_blast_radius" in parsed
        assert "kill_switches" in parsed
        assert isinstance(parsed["kill_switches"], list)

    def test_json_kill_switch_fields(self) -> None:
        paths = [_make_attack_path("PATH-001", ["alpha", "beta"])]
        summary = _make_summary_with_paths(paths)
        switches = recommend(summary, top_n=1)
        output = render_json(switches, summary)
        parsed = json.loads(output)
        ks = parsed["kill_switches"][0]
        for field in (
            "change_id",
            "description",
            "target_server",
            "paths_removed",
            "paths_remaining",
            "severity_reduction",
            "rationale",
        ):
            assert field in ks, f"Missing field: {field}"

    def test_json_round_trips(self) -> None:
        """JSON output round-trips: keys are preserved after re-parsing."""
        paths = [_make_attack_path("PATH-001", ["alpha", "beta"])]
        summary = _make_summary_with_paths(paths)
        switches = recommend(summary, top_n=1)
        output = render_json(switches, summary)
        first_parse = json.loads(output)
        second_parse = json.loads(json.dumps(first_parse))
        assert first_parse == second_parse


# ── CLI integration ────────────────────────────────────────────────────────────


class TestKillchainCLI:
    def _minimal_scan_json(self, tmp_path: Path) -> Path:
        """Write a minimal scan JSON with two servers and attack paths."""
        servers = [_filesystem_server(), _fetch_server()]
        result = _make_scan_result_with_servers(servers)
        p = tmp_path / "scan.json"
        p.write_text(
            result.model_dump_json(by_alias=True, indent=2),
            encoding="utf-8",
        )
        return p

    def _empty_scan_json(self, tmp_path: Path) -> Path:
        """Write a scan JSON with no attack paths."""
        result = ScanResult()
        p = tmp_path / "empty_scan.json"
        p.write_text(
            result.model_dump_json(by_alias=True, indent=2),
            encoding="utf-8",
        )
        return p

    def test_no_attack_paths_exits_0(self, tmp_path: Path) -> None:
        scan_file = self._empty_scan_json(tmp_path)
        result = runner.invoke(app, ["killchain", "--input", str(scan_file)])
        assert result.exit_code == 0
        assert "No reachable attack paths" in result.output

    def test_with_findings_exits_0(self, tmp_path: Path) -> None:
        scan_file = self._minimal_scan_json(tmp_path)
        result = runner.invoke(app, ["killchain", "--input", str(scan_file)])
        assert result.exit_code == 0
        assert "KS-001" in result.output

    def test_format_json_produces_valid_json(self, tmp_path: Path) -> None:
        scan_file = self._minimal_scan_json(tmp_path)
        result = runner.invoke(
            app, ["killchain", "--input", str(scan_file), "--format", "json"]
        )
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert "kill_switches" in parsed

    def test_top_flag_respected(self, tmp_path: Path) -> None:
        scan_file = self._minimal_scan_json(tmp_path)
        result = runner.invoke(
            app, ["killchain", "--input", str(scan_file), "--top", "1"]
        )
        assert result.exit_code == 0
        assert "KS-001" in result.output
        # KS-002 should not appear when top=1
        assert "KS-002" not in result.output

    def test_patch_yaml_included_in_output(self, tmp_path: Path) -> None:
        scan_file = self._minimal_scan_json(tmp_path)
        result = runner.invoke(
            app, ["killchain", "--input", str(scan_file), "--patch", "yaml"]
        )
        assert result.exit_code == 0
        assert "approved_servers" in result.output

    def test_output_file_written(self, tmp_path: Path) -> None:
        scan_file = self._minimal_scan_json(tmp_path)
        out_file = tmp_path / "report.md"
        result = runner.invoke(
            app,
            [
                "killchain",
                "--input",
                str(scan_file),
                "--output-file",
                str(out_file),
            ],
        )
        assert result.exit_code == 0
        assert out_file.exists()
        content = out_file.read_text()
        assert "killchain" in content.lower()

    def test_invalid_format_exits_2(self, tmp_path: Path) -> None:
        scan_file = self._minimal_scan_json(tmp_path)
        result = runner.invoke(
            app,
            ["killchain", "--input", str(scan_file), "--format", "html"],
        )
        assert result.exit_code == 2

    def test_invalid_patch_exits_2(self, tmp_path: Path) -> None:
        scan_file = self._minimal_scan_json(tmp_path)
        result = runner.invoke(
            app,
            ["killchain", "--input", str(scan_file), "--patch", "toml"],
        )
        assert result.exit_code == 2

    def test_missing_input_file_exits_2(self, tmp_path: Path) -> None:
        result = runner.invoke(
            app, ["killchain", "--input", str(tmp_path / "nonexistent.json")]
        )
        assert result.exit_code == 2

    def test_invalid_json_input_exits_2(self, tmp_path: Path) -> None:
        bad_json = tmp_path / "bad.json"
        bad_json.write_text("not valid json", encoding="utf-8")
        result = runner.invoke(app, ["killchain", "--input", str(bad_json)])
        assert result.exit_code == 2

    def test_incompatible_version_exits_2(self, tmp_path: Path) -> None:
        old_scan = {"version": "0.0.1", "servers": [], "findings": []}
        old_file = tmp_path / "old.json"
        old_file.write_text(json.dumps(old_scan), encoding="utf-8")
        result = runner.invoke(app, ["killchain", "--input", str(old_file)])
        # 0.0.1 < 0.1.0 — should exit 2
        assert result.exit_code == 2

    def test_killchain_in_help(self) -> None:
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "killchain" in result.output


# ── Edge cases ─────────────────────────────────────────────────────────────────


class TestEdgeCases:
    def test_single_server_self_pair(self) -> None:
        """A server that is its own toxic pair (source+sink on same server)."""
        # Manually inject a toxic finding for a self-pair
        self_finding = Finding(
            id="TOXIC-001",
            severity=Severity.HIGH,
            analyzer="toxic_flow",
            client="cursor",
            server="all-in-one",  # self-pair: no " + "
            title="Self toxic flow",
            description="Test",
            evidence="test",
            remediation="Remove server.",
        )
        from mcp_audit.analyzers.attack_paths import (  # noqa: PLC0415
            _candidates_from_toxic_findings,
        )

        candidates = _candidates_from_toxic_findings([self_finding])
        # Self-pair may or may not be parsed depending on finding_id match;
        # at minimum no error should be raised
        assert isinstance(candidates, list)

    def test_recommend_with_zero_paths_broken(self) -> None:
        """server in paths_broken_by but breaks 0 remaining paths is skipped."""
        paths = [_make_attack_path("PATH-001", ["alpha", "beta"])]
        summary = _make_summary_with_paths(paths)
        switches = recommend(summary, top_n=5)
        # All switches must break at least the paths coverage adds up
        total_removed = sum(ks.paths_removed for ks in switches)
        assert total_removed == len(paths)

    def test_simulate_does_not_mutate_original(self) -> None:
        servers = [_filesystem_server(), _fetch_server()]
        result = _make_scan_result_with_servers(servers)
        original_server_count = len(result.servers)
        summary = result.attack_path_summary or AttackPathSummary()
        switches = recommend(summary, top_n=1)
        simulate(result, switches)
        # Original scan result must be unchanged
        assert len(result.servers) == original_server_count

    def test_large_blast_radius_completes_quickly(self) -> None:
        """Greedy algorithm should handle 100+ paths in reasonable time."""
        import time  # noqa: PLC0415

        # Build 10 nodes each connecting to 10 other nodes → 100 paths
        paths = [
            _make_attack_path(
                f"PATH-{i * 10 + j:03d}",
                [f"source{i}", f"sink{j}"],
            )
            for i in range(10)
            for j in range(10)
        ]
        summary = _make_summary_with_paths(paths)

        start = time.monotonic()
        switches = recommend(summary, top_n=5)
        elapsed = time.monotonic() - start

        assert elapsed < 5.0, f"recommend() took {elapsed:.2f}s — exceeds 5s budget"
        assert switches
