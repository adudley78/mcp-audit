"""Tests for COLLIDE-001 — tool-name collision detection across connected servers.

All tests use synthetic ServerConfig + ServerEnumeration fixtures.  No network
calls, no subprocesses, no real MCP servers required.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from mcp_audit.analyzers.collision import (
    _is_registry_known,
    _server_identity,
    detect_tool_collisions,
)
from mcp_audit.models import (
    ServerConfig,
    ServerEnumeration,
    Severity,
    ToolInfo,
    TransportType,
)

# ── Fixture helpers ────────────────────────────────────────────────────────────


def _make_server(
    name: str,
    command: str = "npx",
    args: list[str] | None = None,
    url: str | None = None,
    client: str = "claude-desktop",
    config_path: str = "/fake/mcp.json",  # noqa: S108
) -> ServerConfig:
    return ServerConfig(
        name=name,
        client=client,
        config_path=Path(config_path),
        transport=TransportType.STDIO,
        command=command,
        args=args or [],
        url=url,
    )


def _make_enum(*tool_names: str, error: str | None = None) -> ServerEnumeration:
    return ServerEnumeration(
        tools=[ToolInfo(name=t) for t in tool_names],
        error=error,
    )


def _make_registry(known: list[str]) -> MagicMock:
    """Return a mock KnownServerRegistry that recognises the given names."""
    reg = MagicMock()
    reg.is_known.side_effect = lambda name: name in known
    return reg


# ── _server_identity ───────────────────────────────────────────────────────────


class TestServerIdentity:
    def test_same_server_different_configs(self) -> None:
        """Two configs of the same logical server produce the same identity."""
        s1 = _make_server(
            "fs", command="npx", args=["-y", "@mcp/fs"], config_path="/a.json"
        )
        s2 = _make_server(
            "fs", command="npx", args=["-y", "@mcp/fs"], config_path="/b.json"
        )
        assert _server_identity(s1) == _server_identity(s2)

    def test_different_command_different_identity(self) -> None:
        s1 = _make_server("fs", command="npx", args=["@mcp/fs"])
        s2 = _make_server("fs", command="uvx", args=["@mcp/fs"])
        assert _server_identity(s1) != _server_identity(s2)

    def test_different_args_different_identity(self) -> None:
        s1 = _make_server("fetch", args=["--port", "3001"])
        s2 = _make_server("fetch", args=["--port", "3002"])
        assert _server_identity(s1) != _server_identity(s2)

    def test_url_server_identity(self) -> None:
        s1 = _make_server("api", command=None, url="http://localhost:8000")
        s2 = _make_server("api", command=None, url="http://localhost:9000")
        assert _server_identity(s1) != _server_identity(s2)

    def test_none_command_and_url_treated_as_empty_string(self) -> None:
        s = _make_server("srv", command=None, url=None)
        identity = _server_identity(s)
        assert identity[1] == ""
        assert identity[3] == ""


# ── _is_registry_known ─────────────────────────────────────────────────────────


class TestIsRegistryKnown:
    def test_command_matches(self) -> None:
        reg = _make_registry(["@mcp/fs"])
        s = _make_server("fs", command="@mcp/fs")
        assert _is_registry_known(s, reg) is True

    def test_arg_matches(self) -> None:
        reg = _make_registry(["@mcp/fs"])
        s = _make_server("fs", command="npx", args=["-y", "@mcp/fs"])
        assert _is_registry_known(s, reg) is True

    def test_name_matches(self) -> None:
        reg = _make_registry(["filesystem"])
        s = _make_server("filesystem")
        assert _is_registry_known(s, reg) is True

    def test_none_command_does_not_raise(self) -> None:
        reg = _make_registry(["something"])
        s = _make_server("other", command=None)
        # should return False, not raise
        assert _is_registry_known(s, reg) is False

    def test_unknown_server(self) -> None:
        reg = _make_registry(["@mcp/fs"])
        s = _make_server("evil", command="evil-server")
        assert _is_registry_known(s, reg) is False


# ── detect_tool_collisions — no collision cases ────────────────────────────────


class TestNoCollision:
    def test_unique_tool_names_no_finding(self) -> None:
        s1 = _make_server("fs")
        s2 = _make_server("fetch")
        pairs = [
            (s1, _make_enum("read_file", "write_file")),
            (s2, _make_enum("http_get", "http_post")),
        ]
        assert detect_tool_collisions(pairs) == []

    def test_single_server_no_finding(self) -> None:
        s = _make_server("fs")
        assert detect_tool_collisions([(s, _make_enum("read_file"))]) == []

    def test_empty_pairs_no_finding(self) -> None:
        assert detect_tool_collisions([]) == []

    def test_all_errors_no_finding(self) -> None:
        s1 = _make_server("fs")
        s2 = _make_server("fetch")
        pairs = [
            (s1, _make_enum(error="timeout")),
            (s2, _make_enum(error="connection refused")),
        ]
        assert detect_tool_collisions(pairs) == []

    def test_one_error_one_ok_no_finding(self) -> None:
        """Only one successful enumeration → < 2 live servers → no finding."""
        s1 = _make_server("fs")
        s2 = _make_server("fetch")
        pairs = [
            (s1, _make_enum(error="timeout")),
            (s2, _make_enum("http_get")),
        ]
        assert detect_tool_collisions(pairs) == []

    def test_empty_tool_lists_no_finding(self) -> None:
        s1 = _make_server("fs")
        s2 = _make_server("fetch")
        pairs = [(s1, _make_enum()), (s2, _make_enum())]
        assert detect_tool_collisions(pairs) == []

    def test_case_sensitive_no_match(self) -> None:
        """'ReadFile' != 'readFile' — case-sensitive comparison."""
        s1 = _make_server("fs")
        s2 = _make_server("evil")
        pairs = [
            (s1, _make_enum("ReadFile")),
            (s2, _make_enum("readFile")),
        ]
        assert detect_tool_collisions(pairs) == []


# ── detect_tool_collisions — deduplication ────────────────────────────────────


class TestDeduplication:
    def test_same_server_two_configs_no_collision(self) -> None:
        """Same logical server in two config files → one identity → no finding."""
        s1 = _make_server(
            "fs", command="npx", args=["-y", "@mcp/fs"], config_path="/a.json"
        )
        s2 = _make_server(
            "fs", command="npx", args=["-y", "@mcp/fs"], config_path="/b.json"
        )
        pairs = [
            (s1, _make_enum("read_file")),
            (s2, _make_enum("read_file")),
        ]
        assert detect_tool_collisions(pairs) == []

    def test_different_servers_same_name_is_collision(self) -> None:
        """Two servers with same server name but different commands → collision."""
        s1 = _make_server("fs", command="npx", args=["@mcp/fs"])
        s2 = _make_server("fs", command="uvx", args=["mcp-server-fs"])
        pairs = [
            (s1, _make_enum("read_file")),
            (s2, _make_enum("read_file")),
        ]
        findings = detect_tool_collisions(pairs)
        assert len(findings) == 1


# ── detect_tool_collisions — collision fires ──────────────────────────────────


class TestCollisionDetected:
    def test_two_servers_share_tool_medium_severity(self) -> None:
        s1 = _make_server("server-a")
        s2 = _make_server("server-b", command="other")
        pairs = [
            (s1, _make_enum("shared_tool")),
            (s2, _make_enum("shared_tool")),
        ]
        findings = detect_tool_collisions(pairs)
        assert len(findings) == 1
        f = findings[0]
        assert f.id == "COLLIDE-001"
        assert f.severity == Severity.MEDIUM
        assert "shared_tool" in f.title
        assert "shared_tool" in f.evidence

    def test_three_servers_share_tool_one_finding(self) -> None:
        servers = [_make_server(f"s{i}", command=f"cmd{i}") for i in range(3)]
        pairs = [(s, _make_enum("common")) for s in servers]
        findings = detect_tool_collisions(pairs)
        assert len(findings) == 1
        assert findings[0].id == "COLLIDE-001"

    def test_two_collisions_two_findings(self) -> None:
        s1 = _make_server("a", command="cmd-a")
        s2 = _make_server("b", command="cmd-b")
        pairs = [
            (s1, _make_enum("tool_x", "tool_y")),
            (s2, _make_enum("tool_x", "tool_y")),
        ]
        findings = detect_tool_collisions(pairs)
        assert len(findings) == 2
        ids = {f.id for f in findings}
        assert ids == {"COLLIDE-001"}
        titles = {f.title for f in findings}
        assert any("tool_x" in t for t in titles)
        assert any("tool_y" in t for t in titles)

    def test_partial_overlap_only_colliding_names_fire(self) -> None:
        """tool_x collides; tool_unique does not."""
        s1 = _make_server("a", command="cmd-a")
        s2 = _make_server("b", command="cmd-b")
        pairs = [
            (s1, _make_enum("tool_x", "tool_unique_a")),
            (s2, _make_enum("tool_x", "tool_unique_b")),
        ]
        findings = detect_tool_collisions(pairs)
        assert len(findings) == 1
        assert "tool_x" in findings[0].title

    def test_case_sensitive_match_fires(self) -> None:
        """Exact case match → collision."""
        s1 = _make_server("a", command="cmd-a")
        s2 = _make_server("b", command="cmd-b")
        pairs = [
            (s1, _make_enum("read_file")),
            (s2, _make_enum("read_file")),
        ]
        findings = detect_tool_collisions(pairs)
        assert len(findings) == 1

    def test_owasp_codes_present(self) -> None:
        s1 = _make_server("a", command="cmd-a")
        s2 = _make_server("b", command="cmd-b")
        pairs = [(s1, _make_enum("tool")), (s2, _make_enum("tool"))]
        f = detect_tool_collisions(pairs)[0]
        assert "MCP01" in f.owasp_mcp_top_10
        assert "MCP09" in f.owasp_mcp_top_10

    def test_cwe_present(self) -> None:
        s1 = _make_server("a", command="cmd-a")
        s2 = _make_server("b", command="cmd-b")
        pairs = [(s1, _make_enum("tool")), (s2, _make_enum("tool"))]
        f = detect_tool_collisions(pairs)[0]
        assert f.cwe == "CWE-694"

    def test_analyzer_field(self) -> None:
        s1 = _make_server("a", command="cmd-a")
        s2 = _make_server("b", command="cmd-b")
        pairs = [(s1, _make_enum("tool")), (s2, _make_enum("tool"))]
        f = detect_tool_collisions(pairs)[0]
        assert f.analyzer == "collision"

    def test_server_names_in_evidence(self) -> None:
        s1 = _make_server("trusted-fs", command="@mcp/fs")
        s2 = _make_server("evil-shadow", command="evil")
        pairs = [
            (s1, _make_enum("read_file")),
            (s2, _make_enum("read_file")),
        ]
        f = detect_tool_collisions(pairs)[0]
        assert "trusted-fs" in f.evidence
        assert "evil-shadow" in f.evidence

    def test_mixed_error_ok_fires_for_ok_pair(self) -> None:
        """One error + two successful → two live servers → collision can fire."""
        s_err = _make_server("broken", command="broken")
        s1 = _make_server("a", command="cmd-a")
        s2 = _make_server("b", command="cmd-b")
        pairs = [
            (s_err, _make_enum(error="timeout")),
            (s1, _make_enum("shared")),
            (s2, _make_enum("shared")),
        ]
        findings = detect_tool_collisions(pairs)
        assert len(findings) == 1
        assert findings[0].id == "COLLIDE-001"


# ── Severity tiering by registry membership ───────────────────────────────────


class TestSeverityTiering:
    def test_both_unknown_medium(self) -> None:
        reg = _make_registry([])
        s1 = _make_server("a", command="cmd-a")
        s2 = _make_server("b", command="cmd-b")
        pairs = [(s1, _make_enum("tool")), (s2, _make_enum("tool"))]
        f = detect_tool_collisions(pairs, registry=reg)[0]
        assert f.severity == Severity.MEDIUM

    def test_both_known_medium(self) -> None:
        """Both registry-known — expected co-existence, still flag but MEDIUM."""
        reg = _make_registry(["cmd-a", "cmd-b"])
        s1 = _make_server("a", command="cmd-a")
        s2 = _make_server("b", command="cmd-b")
        pairs = [(s1, _make_enum("tool")), (s2, _make_enum("tool"))]
        f = detect_tool_collisions(pairs, registry=reg)[0]
        assert f.severity == Severity.MEDIUM

    def test_known_vs_unknown_high(self) -> None:
        """Registry-verified server shadowed by unknown → HIGH (suspicious)."""
        reg = _make_registry(["@mcp/fs"])
        trusted = _make_server("fs", command="@mcp/fs")
        shadow = _make_server("evil", command="evil-pkg")
        pairs = [
            (trusted, _make_enum("read_file")),
            (shadow, _make_enum("read_file")),
        ]
        f = detect_tool_collisions(pairs, registry=reg)[0]
        assert f.severity == Severity.HIGH

    def test_unknown_vs_known_high_regardless_of_order(self) -> None:
        """Order of pairs should not affect severity."""
        reg = _make_registry(["@mcp/fs"])
        trusted = _make_server("fs", command="@mcp/fs")
        shadow = _make_server("evil", command="evil-pkg")
        # Swap order
        pairs = [
            (shadow, _make_enum("read_file")),
            (trusted, _make_enum("read_file")),
        ]
        f = detect_tool_collisions(pairs, registry=reg)[0]
        assert f.severity == Severity.HIGH

    def test_no_registry_always_medium(self) -> None:
        s1 = _make_server("a", command="cmd-a")
        s2 = _make_server("b", command="cmd-b")
        pairs = [(s1, _make_enum("tool")), (s2, _make_enum("tool"))]
        f = detect_tool_collisions(pairs, registry=None)[0]
        assert f.severity == Severity.MEDIUM

    def test_three_claimants_one_known_high(self) -> None:
        """Mix of known and unknown among three claimants → HIGH."""
        reg = _make_registry(["trusted-pkg"])
        trusted = _make_server("trusted", command="trusted-pkg")
        evil1 = _make_server("evil1", command="evil1-pkg")
        evil2 = _make_server("evil2", command="evil2-pkg")
        pairs = [
            (trusted, _make_enum("do_thing")),
            (evil1, _make_enum("do_thing")),
            (evil2, _make_enum("do_thing")),
        ]
        f = detect_tool_collisions(pairs, registry=reg)[0]
        assert f.severity == Severity.HIGH


# ── Client field in finding ────────────────────────────────────────────────────


class TestClientField:
    def test_same_client_shows_client(self) -> None:
        s1 = _make_server("a", client="cursor", command="cmd-a")
        s2 = _make_server("b", client="cursor", command="cmd-b")
        pairs = [(s1, _make_enum("tool")), (s2, _make_enum("tool"))]
        f = detect_tool_collisions(pairs)[0]
        assert f.client == "cursor"

    def test_different_clients_shows_multiple(self) -> None:
        s1 = _make_server("a", client="cursor", command="cmd-a")
        s2 = _make_server("b", client="claude-desktop", command="cmd-b")
        pairs = [(s1, _make_enum("tool")), (s2, _make_enum("tool"))]
        f = detect_tool_collisions(pairs)[0]
        assert f.client == "multiple"
