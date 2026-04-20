"""Tests for the HTML dashboard generator and dashboard CLI command."""

from __future__ import annotations

import json
import re
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from mcp_audit.cli import app
from mcp_audit.models import (
    AttackPath,
    AttackPathSummary,
    Finding,
    ScanResult,
    ServerConfig,
    Severity,
    TransportType,
)
from mcp_audit.output.dashboard import _build_scan_data, generate_html

# ── Test fixtures ─────────────────────────────────────────────────────────────


def _server(
    name: str = "filesystem",
    args: list[str] | None = None,
    client: str = "cursor",
) -> ServerConfig:
    resolved_args = args or ["-y", "@modelcontextprotocol/server-filesystem"]
    return ServerConfig(
        name=name,
        client=client,
        config_path=Path("/tmp/test_mcp.json"),  # noqa: S108
        transport=TransportType.STDIO,
        command="npx",
        args=resolved_args,
        env={},
        raw={"command": "npx", "args": resolved_args},
    )


def _finding(
    server: str = "filesystem + fetch",
    severity: Severity = Severity.HIGH,
    analyzer: str = "toxic_flow",
    finding_id: str = "TOXIC-001",
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


def _minimal_result() -> ScanResult:
    """A ScanResult with no findings and no servers — the zero case."""
    return ScanResult(clients_scanned=1, servers_found=0)


def _rich_result() -> ScanResult:
    """A ScanResult populated with servers, findings, and attack paths."""
    fs = _server("filesystem", args=["-y", "@modelcontextprotocol/server-filesystem"])
    fetch = _server("fetch", args=["-y", "@modelcontextprotocol/server-fetch"])
    vault = _server("vault", args=["vault-mcp-server"])

    findings = [
        _finding("filesystem + fetch", Severity.HIGH, "toxic_flow", "TOXIC-001"),
        _finding("vault + fetch", Severity.CRITICAL, "toxic_flow", "TOXIC-003"),
        _finding(
            "filesystem",
            Severity.MEDIUM,
            "poisoning",
            "POISON-001",
        ),
    ]

    attack_path_summary = AttackPathSummary(
        paths=[
            AttackPath(
                id="PATH-001",
                severity=Severity.HIGH,
                title="File exfiltration via network",
                description="filesystem reads files, fetch exfiltrates.",
                hops=["filesystem", "fetch"],
                source_capability="file_read",
                sink_capability="network_out",
            ),
            AttackPath(
                id="PATH-002",
                severity=Severity.CRITICAL,
                title="Credential theft + exfiltration",
                description="vault accesses secrets, fetch exfiltrates.",
                hops=["vault", "fetch"],
                source_capability="secrets",
                sink_capability="network_out",
            ),
        ],
        hitting_set=["fetch"],
        paths_broken_by={
            "filesystem": ["PATH-001"],
            "fetch": ["PATH-001", "PATH-002"],
            "vault": ["PATH-002"],
        },
    )

    return ScanResult(
        clients_scanned=1,
        servers_found=3,
        servers=[fs, fetch, vault],
        findings=findings,
        attack_path_summary=attack_path_summary,
    )


# ── _build_scan_data ──────────────────────────────────────────────────────────


class TestBuildScanData:
    def test_required_top_level_keys_present(self) -> None:
        data = _build_scan_data(_rich_result())
        required = {
            "version",
            "timestamp",
            "clients_scanned",
            "servers_found",
            "finding_counts",
            "findings",
            "servers",
            "toxic_edges",
            "attack_paths",
            "hitting_set",
            "paths_broken_by",
            "summary",
        }
        assert required <= set(data.keys())

    def test_finding_counts_all_severities_present(self) -> None:
        data = _build_scan_data(_rich_result())
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            assert sev in data["finding_counts"]

    def test_findings_have_required_fields(self) -> None:
        data = _build_scan_data(_rich_result())
        for f in data["findings"]:
            for key in ("id", "severity", "analyzer", "server", "title", "evidence"):
                assert key in f, f"Missing key {key!r} in finding {f}"

    def test_servers_have_required_fields(self) -> None:
        data = _build_scan_data(_rich_result())
        assert len(data["servers"]) == 3
        for s in data["servers"]:
            for key in (
                "id",
                "name",
                "client",
                "capabilities",
                "finding_count",
                "in_hitting_set",
            ):
                assert key in s, f"Missing key {key!r} in server {s}"

    def test_server_id_equals_name(self) -> None:
        data = _build_scan_data(_rich_result())
        for s in data["servers"]:
            assert s["id"] == s["name"]

    def test_server_in_hitting_set_flag(self) -> None:
        data = _build_scan_data(_rich_result())
        # "fetch" is the only hitting set member in _rich_result
        fetch = next(s for s in data["servers"] if s["name"] == "fetch")
        assert fetch["in_hitting_set"] is True
        fs = next(s for s in data["servers"] if s["name"] == "filesystem")
        assert fs["in_hitting_set"] is False

    def test_server_capabilities_detected(self) -> None:
        data = _build_scan_data(_rich_result())
        fs = next(s for s in data["servers"] if s["name"] == "filesystem")
        assert "file_read" in fs["capabilities"]

    def test_toxic_edges_extracted(self) -> None:
        data = _build_scan_data(_rich_result())
        sources = {e["source"] for e in data["toxic_edges"]}
        targets = {e["target"] for e in data["toxic_edges"]}
        assert "filesystem" in sources
        assert "fetch" in targets

    def test_toxic_edges_have_label(self) -> None:
        data = _build_scan_data(_rich_result())
        for edge in data["toxic_edges"]:
            assert "label" in edge
            assert isinstance(edge["label"], str)

    def test_toxic_edges_deduplicated(self) -> None:
        # Duplicate the same finding twice — should produce one edge.
        result = _rich_result()
        dup = _finding("filesystem + fetch", Severity.HIGH)
        result.findings.append(dup)
        data = _build_scan_data(result)
        edge_keys = [(e["source"], e["target"]) for e in data["toxic_edges"]]
        assert edge_keys.count(("filesystem", "fetch")) == 1

    def test_attack_paths_serialized(self) -> None:
        data = _build_scan_data(_rich_result())
        assert len(data["attack_paths"]) == 2
        path = data["attack_paths"][0]
        for key in ("id", "severity", "title", "description", "hops"):
            assert key in path

    def test_hitting_set_correct(self) -> None:
        data = _build_scan_data(_rich_result())
        assert data["hitting_set"] == ["fetch"]

    def test_paths_broken_by_correct(self) -> None:
        data = _build_scan_data(_rich_result())
        assert "fetch" in data["paths_broken_by"]
        assert set(data["paths_broken_by"]["fetch"]) == {"PATH-001", "PATH-002"}

    def test_server_max_severity_computed(self) -> None:
        data = _build_scan_data(_rich_result())
        fetch = next(s for s in data["servers"] if s["name"] == "fetch")
        # fetch is the sink for both TOXIC-001 (HIGH) and TOXIC-003 (CRITICAL)
        assert fetch["max_severity"] == "CRITICAL"

    def test_empty_result_produces_valid_data(self) -> None:
        data = _build_scan_data(_minimal_result())
        assert data["findings"] == []
        assert data["servers"] == []
        assert data["attack_paths"] == []
        assert data["hitting_set"] == []

    def test_self_pair_finding_not_in_toxic_edges(self) -> None:
        """Self-pair findings (no ' + ') should be excluded from toxic_edges."""
        result = _minimal_result()
        result.findings = [_finding("everything", Severity.HIGH)]
        data = _build_scan_data(result)
        assert data["toxic_edges"] == []

    def test_non_toxic_findings_excluded_from_toxic_edges(self) -> None:
        result = _minimal_result()
        result.findings = [
            _finding("filesystem", Severity.MEDIUM, analyzer="poisoning")
        ]
        data = _build_scan_data(result)
        assert data["toxic_edges"] == []

    def test_summary_structure(self) -> None:
        data = _build_scan_data(_rich_result())
        s = data["summary"]
        for key in (
            "total_findings",
            "critical",
            "high",
            "medium",
            "low",
            "info",
            "server_count",
            "path_count",
        ):
            assert key in s, f"Missing summary key {key!r}"
        assert s["server_count"] == 3
        assert s["path_count"] == 2
        assert s["total_findings"] == 3

    def test_version_field_present(self) -> None:
        data = _build_scan_data(_rich_result())
        assert "version" in data
        assert isinstance(data["version"], str)
        assert data["version"]  # non-empty


# ── generate_html ─────────────────────────────────────────────────────────────


class TestGenerateHtml:
    @pytest.fixture()
    def html(self, pro_enabled: None) -> str:
        return generate_html(_rich_result())  # type: ignore[return-value]

    def test_returns_string(self, html: str) -> None:
        assert isinstance(html, str)
        assert len(html) > 10_000  # substantive output

    def test_is_valid_html_structure(self, html: str) -> None:
        assert "<!DOCTYPE html>" in html
        assert "<html" in html
        assert "</html>" in html
        assert "<head>" in html
        assert "<body" in html  # may have class/data-theme attributes

    def test_scan_data_embedded(self, html: str) -> None:
        assert "const SCAN_DATA =" in html

    def test_embedded_scan_data_is_valid_json(self, html: str) -> None:
        match = re.search(
            r"const SCAN_DATA = (.+?);</script>",
            html,
            re.DOTALL,
        )
        assert match is not None, "SCAN_DATA not found in HTML"
        payload = match.group(1)
        data = json.loads(payload)
        assert isinstance(data, dict)

    def test_all_required_keys_in_embedded_json(self, html: str) -> None:
        match = re.search(r"const SCAN_DATA = (.+?);</script>", html, re.DOTALL)
        data = json.loads(match.group(1))  # type: ignore[union-attr]
        required = {
            "version",
            "timestamp",
            "clients_scanned",
            "servers_found",
            "finding_counts",
            "findings",
            "servers",
            "toxic_edges",
            "attack_paths",
            "hitting_set",
            "paths_broken_by",
            "summary",
        }
        assert required <= set(data.keys())

    def test_d3_is_embedded(self, html: str) -> None:
        # D3 v7 exposes a global `d3` object and uses these identifiers.
        assert "forceSimulation" in html
        assert "forceManyBody" in html

    def test_no_external_script_tags(self, html: str) -> None:
        # Must be fully self-contained — no src= on <script> tags.
        external = re.findall(r"<script[^>]+src\s*=", html, re.IGNORECASE)
        assert external == [], f"Found external script tags: {external}"

    def test_no_external_link_tags(self, html: str) -> None:
        stylesheet_links = re.findall(
            r'<link[^>]+rel\s*=\s*["\']stylesheet["\']', html, re.IGNORECASE
        )
        assert stylesheet_links == [], f"Found external stylesheets: {stylesheet_links}"

    def test_server_names_present_in_html(self, html: str) -> None:
        for name in ("filesystem", "fetch", "vault"):
            assert name in html

    def test_attack_path_ids_present(self, html: str) -> None:
        assert "PATH-001" in html
        assert "PATH-002" in html

    def test_hitting_set_server_present(self, html: str) -> None:
        assert "fetch" in html

    def test_severity_colors_embedded_in_css(self, html: str) -> None:
        # Check that the new severity palette is defined in the CSS/JS.
        assert "#ff3b4f" in html  # CRITICAL
        assert "#ff8c2e" in html  # HIGH
        assert "#ffcc30" in html  # MEDIUM

    def test_font_import_present(self, html: str) -> None:
        # Google Fonts import should be embedded as @import inside <style>.
        assert "DM Sans" in html
        assert "JetBrains Mono" in html
        assert "fonts.googleapis.com" in html
        # Must NOT be a <link> tag
        link_tags = re.findall(r"<link[^>]+fonts\.googleapis\.com", html, re.IGNORECASE)
        assert link_tags == [], "Font should use @import, not <link>"

    def test_new_css_classes_present(self, html: str) -> None:
        for cls in (
            ".path-card",
            ".sev-badge",
            ".hs-panel",
            ".findings-table",
            ".filter-btn",
            ".top-bar",
            ".graph-panel",
            ".sidebar",
        ):
            assert cls in html, f"Expected CSS class {cls!r} not found in HTML"

    def test_summary_in_embedded_json(self, html: str) -> None:
        match = re.search(r"const SCAN_DATA = (.+?);</script>", html, re.DOTALL)
        data = json.loads(match.group(1))  # type: ignore[union-attr]
        s = data["summary"]
        assert "total_findings" in s
        assert "server_count" in s
        assert "path_count" in s

    def test_toxic_edges_in_embedded_json(self, html: str) -> None:
        match = re.search(r"const SCAN_DATA = (.+?);</script>", html, re.DOTALL)
        data = json.loads(match.group(1))  # type: ignore[union-attr]
        assert "toxic_edges" in data
        assert "toxic_pairs" not in data  # old name must be gone

    def test_server_id_and_hitting_set_in_embedded_json(self, html: str) -> None:
        match = re.search(r"const SCAN_DATA = (.+?);</script>", html, re.DOTALL)
        data = json.loads(match.group(1))  # type: ignore[union-attr]
        for s in data["servers"]:
            assert "id" in s
            assert "in_hitting_set" in s

    def test_minimal_result_generates_html(self, pro_enabled: None) -> None:
        html = generate_html(_minimal_result())
        assert "const SCAN_DATA =" in html
        match = re.search(r"const SCAN_DATA = (.+?);</script>", html, re.DOTALL)
        data = json.loads(match.group(1))  # type: ignore[union-attr]
        assert data["findings"] == []

    def test_theme_css_blocks_present(self, html: str) -> None:
        # Both theme blocks must be defined so the toggle works in either state.
        assert '[data-theme="dark"]' in html
        assert '[data-theme="light"]' in html

    def test_dark_theme_palette_values(self, html: str) -> None:
        # Key dark-mode CSS custom properties.
        assert "--bg-deep:#0c0c1a" in html
        assert "--accent:#00ccff" in html
        assert "--hit:#d946ef" in html

    def test_light_theme_palette_values(self, html: str) -> None:
        # Key light-mode CSS custom properties.
        assert "--bg-deep:#f0f1f5" in html
        assert "--bg-panel:#ffffff" in html
        assert "--accent:#0088cc" in html
        assert "--hit:#a855f7" in html

    def test_theme_toggle_button_present(self, html: str) -> None:
        assert 'class="theme-toggle"' in html
        assert "toggleTheme()" in html

    def test_body_has_dash_class_and_default_dark_theme(self, html: str) -> None:
        assert 'class="dash"' in html
        assert 'data-theme="dark"' in html

    def test_no_root_css_block(self, html: str) -> None:
        # :root must not be used for theme vars; all must be in [data-theme] blocks.
        assert ":root{" not in html


# ── Empty-state handling ──────────────────────────────────────────────────────


class TestEmptyStates:
    """Verify the JS template contains all empty-state handling code.

    Since empty-state logic executes in the browser (not Python), we verify
    that the literal message strings and JS guard expressions are present in
    the generated HTML source.  The fixtures below use ``_minimal_result()``
    (zero servers, zero findings) and a no-paths variant.
    """

    @pytest.fixture()
    def minimal_html(self, pro_enabled: None) -> str:
        return generate_html(_minimal_result())  # type: ignore[return-value]

    def test_no_servers_message_present(self, minimal_html: str) -> None:
        assert "No MCP servers detected." in minimal_html

    def test_no_servers_discover_hint_present(self, minimal_html: str) -> None:
        assert "mcp-audit discover" in minimal_html

    def test_no_findings_message_present(self, minimal_html: str) -> None:
        assert "No security issues found" in minimal_html

    def test_no_attack_paths_message_present(self, minimal_html: str) -> None:
        assert "No exploitable attack paths detected." in minimal_html

    def test_hs_panel_hidden_when_no_paths(self, minimal_html: str) -> None:
        # JS must set display:none on the hs-panel element when attack_paths is empty.
        assert "hs-panel" in minimal_html
        assert "display" in minimal_html and "'none'" in minimal_html

    def test_no_servers_fixes_agent_at_centre(self, minimal_html: str) -> None:
        # The JS guard that pins the agent node when there are no servers.
        assert "nodes[0].fx = W/2" in minimal_html
        assert "nodes[0].fy = H/2" in minimal_html

    def test_adaptive_charge_for_small_graphs(self, minimal_html: str) -> None:
        assert "isSmall" in minimal_html
        assert "-150" in minimal_html  # weaker charge for small graphs

    def test_no_servers_scan_data_is_valid(self, minimal_html: str) -> None:
        match = re.search(r"const SCAN_DATA = (.+?);</script>", minimal_html, re.DOTALL)
        data = json.loads(match.group(1))  # type: ignore[union-attr]
        assert data["servers"] == []
        assert data["findings"] == []
        assert data["attack_paths"] == []
        assert data["summary"]["server_count"] == 0
        assert data["summary"]["total_findings"] == 0

    def test_servers_no_findings_state(self) -> None:
        """Servers present but zero findings — summary should reflect that."""
        result = _minimal_result()
        result.servers = [
            _server("filesystem"),
            _server("fetch", args=["-y", "@modelcontextprotocol/server-fetch"]),
        ]
        result.servers_found = 2
        data = _build_scan_data(result)
        assert data["summary"]["server_count"] == 2
        assert data["summary"]["total_findings"] == 0
        assert data["findings"] == []
        assert data["toxic_edges"] == []

    def test_servers_no_attack_paths_state(self) -> None:
        """Servers + non-toxic findings — no attack paths, no hitting set."""
        result = _minimal_result()
        result.servers = [_server("filesystem")]
        result.servers_found = 1
        result.findings = [
            _finding("filesystem", Severity.MEDIUM, "poisoning", "POISON-001")
        ]
        data = _build_scan_data(result)
        assert data["attack_paths"] == []
        assert data["hitting_set"] == []
        assert data["summary"]["path_count"] == 0
        assert data["summary"]["total_findings"] == 1


# ── Dashboard CLI command ─────────────────────────────────────────────────────


class TestDashboardCommand:
    """Tests for the `mcp-audit dashboard` CLI command.

    The HTTP server and browser open are mocked so tests finish immediately.
    """

    @pytest.fixture(autouse=True)
    def _pro(self, pro_enabled: None) -> None:
        """Ensure the Pro gate is open for all dashboard CLI tests."""

    def _invoke_dashboard(
        self,
        result: ScanResult | None = None,
        extra_args: list[str] | None = None,
    ) -> object:
        """Invoke `mcp-audit dashboard` with mocked scan and server.

        ``http.server`` and ``tempfile`` are imported *inside* the dashboard
        command, so they must be patched at the stdlib module level, not the
        cli module level.
        """
        runner = CliRunner()
        mock_result = result or _rich_result()

        with (
            patch("mcp_audit.cli.run_scan", return_value=mock_result),
            patch("mcp_audit.output.dashboard._load_d3", return_value="/* d3 */"),
            patch("http.server.HTTPServer") as mock_srv_cls,
            patch("threading.Timer"),
        ):
            srv_instance = MagicMock()
            srv_instance.serve_forever.side_effect = KeyboardInterrupt
            mock_srv_cls.return_value = srv_instance

            args = ["dashboard", "--no-open"] + (extra_args or [])
            r = runner.invoke(app, args)
            return r, mock_srv_cls

    def test_command_exits_cleanly_on_keyboard_interrupt(self) -> None:
        result, _ = self._invoke_dashboard()
        assert result.exit_code == 0  # type: ignore[union-attr]

    def test_command_calls_run_scan(self) -> None:
        with (
            patch("mcp_audit.cli.run_scan", return_value=_rich_result()) as mock_scan,
            patch("mcp_audit.output.dashboard._load_d3", return_value="/* d3 */"),
            patch("http.server.HTTPServer") as mock_srv_cls,
            patch("threading.Timer"),
        ):
            srv = MagicMock()
            srv.serve_forever.side_effect = KeyboardInterrupt
            mock_srv_cls.return_value = srv
            runner = CliRunner()
            runner.invoke(app, ["dashboard", "--no-open"])
        mock_scan.assert_called_once()

    def test_command_output_contains_url(self) -> None:
        result, _ = self._invoke_dashboard()
        assert "localhost:8088" in result.output  # type: ignore[union-attr]

    def test_dashboard_serves_from_memory_no_disk_write(self) -> None:
        """Dashboard HTML is served from memory; no temp file is written to disk."""
        with (
            patch("mcp_audit.cli.run_scan", return_value=_rich_result()),
            patch("mcp_audit.output.dashboard._load_d3", return_value="/* d3 */"),
            patch("http.server.HTTPServer") as mock_srv_cls,
            patch("threading.Timer"),
            patch("tempfile.NamedTemporaryFile") as mock_ntf,
        ):
            srv = MagicMock()
            srv.serve_forever.side_effect = KeyboardInterrupt
            mock_srv_cls.return_value = srv
            runner = CliRunner()
            runner.invoke(app, ["dashboard", "--no-open"])

        # No world-readable temp file should be written.
        mock_ntf.assert_not_called()

    def test_port_flag_passed_to_server(self) -> None:
        with (
            patch("mcp_audit.cli.run_scan", return_value=_rich_result()),
            patch("mcp_audit.output.dashboard._load_d3", return_value="/* d3 */"),
            patch("http.server.HTTPServer") as mock_srv_cls,
            patch("threading.Timer"),
        ):
            srv = MagicMock()
            srv.serve_forever.side_effect = KeyboardInterrupt
            mock_srv_cls.return_value = srv
            runner = CliRunner()
            runner.invoke(app, ["dashboard", "--no-open", "--port", "9999"])

        call_args = mock_srv_cls.call_args
        assert call_args[0][0] == ("127.0.0.1", 9999)

    def test_dashboard_exits_early_without_license(self) -> None:
        """Dashboard must exit before run_scan when the Pro license is absent."""
        with (
            patch("mcp_audit.cli.is_pro_feature_available", return_value=False),
            patch("mcp_audit.cli.run_scan") as mock_scan,
        ):
            r = CliRunner().invoke(app, ["dashboard", "--no-open"])

        mock_scan.assert_not_called()
        assert r.exit_code == 0
        assert "Pro" in r.output or "pro" in r.output.lower()
