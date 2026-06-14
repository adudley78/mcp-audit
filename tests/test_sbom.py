"""Tests for cli/sbom.py — the ``mcp-audit sbom`` command.

Covers:
- Default cyclonedx output to stdout with mocked discovery/parsing
- --output-file writes to disk, creates parent directories
- Path not found → exit 2 with clean message
- No servers found (no configs) → exit 0 with message
- No servers found (config exists but empty) → exit 0
- CycloneDxFormatter raises ImportError → exit 2 with clean message
- --format terminal renders Rich tree
- Unknown --format → exit 2
- --offline flag suppresses network dep resolution
- parse_config ValueError handled gracefully (warning printed, scan continues)
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from mcp_audit.cli import app
from mcp_audit.discovery import DiscoveredConfig
from mcp_audit.models import ServerConfig, TransportType
from mcp_audit.vulnerability.models import Ecosystem, ResolvedPackage

runner = CliRunner()

# ── Fixtures ──────────────────────────────────────────────────────────────────


def _server(name: str = "filesystem", client: str = "claude-desktop") -> ServerConfig:
    return ServerConfig(
        name=name,
        client=client,
        command="npx",
        args=["-y", "@modelcontextprotocol/server-filesystem"],
        env={},
        config_path=Path("/fake/mcp.json"),
        transport=TransportType.STDIO,
        raw={},
    )


def _discovered_config(path: Path) -> DiscoveredConfig:
    return DiscoveredConfig(
        client_name="claude-desktop",
        root_key="mcpServers",
        path=path,
        raw={},
    )


def _fake_cyclonedx_output(servers: list[ServerConfig]) -> str:
    """Return a minimal CycloneDX-shaped JSON string for mock use."""
    return json.dumps(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": "urn:uuid:test",
            "components": [{"type": "application", "name": s.name} for s in servers],
            "vulnerabilities": [],
        }
    )


# ── Tests ──────────────────────────────────────────────────────────────────────


class TestSbomCommand:
    def test_cyclonedx_output_to_stdout(self, tmp_path: Path) -> None:
        """Default invocation prints CycloneDX JSON to stdout."""
        cfg_path = tmp_path / "mcp.json"
        # Create the file so the path-validation check passes
        cfg_path.write_text('{"mcpServers":{}}', encoding="utf-8")
        servers = [_server("alpha"), _server("beta")]

        with (
            patch(
                "mcp_audit.cli.sbom.discover_configs",
                return_value=[_discovered_config(cfg_path)],
            ),
            patch(
                "mcp_audit.cli.sbom.parse_config",
                return_value=servers,
            ),
            patch(
                "mcp_audit.cli.sbom.fetch_transitive_deps",
                return_value=[
                    ResolvedPackage(
                        ecosystem=Ecosystem.NPM,
                        name="@modelcontextprotocol/server-filesystem",
                        version="1.0.0",
                        direct=True,
                        source_server="alpha",
                    )
                ],
            ),
            patch(
                "mcp_audit.output.cyclonedx.CycloneDxFormatter.format",
                return_value=_fake_cyclonedx_output(servers),
            ),
        ):
            result = runner.invoke(app, ["sbom", str(cfg_path)])

        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["bomFormat"] == "CycloneDX"
        names = {c["name"] for c in data["components"]}
        assert "alpha" in names
        assert "beta" in names

    def test_output_file_written_with_parent_dirs(self, tmp_path: Path) -> None:
        """--output writes to file and creates parent dirs automatically."""
        cfg_path = tmp_path / "mcp.json"
        cfg_path.write_text('{"mcpServers":{}}', encoding="utf-8")
        out_file = tmp_path / "sboms" / "deep" / "output.json"
        servers = [_server("fs")]
        cdx_content = _fake_cyclonedx_output(servers)

        with (
            patch(
                "mcp_audit.cli.sbom.discover_configs",
                return_value=[_discovered_config(cfg_path)],
            ),
            patch(
                "mcp_audit.cli.sbom.parse_config",
                return_value=servers,
            ),
            patch("mcp_audit.cli.sbom.fetch_transitive_deps", return_value=[]),
            patch(
                "mcp_audit.output.cyclonedx.CycloneDxFormatter.format",
                return_value=cdx_content,
            ),
        ):
            result = runner.invoke(
                app, ["sbom", str(cfg_path), "--output", str(out_file)]
            )

        assert result.exit_code == 0
        assert out_file.exists()
        assert out_file.read_text(encoding="utf-8") == cdx_content

    def test_nonexistent_path_exits_2(self, tmp_path: Path) -> None:
        """A path argument that does not exist produces exit code 2."""
        missing = tmp_path / "does_not_exist.json"
        result = runner.invoke(app, ["sbom", str(missing)])
        assert result.exit_code == 2
        assert "not found" in result.output.lower() or "error" in result.output.lower()

    def test_no_config_files_found_exits_0(self, tmp_path: Path) -> None:
        """No MCP config files discovered → exit 0 with message."""
        with patch("mcp_audit.cli.sbom.discover_configs", return_value=[]):
            result = runner.invoke(app, ["sbom", str(tmp_path)])
        assert result.exit_code == 0
        assert "no mcp config" in result.output.lower()

    def test_config_found_but_no_servers_exits_0(self, tmp_path: Path) -> None:
        """Config file found but it contains no servers → exit 0."""
        cfg_path = tmp_path / "mcp.json"
        cfg_path.write_text('{"mcpServers":{}}', encoding="utf-8")

        with (
            patch(
                "mcp_audit.cli.sbom.discover_configs",
                return_value=[_discovered_config(cfg_path)],
            ),
            patch("mcp_audit.cli.sbom.parse_config", return_value=[]),
        ):
            result = runner.invoke(app, ["sbom", str(cfg_path)])

        assert result.exit_code == 0
        assert "no servers" in result.output.lower() or "0" in result.output

    def test_cyclonedx_import_error_exits_2(self, tmp_path: Path) -> None:
        """When cyclonedx-python-lib is missing, exit 2 with a clean message."""
        cfg_path = tmp_path / "mcp.json"
        cfg_path.write_text('{"mcpServers":{}}', encoding="utf-8")
        servers = [_server()]

        with (
            patch(
                "mcp_audit.cli.sbom.discover_configs",
                return_value=[_discovered_config(cfg_path)],
            ),
            patch("mcp_audit.cli.sbom.parse_config", return_value=servers),
            patch("mcp_audit.cli.sbom.fetch_transitive_deps", return_value=[]),
            patch(
                "mcp_audit.output.cyclonedx.CycloneDxFormatter.format",
                side_effect=ImportError("cyclonedx not installed"),
            ),
        ):
            result = runner.invoke(app, ["sbom", str(cfg_path)])

        assert result.exit_code == 2
        assert "error" in result.output.lower()

    def test_terminal_format_renders_tree(self, tmp_path: Path) -> None:
        """--format terminal renders a Rich dependency tree."""
        cfg_path = tmp_path / "mcp.json"
        cfg_path.write_text('{"mcpServers":{}}', encoding="utf-8")
        servers = [_server("fs")]

        with (
            patch(
                "mcp_audit.cli.sbom.discover_configs",
                return_value=[_discovered_config(cfg_path)],
            ),
            patch("mcp_audit.cli.sbom.parse_config", return_value=servers),
            patch(
                "mcp_audit.cli.sbom.fetch_transitive_deps",
                return_value=[
                    ResolvedPackage(
                        ecosystem=Ecosystem.NPM,
                        name="@modelcontextprotocol/server-filesystem",
                        version="1.0.0",
                        direct=True,
                        source_server="fs",
                    ),
                    ResolvedPackage(
                        ecosystem=Ecosystem.NPM,
                        name="lodash",
                        version="4.17.21",
                        direct=False,
                        source_server="fs",
                    ),
                ],
            ),
        ):
            result = runner.invoke(
                app,
                ["sbom", str(cfg_path), "--format", "terminal"],
            )

        assert result.exit_code == 0
        assert "mcp" in result.output.lower() or "filesystem" in result.output.lower()

    def test_unknown_format_exits_2(self, tmp_path: Path) -> None:
        """An unsupported --format value exits with code 2."""
        cfg_path = tmp_path / "mcp.json"
        cfg_path.write_text('{"mcpServers":{}}', encoding="utf-8")
        servers = [_server()]

        with (
            patch(
                "mcp_audit.cli.sbom.discover_configs",
                return_value=[_discovered_config(cfg_path)],
            ),
            patch("mcp_audit.cli.sbom.parse_config", return_value=servers),
            patch("mcp_audit.cli.sbom.fetch_transitive_deps", return_value=[]),
        ):
            result = runner.invoke(
                app,
                ["sbom", str(cfg_path), "--format", "xml"],
            )

        assert result.exit_code == 2
        assert "unknown format" in result.output.lower()

    def test_offline_skips_transitive_deps(self, tmp_path: Path) -> None:
        """--offline mode uses registry-only data, not fetch_transitive_deps."""
        cfg_path = tmp_path / "mcp.json"
        cfg_path.write_text('{"mcpServers":{}}', encoding="utf-8")
        servers = [_server("fs")]

        with (
            patch(
                "mcp_audit.cli.sbom.discover_configs",
                return_value=[_discovered_config(cfg_path)],
            ),
            patch("mcp_audit.cli.sbom.parse_config", return_value=servers),
            patch("mcp_audit.cli.sbom.fetch_transitive_deps") as mock_fetch,
            patch(
                "mcp_audit.output.cyclonedx.CycloneDxFormatter.format",
                return_value=_fake_cyclonedx_output(servers),
            ),
            patch(
                "mcp_audit.cli.sbom.extract_ecosystem_and_version",
                return_value=None,
            ),
        ):
            result = runner.invoke(app, ["sbom", str(cfg_path), "--offline"])

        assert result.exit_code == 0
        # fetch_transitive_deps should NOT have been called in offline mode
        mock_fetch.assert_not_called()

    def test_offline_warning_message_shown(self, tmp_path: Path) -> None:
        """--offline prints a warning about limited SBOM scope."""
        cfg_path = tmp_path / "mcp.json"
        cfg_path.write_text('{"mcpServers":{}}', encoding="utf-8")
        servers = [_server()]

        with (
            patch(
                "mcp_audit.cli.sbom.discover_configs",
                return_value=[_discovered_config(cfg_path)],
            ),
            patch("mcp_audit.cli.sbom.parse_config", return_value=servers),
            patch("mcp_audit.cli.sbom.fetch_transitive_deps", return_value=[]),
            patch(
                "mcp_audit.output.cyclonedx.CycloneDxFormatter.format",
                return_value=_fake_cyclonedx_output(servers),
            ),
            patch(
                "mcp_audit.cli.sbom.extract_ecosystem_and_version",
                return_value=None,
            ),
        ):
            result = runner.invoke(app, ["sbom", str(cfg_path), "--offline"])

        assert "offline" in result.output.lower()

    def test_parse_config_value_error_prints_warning_and_continues(
        self, tmp_path: Path
    ) -> None:
        """parse_config raising ValueError emits a warning but does not abort."""
        cfg_path = tmp_path / "mcp.json"
        cfg_path.write_text('{"mcpServers":{}}', encoding="utf-8")
        good_server = _server("good")

        parse_calls = [ValueError("bad config"), [good_server]]

        def fake_parse(_dc):
            result = parse_calls.pop(0)
            if isinstance(result, Exception):
                raise result
            return result

        with (
            patch(
                "mcp_audit.cli.sbom.discover_configs",
                return_value=[
                    _discovered_config(tmp_path / "bad.json"),
                    _discovered_config(cfg_path),
                ],
            ),
            patch("mcp_audit.cli.sbom.parse_config", side_effect=fake_parse),
            patch("mcp_audit.cli.sbom.fetch_transitive_deps", return_value=[]),
            patch(
                "mcp_audit.output.cyclonedx.CycloneDxFormatter.format",
                return_value=_fake_cyclonedx_output([good_server]),
            ),
        ):
            result = runner.invoke(app, ["sbom", str(cfg_path)])

        # Command should still succeed
        assert result.exit_code == 0
        assert "warning" in result.output.lower()
