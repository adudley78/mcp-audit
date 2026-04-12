"""Tests for MCP client discovery."""

from __future__ import annotations

import json
from unittest.mock import patch

from mcp_audit.discovery import (
    ClientSpec,
    _get_client_specs,
    discover_configs,
)


def _client_names() -> list[str]:
    return [spec.name for spec in _get_client_specs()]


class TestClientSpecs:
    def test_includes_all_known_clients(self):
        names = _client_names()
        for expected in [
            "claude-desktop",
            "cursor",
            "vscode",
            "windsurf",
            "claude-code",
            "copilot-cli",
            "augment",
        ]:
            assert expected in names, f"Missing client spec: {expected}"

    def test_copilot_cli_spec(self):
        spec = next(s for s in _get_client_specs() if s.name == "copilot-cli")
        assert spec.root_key == "mcpServers"
        assert any(
            str(p).endswith(".copilot/mcp-config.json") for p in spec.config_paths
        )

    def test_augment_spec(self):
        spec = next(s for s in _get_client_specs() if s.name == "augment")
        assert spec.root_key == "mcpServers"
        assert any(
            str(p).endswith(".augment/settings.json") for p in spec.config_paths
        )


class TestDiscoverConfigs:
    def test_discovers_copilot_cli_config(self, tmp_path):
        config_file = tmp_path / "mcp-config.json"
        payload = {"mcpServers": {"my-tool": {"command": "node", "args": ["tool.js"]}}}
        config_file.write_text(json.dumps(payload))

        spec = ClientSpec(
            name="copilot-cli",
            root_key="mcpServers",
            config_paths=[config_file],
        )

        with patch("mcp_audit.discovery._get_client_specs", return_value=[spec]):
            results = discover_configs()

        assert len(results) == 1
        assert results[0].client_name == "copilot-cli"
        assert results[0].root_key == "mcpServers"
        assert results[0].path == config_file

    def test_discovers_augment_config(self, tmp_path):
        # Augment settings.json may contain non-MCP keys alongside mcpServers
        config_file = tmp_path / "settings.json"
        config_file.write_text(
            json.dumps({
                "theme": "dark",
                "telemetry": False,
                "mcpServers": {
                    "aug-tool": {"command": "python", "args": ["-m", "aug_tool"]},
                },
            })
        )

        spec = ClientSpec(
            name="augment",
            root_key="mcpServers",
            config_paths=[config_file],
        )

        with patch("mcp_audit.discovery._get_client_specs", return_value=[spec]):
            results = discover_configs()

        assert len(results) == 1
        assert results[0].client_name == "augment"
        assert results[0].root_key == "mcpServers"

    def test_skips_missing_config_files(self, tmp_path):
        spec = ClientSpec(
            name="copilot-cli",
            root_key="mcpServers",
            config_paths=[tmp_path / "nonexistent" / "mcp-config.json"],
        )

        with patch("mcp_audit.discovery._get_client_specs", return_value=[spec]):
            results = discover_configs()

        assert results == []
