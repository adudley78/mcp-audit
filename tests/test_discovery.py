"""Tests for MCP client discovery."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from mcp_audit.config_parser import parse_config
from mcp_audit.discovery import (
    ClientSpec,
    DiscoveredConfig,
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
        # Use POSIX path repr so the assertion is portable across OSes (Windows
        # uses backslashes in str(Path), which breaks a naive endswith check).
        assert any(
            p.as_posix().endswith(".copilot/mcp-config.json") for p in spec.config_paths
        )

    def test_augment_spec(self):
        spec = next(s for s in _get_client_specs() if s.name == "augment")
        assert spec.root_key == "mcpServers"
        assert any(
            p.as_posix().endswith(".augment/settings.json") for p in spec.config_paths
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
            json.dumps(
                {
                    "theme": "dark",
                    "telemetry": False,
                    "mcpServers": {
                        "aug-tool": {"command": "python", "args": ["-m", "aug_tool"]},
                    },
                }
            )
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


class TestSymlinkProtection:
    """V-06: symlinked config files must be skipped to prevent arbitrary file reads."""

    @staticmethod
    def _write_config(path: Path) -> None:
        path.write_text(
            json.dumps({"mcpServers": {"srv": {"command": "node", "args": ["s.js"]}}})
        )

    @staticmethod
    def _empty_specs() -> list[ClientSpec]:
        return []

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlinks only")
    def test_symlinked_known_client_config_is_skipped(self, tmp_path: Path) -> None:
        real_file = tmp_path / "real_config.json"
        self._write_config(real_file)

        symlink = tmp_path / "mcp.json"
        symlink.symlink_to(real_file)

        spec = ClientSpec(
            name="cursor",
            root_key="mcpServers",
            config_paths=[symlink],
        )

        with patch("mcp_audit.discovery._get_client_specs", return_value=[spec]):
            results = discover_configs()

        assert results == [], "Symlinked config should not be discovered"

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlinks only")
    def test_symlinked_extra_path_file_is_skipped(self, tmp_path: Path) -> None:
        real_file = tmp_path / "real.json"
        self._write_config(real_file)

        symlink = tmp_path / "link.json"
        symlink.symlink_to(real_file)

        with patch(
            "mcp_audit.discovery._get_client_specs", return_value=self._empty_specs()
        ):
            results = discover_configs(extra_paths=[symlink])

        assert results == [], "Symlinked extra_path file should not be discovered"

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlinks only")
    def test_symlinked_file_inside_extra_path_dir_is_skipped(
        self, tmp_path: Path
    ) -> None:
        scan_dir = tmp_path / "configs"
        scan_dir.mkdir()

        real_file = tmp_path / "real.json"
        self._write_config(real_file)

        symlink = scan_dir / "linked.json"
        symlink.symlink_to(real_file)

        # Also place a real file to confirm it IS discovered
        real_in_dir = scan_dir / "real_config.json"
        self._write_config(real_in_dir)

        with patch(
            "mcp_audit.discovery._get_client_specs", return_value=self._empty_specs()
        ):
            results = discover_configs(extra_paths=[scan_dir])

        paths = [r.path for r in results]
        assert real_in_dir in paths, "Real file in dir should be discovered"
        assert symlink not in paths, "Symlinked file in dir should be skipped"

    def test_real_config_file_is_still_discovered(self, tmp_path: Path) -> None:
        config_file = tmp_path / "mcp.json"
        self._write_config(config_file)

        spec = ClientSpec(
            name="test-client",
            root_key="mcpServers",
            config_paths=[config_file],
        )

        with patch("mcp_audit.discovery._get_client_specs", return_value=[spec]):
            results = discover_configs()

        assert len(results) == 1
        assert results[0].path == config_file


# ── Malformed JSON resilience tests ──────────────────────────────────────────


class TestMalformedJsonRobustness:
    """parse_config() must raise ValueError (not crash) on bad input.

    The scanner catches ValueError and logs a warning — callers must NOT crash.
    Each test exercises a different client format to ensure the common parsing
    path handles malformed input regardless of ``root_key`` or ``client_name``.
    """

    def _discovered(self, path: Path, client: str, root_key: str) -> DiscoveredConfig:
        return DiscoveredConfig(path=path, client_name=client, root_key=root_key)

    def test_discovery_malformed_json_claude(self, tmp_path: Path) -> None:
        """Malformed JSON for a claude-desktop config raises ValueError, not a crash."""
        bad = tmp_path / "claude_desktop_config.json"
        bad.write_text("{not valid json", encoding="utf-8")
        cfg = self._discovered(bad, "claude-desktop", "mcpServers")
        with pytest.raises(ValueError, match="Invalid JSON"):
            parse_config(cfg)

    def test_discovery_malformed_json_cursor(self, tmp_path: Path) -> None:
        """A JSON 'null' top-level value raises ValueError (not a crash)."""
        bad = tmp_path / "mcp.json"
        bad.write_text("null", encoding="utf-8")
        cfg = self._discovered(bad, "cursor", "mcpServers")
        # null parses to None which is not a dict — parse_config raises ValueError.
        with pytest.raises(ValueError, match="Expected JSON object"):
            parse_config(cfg)

    def test_discovery_malformed_json_vscode(self, tmp_path: Path) -> None:
        """Malformed JSON for VS Code config (uses 'servers' key) raises ValueError."""
        bad = tmp_path / "settings.json"
        bad.write_text("{{broken", encoding="utf-8")
        cfg = self._discovered(bad, "vscode", "servers")
        with pytest.raises(ValueError, match="Invalid JSON"):
            parse_config(cfg)

    def test_discovery_malformed_json_empty_file(self, tmp_path: Path) -> None:
        """An empty config file raises ValueError and does not crash the scanner."""
        bad = tmp_path / "empty.json"
        bad.write_text("", encoding="utf-8")
        cfg = self._discovered(bad, "windsurf", "mcpServers")
        with pytest.raises(ValueError):
            parse_config(cfg)

    def test_discovery_malformed_json_wrong_type(self, tmp_path: Path) -> None:
        """A JSON array at the top level raises ValueError — expected an object."""
        bad = tmp_path / "array.json"
        bad.write_text("[]", encoding="utf-8")
        cfg = self._discovered(bad, "augment", "mcpServers")
        with pytest.raises(ValueError, match="Expected JSON object"):
            parse_config(cfg)
