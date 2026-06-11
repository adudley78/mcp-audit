"""Tests for project-level MCP config discovery and scan --project flag.

Covers:
- discover_project_configs(): each supported client file pattern, nested depth,
  node_modules / .git skip, symlink loop guard, empty directory, depth cap.
- _apply_project_scan(): TRUST-001 emission, full pipeline integration.
- CLI CliRunner: exit codes 0 (no configs), 1 (findings), 2 (bad --project path).
- Regression: default scan and discover_configs() are unaffected.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from mcp_audit.cli import app
from mcp_audit.cli.scan import _apply_project_scan
from mcp_audit.config_parser import parse_config
from mcp_audit.discovery import (
    _PROJECT_CONFIG_SPECS,
    _WALK_MAX_DEPTH,
    _WALK_SKIP_DIRS,
    DiscoveredConfig,
    discover_configs,
    discover_project_configs,
)
from mcp_audit.models import ScanResult, Severity

runner = CliRunner()

# ── Fixture helpers ────────────────────────────────────────────────────────────

_STDIO_SERVER = {"command": "node", "args": ["server.js"]}
_HTTP_SERVER = {"url": "https://api.example.com/mcp"}


def _write_mcp_config(
    path: Path, servers: dict | None = None, root_key: str = "mcpServers"
) -> None:
    """Write a minimal MCP config JSON file."""
    payload: dict = {root_key: servers or {"demo-server": _STDIO_SERVER}}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def _empty_result() -> ScanResult:
    return ScanResult(clients_scanned=0, servers_found=0)


# ── discover_project_configs() unit tests ─────────────────────────────────────


class TestDiscoverProjectConfigsPatterns:
    """Verify each known project-file spec is discovered at the repo root."""

    def _test_pattern(self, tmp_path: Path, rel_path: str, root_key: str) -> None:
        target = tmp_path / rel_path
        _write_mcp_config(target, root_key=root_key)
        found = discover_project_configs(tmp_path)
        paths = [c.path for c in found]
        assert target in paths, f"Expected {rel_path} to be discovered"
        cfg = next(c for c in found if c.path == target)
        assert cfg.is_project_scoped is True
        assert cfg.root_key == root_key

    def test_mcp_json_root(self, tmp_path: Path) -> None:
        self._test_pattern(tmp_path, ".mcp.json", "mcpServers")

    def test_claude_settings_json(self, tmp_path: Path) -> None:
        self._test_pattern(tmp_path, ".claude/settings.json", "mcpServers")

    def test_claude_settings_local_json(self, tmp_path: Path) -> None:
        self._test_pattern(tmp_path, ".claude/settings.local.json", "mcpServers")

    def test_cursor_mcp_json(self, tmp_path: Path) -> None:
        self._test_pattern(tmp_path, ".cursor/mcp.json", "mcpServers")

    def test_cursor_settings_json(self, tmp_path: Path) -> None:
        self._test_pattern(tmp_path, ".cursor/settings.json", "mcpServers")

    def test_vscode_mcp_json(self, tmp_path: Path) -> None:
        self._test_pattern(tmp_path, ".vscode/mcp.json", "servers")

    def test_all_specs_covered(self) -> None:
        """Ensure _PROJECT_CONFIG_SPECS covers at least 6 entries."""
        assert len(_PROJECT_CONFIG_SPECS) >= 6


class TestDiscoverProjectConfigsDepth:
    """Depth-capping and nested discovery."""

    def test_finds_config_at_depth_1(self, tmp_path: Path) -> None:
        sub = tmp_path / "packages" / "frontend"
        _write_mcp_config(sub / ".mcp.json")
        found = discover_project_configs(tmp_path)
        assert any(c.path == sub / ".mcp.json" for c in found)

    def test_does_not_exceed_max_depth(self, tmp_path: Path) -> None:
        # Build a deeply nested dir: depth = _WALK_MAX_DEPTH + 1 levels below root
        deep = tmp_path
        for i in range(_WALK_MAX_DEPTH + 1):
            deep = deep / f"level_{i}"
        _write_mcp_config(deep / ".mcp.json")
        found = discover_project_configs(tmp_path)
        # The config is deeper than the cap — must NOT be found.
        assert not any(c.path == deep / ".mcp.json" for c in found)

    def test_finds_config_at_exactly_max_depth(self, tmp_path: Path) -> None:
        deep = tmp_path
        for i in range(_WALK_MAX_DEPTH):
            deep = deep / f"level_{i}"
        target = deep / ".mcp.json"
        _write_mcp_config(target)
        found = discover_project_configs(tmp_path)
        assert any(c.path == target for c in found)

    def test_monorepo_finds_multiple_configs(self, tmp_path: Path) -> None:
        _write_mcp_config(tmp_path / ".mcp.json")
        _write_mcp_config(tmp_path / "backend" / ".cursor" / "mcp.json")
        found = discover_project_configs(tmp_path)
        assert len(found) >= 2


class TestDiscoverProjectConfigsSkipDirs:
    """node_modules, .git, and other skip-dirs must be excluded."""

    def test_skips_node_modules(self, tmp_path: Path) -> None:
        nm = tmp_path / "node_modules" / "evil-pkg"
        _write_mcp_config(nm / ".mcp.json")
        found = discover_project_configs(tmp_path)
        assert not any("node_modules" in str(c.path) for c in found)

    def test_skips_git(self, tmp_path: Path) -> None:
        git = tmp_path / ".git" / "hooks"
        _write_mcp_config(git / ".mcp.json")
        found = discover_project_configs(tmp_path)
        assert not any(".git" in str(c.path) for c in found)

    def test_skips_pycache(self, tmp_path: Path) -> None:
        pc = tmp_path / "__pycache__"
        _write_mcp_config(pc / ".mcp.json")
        found = discover_project_configs(tmp_path)
        assert not any("__pycache__" in str(c.path) for c in found)

    def test_skip_dirs_constant_contains_expected_names(self) -> None:
        for name in ("node_modules", ".git", "__pycache__"):
            assert name in _WALK_SKIP_DIRS


class TestDiscoverProjectConfigsSymlinks:
    """Symlinked directories and files must not be followed."""

    def test_does_not_follow_symlinked_dir(self, tmp_path: Path) -> None:
        real_dir = tmp_path / "real"
        real_dir.mkdir()
        _write_mcp_config(real_dir / ".mcp.json")

        link_dir = tmp_path / "link"
        try:
            link_dir.symlink_to(real_dir)
        except (OSError, NotImplementedError):
            pytest.skip("Symlinks not supported on this platform")

        found = discover_project_configs(tmp_path)
        found_paths = {c.path for c in found}

        # Real dir was discovered.
        assert real_dir / ".mcp.json" in found_paths
        # Symlinked dir path must NOT have been followed.
        assert link_dir / ".mcp.json" not in found_paths

    def test_does_not_follow_symlinked_file(self, tmp_path: Path) -> None:
        real_file = tmp_path / "actual.json"
        _write_mcp_config(real_file)
        link_file = tmp_path / ".mcp.json"
        try:
            link_file.symlink_to(real_file)
        except (OSError, NotImplementedError):
            pytest.skip("Symlinks not supported on this platform")

        found = discover_project_configs(tmp_path)
        assert not any(c.path == link_file for c in found)


class TestDiscoverProjectConfigsEdgeCases:
    """Empty directories, missing files, permission errors."""

    def test_empty_directory_returns_empty(self, tmp_path: Path) -> None:
        found = discover_project_configs(tmp_path)
        assert found == []

    def test_config_missing_mcp_key_returns_no_servers(self, tmp_path: Path) -> None:
        # File exists but has no mcpServers/servers key → parsed as 0 servers.
        target = tmp_path / ".mcp.json"
        target.write_text(json.dumps({"other": "data"}))
        found = discover_project_configs(tmp_path)
        assert any(c.path == target for c in found)
        cfg = next(c for c in found if c.path == target)
        servers = parse_config(cfg)
        assert servers == []

    def test_is_project_scoped_flag_is_true(self, tmp_path: Path) -> None:
        _write_mcp_config(tmp_path / ".mcp.json")
        found = discover_project_configs(tmp_path)
        assert all(c.is_project_scoped for c in found)

    def test_permission_error_is_skipped_gracefully(self, tmp_path: Path) -> None:
        """A directory we cannot read should not crash the walker."""
        sub = tmp_path / "locked"
        sub.mkdir()
        _write_mcp_config(sub / ".mcp.json")
        original_iterdir = Path.iterdir

        def _raise_if_locked(self: Path):
            if self == sub:
                raise PermissionError("no access")
            return original_iterdir(self)

        with patch.object(Path, "iterdir", _raise_if_locked):
            found = discover_project_configs(tmp_path)
        # Should not crash; the locked sub is simply skipped.
        assert isinstance(found, list)


# ── is_project_scoped propagated through parser ───────────────────────────────


class TestIsProjectScopedPropagation:
    def test_project_scoped_flag_on_server_config(self, tmp_path: Path) -> None:
        target = tmp_path / ".mcp.json"
        _write_mcp_config(target)
        cfg = DiscoveredConfig(
            client_name="claude-code",
            root_key="mcpServers",
            path=target,
            is_project_scoped=True,
        )
        servers = parse_config(cfg)
        assert servers
        assert all(s.is_project_scoped for s in servers)

    def test_non_project_scoped_flag_false_by_default(self, tmp_path: Path) -> None:
        target = tmp_path / "mcp.json"
        _write_mcp_config(target)
        cfg = DiscoveredConfig(
            client_name="custom",
            root_key="mcpServers",
            path=target,
            is_project_scoped=False,
        )
        servers = parse_config(cfg)
        assert servers
        assert all(not s.is_project_scoped for s in servers)


# ── _apply_project_scan() unit tests ──────────────────────────────────────────


def _patch_no_clients():
    return patch("mcp_audit.discovery._get_client_specs", return_value=[])


class TestApplyProjectScan:
    def test_trust001_emitted_for_each_server(self, tmp_path: Path) -> None:
        target = tmp_path / ".mcp.json"
        _write_mcp_config(
            target,
            servers={
                "server-a": _STDIO_SERVER,
                "server-b": _STDIO_SERVER,
            },
        )
        result = _empty_result()
        with _patch_no_clients():
            result = _apply_project_scan(result, tmp_path, None, None, _null_console())

        trust_findings = [f for f in result.findings if f.id == "TRUST-001"]
        assert len(trust_findings) == 2
        server_names = {f.server for f in trust_findings}
        assert server_names == {"server-a", "server-b"}

    def test_trust001_severity_is_high(self, tmp_path: Path) -> None:
        _write_mcp_config(tmp_path / ".mcp.json")
        result = _empty_result()
        with _patch_no_clients():
            result = _apply_project_scan(result, tmp_path, None, None, _null_console())

        trust = [f for f in result.findings if f.id == "TRUST-001"]
        assert trust
        assert all(f.severity == Severity.HIGH for f in trust)

    def test_trust001_owasp_mcp09(self, tmp_path: Path) -> None:
        _write_mcp_config(tmp_path / ".mcp.json")
        result = _empty_result()
        with _patch_no_clients():
            result = _apply_project_scan(result, tmp_path, None, None, _null_console())

        trust = [f for f in result.findings if f.id == "TRUST-001"]
        assert trust
        assert all("MCP09" in f.owasp_mcp_top_10 for f in trust)

    def test_trust001_cwe829(self, tmp_path: Path) -> None:
        _write_mcp_config(tmp_path / ".mcp.json")
        result = _empty_result()
        with _patch_no_clients():
            result = _apply_project_scan(result, tmp_path, None, None, _null_console())

        trust = [f for f in result.findings if f.id == "TRUST-001"]
        assert trust
        assert all(f.cwe == "CWE-829" for f in trust)

    def test_trust001_finding_path_set(self, tmp_path: Path) -> None:
        _write_mcp_config(tmp_path / ".mcp.json")
        result = _empty_result()
        with _patch_no_clients():
            result = _apply_project_scan(result, tmp_path, None, None, _null_console())

        trust = [f for f in result.findings if f.id == "TRUST-001"]
        assert trust
        assert all(f.finding_path is not None for f in trust)

    def test_full_pipeline_runs_on_project_servers(self, tmp_path: Path) -> None:
        """Standard analyzers also fire on project-scoped servers."""
        cred_server = {
            "url": "https://api.example.com/mcp",
            "env": {
                "OPENAI_API_KEY": "sk-abcdefghijklmnopqrstuvwxyz1234567890abcdef12"
            },
        }
        target = tmp_path / ".mcp.json"
        _write_mcp_config(target, servers={"cred-server": cred_server})
        result = _empty_result()
        with _patch_no_clients():
            result = _apply_project_scan(result, tmp_path, None, None, _null_console())

        ids = {f.id for f in result.findings}
        assert "TRUST-001" in ids
        # Credentials analyzer should also have fired.
        cred_findings = [f for f in result.findings if f.analyzer == "credentials"]
        assert cred_findings, "Expected credentials analyzer to fire on project servers"

    def test_no_configs_returns_result_unchanged(self, tmp_path: Path) -> None:
        result = _empty_result()
        result.findings.append(_make_finding("EXISTING-001"))
        with _patch_no_clients():
            returned = _apply_project_scan(
                result, tmp_path, None, None, _null_console()
            )

        assert returned is result
        ids = [f.id for f in result.findings]
        assert ids == ["EXISTING-001"]

    def test_multiple_client_files_discovered(self, tmp_path: Path) -> None:
        _write_mcp_config(tmp_path / ".mcp.json")
        _write_mcp_config(tmp_path / ".vscode" / "mcp.json", root_key="servers")
        result = _empty_result()
        with _patch_no_clients():
            result = _apply_project_scan(result, tmp_path, None, None, _null_console())

        trust = [f for f in result.findings if f.id == "TRUST-001"]
        assert len(trust) >= 2

    def test_vscode_servers_root_key_parsed(self, tmp_path: Path) -> None:
        target = tmp_path / ".vscode" / "mcp.json"
        _write_mcp_config(target, root_key="servers")
        result = _empty_result()
        with _patch_no_clients():
            result = _apply_project_scan(result, tmp_path, None, None, _null_console())

        trust = [f for f in result.findings if f.id == "TRUST-001"]
        assert trust


# ── CLI CliRunner end-to-end tests ────────────────────────────────────────────


class TestScanProjectCLI:
    def test_exit_1_when_project_findings(self, tmp_path: Path) -> None:
        _write_mcp_config(tmp_path / ".mcp.json")
        with _patch_no_clients():
            result = runner.invoke(
                app,
                ["scan", "--project", str(tmp_path), "--format", "json"],
            )
        assert result.exit_code == 1

    def test_exit_0_when_no_project_configs(self, tmp_path: Path) -> None:
        empty_dir = tmp_path / "empty_repo"
        empty_dir.mkdir()
        with _patch_no_clients():
            result = runner.invoke(
                app,
                ["scan", "--project", str(empty_dir), "--format", "json"],
            )
        assert result.exit_code == 0

    def test_exit_2_when_project_path_not_found(self, tmp_path: Path) -> None:
        nonexistent = tmp_path / "does_not_exist"
        result = runner.invoke(
            app,
            ["scan", "--project", str(nonexistent), "--format", "json"],
        )
        assert result.exit_code == 2

    def test_exit_2_when_project_is_a_file(self, tmp_path: Path) -> None:
        f = tmp_path / "somefile.json"
        f.write_text("{}")
        result = runner.invoke(
            app,
            ["scan", "--project", str(f), "--format", "json"],
        )
        assert result.exit_code == 2

    def test_trust001_present_in_json_output(self, tmp_path: Path) -> None:
        _write_mcp_config(tmp_path / ".mcp.json")
        with _patch_no_clients():
            result = runner.invoke(
                app,
                ["scan", "--project", str(tmp_path), "--format", "json"],
            )
        assert result.exit_code == 1
        # Rich console may print progress lines before the JSON block; skip them.
        data = json.loads(_extract_json(result.output))
        ids = {f["id"] for f in data["findings"]}
        assert "TRUST-001" in ids

    def test_severity_threshold_filters_trust001(self, tmp_path: Path) -> None:
        """With --severity-threshold critical, HIGH TRUST-001 should be filtered out."""
        _write_mcp_config(tmp_path / ".mcp.json")
        with _patch_no_clients():
            result = runner.invoke(
                app,
                [
                    "scan",
                    "--project",
                    str(tmp_path),
                    "--format",
                    "json",
                    "--severity-threshold",
                    "critical",
                ],
            )
        # No CRITICAL findings → exit 0 (TRUST-001 is HIGH, filtered by threshold)
        assert result.exit_code == 0
        data = json.loads(_extract_json(result.output))
        ids = {f["id"] for f in data["findings"]}
        assert "TRUST-001" not in ids

    def test_default_scan_not_affected(self, tmp_path: Path) -> None:
        """Invoking scan without --project must not discover project configs."""
        _write_mcp_config(tmp_path / ".mcp.json")
        with (
            _patch_no_clients(),
            patch("mcp_audit.discovery.Path.cwd", return_value=Path("/tmp")),  # noqa: S108
        ):
            result = runner.invoke(
                app,
                ["scan", "--path", str(tmp_path / ".mcp.json"), "--format", "json"],
            )
        data = json.loads(result.output)
        trust_ids = [f["id"] for f in data["findings"] if f["id"] == "TRUST-001"]
        msg = "TRUST-001 must not appear in a default (non-project) scan"
        assert trust_ids == [], msg


# ── Regression: existing discovery unaffected ─────────────────────────────────


class TestRegressionDefaultDiscovery:
    def test_discover_configs_unchanged(self, tmp_path: Path) -> None:
        """discover_configs() must not return is_project_scoped=True entries."""
        # Create a valid user-level config fixture
        config_file = tmp_path / "mcp.json"
        _write_mcp_config(config_file)
        from mcp_audit.discovery import ClientSpec

        spec = ClientSpec(
            name="test-client",
            root_key="mcpServers",
            config_paths=[config_file],
        )
        with patch("mcp_audit.discovery._get_client_specs", return_value=[spec]):
            configs = discover_configs()

        assert configs
        # All discovered user-level configs must have is_project_scoped=False.
        assert all(not c.is_project_scoped for c in configs)

    def test_discover_project_configs_does_not_call_get_client_specs(
        self, tmp_path: Path
    ) -> None:
        """discover_project_configs must be independent of user-level specs."""
        _write_mcp_config(tmp_path / ".mcp.json")
        with patch(
            "mcp_audit.discovery._get_client_specs",
            side_effect=AssertionError("Should not be called"),
        ):
            found = discover_project_configs(tmp_path)
        assert found  # still found the config


# ── Helpers ────────────────────────────────────────────────────────────────────


def _extract_json(output: str) -> str:
    """Extract the JSON block from CLI output that may contain Rich console lines."""
    idx = output.index("{")
    return output[idx:]


def _null_console():
    """Return a Rich Console that discards all output."""
    from rich.console import Console  # noqa: PLC0415

    return Console(quiet=True)


def _make_finding(finding_id: str):
    from mcp_audit.models import Finding  # noqa: PLC0415

    return Finding(
        id=finding_id,
        severity=Severity.INFO,
        analyzer="test",
        client="test",
        server="test-server",
        title="Test finding",
        description="Test",
        evidence="Test",
        remediation="Test",
    )
