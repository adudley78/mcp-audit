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
    build_info_symlink_finding,
    build_project_symlink_finding,
    build_untraversed_symlink_dir_finding,
    discover_configs,
    discover_project_autoexec_files,
    discover_project_configs,
)
from mcp_audit.models import Severity


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


class TestSymlinkHandling:
    """TRUST-002/TRUST-004: symlinked config candidates are reported, not skipped.

    Superseded 2026-09-08 (STORY-0065). A symlinked candidate is no longer
    silently dropped (that was the V-06 defect this class originally
    guarded): it is included with ``is_symlink=True`` so the caller still
    parses it (coverage restored) and can emit a TRUST-002/TRUST-004
    finding. See humans/decisions/2026-09-08-trust-002-symlink-sites.md
    (marcus repo).
    """

    @staticmethod
    def _write_config(path: Path) -> None:
        path.write_text(
            json.dumps({"mcpServers": {"srv": {"command": "node", "args": ["s.js"]}}})
        )

    @staticmethod
    def _empty_specs() -> list[ClientSpec]:
        return []

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlinks only")
    def test_symlinked_known_client_config_is_included_info_shaped(
        self, tmp_path: Path
    ) -> None:
        """A known-client symlink is included with is_symlink=True, no root."""
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

        assert len(results) == 1
        assert results[0].path == symlink
        assert results[0].is_symlink is True
        assert results[0].symlink_root is None

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlinks only")
    def test_symlinked_extra_path_file_is_included_info_shaped(
        self, tmp_path: Path
    ) -> None:
        """An explicit --path symlink is included, not silently skipped (was a bug)."""
        real_file = tmp_path / "real.json"
        self._write_config(real_file)

        symlink = tmp_path / "link.json"
        symlink.symlink_to(real_file)

        with patch(
            "mcp_audit.discovery._get_client_specs", return_value=self._empty_specs()
        ):
            results = discover_configs(extra_paths=[symlink])

        assert len(results) == 1
        assert results[0].path == symlink
        assert results[0].is_symlink is True
        assert results[0].symlink_root is None

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlinks only")
    def test_symlinked_file_inside_extra_path_dir_is_included(
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

        by_path = {r.path: r for r in results}
        assert real_in_dir in by_path, "Real file in dir should be discovered"
        assert not by_path[real_in_dir].is_symlink
        assert symlink in by_path, "Symlinked file in dir should be discovered too"
        assert by_path[symlink].is_symlink is True

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlinks only")
    def test_symlinked_cwd_vscode_mcp_is_boundary_shaped(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """cwd-scoped .vscode/mcp.json symlink is boundary-shaped (symlink_root=cwd)."""
        real_file = tmp_path / "elsewhere" / "real.json"
        real_file.parent.mkdir()
        self._write_config(real_file)

        project = tmp_path / "project"
        (project / ".vscode").mkdir(parents=True)
        (project / ".vscode" / "mcp.json").symlink_to(real_file)

        monkeypatch.chdir(project)
        with patch(
            "mcp_audit.discovery._get_client_specs", return_value=self._empty_specs()
        ):
            results = discover_configs()

        vscode_results = [r for r in results if r.client_name == "vscode"]
        assert len(vscode_results) == 1
        assert vscode_results[0].is_symlink is True
        assert vscode_results[0].symlink_root == project

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


class TestHomeHelperConsistency:
    """V-16 regression: _get_client_specs() must use _home() consistently.

    Previously the Windows branch called Path.home() directly, bypassing
    the _home() indirection used everywhere else in the module. This class
    verifies that patching mcp_audit.discovery._home is sufficient to
    redirect ALL home-relative paths produced by _get_client_specs().
    """

    def test_discovery_uses_home_helper(self, tmp_path: Path, monkeypatch) -> None:
        """All paths from _get_client_specs() must be rooted under _home()."""
        monkeypatch.setattr("mcp_audit.discovery._home", lambda: tmp_path)
        specs = _get_client_specs()
        for spec in specs:
            for path in spec.config_paths:
                # Every config path must be under tmp_path, not the real home.
                assert str(path).startswith(str(tmp_path)), (
                    f"{spec.name}: {path} is not under the patched _home() "
                    f"({tmp_path}). This indicates a direct Path.home() call."
                )


# ── TRUST-002 / TRUST-004 / TRUST-005 finding builders ───────────────────────
#
# See humans/decisions/2026-09-08-trust-002-symlink-sites.md (marcus repo).
# Both directions of the standing rule are tested: a stow-style user-global
# symlink must never produce a HIGH, and a repo-scoped symlink escaping the
# root must always produce one.


class TestBuildProjectSymlinkFinding:
    """TRUST-002: severity depends on where the symlink resolves, relative to root."""

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlinks only")
    def test_target_outside_root_is_high(self, tmp_path: Path) -> None:
        root = tmp_path / "repo"
        outside = tmp_path / "outside"
        outside.mkdir()
        root.mkdir()
        target = outside / "secret.json"
        target.write_text("{}", encoding="utf-8")
        link = root / ".mcp.json"
        link.symlink_to(target)

        finding = build_project_symlink_finding(link, "claude-code", root)

        assert finding.id == "TRUST-002"
        assert finding.severity == Severity.HIGH
        assert str(target.resolve()) in finding.evidence
        assert str(link) in finding.evidence

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlinks only")
    def test_target_inside_root_is_medium(self, tmp_path: Path) -> None:
        root = tmp_path / "repo"
        root.mkdir()
        target = root / "nested" / "real.json"
        target.parent.mkdir()
        target.write_text("{}", encoding="utf-8")
        link = root / ".mcp.json"
        link.symlink_to(target)

        finding = build_project_symlink_finding(link, "claude-code", root)

        assert finding.id == "TRUST-002"
        assert finding.severity == Severity.MEDIUM

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlinks only")
    def test_broken_link_is_info_never_high(self, tmp_path: Path) -> None:
        """A dangling symlink is INFO regardless of where it would have pointed."""
        root = tmp_path / "repo"
        root.mkdir()
        link = root / ".mcp.json"
        link.symlink_to(tmp_path / "does-not-exist.json")

        finding = build_project_symlink_finding(link, "claude-code", root)

        assert finding.id == "TRUST-002"
        assert finding.severity == Severity.INFO

    def test_finding_path_redaction_anchor_is_visible_path(
        self, tmp_path: Path
    ) -> None:
        """finding_path is the visible (symlink) path, not the resolved target."""
        root = tmp_path / "repo"
        root.mkdir()
        target = root / "real.json"
        target.write_text("{}", encoding="utf-8")
        link = root / ".mcp.json"
        if sys.platform != "win32":
            link.symlink_to(target)
            finding = build_project_symlink_finding(link, "claude-code", root)
            assert finding.finding_path == str(link)


class TestBuildInfoSymlinkFinding:
    """TRUST-004: always INFO — the stow/chezmoi/yadm dotfile-manager shape."""

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlinks only")
    def test_user_global_symlink_is_always_info(self, tmp_path: Path) -> None:
        """Never HIGH, even when the target is far outside any project root."""
        dotfiles = tmp_path / "dotfiles" / "claude.json"
        dotfiles.parent.mkdir(parents=True)
        dotfiles.write_text("{}", encoding="utf-8")
        link = tmp_path / "home" / ".claude.json"
        link.parent.mkdir()
        link.symlink_to(dotfiles)

        finding = build_info_symlink_finding(link, "claude-code")

        assert finding.id == "TRUST-004"
        assert finding.severity == Severity.INFO

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlinks only")
    def test_broken_user_global_symlink_is_info(self, tmp_path: Path) -> None:
        link = tmp_path / ".claude.json"
        link.symlink_to(tmp_path / "nope.json")

        finding = build_info_symlink_finding(link, "claude-code")

        assert finding.severity == Severity.INFO
        assert "broken" in finding.description.lower()


class TestBuildUntraversedSymlinkDirFinding:
    """TRUST-005: always LOW, names the directory that was not traversed."""

    def test_is_low_and_names_directory(self, tmp_path: Path) -> None:
        directory = tmp_path / "linked_dir"
        finding = build_untraversed_symlink_dir_finding(directory, "project")

        assert finding.id == "TRUST-005"
        assert finding.severity == Severity.LOW
        assert str(directory) in finding.evidence


# ── discover_project_configs / discover_project_autoexec_files symlinks ──────


class TestDiscoverProjectConfigsSymlinkHandling:
    """Project-tree walk: symlinked candidates are TRUST-002, not silently dropped."""

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlinks only")
    def test_symlinked_config_candidate_is_included_boundary_shaped(
        self, tmp_path: Path
    ) -> None:
        real_file = tmp_path / "actual.json"
        real_file.write_text(json.dumps({"mcpServers": {"srv": {"command": "node"}}}))
        link_file = tmp_path / ".mcp.json"
        link_file.symlink_to(real_file)

        found = discover_project_configs(tmp_path)

        matches = [c for c in found if c.path == link_file]
        assert len(matches) == 1
        assert matches[0].is_symlink is True
        assert matches[0].symlink_root == tmp_path

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlinks only")
    def test_symlinked_child_directory_reports_trust_005_and_is_not_traversed(
        self, tmp_path: Path
    ) -> None:
        real_dir = tmp_path / "real_subdir"
        real_dir.mkdir()
        (real_dir / ".mcp.json").write_text(
            json.dumps({"mcpServers": {"srv": {"command": "node"}}})
        )
        link_dir = tmp_path / "linked_subdir"
        link_dir.symlink_to(real_dir, target_is_directory=True)

        skip_findings: list = []
        found = discover_project_configs(tmp_path, skip_findings=skip_findings)

        # The .mcp.json is reachable directly (real_dir is a normal child of
        # tmp_path), but the symlinked path into the same content is not
        # traversed — that's the behaviour under test.
        assert any(c.path == real_dir / ".mcp.json" for c in found)
        assert not any(c.path == link_dir / ".mcp.json" for c in found)
        # But the refusal is now audible.
        trust_005 = [f for f in skip_findings if f.id == "TRUST-005"]
        assert len(trust_005) == 1
        assert str(link_dir) in trust_005[0].evidence


class TestDiscoverProjectAutoexecFilesSymlinkHandling:
    """TRUST-003 autoexec walk: symlinked candidates are TRUST-002, not dropped."""

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX symlinks only")
    def test_symlinked_autoexec_candidate_is_included_boundary_shaped(
        self, tmp_path: Path
    ) -> None:
        real_file = tmp_path / "actual_tasks.json"
        real_file.write_text(json.dumps({"tasks": []}))
        vscode_dir = tmp_path / ".vscode"
        vscode_dir.mkdir()
        link_file = vscode_dir / "tasks.json"
        link_file.symlink_to(real_file)

        found = discover_project_autoexec_files(tmp_path)

        matches = [f for f in found if f.path == link_file]
        assert len(matches) == 1
        assert matches[0].is_symlink is True
        assert matches[0].symlink_root == tmp_path
