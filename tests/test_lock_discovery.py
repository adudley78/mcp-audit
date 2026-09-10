"""Tests for mcp_audit.lock.discovery — nearest-ancestor mcp-lock.json lookup."""

from __future__ import annotations

from pathlib import Path

from mcp_audit.lock.discovery import find_lock_for


def _git_init(root: Path) -> None:
    (root / ".git").mkdir()


class TestFindLockFor:
    def test_no_lock_anywhere_returns_none(self, tmp_path: Path) -> None:
        _git_init(tmp_path)
        config = tmp_path / "sub" / ".mcp.json"
        config.parent.mkdir(parents=True)
        assert find_lock_for(config) is None

    def test_lock_in_same_directory_as_config(self, tmp_path: Path) -> None:
        _git_init(tmp_path)
        config_dir = tmp_path / "project"
        config_dir.mkdir()
        config = config_dir / ".mcp.json"
        (config_dir / "mcp-lock.json").write_text("{}")
        found = find_lock_for(config)
        assert found == (config_dir / "mcp-lock.json").resolve()

    def test_lock_at_git_root_found_from_nested_config(self, tmp_path: Path) -> None:
        _git_init(tmp_path)
        (tmp_path / "mcp-lock.json").write_text("{}")
        nested = tmp_path / "a" / "b" / "c" / ".mcp.json"
        nested.parent.mkdir(parents=True)
        found = find_lock_for(nested)
        assert found == (tmp_path / "mcp-lock.json").resolve()

    def test_nearest_lock_wins_over_git_root_lock(self, tmp_path: Path) -> None:
        _git_init(tmp_path)
        (tmp_path / "mcp-lock.json").write_text("{}")
        nested_dir = tmp_path / "packages" / "svc-a"
        nested_dir.mkdir(parents=True)
        (nested_dir / "mcp-lock.json").write_text("{}")
        config = nested_dir / ".mcp.json"
        found = find_lock_for(config)
        assert found == (nested_dir / "mcp-lock.json").resolve()

    def test_outside_git_repo_only_checks_own_directory(self, tmp_path: Path) -> None:
        # No .git anywhere under tmp_path: a lock one level up must not be
        # picked up — otherwise an unrelated ancestor (e.g. $HOME) could leak
        # into an unbounded upward walk.
        parent = tmp_path / "parent"
        parent.mkdir()
        (parent / "mcp-lock.json").write_text("{}")
        child = parent / "child"
        child.mkdir()
        config = child / ".mcp.json"
        assert find_lock_for(config) is None

    def test_outside_git_repo_lock_in_same_dir_still_found(
        self, tmp_path: Path
    ) -> None:
        config_dir = tmp_path / "standalone"
        config_dir.mkdir()
        (config_dir / "mcp-lock.json").write_text("{}")
        config = config_dir / ".mcp.json"
        assert find_lock_for(config) == (config_dir / "mcp-lock.json").resolve()
