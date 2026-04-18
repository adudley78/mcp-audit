"""Tests for sast/bundler.py — semgrep-rules/ resolution across execution contexts.

Covers:
- get_bundled_rules_path() via PyInstaller _MEIPASS (frozen)
- get_bundled_rules_path() returning None in dev context (no importlib match)
- find_rules_dir() returning a non-None, valid directory
- find_rules_dir() returning a directory containing at least one YAML rule
- find_rules_dir() importlib branch: exercised when repo root is suppressed
- resolve_bundled_resource() unit tests (happy path + each fallback step)
"""

from __future__ import annotations

import importlib.resources
import sys
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

import pytest

from mcp_audit._paths import resolve_bundled_resource
from mcp_audit.sast.bundler import get_bundled_rules_path
from mcp_audit.sast.runner import find_rules_dir

# ── get_bundled_rules_path ─────────────────────────────────────────────────────


class TestGetBundledRulesPath:
    def test_returns_none_in_dev_context(self) -> None:
        """In a dev / editable install, importlib finds no installed rules."""
        # The editable install doesn't copy semgrep-rules/ into src/mcp_audit/,
        # so neither the _MEIPASS branch nor the importlib branch should match.
        # The repo-root fallback is handled by find_rules_dir(), not this function.
        assert not getattr(sys, "frozen", False), "test must run in non-frozen mode"
        result = get_bundled_rules_path()
        # In the dev tree, src/mcp_audit/semgrep-rules does not exist → None.
        assert result is None

    def test_returns_meipass_path_when_frozen(self, tmp_path: Path) -> None:
        """Returns the _MEIPASS semgrep-rules/ directory in frozen mode."""
        fake_rules = tmp_path / "semgrep-rules"
        fake_rules.mkdir()

        with (
            patch.object(sys, "frozen", True, create=True),
            patch.object(sys, "_MEIPASS", str(tmp_path), create=True),
        ):
            result = get_bundled_rules_path()

        assert result == fake_rules
        assert result.is_dir()

    def test_meipass_absent_directory_returns_none(self, tmp_path: Path) -> None:
        """Returns None when the frozen binary lacks semgrep-rules/."""
        with (
            patch.object(sys, "frozen", True, create=True),
            patch.object(sys, "_MEIPASS", str(tmp_path), create=True),
        ):
            # semgrep-rules/ NOT created inside tmp_path
            result = get_bundled_rules_path()

        assert result is None


# ── find_rules_dir ─────────────────────────────────────────────────────────────


class TestFindRulesDir:
    def test_returns_path(self) -> None:
        """find_rules_dir() always returns a non-None Path in the dev repo."""
        result = find_rules_dir()
        assert result is not None

    def test_returned_path_is_dir(self) -> None:
        """The resolved path is an existing directory."""
        result = find_rules_dir()
        assert result is not None
        assert result.is_dir()

    def test_contains_yaml_rules(self) -> None:
        """The resolved directory contains at least one .yml or .yaml file."""
        result = find_rules_dir()
        assert result is not None
        yaml_files = list(result.rglob("*.yml")) + list(result.rglob("*.yaml"))
        assert len(yaml_files) > 0, f"No YAML files found under {result}"

    def test_importlib_branch_via_mocked_bundler(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """find_rules_dir() uses the importlib branch when repo root is absent.

        Simulates a pip-installed wheel context by:
        - Suppressing the dev repo-root fallback (_REPO_RULES_DIR → non-existent).
        - Ensuring sys.frozen is False (no PyInstaller).
        - Mocking importlib.resources.as_file() to return a temp directory.
        - Suppressing the exe-adjacent fallback (shutil.which → None).
        """
        import shutil as shutil_mod

        import mcp_audit.sast.runner as runner_mod

        fake_rules = tmp_path / "semgrep-rules"
        fake_rules.mkdir()
        (fake_rules / "test-rule.yml").write_text("# synthetic rule for test\n")

        # Block step 1 — dev repo root
        monkeypatch.setattr(runner_mod, "_REPO_RULES_DIR", tmp_path / "__nonexistent__")

        # Block PyInstaller (step 2)
        monkeypatch.setattr(sys, "frozen", False, raising=False)

        # Block step 4 — executable-adjacent fallback
        monkeypatch.setattr(shutil_mod, "which", lambda _: None)

        # Simulate step 3 — importlib.resources finds the pip-installed rules
        @contextmanager
        def _fake_as_file(ref: object) -> Generator[Path, None, None]:
            yield fake_rules

        monkeypatch.setattr(importlib.resources, "as_file", _fake_as_file)

        result = find_rules_dir()

        assert result is not None
        assert result == fake_rules
        assert result.is_dir()

    def test_returns_none_when_no_source_found(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """find_rules_dir() returns None when every resolution step fails."""
        import shutil as shutil_mod

        import mcp_audit.sast.runner as runner_mod

        monkeypatch.setattr(runner_mod, "_REPO_RULES_DIR", tmp_path / "__nonexistent__")
        monkeypatch.setattr(sys, "frozen", False, raising=False)
        # Return a fake exe path whose parent contains no semgrep-rules/ dir.
        monkeypatch.setattr(shutil_mod, "which", lambda _: str(tmp_path / "mcp-audit"))

        # Make importlib return a non-existent path
        @contextmanager
        def _absent_as_file(ref: object) -> Generator[Path, None, None]:
            yield tmp_path / "__nonexistent_rules__"

        monkeypatch.setattr(importlib.resources, "as_file", _absent_as_file)

        result = find_rules_dir()
        assert result is None


# ── resolve_bundled_resource ───────────────────────────────────────────────────


class TestResolveBundledResource:
    def test_dev_fallback_used_when_importlib_absent(self, tmp_path: Path) -> None:
        """Falls back to dev_fallback when importlib finds nothing."""
        dev_dir = tmp_path / "my-resource"
        dev_dir.mkdir()

        @contextmanager
        def _absent(ref: object) -> Generator[Path, None, None]:
            yield tmp_path / "__missing__"

        with (
            patch.object(sys, "frozen", False, create=True),
            patch.object(importlib.resources, "as_file", _absent),
        ):
            result = resolve_bundled_resource(
                package="mcp_audit",
                subdir="nonexistent-subdir",
                dev_fallback=dev_dir,
            )

        assert result == dev_dir

    def test_frozen_path_takes_priority(self, tmp_path: Path) -> None:
        """PyInstaller _MEIPASS path is returned before importlib and dev_fallback."""
        frozen_dir = tmp_path / "frozen-rules"
        frozen_dir.mkdir()
        dev_dir = tmp_path / "dev-rules"
        dev_dir.mkdir()

        with (
            patch.object(sys, "frozen", True, create=True),
            patch.object(sys, "_MEIPASS", str(tmp_path), create=True),
        ):
            result = resolve_bundled_resource(
                package="mcp_audit",
                subdir="frozen-rules",
                frozen_subpath="frozen-rules",
                dev_fallback=dev_dir,
            )

        assert result == frozen_dir

    def test_importlib_branch_preferred_over_dev_fallback(self, tmp_path: Path) -> None:
        """importlib result is returned before the dev_fallback."""
        importlib_dir = tmp_path / "importlib-rules"
        importlib_dir.mkdir()
        dev_dir = tmp_path / "dev-rules"
        dev_dir.mkdir()

        @contextmanager
        def _found(ref: object) -> Generator[Path, None, None]:
            yield importlib_dir

        with (
            patch.object(sys, "frozen", False, create=True),
            patch.object(importlib.resources, "as_file", _found),
        ):
            result = resolve_bundled_resource(
                package="mcp_audit",
                subdir="semgrep-rules",
                dev_fallback=dev_dir,
            )

        assert result == importlib_dir

    def test_returns_none_when_all_steps_fail(self, tmp_path: Path) -> None:
        """Returns None when frozen path, importlib, and dev_fallback all miss."""

        @contextmanager
        def _absent(ref: object) -> Generator[Path, None, None]:
            yield tmp_path / "__missing__"

        with (
            patch.object(sys, "frozen", False, create=True),
            patch.object(importlib.resources, "as_file", _absent),
        ):
            result = resolve_bundled_resource(
                package="mcp_audit",
                subdir="nonexistent",
                dev_fallback=None,
            )

        assert result is None

    def test_frozen_subpath_defaults_to_subdir(self, tmp_path: Path) -> None:
        """When frozen_subpath is omitted, subdir is used as the _MEIPASS sub-path."""
        rules_dir = tmp_path / "semgrep-rules"
        rules_dir.mkdir()

        with (
            patch.object(sys, "frozen", True, create=True),
            patch.object(sys, "_MEIPASS", str(tmp_path), create=True),
        ):
            # No frozen_subpath supplied — should default to subdir="semgrep-rules"
            result = resolve_bundled_resource(
                package="mcp_audit",
                subdir="semgrep-rules",
            )

        assert result == rules_dir

    def test_importlib_exception_falls_through(self, tmp_path: Path) -> None:
        """ModuleNotFoundError from importlib is silently absorbed."""
        dev_dir = tmp_path / "fallback"
        dev_dir.mkdir()

        def _raising_files(package: str) -> object:
            raise ModuleNotFoundError(package)

        with (
            patch.object(sys, "frozen", False, create=True),
            patch.object(importlib.resources, "files", _raising_files),
        ):
            result = resolve_bundled_resource(
                package="mcp_audit",
                subdir="semgrep-rules",
                dev_fallback=dev_dir,
            )

        assert result == dev_dir
