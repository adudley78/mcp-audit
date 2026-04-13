"""Tests for mcp_audit._paths.data_dir().

Covers both normal (source) execution and simulated PyInstaller frozen mode.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from mcp_audit._paths import data_dir

# Files that must always be present inside the data directory.
_EXPECTED_FILES = {
    "known_npm_packages.yaml",
    "d3.v7.min.js",
}


class TestDataDirUnfrozen:
    """data_dir() in normal (non-frozen) execution."""

    def test_returns_path(self) -> None:
        result = data_dir()
        assert isinstance(result, Path)

    def test_directory_exists(self) -> None:
        assert data_dir().is_dir(), f"data_dir() {data_dir()} does not exist"

    def test_expected_files_present(self) -> None:
        present = {p.name for p in data_dir().iterdir()}
        missing = _EXPECTED_FILES - present
        assert not missing, f"Missing files in data_dir(): {missing}"

    def test_not_using_meipass(self) -> None:
        # In source mode the path must be inside the installed package tree,
        # not any temp directory.
        assert "mcp_audit" in str(data_dir()), (
            f"Unexpected data_dir() path in source mode: {data_dir()}"
        )


class TestDataDirFrozen:
    """data_dir() under simulated PyInstaller frozen mode."""

    @pytest.fixture()
    def fake_meipass(self, tmp_path: Path) -> Path:
        """Create a fake _MEIPASS tree with the expected data files."""
        fake_data = tmp_path / "mcp_audit" / "data"
        fake_data.mkdir(parents=True)
        for fname in _EXPECTED_FILES:
            (fake_data / fname).write_text(f"# fake {fname}")
        return tmp_path

    def _patch_frozen(self, meipass: Path):  # type: ignore[no-untyped-def]
        """Return a context-manager that patches sys to look frozen.

        ``sys.frozen`` and ``sys._MEIPASS`` don't exist in a normal Python
        process, so ``create=True`` is required for both patches.
        """
        return patch.multiple(
            sys,
            create=True,
            frozen=True,
            _MEIPASS=str(meipass),
        )

    def test_returns_meipass_based_path(self, fake_meipass: Path) -> None:
        with self._patch_frozen(fake_meipass):
            result = data_dir()
        expected = fake_meipass / "mcp_audit" / "data"
        assert result == expected

    def test_directory_exists_in_fake_bundle(self, fake_meipass: Path) -> None:
        with self._patch_frozen(fake_meipass):
            result = data_dir()
        assert result.is_dir()

    def test_expected_files_present_in_fake_bundle(self, fake_meipass: Path) -> None:
        with self._patch_frozen(fake_meipass):
            result = data_dir()
        present = {p.name for p in result.iterdir()}
        missing = _EXPECTED_FILES - present
        assert not missing, f"Missing files in frozen data_dir(): {missing}"

    def test_does_not_fall_back_to_source_dir(self, fake_meipass: Path) -> None:
        with self._patch_frozen(fake_meipass):
            result = data_dir()
        assert str(fake_meipass) in str(result), (
            "Frozen mode should use _MEIPASS, not the source tree"
        )
