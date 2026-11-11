"""Tests for mcp_audit._fs: the one safe-write helper (2026-11 hardening)."""

from __future__ import annotations

import ast
import json
import os
import stat
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from mcp_audit._fs import atomic_write, create_exclusive

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX modes/symlinks")


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


class TestAtomicWrite:
    def test_writes_bytes_and_text(self, tmp_path: Path) -> None:
        atomic_write(tmp_path / "a", b"\x00\x01")
        atomic_write(tmp_path / "b", "héllo")
        assert (tmp_path / "a").read_bytes() == b"\x00\x01"
        assert (tmp_path / "b").read_text(encoding="utf-8") == "héllo"

    @posix_only
    def test_default_mode_is_private(self, tmp_path: Path) -> None:
        atomic_write(tmp_path / "s.json", "{}")
        assert _mode(tmp_path / "s.json") == 0o600

    @posix_only
    def test_existing_wide_file_is_narrowed(self, tmp_path: Path) -> None:
        """O_CREAT|O_TRUNC kept an old 0o644; the helper never does."""
        target = tmp_path / "state.json"
        target.write_text("old")
        target.chmod(0o644)
        atomic_write(target, "new")
        assert _mode(target) == 0o600
        assert target.read_text() == "new"

    @posix_only
    def test_explicit_mode(self, tmp_path: Path) -> None:
        atomic_write(tmp_path / "r.pdf", b"%PDF", mode=0o640)
        assert _mode(tmp_path / "r.pdf") == 0o640

    @posix_only
    def test_symlink_at_destination_is_replaced_not_followed(
        self, tmp_path: Path
    ) -> None:
        victim = tmp_path / "victim"
        victim.write_text("precious")
        link = tmp_path / "out.json"
        link.symlink_to(victim)
        atomic_write(link, "new")
        assert victim.read_text() == "precious"
        assert not link.is_symlink()
        assert link.read_text() == "new"

    @posix_only
    def test_planted_fixed_tmp_name_is_never_used(self, tmp_path: Path) -> None:
        """The pre-2026-11 writers used `<name>.tmp`; a repo can plant that."""
        victim = tmp_path / "victim"
        victim.write_text("precious")
        (tmp_path / "mcp-lock.json.tmp").symlink_to(victim)
        atomic_write(tmp_path / "mcp-lock.json", "{}")
        assert victim.read_text() == "precious"

    def test_failure_leaves_destination_and_no_temp(self, tmp_path: Path) -> None:
        target = tmp_path / "keep.json"
        target.write_text("old")
        with (
            patch("mcp_audit._fs.os.replace", side_effect=OSError("boom")),
            pytest.raises(OSError, match="boom"),
        ):
            atomic_write(target, "new")
        assert target.read_text() == "old"
        assert sorted(p.name for p in tmp_path.iterdir()) == ["keep.json"]

    @posix_only
    def test_dir_mode_creates_private_parents(self, tmp_path: Path) -> None:
        target = tmp_path / "a" / "b" / "c.json"
        atomic_write(target, "{}", dir_mode=0o700)
        assert _mode(tmp_path / "a" / "b") == 0o700

    def test_private_write_never_chmods(self, tmp_path: Path) -> None:
        """mkstemp creates 0o600, so there is no window and no chmod."""
        with patch("mcp_audit._fs.os.chmod") as chmod:
            atomic_write(tmp_path / "x", "y")
        chmod.assert_not_called()


class TestCreateExclusive:
    def test_creates(self, tmp_path: Path) -> None:
        create_exclusive(tmp_path / "f.bak", "orig", mode=0o600)
        assert (tmp_path / "f.bak").read_text() == "orig"

    def test_refuses_existing(self, tmp_path: Path) -> None:
        (tmp_path / "f.bak").write_text("first")
        with pytest.raises(FileExistsError):
            create_exclusive(tmp_path / "f.bak", "second", mode=0o600)
        assert (tmp_path / "f.bak").read_text() == "first"

    @posix_only
    def test_refuses_dangling_symlink(self, tmp_path: Path) -> None:
        """Path.exists() says False for a dangling link; O_EXCL still refuses."""
        target = tmp_path / "would-be-created"
        (tmp_path / "f.bak").symlink_to(target)
        with pytest.raises(FileExistsError):
            create_exclusive(tmp_path / "f.bak", "x", mode=0o600)
        assert not target.exists()


class TestFixerAndLockUseTheHelper:
    @posix_only
    def test_fix_apply_ignores_planted_tmp_and_bak_symlinks(
        self, tmp_path: Path
    ) -> None:
        from mcp_audit.fixer.fixer import run_pins  # noqa: PLC0415

        cfg = tmp_path / ".mcp.json"
        cfg.write_text(
            json.dumps({"mcpServers": {"s": {"command": "npx", "args": ["-y", "pkg"]}}})
        )
        victim = tmp_path / "victim"
        victim.write_text("precious")
        (tmp_path / ".mcp.json.tmp").symlink_to(victim)
        (tmp_path / ".mcp.json.bak").symlink_to(tmp_path / "dangling-target")

        result = run_pins(cfg, [("s", "pkg", "1.0.0")], apply=True)

        assert victim.read_text() == "precious"
        assert not (tmp_path / "dangling-target").exists()
        assert result.backup_path == tmp_path / ".mcp.json.bak.1"
        assert "pkg@1.0.0" in cfg.read_text()

    @posix_only
    def test_lock_write_ignores_planted_tmp_symlink(self, tmp_path: Path) -> None:
        from mcp_audit.lock.writer import write_atomic  # noqa: PLC0415

        victim = tmp_path / "victim"
        victim.write_text("precious")
        (tmp_path / "mcp-lock.json.tmp").symlink_to(victim)
        write_atomic(tmp_path / "mcp-lock.json", b"{}\n")
        assert victim.read_text() == "precious"
        assert (tmp_path / "mcp-lock.json").read_bytes() == b"{}\n"


def test_no_hand_rolled_truncating_writes_left_in_src() -> None:
    """Persisted state goes through _fs; no `O_CREAT | O_TRUNC` copies return.

    Exception: none today. A new site must use atomic_write/create_exclusive.
    """
    src = Path(__file__).resolve().parents[1] / "src" / "mcp_audit"
    offenders: list[str] = []
    for path in src.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr == "O_TRUNC":
                offenders.append(f"{path.relative_to(src)}:{node.lineno}")
    assert offenders == [], offenders


def test_os_write_short_write_is_not_used_for_files() -> None:
    """Bare os.write() may write fewer bytes than asked; no file writer uses it.

    runtime/relay.py is exempt: it writes to a pipe and loops on the count.
    """
    src = Path(__file__).resolve().parents[1] / "src" / "mcp_audit"
    offenders: list[str] = []
    for path in src.rglob("*.py"):
        if path.relative_to(src).as_posix() == "runtime/relay.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "write"
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "os"
            ):
                offenders.append(f"{path.relative_to(src)}:{node.lineno}")
    assert offenders == [], offenders


def test_umask_does_not_matter_for_private_files(tmp_path: Path) -> None:
    if sys.platform == "win32":
        pytest.skip("POSIX modes")
    old = os.umask(0)
    try:
        atomic_write(tmp_path / "x", "y")
    finally:
        os.umask(old)
    assert _mode(tmp_path / "x") == 0o600
