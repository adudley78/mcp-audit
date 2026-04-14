"""Tests for mcp_audit.watcher — ConfigWatcher and debounce logic."""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

from mcp_audit.watcher import (
    ConfigWatcher,
    _known_config_filenames,
    _McpConfigEventHandler,
    _watch_directories,
)

# ── _known_config_filenames ────────────────────────────────────────────────────


class TestKnownConfigFilenames:
    def test_includes_cursor_config(self) -> None:
        names = _known_config_filenames()
        assert "mcp.json" in names

    def test_includes_claude_desktop_config(self) -> None:
        names = _known_config_filenames()
        assert "claude_desktop_config.json" in names

    def test_includes_dotmcp_project_config(self) -> None:
        names = _known_config_filenames()
        assert ".mcp.json" in names

    def test_returns_frozenset(self) -> None:
        names = _known_config_filenames()
        assert isinstance(names, frozenset)


# ── _watch_directories ─────────────────────────────────────────────────────────


class TestWatchDirectories:
    def test_watchable_dirs_exist(self) -> None:
        watchable, _ = _watch_directories()
        for d in watchable:
            assert d.exists(), f"Listed as watchable but missing: {d}"

    def test_skipped_dirs_do_not_exist(self) -> None:
        _, skipped = _watch_directories()
        for d in skipped:
            assert not d.exists(), f"Listed as skipped but actually exists: {d}"

    def test_extra_file_path_adds_its_parent(self, tmp_path: Path) -> None:
        cfg = tmp_path / "mcp.json"
        cfg.write_text('{"mcpServers": {}}')
        watchable, _ = _watch_directories(extra_paths=[cfg])
        assert tmp_path in watchable

    def test_extra_dir_path_added_directly(self, tmp_path: Path) -> None:
        watchable, _ = _watch_directories(extra_paths=[tmp_path])
        assert tmp_path in watchable

    def test_nonexistent_extra_path_goes_to_skipped(self, tmp_path: Path) -> None:
        missing = tmp_path / "ghost" / "mcp.json"
        _, skipped = _watch_directories(extra_paths=[missing])
        assert missing.parent in skipped


# ── ConfigWatcher directory properties ────────────────────────────────────────


class TestConfigWatcherDirectories:
    def test_watchable_dirs_from_discovery(self, tmp_path: Path) -> None:
        cfg = tmp_path / "mcp.json"
        cfg.write_text('{"mcpServers": {}}')
        watcher = ConfigWatcher(on_change_callback=MagicMock(), extra_paths=[cfg])
        assert tmp_path in watcher.watchable_dirs

    def test_skipped_dirs_reported(self, tmp_path: Path) -> None:
        ghost = tmp_path / "nonexistent" / "mcp.json"
        watcher = ConfigWatcher(
            on_change_callback=MagicMock(), extra_paths=[ghost]
        )
        assert ghost.parent in watcher.skipped_dirs

    def test_extra_json_filename_added_to_known(self, tmp_path: Path) -> None:
        cfg = tmp_path / "my-custom.json"
        cfg.write_text('{"mcpServers": {}}')
        watcher = ConfigWatcher(on_change_callback=MagicMock(), extra_paths=[cfg])
        assert "my-custom.json" in watcher._known_filenames


# ── _McpConfigEventHandler — event filtering ──────────────────────────────────


class TestEventFiltering:
    def _make_handler(
        self, callback: object | None = None
    ) -> _McpConfigEventHandler:
        cb = callback or MagicMock()
        known = frozenset({"mcp.json", "claude_desktop_config.json", ".mcp.json"})
        return _McpConfigEventHandler(cb, known)  # type: ignore[arg-type]

    def test_relevant_json_config_accepted(self) -> None:
        handler = self._make_handler()
        assert handler._is_relevant("/home/user/.cursor/mcp.json")

    def test_non_json_file_rejected(self) -> None:
        handler = self._make_handler()
        assert not handler._is_relevant("/home/user/.cursor/mcp.yaml")

    def test_unknown_json_filename_rejected(self) -> None:
        handler = self._make_handler()
        assert not handler._is_relevant("/tmp/random-config.json")  # noqa: S108

    def test_dotmcp_json_accepted(self) -> None:
        handler = self._make_handler()
        assert handler._is_relevant("/project/.mcp.json")


# ── Debounce behaviour ─────────────────────────────────────────────────────────


class TestDebounce:
    def test_three_rapid_events_fire_callback_once(self, tmp_path: Path) -> None:
        """Three events within 500 ms must collapse to a single callback call."""
        fired: list[tuple[Path, str]] = []

        def cb(p: Path, et: str) -> None:
            fired.append((p, et))

        known = frozenset({"mcp.json"})
        handler = _McpConfigEventHandler(cb, known)

        target = tmp_path / "mcp.json"
        for _ in range(3):
            handler._schedule(target, "modified")
            time.sleep(0.05)  # 50 ms between each — all within 500 ms window

        # Wait long enough for the debounce timer to fire.
        time.sleep(0.7)

        assert len(fired) == 1
        assert fired[0] == (target, "modified")

    def test_two_separate_bursts_fire_twice(self, tmp_path: Path) -> None:
        """Two bursts separated by > 500 ms should each produce a callback."""
        fired: list[tuple[Path, str]] = []

        def cb(p: Path, et: str) -> None:
            fired.append((p, et))

        known = frozenset({"mcp.json"})
        handler = _McpConfigEventHandler(cb, known)
        target = tmp_path / "mcp.json"

        handler._schedule(target, "modified")
        time.sleep(0.7)  # first burst settles

        handler._schedule(target, "modified")
        time.sleep(0.7)  # second burst settles

        assert len(fired) == 2

    def test_cancel_all_prevents_pending_fire(self, tmp_path: Path) -> None:
        fired: list[tuple[Path, str]] = []

        def cb(p: Path, et: str) -> None:
            fired.append((p, et))

        known = frozenset({"mcp.json"})
        handler = _McpConfigEventHandler(cb, known)
        target = tmp_path / "mcp.json"

        handler._schedule(target, "modified")
        handler.cancel_all()
        time.sleep(0.7)

        assert fired == []


# ── ConfigWatcher start / stop lifecycle ──────────────────────────────────────


class TestConfigWatcherLifecycle:
    def test_start_and_stop_without_error(self, tmp_path: Path) -> None:
        cfg = tmp_path / "mcp.json"
        cfg.write_text('{"mcpServers": {}}')
        watcher = ConfigWatcher(
            on_change_callback=MagicMock(), extra_paths=[cfg]
        )
        watcher.start()
        watcher.stop()  # must not raise

    def test_file_modification_triggers_callback(self, tmp_path: Path) -> None:
        cfg = tmp_path / "mcp.json"
        cfg.write_text('{"mcpServers": {}}')

        received: list[tuple[Path, str]] = []
        event = threading.Event()

        def cb(p: Path, et: str) -> None:
            received.append((p, et))
            event.set()

        watcher = ConfigWatcher(on_change_callback=cb, extra_paths=[cfg])
        watcher.start()
        try:
            time.sleep(0.2)
            cfg.write_text('{"mcpServers": {"new": {"command": "node"}}}')
            triggered = event.wait(timeout=3.0)
        finally:
            watcher.stop()

        assert triggered, "Callback was not triggered within 3 s"
        assert received[0][0] == cfg
        assert received[0][1] in {"modified", "created"}


# ── watch CLI command ──────────────────────────────────────────────────────────


def _make_noop_watcher_patches() -> tuple[object, object]:
    """Return patches for ConfigWatcher.start and .stop that are no-ops."""

    def _fake_start(self_: object) -> None:
        pass

    def _fake_stop(self_: object) -> None:
        pass

    return (
        patch("mcp_audit.watcher.ConfigWatcher.start", _fake_start),
        patch("mcp_audit.watcher.ConfigWatcher.stop", _fake_stop),
    )


class TestWatchCLI:
    """CLI-level tests for the watch command.

    The strategy: patch run_scan to return a clean ScanResult immediately, and
    patch threading.Event.wait to return True on the first call so the blocking
    loop in the watch command exits without waiting a real second.
    """

    @staticmethod
    def _patched_event_wait(
        self_: threading.Event, timeout: float | None = None
    ) -> bool:
        """Always returns True so `while not stop_event.wait(...)` exits."""
        return True

    def test_watch_command_exits_cleanly(self, tmp_path: Path) -> None:
        """The watch command should run the initial scan and exit when the loop
        is unblocked."""
        from typer.testing import CliRunner

        from mcp_audit.cli import app
        from mcp_audit.models import ScanResult

        cfg = tmp_path / "mcp.json"
        cfg.write_text(json.dumps({"mcpServers": {}}))

        mock_result = ScanResult()
        start_patch, stop_patch = _make_noop_watcher_patches()

        with (
            patch("mcp_audit.cli.run_scan", return_value=mock_result),
            patch("threading.Event.wait", self._patched_event_wait),
            start_patch,
            stop_patch,
        ):
            result = CliRunner().invoke(
                app,
                ["watch", "--path", str(cfg)],
                catch_exceptions=False,
            )

        assert result.exit_code == 0
        assert "Watching" in result.output
        assert "Stopped watching" in result.output

    def test_watch_command_accepts_all_flags(self, tmp_path: Path) -> None:
        """All documented flags must be accepted without 'No such option' errors."""
        from typer.testing import CliRunner

        from mcp_audit.cli import app
        from mcp_audit.models import ScanResult

        cfg = tmp_path / "mcp.json"
        cfg.write_text(json.dumps({"mcpServers": {}}))

        mock_result = ScanResult()
        start_patch, stop_patch = _make_noop_watcher_patches()

        with (
            patch("mcp_audit.cli.run_scan", return_value=mock_result),
            patch("threading.Event.wait", self._patched_event_wait),
            start_patch,
            stop_patch,
        ):
            result = CliRunner().invoke(
                app,
                [
                    "watch",
                    "--path", str(cfg),
                    "--severity-threshold", "HIGH",
                    "--format", "terminal",
                ],
                catch_exceptions=False,
            )

        assert "No such option" not in (result.output or "")
        assert result.exit_code == 0

    def test_watch_command_invalid_severity_exits_2(self, tmp_path: Path) -> None:
        from typer.testing import CliRunner

        from mcp_audit.cli import app

        result = CliRunner().invoke(
            app,
            ["watch", "--severity-threshold", "BOGUS"],
        )
        assert result.exit_code == 2
