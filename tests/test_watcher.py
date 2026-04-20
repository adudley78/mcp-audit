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
        watcher = ConfigWatcher(on_change_callback=MagicMock(), extra_paths=[ghost])
        assert ghost.parent in watcher.skipped_dirs

    def test_extra_json_filename_added_to_known(self, tmp_path: Path) -> None:
        cfg = tmp_path / "my-custom.json"
        cfg.write_text('{"mcpServers": {}}')
        watcher = ConfigWatcher(on_change_callback=MagicMock(), extra_paths=[cfg])
        assert "my-custom.json" in watcher._known_filenames


# ── _McpConfigEventHandler — event filtering ──────────────────────────────────


class TestEventFiltering:
    def _make_handler(self, callback: object | None = None) -> _McpConfigEventHandler:
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


# ── Concurrency — scan lock + pending rescan coalescing ───────────────────────


class TestFireConcurrency:
    """Verify that ``_fire`` serialises callback execution and that events
    arriving while a scan is in flight coalesce into exactly one re-fire.

    Rationale: two rapid config saves could otherwise spawn overlapping
    ``run_scan`` calls that both read and overwrite ``state_<hash>.json``,
    silently discarding the earlier rug-pull results.
    """

    def test_concurrent_fire_does_not_call_callback_twice_simultaneously(
        self, tmp_path: Path
    ) -> None:
        """Two ``_fire`` invocations must never execute the callback
        concurrently.  The second call must wait for (or defer) the first.
        """
        overlap_detected: list[bool] = []
        in_flight_lock = threading.Lock()
        first_started = threading.Event()
        release_first = threading.Event()
        call_count = [0]

        def cb(p: Path, et: str) -> None:
            if not in_flight_lock.acquire(blocking=False):
                overlap_detected.append(True)
                return
            try:
                call_count[0] += 1
                if call_count[0] == 1:
                    first_started.set()
                    # Block the first callback until the test releases it,
                    # giving the second thread a real chance to overlap.
                    release_first.wait(timeout=3.0)
            finally:
                in_flight_lock.release()

        known = frozenset({"mcp.json"})
        handler = _McpConfigEventHandler(cb, known)
        target = tmp_path / "mcp.json"

        t1 = threading.Thread(target=handler._fire, args=(target, "modified"))
        t2 = threading.Thread(target=handler._fire, args=(target, "modified"))
        t1.start()
        # Wait until t1 is definitely inside the callback before starting t2.
        assert first_started.wait(timeout=3.0), "first callback never started"

        t2.start()
        # Give t2 enough wall time to attempt acquiring the scan lock.
        time.sleep(0.1)

        release_first.set()
        t1.join(timeout=3.0)
        t2.join(timeout=3.0)

        assert overlap_detected == [], (
            "Callback was executed concurrently from two threads — "
            "_scan_lock is not protecting the critical section."
        )

    def test_pending_rescan_retriggers_after_first_completes(
        self, tmp_path: Path
    ) -> None:
        """A second _fire while the first is running must re-trigger the
        callback exactly once when the first completes — not zero times
        (lost event) and not two additional times (amplification).
        """
        first_started = threading.Event()
        release_first = threading.Event()
        call_args: list[tuple[Path, str]] = []
        lock = threading.Lock()

        def cb(p: Path, et: str) -> None:
            with lock:
                call_args.append((p, et))
                idx = len(call_args)
            if idx == 1:
                first_started.set()
                release_first.wait(timeout=3.0)

        known = frozenset({"mcp.json"})
        handler = _McpConfigEventHandler(cb, known)
        target = tmp_path / "mcp.json"

        t1 = threading.Thread(target=handler._fire, args=(target, "modified"))
        t1.start()
        assert first_started.wait(timeout=3.0)

        # Fire a second event while the first callback is still blocked —
        # this must land on the pending_rescan path, not execute immediately.
        t2 = threading.Thread(target=handler._fire, args=(target, "created"))
        t2.start()
        time.sleep(0.1)  # let t2 reach the acquire() check

        # Before the first callback finishes we must still have exactly
        # one recorded call — the second has been deferred.
        assert len(call_args) == 1

        release_first.set()
        t1.join(timeout=3.0)
        t2.join(timeout=3.0)

        # Exactly two calls: the original plus the single coalesced re-fire.
        assert len(call_args) == 2, (
            f"Expected exactly 2 callback invocations, got {len(call_args)}: "
            f"{call_args}"
        )
        # The re-fire preserves the latest (path, event_type).
        assert call_args[1] == (target, "created")

    def test_multiple_pending_events_coalesce_into_single_retrigger(
        self, tmp_path: Path
    ) -> None:
        """Several events arriving while a scan is in flight must collapse
        to exactly one re-trigger — the most recent wins.
        """
        first_started = threading.Event()
        release_first = threading.Event()
        call_args: list[tuple[Path, str]] = []
        lock = threading.Lock()

        def cb(p: Path, et: str) -> None:
            with lock:
                call_args.append((p, et))
                idx = len(call_args)
            if idx == 1:
                first_started.set()
                release_first.wait(timeout=3.0)

        known = frozenset({"mcp.json"})
        handler = _McpConfigEventHandler(cb, known)
        target = tmp_path / "mcp.json"

        t1 = threading.Thread(target=handler._fire, args=(target, "modified"))
        t1.start()
        assert first_started.wait(timeout=3.0)

        # Fire N events while the first is blocked.  All must coalesce.
        deferred_threads = [
            threading.Thread(target=handler._fire, args=(target, f"modified-{i}"))
            for i in range(5)
        ]
        for t in deferred_threads:
            t.start()
        for t in deferred_threads:
            t.join(timeout=1.0)

        release_first.set()
        t1.join(timeout=3.0)

        # One initial + exactly one re-fire for the coalesced backlog.
        assert len(call_args) == 2, (
            f"Expected coalesced backlog to produce exactly 2 total "
            f"callbacks, got {len(call_args)}: {call_args}"
        )


# ── ConfigWatcher start / stop lifecycle ──────────────────────────────────────


class TestConfigWatcherLifecycle:
    def test_start_and_stop_without_error(self, tmp_path: Path) -> None:
        cfg = tmp_path / "mcp.json"
        cfg.write_text('{"mcpServers": {}}')
        watcher = ConfigWatcher(on_change_callback=MagicMock(), extra_paths=[cfg])
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
                    "--path",
                    str(cfg),
                    "--severity-threshold",
                    "HIGH",
                    "--format",
                    "terminal",
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
