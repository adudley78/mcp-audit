"""Filesystem watcher that triggers re-scans when MCP config files change."""

from __future__ import annotations

import threading
from collections.abc import Callable
from pathlib import Path

from watchdog.events import (
    FileCreatedEvent,
    FileDeletedEvent,
    FileModifiedEvent,
    FileMovedEvent,
    FileSystemEvent,
    FileSystemEventHandler,
)
from watchdog.observers import Observer

from mcp_audit.discovery import _get_client_specs, discover_configs

# Callback type: (changed_path, event_type) where event_type is
# 'created', 'modified', 'deleted', or 'moved'.
ChangeCallback = Callable[[Path, str], None]

_DEBOUNCE_SECONDS = 0.5


def _known_config_filenames() -> frozenset[str]:
    """Return the set of config filenames that mcp-audit cares about.

    Collects filenames from all client specs plus hard-coded project-level
    names that are only discovered relative to CWD at runtime.
    """
    names: set[str] = set()
    for spec in _get_client_specs():
        for p in spec.config_paths:
            names.add(p.name)
    # Project-level configs discovered relative to CWD.
    names.update({"mcp.json", ".mcp.json"})
    return frozenset(names)


def _watch_directories(
    extra_paths: list[Path] | None = None,
) -> tuple[list[Path], list[Path]]:
    """Resolve the directories to watch and report which exist vs. are missing.

    Always includes every known client config directory (even when the config
    file itself is absent) so that newly created files are detected.

    Args:
        extra_paths: Additional file/directory paths requested by the caller.

    Returns:
        ``(watchable, skipped)`` — directories that exist and those that don't.
    """
    dirs: set[Path] = set()

    for spec in _get_client_specs():
        for p in spec.config_paths:
            dirs.add(p.parent)

    # Project-level: watch CWD and CWD/.vscode
    from pathlib import Path as _Path  # noqa: PLC0415 — avoid circular at module init

    cwd = _Path.cwd()
    dirs.add(cwd)
    dirs.add(cwd / ".vscode")

    if extra_paths:
        for p in extra_paths:
            expanded = p.expanduser().resolve()
            dirs.add(expanded if expanded.is_dir() else expanded.parent)

    # Also pick up directories from currently discovered configs (e.g. extra
    # paths that may be files).
    for cfg in discover_configs(extra_paths=extra_paths):
        dirs.add(cfg.path.parent)

    watchable = [d for d in sorted(dirs) if d.exists()]
    skipped = [d for d in sorted(dirs) if not d.exists()]
    return watchable, skipped


class _McpConfigEventHandler(FileSystemEventHandler):
    """Watchdog event handler that filters for MCP config files and debounces."""

    def __init__(
        self,
        callback: ChangeCallback,
        known_filenames: frozenset[str],
    ) -> None:
        super().__init__()
        self._callback = callback
        self._known_filenames = known_filenames
        self._lock = threading.Lock()
        self._pending: dict[Path, threading.Timer] = {}

    def _is_relevant(self, path_str: str) -> bool:
        p = Path(path_str)
        return p.suffix == ".json" and p.name in self._known_filenames

    def _schedule(self, path: Path, event_type: str) -> None:
        """Debounce: cancel any pending timer for this path and start a new one."""
        with self._lock:
            existing = self._pending.get(path)
            if existing is not None:
                existing.cancel()
            timer = threading.Timer(
                _DEBOUNCE_SECONDS,
                self._fire,
                args=(path, event_type),
            )
            self._pending[path] = timer
            timer.start()

    def _fire(self, path: Path, event_type: str) -> None:
        with self._lock:
            self._pending.pop(path, None)
        self._callback(path, event_type)

    def on_created(self, event: FileSystemEvent) -> None:
        if isinstance(event, FileCreatedEvent) and self._is_relevant(event.src_path):
            self._schedule(Path(event.src_path), "created")

    def on_modified(self, event: FileSystemEvent) -> None:
        if isinstance(event, FileModifiedEvent) and self._is_relevant(event.src_path):
            self._schedule(Path(event.src_path), "modified")

    def on_deleted(self, event: FileSystemEvent) -> None:
        if isinstance(event, FileDeletedEvent) and self._is_relevant(event.src_path):
            self._schedule(Path(event.src_path), "deleted")

    def on_moved(self, event: FileSystemEvent) -> None:
        if not isinstance(event, FileMovedEvent):
            return
        # Treat dest as "created" if it's a known config; src as "deleted".
        if self._is_relevant(event.dest_path):
            self._schedule(Path(event.dest_path), "created")
        if self._is_relevant(event.src_path):
            self._schedule(Path(event.src_path), "deleted")

    def cancel_all(self) -> None:
        """Cancel all outstanding debounce timers (called on shutdown)."""
        with self._lock:
            for timer in self._pending.values():
                timer.cancel()
            self._pending.clear()


class ConfigWatcher:
    """Watches MCP config files for changes and triggers re-scans.

    Runs a watchdog :class:`~watchdog.observers.Observer` in a background
    thread.  Call :meth:`start` to begin watching and :meth:`stop` to shut
    down cleanly.  :meth:`run_until_interrupt` is a convenience wrapper that
    blocks the calling thread until ``KeyboardInterrupt``.

    Example::

        def on_change(path: Path, event_type: str) -> None:
            print(f"{event_type}: {path}")

        watcher = ConfigWatcher(on_change_callback=on_change)
        watcher.run_until_interrupt()
    """

    def __init__(
        self,
        on_change_callback: ChangeCallback,
        extra_paths: list[Path] | None = None,
    ) -> None:
        """
        Args:
            on_change_callback: Called with ``(changed_path, event_type)`` when
                a config changes.  ``event_type`` is ``'created'``,
                ``'modified'``, ``'deleted'``, or ``'moved'``.
            extra_paths: Additional paths to watch beyond auto-discovered
                locations.  May be files or directories.
        """
        self._callback = on_change_callback
        self._extra_paths = extra_paths or []

        self._known_filenames = _known_config_filenames()
        if extra_paths:
            for p in extra_paths:
                ep = p.expanduser()
                if ep.suffix == ".json":
                    self._known_filenames = frozenset(self._known_filenames | {ep.name})

        self._watchable, self._skipped = _watch_directories(extra_paths)
        self._handler = _McpConfigEventHandler(self._callback, self._known_filenames)
        self._observer: Observer = Observer()

    @property
    def watchable_dirs(self) -> list[Path]:
        """Directories that exist and will be monitored."""
        return list(self._watchable)

    @property
    def skipped_dirs(self) -> list[Path]:
        """Directories that were requested but do not exist."""
        return list(self._skipped)

    def start(self) -> None:
        """Schedule all watchable directories and start the observer thread."""
        for directory in self._watchable:
            self._observer.schedule(self._handler, str(directory), recursive=False)
        self._observer.start()

    def stop(self) -> None:
        """Stop the observer and cancel any pending debounce timers."""
        self._handler.cancel_all()
        self._observer.stop()
        self._observer.join()

    def run_until_interrupt(self) -> None:
        """Block until ``KeyboardInterrupt``, then stop cleanly."""
        self.start()
        stop_event = threading.Event()
        try:
            while not stop_event.wait(timeout=1.0):
                if not self._observer.is_alive():
                    break
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()
