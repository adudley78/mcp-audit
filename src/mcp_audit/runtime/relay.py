"""Byte-exact stdio relay between an MCP client and a child server process.

Story 1.1 of EPIC-0009. The wrapper starts the server as a child, copies the
client's stdin to the child and the child's stdout to the client unchanged,
and passes stderr straight through (the child inherits the wrapper's stderr
descriptor, so it is never buffered or reordered).

Process model (POSIX):

* The child runs in its own session and process group
  (``start_new_session=True``), so a terminal Ctrl-C is not delivered twice
  and the whole group (``npx`` → ``node`` and so on) can be signalled at once.
* SIGINT, SIGTERM and SIGHUP received by the wrapper are forwarded to the
  child's process group.
* When the child exits, any process still left in its group is sent SIGTERM,
  so nothing is orphaned.
* The wrapper exits with the child's exit code. A child killed by a signal is
  mirrored by the wrapper dying of the same signal, with ``128 + n`` as a
  fallback exit code.

Windows gets the same relay and exit-code propagation; group signalling is
POSIX-only (Windows sandboxing is a non-goal of EPIC-0009).
"""

from __future__ import annotations

import contextlib
import os
import signal
import subprocess  # nosec B404 — list-form, shell=False launch of the user's own configured server
import sys
import threading
from collections.abc import Callable, Sequence
from types import FrameType

#: Read size for each relay copy. Large enough that big ``tools/list``
#: responses move in a few syscalls; small enough to keep latency low.
CHUNK_SIZE = 65536

#: Exit codes when the server command cannot be started (shell conventions).
EXIT_NOT_FOUND = 127
EXIT_NOT_EXECUTABLE = 126

_POSIX = os.name == "posix"
_FORWARDED_SIGNALS: tuple[int, ...] = (
    (signal.SIGINT, signal.SIGTERM, signal.SIGHUP) if _POSIX else (signal.SIGINT,)
)


def _write_all(fd: int, data: bytes) -> None:
    """Write every byte of *data* to *fd*, retrying on short writes."""
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        view = view[written:]


#: Longest line enforce mode will hold back to inspect. MCP stdio messages
#: are newline-delimited; a line longer than this is relayed uninspected
#: rather than buffered without bound.
MAX_LINE = 64 * 1024 * 1024


def _pump(
    src_fd: int,
    dst_fd: int,
    on_done: Callable[[], None],
    *,
    tap: Callable[[bytes], object] | None = None,
) -> None:
    """Copy bytes from *src_fd* to *dst_fd* until EOF or a broken pipe.

    *tap*, when given, is shown every complete line after it has been
    forwarded (monitor mode); it never changes what is relayed, and an
    exception in it is ignored. *on_done* runs exactly once when copying
    stops, for any reason.
    """
    pending = b""
    try:
        while True:
            try:
                chunk = os.read(src_fd, CHUNK_SIZE)
            except OSError:
                break
            if not chunk:
                break
            try:
                _write_all(dst_fd, chunk)
            except OSError:
                break
            if tap is not None:
                pending += chunk
                *lines, pending = pending.split(b"\n")
                for line in lines:
                    with contextlib.suppress(Exception):
                        tap(line + b"\n")
                if len(pending) > MAX_LINE:
                    pending = b""
    finally:
        on_done()


def _line_pump(
    src_fd: int,
    dst_fd: int,
    on_done: Callable[[], None],
    *,
    handle: Callable[[bytes], tuple[bytes | None, bytes | None]],
    out_lock: threading.Lock,
    reply_fd: int | None = None,
    dst_is_client: bool = False,
) -> None:
    """Relay *src_fd* to *dst_fd* line by line through *handle* (enforce mode).

    *handle* returns ``(forward, reply)``: bytes for *dst_fd* (``None`` to
    drop the line) and bytes for *reply_fd* (the client) instead. Every write
    to the client goes through *out_lock*, so a reply never lands inside a
    server message. A line *handle* fails on is forwarded unchanged, and a
    line longer than :data:`MAX_LINE` is forwarded uninspected.
    """

    def _client_write(data: bytes) -> None:
        with out_lock:
            _write_all(reply_fd if reply_fd is not None else dst_fd, data)

    def _forward(data: bytes) -> None:
        if dst_is_client:
            _client_write(data)
        else:
            _write_all(dst_fd, data)

    pending = b""
    try:
        while True:
            try:
                chunk = os.read(src_fd, CHUNK_SIZE)
            except OSError:
                break
            if not chunk:
                break
            pending += chunk
            *lines, pending = pending.split(b"\n")
            try:
                for line in lines:
                    raw = line + b"\n"
                    try:
                        forward, reply = handle(raw)
                    except Exception:  # noqa: BLE001 — never break the session
                        forward, reply = raw, None
                    if forward is not None:
                        _forward(forward)
                    if reply is not None and reply_fd is not None:
                        _client_write(reply)
                if len(pending) > MAX_LINE:
                    _forward(pending)
                    pending = b""
            except OSError:
                break
        if pending:
            with contextlib.suppress(OSError):
                _forward(pending)
    finally:
        on_done()


def _signal_group(proc: subprocess.Popen[bytes], signum: int) -> None:
    """Send *signum* to the child's process group (POSIX) or the child."""
    if _POSIX:
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(proc.pid, signum)
    else:
        with contextlib.suppress(OSError):
            proc.send_signal(signum)


def _report(message: str) -> None:
    """Write one diagnostic line to the wrapper's stderr."""
    with contextlib.suppress(OSError):
        sys.stderr.write(f"mcp-audit run: {message}\n")
        sys.stderr.flush()


def exit_code_for(returncode: int) -> int:
    """Map a child return code to a process exit status.

    A negative return code means the child died of signal ``-returncode``;
    the shell convention for that is ``128 + n``.
    """
    return returncode if returncode >= 0 else 128 - returncode


def mirror_exit(returncode: int) -> int:
    """Terminate the way the child did, or return the exit code to use.

    For a child killed by a signal, the wrapper re-raises that signal on
    itself with the default handler (POSIX), so the client sees the same
    termination it would without the wrapper. Only the CLI entry point calls
    this; :func:`relay` itself never kills the calling process.
    """
    code = exit_code_for(returncode)
    if returncode < 0 and _POSIX:
        signum = -returncode
        if signum not in (signal.SIGKILL, signal.SIGSTOP):
            with contextlib.suppress(OSError, ValueError):
                signal.signal(signum, signal.SIG_DFL)
                os.kill(os.getpid(), signum)
    return code


def relay(
    command: Sequence[str],
    *,
    stdin_fd: int | None = None,
    stdout_fd: int | None = None,
    guard: object | None = None,
) -> int:
    """Run *command* as a child and relay stdio until it exits.

    Args:
        command: The server's original argv (program first). Never run through
            a shell.
        stdin_fd: Descriptor the client writes to (default: the wrapper's
            stdin). Injectable for tests.
        stdout_fd: Descriptor the client reads from (default: the wrapper's
            stdout). Injectable for tests.
        guard: A :class:`~mcp_audit.runtime.tools.ToolGuard` (duck-typed:
            ``enforce``, ``client_line``, ``server_line``). In monitor mode it
            only watches a copy of each line and the relay stays byte-exact;
            in enforce mode the relay goes line by line through it.

    Returns:
        The child's return code as :class:`subprocess.Popen` reports it
        (negative when the child died of a signal), or an exit status of 2,
        126 or 127 when the child could not be started. Pass it to
        :func:`mirror_exit`.
    """
    if not command:
        _report("no server command given (usage: mcp-audit run -- <command> [args])")
        return 2

    in_fd = sys.stdin.fileno() if stdin_fd is None else stdin_fd
    out_fd = sys.stdout.fileno() if stdout_fd is None else stdout_fd

    try:
        proc = subprocess.Popen(  # noqa: S603  # nosec B603 — list form, shell=False
            list(command),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=None,  # inherit: stderr passes through untouched
            bufsize=0,
            start_new_session=_POSIX,
        )
    except FileNotFoundError:
        _report(f"command not found: {command[0]}")
        return EXIT_NOT_FOUND
    except PermissionError:
        _report(f"permission denied: {command[0]}")
        return EXIT_NOT_EXECUTABLE
    except OSError as exc:
        _report(f"could not start {command[0]}: {exc.strerror or exc}")
        return EXIT_NOT_EXECUTABLE

    assert proc.stdin is not None  # noqa: S101 — guaranteed by stdin=PIPE
    assert proc.stdout is not None  # noqa: S101 — guaranteed by stdout=PIPE
    child_in = proc.stdin.fileno()
    child_out = proc.stdout.fileno()

    def _close_child_stdin() -> None:
        with contextlib.suppress(OSError):
            proc.stdin.close()  # type: ignore[union-attr]

    def _client_gone() -> None:
        # Child stdout hit EOF, or the client stopped reading (EPIPE). In the
        # second case the child would block on a full pipe forever: stop it.
        if proc.poll() is None:
            _signal_group(proc, signal.SIGTERM)

    previous: dict[int, object] = {}

    def _forward(signum: int, _frame: FrameType | None) -> None:
        _signal_group(proc, signum)

    if threading.current_thread() is threading.main_thread():
        for signum in _FORWARDED_SIGNALS:
            with contextlib.suppress(OSError, ValueError):
                previous[signum] = signal.signal(signum, _forward)

    if guard is not None and getattr(guard, "enforce", False):
        out_lock = threading.Lock()

        def _to_server(line: bytes) -> tuple[bytes | None, bytes | None]:
            return guard.client_line(line)  # type: ignore[attr-defined]

        def _to_client(line: bytes) -> tuple[bytes | None, bytes | None]:
            return guard.server_line(line), None  # type: ignore[attr-defined]

        to_child = threading.Thread(
            target=_line_pump,
            args=(in_fd, child_in, _close_child_stdin),
            kwargs={"handle": _to_server, "out_lock": out_lock, "reply_fd": out_fd},
            daemon=True,
        )
        from_child = threading.Thread(
            target=_line_pump,
            args=(child_out, out_fd, _client_gone),
            kwargs={"handle": _to_client, "out_lock": out_lock, "dst_is_client": True},
            daemon=True,
        )
    else:
        client_tap = getattr(guard, "client_line", None)
        server_tap = getattr(guard, "server_line", None)
        to_child = threading.Thread(
            target=_pump,
            args=(in_fd, child_in, _close_child_stdin),
            kwargs={"tap": client_tap},
            daemon=True,
        )
        from_child = threading.Thread(
            target=_pump,
            args=(child_out, out_fd, _client_gone),
            kwargs={"tap": server_tap},
            daemon=True,
        )
    to_child.start()
    from_child.start()

    try:
        returncode = proc.wait()
        # The server has exited; anything left in its group is a leftover
        # (e.g. a grandchild still holding the stdout pipe open). Stop it
        # now, then drain: bytes already in the pipe survive the writer, so
        # nothing the server wrote is lost, and shutdown isn't held up.
        if _POSIX:
            _signal_group(proc, signal.SIGTERM)
        from_child.join(timeout=5)
    finally:
        for signum, handler in previous.items():
            with contextlib.suppress(OSError, ValueError, TypeError):
                signal.signal(signum, handler)  # type: ignore[arg-type]
        # Close our pipe ends only once their relay thread has stopped: closing
        # a descriptor another thread may still use lets the number be reused.
        if not from_child.is_alive():
            with contextlib.suppress(OSError):
                proc.stdout.close()
        if not to_child.is_alive():
            _close_child_stdin()

    return returncode
