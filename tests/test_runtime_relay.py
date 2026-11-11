"""Tests for the ``mcp-audit run`` stdio relay (EPIC-0009 Story 1.1).

The relay is exercised two ways: in-process through :func:`relay` with
injected descriptors, and end to end by launching ``python -m mcp_audit._entry
run -- ...`` as a real subprocess, which is how an AI client launches it.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import textwrap
import threading
import time
from pathlib import Path

import pytest

from mcp_audit.runtime.relay import (
    EXIT_NOT_FOUND,
    exit_code_for,
    relay,
)

POSIX = os.name == "posix"
posix_only = pytest.mark.skipif(not POSIX, reason="POSIX signals and process groups")

PY = sys.executable

#: Child that copies stdin to stdout byte for byte, then exits 0.
CAT = [
    PY,
    "-c",
    "import os,sys\n"
    "while True:\n"
    "    b=os.read(0,4096)\n"
    "    if not b: break\n"
    "    os.write(1,b)\n",
]

#: Minimal newline-delimited JSON-RPC MCP server: answers initialize and
#: tools/list, ignores notifications, exits on stdin EOF.
MCP_SERVER = textwrap.dedent(
    """
    import json, sys
    TOOLS = [{"name": "echo", "description": "Echo text back.",
              "inputSchema": {"type": "object",
                              "properties": {"text": {"type": "string"}}}}]
    for line in sys.stdin:
        msg = json.loads(line)
        if "id" not in msg:
            continue
        if msg["method"] == "initialize":
            result = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                      "serverInfo": {"name": "fixture", "version": "1.0.0"}}
        elif msg["method"] == "tools/list":
            result = {"tools": TOOLS}
        else:
            result = {}
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg["id"],
                                     "result": result}) + "\\n")
        sys.stdout.flush()
    """
)


def _relay_in_thread(command: list[str]) -> tuple[int, int, dict[str, int]]:
    """Start relay() in a thread with pipe descriptors; return (w, r, result)."""
    in_r, in_w = os.pipe()
    out_r, out_w = os.pipe()
    result: dict[str, int] = {}

    def _run() -> None:
        result["code"] = relay(command, stdin_fd=in_r, stdout_fd=out_w)
        os.close(out_w)

    threading.Thread(target=_run, daemon=True).start()
    return in_w, out_r, result


def _read_all(fd: int) -> bytes:
    chunks = []
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        chunks.append(chunk)
    os.close(fd)
    return b"".join(chunks)


def _wrapper(*args: str, **kwargs: object) -> subprocess.Popen[bytes]:
    """Launch ``mcp-audit run`` the way an AI client does."""
    return subprocess.Popen(  # noqa: S603
        [PY, "-m", "mcp_audit._entry", "run", *args],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        **kwargs,  # type: ignore[arg-type]
    )


class TestByteExact:
    def test_arbitrary_bytes_roundtrip_unchanged(self) -> None:
        payload = bytes(range(256)) * 512 + b"no trailing newline\r\n\x00tail"
        in_w, out_r, result = _relay_in_thread(CAT)

        def _feed() -> None:
            os.write(in_w, payload)
            os.close(in_w)

        feeder = threading.Thread(target=_feed)
        feeder.start()
        received = _read_all(out_r)
        feeder.join()
        assert received == payload
        assert result["code"] == 0

    def test_large_payload_through_real_wrapper(self) -> None:
        payload = os.urandom(3 * 1024 * 1024)
        proc = _wrapper("--", *CAT)
        out, err = proc.communicate(payload, timeout=60)
        assert out == payload
        assert proc.returncode == 0
        assert err == b""

    def test_stderr_passes_through(self) -> None:
        proc = _wrapper("--", PY, "-c", "import os; os.write(2, b'diag line\\n')")
        out, err = proc.communicate(b"", timeout=30)
        assert out == b""
        assert err == b"diag line\n"

    def test_mcp_handshake_through_wrapper(self, tmp_path: Path) -> None:
        server = tmp_path / "server.py"
        server.write_text(MCP_SERVER)
        requests = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        ]
        raw_in = b"".join(json.dumps(r).encode() + b"\n" for r in requests)
        proc = _wrapper("--", PY, str(server))
        out, _ = proc.communicate(raw_in, timeout=30)
        assert proc.returncode == 0
        lines = [json.loads(line) for line in out.splitlines()]
        assert [m["id"] for m in lines] == [1, 2]
        assert lines[1]["result"]["tools"][0]["name"] == "echo"

        # Byte-exact: identical to running the server without the wrapper.
        direct = subprocess.run(  # noqa: S603
            [PY, str(server)], input=raw_in, capture_output=True, timeout=30
        )
        assert out == direct.stdout


class TestExitCodes:
    @pytest.mark.parametrize("code", [0, 1, 3, 42])
    def test_exit_code_propagates(self, code: int) -> None:
        proc = _wrapper("--", PY, "-c", f"import sys; sys.exit({code})")
        proc.communicate(b"", timeout=30)
        assert proc.returncode == code

    def test_command_not_found(self) -> None:
        proc = _wrapper("--", "definitely-not-a-real-mcp-server-binary")
        _, err = proc.communicate(b"", timeout=30)
        assert proc.returncode == EXIT_NOT_FOUND
        assert b"command not found: definitely-not-a-real-mcp-server-binary" in err

    def test_no_command_is_usage_error(self) -> None:
        proc = _wrapper()
        _, err = proc.communicate(b"", timeout=30)
        assert proc.returncode == 2
        assert b"usage: mcp-audit run" in err

    def test_server_flags_after_dashdash_reach_the_server(self) -> None:
        proc = _wrapper(
            "--", PY, "-c", "import sys; print(' '.join(sys.argv[1:]))", "--help", "-v"
        )
        out, _ = proc.communicate(b"", timeout=30)
        assert proc.returncode == 0
        assert out.strip() == b"--help -v"

    def test_exit_code_for_maps_signals(self) -> None:
        assert exit_code_for(0) == 0
        assert exit_code_for(7) == 7
        assert exit_code_for(-15) == 143


@posix_only
class TestSignals:
    def test_child_killed_by_signal_is_mirrored(self) -> None:
        proc = _wrapper(
            "--", PY, "-c", "import os, signal; os.kill(os.getpid(), signal.SIGTERM)"
        )
        proc.communicate(b"", timeout=30)
        assert proc.returncode == -signal.SIGTERM

    @pytest.mark.parametrize("signame", ["SIGTERM", "SIGINT", "SIGHUP"])
    def test_signal_to_wrapper_reaches_child(
        self, signame: str, tmp_path: Path
    ) -> None:
        # Names, not signal.SIGHUP: Windows has no SIGHUP, and the parametrize
        # list is evaluated at collection even when the class is skipped.
        signum = getattr(signal, signame)
        marker = tmp_path / "got-signal"
        child = textwrap.dedent(
            f"""
            import signal, sys, time
            def h(n, f):
                open({str(marker)!r}, "w").write(str(n))
                sys.exit(5)
            signal.signal({int(signum)}, h)
            print("ready", flush=True)
            time.sleep(60)
            """
        )
        proc = _wrapper("--", PY, "-c", child)
        assert proc.stdout is not None
        assert proc.stdout.readline() == b"ready\n"
        proc.send_signal(signum)
        proc.wait(timeout=30)
        assert marker.read_text() == str(int(signum))
        assert proc.returncode == 5

    def test_no_orphaned_grandchildren(self, tmp_path: Path) -> None:
        pid_file = tmp_path / "grandchild.pid"
        # The child spawns a long-lived grandchild (like npx -> node), then
        # exits on stdin EOF while the grandchild keeps running.
        child = textwrap.dedent(
            f"""
            import subprocess, sys
            g = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
            open({str(pid_file)!r}, "w").write(str(g.pid))
            sys.stdin.read()
            """
        )
        proc = _wrapper("--", PY, "-c", child)
        proc.communicate(b"", timeout=30)
        grandchild = int(pid_file.read_text())
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                os.kill(grandchild, 0)
            except ProcessLookupError:
                break
            # A reaped-but-zombie entry still answers kill(0); check state.
            stat = Path(f"/proc/{grandchild}/stat")
            if stat.exists() and stat.read_text().split()[2] == "Z":
                break
            time.sleep(0.1)
        else:
            os.kill(grandchild, signal.SIGKILL)
            pytest.fail("grandchild outlived the wrapper")

    def test_client_closing_stdin_ends_session(self) -> None:
        proc = _wrapper("--", *CAT)
        assert proc.stdin is not None
        proc.stdin.write(b"ping\n")
        proc.stdin.close()
        assert proc.stdout is not None
        assert proc.stdout.read() == b"ping\n"
        assert proc.wait(timeout=30) == 0
