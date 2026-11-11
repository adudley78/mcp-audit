"""Runtime harness: real MCP servers launched through ``mcp-audit run``.

EPIC-0009 Story 1.1. Unlike the config-fixture benchmark, these tests start
real servers that need no credentials, complete the MCP handshake through the
wrapper, and check that the tool list matches a direct launch.

Opt-in: they download packages from npm, so they run only when
``MCP_AUDIT_RUNTIME_TESTS=1`` and ``npx`` is on PATH. CI's ``runtime`` job
sets both. Versions are pinned so a server release cannot change the result.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("MCP_AUDIT_RUNTIME_TESTS") != "1" or shutil.which("npx") is None,
    reason="runtime harness is opt-in: set MCP_AUDIT_RUNTIME_TESTS=1 with npx on PATH",
)

#: Official servers that start without credentials. ``{tmp}`` is replaced
#: with a per-test directory (the filesystem server's allowed root).
SERVERS: dict[str, list[str]] = {
    "everything": ["@modelcontextprotocol/server-everything@2.3.0"],
    "filesystem": ["@modelcontextprotocol/server-filesystem@2.3.0", "{tmp}"],
    "memory": ["@modelcontextprotocol/server-memory@2.1.1"],
    "sequential-thinking": ["@modelcontextprotocol/server-sequential-thinking@2.1.1"],
}

HANDSHAKE = [
    {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "mcp-audit-runtime-harness", "version": "1"},
        },
    },
    {"jsonrpc": "2.0", "method": "notifications/initialized"},
    {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
]


def _session(argv: list[str], timeout: float = 180) -> tuple[dict, list[str]]:
    """Run the handshake against *argv*; return (tools/list result, tool names)."""
    proc = subprocess.Popen(  # noqa: S603
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    assert proc.stdin is not None
    assert proc.stdout is not None
    for msg in HANDSHAKE:
        proc.stdin.write(json.dumps(msg) + "\n")
    proc.stdin.flush()
    result: dict | None = None
    try:
        for line in proc.stdout:
            msg = json.loads(line)
            if msg.get("id") == 2:
                result = msg["result"]
                break
    finally:
        proc.stdin.close()
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
    assert result is not None, f"no tools/list response from {argv}"
    return result, sorted(t["name"] for t in result["tools"])


@pytest.mark.parametrize("name", sorted(SERVERS))
def test_server_runs_wrapped_with_identical_tools(name: str, tmp_path: Path) -> None:
    args = [a.replace("{tmp}", str(tmp_path)) for a in SERVERS[name]]
    npx = shutil.which("npx")
    assert npx is not None
    direct_cmd = [npx, "-y", *args]
    wrapped_cmd = [sys.executable, "-m", "mcp_audit._entry", "run", "--", *direct_cmd]

    direct, direct_names = _session(direct_cmd)
    wrapped, wrapped_names = _session(wrapped_cmd)

    assert wrapped_names, f"{name} exposed no tools"
    assert wrapped_names == direct_names
    assert wrapped == direct
