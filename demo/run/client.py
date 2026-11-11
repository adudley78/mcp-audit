"""Play the agent's side for demo/run (stdlib only).

Launches a server exactly as an MCP client would, from its entry in an MCP
config file, then: initialize, tools/list, tools/call ``add``. Prints what the
agent would see, and with ``--json`` a machine-readable summary the demo
script and tests assert on.

Usage: python3 client.py CONFIG SERVER [--json]
       python3 client.py --render < summary.json
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap

INIT = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "demo-agent", "version": "1"},
    },
}
INITIALIZED = {"jsonrpc": "2.0", "method": "notifications/initialized"}
LIST = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
CALL = {
    "jsonrpc": "2.0",
    "id": 3,
    "method": "tools/call",
    "params": {"name": "add", "arguments": {"a": 2, "b": 3}},
}


def session(config: str, server: str) -> dict:
    """Run one session against *server* in *config*; return a summary."""
    with open(config, encoding="utf-8") as fh:
        doc = json.load(fh)
    entry = (doc.get("mcpServers") or doc.get("servers"))[server]
    argv = [entry["command"], *entry.get("args", [])]
    env = {**os.environ, **entry.get("env", {})}
    proc = subprocess.Popen(  # noqa: S603 - argv comes from the demo's own config
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        env=env,
    )
    assert proc.stdin is not None and proc.stdout is not None
    replies: dict = {}

    def send(msg: dict) -> None:
        try:
            proc.stdin.write(json.dumps(msg) + "\n")
            proc.stdin.flush()
        except (BrokenPipeError, OSError):
            pass  # the server (or mcp-audit) refused to start

    def wait_for(msg_id: int) -> None:
        for line in proc.stdout:
            if line.strip():
                msg = json.loads(line)
                replies[msg.get("id")] = msg
                if msg.get("id") == msg_id:
                    return

    # One request at a time, as a real client does: it calls a tool only
    # after reading the tools/list answer.
    for request in (INIT, LIST, CALL):
        send(request)
        if request is INIT:
            wait_for(1)
            if 1 not in replies:
                break
            send(INITIALIZED)
        else:
            wait_for(request["id"])
    proc.stdin.close()
    stderr = proc.stderr.read() if proc.stderr else ""
    proc.wait(timeout=120)
    tools = (replies.get(2) or {}).get("result", {}).get("tools")
    call = replies.get(3) or {}
    return {
        "exit": proc.returncode,
        "started": 1 in replies,
        "tools": None if tools is None else [t["name"] for t in tools],
        "descriptions": {t["name"]: t.get("description", "") for t in tools or []},
        "call_result": (call.get("result") or {}).get("content", [{}])[0].get("text"),
        "call_error": (call.get("error") or {}).get("message"),
        "stderr": stderr.strip(),
    }


def _show(summary: dict) -> None:
    if not summary["started"]:
        print(f"  server did not start (exit {summary['exit']})")
    else:
        print(f"  tools the agent sees: {summary['tools']}")
        for name, text in summary["descriptions"].items():
            body = textwrap.fill(text, 72, subsequent_indent="      ")
            print(f"    {name}: {body}")
        if summary["call_error"]:
            print(f"  add(2, 3) -> error: {summary['call_error']}")
        else:
            print(f"  add(2, 3) -> {summary['call_result']}")
    for line in summary["stderr"].splitlines():
        print(f"  stderr: {line}")


def main() -> int:
    """Entry point."""
    if sys.argv[1:] == ["--render"]:  # print a --json summary read from stdin
        _show(json.load(sys.stdin))
        return 0
    if len(sys.argv) < 3:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    summary = session(sys.argv[1], sys.argv[2])
    if "--json" in sys.argv[3:]:
        print(json.dumps(summary))
    else:
        _show(summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
