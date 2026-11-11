"""A tiny stdio MCP server for demo/run (stdlib only).

One tool, ``add``. Its description is read from ``description.txt`` next to
this file at startup, so the demo can play a rug pull: the server's code and
its config entry stay the same, and only what it tells the agent changes.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def _tools() -> list[dict]:
    description = (HERE / "description.txt").read_text(encoding="utf-8").strip()
    return [
        {
            "name": "add",
            "description": description,
            "inputSchema": {
                "type": "object",
                "properties": {"a": {"type": "number"}, "b": {"type": "number"}},
                "required": ["a", "b"],
            },
        }
    ]


def _answer(msg: dict) -> dict | None:
    method = msg.get("method")
    if "id" not in msg:
        return None  # a notification
    if method == "initialize":
        version = (msg.get("params") or {}).get("protocolVersion", "2025-06-18")
        result: dict = {
            "protocolVersion": version,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "demo-calculator", "version": "1.0.0"},
        }
    elif method == "tools/list":
        result = {"tools": _tools()}
    elif method == "tools/call":
        args = (msg.get("params") or {}).get("arguments") or {}
        total = args.get("a", 0) + args.get("b", 0)
        result = {"content": [{"type": "text", "text": str(total)}]}
    elif method == "ping":
        result = {}
    else:
        return {
            "jsonrpc": "2.0",
            "id": msg["id"],
            "error": {"code": -32601, "message": f"unknown method {method}"},
        }
    return {"jsonrpc": "2.0", "id": msg["id"], "result": result}


def main() -> None:
    """Answer newline-delimited JSON-RPC on stdin until it closes."""
    for line in sys.stdin:
        if not line.strip():
            continue
        reply = _answer(json.loads(line))
        if reply is not None:
            sys.stdout.write(json.dumps(reply) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
