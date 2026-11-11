# `mcp-audit run`

`mcp-audit run` launches an MCP server through mcp-audit. Your AI client runs it
in place of the server's own command:

```json
{
  "mcpServers": {
    "memory": {
      "command": "mcp-audit",
      "args": ["run", "--", "npx", "-y", "@modelcontextprotocol/server-memory"]
    }
  }
}
```

Everything after `--` is the server's original command, passed on verbatim, so
server flags such as `--help` reach the server rather than mcp-audit.

## What it does today (EPIC-0009 Story 1.1)

`run` is a relay. It changes nothing the client and server send each other:

- **stdin and stdout** are copied byte for byte in both directions.
- **stderr** is the server's own: the server writes straight to the client's
  stderr.
- **Signals.** SIGINT, SIGTERM and SIGHUP sent to `run` are forwarded to the
  server's whole process group (POSIX).
- **Exit code.** `run` exits with the server's exit code. If a signal killed
  the server, `run` dies of the same signal.
- **No orphans.** When the server exits, anything still running in its
  process group (an `npx` → `node` grandchild, for example) is sent SIGTERM.
- **Can't start.** A missing command exits 127 and a non-executable one 126,
  with one line on stderr: `mcp-audit run: command not found: <cmd>`.

The launch gate (refuse unlocked or drifted servers), the runtime tool-list
check and the sandbox are later stories of EPIC-0009. Until they ship, `run`
enforces nothing.

On Windows the relay and exit codes work the same; process-group signalling
is POSIX-only.

## Launch overhead

`run` is on every wrapped server's launch path, so it does not import the
scanner, analyzers, registry, Typer or Rich (`tests/test_runtime_entry.py`
fails if it does).

Measured with `scripts/measure_run_overhead.py` (15 runs, median, a trivial
Python server that answers one JSON-RPC request):

| Install | Direct | Wrapped | Overhead |
|---|---|---|---|
| pip (`python -m mcp_audit._entry`), Linux x86-64, Python 3.12, 2026-11-11 | 22.5 ms | 69.0 ms | 46.5 ms |
| PyInstaller one-file binary (`mcp-audit-linux-x86_64.spec`), same machine | 17.8 ms | 617.1 ms | 599.3 ms (10 runs) |

The one-file binary unpacks itself to a temporary directory on every start,
which is almost all of its overhead. For wrapped servers, install with `pip`,
`pipx` or `uv tool` until the binary build changes.

The CI `runtime` job prints the same measurement for Linux and macOS on every
PR. To measure a PyInstaller binary, pass it as the wrapper:

```bash
python scripts/measure_run_overhead.py --wrapper ./dist/mcp-audit
```

## Testing against real servers

`tests/runtime/` launches the official `everything`, `filesystem`, `memory`
and `sequential-thinking` servers from npm (pinned versions) through `run` and
checks that the MCP handshake and `tools/list` result match a direct launch.
The tests download packages, so they are opt-in:

```bash
MCP_AUDIT_RUNTIME_TESTS=1 uv run pytest tests/runtime/ -v
```
