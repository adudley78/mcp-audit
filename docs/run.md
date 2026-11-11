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

## Launch gate (Story 1.3)

Give `run` the server's config file and name, and it checks the launch
against the nearest `mcp-lock.json` before starting the server:

```json
{
  "mcpServers": {
    "memory": {
      "command": "mcp-audit",
      "args": ["run", "--config", "/path/to/project/.mcp.json", "--server", "memory",
               "--mode", "enforce", "--", "npx", "-y", "@modelcontextprotocol/server-memory"]
    }
  }
}
```

| Result | Monitor (default) | `--mode enforce` |
|---|---|---|
| Launch matches its lock entry | starts, says nothing | starts, says nothing |
| `LOCK-002` server not in the lock | one stderr line, starts | refuses, exit 78 |
| `LOCK-001` launch differs from the approved one | one stderr line, starts | refuses, exit 78 |
| `RUN-001` no lock covers the config | one stderr line, starts | refuses, exit 78 |
| `RUN-002` lock unreadable, invalid or too new | one stderr line, starts | refuses, exit 78 |

The refusal is one line naming the finding and the fix, for example:

```
mcp-audit run: refused: LOCK-002 server 'memory' is not in mcp-lock.json. Fix: review it, then run `mcp-audit lock` to approve it
```

How it compares:

- It checks the command **actually being launched** (everything after
  `--`), not the config file, so a rewritten command is caught too.
- Matching uses the same key as `lock --verify`: the config file's path
  relative to the lock's directory, plus the server name.
- `${VAR}`, `${VAR:-default}` and `${env:VAR}` in the locked arguments match
  whatever the client substituted, within that one argument only.
- A credential the lock redacted compares the way `lock --verify` compares
  it, so changing only a credential's value is not drift (see `GAPS.md`).
- Not checked at launch: environment-variable and header names (the launch
  doesn't show them), the lock's own checksum (`lock --verify` reports
  tampering as LOCK-005), and live tool definitions (Story 1.4).

`--mode enforce` without `--config` and `--server` is a usage error (exit 2):
there is nothing to check the launch against.

## The relay (Story 1.1)

`run` changes nothing the client and server send each other:

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

The runtime tool-list check, pinned launch, event log and sandbox are later
stories of EPIC-0009.

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

The launch gate adds 9.9 ms on top of the relay on the same machine
(`--gate`, enforce mode, a matching lock entry): its common path imports
only the standard library.

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
