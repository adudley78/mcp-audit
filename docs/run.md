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

## Wrapping your clients' servers (Story 1.2)

You don't have to edit configs by hand:

```bash
mcp-audit wrap                      # dry run: every discovered config, diff + gate decision per server
mcp-audit wrap --mode enforce       # same, for enforce mode
mcp-audit wrap --apply              # write (backup next to each file), then restart the client
mcp-audit unwrap --apply            # put everything back
```

`--path FILE`, `--client NAME` and `--server NAME` narrow it down. `wrap`
writes the absolute path of the `mcp-audit` it runs from (GUI clients don't
inherit your shell's PATH); `--exe` overrides it.

Supported: Claude Code (`~/.claude.json`, `.mcp.json`), Cursor, Claude
Desktop, VS Code, Windsurf, Copilot CLI and Augment JSON configs, and any JSON
config named with `--path`. Not rewritten: configs with comments or trailing
commas, Codex (TOML), Gemini CLI, OpenCode, MCP gateway files, plugin and
subagent definitions, and remote (URL) servers.

A wrapped entry changes only `command` and `args`:

```json
"memory": {
  "command": "/Users/you/.local/bin/mcp-audit",
  "args": ["run", "--config", "/Users/you/project/.mcp.json", "--server", "memory",
           "--mode", "monitor", "--original-sha256", "…",
           "--", "npx", "-y", "@modelcontextprotocol/server-memory"],
  "env": {"MEMORY_FILE": "…"}
}
```

`--original-sha256` is the digest of the entry before wrapping; `unwrap`
uses it to confirm it restored exactly what was there, and says when the
entry was edited in between.

Everything else in mcp-audit reads a wrapped entry as the server it runs:
scans analyse the real package, and `lock`/`lock --verify` record and compare
the inner command, so wrapping a locked server isn't drift. Only an
mcp-audit executable named by absolute path or bare name counts as the
wrapper; a relative `./mcp-audit` in a cloned repository is analysed as the
command it is.

`check` adds a `Launch gate:` line once any server is wrapped, and a policy
with `runtime.require_wrap: true` makes `scan` report each unwrapped local
server as WRAP-001.

### What a refused server looks like in each client

When enforce mode refuses a server, `run` exits 78 after writing one line to
stderr, before the MCP handshake, so the client sees a server that failed to
start. When it withholds a tool, the server starts and the tool is missing
from its list.

**Claude Code** (2.1.322, checked 2026-11-11 with the `demo/run/` server, a
project `.mcp.json` wrapped in enforce mode):

| Case | `/mcp` panel | `claude mcp list` | Where the mcp-audit line is |
|---|---|---|---|
| Launch refused (LOCK-001) | `✘ calculator`; detail view `Status: ✘ failed`, with Reconnect / Disable | `✗ Failed to connect — CONNECTION_CLOSED: Connection closed` | `claude mcp list` writes it to `~/.cache/claude-cli-nodejs/<project>/mcp-logs-<server>/*.jsonl` as `Server stderr: mcp-audit run: refused: LOCK-001 …`. An interactive session shows it only when started with `claude --debug` (the panel says so). |
| Tool withheld (LOCK-008) | `⚠ calculator  no tools · connected` | `✓ Connected` | Same as above; the agent itself gets mcp-audit's JSON-RPC error if it calls the tool. |

Claude Code doesn't show the reason in its main view, so after wrapping in
enforce mode, check `/mcp` for `✘` or `no tools` and run `mcp-audit lock
--verify --connect` to see the finding. Cursor, Claude Desktop and VS Code are
not checked yet.

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
  doesn't show them) and the lock's top-level checksum (`lock --verify`
  reports tampering as LOCK-005). Live tool definitions are checked once the
  server runs (below).

`--mode enforce` without `--config` and `--server` is a usage error (exit 2):
there is nothing to check the launch against.

## Tool check (Story 1.4)

Once a server passes the gate, every `tools/list` answer it sends is compared
with the tool digests `mcp-audit lock --connect` recorded for it, the same
comparison `lock --verify --connect` makes:

| Finding | Meaning | Monitor | `--mode enforce` |
|---|---|---|---|
| `LOCK-006` | a tool was added | reported | tool withheld |
| `LOCK-007` | a tool's schema or annotations changed | reported | tool withheld |
| `LOCK-008` | only a tool's description or title changed | reported | tool withheld |
| `LOCK-009` | a locked tool is gone | reported | reported (nothing to withhold) |
| `RUN-003` | the lock has no tool record for this server | reported | every tool withheld |

"Withheld" means two things in enforce mode:

- The tool is removed from the `tools/list` result the client sees, so the
  agent never reads its description.
- A `tools/call` for it is answered by mcp-audit with a JSON-RPC error
  (`-32602`, `data.finding` names the ID) and never reaches the server. Enforce
  mode only lets a call through for a tool that matched the lock in a
  `tools/list` it has already checked, so a call made before the client has
  listed the tools is answered the same way (`data.finding` is `null`).

Each change is reported once, as one stderr line naming the finding, the
tools and the fix. Tool text is never quoted. A `tools/list` response is only
rewritten when something is withheld; otherwise its bytes are relayed exactly,
and monitor mode never changes a byte. `notifications/tools/list_changed`
passes through and the client's next `tools/list` is compared afresh, so a
server that changes back is released again. A paginated list is judged as a
whole: removed tools only once the last page has arrived.

`lock --connect` needs the `mcp` extra (`pip install 'mcp-audit-scanner[mcp]'`),
which the standalone binary doesn't include. Without a tool record, enforce
mode withholds every tool (RUN-003).

A lock written by `lock --connect` under `mcp` SDK 2.x digests only the
annotation keys the MCP spec defines; SDK 1.x digests every key. `run` accepts
a tool that matches either form, so an unchanged server never reports drift
whichever SDK wrote the lock (see `GAPS.md`).

A `tools` section that fails its own checksum is RUN-002 at the gate: enforce
mode refuses to start the server.

### Poisoned tool text

Every tool that passes the lock comparison also goes through the same
POISON-* checks `scan --connect` runs, over the text the server actually sent.
A tool whose worst match is at or above `runtime.poison_threshold` is reported
in monitor mode and withheld in enforce mode, under its POISON-* ID. This
catches a poisoned tool that was approved into the lock.

```yaml
# .mcp-audit-policy.yml (next to the MCP config, its git root, or the user policy)
runtime:
  poison_threshold: critical   # off | critical | high | medium | low | info
```

The default is `critical`. On the 100 most-downloaded MCP servers on npm
(2026-10-29), POISON-* raised no CRITICAL findings, and both HIGH findings were
false positives (`docs/research/2026-10-29-top100-npm/README.md`), so a lower
threshold will withhold legitimate tools; raise it only after reading what it
catches. `run --policy FILE` names a policy explicitly; otherwise it's looked
for next to `--config`, then in that directory's git root, then in the user
policy. An invalid policy is reported once and the default applies.

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

Pinned launch, the event log and the sandbox are later stories of EPIC-0009.

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

The launch gate and tool check add 43.6 ms on top of the relay on the same
machine (`--gate`, enforce mode, a matching lock entry). The gate itself
imports only the standard library; most of the cost is the poisoning check
loading its analyzer and the policy on a background thread while the server
starts.

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
