# Live MCP Server Connection (`--connect`)

`credenzo scan --connect` performs a live MCP protocol handshake against each
discovered server, enumerates the tools/resources/prompts it actually exposes at
runtime, and runs the poisoning analyzer against that live data.  This surfaces
prompt-injection payloads hidden inside tool descriptions that look clean in the
static config file.

**Requires the optional `mcp` extra:**

```bash
pip install 'credenzo[mcp]'
```

The GitHub Release standalone binary does **not** bundle the MCP SDK — `mcp`
is excluded from the PyInstaller specs the same way `sigstore` is. Running
`--connect` from that binary prints an install hint rather than connecting.
Use a pip or uv install with the `[mcp]` extra for live analysis.

---

## Basic usage

```bash
# Connect to all auto-discovered servers and analyze live tool descriptions.
credenzo scan --connect

# Connect to servers in a specific config file only.
credenzo scan --connect --path ~/.config/Claude/claude_desktop_config.json
```

---

## Stderr suppression

MCP servers often print startup diagnostics, version banners, or debug logs to
stderr.  Without suppression these messages appear interleaved with Credenzo's
own Rich output, which can alarm users who don't know the output originates from
the server process.

As of v0.6.0, server stderr is **always captured** and kept out of the terminal.
Use `--verbose` to see what the server wrote:

```bash
# Stderr is captured silently — terminal stays clean.
credenzo scan --connect

# Print captured server stderr under a "Server output" header.
credenzo scan --connect --verbose
```

Captured stderr is also available in JSON output under the `server_logs` array:

```bash
credenzo scan --connect --format json | jq '.server_logs'
```

**When a server fails to start** (STORY-0105), its stderr is still read, and the
error names the real cause rather than the MCP SDK's wrapper text ("unhandled errors
in a TaskGroup (1 sub-exception)"): the first underlying exception, followed by the
last line the server wrote, in the form
`[connect] stripe: Enumeration failed: <ExceptionType>: <message> (server stderr:
Error: STRIPE_SECRET_KEY not set)`.  Server text is redacted before it is shown or
saved: known credential formats, the values of the server's own `env` entries (8
characters or longer), and the password in any `scheme://user:pass@host`.  At most
the last 64 KiB of stderr is kept, and the quoted line is cut at 300 characters.

---

## Authentication (`--connect-token`)

SSE and Streamable-HTTP MCP servers often require an API key or bearer token.
Pass it with `--connect-token`:

```bash
credenzo scan --connect --connect-token "$MY_API_TOKEN"
```

The token is sent as `Authorization: Bearer <token>` on every HTTP request.

**Security notes:**

- The token is **never stored** in any config file, baseline, or scan result.
- The token does **not** appear in JSON, SARIF, or terminal output.
- For stdio servers, `--connect-token` is silently ignored (stdio servers do not
  use HTTP auth).

### Error messages

| Situation | Credenzo output |
|---|---|
| Server returns `401 Unauthorized` | `Connection to <url> failed: 401 Unauthorized — use --connect-token to provide credentials` |
| Server returns `403 Forbidden` | `Connection to <url> failed: 403 Forbidden — the provided token may lack the required permissions` |
| No auth needed, no token given | Normal enumeration, unchanged from prior behavior |
| Token passed to a stdio server | Token silently ignored; enumeration proceeds normally |

---

## The name Credenzo gives the server (`--identify-as`, STORY-0177)

A server reads the client's name in the MCP handshake (`clientInfo.name`). A
hostile server can list one set of tools for a scanner and another for the
agent. The MCP Python SDK's default name is `mcp` (version `0.1.0`), which no
agent sends. Until STORY-0177 Credenzo connected with that default.

- A server from a Claude Code config (`~/.claude.json`, `.mcp.json`, local
  scope) is now asked as Claude Code. The identity is the one a live Claude
  Code 2.1.328 session sent on 2026-11-19: name `claude-code`, title
  `Claude Code`, version `2.1.328`.
- The rule goes by the client that Credenzo found the file for. A file named
  with `scan --path` has the client `custom`, also when it is a `.mcp.json`:
  it keeps the SDK default. Use `--identify-as claude-code@2.1.328` there.
- A server from any other client's config keeps the SDK default. The names
  that other clients send are not verified here. A wrong guess would make
  `lock --connect` record tools that the real client never sees.
- `--identify-as NAME[@VERSION]` (with `scan --connect` or `lock --connect`)
  sets the name for every server of that run.

`lock --connect` records what the named client sees. After this change, a
server that lists other tools for Claude Code than for `mcp` shows as changed
on the next `lock --verify --connect`. That difference is real; review it.

Limits: Credenzo does not copy a client's declared capabilities (Claude Code
declares `elicitation` and `roots`), its protocol version or its network
address. A server can tell clients apart by those. Credenzo does not connect
two times under two names to compare the answers.

## Supported transports

| Transport | `--connect` support | `--connect-token` |
|---|---|---|
| `stdio` | ✓ | Ignored (not HTTP) |
| `sse` | ✓ | ✓ |
| `streamable-http` | ✓ | ✓ |
| `unknown` | ✗ | N/A |

---

## Example: npx-based stdio server

```bash
# No token needed; stderr is captured automatically.
credenzo scan --connect \
  --path ~/.config/Claude/claude_desktop_config.json

# See what the server logged during startup.
credenzo scan --connect --verbose \
  --path ~/.config/Claude/claude_desktop_config.json
```

## Example: SSE server with Bearer auth

```bash
# Pass the token; connection succeeds and tools are enumerated.
credenzo scan --connect \
  --connect-token "$MCP_API_TOKEN" \
  --path my-sse-config.json
```

---

## Out of scope

The following auth methods are **not** currently supported:

- OAuth 2.0 / OIDC flows
- mTLS client certificates
- Cookie-based auth
- Arbitrary custom headers (`--connect-header` — planned for a future release)

For non-Bearer schemes, use `--connect-header` once it is available, or pre-negotiate
a bearer token through your identity provider and pass it via `--connect-token`.

---

## Troubleshooting

**`MCP SDK not installed`** — Run `pip install 'credenzo[mcp]'`. The standalone
binary does not include the SDK; switch to a pip/uv install with the `[mcp]` extra.

**`MCP SDK is not bundled in the standalone binary`** — Same cause, different
wording: you ran the GitHub Release binary. Live `--connect` needs a pip or
uv install of credenzo with the mcp extra.

**Connection timed out** — The server did not complete the handshake within the
default 10 s window.  Check that the server process starts correctly with
`credenzo scan --connect --verbose`.

**`401 Unauthorized`** — Add `--connect-token <token>`.

**`403 Forbidden`** — Your token is valid but lacks the required permissions.
Check the server's access-control configuration.
