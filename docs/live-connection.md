# Live MCP Server Connection (`--connect`)

`mcp-audit scan --connect` performs a live MCP protocol handshake against each
discovered server, enumerates the tools/resources/prompts it actually exposes at
runtime, and runs the poisoning analyzer against that live data.  This surfaces
prompt-injection payloads hidden inside tool descriptions that look clean in the
static config file.

**Requires the optional `mcp` extra:**

```bash
pip install 'mcp-audit[mcp]'
# or
pip install 'mcp-audit-scanner[mcp]'
```

---

## Basic usage

```bash
# Connect to all auto-discovered servers and analyze live tool descriptions.
mcp-audit scan --connect

# Connect to servers in a specific config file only.
mcp-audit scan --connect --path ~/.config/Claude/claude_desktop_config.json
```

---

## Stderr suppression

MCP servers often print startup diagnostics, version banners, or debug logs to
stderr.  Without suppression these messages appear interleaved with mcp-audit's
own Rich output, which can alarm users who don't know the output originates from
the server process.

As of v0.6.0, server stderr is **always captured** and kept out of the terminal.
Use `--verbose` to see what the server wrote:

```bash
# Stderr is captured silently — terminal stays clean.
mcp-audit scan --connect

# Print captured server stderr under a "Server output" header.
mcp-audit scan --connect --verbose
```

Captured stderr is also available in JSON output under the `server_logs` array:

```bash
mcp-audit scan --connect --format json | jq '.server_logs'
```

---

## Authentication (`--connect-token`)

SSE and Streamable-HTTP MCP servers often require an API key or bearer token.
Pass it with `--connect-token`:

```bash
mcp-audit scan --connect --connect-token "$MY_API_TOKEN"
```

The token is sent as `Authorization: Bearer <token>` on every HTTP request.

**Security notes:**

- The token is **never stored** in any config file, baseline, or scan result.
- The token does **not** appear in JSON, SARIF, or terminal output.
- For stdio servers, `--connect-token` is silently ignored (stdio servers do not
  use HTTP auth).

### Error messages

| Situation | mcp-audit output |
|---|---|
| Server returns `401 Unauthorized` | `Connection to <url> failed: 401 Unauthorized — use --connect-token to provide credentials` |
| Server returns `403 Forbidden` | `Connection to <url> failed: 403 Forbidden — the provided token may lack the required permissions` |
| No auth needed, no token given | Normal enumeration, unchanged from prior behavior |
| Token passed to a stdio server | Token silently ignored; enumeration proceeds normally |

---

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
mcp-audit scan --connect \
  --path ~/.config/Claude/claude_desktop_config.json

# See what the server logged during startup.
mcp-audit scan --connect --verbose \
  --path ~/.config/Claude/claude_desktop_config.json
```

## Example: SSE server with Bearer auth

```bash
# Pass the token; connection succeeds and tools are enumerated.
mcp-audit scan --connect \
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

**`MCP SDK not installed`** — Run `pip install 'mcp-audit[mcp]'`.

**Connection timed out** — The server did not complete the handshake within the
default 10 s window.  Check that the server process starts correctly with
`mcp-audit scan --connect --verbose`.

**`401 Unauthorized`** — Add `--connect-token <token>`.

**`403 Forbidden`** — Your token is valid but lacks the required permissions.
Check the server's access-control configuration.
