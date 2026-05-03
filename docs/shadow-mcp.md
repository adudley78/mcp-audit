# Shadow MCP Servers — `mcp-audit shadow`

> Find your shadow MCP servers — every one on every developer's machine,
> classified, scored, and event-logged. OWASP MCP09. Open source. No agent.
> No telemetry.

## What is a Shadow MCP Server?

**OWASP MCP Top 10 — MCP09: Shadow MCP Servers** describes the risk posed by
MCP servers that are installed and active on a developer's machine or in a CI
environment without the knowledge or approval of the organisation's security
team. Shadow servers are a direct analogue to _shadow IT_ — unsanctioned
software that bypasses security controls by operating outside the visibility of
approved tooling.

Because MCP servers have access to files, databases, shells, secret stores, and
external networks, a single undiscovered shadow server can give an attacker or
a malicious prompt-injected agent everything it needs to exfiltrate data or
execute arbitrary code.

The `mcp-audit shadow` command gives security teams one opinionated workflow to
answer the question every CISO needs answered:

> _What MCP servers are running on our developers' machines, and are any of them
> ones we never approved?_

---

## Quick Start

```bash
# Single sweep — all shadow, no allowlist
mcp-audit shadow

# JSON output, pipeline-friendly
mcp-audit shadow --format json | jq '.[] | select(.classification == "shadow")'

# With an allowlist of approved servers
mcp-audit shadow --allowlist .mcp-audit-allowlist.yml

# Continuous daemon mode — emits events on config change
mcp-audit shadow --continuous
```

---

## How It Works

On each invocation `mcp-audit shadow`:

1. **Sweeps** every known MCP config location on the host (Claude Desktop,
   Cursor, VS Code, Windsurf, Augment, Claude Code, Copilot CLI, project-local
   `.mcp.json`, plus any `--path` you specify).
2. **De-duplicates** servers that appear in multiple client configs by
   `(client, name)` key.
3. **Tags** each server with capability labels (`file_read`, `network_out`,
   `database`, `shell_exec`, …) using the curated known-server registry and
   keyword heuristics from `analyzers/toxic_flow.py`.
4. **Scores** risk for each server — checks for single-server toxic capability
   pairs (e.g. `database + network_out`) using the same severity rubric as the
   `scan` command.
5. **Classifies** each server as `sanctioned` (matches your allowlist) or
   `shadow` (does not). The known-server registry is a _trust signal_, not an
   allowlist — registry membership alone does not promote a server to
   sanctioned.
6. **Persists** `first_seen` / `last_seen` timestamps to
   `<user-config-dir>/mcp-audit/shadow/state.json` so event history survives
   across invocations.
7. **Emits** results to stdout (Rich table or JSON lines).

---

## Allowlist Format

The allowlist is a YAML file that lists servers your organisation has explicitly
approved. Create `.mcp-audit-allowlist.yml` in your repo root or home config
directory:

```yaml
# .mcp-audit-allowlist.yml

sanctioned_servers:
  # Match by npm package name (in npx args)
  - "@modelcontextprotocol/server-filesystem"
  - "@modelcontextprotocol/server-github"

  # Match by server name
  - name: "internal-postgres"

  # Match by name AND command (both must match)
  - name: "internal-postgres"
    command: "/opt/internal/mcp/postgres-server"

sanctioned_capabilities: []  # informational only — does not affect classification
```

### Allowlist Resolution Order

When `--allowlist` is not given, `mcp-audit shadow` auto-discovers the allowlist
in this order:

1. `.mcp-audit-allowlist.yml` / `.mcp-audit-allowlist.yaml` / `mcp-audit-allowlist.yml`
   in the **current working directory**.
2. Same filenames in the **git repo root** (walks up from cwd).
3. `<user-config-dir>/mcp-audit/allowlist.yml` (macOS:
   `~/Library/Application Support/mcp-audit/allowlist.yml`).
4. No allowlist found → every server is `shadow`.

### Default: All Shadow

When no allowlist is configured, every server is classified as `shadow`. This
is intentional — the "everything is shadow until you say otherwise" default
gives CISOs full visibility on first run without any false sense of safety.

### Allowlist Entry Matching

A string entry matches a server when the string equals (case-insensitively):
- The server's `name` field
- The server's `command` field
- Any argument in the server's `args` list (catches npm package names in `npx`
  invocations)

A structured entry (`name:` / `command:`) matches when all non-`null` fields
match. An entry with both fields set acts as an AND condition.

---

## JSON Output Schema

With `--format json`, each record in the output array has these fields:

| Field | Type | Description |
|-------|------|-------------|
| `host` | string | Hostname from `platform.node()` |
| `client` | string | MCP client (e.g. `claude-desktop`, `cursor`) |
| `server_name` | string | Name key from the MCP config |
| `package_name` | string\|null | npm/pip package name if determinable |
| `classification` | `sanctioned`\|`shadow` | Allowlist result |
| `risk_level` | `INFO`\|`LOW`\|`MEDIUM`\|`HIGH`\|`CRITICAL`\|`UNKNOWN` | Capability risk |
| `capability_tags` | string[] | Detected capabilities |
| `findings` | string[] | Finding IDs (reserved for future use) |
| `owasp_mcp_top_10` | string[] | Always `["MCP09"]` |
| `first_seen` | ISO 8601 datetime | When this server was first observed |
| `last_seen` | ISO 8601 datetime | When this server was last observed |

### Risk Levels

Risk is scored per-server against single-server toxic flow pairs:

| Risk | Example |
|------|---------|
| `CRITICAL` | `shell_exec + network_out`, `secrets + network_out` |
| `HIGH` | `database + network_out`, `file_read + network_out` |
| `MEDIUM` | `git + network_out` |
| `LOW` | Capabilities present, no toxic pair |
| `INFO` | Registry-verified server with no capabilities |
| `UNKNOWN` | Registry entry with `capabilities: null` or no data |

When `UNKNOWN` is returned, the rationale includes a hint to file an issue
against the registry to request capability enrichment.

---

## Continuous Mode

`--continuous` turns `mcp-audit shadow` into a long-running daemon that emits
structured events whenever the underlying MCP config files change:

```bash
mcp-audit shadow --continuous --format json
```

### Event Types

| Event type | When emitted |
|------------|-------------|
| `new_shadow_server` | A server appears that was not seen before |
| `server_drift` | A tracked server's config changed (command, args, env, tools) |
| `server_removed` | A tracked server disappeared from all configs |

All events carry `owasp_mcp_top_10: ["MCP09"]` and an ISO 8601 timestamp.

### Writing Events to a File

```bash
mcp-audit shadow --continuous --format json --output-file /var/log/mcp-shadow.jsonl
```

### Wiring to syslog / SIEM

Pipe stdout directly to a syslog forwarder:

```bash
mcp-audit shadow --continuous --format json | logger -t mcp-audit-shadow
```

Or use the built-in syslog sink (uses `SysLogHandler` — `/dev/log` on Linux,
`localhost:514` on macOS/Windows) by setting `sink="syslog"` programmatically
via the `shadow.events.emit()` API.

### launchd (macOS)

Create `~/Library/LaunchAgents/com.mcp-audit.shadow.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.mcp-audit.shadow</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/mcp-audit</string>
    <string>shadow</string>
    <string>--continuous</string>
    <string>--format</string>
    <string>json</string>
    <string>--output-file</string>
    <string>/usr/local/var/log/mcp-shadow.jsonl</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
</dict>
</plist>
```

Load it:
```bash
launchctl load ~/Library/LaunchAgents/com.mcp-audit.shadow.plist
```

### systemd (Linux)

```ini
# /etc/systemd/system/mcp-audit-shadow.service
[Unit]
Description=mcp-audit shadow — continuous MCP server detection
After=network.target

[Service]
ExecStart=/usr/local/bin/mcp-audit shadow --continuous --format json \
  --output-file /var/log/mcp-shadow.jsonl
Restart=on-failure
User=mcp-audit

[Install]
WantedBy=multi-user.target
```

Enable:
```bash
systemctl enable --now mcp-audit-shadow
```

---

## OWASP MCP09 Reference

This command implements detection for
[OWASP MCP Top 10 — MCP09: Shadow MCP Servers](https://owasp.org/www-project-mcp-top-10/)
(2025 beta).

Every server record and every continuous-mode event carries
`owasp_mcp_top_10: ["MCP09"]` so downstream SIEM rules can pivot on the
standard category code without custom parsing.

---

## Architecture Notes

- **No network calls.** `shadow` runs fully offline by default; capability
  lookup uses the bundled registry. The user-cached registry update path
  (`mcp-audit update-registry`) is unchanged.
- **Allowlist ≠ governance policy.** The allowlist is specific to `shadow` and
  is not coupled to the governance engine's `approved_servers` list (see
  [governance.md](governance.md)). A future story may unify them.
- **State permissions.** Shadow state is stored with `0o700` directory /
  `0o600` file permissions, matching the baseline and rug-pull conventions.
- **Continuous mode internals.** `--continuous` reuses `watcher.py`'s
  `ConfigWatcher` and `_McpConfigEventHandler._fire()`. The `_scan_lock`
  serialisation invariants that prevent concurrent scans from racing on state
  files are preserved — the shadow callback is passed directly as the watcher
  callback and executes within the lock.
