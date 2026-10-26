# mcp-audit Demo Environment

This directory contains intentionally vulnerable MCP server configurations for
testing `mcp-audit` locally. It simulates a developer machine with three client
configs — some clean, some suspicious, some actively malicious.

## What's in the configs

### `configs/claude_desktop_config.json`
Three servers mimicking a typical Claude Desktop setup:
- `filesystem` — legitimate file access server
- `fetch` — legitimate HTTP fetch server
- `github` — GitHub server with a **real-looking GitHub token** hardcoded in env

Expected findings: credential exposure (GitHub token), transport warnings (npx
runtime fetching), toxic flow TOXIC-001 (filesystem + fetch/github = file read
+ network exfiltration path).

### `configs/cursor_mcp.json`
Three servers demonstrating active attacks and supply chain risk:
- `evil-calculator` — looks like a math tool; its `add_numbers` description
  contains **SSH key exfiltration instructions** hidden inside `<IMPORTANT>` tags
- `shell-exec` — shell execution server (legitimate use case, high risk in combination)
- `typosquat-server` — installs `@modelcontextprotocol/server-filesytem` (note
  the missing `s`) — one character from the real package name

Expected findings: CRITICAL poisoning (SSH exfiltration + XML injection),
CRITICAL supply chain (edit-distance-1 typosquat), toxic flow TOXIC-006
(shell-exec + any network server = critical exfiltration path).

### `configs/vscode_mcp.json`
Two servers in VS Code format (`"servers"` root key):
- `remote-api` — connects via **unencrypted HTTP** to a suspicious external host
  with an Anthropic API key in env
- `database` — Postgres server with **database URL containing plaintext credentials**

Expected findings: transport (unencrypted SSE), credential exposure (Anthropic
key, database URL with password), toxic flow TOXIC-005 (database + network).
The `database` server also gets SC-007 (MEDIUM) and SC-008 (CRITICAL): it launches
`npx -y mcp-server-postgres`, an unscoped twin of `@modelcontextprotocol/server-postgres`
that OSV has listed as malicious since June 2026 (MAL-2026-5481), so the demo now
shows a real known-bad package, not a constructed one.

## Setup

The demo uses the installed `mcp-audit` CLI. If you're working inside the
development environment:

```bash
cd /path/to/mcp-audit
uv sync --all-extras
```

Or if installed globally:

```bash
pip install mcp-audit
```

## Run the demo

```bash
bash demo/run_demo.sh
```

The script runs eight commands in sequence:

| Step | Command | Expected result |
|------|---------|-----------------|
| 1 | `discover` | Lists 3 config files, 8 servers |
| 2 | `scan` (terminal) | 70 findings on a first scan (rug-pull records 8 first-scan INFO findings); 62 once rug-pull state exists |
| 3 | `pin` | Records baseline hashes for all 8 servers |
| 4 | `diff` | Reports no changes (nothing changed since pin) |
| 5 | `scan --format json` | Writes `output/results.json` |
| 6 | `scan --format sarif` | Writes `output/results.sarif` |
| 7 | `scan --format nucleus` | Writes `output/results.nucleus.json` |
| 8 | `scan --ci --severity-threshold HIGH` | CI mode, HIGH+ only |

Generated files land in `demo/output/` (gitignored).

## Try `mcp-audit lock`

`demo/lock/` is a separate, smaller fixture — two servers
(`@modelcontextprotocol/server-filesystem`, `@modelcontextprotocol/server-github`)
under `demo/lock/.cursor/mcp.json` — built specifically to reproduce the
`lock` → drift → `lock --verify` → `lock --accept` sequence shown in the
main [README.md](../README.md) first screen. Run it directly:

```bash
bash demo/lock/run.sh
```

It requires network (package version resolution against the npm registry),
asserts every exit code along the way (a failed `lock --verify` after a
one-line config edit, exit 1 with exactly one `LOCK-001`; a clean `--verify`
after `--accept`, exit 0), and restores the fixture and deletes the
generated `mcp-lock.json` when it finishes. See [docs/lock.md](../docs/lock.md)
for the full `lock` reference.

## Run individual commands

```bash
# Scan all three configs at once
mcp-audit scan --path demo/configs

# Only show CRITICAL findings
mcp-audit scan --path demo/configs --severity-threshold CRITICAL

# Scan a single config
mcp-audit scan --path demo/configs/cursor_mcp.json

# Export for GitHub Security tab
mcp-audit scan --path demo/configs --format sarif -o demo/output/results.sarif

# Pin the current state as trusted baseline
mcp-audit pin --path demo/configs

# Show what changed since last pin
mcp-audit diff --path demo/configs
```

## Expected finding summary

Counts are for `mcp-audit scan --path demo/configs` (all three configs together).
First-scan numbers include rug-pull INFO findings; second and subsequent scans
drop rug-pull to 0 once baselines are established.

| Analyzer | Finding IDs | First-scan count |
|----------|-------------|-----------------|
| Poisoning | POISON-001, 010, 012, 030 | 4 |
| Credentials | CRED-001 | 3 |
| Transport | TRANSPORT-001, 003 | 5 |
| Supply chain | SC-001, SC-004, SC-007, SC-008 | 4 |
| Auth | AUTH-001 | 1 |
| Config hygiene | CFHYG-001 (8, one per server, because a fresh checkout leaves the files world-readable), CFHYG-003 (3) | 11 |
| Rug-pull | RUGPULL-000 (INFO, first scan only) | 8 |
| Community rules | COMM-004, 010, 013, 022, 024, 031, 034 | 20 |
| Toxic flow | TOXIC-001, 004, 005, 006, 007, INTEG-001 | 14 |

**Total on first scan: 70 findings across all demo configs** (62 on subsequent
runs once rug-pull baselines are established; counted 2026-10-26). Cross-config
toxic-flow pairs add extra findings when all configs are scanned together vs.
individually — notably the two TOXIC-005 database+network pairs that only appear
in a full 3-config scan.
