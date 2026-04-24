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
| 2 | `scan` (terminal) | 34 findings across all 7 analyzers (first scan adds rug-pull INFO; subsequent scans drop to ~26 after baselines are set) |
| 3 | `pin` | Records baseline hashes for all 8 servers |
| 4 | `diff` | Reports no changes (nothing changed since pin) |
| 5 | `scan --format json` | Writes `output/results.json` |
| 6 | `scan --format sarif` | Writes `output/results.sarif` |
| 7 | `scan --format nucleus` | Writes `output/results.nucleus.json` |
| 8 | `scan --ci --severity-threshold HIGH` | CI mode, HIGH+ only |

Generated files land in `demo/output/` (gitignored).

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
| Transport | TRANSPORT-001, 003 | 4 |
| Supply chain | SC-001 | 1 |
| Rug-pull | RUGPULL-002 (INFO, first scan only) | 8 |
| Community rules | COMM-004, COMM-010 | 10 |
| Toxic flow | TOXIC-001, 004, 005, 006, 007 | 12 |

**Total on first scan: 34 findings across all demo configs** (drops to ~26 on
subsequent runs once rug-pull baselines are established; cross-config toxic-flow
pairs add extra findings when all configs are scanned together vs. individually — notably the two TOXIC-005 database+network pairs that only appear in a full 3-config scan).
