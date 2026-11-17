# Credenzo Usage Guide

A practical guide to getting started with Credenzo and using it in common workflows.

---

## Installation

**Standalone binary (no Python required):**

Download the binary for your platform from the [GitHub Releases](https://github.com/adudley78/credenzo/releases) page and place it on your PATH.

```bash
# macOS (Apple Silicon)
curl -L https://github.com/adudley78/credenzo/releases/latest/download/mcp-audit-macos-arm64 -o mcp-audit
chmod +x mcp-audit
sudo mv mcp-audit /usr/local/bin/

# Linux (x86_64)
curl -L https://github.com/adudley78/credenzo/releases/latest/download/mcp-audit-linux-x86_64 -o mcp-audit
chmod +x mcp-audit
sudo mv mcp-audit /usr/local/bin/
```

**From PyPI (Python 3.11+ required):**

```bash
pip install credenzo
```

**From source (for contributors):**

```bash
git clone https://github.com/adudley78/credenzo
cd mcp-audit
pip install uv
uv pip install -e ".[dev]"
```

---

## Quick Start

Run your first scan in 30 seconds. Credenzo will discover all MCP configs on your machine automatically.

```bash
credenzo scan
```

That's it. Credenzo searches your home directory for MCP configurations across all supported AI coding clients — Claude Desktop, Cursor, VS Code, Windsurf, Claude Code, Copilot CLI, Augment, Codex and Gemini CLI — and prints a findings report with a letter grade.

---

## Supported Clients

Credenzo automatically discovers MCP server configurations for:

| Client | Config location |
|--------|----------------|
| Claude Desktop | `~/.config/Claude/claude_desktop_config.json` (Linux/Windows) / `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) |
| Cursor | `~/.cursor/mcp.json` |
| VS Code | `~/.vscode/mcp.json` (uses `"servers"` key instead of `"mcpServers"`) |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |
| Claude Code | `~/.claude/claude_mcp_config.json` |
| Copilot CLI | `~/.config/github-copilot/mcp.json` |
| Augment | `~/.augment/mcp_config.json` |
| Codex | `$CODEX_HOME/config.toml` (default `~/.codex/config.toml`), project `.codex/config.toml` (TOML) |
| Gemini CLI | `~/.gemini/settings.json`, project `.gemini/settings.json` |

The full table, with project files and how each one is read, is in [clients.md](clients.md).

---

## Understanding the Output

After a scan, Credenzo prints:

- **Findings** — security issues organized by severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)
- **Registry stats** — how many servers were recognized from the known-server registry
- **Scan score** — an A–F letter grade with a 0–100 numeric score

Exit codes:
- `0` — clean, no findings
- `1` — findings were detected
- `2` — error (bad config path, malformed file, etc.)

---

## Common Workflows

### Scan and get a JSON report

```bash
credenzo scan --format json --output-file results.json
```

Useful for piping into other tools or storing scan history.

### Scan and upload to GitHub Security tab (SARIF)

```bash
credenzo scan --format sarif --output-file results.sarif
```

Upload `results.sarif` to GitHub via the Security tab, or use the [Credenzo GitHub Action](#github-action) to do this automatically in CI.

### Only show HIGH and CRITICAL findings

```bash
credenzo scan --severity-threshold HIGH
```

### Discover configs without scanning

```bash
credenzo discover
```

Shows all MCP config files found on the machine without running any analysis — useful for confirming discovery before a full scan.

### Pin server hashes for supply chain tracking

```bash
credenzo pin
```

Captures the current hashes of all configured MCP servers. Each later `credenzo scan` compares every entry with that state and flags a changed one as RUGPULL-001.

### Compare two configuration states

```bash
credenzo diff main HEAD          # git refs, directories, or scan JSON files
```

MCP-aware diff for PR review and CI gates: added, removed and changed servers, capabilities, endpoints and credentials, with a risk level. See [diff.md](diff.md).

### View the interactive attack graph dashboard

```bash
credenzo dashboard
# With custom rules:
credenzo dashboard --rules-dir /path/to/rules
```

Opens an interactive D3.js visualization of cross-server attack paths in your browser.
Pass `--rules-dir` to apply additional YAML detection rules on the dashboard scan (community rules always run in addition).

### Watch for config changes in real time

```bash
credenzo watch
# With custom rules:
credenzo watch --rules-dir /path/to/rules
```

Monitors MCP config files for changes and re-runs the scan automatically when a config is modified.
Pass `--rules-dir` to apply additional YAML detection rules on every re-scan (community rules always run in addition).

---

## Baseline Snapshots and Drift Detection

Baselines let you capture a known-good state and be alerted when anything changes.

```bash
# Save the current scan state as a named baseline
credenzo baseline save pre-deploy

# List all saved baselines
credenzo baseline list

# Compare the current scan to a baseline
credenzo scan --baseline pre-deploy

# Compare to the most recently saved baseline
credenzo scan --baseline latest

# Export a baseline to JSON for archiving
credenzo baseline export pre-deploy --output-file baseline-pre-deploy.json

# Delete a baseline you no longer need
credenzo baseline delete pre-deploy
```

Drift findings appear in all output formats with a `drift` category and severity mapping.

---

## Supply Chain Verification

Verify that your MCP servers match known-good hashes from the Credenzo registry.

```bash
# Verify hashes for all servers during a scan
credenzo scan --verify-hashes

# Run verification as a standalone command
credenzo verify
```

Network access is required to fetch npm tarballs and PyPI digests.

> **Incompatibility:** `--verify-hashes` cannot be combined with `--offline`. Because hash verification must download package tarballs from npm and PyPI, using both flags together will produce an error (exit code 2) and the scan will not run. Use `--offline-registry` instead if you want to skip registry cache updates while still allowing hash verification network calls.

---

## SAST Analysis

Run Credenzo's 37 MCP-specific Semgrep rules against server source code. Requires [Semgrep](https://semgrep.dev) to be installed separately (`pip install semgrep`).

```bash
# Run SAST against a local MCP server repo
credenzo sast ./my-mcp-server/

# Include SAST in a full scan
credenzo scan --sast ./my-mcp-server/
```

SAST findings flow through all output formats (terminal, JSON, SARIF, HTML).

---

## Governance Policies

Governance policies let you define organization-wide rules for MCP server configurations.

**Running a policy:**

```bash
credenzo scan --policy ./policies/strict.yml
```

**Generating a starter policy:**

```bash
credenzo policy init --output starter.yml
```

**Validating a policy file:**

```bash
credenzo policy validate ./my-policy.yml
```

**Checking all configs against a policy without a full scan:**

```bash
credenzo policy check --policy ./my-policy.yml
```

Governance findings appear as a yellow "Policy Violations" panel in the terminal and are included in JSON, SARIF, and HTML output.

Policy files support five check types: approved server allowlist/denylist (glob patterns), scan score threshold, transport policy, registry membership enforcement, and finding count tolerance. Policies can include per-client overrides.

See `docs/governance.md` for the full policy schema reference.

---

## IDE Extension Scanning

Scan VS Code and Cursor extensions for security risks — dangerous permission combinations, wildcard activation, unknown publishers, sideloaded extensions, and known vulnerabilities.

```bash
# Inventory all installed extensions
credenzo extensions discover

# Full security analysis of installed extensions
credenzo extensions scan

# Include extension analysis in a full scan
credenzo scan --include-extensions
```

---

## Known-Server Registry

Credenzo ships with a curated registry of 64 known MCP servers. The registry is used for typosquatting detection and supply chain hash verification.

```bash
# Update the registry to the latest version
credenzo update-registry

# Use a custom registry file
credenzo scan --registry ./my-registry.json

# Scan without any network registry updates
credenzo scan --offline-registry
```

---

## Custom Detection Rules

The bundled community detection rules (`rules/community/`) run automatically for all users. You can also write your own rules in YAML.

```bash
# Validate a custom rule file
credenzo rule validate ./my-rule.yml

# Test a rule against a fixture config
credenzo rule test ./my-rule.yml --against ./test-config.json

# Run a scan with a custom rules directory
credenzo scan --rules-dir ./custom-rules/
```

See `docs/writing-rules.md` for the rule format reference.

---

## GitHub Action

Add Credenzo to your CI pipeline with one step. On every push, Credenzo scans for MCP config security issues and uploads findings to the GitHub Security tab.

```yaml
# .github/workflows/mcp-security.yml
name: MCP Security Scan

on: [push, pull_request]

jobs:
  mcp-audit:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: adudley78/credenzo@v0.33.0
        with:
          version: v0.33.0
          severity-threshold: high
          sarif-output: mcp-audit.sarif
```

**With SAST analysis** (the action installs Semgrep itself, with `pipx`, when `run-sast` is `'true'`):

```yaml
      - uses: adudley78/credenzo@v0.33.0
        with:
          version: v0.33.0
          run-sast: 'true'
          sast-path: './src'
          sarif-output: mcp-audit.sarif
```

**Exit code behavior:** a finding at or above `severity-threshold` makes the scan exit `1`, and with the default `fail-on-findings: 'true'` that fails the step. Set `fail-on-findings: 'false'` to upload SARIF and track findings without blocking merges. Exit code `2` (a tool error) always fails the step. See [github-action.md](github-action.md#inputs) for every input.

---

## Fleet Scanning

Scan multiple machines and merge findings into a single report.

```bash
# On each machine, save scan output to a JSON file
credenzo scan --format json --output-file scan-$(hostname).json --asset-prefix prod

# On a collection machine, merge all scans
credenzo merge --dir ./scans/ --format terminal
```

The merge report includes fleet-wide statistics: riskiest machine, most widespread finding, and per-machine summaries. Version mismatch warnings appear if machines are running different versions of Credenzo.

---

## Nucleus Security Integration

Push scan findings directly to a Nucleus Security project via the FlexConnect API.

```bash
export NUCLEUS_API_KEY="your-api-key"

credenzo push-nucleus \
  --url https://<your-nucleus-url> \
  --project-id 42
```

`push-nucleus` runs a full scan, formats results as FlexConnect JSON, uploads via multipart/form-data, and polls the import job to completion — all in one command.

**Options:**

| Flag | Default | Description |
|---|---|---|
| `--url` | required | Nucleus instance base URL |
| `--project-id` | required | Target Nucleus project ID |
| `--api-key` | `NUCLEUS_API_KEY` env | API key |
| `--asset-prefix` | hostname | Override the asset identifier in Nucleus |
| `--config-paths` | auto-discover | Limit scan to specific config files (repeatable) |
| `--severity-threshold` | `INFO` (all) | Filter findings before pushing |
| `--timeout` | 120 s | Job poll timeout |
| `--output-file` | — | Also write FlexConnect JSON to disk |

**Exit codes:** 0 = job succeeded · 1 = job ERROR/DESCHEDULED · 2 = config or network error.

To produce FlexConnect JSON without pushing (for manual upload or debugging):

```bash
credenzo scan --format nucleus --output-file findings.json
```

See [docs/nucleus-integration.md](nucleus-integration.md) for the full guide including fleet deployment examples.

---

## Pre-Commit Hook

Add Credenzo to your pre-commit pipeline to catch MCP config issues before they are committed.

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/adudley78/credenzo
    rev: v0.33.0
    hooks:
      - id: mcp-audit
```

The hook exits `0` cleanly when no MCP configs are present in the repo.

---

## All Commands Reference

| Command | Description |
|---------|-------------|
| `credenzo scan` | Run a full security scan |
| `credenzo discover` | Discover MCP config files without scanning |
| `credenzo pin` | Pin current server hashes |
| `credenzo diff BASE HEAD` | MCP-aware diff of two configuration states |
| `credenzo verify` | Verify server hashes against registry |
| `credenzo watch` | Watch configs for changes and re-scan |
| `credenzo baseline save NAME` | Save current scan as a named baseline |
| `credenzo baseline list` | List saved baselines |
| `credenzo baseline compare NAME` | Compare baselines |
| `credenzo baseline delete NAME` | Delete a baseline |
| `credenzo baseline export NAME` | Export a baseline to JSON |
| `credenzo rule validate FILE` | Validate a custom rule YAML |
| `credenzo rule test FILE --against CONFIG` | Test a rule against a config |
| `credenzo rule list` | List currently loaded rules |
| `credenzo policy validate FILE` | Validate a governance policy file |
| `credenzo policy init` | Generate a starter governance policy |
| `credenzo policy check` | Check configs against a policy |
| `credenzo extensions discover` | Inventory installed IDE extensions |
| `credenzo extensions scan` | Full security scan of IDE extensions |
| `credenzo dashboard` | Open D3 attack graph in browser |
| `credenzo update-registry` | Update the known-server registry |
| `credenzo sast PATH` | Run MCP-specific Semgrep rules |
| `credenzo push-nucleus` | Scan and push results to a Nucleus project |
| `credenzo merge` | Merge fleet scan outputs |
| `credenzo version` | Show version information |

---

## Key Scan Flags

| Flag | Description |
|------|-------------|
| `--format [terminal\|json\|sarif\|nucleus]` | Output format (default: terminal). HTML output is available via `credenzo dashboard`, not via `--format html`. |
| `--output-file PATH` | Write output to a file |
| `--severity-threshold LEVEL` | Only report findings at or above this level. **Note:** the scan score is always computed from the full finding set before this filter is applied — see [docs/scoring.md](scoring.md#scoring-and-severity-filtering) for details. |
| `--no-score` | Suppress the scan score panel |
| `--baseline NAME` | Compare scan to a saved baseline (use `latest` for the most recent) |
| `--verify-hashes` | Verify server hashes against the registry |
| `--sast PATH` | Run MCP Semgrep rules against a source directory |
| `--include-extensions` | Include IDE extension analysis |
| `--policy PATH` | Run a governance policy |
| `--registry PATH` | Use a custom registry file |
| `--offline-registry` | Disable registry network updates |
| `--rules-dir PATH` | Run additional custom rules from a directory (bundled community rules always apply) |
| `--asset-prefix PREFIX` | Tag findings with a machine/fleet prefix |
| `--connect` | Connect live to running MCP servers (requires MCP SDK) |
