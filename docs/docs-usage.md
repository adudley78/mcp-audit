# mcp-audit Usage Guide

A practical guide to getting started with mcp-audit and using it in common workflows.

---

## Installation

**Standalone binary (no Python required):**

Download the binary for your platform from the [GitHub Releases](https://github.com/adudley78/mcp-audit/releases) page and place it on your PATH.

```bash
# macOS (Apple Silicon)
curl -L https://github.com/adudley78/mcp-audit/releases/latest/download/mcp-audit-macos-arm64 -o mcp-audit
chmod +x mcp-audit
sudo mv mcp-audit /usr/local/bin/

# Linux (x86_64)
curl -L https://github.com/adudley78/mcp-audit/releases/latest/download/mcp-audit-linux-x86_64 -o mcp-audit
chmod +x mcp-audit
sudo mv mcp-audit /usr/local/bin/
```

**From PyPI (Python 3.11+ required):**

```bash
pip install mcp-audit
```

**From source (for contributors):**

```bash
git clone https://github.com/adudley78/mcp-audit
cd mcp-audit
pip install uv
uv pip install -e ".[dev]"
```

---

## Quick Start

Run your first scan in 30 seconds. mcp-audit will discover all MCP configs on your machine automatically.

```bash
mcp-audit scan
```

That's it. mcp-audit searches your home directory for MCP configurations across all supported AI coding clients — Claude Desktop, Cursor, VS Code, Windsurf, Claude Code, Copilot CLI, and Augment — and prints a findings report with a letter grade.

---

## Supported Clients

mcp-audit automatically discovers MCP server configurations for:

| Client | Config location |
|--------|----------------|
| Claude Desktop | `~/.config/Claude/claude_desktop_config.json` (Linux/Windows) / `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) |
| Cursor | `~/.cursor/mcp.json` |
| VS Code | `~/.vscode/mcp.json` (uses `"servers"` key instead of `"mcpServers"`) |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |
| Claude Code | `~/.claude/claude_mcp_config.json` |
| Copilot CLI | `~/.config/github-copilot/mcp.json` |
| Augment | `~/.augment/mcp_config.json` |

---

## Understanding the Output

After a scan, mcp-audit prints:

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
mcp-audit scan --format json --output-file results.json
```

Useful for piping into other tools or storing scan history.

### Scan and upload to GitHub Security tab (SARIF)

```bash
mcp-audit scan --format sarif --output-file results.sarif
```

Upload `results.sarif` to GitHub via the Security tab, or use the [mcp-audit GitHub Action](#github-action) to do this automatically in CI.

### Only show HIGH and CRITICAL findings

```bash
mcp-audit scan --severity-threshold HIGH
```

### Discover configs without scanning

```bash
mcp-audit discover
```

Shows all MCP config files found on the machine without running any analysis — useful for confirming discovery before a full scan.

### Pin server hashes for supply chain tracking

```bash
mcp-audit pin
```

Captures the current hashes of all configured MCP servers. Run `mcp-audit diff` later to detect changes.

### Compare current state to a previous pin

```bash
mcp-audit diff
```

Detects rug-pull risk: servers that have changed since the last `pin`.

### View the interactive attack graph dashboard

```bash
mcp-audit dashboard
# With custom rules:
mcp-audit dashboard --rules-dir /path/to/rules
```

Opens an interactive D3.js visualization of cross-server attack paths in your browser.
Pass `--rules-dir` to apply additional YAML detection rules on the dashboard scan (community rules always run in addition).

### Watch for config changes in real time

```bash
mcp-audit watch
# With custom rules:
mcp-audit watch --rules-dir /path/to/rules
```

Monitors MCP config files for changes and re-runs the scan automatically when a config is modified.
Pass `--rules-dir` to apply additional YAML detection rules on every re-scan (community rules always run in addition).

---

## Baseline Snapshots and Drift Detection

Baselines let you capture a known-good state and be alerted when anything changes.

```bash
# Save the current scan state as a named baseline
mcp-audit baseline save pre-deploy

# List all saved baselines
mcp-audit baseline list

# Compare the current scan to a baseline
mcp-audit scan --baseline pre-deploy

# Compare to the most recently saved baseline
mcp-audit scan --baseline latest

# Export a baseline to JSON for archiving
mcp-audit baseline export pre-deploy --output-file baseline-pre-deploy.json

# Delete a baseline you no longer need
mcp-audit baseline delete pre-deploy
```

Drift findings appear in all output formats with a `drift` category and severity mapping.

---

## Supply Chain Verification

Verify that your MCP servers match known-good hashes from the mcp-audit registry.

```bash
# Verify hashes for all servers during a scan
mcp-audit scan --verify-hashes

# Run verification as a standalone command
mcp-audit verify
```

Network access is required to fetch npm tarballs and PyPI digests.

> **Incompatibility:** `--verify-hashes` cannot be combined with `--offline`. Because hash verification must download package tarballs from npm and PyPI, using both flags together will produce an error (exit code 2) and the scan will not run. Use `--offline-registry` instead if you want to skip registry cache updates while still allowing hash verification network calls.

---

## SAST Analysis

Run mcp-audit's 37 MCP-specific Semgrep rules against server source code. Requires [Semgrep](https://semgrep.dev) to be installed separately (`pip install semgrep`).

```bash
# Run SAST against a local MCP server repo
mcp-audit sast ./my-mcp-server/

# Include SAST in a full scan
mcp-audit scan --sast ./my-mcp-server/
```

SAST findings flow through all output formats (terminal, JSON, SARIF, HTML).

---

## Governance Policies

Governance policies let you define organization-wide rules for MCP server configurations.

**Running a policy:**

```bash
mcp-audit scan --policy ./policies/strict.yml
```

**Generating a starter policy:**

```bash
mcp-audit policy init --output starter.yml
```

**Validating a policy file:**

```bash
mcp-audit policy validate ./my-policy.yml
```

**Checking all configs against a policy without a full scan:**

```bash
mcp-audit policy check --policy ./my-policy.yml
```

Governance findings appear as a yellow "Policy Violations" panel in the terminal and are included in JSON, SARIF, and HTML output.

Policy files support five check types: approved server allowlist/denylist (glob patterns), scan score threshold, transport policy, registry membership enforcement, and finding count tolerance. Policies can include per-client overrides.

See `docs/governance.md` for the full policy schema reference.

---

## IDE Extension Scanning

Scan VS Code and Cursor extensions for security risks — dangerous permission combinations, wildcard activation, unknown publishers, sideloaded extensions, and known vulnerabilities.

```bash
# Inventory all installed extensions
mcp-audit extensions discover

# Full security analysis of installed extensions
mcp-audit extensions scan

# Include extension analysis in a full scan
mcp-audit scan --include-extensions
```

---

## Known-Server Registry

mcp-audit ships with a curated registry of 57 known MCP servers. The registry is used for typosquatting detection and supply chain hash verification.

```bash
# Update the registry to the latest version
mcp-audit update-registry

# Use a custom registry file
mcp-audit scan --registry ./my-registry.json

# Scan without any network registry updates
mcp-audit scan --offline-registry
```

---

## Custom Detection Rules

Community detection rules (COMM-001 through COMM-012) run automatically for all users. You can also write your own rules in YAML.

```bash
# Validate a custom rule file
mcp-audit rule validate ./my-rule.yml

# Test a rule against a fixture config
mcp-audit rule test ./my-rule.yml --config ./test-config.json

# Run a scan with a custom rules directory
mcp-audit scan --rules-dir ./custom-rules/
```

See `docs/writing-rules.md` for the rule format reference.

---

## GitHub Action

Add mcp-audit to your CI pipeline with one step. On every push, mcp-audit scans for MCP config security issues and uploads findings to the GitHub Security tab.

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
      - uses: adudley78/mcp-audit@v1
        with:
          severity-threshold: HIGH
          output-file: mcp-audit.sarif
```

**With SAST analysis:**

```yaml
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - run: pip install semgrep
      - uses: adudley78/mcp-audit@v1
        with:
          sast: 'true'
          sast-path: './src'
          output-file: mcp-audit.sarif
```

**Exit code behavior:** Finding MCP security issues exits with code `1`. The action is wired so that exit code `1` does *not* fail your CI job — only exit code `2` (a tool error) fails the build. This lets you upload SARIF and track findings without blocking merges.

---

## Fleet Scanning

Scan multiple machines and merge findings into a single report.

```bash
# On each machine, save scan output to a JSON file
mcp-audit scan --format json --output-file scan-$(hostname).json --asset-prefix prod

# On a collection machine, merge all scans
mcp-audit merge --dir ./scans/ --format terminal
```

The merge report includes fleet-wide statistics: riskiest machine, most widespread finding, and per-machine summaries. Version mismatch warnings appear if machines are running different versions of mcp-audit.

---

## Nucleus Security Integration

Push scan findings directly to a Nucleus Security project via the FlexConnect API.

```bash
export NUCLEUS_API_KEY="your-api-key"

mcp-audit push-nucleus \
  --url https://your-nucleus-instance.nucleussec.com \
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
mcp-audit scan --format nucleus --output-file findings.json
```

See [docs/nucleus-integration.md](nucleus-integration.md) for the full guide including fleet deployment examples.

---

## Pre-Commit Hook

Add mcp-audit to your pre-commit pipeline to catch MCP config issues before they are committed.

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/adudley78/mcp-audit
    rev: v0.1.0
    hooks:
      - id: mcp-audit
```

The hook exits `0` cleanly when no MCP configs are present in the repo.

---

## Legacy License Commands

mcp-audit is now fully open source (Apache 2.0) and all features are
available to every user. The `activate` and `license` commands are kept
only so users with previously-issued keys continue to have a working flow —
they no longer unlock anything.

```bash
# Kept for backward compatibility only
mcp-audit activate YOUR-LICENSE-KEY
mcp-audit license
```

---

## All Commands Reference

| Command | Description |
|---------|-------------|
| `mcp-audit scan` | Run a full security scan |
| `mcp-audit discover` | Discover MCP config files without scanning |
| `mcp-audit pin` | Pin current server hashes |
| `mcp-audit diff` | Compare to pinned hashes |
| `mcp-audit verify` | Verify server hashes against registry |
| `mcp-audit watch` | Watch configs for changes and re-scan |
| `mcp-audit baseline save NAME` | Save current scan as a named baseline |
| `mcp-audit baseline list` | List saved baselines |
| `mcp-audit baseline compare NAME` | Compare baselines |
| `mcp-audit baseline delete NAME` | Delete a baseline |
| `mcp-audit baseline export NAME` | Export a baseline to JSON |
| `mcp-audit rule validate FILE` | Validate a custom rule YAML |
| `mcp-audit rule test FILE` | Test a rule against a config |
| `mcp-audit rule list` | List currently loaded rules |
| `mcp-audit policy validate FILE` | Validate a governance policy file |
| `mcp-audit policy init` | Generate a starter governance policy |
| `mcp-audit policy check` | Check configs against a policy |
| `mcp-audit extensions discover` | Inventory installed IDE extensions |
| `mcp-audit extensions scan` | Full security scan of IDE extensions |
| `mcp-audit dashboard` | Open D3 attack graph in browser |
| `mcp-audit update-registry` | Update the known-server registry |
| `mcp-audit sast PATH` | Run MCP-specific Semgrep rules |
| `mcp-audit push-nucleus` | Scan and push results to a Nucleus project |
| `mcp-audit merge` | Merge fleet scan outputs |
| `mcp-audit activate KEY` | Legacy — validate a previously issued license key |
| `mcp-audit license` | Legacy — show details of a previously activated key |
| `mcp-audit version` | Show version information |

---

## Key Scan Flags

| Flag | Description |
|------|-------------|
| `--format [terminal\|json\|sarif\|nucleus]` | Output format (default: terminal). HTML output is available via `mcp-audit dashboard`, not via `--format html`. |
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
