# mcp-audit

[![CI](https://github.com/adudley78/mcp-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/adudley78/mcp-audit/actions/workflows/ci.yml)

**Privacy-first security scanner for MCP server configurations.**

MCP (Model Context Protocol) servers give AI agents access to your tools, files, APIs, and databases. Misconfigured or malicious servers can exfiltrate credentials, poison tool behavior, and compromise your development environment — without anything appearing in the UI.

`mcp-audit` scans your local MCP configurations across all major AI coding clients, connects to running servers to inspect what agents actually see, and flags security issues across individual servers and dangerous cross-server combinations.

## Why vulnerability management matters for MCP security

MCP security findings today exist in isolation. A developer runs a scanner, sees terminal output, and maybe fixes something. But enterprises deploying AI agents across hundreds of developers need the same workflow they use for every other vulnerability class: ingest findings into a centralized platform, correlate with asset context, deduplicate across scans, assign ownership, track remediation, and report progress.

mcp-audit's --format nucleus output is designed to align with the Nucleus Security FlexConnect schema, mapping findings to the standard ingestion fields (asset_name, finding_number, finding_severity, etc.) — the same ingestion pipeline that normalizes data from Qualys, Tenable, CrowdStrike, and 200+ other security tools. (This integration has not yet been validated against a live Nucleus instance — see GAPS.md for details. Once validated, this means MCP server vulnerabilities appear alongside infrastructure, cloud, and application vulnerabilities in a single prioritized view, with the same automation, SLA tracking, and reporting that security teams already use.)

Tenable WAS has added MCP server detection plugins that scan server-side code for web vulnerabilities — but no standalone MCP configuration scanner bridges the gap between developer-side config analysis (tool poisoning, credential exposure, toxic flows, supply chain risks) and enterprise vulnerability management. Most output to terminal or JSON and stop there.

## Features

- **Auto-discovers** MCP configs across 8 clients (Claude Desktop, Cursor, VS Code, Windsurf, Claude Code user-level, Claude Code project-level, GitHub Copilot CLI, Augment Code)
- **Tool poisoning detection** — 11 regex patterns across 5 severity tiers
- **Credential exposure** — 9 patterns covering AWS, GitHub, OpenAI, Anthropic, Stripe, Slack, and database URLs
- **Transport security** — unencrypted connections, elevated privileges, runtime package fetching
- **Supply chain** — typosquatting detection via Levenshtein distance against 57 known-legitimate MCP servers
- **Rug-pull detection** — stateful SHA-256 hash comparison of tool descriptions across scans
- **Cross-server toxic flows** — capability tagging and 7 dangerous pair patterns detecting multi-server attack paths
- **Attack path engine** — multi-hop path detection with greedy hitting set algorithm (minimum set of servers to remove to break all attack paths)
- **Interactive attack graph dashboard** — `mcp-audit dashboard` opens a D3 force-directed graph in your browser with light/dark mode, click-to-highlight attack paths, and hitting set recommendations
- **Live server analysis** — connects to running servers via MCP protocol to inspect actual tool definitions
- **5 output formats** — terminal (Rich), JSON, SARIF (GitHub Security tab), Nucleus FlexConnect, self-contained HTML dashboard
- **Continuous monitoring** — `mcp-audit watch` monitors config files in real-time and re-scans on any change
- **Fleet deployment** — machine-tagged output with `--asset-prefix` for enterprise-wide aggregation
- **Fully offline by default** — no data leaves your machine

## Community vs Pro vs Enterprise

| Feature | Community (free) | Pro | Enterprise |
|---------|-----------------|-----|------------|
| All 6 analyzers (poisoning, credentials, transport, supply chain, rug-pull, toxic flow) | ✓ | ✓ | ✓ |
| Attack path engine | ✓ | ✓ | ✓ |
| 8 client config discovery | ✓ | ✓ | ✓ |
| 12 bundled community detection rules | ✓ | ✓ | ✓ |
| Terminal, JSON, SARIF output | ✓ | ✓ | ✓ |
| GitHub Action + pre-commit hook | ✓ | ✓ | ✓ |
| `--policy` flag (governance policy execution) | ✓ | ✓ | ✓ |
| `mcp-audit verify` (supply chain hash verification) | ✓ | ✓ | ✓ |
| `mcp-audit extensions discover` (extension inventory) | ✓ | ✓ | ✓ |
| Scan scoring (A–F grade) | ✓ | ✓ | ✓ |
| Baseline snapshots + drift detection | ✓ | ✓ | ✓ |
| Interactive D3.js attack graph dashboard | — | ✓ | ✓ |
| HTML report export | — | ✓ | ✓ |
| Custom rule authoring + `--rules-dir` | — | ✓ | ✓ |
| `mcp-audit update-registry` | — | ✓ | ✓ |
| Governance policy authoring (`policy init`, `policy check`) | — | ✓ | ✓ |
| SAST integration (`scan --sast`, `mcp-audit sast`) | — | ✓ | ✓ |
| IDE extension security scan (`extensions scan`, `scan --include-extensions`) | — | ✓ | ✓ |
| Nucleus FlexConnect output | — | — | ✓ |
| Fleet merge (`mcp-audit merge`) | — | — | ✓ |
| Fleet governance | — | — | ✓ |
| Fleet extension inventory | — | — | ✓ |

Upgrade: [https://mcp-audit.dev/pro](https://mcp-audit.dev/pro)

Already have a key? Run `mcp-audit activate <your-key>` to unlock Pro features.

---

## Install

> **Note:** mcp-audit is not yet published to PyPI. Install from source or
> download a standalone binary from
> [GitHub Releases](https://github.com/adudley78/mcp-audit/releases).

```bash
pip install git+https://github.com/adudley78/mcp-audit.git
```

For live server connection support:

```bash
pip install 'mcp-audit[mcp] @ git+https://github.com/adudley78/mcp-audit.git'
```

## Quick start

```bash
mcp-audit scan                                        # Scan all detected MCP configs
mcp-audit scan --connect                              # Also connect to running servers
mcp-audit scan --format sarif -o results.sarif        # SARIF for GitHub Security
mcp-audit scan --format nucleus -o results.json       # Nucleus FlexConnect (Enterprise)
mcp-audit dashboard                                   # Open interactive attack graph dashboard (Pro)
mcp-audit dashboard --path demo/configs               # Dashboard against demo data
mcp-audit discover                                    # List detected clients and servers
mcp-audit pin                                         # Lock current state as trusted baseline
mcp-audit diff                                        # Show changes since last pin
mcp-audit watch                                       # Monitor configs and re-scan on changes
mcp-audit activate <your-key>                         # Activate a Pro/Enterprise license
mcp-audit license                                     # Show current license status
```

## Supported clients

| Client | Config location |
|--------|----------------|
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Cursor | `~/.cursor/mcp.json` |
| VS Code | `.vscode/mcp.json` (workspace) |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |
| Claude Code (user) | `~/.claude.json` |
| Claude Code (project) | `.mcp.json` (project root) |
| GitHub Copilot CLI | `~/.copilot/mcp-config.json` |
| Augment Code | `~/.augment/settings.json` |

## What it detects

| Analyzer | Finding IDs | Examples |
|----------|-------------|---------|
| Tool poisoning | 11 patterns (POISON-001 – POISON-050) | SSH key exfiltration instructions, XML injection markers (`<IMPORTANT>`), behavioral overrides ("ignore previous instructions"), zero-width Unicode stealth characters |
| Credential exposure | CRED-001…009 | AWS access keys, GitHub tokens, OpenAI/Anthropic API keys, Stripe secrets, database connection strings with embedded passwords |
| Transport security | TRANSPORT-001…003 | Unencrypted remote SSE connections, elevated privilege execution, runtime package fetching via `npx`/`uvx` without version pinning |
| Supply chain | SC-001…003 | Typosquatted package names (`@modelcontextprotocol/server-filesytem` vs `server-filesystem`), distance-1 substitutions flagged CRITICAL |
| Rug-pull | RUGPULL-001…003 | Tool description changed since last scan (HIGH), new server appeared (INFO), previously tracked server removed (INFO) |
| Toxic flow | TOXIC-001…007 | File-read server + network server (exfiltration path), secret-access server + network server (credential theft), shell-exec server + network server (arbitrary command + exfiltration) |

## Live server analysis

By default, `mcp-audit` performs static analysis — it reads config files and inspects the command, args, env vars, and any tool descriptions stored there.

The `--connect` flag goes further: it connects to each server using the MCP protocol, completes the initialization handshake, and calls `list_tools()`, `list_resources()`, and `list_prompts()` to retrieve the actual definitions the server exposes to the AI agent. Those live definitions are then run through the poisoning analyzer.

This matters because a config file can look completely clean while the server it points to is serving poisoned tool descriptions. Static analysis cannot catch this. Connection-based analysis can.

```bash
mcp-audit scan --connect
```

Requires the optional MCP SDK dependency:

```bash
pip install 'mcp-audit[mcp]'
```

Connection is best-effort: servers that do not respond within 10 seconds produce an error finding rather than crashing the scan. All static analysis still runs regardless.

## Cross-server attack paths

Most MCP security analysis focuses on individual servers. That misses an entire category of risk.

Server A reads files. Server B makes HTTP requests. Neither is malicious alone — they each do exactly what the config says. Together, a prompt injection can instruct the agent to read your SSH keys with A and POST them to an attacker's endpoint with B. No single server ever looked dangerous.

`mcp-audit` detects 7 categories of these toxic combinations by tagging each server with capability labels (`FILE_READ`, `NETWORK_OUT`, `SHELL_EXEC`, `DATABASE`, `SECRETS`, etc.) and checking every server pair for known-dangerous combinations:

| ID | Combination | Severity |
|----|-------------|----------|
| TOXIC-001 | File read + outbound network | HIGH |
| TOXIC-002 | File read + email | HIGH |
| TOXIC-003 | Secret store access + outbound network | CRITICAL |
| TOXIC-004 | File read + shell execution | HIGH |
| TOXIC-005 | Database access + outbound network | HIGH |
| TOXIC-006 | Shell execution + outbound network | CRITICAL |
| TOXIC-007 | Git repository access + outbound network | MEDIUM |

† A single server that provides both capabilities of a dangerous pair is also flagged — no second server required.

## Attack graph dashboard

```bash
mcp-audit dashboard                      # Scan your real MCP environment and open browser
mcp-audit dashboard --path demo/configs  # Use the bundled demo data
mcp-audit dashboard --port 9090          # Custom port
mcp-audit dashboard --connect            # Include live-connection findings
```

One command runs a full scan, generates a self-contained HTML report, and opens it in your browser. No external dependencies — D3 v7, all scan data, and fonts are embedded inline. No CDN requests are made.

The dashboard shows:

- **Force-directed attack graph** — your MCP servers arranged around a central AI Agent node. Server nodes are colour-coded by max severity (green = clean, orange = high, red = critical). Toxic flow edges connect pairs with dangerous capability combinations.
- **Attack path sidebar** — every exploitable multi-hop path listed as a card with severity badge, hop chain, and description. Click a card to highlight the path on the graph with animated dashed lines.
- **Hitting set recommendation** — at the bottom of the sidebar, the minimum set of servers you can remove to break every attack path. Example: removing `fetch` alone breaks three separate attack paths.
- **Findings table** — full findings list with severity filter pills and sortable columns.
- **Light/dark mode toggle** — pill toggle in the top bar. Preference is applied instantly via CSS custom properties; no page reload required.

The dashboard works against your real MCP environment — whatever `mcp-audit scan` finds on your machine is what appears in the graph. It is not restricted to demo data.

## Rug-pull detection

MCP servers can update their tool definitions at any time. A server can publish clean, trusted descriptions during initial review and silently swap them for malicious ones after developers have granted access.

`mcp-audit pin` records SHA-256 hashes of every tracked server's configuration as a trusted baseline. Subsequent `mcp-audit scan` runs compare against that baseline and flag any change as RUGPULL-001 (HIGH).

```bash
mcp-audit pin   # Record current state as trusted
mcp-audit diff  # Show what has changed since last pin
```

Rug-pull state is stored per-config-set at `~/.mcp-audit/state_<hash>.json`. All other persistent state (baselines, registry cache, policy, rules, license) uses the platform user-config directory: `~/Library/Application Support/mcp-audit/` on macOS, `~/.config/mcp-audit/` on Linux, `%APPDATA%\mcp-audit\` on Windows.

## CI/CD usage

`mcp-audit` exits with code `1` when findings are detected, `0` when clean, and `2` on errors.

```yaml
# .github/workflows/mcp-security.yml
- name: Scan MCP configs
  run: mcp-audit scan --severity-threshold HIGH

- name: Export SARIF for GitHub Security tab
  run: mcp-audit scan --format sarif -o mcp-audit.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: mcp-audit.sarif
```

## Where the detection logic comes from

All detection patterns are original implementations based on published security research — no code was copied from existing scanners. Sources include Invariant Labs' tool poisoning disclosure, CrowdStrike's MCP exfiltration research, CyberArk's agent attack demonstrations, the OWASP Agentic Top 10, and MITRE ATLAS agent-specific techniques. Supply chain patterns follow npm package naming conventions; credential patterns follow the publicly documented key formats from AWS, GitHub, OpenAI, Anthropic, Stripe, and others.

1,351 tests validate detection accuracy and guard against regressions.

See [PROVENANCE.md](PROVENANCE.md) for the full list of research sources, framework mappings, and contribution guidelines for new detection rules.

## CLI reference

| Command | Tier | Key flags | Description |
|---------|------|-----------|-------------|
| `mcp-audit scan` | free | `--connect`, `--format`, `--output`, `--severity-threshold`, `--asset-prefix`, `--baseline`, `--policy`, `--verify-hashes`, `--no-score`, `--registry`, `--offline-registry`, `--rules-dir` *(Pro)*, `--sast` *(Pro)*, `--include-extensions` *(Pro)* | Run all analyzers and report findings |
| `mcp-audit dashboard` | Pro | `--path`, `--port`, `--connect`, `--no-open` | Generate and open the interactive attack graph dashboard |
| `mcp-audit watch` | free | `--path`, `--format`, `--severity-threshold`, `--connect` | Monitor config files and re-scan on any change |
| `mcp-audit discover` | free | — | List all detected MCP clients and their configured servers |
| `mcp-audit pin` | free | — | Record current server state as a trusted baseline |
| `mcp-audit diff` | free | — | Show configuration changes since the last `pin` |
| `mcp-audit verify` | free | `<package\|config-path>` | Verify server hashes: pass a package name (`@scope/pkg`), a config file path, or `--all` |
| `mcp-audit activate` | free | `<key>` | Activate a Pro or Enterprise license key |
| `mcp-audit license` | free | — | Show current license tier and expiry |
| `mcp-audit version` | free | — | Print version string and active license tier |
| `mcp-audit update-registry` | Pro | — | Fetch the latest known-server registry from upstream |
| `mcp-audit sast` | Pro | `<path>` | Run MCP-aware Semgrep SAST rules on server source code |
| `mcp-audit merge` | Enterprise | `--dir`, `--format`, `--asset-prefix` | Merge JSON scan outputs from multiple machines into a fleet report |
| `mcp-audit baseline save [NAME]` | free | `--path` | Capture a baseline snapshot; NAME is optional (auto-generated if omitted) |
| `mcp-audit baseline list` | free | — | List all saved baselines |
| `mcp-audit baseline compare [NAME]` | free | `--path` | Compare current config against a saved baseline (defaults to latest) |
| `mcp-audit baseline delete NAME` | free | `--yes` | Delete a saved baseline |
| `mcp-audit baseline export NAME` | free | `--output-file` | Write a baseline as raw JSON to stdout or a file |
| `mcp-audit rule validate` | Pro | `<file>` | Validate a rule file without running a scan |
| `mcp-audit rule test` | Pro | `<rule> <config>` | Test a rule file against a specific MCP config file |
| `mcp-audit rule list` | free | — | List all currently loaded rules (bundled + user-local) |
| `mcp-audit policy validate` | free | `<file>` | Validate a governance policy YAML file |
| `mcp-audit policy init` | Pro | — | Scaffold a new governance policy file |
| `mcp-audit policy check` | Pro | `--policy`, `--result` | Check a scan result against a policy file |
| `mcp-audit extensions discover` | free | — | Inventory installed IDE extensions from VS Code/Cursor |
| `mcp-audit extensions scan` | Pro | — | Analyze installed IDE extensions for security risks |

**`mcp-audit scan` flags**

| Flag | Default | Description |
|------|---------|-------------|
| `--format` | `terminal` | Output format: `terminal`, `json`, `sarif`, `nucleus` |
| `--output / --output-file / -o` | stdout | File path for `json`/`sarif`/`nucleus` output; parent directories are created automatically |
| `--connect` | off | Connect to running servers via MCP protocol |
| `--severity-threshold` | `INFO` | Filter findings and set exit code; exit 1 if any finding at or above this level |
| `--path` | auto-detect | Directory to search for MCP configs |
| `--asset-prefix` | hostname | Override machine identifier in Nucleus/SARIF output |
| `--no-score` | off | Suppress the score/grade panel in terminal output |
| `--registry` | bundled | Custom registry file path (overrides user cache and bundled registry) |
| `--baseline` | none | Compare scan results against a named baseline (`latest` selects most recent) |
| `--rules-dir` | none | Load additional detection rules from this directory *(Pro — soft gate: scan continues with bundled community rules only if no license)* |
| `--offline-registry` | off | Use bundled registry only, skip user cache |
| `--policy` | auto-discover | Path to a governance policy file; auto-discovers `.mcp-audit-policy.yml` in cwd/repo root when omitted |
| `--verify-hashes` | off | Download and verify package hashes against registry (free; requires network) |
| `--sast` | none | Path to MCP server source code to scan with Semgrep SAST rules *(Pro — soft gate: scan continues without SAST if no license)* |
| `--include-extensions` | off | Also scan installed IDE extensions for security issues *(Pro — soft gate: scan continues without extension scanning if no license)* |

**`mcp-audit dashboard` flags**

| Flag | Default | Description |
|------|---------|-------------|
| `--path` | auto-detect | Directory to search for MCP configs |
| `--port` | `8088` | HTTP port for the local dashboard server |
| `--connect` | off | Include live-connection findings in the dashboard |
| `--no-open` | off | Generate the report without opening a browser tab |

## GitHub Action

[![MCP Security Scan](https://github.com/adudley78/mcp-audit/actions/workflows/mcp-audit-example.yml/badge.svg)](https://github.com/adudley78/mcp-audit/actions/workflows/mcp-audit-example.yml)

`mcp-audit` ships as a [composite GitHub Action](action.yml) that you can drop into any repository with a single workflow addition. It installs `mcp-audit`, runs a full scan against your MCP configs, uploads findings to the GitHub Security tab as SARIF, and writes a findings summary to the job summary page. The build fails only when findings at or above your chosen severity threshold exist — making it easy to adopt incrementally (start with `severity-threshold: high`, tighten to `medium` once you've cleared existing issues).

### Minimal setup

Add this workflow to `.github/workflows/mcp-audit.yml` in your repo:

```yaml
name: MCP Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  mcp-audit:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read

    steps:
      - uses: actions/checkout@v4

      - name: Run mcp-audit
        uses: adudley78/mcp-audit@main
        with:
          severity-threshold: high
          upload-sarif: 'true'
```

The `permissions: security-events: write` block is required for SARIF upload on public repositories. Without it the upload step will fail silently.

### Action inputs

| Input | Default | Description |
|-------|---------|-------------|
| `severity-threshold` | `high` | Fail the build if findings at or above this level exist (`critical`, `high`, `medium`, `low`, `info`) |
| `format` | `sarif` | Output format (`sarif`, `json`, `terminal`) |
| `config-paths` | _(auto-discover)_ | Single MCP config file path to scan |
| `baseline` | _(none)_ | Baseline name for drift detection |
| `upload-sarif` | `true` | Upload SARIF results to the GitHub Security tab |

### Action outputs

| Output | Description |
|--------|-------------|
| `finding-count` | Total number of findings |
| `grade` | Letter grade (A–F) |
| `sarif-path` | Path to generated SARIF file |

### More examples

See [`examples/github-actions/`](examples/github-actions/) for:
- [`basic.yml`](examples/github-actions/basic.yml) — visibility-only, never fails the build
- [`strict.yml`](examples/github-actions/strict.yml) — fail on any MEDIUM or higher finding
- [`with-baseline.yml`](examples/github-actions/with-baseline.yml) — drift detection against a committed baseline

Full reference, troubleshooting, and baseline setup instructions: [`docs/github-action.md`](docs/github-action.md).

## Pre-Commit Hook

`mcp-audit` ships as a [pre-commit](https://pre-commit.com) hook, catching MCP misconfigurations before they land in the repository. The hook fires only when a JSON file is staged — no false triggers on Python-only or markdown-only commits — and exits 1 to block the commit when findings at or above your chosen severity threshold exist.

### Minimal setup

Add this to your `.pre-commit-config.yaml` (replace `rev` with the [latest release tag](https://github.com/adudley78/mcp-audit/releases)):

```yaml
repos:
  - repo: https://github.com/adudley78/mcp-audit
    rev: v0.1.0  # Replace with the latest release tag
    hooks:
      - id: mcp-audit
```

Then install the hooks:

```bash
pip install pre-commit
pre-commit install
```

The hook uses `--severity-threshold high` by default. To lower the bar to MEDIUM, override `args`:

```yaml
hooks:
  - id: mcp-audit
    args: [scan, --severity-threshold, medium]
```

**Note:** `pass_filenames: false` is set intentionally. pre-commit would otherwise pass individual staged JSON filenames to the command, but `mcp-audit scan` requires full config files discovered through its own client-aware logic. The hook re-scans all MCP configs (not just staged ones) each time it fires.

See [`examples/pre-commit/`](examples/pre-commit/) for ready-to-copy config patterns and [`docs/pre-commit.md`](docs/pre-commit.md) for the full reference.

## Development

```bash
git clone https://github.com/adudley78/mcp-audit.git
cd mcp-audit
uv sync --all-extras

uv run pytest                        # Run all 1,351 tests
uv run ruff check src/ tests/        # Lint
uv run bandit -r src/                # Security audit of the scanner itself
```

## Known limitations

This tool is in early development. See [GAPS.md](GAPS.md) for known detection gaps, untested areas, and planned improvements.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
