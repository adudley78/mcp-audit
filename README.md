# mcp-audit

**Privacy-first security scanner for MCP server configurations.**

MCP (Model Context Protocol) servers give AI agents access to your tools, files, APIs, and databases. Misconfigured or malicious servers can exfiltrate credentials, poison tool behavior, and compromise your development environment — without anything appearing in the UI.

`mcp-audit` scans your local MCP configurations across all major AI coding clients, connects to running servers to inspect what agents actually see, and flags security issues across individual servers and dangerous cross-server combinations.

## Why vulnerability management matters for MCP security

MCP security findings today exist in isolation. A developer runs a scanner, sees terminal output, and maybe fixes something. But enterprises deploying AI agents across hundreds of developers need the same workflow they use for every other vulnerability class: ingest findings into a centralized platform, correlate with asset context, deduplicate across scans, assign ownership, track remediation, and report progress.

mcp-audit's --format nucleus output is designed to align with the Nucleus Security FlexConnect schema, mapping findings to the standard ingestion fields (asset_name, finding_number, finding_severity, etc.) — the same ingestion pipeline that normalizes data from Qualys, Tenable, CrowdStrike, and 200+ other security tools. This integration has not yet been validated against a live Nucleus instance — see GAPS.md for details. Once validated, this means MCP server vulnerabilities appear alongside infrastructure, cloud, and application vulnerabilities in a single prioritized view, with the same automation, SLA tracking, and reporting that security teams already use.

Tenable WAS has added MCP server detection plugins that scan server-side code for web vulnerabilities — but no standalone MCP configuration scanner bridges the gap between developer-side config analysis (tool poisoning, credential exposure, toxic flows, supply chain risks) and enterprise vulnerability management. Most output to terminal or JSON and stop there.

## Features

- 🔍 **Auto-discovers** MCP configs across 6 clients (Claude Desktop, Cursor, VS Code, Windsurf, Claude Code user-level, Claude Code project-level)
- 🧪 **Tool poisoning detection** — 14 regex patterns across 5 severity tiers
- 🔑 **Credential exposure** — 9 patterns covering AWS, GitHub, OpenAI, Anthropic, Stripe, Slack, and database URLs
- 🔒 **Transport security** — unencrypted connections, elevated privileges, runtime package fetching
- 📦 **Supply chain** — typosquatting detection via Levenshtein distance against 43 known-legitimate npm MCP packages
- 🔄 **Rug-pull detection** — stateful SHA-256 hash comparison of tool descriptions across scans
- ⚡ **Cross-server toxic flows** — capability tagging and 7 dangerous pair patterns detecting multi-server attack paths
- 🌐 **Live server analysis** — connects to running servers via MCP protocol to inspect actual tool definitions
- 📊 **4 output formats** — terminal (Rich), JSON, SARIF (GitHub Security tab), Nucleus FlexConnect
- 🏠 **Fully offline by default** — no data leaves your machine

## Install

```bash
pip install mcp-audit
```

For live server connection support:

```bash
pip install 'mcp-audit[mcp]'
```

## Quick start

```bash
mcp-audit scan                                        # Scan all detected MCP configs
mcp-audit scan --connect                              # Also connect to running servers
mcp-audit scan --format sarif -o results.sarif        # SARIF for GitHub Security
mcp-audit scan --format nucleus -o results.json       # Nucleus FlexConnect
mcp-audit discover                                    # List detected clients and servers
mcp-audit pin                                         # Lock current state as trusted baseline
mcp-audit diff                                        # Show changes since last pin
mcp-audit scan --ci --severity-threshold HIGH         # CI mode
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

## What it detects

| Analyzer | Finding IDs | Examples |
|----------|-------------|---------|
| Tool poisoning | POISON-001…050 | SSH key exfiltration instructions, XML injection markers (`<IMPORTANT>`), behavioral overrides ("ignore previous instructions"), zero-width Unicode stealth characters |
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

A single server that holds both capabilities (e.g., `@modelcontextprotocol/server-github` provides both `GIT` and `NETWORK_OUT`) is also flagged as a self-contained toxic flow.

## Rug-pull detection

MCP servers can update their tool definitions at any time. A server can publish clean, trusted descriptions during initial review and silently swap them for malicious ones after developers have granted access.

`mcp-audit pin` records SHA-256 hashes of every tracked server's configuration as a trusted baseline. Subsequent `mcp-audit scan` runs compare against that baseline and flag any change as RUGPULL-001 (HIGH).

```bash
mcp-audit pin   # Record current state as trusted
mcp-audit diff  # Show what has changed since last pin
```

State is stored in `~/.mcp-audit/state.json`.

## CI/CD usage

`mcp-audit` exits with code `1` when findings are detected, `0` when clean, and `2` on errors.

```yaml
# .github/workflows/mcp-security.yml
- name: Scan MCP configs
  run: mcp-audit scan --ci --severity-threshold HIGH

- name: Export SARIF for GitHub Security tab
  run: mcp-audit scan --format sarif -o mcp-audit.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: mcp-audit.sarif
```

## Where the detection logic comes from

All detection patterns are original implementations based on published security research — no code was copied from existing scanners. Sources include Invariant Labs' tool poisoning disclosure, CrowdStrike's MCP exfiltration research, CyberArk's agent attack demonstrations, the OWASP Agentic Top 10, and MITRE ATLAS agent-specific techniques. Supply chain patterns follow npm package naming conventions; credential patterns follow the publicly documented key formats from AWS, GitHub, OpenAI, Anthropic, Stripe, and others.

321 tests validate detection accuracy and guard against regressions.

See [PROVENANCE.md](PROVENANCE.md) for the full list of research sources, framework mappings, and contribution guidelines for new detection rules.

## Development

```bash
git clone https://github.com/yourusername/mcp-audit.git
cd mcp-audit
uv sync --all-extras

uv run pytest                        # Run all 321 tests
uv run ruff check src/ tests/        # Lint
uv run bandit -r src/                # Security audit of the scanner itself
```

## Known limitations

This tool is in early development. See [GAPS.md](GAPS.md) for known detection gaps, untested areas, and planned improvements.

## License

License pending. This software is not yet licensed for redistribution.
