# mcp-audit

**Privacy-first security scanner for MCP server configurations.**

MCP (Model Context Protocol) servers give AI agents access to your tools, files, APIs, and databases. But misconfigured or malicious MCP servers can exfiltrate credentials, poison tool behavior, and compromise your development environment — all without you seeing it in the UI.

`mcp-audit` scans your local MCP configurations across Claude Desktop, Cursor, VS Code, Windsurf, and Claude Code to find security issues before they find you.

## Features

- 🔍 **Auto-discovers** MCP configs across all major AI coding clients
- 🧪 **Tool poisoning detection** — finds hidden instructions in tool descriptions
- 🔑 **Credential exposure** — catches API keys and secrets in configs
- 🔒 **Transport security** — flags unencrypted remote connections
- 🏠 **Fully offline** — no data ever leaves your machine
- 📊 **Multiple output formats** — terminal, JSON, SARIF (GitHub Security)

## Install

```bash
pip install mcp-audit
```

## Quick start

```bash
# Scan all detected MCP configurations
mcp-audit scan

# See what configs exist on your machine
mcp-audit discover

# Output as JSON for CI/CD
mcp-audit scan --json

# Only show HIGH and CRITICAL findings
mcp-audit scan --severity-threshold HIGH

# Scan a specific config file
mcp-audit scan --path ~/.cursor/mcp.json
```

## Supported clients

| Client | Status |
|--------|--------|
| Claude Desktop | ✅ |
| Cursor | ✅ |
| VS Code | ✅ |
| Windsurf | ✅ |
| Claude Code | ✅ |

## What it detects

| Category | Examples |
|----------|---------|
| Tool poisoning | Hidden exfiltration instructions, instruction injection markers, behavioral overrides, zero-width Unicode stealth |
| Credential exposure | API keys (AWS, GitHub, OpenAI, Anthropic, Stripe), database URLs with passwords, secrets in command args |
| Transport security | Unencrypted remote connections, elevated privilege execution, runtime package fetching (npx/uvx) |

## CI/CD usage

`mcp-audit` exits with code `1` when findings are detected:

```yaml
# GitHub Actions
- name: Scan MCP configs
  run: mcp-audit scan --ci --severity-threshold HIGH
```

## Development

```bash
# Clone and install
git clone https://github.com/yourusername/mcp-audit.git
cd mcp-audit
uv sync --all-extras

# Run tests
uv run pytest

# Lint
uv run ruff check src/ tests/
```

## License

Apache 2.0
