# mcp-audit

An open-source, privacy-first CLI tool that scans MCP (Model Context Protocol)
server configurations for security vulnerabilities. Think "Snyk for MCP servers."

## What this project does

Developers use MCP servers to give AI agents (Claude, Cursor, VS Code Copilot) access
to tools — file systems, databases, APIs, etc. These servers are configured via JSON
files and can be poisoned, misconfigured, or compromised. mcp-audit scans those configs
and flags security issues.

## Tech stack

- Python 3.11+, managed with `uv`
- CLI: Typer + Rich
- Data models: Pydantic v2
- Testing: pytest + pytest-asyncio
- Linting: Ruff + Bandit
- Packaging: hatchling via pyproject.toml

## Project layout

```
src/mcp_audit/
├── cli.py             # Typer app — all CLI commands live here
├── scanner.py         # Orchestrator: discovery → parsing → analysis → output
├── discovery.py       # Finds MCP config files across all supported clients
├── config_parser.py   # Parses JSON configs, normalizes across client formats
├── models.py          # Pydantic models: Finding, ServerConfig, ScanResult, Severity
├── analyzers/
│   ├── base.py        # BaseAnalyzer abstract class — all analyzers inherit this
│   ├── poisoning.py   # Tool description poisoning detection (regex-based)
│   ├── credentials.py # Secret/API key exposure in configs
│   ├── transport.py   # Transport security (TLS, localhost binding, etc.)
│   ├── supply_chain.py# Package provenance and known CVE checks
│   └── rug_pull.py    # Description change detection via hashing
├── output/
│   ├── terminal.py    # Rich-formatted console output (default)
│   ├── json_out.py    # JSON formatter
│   ├── sarif.py       # SARIF for GitHub Security integration
│   └── nucleus.py     # Nucleus FlexConnect formatter
└── data/
    ├── patterns.yaml  # Externalized detection regex patterns
    └── known_servers.yaml  # Hashes of known-good MCP server descriptions
```

## Key conventions

- Every module has a corresponding test file in tests/ (e.g., test_discovery.py)
- Detection patterns are externalized in data/patterns.yaml — NOT hardcoded in analyzers
- All findings use the `Finding` Pydantic model from models.py
- Analyzers inherit from `BaseAnalyzer` and implement an `analyze()` method
- Output formatters inherit from `BaseFormatter` and implement a `format()` method

## Critical implementation details

- **VS Code uses `"servers"` as its MCP config root key; all other clients use `"mcpServers"`**
- MCP protocol communication is async — use asyncio and pytest-asyncio
- Core scanning MUST work fully offline — no network calls by default
- OSV.dev lookups are opt-in, skipped with --offline flag
- Rug-pull state is stored in ~/.mcp-audit/state.json
- Exit codes: 0 = clean, 1 = findings found, 2 = error

## Quality gates

- Run `uv run pytest` after every change
- Run `uv run ruff check src/ tests/` before committing
- Run `uv run bandit -r src/` periodically (we're a security tool — act like it)
- Type hints on ALL function signatures
- Docstrings on all public functions and classes

### When to flag for Opus review

If a task involves designing a new module interface, changing how analyzers
interact with each other, restructuring data models, or you find yourself
uncertain between two fundamentally different approaches — stop and say:
"⚡ Architecture decision — consider switching to Opus for this."
Do not attempt to resolve architectural ambiguity by guessing. Flag it.

## Current phase

Prototype complete (built on April 11, 2026).

What's built:
- 6 analyzers: poisoning, credentials, transport, supply chain, rug-pull, toxic flow
- 4 output formats: terminal, JSON, SARIF, Nucleus FlexConnect
- 5 CLI commands: scan, discover, pin, diff, version
- Live MCP server connection via --connect (optional, MCP SDK)
- Scoped rug-pull state management (per-config-set hash isolation)
- Demo environment with 27 findings across all analyzer categories
- 329 tests passing, ruff clean

What's next (non-code):
- Disclose project to Nucleus colleagues, get expert feedback on detection logic
- Validate FlexConnect output against real Nucleus instance (need Swagger docs)
- Tune false positives (e.g., "base64 encode" in official filesystem server)
- Update README to reflect full feature set

What's next (code, after feedback):
- Detection pattern tuning based on practitioner review
- pip packaging for public release (pyproject.toml ready, needs TestPyPI run)
- GitHub Actions CI (test on macOS, Linux, Windows)
- Documentation (usage guide, rule-writing guide, Nucleus integration guide)

## Provenance

All detection patterns are original implementations based on published security
research. No code was copied from existing scanners. Full source attribution is
documented in PROVENANCE.md — read it before adding new detection patterns.
Every new pattern must cite its research source.
The project now has 6 analyzers with patterns sourced from the research listed in PROVENANCE.md. Update PROVENANCE.md when adding new detection patterns or analyzers.
