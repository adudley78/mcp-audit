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
- License key crypto: `cryptography` (Ed25519)

## Project layout

```
src/mcp_audit/
├── cli.py             # Typer app — all CLI commands live here
├── scanner.py         # Orchestrator: discovery → parsing → analysis → output
├── scoring.py         # Scan score calculation (0–100) and letter grade (A–F) formatting
├── discovery.py       # Finds MCP config files across all supported clients
├── config_parser.py   # Parses JSON configs, normalizes across client formats
├── models.py          # Pydantic models: Finding, ServerConfig, ScanResult, ScanScore, Severity, AttackPath, MachineInfo
├── licensing.py       # Ed25519 license key verification; LicenseInfo model; is_pro_feature_available()
├── watcher.py         # Filesystem watcher for continuous monitoring (mcp-audit watch)
├── mcp_client.py      # Live MCP server connection via MCP SDK (--connect)
├── _paths.py          # data_dir() — resolves data/ in both source and PyInstaller frozen modes
├── fleet/
│ ├── __init__.py    # Package marker
│ └── merger.py      # FleetMerger, MachineReport, DeduplicatedFinding, FleetStats, FleetReport; fleet HTML generation
├── analyzers/
│   ├── base.py        # BaseAnalyzer abstract class — all analyzers inherit this
│   ├── poisoning.py   # Tool description poisoning detection (regex-based)
│   ├── credentials.py # Secret/API key exposure in configs
│   ├── transport.py   # Transport security (TLS, localhost binding, etc.)
│   ├── supply_chain.py# Package provenance and typosquatting detection (registry-backed)
│   ├── rug_pull.py    # Description change detection via hashing
│   ├── toxic_flow.py  # Cross-server capability tagging and dangerous pair detection
│   └── attack_paths.py# Multi-hop attack path detection and greedy hitting set algorithm
├── baselines/
│   ├── __init__.py    # Package marker
│   └── manager.py     # BaselineManager, Baseline, BaselineServer, DriftFinding, DriftType; save/load/compare
├── registry/
│   ├── __init__.py    # Package marker
│   └── loader.py      # KnownServerRegistry, RegistryEntry, load_registry(); Levenshtein helper
├── output/
│   ├── terminal.py    # Rich-formatted console output (default); renders score/grade panel
│   ├── sarif.py       # SARIF for GitHub Security integration
│   ├── nucleus.py     # Nucleus FlexConnect formatter
│   └── dashboard.py   # Self-contained HTML dashboard with embedded D3 v7 graph and grade badge
└── data/
    ├── known_npm_packages.yaml  # Legacy npm package list (retained for reference; superseded by registry)
    └── d3.v7.min.js             # Bundled D3 v7 (embedded inline in dashboard HTML)
```

Data files at project root:
- `registry/known-servers.json` — curated dataset of 57 known-legitimate MCP servers; queried by the supply chain analyzer for typosquatting detection; ships in both the pip wheel and PyInstaller binary

GitHub Action at project root:
- `action.yml` — composite GitHub Action definition; allows any repo to wire mcp-audit into CI with a single workflow addition; inputs: `severity-threshold`, `format`, `config-paths`, `baseline`, `upload-sarif`; outputs: `finding-count`, `grade`, `sarif-path`

CI workflow and example workflows:
- `.github/workflows/mcp-audit-example.yml` — runs mcp-audit on this repo on push/PR; also the reference workflow users copy
- `examples/github-actions/basic.yml` — minimal setup (visibility only, never fails build)
- `examples/github-actions/strict.yml` — fail on MEDIUM or higher
- `examples/github-actions/with-baseline.yml` — drift detection against a committed baseline

Build and distribution scripts at project root:
- `build.py` — PyInstaller build script; produces `dist/mcp-audit-{os}-{arch}` single-file binary
- `scripts/install.sh` — curl-based end-user installer for GitHub Releases
- `scripts/generate_license.py` — **NOT shipped in the package** (excluded from wheel); offline tool for issuing Ed25519-signed Pro/Enterprise license keys to customers

## Key conventions

- Every module has a corresponding test file in tests/ (e.g., test_discovery.py)
- Detection patterns are hardcoded in each analyzer (regex constants); supply-chain data is now sourced from `registry/known-servers.json` via `registry/loader.py`
- All findings use the `Finding` Pydantic model from models.py
- Analyzers inherit from `BaseAnalyzer` and implement an `analyze()` method
- Output formatters inherit from `BaseFormatter` and implement a `format()` method
- The dashboard HTML template is a single large string (`_DASHBOARD_HTML`) embedded in `output/dashboard.py`. All scan data is injected via a `__SCAN_DATA_JSON__` placeholder at render time. D3 v7 is bundled from `data/d3.v7.min.js` and injected via `__D3_JS__`. Do not split the template into separate files.
- **Scoring** runs after all analyzers complete inside `scanner.py` and attaches a `ScanScore` to `ScanResult`. Analyzers never call the scorer directly. See `scoring.py` and `docs/scoring.md`.
- **Registry resolution order** for the supply chain analyzer: explicit `--registry PATH` CLI flag → user-local cache at `~/.config/mcp-audit/registry/known-servers.json` (written by `update-registry`) → PyInstaller `sys._MEIPASS/registry/` → `importlib.resources` (installed wheel) → dev repo-root fallback (`registry/known-servers.json`).
- `SupplyChainAnalyzer` accepts `registry=KnownServerRegistry` or `registry_path=Path` in `__init__` to allow test injection without touching the filesystem.

## Critical implementation details

- **VS Code uses `"servers"` as its MCP config root key; all other clients use `"mcpServers"`**
- MCP protocol communication is async — use asyncio and pytest-asyncio
- Core scanning MUST work fully offline — no network calls by default
- OSV.dev lookups are opt-in, skipped with --offline flag
- Rug-pull state is stored in ~/.mcp-audit/state.json
- License key stored at `~/.config/mcp-audit/license.key` (permissions 0o600); activate with `mcp-audit activate <key>`
- **Pro feature gating happens at the output/rendering layer only.** Analyzers and scan logic never check license state. Scans always run fully — gating only restricts which output formats are rendered.
- License verification is fully offline (Ed25519 public key hardcoded in `licensing.py`); the private key never ships with the package
- Exit codes: 0 = clean, 1 = findings found, 2 = error
- JSON output includes top-level `score` and `grade` fields from `ScanScore`; HTML dashboard displays a colour-coded grade badge in the header
- `scan --no-score` suppresses the grade panel in terminal output only; score is still calculated and present in JSON/HTML
- `scan --registry PATH` overrides the bundled and cached registry for that run
- `scan --baseline NAME` (or `--baseline latest`) loads a saved baseline and appends `DriftFinding`s converted to `Finding` objects (`analyzer="baseline"`) into all output formats after the normal scan
- `scan --output-file PATH` (alias for `--output` / `-o`) writes scan results to a file; parent directories are created automatically; required for the GitHub Action SARIF upload step
- `scan --severity-threshold LEVEL` filters findings to only those at or above the given level and drives exit code; default is `INFO` (all findings); `--severity-threshold high` exits 1 only if HIGH or CRITICAL findings exist
- `update-registry` fetches `registry/known-servers.json` from GitHub and saves it to the user-local cache; requires Pro tier (gated via `is_pro_feature_available("html_report")` as a proxy until a dedicated feature key is formalised)
- **Baseline storage** uses 0o700 dir / 0o600 file permissions, same pattern as rug-pull state files; env values are never stored, only key names (security — prevents secrets being persisted to disk)

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

Prototype complete (April 11, 2026). Built in a single day; extended April 12–13.

What's built:
- 6 analyzers: poisoning, credentials, transport, supply chain, rug-pull, toxic flow
- Attack path engine with multi-hop detection and greedy hitting set algorithm
- 5 output formats: terminal, JSON, SARIF, Nucleus FlexConnect, HTML dashboard
- Interactive D3 attack graph dashboard with light/dark mode (`mcp-audit dashboard`)
- `mcp-audit watch` command — continuous filesystem monitoring, re-scans on config change
- Machine identification (MachineInfo) embedded in scan output; `--asset-prefix` flag for fleet deployment
- PyInstaller binary builds — 16.6 MB standalone executable, no Python required
- Live MCP server connection via --connect (optional, MCP SDK)
- Scoped rug-pull state management (per-config-set hash isolation)
- 8 supported MCP clients including Copilot CLI and Augment
- Demo environment producing 27+ findings across all analyzer categories
- 662 tests passing, ruff clean
- Security review completed — 6 vulnerabilities fixed (V-01 through V-06)
- Pro/Enterprise license key system (Ed25519, fully offline); `licensing.py` + `scripts/generate_license.py`
- 11 CLI commands: scan, discover, pin, diff, dashboard, watch, version, activate, license, update-registry, merge
- **Fleet merge** — `mcp-audit merge [FILES...] [--dir DIRECTORY]` consolidates JSON scan outputs from multiple machines into a single fleet report; Enterprise-gated via `fleet_merge` feature key; supports terminal, JSON, and HTML output formats; deduplicates findings across machines by `(analyzer, server_name, title)`; see `docs/fleet-scanning.md`
- **GitHub Action** — `action.yml` at repo root; composite action with `severity-threshold`, `format`, `config-paths`, `baseline`, `upload-sarif` inputs; uploads SARIF to GitHub Security tab; writes job summary; see `docs/github-action.md`
- **Baseline snapshot & drift detection** — 5 new `baseline` sub-commands (save, list, compare, delete, export); `scan --baseline NAME/latest` injects drift findings into all output formats; storage in `~/.config/mcp-audit/baselines/` with 0o700 dir / 0o600 file permissions; env values never stored, only key names; see `docs/baselines.md`
- **Scan Score** — every scan now produces a numeric score (0–100) and letter grade (A–F); see `scoring.py` and `docs/scoring.md`
- **Known-Server Registry** — 57-entry curated dataset of legitimate MCP servers replaces the hardcoded YAML in the supply chain analyzer; see `registry/known-servers.json` and `docs/registry.md`

What's next (non-code):
- Disclose project to Nucleus colleagues, get expert feedback on detection logic
- Validate FlexConnect output against real Nucleus instance (need Swagger docs)
- Tune false positives (e.g., "base64 encode" in official filesystem server)

What's next (code, after feedback):
- Detection pattern tuning based on practitioner review
- GitHub Actions CI (test on macOS, Linux, Windows; multi-arch binary matrix)
- Documentation (usage guide, rule-writing guide, Nucleus integration guide)

## Provenance

All detection patterns are original implementations based on published security
research. No code was copied from existing scanners. Full source attribution is
documented in PROVENANCE.md — read it before adding new detection patterns.
Every new pattern must cite its research source.
The project now has 6 analyzers with patterns sourced from the research listed in PROVENANCE.md. Update PROVENANCE.md when adding new detection patterns or analyzers.
See GAPS.md for known detection quality limitations, severity calibration issues, and untested areas. Consult before claiming detection completeness or accuracy.
