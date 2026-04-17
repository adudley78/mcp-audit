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
├── attestation/
│   ├── __init__.py    # Package marker
│   ├── hasher.py      # HashResult dataclass; compute_hash_from_file/url; resolve_npm/pip_tarball_url; verify_package_hash
│   └── verifier.py    # verify_server_hashes(); extract_version_from_server(); bridges registry → hasher → Finding objects
├── baselines/
│   ├── __init__.py    # Package marker
│   └── manager.py     # BaselineManager, Baseline, BaselineServer, DriftFinding, DriftType; save/load/compare
├── registry/
│   ├── __init__.py    # Package marker
│   └── loader.py      # KnownServerRegistry, RegistryEntry, load_registry(); Levenshtein helper
├── rules/
│   ├── __init__.py    # Package marker
│   └── engine.py      # PolicyRule, RuleMatch, MatchCondition, RuleEngine; load_rules_from_file/dir; load_bundled_community_rules
├── governance/
│   ├── __init__.py    # Package marker
│   ├── models.py      # GovernancePolicy, ApprovedServers, ScoreThreshold, TransportPolicy, RegistryPolicy, FindingPolicy, ClientOverride, PolicyMode
│   ├── loader.py      # load_policy(); resolution order: explicit → cwd → repo root → user config
│   └── evaluator.py   # evaluate_governance(); per-server policy checks; produces Finding objects with analyzer="governance"
├── output/
│   ├── terminal.py    # Rich-formatted console output (default); renders score/grade panel
│   ├── sarif.py       # SARIF for GitHub Security integration
│   ├── nucleus.py     # Nucleus FlexConnect formatter
│   └── dashboard.py   # Self-contained HTML dashboard with embedded D3 v7 graph and grade badge
├── extensions/
│   ├── __init__.py    # Package marker
│   ├── models.py      # ExtensionManifest, ExtensionVulnEntry Pydantic models
│   ├── discovery.py   # discover_extensions(), parse_manifest(); EXTENSION_PATHS per-client config
│   └── analyzer.py    # analyze_extensions(); check_known_vulns, check_permissions, check_wildcard_activation, check_provenance, check_sideloaded, check_stale; load_vuln_registry()
├── sast/
│   ├── __init__.py    # Package marker
│   ├── runner.py      # SastResult; find_semgrep(); find_rules_dir(); run_semgrep(); parse_semgrep_output(); severity mapping
│   └── bundler.py     # get_bundled_rules_path() — resolves semgrep-rules/ in PyInstaller builds
└── data/
    ├── known_npm_packages.yaml  # Legacy npm package list (retained for reference; superseded by registry)
    └── d3.v7.min.js             # Bundled D3 v7 (embedded inline in dashboard HTML)
```

Standalone rule pack at repo root:
- `semgrep-rules/` — 37 Semgrep rules (28 Python, 9 TypeScript) across 5 categories;
  runnable with `semgrep --config semgrep-rules/ <path>` without mcp-audit installed;
  bundled in the pip wheel and PyInstaller binary; see `docs/sast-rules.md`

Data files at project root:
- `registry/known-servers.json` — curated dataset of 57 known-legitimate MCP servers; queried by the supply chain analyzer for typosquatting detection; ships in both the pip wheel and PyInstaller binary
- `rules/community/` — 12 bundled community detection rules (COMM-001 through COMM-012); ship in both pip wheel and PyInstaller binary; run for ALL users including Community tier; see `docs/writing-rules.md`

GitHub Action at project root:
- `action.yml` — composite GitHub Action definition; allows any repo to wire mcp-audit into CI with a single workflow addition; inputs: `severity-threshold`, `format`, `config-paths`, `baseline`, `upload-sarif`; outputs: `finding-count`, `grade`, `sarif-path`

Pre-commit hook at project root:
- `.pre-commit-hooks.yaml` — pre-commit hook definition; `language: python`, `entry: mcp-audit`, `pass_filenames: false` (mcp-audit uses its own discovery), `types: [json]` (fires only on staged JSON files), `always_run: false`; default args run `scan --severity-threshold high`; see `docs/pre-commit.md`

CI workflow and example workflows:
- `.github/workflows/mcp-audit-example.yml` — runs mcp-audit on this repo on push/PR; also the reference workflow users copy
- `examples/github-actions/basic.yml` — minimal setup (visibility only, never fails build)
- `examples/github-actions/strict.yml` — fail on MEDIUM or higher
- `examples/github-actions/with-baseline.yml` — drift detection against a committed baseline
- `examples/pre-commit/basic.yaml` — minimal pre-commit config (blocks on HIGH+)
- `examples/pre-commit/strict.yaml` — strict pre-commit config (blocks on MEDIUM+)

Build and distribution scripts at project root:
- `build.py` — PyInstaller build script; produces `dist/mcp-audit-{os}-{arch}` single-file binary
- `scripts/build-linux.sh` — builds a standalone Linux x86_64 binary inside a `python:3.11-slim` Docker container; requires Docker Desktop running; outputs `dist/mcp-audit-linux-x86_64`; installs `binutils` (required by PyInstaller on Linux) via `apt-get` before building; prints file size and SHA-256 on success
- `scripts/install.sh` — curl-based end-user installer for GitHub Releases
- `scripts/generate_license.py` — **NOT shipped in the package** (excluded from wheel); offline tool for issuing Ed25519-signed Pro/Enterprise license keys to customers

## Key conventions

- Every module has a corresponding test file in tests/ (e.g., test_discovery.py)
- Detection patterns are hardcoded in each analyzer (regex constants); supply-chain data is now sourced from `registry/known-servers.json` via `registry/loader.py`
- All findings use the `Finding` Pydantic model from models.py
- Analyzers inherit from `BaseAnalyzer` and implement an `analyze()` method. **Exception:** `rug_pull.py` and `toxic_flow.py` have a no-op `analyze()` — real work is in `analyze_all()` (they need the full server list). `attack_paths.py` is not a `BaseAnalyzer` subclass — it is a standalone module exposing `summarize_attack_paths()`.
- Output formatters inherit from `BaseFormatter` and implement a `format()` method
- The dashboard HTML template is a single large string (`_DASHBOARD_HTML`) embedded in `output/dashboard.py`. All scan data is injected via a `__SCAN_DATA_JSON__` placeholder at render time. D3 v7 is bundled from `data/d3.v7.min.js` and injected via `__D3_JS__`. Do not split the template into separate files.
- **Scoring** runs after all analyzers complete inside `scanner.py` and attaches a `ScanScore` to `ScanResult`. Analyzers never call the scorer directly. See `scoring.py` and `docs/scoring.md`.
- **Registry resolution order** for the supply chain analyzer: explicit `--registry PATH` CLI flag → user-local cache at `~/.config/mcp-audit/registry/known-servers.json` (written by `update-registry`) → PyInstaller `sys._MEIPASS/registry/` → `importlib.resources` (installed wheel) → dev repo-root fallback (`registry/known-servers.json`). Pass `--offline-registry` to skip the user-local cache step.
- **Terminal output** includes a dim one-liner registry stats line after the summary (e.g. "Registry: 57 known servers (v1.0, updated 2026-04-15)") pulled from `ScanResult.registry_stats`; omitted silently if `registry_stats` is `None`.
- **SARIF output** adds a `run.properties` block with `mcp-audit/grade`, `mcp-audit/numericScore`, `mcp-audit/positiveSignals`, and `mcp-audit/deductions` when `ScanResult.score` is not `None`; the block is absent when `--no-score` suppresses scoring.
- `SupplyChainAnalyzer` accepts `registry=KnownServerRegistry` or `registry_path=Path` in `__init__` to allow test injection without touching the filesystem.
- **Community rules always run.** The policy-as-code rule engine loads `rules/community/` for every scan regardless of license tier. Pro gating applies only to authoring tools (`rule validate`, `rule test`) and custom rule directories (`--rules-dir`, `~/.config/mcp-audit/rules/`). The engine is invoked via `_run_rules_engine()` in `scanner.py` after all built-in analyzers complete. Rule findings use `analyzer="rules"` and `id=rule.id`.
- **Rule engine resolution order** for community rules: PyInstaller `sys._MEIPASS/rules/community/` → `importlib.resources` (installed wheel at `mcp_audit/rules/community/`) → dev repo-root fallback (`rules/community/`).
- **Supply chain attestation** (`attestation/`) implements Layer 1 hash-based integrity verification. `scan --verify-hashes` downloads package tarballs, computes SHA-256, and compares against pins in `RegistryEntry.known_hashes`. `mcp-audit verify` is a standalone free-tier command for interactive package verification. Attestation findings use `analyzer="attestation"`; CRITICAL for mismatches, INFO for unverifiable cases. See `docs/supply-chain.md`.

## Critical implementation details

- **VS Code uses `"servers"` as its MCP config root key; all other clients use `"mcpServers"`**
- MCP protocol communication is async — use asyncio and pytest-asyncio
- Core scanning MUST work fully offline — no network calls by default
- OSV.dev lookups are planned but **not yet implemented** — the `--offline` flag is accepted but currently has no network calls to suppress
- Rug-pull state is stored in ~/.mcp-audit/state.json
- License key stored at `~/.config/mcp-audit/license.key` (permissions 0o600); activate with `mcp-audit activate <key>`
- **Pro feature gating happens at the output/rendering layer only.** Analyzers and scan logic never check license state. Scans always run fully — gating only restricts which output formats are rendered.
- License verification is fully offline (Ed25519 public key hardcoded in `licensing.py`); the private key never ships with the package
- Exit codes: 0 = clean, 1 = findings found, 2 = error
- JSON output includes top-level `score` and `grade` fields from `ScanScore`; HTML dashboard displays a colour-coded grade badge in the header
- `scan --no-score` suppresses the grade panel in terminal output only; score is still calculated and present in JSON/HTML
- `scan --registry PATH` overrides the bundled and cached registry for that run
- `scan --offline-registry` uses the bundled registry only, skipping the user-local cache at `~/.config/mcp-audit/registry/known-servers.json`; typosquatting detection still runs using bundled data
- `scan --baseline NAME` (or `--baseline latest`) loads a saved baseline and appends `DriftFinding`s converted to `Finding` objects (`analyzer="baseline"`) into all output formats after the normal scan
- `scan --output-file PATH` (alias for `--output` / `-o`) writes scan results to a file; parent directories are created automatically; required for the GitHub Action SARIF upload step
- `scan --severity-threshold LEVEL` filters findings to only those at or above the given level and drives exit code; default is `INFO` (all findings); `--severity-threshold high` exits 1 only if HIGH or CRITICAL findings exist
- `scan --rules-dir PATH` loads additional YAML rule files from PATH for this scan; requires Pro tier (gated via `is_pro_feature_available("custom_rules")`); community rules always run regardless
- `update-registry` fetches `registry/known-servers.json` from GitHub and saves it to the user-local cache; requires Pro tier (gated via `is_pro_feature_available("update_registry")`; `update_registry` → pro, enterprise)
- **Baseline storage** uses 0o700 dir / 0o600 file permissions, same pattern as rug-pull state files; env values are never stored, only key names (security — prevents secrets being persisted to disk)
- `scan --policy PATH` loads a governance policy file; governance findings are appended to `result.findings` after the scan completes (and after baseline drift) so they flow through all output formatters automatically. `--policy` flag is free; `policy init` and `policy check` require Pro.
- **Governance policy resolution order** when `--policy` is not given: explicit flag → cwd → git repo root → `~/.config/mcp-audit/policy.yml`. Returns `None` (no check) if no file found.
- `scan --verify-hashes` downloads package tarballs and verifies SHA-256 against `known_hashes` pins in the registry; requires network; free for all tiers; findings appended to `result.findings` after the scan.

## Governance vs Rule Engine

The rule engine (`rules/`) pattern-matches inside server configs and produces `Finding` objects with `analyzer="rules"`. The governance engine (`governance/`) enforces *organisational requirements* — approved server lists, minimum scan scores, transport constraints, registry membership, finding tolerances — and produces `Finding` objects with `analyzer="governance"`. They are complementary: run together in every scan when a policy file is present.

Key differences:
- Rule engine: detects security issues in *how servers are configured* (e.g. credential leaks, poisoning patterns)
- Governance engine: enforces *which servers are allowed and what quality bar* the configuration must meet
- Community rules always run (free tier); custom rules are Pro-gated
- Governance `--policy` flag is free; `policy init` / `policy check` authoring tools are Pro-gated
- Governance findings appear in a distinct "Policy Violations" panel in terminal output (yellow border)

## Security hardening invariants

The following invariants were established during the pre-launch security hardening
pass (2026-04-17) and **must be maintained** in all future changes:

- **`subprocess.run()` always uses list form with `shell=False` (implicit default).**
  Never construct a shell command as a string and pass it to `subprocess.run()`.
  The `SEMGREP_TIMEOUT_SECONDS = 300` constant in `sast/runner.py` must be used
  for any subprocess timeout; hardcoded timeout integers are forbidden.
- **Baseline and registry cache files are always created at 0o700 dir / 0o600 file.**
  Use `os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)` for sensitive
  writes. Never use `Path.write_text()` for files in `~/.config/mcp-audit/` unless
  a `chmod(0o600)` immediately follows.
- **No bare `except:` clauses.** Use `except Exception:` at minimum, or a more
  specific type. Verify with `grep -rn "except:" src/` — must return zero matches.
- **All user-supplied paths resolved with `Path.resolve()` before use.**
  For baseline paths, confirm the resolved path stays within the storage directory
  via `candidate.relative_to(self._storage_dir)`. For `--registry` and `--policy`
  paths, `resolve()` is sufficient (no boundary check needed).
- **All `--path`, `--registry`, `--sast`, and `--policy` CLI arguments are validated
  to exist before use**, producing a clean exit code 2 and human-readable message on
  failure, never a Python traceback.

Known exception: `licensing.py` directory creation does not set `mode=0o700` (marked
do-not-modify). See GAPS.md → "Security limitations" for details.

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
- 1010 tests passing; `ruff check src/ tests/` clean (zero errors); `ruff format src/ tests/` clean (zero files requiring reformatting)
- Security review completed — 6 vulnerabilities fixed (V-01 through V-06)
- Pro/Enterprise license key system (Ed25519, fully offline); `licensing.py` + `scripts/generate_license.py`
- 18 top-level CLI commands: scan, discover, pin, diff, dashboard, watch, version, activate, license, update-registry, merge, verify, sast, baseline (5 sub-commands: save, list, compare, delete, export), rule (3 sub-commands: validate, test, list), policy (3 sub-commands: validate, init, check), extensions (2 sub-commands: discover, scan)
- **Fleet merge** — `mcp-audit merge [FILES...] [--dir DIRECTORY]` consolidates JSON scan outputs from multiple machines into a single fleet report; Enterprise-gated via `fleet_merge` feature key; supports terminal, JSON, and HTML output formats; deduplicates findings across machines by `(analyzer, server_name, title)`; see `docs/fleet-scanning.md`
- **GitHub Action** — `action.yml` at repo root; composite action with `severity-threshold`, `format`, `config-paths`, `baseline`, `upload-sarif` inputs; uploads SARIF to GitHub Security tab; writes job summary; see `docs/github-action.md`
- **Baseline snapshot & drift detection** — 5 new `baseline` sub-commands (save, list, compare, delete, export); `scan --baseline NAME/latest` injects drift findings into all output formats; storage in `~/.config/mcp-audit/baselines/` with 0o700 dir / 0o600 file permissions; env values never stored, only key names; see `docs/baselines.md`
- **Scan Score** — every scan now produces a numeric score (0–100) and letter grade (A–F); see `scoring.py` and `docs/scoring.md`
- **Known-Server Registry** — 57-entry curated dataset of legitimate MCP servers replaces the hardcoded YAML in the supply chain analyzer; see `registry/known-servers.json` and `docs/registry.md`
- **Policy-as-code rule engine** (Chain Reaction Feature) — YAML-based custom detection rules; 12 community rules ship bundled and run for ALL users; `rule validate` / `rule test` / `rule list` subcommands; `scan --rules-dir PATH` and `~/.config/mcp-audit/rules/` for Pro user-local rules; rule findings flow through all output formats automatically; `custom_rules` feature key in `_FEATURE_TIERS`; see `docs/writing-rules.md` and `rules/README.md`
- **Pre-commit hook** (Chain Reaction Feature) — `.pre-commit-hooks.yaml` at repo root; `language: python`, `entry: mcp-audit`, `pass_filenames: false`, `types: [json]`; default threshold is HIGH; `examples/pre-commit/` has basic and strict configs; see `docs/pre-commit.md`
- **Governance policy engine** — YAML-based organisational requirements (approved server lists, score thresholds, transport constraints, registry membership, finding tolerances); `policy validate` / `policy init` / `policy check` subcommands; `scan --policy PATH` flag (free) auto-discovers `.mcp-audit-policy.yml` in cwd / repo root; governance findings flow through all output formats; terminal output shows a distinct yellow "Policy Violations" panel; SARIF governance findings tagged `governance-policy` with `GOV-` rule IDs; `governance` + `fleet_governance` feature keys in `_FEATURE_TIERS`; see `docs/governance.md` and `examples/policies/`
- **SAST rule pack** — 37 Semgrep rules (28 Python, 9 TypeScript) detecting injection, poisoning, credential, protocol, and transport vulnerabilities in MCP server source code; standalone (`semgrep --config semgrep-rules/ <path>`) or integrated (`mcp-audit scan --sast <path>`); Pro-gated integration; `mcp-audit sast <path>` standalone command; SAST findings have `analyzer="sast"` and flow through all output formats; `sast` feature key in `_FEATURE_TIERS`; `semgrep-rules/` bundled in pip wheel and PyInstaller binary; see `docs/sast-rules.md`, `docs/contributing-rules.md`, and `semgrep-rules/README.md`
- **IDE extension scanner** — discovers installed extensions across VS Code and Cursor (+ Windsurf/Augment paths for portability); 6 analysis layers: known-vuln registry, dangerous capability combos, wildcard activation, unknown publisher, sideloaded VSIX, stale AI extensions; `mcp-audit extensions discover` (free) and `mcp-audit extensions scan` (Pro); `scan --include-extensions` flag (Pro); `registry/known-extension-vulns.json` seed dataset (5 entries); `extensions` + `fleet_extensions` feature keys in `_FEATURE_TIERS`; findings use `analyzer="extensions"` and flow through all output formats; see `docs/extensions.md`

What's next (non-code):
- Disclose project to Nucleus colleagues, get expert feedback on detection logic
- Validate FlexConnect output against real Nucleus instance (need Swagger docs)
- Tune false positives (e.g., "base64 encode" in official filesystem server)

What's next (code, after feedback):
- Detection pattern tuning based on practitioner review
- Community rule contributions — grow COMM-NNN library based on practitioner input
- GitHub Actions CI (test on macOS, Linux, Windows; multi-arch binary matrix)
- Documentation (usage guide, Nucleus integration guide)

## Provenance

All detection patterns are original implementations based on published security
research. No code was copied from existing scanners. Full source attribution is
documented in PROVENANCE.md — read it before adding new detection patterns.
Every new pattern must cite its research source.
The project now has 6 analyzers with patterns sourced from the research listed in PROVENANCE.md. Update PROVENANCE.md when adding new detection patterns or analyzers.
See GAPS.md for known detection quality limitations, severity calibration issues, and untested areas. Consult before claiming detection completeness or accuracy.
