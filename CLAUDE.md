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
├── cli/               # Typer app package — one submodule per command group
│ ├── __init__.py      # Defines `app` + sub-apps (baseline/rule/policy/extensions);
│ │                    #   re-exports `run_scan`, `cached_is_pro_feature_available`,
│ │                    #   `discover_configs`, `parse_config`, and
│ │                    #   `_REGISTRY_CACHE_PATH` so existing test patches at
│ │                    #   `mcp_audit.cli.*` continue to intercept.  Imports
│ │                    #   the command submodules at the bottom so their
│ │                    #   `@app.command()` decorators register.
│ ├── __main__.py      # `python -m mcp_audit.cli` entry (plus PyInstaller target)
│ ├── _helpers.py      # Cross-cutting helpers (`_write_output`)
│ ├── scan.py          # scan, discover, pin, diff, watch (+ `_drift_to_findings`,
│ │                    #   `_scoped_state_path`, `_newest_last_seen`).  The
│ │                    #   `scan` command is composed from `_apply_*` pipeline
│ │                    #   stages (baseline drift, governance, SAST,
│ │                    #   extensions, severity filter) and `_write_*` output
│ │                    #   helpers — see "scan() pipeline conventions" below.
│ ├── baseline.py      # baseline sub-app: save / list / compare / delete / export
│ ├── registry.py      # update-registry, verify
│ ├── rules.py         # rule sub-app: validate / test / list
│ ├── policy.py        # policy sub-app: validate / init / check (+ `_POLICY_TEMPLATE`)
│ ├── extensions.py    # extensions sub-app: discover / scan
│ ├── sast.py          # sast command
│ ├── dashboard.py     # dashboard command
│ ├── fleet.py         # merge command (+ `_collect_json_paths_from_dir`,
│ │                    #   `_print_fleet_report`)
│ └── license.py       # activate, license, version
├── scanner.py         # Orchestrator: discovery → parsing → analysis → output
├── scoring.py         # Scan score calculation (0–100) and letter grade (A–F) formatting
├── discovery.py       # Finds MCP config files across all supported clients
├── config_parser.py   # Parses JSON configs, normalizes across client formats
├── models.py          # Pydantic models: Finding, ServerConfig, ScanResult, ScanScore, Severity, AttackPath, MachineInfo
├── licensing.py       # Ed25519 license key verification; LicenseInfo model; is_pro_feature_available()
├── _gate.py           # gate(feature, console, message) — shared CLI helper for Pro/Enterprise feature gating; renders the standardised upsell panel
├── watcher.py         # Filesystem watcher for continuous monitoring (mcp-audit watch); _McpConfigEventHandler serialises callbacks via _scan_lock with single-event coalesced re-trigger
├── mcp_client.py      # Live MCP server connection via MCP SDK (--connect)
├── _paths.py          # data_dir() and resolve_bundled_resource() — shared helpers for locating bundled data in source, wheel, and PyInstaller frozen contexts
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
- `registry/known-servers.json` — curated dataset of 60 known-legitimate MCP servers; queried by the supply chain analyzer for typosquatting detection and by the toxic flow analyzer for authoritative capability tags (`RegistryEntry.capabilities`); ships in both the pip wheel and PyInstaller binary
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
- **`_run_static_pipeline()` in `scanner.py` is the canonical implementation of the analysis pipeline.** Both `run_scan` (sync) and `run_scan_async` (async, after live `--connect` enumeration completes) delegate to it. The helper is intentionally synchronous and runs steps 1–7 in this exact order: (1) per-server analyzers, (2) `RugPullAnalyzer.analyze_all`, (3) `ToxicFlowAnalyzer.analyze_all` with the shared registry, (4) `summarize_attack_paths`, (5) policy-as-code rule engine, (6) `calculate_score`, (7) attach `registry_stats`. Wire new analyzers or pipeline changes here, not in either entry point.
- Output formatters inherit from `BaseFormatter` and implement a `format()` method
- The dashboard HTML template is a single large string (`_DASHBOARD_HTML`) embedded in `output/dashboard.py`. All scan data is injected via a `__SCAN_DATA_JSON__` placeholder at render time. D3 v7 is bundled from `data/d3.v7.min.js` and injected via `__D3_JS__`. Do not split the template into separate files.
- **Scoring** runs after all analyzers complete inside `scanner.py` and attaches a `ScanScore` to `ScanResult`. Analyzers never call the scorer directly. See `scoring.py` and `docs/scoring.md`.
- **Registry resolution order** for the supply chain analyzer: explicit `--registry PATH` CLI flag → user-local cache at `<user-config-dir>/mcp-audit/registry/known-servers.json` (written by `update-registry`; path resolved via `platformdirs`) → PyInstaller `sys._MEIPASS/registry/` → `importlib.resources` (pip-installed wheel at `mcp_audit/registry/known-servers.json`) → dev repo-root fallback (`registry/known-servers.json`). Pass `--offline-registry` to skip the user-local cache step. All bundled resource resolution (registry, rules, semgrep-rules, extension vulns) goes through the shared `resolve_bundled_resource()` helper in `_paths.py`.
- **Terminal output** includes a dim one-liner registry stats line after the summary (e.g. "Registry: 60 known servers (v1.0, updated 2026-04-20)") pulled from `ScanResult.registry_stats`; omitted silently if `registry_stats` is `None`.
- **SARIF output** adds a `run.properties` block with `mcp-audit/grade`, `mcp-audit/numericScore`, `mcp-audit/positiveSignals`, and `mcp-audit/deductions` when `ScanResult.score` is not `None`; the block is absent when `--no-score` suppresses scoring.
- `SupplyChainAnalyzer` accepts `registry=KnownServerRegistry` or `registry_path=Path` in `__init__` to allow test injection without touching the filesystem.
- `TransportAnalyzer` accepts an optional `registry=KnownServerRegistry` in `__init__` to tier `TRANSPORT-003` severity by registry membership: verified entries suppress the finding, known-but-unverified entries fire at LOW, unknown packages fire at MEDIUM. `get_default_analyzers()` and `cli/scan.py::_build_custom_analyzers` share the same `SupplyChainAnalyzer.registry` instance so the JSON is read from disk exactly once per scan. Constructing `TransportAnalyzer()` without a registry preserves the historic "always MEDIUM" behaviour for tests that don't need the registry path.
- **Community rules always run.** The policy-as-code rule engine loads `rules/community/` for every scan regardless of license tier. Pro gating applies only to authoring tools (`rule validate`, `rule test`) and custom rule directories (`--rules-dir`, `<user-config-dir>/mcp-audit/rules/`; path resolved via `platformdirs`). The engine is invoked via `_run_rules_engine()` in `scanner.py` after all built-in analyzers complete. Rule findings use `analyzer="rules"` and `id=rule.id`.
- **Rule engine resolution order** for community rules: PyInstaller `sys._MEIPASS/rules/community/` → `importlib.resources` (installed wheel at `mcp_audit/rules/community/`) → dev repo-root fallback (`rules/community/`).
- **Supply chain attestation** (`attestation/`) implements Layer 1 hash-based integrity verification. `scan --verify-hashes` downloads package tarballs, computes SHA-256, and compares against pins in `RegistryEntry.known_hashes`. `mcp-audit verify` is a standalone free-tier command for interactive package verification. Attestation findings use `analyzer="attestation"`; CRITICAL for mismatches, INFO for unverifiable cases. See `docs/supply-chain.md`.
- **`scan()` pipeline conventions** (`cli/scan.py`): the `scan` command is a thin orchestrator that delegates each optional phase to a named helper. Helpers are `_apply_*` for pipeline stages that mutate/inject into `ScanResult` (baseline drift, governance, SAST, extensions, severity threshold) and `_write_*` for output-layer dispatch (`_write_formatted_output`). Preflight validation lives in `_preflight_checks`. Each helper has a docstring that states when it is called and its contract when the feature is not requested. Future scan-pipeline additions should follow this `_apply_*` / `_write_*` naming and be inserted into `scan()` as a single-line delegation — do not inline new phases in the command body. Test-patched symbols (`verify_server_hashes`, `discover_extensions`, `analyze_extensions`, `run_semgrep`) are imported as their containing module (e.g. `from mcp_audit.sast import runner as _sast_runner`) so `patch("mcp_audit.sast.runner.run_semgrep", ...)` continues to intercept.
- **Capability tags for toxic flow detection** are stored in `RegistryEntry.capabilities` (optional `list[str]` in `registry/known-servers.json`) and consulted by `analyzers/toxic_flow.py::tag_server(server, registry=...)` **before** any keyword or tool-name heuristic fallback. When `registry` is supplied and resolves a known package whose `capabilities` field is not `None`, those tags are returned verbatim — the registry is the single source of truth. The in-module `KNOWN_SERVERS` dict in `toxic_flow.py` is retained as a deterministic fallback for (a) unit tests that inject no registry and (b) cases where the registry is present but the entry has `capabilities=None`. `scanner.py` passes the `SupplyChainAnalyzer.registry` instance to `ToxicFlowAnalyzer(registry=…)` so the JSON file is read from disk exactly once per scan.

## Critical implementation details

- **VS Code uses `"servers"` as its MCP config root key; all other clients use `"mcpServers"`**
- MCP protocol communication is async — use asyncio and pytest-asyncio
- Core scanning MUST work fully offline — no network calls by default
- OSV.dev lookups are planned but **not yet implemented** — the `--offline` flag is accepted but currently has no network calls to suppress
- Rug-pull state is stored in `<user-config-dir>/mcp-audit/state/state.json` (resolved via `platformdirs`; macOS: `~/Library/Application Support/mcp-audit/state/`); a one-time migration copies state files from the legacy `~/.mcp-audit/` location on first access
- License key stored at `~/.config/mcp-audit/license.key` (permissions 0o600); activate with `mcp-audit activate <key>`
- **Pro feature gating happens at the output/rendering layer only.** Analyzers and scan logic never check license state. Scans always run fully — gating only restricts which output formats are rendered.
- **`gate(feature, console, message=None)` in `_gate.py` is the shared helper for CLI-layer Pro feature gating.** All CLI soft- and hard-gate sites funnel through this helper so the upsell panel wording stays consistent. Never call `gate()` from analyzers or `scanner.py` — gating is a CLI/presentation concern. Hard-gated commands follow the pattern `if not gate("feature", console): raise typer.Exit(N)`. The helper resolves its license check via `mcp_audit.cli.cached_is_pro_feature_available` so existing test patches at that attribute continue to intercept.
- **Watcher callback serialisation.** `_McpConfigEventHandler._fire()` holds `_scan_lock` for the entire duration of the user callback to prevent two `run_scan` calls from racing on `state_<hash>.json`. Events arriving while a scan is in flight are stored in `_pending_rescan` (tuple of latest `(path, event_type)`) and coalesced into a single re-trigger when the active callback returns. Never release the scan lock before the callback finishes.
- License verification is fully offline (Ed25519 public key hardcoded in `licensing.py`); the private key never ships with the package
- Exit codes: 0 = clean, 1 = findings found, 2 = error
- JSON output includes a nested `score` object from `ScanScore`: `{"numeric": int, "grade": str, "positive_signals": [], "deductions": []}` — `numeric` is 0–100, `grade` is "A"–"F", `positive_signals` and `deductions` carry the per-signal strings displayed in the terminal score panel; HTML dashboard displays a colour-coded grade badge in the header
- `scan --no-score` suppresses the grade panel in terminal output only; score is still calculated and present in JSON/HTML
- `scan --registry PATH` overrides the bundled and cached registry for that run
- `scan --offline-registry` uses the bundled registry only, skipping the user-local cache at `<user-config-dir>/mcp-audit/registry/known-servers.json`; typosquatting detection still runs using bundled data
- `scan --baseline NAME` (or `--baseline latest`) loads a saved baseline and appends `DriftFinding`s converted to `Finding` objects (`analyzer="baseline"`) into all output formats after the normal scan
- `scan --output-file PATH` (alias for `--output` / `-o`) writes scan results to a file; parent directories are created automatically; required for the GitHub Action SARIF upload step
- `scan --severity-threshold LEVEL` filters findings to only those at or above the given level and drives exit code; default is `INFO` (all findings); `--severity-threshold high` exits 1 only if HIGH or CRITICAL findings exist
- `scan --rules-dir PATH` loads additional YAML rule files from PATH for this scan; requires Pro tier (gated via `is_pro_feature_available("custom_rules")`); community rules always run regardless
- `update-registry` fetches `registry/known-servers.json` from GitHub and saves it to the user-local cache; requires Pro tier (gated via `is_pro_feature_available("update_registry")`; `update_registry` → pro, enterprise)
- **Baseline storage** uses 0o700 dir / 0o600 file permissions, same pattern as rug-pull state files; env values are never stored, only key names (security — prevents secrets being persisted to disk)
- `scan --policy PATH` loads a governance policy file; governance findings are appended to `result.findings` after the scan completes (and after baseline drift) so they flow through all output formatters automatically. `--policy` flag is free; `policy init` and `policy check` require Pro.
- **Governance policy resolution order** when `--policy` is not given: explicit flag → cwd → git repo root → `<user-config-dir>/mcp-audit/policy.yml` (resolved via `platformdirs`). Returns `None` (no check) if no file found.
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
 writes. Never use `Path.write_text()` for files under the user config directory
 (resolved via `platformdirs.user_config_dir("mcp-audit")`) unless a
 `chmod(0o600)` immediately follows.
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

**Dev extras required:** Run `uv sync --extra dev` before running tests for the
first time, or after a fresh clone. A plain `uv sync` omits `pytest-asyncio`
and other dev tools — async tests will silently fail with unknown-mark warnings
if this step is skipped.

- Run `uv run pytest` after every change
- Run `uv run ruff check src/ tests/` before committing
- Run `uv run bandit -r src/ -ll -f txt` periodically (we're a security tool — act like it)
- Run `./scripts/update_test_count.py` before tagging a release (or after a PR that changes the test count) to sync the hand-maintained test-count references in `README.md` and `CLAUDE.md`. CI runs the same script with `--check` on the ubuntu/py3.12 leg and fails on drift.
- Type hints on ALL function signatures
- Docstrings on all public functions and classes

**pip-audit status (2026-04-17):** `pip-audit` returns zero findings after bumping `cryptography` to `>=46.0.6,<47.0` to resolve CVE-2026-26007 (EC subgroup validation, fixed 46.0.5) and CVE-2026-34073 (DNS name constraint bypass, fixed 46.0.6). The lockfile resolves to `cryptography==46.0.7`.

**Bandit status (2026-04-17):** `bandit -r src/ -ll` returns zero medium+ findings.
Three B310 (`urllib.request` URL open) calls are intentionally suppressed via
`# nosec B310` with inline justifications:
- `attestation/hasher.py:67` — `urlretrieve` called only after an explicit
  `https://` scheme guard; URL is always an npm registry HTTPS tarball URL.
- `attestation/hasher.py:123` — `urlopen` target is always `https://pypi.org/…`
  (produced by `resolve_pip_tarball_url`; scheme guard in caller validates it).
- `cli/registry.py` (`update_registry`) — `urlopen` target is
 `_UPDATE_REGISTRY_URL`, a hardcoded `https://raw.githubusercontent.com/…`
 constant.
All three suppressions carry the rule ID and a one-line reason. No blanket
`# nosec` without a rule ID exists anywhere in the codebase.

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
- Demo environment producing 32 findings across all demo configs (8 per-config for `claude_desktop_config.json`; community rules analyzer included)
- 1398 tests passing; `ruff check src/ tests/` clean (zero errors); `ruff format src/ tests/` clean (zero files requiring reformatting) — verify with `uv run pytest --collect-only -q` before each release
- scanner.py coverage raised from ~50% to **89%** (2026-04-18); 45 new tests in `tests/test_scanner.py` covering all 15 integration scenarios: clean scan, findings scan, baseline drift, verify-hashes, SAST, extensions, policy, no-score, severity-threshold, offline-registry, empty config, rules-dir, pipeline order, asset-prefix, and async code paths; only the live `--connect` MCP protocol block (lines 215-240) remains untested (requires running MCP server + optional SDK)
- Security review completed — 6 vulnerabilities fixed (V-01 through V-06)
- Pro/Enterprise license key system (Ed25519, fully offline); `licensing.py` + `scripts/generate_license.py`
- 18 top-level CLI commands: scan, discover, pin, diff, dashboard, watch, version, activate, license, update-registry, merge, verify, sast, push-nucleus, baseline (5 sub-commands: save, list, compare, delete, export), rule (3 sub-commands: validate, test, list), policy (3 sub-commands: validate, init, check), extensions (2 sub-commands: discover, scan) — verify with `mcp-audit --help` before each release
- **push-nucleus** — `mcp-audit push-nucleus --url <url> --project-id <id>` runs a scan and pushes results directly to a Nucleus Security project via the FlexConnect API; Enterprise-gated via `nucleus` feature key; multipart/form-data upload using `urllib.request` only; polls import job to completion; Rich summary panel on success; `--output-file` for local copy; validated against nucleus-demo.nucleussec.com (2026-04-23); see `docs/nucleus-integration.md`
- **Fleet merge** — `mcp-audit merge [FILES...] [--dir DIRECTORY]` consolidates JSON scan outputs from multiple machines into a single fleet report; Enterprise-gated via `fleet_merge` feature key; supports terminal, JSON, and HTML output formats; deduplicates findings across machines by `(analyzer, server_name, title)`; see `docs/fleet-scanning.md`
- **GitHub Action** — `action.yml` at repo root; composite action with `severity-threshold`, `format`, `config-paths`, `baseline`, `upload-sarif`, `sast`, `sast-path` inputs; uploads SARIF to GitHub Security tab; writes job summary; `sast: 'true'` requires mcp-audit Pro and Semgrep pre-installed in the CI job (`pip install semgrep`) — Semgrep is not bundled in the action; see `docs/github-action.md`
- **Baseline snapshot & drift detection** — 5 new `baseline` sub-commands (save, list, compare, delete, export); `scan --baseline NAME/latest` injects drift findings into all output formats; storage in `<user-config-dir>/mcp-audit/baselines/` (resolved via `platformdirs`) with 0o700 dir / 0o600 file permissions; env values never stored, only key names; see `docs/baselines.md`
- **Scan Score** — every scan now produces a numeric score (0–100) and letter grade (A–F); see `scoring.py` and `docs/scoring.md`
- **Known-Server Registry** — 60-entry curated dataset of legitimate MCP servers replaces the hardcoded YAML in the supply chain analyzer and now also owns toxic-flow capability tags via the optional `RegistryEntry.capabilities` field; see `registry/known-servers.json` and `docs/registry.md`
- **Policy-as-code rule engine** (Chain Reaction Feature) — YAML-based custom detection rules; 12 community rules ship bundled and run for ALL users; `rule validate` / `rule test` / `rule list` subcommands; `scan --rules-dir PATH` and `<user-config-dir>/mcp-audit/rules/` for Pro user-local rules; rule findings flow through all output formats automatically; `custom_rules` feature key in `_FEATURE_TIERS`; see `docs/writing-rules.md` and `rules/README.md`
- **Pre-commit hook** (Chain Reaction Feature) — `.pre-commit-hooks.yaml` at repo root; `language: python`, `entry: mcp-audit`, `pass_filenames: false`, `types: [json]`; default threshold is HIGH; `examples/pre-commit/` has basic and strict configs; see `docs/pre-commit.md`
- **Governance policy engine** — YAML-based organisational requirements (approved server lists, score thresholds, transport constraints, registry membership, finding tolerances); `policy validate` / `policy init` / `policy check` subcommands; `scan --policy PATH` flag (free) auto-discovers `.mcp-audit-policy.yml` in cwd / repo root; governance findings flow through all output formats; terminal output shows a distinct yellow "Policy Violations" panel; SARIF governance findings tagged `governance-policy` with `GOV-` rule IDs; `governance` + `fleet_governance` feature keys in `_FEATURE_TIERS`; see `docs/governance.md` and `examples/policies/`
- **SAST rule pack** — 37 Semgrep rules (28 Python, 9 TypeScript) detecting injection, poisoning, credential, protocol, and transport vulnerabilities in MCP server source code; standalone (`semgrep --config semgrep-rules/ <path>`) or integrated (`mcp-audit scan --sast <path>`); Pro-gated integration; `mcp-audit sast <path>` standalone command; SAST findings have `analyzer="sast"` and flow through all output formats; `sast` feature key in `_FEATURE_TIERS`; `semgrep-rules/` bundled in pip wheel and PyInstaller binary; see `docs/sast-rules.md`, `docs/contributing-rules.md`, and `semgrep-rules/README.md`
- **IDE extension scanner** — discovers installed extensions across VS Code and Cursor (+ Windsurf/Augment paths for portability); 6 analysis layers: known-vuln registry, dangerous capability combos, wildcard activation, unknown publisher, sideloaded VSIX, stale AI extensions; `mcp-audit extensions discover` (free) and `mcp-audit extensions scan` (Pro); `scan --include-extensions` flag (Pro); `registry/known-extension-vulns.json` seed dataset (5 entries); `extensions` + `fleet_extensions` feature keys in `_FEATURE_TIERS`; findings use `analyzer="extensions"` and flow through all output formats; see `docs/extensions.md`

What's next (non-code):
- Disclose project to Nucleus colleagues, get expert feedback on detection logic
- ~~Validate FlexConnect output against real Nucleus instance~~ — completed 2026-04-23; `push-nucleus` command ships with validated schema
- Tune false positives (e.g., "base64 encode" in official filesystem server)
- Binary end-to-end smoke test now runs on all four platforms in CI as part of
  the release workflow; also runs on Ubuntu on every PR. See `scripts/smoke_test.py`.
- Binary size gate: warns at 25 MB, fails at 35 MB (sigstore dependency tree
  pushed the baseline from 16.6 MB to ~22–24 MB as of 0.6.0).

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

## Commit history audit (2026-04-17)

A full git commit history audit was performed before public release. All five
scan categories returned clean — no true positives found.

Audit steps run and verdict:

1. **Credential-like patterns** — All matches are false positives: regex constants
   inside `credentials.py`, Semgrep rule fixtures in `semgrep-rules/tests/*/vulnerable/`,
   test helper strings in `tests/test_analyzers.py` and `tests/fixtures/`, and demo
   configs in `demo/configs/`. No real credentials.

2. **Internal/non-public URLs** — `localhost` matches are in test fixtures and
   transport-analyzer unit tests (expected). `nucleussec.com` appears once in
   `output/nucleus.py` as a schema-reference comment (`# Schema reference: https://nucleussec.com/flexconnect`),
   which is public documentation — not an internal URL. No corp/staging/internal
   domain leakage.

3. **Private key material** — No matches. No `-----BEGIN … KEY` blocks anywhere
   in history.

4. **Common secret formats (AWS/GitHub/OpenAI tokens)** — All matches are
   intentional test fixtures:
   - `sk-abcdefghijklmnopqrstuvwxyz…` in `semgrep-rules/tests/*/vulnerable/`
     (Semgrep rule true-positive test cases — purely synthetic, not valid keys)
   - `ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890` in `tests/test_analyzers.py`,
     `tests/fixtures/clean_with_credential.json`, and `demo/configs/claude_desktop_config.json`
     (credential-detector test fixtures — purely synthetic, not a valid GitHub token)

5. **.gitignore coverage** — `.env`, `.env.*`, `*.key`, `*.pem` are all covered.

Result: **CLEAN — safe to make public.**

## Release engineering

### PyInstaller path resolution — test coverage (2026-04-17)

| Behaviour | Test coverage | Notes |
|---|---|---|
| `_resolve_bundled_path()` returns `_MEIPASS/registry/known-servers.json` when `sys.frozen=True` | `tests/test_registry.py::TestMeipassResolution` | Patches `sys.frozen` + `sys._MEIPASS` via `monkeypatch` |
| `KnownServerRegistry` loads from a simulated `_MEIPASS` layout | `tests/test_registry.py::TestMeipassResolution::test_frozen_registry_loads_via_patched_bundled_path` | Monkeypatches `BUNDLED_REGISTRY_PATH` |
| Corrupt PyInstaller bundle (missing registry file) raises `FileNotFoundError` | `tests/test_registry.py::TestMeipassResolution::test_locate_raises_when_bundled_path_missing` | Both user-cache and bundled path missing |
| `_LICENSE_FILE` is rooted at `Path.home() / ".config" / "mcp-audit"` | `tests/test_licensing.py::TestLicenseKeyPathResolution` | Asserts path shape without modifying `licensing.py` |
| `Path.home()` remains usable when `sys.frozen=True` | `tests/test_licensing.py::TestLicenseKeyPathResolution::test_license_file_path_survives_frozen_context` | PyInstaller does not break `Path.home()` |
| Binary entry point and bundled data intact after build | CI smoke test in `.github/workflows/release.yml` | `dist/<binary> version` runs before `upload-artifact` |

**Windows license path limitation:** `_LICENSE_FILE` in `licensing.py` still uses
`Path.home() / ".config" / ...` (POSIX-style), not `%APPDATA%`, because `licensing.py`
is marked do-not-modify.  All other config paths (`baselines/`, `registry/`, `policy.yml`,
`rules/`) now use `platformdirs.user_config_dir("mcp-audit")` and resolve correctly on
all platforms.  The `_LICENSE_FILE` fix is deferred to the next `licensing.py` refactor.

### CI workflow (`.github/workflows/ci.yml`)

Triggers on every push and pull request to **any branch**. Runs a 3×2 matrix (6 combinations):
- **OS:** `ubuntu-latest`, `macos-latest`, `windows-latest`
- **Python:** `3.11`, `3.12`
- `fail-fast: false` — a failure on one leg does not cancel the others.

Each leg runs: `pip install uv` → `uv pip install -e ".[dev]" --system` → `pytest tests/ -x -q` → `ruff check src/ tests/` → `ruff format --check src/ tests/`.

Uses `actions/setup-python@v5` (not the `astral-sh/setup-uv` action) so uv installs into the runner's system Python via `--system`, avoiding venv PATH issues. The workflow status badge is in `README.md`.

### Release workflow (`.github/workflows/release.yml`)

Triggers on `v*.*.*` tags (e.g. `git tag v0.2.0 && git push --tags`). Builds four binaries in parallel, then creates a GitHub Release with all four attached and auto-generated release notes.

| Runner | Spec file | Output binary |
|---|---|---|
| `macos-13` | `mcp-audit-darwin-x86_64.spec` | `mcp-audit-darwin-x86_64` |
| `macos-latest` | `mcp-audit-darwin-arm64.spec` | `mcp-audit-darwin-arm64` |
| `ubuntu-latest` | `mcp-audit-linux-x86_64.spec` | `mcp-audit-linux-x86_64` |
| `windows-latest` | `mcp-audit-windows-x86_64.spec` | `mcp-audit-windows-x86_64.exe` |

> `macos-13` is used for the x86_64 macOS build — `macos-latest` is now arm64 and would silently produce the wrong architecture.

### PyInstaller spec files

Four spec files live at the repo root: `mcp-audit-darwin-x86_64.spec`, `mcp-audit-darwin-arm64.spec`, `mcp-audit-linux-x86_64.spec`, `mcp-audit-windows-x86_64.spec`. All use a portable SPECPATH-relative root instead of hardcoded absolute paths:

```python
import os
root = os.path.dirname(os.path.abspath(SPECPATH))
```

All four specs include identical `datas` (5 entries: `mcp_audit/data`, both registry JSONs, `rules/community/`, `semgrep-rules/`) and the same full `hiddenimports` list. The only difference between specs is the `name=` field in the `EXE` block. The Linux spec is also consumed by `scripts/build-linux.sh` (Docker-based build); it uses the same SPECPATH-relative paths, which resolve correctly inside the container when the repo is mounted at any path.
