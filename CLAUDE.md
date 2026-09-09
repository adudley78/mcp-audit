# mcp-audit

An open-source, privacy-first CLI tool that scans MCP (Model Context Protocol)
server configurations for security vulnerabilities. Think "Snyk for MCP servers."

## What this project does

Developers use MCP servers to give AI agents (Claude, Cursor, VS Code Copilot) access
to tools — file systems, databases, APIs, etc. These servers are configured via JSON
files and can be poisoned, misconfigured, or compromised. mcp-audit scans those configs
and flags security issues.

## Business model

Fully open source under Apache 2.0 — every feature is free for every user. There
is no Community / Pro / Enterprise split, no license-key gate, and no paid tier.
All paid-license plumbing (Ed25519 signing, revocation lists, `activate` /
`license` commands, the `gate()` shim) was removed in v0.2.0; anything that
still references `licensing.py` or `_gate.py` is stale. Funding is requested
via GitHub Sponsors (handle configured in `.github/FUNDING.yml`, with a
"Support" section in `README.md`), not through feature gating.

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
├── cli/               # Typer app package — one submodule per command group
│   ├── __init__.py      # Defines `app` + sub-apps (baseline/rule/policy/extensions/
│   │                    #   agent-files); re-exports `run_scan`, `discover_configs`,
│   │                    #   `parse_config`, and `_REGISTRY_CACHE_PATH` so test
│   │                    #   patches at `mcp_audit.cli.*` continue to intercept.
│   │                    #   Imports the command submodules at the bottom so their
│   │                    #   `@app.command()` decorators register.
│   ├── __main__.py      # `python -m mcp_audit.cli` entry (plus PyInstaller target)
│   ├── _helpers.py      # Cross-cutting helpers (`_write_output`)
│   ├── scan.py          # scan, discover, pin, watch (+ `_drift_to_findings`,
│   │                    #   `_scoped_state_path`, `_newest_last_seen`).  The
│   │                    #   `scan` command is composed from `_apply_*` pipeline
│   │                    #   stages (baseline drift, governance, SAST, extensions,
│   │                    #   agent-files, severity filter) and `_write_*` output
│   │                    #   helpers — see "scan() pipeline conventions" below.
│   ├── check.py         # check command: one-page practitioner verdict (+ _write_pdf_report)
│   ├── fix.py           # fix command: apply safe remediations to config files
│   ├── diff.py          # diff command: MCP-aware diff for PR review / CI gates
│   ├── baseline.py      # baseline sub-app: save / list / compare / delete / export
│   ├── registry.py      # update-registry, verify
│   ├── rules.py         # rule sub-app: validate / test / list
│   ├── policy.py        # policy sub-app: validate / init / check (+ `_POLICY_TEMPLATE`)
│   ├── extensions.py    # extensions sub-app: discover / scan
│   ├── agent_files.py   # agent-files sub-app: discover / scan (skills, memory, hooks)
│   ├── sast.py          # sast command
│   ├── sbom.py          # sbom command: CycloneDX 1.5 SBOM export
│   ├── vet.py           # vet command: pre-install package verdict (offline, facts not grades)
│   ├── shadow.py        # shadow command: shadow MCP server sweep (+ --continuous daemon)
│   ├── killchain.py     # killchain command: top blast-radius-cutting changes
│   ├── snapshot.py      # snapshot command: signed forensic snapshots (+ --rehydrate/--stream)
│   ├── dashboard.py     # dashboard command
│   ├── fleet.py         # merge command (+ `_collect_json_paths_from_dir`,
│   │                    #   `_print_fleet_report`)
│   ├── push_nucleus.py  # push-nucleus command: scan + push to Nucleus FlexConnect API
│   ├── register.py      # register command: interactive opt-in flow, --clear, --status
│   ├── advise.py        # advise command + feed sub-app (feed verify): OSV advisory feed
│   └── version.py       # version command
├── scanner.py         # Orchestrator: discovery → parsing → analysis → output
├── scoring.py         # Scan score calculation (0–100) and letter grade (A–F) formatting
├── discovery.py       # Finds MCP config files across all supported clients
├── config_parser.py   # Parses JSON configs, normalizes across client formats
├── models.py          # Pydantic models: Finding, ServerConfig, ScanResult, ScanScore, Severity, AttackPath, MachineInfo
├── owasp_mcp.py       # Single source of truth for OWASP MCP Top 10 codes/names (MCP01–MCP10)
├── verdict.py         # Pure verdict builder for `vet` (shared with the mcp-audit.dev generator)
├── watcher.py         # Filesystem watcher for continuous monitoring (mcp-audit watch); _McpConfigEventHandler serialises callbacks via _scan_lock with single-event coalesced re-trigger
├── mcp_client.py      # Live MCP server connection via MCP SDK (--connect)
├── _paths.py          # data_dir() and resolve_bundled_resource() — shared helpers for locating bundled data in source, wheel, and PyInstaller frozen contexts
├── _network.py        # NetworkPolicy + require_offline_compatible() — centralised --offline mutual-exclusion enforcement for network-touching flags
├── analyzers/
│   ├── base.py         # BaseAnalyzer abstract class — all analyzers inherit this
│   ├── poisoning.py    # Tool description poisoning detection (regex-based); PATTERNS list reused by agent_files; also owns POISON-041/042 concealment-channel extract/decode/rescan (scan_concealed_channels, build_concealment_finding), shared with agent_files
│   ├── credentials.py  # Secret/API key exposure in configs (SECRET_PATTERNS)
│   ├── transport.py    # Transport security (TLS, localhost binding, etc.)
│   ├── supply_chain.py # Package provenance and typosquatting detection (registry-backed)
│   ├── config_hygiene.py # Config-file filesystem hygiene (CFHYG-001..006); hook-command checks HOOK-001/002 via analyze_config
│   ├── rug_pull.py     # Description change detection via hashing
│   ├── toxic_flow.py   # Cross-server capability tagging and dangerous pair detection
│   ├── auth.py         # Remote server authentication checks (AUTH-001, AUTH-002)
│   ├── collision.py    # Tool-name collision detection across --connect servers (COLLIDE-001)
│   └── attack_paths.py # Multi-hop attack path detection and greedy hitting set algorithm
├── agent_files/       # Agent instruction/memory file scanner (SKILL-001/002/003, MEM-001/002; also emits POISON-041/042, analyzer="poisoning")
│   ├── __init__.py    # Package marker; offline-only invariant docs
│   ├── models.py      # AgentFile dataclass, AgentFileSurface StrEnum
│   ├── discovery.py   # discover_agent_files(); user-global + project-tree walk (mirrors discovery.py conventions)
│   └── analyzer.py    # analyze_agent_files(); imports PATTERNS from analyzers/poisoning.py (never forked), plus scan_concealed_channels/build_concealment_finding for POISON-041/042. NB: HOOK-001/002 live in analyzers/config_hygiene.py, not here
├── advisory/          # OSV 1.6.0 advisory records + signed feed (mcp-audit advise / feed verify)
│   ├── __init__.py    # Package marker; re-exports Advisory, build_advisory, write_feed, sign_feed, verify_feed
│   ├── schema.py      # Advisory dataclass → OSV 1.6.0 JSON; stable `x_MCPSA-<12hex>` IDs; MCP metadata under affected[].database_specific; FINDING_CLASS_TO_OWASP + owasp_for(); rejects codes owasp_mcp.py does not define
│   ├── classify.py    # finding ID → finding_class / observation / CVSS 3.1 vector (cvss_base_score reconciliation); owasp_codes_for() validates against owasp_mcp.py; is_advisable() excludes non-vulnerability findings
│   ├── canonical.py   # RFC 8785 JCS canonicalization (UTF-16 key order, ECMAScript number format) — the bytes that get signed; depth/size bound (CanonicalError)
│   ├── freshness.py   # snapshot_version / published_at / expires on index.json only; TTL; seen.json keyed on signing identity
│   ├── feed.py        # build_advisory / build_advisories / write_feed (advisories/, index.json, osv/all.json+zip); resolve_package, redact; feed_version 1.1
│   ├── sign.py        # cosign (default) + minisign backends, static project key; sign_feed / verify_feed / feed_is_signed; signing block embedded in index.json
│   ├── validate.py    # validate_osv() against the vendored schema; ValidationUnavailableError when jsonschema is absent
│   └── osv_schema/    # Vendored osv-1.6.0.json — pinned, offline, bundled in wheel and PyInstaller binary
├── attestation/       # Supply-chain integrity verification (Layer 1 hashes, Layer 2 Sigstore)
│   ├── __init__.py    # Package marker
│   ├── hasher.py      # HashResult dataclass; compute_hash_from_file/url; resolve_npm/pip_tarball_url; verify_package_hash
│   ├── verifier.py    # verify_server_hashes(); extract_version_from_server(); bridges registry → hasher → Finding objects
│   ├── sigstore_client.py   # Layer 2 Sigstore bundle discovery/verification via npm + PyPI registry APIs
│   └── sigstore_findings.py # AttestationResult → Finding translation for Layer 2 Sigstore verification
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
├── vulnerability/     # OSV.dev CVE lookups for `scan --check-vulns` (network, opt-in)
│   ├── __init__.py    # Package marker
│   ├── models.py      # ResolvedPackage, VulnAdvisory data models
│   ├── resolver.py    # extract_ecosystem_and_version(); resolve_latest_version() from a ServerConfig
│   ├── depsdev.py     # fetch_transitive_deps() — transitive dependency graph from deps.dev
│   ├── osv.py         # query_vulns_batch() — OSV.dev batch CVE query
│   └── scanner.py     # check_vulnerabilities() — orchestrates resolver → depsdev → osv → Finding objects
├── diff/              # MCP-aware diff engine (mcp-audit diff)
│   ├── __init__.py    # Package marker
│   ├── loader.py      # Load diff inputs (directory, JSON scan file, or git SHA) into ServerConfig lists
│   ├── comparator.py  # Compare two ServerConfig lists → flat list of Change objects
│   ├── risk.py        # Risk classification for diff changes
│   └── render.py      # Render diff to terminal, JSON, and PR-comment Markdown
├── fixer/             # Safe-remediation engine (mcp-audit fix)
│   ├── __init__.py    # Package marker
│   ├── fixer.py       # Fixer orchestrator — load config, apply strategies, write atomically with .bak
│   └── strategies/
│       ├── __init__.py     # Package marker
│       ├── base.py         # FixStrategy abstract base
│       ├── credentials.py  # CRED-001/002/003 — redact plaintext secrets with ${ENV_KEY}
│       ├── transport.py    # TRANSPORT-001 — upgrade http:// URLs to https://
│       └── pinning.py      # SC-001/002 — replace typosquat with verified registry name @version
├── killchain/         # Decision engine over the attack-path graph (mcp-audit killchain)
│   ├── __init__.py    # Package marker
│   ├── recommender.py # Rank kill switches from the hitting-set output by incremental path reduction
│   ├── simulator.py   # What-if simulation: re-run summarize_attack_paths against the modified server list
│   ├── patches.py     # Generate governance-policy denylist / PR-comment patch snippets
│   └── render.py      # Markdown and JSON output formatters for killchain results
├── shadow/            # Shadow MCP server detection (mcp-audit shadow)
│   ├── __init__.py    # Package marker
│   ├── allowlist.py   # Operator allowlist of sanctioned servers; load/match
│   ├── classifier.py  # Pure sanctioned-vs-shadow classification given server + allowlist
│   ├── risk.py        # RiskLevel scoring for a single server (toxic-flow capability logic)
│   ├── events.py      # Structured events for --continuous daemon mode (new_shadow_server, server_drift, server_removed)
│   └── state.py       # first_seen/last_seen state at <user-config-dir>/mcp-audit/shadow/state.json (0o600)
├── snapshot/          # Forensic snapshot rehydrate/diff (mcp-audit snapshot)
│   ├── __init__.py    # Package marker
│   ├── rehydrate.py   # Reconstruct the historical attack-path graph from a recorded snapshot JSON
│   └── diff.py        # "What changed since the snapshot?" — servers added/removed/changed
├── output/
│   ├── __init__.py    # Package marker
│   ├── base.py        # BaseFormatter abstract class — all formatters inherit this
│   ├── terminal.py    # Rich-formatted console output (default); renders score/grade panel
│   ├── sarif.py       # SARIF for GitHub Security integration
│   ├── nucleus.py     # Nucleus FlexConnect formatter
│   ├── dashboard.py   # Self-contained HTML dashboard with embedded D3 v7 graph and grade badge
│   ├── check.py       # One-page security verdict formatter for `mcp-audit check` (_HINTS)
│   ├── advisory.py    # AdvisoryFormatter(BaseFormatter) — ScanResult → JSON array of OSV 1.6.0 records; byte-identical to feed/osv/all.json (feed *directories* stay in advisory/feed.py)
│   ├── cyclonedx.py   # CycloneDX SBOM formatter (supports cyclonedx-python-lib 7.x–11.x)
│   ├── snapshot.py    # Snapshot formatters: CycloneDX AI/ML-BOM and native JSON
│   └── pdf.py         # Letter-size PDF compliance report (mcp-audit scan --report pdf)
├── extensions/
│   ├── __init__.py    # Package marker
│   ├── models.py      # ExtensionManifest, ExtensionVulnEntry Pydantic models
│   ├── discovery.py   # discover_extensions(), parse_manifest(); EXTENSION_PATHS per-client config
│   └── analyzer.py    # analyze_extensions(); check_known_vulns, check_permissions, check_wildcard_activation, check_provenance, check_sideloaded, check_stale; load_vuln_registry()
├── registration/
│   ├── __init__.py    # Package marker; privacy-invariant docs
│   ├── models.py      # RegistrationConfig, RegistrationPostPayload, RegistrationPingPayload Pydantic models
│   ├── manager.py     # load/save/clear_registration(); build_registration(); 0o600 file write; platformdirs storage
│   └── client.py      # post_registration() (PII POST, once); post_ping() (no-PII, per scan); _REGISTER_ENDPOINT constant; urllib.request only
├── sast/
│   ├── __init__.py    # Package marker
│   ├── runner.py      # SastResult; find_semgrep(); find_rules_dir(); run_semgrep(); parse_semgrep_output(); severity mapping
│   └── bundler.py     # get_bundled_rules_path() — resolves semgrep-rules/ in PyInstaller builds
├── fleet/
│   ├── __init__.py    # Package marker
│   └── merger.py      # FleetMerger, MachineReport, DeduplicatedFinding, FleetStats, FleetReport; fleet HTML generation
└── data/
    ├── known_npm_packages.yaml  # Legacy npm package list (retained for reference; superseded by registry)
    └── d3.v7.min.js             # Bundled D3 v7 (embedded inline in dashboard HTML)
```

Standalone rule pack at repo root:
- `semgrep-rules/` — 89 Semgrep rules (46 Python, 43 TypeScript) across 6 categories;
 runnable with `semgrep --config semgrep-rules/ <path>` without mcp-audit installed;
 bundled in the pip wheel and PyInstaller binary; see `docs/sast-rules.md`

Data files at project root:
- `registry/known-servers.json` — curated dataset of 50 known-legitimate MCP servers; queried by the supply chain analyzer for typosquatting detection and by the toxic flow analyzer for authoritative capability tags (`RegistryEntry.capabilities`); ships in both the pip wheel and PyInstaller binary
- `rules/community/` — 37 bundled community rules total: 36 real detection rules (`COMM-001` through `COMM-034`; `COMM-032` is intentionally reserved/unissued — see `PROVENANCE.md`) plus `STDIO-001`/`STDIO-002a`/`STDIO-002b` (launch-command trust boundary, STORY-0067; `STDIO-001` ships `enabled: false` — see `GAPS.md`) plus `TEMPLATE.yml` itself, which loads as the always-inert `COMM-000` (contribution template — `tests/test_rules.py` guarantees it never fires on a real config); `BOUNTY.md` (bounty program terms) ships alongside but is not a rule file. All ship in both pip wheel and PyInstaller binary; run for ALL users; see `docs/writing-rules.md` and `docs/contributing-rules.md`

GitHub Action at project root:
- `action.yml` — composite GitHub Action definition; allows any repo to wire mcp-audit into CI with a single workflow addition; inputs: `config-paths`, `severity-threshold`, `sarif-output`, `upload-sarif`, `check-vulns`, `verify-signatures`, `run-sast`, `sast-path`, `baseline-name`, `fail-on-findings`, `version`; outputs: `findings-count`, `grade`, `sarif-path`. Uses `github/codeql-action/upload-sarif@v4` with `continue-on-error: true` so repos without Code Scanning enabled still run cleanly. Marketplace-ready — passes `tests/test_action_yaml.py` structural and safety checks.

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
- `scripts/install.sh` — curl-based end-user installer for GitHub Releases

## Key conventions

- Every module has a corresponding test file in tests/ (e.g., test_discovery.py)
- Detection patterns are hardcoded in each analyzer (regex constants); supply-chain data is now sourced from `registry/known-servers.json` via `registry/loader.py`
- All findings use the `Finding` Pydantic model from models.py
- Analyzers inherit from `BaseAnalyzer` and implement an `analyze()` method. **Exception:** `rug_pull.py` and `toxic_flow.py` have a no-op `analyze()` — real work is in `analyze_all()` (they need the full server list). `attack_paths.py` is not a `BaseAnalyzer` subclass — it is a standalone module exposing `summarize_attack_paths()`. `collision.py` is also not a `BaseAnalyzer` subclass — it exposes `detect_tool_collisions(pairs)` and is called in `run_scan_async()` after the `--connect` loop, before `_run_static_pipeline()`.
- **`_run_static_pipeline()` in `scanner.py` is the canonical implementation of the analysis pipeline.** Both `run_scan` (sync) and `run_scan_async` (async, after live `--connect` enumeration completes) delegate to it. The helper is intentionally synchronous and runs steps 1–7 in this exact order: (1) per-server analyzers, (2) `RugPullAnalyzer.analyze_all`, (3) `ToxicFlowAnalyzer.analyze_all` with the shared registry, (4) `summarize_attack_paths`, (5) policy-as-code rule engine, (6) `calculate_score`, (7) attach `registry_stats`. Wire new analyzers or pipeline changes here, not in either entry point. **Exception:** `detect_tool_collisions()` from `collision.py` runs in `run_scan_async()` inside the `if connect:` block, immediately after the per-server enumeration loop and before `_run_static_pipeline()`. It is not part of `_run_static_pipeline()` because it requires live `ServerEnumeration` data that is not available in the static pipeline.
- Output formatters inherit from `BaseFormatter` and implement a `format()` method
- The dashboard HTML template is a single large string (`_DASHBOARD_HTML`) embedded in `output/dashboard.py`. All scan data is injected via a `__SCAN_DATA_JSON__` placeholder at render time. D3 v7 is bundled from `data/d3.v7.min.js` and injected via `__D3_JS__`. Do not split the template into separate files.
- **Scoring** runs after all analyzers complete inside `scanner.py` and attaches a `ScanScore` to `ScanResult`. Analyzers never call the scorer directly. See `scoring.py` and `docs/scoring.md`.
- **Registry resolution order** for the supply chain analyzer: explicit `--registry PATH` CLI flag → user-local cache at `<user-config-dir>/mcp-audit/registry/known-servers.json` (written by `update-registry`; path resolved via `platformdirs`) → PyInstaller `sys._MEIPASS/registry/` → `importlib.resources` (pip-installed wheel at `mcp_audit/registry/known-servers.json`) → dev repo-root fallback (`registry/known-servers.json`). Pass `--offline-registry` to skip the user-local cache step. All bundled resource resolution (registry, rules, semgrep-rules, extension vulns) goes through the shared `resolve_bundled_resource()` helper in `_paths.py`.
- **Terminal output** includes a dim one-liner registry stats line after the summary (e.g. "Registry: 60 known servers (v1.0, updated 2026-04-20)") pulled from `ScanResult.registry_stats`; omitted silently if `registry_stats` is `None`.
- **SARIF output** adds a `run.properties` block with `mcp-audit/grade`, `mcp-audit/numericScore`, `mcp-audit/positiveSignals`, and `mcp-audit/deductions` when `ScanResult.score` is not `None`; the block is absent when `--no-score` suppresses scoring.
- `SupplyChainAnalyzer` accepts `registry=KnownServerRegistry` or `registry_path=Path` in `__init__` to allow test injection without touching the filesystem.
- `TransportAnalyzer` accepts an optional `registry=KnownServerRegistry` in `__init__` to tier `TRANSPORT-003` severity by registry membership: verified entries suppress the finding, known-but-unverified entries fire at LOW, unknown packages fire at MEDIUM. `get_default_analyzers()` and `cli/scan.py::_build_custom_analyzers` share the same `SupplyChainAnalyzer.registry` instance so the JSON is read from disk exactly once per scan. Constructing `TransportAnalyzer()` without a registry preserves the historic "always MEDIUM" behaviour for tests that don't need the registry path.
- **Every Finding carries an OWASP MCP Top 10 mapping** in `Finding.owasp_mcp_top_10` (list of `MCP01`–`MCP10` codes; empty list = unmapped). The single source of truth for codes/names is `src/mcp_audit/owasp_mcp.py`. SARIF output exposes the mapping via a `runs[0].taxonomies` block and per-rule `relationships`. The full per-finding-ID mapping is documented in `docs/severity-framework.md`. Terminal output shows codes inline; `mcp-audit scan --owasp-report` prints a category-level aggregation.
- **Community rules always run.** The policy-as-code rule engine loads `rules/community/` for every scan. Authoring tools (`rule validate`, `rule test`) and custom rule directories (`--rules-dir`, `<user-config-dir>/mcp-audit/rules/`; path resolved via `platformdirs`) are available to everyone — gating has been removed. The engine is invoked via `_run_rules_engine()` in `scanner.py` after all built-in analyzers complete. Rule findings use `analyzer="rules"` and `id=rule.id`.
- **Rule engine resolution order** for community rules: PyInstaller `sys._MEIPASS/rules/community/` → `importlib.resources` (installed wheel at `mcp_audit/rules/community/`) → dev repo-root fallback (`rules/community/`).
- **Supply chain attestation** (`attestation/`) implements Layer 1 hash-based integrity verification. `scan --verify-hashes` downloads package tarballs, computes SHA-256, and compares against pins in `RegistryEntry.known_hashes`. `mcp-audit verify` is a standalone command for interactive package verification. Attestation findings use `analyzer="attestation"`; CRITICAL for mismatches, INFO for unverifiable cases. See `docs/supply-chain.md`.
- **`scan()` pipeline conventions** (`cli/scan.py`): the `scan` command is a thin orchestrator that delegates each optional phase to a named helper. Helpers are `_apply_*` for pipeline stages that mutate/inject into `ScanResult` (baseline drift, governance, SAST, extensions, agent-files, advisory feed, severity threshold) and `_write_*` for output-layer dispatch (`_write_formatted_output`). Preflight validation lives in `_preflight_checks`. Each helper has a docstring that states when it is called and its contract when the feature is not requested. Future scan-pipeline additions should follow this `_apply_*` / `_write_*` naming and be inserted into `scan()` as a single-line delegation — do not inline new phases in the command body. Test-patched symbols (`verify_server_hashes`, `discover_extensions`, `analyze_extensions`, `run_semgrep`) are imported as their containing module (e.g. `from mcp_audit.sast import runner as _sast_runner`) so `patch("mcp_audit.sast.runner.run_semgrep", ...)` continues to intercept.
- **Capability tags for toxic flow detection** are stored in `RegistryEntry.capabilities` (optional `list[str]` in `registry/known-servers.json`) and consulted by `analyzers/toxic_flow.py::tag_server(server, registry=...)` **before** any keyword or tool-name heuristic fallback. When `registry` is supplied and resolves a known package whose `capabilities` field is not `None`, those tags are returned verbatim — the registry is the single source of truth. The in-module `KNOWN_SERVERS` dict in `toxic_flow.py` is retained as a deterministic fallback for (a) unit tests that inject no registry and (b) cases where the registry is present but the entry has `capabilities=None`. `scanner.py` passes the `SupplyChainAnalyzer.registry` instance to `ToxicFlowAnalyzer(registry=…)` so the JSON file is read from disk exactly once per scan.
  **This override-not-union design means an incomplete `capabilities` list on
  a `verified` entry is strictly worse than no list at all** — it switches
  off the keyword-heuristic fallback that would otherwise have caught the
  gap (R34, prompted by a docpull registry-entry-vs-checkbox mismatch that
  had already produced one wrong public comment on
  [#35](https://github.com/adudley78/mcp-audit/issues/35)). Two read-only,
  offline checks in `scripts/audit_registry.py` guard against this on every
  run, unconditionally, before the network audit loop: (1) any entry whose
  declared `capabilities` are a **strict subset** of what the keyword
  heuristics alone would infer for that package name (`compute_inferred_capabilities`
  / `find_undeclared_capabilities`) is reported for human review — a subset
  is a signal, not proof, so it is never auto-fixed; (2) any capability
  string in the registry that is **not** a defined `Capability` enum member
  (`find_unknown_capabilities`) is reported and must be fixed by hand — this
  caught a real, live defect where three entries (`@mcpjam/inspector`,
  `gemini-mcp-tool`, `flowise`) used `"subprocess"` instead of `"shell_exec"`,
  meaning `_is_known_cap()` had been silently dropping it and `flowise`'s
  declared `network_out` + intended `shell_exec` never once triggered
  `TOXIC-006` (CRITICAL) for anyone scanning it, despite both packages
  independently carrying RCE CVEs (CVE-2025-59528, GHSA-4h5r-5jm8-jxjm) that
  corroborate the intended capability. Deliberately asymmetric with
  `_is_known_cap()`'s own silent-drop behaviour at read time: that silence
  is forward compatibility (an older installed client must not crash on a
  capability name a newer registry file defines), while this script speaks
  for the maintainers validating *our own* data before it ships, where the
  same string is just a typo nobody would otherwise see.
  `Capability.CLOUD` (added in R34) is deliberately **tag-only** — recorded,
  inferable via a `KEYWORD_RULES` entry (aws/gcp/azure/s3/ec2/lambda/etc.),
  but not wired into `TOXIC_PAIRS` or `attack_paths.CAPABILITY_FLOWS`, because
  it does not open a new exfiltration primitive `NETWORK_OUT` doesn't already
  cover (cloud SDK calls are HTTPS) and calibrating dedicated pairs for its
  distinct blast radius (IAM-scoped infrastructure control) needs its own
  research-and-measurement pass, not a guess. The registry-submission issue
  template (`.github/ISSUE_TEMPLATE/registry-submission.yml`) offers exactly
  one checkbox per `Capability` member and vice versa — pinned by
  `tests/test_registry_submission_template.py` — after R34 dropped a
  "persist data across sessions (memory)" checkbox that mapped to nothing
  (submitters should check whichever of file/database/network already
  covers their actual persistence mechanism) and merged "execute code" into
  "execute shell commands" (both are `SHELL_EXEC`).
  **R35 tightened both of R34's own checks after they shipped with gaps:**
  (1) `find_undeclared_capabilities()` was a strict-subset test
  (`declared < inferred`), which misses the partial-overlap case where an
  entry declares something the heuristics don't infer AND omits something
  they do (those sets are incomparable, so `<` is `False`). Generalised to
  `inferred - declared` non-empty (subsumes strict subset); each hit is
  tagged `"subset"` or `"disjoint"` so the two shapes stay distinguishable
  in the report. Measured before adopting, per the task's own decision
  rule: re-running against all 50 live entries (correctly, via `uv run
  python3` — see next point) found exactly one new hit beyond the zero the
  strict form found, and it was real, not heuristic over-fire, so the
  general predicate was adopted outright with no reviewed-exception
  mechanism (there was no legitimate-narrowing case in the data to design
  one against). Both real hits found across the two runs were fixed in the
  same PR: `@palisadeemail/mcp` (declared only `network_out`; its own
  `tags` already say `"email"`) and `@azure/mcp` (declared only
  `network_out`; its own `tags` already say `"cloud"`) — the same
  self-contradicting-metadata shape as the R34 `docpull` near-miss, just
  caught before a comment about it went out this time.
  (2) Added `find_dead_capabilities()`: a `Capability` that appears in no
  `TOXIC_PAIRS` entry and no `attack_paths.CAPABILITY_FLOWS` edge can be
  recorded but never contributes to a finding — the `subprocess` defect's
  shape arriving through design instead of a typo. Compared against an
  explicit, mandatory-reason allowlist, `toxic_flow.KNOWN_TAG_ONLY_CAPABILITIES`
  (a tuple of `TagOnlyCapability(capability, kind, reason)` — `__post_init__`
  rejects an empty `reason`), so the next tag-only addition is a conscious
  act, not an accident. Running it found `Capability.CLOUD` as expected
  (see above) **and, unexpectedly, `Capability.FILE_WRITE`**: every
  `TOXIC_PAIRS`/`CAPABILITY_FLOWS` entry models one axis — confidentiality,
  `attack_paths._SOURCE_CAPS`/`_SINK_CAPS`, source "produces data" / sink
  "exfiltrates" — and never asks whether state can be changed or a change
  can persist and later re-execute (e.g. one server writes a payload, a
  second server with `SHELL_EXEC` runs it). `FILE_WRITE` has a display
  label in `attack_paths._CAP_LABELS` and no role anywhere else because
  there is no axis in the model to put it on — a missing dimension, not a
  missing table row. `kind` exists specifically so this is NOT recorded the
  same way as `CLOUD`: `CLOUD` is `DELIBERATE_DEFERRAL` (wiring consciously
  postponed, no known missing row); `FILE_WRITE` is `SUSPECTED_GAP` (dead
  because the model has no axis for it, a known-but-unfixed gap, not a
  settled decision). Collapsing that distinction is exactly how
  `subprocess` sat inert for months, so the allowlist can express it
  instead of laundering a gap into a decision. `FILE_WRITE`'s wiring is
  explicitly **not** designed here — the shape of the fix isn't known yet
  either — and is queued as its own measure-first prompt (R37).
  **R37 resolved this by measuring first, not by guessing.** Across the
  live 50-entry registry: only 3 entries declare `file_write`
  (`server-filesystem`, `server-everything`, `docpull`); a general
  `FILE_WRITE + NETWORK_OUT` pair would fire on 60 cross-server
  combinations dominated by `server-filesystem` paired against *any* of
  the 21 `NETWORK_OUT`-capable entries (the exact "obviously that's what
  it does, why did this fire" trap the task warned against), and its
  severity is inherently write-target-dependent (a scratch directory vs.
  `~/.claude/CLAUDE.md`) with no write-target model to calibrate it —
  Part 3's own investigation found `agent_files/discovery.py` only holds
  the agent-instruction path set as inline walk logic, not an importable
  constant, and connecting it to a server's actual write scope would
  require building a filesystem-scope inspector the task explicitly said
  not to invent in-task. `FILE_WRITE + NETWORK_OUT` was therefore declined
  and is tracked as a measured, open gap in GAPS.md ("FILE_WRITE integrity
  axis (R37)") rather than shipped with an indefensible severity.
  `FILE_WRITE + SHELL_EXEC` had none of that problem (11 cross-server hits,
  dominated by entries already CVE-flagged elsewhere, not benign ones; and
  SHELL_EXEC's reach is not write-target-scoped for a write any more than
  for a read) and shipped as `INTEG-001` in a new `INTEGRITY_PAIRS` list —
  deliberately a *separate* list from `TOXIC_PAIRS`, combined only via
  `TOXIC_AND_INTEGRITY_PAIRS` (consumed by `ToxicFlowAnalyzer`,
  `shadow/risk.py`, and `diff/comparator.py`), with its own `INTEG-*`
  finding-ID prefix so filtering on `TOXIC-*` (confidentiality) never
  silently returns an `INTEG-*` (integrity) finding or vice versa.
  `Capability.FILE_WRITE` was removed from `KNOWN_TAG_ONLY_CAPABILITIES`
  entirely — it now participates in a real detection path, so it is no
  longer tag-only, and `compute_dead_capabilities()` was repointed at
  `TOXIC_AND_INTEGRITY_PAIRS` so the dead-capability check still holds.
  `tests/test_toxic_flow.py::TestComputeDeadCapabilities` asserts zero
  unexpected tag-only capabilities on every PR (not just ones touching the
  registry file or this script), since a capability-table change lives
  entirely in `toxic_flow.py`/`attack_paths.py` and would not otherwise
  trigger `registry-drift.yml`. Separately, `find_entirely_tag_only_entries()`
  flags any registry entry whose *entire* declared capability set is
  tag-only — such an entry produces zero toxic-flow findings while looking
  fully described, the `subprocess` failure in a new costume; zero hits
  today, proven (not just reasoned about) by
  `TestCloudOnlyEntryYieldsNoToxicFlowFindings`, which builds a registry
  entry declaring only `["cloud"]`, runs it through `ToxicFlowAnalyzer`,
  and asserts the finding list is empty.
  **R39 revisited the `FILE_WRITE + NETWORK_OUT` write-target blocker and
  kept it declined, on new grounds.** The path-list half of R37's Part 3
  blocker is fixed: `agent_files/discovery.py`'s relative-path list is now
  a single importable constant, `AGENT_INSTRUCTION_PATTERNS`, with a
  generic `_resolve_relative_pattern()` resolver driving both
  `_discover_user_global()` and `_discover_project_tree()` — no more
  hand-written duplicate of the same paths inside each walk function.
  `discover_agent_files()`'s existing 50-test suite passed unmodified
  against the refactor, proving behaviour didn't move. The harder half —
  whether a server's write scope can be *read off its own config* instead
  of invented — was then measured directly: 4 of 4 real/demo config
  fixtures using `@modelcontextprotocol/server-filesystem` declare a
  directory argument (100%), and the package's own docs confirm those
  args are its access-control list. That looked like a green light, but
  it does not unblock a rule for two reasons the measurement itself
  surfaced: (1) it is a single-named-package convention, not a capability
  signal — `server-everything` has no args-based scope at all and
  `docpull` writes to its own internal cache, so a rule built on it would
  need a hardcoded package-name allowlist, a different analyzer shape
  from everything else in `toxic_flow.py`; (2) a server with *no* declared
  args is not necessarily unconstrained — `server-filesystem` also honours
  the MCP Roots protocol, a client-runtime capability grant invisible to
  a static config scan, so "no args" is ambiguous between Roots-scoped,
  unconstrained, and non-functional. Reading "no args" as "unconstrained,
  therefore worse" would misclassify an unknown number of Roots-scoped
  servers — the same "shipping a severity we cannot defend" trap R37
  refused, now on the config-parsing side rather than the agent-path side.
  `FILE_WRITE + NETWORK_OUT` stays the open, measured gap recorded in
  GAPS.md; closing it for real needs a signal mcp-audit's offline static
  scan structurally cannot have (whether the client granted Roots).
  **Also found while building this**: the first Part-1 measurement pass
  silently ran against a stale, separately pip-installed `mcp_audit`
  (bare `python3` resolved
  `/Library/.../site-packages/mcp_audit`, not this repo's `src/mcp_audit`,
  because only `uv run python3` activates the dev venv) and, missing the
  `CLOUD` capability entirely, undercounted the real hits by one. Fixed
  with `_assert_mcp_audit_is_repo_local()`, called at the top of `main()`:
  resolves `mcp_audit.__file__`, fails loudly (exit 2, naming the actual
  resolved path) if it is not under `<repo>/src/mcp_audit`. Same class of
  defect as a missing duplicate-name guard — a measurement tool that can
  silently measure the wrong build produces confident wrong numbers, which
  is worse than producing none.
  **Provenance of the original `subprocess` defect (Part 3):** both invalid
  entries' history traces to a single commit, `96f8210` ("release: v0.12.0
  — SC-004 CVE advisories, COLLIDE-001 seed, release prep", 2026-06-13),
  which added all three offending entries (`@mcpjam/inspector`,
  `gemini-mcp-tool`, `flowise`) in one batch alongside their CVE data; the
  commit message documents the CVE additions but never mentions
  `capabilities` at all. No doc, template, or `CLAUDE.md` revision at any
  point in the repo's history ever suggested `"subprocess"` as a capability
  value (`git log --all -p -S'"subprocess"' -- '*.md' '*.yml' '*.yaml'`
  returns zero matches touching registry/template/capability docs; the
  `.github/ISSUE_TEMPLATE/registry-submission.yml` template — added the
  same day, commit `844c240` — has only ever offered "Execute shell
  commands" and "Execute code," never "subprocess"; these three entries
  weren't submitted through that template anyway, since they are seeded
  CVE-advisory entries, not community submissions). Conclusion: invented at
  triage time, with no source — the template fix in R34 closes a door this
  defect never used. This is a finding about process (an ad-hoc metadata
  edit that never cross-checked the `Capability` enum), not about
  documentation, and is recorded here rather than smoothed over.

- **Agent-file scanning** (`agent_files/`) covers the non-MCP-config instruction
  surfaces an agent reads: Claude Code commands/memory, Cursor `.mdc` rules, and
  Copilot instruction/prompt files. It is **not** part of `_run_static_pipeline()`;
  the standalone `agent-files discover|scan` commands call it directly, and `scan
  --include-agent-files` wires it via `_apply_agent_files()` in `cli/scan.py`
  (same `_apply_*` additive convention as `--include-extensions`). Findings use
  `analyzer="agent_files"` (SKILL-001/002/003/004, MEM-001/002) — **except**
  POISON-041/042 (concealment channels, STORY-0068), which this module also
  emits but which always carry `analyzer="poisoning"`, matching the config
  surface, because the shared builder `build_concealment_finding()` lives in
  and is owned by `analyzers/poisoning.py` (see that module's docstring and
  `agent_files/analyzer.py`'s own "documented exception" note). Detection
  patterns are **imported** from `analyzers/poisoning.py` — never forked.
  **HOOK-001/002** (network-egress and config-write hook commands) deliberately
  live in `analyzers/config_hygiene.py::analyze_config` (pipeline step 0), not in
  `agent_files/`, because they inspect the parsed `hooks` section of a Claude config
  file; they are distinct IDs from CFHYG-005 (which fires on mere presence of a
  `hooks` section) and the conditions do not overlap.

## Critical implementation details

- **VS Code uses `"servers"` as its MCP config root key; all other clients use `"mcpServers"`**
- MCP protocol communication is async — use asyncio and pytest-asyncio
- Core scanning MUST work fully offline — no network calls by default
- OSV.dev lookups **are implemented** via `scan --check-vulns` (deps.dev transitive graph + OSV.dev CVE batch query; shipped v0.6.0). The `--offline` flag enforces mutual exclusion with network-touching opt-in flags (`--verify-hashes`, `--verify-signatures`, `--check-vulns`, `--connect`); a plain scan already makes no network calls, so `--offline` is a no-op for the default configuration
- **mcp-audit does not implement semver range resolution anywhere** — no semver library appears in `src/mcp_audit/vulnerability/` or `src/mcp_audit/attestation/`. For an unpinned npm server, `resolve_latest_version()` asks `registry.npmjs.org/<pkg>/latest` (the `latest` dist-tag, npm-pick-manifest's own first-preference rule) rather than computing a highest-satisfying version, so the class of resolver bug an external measurement (issue [#88](https://github.com/adudley78/mcp-audit/issues/88)) found in a from-scratch range resolver — preferring a higher non-`latest`-tagged version over the dist-tag — cannot reach us; we declined to implement the thing that has the bug. For PyPI, `info.version` from the PyPI JSON API is documented to report the latest **stable** release (pre-releases excluded), matching pip's/`uvx`'s/`pipx`'s own default install behaviour, so it errs the same direction a real install would. `resolver.is_version_range()` (R36) is a syntactic, non-semver detector for a config entry that carries a floating specifier (`^1.2.3`, `~1.2.3`, `>=1.0.0`, `1.2.x`, `*`, `1.0.0 - 2.0.0`, `latest`) rather than an exact pin; `check_vulnerabilities()` and `mcp-audit sbom` both check it before calling `fetch_transitive_deps()`, because deps.dev requires an exact `(name, version)` key and 404s on a range — without the check, that 404 was caught by `fetch_transitive_deps()`'s own `except URLError/HTTPError` and silently degraded to a top-level-only result carrying the literal range string as its "version," with no warning. Both call sites now resolve a concrete version first (same as the existing "unpinned" path) and surface a visible `VULN-UNPINNED` finding / Rich console warning naming the original range and the resolved version. See "Known limitation: the published graph vs. the installed tree" in `docs/supply-chain.md` for the measured, externally-contributed error-rate bound on the deps.dev-vs-real-install gap this same issue established.
- Rug-pull state is stored in `<user-config-dir>/mcp-audit/state/state.json` (resolved via `platformdirs`; macOS: `~/Library/Application Support/mcp-audit/state/`); a one-time migration copies state files from the legacy `~/.mcp-audit/` location on first access
- **No feature gating.** mcp-audit is fully open source (Apache 2.0); every feature ships in every binary. Do not re-introduce conditional feature availability at any layer.
- **Watcher callback serialisation.** `_McpConfigEventHandler._fire()` holds `_scan_lock` for the entire duration of the user callback to prevent two `run_scan` calls from racing on `state_<hash>.json`. Events arriving while a scan is in flight are stored in `_pending_rescan` (tuple of latest `(path, event_type)`) and coalesced into a single re-trigger when the active callback returns. Never release the scan lock before the callback finishes.
- Exit codes: 0 = clean, 1 = findings found, 2 = error
- JSON output includes a nested `score` object from `ScanScore`: `{"numeric": int, "grade": str, "positive_signals": [], "deductions": []}` — `numeric` is 0–100, `grade` is "A"–"F", `positive_signals` and `deductions` carry the per-signal strings displayed in the terminal score panel; HTML dashboard displays a colour-coded grade badge in the header
- `scan --no-score` suppresses the grade panel in terminal output only; score is still calculated and present in JSON/HTML
- `scan --registry PATH` overrides the bundled and cached registry for that run
- `scan --offline-registry` uses the bundled registry only, skipping the user-local cache at `<user-config-dir>/mcp-audit/registry/known-servers.json`; typosquatting detection still runs using bundled data
- `scan --baseline NAME` (or `--baseline latest`) loads a saved baseline and appends `DriftFinding`s converted to `Finding` objects (`analyzer="baseline"`) into all output formats after the normal scan
- `scan --output-file PATH` (alias for `--output` / `-o`) writes scan results to a file; parent directories are created automatically; required for the GitHub Action SARIF upload step
- `scan --severity-threshold LEVEL` filters findings to only those at or above the given level and drives exit code; default is `INFO` (all findings); `--severity-threshold high` exits 1 only if HIGH or CRITICAL findings exist
- `scan --rules-dir PATH` loads additional YAML rule files from PATH for this scan; available to all users; community rules always run regardless
- `scan --project <dir>` walks the directory tree of a repository for project-level MCP config files (`.mcp.json`, `.cursor/mcp.json`, `.claude/settings.json`, `.claude/settings.local.json`, `.cursor/settings.json`, `.vscode/mcp.json`, `.amazonq/mcp.json`) and emits `TRUST-001` (HIGH) for every server found; runs the full analyzer pipeline on project-scoped servers too; tree walk caps at depth 8, skips `node_modules`/`.git`; `--project` path is validated to exist (exit 2 on failure); use before opening a freshly cloned repo in an AI editor; additive — default scan is unchanged. CWE-829 / OWASP MCP09. **Symlink handling (TRUST-002/TRUST-004/TRUST-005, added 2026-09-08):** a symlinked directory is still never followed (unchanged loop/blow-up protection) but now emits `TRUST-005` (LOW) naming it instead of vanishing silently; a symlinked config/agent-file *candidate* is included and parsed normally (coverage was never actually at stake — `Path.read_text()` follows a symlink transparently) and reported as `TRUST-002` (HIGH outside the scanned root, MEDIUM inside, INFO if broken) for project/cwd-scoped candidates or `TRUST-004` (always INFO — the GNU Stow/chezmoi/yadm dotfile-manager shape) for user-global/explicit ones. Applies uniformly across `discovery.py` (six sites) and `agent_files/discovery.py` (three sites). See `humans/decisions/2026-09-08-trust-002-symlink-sites.md` (marcus repo).
- `update-registry` fetches `registry/known-servers.json` from GitHub and saves it to the user-local cache; available to all users
- **Baseline storage** uses 0o700 dir / 0o600 file permissions, same pattern as rug-pull state files; env values are never stored, only key names (security — prevents secrets being persisted to disk)
- `scan --policy PATH` loads a governance policy file; governance findings are appended to `result.findings` after the scan completes (and after baseline drift) so they flow through all output formatters automatically. `--policy`, `policy init`, and `policy check` are all available to every user.
- **Governance policy resolution order** when `--policy` is not given: explicit flag → cwd → git repo root → `<user-config-dir>/mcp-audit/policy.yml` (resolved via `platformdirs`). Returns `None` (no check) if no file found.
- `scan --verify-hashes` downloads package tarballs and verifies SHA-256 against `known_hashes` pins in the registry; requires network; free for all tiers; findings appended to `result.findings` after the scan.

## Advisory feed invariants

The advisory feed is a published, externally-consumed artifact. Breaking any of the
following silently breaks downstream consumers, so treat them as contract:

- **Determinism is the whole product.** The same finding must produce byte-identical
  advisory JSON on every host, forever. Advisory IDs are derived from ecosystem +
  package + rule ID + finding class (+ normalized location when set) — never from a
  filesystem path, hostname, or timestamp. Timestamps come from `--published-at`,
  then `SOURCE_DATE_EPOCH`, and only then wall-clock; never call `datetime.now()`
  inside `build_advisory`.
- **`canonical.py` implements RFC 8785, not "JSON with sorted keys".** Object keys
  sort by UTF-16 code unit (not code point) and numbers use ECMAScript
  `Number::toString`. These differ from `json.dumps(sort_keys=True)` for non-BMP keys
  and for floats. Signatures are over canonical bytes, so any change here invalidates
  every published signature.
- **`src/mcp_audit/owasp_mcp.py` is the only definition of the OWASP MCP Top 10.**
  The advisory package must never hold its own copy of the code list. It publishes the
  bare `MCP01`..`MCP10` form that SARIF output and `docs/owasp-mapping.json` already
  use, so records join to the rest of mcp-audit's output without translation, and
  `scripts/validate_owasp_mapping.py` stays the single CI gate. `owasp_codes_for()`
  validates against `owasp_mcp.py` and drops anything unrecognised; `Advisory` raises
  on an unknown code. A finding with no clean mapping gets `owasp_mcp: []` and an
  `owasp_mcp_todo` string — it does not get a guessed code. Two tests enforce this: an
  AST scan for year-suffixed codes in the advisory package's *code* (docstrings are
  exempt — `owasp_codes_for` documents that it accepts that form on input), and a check
  that `mcp_audit.advisory.owasp` stays deleted.
- **The index is the integrity root.** `index.json` records a `canonical_sha256` per
  advisory plus the `signing` block, and is itself signed. `verify_feed` re-canonicalizes
  each advisory, checks its digest against the signed index, verifies its signature, and
  fails on any advisory file present on disk but absent from the index. Do not add a
  verification path that trusts a per-advisory signature alone — that would let an
  attacker swap in a differently-but-validly signed record.
- **Feed freshness lives only on the index.** `snapshot_version`, `published_at`, and
  `expires` are mcp-audit fields on `index.json` (`feed_version` 1.1). They are never
  copied onto OSV advisory records. `feed verify` hard-fails on expiry or rollback;
  `scan --advisory-feed` skips matching, emits `feed_status`, and still completes.
  There is no `--allow-expired`. Client `seen.json` is keyed on the signing identity
  (workflow ref + OIDC issuer), not a certificate fingerprint; changing that identity
  resets rollback protection. Do not make the first signed publish until
  `.github/workflows/advisory-feed-publish.yml` is the publisher (Amendment 7).
  As of R30 it is: the `build`/`publish` split commits the feed to a fetchable
  `feed` branch. As of R32, Amendment 7's gate is fully satisfied: a real
  minisign project key exists (private half in the `MCP_AUDIT_FEED_SIGNING_KEY`
  secret, scoped to the `feed-signing` GitHub environment restricted to `main`;
  public half committed at `keys/mcp-audit-feed.pub` and bundled in the
  package), `build` signs every scheduled publish and verifies its own output
  before `publish` ever sees it, and the first real signed publish has shipped.
  That first publish (2026-09-07T19:40:39Z, snapshot_version 4) shipped
  `index.json` with a `signing` block but no `index.json.sig` — `publish`'s
  "Replace the published feed content" step copied `advisories/`, `osv/`, and
  `index.json` from the candidate artifact but never the sibling `.sig` file
  `sign_feed()` writes next to the index (advisory `.sig` files were
  unaffected; they live inside `advisories/`, copied wholesale). CI's own
  verify step never caught this because it only ever checks the candidate
  artifact pre-`publish`, never the post-`publish` branch content. Caught the
  same day by a disposable `unshare --net` proof against the live feed
  (23/24 artifacts OK, `index.json` FAILED with "Missing signature artifact
  index.json.sig"); fixed with one added `cp` line
  (`test_publish_copies_index_json_sig_alongside_index_json` pins it) and
  re-published. The corrected bytes (snapshot_version 5) were re-verified
  offline the same way: all 24 artifacts OK, and a one-byte tamper of a
  downloaded advisory still fails offline. A stateless client accepts any unexpired validly-signed snapshot; TTL is the only
  lever. Stolen key, a publisher omitting advisories at a new version, a client clock
  in the past, and mix-and-match (already bound by `canonical_sha256`) are not covered.
- **Publishing is two-phase.** `write_feed()` emits the unsigned index; `sign_feed()`
  rewrites it with the `signing` block and then signs it. Determinism assertions must
  compare pre-signing output.
- **A feed is signed with a static project key, not Sigstore keyless.** This is the
  documented divergence from `snapshot --sign`, and it is threat-model driven: a
  snapshot is a one-off forensic artifact verified online where the human identity is
  the evidence; a feed is consumed offline, reproducibly, against a stable *project*
  identity. `advise --sign` therefore requires `--key` / `$MCP_AUDIT_SIGNING_KEY` and
  fails fast via `SigningConfig.require_signing_key()` before writing any signature.
  `--keyless` stays reachable for one-off attestations but must never become the
  default. Do not re-point this at `sigstore-python`: it is keyless-only, cannot use a
  static key, and is excluded from the PyInstaller binary.
- **cosign and minisign are optional external tools.** A missing backend degrades
  exactly like a missing semgrep in `sast/runner.py` — an actionable message naming
  the install step and `--no-sign`, never a traceback. Never vendor the crypto into
  the binary to avoid this.
- **Signatures stay detached and over canonical bytes, so rotation never rewrites a
  record.** Nothing signature-shaped is ever stored inside an advisory, and the signed
  payload is the JCS canonicalization rather than the on-disk file. Together these make
  a key rotation invisible to anyone consuming records instead of signatures — IDs,
  digests, and bytes are unchanged, and mirrors see no diff. Inlining a signature or
  certificate into a record would make every rotation churn the whole feed; signing raw
  file bytes would freeze the feed into one byte layout and break re-serialising
  mirrors. `TestRotationLeavesRecordsUntouched` in `tests/test_advisory_sign.py` pins
  this; no other test would catch either regression.
- **An unsigned feed is a supported artifact.** `examples/feed/` ships unsigned
  because signing it reproducibly would mean committing a private key — this stays
  true even now that the *live published* feed on the `feed` branch is signed with
  the real project key; the two are deliberately different artifacts. `verify_feed`
  reports `signed=False` and checks integrity only; tampering is still caught through
  `canonical_sha256`. A feed whose index carries a `signing` block still *fails* when
  a signature is missing, so this can never become a silent downgrade. The signing
  path is proven by ephemeral-keypair tests in `tests/test_advisory_sign.py`.
  **`canonical_sha256` is the only integrity guarantee consumers of the in-repo
  `examples/feed/` get** — no signature covers that fixture, so
  `test_a_mutated_record_still_fails_when_unsigned` is load-bearing rather than
  redundant with the signed-feed tests. Do not weaken it.
- **`x_MCPSA` prefix is deliberate.** OSV restricts `id` prefixes to a registered
  allowlist plus the `x_` experimental namespace, so records validate today. Drop the
  `x_` only once `MCPSA` is registered upstream.
- **Not every finding is an advisory.** `classify.py::is_advisable()` excludes
  informational/stateful IDs (RUGPULL-000/003, ATTEST-010/015, BL-001, COMM-000,
  CFHYG-004). New non-vulnerability finding IDs belong in `NON_ADVISORY_IDS`.
  `observation` distinguishes `package-intrinsic` (the package itself is affected)
  from `deployment` (this installation is misconfigured) — consumers rely on it to
  decide whether the record indicts the upstream package.
- **Advisory prose is published to the world.** `feed.py::redact()` scrubs
  `SECRET_PATTERNS` matches from summary/details before write. Any new field that
  carries analyzer text must go through it.
- **The OSV schema is vendored, not fetched.** `advisory/osv_schema/osv-1.6.0.json`
  is pinned so validation is offline and stable. Bumping it is a deliberate act:
  update `OSV_SCHEMA_VERSION`, re-run the round-trip tests, and re-sign the example
  feed. All four PyInstaller specs and the wheel must keep bundling it.

## Governance vs Rule Engine

The rule engine (`rules/`) pattern-matches inside server configs and produces `Finding` objects with `analyzer="rules"`. The governance engine (`governance/`) enforces *organisational requirements* — approved server lists, minimum scan scores, transport constraints, registry membership, finding tolerances — and produces `Finding` objects with `analyzer="governance"`. They are complementary: run together in every scan when a policy file is present.

Key differences:
- Rule engine: detects security issues in *how servers are configured* (e.g. credential leaks, poisoning patterns)
- Governance engine: enforces *which servers are allowed and what quality bar* the configuration must meet
- Community rules always run; custom rules, `rule validate`, and `rule test` are all available to everyone (no gating)
- Governance `--policy` flag, `policy init`, and `policy check` are all available to every user
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

## Quality gates

**Dev extras required:** Run `uv sync --extra dev` before running tests for the
first time, or after a fresh clone. A plain `uv sync` omits `pytest-asyncio`
and other dev tools — async tests will silently fail with unknown-mark warnings
if this step is skipped.

- Run `uv run pytest` after every change
- Run `uv run ruff check src/ tests/` before committing
- Run `uv run bandit -r src/ -ll -f txt` periodically (we're a security tool — act like it)
- Run `./scripts/update_test_count.py` before tagging a release (or after any PR that changes test count, SAST rule count, community rule count, or analyzer count) to sync all hand-maintained count references in `README.md` and `CLAUDE.md`. The script now covers: test count, SAST rule count (total + Python/TypeScript breakdown), community rule count, and concrete analyzer count. CI runs the same script with `--check` on the ubuntu/py3.12 leg and fails on drift.
- Run `python scripts/validate_owasp_mapping.py` after adding any new finding ID to verify it is mapped in `docs/owasp-mapping.json`. CI runs this on the ubuntu/py3.12 leg and fails when any finding ID is missing from the mapping file. **Every PR that adds a new finding ID must also add a mapping entry.**
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
- 8 analyzers: poisoning, credentials, transport, supply chain, rug-pull, toxic flow, config hygiene, auth
- Attack path engine with multi-hop detection and greedy hitting set algorithm
- 5 output formats: terminal, JSON, SARIF, Nucleus FlexConnect, HTML dashboard
- Interactive D3 attack graph dashboard with light/dark mode (`mcp-audit dashboard`)
- `mcp-audit watch` command — continuous filesystem monitoring, re-scans on config change
- Machine identification (MachineInfo) embedded in scan output; `--asset-prefix` flag for fleet deployment
- PyInstaller binary builds — 16.6 MB standalone executable, no Python required
- Live MCP server connection via --connect (optional, MCP SDK)
- Scoped rug-pull state management (per-config-set hash isolation)
- 8 supported MCP clients including Copilot CLI and Augment
- Demo environment producing 53 findings across all demo configs (16 per-config for `claude_desktop_config.json`; community rules + AUTH-001 + SC-004 analyzers included). Note: the full 3-config scan produces more findings than single-config scans because toxic_flow sees all 8 servers together and generates cross-config TOXIC-005 pairs (database+fetch, database+github) that don't appear when scanning claude_desktop_config.json alone. AUTH-001 fires on the remote server visible in the multi-config scan. Run `mcp-audit scan demo/configs/ --format json` to verify current count before each release.
- 3379 tests passing; `ruff check src/ tests/` clean (zero errors); `ruff format src/ tests/` clean (zero files requiring reformatting) — verify with `uv run pytest --collect-only -q` before each release
- scanner.py coverage raised from ~50% to **89%** (2026-04-18); 45 new tests in `tests/test_scanner.py` covering all 15 integration scenarios: clean scan, findings scan, baseline drift, verify-hashes, SAST, extensions, policy, no-score, severity-threshold, offline-registry, empty config, rules-dir, pipeline order, asset-prefix, and async code paths; only the live `--connect` MCP protocol block (lines 215-240) remains untested (requires running MCP server + optional SDK)
- Security review completed — 6 vulnerabilities fixed (V-01 through V-06)
- 27 top-level CLI commands: vet, check, fix, scan, discover, pin, diff, dashboard, watch, version, update-registry, merge, verify, sast, sbom, push-nucleus, shadow, killchain, snapshot, register, advise, baseline (5 sub-commands: save, list, compare, delete, export), rule (3 sub-commands: validate, test, list), policy (3 sub-commands: validate, init, check), extensions (2 sub-commands: discover, scan), agent-files (2 sub-commands: discover, scan), feed (1 sub-command: verify) — verify with `mcp-audit --help` before each release
- **push-nucleus** — `mcp-audit push-nucleus --url <url> --project-id <id>` runs a scan and pushes results directly to a Nucleus Security project via the FlexConnect API; available to all users; multipart/form-data upload using `urllib.request` only; polls import job to completion; Rich summary panel on success; `--output-file` for local copy; validated against a live Nucleus instance (2026-04-23); see `docs/nucleus-integration.md`
- **Fleet merge** — `mcp-audit merge [FILES...] [--dir DIRECTORY]` consolidates JSON scan outputs from multiple machines into a single fleet report; available to all users; supports terminal, JSON, and HTML output formats; deduplicates findings across machines by `(analyzer, server_name, title)`; see `docs/fleet-scanning.md`
- **GitHub Action** — `action.yml` at repo root; composite action Marketplace-ready with `branding`, `config-paths`, `severity-threshold`, `sarif-output`, `upload-sarif`, `check-vulns`, `verify-signatures`, `run-sast`, `sast-path`, `baseline-name`, `fail-on-findings`, `version` inputs and `findings-count`, `grade`, `sarif-path` outputs; uploads SARIF to GitHub Code Scanning via `upload-sarif@v4` (continue-on-error so repos without Code Scanning still run cleanly); `.github/workflows/action-ci.yml` runs the composite against `demo/configs/` as a self-test on every PR; the Semgrep **rule pack** (`semgrep-rules/`) ships bundled in `mcp-audit-scanner`, but the Semgrep CLI binary itself is not — when `run-sast: 'true'` is set, the action installs Semgrep automatically (`pip install semgrep --quiet`) inside the SAST step, so users do not need a separate install step; see `docs/github-action.md`
- **Baseline snapshot & drift detection** — 5 new `baseline` sub-commands (save, list, compare, delete, export); `scan --baseline NAME/latest` injects drift findings into all output formats; storage in `<user-config-dir>/mcp-audit/baselines/` (resolved via `platformdirs`) with 0o700 dir / 0o600 file permissions; env values never stored, only key names; see `docs/baselines.md`
- **Scan Score** — every scan now produces a numeric score (0–100) and letter grade (A–F); see `scoring.py` and `docs/scoring.md`
- **Known-Server Registry** — 50-entry curated dataset of legitimate MCP servers replaces the hardcoded YAML in the supply chain analyzer and now also owns toxic-flow capability tags via the optional `RegistryEntry.capabilities` field; see `registry/known-servers.json` and `docs/registry.md`
- **Policy-as-code rule engine** (Chain Reaction Feature) — YAML-based custom detection rules; 37 community rules ship bundled and run for ALL users; `rule validate` / `rule test` / `rule list` subcommands; `scan --rules-dir PATH` and `<user-config-dir>/mcp-audit/rules/` for user-local rules; all rule commands are available to every user; rule findings flow through all output formats automatically; see `docs/writing-rules.md` and `rules/README.md`
- **Community rule contribution program** — `TEMPLATE.yml`, `BOUNTY.md`, and `docs/contributing-rules.md` provide a 30-minute on-ramp for security practitioners to contribute detection rules; first 50 accepted contributors named in changelog and `docs/contributors.md`; see `docs/community-rule-spec.md` for the published YAML spec (Apache 2.0, ecosystem-adoptable)
- **Pre-commit hook** (Chain Reaction Feature) — `.pre-commit-hooks.yaml` at repo root; `language: python`, `entry: mcp-audit`, `pass_filenames: false`, `types: [json]`; default threshold is HIGH; `examples/pre-commit/` has basic and strict configs; see `docs/pre-commit.md`
- **Governance policy engine** — YAML-based organisational requirements (approved server lists, score thresholds, transport constraints, registry membership, finding tolerances); `policy validate` / `policy init` / `policy check` subcommands; `scan --policy PATH` flag auto-discovers `.mcp-audit-policy.yml` in cwd / repo root; all governance commands are available to every user; governance findings flow through all output formats; terminal output shows a distinct yellow "Policy Violations" panel; SARIF governance findings tagged `governance-policy` with `GOV-` rule IDs; see `docs/governance.md` and `examples/policies/`
- **SAST rule pack** — 89 Semgrep rules (46 Python, 43 TypeScript) detecting injection, poisoning, credential, protocol, transport, and auth vulnerabilities in MCP server source code; standalone (`semgrep --config semgrep-rules/ <path>`) or integrated (`mcp-audit scan --sast <path>`); available to all users; `mcp-audit sast <path>` standalone command; SAST findings have `analyzer="sast"` and flow through all output formats; `semgrep-rules/` bundled in pip wheel and PyInstaller binary; see `docs/sast-rules.md`, `docs/contributing-rules.md`, and `semgrep-rules/README.md`
- **IDE extension scanner** — discovers installed extensions across VS Code and Cursor (+ Windsurf/Augment paths for portability); 6 analysis layers: known-vuln registry, dangerous capability combos, wildcard activation, unknown publisher, sideloaded VSIX, stale AI extensions; `mcp-audit extensions discover` and `mcp-audit extensions scan` plus `scan --include-extensions` are all available to every user; `registry/known-extension-vulns.json` seed dataset (5 entries); findings use `analyzer="extensions"` and flow through all output formats; see `docs/extensions.md`
- **Shadow MCP server detection** (hero feature) — `mcp-audit shadow` sweeps every known MCP config location on the host; classifies each server as `sanctioned` (matches operator allowlist) or `shadow` (does not); scores capability risk using toxic-flow logic; emits structured events in `--continuous` daemon mode (`new_shadow_server`, `server_drift`, `server_removed`); `--format json` for syslog/SIEM piping; persists `first_seen`/`last_seen` state; OWASP MCP09; see `docs/shadow-mcp.md`
- **`mcp-audit diff <base> <head>`** — MCP-aware diff for PR review and CI gates. Compares two MCP configuration states (directories, JSON scan files, or git refs) and surfaces added, removed, and changed servers, tools, capabilities, env-var references, external endpoints, and credentials with risk classification. `--format pr-comment` outputs GitHub-flavored Markdown ≤ 100 lines with `<details>` collapsibles for each changed server. `--format json` produces a flat list of change records. `--severity-threshold` and exit codes mirror `scan`. `action.yml` extended with `mode: diff` input. New modules: `src/mcp_audit/diff/` (`loader.py`, `comparator.py`, `risk.py`, `render.py`), `src/mcp_audit/cli/diff.py`; see `docs/diff.md`

- **`mcp-audit killchain`** — decision engine on top of the attack-path graph. Identifies the top N configuration changes (default 3) that cut the largest blast radius, ranked by incremental path reduction. Outputs a prescriptive Markdown report (copy-paste into Slack/email) or JSON (`--format json`). `--patch yaml` emits a governance-policy denylist patch; `--patch pr` emits a PR-comment stub. `--input <scan.json>` accepts an existing scan result; default behaviour re-runs the full pipeline. What-if simulation re-runs `summarize_attack_paths` against the modified server list so the math is real. New modules: `src/mcp_audit/killchain/` (`recommender.py`, `simulator.py`, `patches.py`, `render.py`), `src/mcp_audit/cli/killchain.py`; see `docs/killchain.md`

- **VS Code / Cursor extension (STORY-0032).** Companion extension `mcp-audit-vscode` (separate repo: `https://github.com/mcp-audit/mcp-audit-vscode`) surfaces `mcp-audit scan --format json` output as inline VS Code diagnostics. Tech stack: TypeScript, VS Code Extension API, esbuild, jsonc-parser. The extension shells out to the mcp-audit binary — no detection logic is reimplemented in TypeScript. `ScanResult`/`Finding` JSON serialisation is the public API contract between the extension and the CLI; breaking field-name changes require a coordinated update to `types.ts` in the extension repo. ADR: `docs/decisions/ADR-0002-extension-separate-repo.md`; docs: `docs/ide-extension.md`.

- **`mcp-audit vet <package>`** — pre-install verdict on any public MCP server package. Registry-corpus-based, offline by default, facts not grades. Surfaces: verification status, known CVEs (NVD links, fixed-in version), declared capabilities, hash pins, typosquat detection (Levenshtein, same threshold as supply-chain analyzer). `--format json` emits a verdict document conforming to `mcp-audit.dev/v1/schema.json`. `--badge` emits a Shields.io Markdown badge. `--online` fetches from `mcp-audit.dev` and caches at 0o600. `--strict` exits 1 for unknown packages (CI). Exit codes: 0 = clean/unknown-without-strict; 1 = CVEs/typosquat/unknown+strict; 2 = error. 61 tests in `tests/test_vet.py`. New modules: `src/mcp_audit/verdict.py` (pure builder, shared with mcp-audit.dev generator), `src/mcp_audit/cli/vet.py`; ADR: `docs/decisions/ADR-0003-vet-verdict.md`; docs: `docs/vet.md`. Supersedes stale `lookup` command on branch `story/0016-mcp-audit-dev`.

- **`mcp-audit check`** — one-command practitioner verdict (STORY-0037). Runs the full scan pipeline and presents a concise one-page summary: letter grade, score, top 5 findings by severity, per-finding plain-English remediation hints, and a pointer to `mcp-audit fix`. `--verbose` shows full `scan` terminal output; `--json` outputs the raw `ScanResult` JSON. Exit codes: 0 = grade A/B (score ≥ 70, no CRIT/HIGH); 1 = grade C/D/F or any CRIT/HIGH; 2 = error. Auto-fixable IDs (CRED-001, CRED-002, TRANSPORT-001, SC-001, SC-002) print "Run `mcp-audit fix --apply`"; all other IDs map to specific manual instructions via `output/check.py::_HINTS`. 38 tests in `tests/test_check.py`. New modules: `src/mcp_audit/cli/check.py`, `src/mcp_audit/output/check.py`; see `docs/check.md`

- **`mcp-audit fix`** — apply safe remediations back to MCP config files (STORY-0031). Dry-run by default (unified diff to stdout). `--apply` writes changes atomically with a `.bak` backup. Three fix types: `credentials` (CRED-001/002/003 — redact plaintext secrets with `${ENV_KEY}`; CRED-003 preserves any existing auth-scheme prefix, e.g. `Bearer ${HEADER_NAME}`), `transport` (TRANSPORT-001 — upgrade `http://` URLs to `https://`), `pinning` (SC-001/002 — replace typosquatted package name with verified registry name and pin to `@latest-version`). Registry validation: checks mcp-audit's own `known-servers.json` before pinning; emits a warning (non-blocking) when replacement package is not in the registry. `--input <scan.json>` skips re-scan. `--fix-type` filter restricts which strategies run. `--offline` suppresses version-resolution network calls. Exit codes: 0 = success or no fixable findings; 2 = error. New modules: `src/mcp_audit/fixer/` (`fixer.py`, `strategies/base.py`, `strategies/credentials.py`, `strategies/transport.py`, `strategies/pinning.py`), `src/mcp_audit/cli/fix.py`; see `docs/fix.md`

- **`mcp-audit snapshot`** — forensic-layer export (STORY-0015). Time-stamped, sigstore-signed snapshots of every MCP server on a host. CycloneDX 1.5 AI/ML-BOM by default; mcp-audit-native JSON optional (`--format native`). Each server is a CycloneDX `component` of `type: application` with capability tags, transport, and finding IDs in `properties`. Each finding is a CycloneDX `vulnerability` with ratings, CWEs, and OWASP MCP Top 10 mapping. `--sign` wraps sigstore signing (ambient OIDC; requires `[attestation]` extra). `--rehydrate <snapshot>` reconstructs the historical attack-path graph from recorded servers and findings — bypasses live discovery for incident response. `--stream` emits NDJSON (one finding per line) for SIEM/EDR ingestion. `--input <scan.json>` skips live scan. 56 tests in `tests/test_snapshot.py` including CycloneDX schema validation. SIEM recipes in `docs/integrations/splunk.md` and `docs/integrations/sentinel.md`. New modules: `src/mcp_audit/snapshot/` (`rehydrate.py`, `diff.py`), `src/mcp_audit/output/snapshot.py`, `src/mcp_audit/cli/snapshot.py`; see `docs/snapshot.md`

- **Agent-file scanner** (v0.14.0, skills added 2026-09-08/STORY-0065) — extends
  scanning beyond MCP config files to the agent instruction/memory surfaces: Claude
  Code commands (`~/.claude/commands/`, `.claude/commands/`), Claude Code skills
  (`~/.claude/skills/**/SKILL.md`, `.claude/skills/**/SKILL.md`, matched recursively
  at any nesting depth) and memory (`CLAUDE.md` tiers), Cursor rules
  (`.cursor/rules/*.mdc`), and GitHub Copilot instruction/scoped/prompt files
  (`.github/`). `agent-files discover` and `agent-files scan` standalone commands plus
  `scan --include-agent-files`; findings use `analyzer="agent_files"`
  (SKILL-001/002/003/004, MEM-001/002). SKILL-004 (INFO) inventories a skill's bundled
  `scripts/` filenames only — never contents, never executed. HOOK-001/002 hook-command
  checks live in `config_hygiene.py`. Fully offline. A symlinked candidate at any of
  this package's three discovery sites is included (not dropped) and reported as
  TRUST-002/TRUST-004 — see the `scan --project` symlink-handling note above. New
  package `src/mcp_audit/agent_files/` (`models.py`, `discovery.py`, `analyzer.py`)
  and `src/mcp_audit/cli/agent_files.py`; see `docs/agent-files.md`. Unconfirmed
  surfaces (Windsurf, Augment, Kiro, user-global Copilot) tracked in `GAPS.md`.
  **POISON-041/042** (concealment channels — Unicode TAG-character runs decoded
  per UTS #39/ASCII-smuggling research, and HTML comments — STORY-0068, added
  2026-09-09) fire from both this module and `PoisoningAnalyzer`, always with
  `analyzer="poisoning"`; see `analyzers/poisoning.py`'s "Concealment channels"
  section and this module's own docstring for the shared-builder rationale.

- **Advisory feed** — `mcp-audit advise <target>` turns scan findings into OSV
  schema_version 1.6.0 advisory records and publishes them as a signed, verifiable
  feed; `mcp-audit feed verify <dir>` checks it. A weekly **signed** build (minisign,
  R32) is published to a dedicated orphan `feed` branch in this repo, fetchable at
  `https://raw.githubusercontent.com/adudley78/mcp-audit/feed/index.json` with no
  repository access required (R30); the publish job runs — and commits —
  on every scheduled run, whether or not advisory content changed, so
  `expires` never freezes (R31 fixed an R30 bug where skipping the commit
  on unchanged content froze the feed's own expiry); `scripts/feed_diff.py`
  now only shapes the commit message (see
  `.github/workflows/advisory-feed-publish.yml`). The `build` job signs with a
  minisign project key held only in the `MCP_AUDIT_FEED_SIGNING_KEY` secret of the
  `feed-signing` GitHub environment (restricted to `main`), verifies its own signed
  output before `publish` ever sees it, and the public half is committed at
  `keys/mcp-audit-feed.pub` and bundled in the package so `feed verify --key-alt
  minisign` resolves it with no extra flag and no network fetch. A separate,
  independently scheduled `advisory-feed-freshness-canary.yml` fails loudly if the
  live feed is ever closer to expiry than one publish interval — the signal
  that the publisher itself has stopped running.
  There is no CVE/OSV/NVD equivalent
  for MCP servers, so this is the canonical machine-readable feed other registries,
  gateways, and scanners can consume. Core OSV fields are used verbatim; everything
  MCP-specific lives under `affected[].database_specific` (`owasp_mcp`,
  `mcp_transport`, `finding_class`, `mcp_audit_rule_id`, `verified_patch`,
  `mcp_observation`, `cvss_basis`). Output layout: `advisories/<id>.json`,
  `index.json`, and an osv-scanner-consumable `osv/all.json` + `osv/all.zip`.
  Records are deterministic (stable content-derived IDs, no host paths, RFC 8785
  canonical bytes) and always signed with a **static project key**, never keyless —
  `advise --sign` defaults to the `cosign` backend, `--key-alt minisign` is the
  low-dependency alternative and the one the published feed actually uses,
  `--keyless` remains opt-in and is never the default. The committed
  `examples/feed/` is unsigned by design (no private key in the repo); `feed
  verify` still checks its integrity.
  See "Advisory feed invariants" below and `docs/advisory-feed.md`.

What's next (non-code):
- Disclose project to Nucleus colleagues, get expert feedback on detection logic
- Tune false positives (e.g., "base64 encode" in official filesystem server)

What's next (code, after feedback):
- Detection pattern tuning based on practitioner review
- Community rule contributions — grow COMM-NNN library based on practitioner input

## Provenance

All detection patterns are original implementations based on published security
research. No code was copied from existing scanners. Full source attribution is
documented in PROVENANCE.md — read it before adding new detection patterns.
Every new pattern must cite its research source.
The project now has 8 analyzers with patterns sourced from the research listed in PROVENANCE.md. Update PROVENANCE.md when adding new detection patterns or analyzers.
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
   transport-analyzer unit tests (expected). The prior `nucleussec.com` schema-reference
   comment in `output/nucleus.py` has been generalised. No corp/staging/internal
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
| Binary entry point and bundled data intact after build | Shared composite + `scripts/smoke_test.py` | `.github/actions/build-binary/` is invoked by CI `binary-smoke` and `release.yml` `build` |

### CI workflow (`.github/workflows/ci.yml`)

Triggers on every push and pull request to **any branch**. Runs a 3×2 matrix (6 combinations):
- **OS:** `ubuntu-latest`, `macos-latest`, `windows-latest`
- **Python:** `3.11`, `3.12`
- `fail-fast: false` — a failure on one leg does not cancel the others.

Each test-matrix leg runs: `pip install uv` → `uv pip install -e ".[dev]" --system` → `pytest tests/ -x -q` → `ruff check src/ tests/` → `ruff format --check src/ tests/`. The matrix uses `actions/setup-python` so uv installs into the runner's system Python via `--system`.

`wheel-check` (every push/PR) uses `setup-uv` + CPython 3.12.14, builds the wheel, fetches the publish action's `runtime.txt` at the pinned SHA, and runs that Twine (`uvx twine==… check --strict`) so a Core-Metadata bump fails on the PR, not at the tag. Hatchling stays unpinned; the Twine version is not copied into `ci.yml`.

The workflow status badge is in `README.md`.

### Release workflow (`.github/workflows/release.yml`)

Triggers on `v*.*.*` tags (e.g. `git tag v0.2.0 && git push --tags`), and on `workflow_dispatch` as a dry-run of the `build` job (no GitHub Release, no PyPI). Builds four binaries in parallel, then creates a GitHub Release with all four attached and auto-generated release notes.

**Shipped binaries are built by `.github/actions/build-binary/`.** CI `binary-smoke` and this workflow's `build` job both call it (CPython 3.12.14 via `uv python install`, `uv sync --all-extras`, spec, PyInstaller, PYZ inspect, smoke, size). Do not copy those steps into either workflow. History of the three CI/release drifts: `docs/building-binaries.md`.

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

All four specs include identical `datas` (5 entries: `mcp_audit/data`, both registry JSONs, `rules/community/`, `semgrep-rules/`) and the same full `hiddenimports` list. The only difference between specs is the `name=` field in the `EXE` block.
