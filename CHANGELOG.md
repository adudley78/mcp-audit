# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [Unreleased]

_Accumulates entries for work done after the last milestone and before the first public release tag._

---

## [0.6.0] - 2026-04-23 — Supply Chain Layers 2 & 3

### Added
- **Layer 2: Sigstore provenance verification** (`attestation/sigstore_client.py`, `attestation/sigstore_findings.py`): opt-in `--verify-signatures` flag (free, default OFF) verifies Sigstore provenance bundles for registry-known npm and PyPI packages. Fetches bundles from the npm attestations API and PyPI PEP 740 provenance API; verifies with the `sigstore` Python library (Fulcio cert chain, SCT, Rekor inclusion proof); extracts OIDC issuer (OID `1.3.6.1.4.1.57264.1.1`) and SAN URI from the signing certificate; compares signing repo against `RegistryEntry.repo`. `--strict-signatures` raises "absent" findings from INFO to MEDIUM. Six new finding IDs: `ATTEST-010` (valid match, INFO), `ATTEST-011` (valid but wrong repo, HIGH), `ATTEST-012` (invalid signature, CRITICAL), `ATTEST-013` (expected attestation absent, MEDIUM), `ATTEST-014` (absent, INFO/MEDIUM), `ATTEST-015` (network error, INFO). `attestation_expected: bool = False` field added to `RegistryEntry`; set to `true` for all 26 Anthropic-maintained entries in the registry.
- `sigstore>=3.0,<4.0` added to package dependencies.
- `docs/supply-chain.md` — Layer 2 section documenting all finding IDs, flag behaviour, and `--strict-signatures` usage.
- `docs/severity-framework.md` — `ATTEST-010` through `ATTEST-015` severity table.

### Notes
- Binary size advisory: the `sigstore` dependency tree (`betterproto`, `tuf`, `rfc3161-client`, `securesystemslib`) is expected to push the PyInstaller binary above the 22 MB target. Three mitigation options documented in `attestation/sigstore_client.py`; a rebuild is required before the next release cut to measure actual impact.

---

## [0.5.0] - 2026-04-23 — Detection Validity, Hardening & Supply Chain Depth

### Security
- **V-07 — Unicode homoglyph bypass closed** (`poisoning.py`): Added `POISON-060` pattern matching Cyrillic, Greek, general-punctuation lookalike, and fullwidth-ASCII Unicode blocks. All patterns now run against NFKD-normalised ASCII text; `POISON-060` runs against the original bytes. Deduplication on `(id, server, evidence)` prevents duplicate findings when both the raw and normalised text match.
- **V-08 — Depth-11 nesting bypass closed** (`poisoning.py`): Recursion limit in `_extract_text_fields` and `_extract_description_fields` raised from `depth > 10` to `depth > 50`, making the depth-bypass impractical while still guarding against infinite recursion.
- **V-09 — Wildcard interface binding** (`transport.py`): New `TRANSPORT-004` finding (HIGH, CWE-1327) fires when the server URL hostname is `0.0.0.0`, `::`, `[::]`, or their equivalents. `_WILDCARD_BINDINGS` frozenset added.
- **V-10 — Privilege escalation coverage expanded** (`transport.py`): `TRANSPORT-002` now catches `pkexec`, `su`, and `run0` in addition to `sudo` and `doas`. Absolute-path forms (e.g. `/usr/bin/sudo`) detected via `_PRIV_ESC_SUFFIXES`. Privilege-escalation binary appearing as `args[0]` (e.g. `command=sh, args=["sudo", …]`) now also fires.
- **V-11 — Supply chain coverage expanded** (`transport.py`, `supply_chain.py`): `pipx` added to `_RUNTIME_FETCH_COMMANDS`. `yarn dlx` detected in both `TransportAnalyzer` (TRANSPORT-003) and `SupplyChainAnalyzer` (typosquatting); `args[1:]` slicing used when extracting the package name to skip the `dlx` token.

### Added
- **Exploit validation test suite** (`tests/test_exploit_validation.py`): Six test classes reconstruct real published attack PoCs — Invariant Labs SSH exfiltration, CrowdStrike `add_numbers`, fake Postmark base64 exfiltration, CyberArk XML `<OVERRIDE>` injection, Palo Alto Unit 42 cloud credential targeting, and MINJA behavioral override. Each class asserts specific finding IDs and severities; `TestExploitCoverage` enforces all six fixture files are present and valid JSON.
- **Exploit fixtures** (`tests/fixtures/exploits/`): Six JSON fixtures reconstructing the above PoCs from published research sources cited in `PROVENANCE.md`.
- **False-positive benchmark** (`tests/test_false_positive_benchmark.py`): Runs poisoning and credentials analyzers against 22 real-world MCP server configs (12 official `@modelcontextprotocol/*`, 10 popular community servers). Asserts 0% poisoning false-positive rate across the full set. Parametrised per-server to pinpoint regressions immediately. Acts as a merge gate — any pattern change that fires on a legitimate server fails CI.
- **Real-server fixtures** (`tests/fixtures/real_servers/`): `official_mcp_servers.json` (12 servers) and `community_mcp_servers.json` (10 servers) with realistic production configs and empty env-var values.
- **Severity framework** (`docs/severity-framework.md`): CVSS base scores and OWASP Agentic Top 10 (ASI01–ASI10) mappings for every finding ID across all six analyzers (POISON-*, CRED-*, TRANSPORT-*, SC-*, RUG-*, TOXIC-*, ATTEST-*). Includes a decision tree for calibrating new findings.
- `TRANSPORT-004` added to `docs/severity-framework.md` under the Transport analyzer table.

### Added (continued)
- **Registry metadata enrichment** (`registry/loader.py`, `registry/known-servers.json`): Three optional fields added to `RegistryEntry` — `first_published` (ISO date), `weekly_downloads` (integer), `publisher_history` (list of publisher account names, most-recent first). Populated for 10 entries; registry grew from 60 to 64 entries with four new community servers (`@linear/mcp-server`, `exa-mcp-server`, `@notion/mcp-server`, `mcp-perplexity`). SC-001/SC-002 finding descriptions now append publish date, download count, and known publishers when data is present, giving users signal about package legitimacy. `scripts/enrich_registry.py` maintainer tool added (not shipped in wheel) to refresh metadata from the npm registry API; supports `--dry-run`.

### Fixed
- `GAPS.md` — three Detection Validity gaps closed (exploit validation, false-positive rate, severity framework); V-07 through V-11 marked resolved; registry metadata enrichment marked resolved; `--offline --verify-hashes` conflict confirmed already blocked by `_preflight_checks`.

---

## [0.4.0] - 2026-04-17 — Security Hardening & CI

### Security
- Resolved all Bandit medium+ findings; suppressed three `B310` (`urllib` URL-open) calls with inline `# nosec B310` comments and one-line justifications — no blanket suppressions.
- Bumped `cryptography` to `>=46.0.6,<47.0` to fix CVE-2026-26007 (EC subgroup validation) and CVE-2026-34073 (DNS name constraint bypass); lockfile resolves to `cryptography==46.0.7`. `pip-audit` now returns zero findings.
- Pre-launch hardening pass (V-01 through V-06): path-traversal fix via `_safe_baseline_path` + `Path.resolve()`, state file permission enforcement (`0o600`/`0o700`), bare `except:` removal, CLI input validation for `--path`/`--registry`/`--sast`/`--policy`, `subprocess.run()` converted to list form everywhere (`shell=False`).
- Converted `subprocess` calls in `sast/runner.py` to list form; introduced `SEMGREP_TIMEOUT_SECONDS = 300` constant — hardcoded timeout integers are now forbidden.

### Added
- `scripts/build-linux.sh` — Docker-based Linux x86_64 binary build inside `python:3.11-slim`; installs `binutils` via `apt-get`; prints file size and SHA-256 on success.
- `sast` and `sast-path` inputs wired into `action.yml` (GitHub Action).
- `ci.yml` — 3×2 CI matrix (Ubuntu / macOS / Windows × Python 3.11 / 3.12); `fail-fast: false`.
- `release.yml` — binary release workflow; builds four PyInstaller executables in parallel on tag push (`v*.*.*`); creates a GitHub Release with auto-generated notes.
- Four portable PyInstaller spec files (`mcp-audit-darwin-x86_64.spec`, `mcp-audit-darwin-arm64.spec`, `mcp-audit-linux-x86_64.spec`, `mcp-audit-windows-x86_64.spec`) using `SPECPATH`-relative roots.
- Full PyInstaller `hiddenimports` list; complete bundled `datas` (5 entries).
- Test coverage for PyInstaller path resolution (`_MEIPASS` monkeypatching) and license key storage path shape.
- 13 additional edge-case tests covering scanner integration scenarios, raising `scanner.py` line coverage from ~50 % to 89 %.
- Replaced hardcoded `~/.config/mcp-audit` paths with `platformdirs.user_config_dir("mcp-audit")` across all modules (baselines, registry cache, policy, rules); `licensing.py` deferred (marked do-not-modify).
- `packaging>=21.0` declared as an explicit dependency.
- Clean commit-history audit recorded before public release (credentials, private keys, internal URLs — all categories clean).

### Fixed
- `malformed JSON` errors now surfaced to the user rather than silently swallowed.
- `--no-score` correctly suppresses the `run.properties` score block in SARIF output.
- GitHub Action: workflow-level `permissions` added for SARIF upload; `codeql-action` bumped to v4; double-scan removed; SARIF path guarded.
- `httpx` moved to the `mcp` optional-dependency group (resolves V-12).

---

## [0.3.0] - 2026-04-10 — Moat Deepening

### Added
- **Governance policy engine** — YAML-based organisational requirements: approved server lists, minimum scan scores, transport constraints, registry membership, finding tolerances. New CLI commands: `policy validate`, `policy init` (Pro), `policy check` (Pro). `scan --policy PATH` flag (free) with auto-discovery (cwd → repo root → user config dir). Governance findings rendered in a distinct yellow "Policy Violations" panel in terminal output; SARIF findings tagged `governance-policy` with `GOV-` rule IDs. `governance` and `fleet_governance` feature keys.
- **Supply chain attestation — Layer 1** — hash-based integrity verification via `attestation/hasher.py` and `attestation/verifier.py`. `scan --verify-hashes` downloads package tarballs and computes SHA-256 against `known_hashes` pins in `RegistryEntry`. `mcp-audit verify` standalone free-tier command. Five registry entries seeded with real hashes. Attestation findings use `analyzer="attestation"` (CRITICAL for mismatches, INFO for unverifiable).
- **Semgrep SAST rule pack** — 37 rules (28 Python, 9 TypeScript) across 5 categories (injection, poisoning, credential, protocol, transport). Runnable standalone (`semgrep --config semgrep-rules/ <path>`) or integrated (`mcp-audit scan --sast <path>`). `mcp-audit sast <path>` standalone command. Pro-gated integration; `sast` feature key. Bundled in pip wheel and PyInstaller binary. `SastResult` model; Semgrep auto-discovery; severity mapping.
- **IDE extension security scanner** — discovers extensions across VS Code, Cursor, Windsurf, and Augment. Six analysis layers: known-vuln registry, dangerous capability combos, wildcard activation, unknown publisher, sideloaded VSIX, stale AI extensions. `mcp-audit extensions discover` (free) and `mcp-audit extensions scan` (Pro). `scan --include-extensions` flag (Pro). `registry/known-extension-vulns.json` seed dataset (5 entries). `extensions` and `fleet_extensions` feature keys. Findings use `analyzer="extensions"`.

---

## [0.2.0] - 2026-04-07 — Chain Reaction

### Added
- **Scan score & grade** — every scan produces a numeric score (0–100) and letter grade (A–F) via `scoring.py`. Grade panel rendered in terminal output. `scan --no-score` suppresses the terminal panel only; score still present in JSON/HTML. JSON output includes top-level `score` and `grade` fields. SARIF `run.properties` block carries `mcp-audit/grade`, `mcp-audit/numericScore`, `mcp-audit/positiveSignals`, and `mcp-audit/deductions`.
- **Known-server registry** — `registry/known-servers.json` curated dataset (57 entries) replaces hardcoded YAML in the supply chain analyzer. `KnownServerRegistry` loader with Levenshtein typosquatting detection. `update-registry` command (Pro) fetches latest registry from GitHub to user-local cache. `scan --registry PATH` override; `scan --offline-registry` flag. Registry stats dim one-liner appended to terminal output.
- **Baseline snapshot & drift detection** — five `baseline` sub-commands: `save`, `list`, `compare`, `delete`, `export`. `scan --baseline NAME` (or `--baseline latest`) injects `DriftFinding`s (converted to `Finding` objects with `analyzer="baseline"`) into all output formats. Storage at `<user-config-dir>/mcp-audit/baselines/` with `0o700`/`0o600` permissions. Environment variable values never stored, only key names.
- **GitHub Action** (`action.yml`) — composite action; inputs: `severity-threshold`, `format`, `config-paths`, `baseline`, `upload-sarif`; outputs: `finding-count`, `grade`, `sarif-path`. Uploads SARIF to GitHub Security tab; writes job summary. Exit-1-safe design.
- **Fleet merge** (`mcp-audit merge`) — consolidates JSON scan outputs from multiple machines into a single fleet report. Deduplicates findings by `(analyzer, server_name, title)`. Supports terminal, JSON, and HTML output. Enterprise-gated via `fleet_merge` feature key.
- **Policy-as-code rule engine** — YAML-based custom detection rules. 12 community rules (`COMM-001` through `COMM-012`) bundled and run for all users (free tier). `rule validate`, `rule test`, `rule list` sub-commands. `scan --rules-dir PATH` and user-local rules directory for Pro users. `custom_rules` feature key. Rule findings use `analyzer="rules"`. Community rules always run regardless of license tier.
- **Pre-commit hook** (`.pre-commit-hooks.yaml`) — `language: python`, `entry: mcp-audit`, `pass_filenames: false`, `types: [json]`. Default threshold is HIGH. Example configs in `examples/pre-commit/` (basic and strict).
- **Ed25519 license key system** — fully offline verification (public key hardcoded in `licensing.py`; private key never ships). `mcp-audit activate <key>` and `mcp-audit license` commands. License stored at `~/.config/mcp-audit/license.key` (permissions `0o600`). Three tiers: Community, Pro, Enterprise. `scripts/generate_license.py` (not shipped in package).
- `scan --policy PATH` auto-discovery: cwd → git repo root → user config dir → `None` (no check).
- `scan --output-file PATH` (alias `--output` / `-o`) with automatic parent directory creation.
- `scan --severity-threshold LEVEL` filters findings and drives exit code.
- Terminal output: dim registry stats one-liner after summary.
- Machine identification (`MachineInfo`) embedded in scan output; `--asset-prefix` flag for fleet deployments.
- `offline-registry` flag; SARIF score properties block.
- Example workflows: `examples/github-actions/basic.yml`, `strict.yml`, `with-baseline.yml`.
- Example pre-commit configs: `examples/pre-commit/basic.yaml`, `strict.yaml`.
- `examples/policies/` — sample governance policy files.

### Fixed
- `html_report` proxy gate replaced with dedicated `update_registry` feature key.

---

## [0.1.0] - 2026-04-01 — Prototype

### Added
- Initial working CLI scaffold using Typer + Rich, Pydantic v2 data models, pytest suite.
- **Six security analyzers:**
  - `poisoning.py` — tool-description poisoning detection (14 regex patterns).
  - `credentials.py` — secret/API-key exposure in configs (9 patterns).
  - `transport.py` — transport security (TLS, localhost binding).
  - `supply_chain.py` — package provenance and typosquatting via Levenshtein distance.
  - `rug_pull.py` — description-change detection using stateful config hashing; state scoped per config-set at `~/.mcp-audit/state.json`.
  - `toxic_flow.py` — cross-server capability tagging and dangerous pair detection; live MCP server enumeration via `--connect`.
- **Attack path engine** (`attack_paths.py`) — multi-hop detection (up to 4 servers), greedy hitting set algorithm, `summarize_attack_paths()`.
- **Eight supported MCP clients** — Claude Desktop, Cursor, VS Code, Windsurf, Claude Code (user-scoped), Claude Code (project-scoped), GitHub Copilot CLI, Augment Code.
- **Five output formats** — terminal (Rich), JSON, SARIF 2.1.0, Nucleus FlexConnect, self-contained HTML dashboard.
- **Interactive HTML dashboard** — embedded D3 v7 attack graph, light/dark mode toggle, grade badge, empty-state handling. D3 bundled from `data/d3.v7.min.js`.
- `mcp-audit watch` — filesystem watcher for continuous monitoring; re-scans on config change.
- `mcp-audit discover` — lists discovered MCP config paths across all clients.
- **Demo environment** (`demo/`) — produces 27+ findings across all analyzer categories.
- PyInstaller build pipeline (`build.py`) — 16.6 MB standalone binary, no Python required.
- `BaseAnalyzer` abstract class; `BaseFormatter` abstract class.
- `Finding`, `ServerConfig`, `ScanResult`, `ScanScore`, `Severity`, `AttackPath`, `MachineInfo` Pydantic models.
- Security review and patch pass — six vulnerabilities fixed (V-01 through V-06); internal findings V-07 through V-17 documented in `GAPS.md`.
- `GAPS.md` — known detection-quality limitations, severity calibration issues, untested areas.
- `PROVENANCE.md` — research attribution for all detection patterns.

---

_This changelog covers the full pre-release development history. The first public version tag will be added here when the initial release is cut._
