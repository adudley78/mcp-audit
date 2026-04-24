# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [Unreleased]

_Accumulates entries for work done after the last milestone and before the first public release tag._

---

## [0.1.2] - 2026-04-24 — Release infrastructure fix, dependency widening

The `v0.1.1` tag was cut on 2026-04-24 but never produced a GitHub release: the `Build darwin-x86_64` matrix leg targeted the `macos-13` runner image, which GitHub [retired on 2025-12-08](https://github.blog/changelog/2025-09-19-github-actions-macos-13-runner-image-is-closing-down/). Jobs requesting that label queue indefinitely instead of erroring, so every v0.1.1 release run hung. `0.1.2` is the first successful release under the new semver line; no user-facing code changed between 0.1.0 and 0.1.2.

### Fixed
- **`.github/workflows/release.yml`:** migrated the `darwin-x86_64` matrix leg from the retired `macos-13` runner to `macos-15-intel` (GitHub's replacement x86_64 label, supported through 2027-08). After that date, Actions drops x86_64 macOS entirely and this leg will need to be removed — Apple Silicon Macs run the x86_64 binary transparently via Rosetta in the meantime.
- **`src/mcp_audit/__init__.py`:** `__version__` now looks up the correct PyPI distribution name (`mcp-audit-scanner`, not `mcp-audit`). Every prior release silently fell through to the hard-coded `"0.1.0"` fallback because the metadata lookup used the CLI command name instead of the wheel name, so the embedded version string on released binaries was always stale. Fallback bumped to `"0.1.2"` for source installs.

### Changed
- **`pyproject.toml`:** `cyclonedx-python-lib>=7.0,<12.0` (was `<8.0`) — the `[sbom]` extra now installs against v7 or v8–v11 transparently. `src/mcp_audit/output/cyclonedx.py` was ported to the v8+ `cyclonedx.model.tool.Tool` location and `ToolRepository` metadata API with a v7 fallback, and all cyclonedx imports are now deferred into `format()` so the module imports cleanly when the extra is absent (previously raised `NameError` on any import with the extra missing — the no-extra fallback path was silently broken). Added `tests/test_cyclonedx_output.py` (9 cases) covering both the extra-missing path and formatter output against v7–v11.
- **`pyproject.toml`:** `sigstore>=3.0,<5.0` (was `<4.0`), `rich>=13.0,<16.0` (was `<14.0`), `watchdog>=4.0,<7.0` (was `<6.0`). Dependabot updates; no code changes required.

### Tooling
- **`actions/checkout@v6`** (was v5) across all four workflows.
- **`github/codeql-action@v4`** (was v3).
- **`softprops/action-gh-release@v3`** (was v2).

---

## [0.1.0] - 2026-04-23 — First public PyPI release

Version set to `0.1.0` (clean-slate public semver; internal development milestones tracked separately in `[0.11.x]` entries below).

**PyPI package name: `mcp-audit-scanner`** — the `mcp-audit` name was already
claimed on PyPI. The CLI command remains `mcp-audit` in all cases.

```bash
pip install mcp-audit-scanner
uv add mcp-audit-scanner
```

### Changed
- `pyproject.toml`: Development Status bumped from Alpha → Beta.
- `pyproject.toml`: Keywords expanded for PyPI search discoverability.
- `pyproject.toml`: URLs block updated — Homepage points to `mcp-audit.dev`; Documentation and Changelog links added.
- `README.md`: Install instructions updated to `pip install mcp-audit-scanner`; git+ source install removed.

---

## [0.11.0] - 2026-04-23 — Open Source Conversion

### Changed
- **All features are now free.** mcp-audit is fully open source under Apache 2.0. There are no paid tiers. `is_pro_feature_available()` always returns `True`; `gate()` is a permanent no-op. This removes the Community / Pro / Enterprise split entirely.
- **`sast.py`** — dropped `gate("sast", ...)` call and "(Pro feature)" wording from command docstring.
- **`dashboard.py`** — dropped `gate(...)` calls, "(Pro/Enterprise)" help text on `--rules-dir`, and the `html is None` dead branch (unreachable since `generate_html()` always returns a string).
- **`scan.py`** — removed `vuln_mirror`, `sast`, `extensions`, and `custom_rules` gates; dropped "(Pro)" from `--format` help text.
- **`license.py`** — `version` no longer prints a tier; `activate` / `license` commands label themselves as legacy key handling on an open-source build and no longer reference `mcp-audit.dev/pro`.
- **`CLAUDE.md`** — "Business model" section rewritten; all "Pro/Enterprise" / `_FEATURE_TIERS` references removed; `_gate.py` reframed as a permanent no-op shim.
- **`CONTRIBUTING.md`** — "Adding a new Pro feature" section replaced with open-source workflow; "won't accept" list bars re-introducing paid tiers.
- **`rules/README.md`** — dropped "(requires Pro)" from `rule validate` instruction.

### Removed
- 43 gate-specific tests deleted across `test_license_cache.py`, `test_dashboard.py`, `test_push_nucleus.py`, `test_fleet.py`, `test_governance.py`, `test_sast.py`, `test_extensions.py`, `test_registry.py`, `test_scanner.py`, `test_rules.py`. These tested behaviour that no longer exists. **1355 tests passing** (down from 1398; all removals are intentional).

### Notes
- `activate` and `license` commands are retained to honour any previously issued keys — they do nothing harmful on an open-source build.
- `scripts/generate_license.py` is retained (not shipped in the wheel) for the same reason.
- `push-nucleus` is ungated — it is the natural workflow for teams with a Nucleus instance, not a paywall.

---

## [0.10.1] - 2026-04-23 — SARIF 2.1.0 Schema Fixes

### Fixed
- **`invocation` extra fields** (`src/mcp_audit/output/sarif.py`, commit `46d9a34`): `machine`, `account`, and `operatingSystem` were placed directly on the `invocation` object. The SARIF 2.1.0 schema declares `invocation` with `additionalProperties: false`, making these unrecognised keys a hard schema violation. Fixed by moving all three into `invocation.properties` — a `propertyBag` (free-form key→value map) that the spec explicitly permits on every SARIF object.
- **`fixes` without `artifactChanges`** (`src/mcp_audit/output/sarif.py`, commit `46d9a34`): `result.fixes[*]` contained only `{"description": {"text": remediation}}`. The SARIF schema requires `artifactChanges` in every `fix` object, as `fixes` is designed for structured byte-level code patches, not free-text advice. Removed `fixes` entirely and moved the remediation string to `rule.help.text` (SARIF §3.49.11), the correct field for human-readable fix guidance.

### Changed
- **Playwright browser tests now pass** (previously skipped): `test_dashboard_compat.py` cross-browser tests (Chromium, Firefox, WebKit) run fully with browsers installed. Full suite: **1398 passed, 0 failed, 0 skipped**.

---

## [0.10.0] - 2026-04-23 — Nucleus FlexConnect Integration

### Added
- **`mcp-audit push-nucleus` command** (`src/mcp_audit/cli/push_nucleus.py`): Enterprise-gated command that runs a full scan and pushes results directly to a Nucleus Security project via the FlexConnect API. Multipart/form-data upload via `urllib.request` (no third-party HTTP lib). Polls job to completion with configurable timeout. Prints a Rich success panel with project ID, job ID, finding count, asset name, and a direct UI link. `--output-file` writes the FlexConnect JSON locally alongside the push. 11 tests in `tests/test_push_nucleus.py`.
- **Validated FlexConnect schema** (`src/mcp_audit/output/nucleus.py`): corrected from placeholder format to the live-validated schema. Top-level `assets` array defines the host asset; top-level `findings` array references it via `host_name`; `scan_type` is `"Host"`. Previously the formatter used a flat `host_name`/`asset_name` structure that was rejected by Nucleus ingestion ("Scan did not have any assets defined"). Validated against nucleus-demo.nucleussec.com.
- **`scripts/validate_nucleus.py`**: retained as a standalone regression/validation tool for testing the FlexConnect shape against a live instance without running a full scan.

### Changed
- `_finding_to_nucleus()` now sets `host_name` per finding (linking to the `assets` entry) instead of `asset_name` with `{prefix}/{client}/{server}` formatting.
- `format_nucleus()`: `scan_type` changed from `"Application"` to `"Host"`; top-level `host_name`/`operating_system_name` envelope fields replaced by the `assets` array.
- `tests/test_nucleus_output.py`: 3 tests updated, 4 new tests added for the `assets` array structure.
- `tests/test_machine_info.py`: 7 stale `TestNucleusFormatter` tests updated to match the corrected format.

---

## [0.9.0] - 2026-04-23 — License Revocation & Commercial Infrastructure

### Added
- **Bundled certificate revocation list** (`src/mcp_audit/data/revoked.json`): signed with the same Ed25519 keypair as license keys; `_load_revoked_kids()` reads and verifies the list once at module import and caches the result in `_REVOKED_KIDS: frozenset[str]`. Returns an empty frozenset on any parse, missing-file, or signature failure — scans never hard-fail because the CRL is unsigned or corrupt (graceful degradation during development with the placeholder key).
- **`kid` and `sub` fields in license key payload**: `kid` (8-char lowercase hex, auto-generated via `secrets.token_hex(4)` if omitted) is the primary revocation handle, always included in new keys. `sub` (Lemon Squeezy order ID) is included when provided. Both fields are optional in `LicenseInfo` (`kid: str | None = None`, `subscription_id: str | None = None`) — existing keys without these fields are backward-compatible and treated as non-revocable (they expire naturally on their existing schedule).
- **Revocation check in `verify_license()`**: if `kid` is present in `_REVOKED_KIDS`, the function returns `None` immediately. Legacy keys without a `kid` field bypass the revocation check.
- **Thread-local failure discriminator** (`_set_last_verify_failure()` / `get_last_verify_failure()`): allows the CLI to surface `MCPA-LIC-REVOKED` vs `MCPA-LIC-EXPIRED` vs generic-invalid without leaking the reason into `LicenseInfo`. Error codes follow the `GOV-*` / `COMM-*` convention.
- **Discriminated error messages in `cli/license.py`**: `activate` command checks `get_last_verify_failure()` after a failed key save and prints the appropriate message: "License revoked. Contact support@mcp-audit.dev with your order ID. [MCPA-LIC-REVOKED]", "License expired. [MCPA-LIC-EXPIRED]", or generic invalid.
- **`sign-revocation-list` sub-command in `scripts/generate_license.py`**: emits a signed `revoked.json` ready to commit. Usage: `python scripts/generate_license.py sign-revocation-list --kids a1b2c3d4,deadbeef --key-file ~/.mcp-audit-signing-key.pem --out src/mcp_audit/data/revoked.json`.
- **Operator audit log**: every key issuance appends a JSONL row to `~/.mcp-audit-issued-keys.jsonl` (permissions 0o600). Fields: `kid`, `email`, `sub`, `issued`, `expires`, `revoked`.
- **`tests/test_licensing_revocation.py`**: 12 new tests covering backward compat, `_load_revoked_kids` (empty list, revoked kid, tampered signature, missing file, malformed JSON, placeholder empty signature), `verify_license` revocation paths (valid-unrevoked, revoked kid, legacy key without kid), and the 90-day default issuance window.
- **No telemetry policy** (`docs/telemetry.md`): authoritative no-telemetry statement — what isn't collected, why, trade-offs accepted, and the bar any future opt-in change must clear. Linked from `docs/README.md` and `README.md`.

### Changed
- **Default key issuance window: 365 → 90 days** in `scripts/generate_license.py`. Natural expiry is the primary revocation mechanism; the bundled CRL is the break-glass for the 90-day window between a refund event and expiry.
- `generate_license_key()` gains `kid` and `sub` optional kwargs; both conditionally included in the signed payload.
- `GAPS.md` telemetry references consolidated to a single pointer to `docs/telemetry.md`.

### Notes
- The Cloudflare Worker webhook (Lemon Squeezy `order_created` → auto-issue, `order_refunded` → stop re-issuing) and the nightly GitHub Actions re-issue cron are a separate PR, pending domain and purchase URL going live.
- `src/mcp_audit/data/revoked.json` ships with `"signature": ""` until the real Ed25519 private key is available; `_load_revoked_kids()` returns `frozenset()` for this case — no scan impact.

---

## [0.8.0] - 2026-04-23 — Integration Validation: SARIF Hardening & Browser Compatibility

### Fixed
- **SARIF `%SRCROOT%` resolution** (`output/sarif.py`): Added `originalUriBaseIds` to the SARIF run object, anchoring `%SRCROOT%` to `file:///` per SARIF 2.1.0 §3.14.14. GitHub's code scanning API requires this definition to resolve relative artifact paths to repo-root-relative links in the Security tab.
- **SARIF `file:///unknown` fallback** (`output/sarif.py`): `_finding_to_file_uri` now returns the relative sentinel `"unknown"` instead of `"file:///unknown"` when `finding_path` is `None`. GitHub's SARIF uploader rejects the invalid absolute URI when `uriBaseId` is set; the relative form is accepted and gracefully omitted from source links.
- Updated 3 assertions in `tests/test_sarif_output.py` to match the corrected `"unknown"` sentinel.

### Added
- **`automationDetails.id` in SARIF output** (`output/sarif.py`): Run ID derived from scan timestamp. Prevents GitHub from creating duplicate code scanning alerts on repeated uploads of the same findings.
- **SARIF schema validation tests** (`tests/test_sarif_schema.py`): 10 tests validating mcp-audit SARIF output against the official OASIS SARIF 2.1.0 JSON schema (fetched once and cached at `tests/fixtures/sarif-schema-2.1.0.json`; tests skip gracefully if neither cache nor network is available). Covers run structure, `originalUriBaseIds` presence, `automationDetails`, finding shape, `uriBaseId` values, and version field.
- **`jsonschema>=4.0` and `playwright>=1.40`** added to `[project.optional-dependencies] dev` in `pyproject.toml`.
- **`docs/github-action.md` — SARIF upload verification guide**: 5-step manual checklist for confirming SARIF output reaches the GitHub Security tab, including common failure causes (`%SRCROOT%` unresolved, `file:///unknown` rejection, missing `write` permission on `security-events`).
- **Dashboard browser compatibility tests** (`tests/test_dashboard_compat.py`): 7 tests total. Three parametrised Playwright tests (Chromium / Firefox / WebKit) verify no JS console errors, grade badge visible (`.grade-badge`), finding rows present (`.findings-table`), dark-mode toggle works (`.theme-toggle`), and SVG attack graph rendered (`#graph-svg`). Four structural tests run without a browser: no external CDN references in dashboard HTML, D3 bundled inline, scan data JSON embedded, grade letter present. Playwright tests skip gracefully when browser binaries are not installed.
- **Playwright browser install step** in `.github/workflows/ci.yml`: runs `playwright install --with-deps chromium firefox webkit` on the `ubuntu-latest / 3.12` leg only, before the test step. Browser tests are skipped on all other matrix legs.
- `GAPS.md` — "SARIF not tested with GitHub" and "Dashboard browser compatibility untested" items resolved (2026-04-23).

---

## [0.7.0] - 2026-04-23 — Platform Coverage & CI Hardening

### Added
- **End-to-end binary smoke test** (`scripts/smoke_test.py`): cross-platform Python script (stdlib only) that runs 8 checks against the built binary: `version`, `discover`, scan of a malicious fixture (asserts exit 1), JSON output validity (findings, score, per-finding keys), clean scan (asserts exit 0), `--severity-threshold critical` filtering, SARIF 2.1.0 structure, and baseline save/list/delete roundtrip.
- **Smoke test fixture** (`tests/fixtures/smoke_test_config.json`): self-contained config with a poisoned server (triggers POISON-001) and a credential server (triggers credential finding via `sk-[A-Za-z0-9]{20,}` pattern). Used by both the binary smoke test and `tests/test_smoke_fixture.py`.
- **`tests/test_smoke_fixture.py`**: 4 unit tests that keep the smoke fixture honest without requiring a binary build — verifies POISON-001, a credential finding, and at least one finding overall.
- **Binary size gate** in `release.yml`: warns at 25 MB, fails at 35 MB. Actual size post-sigstore is ~22–24 MB; thresholds will be tightened after first rebuild measurement.
- **Release job summary** (`report` job in `release.yml`): posts a binary-size table to the GitHub job summary after every release build.
- **PR-level binary build** (`binary-smoke` job in `ci.yml`): builds the Linux x86_64 binary with PyInstaller and runs the full smoke test on every PR and push to `main`. Catches PyInstaller breakage before tagging.

### Fixed
- `release.yml` — replaced one-line `mcp-audit version` smoke test with the full 8-check `smoke_test.py` workflow on all four platforms.

---

## [0.6.0] - 2026-04-23 — Supply Chain Layers 2 & 3

### Added
- **Layer 2: Sigstore provenance verification** (`attestation/sigstore_client.py`, `attestation/sigstore_findings.py`): opt-in `--verify-signatures` flag (free, default OFF) verifies Sigstore provenance bundles for registry-known npm and PyPI packages. Fetches bundles from the npm attestations API and PyPI PEP 740 provenance API; verifies with the `sigstore` Python library (Fulcio cert chain, SCT, Rekor inclusion proof); extracts OIDC issuer (OID `1.3.6.1.4.1.57264.1.1`) and SAN URI from the signing certificate; compares signing repo against `RegistryEntry.repo`. `--strict-signatures` raises "absent" findings from INFO to MEDIUM. Six new finding IDs: `ATTEST-010` (valid match, INFO), `ATTEST-011` (valid but wrong repo, HIGH), `ATTEST-012` (invalid signature, CRITICAL), `ATTEST-013` (expected attestation absent, MEDIUM), `ATTEST-014` (absent, INFO/MEDIUM), `ATTEST-015` (network error, INFO). `attestation_expected: bool = False` field added to `RegistryEntry`; set to `true` for all 26 Anthropic-maintained entries in the registry.
- `sigstore>=3.0,<4.0` added to package dependencies.
- `docs/supply-chain.md` — Layer 2 section documenting all finding IDs, flag behaviour, and `--strict-signatures` usage.
- `docs/severity-framework.md` — `ATTEST-010` through `ATTEST-015` severity table.

- **Layer 3: Known-vulnerability scanning** (`vulnerability/` module): opt-in `--check-vulns` flag (free, default OFF) resolves transitive dependencies via the deps.dev API and checks them against OSV.dev in a single batched call. Full transitive graph coverage (not just direct deps). Graceful degradation on network failure per batch — scan never crashes. `VULN-<OSV-ID>` findings (severity from CVSS score), `VULN-UNPINNED` (LOW) for unversioned packages. Supports npx/bunx/pnpx/uvx/pipx/yarn-dlx ecosystems via the shared `vulnerability/resolver.py`. `--vuln-registry URL` (Pro soft-gate) for air-gapped OSV mirrors.
- **`mcp-audit sbom` command** (`cli/sbom.py`): generates a CycloneDX 1.5 JSON SBOM for all configured MCP servers and their transitive dependencies. `cyclonedx-python-lib` is an optional `[sbom]` extra (not bundled in the PyInstaller binary); the command prints a clear install instruction if absent. Supports `--format cyclonedx` (default) and `--format terminal` (Rich dependency tree). `--output PATH` writes to file.
- **`_network.py` — unified `--offline` contract**: `NetworkPolicy` dataclass + `require_offline_compatible()` replaces all scattered `if offline and <flag>` guards in `_preflight_checks`. Now covers `--verify-hashes`, `--verify-signatures`, `--check-vulns`, and `--connect` in one place.
- `"vuln_mirror": frozenset({"pro", "enterprise"})` feature key added to `licensing.py`.

### Notes
- Binary size advisory: the `sigstore` dependency tree (`betterproto`, `tuf`, `rfc3161-client`, `securesystemslib`) is expected to push the PyInstaller binary above the 22 MB target. Three mitigation options documented in `attestation/sigstore_client.py`; a rebuild is required before the next release cut to measure actual impact. `cyclonedx-python-lib` excluded from PyInstaller specs to contain further growth.

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
