# Known gaps and improvement areas

This document catalogs the known limitations of mcp-audit in its current prototype state. These are areas that need work before the tool is ready for production use by security practitioners. Contributions and feedback welcome.

## Recently resolved

- **Paid-license infrastructure removed** (v0.2.0): Ed25519 key verification (`licensing.py`), license cache (`_license_cache.py`), feature-gate shim (`_gate.py`), key-issuance script (`scripts/generate_license.py`), bundled revocation list (`data/revoked.json`), and the `activate` / `license` CLI commands are all gone. mcp-audit is fully open source (Apache 2.0); every feature ships in every build. `cryptography` moved to the `[attestation]` optional extra because attestation's X.509 parser is its only remaining consumer.

- **`run_scan` and `run_scan_async` duplicated the full analysis pipeline** (fixed 2026-04-20): Both entry points re-implemented the same seven-step pipeline (per-server analyzers → rug-pull → toxic-flow → attack paths → rule engine → scoring → registry stats), which meant any new analyzer or pipeline bug fix had to be applied twice or one path would silently lag. Fix: extracted `_run_static_pipeline()` in `scanner.py` as the canonical pipeline implementation; both `run_scan` (sync) and `run_scan_async` (async, after live enumeration completes) delegate to it. The helper is synchronous — `run_scan_async` now completes any `--connect` live MCP enumeration *before* calling the pipeline, which produces the same set of findings as before (only the insertion order of runtime poisoning findings changed; no test asserts on that order). New tests `test_static_pipeline_documents_order`, `test_run_scan_delegates_to_static_pipeline`, and `test_run_scan_async_delegates_to_static_pipeline` in `tests/test_scanner.py` lock the delegation contract. Test count: 1105 → 1108.

- **`--no-score` leaked score into SARIF `run.properties`** (fixed 2026-04-16): When `--no-score` was passed, the SARIF formatter still included the grade/score properties block because score suppression only reached the terminal renderer. Fix: `cli.py` now nulls `result.score` after scanning and before any formatter is called.

- **Malformed JSON config silently swallowed** (fixed 2026-04-16): `mcp-audit scan --path /tmp/bad.json` (with invalid JSON content) produced "No security issues found" and exit 0. Fix: `cli.py` now checks `result.errors` for parse failures on user-specified paths, prints a `[red]Error:[/red]` line with the file path and parse error detail, and exits 2.

- **Missing LICENSE file** (fixed 2026-04-16): No LICENSE file existed in the repo. Fix: Apache 2.0 LICENSE created; `pyproject.toml` license field and classifiers aligned.

- **Missing CONTRIBUTING.md** (fixed 2026-04-16): No contributor guide existed. Fix: CONTRIBUTING.md added with development setup, code conventions, and PR requirements.

- **Placeholder strings throughout codebase** (fixed 2026-04-16): `yourusername`, `Your Name`, `you@example.com` appeared in `pyproject.toml`, `sarif.py`, `README.md`, `scripts/install.sh`, and `docs/enterprise-deployment.md`. Fix: all replaced with real values (`adudley78`, `Adam Dudley`, and a GitHub noreply author address).

- **Cryptography dependency pin excluded security fix versions** (fixed 2026-04-17): `cryptography>=42.0,<47.0` resolved to 44.0.3 which is still vulnerable to CVE-2026-26007 (missing EC public key subgroup validation, fixed 46.0.5) and CVE-2026-34073 (DNS name constraint bypass for peer names, fixed 46.0.6). Fix: lower bound raised to `>=46.0.6,<47.0`; lockfile now resolves to `cryptography==46.0.7`. Confirmed clean with `pip-audit` — zero findings.

- **`.gitignore` missing `.env` and `*.key` patterns** (fixed 2026-04-16): Contributors could accidentally commit secrets. Fix: `.env`, `.env.*`, `*.key`, `*.pem` added to `.gitignore`.

- **Unused imports (F401)** (fixed 2026-04-16): `config_parser.py` imported unused `Path`; `test_nucleus_output.py` imported unused `MachineInfo`. Fix: both removed.

- **31 pre-existing ruff errors** (fixed 2026-04-16): 29 × E501 (line too long) in analyzers, `config_parser.py`, `licensing.py`, `terminal.py`, `test_analyzers.py`; 1 × SIM102 (collapsible nested if) in `transport.py`; 1 × S108 (insecure temp path) in `test_analyzers.py`. Fix: all lines wrapped within 88 chars using implicit string concatenation; SIM102 collapsed into single `if` with `and`; S108 replaced with pytest `tmp_path` fixture. `ruff check src/ tests/` now returns zero errors.

- **22 files not passing `ruff format`** (fixed 2026-04-16): 10 source files and 12 test files had formatting inconsistencies (trailing commas, indentation, string join wrapping, blank lines after docstrings). Fix: `ruff format src/ tests/` applied; one exposed E501 in `nucleus.py` suppressed with `# noqa: E501` (Rich markup string). `ruff format --check src/ tests/` now returns zero files; `ruff check src/ tests/` remains clean.

- **Version string hardcoded in 6 locations** (fixed 2026-04-16): V-13 resolved. `__version__` is now defined once in `src/mcp_audit/__init__.py` via `importlib.metadata` with a dev-install fallback. All 6 consumer locations import from there. A consistency test verifies alignment.

- **Stale doc counts and claims** (fixed 2026-04-16): README test counts (546/517 → 845), registry count (43 → 57), CLAUDE.md test/command counts, and multiple docs inaccuracies corrected. SARIF score documentation in `docs/scoring.md` updated. Stale proxy-gate note in `docs/registry.md` removed. `docs/github-action.md` drift severity table and nonexistent `baseline import` command corrected. OSV.dev references in `docs/enterprise-deployment.md` removed (feature not implemented).

## Detection quality

**False positive rate benchmarked at 0% across 22 servers (2026-04-23).** The poisoning analyzer was validated against 12 official `@modelcontextprotocol/*` servers and 10 popular community servers. Zero poisoning false positives were found. See `tests/test_false_positive_benchmark.py` for the full benchmark — this is now a regression test. Acceptable non-FP findings on legitimate servers: TRANSPORT-003 (runtime package fetch, expected for all npx/uvx servers), COMM-010 (npx without pinned version). Note: the "base64 encode" false positive from the filesystem server's runtime tool descriptions (fetched via `--connect`) is not covered by static analysis and remains a known limitation of the live connection path.

**Exploit validation suite added (2026-04-23).** Six published attack PoCs are now reconstructed as fixtures in `tests/fixtures/exploits/` and verified by `tests/test_exploit_validation.py`: Invariant Labs SSH exfiltration, CrowdStrike `add_numbers`, fake Postmark exfiltration, XML injection override, cloud credential exfiltration, and behavioral override stealth. All six are detected. Detection is based on static config analysis — whether these patterns cause real LLMs to follow injected instructions in production is a separate validation question that requires live red-team testing against actual agent deployments.

**Pattern coverage is thin.** The poisoning analyzer has 11 patterns (authoritative count: `len(PATTERNS)` in `analyzers/poisoning.py`, not the highest ID number). The credential analyzer has 9. Production secret scanners like truffleHog and detect-secrets use 700+ credential patterns. The poisoning patterns cover the most-cited attack techniques but will miss novel or obfuscated injection methods. Pattern count should grow based on practitioner feedback and new published research.

**POISON-050 checks statically available description fields only.** The oversized-payload rule (POISON-050) is scoped to `name` and `description` keys in the raw server config — the fields an AI model reads when deciding whether to invoke a tool. Fields such as `command`, `args`, and environment variable values are intentionally excluded because they are not model-visible and do not constitute an attack surface for tool description padding. Additionally, tool manifests fetched at runtime via the MCP protocol (i.e., `ToolInfo.description` returned by a live `tools/list` call) are not checked by the static analyzer; connecting with `--connect` enumerates live tools and runs the poisoning patterns against their descriptions, but this requires a running server and an optional SDK dependency. As a result, POISON-050 will not fire for servers whose tool descriptions are only visible after protocol negotiation.

## Severity calibration

**Severity framework documented (2026-04-23).** Severity levels are now mapped to CVSS base score bands and OWASP Agentic Top 10 risk categories with written rationale for each finding ID. See `docs/severity-framework.md`. CVSS scores are approximate (no environmental/temporal modifiers applied) and should be reviewed by a credentialed practitioner before any formal CVE or compliance reporting.

## Supply Chain Attestation (Layer 1)

**Version extraction is best-effort.** mcp-audit recognises only the `npx package@version` invocation pattern when extracting the installed version from a server config. Servers installed via other mechanisms (pip, uvx, docker, system packages, direct binary path) cannot have their versions extracted automatically — an INFO finding is produced instead of a hash comparison.

**npm hashes are computed by mcp-audit on download, not sourced from a signed manifest.** PyPI publishes authoritative SHA-256 digests in its JSON API (`digests.sha256` in `/pypi/<pkg>/<version>/json`). npm's `integrity` field uses SHA-512 SRI format, not SHA-256. mcp-audit normalises to SHA-256 by downloading the tarball — meaning the hash is trustworthy only to the extent that the download path (npmjs.org CDN) is trustworthy. This is a weaker guarantee than PyPI's API-published digests.

**`--verify-hashes` requires outbound network access.** Scans run fully offline by default. When `--verify-hashes` is passed, mcp-audit makes HTTPS requests to registry.npmjs.org and pypi.org. If the network is unavailable, INFO findings are produced for packages that could not be verified — the scan does not fail.

~~**Layer 2 (Sigstore signature verification) and Layer 3 (dependency SBOM) are not yet implemented.**~~ **Layer 2 resolved 2026-04-23.** **Layer 3 resolved 2026-04-23.** `scan --verify-signatures` fetches SLSA provenance bundles from the npm and PyPI attestation APIs and verifies them with the `sigstore` Python library (Fulcio cert chain, SCT, Rekor inclusion proof). `scan --check-vulns` resolves transitive dependency graphs via [deps.dev](https://deps.dev) and queries [OSV.dev](https://osv.dev) for known CVEs; emits `VULN-<OSV-ID>` findings. `mcp-audit sbom` generates a CycloneDX 1.5 JSON SBOM. Both features are free for all tiers. `--vuln-registry URL` (Pro/Enterprise) allows a custom OSV-compatible endpoint. See `docs/supply-chain.md` for full documentation.

## Supply chain coverage

**Only npm packages are checked for typosquatting.** The MCP ecosystem includes Python servers (installed via uvx/pip), Docker containers, Go binaries, and other package managers. The supply chain analyzer only checks npm package names (npx/bunx/pnpx commands) against the known-server registry. PyPI typosquatting, Docker image verification, and other ecosystems are not covered.

**Registry size is below launch target.** The known-server registry ships with 64 entries as of April 2026. The launch target is 75+ entries to cover the most-installed community servers. Community contributions are needed before the August launch — open a PR against `registry/known-servers.json`. See `docs/registry-contributions.md` for the contribution guide.

~~**Levenshtein threshold may produce false positives for short package names.**~~ **Resolved 2026-04-30.** Package names of 5 characters or fewer now use a tighter threshold of 1 edit instead of 3. Names of 6+ characters keep the existing threshold of 3. The fix is in `analyzers/supply_chain.py` (`typo_threshold = 1 if len(package) <= 5 else 3`). Covered by `tests/test_supply_chain.py::TestShortNameThreshold`.

~~**No registry metadata enrichment.**~~ **Resolved 2026-04-23.** `RegistryEntry` now carries three optional metadata fields — `first_published` (ISO date), `weekly_downloads` (int), and `publisher_history` (ordered list of publisher accounts). Ten entries in `registry/known-servers.json` have been pre-populated with npm data. When a typosquatted or unknown package is flagged (SC-001/SC-002), the finding description now includes a pipe-delimited metadata blurb for the legitimate package (e.g. "first published: 2024-11-14 | weekly downloads: 42,800 | known publishers: anthropic-bot, modelcontextprotocol"). The `scripts/enrich_registry.py` maintainer script fetches live data from the npm registry API to keep metadata fresh without any network calls during scanning.

## Live connection (`--connect`)

**Tested against one server.** The `--connect` feature has been tested against the official `@modelcontextprotocol/server-filesystem` server only. Behavior against the broader ecosystem of MCP servers (different transports, authentication requirements, non-standard handshakes) is unknown.

**Server stderr output leaks to terminal.** When `--connect` launches a stdio server, the server's stderr output (warnings, logs, startup messages) appears in the user's terminal interleaved with mcp-audit output. This should be captured and suppressed or redirected.

**No authentication support.** Some MCP servers (particularly SSE/HTTP servers) require authentication tokens or headers. The current `--connect` implementation doesn't support passing authentication credentials to remote servers.

## Toxic flow analysis

**Capability tagging is authoritative-first, heuristic-fallback.** For packages present in `registry/known-servers.json` with a `RegistryEntry.capabilities` list, those tags are the single source of truth. For everything else (unknown packages, private forks, custom servers), capabilities are inferred from package names and keyword matching. A server with no matching keywords might have dangerous capabilities that aren't detected. Live enumeration via `--connect` improves this by analyzing actual tool names, but coverage depends on the registry being current and the keyword lists being comprehensive. The historical drift risk — where adding a server to `known-servers.json` did not grant it capability tags (resulting in silent regression to keyword-only tagging) — was closed on 2026-04-20 when capability data was migrated from the in-module `KNOWN_SERVERS` dict into the registry JSON; the dict remains as a deterministic fallback when no registry is injected.

**No weighting or scoring.** All toxic pairs of the same severity are treated equally. In practice, a filesystem + fetch combination on a developer laptop is less risky than a database + shell-exec combination on a production server. Context-aware risk scoring is not implemented.

## Output formats

~~**Nucleus FlexConnect not validated.**~~ **Resolved 2026-04-23.** The FlexConnect output formatter has been validated end-to-end against a live Nucleus instance. The correct schema (top-level `assets` array + per-finding `host_name` field; `scan_type: "Host"`) was confirmed via live API round-trip. The `push-nucleus` command (`src/mcp_audit/cli/push_nucleus.py`) performs a multipart/form-data upload and polls the import job to completion. Both the formatter (`src/mcp_audit/output/nucleus.py`) and the push command have test coverage; the `scripts/validate_nucleus.py` regression script can be re-run against any Nucleus instance to re-validate.

~~**SARIF not tested with GitHub.**~~ **Resolved 2026-04-23.** The SARIF formatter now conforms to the SARIF 2.1.0 schema as validated by `tests/test_sarif_schema.py` (uses the official OASIS JSON schema via `jsonschema`). Key hardening applied: `originalUriBaseIds` added so GitHub's uploader can resolve `%SRCROOT%` to the repo root; `automationDetails.id` added for run deduplication in the Security tab; `file:///unknown` fallback replaced with the relative sentinel `"unknown"` (the invalid absolute URI caused GitHub to silently discard results). Manual verification against a live repository with Code Scanning enabled is documented in `docs/github-action.md` § "Testing the SARIF upload".

## Platform coverage

**Windows not tested.** Config discovery includes Windows paths but the tool has only been tested on macOS. Path handling, file encoding, and process spawning may behave differently on Windows. Extension discovery paths for VS Code, VS Code Insiders, Cursor, and Windsurf are now defined (STORY-0004, 2026-04-30) and unit-tested via monkeypatching; end-to-end validation on a real Windows host is a manual step.

**Linux not tested.** Same as Windows — paths are defined but not validated on actual Linux systems.

## Internal security findings

Self-audit conducted 2026-04-12. Criticals and highs were patched in commit `18bbf66`. The medium and low findings below are tracked for future hardening — normal for a prototype.

### Medium

**V-07: Resolved (2026-04-23).** Poisoning detection bypassed by Unicode homoglyphs. All regex patterns now run against NFKD-normalized ASCII text. A new `POISON-060` pattern detects Cyrillic, Greek, general-punctuation lookalikes, and fullwidth ASCII variants in the original (non-normalized) text. CWE-116.

**V-08: Resolved (2026-04-23).** Poisoning detection bypassed by nesting depth > 10. The recursion limit in `_extract_text_fields` and `_extract_description_fields` raised from 10 to 50. A depth of 50 guards against circular-reference DoS while making the bypass impractical.

**V-09: Resolved (2026-04-23).** `TRANSPORT-004` (HIGH, CWE-1327) added to `TransportAnalyzer`. Fires when the server URL hostname is `0.0.0.0`, `::`, `[::]`, `0:0:0:0:0:0:0:0`, or `[0:0:0:0:0:0:0:0]`. Wildcard bindings expose the server on all interfaces simultaneously — more dangerous than a specific remote host.

**V-10: Resolved (2026-04-23).** `TRANSPORT-002` privilege-escalation check expanded. Now catches `sudo`, `doas`, `pkexec`, `su`, `run0`, absolute paths to those binaries (e.g. `/usr/bin/sudo`, `/usr/local/bin/doas`), the `/usr/sbin/` prefix, and any of those names appearing as `args[0]` when the command is a shell (`sh`, `bash`, etc.).

**V-11: Resolved (2026-04-23).** `yarn dlx` detection added to both `TransportAnalyzer` and `SupplyChainAnalyzer`. `pipx` added to `_RUNTIME_FETCH_COMMANDS`. PyPI typosquatting for `uvx`/`pipx` packages requires a separate known-packages list for PyPI — tracked as a future supply-chain coverage gap.

**V-12: Resolved.** `httpx` moved from `dependencies` to the `mcp` optional group (`pip install 'mcp-audit[mcp]'`). It is not installed in the default distribution and carries no transitive attack surface for users who don't need live server connections.

### Low

**V-13: Resolved.** Version string centralized via `importlib.metadata` in `__init__.py` with consistency test.

**V-14: Resolved.** `pyproject.toml` license field set to `Apache-2.0`; classifiers aligned; LICENSE file created.

**V-15: Resolved.** All `yourusername` placeholder URLs replaced with `adudley78` across `sarif.py`, `pyproject.toml`, `README.md`, `scripts/install.sh`, and `docs/enterprise-deployment.md`.

**V-16: `_home()` inconsistency in discovery.py.** `_home()` wraps `Path.home()` for test mocking, but `_get_client_specs()` calls `Path.home()` directly on one line, defeating the indirection. Fix: use `_home()` consistently.

**V-17: Credential regex overlap and gaps.** The OpenAI pattern `sk-[A-Za-z0-9]{20,}` also matches Anthropic keys (`sk-ant-*`), causing double detection. No coverage for Google service account JSON, Azure SAS tokens, DigitalOcean tokens, Vercel tokens, or PEM-encoded keys. Generic secret pattern requires quotes around values, missing unquoted secrets. Fix: refine patterns and expand coverage incrementally.

## Binary distribution

**Binary distribution is architecture-specific.** The PyInstaller build pipeline produces a single-file binary for the platform it is built on. macOS (`mcp-audit-darwin-{arch}`) is built natively; Linux x86_64 (`mcp-audit-linux-x86_64`) is built via `scripts/build-linux.sh` which runs PyInstaller inside a `python:3.11-slim` Docker container — requires Docker Desktop. Apple Silicon (arm64) Macs require Rosetta 2 or a native arm64 build; Windows users need their own platform builds. GitHub Actions matrix builds across `[macos-13 (x86_64), macos-14 (arm64), ubuntu-latest, windows-latest]` are needed to produce the full platform matrix automatically on each release.

**Linux binary requires glibc ≥ 2.17 at runtime.** The `python:3.11-slim` (Debian bookworm) build environment links against glibc 2.36. PyInstaller sets `for GNU/Linux 3.2.0` as the minimum ELF ABI, but the bundled `.so` files (from the Debian build environment) may reference symbols requiring glibc 2.17+. This covers all modern Linux distributions (Ubuntu 18.04+, Debian 9+, RHEL/CentOS 7+) but will fail on Alpine Linux (musl libc) and very old glibc environments. Use a `python:3.11-alpine`-based build with `--strip` and musl-compatible wheels for Alpine targets.

**Linux binary not tested end-to-end on a real Linux host.** The ELF binary was built and verified via `file(1)` on macOS using the Docker build path. Its behavior on actual Linux distributions — config discovery paths, rug-pull state storage, watcher filesystem events — has not been validated. See the existing "Linux not tested" note under Platform coverage.

~~**Dashboard browser compatibility untested.**~~ **Resolved 2026-04-23.** `tests/test_dashboard_compat.py` covers Chromium, Firefox, and WebKit (Safari engine) headlessly via Playwright. Tests assert: no JS errors on load or dark-mode toggle, findings table present, SVG graph container present, self-contained HTML (no external CDN references), D3 v7 bundled inline, scan data JSON embedded. Browser tests are skipped gracefully when Playwright binaries are not installed; CI installs them on the `ubuntu-latest / 3.12` matrix leg. Mobile browsers and WebView-based environments (Electron, VS Code webview) are not covered.

## Licensing & distribution

**Fully open source — no paid tiers.** Apache 2.0; every feature ships in every build. All license-verification code, revocation lists, and the `activate` / `license` CLI commands were removed in v0.2.0.

**No telemetry or usage analytics.** By design. See `docs/telemetry.md` for
the full rationale and the bar any future opt-in change must clear.

## Scoring

**Score is computed before `--severity-threshold` filtering — intentional.**
`calculate_score()` in `scanner.py` runs against the complete finding set before
the CLI applies `--severity-threshold` filtering.  This means the score and grade
in JSON and SARIF output always reflect all findings regardless of the threshold
set by the operator.  Exit code and `has_findings` reflect only findings at or
above the threshold.  This is a deliberate design choice: the score is a property
of the configuration, not of the alerting threshold.  A practitioner who sets
`--severity-threshold HIGH` to reduce operational noise should still see the true
security posture in the JSON output.  See [docs/scoring.md](docs/scoring.md#scoring-and-severity-filtering)
for a concrete example and further rationale.

**INFO deductions are visible but cosmetically surprising.** INFO-severity findings produce a −1 deduction entry in the score breakdown. If positive signal bonuses (up to +10 total) exceed the total INFO deduction, the numeric score clamps to 100 even though deduction lines appear. The deduction entry is the intended signal to the practitioner. This is a known, accepted tradeoff — a clean scan with minor informational notes should still be achievable as a 100/A.

**Scoring weights are not user-configurable.** The deduction table and bonus thresholds are hardcoded in `scoring.py`. Custom severity weights are planned work but are not yet implemented.

## Baselines

**Server matching uses exact (client, name) pair — renames appear as remove+add.** `BaselineManager.compare()` identifies servers by the `(client, name)` tuple. If a server is renamed in the config file it will show as `server_removed` (old name) and `server_added` (new name) rather than as a single `hash_changed` finding. There is no fuzzy matching on server identity. This is intentional — fuzzy matching would increase false-negative rates — but users should be aware that renaming a server resets its history.

**Trend tracking (multi-baseline comparison) is not yet implemented.** The `BaselineManager` currently supports pairwise comparison (one baseline vs. current state) only. Historical trend views (e.g. "how has this server changed across 5 baselines") are not yet implemented.

## GitHub Action

**Action uses `pip install` rather than the PyInstaller binary.** The `action.yml` composite action installs mcp-audit via `pip install mcp-audit` on the CI runner. This requires a Python environment on the runner (satisfied by all GitHub-hosted `ubuntu-latest`, `macos-latest`, and `windows-latest` runners), adds approximately 20–30 seconds to each CI job, and pulls transitive dependencies. A future optimization would ship the binary via a separate `setup-mcp-audit` action that downloads the prebuilt binary from GitHub Releases (same pattern as `setup-go` or `setup-node`), reducing install time to under 5 seconds.

**Action not tested on self-hosted runners or non-standard Python environments.** GitHub-hosted runners provide Python 3.x in the default PATH. Self-hosted runners with non-standard Python installations (e.g., Conda environments, pyenv without global Python, Alpine Linux with `python3` missing) may fail at the `pip install` step. The action does not attempt to set up Python explicitly; users on non-standard runners should add an `actions/setup-python@v5` step before the action.

**Action not tested on Windows runners.** The action's shell scripts use bash syntax (`set +e`, `ARGS="..."`, heredocs). GitHub-hosted Windows runners default to PowerShell. The action sets `shell: bash` on all steps to use the Git Bash environment that Windows runners include, but this path has not been validated end-to-end. File paths with backslashes may cause issues in `--path` arguments.

**config-paths input accepts only a single path.** The `config-paths` action input is documented as "single MCP config file path" and maps to `--path`. The underlying CLI `--path` accepts a single path. Supporting comma-separated multiple paths would require multiple `--path` invocations or a new `--paths` multi-value flag in `cli.py`. This is a known limitation.

## Fleet merge

**HTML fleet output is a simplified table, not a full D3 fleet dashboard.** `mcp-audit merge --format html` renders a Rich-exported HTML table. A full D3 force-directed fleet visualization (showing machine relationships, shared findings as edges, attack-path overlays) is a future enhancement. The current output is functional but not interactive.

**`--dir` is non-recursive.** `mcp-audit merge --dir ./results/` only looks at `*.json` files at the top level of the directory. Nested subdirectories (e.g. `./results/team-a/machine-1.json`) are not scanned. Use shell globbing (`mcp-audit merge ./results/**/*.json`) for recursive collection.

**Deduplication matches on exact `(analyzer, server_name, title)` triple.** Findings with subtly different titles — for example, two credential findings on the same server but matching different key names (`sk-abc123` vs `OPENAI_KEY=xyz`) — will produce two separate DeduplicatedFindings rather than being collapsed. This is intentional (exact-match deduplication avoids false-merges) but means the unique-findings count may be slightly inflated when the same issue class manifests with different evidence strings.

**`asset_prefix` is not persisted in scan JSON output.** The `--asset-prefix` passed to `mcp-audit scan` is not stored in the resulting JSON file. When merging, `--asset-prefix PREFIX` filters by machine hostname prefix (machine_id), not by a stored asset_prefix field. Machines must be named with a meaningful prefix (e.g. `prod-laptop-adam`) for prefix filtering to be useful.

**Version mismatch detection uses string equality, not semver ordering.** A machine running `0.1.0` and a machine running `0.1.1` are both reported as mismatches against the majority version. There is no "close enough" tolerance — any version string difference triggers a warning.

## Policy-as-code rule engine

**Compound rule `matched_value` may be verbose for OR rules with many conditions.**
For compound `OR` rules, `matched_value` is constructed by joining all matched
condition values with `"; "`. If multiple conditions fire simultaneously, the
resulting `matched_value` string in the finding description and evidence can be
long and repetitive. This is intentional (full transparency) but may surprise
users expecting only the first matched value.

**Rule ID deduplication keeps first-alphabetical file, which may be surprising.**
When `load_rules_from_dir()` encounters two files with the same rule ID, it keeps
the rule from the alphabetically-first filename. Users who place a later-named file
hoping to override an earlier one will find the earlier definition takes precedence.
Use a `primary` + `secondary` pattern (via `merge_rules()`) for intentional
overrides — user-supplied directories are always treated as primary over bundled
community rules.

**Community rule false-positive rate is unmeasured.**
The 12 community rules were written to cover clear-cut cases (netcat as binary,
eval in args, etc.) but have not been validated against a broad sample of
real-world MCP server configurations.

**TRANSPORT-003 tiered by registry membership (2026-04-20).**
The runtime-package-fetching finding (`TRANSPORT-003`) previously fired at
MEDIUM for every server launched via `npx`, `uvx`, or `bunx`, including the
official `@modelcontextprotocol/server-*` packages. Because MEDIUM findings
trigger exit 1 at the `--severity-threshold medium` gate and contribute to
score deductions, this was the same signal-to-noise trap as COMM-004 — the
rule fired on 100% of registry-legitimate servers.

`TransportAnalyzer` now accepts an optional `KnownServerRegistry` (shared
with `SupplyChainAnalyzer` so the JSON is loaded exactly once per scan) and
tiers TRANSPORT-003 severity by registry membership:

- Verified registry entry → finding suppressed. COMM-010 (`npx used without
  pinned version`, LOW) still raises the pinning reminder.
- Known but unverified registry entry → LOW with tailored description
  pointing to `--verify-hashes`.
- Unknown package or no registry → MEDIUM (historic behaviour; strong alarm).

See `src/mcp_audit/analyzers/transport.py::_build_runtime_fetch_finding`
and `tests/test_analyzers.py::TestTransportRuntimeFetchRegistryTiering`.

**COMM-004 rescoped to unrecognized stdio servers (2026-04-20).**
The original COMM-004 (`stdio transport in use`) fired on every stdio MCP
server. Because stdio is the universally-implemented MCP transport today —
including every official `@modelcontextprotocol/server-*` package — the rule
was noise on 100% of real configs and made exit 0 unreachable at the default
`--severity-threshold INFO`. A finding that fires on every target is not a
signal.

Decision: **Option C — scope the rule to unrecognized servers.** Rather than
removing the rule outright or reducing severity (which would not lower the
false-positive rate), the rule engine now supports `exempt_known_servers:
true` on any `PolicyRule`. When set, the engine skips servers whose command,
any argument, or server name matches an entry in the known-server registry.
COMM-004 declares `exempt_known_servers: true`, so it now fires only on
stdio servers the registry cannot resolve (local scripts, unknown packages,
arbitrary binaries). This preserves the rule's signal ("verify this binary
is trusted") for the cases that actually need verification while removing
the noise on vetted packages. Severity stays LOW.

This is expected to be revisited when SSE/HTTP transports become common in
the MCP ecosystem; a future scope might distinguish servers that *declare*
stdio when a remote transport would be expected. See
`rules/community/COMM-004.yml`, `src/mcp_audit/rules/engine.py`
(`PolicyRule.exempt_known_servers`, `_server_in_registry`), and
`docs/writing-rules.md` for details.

## Pre-commit hook

**Hook re-scans all configs on every triggered commit, not just staged ones.** `pass_filenames: false` is required because mcp-audit uses its own client-aware discovery rather than accepting individual filenames. As a side effect, on large multi-client machines (e.g., Claude Desktop + Cursor + VS Code + Windsurf all configured), the hook re-scans all discovered configs even if only one JSON file was staged. Scan time is proportional to total server count across all clients, not to the size of the diff. On typical developer machines this is well under 5 seconds, but may be surprising on machines with dozens of MCP servers.

**Hook not tested with `--from-ref`/`--to-ref` diff modes.** The pre-commit framework supports running hooks in diff mode (e.g., `pre-commit run --from-ref HEAD~1 --to-ref HEAD`). Because `pass_filenames: false` bypasses the normal file-list mechanism, diff-mode invocations produce the same full-machine scan rather than a diff-scoped scan. This is consistent with the hook's design intent but has not been tested end-to-end with the pre-commit framework's diff infrastructure.

## Governance

**Client name matching uses string comparison.** The `client_overrides` map is
keyed by the client's `client` field value (e.g. `"cursor"`, `"claude-desktop"`).
Typos in override keys are silently ignored — the base policy applies to those
clients instead. Valid client keys are: `claude-desktop`, `cursor`, `vscode`,
`windsurf`, `claude-code`, `copilot-cli`, `augment`. There is no validation that
override keys match known client names; unknown keys are ignored without warning.

**Score threshold check requires a completed scan.** `ScoreThreshold.minimum`
is only evaluated when a `ScanResult` with a populated `score` field is passed to
`evaluate_governance()`. Running `policy check` (governance-only mode) omits
scores because no analyzers are run. Combine with a full `scan --policy` to
enforce score thresholds.

**Approved server glob matching is fnmatch-style, not full regex.** Pattern
matching uses Python's `fnmatch.fnmatch()` which supports `*` (any characters),
`?` (single character), and `[seq]` character classes. Unlike shell globbing,
fnmatch `*` matches `/` characters, so `@modelcontextprotocol/*` matches
`@modelcontextprotocol/server-filesystem` as expected. Full regex patterns are
not supported.

**Source detection is inferred from command basename only.** `npx`/`node`/`npm`
→ npm; `python`/`python3`/`uvx`/`uv`/`pip`/`pipx` → pip. Servers launched via
absolute paths, shell scripts, or custom wrappers return `None` source. Such
servers will never match a `source:`-filtered approved-server entry regardless of
the server name.

**Finding policy counts exclude governance findings but not baseline findings.**
`FindingPolicy.max_critical` etc. count only non-governance findings from
`scan_result.findings` at the time `evaluate_governance()` is called. Baseline
drift findings (injected before governance evaluation) are counted, which may
cause unexpected policy violations when combining `--baseline` with
`finding_policy`.

## SAST Rules

The Semgrep SAST rule pack (`semgrep-rules/`) has the following known limitations:

**Heuristic rules with high false positive risk:**
- `mcp-open-path-traversal` and `mcp-pathlib-open-traversal` fire on any variable path in an async function, including validated paths. Suppress with `# nosemgrep` when path validation is present.
- `mcp-no-type-check-before-use` fires when `arguments.get()` is used without an immediately adjacent `isinstance()` check, even when the MCP SDK provides type validation at the protocol level.
- `mcp-flask-no-ssl` matches any `$APP.run(...)` call; explicitly excludes `subprocess.run` and `asyncio.run`, but may fire on other `.run()` patterns.

**TypeScript rules are less comprehensive than Python rules:**
- Python has 28 rules across 5 categories; TypeScript has 9 rules across 4 categories.
- No TypeScript-specific path traversal, SQL injection, or protocol rules yet.
- TypeScript SSRF detection not yet implemented.

**Rules target server source code, not installed binaries:**
- SAST rules require access to the server implementation source code. They cannot scan pre-built npm packages, PyPI wheels, or Docker images. Config scanning (`mcp-audit scan`) remains the primary defense for production deployments.

**Semgrep is not bundled in the mcp-audit binary:**
- `mcp-audit scan --sast` and `mcp-audit sast` require `pip install semgrep` separately. The rule files are bundled; the semgrep engine is not. This matches how other SAST tools (bandit, eslint, etc.) work in the ecosystem.
- Rule file discovery works correctly in all installation modes: PyInstaller binary, `pip install mcp-audit` wheel, and editable dev installs. The resolution uses `mcp_audit._paths.resolve_bundled_resource()` with an `importlib.resources` step so that pip-installed wheels find `mcp_audit/semgrep-rules/` without requiring a source checkout.

**No taint analysis:**
- Current rules are pattern-based, not dataflow-aware. A variable URL used for SSRF only fires if the HTTP call is in the same function, not if the URL is passed from an outer scope. Full taint tracking requires Semgrep Pro rules (dataflow mode).

## IDE Extension Scanner

**Capability classification is heuristic.**  False positives are possible on complex
extensions with unconventional manifests.  The `filesystem`, `network`, `terminal`,
`authentication`, `debuggers`, and `ai_related` capability tags are inferred from
keywords, description text, contributes keys, and activation events in `package.json`.
Runtime behaviour (JS bundle analysis) is not examined.

**Version matching uses simplified prefix comparison, not full semver ranges.**
The `check_known_vulns()` function handles `"*"` (any version) and `"<X.Y.Z"` (integer
tuple comparison only).  Ranges like `">=1.0.0 <2.0.0"`, `"^1.0.0"`, `"~1.2.3"`, and
compound expressions are not parsed and will not match.  Track this as a future task if
the vuln registry grows entries with complex version constraints.

**Discovery paths are hardcoded per-client and may not cover all configurations.**
The paths in `EXTENSION_PATHS` were validated on macOS with VS Code and Cursor; Windsurf
and Augment paths were not found on the build machine.  Paths may differ by:
- OS version (macOS vs Linux vs Windows)
- Client version (path changes between major versions)
- Custom install location (non-default `--extensions-dir`)

**~~Windows extension paths are not validated.~~  Resolved 2026-04-30 (STORY-0004).**
Standard Windows paths are now defined in `_get_windows_paths()` in
`extensions/discovery.py` and merged into `discover_extensions()` at call time:
`%APPDATA%\Code\extensions` and `%APPDATA%\Code - Insiders\extensions` (VS Code),
`%USERPROFILE%\.cursor\extensions` (Cursor), and
`%USERPROFILE%\.windsurf\extensions` (Windsurf).  All four paths are covered by
monkeypatched unit tests that run on every CI platform.  End-to-end validation on a
real Windows host is a manual step deferred to pre-launch.

**No runtime behaviour monitoring.**  The scanner analyses static manifest data only.
Malicious extensions that hide capabilities inside their JS bundle (e.g. deferred
imports, obfuscated network calls) will not be detected by this approach.

**Fleet extension inventory via `merge` not yet implemented.**  The `fleet_extensions`
feature key is reserved but `mcp-audit merge` does not yet aggregate extension findings
across machines (Enterprise, post-launch roadmap).

## Missing capabilities (not started)

- **Multi-arch binary CI release matrix** — GitHub Actions matrix builds for `[macos-13 (x86_64), macos-14 (arm64), ubuntu-latest, windows-latest]` not yet set up
- **pip packaging and TestPyPI dry run** — installable from source only (PyInstaller binary available as alternative; `pip install mcp-audit` used in the action but not yet on PyPI)
- **Documentation beyond README** — no usage guide, Nucleus integration guide (scoring, registry, and rule-writing docs now exist in `docs/`)
- **Telemetry or usage analytics** — deliberately absent; see `docs/telemetry.md`.
- **Registry auto-growth** — the known-server registry requires manual contributions as the MCP ecosystem grows; `update-registry` pulls the latest committed version but does not discover new servers automatically

## Security limitations

Identified during the pre-launch security hardening pass (2026-04-17). Unfixed
limitations are documented here; fixed items are in "Recently resolved" above.

**B310 (`urllib.request` URL open) — three intentional Bandit suppressions (2026-04-17).**
Bandit flags all `urllib.request.urlretrieve` / `urlopen` calls with B310 because
they could in theory allow `file://` or custom scheme URLs. All three call sites in
this codebase are false positives: the URLs are either a hardcoded `https://` constant
(`_UPDATE_REGISTRY_URL` in `cli.py`) or produced by internal resolver functions that
always return `https://` scheme strings (`resolve_npm_tarball_url`,
`resolve_pip_tarball_url`). The `compute_hash_from_url` function additionally enforces
an explicit scheme guard (`if not url.startswith("https://"): raise ValueError(…)`)
as defense-in-depth before calling `urlretrieve`. Each suppression uses
`# nosec B310` with an inline one-line justification. No blanket `# nosec` without a
rule ID exists anywhere in the codebase.

~~**`save_license()` creates the config directory without explicit mode=0o700.**~~
Resolved in v0.2.0 by removing `licensing.py` entirely along with the
module refactor.

**`update-registry` directory `mkdir()` mode caveat.**
Prior to 2026-04-17, `cli.py update_registry` created `~/.config/mcp-audit/registry/`
without an explicit `mode=0o700`. This has been fixed: the directory is now
created with `mode=0o700` and the file written via `os.open(..., 0o600)`.

**TOCTOU in baseline `load()` and `export()`.**
Both methods call `path.exists()` and then `path.read_text()` as separate
operations. A race window exists between the check and the read. This is
inherent to the check-then-act pattern; the practical risk is low because the
storage directory is `0o700` (only the owning user can write to it). Using
`try: open(path)` / `except FileNotFoundError` would eliminate the race but
requires restructuring the error messages; deferred to a future refactor.

**Regex backtracking on adversarial tool descriptions — RESOLVED (2026-04-23).**
All 12 compiled patterns in `poisoning.py` were benchmarked against a
50 000-character adversarial string (`"a" * 50_000 + "!"`).  Max observed
match time: 2.5 ms (pattern 1).  No pattern exceeded 3 ms — no ReDoS risk.
Result documented in the module-level docstring of `poisoning.py`.

## Self-scan results (2026-04-23)

Results of running mcp-audit's own analysis pipeline against its own source,
as required before PyPI publication.

### `mcp-audit sast src/`
Semgrep is not installed in the local dev environment; SAST self-scan could
not be run.  The 37 bundled rules ship in the wheel and are exercised by CI
on every PR via the GitHub Actions workflow.  Manual SAST self-scan deferred
until Semgrep is available in the environment (`pip install semgrep`).

### `mcp-audit scan --check-vulns`
One finding: `rug_pull / claude-desktop/filesystem` (INFO severity).
**False positive** — rug-pull state file records a local "filesystem" server
that existed in a previous scan session on this machine and has since been
removed from the developer's Claude Desktop config.  This is expected
development-machine noise; the finding does not reflect a vulnerability in
mcp-audit itself.  Grade: A (100/100).

### `pip-audit`
Zero findings (run via `uv tool run pip-audit`).

### `bandit -r src/ -ll`
Zero medium+ findings after adding `# nosec B310` to five new `urlopen` call
sites in `attestation/sigstore_client.py`, `vulnerability/depsdev.py`,
`vulnerability/osv.py`, and `vulnerability/resolver.py` (all call HTTPS-only
hardcoded URLs), and `# nosec B104` to the wildcard-bind detection constant
in `analyzers/transport.py`.
