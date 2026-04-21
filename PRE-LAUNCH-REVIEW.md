# mcp-audit — Pre-Launch Architecture, Code-Quality, and Documentation Review

**Review date:** 2026-04-17
**Target release:** public launch, August 2026 (DEF CON / BSides Las Vegas)
**Scope:** scanner orchestration, analyzer abstraction, Pro gating, registry
resolution, state management, CLI entry point, output formatters, test
fixtures, `README.md`, `CHANGELOG.md`, `GAPS.md`, `CONTRIBUTING.md`, and
selected files under `docs/`.

Findings already acknowledged in `GAPS.md` (V-07 … V-17, TOCTOU on baseline,
Unicode homoglyphs, `_PUBLIC_KEY_BYTES` placeholder, `licensing.py` directory
mode, Levenshtein short-name false positives, etc.) are **not repeated** here.

Bar applied: "would a security engineer trust this code." Findings are not
softened.

---

## 1. Architecture Findings

| Severity | File:Line | Issue | Recommendation |
|---|---|---|---|
| High | `src/mcp_audit/scanner.py:139-282` and `:285-402` | `run_scan_async` and `run_scan` duplicate the entire static-analysis pipeline (per-server loop, rug-pull, toxic flow, attack-path summary, rule engine, scoring, registry stats). A change in one path will silently diverge from the other. The documented pipeline order is enforced *twice* with no shared abstraction, and a future 7th analyzer has to be added in two places. | Extract a `_run_static_pipeline(all_servers, configs, …) -> ScanResult` helper and call it from both `run_scan_async` (before live enumeration) and `run_scan` (only path). |
| High | `src/mcp_audit/sast/runner.py:49-73` and `src/mcp_audit/sast/bundler.py:9-20` | `find_rules_dir()` resolution chain is `repo root → _MEIPASS → executable-adjacent`. It is missing the `importlib.resources` step used everywhere else (`registry/loader.py`, `rules/engine.py`). `pyproject.toml:75` ships `semgrep-rules/` inside the wheel at `mcp_audit/semgrep-rules`, but nothing in the runtime looks there — so `mcp-audit scan --sast` **will silently fail on any plain `pip install mcp-audit`**, reporting `"semgrep-rules/ directory not found"`. Dev-editable installs hide this because the repo-root fallback succeeds. | Add an `importlib.resources.files("mcp_audit").joinpath("semgrep-rules")` branch mirroring `_resolve_bundled_community_dir()`. Add a CI test that installs the built wheel into a clean venv and runs `mcp-audit sast demo/`. |
| High | `src/mcp_audit/analyzers/toxic_flow.py:72-106` | `KNOWN_SERVERS` hard-codes 14 MCP package → capability mappings inside the analyzer. The registry refactor (`registry/known-servers.json`, 57 entries) was supposed to be the single source of truth for "known legitimate MCP servers" (per CLAUDE.md). `toxic_flow` and `supply_chain` now have diverging notions of "known" — adding a server to the registry does **not** give it capability tags, so toxic-flow detection degrades to keyword matching for new registry entries. | Move capability tags into `RegistryEntry.capabilities: list[str] \| None` and have `tag_server()` query the registry first, keywords second. Keep keyword rules as fallback for unknown packages. |
| Medium | `src/mcp_audit/cli.py` (entire file, 2,405 lines) | The Typer app is a god object: per-subcommand validation, license gating, formatter dispatch, governance evaluation, baseline drift, hash verification, and SAST/extension orchestration all live in one file. Extending any subcommand requires scrolling past 15 others. Test coverage is hard to reason about at this size. | Split into `cli/scan.py`, `cli/baseline.py`, `cli/rule.py`, `cli/policy.py`, `cli/extensions.py`, `cli/license.py`, etc. Each module registers its commands with the shared `app`. No logic change — pure decomposition. |
| Medium | `src/mcp_audit/analyzers/rug_pull.py:31` | `_STATE_DIR = Path.home() / ".mcp-audit"` is the only persisted-state location that does **not** use `platformdirs.user_config_dir("mcp-audit")`. Baselines, registry cache, policy, and rules all migrated; rug-pull state was missed. On Windows this creates `C:\Users\<u>\.mcp-audit\` instead of `%APPDATA%\mcp-audit\`; on XDG-respecting Linux distros it bypasses `$XDG_CONFIG_HOME`. Also diverges from the CLAUDE.md claim that "All other config paths … now use `platformdirs`". | Migrate `_STATE_DIR` to `Path(user_config_dir("mcp-audit")) / "state"`. Add a one-time migration that reads from the old path if present. Update the README claim "State is stored in `~/.mcp-audit/state.json`" accordingly. |
| Medium | `src/mcp_audit/cli.py:301-307`, `:282-299`, `:399-420`, `:422-441` | Pro gating for `--rules-dir`, `--sast`, and `--include-extensions` is implemented as *soft* gates (print a warning and continue) inside the `scan` command. This is correct per the "gate at output layer" rule, but the gate decision happens **before** `run_scan` for rules and **after** `run_scan` for SAST/extensions, with no shared helper. A future contributor will have to re-derive the pattern for each new Pro feature. | Introduce `gate("feature", console, message=…) -> bool` helper that prints the yellow Pro panel and returns False when unlicensed. Call sites become one-liners and the policy is consistent. |
| Medium | `src/mcp_audit/cli.py:143-144` | The `--ci` flag is declared on `scan` but **never referenced in the function body**. `README.md:83, :193` still advertise `mcp-audit scan --ci --severity-threshold HIGH` as if it did something distinct from `--severity-threshold`. This is a dead flag surfacing in user-facing docs. | Either (a) delete the flag and update the README, or (b) make `--ci` imply `--severity-threshold high --format terminal --no-score` and a cleaner error-path. Do not ship a public release with a dead user-visible flag. |
| Medium | `src/mcp_audit/cli.py:140-142`, `scanner.py:320-321`, `attestation/verifier.py` | `--offline` is accepted and only enforced as a mutual-exclusion check against `--connect`. `--verify-hashes` makes HTTPS requests to `registry.npmjs.org` and `pypi.org`, but passing `--offline --verify-hashes` does **not** prevent those calls. CLAUDE.md admits `--offline` is a no-op today; that's fine, but the combination `--offline --verify-hashes` should fail fast rather than silently making network calls. | Raise `ValueError("Cannot use --verify-hashes with --offline")` in `scan`, or gate the attestation call with `if offline: skip verify-hashes`. |
| Medium | `src/mcp_audit/cli.py:686-767` (dashboard) | `tempfile.NamedTemporaryFile(delete=False)` is used to persist the HTML dashboard to disk. On macOS/Linux it lands in `/tmp` (or `TMPDIR`) with default file permissions (typically world-readable in `/tmp`). The file contains every finding and server name from the scan. On shared hosts this exposes scan content to any local user. The file exists for the full dashboard lifetime (potentially days if left running). | Create the file with `os.open(..., O_CREAT\|O_WRONLY\|O_EXCL, 0o600)`, or skip the disk copy entirely — the HTTP server already serves `html_bytes` from memory. |
| Low | `src/mcp_audit/registry/loader.py:6-12` vs. `_resolve_bundled_path` | Module-level docstring lists resolution order as `(1) path → (2) user cache → (3) importlib.resources → (4) _MEIPASS`, but the code tries `_MEIPASS` first, then `importlib.resources`, then repo-root fallback. CLAUDE.md uses yet a third ordering. The three should agree. | Rewrite the module docstring to match the code exactly (and to match `_resolve_bundled_community_dir` in `rules/engine.py`). Do the same for CLAUDE.md. |
| Low | `src/mcp_audit/analyzers/base.py` and scanner | `BaseAnalyzer.analyze()` is the "per-server" contract, but `RugPullAnalyzer`, `ToxicFlowAnalyzer`, and (conceptually) `attack_paths` need the full server list. Today they hand-roll no-op `analyze()`s and a separate `analyze_all()` method that the scanner has to know about by name. A contributor looking only at `base.py` would not discover this protocol. | Add `BaseAnalyzer.analyze_all(servers) -> list[Finding]` with a default implementation that calls `analyze()` per-server and unions results. Cross-server analyzers override. The scanner then uniformly calls `analyzer.analyze_all(all_servers)` and the weird no-op `analyze()` stubs disappear. |
| Low | `src/mcp_audit/analyzers/attack_paths.py` | Not a `BaseAnalyzer` subclass — invoked as a module-level `summarize_attack_paths()`. Documented in CLAUDE.md, but it means attack-path coverage cannot be disabled through the same "custom analyzer list" injection path the CLI uses for `--registry`/`--offline-registry`. If a contributor later wants to disable it for fleet scans, they'll have to edit `scanner.py`. | Optional — wrap `summarize_attack_paths` in a thin `AttackPathAnalyzer(BaseAnalyzer)` that implements `analyze_all()`. Consistent interface at zero runtime cost. |

---

## 2. Code Quality Findings

| Severity | File:Line | Issue | Recommendation |
|---|---|---|---|
| High | `tests/conftest.py:18-36` | The session-scoped autouse fixture **permanently** patches `is_pro_feature_available` to `True` inside `output.dashboard` and `output.nucleus` for every test in the suite. Every test that imports from those modules runs through the Pro-enabled code path. This gives **false confidence that gating works**: no test in the default run will ever hit `_console.print(Panel("…requires Enterprise"))` unless it explicitly re-patches. Combined with the fact that `is_pro_feature_available` in `cli.py` is *not* patched, there is effectively no integration-level test that "dashboard formatter prints the Pro upsell panel when no license". | Narrow the autouse fixture to an opt-in marker (e.g. `@pytest.fixture` that tests request explicitly), and add positive-and-negative integration tests: `test_dashboard_shows_upsell_without_license` that patches the gate to `False` and asserts the panel is rendered and `None` is returned; `test_nucleus_shows_enterprise_upsell_without_license` similarly. |
| High | `src/mcp_audit/cli.py:455-460` | Severity filtering happens *after* the score is calculated (`scanner.py:277, :397`) but the filtered list replaces `result.findings`. The score was computed from the *unfiltered* findings — defensible — but `result.has_findings` (line 499) and exit-code logic operate on the *filtered* list. A user running `--severity-threshold high` on a scan that has only MEDIUM findings gets a grade of `C` in JSON/SARIF output while exit code is `0` — the grade reflects issues the tool then claims don't exist. | Document this explicitly in `docs/scoring.md`, *or* recompute the score after filtering. Current behaviour is surprising enough that a security engineer will call it out at DEF CON. |
| Medium | `src/mcp_audit/scoring.py:93, :112` | `analyzer_names = {f.analyzer for f in findings}` is computed and then discarded (`_ = analyzer_names`). The comment `# referenced only to avoid unused-import warnings` is misleading — there is no import involved. Dead set construction on a potentially large finding list on every scan. | Delete lines 93 and 112. |
| Medium | `src/mcp_audit/licensing.py:149-157, :186-205` | `is_pro_feature_available()` calls `get_active_license()` (reads and cryptographically verifies the license file) on **every** call. `cli.py` calls it 12+ times per `scan` invocation. Each call re-reads `~/.config/mcp-audit/license.key` and performs Ed25519 verification. Not a security issue, but a lot of I/O + crypto for a privacy-first CLI that markets itself as offline. | Cache the `LicenseInfo` for the lifetime of the process (`functools.lru_cache(maxsize=1)` on `get_active_license()`). `licensing.py` is marked do-not-modify; add a thin cache in `cli.py` or a new `_license_cache.py` shim. |
| Medium | `src/mcp_audit/output/dashboard.py:198` (HTML template) | `@import url('https://fonts.googleapis.com/css2?family=DM+Sans…');` inside the embedded CSS pulls fonts from Google's CDN. The README explicitly promises "fully self-contained HTML — no CDN, no external dependencies". Opening the dashboard HTML while offline silently falls back to system fonts, but a user opening it on a restricted corporate network has just emitted DNS + TLS requests to Google, defeating the "privacy-first, offline" framing. | Bundle the font files (DM Sans + JetBrains Mono) via base64-encoded `@font-face` declarations, or drop the Google Fonts import and fall back to `system-ui`/`JetBrains-Mono-fallback`. |
| Medium | `src/mcp_audit/cli.py:686` (dashboard command) | The `dashboard` command does not check `is_pro_feature_available("dashboard")` itself — it runs a full scan (potentially 5+ seconds on a large machine), generates HTML, starts an HTTP server, and only *then* the embedded gate inside `generate_html()` returns `None`, after which `dashboard` exits cleanly. Users without a license pay the full scan cost to be shown an upsell. Architecturally this also violates the spirit of "gating at output layer" — the scan itself is fine, but starting `tempfile`+`HTTPServer`+`webbrowser` for a gated feature is wasteful. | Move the `is_pro_feature_available("dashboard")` check to the top of the command, short-circuit with the Pro panel, and skip `run_scan`. |
| Medium | `src/mcp_audit/extensions/analyzer.py:27-50` vs. `registry/loader.py:36-65` | Two registry resolvers (`_resolve_vuln_registry_path`, `_resolve_bundled_path`) are near-identical 25-line copies. Bugs fixed in one (e.g. the wheel-path divergence) will not land in the other. | Extract `_resolve_bundled_resource(package, filename, dev_subdir)` helper into `_paths.py`. Use it in both modules and in `rules/engine.py`. Also enables the `sast/runner.py` fix above. |
| Medium | `src/mcp_audit/watcher.py:117-120` + `cli.py` watch command | `_McpConfigEventHandler._fire` releases the lock before invoking the user callback. If two config files are saved within the debounce window and the callback kicks off a scan that takes longer than the next debounce, multiple `run_scan` calls may execute concurrently and race on `~/.mcp-audit/state_<hash>.json` (both reading the file, both writing their new baseline). `save_state` is write-once-then-chmod, so the later writer wins silently — the earlier writer's rug-pull results are discarded. | Serialise callback execution behind a threading lock in the watch command itself, or debounce at the callback level. A "scan in progress" flag + re-trigger queue is the least invasive fix. |
| Medium | `src/mcp_audit/cli.py:306` (scan) vs `:712` (dashboard) vs `:1483-1489` (rule test) | The scan command honours `rules_dir` and `_USER_RULES_DIR` (Pro user-local rules), but the `dashboard` and `watch` commands do not. A user with Pro custom rules that produce a CRITICAL finding will see it in `mcp-audit scan` but not in `mcp-audit dashboard` or `mcp-audit watch`. | Plumb `rules_dir` and `_USER_RULES_DIR` gating into `dashboard` and `watch` via the same helper call path used by `scan`. |
| Medium | `src/mcp_audit/sast/runner.py:196` | `raw_severity: str = extra.get("severity", "WARNING").upper()` — if the semgrep JSON payload contains `"severity": null` (valid JSON), `.upper()` on `None` raises `AttributeError` inside `parse_semgrep_output`, which is called inside `run_semgrep` but *not* wrapped in a `try/except` — the exception propagates up and crashes the entire `scan --sast` invocation. | `raw_severity = (extra.get("severity") or "WARNING").upper()`. |
| Low | `src/mcp_audit/licensing.py:139` | `is_valid = date.today() <= expires` uses the local machine's date. A traveller whose laptop is set to UTC+14 will see the license expire 14 hours earlier than a US customer with the same key. `date.today()` returns a naive date with no timezone reference. | Use `datetime.now(UTC).date()` for consistent global expiry. (Known do-not-modify; flagged for the next licensing refactor.) |
| Low | `src/mcp_audit/registry/loader.py:53`, `extensions/analyzer.py:39`, `rules/engine.py:480` | `Path(str(pkg_resources.files(pkg).joinpath(name)))` is the Python 3.9-era idiom for `importlib.resources`. In Python 3.12+ this still works for wheel-installed packages, but for `zipimport` / future zipapp distribution it silently fails because `MultiplexedPath` cannot be stringified to a real filesystem path. The project already requires Python 3.11+. | Use the documented pattern: `with importlib.resources.as_file(ref) as path: …`. Capture the path once at module load. |
| Low | `src/mcp_audit/analyzers/supply_chain.py`, `registry/loader.py:271-301` | Two separate Levenshtein implementations — one in `registry/loader.py`, one re-implemented inline in `supply_chain.py` (per the registry/loader.py comment: "Same algorithm as in `mcp_audit.analyzers.supply_chain`"). Duplication was acceptable during the registry migration; no longer. | Delete the copy in `supply_chain.py` and import `from mcp_audit.registry.loader import levenshtein`. |
| Low | `src/mcp_audit/baselines/manager.py:243` | `except Exception as exc: warnings.warn(...)` for malformed baseline files writes via `warnings` — which depending on `-W` flags may be suppressed entirely. For a security-tool baseline drift feature, silently skipping a corrupted baseline is the wrong default: users expect to be told when their baseline cannot be parsed. | Replace `warnings.warn` with `logger.warning(...)` and print via Rich at the CLI layer when the user explicitly invokes `baseline list`. Add a Finding-type output if encountered during `scan --baseline`. |
| Low | `src/mcp_audit/cli.py:40` | `_UPDATE_REGISTRY_URL = "https://raw.githubusercontent.com/adudley78/mcp-audit/main/registry/known-servers.json"` is hardcoded to `main`. Once tags exist, a user running an old binary against the registry from `main` can get a registry schema mismatch. | Point `_UPDATE_REGISTRY_URL` at a stable branch or at the current release tag via `__version__`. Add a schema-version compatibility check on the fetched JSON. |
| Info | `src/mcp_audit/cli.py:117-122` | The `--format` flag description does not include `html` even though `dashboard` generates HTML via `generate_html`. Users occasionally expect `scan --format html -o report.html`; today that produces `Unknown format`. | Either wire `"html"` through to `generate_html` (with Pro gating), or document in the help text that HTML is only available via `dashboard`. |

---

## 3. Documentation Findings

| Severity | File:Line | Issue | Recommendation |
|---|---|---|---|
| High | `README.md:208, :369` | Advertises "845 tests validate detection accuracy" and `uv run pytest # Run all 845 tests`. CLAUDE.md states the current count is **1,077** tests. The README undersells the project on the front page that every DEF CON reviewer will open. | Replace both 845 references with the current count, or better, drive the number from a `uv run pytest --collect-only -q \| tail -1` snippet in CI that updates the README. |
| High | `README.md:212-234` (CLI reference table) | The CLI reference omits `policy`, `extensions discover / scan`, `sast`, and `verify`. These are four of the seven sub-apps shipped today. A reader of just the README would not know SAST, governance, attestation, or extension scanning exist. | Add rows for `mcp-audit policy validate/init/check`, `mcp-audit extensions discover/scan`, `mcp-audit sast`, and `mcp-audit verify`. Mark the Pro/Enterprise ones. |
| High | `README.md:36-47` (Community vs Pro table) | The tier table does not reflect the feature matrix in `licensing.py:_FEATURE_TIERS`. Missing entries: custom rules directory (Pro), `update-registry` (Pro), SAST integration (Pro), extension scanner (Pro), governance engine (Pro), fleet merge (Enterprise), fleet governance (Enterprise), fleet extensions (Enterprise). Pre-launch buyers cannot tell what they're actually paying for. | Regenerate the Community/Pro/Enterprise table from `_FEATURE_TIERS`. Keep one authoritative source — either a script that renders the markdown, or a docstring test that asserts the README matches the feature map. |
| Medium | `README.md:184` | "State is stored in `~/.mcp-audit/state.json`." Misleading on two counts: (a) rug-pull state is scoped per config-set (`state_<hash>.json`), not a single file; (b) every *other* persistent state (baselines, registry cache, policy, rules, license) uses `platformdirs.user_config_dir("mcp-audit")` which is `~/.config/mcp-audit/` on Linux and `~/Library/Application Support/mcp-audit/` on macOS. | Rewrite as: "Rug-pull state is stored per-config-set at `~/.mcp-audit/state_<hash>.json`. All other state (baselines, registry cache, policy, rules, license) is stored in the platform user-config directory resolved via `platformdirs`." |
| Medium | `CHANGELOG.md:93` | Prototype entry lists "Cline, Zed" as supported MCP clients. The actual 8 clients in `discovery.py` are Claude Desktop, Cursor, VS Code, Windsurf, Claude Code (user), Claude Code (project), GitHub Copilot CLI, Augment Code. Cline/Zed were never shipped. | Correct the bullet to the real 8-client list. |
| Medium | `CHANGELOG.md:1-14` | Follows "Keep a Changelog" format but no version number exists anywhere. Entries sit under "Pre-release — Security Hardening & CI / Moat Deepening / Chain Reaction / Prototype". Keep-a-Changelog requires versioned sections with dates. For a pre-launch tool the `[Unreleased]` block is correct, but the four milestone sections should be demoted into `[Unreleased]` or given provisional version numbers (`[0.0.4 — 2026-04-17]` etc.) before tagging. | Before cutting the first public tag, consolidate milestone sections into `[0.1.0] - 2026-MM-DD` with Added/Changed/Fixed/Security subsections. |
| Medium | `CONTRIBUTING.md` (all 64 lines) | First-time contributors asking "how do I add an analyzer?" get a one-line answer: "Analyzers inherit from `BaseAnalyzer` and implement `analyze()`". No mention of: (a) the `analyze_all()` exception for cross-server analyzers, (b) how the analyzer is registered in `scanner.get_default_analyzers()`, (c) that findings need CWE and a `finding_path`, (d) where to add provenance (`PROVENANCE.md`), (e) severity assignment conventions, (f) that tests are per-module and should cover the crash path (`_analyzer_crash_finding`). | Add a 40-line "Adding a new analyzer" walk-through that references a minimal example (e.g. the `transport` analyzer). Mention the `analyze_all()` convention explicitly. |
| Medium | `docs/governance.md` | The `--policy` free vs `policy init/check` Pro split is documented in CLAUDE.md but the invocation order (cwd → git root → user config dir) is documented differently in `governance/loader.py` docstring (which adds `.mcp-audit-policy.yml/.yaml/yml` file matrix) than what a user sees. | Cross-check `docs/governance.md` against `governance/loader.py:_load_from_path` and `POLICY_FILENAMES` and unify the resolution-order description in exactly one place. |
| Low | `docs/sast-rules.md` | CLAUDE.md states `semgrep-rules/` ships in pip wheel and PyInstaller binary. As the SAST-runner finding above shows, the wheel path is not actually discovered at runtime. The doc will tell Pro users "SAST just works after `pip install`" — they will bounce with `semgrep-rules/ directory not found`. | After the `find_rules_dir` fix lands, the doc can stay. Until then, add a temporary "Known issue" note advising editable install (`pip install -e .`) or PyInstaller binary for SAST. |
| Low | `README.md:101-110` table "What it detects" | "Tool poisoning — POISON-001…050" and "Credential exposure — CRED-001…009" imply broad pattern coverage. Actual coverage per `PROVENANCE.md` / `GAPS.md` is 14 poisoning patterns and 9 credential patterns. The ID-range notation will mislead reviewers into thinking the catalogue is 50× bigger than it is. | Replace ranges with current counts: "14 patterns" / "9 patterns". GAPS.md is already honest about this; the README should match. |
| Low | `CLAUDE.md` "Current phase" bullet list | Claims "1077 tests passing" and "18 top-level CLI commands" — specifically 18 is inaccurate: counting from `app.command()` decorators in `cli.py` plus sub-apps (`baseline`, `rule`, `policy`, `extensions`) plus their sub-commands gives a different number. | Drive both counts from a CI script rather than maintaining them by hand. |
| Low | `README.md:111-117` toxic pair table | Lists TOXIC-001 through TOXIC-007 but does not mention that a single server holding both capabilities is also flagged. CLAUDE.md and `toxic_flow.py` handle self-pairs, but a practitioner reading the README would not know. | Add a footnote under the toxic-pair table explaining self-pair detection (already stated lower in the same section, but the table is what most readers will scan). |
| Info | `docs/` folder | 15 Markdown files at `docs/` with no `docs/README.md` or TOC. Users landing in the folder from a GitHub link must guess which file to open. | Add `docs/README.md` with a one-line description per file (mirrors the CLAUDE.md layout block). |

---

## Top 5 Highest-Priority Issues (fix before public launch)

1. **SAST silently broken on pip-installed wheels** — `find_rules_dir()` is
   missing the `importlib.resources` branch, so `mcp-audit sast`,
   `mcp-audit scan --sast`, and the GitHub Action's `sast: true` input will
   all fail for any user who installs via pip (the primary distribution
   channel). Dev-editable installs hide this because the repo-root fallback
   succeeds. A Pro customer who pays for SAST and runs `pip install mcp-audit`
   gets a broken feature. **Add a wheel-path branch and a CI test that
   installs the built wheel and exercises `--sast` end-to-end.**

2. **README misrepresents the product.** 845-test count (actual: 1,077), tier
   matrix missing six features (custom rules, SAST, extensions, governance,
   update-registry, fleet merge, fleet governance, fleet extensions), CLI
   reference omits four sub-apps, and the `--ci` flag it advertises is a no-op
   in the code. The README is the first thing a DEF CON attendee reads; today
   it understates the feature set *and* documents a dead flag. **Sync README
   against `_FEATURE_TIERS`, `cli.py`, and the real test count before any
   conference submission.**

3. **Analyzer-vs-registry inconsistency in toxic flow.**
   `toxic_flow.KNOWN_SERVERS` is a hardcoded 14-entry map that ignores the
   57-entry `registry/known-servers.json`. Adding a server to the registry
   doesn't add capability tags — so new registry entries silently regress to
   keyword-only tagging and may miss self-pair toxic flows. **Move capability
   tags into `RegistryEntry.capabilities` and have `tag_server()` consult the
   registry first.**

4. **`conftest.py` autouse fixture hides gating regressions.** The
   session-scoped patch of `is_pro_feature_available → True` in output
   modules means a contributor who accidentally removes the Pro gate from
   `nucleus.py` or `dashboard.py` will see every test pass. For a tool whose
   commercial model depends on that gate, no negative test for it exists in
   the default run. **Narrow the fixture to opt-in and add positive-negative
   gate tests.**

5. **Massive duplication between `run_scan_async` and `run_scan`.** The static
   pipeline (analyzers → rug-pull → toxic flow → attack paths → rules →
   scoring → registry stats) is implemented twice. A future 7th analyzer must
   be added in both or one path will lag. The CLI calls `run_scan` directly;
   the `--connect` path runs the async version. **Extract a single
   `_run_static_pipeline` and delegate from both.** This is also the single
   biggest maintainability win in the codebase.

---

## What's solid

- **Path-resolution security.** `BaselineManager._safe_baseline_path` is a
  textbook implementation (rejects separators, `.`, `..`, and confirms
  resolved path stays under the storage root). `update-registry` correctly
  writes via `os.open(..., 0o600)` after `mkdir(0o700)`. Baseline storage,
  rug-pull state, and registry cache all hit the documented `0o700`/`0o600`
  targets. The `# nosec B310` suppressions in `attestation/hasher.py` and
  `cli.py` each carry an inline justification — no blanket suppressions.
- **Subprocess hygiene.** `sast/runner.py` uses list-form `subprocess.run`,
  captures stderr, enforces a `SEMGREP_TIMEOUT_SECONDS = 300` constant, and
  catches `TimeoutExpired`. The `semgrep` binary is resolved via
  `shutil.which`, not from a user-controlled env var.
- **Registry injection for tests.**
  `SupplyChainAnalyzer.__init__(registry=…, registry_path=…)` cleanly
  decouples analyzer logic from filesystem resolution. This pattern should be
  the template when the 7th analyzer lands.
- **Pipeline order enforcement.** Inside `scanner.run_scan`, the documented
  order `analyzers → rug-pull → toxic-flow → attack paths → rule engine →
  scoring → registry stats` is followed in source order. The baseline drift /
  governance / SAST / extensions additions happen in `cli.py` *after*
  `run_scan` returns — the right layer, because they must observe the
  completed `ScanScore` (governance score thresholds depend on it).
- **SARIF 2.1.0 output.** Deduplicated rule index, optional `run.properties`
  score block, per-analyzer tag mapping, correct CWE tag format, proper
  `file://` URIs. Will round-trip cleanly through GitHub's SARIF ingest once
  tested.
- **Scoring is bounded and deterministic.** `calculate_score` is
  side-effect-free, deductions are named and explained in output, positive
  signals are capped at +10, final value clamped 0–100. The CLI's
  `--no-score` correctly nulls `result.score` after scoring and before any
  formatter runs (resolving the SARIF leak that was in GAPS.md).
- **Rug-pull state hashing scopes per config set.** `derive_state_path`
  prevents demo configs and real-machine configs from cross-contaminating the
  baseline — a subtle but important property for a stateful detector.
- **`GAPS.md` is exceptionally honest.** Severity calibration, detection
  coverage, platform gaps, toxic-flow heuristics, licensing placeholder,
  TOCTOU acknowledgements, regex backtracking — all surfaced. This is the
  document a senior security engineer wants to see. Keep curating it; it is
  doing a lot of trust-building work.

---

*Reviewer's overall read: the engineering bar is high, the security posture
for a pre-launch prototype is already above many shipped security tools, and
the "npm audit for MCP" framing is defensible. The five items above are the
difference between "impressive prototype" and "production-grade OSS security
tool" at August launch.*
