# Credenzo (formerly mcp-audit)

An open-source, privacy-first CLI tool that scans MCP (Model Context Protocol)
server configurations for security vulnerabilities. Think "Snyk for MCP servers."

## Names (0.33.0 rename)

The product is **Credenzo** and the command is `credenzo`. Use those in every
text a person reads: help text, reports, messages, documentation, examples.

These keep the old name on purpose. Do not rename them without a migration:

- The `mcp-audit` command (same entry point; `_entry._old_name_notice` prints one
  stderr line in a terminal, never in CI, a pipe, or `run`).
- The distribution that holds the code, `mcp-audit-scanner`. The `credenzo`
  distribution (`packaging/credenzo/`) holds no code: it pins the same version,
  forwards the extras and declares the `credenzo` command
  (`tests/test_credenzo_package.py`). Publish it with
  `publish-credenzo-name.yml` after each release.
- The import package `mcp_audit`, the release binary names
  (`mcp-audit-<os>-<arch>`), the spec files.
- The repository is `adudley78/credenzo` (renamed 2026-11-16; GitHub redirects
  the old name). URLs use the new name. `setup-action` accepts a binary signed
  under either name. Never create a repository named `mcp-audit`: that ends
  the redirects.
- Machine contracts: exact `"mcp-audit"` literals (platformdirs directory, SARIF
  tool name, CycloneDX/OpenVEX/Nucleus tool names, `_producer`), lock
  `generated_by`, `mcp-audit/…` and `mcp-audit:` property keys, the
  code-scanning category, `.mcp-audit-policy.yml`, `mcp-audit-feed.pub`, the
  `mcp-audit.dev` API host, `MCP_AUDIT_*` environment variables.
- A wrapped config entry may launch `mcp-audit run` (written before 0.33.0) or
  `credenzo run`; `runtime/wrapping._WRAPPER_NAME` accepts both.
- Pre-commit hook ids `mcp-audit` and `mcp-audit-lock-verify` stay beside
  `credenzo` and `credenzo-lock-verify`; the setup action puts both command
  names on PATH and keeps the `mcp-audit-version` output.

## What this project does

Developers use MCP servers to give AI agents (Claude, Cursor, VS Code Copilot) access
to tools — file systems, databases, APIs, etc. These servers are configured via JSON
files and can be poisoned, misconfigured, or compromised. Credenzo scans those configs
and flags security issues.

## Business model

The `credenzo` command is fully open source under Apache 2.0 — every command and
every check is free for every user. There is no Community / Pro / Enterprise
split and no license-key gate in the package. All paid-license plumbing (Ed25519
signing, revocation lists, `activate` / `license` commands, the `gate()` shim)
was removed in v0.2.0; anything that still references `licensing.py` or
`_gate.py` is stale.

There is one paid offer, beside the package and not in it: **Credenzo Team**
(`team/`, `docs/team.md`, added 2026-11-20). It is a GitHub Action that runs
`credenzo lock --verify` and sends drift alerts (an issue, a webhook message).
The check itself is the free command and always runs. Alerts are free for
personal accounts and public repositories, and $99 a month (up to 10 seats) for
the private repositories of an organization. Rules that keep it honest:

- `team/` is never imported by `src/mcp_audit` and never ships in the wheel or
  the binary (`tests/test_team_action.py::test_the_team_code_is_not_in_the_package`).
  Do not put a licence check in the package.
- `team/credenzo_team.py` and `scripts/team_licenses.py` use the standard
  library only. The action sends nothing to the project (no usage report);
  `docs/telemetry.md` still holds.
- A subscription is found by GitHub owner name in the public licence list on
  the `team-licenses` branch, which `.github/workflows/team-licenses.yml`
  builds from Stripe twice an hour. The list holds digests and fillers, never a
  name, an email address, a Stripe ID or a count; neither job prints one. When
  the list cannot be read, alerts stay on.
- The offer (price, checkout link, the date the experiment started) is
  `team/offer.json`; `scripts/team_go_live.py` writes it and the "Subscribe"
  block of `docs/team.md`. `scripts/paid_path_report.py` prints the weekly
  public numbers and applies the continue/stop rule that was set before the
  experiment (10 customers or $1k MRR to continue; under 3 customers or $300
  MRR after 90 days to stop).

Funding is also requested via GitHub Sponsors (handle configured in
`.github/FUNDING.yml`, with a "Support" section in `README.md`).

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
│   │                    #   `_scoped_state_path`).  The
│   │                    #   `scan` command is composed from `_apply_*` pipeline
│   │                    #   stages (baseline drift, governance, SAST, extensions,
│   │                    #   agent-files, severity filter) and `_write_*` output
│   │                    #   helpers — see "scan() pipeline conventions" below.
│   ├── check.py         # check command: one-page practitioner verdict (+ _write_pdf_report)
│   ├── fix.py           # fix command: apply safe remediations to config files
│   ├── wrap.py          # wrap / unwrap: rewrite local servers in JSON client configs to launch through `credenzo run` (EPIC-0009 Story 1.2); dry run + gate prediction by default, --apply via fixer.write_config_change
│   ├── run.py           # `run` as listed in --help; the console script dispatches it to runtime/ before this app loads
│   ├── guard.py         # `guard` as listed in --help; the console script dispatches it to runtime/guard.py before this app loads (STORY-0176)
│   ├── diff.py          # diff command: MCP-aware diff for PR review / CI gates
│   ├── baseline.py      # baseline sub-app: save / list / compare / delete / export
│   ├── registry.py      # update-registry, verify
│   ├── rules.py         # rule sub-app: validate / test / list
│   ├── policy.py        # policy sub-app: validate / init / check (+ `_POLICY_TEMPLATE`)
│   ├── extensions.py    # extensions sub-app: discover / scan
│   ├── agent_files.py   # agent-files sub-app: discover / scan (skills, memory, hooks)
│   ├── plugins.py       # plugins sub-app: discover / scan (Claude Code plugins, STORY-0080)
│   ├── lock.py          # lock command: write / --verify the committable mcp-lock.json (ADR-0005; --connect tool digests, --save-tool-text)
│   ├── _bundle.py       # shared --bundle / --bundle-key handling for scan and affected (STORY-0129)
│   ├── sast.py          # sast command
│   ├── sbom.py          # sbom command: CycloneDX 1.5 SBOM export
│   ├── affected.py      # affected command: is this advisory (CVE/GHSA/MAL/research ID or pkg@range) in any discovered server; AFFECTED / NOT AFFECTED / COULDN'T CHECK with evidence (STORY-0121, docs/affected.md)
│   ├── reach.py         # reach command: what can the agents on this machine touch? one verdict per agent; --format json, --report pdf, --fleet DIR (STORY-0145, docs/reach.md)
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
├── discovery.py       # Finds MCP config files across all supported clients (Claude Code local scope, STORY-0175: `local_scope_dirs(cwd)` = cwd and parents up to the git root, set as `DiscoveredConfig.local_project_dirs` on `~/.claude.json` in a scan with no explicit path; `config_parser._local_scope_servers` then returns `projects.<dir>.mcpServers` as client `claude-code-local` (`LOCAL_SCOPE_CLIENT`), `ServerConfig.local_project` (never dumped) keys rug-pull records per project; `lock`/`wrap` pass `include_local_scope=False`, `fix` skips them, `reach` counts them through `claude.extra_servers`; `tests/conftest.py` stubs `local_scope_dirs`; Codex: `codex_user_config_path()` honours `CODEX_HOME`; Gemini CLI: `gemini_user_config_path()`; cwd copies as `codex-project`/`gemini-cli-project` via `_harness_cwd_configs`, and the `--project` walk skips the user's own files at `$HOME`, STORY-0110; OpenCode: `opencode_user_config_paths()` = `~/.config/opencode/opencode.json(c)` plus `$OPENCODE_CONFIG` when set (a missing path is dropped silently), cwd `opencode.json(c)` as `opencode-project` (skipped when cwd is `$HOME`), the `--project` walk as plain `opencode`, STORY-0142); `_PROJECT_AUTOEXEC_SPECS` drives the TRUST-003/008 auto-run walk (`--project`) and the TRUST-003/008 cwd-root check of a default scan (skipped when cwd is `$HOME`) (`discover_cwd_autoexec_files`, called from `scanner._cwd_autoexec_findings`); see docs/agent-execution-surface.md
├── config_parser.py   # Parses JSON configs, normalizes across client formats; Codex `config.toml` (tomllib, `[mcp_servers.*]`) and Gemini CLI `settings.json` (comments stripped as Gemini does, `httpUrl`/`type` transport order) and OpenCode `opencode.json(c)` (JSONC: comments plus trailing commas stripped, top-level `mcp`, `type` `local` = `command` argv + `environment`, `remote` = `url` + `headers`; `enabled: false` still analysed; an entry of unknown type or wrong shape goes to `config.parse_warnings`, STORY-0142) via `config_dialect()` / `DiscoveredConfig.dialect`, 4 MiB cap, TOML values made JSON-safe (STORY-0110; docs/clients.md)
├── models.py          # Pydantic models: Finding, ServerConfig, ScanResult, ScanScore, Severity, AttackPath, MachineInfo; Finding.line (1-based, set from an agent-file finding's "Line N:" evidence by a model validator; SARIF region.startLine, STORY-0141)
├── owasp_mcp.py       # Single source of truth for OWASP MCP Top 10 codes/names (MCP01–MCP10)
├── verdict.py         # Pure verdict builder for `vet` (shared with the mcp-audit.dev generator)
├── watcher.py         # Filesystem watcher for continuous monitoring (credenzo watch); _McpConfigEventHandler serialises callbacks via _scan_lock with single-event coalesced re-trigger
├── mcp_client.py      # Live MCP server connection via MCP SDK (--connect); connect_identity(server) = the clientInfo sent in `initialize` (STORY-0177): `--identify-as` (set_connect_identity) wins, a `claude-code*` server gets CLAUDE_CODE_IDENTITY (captured from a live 2.1.328 session), any other client the SDK default `mcp`; bound through `_session_class` (functools.partial), so the transport helpers are unchanged; build_runtime_server_config passes every lock-digested tool field (title, input/output schema, annotations) to the text checks (STORY-0099); a failed stdio handshake keeps the server's stderr (last 64 KiB), unwraps the TaskGroup ExceptionGroup and redacts both (redact_server_text, STORY-0105)
├── _paths.py          # data_dir() and resolve_bundled_resource() — shared helpers for locating bundled data in source, wheel, and PyInstaller frozen contexts
├── _network.py        # NetworkPolicy + require_offline_compatible() — centralised --offline mutual-exclusion enforcement for network-touching flags
├── _entry.py          # Console-script entry: dispatches `run` to runtime/ before the Typer app (and the scanner) is imported (EPIC-0009)
├── _jcs.py            # RFC 8785 canonical JSON (moved from advisory/canonical.py, which re-exports it) so the `run` launch path can digest tools without the advisory package
├── runtime/           # `credenzo run` (EPIC-0009, docs/run.md), stdlib-only on the launch path (tests/test_runtime_entry.py, test_runtime_gate.py pin the imports)
│   ├── cli.py         # argparse for run: --config/--server/--lock/--mode; gate → relay; exit 78 when enforce refuses
│   ├── relay.py       # byte-exact stdio relay; process group, signal forwarding, exit mirroring; monitor taps lines, enforce relays line by line through the ToolGuard
│   ├── gate.py        # launch gate: argv vs the lock entry (LOCK-001/002, RUN-001/002); uses lock/core.py only, redaction on the slow path
│   ├── wrapping.py    # wrapper_trusted(command, root=, recorded=) (STORY-0178): `lock --verify` (verifier._check_drift gets the lock root) reads a wrapped entry as its inner launch only when the wrapper is the running install, or its digest is the lock entry's optional `wrapper` (writer.build_entry, absolute wrapper paths only; never the path), or it is outside the git repository above the lock root with nothing recorded; a bare name is never recorded and is refused when PATH resolves it into the repository; wrap_entry/unwrap_entry (--original-sha256 = RFC 8785 digest of the original entry), inner_launch (config_parser analyses a wrapped entry as its inner server; ServerConfig.wrapped/wrap_mode), WRAPPABLE_CLIENTS, wrap_status; a relative ./mcp-audit is never trusted as the wrapper
│   ├── guard.py       # `credenzo guard` (STORY-0176, docs/guard.md): Claude Code PreToolUse hook, dispatched by _entry.py like `run`; decide(event) denies an MCP call when the server (by `mcp_server.source`: project = <CLAUDE_PROJECT_DIR>/.mcp.json, user = ~/.claude.json; other sources not covered unless --strict) is not in the lock (LOCK-002), its config entry changed (LOCK-001; plain compare, then lock.verifier._check_drift on the slow path; wrapping.wrapper_trusted for a wrapped entry), has no tool record (RUN-003), the tool is not in it (LOCK-006) or the lock is unusable (RUN-002, gate.read_lock); never prints allow; --allow-server/--allow-source never apply to an unlocked project server; names cleaned by shown(); exit 2 on failure in enforce mode; --print-hook; no new finding IDs; tests/test_runtime_guard.py reads locks written by the real `lock --connect`
│   └── tools.py       # ToolGuard: live tools/list vs lock tool digests (LOCK-006..009, RUN-003); enforce withholds added/changed tools and denies their tools/call
├── _redact.py         # Local-path redaction for output that leaves the host (advisory feed, SARIF, Nucleus, snapshot)
├── bundle.py          # Signed air-gapped data bundle (STORY-0129): verify_bundle() checks bundle.json + the feed in a private copy, advances seen.json (0o600) only on success; override() points scan/affected at the bundle's data files
├── gateways.py        # MCP gateway upstreams (STORY-0111): mcptoon, 1MCP and MCPHub.nvim config files read as data, upstream servers join discovery as `<gateway>-upstream`; project files .mcptoon.json/.toml and .mcphub/servers.json under --project
├── keys/              # Package carrying the feed public key (mcp-audit-feed.pub), force-included by pyproject.toml
├── _gitobjects.py     # Read-only git object store (STORY-0153): loose objects, pack v2/v3 with index v2, OFS_DELTA/REF_DELTA, refs (HEAD, loose, packed-refs); SHA-1 only, alternates not followed; never runs git; index kept as raw bytes (512 MiB per store), packs read through a memoryview (never a slice copy of the mmap), packed-refs parsed once; bounded (32 MiB per object, inflate stops at the declared size, delta depth 1,000, 64 REF_DELTA hops, 256 MiB of deltas per chain, ReadBudget charged for index/loose bytes, inflated objects and delta results); symlinked objects/, objects/pack/, objects/xx/ or refs/ not read; malformed → GitObjectError, missing → None
├── _gitignore.py      # Is a file git-ignored? Read-only (never runs git): gitignore(5) matcher with linear-time wildcards; reads .gitignore files (symlinked ones skipped, as git ≥2.32), .git/info/exclude and the global excludes file (core.excludesFile / XDG, a plain [include] path followed one level); BOM, `***`, empty segments as git; 1 MiB per file, 512-file / 8 MiB budget, anchored patterns longer than the path rejected up front, 5,000,000-step matching budget (MatchMeter); unreadable or over budget → IgnoreStateUnknownError + error text without absolute paths (STORY-0093)
├── host_platform.py   # detect_host_platform(): windows / wsl / macos / linux from sys.platform plus a size-capped read of /proc/sys/kernel/osrelease or /proc/version for "microsoft"; None when undeterminable; injectable, no subprocess (STORY-0142; used by affected.match.research_rows for records with `platforms`)
├── harness_versions.py # Installed Claude Code / Codex / Gemini CLI / OpenCode (`opencode-ai`) versions read from files only (STORY-0132, STORY-0142): npm global package.json (prefix env, nvm, Homebrew, /usr/local, APPDATA), Claude Code's ~/.local/share/claude/versions/, and OpenCode's ~/.opencode/bin/opencode[.exe] installer (stat only, `HarnessInstall.version` is None: it keeps no version file, so `affected` says COULDN'T CHECK); 1 MiB cap, hostile files skipped and listed, no subprocess; every install returned (PATH winner unknowable); used by affected.match.research_rows only
├── guardrails.py      # Guardrail drift (GUARD-001 MEDIUM/HIGH, GUARD-002 INFO, STORY-0143): normalised record per settings file (Claude Code user/project/local, Codex config.toml honouring CODEX_HOME, Gemini CLI settings.json; managed settings files as SHA-256 only) in <state dir>/guardrails.json (or beside an explicit rug-pull state path), reusing agent_files/drift.py's reader, lock, atomic writer and cap; hook commands stored only as SHA-256 + event + matcher; LOOSENING_TABLE is the only definition of a loosening, one cited row per key (vendor docs read 2026-11-04); first sighting silent, a vanished file reported only if it was the sole source of a deny rule or hook; never raises; _run_static_pipeline step 5c2, scans with no explicit path incl. --project (plus cli/scan._apply_project_scan for the tree); docs/guardrail-drift.md
├── policy_sources.py  # Read-only OS policy readers (STORY-0144): winreg_reader (KEY_READ only, lazy `winreg`, Windows only), read_plist (plistlib, files only, 1 MiB, no symlink out of the root), PlatformSources injected by tests; shared by managed_policy and extensions/policy
├── affected/          # `affected` engine (STORY-0121): query.py (ID or pkg@PEP 440 range), match.py (per-server decision: RegistryRule/RecordRule/RangeRule, LockIndex, research_rows; reuses supply_chain._fix_status/_pinned_version and malicious._range_covers, no new range resolver), render.py (terminal/JSON/SARIF; JSON/SARIF paths redacted)
│   ├── transitive.py  # `affected --transitive` (STORY-0131): check_dependencies() extends per-server rows with deps.dev dependency graphs (vulnerability/depsdev.fetch_dependency_graph, reused); a dependency hit is AFFECTED with Row.dependency path, an unreadable/incomplete graph or a server with no exact version is COULDN'T CHECK; GraphSource caches per package and caps lookups at 100; needs --live
│   ├── fleet.py       # `affected --fleet` (STORY-0131): load_machines() reads `scan --format json` files (bounded, non-blocking, 64 MiB, hostile input becomes COULDN'T CHECK rows); one row per machine x server; no lock lookup (LockIndex(nearest=False))
│   ├── vex.py         # OpenVEX 0.2.0 writer: affected --format openvex, scan --vex (STORY-0125); one statement per purl, most cautious status wins
│   ├── fixplan.py     # `affected --fix`: choose(current, fixes) = lowest release fix above current, else skip with reason; pins via fixer.run_pins / strategies.pinning.pin_exact; match.would_close re-runs the advisory's rules on the target (STORY-0127)
│   └── respond.py     # Respond block (env/header/flag names, shared names, stat-only credential files, saved tool-text count) and --policy-out deniedMcpServers entries checked with managed_policy.entry_matches; never writes the managed dir (STORY-0126)
├── exploit/           # KEV/EPSS/public-PoC signals (STORY-0124): signals.py (index from data/exploit-signals.json, annotate, sort key, --live fetch); refreshed by scripts/sync_exploit_signals.py; docs/exploit-signals.md
├── analyzers/
│   ├── base.py         # BaseAnalyzer abstract class — all analyzers inherit this
│   ├── poisoning.py    # Tool description poisoning detection (regex-based); PATTERNS list reused by agent_files; POISON-060 counts full-width letters/digits, not punctuation (STORY-0107), and a mixed word (ASCII letters with look-alike letters), not a whole Cyrillic or Greek word (STORY-0170); POISON-012 in PATTERNS is `POISON_012_WITHOUT_SECRECY` (the bare "do not say/tell/mention" branch counts only for MEM-001, via memory_override_match) and POISON-040 is `_POISON_040_CLASS` (joiners that Persian/Indic text and emoji need are silent; `_INVISIBLE_FILLERS` are reported and stripped) (STORY-0171); POISON-080..082 (redirection order, `rm -r` / `echo $SECRET`, /etc/passwd) carry `DetectionPattern.tool_text_only=True`, which agent_files/analyzer.py and scan_concealed_channels skip and PoisoningAnalyzer.analyze reads only under raw["tools"/"resources"/"prompts"] (`_TOOL_TEXT_KEYS`), never in a config entry (STORY-0172; compared with Cisco's YARA rules in docs/research/head-to-head/cisco-yara/); POISON-083 (tool promotes itself: "the premium version", "world's best"; MEDIUM, tool_text_only, STORY-0173); directive family POISON-070..075 (secrecy, autonomy override, ask-user tool ban, coercion, startup exec, remote instructions; DetectionPattern.skill_severity sets their SKILL-001 severity) and memory_override_match() for MEM-001 (STORY-0099); also owns POISON-041..045 concealment-channel extract/decode/rescan (TAG, HTML comment, zero-width binary, variation selectors, and POISON-045 text after ≥20 blank lines, STORY-0141; scan_concealed_channels, build_concealment_finding, concealment_finding_id; ConcealedChannel.start is the channel's offset), shared with agent_files; iter_pattern_matches() = every match passing the co-occurrence gate and DetectionPattern.negated_by (for the agent-file framing gate); POISON-076 oversight bypass (skip/bypass/disable/auto-approve permission, approval or confirmation prompts; --dangerously-skip-permissions/bypassPermissions/--yolo unless scoped to a container; HIGH, negated_by veto incl. a flag's purpose clause; sandbox/hooks/monitoring deliberately not matched), POISON-071 stays LOW in skills (STORY-0141 review); POISON-045 also catches ≥200 spaces inside a line and reports one finding per text (ConcealedChannel.runs); evidence redacted before it is cut (redacted_snippet → supply_chain.redact_command)
│   ├── credentials.py  # Secret/API key exposure in configs (SECRET_PATTERNS)
│   ├── transport.py    # Transport security (TLS, localhost binding, etc.)
│   ├── supply_chain.py # Package provenance and typosquatting detection (registry-backed); SC-007 unscoped twins (takes precedence over SC-001..003) and SC-008 OSV MAL-* exact-name matches (STORY-0097); SC-009 INFO when a pinned version and a CVE's fixed_in are in different numbering schemes (calendar vs semantic) and neither RegistryEntry.semver_resumed_at nor the 0.x rule orders them (_fix_status, STORY-0105); secret_arg_values() (values of --api-key/--token-style flags, for redaction); launch_package()/resolve_launch_entry(), the one "which registry entry does this launch install" resolver shared by TRANSPORT-003 and the rule engine's exempt_known_servers; redact_command() for evidence; redact_args()/redact_url() (STORY-0108; STORY-0118 adds credential headers, `Password=` pairs, `curl -u`, secret query parameters, Base64 userinfo, shared with managed_policy and the lock identity; `redact_env_values` for every client's env in JSON) used by TRANSPORT-001/003/004 evidence, CycloneDX snapshots and ServerConfig's JSON serialisers (command/args/url/raw launch keys; env and headers values are not redacted); REDACTION_MARKER read by diff/comparator as a hardcoded credential in scan files
│   ├── hook_runnable.py # HOOK-004 (PreToolUse/UserPromptSubmit/Cursor before* hook command Git Bash on Windows can't start: unquoted backslash paths or an unquoted drive-letter path with a space; LOW, MEDIUM in managed settings; skips `shell: powershell`, `args`, Cursor `failClosed`) and HOOK-005 (unreadable/invalid `~/.cursor/hooks.json` or project `.cursor/hooks.json`, MEDIUM) (STORY-0156); Cursor files get HOOK-001/002 via ConfigHygieneAnalyzer._check_hook_commands; managed_hook_findings()/cursor_hook_findings() run in scanner._discover_and_parse (no explicit path), cursor project file also in `scan --project`; 1 MiB reads, symlinks leaving the root not followed; command strings only, never runs a hook
│   ├── config_hygiene.py # Config-file filesystem hygiene (CFHYG-001..008; CFHYG-007 = project settings `env` redirecting API traffic, STORY-0090; CFHYG-008 = INFO naming the Azure Foundry resource project settings choose, STORY-0108); HARNESS-001 is MEDIUM in project/local settings (Claude Code ≥2.1.257 ignores bypassPermissions there, STORY-0108); hook-command checks HOOK-001/002 and harness posture HARNESS-001..007 (STORY-0079, STORY-0087, STORY-0090) via analyze_config; repo-planted auto-run files TRUST-003 (VS Code) and TRUST-008 (Gemini CLI, Codex, Claude Code scheduled tasks/workflows, STORY-0090) via analyze_autoexec_file
│   ├── rug_pull.py     # Config-entry change detection via hashing (command, args, env key names, raw entry; not live tool definitions)
│   ├── toxic_flow.py   # Cross-server capability tagging and dangerous pair detection (TOXIC-001..011, INTEG-001; COMMS_OUT sinks TOXIC-008..011, STORY-0101)
│   ├── auth.py         # Remote server authentication checks (AUTH-001, AUTH-002)
│   ├── collision.py    # Tool-name collision detection across --connect servers (COLLIDE-001); detect_tool_name_squats() = COLLIDE-002 (STORY-0173): another server's tool name of ≥2 words plus only `_DECORATION_WORDS` (HIGH when every added word is in `_PROMOTION_WORDS` and stands before or after the whole name, else MEDIUM), or the same words in another spelling on two servers (MEDIUM); one spelling per server, `MAX_NAME_COPY_FINDINGS` = 100, HIGH first; names only, runs right after COLLIDE-001; controls in docs/research/mcp-safetybench/name_copy_controls.py; find_description_copies() / detect_description_copies() = COLLIDE-003 (STORY-0174): two tools on two servers where one description holds the other (always MEDIUM, names both, no direction: nothing that a server chooses (names, arguments) changes the severity; no word list; each tool indexed under each long sentence with per-server caps, either tool can be the holder, `_COPY_WORK_BUDGET`, `MAX_DESCRIPTION_COPY_FINDINGS` = 100; the finding never holds the text); copies_of_approved_tools() gives the direction from the lock, and `cli/lock._withhold_copies` leaves a new tool that carries the description of a tool the lock held before on another server (only approved tools are indexed, with no cap; no launch detail excuses a pair; a new tool that the work budget left untested is not approved) out of `lock --connect`, so `run --mode enforce` withholds it (`--allow-copies` records it); measured in docs/research/copy-checks/
│   ├── annotations.py  # ANNOT-001 (LOW, non-advisory, STORY-0136): readOnlyHint true on a tool whose input schema runs commands or writes; detect_annotation_contradictions() runs in run_scan_async after DELEG-* (needs --connect), findings_from_tool_text() reads cwd mcp-lock.tools.json in scanner._discover_and_parse (no explicit path); live hit replaces the saved-text hit for the same tool; bounded schema walk, $ref never followed, names cleaned
│   ├── delegation.py   # Cross-tool delegation in live tool descriptions (DELEG-001..003, STORY-0100): names another
│   │                   #   server's tool / trigger + action its server lacks / rewrite another tool's arguments;
│   │                   #   token-based, budgets shared fairly per server, redacted evidence; runs in run_scan_async
│   │                   #   after COLLIDE-001 (needs --connect: the lock holds digests, not text); SHIPPED_SEVERITY
│   │                   #   must equal results.json's measured gate decision
│   ├── git_exec.py     # Git can run code (TRUST-006/007, STORY-0089): tolerant git-config parser, command-key table (_RULES), includes/worktree configs/gitfiles, hooks, nested bare repos; scan_cwd_repository() (default scan/check, via scanner._discover_and_parse) and scan_git_surfaces() (--project, via discovery.discover_project_git_surfaces); check_git_config() is the standalone per-file API (STORY-0096). Never runs git; not a BaseAnalyzer
│   ├── permissions.py  # Claude Code permission-rule linter (PERM-001..007, STORY-0092): public settings parser (load_claude_settings, reused by sandbox checks); PERM-001..006 via config_hygiene.analyze_config, PERM-007 as _run_static_pipeline step 5b and again across scopes in cli/scan._apply_project_scan; every rule quoted from code.claude.com/docs (docs/permission-rules.md)
│   ├── sandbox.py      # Claude Code sandbox settings a repository can loosen (SANDBOX-001..005, STORY-0093): reuses permissions.load_claude_settings; all five run as _run_static_pipeline step 0b (analyze_sandbox_files, NOT analyze_config), each file in its own try: a SandboxContext says whose file it is (shared project file = repository; settings.local.json = repository only when no ignore file covers it or .claude is a symlink, MEDIUM cap when its git state is unknown, user's own when ignored or outside a work tree; user settings get only SANDBOX-004) and carries UserSettingsLocks read from ~/.claude/settings.json (strictAllowlist → SANDBOX-003/proxy ports INFO; defaultMode bypassPermissions/auto → SANDBOX-002 HIGH); SANDBOX-005 (local settings headed for git, home paths with a masked username) via _gitignore.py; errors prefixed "SANDBOX checks: "; key scopes from code.claude.com/docs settings-reference (docs/permission-rules.md)
│   ├── rule_secrets.py # CRED-004 (STORY-0149): credentials inside permissions.allow/ask/deny strings (redact_rule = redact_command_text + PASSWORD/npm-token shapes, reference/wildcard/template values put back); run from sandbox step 0b, HIGH when headed for git; PERM-* and GUARD-001 quote rules through redact_rule
│   ├── rule_secret_history.py # CRED-005 (STORY-0153): CRED-004's detector over every version of the root .claude/settings.json and settings.local.json in git history (commits reachable from refs and HEAD), reporting rules no longer in today's file (compared by RuleSecretHit.digest, the SHA-256 of the rule as written, so a rotated token counts; commits recorded per rule); a bad object or version is skipped and counted, a budget stop keeps partial findings; reads objects via _gitobjects.py, never runs git; find_repository() mirrors scan_cwd_repository's upward search (linked worktrees via commondir; bare repos skipped); scan_repository_history() runs in scanner._discover_and_parse (no explicit path) and cli/scan._apply_project_scan (the project's repo when it differs from the cwd's); shallow/partial/SHA-256/budget problems go to result.errors; never raises
│   ├── shipped_settings.py # CRED-006 (STORY-0157): .claude/settings(.local).json a Dockerfile's final image or a non-private npm package ships; own walk (scan --project skip list/depth, no symlinked dirs, MAX_DIRS budget); .dockerignore / <Dockerfile>.dockerignore with BuildKit rules (parity-tested vs moby/patternmatcher) on _gitignore.py's wildcard code; stage model (final stage or Compose target, FROM chain, COPY --from traced by image path via WORKDIR, --exclude); npm: files field, else per-folder .npmignore/.gitignore (never global excludes); HIGH with a CRED-004 hit, LOW local file without, shared file without = silent; scan_cwd_repository() in scanner._discover_and_parse (no --path; skips a work tree that is or contains $HOME), scan_tree() in cli/scan._apply_project_scan (deduped); errors prefixed "CRED-006: "; never runs docker/npm/git; never raises
│   ├── managed_policy.py # Claude Code managed MCP policy vs configured servers (MANAGED-001..007, STORY-0112, STORY-0144): reads managed-settings.json + managed-settings.d/*.json (drop-in merge rules) and managed-mcp.json from plugins.mods.managed_settings_dir(); STORY-0144 adds read_effective_policy(): macOS plist (`com.anthropic.claudecode`), HKLM/HKCU `Settings` (injectable PlatformSources, FsProbe), ranked plist/HKLM > files > HKCU-when-no-admin, first-wins or `managedSourcesBehavior: merge`, evidence names the source; MANAGED-006 (policy only in HKCU or a user-writable file) and MANAGED-007 (malformed admin source); file-only output byte-identical (tests/test_managed_policy_regression.py); server-managed settings not read, 1 MiB/file, 256 drop-ins, 8 MiB budget; evaluation per code.claude.com/docs/en/managed-mcp (exclusive control → denylist → strictPluginOnlyCustomization → managedMcpServers precedence → allowlist per transport over the merged list when unlocked; exact commands, `*` URL globs without backtracking, documented default-port rules; allowManagedMcpServersOnly/strictPluginOnlyCustomization fail closed; ${VAR} or allowedMcpServers null = undecidable, never "blocked"); settings_allowlists() skips files under a symlinked component; managed_policy_findings() runs at the end of scanner._discover_and_parse (no explicit path) and in cli/scan._apply_project_scan (machine_findings=False, deduplicated by finding_key); never raises; redacted evidence. Not a BaseAnalyzer
│   ├── secret_reach.py # Credential files a Claude Code session can read without a prompt (REACH-001..003, STORY-0114): stat() only on a fixed list of home stores (SSH default keys, ~/.aws/credentials, gcloud ADC, ~/.git-credentials, ~/.netrc, ~/.pypirc, Claude Code .credentials.json; npmrc/docker/kube/gh as "may hold") and cwd-root .env names — never opened; covered by a Read deny rule (permissions-doc anchoring, gitignore segments matched by non-backtracking DP, `!` carve-outs) from managed/user/project/local settings, blockReadsOutsideWorkingDirectories, or sandbox denyRead/credentials deny; REACH-002 = login store mode bits + searchable parents (POSIX); secret_reach_findings() at the end of scanner._discover_and_parse (no explicit path, only when the Claude config dir exists); never raises; non-advisory; docs/secret-reach.md
│   ├── npx_cache.py    # SC-011 (CRITICAL, STORY-0158): name + version from each package.json under <npm cache>/_npx/*/node_modules (top level, @scope/name; regular files, O_NOFOLLOW, 64 KiB, 2,000 install dirs / 50,000 packages) matched exact-name against the SC-008 mirror via registry/malicious.assess as a pin; cache = $npm_config_cache, else %LocalAppData%\npm-cache on Windows, else ~/.npm (npm_cache_dir, patched to nothing in tests/conftest.py); npx_cache_findings() runs at the end of scanner._discover_and_parse (no explicit path); never raises
│   └── attack_paths.py # Multi-hop attack path detection and greedy hitting set algorithm; one path per hop sequence, the most severe pair's (STORY-0101)
├── reach/             # `reach` engine (STORY-0145): a default ScanResult + settings readers in, MachineReach out; pure, no subprocess (AST-tested); rendering is in output/reach*.py, the command in cli/reach.py
│   ├── engine.py      # build_machine_reach(result, env=, registry=): agent grouping (agent_of_client: claude-code*/codex*/gemini-cli*/opencode* families, other clients one each), verdict_of (not safe > needs work > couldn't check > ready), CRITICAL-finding attribution; one agent's failure never drops the others
│   ├── claude.py      # Claude Code's five answers: settings via secret_reach.load_settings_sources, sandbox/approval (managed > local > project > user, bypassPermissions honoured from managed/user only), sandbox network state (Linux needs bwrap+socat or failIfUnavailable; WebFetch/Bash allow rules, excludedCommands and proxy ports; hooks/apiKeyHelper/statusLine network tools), REACH-001..003 credentials (+ secret-shaped settings env, unsandboxed Bash; an unreadable settings file in any scope or a missing config dir = COULDN'T CHECK), extra_servers() (~/.claude.json projects.*.mcpServers, managed-mcp.json exclusive control, managedMcpServers), managed_policy_source() adapter (file-based policy, writer from owner+mode bits via classify_writer; the one place to switch to the #267 source ranking), OpenTelemetry from managed/user `env` only
│   ├── codex.py       # Codex answers from config.toml (user + cwd project): sandbox_mode, approval_policy, selected profile, sandbox_workspace_write.network_access, [otel] exporter (user file only); credentials and managed config are COULDN'T CHECK
│   ├── surface.py     # the closed surface (round 5): allowlists for settings keys, env names, launch shape and known-local commands; Cmd records, hook handler types, frontmatter/plugin/ancestor readers; anything not on a list is COULDN'T CHECK (docs/reach.md, "How reach decides")
│   ├── network.py     # ServerView/NetworkView: toxic_flow.tag_server + registry; NETWORK_OUT/COMMS_OUT/SHELL_EXEC/BROWSER or remote = reaches the network; a stdio server is quiet only when the registry declares its capabilities, otherwise unclassified (COULDN'T CHECK)
│   ├── common.py      # Assessment and network_status() shared by the per-agent assessors
│   ├── context.py     # Env (home, cwd, config/managed dirs; mask() shows ~/...), read_capped() (non-blocking, regular files, 1 MiB)
│   ├── models.py      # dataclasses + MachineReach.to_dict() (docs/reach.schema.json, schema_version 1.0); sanitize() is the one choke point: redact_command_text, home → ~, control characters, 600-char cap
│   └── fleet.py       # `reach --fleet DIR`: bounded tolerant loader (1000 files, 4 MiB, regular files, non-blocking), counts per agent per verdict, skipped files listed
├── agent_files/       # Agent instruction/memory file scanner (SKILL-001/002/003, MEM-001..006; also emits POISON-041..045, analyzer="poisoning")
│   ├── __init__.py    # Package marker; offline-only invariant docs
│   ├── models.py      # AgentFile dataclass (+ follows_imports, imported_from, edges), AgentFileSurface StrEnum, MEMORY_SURFACES, ImportEdge
│   ├── discovery.py   # discover_agent_files(); user-global + project-tree walk (mirrors discovery.py conventions); AGENT_INSTRUCTION_PATTERNS incl. AGENTS.md, CLAUDE.local.md, .claude/rules, OpenClaw workspace files (STORY-0098); discover_root_agent_files() / discover_user_heartbeat_files() for the default scan; 4 MiB per-file read cap and a per-call budget
│   ├── imports.py     # Claude Code @path imports (documented rules: relative to importer, 4 hops, code/comments skipped) and "read X" prose references; follow_references() never reads outside the root or through a symlink (TRUST-002/004), budgeted (STORY-0098)
│   ├── gitignore.py   # .gitignore matcher read by file (never runs git), non-backtracking wildmatch; MEM-003's "ignored" case
│   ├── heartbeat.py   # MEM-004 detector: HEARTBEAT_OK/NO_REPLY/notify:false forced, paired with hiding, or after an action
│   ├── sleeper.py     # MEM-005 detector (STORY-0099): one sentence with an if/when clause (or leading date) holding an unusual trigger (later user cue, root/sudo, hostname, date, off-hours, unobserved), a consequence opening with an action verb, and a payload cue (URL, curl, secrets, backups, remote endpoint, silently) unless unobserved; run by analyze_instruction_reach once per real file
│   ├── exfil.py       # MEM-006 detector: one sentence with a send verb (not negated), a bulk or local secret (env vars, .env, ~/.ssh, ~/.aws, private keys, all/every ... secrets) within 100 chars and a destination (URL, IP, email, named server/endpoint/webhook) within 160; HIGH in a project file, MEDIUM in the user's own; memory surfaces + Cursor rules + Copilot instructions; run by analyze_instruction_reach with MEM-005; measured in docs/research/mem006/results.json
│   ├── instruction_shapes.py # MEM-008 detector (STORY-0155): an edit instruction aimed at a machine-wide agent config (~/.codex/config.toml, ~/.claude/settings.json, ~/.cursor/mcp.json, ~/.gemini/settings.json; opening imperative verb, payload within 8 lines, table rows and negations skipped) plus SKILL-006's permissions and base-URL shapes (install_steps.text_shape_hits, reused); HIGH outside a git repository, MEDIUM inside one; MEM-007 (MEDIUM) comes from discovery._discover_dropped: AGENTS.md/CLAUDE.md/GEMINI.md/.cursorrules at the top of ~/Downloads and ~/Desktop (AgentFile.dropped; a symlink is TRUST-002 and not read); docs/research/mem008/results.json
│   ├── drift.py       # INSTR-001 (INFO, bytes changed) / INSTR-002 (MEDIUM, changed and a new MEDIUM+ finding ID on the file) (STORY-0113): SHA-256 per user-global + cwd-root instruction file (AGENT_INSTRUCTION_PATTERNS, no walk, cwd skipped when $HOME, project symlinks skipped) in <state dir>/instruction-files.json (or beside an explicit rug-pull state path; 0o600, hashes + finding IDs only, 10,000 records); user-global memory files (CLAUDE.md, rules, ~/.codex/AGENTS.md, OpenClaw) get MEM-004/005 run here for INSTR-002 only (not reported); only content IDs (MEM-/SKILL-/POISON-/AGENT-/HOOK-) count, last 8 hashes remembered so a seen version never re-escalates; writes are atomic (temp + os.replace) under a .lock file after re-reading (merge), an unreadable file is never overwritten, a non-record file is kept as .corrupt; _run_static_pipeline step 5c, every scan with no explicit path incl. --project (cwd root + user files, not the project tree; not --path, pin/diff); first sighting and removal silent; never raises
│   ├── reach.py       # MEM-003/MEM-004/MEM-005 in the default scan (cwd root + ~/.openclaw/workspace/HEARTBEAT.md, via scanner._cwd_instruction_reach_findings) and scan --project (cli/scan._apply_project_instruction_reach); never raises
│   ├── framing.py     # STORY-0141 describes-vs-directs gate, fail-closed (PR #263 review): FileFraming(text) splits blocks once (headings, closed fences, quotes, lists, paragraphs; closing-fence tables keep it linear) and classify(start, end) is directed unless a positive frame says described (short negated clause opening with its negation; checklist or descriptive list item under a detection lead-in — flag/detect/look for/red flags/indicators, not review/audit/checklist; describing sentence; descriptive quote), judged over the whole list item; fenced code, a destination in the line/sentence/item (URL/email/IP/host after 'to'/Markdown link/pipe/curl...), a later clause giving an order, table rows/callouts and sentences addressed to the agent are always directed; obfuscated files (POISON-040/060) get no downgrade; regression strings in tests/test_agent_files_framing_bypasses.py; SKILL-001 only
│   ├── analyzer.py    # analyze_agent_files(); imports PATTERNS from analyzers/poisoning.py (never forked), plus scan_concealed_channels/build_concealment_finding for POISON-041..045; SKILL-001 reports the first directed occurrence or INFO "described, not directed" (framing.py), failing closed when the file has any concealment channel or a pattern matches more than 256 times; SKILL-001/002, MEM-001/002 and POISON-04x evidence starts `Line N:` (file line, frontmatter counted) with the redacted line (STORY-0141); MEM-001 = memory_override_match() or POISON-070 (STORY-0099); calls skill_package.sidecar_findings for a skill's other prose files; MEM-003/004 via analyze_instruction_reach(); imported files get the importer's rules, secrets redacted. NB: HOOK-001/002 live in analyzers/config_hygiene.py, not here
│   ├── skill_package.py # STORY-0095: every file in a skill folder; STORY-0159: USER_SKILL_DIRS / PROJECT_SKILL_DIRS are the one table of skills directories (Claude Code first; .agents/skills = client agent-skills; .gemini, .cursor, .codex (Cursor compat), .copilot (user), .github (project); vendor docs cited there), SkillPackage.client names the agent on findings, skills-dir plugins only in Claude Code's directory, a skill reached from several directories read once (_first_per_skill, table order); (SKILL-005..008), default scan/check (scanner._discover_and_parse → scan_default_skills) and scan --project (cli/scan._apply_project_skills; a skills-dir plugin's config is listed once, as claude-code-plugin, and not re-analysed when the default scan already did); a nested SKILL.md folder is its own package only when discovery returns it (else walked with the parent); .git text records are read, git binaries magic-checked; follows a symlink directly under a skills dir one level when it points at a skill (TRUST-004 INFO; a repo link leaving the repo is TRUST-002 HIGH, not read; decision 2026-10-26) and no other symlink (TRUST-002/004/005), O_NOFOLLOW reads under per-file/per-skill/per-scan budgets, errors → ScanResult.errors; skills-directory plugin (.claude-plugin/plugin.json) servers join discovery as "claude-code-plugin" (discovery._skills_dir_plugin_configs); carried .mcp.json routed through per-server analyzers as "claude-code-skill" (never discovered; check never offers `fix`)
│   ├── install_steps.py # STORY-0095: pure text/byte checks (no I/O): SKILL-005 install-step shapes with per-file literal gates (parity-tested), SKILL-006 text shapes, SKILL-007 format/blob identification, redact()
│   └── subagents.py   # Claude Code subagent definitions (STORY-0094): frontmatter read the way Claude Code's loader reads it (1 MiB file cap, split at the first `---` anywhere, quote-and-retry on a YAML error) plus the `---`-line reading, findings from both; repeated/unreadable security keys are findings; node/nesting/alias budgets; agent_mcp_servers() (one server per item, repeats `name#2`), analyze_agent_definition() AGENT-001..004; files join default discovery as client "claude-code-agent" (discover_configs(include_agents=True); never with --path; lock opts out; auto-verify skips them and lists project ones under a lock root in `lock_status.not_covered`; rug-pull state key excludes), step 0 via ConfigHygieneAnalyzer.analyze_agent_definition (+HOOK-001/002)
├── plugins/           # Claude Code plugin inventory + integrity (PLUGIN-001/002); offline, reads ~/.claude/plugins records only
│   ├── models.py      # InstalledPlugin dataclass; GIT_SOURCE_TYPES; pinned_sha / source_type
│   ├── discovery.py   # discover_installed_plugins(), plugin_agent_files(), plugin_mcp_config_paths(); plugin MCP servers join default auto-discovery (discover_configs(include_plugins=True) is the default; never with an explicit --path; lock opts out; lock auto-verify skips them, listing a repository's skills-directory plugin servers under a lock root in `lock_status.not_covered`; excluded from the rug-pull state key) as client "claude-code-plugin" — skills-directory plugins (`~/.claude/skills/<name>/.claude-plugin/plugin.json`, cwd `.claude/skills/…`) join the same way (STORY-0095), except that the cwd's are `is_project_scoped` and stay in the rug-pull state key so one repository's plugin servers never show up as RUGPULL-003 in another's scan
│   ├── analyzer.py    # analyze_plugin_integrity() — PLUGIN-001 (recorded version != pinned sha prefix), PLUGIN-002 (unpinned git source)
│   ├── checkout.py    # PLUGIN-003/004 (STORY-0096): the marketplace pin vs the commit the plugin checkout actually resolves to (Plugin4Shell, AIR Security); reads git files, never runs git
│   └── mods.py        # Claude Code mods (STORY-0085): discover_mods() (installed plugins, ~/.claude/dev-mods, CLAUDE_CODE_PLUGIN_DIRS), static read of hooks modules (never executed), read_guard_state() (managed-settings file), analyze_mods() MOD-001..005, analyze_plugin_dirs_setting() MOD-006; wired into default discovery next to PLUGIN-001/002
├── ci_workflows/      # GitHub Actions workflows that run an AI agent (WORKFLOW-001..003, STORY-0091); YAML read with safe_load, never run
│   ├── discovery.py   # discover_workflow_files(): <root>/.github/workflows/*.y{a,}ml (top level only); walk=True (--project) adds nested repo roots (a .git entry); a symlinked .github or workflows dir is not read and every file must resolve inside root; 256 KiB per file, 4 MiB per call; size/budget skips and an unreadable workflow dir or file (stat(), not is_dir(), which hides EACCES from 3.13) reported to the caller's errors; every probe catches OSError
│   └── analyzer.py    # analyze_workflow_files(): steps using claude-code-action / claude-code-security-review / run-gemini-cli × stranger-writable trigger × secret in with/env × write (or absent) permissions × tool posture per vendor docs; workflow_call evaluated once per local caller path (triggers + token ceiling); every pass over untrusted text is linear — ${{ }} extraction (no lazy-dot regex), whole-shell rule matching (no adjacent \s* quantifiers), claude_args splitting (_posix_split, not shlex, whose per-char token concatenation is quadratic); parse cached by SHA-256 of the bytes
├── lock/              # mcp-lock.json (ADR-0005): committable record of approved servers
│   ├── model.py       # ownership boundary + top-level checksum ({lock_version, generated_by, servers}); LOCK_VERSION 2, SUPPORTED_LOCK_VERSIONS, ResolutionContext
│   ├── writer.py      # regenerate()/write_lock(); foreign sections preserved; owned `tools` merged
│   ├── verifier.py    # lock --verify: LOCK-001..005, LOCK-006..009 with --connect; lock_version 1 and 2 (STORY-0116): v2 adds LOCK-011/012 (section digests, canonical bytes) and LOCK-010 under --resolve; a v1 lock verifies exactly as before (tests/test_lock_v2.py vs tests/fixtures/lock_v1_corpus); a newer version → exit 2
│   ├── section_digests.py # lock_version 2 `section_digests`: per-section SHA-256 of the RFC 8785 encoding; each producer writes its own entries, keeps the rest verbatim (merge/check/noncanonical_sections)
│   ├── guardrail_section.py # `guardrails` section (STORY-0143): the repository's own .claude/settings.json, .codex/config.toml, .gemini/settings.json (never settings.local.json or home files) as path → {digest, record}; own _producer/_schema_version/_checksum like `tools`; top-level checksum unchanged; lock --verify LOCK-014 (HIGH, fails exit code) per loosening via guardrails.compare; --accept re-records
│   ├── tool_digests.py # `tools` section (STORY-0086): per-tool definition/contract digests, own _checksum; optional per-tool `calendar` {day, dates, undated} when `day=` is given and the text holds an ISO date (STORY-0180); compare() puts a tool whose digests differ only by dates that followed the calendar in ToolDiff.calendar_only (no finding; VerifyResult.calendar_only, `calendar_only` in `lock --verify --format json`; ToolGuard approves it)
│   ├── calendar_text.py # the one calendar rule (STORY-0179/0180), stdlib only (on the `run` launch path): without_dates() cuts real ISO dates out of every string (a string becomes the list of its pieces), moved_with_calendar() (same undated digest; each date equal, moved by the days between the records, or a 1st of a month moved by the months), followed_calendar() tries each day one day earlier and later (server clock vs UTC); scripts/drift_snapshot.py imports without_dates, scripts/drift_compare.py keeps a stdlib copy of moved_with_calendar that tests/test_lock_calendar.py holds equal
│   ├── tool_text.py    # saved tool text `mcp-lock.tools.json` (STORY-0123, #215): store/load, trusted only if it hashes to the lock digest; field + word diffs; POISON over added words
│   ├── core.py        # stdlib-only primitives shared with `run`: LOCK_FILENAME/versions, match_key, index_locked_entries, find_lock_for (re-exported by model/identity/discovery/verifier)
│   └── identity.py, resolve.py (bare spec → "*", resolution_context), discovery.py, auto_verify.py
├── advisory/          # OSV 1.6.0 advisory records + signed feed (credenzo advise / feed verify)
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
│   ├── loader.py      # KnownServerRegistry, RegistryEntry, load_registry(); Levenshtein helper; scoped_parts_close() (find_closest_npm compares @scope and name separately, with osa_distance(), STORY-0105); optional RegistryEntry.semver_resumed_at
│   ├── twins.py       # TwinIndex: unscoped-twin keys derived from registry entries (SC-007, STORY-0097); pure, no I/O
│   ├── malicious.py   # load_known_malicious(), assess(): registry/known-malicious.json (OSV MAL-*) for SC-008 and vet; tolerant loader with size/entry caps, load_error surfaced in ScanResult.errors
│   ├── research.py    # load_research_records(), research_id(): credited research findings with no CVE (STORY-0122), `src/mcp_audit/data/research-records.json` (package data, so no packaging edit); OSV-shaped records `x_MCPRS-<12 hex>`, products as the write-up names them with fixed_in only when stated, optional `introduced` (PEP 440; an install below it is NOT AFFECTED) and `platforms` (subset of windows/wsl/macos/linux; a host outside it is NOT AFFECTED, an undeterminable host COULDN'T CHECK; bad values skip the record, STORY-0142; golden `affected` rows for the older records in `tests/golden/affected_research_rows.json`), `checks` = Credenzo finding IDs that test the condition; tolerant loader (bad entry skipped and reported); docs/research-records.md
│   └── reachability.py # transport tags on known_vulns (affected_transports/requires_auth/verified_by): tags_of, provably_stdio, not_reachable; used by affected/match.py RegistryRule and supply_chain SC-004 (STORY-0125)
├── rules/
│   ├── __init__.py    # Package marker
│   └── engine.py      # PolicyRule, RuleMatch, MatchCondition, RuleEngine; load_rules_from_file/dir; load_bundled_community_rules; a condition's optional `report:` label replaces the field content as matched value; matched values redacted (secret flag values, URL userinfo, SECRET_PATTERNS) before they reach a finding (STORY-0105)
├── governance/
│   ├── __init__.py    # Package marker
│   ├── models.py      # GovernancePolicy, ApprovedServers, ScoreThreshold, TransportPolicy, RegistryPolicy, FindingPolicy, ClientOverride, PolicyMode
│   ├── loader.py      # load_policy(); resolution order: explicit → cwd → repo root → user config
│   └── evaluator.py   # evaluate_governance(); per-server policy checks; produces Finding objects with analyzer="governance"
├── vulnerability/     # OSV.dev CVE lookups for `scan --check-vulns` (network, opt-in)
│   ├── __init__.py    # Package marker
│   ├── models.py      # ResolvedPackage, VulnAdvisory data models
│   ├── resolver.py    # extract_package() (version may be None: `npx -y pkg`), extract_ecosystem_and_version(); resolve_latest_version() from a ServerConfig
│   ├── depsdev.py     # fetch_dependency_graph() → DependencyGraph (relation SELF/DIRECT/INDIRECT, error, incomplete; 8 MiB cap); fetch_transitive_deps() wrapper for sbom
│   ├── osv.py         # query_vulns_batch() (IDs only on OSV.dev) + enrich_advisories()/fetch_vuln_details() (/v1/vulns/{id}, distinct IDs, 256 / 120 s / 4 MiB budgets); severity_from_record(): CVSS v3 → database_specific → MAL-* CRITICAL → unrated (STORY-0106)
│   └── scanner.py     # check_vulnerabilities(errors=result.errors) — resolver → depsdev → osv → VULN-<OSV-ID>, VULN-UNPINNED, VULN-UNRESOLVED (INFO: a lookup that could not run; non-advisory)
├── diff/              # MCP-aware diff engine (credenzo diff)
│   ├── __init__.py    # Package marker
│   ├── loader.py      # Load diff inputs (directory, JSON scan file, or git SHA) into ServerConfig lists
│   ├── comparator.py  # Compare two ServerConfig lists → flat list of Change objects
│   ├── risk.py        # Risk classification for diff changes
│   └── render.py      # Render diff to terminal, JSON, and PR-comment Markdown
├── fixer/             # Safe-remediation engine (credenzo fix)
│   ├── __init__.py    # Package marker
│   ├── fixer.py       # Fixer orchestrator — load config, apply strategies, write atomically with .bak
│   └── strategies/
│       ├── __init__.py     # Package marker
│       ├── base.py         # FixStrategy abstract base
│       ├── credentials.py  # CRED-001/002/003 — redact plaintext secrets with ${ENV_KEY}
│       ├── transport.py    # TRANSPORT-001 — upgrade http:// URLs to https://
│       └── pinning.py      # SC-001/002 — replace typosquat with verified registry name @version
├── killchain/         # Decision engine over the attack-path graph (credenzo killchain)
│   ├── __init__.py    # Package marker
│   ├── recommender.py # Rank kill switches from the hitting-set output by incremental path reduction
│   ├── simulator.py   # What-if simulation: re-run summarize_attack_paths against the modified server list
│   ├── patches.py     # Generate governance-policy denylist / PR-comment patch snippets
│   └── render.py      # Markdown and JSON output formatters for killchain results
├── shadow/            # Shadow MCP server detection (credenzo shadow)
│   ├── __init__.py    # Package marker
│   ├── allowlist.py   # Operator allowlist of sanctioned servers; load/match
│   ├── classifier.py  # Pure sanctioned-vs-shadow classification given server + allowlist
│   ├── risk.py        # RiskLevel scoring for a single server (toxic-flow capability logic)
│   ├── events.py      # Structured events for --continuous daemon mode (new_shadow_server, server_drift, server_removed)
│   └── state.py       # first_seen/last_seen state at <user-config-dir>/mcp-audit/shadow/state.json (0o600)
├── snapshot/          # Forensic snapshot rehydrate/diff (credenzo snapshot)
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
│   ├── check.py       # One-page security verdict formatter for `credenzo check` (_HINTS)
│   ├── advisory.py    # AdvisoryFormatter(BaseFormatter) — ScanResult → JSON array of OSV 1.6.0 records; byte-identical to feed/osv/all.json (feed *directories* stay in advisory/feed.py)
│   ├── cyclonedx.py   # CycloneDX SBOM formatter (supports cyclonedx-python-lib 7.x–11.x)
│   ├── snapshot.py    # Snapshot formatters: CycloneDX AI/ML-BOM and native JSON
│   ├── pdf.py         # Letter-size PDF compliance report (credenzo scan --report pdf)
│   ├── reach.py       # Terminal output for `reach` (reads MachineReach.to_dict(), so every string is already redacted; Rich markup escaped) and the fleet table
│   └── reach_pdf.py   # `reach --report pdf`: ReachPdfFormatter reuses pdf.py's header/footer/palette; KeepInFrame(shrink) keeps one machine on one page
├── extensions/
│   ├── __init__.py    # Package marker
│   ├── models.py      # ExtensionManifest, ExtensionVulnEntry Pydantic models
│   ├── discovery.py   # discover_extensions(), parse_manifest(); EXTENSION_PATHS per-client config
│   ├── policy.py      # EXTPOL-001..003 (STORY-0144): is the editor's AllowedExtensions allowlist enforced by policy (VS Code / Cursor / Windsurf documented locations only) or only in user settings; silent when absent or the policy location is undocumented, EXTPOL-001 (enforced inventory) is in scoring.INVENTORY_ONLY_IDS (not scored, left out of `check`); injectable Environment; extension_policy_findings() runs in scanner._discover_and_parse (no explicit path); docs/extension-policy.md
│   └── analyzer.py    # analyze_extensions(); check_known_vulns, check_permissions, check_wildcard_activation, check_provenance, check_sideloaded, check_stale; load_vuln_registry()
├── registration/
│   ├── __init__.py    # Package marker; privacy-invariant docs
│   ├── models.py      # RegistrationConfig, RegistrationPostPayload, RegistrationPingPayload Pydantic models
│   ├── manager.py     # load/save/clear_registration(); build_registration(); 0o600 file write; platformdirs storage
│   └── client.py      # post_registration() (PII POST, once); post_ping() (no-PII, per `check` run); _REGISTER_ENDPOINT constant (docs/privacy.md must name it; tests/test_registration.py checks); urllib.request only
├── sast/
│   ├── __init__.py    # Package marker
│   ├── runner.py      # SastResult; find_semgrep(); find_rules_dir(); run_semgrep(); parse_semgrep_output(); severity mapping
│   └── bundler.py     # get_bundled_rules_path() — resolves semgrep-rules/ in PyInstaller builds
├── fleet/
│   ├── __init__.py    # Package marker
│   └── merger.py      # FleetMerger, MachineReport, DeduplicatedFinding, FleetStats, FleetReport; fleet HTML generation
└── data/
    ├── known_npm_packages.yaml  # Legacy npm package list (retained for reference; superseded by registry)
    ├── exploit-signals.json     # KEV / EPSS / public-PoC snapshot (STORY-0124; refreshed by scripts/sync_exploit_signals.py)
    ├── research-records.json    # Credited research records with no CVE (STORY-0122)
    ├── header_dark.png          # Header image for the PDF report
    └── d3.v7.min.js             # Bundled D3 v7 (embedded inline in dashboard HTML)
```

Standalone rule pack at repo root:
- `semgrep-rules/` — 91 Semgrep rules (47 Python, 44 TypeScript) across 6 categories;
 runnable with `semgrep --config semgrep-rules/ <path>` without Credenzo installed;
 bundled in the pip wheel and PyInstaller binary; see `docs/sast-rules.md`

Data files at project root:
- `registry/known-servers.json` — curated dataset of 56 known-legitimate MCP servers; queried by the supply chain analyzer for typosquatting detection and by the toxic flow analyzer for authoritative capability tags (`RegistryEntry.capabilities`); ships in both the pip wheel and PyInstaller binary
- `registry/known-malicious.json` — mirror of OSV `MAL-*` records for npm/PyPI packages whose name contains `mcp` or that the registry lists (STORY-0097); written only by `scripts/sync_registry_advisories.py --write` (bulk export; a mirror, so withdrawn records are removed); matched offline by exact name for SC-008 and `vet`; ships in the wheel and all four specs; `update-registry` does not refresh it. Kept out of `known-servers.json` so the registry schema is unchanged
- `rules/community/` — 42 bundled community rules total: 41 real detection rules (`COMM-001` through `COMM-039`; `COMM-032` is intentionally reserved/unissued — see `PROVENANCE.md`) plus `STDIO-001`/`STDIO-002a`/`STDIO-002b` (launch-command trust boundary, STORY-0067; `STDIO-001` ships `enabled: false` — see `GAPS.md`) plus `TEMPLATE.yml` itself, which loads as the always-inert `COMM-000` (contribution template — `tests/test_rules.py` guarantees it never fires on a real config); `BOUNTY.md` (bounty program terms) ships alongside but is not a rule file. All ship in both pip wheel and PyInstaller binary and are available to every user with no gating — but "available to" is not "runs for": 38 of the 39 real rules run by default, and `STDIO-001` does not run for anyone (`enabled: false`, no governance-policy toggle exists to turn it on — see `GAPS.md`); see `docs/writing-rules.md` and `docs/contributing-rules.md`

GitHub Action at project root:
- `action.yml` — composite GitHub Action definition; allows any repo to wire Credenzo into CI with a single workflow addition; inputs: `config-paths`, `severity-threshold`, `sarif-output`, `upload-sarif`, `check-vulns`, `verify-signatures`, `run-sast`, `sast-path`, `baseline-name`, `fail-on-findings`, `version`; outputs: `findings-count`, `grade`, `sarif-path`. Uses `github/codeql-action/upload-sarif` (v4, pinned to a commit SHA like every third-party `uses:` ref in `action.yml`, `setup-action/` and `.github/` — `tests/test_action_yaml.py::test_every_third_party_action_ref_is_sha_pinned`) with `continue-on-error: true` so repos without Code Scanning enabled still run cleanly. Marketplace-ready — passes `tests/test_action_yaml.py` structural and safety checks.

Credenzo Team action (`team/`, the one paid offer; docs/team.md):
- `team/action.yml` + `team/credenzo_team.py` — composite action, one step, standard library only. Runs `credenzo lock --verify --if-present --format json` (the command must already be on PATH) and returns its exit code. On a failed check outside a pull request it keeps one issue ("MCP lock drift", found again by a marker in the body, fingerprint of the findings so the same drift is reported once) and POSTs `{"text": ...}` to `alert-webhook`. An alert holds finding IDs, severities and cleaned server/tool names (`clean_name`), never a finding's own text. `decide()` is the whole pricing rule: personal account or public repository = alerts; else the licence list (`read_offer`): not readable or not live = alerts, owner digest in the list = alerts, otherwise the check runs and one notice is printed. `MEANINGS` must hold every LOCK ID the lock package reports (a test reads the source).
- `team/offer.json` — price, seats, `live_since`, checkout link, payment link ID. Written by `scripts/team_go_live.py`.
- `scripts/team_licenses.py` + `.github/workflows/team-licenses.yml` — Stripe (restricted read key, `team-licenses` environment) to `index.json` on the `team-licenses` branch: `offer` plus `owners`, SHA-256 digests padded with HMAC fillers to a multiple of 64. A failed Stripe request writes nothing. The `publish` job replaces the branch with one parentless commit.
- `scripts/paid_path_report.py` — weekly public numbers (`gh` + pypistats) and `decide()` for the experiment; the paid numbers are arguments, never read or stored.

Pre-commit hook at project root:
- `.pre-commit-hooks.yaml` — pre-commit hook definition; `language: python`, `entry: credenzo` (the old ids `mcp-audit` and `mcp-audit-lock-verify` stay, with `entry: mcp-audit`), `pass_filenames: false` (Credenzo uses its own discovery), `types: [json]` (fires only on staged JSON files), `always_run: false`; default args run `scan --severity-threshold high`; see `docs/pre-commit.md`

CI workflow and example workflows:
- `.github/workflows/mcp-audit-example.yml` — runs Credenzo on this repo on push/PR; also the reference workflow users copy
- `examples/github-actions/basic.yml` — minimal setup (visibility only, never fails build)
- `examples/github-actions/strict.yml` — fail on MEDIUM or higher
- `examples/github-actions/with-baseline.yml` — drift detection against a committed baseline
- `examples/pre-commit/basic.yaml` — minimal pre-commit config (blocks on HIGH+)
- `examples/pre-commit/strict.yaml` — strict pre-commit config (blocks on MEDIUM+)

Build and distribution scripts at project root:
- `scripts/install.sh` — curl-based end-user installer for GitHub Releases

Measurement scripts (dev tooling, not in the package):
- `scripts/bench_poisoning.py` — POISON-* recall and clean-tool flag rate on MCPTox (fetched by hand at release time, never in CI, never committed; any severity and HIGH-or-above) and precision on the top-100 npm corpus (re-measured 2026-10-29 on 0.23.0, Q-045: 1 of 46 real; labels in `docs/research/poisoning-benchmark/top100-labels.json` with `labelled_patterns_fingerprint`, `precision` prints STALE once the code differs; the 2026-10-22 0.21.x labels kept as `top100-labels-2026-10-22.json`) plus a replay of the corpus's committed evidence fragments; pinned in `docs/research/poisoning-benchmark/results.json`. `tests/test_bench_poisoning.py` fingerprints the whole source of `analyzers/poisoning.py` and `mcp_client.build_runtime_server_config`: any change to either forces a re-measure (`precision --write`, `recall --write`, then update the numbers in `docs/poisoning.md`, `GAPS.md` and `README.md`); see `docs/poisoning.md` (STORY-0088). The `delegation` subcommand (STORY-0100) measures DELEG-001..003 on MCPTox in two session models (poisoned tool on its own server; among the target server's tools), counts flagged clean tools with all 45 servers in one session and each alone, and applies the gate (`gate_decision`); `tests/test_delegation.py` fails if `analyzers/delegation.py` changes without `delegation --write`, or if `SHIPPED_SEVERITY` differs from the recorded decision
- `scripts/bench_competitors.py` — head-to-head benchmark harness (STORY-0146, dev-only, never in CI): `corpus` writes/validates the committed corpus (`docs/research/head-to-head/corpus/`, SHA-256 pinned in `manifest.json`), `run --mcptox PATH [--tools ...] [--write]` runs the installed scanners (SkillSpector static, Cisco mcp-scanner YARA only, Credenzo; Snyk agent-scan is always "not run: needs remote analysis") and pins `docs/research/head-to-head/results.json`, `report` prints the table. It never installs a scanner; a missing one is "not run", never zero. MCPTox is generated into a temp dir outside the repo and only its hashes are committed. Competitor output parsers follow public docs and were run against real output on 2026-11-19 (SkillSpector v2.12.0, Cisco mcp-scanner 4.8.7; 1,686 inputs each, no parse error); results in `results.json`. `tests/test_bench_competitors.py`; see `docs/research/head-to-head/README.md`

## Key conventions

- Every module has a corresponding test file in tests/ (e.g., test_discovery.py)
- Detection patterns are hardcoded in each analyzer (regex constants); supply-chain data is now sourced from `registry/known-servers.json` via `registry/loader.py`
- All findings use the `Finding` Pydantic model from models.py
- Analyzers inherit from `BaseAnalyzer` and implement an `analyze()` method. **Exception:** `rug_pull.py` and `toxic_flow.py` have a no-op `analyze()` — real work is in `analyze_all()` (they need the full server list). `attack_paths.py` is not a `BaseAnalyzer` subclass — it is a standalone module exposing `summarize_attack_paths()`. `collision.py` is also not a `BaseAnalyzer` subclass — it exposes `detect_tool_collisions(pairs)` and is called in `run_scan_async()` after the `--connect` loop, before `_run_static_pipeline()`.
- **`_run_static_pipeline()` in `scanner.py` is the canonical implementation of the analysis pipeline.** Both `run_scan` (sync) and `run_scan_async` (async, after live `--connect` enumeration completes) delegate to it. The helper is intentionally synchronous and runs steps 1–7 in this exact order (after step 0, `analyze_config` per config file, and step 0b, SANDBOX-001..005 `sandbox.analyze_sandbox_files`, which reads ignore files and the user's settings, checks each settings file in its own `try`, and reports read failures and crashes in `result.errors`; only when a `ConfigHygieneAnalyzer` is in the list): (1) per-server analyzers, (2) `RugPullAnalyzer.analyze_all`, (3) `ToxicFlowAnalyzer.analyze_all` with the shared registry, (4) `summarize_attack_paths`, (5) policy-as-code rule engine, (5b) PERM-007 (`permissions.analyze_flagged_server_allows`: `mcp__<server>` allow rules on servers with HIGH+ findings, which needs every finding above; only when a `ConfigHygieneAnalyzer` is in the list), (5c) instruction-file drift INSTR-001/002 (`agent_files/drift.py`, scans with no explicit path, needs every finding above), (5c2) guardrail drift GUARD-001/002 (`guardrails.guardrail_drift_findings`, STORY-0143: Claude Code/Codex/Gemini CLI settings files, scans with no explicit path, same skip rules as 5c), (5d) exploit signals (`apply_exploit_signals`: KEV, EPSS and public-PoC data on CVE findings, STORY-0124), (6) `calculate_score`, (7) attach `registry_stats`. Wire new analyzers or pipeline changes here, not in either entry point. **Exception:** `detect_tool_collisions()` from `collision.py` runs in `run_scan_async()` inside the `if connect:` block, immediately after the per-server enumeration loop and before `_run_static_pipeline()`. It is not part of `_run_static_pipeline()` because it requires live `ServerEnumeration` data that is not available in the static pipeline. `detect_tool_name_squats()` (COLLIDE-002, STORY-0173) and `detect_description_copies()` (COLLIDE-003, STORY-0174) run right after it on the same pairs. `detect_delegation()` from `delegation.py` (DELEG-001..003, STORY-0100) runs after that in the same block, over the same pairs, for the same reason. So does `detect_annotation_contradictions()` from `annotations.py` (ANNOT-001, STORY-0136), after delegation.
- Output formatters inherit from `BaseFormatter` and implement a `format()` method
- The dashboard HTML template is a single large string (`_DASHBOARD_HTML`) embedded in `output/dashboard.py`. All scan data is injected via a `__SCAN_DATA_JSON__` placeholder at render time. D3 v7 is bundled from `data/d3.v7.min.js` and injected via `__D3_JS__`. Do not split the template into separate files.
- **Scoring** runs after all analyzers complete inside `scanner.py` and attaches a `ScanScore` to `ScanResult`. Analyzers never call the scorer directly. See `scoring.py` and `docs/scoring.md`.
- **Registry resolution order** for the supply chain analyzer: explicit `--registry PATH` CLI flag → user-local cache at `<user-config-dir>/mcp-audit/registry/known-servers.json` (written by `update-registry`; path resolved via `platformdirs`) → PyInstaller `sys._MEIPASS/registry/` → `importlib.resources` (pip-installed wheel at `mcp_audit/registry/known-servers.json`) → dev repo-root fallback (`registry/known-servers.json`). Pass `--offline-registry` to skip the user-local cache step. All bundled resource resolution (registry, rules, semgrep-rules, extension vulns) goes through the shared `resolve_bundled_resource()` helper in `_paths.py`.
- **Terminal output** includes a dim one-liner registry stats line after the summary (e.g. "Registry: 60 known servers (v1.0, updated 2026-04-20)") pulled from `ScanResult.registry_stats`; omitted silently if `registry_stats` is `None`.
- **SARIF output** adds a `run.properties` block with `mcp-audit/grade`, `mcp-audit/numericScore`, `mcp-audit/positiveSignals`, and `mcp-audit/deductions` when `ScanResult.score` is not `None`; the block is absent when `--no-score` suppresses scoring.
- `SupplyChainAnalyzer` accepts `registry=KnownServerRegistry` or `registry_path=Path` in `__init__` to allow test injection without touching the filesystem.
- `TransportAnalyzer` accepts an optional `registry=KnownServerRegistry` in `__init__` to tier `TRANSPORT-003` severity by registry membership: verified entries suppress the finding, known-but-unverified entries fire at LOW, unknown packages fire at MEDIUM. `get_default_analyzers()` and `cli/scan.py::_build_custom_analyzers` share the same `SupplyChainAnalyzer.registry` instance so the JSON is read from disk exactly once per scan. Constructing `TransportAnalyzer()` without a registry preserves the historic "always MEDIUM" behaviour for tests that don't need the registry path.
- **Every Finding carries an OWASP MCP Top 10 mapping** in `Finding.owasp_mcp_top_10` (list of `MCP01`–`MCP10` codes; empty list = unmapped). The single source of truth for codes/names is `src/mcp_audit/owasp_mcp.py`. SARIF output exposes the mapping via a `runs[0].taxonomies` block and per-rule `relationships`. The full per-finding-ID mapping is documented in `docs/severity-framework.md`. Terminal output shows codes inline; `credenzo scan --owasp-report` prints a category-level aggregation.
- **Community rules always run.** The policy-as-code rule engine loads `rules/community/` for every scan. Authoring tools (`rule validate`, `rule test`) and custom rule directories (`--rules-dir`, `<user-config-dir>/mcp-audit/rules/`; path resolved via `platformdirs`) are available to everyone — gating has been removed. The engine is invoked via `_run_rules_engine()` in `scanner.py` after all built-in analyzers complete. Rule findings use `analyzer="rules"` and `id=rule.id`.
- **Rule engine resolution order** for community rules: PyInstaller `sys._MEIPASS/rules/community/` → `importlib.resources` (installed wheel at `mcp_audit/rules/community/`) → dev repo-root fallback (`rules/community/`).
- **Supply chain attestation** (`attestation/`) implements Layer 1 hash-based integrity verification. `scan --verify-hashes` downloads package tarballs, computes SHA-256, and compares against pins in `RegistryEntry.known_hashes`. `credenzo verify` is a standalone command for interactive package verification. Attestation findings use `analyzer="attestation"`; CRITICAL for mismatches, INFO for unverifiable cases. See `docs/supply-chain.md`.
- **`scan()` pipeline conventions** (`cli/scan.py`): the `scan` command is a thin orchestrator that delegates each optional phase to a named helper. Helpers are `_apply_*` for pipeline stages that mutate/inject into `ScanResult` (baseline drift, governance, SAST, extensions, agent-files, advisory feed, severity threshold) and `_write_*` for output-layer dispatch (`_write_formatted_output`). Preflight validation lives in `_preflight_checks`. Each helper has a docstring that states when it is called and its contract when the feature is not requested. Future scan-pipeline additions should follow this `_apply_*` / `_write_*` naming and be inserted into `scan()` as a single-line delegation — do not inline new phases in the command body. Test-patched symbols (`verify_server_hashes`, `discover_extensions`, `analyze_extensions`, `run_semgrep`) are imported as their containing module (e.g. `from mcp_audit.sast import runner as _sast_runner`) so `patch("mcp_audit.sast.runner.run_semgrep", ...)` continues to intercept.
- **Capability tags for toxic flow detection** are stored in `RegistryEntry.capabilities` (optional `list[str]` in `registry/known-servers.json`) and consulted by `analyzers/toxic_flow.py::tag_server(server, registry=...)` **before** any keyword or tool-name heuristic fallback. When `registry` is supplied and resolves a known package whose `capabilities` field is not `None`, those tags are returned verbatim — the registry is the single source of truth. The in-module `KNOWN_SERVERS` dict in `toxic_flow.py` is retained as a deterministic fallback for (a) unit tests that inject no registry and (b) cases where the registry is present but the entry has `capabilities=None`. `scanner.py` passes the `SupplyChainAnalyzer.registry` instance to `ToxicFlowAnalyzer(registry=…)` so the JSON file is read from disk exactly once per scan.
  Rules that follow from this (history and measurements: `docs/archive/claude-md-2026-11-16.md`):
  - The registry overrides the heuristics, so an incomplete `capabilities` list on an entry is worse than no list. Declare every capability.
  - `scripts/audit_registry.py` runs four offline checks before its network loop: undeclared capabilities, capability strings that are not `Capability` members, dead capabilities (against `toxic_flow.KNOWN_TAG_ONLY_CAPABILITIES`, where every entry needs a reason), and entries whose whole capability set is tag-only. `tests/test_audit_registry.py` pins all four clean against the shipped registry. Run it with `uv run python3`: the script refuses to measure an `mcp_audit` that is not this repo's.
  - `Capability.CLOUD` is tag-only on purpose. `FILE_WRITE + SHELL_EXEC` is `INTEG-001` in `INTEGRITY_PAIRS`, a separate list from `TOXIC_PAIRS`; consumers use `TOXIC_AND_INTEGRITY_PAIRS`. `FILE_WRITE + NETWORK_OUT` was measured twice and declined (GAPS.md, "FILE_WRITE integrity axis").
  - `Capability.COMMS_OUT` is a wired sink (`TOXIC-008..011`); its keyword rule matches platform names as whole tokens and skips path arguments. Measurements: `docs/severity-framework.md`.
  - The registry-submission issue template has exactly one checkbox per `Capability` member (`tests/test_registry_submission_template.py`).

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
  **MEM-003/MEM-004** (STORY-0098: imports from outside the folder or of a
  `.gitignore`'d file; heartbeat output suppression) also run in a default
  `scan`/`check` (cwd-root instruction files, skipped when cwd is `$HOME`, plus
  `~/.openclaw/workspace/HEARTBEAT.md`) and in `scan --project`, through
  `agent_files/reach.py`; findings are deduplicated across the three paths
  (`reach.finding_key`) and only a symlink leaving the folder (TRUST-002 HIGH)
  is reported on the first two. `tests/conftest.py` stubs the user heartbeat
  lookup.
  **HOOK-001/002** (network-egress and config-write hook commands) deliberately
  live in `analyzers/config_hygiene.py::analyze_config` (pipeline step 0), not in
  `agent_files/`, because they inspect the parsed `hooks` section of a Claude config
  file; they are distinct IDs from CFHYG-005 (which fires on mere presence of a
  `hooks` section) and the conditions do not overlap.
  **Subagent definitions** (`.claude/agents/**/*.md`, STORY-0094) are the exception
  to "not part of the pipeline": their frontmatter is a config surface, so the files
  are `DiscoveredConfig`s (client `claude-code-agent`), `parse_config()` reads their
  inline `mcpServers`, and AGENT-001..004 + HOOK-001/002 run at step 0 in the default
  `scan`/`check` and `scan --project` (`discover_project_agent_configs`, kept out of
  `discover_project_configs` so `lock` never sees them). Only their body text follows
  the skills opt-in (`--include-agent-files`, which passes `include_definitions=False`).

## Critical implementation details

- **VS Code uses `"servers"` as its MCP config root key; all other clients use `"mcpServers"`**
- MCP protocol communication is async — use asyncio and pytest-asyncio
- Core scanning MUST work fully offline — no network calls by default
- OSV.dev lookups **are implemented** via `scan --check-vulns` (deps.dev transitive graph + OSV.dev CVE batch query; shipped v0.6.0). The `--offline` flag enforces mutual exclusion with network-touching opt-in flags (`--verify-hashes`, `--verify-signatures`, `--check-vulns`, `--connect`); a plain scan already makes no network calls, so `--offline` is a no-op for the default configuration
- **Credenzo does not implement semver range resolution anywhere** — no semver library appears in `src/mcp_audit/vulnerability/` or `src/mcp_audit/attestation/`. For an unpinned npm server, `resolve_latest_version()` asks `registry.npmjs.org/<pkg>/latest` (the `latest` dist-tag, npm-pick-manifest's own first-preference rule) rather than computing a highest-satisfying version, so the class of resolver bug an external measurement (issue [#88](https://github.com/adudley78/credenzo/issues/88)) found in a from-scratch range resolver — preferring a higher non-`latest`-tagged version over the dist-tag — cannot reach us; we declined to implement the thing that has the bug. For PyPI, `info.version` from the PyPI JSON API is documented to report the latest **stable** release (pre-releases excluded), matching pip's/`uvx`'s/`pipx`'s own default install behaviour, so it errs the same direction a real install would. `resolver.is_version_range()` (R36) is a syntactic, non-semver detector for a config entry that carries a floating specifier (`^1.2.3`, `~1.2.3`, `>=1.0.0`, `1.2.x`, `*`, `1.0.0 - 2.0.0`, `latest`) rather than an exact pin; `check_vulnerabilities()` and `credenzo sbom` both check it before calling `fetch_transitive_deps()`, because deps.dev requires an exact `(name, version)` key and 404s on a range — without the check, that 404 was caught by `fetch_transitive_deps()`'s own `except URLError/HTTPError` and silently degraded to a top-level-only result carrying the literal range string as its "version," with no warning. Both call sites now resolve a concrete version first (same as the existing "unpinned" path) and surface a visible `VULN-UNPINNED` finding / Rich console warning naming the original range and the resolved version. See "Known limitation: the published graph vs. the installed tree" in `docs/supply-chain.md` for the measured, externally-contributed error-rate bound on the deps.dev-vs-real-install gap this same issue established.
- Rug-pull state is stored in `<user-config-dir>/mcp-audit/state/state.json` (resolved via `platformdirs`; macOS: `~/Library/Application Support/mcp-audit/state/`); a one-time migration copies state files from the legacy `~/.mcp-audit/` location on first access
- **No feature gating in the package.** Credenzo is fully open source (Apache 2.0); every feature ships in every binary. Do not re-introduce conditional feature availability at any layer of `src/mcp_audit`. The one paid offer is the Credenzo Team action in `team/` (see "Business model"): it gates its own alerts, never a command.
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
- `scan --project <dir>` walks the directory tree of a repository for project-level MCP config files (`.mcp.json`, `.cursor/mcp.json`, `.claude/settings.json`, `.claude/settings.local.json`, `.cursor/settings.json`, `.vscode/mcp.json`, `.amazonq/mcp.json`, `.codex/config.toml`, `.gemini/settings.json`, plus the gateway files `.mcptoon.json`, `.mcptoon.toml` and `.mcphub/servers.json`) and emits `TRUST-001` (HIGH) for every server found; runs the full analyzer pipeline on project-scoped servers too; tree walk caps at depth 8, skips `node_modules`/`.git`; `--project` path is validated to exist (exit 2 on failure); use before opening a freshly cloned repo in an AI editor; additive — default scan is unchanged. CWE-829 / OWASP MCP09. **Symlink handling (TRUST-002/TRUST-004/TRUST-005, added 2026-09-08):** a symlinked directory is still never followed (unchanged loop/blow-up protection) but now emits `TRUST-005` (LOW) naming it instead of vanishing silently; a symlinked config/agent-file *candidate* is included and parsed normally (coverage was never actually at stake — `Path.read_text()` follows a symlink transparently) and reported as `TRUST-002` (HIGH outside the scanned root, MEDIUM inside, INFO if broken) for project/cwd-scoped candidates or `TRUST-004` (always INFO — the GNU Stow/chezmoi/yadm dotfile-manager shape) for user-global/explicit ones. Applies uniformly across `discovery.py` (six sites) and `agent_files/discovery.py` (three sites). A config candidate reached through a symlinked parent directory (`.claude -> /elsewhere`) is treated like a symlinked file (`is_symlink=True`, TRUST-002) in both the `--project` walk and the default scan's cwd check (STORY-0108, `discovery._reached_through_symlink`, the rule STORY-0090 applies to auto-run files); agent-file discovery never descends a symlinked parent (TRUST-005). See `humans/decisions/2026-09-08-trust-002-symlink-sites.md` (marcus repo).
- **CI workflows (STORY-0091).** A scan with no explicit path reads `<cwd>/.github/workflows/` through `ci_workflows.scan_workflows()` in `scanner._discover_and_parse` (findings are scored, like plugin findings; `check` no longer short-circuits to "No MCP config files found" when findings exist); `--project` reads the project and nested repo roots in `_apply_project_scan`, de-duplicated against the cwd copy. `analyzer="ci_workflow"`, `client="github-actions"`, `server`=job id, `tool`=step. No `action.yml` change was needed: the Action's default run is a cwd scan.
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
  use, so records join to the rest of Credenzo's output without translation, and
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
  `expires` are Credenzo fields on `index.json` (`feed_version` 1.1). They are never
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
- Run `./scripts/update_test_count.py` before tagging a release (or after any PR that changes test count, SAST rule count, community rule count, or analyzer count) to sync all hand-maintained count references in `README.md` and `CLAUDE.md`. The script now covers: test count, SAST rule count (total + Python/TypeScript breakdown), community rule count, concrete analyzer count, and the release pin (`v<pyproject version>`): every `uses: adudley78/credenzo[/setup-action]@` tag or `@main` ref and pinned `version:` input in README.md and the Action docs (`_ACTION_REF_DOCS`, `_VERSION_INPUT_DOCS`), every pre-commit `rev:` for this repo (`_PRE_COMMIT_PIN_FILES`), and `credenzo==` in `docs/enterprise-deployment.md`; prose citing an old release is never rewritten, and `tests/test_update_test_count.py` fails if any example takes a shape the script would miss (STORY-0102), so a release PR fails `--check` until it updates them. CI runs the same script with `--check` on the ubuntu/py3.12 leg and fails on drift.
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

## Current state

What each feature does is in `README.md`, `docs/README.md` (the index of every document) and `CHANGELOG.md`. Known limits are in `GAPS.md`. The long feature history that used to be here is in `docs/archive/claude-md-2026-11-16.md`.

Counts that `scripts/update_test_count.py` keeps in sync:

- 8 analyzers: poisoning, credentials, transport, supply chain, rug-pull, toxic flow, config hygiene, auth
- 11053 tests passing; `ruff check src/ tests/` clean (zero errors); `ruff format src/ tests/` clean (zero files requiring reformatting) — verify with `uv run pytest --collect-only -q` before each release
- 35 top-level CLI commands: affected, vet, reach, check, fix, run, guard, wrap, unwrap, scan, discover, pin, diff, lock, dashboard, watch, version, update-registry, merge, verify, sast, sbom, push-nucleus, shadow, killchain, snapshot, register, advise, baseline (5 sub-commands: save, list, compare, delete, export), rule (3 sub-commands: validate, test, list), policy (3 sub-commands: validate, init, check), extensions (2 sub-commands: discover, scan), agent-files (2 sub-commands: discover, scan), plugins (2 sub-commands: discover, scan), feed (1 sub-command: verify) — verify with `credenzo --help` before each release
- 56-entry curated dataset of legitimate MCP servers (`registry/known-servers.json`, `docs/registry.md`)
- 42 community rules ship bundled; the breakdown is under "Data files at project root" above
- Demo: 75 findings on a first scan of `demo/configs/` (67 once rug-pull state exists; 76 and 68 up to 0.33.0, before STORY-0171 moved the bare "do not mention" out of POISON-012; POISON-070 still reports that text). Recount before each release: `credenzo scan --path demo/configs/ --format json`

## Provenance

All detection patterns are original implementations based on published security
research. No code was copied from existing scanners. Full source attribution is
documented in PROVENANCE.md — read it before adding new detection patterns.
Every new pattern must cite its research source.
The project now has 8 analyzers with patterns sourced from the research listed in PROVENANCE.md. Update PROVENANCE.md when adding new detection patterns or analyzers.
See GAPS.md for known detection quality limitations, severity calibration issues, and untested areas. Consult before claiming detection completeness or accuracy.

## Commit history audit (2026-04-17)

A full audit of the git history before the public release found no real credentials, internal URLs or key material. Every match was a synthetic test fixture (for example the `ghp_aBcDeF…` and `sk-abcdef…` strings in tests, Semgrep rule fixtures and `demo/configs/`). The full record is in `docs/archive/claude-md-2026-11-16.md`.

## Release engineering

### PyInstaller path resolution — test coverage (2026-04-17)

| Behaviour | Test coverage | Notes |
|---|---|---|
| `_resolve_bundled_path()` returns `_MEIPASS/registry/known-servers.json` when `sys.frozen=True` | `tests/test_registry.py::TestMeipassResolution` | Patches `sys.frozen` + `sys._MEIPASS` via `monkeypatch` |
| `KnownServerRegistry` loads from a simulated `_MEIPASS` layout | `tests/test_registry.py::TestMeipassResolution::test_frozen_registry_loads_via_patched_bundled_path` | Monkeypatches `BUNDLED_REGISTRY_PATH` |
| Corrupt PyInstaller bundle (missing registry file) raises `FileNotFoundError` | `tests/test_registry.py::TestMeipassResolution::test_locate_raises_when_bundled_path_missing` | Both user-cache and bundled path missing |
| Binary entry point and bundled data intact after build | Shared composite + `scripts/smoke_test.py` | `.github/actions/build-binary/` is invoked by CI `binary-smoke` and `release.yml` `build` |

### CI workflow (`.github/workflows/ci.yml`)

Triggers on every pull request and on pushes to `main` (until 2026-11-19 also on every branch push, which ran each pull-request commit twice and left macOS jobs waiting for a runner until their time limit). Runs a 3×2 matrix (6 combinations):
- **OS:** `ubuntu-latest`, `macos-latest`, `windows-latest`
- **Python:** `3.11`, `3.12`
- `fail-fast: false` — a failure on one leg does not cancel the others.

Each test-matrix leg runs: `pip install uv` → `uv pip install -e ".[dev]" --system` → `pytest tests/ -x -q` → `ruff check src/ tests/` → `ruff format --check src/ tests/`. The matrix uses `actions/setup-python` so uv installs into the runner's system Python via `--system`.

`wheel-check` (every push/PR) uses `setup-uv` + CPython 3.12.14, builds the wheel, fetches the publish action's `runtime.txt` at the pinned SHA, and runs that Twine (`uvx twine==… check --strict`) so a Core-Metadata bump fails on the PR, not at the tag. Hatchling stays unpinned; the Twine version is not copied into `ci.yml`.

The workflow status badge is in `README.md`.

### Release workflow (`.github/workflows/release.yml`)

Triggers on `v*.*.*` tags (e.g. `git tag v0.2.0 && git push --tags`), and on `workflow_dispatch`: a dry-run of the `build` job (no GitHub Release, no PyPI) unless dispatched on a `vX.Y.Z` tag with `publish: true`, which is how `release-on-version-bump.yml` starts a release. Builds four binaries in parallel, then creates a GitHub Release with all four attached and auto-generated release notes.

**Merging a version bump to `main` is the release (R73, 2026-10-15).** `.github/workflows/release-on-version-bump.yml` runs on pushes to `main` that touch `pyproject.toml`; `scripts/release_gate.py tag` tags the commit (through the refs API, which refuses an existing tag) only if that commit itself changed `[project].version` (compared with its parent), the version is untagged and above every release tag, and CHANGELOG has a non-empty `## [X.Y.Z]` section (checked with `compose_release_notes.extract_changelog_section`, the same parser the `release` job uses, so empty notes can't fail `release` after `publish-pypi` has used up the version). It then dispatches `release.yml` on the tag with `publish=true`, because a tag pushed with `GITHUB_TOKEN` starts no workflow. Every publishing job in `release.yml` (`release`, `publish-pypi`, `tag-major`) needs the `gate` job (`scripts/release_gate.py publish`): the ref must be a `vX.Y.Z` tag on `main` matching `pyproject.toml`, with a non-empty CHANGELOG section and no higher release tag, and a dispatch must say `publish: true` (a plain dispatch is decided as a dry run before anything is read); every refusal fails the run with its reason. `release.yml` has `concurrency: release-${{ github.ref }}` so a tag never runs twice at once. Recovery when the tag exists but the dispatch failed: `gh workflow run release.yml --ref vX.Y.Z -f publish=true` (re-running the bump workflow only reports "already tagged"). Do not switch the tag push to a personal token (it would start `release.yml` by itself and the dispatch would publish a second run). Pinned by `tests/test_release_gate.py` and `tests/test_ci_binary_smoke.py::test_release_dispatch_is_a_dry_run`.

**Shipped binaries are built by `.github/actions/build-binary/`.** CI `binary-smoke` and this workflow's `build` job both call it (CPython 3.12.14 via `uv python install`, `uv sync --all-extras`, spec, PyInstaller, PYZ inspect, smoke, size). Do not copy those steps into either workflow. History of the three CI/release drifts: `docs/building-binaries.md`.

| Runner | Spec file | Output binary |
|---|---|---|
| `macos-15-intel` | `mcp-audit-darwin-x86_64.spec` | `mcp-audit-darwin-x86_64` |
| `macos-latest` | `mcp-audit-darwin-arm64.spec` | `mcp-audit-darwin-arm64` |
| `ubuntu-latest` | `mcp-audit-linux-x86_64.spec` | `mcp-audit-linux-x86_64` |
| `windows-latest` | `mcp-audit-windows-x86_64.spec` | `mcp-audit-windows-x86_64.exe` |

> `macos-15-intel` builds the x86_64 macOS binary (`macos-13` was retired on 2025-12-08; `macos-latest` is arm64 and would silently produce the wrong architecture). GitHub supports the Intel label through 2027-08.

### PyInstaller spec files

Four spec files live at the repo root: `mcp-audit-darwin-x86_64.spec`, `mcp-audit-darwin-arm64.spec`, `mcp-audit-linux-x86_64.spec`, `mcp-audit-windows-x86_64.spec`. All use a portable SPECPATH-relative root instead of hardcoded absolute paths:

```python
import os
root = os.path.dirname(os.path.abspath(SPECPATH))
```

All four specs include identical `datas` (7 entries: `mcp_audit/data`, the three registry JSONs — `known-servers.json`, `known-extension-vulns.json`, `known-malicious.json` — `rules/community/`, `semgrep-rules/`, and the vendored OSV schema; `tests/test_pyinstaller_specs.py` pins the registry files) and the same full `hiddenimports` list. The only difference between specs is the `name=` field in the `EXE` block.
