# `mcp-audit affected`

*Is this advisory in my agent stack?* One command, one answer per server.

```bash
mcp-audit affected CVE-2025-53109                 # an advisory ID
mcp-audit affected MAL-2026-4068                  # an OSV malicious-package ID
mcp-audit affected x_MCPRS-4ad8c07d80d7           # a research record (Plugin4Shell)
mcp-audit affected litellm@==1.107.0              # a package and a version range
mcp-audit affected '@modelcontextprotocol/server-filesystem@<2025.7.1'
```

It reads every MCP server mcp-audit discovers (all supported clients, Codex and Gemini CLI, gateway upstreams, plugin and subagent servers) and prints one of three answers for each:

| Answer | Meaning |
|---|---|
| **AFFECTED** | The server runs the package at a version the advisory covers. The row says which version, where it came from, and the fixed version if there is one. |
| **NOT AFFECTED** | mcp-audit can show why: the server runs the package at a version the advisory does not cover (at or above the fix, or outside the listed range), or it runs a different package. |
| **COULDN'T CHECK** | mcp-audit cannot tell. The row says why. This is never reported as not affected. |

Exit code: `0` nothing affected, `1` something affected, `2` error. `--fail-on-unknown` also exits `1` when anything is COULDN'T CHECK, including a remote server or a config file that could not be parsed.

## Where the version comes from

1. The launch command's exact pin (`npx -y pkg@1.2.3`, `uvx pkg==1.2.3`).
2. Otherwise the `resolved_version` in `mcp-lock.json` for that server: the nearest lock beside the config, plus any you pass with `--lock PATH` (repeatable). The `mcp-lock.json` of an older commit works the same way; mcp-audit never runs `git` to read history.
3. Otherwise nothing: `npx -y pkg` with no pin and no lock is **COULDN'T CHECK**, with "pin it or run `mcp-audit lock`". mcp-audit does not guess what an unpinned launch will install.

## What it checks against

All offline, from files that ship with mcp-audit:

- **The registry** (`registry/known-servers.json`): CVEs recorded against a package, with the version each was fixed in. A pin below the fix is AFFECTED; at or above is NOT AFFECTED. When the fix uses calendar numbering and the pin uses semantic numbering (or the reverse), the answer comes from the entry's `semver_resumed_at` when it has one, and is COULDN'T CHECK when not (the same rule as SC-009).
- **The malicious-package mirror** (`registry/known-malicious.json`, OSV `MAL-*`): listed versions and `ranges[].events`, evaluated the way SC-008 does.
- **Research records** (`research-records.json`, see [research-records.md](research-records.md)): see below.
- **Your own range**, for `package@range`: a PEP 440 specifier set (`==1.107.0`, `<2025.7.1`, `>=1,<2`; a comma means *and*). npm's `^` and `~` shorthands are refused rather than guessed at. A bare `pkg@1.2.3` means `==1.2.3`.

An ID that none of these knows is an error (exit `2`); it does not produce a column of "couldn't check". Add `--live` to fetch it from OSV.dev (see below).

## Research records

A research record is about products (Claude Code, Codex...), not MCP servers, so the rows are per product. mcp-audit reads which Claude Code, Codex and Gemini CLI versions are installed from files only (it never runs them; see below). A product with a recorded fix and an install found is **AFFECTED** (installed version below the fix, with the path it was read from) or **NOT AFFECTED** (at or above it). With no install found, no recorded fix (Copilot, Gemini CLI), or `--path`, the row is **COULDN'T CHECK**, with what the write-up says about that product's fix. The checks the record names (for Plugin4Shell, PLUGIN-003 and PLUGIN-004) are run too; a HIGH or CRITICAL result is an AFFECTED row, and a milder one is listed as COULDN'T CHECK. Those checks look at Claude Code's plugin directory only, only for installs that kept their `.git`, and are not run with `--path`. The plugin checks themselves never produce NOT AFFECTED; only an installed version at or above the fix does. A record with no checks (ContextCrush, `x_MCPRS-32fc646f6f96`: the flaw was in Context7's service, fixed server-side) runs nothing and says so; its one product row is COULDN'T CHECK (`reason: vendor-service`) with the write-up's statement. It does not look at your servers, so it does not say whether a config launches `@upstash/context7-mcp`.

### Installed harness versions (STORY-0132)

`src/mcp_audit/harness_versions.py` reads files only, no subprocess. It looks at:

- npm global installs: `<prefix>/lib/node_modules/{@anthropic-ai/claude-code,@openai/codex,@google/gemini-cli}/package.json` (also `<prefix>/node_modules/...` for Windows) under `npm_config_prefix`, `~/.nvm/versions/node/*` (and `$NVM_DIR`), `/opt/homebrew`, `/usr/local`, `/usr`, `~/.npm-global` and `%APPDATA%\npm`.
- Claude Code's native installer: version-named entries under `~/.local/share/claude/versions/`. Anthropic's [setup page](https://code.claude.com/docs/en/setup#auto-updates) says the native installer manages the launcher `~/.local/bin/claude` as a symlink into that directory, and keeps older versions there (the launcher's target, any running version and the two newest). The target is read with `readlink` to mark which version it points at; an older copy kept beside it is COULDN'T CHECK (`not-launcher-target`), not AFFECTED, because it is not what `claude` runs.

Every install found is listed, one row each. Which one is first on `PATH` cannot be known without running it, so a note says so when there is more than one. A `package.json` over 1 MiB, not JSON, not an object, of a different package name, with a non-string or unparsable `version`, a symlink loop or a non-regular file is skipped and named in the output's notes. Homebrew casks, WinGet, apt/dnf/apk packages and the Windows native installer's layout are not read. Not run with `--path`.

## Launches it will not call clean

- A config file that cannot be parsed hides all its servers, so it appears as one COULDN'T CHECK row (and a warning) instead of silence.
- A launch that installs extra packages (`uvx --with pkg==1.2`, `npx -p pkg`, `--package`) is COULDN'T CHECK when its main package is not the one asked about, because the extra package is installed too and mcp-audit does not read it.
- A pin with extras (`litellm[proxy]==1.107.0`) is read as a pin.
- If no discovered server runs the package you named, the output says so (check the spelling) rather than printing a column of NOT AFFECTED.
- Lock files are read defensively: a regular file only, at most 8 MiB, never blocking on a FIFO or device.
- `package@<2.0` includes `2.0rc1` and `2.0.dev1`: a pre-release sorts below its release, and a security answer should not skip it.

## What it lists

By default the terminal output lists AFFECTED, COULDN'T CHECK and the NOT AFFECTED rows that run the package. Servers on other packages, and servers whose launch names no package mcp-audit can read (a remote URL, a local script), are counted in one line; `--all` lists them. A server with no readable package is COULDN'T CHECK and does trip `--fail-on-unknown`; a gate that must ignore remote servers should not use that flag.

## Output

`--format terminal` (default), `--format json`, `--format sarif`, `--format openvex`, with `-o FILE`. SARIF has one result per AFFECTED server and the query as the rule ID. JSON and SARIF paths are redacted like every other output that leaves the machine.

## `--fix` and `--apply`: pin to the advisory's fix (STORY-0127)

`affected <ID> --fix` prints the diff that pins each AFFECTED `npx`/`bunx`/`pnpx`/`uvx`/`pipx` server to a fixed version taken from the advisory itself, so it needs no network. Nothing is written. `--fix --apply` writes each config atomically with a `.bak` beside it, the same contract as `mcp-audit fix`. Re-run `affected` afterwards: the server reads NOT AFFECTED. A pin changes the config, not your lock, so run `mcp-audit lock` to record the new version.

The version is the **lowest fixed version above the one the server runs** (a release, not a pre-release); when the advisory lists several, the candidates are tried lowest first until the advisory's own rules say the server is clear, so a backport on the server's own line wins over a newer major. A registry advisory records one fix, so a pin can cross a major version; when it does the output says so. A server is **not pinned, with the reason printed**, when the advisory records no fix, none can be ordered (calendar versus semantic numbering, including the `0.x` cases the registry orders specially), no fix is above the current version, the version is unknown and several fixes are listed, the launch uses `--from`/`--with`/`--package`, the launcher is not `npx`/`bunx`/`pnpx`/`uvx`/`pipx` (a full path, `.cmd` and `cmd /c` wrappers are fine), the name is under both `mcpServers` and `servers`, or the config is TOML (Codex) or not plain JSON. One config that cannot be edited never stops the others. The existing style is kept (`pkg==1.0` stays `==`, `pkg@1.0` stays `@`, extras are kept). A config where no pin applies is not rewritten. `--apply` keeps the file's permissions (the backup gets the same), edits a symlinked config where it points, and never overwrites an earlier backup (`.bak`, then `.bak.1`, ...). The exit code still reports what was found, not what was fixed. `--fix` works with the terminal format only. Like `fix`, a rewritten file is re-serialised as indented JSON.

## Respond: what to rotate, and the policy entry (STORY-0126)

For each AFFECTED server the terminal output (and `--format json`, under `respond`) adds a **Respond** block:

- **could read:** the *names* of its environment variables, configured headers and credential-looking flags (`--token`, `--api-key`, `-H`; the value is cut however it is attached). No value is read into the output.
- **also set on:** other servers in the same config file that set any of those names, because one rotated secret is often shared.
- **credential file here:** which well-known credential files exist on this machine (the REACH-001..003 list, plus `~/.claude.json` and `~/.codex/config.toml`, and `.env` files in the working directory). Files are only `stat()`-ed, never opened.
- **saved tool text:** how many tool definitions `lock --connect --save-tool-text` saved for the server (never the text); `lock --verify --connect` shows what changed.

If an affected version ran, treat what it could read as exposed.

`--policy-out FILE` writes `{"deniedMcpServers": [...]}` for the AFFECTED servers, in the shape Claude Code's managed settings read ([Control MCP server access](https://code.claude.com/docs/en/managed-mcp)). Each entry is a `serverCommand`: the exact launch, checked with the evaluator `scan` uses for MANAGED-001..005. The file is deployed to other machines, so a command is written only when every argument is the package itself (name, optionally a version) or a launcher or transport word (`-y`, `run`, `--transport`, `sse`, ...). A URL, a path, a positional value or any other flag might be a secret, so that server gets no entry and a note says so; mcp-audit never writes a `serverName` entry, which would deny every server of that name on every machine. Limits, stated in the output: an entry blocks that exact launch only (not the package launched another way), only Claude Code reads it, and servers that could not be checked are not in it. mcp-audit writes only the file you name, never overwrites an existing file, refuses a path inside the managed-settings directory (case-insensitively) or the same path as `--output`, and writes nothing when no server is AFFECTED. In machine formats the notes go to stderr. Deploying the file is the admin's step.

## Transport tags and OpenVEX

A registry advisory can say which transports its vulnerable code runs on (`affected_transports`: `stdio`, `http`, `sse`), with `verified_by` naming who checked it and against what. A server is cleared of a tagged advisory only when it is *provably* stdio: a command launch, no URL, no `--transport`, `-t`, `--port`, `-p`, `--host`, `--sse`, `--http` or similar argument, no `sse`/`http` word in the arguments, no `envFile`, `--env-file` or `cwd` (they can load a transport), and no environment variable named `TRANSPORT`, `PORT`, `HOST`, `BIND` or `LISTEN`. Then the row reads NOT AFFECTED with the tag's source in the evidence, and `scan`'s `SC-004` leaves the CVE out and names it. Everything else keeps the advisory: untagged advisories, a tag without `verified_by`, remote URLs, a launch that could select another transport. `requires_auth` is recorded where the advisory states it and changes no verdict. Five advisories carry a tag today; `scripts/audit_registry.py` prints the count and fails on a tag it cannot use.

`--format openvex` (an advisory ID; not a range) and `scan --vex PATH` write an [OpenVEX](https://openvex.dev) 0.2.0 document. Each statement is one package URL and one advisory: `affected` (with the fix as the action), `fixed`, `not_affected` with `vulnerable_code_not_in_execute_path`, or `under_investigation` for COULDN'T CHECK. Servers on other packages say nothing. Config paths, server names and environment values are never written. When two servers run the same package and version and disagree (one stdio, one HTTP), the document carries the more cautious status, because a VEX statement is about the product. `not_affected` is written only when the version is known (a versionless package URL would claim every release); otherwise the statement is `under_investigation`. `scan --vex` states every advisory in the registry the scan used against the servers it found, offline; with nothing to state it writes no file.

## `--live`

`--live` fetches an advisory that is not bundled from OSV.dev (`/v1/vulns/{id}`, the endpoint `scan --check-vulns` already uses) and evaluates its npm and PyPI ranges. It is refused with `--offline`. Without it, nothing leaves the machine.

## `--transitive`: the dependency tree (STORY-0131)

`affected <ID or range> --live --transitive` also checks what each server pulls in. For every server whose exact version is known (a launch pin or a lock's `resolved_version`), it reads the dependency graph from deps.dev (the client `scan --check-vulns` uses; no new endpoint) and evaluates the advisory's rules against every dependency in it.

- A dependency hit is AFFECTED, with the path in the terminal output, `results[].dependency` in JSON and `properties.dependency` in SARIF: `wrapper@1.0.0 -> leftpad@1.3.0 (INDIRECT)`. deps.dev reports each node's relation (DIRECT or INDIRECT) but not the chain between, so the path is the server, the dependency and the relation. `--format openvex` names the dependency's package URL, not the server's.
- A graph that could not be read (HTTP 404, network error, over 8 MiB, malformed) or that deps.dev flags as incomplete is COULDN'T CHECK, never NOT AFFECTED. A hit in an incomplete graph is still AFFECTED.
- A server with no exact version has no graph to look up, so it is COULDN'T CHECK too. This includes servers on other packages: with `--transitive`, a floating `npx -y other-pkg` is COULDN'T CHECK because its tree is unknown.
- A dependency whose version cannot be ordered against the advisory counts as COULDN'T CHECK for the server.
- Each distinct package version is looked up once per run, and at most 100 lookups are made; the rest are COULDN'T CHECK.
- It needs `--live` (exit 2 otherwise) and is refused with `--offline` or `--bundle`. `--fix` does not pin a server affected only through a dependency, because pinning the wrapper does not change the dependency.

## `--fleet`: other machines' scans (STORY-0131)

`affected <ID or range> --fleet a.json --fleet b.json` answers from `mcp-audit scan --format json` files instead of this machine's configs, one row per machine and server. The machine is `machine_info.asset_id`, else `hostname`; two files with the same name are kept apart by file name. The scan JSON already carries each server's launch command and arguments, so no field was added; a version comes from the launch pin. Lock files are not read: a config path in a scan file belongs to another machine, so a floating launch is COULDN'T CHECK. `mcp-audit merge` output keeps findings but not servers, so it is reported as such, with a pointer to the per-machine files. The Respond block, `--policy-out`, `--fix` and `--path` read or change this machine and are refused or skipped with `--fleet`. A research-record ID (`x_MCPRS-…`) is answered from this machine's harness installs, so `--fleet` refuses it (exit 2). `--fleet` combines with `--live --transitive`.

The files are untrusted: each is opened without blocking, must be a regular file, is read up to 64 MiB, and is parsed defensively (at most 1,000 files and 10,000 servers per file). An unreadable, oversized, malformed or non-scan file becomes a COULDN'T CHECK row and a warning; a server entry that does not parse is counted and skipped.

## Measured error

The comparison itself is exact (PEP 440 ordering, OSV event order). The error is in the data, and these are the counts today:

- **Registry:** 14 packages carry advisories, in 180 structured records. 17 of them record no fixed version, so a pinned server on one of those is AFFECTED ("no fixed version recorded") and can never be shown as fixed.
- **Numbering schemes:** a version range or fix that mixes calendar and semantic numbering is COULDN'T CHECK, except where the registry records `semver_resumed_at` for the package.
- **Malicious mirror:** 217 records; 150 list explicit versions and 99 carry a blanket "every version" range. For a package in the registry, the blanket range is ignored when the record also lists versions (the SC-008 rule).
- **Coverage:** an advisory the registry, the mirror and the research records do not hold is not answered offline. The registry's CVE history is curated, not NVD; a package missing a CVE here is not evidence that it has none.
- **Version:** a version mcp-audit cannot parse, or order against the fix, is COULDN'T CHECK. An unpinned launch is COULDN'T CHECK; the floating spec's installed version can differ from a lock's if the lock is stale.

## Not in this version

- `--transitive` shows the server, the dependency and its relation, not the full chain between them (deps.dev's graph call used here does not return edges), and `--fleet` cannot use a lock's `resolved_version` (the scan JSON does not carry it).
- Installed versions of GitHub Copilot and other harnesses (no recorded fix to compare with, or no documented file layout), and package-manager or Windows-native installs of the three above.
- Fixing (`affected --fix`), exploit signals, reachability and VEX output come in later EPIC-0008 stories.

## LiteLLM and other gateways

LiteLLM's MCP gateway is in the registry (not `verified`). A launch such as `uvx litellm[proxy]==1.83.0` is read as a pin and compared with `CVE-2026-59822` (fixed in 1.84.0). A config that only points at a gateway by URL is COULDN'T CHECK: the version it runs is not in your config. `affected MAL-2026-2144` matches the compromised releases (1.82.7, 1.82.8, 1.107.0) by exact version only; every other version is NOT AFFECTED by that record. The registry takes on a gateway or SDK only when a discovered MCP config can reach it. Advisories are stored with their highest fixed version only, so a release on an older backport branch, or one older than the advisory's first affected version, can read AFFECTED when it is not.

## Air-gapped

`--bundle DIR` reads the registry, malicious list, research records and exploit signals from a signed bundle instead of the installed copies, with no network, and prints the bundle's date. See `docs/air-gapped.md`.
