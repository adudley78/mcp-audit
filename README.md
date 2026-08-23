# mcp-audit

[![CI](https://github.com/adudley78/mcp-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/adudley78/mcp-audit/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![VS Code Marketplace](https://img.shields.io/visual-studio-marketplace/v/mcp-audit.mcp-audit-vscode?label=VS%20Code%20Extension&logo=visualstudiocode&logoColor=white)](https://marketplace.visualstudio.com/items?itemName=mcp-audit.mcp-audit-vscode)

**Privacy-first security scanner for MCP server configurations.**

**Free & open source.** Apache 2.0, all features included — no paid tier, no
license keys required.

**Privacy-first:** mcp-audit collects no telemetry. Every scan runs locally.
See [docs/telemetry.md](docs/telemetry.md) for the full policy.

MCP (Model Context Protocol) servers give AI agents access to your tools, files, APIs, and databases. Misconfigured or malicious servers can exfiltrate credentials, poison tool behavior, and compromise your development environment — without anything appearing in the UI.

`mcp-audit` scans your local MCP configurations across all major AI coding clients, connects to running servers to inspect what agents actually see, and flags security issues across individual servers and dangerous cross-server combinations.

## Features

- **Auto-discovers** MCP configs across 8 clients (Claude Desktop, Cursor, VS Code, Windsurf, Claude Code user-level, Claude Code project-level, GitHub Copilot CLI, Augment Code)
- **Tool poisoning detection** — 11 regex patterns across 5 severity tiers, validated against 6 published exploit PoCs (Invariant Labs, CrowdStrike, CyberArk) with zero false positives on our published 22-server benchmark (a regression test)
- **Credential exposure** — 9 patterns covering AWS, GitHub, OpenAI, Anthropic, Stripe, Slack, and database URLs
- **Transport security** — unencrypted connections, elevated privileges (`sudo`/`doas`/`pkexec`/`su`/`run0`), wildcard bindings (`0.0.0.0`, `::`), runtime package fetching
- **Supply chain** — typosquatting detection via Levenshtein distance against 83 known-legitimate MCP servers; offline CVE advisory check (`SC-004`) against the bundled registry (`known_vulnerabilities`); SHA-256 hash verification; Sigstore SLSA provenance verification; transitive-dependency CVE lookup via OSV.dev; CycloneDX SBOM generation
- **Rug-pull detection** — stateful SHA-256 hash comparison of tool descriptions across scans
- **Cross-server toxic flows** — capability tagging and 7 dangerous pair patterns detecting multi-server attack paths (file-read + network, secrets + network, shell-exec + network, etc.)
- **Attack path engine** — multi-hop path detection with greedy hitting set algorithm (minimum set of servers to remove to break all attack paths)
- **Interactive attack graph dashboard** — `mcp-audit dashboard` opens a D3 force-directed graph in your browser with light/dark mode, click-to-highlight attack paths, and hitting set recommendations
- **Live server analysis** — connects to running servers via MCP protocol to inspect actual tool definitions; `--connect` mode also detects tool-name collisions across servers (`COLLIDE-001`) — the namespace-shadowing attack named in NSA's MCP security guidance
- **Project-level config scan** — `scan --project <dir>` walks a cloned repo for project-level MCP config files and emits `TRUST-001` (HIGH) before you click "Trust this folder" in your AI editor (Adversa TrustFall / CVE-2026-30615)
- **SAST rule pack** — 89 Semgrep rules (46 Python, 43 TypeScript) across 6 categories for MCP server source code
- **IDE extension scanner** — known-vuln registry, dangerous capability combos, wildcard activation, unknown publisher, sideloaded VSIX, stale AI extensions
- **Agent-file scanner** — scans the other instruction surfaces the AI agent reads: Claude Code custom commands, Cursor rules, GitHub Copilot instruction/prompt files, and CLAUDE.md memory files; also detects network-egress and config-persistence patterns in Claude Code hook commands (CVE-2026-30615); `mcp-audit agent-files scan` or `mcp-audit scan --include-agent-files`
- **Signed advisory feed** — there is no CVE/OSV/NVD equivalent for MCP servers, so `mcp-audit advise` publishes one: findings become OSV 1.6.0 records with OWASP MCP Top 10 metadata, canonicalized (RFC 8785) and signed with cosign, ready for any osv-scanner-compatible consumer; `mcp-audit feed verify` checks the whole feed; see [`docs/advisory-feed.md`](docs/advisory-feed.md) and the committed [`examples/feed/`](examples/feed/)
- **Config hygiene** — `ConfigHygieneAnalyzer` detects missing descriptions, duplicate tool names, and other structural config issues
- **CVE tagging** — findings carry a `Finding.cve` field so matched CVEs surface in JSON, SARIF, and terminal output
- **Authentication checks** — `AUTH-001` flags remote HTTP/SSE servers with no auth material (HIGH for public hosts, MEDIUM for private/RFC 1918); `AUTH-002` flags OAuth-configured servers missing RFC 8707 audience binding; backed by arXiv 2605.22333 (40.55% of 7,973 live remote MCP servers unauthenticated)
- **Governance + policy-as-code** — YAML governance policies (approved server lists, score thresholds, transport constraints) and custom detection rules; 34 community rules ship bundled and run for every user
- **OWASP MCP Top 10 mapping** — every finding carries `MCP01`–`MCP10` codes in terminal, JSON, and SARIF (taxonomy block + per-rule relationships); `--owasp-report` prints a polished 10-category table with worst-finding summaries and "Coverage: 10/10" line; machine-readable mapping at [`docs/owasp-mapping.json`](docs/owasp-mapping.json); see [`docs/owasp-mcp-top-10.md`](docs/owasp-mcp-top-10.md)
- **5 output formats** — terminal (Rich), JSON, SARIF (GitHub Security tab), Nucleus Security FlexConnect, self-contained HTML dashboard
- **Continuous monitoring** — `mcp-audit watch` monitors config files in real-time and re-scans on any change
- **Fleet deployment** — machine-tagged output with `--asset-prefix` for enterprise-wide aggregation
- **Fully offline by default** — no data leaves your machine

## Enterprise vulnerability management

MCP security findings typically exist in isolation: a developer runs a scanner, sees terminal output, maybe fixes something. Enterprises deploying AI agents across hundreds of developers need the same workflow they use for every other vulnerability class — centralized ingestion, asset correlation, deduplication, ownership, remediation tracking, and SLA reporting.

`mcp-audit`'s `--format nucleus` output and `mcp-audit push-nucleus` command align with the [Nucleus Security](https://nucleussec.com) FlexConnect schema — the same ingestion pipeline that normalizes data from Qualys, Tenable, CrowdStrike, and 200+ other security tools. Validated end-to-end against a live Nucleus instance on 2026-04-23; see [`docs/nucleus-integration.md`](docs/nucleus-integration.md).

Tenable WAS has added MCP server detection plugins that scan server-side code for web vulnerabilities, but no other standalone MCP configuration scanner bridges developer-side config analysis (tool poisoning, credential exposure, toxic flows, supply chain risks) with enterprise vulnerability management. Most output to terminal or JSON and stop there.

## Free & open source

mcp-audit is released under the [Apache License 2.0](LICENSE) and every
feature is available to every user. There are no paid tiers, license keys,
or gated commands — the full scanner, rule authoring, governance, SAST
integration, extension scanning, dashboard, fleet merge, and Nucleus
FlexConnect output all ship in the same binary.

---

## Install

```bash
pip install mcp-audit-scanner
```

or with [uv](https://docs.astral.sh/uv/):

```bash
uv add mcp-audit-scanner
```

> **Note:** The PyPI package name is `mcp-audit-scanner` (the `mcp-audit` name
> was already taken). The CLI command is still `mcp-audit`.
> Standalone binaries are also available on
> [GitHub Releases](https://github.com/adudley78/mcp-audit/releases).
> Each run of a standalone binary is silent for about ten seconds while it starts; that is expected.
> Each release attaches a CycloneDX 1.5 SBOM per binary (`mcp-audit-<platform>.cdx.json`)
> plus `mcp-audit-scanner-wheel.cdx.json` for the PyPI wheel. See
> [docs/building-binaries.md](docs/building-binaries.md#release-sboms).

For live server connection support:

```bash
pip install 'mcp-audit-scanner[mcp]'
```

For Sigstore-based signature verification (`scan --verify-signatures`):

```bash
pip install 'mcp-audit-scanner[attestation]'
```

> **Note:** `scan --verify-hashes` uses stdlib SHA-256 and works without any extra.
> The `[attestation]` extra is only needed for Sigstore/Rekor signature verification.

### macOS notes

If `pip install` fails with `bad interpreter: /usr/bin/python: no such file or directory`, invoke pip through Python directly:

```bash
python3 -m pip install mcp-audit-scanner
```

After installing, if `mcp-audit` is not found in your shell, add Python's bin directory to your PATH:

```bash
echo 'export PATH="/Library/Frameworks/Python.framework/Versions/3.12/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

If you installed via Homebrew Python, the path will be different — use `python3 -c "import sys; print(sys.prefix)"` to find it and append `/bin`.

## Quick start

```bash
mcp-audit vet @modelcontextprotocol/server-filesystem # Before you install
mcp-audit check                                       # One-command security verdict (start here)
mcp-audit check --verbose                             # Full scan output (equivalent to scan)
mcp-audit check --json | jq '.score.grade'            # Machine-readable grade
mcp-audit scan --project ./cloned-repo                # Before you trust a freshly cloned repo
mcp-audit shadow                                      # Find shadow MCP servers on this machine
mcp-audit shadow --format json | jq .                 # JSON output for syslog / SIEM
mcp-audit shadow --allowlist .mcp-audit-allowlist.yml # Classify against an allowlist
mcp-audit shadow --continuous                         # Daemon: emit events on config change
mcp-audit scan                                        # Scan all detected MCP configs
mcp-audit scan --connect                              # Also connect to running servers
mcp-audit scan --format sarif -o results.sarif        # SARIF for GitHub Security
mcp-audit scan --format nucleus -o results.json       # Nucleus FlexConnect output
mcp-audit dashboard                                   # Open interactive attack graph dashboard
mcp-audit dashboard --path demo/configs               # Dashboard against demo data
mcp-audit discover                                    # List detected clients and servers
mcp-audit pin                                         # Lock current state as trusted baseline
mcp-audit diff HEAD~1 HEAD                            # MCP-aware diff between two git commits
mcp-audit diff HEAD~1 HEAD --format pr-comment        # Markdown output for PR comments
mcp-audit diff configs/before/ configs/after/         # Compare two config directories
mcp-audit watch                                       # Monitor configs and re-scan on changes
mcp-audit push-nucleus --url ... --project-id ...     # Scan and push to a Nucleus project
mcp-audit merge --dir ./scans                         # Merge multi-machine JSON outputs
mcp-audit killchain                                   # Top 3 changes to cut blast radius
mcp-audit killchain --input scan.json --top 5         # From saved scan, show top 5
mcp-audit killchain --patch yaml -o report.md         # With governance policy patch
mcp-audit snapshot --output snapshot.json             # Forensic CycloneDX snapshot
mcp-audit snapshot --format native -o snap.json       # mcp-audit-native JSON
mcp-audit snapshot --sign --output snapshot.json      # Sigstore-signed snapshot
mcp-audit snapshot --stream | vector --config ...     # NDJSON stream to SIEM/EDR
mcp-audit snapshot --rehydrate old-snapshot.json      # Reconstruct historical attack graph
```

The three primary practitioner verbs — before, after, and fix:

```bash
mcp-audit vet @scope/your-server   # Before you install: registry status + known CVEs
mcp-audit check                    # After installing: one-command security verdict
mcp-audit fix --apply              # Fix detected issues automatically
```

## For MCP server authors

If you publish an MCP server package, you can show users your registry status and
known CVE count with a Shields.io badge:

```bash
mcp-audit vet @your-scope/your-mcp-server --badge
```

This prints a Markdown snippet you can paste directly into your README:

[![mcp-audit verdict](https://img.shields.io/endpoint?url=https://mcp-audit.dev/v1/badge/npm/at-modelcontextprotocol-server-filesystem.json)](https://mcp-audit.dev/v1/verdicts/npm/at-modelcontextprotocol-server-filesystem.json)

The badge shows **registry verification status** (confirmed maintainer link) and
**known CVE count** — two facts, nothing more. It is not a security grade or
endorsement. See [docs/badge.md](docs/badge.md) for the full specification: what the
badge asserts, what it does not assert, and how badge data updates.

**Your package not listed?** The badge shows `unknown` (grey) until your entry is
added to the registry. Add it in ~5 minutes:

1. Run `mcp-audit vet @your-scope/your-server` to see what users see today.
2. [Open a registry submission issue](https://github.com/adudley78/mcp-audit/issues/new?template=registry-submission.yml)
   or edit `registry/known-servers.json` and open a PR.
3. Once merged, your badge turns green (`verified · 0 known CVEs`).

See [docs/registry-contributions.md](docs/registry-contributions.md) for the entry
format and verification standard.

## Find your shadow MCP servers (OWASP MCP09)

**[OWASP MCP09: Shadow MCP Servers](https://owasp.org/www-project-mcp-top-10/)** — MCP servers
running on a developer's machine without the security team's knowledge or approval are one of
the top risks in the OWASP MCP Top 10. The `mcp-audit shadow` command gives you a single
command to surface every one:

```bash
# Sweep all known MCP config locations on this machine
mcp-audit shadow

# Classify against your org's approved server list
echo "sanctioned_servers:" > .mcp-audit-allowlist.yml
echo "  - '@modelcontextprotocol/server-filesystem'" >> .mcp-audit-allowlist.yml
mcp-audit shadow --allowlist .mcp-audit-allowlist.yml

# Continuous daemon — emits events when configs change
mcp-audit shadow --continuous --format json | logger -t mcp-audit-shadow
```

Each server is classified as `sanctioned` (in your allowlist) or `shadow` (not), with a
risk score (`INFO` → `UNKNOWN`) derived from capability tags and toxic-flow analysis.
JSON output is pipeline-ready: pipe to `jq`, syslog, or your SIEM directly.

See [`docs/shadow-mcp.md`](docs/shadow-mcp.md) for the full reference including allowlist
format, launchd/systemd wiring, and the JSON output schema.

## Kill-chain remediation engine

`mcp-audit killchain` is the decision engine on top of the attack-path graph.
Instead of listing findings, it answers: **"Here are the 3 changes that fix everything."**

```bash
mcp-audit killchain                          # Fresh scan → top 3 recommendations
mcp-audit killchain --input scan.json        # From a saved scan result
mcp-audit killchain --top 5                  # Top 5 recommendations
mcp-audit killchain --patch yaml             # Include governance policy patch
mcp-audit killchain --format json            # Machine-ingestible JSON
```

Each recommendation includes the specific server and capability to restrict, the
number of attack paths it eliminates, and a one-line rationale. A what-if
simulation shows the resulting blast radius if all recommendations are applied.

See [`docs/killchain.md`](docs/killchain.md) for the full reference.

## PR-comment diff for team adoption

The fastest way to spread MCP security awareness across an engineering team is
`mcp-audit diff --format pr-comment`. Every pull request that touches an MCP
config gets an automatic summary posted to the PR conversation tab — reviewers
see what changed (added servers, new tools, credential refs, external endpoints)
and the risk classification, without leaving GitHub.

```bash
# Preview locally
mcp-audit diff HEAD~1 HEAD --format pr-comment

# Block a PR on MEDIUM+ MCP changes and post a comment
mcp-audit diff base.json head.json \
  --format pr-comment \
  --severity-threshold medium \
  > diff-output.md
```

**Copy-paste GitHub Actions workflow** — scan base and head commits separately,
then post the diff as a PR comment via `github-script`:

```yaml
- uses: actions/checkout@v4
  with: { fetch-depth: 0 }

- uses: adudley78/setup-mcp-audit@v1

- run: git checkout ${{ github.event.pull_request.base.sha }}
        && mcp-audit scan --format json -o base.json || true

- run: git checkout ${{ github.event.pull_request.head.sha }}
        && mcp-audit scan --format json -o head.json || true

- run: mcp-audit diff base.json head.json --format pr-comment
        --severity-threshold medium > diff-output.md
  continue-on-error: true

- uses: actions/github-script@v7
  with:
    script: |
      const body = require('fs').readFileSync('diff-output.md', 'utf8');
      await github.rest.issues.createComment({
        ...context.repo, issue_number: context.issue.number, body });
```

Full workflow at [`examples/github-actions/diff-pr-comment.yml`](examples/github-actions/diff-pr-comment.yml).
For a one-step setup using the composite action, see
[`examples/github-actions/diff-mode.yml`](examples/github-actions/diff-mode.yml).

See [`docs/diff.md`](docs/diff.md) for input formats, severity table, and edge cases.

## Supported clients

| Client | Config location |
|--------|----------------|
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Cursor | `~/.cursor/mcp.json` |
| VS Code | `.vscode/mcp.json` (workspace) |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |
| Claude Code (user) | `~/.claude.json` |
| Claude Code (project) | `.mcp.json` (project root) |
| GitHub Copilot CLI | `~/.copilot/mcp-config.json` |
| Augment Code | `~/.augment/settings.json` |

## What it detects

| Analyzer | Finding IDs | Examples |
|----------|-------------|---------|
| Tool poisoning | 11 patterns (POISON-001 – POISON-050) | SSH key exfiltration instructions, XML injection markers (`<IMPORTANT>`), behavioral overrides ("ignore previous instructions"), zero-width Unicode stealth characters |
| Credential exposure | CRED-001…009 | AWS access keys, GitHub tokens, OpenAI/Anthropic API keys, Stripe secrets, database connection strings with embedded passwords |
| Transport security | TRANSPORT-001…003 | Unencrypted remote SSE connections, elevated privilege execution, runtime package fetching via `npx`/`uvx` without version pinning |
| Supply chain | SC-001…003 | Typosquatted package names (`@modelcontextprotocol/server-filesytem` vs `server-filesystem`), distance-1 substitutions flagged CRITICAL |
| Rug-pull | RUGPULL-001…003 | Tool description changed since last scan (HIGH), new server appeared (INFO), previously tracked server removed (INFO) |
| Toxic flow | TOXIC-001…007 | File-read server + network server (exfiltration path), secret-access server + network server (credential theft), shell-exec server + network server (arbitrary command + exfiltration) |

## Live server analysis

By default, `mcp-audit` performs static analysis — it reads config files and inspects the command, args, env vars, and any tool descriptions stored there.

The `--connect` flag goes further: it connects to each server using the MCP protocol, completes the initialization handshake, and calls `list_tools()`, `list_resources()`, and `list_prompts()` to retrieve the actual definitions the server exposes to the AI agent. Those live definitions are then run through the poisoning analyzer.

This matters because a config file can look completely clean while the server it points to is serving poisoned tool descriptions. Static analysis cannot catch this. Connection-based analysis can.

```bash
mcp-audit scan --connect
```

Requires the optional MCP SDK dependency:

```bash
pip install 'mcp-audit-scanner[mcp]'
```

Connection is best-effort: servers that do not respond within 10 seconds produce an error finding rather than crashing the scan. All static analysis still runs regardless.

## Cross-server attack paths

Most MCP security analysis focuses on individual servers. That misses an entire category of risk.

Server A reads files. Server B makes HTTP requests. Neither is malicious alone — they each do exactly what the config says. Together, a prompt injection can instruct the agent to read your SSH keys with A and POST them to an attacker's endpoint with B. No single server ever looked dangerous.

`mcp-audit` detects 7 categories of these toxic combinations by tagging each server with capability labels (`FILE_READ`, `NETWORK_OUT`, `SHELL_EXEC`, `DATABASE`, `SECRETS`, etc.) and checking every server pair for known-dangerous combinations:

| ID | Combination | Severity |
|----|-------------|----------|
| TOXIC-001 | File read + outbound network | HIGH |
| TOXIC-002 | File read + email | HIGH |
| TOXIC-003 | Secret store access + outbound network | CRITICAL |
| TOXIC-004 | File read + shell execution | HIGH |
| TOXIC-005 | Database access + outbound network | HIGH |
| TOXIC-006 | Shell execution + outbound network | CRITICAL |
| TOXIC-007 | Git repository access + outbound network | MEDIUM |

† A single server that provides both capabilities of a dangerous pair is also flagged — no second server required.

## Attack graph dashboard

```bash
mcp-audit dashboard                      # Scan your real MCP environment and open browser
mcp-audit dashboard --path demo/configs  # Use the bundled demo data
mcp-audit dashboard --port 9090          # Custom port
mcp-audit dashboard --connect            # Include live-connection findings
```

One command runs a full scan, generates a self-contained HTML report, and opens it in your browser. No external dependencies — D3 v7, all scan data, and fonts are embedded inline. No CDN requests are made.

The dashboard shows:

- **Force-directed attack graph** — your MCP servers arranged around a central AI Agent node. Server nodes are colour-coded by max severity (green = clean, orange = high, red = critical). Toxic flow edges connect pairs with dangerous capability combinations.
- **Attack path sidebar** — every exploitable multi-hop path listed as a card with severity badge, hop chain, and description. Click a card to highlight the path on the graph with animated dashed lines.
- **Hitting set recommendation** — at the bottom of the sidebar, the minimum set of servers you can remove to break every attack path. Example: removing `fetch` alone breaks three separate attack paths.
- **Findings table** — full findings list with severity filter pills and sortable columns.
- **Light/dark mode toggle** — pill toggle in the top bar. Preference is applied instantly via CSS custom properties; no page reload required.

The dashboard works against your real MCP environment — whatever `mcp-audit scan` finds on your machine is what appears in the graph. It is not restricted to demo data.

## Rug-pull detection

MCP servers can update their tool definitions at any time. A server can publish clean, trusted descriptions during initial review and silently swap them for malicious ones after developers have granted access.

`mcp-audit pin` records SHA-256 hashes of every tracked server's configuration as a trusted baseline. Subsequent `mcp-audit scan` runs compare against that baseline and flag any change as RUGPULL-001 (HIGH).

```bash
mcp-audit pin   # Record current state as trusted
mcp-audit diff  # Show what has changed since last pin
```

Rug-pull state is stored per-config-set at `~/.mcp-audit/state_<hash>.json`. All other persistent state (baselines, registry cache, policy, rules, license) uses the platform user-config directory: `~/Library/Application Support/mcp-audit/` on macOS, `~/.config/mcp-audit/` on Linux, `%APPDATA%\mcp-audit\` on Windows.

## CI/CD usage

`mcp-audit` exits with code `1` when findings are detected, `0` when clean, and `2` on errors.

```yaml
# .github/workflows/mcp-security.yml
- name: Scan MCP configs
  run: mcp-audit scan --severity-threshold HIGH

- name: Export SARIF for GitHub Security tab
  run: mcp-audit scan --format sarif -o mcp-audit.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: mcp-audit.sarif
```

## Where the detection logic comes from

All detection patterns are original implementations based on published security research — no code was copied from existing scanners. Sources include Invariant Labs' tool poisoning disclosure, CrowdStrike's MCP exfiltration research, CyberArk's agent attack demonstrations, the OWASP Agentic Top 10, and MITRE ATLAS agent-specific techniques. Supply chain patterns follow npm package naming conventions; credential patterns follow the publicly documented key formats from AWS, GitHub, OpenAI, Anthropic, Stripe, and others.

3,000 tests validate detection accuracy and guard against regressions.

See [PROVENANCE.md](PROVENANCE.md) for the full list of research sources, framework mappings, and contribution guidelines for new detection rules.

## CLI reference

Every command is available to every user — no tier, no license required.

| Command | Key flags | Description |
|---------|-----------|-------------|
| `mcp-audit vet <package>` | `--ecosystem`, `--format json`, `--badge`, `--online`, `--strict` | Pre-install verdict: verification status, known CVEs, capabilities. Ask before you install. Offline by default |
| `mcp-audit check` | `--path`, `--verbose`, `--json` | One-command security verdict: grade, top findings, fix hints. Recommended entry point for new users |
| `mcp-audit fix` | `--path`, `--input`, `--apply`, `--fix-type`, `--offline` | Apply safe remediations (credential redaction, transport upgrade, package pinning) directly to config files; dry-run by default |
| `mcp-audit scan` | `--connect`, `--format`, `--output`, `--severity-threshold`, `--asset-prefix`, `--baseline`, `--policy`, `--verify-hashes`, `--no-score`, `--registry`, `--offline-registry`, `--rules-dir`, `--sast`, `--include-extensions` | Run all analyzers and report findings |
| `mcp-audit dashboard` | `--path`, `--port`, `--connect`, `--no-open` | Generate and open the interactive attack graph dashboard |
| `mcp-audit watch` | `--path`, `--format`, `--severity-threshold`, `--connect` | Monitor config files and re-scan on any change |
| `mcp-audit discover` | — | List all detected MCP clients and their configured servers |
| `mcp-audit pin` | — | Record current server state as a trusted baseline |
| `mcp-audit diff` | — | Show configuration changes since the last `pin` |
| `mcp-audit verify` | `<package\|config-path>` | Verify server hashes: pass a package name (`@scope/pkg`), a config file path, or `--all` |
| `mcp-audit version` | — | Print version string |
| `mcp-audit update-registry` | — | Fetch the latest known-server registry from upstream |
| `mcp-audit sast` | `<path>` | Run MCP-aware Semgrep SAST rules on server source code |
| `mcp-audit push-nucleus` | `--url`, `--project-id`, `--api-key`, `--asset-prefix` | Run a scan and push results to a Nucleus Security project via FlexConnect |
| `mcp-audit merge` | `--dir`, `--format`, `--asset-prefix` | Merge JSON scan outputs from multiple machines into a fleet report |
| `mcp-audit baseline save [NAME]` | `--path` | Capture a baseline snapshot; NAME is optional (auto-generated if omitted) |
| `mcp-audit baseline list` | — | List all saved baselines |
| `mcp-audit baseline compare [NAME]` | `--path` | Compare current config against a saved baseline (defaults to latest) |
| `mcp-audit baseline delete NAME` | `--yes` | Delete a saved baseline |
| `mcp-audit baseline export NAME` | `--output-file` | Write a baseline as raw JSON to stdout or a file |
| `mcp-audit rule validate` | `<file>` | Validate a rule file without running a scan |
| `mcp-audit rule test` | `<rule> <config>` | Test a rule file against a specific MCP config file |
| `mcp-audit rule list` | — | List all currently loaded rules (bundled + user-local) |
| `mcp-audit policy validate` | `<file>` | Validate a governance policy YAML file |
| `mcp-audit policy init` | — | Scaffold a new governance policy file |
| `mcp-audit policy check` | `--policy`, `--result` | Check a scan result against a policy file |
| `mcp-audit extensions discover` | — | Inventory installed IDE extensions from VS Code/Cursor |
| `mcp-audit extensions scan` | — | Analyze installed IDE extensions for security risks |
| `mcp-audit agent-files discover` | `--project PATH` | Inventory agent instruction/memory files across supported clients |
| `mcp-audit agent-files scan` | `--project PATH`, `--format` | Scan agent instruction/memory files for injection, obfuscation, and hook exploits |
| `mcp-audit snapshot` | `--output`, `--format`, `--sign`, `--stream`, `--rehydrate`, `--input` | Time-stamped forensic export — CycloneDX 1.5 AI/ML-BOM (default) or native JSON; sigstore-signed; NDJSON stream for SIEM/EDR |
| `mcp-audit advise` | `--out`, `--input`, `--sign`, `--key`, `--key-alt`, `--severity-threshold`, `--observation`, `--published-at` | Convert findings into signed OSV 1.6.0 advisory records and write a publishable feed |
| `mcp-audit feed verify` | `<dir>`, `--key-alt`, `--public-key`, `--identity`, `--oidc-issuer` | Re-canonicalize and verify every advisory signature, the index signature, and each recorded digest |

**`mcp-audit scan` flags**

| Flag | Default | Description |
|------|---------|-------------|
| `--format` | `terminal` | Output format: `terminal`, `json`, `sarif`, `nucleus` |
| `--output / --output-file / -o` | stdout | File path for `json`/`sarif`/`nucleus` output; parent directories are created automatically |
| `--connect` | off | Connect to running servers via MCP protocol |
| `--severity-threshold` | `INFO` | Filter findings and set exit code; exit 1 if any finding at or above this level |
| `--path` | auto-detect | Directory to search for MCP configs |
| `--asset-prefix` | hostname | Override machine identifier in Nucleus/SARIF output |
| `--no-score` | off | Suppress the score/grade panel in terminal output |
| `--registry` | bundled | Custom registry file path (overrides user cache and bundled registry) |
| `--baseline` | none | Compare scan results against a named baseline (`latest` selects most recent) |
| `--rules-dir` | none | Load additional detection rules from this directory (bundled community rules still apply) |
| `--offline-registry` | off | Use bundled registry only, skip user cache |
| `--policy` | auto-discover | Path to a governance policy file; auto-discovers `.mcp-audit-policy.yml` in cwd/repo root when omitted |
| `--verify-hashes` | off | Download and verify package hashes against registry (requires network) |
| `--sast` | none | Path to MCP server source code to scan with Semgrep SAST rules |
| `--include-extensions` | off | Also scan installed IDE extensions for security issues |
| `--include-agent-files` | off | Also scan agent instruction/memory files (skills, CLAUDE.md, Cursor rules, Copilot instructions) |

**`mcp-audit dashboard` flags**

| Flag | Default | Description |
|------|---------|-------------|
| `--path` | auto-detect | Directory to search for MCP configs |
| `--port` | `8088` | HTTP port for the local dashboard server |
| `--connect` | off | Include live-connection findings in the dashboard |
| `--no-open` | off | Generate the report without opening a browser tab |

## IDE Integration

Install the [mcp-audit VS Code extension](https://github.com/mcp-audit/mcp-audit-vscode) to get inline diagnostics directly in your editor — the same findings `mcp-audit scan` reports, shown as red/yellow squiggles the moment you open or save an MCP config file.

```
ext install mcp-audit.mcp-audit-vscode
```

- Red/yellow squiggles on offending server keys in `claude_desktop_config.json`, `mcp.json`, and all other supported MCP config files
- Hover cards with finding title, description, evidence, and remediation
- Status bar grade badge (`mcp-audit: B (3 findings)`)
- Command palette: `mcp-audit: Scan current file`, `mcp-audit: Scan workspace`, `mcp-audit: Fix current file`
- Works in both VS Code and Cursor (Cursor is a VS Code fork — no changes needed)

The extension requires the `mcp-audit` binary to be installed (`pip install mcp-audit`). It shells out to the binary — no detection logic is reimplemented in TypeScript. See [`docs/ide-extension.md`](docs/ide-extension.md) for full setup and configuration details.

## GitHub Action

[![MCP Security Scan](https://github.com/adudley78/mcp-audit/actions/workflows/mcp-audit-example.yml/badge.svg)](https://github.com/adudley78/mcp-audit/actions/workflows/mcp-audit-example.yml)

`mcp-audit` ships as a [composite GitHub Action](action.yml) that you can drop into any repository with a single workflow addition. It installs `mcp-audit`, runs a full scan against your MCP configs, uploads findings to the GitHub Security tab as SARIF, and writes a findings summary to the job summary page. The build fails only when findings at or above your chosen severity threshold exist — making it easy to adopt incrementally (start with `severity-threshold: high`, tighten to `medium` once you've cleared existing issues).

### Minimal setup

Add this workflow to `.github/workflows/mcp-audit.yml` in your repo:

```yaml
name: MCP Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  mcp-audit:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read

    steps:
      - uses: actions/checkout@v4

      - name: Run mcp-audit
        uses: adudley78/mcp-audit@main
        with:
          severity-threshold: high
          upload-sarif: 'true'
```

The `permissions: security-events: write` block is required for SARIF upload on public repositories. Without it the upload step will fail silently.

### Action inputs

| Input | Default | Description |
|-------|---------|-------------|
| `severity-threshold` | `high` | Fail the build if findings at or above this level exist (`critical`, `high`, `medium`, `low`, `info`) |
| `format` | `sarif` | Output format (`sarif`, `json`, `terminal`) |
| `config-paths` | _(auto-discover)_ | Single MCP config file path to scan |
| `baseline` | _(none)_ | Baseline name for drift detection |
| `upload-sarif` | `true` | Upload SARIF results to the GitHub Security tab |

### Action outputs

| Output | Description |
|--------|-------------|
| `finding-count` | Total number of findings |
| `grade` | Letter grade (A–F) |
| `sarif-path` | Path to generated SARIF file |

### More examples

See [`examples/github-actions/`](examples/github-actions/) for:
- [`basic.yml`](examples/github-actions/basic.yml) — visibility-only, never fails the build
- [`strict.yml`](examples/github-actions/strict.yml) — fail on any MEDIUM or higher finding
- [`with-baseline.yml`](examples/github-actions/with-baseline.yml) — drift detection against a committed baseline

Full reference, troubleshooting, and baseline setup instructions: [`docs/github-action.md`](docs/github-action.md).

## Works well with

mcp-audit is designed to complement, not replace, the security tools you
already run. Each integration has a dedicated guide:

| Tool | What it adds alongside mcp-audit | Guide |
|------|----------------------------------|-------|
| **Snyk Code** | Source-code SAST (injection, secrets in code, insecure APIs). mcp-audit covers the config layer; Snyk covers the source layer. Both output SARIF to the same GitHub Security tab. | [`docs/snyk-integration.md`](docs/snyk-integration.md) |
| **Nucleus Security** | Enterprise vulnerability management — deduplication, ownership, SLA tracking across all your security tools. mcp-audit findings push via the FlexConnect schema. | [`docs/nucleus-integration.md`](docs/nucleus-integration.md) |
| **GitHub Code Scanning** | mcp-audit SARIF uploads via `github/codeql-action/upload-sarif@v4`. Findings appear as PR annotations and Security tab alerts out of the box. | [`docs/github-action.md`](docs/github-action.md) |

## Pre-Commit Hook

`mcp-audit` ships as a [pre-commit](https://pre-commit.com) hook, catching MCP misconfigurations before they land in the repository. The hook fires only when a JSON file is staged — no false triggers on Python-only or markdown-only commits — and exits 1 to block the commit when findings at or above your chosen severity threshold exist.

### Minimal setup

Add this to your `.pre-commit-config.yaml` (replace `rev` with the [latest release tag](https://github.com/adudley78/mcp-audit/releases)):

```yaml
repos:
  - repo: https://github.com/adudley78/mcp-audit
    rev: v0.1.0  # Replace with the latest release tag
    hooks:
      - id: mcp-audit
```

Then install the hooks:

```bash
pip install pre-commit
pre-commit install
```

The hook uses `--severity-threshold high` by default. To lower the bar to MEDIUM, override `args`:

```yaml
hooks:
  - id: mcp-audit
    args: [scan, --severity-threshold, medium]
```

**Note:** `pass_filenames: false` is set intentionally. pre-commit would otherwise pass individual staged JSON filenames to the command, but `mcp-audit scan` requires full config files discovered through its own client-aware logic. The hook re-scans all MCP configs (not just staged ones) each time it fires.

See [`examples/pre-commit/`](examples/pre-commit/) for ready-to-copy config patterns and [`docs/pre-commit.md`](docs/pre-commit.md) for the full reference.

## Development

```bash
git clone https://github.com/adudley78/mcp-audit.git
cd mcp-audit
uv sync --all-extras

uv run pytest                        # Run all 3,000 tests
uv run ruff check src/ tests/        # Lint
uv run bandit -r src/                # Security audit of the scanner itself
```

## Known limitations

This tool is in early development. See [GAPS.md](GAPS.md) for known detection gaps, untested areas, and planned improvements.

## Registration (optional)

mcp-audit **does not collect telemetry**.  Every scan runs entirely on your machine.

If you'd like to receive new community detection rule notifications and optionally allow a follow-up when your grade is below C, you can opt in:

```bash
mcp-audit register
```

What registration does **not** collect: config data, server names, tool descriptions, credentials, file paths, or any scan output.

What registration sends (one time only): your name, org, email, mcp-audit version, and grade.
Subsequent scan pings send only version and grade — no PII.

```bash
mcp-audit register --status   # check current registration
mcp-audit register --clear    # remove registration and stop pings
```

See [docs/privacy.md](docs/privacy.md) for the complete plain-English privacy policy.

---

## Support

If `mcp-audit` saves your team time or prevents a security incident, consider
[sponsoring the project on GitHub](https://github.com/sponsors/adudley78).

Sponsorship funds ongoing MCP attack-pattern research, false-positive tuning,
new detection rules, and timely releases. Every dollar goes to development
time — there is no legal entity, no paid tier, and no gated features.
All work remains Apache 2.0 and available to every user.

Not in a position to sponsor? You can help just as much by:

- **Opening issues** with real-world MCP configs that produce false positives or misses
- **Contributing rules** — the [policy-as-code engine](docs/writing-rules.md) accepts community YAML rules
- **Starring the repo** so other teams can find it

## Contributing Detection Rules

If you have encountered an MCP attack pattern in the wild — a tool description
that hijacks model behavior, a credential key name in a suspicious config, a
binary installed in `/tmp/` — turn it into a community rule that protects everyone.

Contributing a rule takes about 30 minutes:

1. Copy `rules/community/TEMPLATE.yml` to `rules/community/COMM-NNN.yml`
2. Fill in the detection pattern and cite your research source
3. Validate: `mcp-audit rule validate rules/community/COMM-NNN.yml`
4. Test: `mcp-audit rule test rules/community/COMM-NNN.yml --against <config>`
5. Open a PR

See **[docs/contributing-rules.md](docs/contributing-rules.md)** for the full
guide. The **[bounty program](rules/community/BOUNTY.md)** recognises the first
50 accepted contributors in the changelog and in
[docs/contributors.md](docs/contributors.md).

## License

Apache License 2.0 — see [LICENSE](LICENSE).
