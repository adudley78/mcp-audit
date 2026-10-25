# The 100 most-downloaded MCP servers on npm: scan data (2026-10-22)

The data behind Adam Dudley's write-up on scanning the 100 most-downloaded MCP servers on npm ([adudley.medium.com](https://adudley.medium.com)). Every number it gives about the 100 servers comes from `summary.json` or `sast-summary.json` in this directory.

## What was scanned

- **Corpus.** On 2026-10-22, six npm searches (`mcp server`, `keywords:mcp`, `mcp-server`, `model context protocol server`, `keywords:mcp-server`, `keywords:modelcontextprotocol`) returned 4,383 candidates. Kept: packages that ship an executable (`bin`) and describe themselves as an MCP server. Removed by hand: frameworks, clients, installers, templates and generators (listed in `corpus.json` under `excluded_manual`). The top 100 by weekly downloads were kept, each pinned to its latest version.
- **Environment.** A clean Linux sandbox (2 vCPU, Node 22.22.0, Python 3.13) with no accounts and no API keys. mcp-audit 0.21.0 from PyPI with the `[mcp]` extra; semgrep 1.182.1.
- **Passes.**
  1. Static: `mcp-audit scan --path scan-config-100-servers.mcp.json --format json`, then the same with `--check-vulns`.
  2. Live: `mcp_audit.mcp_client.connect_and_enumerate` (the `--connect` path) with a 60-second timeout instead of the CLI's 10, so slow cold starts are not counted as failures. Servers that failed on the plain `npx -y <name>@<version>` were retried twice with adjusted arguments (a directory, `--stdio`, or a subcommand such as `start --transport stdio`); `overrides.json` and `overrides3.json` hold them. mcp-audit's poisoning analyzer and COLLIDE-001 were then run over the live tool definitions, exactly as `scan --connect` does.
  3. Dependencies: each server's dependency graph from deps.dev (`v3alpha`, latest version), every package in it queried against OSV. Counts are per (server, advisory).
  4. Source: the 77 packages that name a GitHub repo were cloned; 72 were scanned with mcp-audit's Semgrep rule pack (`semgrep --config <rules> -j 2 --timeout 30`, 400-second cap per repo). Hits in test, fixture, example, docs, build and dist paths are counted separately.

## Files

| File | What it holds |
|---|---|
| `corpus.json` | The 100 servers: version, weekly and monthly downloads, publisher, repository, `bin`, provenance attestation, publish dates. |
| `scan-config-100-servers.mcp.json` | The config fed to `mcp-audit scan`: every server as `npx -y <name>@<version>`. |
| `connect-summary.json` | Which servers completed a handshake on the live pass and which did not. |
| `overrides.json`, `overrides3.json` | The adjusted arguments used for the second and third live passes. |
| `failure-classification.json` | For the 40 that did not: credential-gated (and the credential it asked for), CLI wrapper, needs a project, or no handshake. |
| `summary.json` | Every aggregate the write-up cites: corpus, live pass, tools, collisions, poisoning, static scan, dependency advisories. |
| `sast-summary.json` | Semgrep matches per rule, all paths and source paths, and the number of repos per rule. |
| `scripts/` | The scripts that built the corpus, ran the live pass, captured failure output and computed the summaries. |

## What is not here, and why

Every count is published. The per-server rows behind four of them are not:

- which servers carry which dependency advisory,
- which repos matched which Semgrep rule,
- which servers produced which poisoning finding,
- which servers the static scan's SC-004 findings named.

An advisory in a dependency is exposure only if the vulnerable code is reachable, and mcp-audit does not do reachability analysis. Most Semgrep matches are places to review, not findings. None of the poisoning findings in this corpus was a real attack. A list of names next to any of those would accuse servers of something the data does not show. In `summary.json`, those lists are replaced by their counts (see the `_published` key); no number changed.

The full tool definitions (about 6 MB) and raw Semgrep output (about 18 MB) are also left out for size. `scripts/enumerate.py` and the Semgrep command above regenerate them.

## Reproducing

Run from a working directory with a `data/` folder, Python 3.11+ and `mcp-audit-scanner[mcp]` installed.

1. `python scripts/corpus.py data/npm-candidates.json`, then select the top 100 into `data/corpus.json` (the manual exclusions are in this directory's `corpus.json`).
2. `scripts/warm.sh <package>` for each server, to fill the npx cache before the timed pass.
3. `python scripts/enumerate.py data/corpus.json data/enum` for the live pass. For the retry passes, set `MCP_OVERRIDES=overrides.json` (then `overrides3.json`) and write to `data/enum2` and `data/enum3`.
4. `python scripts/probe.py data/enum data/probe-failures.json` to capture stderr from servers that did not connect.
5. The static scan, the deps.dev and OSV lookups and the Semgrep run, as described under Passes, into `data/`.
6. `python scripts/summarize.py` and `python scripts/sast_summary.py` write `data/summary.json` and `data/sast-summary.json`.

Results drift with time: servers publish new versions, deps.dev indexes new releases, and OSV adds advisories.

## Defects in mcp-audit that this scan found

The scan's job was to measure the servers, and it also measured mcp-audit. Found in 0.21.0 and still present in 0.21.1:

- **POISON-060** (Unicode homoglyph substitution) fires on full-width punctuation in tool descriptions written in Chinese. 488 of the 661 poisoning findings were this; none of the 661 were real.
- **SC-004** compares versions numerically and reads `@modelcontextprotocol/server-filesystem` 2.0.0 as older than 2025.7.1 after the package moved from calendar versions to semver, so it reports two fixed CVEs as present.
- **COMM-010** ("npx without a pinned version") fires on every server in the config, all of which are pinned, because it checks the command and not the arguments.
- **SC-003** reports `@netlify/mcp` as a lookalike of `@mintlify/mcp`.
- **`--check-vulns`** reports every dependency advisory as INFO with no summary, HIGH advisories included.

The ecosystem numbers in `summary.json` were computed from the raw data, not from the scanner's verdicts where those were wrong.

The 661 poisoning findings are labelled and scored as mcp-audit's precision benchmark in `docs/research/poisoning-benchmark/`; method and results in [`docs/poisoning.md`](../../poisoning.md).
