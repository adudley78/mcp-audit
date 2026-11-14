# Launch drift study: frozen corpus (2026-11-14)

This folder holds the corpus for the December 2026 research drop. The question it answers is: **how often do popular MCP servers change what they tell the agent, and does anyone notice?** The scope, the measurements (M1–M5) and the disclosure rules are in the Marcus scope document `claude/launch-2026-12-research-scope.md`.

The corpus was frozen on 2026-11-14. It does not change after this date. The 11-19 snapshot and every measurement use these lists.

## The three strata

| Stratum | File | Size | Ranking source |
|---|---|---|---|
| npm top 100 | `corpus-npm.json` | 100 | npm search weekly downloads, same six queries as 10-22 and 10-29 |
| PyPI top MCP servers | `corpus-pypi.json` | 48 | hugovk/top-pypi-packages 30-day list (2026-11-01, top 15,000 projects) |
| Official MCP Registry, all | `corpus-registry-all.json.gz` | 21,177 packages | none (complete list) |
| Official MCP Registry, live pass | `corpus-registry-live.json` | 200 | 100 by downloads (npm last-week, PyPI 30-day list), plus 100 drawn at random (seed 20261114) |

### npm

- The rule is the 10-29 rule, unchanged: keep a package that ships a `bin` and whose npm description says it is (or ships) an MCP server, or whose name does.
- Every 10-22 and 10-29 decision stands. The 16 new decisions are in `corpus-npm.json` under `excluded_new_2026-11-14`, each with its reason. Five packages qualify on their name alone; they are listed in `scripts/npm_corpus.py`.
- 83 of the 100 are the same packages as on 10-29.

### PyPI

- The same rule, applied to PyPI: the package ships a `console_scripts` entry point (read from its latest wheel) and its summary or name says it is an MCP server.
- Candidates: every project in the 15,000-project download list whose name contains `mcp`, plus every project in that list that the official MCP Registry lists as a PyPI package (94 candidates).
- **48 qualify, not 50.** Packages below the list's floor have no comparable download count. The corpus stops at 48 rather than mix two ranking sources. Each exclusion and its reason is in `corpus-pypi.json`.

### Official MCP Registry

- Every active server, latest version, that ships an npm or PyPI package. Packages already in the npm or PyPI strata are removed.
- **The live pass does not cover all 21,177 packages.** Installing and running every package before 11-19 is not possible. So:
  - The static measurements (M2 unpinned launches, M4 toxic flows, M5 malicious packages) run on all of them.
  - The live measurements (M1 tool drift, M3 POISON-*) run on the 200 packages in `corpus-registry-live.json`: the 100 most-downloaded stdio packages, plus 100 drawn at random from the rest with seed 20261114.
- The registry also lists packages that the npm rule excludes, for example `@playwright/mcp` (its description does not say "server"). They are measured here, in the registry stratum, so the npm stratum stays comparable with 10-22 and 10-29.

## Old-date snapshots (input to M1)

M1 compares each server's `tools/list` on 2026-10-22, 2026-10-29 and 2026-11-19. The 10-22 and 10-29 definitions were not committed, so they are regenerated:

1. `scripts/snapshot_versions.py` finds the version current on each date. It uses the version a past study recorded for that date. Otherwise it uses the highest stable release published by the end of that day (unpublished npm versions and yanked PyPI releases do not count). The source of each version is recorded.
2. `scripts/snapshot_run.py` takes each (package, version) in turn. It installs it in its own prefix as the unprivileged `probe` user: npm with `--ignore-scripts`, PyPI wheels only (`--only-binary :all:`), so no package code runs at install time. It runs the server as `probe`, under `unshare --net` (no network interface) and `env -i` (empty environment), records its tool definitions and lock digests (`lock/tool_digests.py`), and deletes the prefix. The 10-22 and 10-29 launch overrides apply to the same npm packages.
3. `scripts/snapshot_summary.py` writes `snapshot-summary.json`: per pair, connected or not, tool count and digests. The tool text (several MB) is not committed; step 2 regenerates it.

### What this cannot show

- A server that builds its tool list from data it fetches at startup gives a different list offline than it gave on the date. The old 10-22 run had network access; this run does not.
- A server whose tools changed **without** a version bump looks unchanged here, because the same version is installed for both dates. The 11-19 live snapshot is the only place a same-version change can appear.

## Files

| File | What it holds |
|---|---|
| `corpus-npm.json` | The 100 npm servers, the rule, and every exclusion with its reason |
| `corpus-pypi.json` | The PyPI servers, their entry points and wheel digests, and every exclusion |
| `corpus-registry-all.json.gz` | Every registry npm/PyPI package, deduplicated |
| `corpus-registry-live.json` | The registry packages in the live pass |
| `registry-npm-downloads.json` | Last-week npm downloads for every registry npm package (the live-pass ranking) |
| `snapshot-versions.json` | The 10-22 and 10-29 version of each live-pass package, and its source |
| `snapshot-summary.json` | Per (package, version): connected or not, tool count, digests |
| `scripts/` | Every step above |

## Snapshot run (2026-11-14)

- 468 (package, version) pairs; 231 connected with no network and no credentials. The failures are classed automatically in `snapshot-summary.json` (`failure_classes`): most servers that fail need a key, a network service or a host app to start, as on 10-29.
- Servers that connected on both dates: 57 npm, 27 PyPI, 73 registry. The npm figure matches the 10-29 study (61 of 100 connected there, with the same isolation).
- These are inputs to M1, not results. M1 is computed after the 11-19 snapshot.
