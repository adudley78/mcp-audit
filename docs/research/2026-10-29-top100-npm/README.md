# The 100 most-downloaded MCP servers on npm: re-measure on 0.23.0 (2026-10-29)

A fresh run of the [2026-10-22 scan](../2026-10-top100-npm/README.md), with the same corpus method and the same live pass, on mcp-audit 0.23.0 (`main` at 91120b0). It exists to re-measure POISON-* precision on current code (Q-045, STORY-0120). The 2026-10-22 numbers are a fixed measurement of 0.21.0 and stay where they are.

## What was scanned

- **Corpus.** On 2026-10-29, the same six npm searches returned 4,378 candidates. The same rule kept packages that ship a `bin` and describe themselves as an MCP server, ranked by weekly downloads. 80 of the 100 are the same packages as on 10-22; 20 are new. The 18 exclusions from 10-22 still apply. New exclusions (installers, clients, proxies, frameworks, agent harnesses, templates, test fixtures, platform-binary duplicates) are listed with a reason in `corpus.json` under `excluded_manual`. The cutoff was 21,738 weekly downloads.
- **Environment.** This is not a separate clean machine. The isolation is built in:
  - Each package was installed with `npm install --ignore-scripts` as an unprivileged `probe` user, so no package code ran at install time (`scripts/install.py`). 99 of 100 installed; `blume` timed out after 900 seconds.
  - Each server then ran from its installed `bin` as that user under `unshare --net`, with no network at all and an empty environment (`env -i`) (`scripts/enumerate_isolated.py`). No account, API key or repository credential was reachable from any server.
  - The 10-22 run had network access, so a few servers that fetch something at startup may have failed here and connected there.
- **Passes.**
  - **Static:** `mcp-audit scan --path scan-config-100-servers.mcp.json --format json --offline`.
  - **Live:** `mcp_audit.mcp_client.connect_and_enumerate` with a 60-second timeout. It was retried with the 10-22 `overrides.json` and `overrides3.json`, which use the same adjusted arguments.
  - **Poisoning:** `PoisoningAnalyzer` over each connected server's runtime config, exactly as `scan --connect` runs it. Each server is counted once, from the pass that connected it. The 10-22 script added findings from every pass, so a server that connected in more than one pass would have been counted twice.
  - **Not re-run:** the dependency (deps.dev, OSV) and Semgrep passes. Their 10-22 figures stand as published.

## Results (`summary.json`)

- **Live pass:** 60 of 100 connected: 46 on the default invocation, 14 with adjusted arguments. 40 failed; `connect.failure_classes` classifies them automatically from each failure message (10-22 classified by hand).
- **Tools:** 1,382 tools, with a median of 13 per server.
- **Runtime poisoning:** 46 findings on 16 servers:
  - 32 POISON-050 (LOW, a description of 2,000 characters or more)
  - 12 POISON-030 (MEDIUM, workflow wording such as "first call" and "instead of calling")
  - 2 POISON-012 (HIGH, "Override default result limit")
- **Precision:** all 46 were read in their full live definitions; none is an attack. The labels are in `../poisoning-benchmark/top100-labels.json`, and `scripts/bench_poisoning.py precision` scores them. **0 of 46 real (0.0%), 0 of 2 at HIGH or above, 3.3 findings per 100 tools.** On 0.21.0 it was 0 of 661, 41 per 100.
- **Static:** 660 findings.

## Measured error

- **No attacks to find.** The corpus holds no real attack, so 0 of 46 measures the false-alarm rate on popular servers, not detection.
- **No network at runtime.** Running without network is the isolation trade-off described above; it may lower the connect count against 10-22.
- **Automatic failure classes.** The failure classes come from a keyword match on each failure message, not a hand reading.

## What is not here

Which servers produced which poisoning finding is left out, as on 10-22: none was an attack. The full tool definitions (about 3 MB) are not committed either. Running `scripts/install.py` and then `scripts/enumerate_isolated.py` on `corpus.json` regenerates them.

## Files

| File | What it holds |
|---|---|
| `corpus.json` | The 100 servers, with every manual exclusion and its reason |
| `scan-config-100-servers.mcp.json` | The config the static pass scanned |
| `connect-summary.json` | Which servers connected and which did not |
| `summary.json` | Every aggregate above |
| `scripts/` | `install.py`, `enumerate_isolated.py` and `summarize_q045.py`. The search step is `../2026-10-top100-npm/scripts/corpus.py`. |
