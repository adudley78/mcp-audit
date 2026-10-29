# The 100 most-downloaded MCP servers on npm: re-measure on 0.23.0 (2026-10-29)

A fresh run of the [2026-10-22 scan](../2026-10-top100-npm/README.md), with the same corpus method and the same live pass, on mcp-audit 0.23.0 (`main` at 91120b0). It exists to re-measure POISON-* precision on current code (Q-045, STORY-0120). The 2026-10-22 numbers are a fixed measurement of 0.21.0 and stay where they are.

## What was scanned

- **Corpus.** On 2026-10-29 the same six npm searches returned 4,378 candidates. The rule, written down in `corpus.json` under `rule`: keep a package that ships a `bin` and whose npm description says it is, or ships, an MCP server. Two packages qualify on their name alone (`@tableau/mcp-server`, `@bitbonsai/mcpvault`).
  - Excluded: templates and hello-world servers, frameworks and SDKs, clients, inspectors and proxies, installers and config tools, agent harnesses, test fixtures, platform-binary duplicates, and packages that never call themselves an MCP server. Each exclusion and its reason is in `corpus.json` under `excluded_manual`.
  - Two of the 2026-10-22 exclusions, `kordoc` and `agent-blackboard`, now describe themselves as "CLI + MCP server" and are included under this rule.
  - The top 100 by weekly downloads were kept; the cutoff is 22,683. 79 of them are the same packages as on 10-22.
- **Environment.** This was not a separate clean machine, so the isolation is built in.
  - **Install:** each package was installed with `npm install --ignore-scripts` as an unprivileged `probe` user, so no package code ran at install time. npm reached the registry through this sandbox's HTTPS proxy (`scripts/install.py`). 99 of 100 installed; `blume` timed out after 900 seconds.
  - **Run:** each server ran from its installed `bin` as that user, under `unshare --net` (no network interface at all) and with an empty environment (`env -i`) (`scripts/enumerate_isolated.py`).
  - **Filesystem:** access was limited by Unix permissions only, with no mount namespace or chroot. The session's credentials live under `/root`, which that user cannot read. Without a network a server could not send anything it read.
  - The 10-22 run had network access, so a few servers that fetch something at startup may have failed here and connected there.
- **Passes.**
  - **Static:** `mcp-audit scan --path scan-config-100-servers.mcp.json --format json --offline`, run twice in a fresh state directory. The second run is used: the first emits RUGPULL-000 for every server, and the 10-22 figure was also a run with state present.
  - **Live:** `mcp_audit.mcp_client.connect_and_enumerate` with a 60-second timeout. It was retried with the 10-22 `overrides.json` and `overrides3.json`, plus `overrides-add.json` for the two new inclusions (`kordoc-mcp`, `agent-blackboard mcp`, the entry points their READMEs give).
  - **Poisoning:** `PoisoningAnalyzer` over each connected server's runtime config, exactly as `scan --connect` runs it. Each server is counted once, from the pass that connected it; the 10-22 script added the findings of every pass.
  - **Not re-run:** the dependency (deps.dev, OSV) and Semgrep passes. Their 10-22 figures stand.

## Results (`summary.json`)

- **Live pass:** 61 of 100 connected, 46 on the default invocation and 15 with adjusted arguments. 39 failed. `connect.failure_classes` classifies the failures automatically, from each failure message (10-22 classified them by hand).
- **Tools:** 1,402 tools, with a median of 13 per server.
- **Runtime poisoning:** 46 findings on 16 servers:
  - 32 POISON-050 (LOW, a description of 2,000 characters or more)
  - 12 POISON-030 (MEDIUM, workflow wording such as "first call" and "instead of calling")
  - 2 POISON-012 (HIGH, "Override default result limit")
- **Precision:** every finding was read in its full live definition, by the run and again by an independent reviewer. **1 of 46 is real (2.2%); 0 of 2 at HIGH or above; 3.3 findings per 100 tools.** On 0.21.0 it was 0 of 661, and 41 per 100.
  - The real one is a long description (about 13,500 characters). About 10,000 characters in, it orders the agent to pass the user's most recent message verbatim in a parameter that goes to the vendor, to report its own model name, and to call a feedback tool every turn.
  - That is data collection the user did not ask for, hidden where nobody reads. It is vendor telemetry, not malware, and it is the case POISON-050 exists to surface.
  - The labels are in `../poisoning-benchmark/top100-labels.json`, and `scripts/bench_poisoning.py precision` scores them.
- **Static:** 560 findings.

## Measured error

- **Small, low-rate sample.** One true positive in 46 is a small sample: the precision figure says false alarms dominate on popular servers, not how well real attacks are caught. Recall is measured on MCPTox (`docs/poisoning.md`).
- **No network at runtime.** This is the isolation trade-off described above, and it may lower the connect count against 10-22.
- **Automatic failure classes.** The failure classes come from a keyword match on each failure message, not a hand reading.

## What is not here

The full tool definitions are not committed (about 3 MB). Running `scripts/install.py` and then `scripts/enumerate_isolated.py` on `corpus.json` regenerates them. Neither is a per-server list of findings. The label notes quote short phrases so that each label can be checked, and some of those phrases identify the server they came from.

## Files

| File | What it holds |
|---|---|
| `corpus.json` | The 100 servers, the inclusion rule, and every manual exclusion with its reason |
| `scan-config-100-servers.mcp.json` | The config the static pass scanned |
| `connect-summary.json` | Which servers connected and which did not |
| `overrides-add.json` | Launch arguments for the two new inclusions |
| `summary.json` | Every aggregate above |
| `scripts/` | `install.py`, `enumerate_isolated.py` and `summarize_q045.py`. The search step is `../2026-10-top100-npm/scripts/corpus.py`. |
