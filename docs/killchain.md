# mcp-audit killchain

> _Find the 2–3 changes that cut your blast radius. Decision engine on top of the
> attack-path graph mcp-audit already computes._

## What it does

`mcp-audit killchain` translates the multi-hop attack-path graph (already built by
`mcp-audit scan`) into a short, prioritised action list: the specific configuration
changes that eliminate the most attack paths with the fewest edits.

Instead of "here are 47 findings", it says:

> **KS-001:** Remove or restrict `shell execution` capability on server `db-admin-mcp`
> — breaks 8 of 12 attack paths (3 CRITICAL, 5 HIGH)

## How the ranking works

The underlying engine uses the **greedy minimum hitting-set algorithm** already in
`analyzers/attack_paths.py`:

1. Build the full multi-hop attack-path graph (capability flows across servers).
2. Find the server that appears in the most unbroken paths.
3. Mark those paths as "covered"; repeat for the remaining uncovered paths.
4. Stop when all paths are covered (or the top-N limit is reached).

The recommender wraps each greedy step with:
- **Capability label** — which capability on that server is the attack vector.
- **Incremental count** — how many *new* paths this change breaks (after previous steps).
- **Rationale** — whether the server acts as a data-source, exfiltration, or intermediate node.
- **Severity reduction** — the CRITICAL/HIGH/MEDIUM breakdown of removed paths.

Ties are broken alphabetically by server name, so output is always deterministic.

## What-if simulation

After ranking, `killchain` simulates applying all N recommended changes by removing
the target servers from the server list and re-running `summarize_attack_paths` — the
same pure function used in the main scan pipeline. The result is mathematically
identical to what `mcp-audit scan` would produce if those servers were actually removed
from the config.

## Usage

```bash
# Fresh scan — runs the full static pipeline, then recommends changes
mcp-audit killchain

# Consume an existing scan result (faster; no re-scan)
mcp-audit killchain --input scan.json

# Top 5 instead of the default 3
mcp-audit killchain --top 5

# JSON output for machine ingest / CI pipelines
mcp-audit killchain --format json

# Emit a governance-policy patch alongside the report
mcp-audit killchain --patch yaml

# Emit a PR-comment stub alongside the report
mcp-audit killchain --patch pr

# Write the report to a file (--patch yaml writes <name>.patch.yml alongside it)
mcp-audit killchain --output-file report.md --patch yaml

# Scan specific config paths
mcp-audit killchain --path ~/.cursor/mcp.json --path ~/claude_desktop_config.json
```

## Output formats

### Markdown (default)

Clean, copy-paste friendly output suitable for Slack, email, or a PR description.
Sections:

1. **Current blast radius** — total path count with severity breakdown.
2. **Top N recommended changes** — one section per kill switch with paths removed,
   paths remaining, rationale, and severity reduction.
3. **What-if simulation** — blast radius after applying all recommendations.

### JSON (`--format json`)

Machine-ingestible payload:

```json
{
  "generated": "2026-05-03T11:00:00+00:00",
  "original_blast_radius": 12,
  "simulated_blast_radius": 0,
  "kill_switches": [
    {
      "change_id": "KS-001",
      "description": "Remove or restrict `shell execution` capability on server `db-admin-mcp`",
      "target_server": "db-admin-mcp",
      "target_tool": null,
      "capability": "shell execution",
      "paths_removed": 8,
      "paths_remaining": 4,
      "severity_reduction": "removes 3 CRITICAL, 5 HIGH",
      "rationale": "`db-admin-mcp` acts as a data-source node in 8 of 12 attack paths...",
      "governance_patch": null
    }
  ]
}
```

## Governance patch (`--patch yaml`)

The `--patch yaml` flag generates a YAML fragment that can be appended to an existing
`.mcp-audit-policy.yml` to add the recommended servers to the `approved_servers`
denylist. This prevents re-introduction without an explicit policy review.

**Schema gap:** The current governance schema enforces server-level restrictions only.
Fine-grained capability restrictions (e.g., disabling a specific tool on a server)
are not yet supported. Each patch entry denylists the entire server as the closest
available approximation. A future governance schema extension will add per-server
capability controls.

Example patch output:

```yaml
# mcp-audit killchain — governance policy patch
# Generated: 2026-05-03  Covers: KS-001, KS-002
#
# Append this block to your .mcp-audit-policy.yml …

approved_servers:
  mode: denylist
  entries:
    - name: "db-admin-mcp"  # KS-001: shell execution — breaks 8 attack path(s)
    - name: "filesystem"    # KS-002: file read — breaks 3 attack path(s)
```

## Edge cases

| Scenario | Behaviour |
|---|---|
| No attack paths | Exits 0. Prints "No reachable attack paths — no changes recommended." |
| All paths share no common edge | Note added to report. Each kill switch targets one unique path. |
| `--top N` exceeds the hitting-set size | Returns fewer than N switches (correct — no more changes needed). |
| `--input` file from an old mcp-audit version | Schema-version check; exits 2 with a clear error if below `0.1.0`. |
| Extreme blast radius (>1000 paths) | Greedy hitting-set is O(paths × servers); completes in under 5 seconds for typical MCP configurations. |

## Algorithm complexity

The greedy hitting-set approximation runs in **O(P × S)** time where P is the number
of attack paths and S is the number of unique servers. For typical MCP configurations
(tens of servers, hundreds of paths), this completes in milliseconds. The algorithm
provides an approximation ratio of ln(P)+1 relative to the optimal minimum hitting set.

## Relationship to `mcp-audit scan`

`killchain` does **not** replace `scan`. It consumes `scan` output (either inline or
via `--input`) and adds the prescriptive layer. The underlying attack-path graph and
greedy algorithm in `analyzers/attack_paths.py` are unchanged — `killchain` is a
presentation layer, not a new analysis engine.
