# `mcp-audit diff` — MCP-aware diff for PRs and CI gates

`mcp-audit diff <base> <head>` compares two MCP configuration states and surfaces
what changed in MCP terms — servers, tools, capabilities, environment-variable
references, external endpoints, and credentials — with risk classification.

## When to use it vs `scan`

| Use case | Command |
|----------|---------|
| Full security audit of the current state | `mcp-audit scan` |
| "What did this PR change, and how risky is it?" | `mcp-audit diff base head` |
| Continuous monitoring on every config write | `mcp-audit watch` |

`diff` is additive — it does not replace `scan`. AppSec teams typically run both:
`scan` in the baseline CI workflow and `diff` on every pull request.

## Input formats

Each of `<base>` and `<head>` can be:

- **A directory path** — all MCP configs discovered under that directory (same
  discovery logic as `mcp-audit scan --path`).
- **A JSON file path** — either a `mcp-audit scan --output-file` ScanResult JSON
  or a raw MCP config JSON (`mcpServers` / `servers` root key).
- **A git ref** — any ref that `git show` can resolve: a SHA, `HEAD~3`, a branch
  name, a tag. mcp-audit checks each known MCP config path at that ref.

```bash
# Compare two directories
mcp-audit diff configs/before/ configs/after/

# Compare a saved scan against the current state
mcp-audit diff scan-baseline.json configs/

# Compare two git commits (most useful in CI)
mcp-audit diff HEAD~1 HEAD
mcp-audit diff $GITHUB_BASE_REF $GITHUB_HEAD_REF
```

## Output formats

| Format | Flag | Use case |
|--------|------|----------|
| Terminal (Rich) | `--format terminal` (default) | Local development |
| JSON | `--format json` | Machine-readable, syslog/SIEM |
| PR-comment Markdown | `--format pr-comment` | GitHub PR comments, CI summaries |

### JSON record schema

Each record in the JSON array has:

```json
{
  "change_type": "added" | "removed" | "changed",
  "entity_type": "server" | "tool" | "capability" | "env_var" | "endpoint" | "credential",
  "entity_name": "string",
  "before": null | { ... },
  "after": null | { ... },
  "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",
  "owasp_mcp_top_10": ["MCP01", ...],
  "parent_server": "string | null",
  "command_diff": null | { "before_command": ..., "after_command": ..., "before_args": ..., "after_args": ... }
}
```

### PR-comment format

The `--format pr-comment` output is GitHub-flavored Markdown ≤ 100 lines, with
each changed server wrapped in a collapsible `<details>` block. Pipe it directly
into `gh pr comment`:

```bash
mcp-audit diff HEAD~1 HEAD --format pr-comment | gh pr comment --body-file -
```

## Severity classification

| Severity | Triggers |
|----------|---------|
| CRITICAL | Hardcoded credential in args/env values; newly-created toxic-flow pair |
| HIGH | New server with shell-exec or file-write capability; new external endpoint; new high-value credential env-var reference (AWS, GCP, Azure, GitHub) |
| MEDIUM | New tools added; new/changed env-var references; command or args changed |
| LOW | New server with sanctioned capabilities, no credentials, no external endpoints |
| INFO | Server removed |

## Severity threshold and exit codes

`--severity-threshold <level>` filters changes to only those at or above the
given level. Exit codes mirror `mcp-audit scan`:

- `0` — no changes at or above the threshold.
- `1` — one or more changes at or above the threshold.
- `2` — error (invalid input, git ref not found, etc.).

```bash
# Block the build only on HIGH+ MCP changes
mcp-audit diff HEAD~1 HEAD --severity-threshold high
```

## GitHub Action integration

Add `mode: diff` to the existing action — no separate workflow needed:

```yaml
- name: MCP diff
  uses: adudley78/mcp-audit@v0.8.0
  with:
    mode: diff
    severity-threshold: medium
```

When running on a `pull_request` event, the action automatically posts the
PR-comment Markdown as a comment on the PR conversation tab.

See `examples/github-actions/diff-mode.yml` for a complete reference workflow.

## Edge cases

- **Renamed server** (same command + package, new `name` key): reported as
  `server changed`, not `removed + added`.
- **Reordered tools array**: no diff reported — tool comparison uses set equality.
- **Whitespace-only JSON changes**: no diff reported.
- **Git ref with no MCP configs**: returns empty list (no diff). Clear error
  if the ref itself cannot be resolved.
