# `mcp-audit diff` — MCP-aware diff for PRs and CI gates

`mcp-audit diff <base> <head>` compares two MCP configuration states and surfaces
what changed in MCP terms — servers, tools, capabilities, environment-variable
references, external endpoints, and credentials — with risk classification.

## PR Comment Output

**`--format pr-comment` is the recommended output for any team already using the
GitHub Action.** It posts a concise, GitHub-flavored Markdown summary directly on
the PR conversation tab, putting MCP security in front of every reviewer — not
just the engineer who ran the scanner.

```bash
# One-liner for local preview
mcp-audit diff HEAD~1 HEAD --format pr-comment

# Pipe straight into gh CLI
mcp-audit diff HEAD~1 HEAD --format pr-comment | gh pr comment --body-file -
```

Output is capped at 100 lines with each changed server wrapped in a collapsible
`<details>` block. All output lines are ≤ 100 characters wide (renders cleanly
in the GitHub PR conversation view without horizontal scroll).

**No-change case:** when base and head are identical, `--format pr-comment`
outputs a clean "No MCP configuration changes detected" message and exits 0.

### Copy-paste GitHub Actions workflow

The fastest way to add PR-comment diffs to a repo is `examples/github-actions/diff-pr-comment.yml`
(also at [`examples/github-actions/diff-pr-comment.yml`](../examples/github-actions/diff-pr-comment.yml)):

```yaml
name: MCP Diff (PR Comment)

on:
  pull_request:
    branches: [main]

permissions:
  contents: read
  pull-requests: write

jobs:
  mcp-diff:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Install mcp-audit
        uses: adudley78/setup-mcp-audit@v1

      - name: Scan base commit
        run: |
          git checkout ${{ github.event.pull_request.base.sha }}
          mcp-audit scan --format json -o base.json || true

      - name: Scan head commit
        run: |
          git checkout ${{ github.event.pull_request.head.sha }}
          mcp-audit scan --format json -o head.json || true

      - name: MCP-aware diff
        run: |
          mcp-audit diff base.json head.json \
            --format pr-comment \
            --severity-threshold medium \
            > diff-output.md
        continue-on-error: true

      - name: Post PR comment
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const body = fs.readFileSync('diff-output.md', 'utf8');
            await github.rest.issues.createComment({
              owner: context.repo.owner,
              repo: context.repo.repo,
              issue_number: context.issue.number,
              body,
            });
```

For teams using the composite action, `mode: diff` is a shorter alternative —
see [`examples/github-actions/diff-mode.yml`](../examples/github-actions/diff-mode.yml).

### When to prefer `diff-pr-comment.yml` over `mode: diff`

| Approach | When to use |
|----------|-------------|
| `diff-pr-comment.yml` (explicit steps) | Full control over scan flags, separate base/head scans, custom comment body |
| `mode: diff` in composite action | Simplest setup; single-step YAML; no separate install |

---

## JSON output

The `--format json` output is a flat JSON array — one record per changed entity.
Pipe it into `jq`, syslog, or your SIEM.

```bash
mcp-audit diff HEAD~1 HEAD --format json | jq '.[] | select(.severity == "HIGH")'
```

### JSON record schema

Each record has:

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
  "command_diff": null | {
    "before_command": ..., "after_command": ...,
    "before_args": ..., "after_args": ...
  }
}
```

## Other output formats

| Format | Flag | Use case |
|--------|------|----------|
| Terminal (Rich) | `--format terminal` (default) | Local development |
| JSON | `--format json` | Machine-readable, syslog/SIEM |
| PR-comment Markdown | `--format pr-comment` | GitHub PR comments, CI summaries |

## When to use `diff` vs `scan`

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
  uses: adudley78/mcp-audit@v0.10.0
  with:
    mode: diff
    severity-threshold: medium
```

When running on a `pull_request` event, the action automatically posts the
PR-comment Markdown as a comment on the PR conversation tab.

See [`examples/github-actions/diff-pr-comment.yml`](../examples/github-actions/diff-pr-comment.yml)
for the explicit step-by-step workflow (recommended when you need separate scan
flags for base and head).

## Edge cases

- **Renamed server** (same command + package, new `name` key): reported as
  `server changed`, not `removed + added`.
- **Reordered tools array**: no diff reported — tool comparison uses set equality.
- **Whitespace-only JSON changes**: no diff reported.
- **Git ref with no MCP configs**: returns empty list (no diff). Clear error
  if the ref itself cannot be resolved.
