# AI agents in GitHub Actions workflows (WORKFLOW-001..003)

A workflow that runs an AI agent on an issue, a comment or a pull request reads
text that anyone on the internet can write. If that agent also holds the
repository's secrets, a token that can write, and tools that can run commands,
one hidden sentence can make it post the secrets back. That happened to three
vendors' CI agents in 2026 ("Comment and Control", ACM CCS 2026): Claude Code
Security Review put its environment in a pull-request comment, the Gemini CLI
action posted `GEMINI_API_KEY` as an issue comment, and the Copilot agent pushed
it in a commit.

mcp-audit reads `.github/workflows/*.yml` and `*.yaml` and reports that shape
before the first malicious comment arrives. It parses the files with
`yaml.safe_load`; it never runs them, and it never calls `git` or `gh`.

## Where it looks

| Command | What is read |
|---|---|
| `mcp-audit scan`, `mcp-audit check` (no path) | `<working directory>/.github/workflows/`. This is what the mcp-audit GitHub Action's default run sees, because it scans from the checkout. |
| `mcp-audit scan --project DIR` | `DIR/.github/workflows/`, plus the same directory under every nested folder that is itself a repository root (has a `.git` entry, such as a submodule or a folder of checkouts). Copies of workflows inside one repository (vendored code, test data) are not read, because GitHub would not run them. |
| `mcp-audit scan PATH` / `--path` | Nothing: an explicit path scans exactly what it names. |

Only the top level of `.github/workflows/` is read, as GitHub does. When the
working directory is also the `--project` directory, each finding is reported
once. A `.github` or `.github/workflows` that is a symlink is not read, and
every file must resolve inside the scanned directory, so a link cannot pass
another directory's workflows off as the repository's own. An unreadable
directory is skipped without stopping the scan.

Files over 256 KiB are skipped, and one scan reads at most 4 MiB of workflow
files (about 4–5 seconds of parsing for real workflows; files built to parse
slowly were measured at about 45 seconds for the full 4 MiB). Each file skipped this way is listed
under the scan's errors, so a clean result never hides what was not read.

## What it checks

A step is an **agent step** when its `uses:` names one of these actions (exact
`owner/repo`, any version):

| Action | How mcp-audit reads its tool limits |
|---|---|
| `anthropics/claude-code-action` | By default Claude gets file operations, comments and basic GitHub operations and **cannot run arbitrary shell commands** (the action's `docs/configuration.md`). `--allowedTools` adds tools to that set. So the default counts as limited, and the step counts as open only when `claude_args` (or the v0.x `allowed_tools` input, or `permissions` in the `settings` JSON) allows every shell command (`Bash`, `Bash(*)`), allows a broad command such as `Bash(cat:*)`, `Bash(python3:*)` or `Bash(gh:*)` (the HARNESS-005 list), or sets `--dangerously-skip-permissions` / `--permission-mode bypassPermissions` / `defaultMode: bypassPermissions`. |
| `anthropics/claude-code-security-review` | Has no input that limits Claude's tools. Its README says it "is not hardened against prompt injection attacks and should only be used to review trusted PRs". Always open. |
| `google-github-actions/run-gemini-cli` | Always runs `gemini --yolo`, which approves every tool call. Limited only by a `tools.core` allowlist in the `settings` input (the older flat `coreTools` key is read too); Google's own example workflows use `"tools": {"core": []}`. A bare `run_shell_command` or a broad command such as `run_shell_command(cat)` in that list opens it again. `security.disableYoloMode: true` counts as limited. A `settings` value mcp-audit cannot read as JSON (for example a file path) produces no finding. |

Then four facts from the file:

1. **Trigger.** The workflow runs on `issues`, `issue_comment`,
   `pull_request_target`, `pull_request_review`, `pull_request_review_comment`,
   `discussion` or `discussion_comment`: events whose text a stranger can write.
   Issue, comment, discussion and `pull_request_target` runs get the
   repository's secrets for anyone's input. The two review events get them
   only for pull requests from a branch of the repository itself; for a pull
   request from a fork GitHub withholds secrets and gives a read-only token,
   but anyone can still comment on a branch pull request. Plain
   `pull_request` is not on the list, because fork pull requests get no
   secrets and a read-only token. A workflow that only has `workflow_call`
   runs once for each workflow in the same repository that calls it with
   `uses: ./.github/workflows/<file>`, with that caller's triggers and a token
   capped at the calling job's permissions. Each caller path is checked on
   its own: a step is reported only when one path has both a trigger from this
   list and a writable token.
2. **Secret.** `${{ secrets.NAME }}` or `${{ github.token }}` reaches the step
   through its `with:` or `env:`, the job's `env:`, or the workflow's `env:`.
   `GITHUB_TOKEN` counts.
3. **Write.** The job's permissions (a job-level `permissions:` replaces the
   workflow-level one) include `write` on any scope, `id-token: write`
   included, or `write-all`; or there is no `permissions:` key at all. With no
   key, the token gets the repository's default permissions, which may be
   read-only or read-write depending on a repository setting the file does not
   show; the finding says so instead of claiming write.
4. **Tools**, as in the table above.

| ID | Severity | Fires when |
|---|---|---|
| WORKFLOW-001 | HIGH | An agent step meets 1, 2 and 3, and its tools are open with nothing limiting them. |
| WORKFLOW-002 | MEDIUM | As WORKFLOW-001, but a deny list (`--disallowedTools`, `disallowed_tools`, `permissions.deny`, `tools.exclude`) is the only limit. A deny list names what to block; the injected instruction finds another way. Anthropic's fix after the paper blocked `Bash(ps:*)`, and `cat /proc/*/environ` prints the same environment. |
| WORKFLOW-003 | HIGH | A `run-gemini-cli` step on a trigger from 1 is pinned to an action version below 0.1.22 (`@v0.1.21`), sets `gemini_cli_version` below 0.39.1 / 0.40.0-preview.3, or sets `GEMINI_CLI_TRUST_WORKSPACE` (or `GEMINI_TRUST_WORKSPACE`) to true after the job checked out pull-request code (`actions/checkout` with a `github.event.pull_request.head.*` / `github.head_ref` / `refs/pull/` ref, or `gh pr checkout`). Both come from GHSA-wpqr-6v78-jr5g (CVSS 10.0): older versions trusted the workspace in headless runs and ignored the tool allowlist under `--yolo`; turning trust on over pull-request code brings the first problem back on a fixed version. |

Each finding names the file, the job (`server`), the step (`tool`), the
triggers, the secret names (never their values), the permissions and the
setting that opened the tools.

## Examples

Reported (WORKFLOW-001): Claude can run any command on an issue comment, with
an API key and write access.

```yaml
on:
  issue_comment:
permissions:
  contents: write
  issues: write
jobs:
  claude:
    runs-on: ubuntu-latest
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
          claude_args: --allowedTools Bash
```

Not reported: the same workflow with `claude_args: --allowedTools "Bash(gh
issue view:*)"`, or with no `claude_args` (the action's default tools), or on
`push`, or with `permissions: read-all` and no `id-token: write`.

Not reported: Google's triage pattern, where the agent job has an empty
`tools.core`, reads only, and a separate job applies the labels.

```yaml
- uses: google-github-actions/run-gemini-cli@v0
  env:
    GEMINI_CLI_TRUST_WORKSPACE: 'true'
    GITHUB_TOKEN: ''
  with:
    gemini_api_key: ${{ secrets.GEMINI_API_KEY }}
    settings: |
      {"tools": {"core": []}}
```

## Fixing a finding

- Allow only the commands the job needs (`--allowedTools "Bash(gh issue view:*)"`
  for Claude Code, a `tools.core` list for Gemini CLI) instead of a deny list.
- Give the job that reads untrusted text read-only permissions and no
  `id-token: write`, and do writes (labels, comments) in a separate job that
  reads the agent's output.
- Run `claude-code-security-review` on `pull_request`, not on
  `pull_request_target` or issue events.
- Use `run-gemini-cli@v0` (or 0.1.22 or later) with the default `latest` CLI,
  and set workspace trust only in jobs whose workspace holds no pull-request
  code.

## Limits

See `GAPS.md`, "CI workflow agents". In short: other agent actions and GitHub
Agentic Workflows (`.github/workflows/*.md`) are not read; an `if:` that limits
who can start a job is not taken into account; callers in other repositories
and `workflow_run` chains are not followed; an agent on `schedule` or
`workflow_run` that reads issues or a fork's CI output is not reported; a
secret that reaches the agent through a file or an earlier step's output is
not seen.

## Sources

- Aonan Guan, Zhengyu Liu, Gavin Zhong, "Comment and Control" (2026-04-15; paper
  accepted at ACM CCS 2026),
  <https://oddguan.com/blog/comment-and-control-prompt-injection-credential-theft-claude-code-gemini-cli-github-copilot/>
- `anthropics/claude-code-action`: `action.yml`, `docs/configuration.md`
  (default tools), `docs/security.md` (write-access check,
  `allowed_non_write_users`, `pull_request_target`), `docs/migration-guide.md`
  (`allowed_tools` → `claude_args: --allowedTools`)
- `anthropics/claude-code-security-review` README (inputs, "not hardened
  against prompt injection")
- Claude Code CLI reference, <https://code.claude.com/docs/en/cli-reference>
  (`--allowedTools`/`--allowed-tools`, `--disallowedTools`,
  `--dangerously-skip-permissions`, `--permission-mode`)
- `google-github-actions/run-gemini-cli`: `action.yml` (`gemini --yolo`),
  example workflows, advisory GHSA-wpqr-6v78-jr5g,
  <https://github.com/google-github-actions/run-gemini-cli/security/advisories/GHSA-wpqr-6v78-jr5g>
- Gemini CLI configuration reference, <https://geminicli.com/docs/reference/configuration>
  (`tools.core`, `tools.exclude`, `security.disableYoloMode`,
  `GEMINI_CLI_TRUST_WORKSPACE`)
- GitHub Docs, "Events that trigger workflows" and "Workflow syntax"
  (`permissions`), <https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows>
