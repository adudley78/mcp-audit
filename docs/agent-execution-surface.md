# Files in a repository that an agent harness runs or obeys

A cloned repository can carry files that a coding-agent harness or editor
executes, or treats as its own configuration, once you open the folder.
This page lists the ones mcp-audit reads, per harness, with the finding each
one produces and the vendor documentation that says why it can run code.
mcp-audit only reads these files. It never runs a harness, a hook, a script
or `git`.

Two scan paths reach them:

- **`scan --project <dir>`** walks the tree (depth 8, skipping `node_modules`,
  `.git` and the other directories in `discovery.py::_WALK_SKIP_DIRS`).
- **A default `scan` or `check`** (no path given, which is how the GitHub
  Action runs) reads the root of the working directory only.

A default scan run from your home directory skips the cwd-root check
entirely, and the `--project` walk skips the TRUST-008 paths directly under
`$HOME`: `~/.gemini/`, `~/.codex/` and `~/.claude/` are each harness's
user-level config, not a repository's.

## Gemini CLI

| File | What runs or applies | Finding | Scan path | Source |
|---|---|---|---|---|
| `.gemini/settings.json` | `hooks.<Event>[].hooks[]` entries with `type: "command"` run a shell command at that event (SessionStart, BeforeTool, …). Project hooks are fingerprinted; a new or changed one is warned about before it runs. | TRUST-008 HIGH (CRITICAL if a command reaches the network) | both | [Hooks](https://geminicli.com/docs/hooks/) |
| `.gemini/settings.json` | `tools.enableHooks: true` with no hooks of its own. Off by default in 0.18–0.22, so it switched on every layer's hooks; default `true` from 0.24 and replaced by `hooksConfig.enabled`. | TRUST-008 MEDIUM | both | `docs/get-started/configuration.md` at v0.18.0–v0.26.0; [configuration reference](https://geminicli.com/docs/reference/configuration/) |
| `.gemini/.env` | Loaded into the CLI's environment in preference to `.env` unless the folder is untrusted; never filtered by `advanced.excludedEnvVars`. Before 0.39.1, headless (CI) mode trusted the workspace automatically (GHSA-wpqr-6v78-jr5g, CVSS 10.0). | TRUST-008 MEDIUM; HIGH if it redirects `GOOGLE_GEMINI_BASE_URL`, `GOOGLE_VERTEX_BASE_URL` or a proxy; CRED-001 per literal secret (names only) | both | [Configuration reference](https://geminicli.com/docs/reference/configuration/), [Trusted folders](https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/trusted-folders.md), [advisory](https://github.com/google-github-actions/run-gemini-cli/security/advisories/GHSA-wpqr-6v78-jr5g) |

The Miasma worm (2026-06) planted a `.gemini/settings.json` SessionStart hook
identical to its `.claude/settings.json` one in at least 123 repositories
([SafeDep](https://safedep.io/miasma-worm-ai-coding-agent-config-injection/)).

## Codex

Codex loads a project's `.codex/` layer (config, hooks, rules) only once you
trust the project ([advanced config](https://learn.chatgpt.com/docs/config-file/config-advanced)).

| File | What runs or applies | Finding | Scan path | Source |
|---|---|---|---|---|
| `.codex/config.toml` | `notify`: a program run after every agent turn. Cymulate (2026) showed it running outside the sandbox from a project config; current Codex ignores it in project config and warns. | TRUST-008 HIGH (CRITICAL on network) | both | [Config reference](https://learn.chatgpt.com/docs/config-file/config-reference), [Cymulate](https://cymulate.com/blog/the-race-to-ship-ai-tools-left-security-behind/) |
| `.codex/config.toml` | `approval_policy = "never"`: Codex never asks before running a command. | TRUST-008 HIGH | both | [Config reference](https://learn.chatgpt.com/docs/config-file/config-reference) |
| `.codex/config.toml` | `sandbox_mode = "danger-full-access"`: no sandbox for the commands Codex runs. | TRUST-008 HIGH | both | [Config reference](https://learn.chatgpt.com/docs/config-file/config-reference) |
| `.codex/config.toml` | Inline `[hooks]` command handlers (reviewed and trusted per hook before they run). | TRUST-008 HIGH (CRITICAL on network) | both | [Hooks](https://learn.chatgpt.com/docs/hooks) |
| `.codex/hooks.json` | Command hooks, same schema and trust review. | TRUST-008 HIGH (CRITICAL on network) | both | [Hooks](https://learn.chatgpt.com/docs/hooks) |

## Claude Code

| File | What runs or applies | Finding | Scan path | Source |
|---|---|---|---|---|
| `.claude/settings.json`, `.claude/settings.local.json` | `hooks` (run shell commands at lifecycle events) | CFHYG-005, HOOK-001/002 | both | [Hooks](https://code.claude.com/docs/en/hooks) |
| same | Approval switched off or widened | HARNESS-001..006 | both | [Permissions](https://code.claude.com/docs/en/permissions) |
| same | `enabledMcpjsonServers`: named `.mcp.json` servers connect without a prompt once the folder is trusted | HARNESS-007 INFO (and HARNESS-002 for `enableAllProjectMcpServers`) | both | [Settings reference](https://code.claude.com/docs/en/settings-reference) |
| same | Top-level `env` sets an API endpoint (`ANTHROPIC_*_BASE_URL`, `OPENAI_BASE_URL`, `GOOGLE_*_BASE_URL`) or `HTTP(S)_PROXY` to a host that is not the provider's own. Applied after workspace trust and at startup in `claude -p`. CVE-2026-21852. | CFHYG-007 HIGH | both | [Settings reference: `env`](https://code.claude.com/docs/en/settings-reference#env), [env vars](https://code.claude.com/docs/en/env-vars), [Check Point](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/) |
| `.claude/scheduled_tasks.json` | Saved scheduled tasks (prompts run on a timer). Listed by Anthropic among "the files Claude Code runs on its own". | TRUST-008 MEDIUM | both | [Scheduled tasks](https://code.claude.com/docs/en/scheduled-tasks), [Sandboxing](https://code.claude.com/docs/en/sandboxing) |
| `.claude/workflows/` | Saved workflow scripts (JavaScript that steers subagents), run as `/<name>` by everyone who clones the repository. | TRUST-008 MEDIUM (names listed, contents not read) | both | [Workflows](https://code.claude.com/docs/en/workflows), [Sandboxing](https://code.claude.com/docs/en/sandboxing) |
| `.mcp.json` and other project MCP configs | MCP servers spawned on trust | TRUST-001 HIGH | `--project` | See `docs/severity-framework.md` |

## VS Code

| File | What runs or applies | Finding | Scan path | Source |
|---|---|---|---|---|
| `.vscode/tasks.json` | A task with `runOptions.runOn: "folderOpen"` runs when the folder opens. | TRUST-003 HIGH (CRITICAL on network) | both | See `docs/severity-framework.md` |
| `.vscode/settings.json` | Command-bearing keys (terminal profiles/env/shellArgs, `*Path` interpreters) | TRUST-003 HIGH (CRITICAL on network) | both | See `docs/severity-framework.md` |

The Keyv and Miasma worms (2026) both planted a folder-open `.vscode/tasks.json`
next to a `.claude/settings.json` SessionStart hook.

## Not read

Known gaps are listed in `GAPS.md` ("Other harnesses' auto-run files" and
"Repo-planted IDE auto-execution files"), including `.vscode/launch.json`,
JetBrains run configurations, Codex `requirements.toml` and
`[sandbox_workspace_write]`, Gemini `.gemini/policies/`, and the contents of
workflow scripts and scheduled-task prompts. Gemini CLI and Codex **MCP server**
definitions are a separate, queued surface.
