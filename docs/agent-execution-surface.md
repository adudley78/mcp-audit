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

git is the exception to both: a default scan checks the repository git itself
would use from the working directory (found the way git finds it, walking
upward), and the `--project` walk, which never descends into `.git`, still
reads each `.git` entry's config and lists its hooks (see "git" below).

A default scan run from your home directory skips the cwd-root check
entirely, and the `--project` walk skips the TRUST-008 paths directly under
`$HOME`: `~/.gemini/`, `~/.codex/` and `~/.claude/` are each harness's
user-level config, not a repository's.

## Gemini CLI

| File | What runs or applies | Finding | Scan path | Source |
|---|---|---|---|---|
| `.gemini/settings.json` | `hooks.<Event>[].hooks[]` entries with `type: "command"` run a shell command at that event (SessionStart, BeforeTool, …). Project hooks are fingerprinted; a new or changed one is warned about before it runs. | TRUST-008 HIGH (CRITICAL if a command reaches the network) | both | [Hooks](https://geminicli.com/docs/hooks/) |
| `.gemini/settings.json` | `tools.enableHooks: true` with no hooks of its own. Off by default in 0.18–0.22, so it switched on every layer's hooks; default `true` from 0.24 and replaced by `hooksConfig.enabled`. | TRUST-008 MEDIUM | both | `docs/get-started/configuration.md` at v0.18.0–v0.26.0; [configuration reference](https://geminicli.com/docs/reference/configuration/) |
| `.gemini/.env` | Loaded into the CLI's environment in preference to `.env` unless the folder is untrusted; never filtered by `advanced.excludedEnvVars`. Before 0.39.1, headless (CI) mode trusted the workspace automatically (GHSA-wpqr-6v78-jr5g, CVSS 10.0). | TRUST-008 MEDIUM; HIGH if it redirects `GOOGLE_GEMINI_BASE_URL`, `GOOGLE_VERTEX_BASE_URL` or a proxy; CRED-001 for a value matching one of CRED-001's secret patterns (names only) | both | [Configuration reference](https://geminicli.com/docs/reference/configuration/), [Trusted folders](https://github.com/google-gemini/gemini-cli/blob/main/docs/cli/trusted-folders.md), [advisory](https://github.com/google-github-actions/run-gemini-cli/security/advisories/GHSA-wpqr-6v78-jr5g) |

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
| `.codex/config.toml` | `[mcp_servers.<name>] http_headers_helper`: a shell command Codex runs on each connection to that server to print its HTTP headers; allowed in a project config (STORY-0110). | TRUST-008 HIGH (CRITICAL on network) | both | [`mcp_types.rs`](https://github.com/openai/codex/blob/main/codex-rs/config/src/mcp_types.rs) |
| `.codex/config.toml` | Inline `[hooks]` command handlers (reviewed and trusted per hook before they run). | TRUST-008 HIGH (CRITICAL on network) | both | [Hooks](https://learn.chatgpt.com/docs/hooks) |
| `.codex/hooks.json` | Command hooks, same schema and trust review. | TRUST-008 HIGH (CRITICAL on network) | both | [Hooks](https://learn.chatgpt.com/docs/hooks) |
| `AGENTS.md`, `AGENTS.override.md` (any directory from the project root down to the working directory; `~/.codex/AGENTS.md`, `~/.codex/AGENTS.override.md`) | Instructions: "Codex concatenates files from the root down", one per directory, override first, up to `project_doc_max_bytes` (32 KiB). No import syntax. | MEM-001/002 | agent-file scan | [AGENTS.md](https://learn.chatgpt.com/docs/agent-configuration/agents-md) |

## Claude Code

| File | What runs or applies | Finding | Scan path | Source |
|---|---|---|---|---|
| `.claude/settings.json`, `.claude/settings.local.json` | `hooks` (run shell commands at lifecycle events) | CFHYG-005, HOOK-001/002 | both | [Hooks](https://code.claude.com/docs/en/hooks) |
| same | Approval switched off or widened | HARNESS-001..006 | both | [Permissions](https://code.claude.com/docs/en/permissions) |
| same | `enabledMcpjsonServers`: named `.mcp.json` servers connect without a prompt once the folder is trusted | HARNESS-007 INFO (and HARNESS-002 for `enableAllProjectMcpServers`) | both | [Settings reference](https://code.claude.com/docs/en/settings-reference) |
| same | `sandbox` block: a key that weakens the Bash sandbox (`enableWeakerNestedSandbox`, `enableWeakerNetworkIsolation`, `network.allowAllUnixSockets`, `network.allowLocalBinding`, `enabled: false`), a proxy port, a code-running command taken out of it (`excludedCommands`), the Docker socket (`allowUnixSockets`), or a publish-anywhere host in `allowedDomains`. A repository's files can set these unless managed settings make the sandbox admin-required. | SANDBOX-001 HIGH/MEDIUM, SANDBOX-002 HIGH/MEDIUM, SANDBOX-003 MEDIUM (INFO under the user's `strictAllowlist`); SANDBOX-004 INFO for keys the file can't set. A `settings.local.json` counts only when git carries it | both | [Sandboxing](https://code.claude.com/docs/en/sandboxing), [Settings reference](https://code.claude.com/docs/en/settings-reference) |
| `.claude/settings.local.json` | One person's approvals and overrides; when tracked in git, Claude Code treats it as repository-supplied. Reported when it sits in a git work tree that no ignore file covers (ignore files are read; git is not run). | SANDBOX-005 MEDIUM (LOW for home paths with a username in any settings file headed for git) | both | [Settings](https://code.claude.com/docs/en/settings), [Permissions](https://code.claude.com/docs/en/permissions) |
| same | Top-level `env` sets an API endpoint (`ANTHROPIC_*_BASE_URL`, `OPENAI_BASE_URL`, `GOOGLE_*_BASE_URL`) or `HTTP(S)_PROXY` to a host that is not the provider's own. Applied after workspace trust and at startup in `claude -p`. CVE-2026-21852. | CFHYG-007 HIGH | both | [Settings reference: `env`](https://code.claude.com/docs/en/settings-reference#env), [env vars](https://code.claude.com/docs/en/env-vars), [Check Point](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/) |
| same | Top-level `env` chooses a Microsoft Foundry resource (`ANTHROPIC_FOUNDRY_BASE_URL` on `<resource>.services.ai.azure.com`, or `ANTHROPIC_FOUNDRY_RESOURCE`). The host is Microsoft's, but anyone can create a resource in their own Azure subscription. | CFHYG-008 INFO (names the resource to confirm) | both | [Microsoft Foundry](https://code.claude.com/docs/en/microsoft-foundry), [env vars](https://code.claude.com/docs/en/env-vars) |
| `.claude/scheduled_tasks.json` | Saved scheduled tasks (prompts run on a timer). Listed by Anthropic among "the files Claude Code runs on its own". | TRUST-008 MEDIUM | both | [Scheduled tasks](https://code.claude.com/docs/en/scheduled-tasks), [Sandboxing](https://code.claude.com/docs/en/sandboxing) |
| `.claude/workflows/` | Saved workflow scripts (JavaScript that steers subagents), run as `/<name>` by everyone who clones the repository. | TRUST-008 MEDIUM (names listed, contents not read) | both | [Workflows](https://code.claude.com/docs/en/workflows), [Sandboxing](https://code.claude.com/docs/en/sandboxing) |
| `.mcp.json` and other project MCP configs | MCP servers spawned on trust | TRUST-001 HIGH | `--project` | See `docs/severity-framework.md` |
| `.claude/agents/**/*.md` (subagent frontmatter) | `hooks` run shell commands while the subagent is active, once the folder holding the file is trusted (since 2.1.218; before, from untrusted folders) | AGENT-003 MEDIUM, plus HOOK-001/002 on each command | both | [Sub-agents](https://code.claude.com/docs/en/sub-agents), [Permissions: what runs before you trust a folder](https://code.claude.com/docs/en/permissions) |
| same | Inline `mcpServers` entries start when Claude delegates to the subagent, after folder trust (since 2.1.238); never in `mcp-lock.json` | AGENT-004 INFO/LOW (MEDIUM under a lock root), TRUST-001 HIGH under `--project`, and every per-server check as client `claude-code-agent` | both | [Sub-agents](https://code.claude.com/docs/en/sub-agents) |
| same | `permissionMode: acceptEdits`/`auto` loosens prompts for delegated tasks; `bypassPermissions` escalated before 2.1.267 | AGENT-001 MEDIUM | both | [Sub-agents](https://code.claude.com/docs/en/sub-agents) |
| `~/.claude/agents/**/*.md` | The same keys in your own (or copied-in) subagents, which run with no trust step | AGENT-001 LOW, AGENT-003 INFO, AGENT-004 INFO/LOW; HOOK-001/002 | default scan | [Sub-agents](https://code.claude.com/docs/en/sub-agents) |
| `.claude/skills/<name>/.claude-plugin/plugin.json` | The folder loads as the plugin `<name>@skills-dir` once the folder is trusted: its MCP servers (with per-server approval), hooks, language servers and `bin/` programs on the Bash PATH. Bundles and monitors are skipped in a repository. | SKILL-006 HIGH for a server (also TRUST-001 and the per-server checks), MEDIUM for hooks, language servers and `bin/` (HIGH if a program shadows a common command), plus HOOK-001/002 | both | [Plugins: loading](https://code.claude.com/docs/en/plugins/loading), [Skills](https://code.claude.com/docs/en/skills) |
| `.claude/skills/**/SKILL.md` frontmatter `hooks` | Registered when the skill is invoked, kept for the rest of the session, including in a `-p` run in a folder you have not trusted | SKILL-006 MEDIUM, plus HOOK-001/002 | both | [Hooks: Hooks in skills and agents](https://code.claude.com/docs/en/hooks) |
| Any other file in a skill folder | Scripts and setup guides the agent is told to run | SKILL-005 (install steps), SKILL-007 (unreadable content), SKILL-008 (bundled code plus another finding) | both | [skill-packages.md](skill-packages.md) |
| `CLAUDE.md`, `.claude/CLAUDE.md`, `CLAUDE.local.md`, `.claude/rules/**/*.md`; `AGENTS.md` and `.claude/AGENTS.md` (2.1.277+, when no `CLAUDE.md` is present or the setting says both) | Loaded into context every session (subdirectory files on demand). `@path` imports are expanded with them, four hops deep; an import outside the working directory loads after a one-time per-project approval. | MEM-003 MEDIUM (import outside the folder, or of a `.gitignore`'d file; LOW for `~/.claude/*.md`); MEM-001/002 on the files and everything they import | both (MEM-003); agent-file scan (MEM-001/002) | [Memory](https://code.claude.com/docs/en/memory) |

A default scan reads `~/.claude/agents/` and the working directory's
`.claude/agents/` (not the ones between it and the repository root); `--project`
walks every `.claude/agents/` under the directory. The frontmatter is read the
way Claude Code reads it (it ends at the first `---`, even mid-line) and also
up to the first `---` line; findings from both readings are kept. See
`docs/agent-files.md`.

## OpenClaw

The workspace is `~/.openclaw/workspace` by default; a repository can be one
(OpenClaw suggests keeping it in a private git repository).

| File | What runs or applies | Finding | Scan path | Source |
|---|---|---|---|---|
| `HEARTBEAT.md` | Read on a timer (`30m` by default): "Read HEARTBEAT.md if it exists ... Follow it strictly ... If nothing needs attention, reply HEARTBEAT_OK". A reply starting or ending with `HEARTBEAT_OK` is dropped when at most 300 characters remain; `NO_REPLY` and `notify: false` deliver nothing. Newer releases import it into automation jobs (`openclaw doctor --fix`). | MEM-004 HIGH when it forces that reply, pairs it with hiding a step, or uses it right after running something | both, plus `~/.openclaw/workspace/HEARTBEAT.md` in every default scan | [Heartbeat](https://docs.openclaw.ai/gateway/heartbeat), [Agent Commander](https://embracethered.com/blog/posts/2026/agent-commander-your-agent-works-for-me-now/) |
| `AGENTS.md`, `SOUL.md`, `USER.md`, `MEMORY.md` | Loaded every session (`MEMORY.md` in the main private session only). | MEM-001/002 | agent-file scan | [Agent workspace](https://docs.openclaw.ai/concepts/agent-workspace) |

## Other AGENTS.md readers

Cursor applies `AGENTS.md` "in the project root and subdirectories"
([rules](https://cursor.com/docs/context/rules)); GitHub Copilot reads
`AGENTS.md` files "stored anywhere within the repository", the nearest taking
precedence; [agents.md](https://agents.md/) lists further readers. Every
`AGENTS.md` in the walk gets MEM-001/002 in the agent-file scan, and the
`@path` imports in it get MEM-003 (Claude Code expands them).

## VS Code

| File | What runs or applies | Finding | Scan path | Source |
|---|---|---|---|---|
| `.vscode/tasks.json` | A task with `runOptions.runOn: "folderOpen"` runs when the folder opens. | TRUST-003 HIGH (CRITICAL on network) | both | See `docs/severity-framework.md` |
| `.vscode/settings.json` | Command-bearing keys (terminal profiles/env/shellArgs, `*Path` interpreters) | TRUST-003 HIGH (CRITICAL on network) | both | See `docs/severity-framework.md` |

The Keyv and Miasma worms (2026) both planted a folder-open `.vscode/tasks.json`
next to a `.claude/settings.json` SessionStart hook.

## git (every harness)

Every coding agent runs `git status` or `git diff` in the background when it
opens a folder. A repository that arrives with its `.git` folder intact (a zip,
a shared drive) can make that git run a program before any trust prompt:
GitSpawn (Manifold Security, 2026-09: seven agents, eight flaws;
[write-up](https://www.manifold.security/blog/ai-coding-agents-git-hijack)).
The keys and severities are in [`docs/git-exec.md`](git-exec.md).

| File | What runs or applies | Finding | Scan path | Source |
|---|---|---|---|---|
| `.git/config` (and in-tree `include.path` / `includeIf` targets) | Keys whose value git runs as a program: `core.fsmonitor` on every `git status`/`git diff`; `core.sshCommand`, `diff.external`, diff and filter drivers, `!` credential helpers on fetch, diff and checkout; editor, signing and merge-driver keys on commit or merge; programs git-lfs (`lfs.extension.*`, `lfs.customtransfer.*`) and delta (`delta.pager`) read from their own sections. An include outside the tree is reported but not read. | TRUST-006 HIGH / MEDIUM / LOW (INFO for known tools' own forms) | both | [git-config](https://git-scm.com/docs/git-config); GitSpawn |
| `.git/config.worktree`, `.git/worktrees/*/config.worktree` | The same keys, per worktree, when `extensions.worktreeConfig` is on. | TRUST-006 | both | [gitrepository-layout](https://git-scm.com/docs/gitrepository-layout) |
| `.git` file (`gitdir: …`) | Points git at another git directory, whose config and hooks then apply. | TRUST-006 / TRUST-007 on the target | both | [gitrepository-layout](https://git-scm.com/docs/gitrepository-layout) |
| `.git/hooks/post-index-change` | Run by `git status` when it refreshes the index. | TRUST-007 HIGH | both | [githooks](https://git-scm.com/docs/githooks); CVE-2026-26268 |
| `.git/hooks/*` (other githooks names), `core.hooksPath` | Run on commit, merge, checkout, push. A `core.hooksPath` inside the repository (husky) is listed; one outside is MEDIUM. | TRUST-007 INFO inventory; TRUST-006 for `core.hooksPath` | both | [githooks](https://git-scm.com/docs/githooks) |
| A nested bare repository (`HEAD`, `objects/`, `refs/`, not named `.git`) | git run inside it uses its `config` and hooks. INFO in a test fixture or dependency-cache directory when it runs nothing. | TRUST-007 HIGH | `--project` | git-config [`safe.bareRepository`](https://git-scm.com/docs/git-config#Documentation/git-config.txt-safebareRepository) |

## GitHub Actions

These run on GitHub's runners rather than on your machine, but with the
repository's secrets, and the text the agent reads can come from anyone.
Under `--project` only the project root and nested repository roots (a `.git`
entry) are read, because GitHub runs only a repository's root workflows.

| File | What runs or applies | Finding | Scan path | Source |
|---|---|---|---|---|
| `.github/workflows/*.yml`, `*.yaml` | A step using `anthropics/claude-code-action`, `anthropics/claude-code-security-review` or `google-github-actions/run-gemini-cli` on an issue, comment, review, discussion or `pull_request_target` event, with a secret, a writable token and tools open to any command. | WORKFLOW-001 HIGH; WORKFLOW-002 MEDIUM when a deny list is the only limit | both | ["Comment and Control"](https://oddguan.com/blog/comment-and-control-prompt-injection-credential-theft-claude-code-gemini-cli-github-copilot/); see `docs/ci-workflows.md` |
| same | A run-gemini-cli step below action 0.1.22 / Gemini CLI 0.39.1, or trusting a workspace that holds pull-request code. | WORKFLOW-003 HIGH | both | [GHSA-wpqr-6v78-jr5g](https://github.com/google-github-actions/run-gemini-cli/security/advisories/GHSA-wpqr-6v78-jr5g) |

## Not read

Known gaps are listed in `GAPS.md` ("Other harnesses' auto-run files",
"Repo-planted IDE auto-execution files" and "Git can run code"), including `.vscode/launch.json`,
JetBrains run configurations, Codex `requirements.toml` and
`[sandbox_workspace_write]`, Gemini `.gemini/policies/`, and the contents of
workflow scripts and scheduled-task prompts. Gemini CLI and Codex **MCP server**
definitions in these same files are read as MCP configs (STORY-0110; see
`docs/clients.md`): their servers go through every per-server check, and
`scan --project` reports each as TRUST-001.
