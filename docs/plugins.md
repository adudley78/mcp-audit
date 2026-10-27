# Claude Code plugins

`mcp-audit plugins discover` and `mcp-audit plugins scan` look at the plugins Claude
Code has installed (STORY-0080), and a normal `mcp-audit scan` includes them by
default. Fully offline: mcp-audit
reads the files Claude Code keeps under its plugins root and never runs git, a
package manager, or the agent.

## What it reads

The plugins root is `~/.claude/plugins`, or `CLAUDE_CODE_PLUGIN_CACHE_DIR` when set.

| File | Used for |
|---|---|
| `installed_plugins.json` | every install record: plugin id, scope, project, install path, recorded version |
| `known_marketplaces.json` | where each marketplace's clone lives |
| `<marketplace>/.claude-plugin/marketplace.json` | each plugin's `source`, including a `sha` pin |
| `<install path>/.claude-plugin/plugin.json` | the plugin's own `version`, and inline `mcpServers` |
| `<install path>/.mcp.json`, `skills/**/SKILL.md`, `commands/*.md` | what the plugin ships |
| `<install path>/.git`: `HEAD`, loose refs under `refs/`, `packed-refs`, `config`, hook names | when a plugin's install directory is a git checkout: the commit it holds, branches named like a SHA, and git settings that run commands (PLUGIN-003/004, TRUST-006/007) |
| `marketplaces/<name>/.git` | the git config and hooks of each marketplace clone Claude Code fetches into (TRUST-006/007) |

## Findings

| ID | Severity | Fires when |
|---|---|---|
| PLUGIN-001 | MEDIUM | A git-sourced plugin (`github`/`url`) is pinned to a commit, but the version Claude Code recorded is not that commit |
| PLUGIN-002 | LOW | A git-sourced plugin has no `sha` pin, so it follows a branch |
| PLUGIN-003 | CRITICAL | A pinned plugin's git checkout resolves `HEAD` to a commit other than the pin, and either `HEAD` is on a branch named like a commit SHA or `FETCH_HEAD` (the Plugin4Shell shape) or Claude Code's install record says it installed the pin |
| PLUGIN-003 | MEDIUM | The checkout's `HEAD` differs from the pin for a reason the install record doesn't explain (including `HEAD` on an ordinary branch), or `HEAD` can't be resolved by reading files |
| PLUGIN-004 | HIGH | A git-sourced plugin's checkout holds a branch, tag or remote branch named like a commit SHA (40 or 64 hex characters) or `FETCH_HEAD` |
| PLUGIN-004 | MEDIUM | The marketplace entry's `sha` is set but is not a full 40-character SHA |
| PLUGIN-004 | LOW | A plugin pinned to a full SHA is fetched from a host other than github.com |

**What PLUGIN-001 checks, and what it does not.** When neither `plugin.json` nor the
marketplace entry sets `version`, Claude Code records a git plugin's version as the
commit SHA shortened to 12 characters. PLUGIN-001 compares that record with the
commit the marketplace pins today. A mismatch usually means the marketplace moved its
pin and the plugin has not been updated yet; it can also mean the record does not
match the pin for some other reason. That is why the finding is MEDIUM and the
remediation is to update first.

It is not a Plugin4Shell detector. Plugin4Shell (AIR Security, 2026-09-17) showed
Claude Code, Codex, Copilot and Gemini CLI checking out a marketplace-pinned commit
without verifying the result, so a hostile plugin repository could swap the code
while the agent still reported the pinned commit. A swap recorded that way leaves no
mismatch, and PLUGIN-001 does not hash plugin files, so it cannot see one. Claude
Code fixed the checkout in 2.1.179; the remediation points there.

PLUGIN-001 never guesses. It is skipped when a version is set in `plugin.json` or the
marketplace entry (the recorded version is then that string), for `git-subdir`
sources (their version also carries a path hash in an undocumented form), and when
the recorded version is `unknown` (anthropics/claude-code#17032).

## Pin vs the checkout (PLUGIN-003/004, STORY-0096)

PLUGIN-001 compares two records. PLUGIN-003 compares the pin with what is on disk,
the control the Cloud Security Alliance's Plugin4Shell note asks for: keep "a record
of exactly which commit each installed plugin currently resolves to" and verify it
"independently of the agent's self-reported pin status"
([CSA](https://labs.cloudsecurityalliance.org/research/csa-research-note-plugin4shell-ai-coding-agent-supply-chain/)).

**How the swap works.** An agent installing a pinned plugin runs `git clone` and
then `git checkout <sha>`
([AIR Security](https://www.air.security/blog-posts/plugin4shell)). When a local
branch has exactly that name, git checks out the branch, not the commit, and only
prints `warning: refname '<sha>' is ambiguous`. A clone creates a local branch for
the remote's default branch, so a repository whose default branch is named after the
pinned SHA wins; a non-default branch with that name only arrives as
`refs/remotes/origin/<sha>` and the checkout falls back to the commit. The Gemini CLI
variant (`git fetch origin <sha>; git checkout FETCH_HEAD`) is beaten the same way by
a default branch named `FETCH_HEAD`. Verified with git 2.43: after the swap, `.git/HEAD`
reads `ref: refs/heads/<sha>` (or `ref: refs/heads/FETCH_HEAD`) instead of the
detached commit a real pinned checkout leaves; a *tag* named like a full SHA does not
win (git takes a full 40-hex name as the object), but for an abbreviated SHA a tag or
branch of that name does.

**What mcp-audit reads, and never runs.** Running git in a checkout someone else
shaped is the GitSpawn attack (`docs/git-exec.md`), so mcp-audit reads `.git/HEAD`,
the loose ref files and `packed-refs` as text, follows at most five symbolic refs as
git does, and reads no objects. The install directory must sit under the plugins root
with no symbolic link between them; a symlinked `.git`, a ref that is a symbolic link
outside `refs/`, or a `.git` file pointing outside the plugins root is not followed.
HEAD and loose refs are read up to 4 KiB, `packed-refs` up to 32 MiB, with 20,000
loose refs per checkout, and 64 MiB, 100,000 refs and 512 checkouts per scan; anything cut short is
named in the scan's errors, and a pinned plugin whose `HEAD` could not be resolved
gets PLUGIN-003 MEDIUM rather than silence.

**When it applies.** Claude Code 2.1.311 copies a plugin into
`cache/<marketplace>/<plugin>/<version>/` without its `.git` (observed for `url`,
`git-subdir` and relative-path sources, 2026-10-27), so for plugins it installed there is
no checkout to read and PLUGIN-003 and PLUGIN-004 HIGH stay silent. Earlier versions kept
the clone's `.git` in the cache for at least some installs (a public bug report against
2.1.131, anthropics/claude-code#56740), and Claude Code keeps a cached copy until the
plugin's computed version changes, so a plugin swapped before the 2.1.179 fix can still
be on disk: 2.1.179 checks HEAD at install time (observed on 2.1.311: "SHA pin
verification failed: expected HEAD to be …, got …. Refusing to install."), it does not
re-check copies already installed.

**How PLUGIN-003 decides.** With the pin `S` and the checkout's `HEAD` resolving to
`H`:

| Situation | Result |
|---|---|
| `H` is `S` | nothing |
| `H` is not `S`, and `HEAD` is on a branch named like a SHA or `FETCH_HEAD` | CRITICAL (the Plugin4Shell shape) |
| `H` is not `S`, and the install record says the pin was installed (`gitCommitSha` is `S`, or the recorded version is `S`'s 12-character prefix when no version string is set) | CRITICAL (the record and the disk disagree) |
| `H` is not `S`, `HEAD` is detached, and the record names `H` | nothing: the marketplace moved its pin after install (PLUGIN-001 reports that for plugins without a version string) |
| anything else where `H` is not `S` | MEDIUM: the record doesn't explain it; a pinned install leaves `HEAD` detached at the commit |
| `HEAD` can't be resolved, or the checkout uses SHA-256 ids | MEDIUM: could not be verified |

`gitCommitSha` is a field Claude Code writes into `installed_plugins.json` but doesn't
document. On 2.1.311 it held the resolved commit of a `url` or `git-subdir` plugin (the
pin) and the marketplace's commit for a relative-path plugin.

**The update channel (PLUGIN-004).** A SHA-shaped branch, tag or remote branch in a
plugin's checkout is HIGH whether or not the plugin is pinned: no legitimate workflow
needs one, and GitHub refuses branch names shaped like a full SHA. A `sha` that is set but
is not a full 40-character SHA is MEDIUM (Claude Code's marketplace reference requires
the full form; git reads an abbreviated hash as a ref name first). A full-SHA pin on a
host other than github.com is LOW: GitLab, Bitbucket and self-hosted servers accept
SHA-shaped branch names, so only the agent's own check (Claude Code 2.1.179 and later)
stands between the pin and a swap. The host is read strictly: userinfo and port are
dropped, anything other than exactly `github.com` counts as another host, and a
backslash in the authority makes the host unknown.

**Checkouts get the git checks too.** Each plugin checkout and each marketplace clone
under `marketplaces/` gets STORY-0089's TRUST-006/007 (git config that runs a command,
hooks): Claude Code runs git in marketplace clones whenever it refreshes them.

## Mods (MOD-001..006, STORY-0085)

A mod is a plugin whose `hooks/hooks.json` has a `modules` key naming a JavaScript or
TypeScript hooks module. Mods shipped in Claude Code 2.1.287 (2026-10-01). They run
inside Claude Code with your permissions and aren't sandboxed. A mod can read files and
environment variables, start programs, make network requests, rewrite prompts and tool
descriptions, and approve a tool call before the permission prompt appears.

mcp-audit finds mods in three places:

- installed plugins;
- mods Claude wrote during a session, in `~/.claude/dev-mods/<session>/<mod>/`;
- directories in `CLAUDE_CODE_PLUGIN_DIRS`, from the environment or your settings.

It reads each hooks module and the files it imports, and never runs them. Claude Code
refuses to load a mod unless its event names are string literals and its `$` calls are
written in full, so this static read sees the same hooks and calls that
`claude plugin validate` prints. The findings follow Anthropic's own review checklist
([Review what a mod can do](https://code.claude.com/docs/en/plugins/mods/admin#review-what-a-mod-can-do)):

| ID | Severity | Fires when |
|---|---|---|
| MOD-001 | HIGH | The mod hooks `tool.check`, so it can allow or deny tool calls before you're asked. In auto mode, a call it approves skips the classifier. |
| MOD-002 | HIGH / MEDIUM | One mod reads secrets (`$.env.get`, `$.settings.read`: HIGH) or files (`$.fs.read`: MEDIUM) and makes network requests (`$.http.fetch`). A `Read(.env)` deny rule doesn't cover a mod's own `$.fs.read`. A program the mod starts could also send data; that is MOD-004. |
| MOD-003 | MEDIUM | The mod rewrites what Claude reads (`tool.describe`, `prompt.compose`, `prompt.section`, `prompt.context`, `prompt.attachment`, `skill.prompt`, `session.append`) or submits prompts as you (`$.prompt.submit`). |
| MOD-004 | MEDIUM | The mod starts programs (`$.process.run`/`spawn`) or sets environment variables for later commands (`$.env.set`). |
| MOD-005 | INFO | Inventory: one per mod, with its events and calls. |
| MOD-006 | MEDIUM | `CLAUDE_CODE_PLUGIN_DIRS` is set in your Claude Code settings, so every session loads those directories. |

**The built-in guard.** `sec-default@builtin` stops user mods from overriding deny
rules and managed hooks, but it loads only on a machine with managed settings or for a
Team or Enterprise sign-in. mcp-audit reads the managed settings file
(`/Library/Application Support/ClaudeCode/`, `/etc/claude-code/`,
`C:\Program Files\ClaudeCode\`, plus `managed-settings.d/`). When it finds none, the
findings say the guard wasn't detected; they don't say it's off, because MDM, registry
or server-delivered policy and your sign-in aren't visible offline. With
`allowManagedModsOnly` set, user mods don't load, so only MOD-005 is reported for them.
With `allowModsToOverrideDenyRules` set, MOD-001 says so.

## What plugins ship

- **Skills and commands** go through the agent-file checks (POISON-*, SKILL-*), with
  scope `plugin`.
- **MCP servers** declared in a plugin's `.mcp.json` or inline in `plugin.json` go
  through the full analyzer pipeline as client `claude-code-plugin`.

## In a normal scan

A plugin's MCP servers run in Claude Code like any other configured server, so
`mcp-audit scan` (and `check`, `dashboard`, `shadow`, `sbom`, `watch`, everything that
auto-discovers configs) includes them by default, along with PLUGIN-001..004:

| Command | Plugin MCP servers | PLUGIN-001..004 and MOD-* | Plugin skills and commands |
|---|---|---|---|
| `mcp-audit scan` | yes | yes | with `--include-agent-files` |
| `mcp-audit scan --path <file>` | no | no | with `--include-agent-files` |
| `mcp-audit scan --no-plugins` | no | no | no |
| `mcp-audit plugins scan` | yes | yes | yes |

`mcp-audit plugins discover` shows a Mod column (the number of hooks), and its JSON
gives each mod's events and calls, including Claude-written dev mods and
`CLAUDE_CODE_PLUGIN_DIRS` directories.

An explicit `--path` means "scan exactly this", so plugin servers stay out of it.
`mcp-audit lock` never records plugin servers: their marketplace `sha` already pins
them (PLUGIN-001 checks it), and their cache paths differ per machine.

See `GAPS.md` for what is not covered.
