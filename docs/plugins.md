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

## Findings

| ID | Severity | Fires when |
|---|---|---|
| PLUGIN-001 | MEDIUM | A git-sourced plugin (`github`/`url`) is pinned to a commit, but the version Claude Code recorded is not that commit |
| PLUGIN-002 | LOW | A git-sourced plugin has no `sha` pin, so it follows a branch |

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
| MOD-002 | HIGH / MEDIUM | One mod reads secrets (`$.env.get`, `$.settings.read`: HIGH) or files (`$.fs.read`: MEDIUM) and can send data out (`$.http.fetch`, `$.process.run`, `$.process.spawn`). A `Read(.env)` deny rule doesn't cover a mod's own `$.fs.read`. |
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
auto-discovers configs) includes them by default, along with PLUGIN-001/002:

| Command | Plugin MCP servers | PLUGIN-001/002 and MOD-* | Plugin skills and commands |
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
