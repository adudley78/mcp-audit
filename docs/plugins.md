# Claude Code plugins

`mcp-audit plugins discover`, `mcp-audit plugins scan`, and `scan --include-plugins`
look at the plugins Claude Code has installed (STORY-0080). Fully offline: mcp-audit
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

**Why PLUGIN-001 matters.** Plugin4Shell (AIR Security, 2026-09-17) showed Claude
Code, Codex, Copilot and Gemini CLI checking out a marketplace-pinned commit without
verifying the result, so a hostile plugin repository could swap the code while the pin
still looked honored. Claude Code fixed it in 2.1.179. When neither `plugin.json` nor
the marketplace entry sets `version`, Claude Code records a git plugin's version as
the commit SHA shortened to 12 characters, so a recorded version that is not the
pinned SHA's prefix is the on-disk symptom. It is also what a plugin looks like when
the marketplace moved its pin and the plugin has not been updated yet, which is why
the finding is MEDIUM and the remediation is to update first.

PLUGIN-001 never guesses. It is skipped when a version is set in `plugin.json` or the
marketplace entry (the recorded version is then that string), for `git-subdir`
sources (their version also carries a path hash in an undocumented form), and when
the recorded version is `unknown` (anthropics/claude-code#17032).

## What plugins ship

- **Skills and commands** go through the agent-file checks (POISON-*, SKILL-*), with
  scope `plugin`.
- **MCP servers** declared in a plugin's `.mcp.json` or inline in `plugin.json` go
  through the full analyzer pipeline as client `claude-code-plugin`, under
  `scan --include-plugins` and `plugins scan`.

See `GAPS.md` for what is not covered.
