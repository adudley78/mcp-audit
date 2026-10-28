# Managed MCP policy report (MANAGED-001..005)

An organization can decide which MCP servers Claude Code loads on its developers'
machines. It deploys files to a system directory, and Claude Code reads them above
every user and project setting. mcp-audit reads the same files and compares them with
the servers it found, so you can see three things a developer normally can't:

- which policy is on this machine;
- which configured servers the policy keeps from loading (Claude Code removes them
  from `/mcp` without saying why);
- where the policy leaves a gap: managed settings with no MCP policy, an allowlist a
  repository can widen, or an allowlist that trusts server names.

The check runs in every default `scan` and `check`, and in `scan --project` for the
repository's servers and settings files. It reads files only, makes no network call,
and is skipped when you pass an explicit config path.

## What is read

| File (in the system directory) | Read for |
|---|---|
| `managed-settings.json`, then `managed-settings.d/*.json` in alphabetical order (hidden files skipped) | `allowedMcpServers`, `deniedMcpServers`, `allowManagedMcpServersOnly`, `managedMcpServers`, `strictPluginOnlyCustomization` |
| `managed-mcp.json` | exclusive control: its presence means no user, project or plugin server loads |

The system directory is `/Library/Application Support/ClaudeCode/` on macOS,
`/etc/claude-code/` on Linux and WSL, and `C:\Program Files\ClaudeCode\` on Windows
(Anthropic, [Deploy managed settings](https://code.claude.com/docs/en/managed-settings)).
Drop-in files merge the way Claude Code merges them: lists combine with duplicates
removed, a single value is replaced by the later file, and a later `managedMcpServers`
entry with the same name replaces the earlier one. Each file is capped at 1 MiB, the
directory at 256 drop-ins and 8 MiB; anything skipped is listed in the scan's errors.

**Not read:** an MDM configuration profile, the Windows HKLM/HKCU registry, and
server-managed settings from the claude.ai console. Claude Code ranks those above the
files, and under its default "first-wins" rule a higher source that delivers any
policy key replaces the files' allowlist. `deniedMcpServers` and
`allowManagedMcpServersOnly` are still read from every admin source (Claude Code
2.1.273 or later), and `managed-mcp.json` always applies. Run `/status` in Claude Code
to see which source is in force.

## How a server is evaluated

The rules are Anthropic's, from
[Control MCP server access for your organization](https://code.claude.com/docs/en/managed-mcp):

1. **Exclusive control.** With a readable `managed-mcp.json`, "Users can't add,
   modify, or use any other MCP servers, including plugin-provided servers". Every
   user, project and plugin server is reported.
2. **Denylist.** "A server that matches any denylist entry, by URL, command, or name,
   is blocked. Nothing overrides a denylist match."
3. **Plugin servers only.** `strictPluginOnlyCustomization` set to `true` or to an
   array containing `"mcp"`: "Users can't add servers through `~/.claude.json` or
   `.mcp.json`; plugin servers still load". A value that is neither a boolean nor an
   array is treated as `true` (managed-settings, "Keys that fail closed", 2.1.282 or
   later). A quoted boolean or an object marks a policy as present but is never used to
   report a server as blocked.
4. **Provided servers.** A `managedMcpServers` entry "takes precedence over a server
   with the same name in local, project, or user scope, and over a plugin server …
   that points at the same URL" (Claude Code 2.1.259 or later). Entries Claude Code
   drops (not `http`/`sse`, not `https://`, a `command`/`args`/`env`/`headersHelper`
   member, a `${VAR}` reference, a name outside letters, numbers, `-` and `_`) are
   listed in MANAGED-001 and don't count, as do entries with control or invisible
   formatting characters.
5. **Allowlist.** Unset: every server loads. An empty list: none of the servers users
   add loads. Otherwise a remote server must match a `serverUrl` entry and a stdio
   server a `serverCommand` entry; "A `serverName` match counts only when the
   allowlist contains no" entries of that kind. When `allowManagedMcpServersOnly` is
   not true, allowlists from every settings scope merge, so mcp-audit merges the
   entries in `~/.claude/settings.json` and the project's `.claude/settings.json` and
   `.claude/settings.local.json` into the managed list and applies the per-transport
   rule to the merged list before reporting a server as blocked. `allowedMcpServers:
   null` removes the key; when a file does that, allowlist verdicts are not reported.

`allowManagedMcpServersOnly` reads `true`/`"true"` as locked and `false`/`"false"` as
unlocked; `null` removes it; any other value fails closed and reads as `true`.

Matching: commands match exactly, every argument in order; `serverUrl` patterns take
`*` anywhere (including the scheme), hostnames compare case-insensitively and ignore a
trailing dot, paths are case-sensitive, and a pattern with no path matches any path.
Ports: with no port in the pattern, a hostname written out in full matches only the
scheme's default port (443 for `https`, 80 for `http`) and a hostname with a `*` in it
matches every port; `:*` matches every port, 443 included; an explicit port must match
(a server URL with no port is on the default port). A server whose scheme has no
known default port, or whose port isn't a number, is undecidable and never reported.
A malformed entry is stripped, as Claude Code strips it; an `allowedMcpServers` value
that isn't a list is enforced as an empty allowlist.

Servers compared: user scope (`~/.claude.json`), project `.mcp.json`, and installed
plugin servers. Subagent inline servers and other clients (Cursor, VS Code, Claude
Desktop) are not, because the policy doesn't govern them or the documentation doesn't
say it does.

## Findings

| ID | Severity | Fires when |
|---|---|---|
| MANAGED-001 | INFO | Any managed file exists. Describes the MCP policy it sets (or "no MCP policy keys"). Not an advisory. |
| MANAGED-002 | INFO | A configured Claude Code server does not load under the policy; the evidence names the reason (`exclusive`, `denied`, `plugin-only`, `shadowed`, `not-allowed`). Not an advisory. |
| MANAGED-003 | LOW | Managed settings files exist but set no MCP key, and there is no `managed-mcp.json`: "By default, anyone running Claude Code can connect any MCP server they choose." Not an advisory. |
| MANAGED-004 | MEDIUM / LOW | The managed allowlist is not locked and a settings file adds entries it doesn't have. MEDIUM for a repository's shared `.claude/settings.json` (it widens the list for everyone who opens the repository), LOW for `.claude/settings.local.json` and `~/.claude/settings.json`. A file reached through a symlinked `.claude` directory is not attributed to the repository. |
| MANAGED-005 | LOW | The managed allowlist has `serverName` entries and no `serverUrl` entries (remote servers) and/or no `serverCommand` entries (stdio servers): "A `serverName` entry, in either list, is not a security control." |

Commands and URLs in finding text have the values of secret-named flags
(`--api-key VALUE`, `--token=VALUE`), URL passwords, secret-named query parameters and
known credential formats removed.

## What it can't tell

- A `${VAR}` in a policy entry or a server's command or URL is not expanded; such a
  pair is never reported as blocked.
- Whether an MDM profile or server-managed settings replace the files (see above).
- Cursor and VS Code organization MCP controls are not checked. VS Code documents
  `ChatAllowedMcpServers`, `ChatDeniedMcpServers` and `ChatAllowManagedMcpServersOnly`
  policies but not, on the pages read for this story, the shape of their entries.
