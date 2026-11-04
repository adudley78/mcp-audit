# Managed MCP policy report (MANAGED-001..007)

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
repository's servers and settings files. It reads files, macOS managed preferences and the Windows registry (read-only), makes
no network call, and is skipped when you pass an explicit config path.

## What is read

| File (in the system directory) | Read for |
|---|---|
| `managed-settings.json`, then `managed-settings.d/*.json` in alphabetical order (hidden files skipped) | `allowedMcpServers`, `deniedMcpServers`, `allowManagedMcpServersOnly`, `managedMcpServers`, `strictPluginOnlyCustomization` |
| `managed-mcp.json` | exclusive control: its presence means no user, project or plugin server loads |

The system directory is `/Library/Application Support/ClaudeCode/` on macOS,
`/etc/claude-code/` on Linux and WSL, and `C:\Program Files\ClaudeCode\` on Windows
(Anthropic, [Deploy managed settings](https://code.claude.com/docs/en/managed-settings)).
Drop-in files merge the way Claude Code merges them: lists combine with duplicates
removed (including `strictPluginOnlyCustomization` arrays), a single value is replaced by the later file, and a later `managedMcpServers`
entry with the same name replaces the earlier one. Each file is capped at 1 MiB, the
directory at 256 drop-ins and 8 MiB; anything skipped is listed in the scan's errors.

## Which source is in force

Claude Code takes admin policy from several places and ranks them (Anthropic,
[Deploy managed settings](https://code.claude.com/docs/en/managed-settings)). mcp-audit
reads every one it can and evaluates MANAGED-001..005 against the one Claude Code uses:

| Rank | Source | Read how |
|---|---|---|
| 1 | Server-managed settings (claude.ai console) | **Not read**: there is no local copy. Run `/status` in Claude Code to see whether one is in force. |
| 2 | **macOS** configuration profile, domain `com.anthropic.claudecode` | `/Library/Managed Preferences/com.anthropic.claudecode.plist` (device), then `/Library/Managed Preferences/<user>/com.anthropic.claudecode.plist` (the current user's profile), parsed with `plistlib`, files only. A symlink that leaves `/Library/Managed Preferences` is not followed. |
| 2 | **Windows** `HKLM\SOFTWARE\Policies\ClaudeCode`, value `Settings` | `REG_SZ` / `REG_EXPAND_SZ` holding the same JSON as `managed-settings.json`, read with `winreg` (`KEY_READ` only; the value is not environment-expanded). |
| 3 | Managed settings files | As in "What is read" above. |
| 4 | **Windows** `HKCU\SOFTWARE\Policies\ClaudeCode`, value `Settings` | Used only when no admin document (rank 2 or 3) is present. |

Plist and registry reads are capped at 1 MiB, never write, and never import `winreg`
off Windows. A plist that expands to more than 100,000 nodes (a shared-reference binary
plist can be a few hundred bytes) is reported as "plist too complex" and not read.

**What counts as a source.** A *policy key* is any settings key other than the two
control keys `wslInheritsWindowsSettings` and `managedSourcesBehavior`, with a value
other than `null`. A plist, `HKLM` value or file that has none (`{}`, only control
keys, only `null` values, an empty `managed-settings.json`) "doesn't count": it is not
a source and not "present". A document is present when it sets a policy key or exists
but can't be read. `HKCU` is used only when no admin document is present, and only if
it has at least one policy key.

**First-wins (the default `managedSourcesBehavior`).** The highest-ranked admin source
that delivers a policy key is the one evaluated, and the other sources' values are
ignored, except the keys Claude Code reads from every admin source (2.1.273 or later):
`deniedMcpServers` (an entry in any admin source applies), `allowManagedMcpServersOnly`
(a `true` in any admin source turns the lock on) and, "while the lock is on, the managed
`allowedMcpServers` list comes from the highest-ranked admin source that sets one", so
a lock in `HKLM` with the allowlist in the files evaluates the files' list.

**Merge.** `managedSourcesBehavior: "merge"` is read from the highest-ranked source that
carries the key or a policy key (a lower source can't opt itself in; an `HKLM` value
holding only `"merge"` does merge). Then, per Anthropic's table: `deniedMcpServers`
entries union; `allowedMcpServers`, a restriction allowlist, is taken whole from the
highest-ranked source that sets it, with no entries added from lower sources; locks
(`allowManagedMcpServersOnly`, `strictPluginOnlyCustomization`) take the strictest
value; a `managedMcpServers` entry of the same name from a higher source wins. `HKCU`
never merges. Evidence on every finding names the source
(`source: HKLM registry`, `source: macOS configuration profile (device)`,
`source: HKCU registry (user-writable)`, `source: merged admin sources (...)`); with only
the managed files present the output is exactly what earlier versions printed, on every
platform.

The device plist is ranked before the current user's profile plist. Anthropic's page
does not rank those two against each other; mcp-audit treats them as two admin documents
of the same tier, device first.

Not read: server-managed settings (above), and MDM profiles for any user other than the
current one.

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

Servers compared: user scope (the top-level `mcpServers` in `~/.claude.json`), project
`.mcp.json`, and installed plugin servers. Local-scope servers (`projects.<path>.mcpServers`
in `~/.claude.json`) are not compared. Subagent inline servers and other clients (Cursor, VS Code, Claude
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

| MANAGED-006 | MEDIUM | Policy exists only where the user can change it: **HKCU** with no admin document present (and at least one policy key), or managed policy files in a place the current non-root user can write. Probed: the managed directory, `managed-settings.d` (even empty: a user can add a drop-in), each settings file with policy keys and `managed-mcp.json`; a path counts when the current user owns it or `access(W_OK)` is true (the evidence says "owned" or "writable through group or other permission bits or an ACL"). Under WSL Anthropic notes "/etc/claude-code is user-writable as well", so policy files there count. Title "Claude Code policy is set, not enforced"; evidence names the source and the policy key names (each capped at 64 characters). Windows reports the HKCU half only, and a scan run as root skips the file half. Not an advisory. |
| MANAGED-007 | INFO | An admin source Claude Code can't parse: a plist that is not a plist or whose top level is not a dictionary, or an `HKLM` value that is not a string, is empty, is not JSON or not an object. Claude Code "refuses to start" on it, even when another source delivers a valid policy, and MANAGED-002..005 are withheld. A source the operating system denied reading ("every session starts without that source's policies") or that failed for another reason (or hit mcp-audit's 1 MiB / complexity limit) is not reported as 007: MANAGED-001 says what happened. A malformed `HKCU` value never blocks launch and is ignored. Not an advisory. |

Commands and URLs in finding text have secrets removed: the values of secret-named
flags (`--api-key VALUE`, `--token=VALUE`) and assignments (`-e GITHUB_TOKEN=…`,
`--env=API_KEY=…`), whatever follows `Authorization:`, `Bearer ` or `Basic `, URL
passwords, secret-named query and fragment parameters (`?sig=…`, `X-Amz-Signature=…`,
`#access_token=…`), and known credential formats. The same launch-argument redaction
as the JSON `servers[].args` output (STORY-0108) runs last.

**Verdicts are withheld when a managed file can't be read.** If a managed settings
file is unreadable, over the size limit or not a JSON object, or the
`managed-settings.d` directory can't be listed, only MANAGED-001 is reported, saying
why: Claude Code drops a source it can't read and refuses to start on a managed
document it can't parse, so a verdict built from the remaining files would be a guess.

## What it can't tell

- A `${VAR}` in a policy entry or a server's command or URL is not expanded; such a
  pair is never reported as blocked.
- Whether server-managed settings from the claude.ai console replace the source mcp-audit evaluated (see above).
- Cursor and VS Code organization MCP controls are not checked. VS Code documents
  `ChatAllowedMcpServers`, `ChatDeniedMcpServers` and `ChatAllowManagedMcpServersOnly`
  policies but not, on the pages read for this story, the shape of their entries.
