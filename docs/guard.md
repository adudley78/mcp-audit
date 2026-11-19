# `credenzo guard`

`credenzo guard` stops a call to an MCP tool that nobody approved. It is a
Claude Code `PreToolUse` hook. Claude Code runs it before each MCP tool call.
The guard reads `mcp-lock.json` and denies the call when the tool or its
server is not in the lock.

The agent does not decide. A tool that is not approved cannot be called,
whatever its description says.

## What it is for

An agent picks a tool from its name and its description. A server can write
both. A text check can guess that a description is hostile, and a new attack
can change every word. The guard does not read the text. It checks one fact:
did a person approve this tool of this server?

It protects an honest agent from:

- a server that someone added to the project's `.mcp.json` and nobody locked;
- a tool that a server added after it was locked;
- a copy of an approved tool on another server, which `lock --connect` does
  not record ([lock.md](lock.md), "A copy is not approved");
- a server whose command, arguments, URL, environment-variable names or
  header names changed after it was locked.

It does not contain an agent that works against you. An agent that can run
shell commands can change the lock file. See "Limits".

## Set it up

1. Record the approved servers and their tools:

   ```bash
   credenzo lock --connect
   ```

   Commit `mcp-lock.json`.

2. Print the hook settings:

   ```bash
   credenzo guard --print-hook
   ```

   ```json
   {
     "hooks": {
       "PreToolUse": [
         {
           "matcher": "mcp__.*",
           "hooks": [
             {
               "type": "command",
               "command": "/usr/local/bin/credenzo",
               "args": ["guard"],
               "timeout": 30,
               "onFailure": "block"
             }
           ]
         }
       ]
     }
   }
   ```

3. Merge that block into your user settings, `~/.claude/settings.json`. Use
   the user file (or managed settings), not the project's
   `.claude/settings.json`: a repository can change its own settings file.

`onFailure: block` makes a guard that cannot start, or that runs out of time,
stop the call. It needs Claude Code 2.1.295 or later; without it Claude Code
lets the call through when a hook fails.

## What it decides

| Case | Result |
|---|---|
| The call is not an MCP tool call | no decision |
| The tool is in the lock's record for its server, and the server's config entry is unchanged | no decision |
| The tool is not in the record | denied, LOCK-006 |
| The server is not in the lock | denied, LOCK-002 |
| The server's config entry changed since it was locked (command, arguments, URL, environment or header names; an entry with both a URL and a command; a launch through a file that is only named like Credenzo) | denied, LOCK-001 |
| The lock holds no tool record for the server (it was written without `--connect`) | denied, RUN-003 |
| The lock cannot be read, is a newer version, or its `tools` section fails its checksum | denied, RUN-002 |
| The server comes from a source the lock cannot describe, or there is no lock | no decision; denied (RUN-001) with `--strict` |

"No decision" means the guard prints nothing. Claude Code's own permission
rules then decide, as they do without the guard. The guard never approves a
call.

When the guard denies a call, the agent gets one sentence with the finding ID
and the names. You get the same sentence and the fix.

## Which servers the lock can describe

Claude Code tells the hook where each server comes from (`mcp_server.source`,
Claude Code 2.1.274 and later). The guard uses that, not the server's name.

| Source | Where the server is defined | Guard |
|---|---|---|
| `project` | the project's `.mcp.json` | decided from the lock |
| `user` | `~/.claude.json`, top level | decided from the lock when the lock holds user-level entries (`lock --include-user`); otherwise not covered |
| `local` | `~/.claude.json`, under the project's path (`claude mcp add` default) | not covered |
| `plugin`, `claudeai`, `managed`, `enterprise`, `agent`, `dynamic`, `sdk`, any other | plugins, claude.ai connectors, managed settings, subagent files, the SDK | not covered |

A server that is not covered passes by default. With `--strict` the guard
denies it. Use `--strict` with exceptions that you name:

```bash
credenzo guard --print-hook --strict --allow-source managed --allow-server "plugin:github:github"
```

- `--allow-source SOURCE`: with `--strict`, let servers of this source
  through.
- `--allow-server NAME`: with `--strict`, let this server through when the
  lock cannot describe it. The name is exact, as Claude Code reports it. It
  also lets a server through that is in the lock and unchanged but has no
  tool record, for a server that `lock --connect` cannot reach.

The exceptions never apply to a project server that is not in the lock. A
repository chooses the names of its own servers, so a name on your list
proves nothing about a server in `.mcp.json`. They never excuse a changed
server or a tool that is not in the record.

A local-scope server never uses the approval of a project server with the
same name, and a user server never uses a project server's record.

When the hook's environment has no home directory, the guard cannot read
`~/.claude.json`. User-level servers are then not covered (denied only with
`--strict`). Project servers are decided as usual.

## Options

| Option | Meaning |
|---|---|
| `--mode enforce` (default) | deny the call |
| `--mode monitor` | tell you, and let the call go on |
| `--strict` | also deny a server that the lock cannot describe |
| `--lock FILE` | use this `mcp-lock.json` (default: the nearest one above the project's `.mcp.json`, inside the git repository) |
| `--allow-server NAME` | repeatable |
| `--allow-source SOURCE` | repeatable |
| `--print-hook` | print the settings block and exit |

Exit status: 0 with a decision (or nothing) on stdout. In enforce mode the
guard exits 2 when it cannot read its input or fails; Claude Code stops the
call on exit 2.

## Cost

The guard starts no server and makes no network call. It reads the hook
input, `mcp-lock.json` and one config file.

- An entry that the lock holds as the config writes it: about 80 ms a call
  on a two-core machine (median of 40 calls, a lock with 10 servers and 300
  tools). This path loads only the Python standard library.
- An entry with a credential in its arguments or its URL, or a URL that
  `lock` wrote in another form (upper case, a default port, a query string):
  the guard uses the comparison that `lock --verify` uses. That loads the
  config parser and takes about 0.4 to 0.5 s a call.

## Limits

- **Names, not text.** The guard sees the tool's name. It does not see the
  description or the schema. A server that changes the text of an approved
  tool is not stopped here. For a local server, `credenzo run --mode enforce`
  compares each tool definition with the lock ([run.md](run.md)). For any
  server, `credenzo lock --verify --connect` reports the change.
- **An agent with a shell can change the lock.** The guard trusts the
  `mcp-lock.json` on disk. Commit the lock, and run
  `credenzo lock --verify` in CI or in a pre-commit hook: that compares the
  config with the committed lock. A deny rule for edits to `mcp-lock.json` in
  your Claude Code permissions stops the direct route.
- **A lock that you did not write.** The lock is the record of what a person
  approved. A repository that you cloned can bring its own `mcp-lock.json`
  that approves its own servers. The guard gives no protection there. Read
  `credenzo scan --project .` before you trust a repository's lock.
- **Sources that are not covered.** By default the guard decides only for
  project servers and locked user servers. A hostile repository can define a
  server in a subagent file (source `agent`); the default guard does not
  decide for it. `--strict` does.
- **Claude Code before 2.1.274** sends no `mcp_server`. The guard then reads
  the server from the tool name and looks in the project's `.mcp.json`, then
  in `~/.claude.json`. It cannot see a local-scope server that has the same
  name as a project server. A server whose name it finds in neither file is
  not covered (denied only with `--strict`).
- **Tool names as Claude Code writes them.** Claude Code replaces each
  character outside `A-Z a-z 0-9 _ -` with `_`. The docs state this rule for
  plugin servers; the guard applies it to every server and also accepts the
  name unchanged. Two tools of one server whose names differ only in such
  characters are one name to the guard.
- **Claude Code only.** Other clients have other hook formats. For them, wrap
  local servers with `credenzo wrap` ([run.md](run.md)).
- **Checked in one live session.** On 2026-11-19, in a Claude Code 2.1.328
  session with the settings that `--print-hook` prints, a call to an approved
  tool went through, a call to a tool that the server added after the lock
  was denied (LOCK-006), and a call to a server that was not locked was
  denied (LOCK-002). A `.mcp.json` server named `my.files v2` arrived as
  `mcp_server.name` `my.files v2` with the tool name
  `mcp__my_files_v2__ping`. Sources other than `project` were not run live;
  the tests give the guard the documented input
  (<https://code.claude.com/docs/en/hooks>, read 2026-11-19).
