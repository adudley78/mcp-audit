# `mcp-audit reach`: what can the agents on this machine touch?

```bash
mcp-audit reach                         # one card per agent, terminal
mcp-audit reach --format json           # docs/reach.schema.json, schema_version "1.0"
mcp-audit reach --report pdf -o reach.pdf   # one page per machine
mcp-audit reach --fleet ./reach-files/  # roll up reach JSON from many machines
```

`reach` answers the question a security team asks before it lets a coding agent
run on a laptop (the questions under @amasad's Replit CEO advisory on X asked
the same four things):

1. **Where does it run?** Sandbox on or off; approval mode.
2. **Whose credentials can it read?**
3. **What can it reach on the network?**
4. **Is policy enforced?**
5. **Is its activity logged?**

It is static and offline. It reads settings files and one default scan; it never
executes an agent, never starts an MCP server, and never watches a live call.
It composes the existing analyzers (REACH-001..003, HARNESS-*, MANAGED-*, the
toxic-flow capability tags) and re-implements no detection. It writes nothing:
the scan runs with rug-pull state skipped.

`--path` is not accepted: this is a machine view of the working directory and the
user's home.

## The agents

| Agent | What is read |
|---|---|
| Claude Code | settings (managed, user, project, local), REACH-001..003, HARNESS-001, managed policy files, MCP servers |
| Codex | `$CODEX_HOME/config.toml` (`~/.codex/config.toml`) and the working directory's `.codex/config.toml`, MCP servers |
| Gemini CLI, OpenCode, Cursor, VS Code, Claude Desktop, any other client with a discovered MCP config | MCP servers only; every other question is COULDN'T CHECK until a reader exists |

OpenCode is treated as any client with a discovered MCP config (client name
`opencode`, or any name starting `opencode-`), so it appears as soon as discovery
finds its servers. Gemini CLI is listed when its `~/.gemini/settings.json`
exists, even with no servers.

## Answers

Every answer is `pass`, `fail`, `couldnt_check` or `info`, names the file and key
it came from, and `couldnt_check` is never read as fine.

### Claude Code

Vendor documentation (read 2026-11-04): [settings reference](https://code.claude.com/docs/en/settings-reference),
[sandboxing](https://code.claude.com/docs/en/sandboxing),
[monitoring usage](https://code.claude.com/docs/en/monitoring-usage),
[managed MCP](https://code.claude.com/docs/en/managed-mcp).

| Question | Source | Answer |
|---|---|---|
| Where it runs | `sandbox.enabled` (highest precedence: managed, local, project, user), `sandbox.filesystem.disabled` (user or managed), `sandbox.failIfUnavailable` (user or managed), `permissions.defaultMode`, `permissions.disableBypassPermissionsMode` | **pass** when the sandbox is on, on a supported OS (macOS, Linux, WSL2) and filesystem isolation is not disabled. On Linux and WSL2 the sandbox needs `bubblewrap` and `socat` and otherwise "Claude Code runs commands without sandboxing" unless `sandbox.failIfUnavailable` is true, so it passes only with that key set in user or managed settings or with both `bwrap` and `socat` found on `PATH` (looked up, never run); otherwise `couldnt_check`. **fail** when it is off (the default) or when bypass mode is in effect. A settings file in any scope that cannot be read (for example one over 1 MiB) makes it `couldnt_check`, because a repository file can switch the sandbox off |
| Credentials | REACH-001 (readable without a prompt), plus a stat-only inventory of the same fixed store list so covered stores are listed; secret-shaped names or values in the `env` block of any settings file (names only are reported) | **fail** when REACH-001 fired, when a secret-shaped variable is in a settings `env` block (every command and local MCP server inherits it), or when Bash can run outside the sandbox (a deny rule only holds inside it, so the stores it covers count as readable). **pass** only when the checks ran (Claude Code's config directory exists) and reported no problem. Otherwise `couldnt_check` |
| Network | the agent's MCP servers through `toxic_flow.tag_server` with the shared registry (`NETWORK_OUT`, `COMMS_OUT`, `SHELL_EXEC` or `BROWSER`, or an http/sse URL), including `~/.claude.json` `projects.*.mcpServers`, `managed-mcp.json` and the managed `managedMcpServers`; hooks, `apiKeyHelper` and `statusLine` commands that run a network tool; and the sandbox's network state | see below |
| Policy | `managed-settings.json`, `managed-settings.d/*.json`, `managed-mcp.json`, the macOS managed-preferences profile and the Windows `HKLM`/`HKCU` values, ranked by `managed_policy.read_effective_policy` (the source in force is named in a fact); who can change them from owner and mode bits | **pass**: the source in force is admin-only (profile, `HKLM`, or files only root can change). **fail**: a non-root account can change it, or only `HKCU` delivers policy (user-writable). `couldnt_check`: nothing found (server-managed settings are not read), unreadable, or group/ACL ownership unknown |
| Logging | `env` of managed and user settings: `CLAUDE_CODE_ENABLE_TELEMETRY`, `OTEL_LOGS_EXPORTER`, `OTEL_EXPORTER_OTLP_PROTOCOL` / `_LOGS_PROTOCOL`, `OTEL_EXPORTER_OTLP_ENDPOINT` / `_LOGS_ENDPOINT` | **pass**: telemetry is `1`, the logs exporter includes `otlp`, a protocol and an endpoint are set. **fail**: telemetry off, exporter not `otlp` (console is not durable), no protocol (Claude Code "has no default protocol"), or a repository file sets `OTEL_LOGS_EXPORTER` to `none` while managed settings do not set it. `couldnt_check`: no endpoint (no documented default), or a telemetry value the monitoring doc does not define |

Network state of the sandbox (sandboxing doc, "Network isolation"): with the
sandbox on there is no direct route out and unlisted hosts are prompted for in
the default modes, refused with `sandbox.network.strictAllowlist` (user or
managed) or `allowManagedDomainsOnly` (managed), and allowed without a prompt
under `bypassPermissions` or when `allowedDomains` contains `*`. `reach`
accepts both "prompts" and "refused" as network-restricted: the sanctioned path
is "no silent route out". The state and its source are shown. The network item
passes only when that restriction applies **and** no MCP server reaches the
network: MCP servers are separate processes outside the sandbox ("Claude's file
tools, MCP servers, and hooks run outside it"), so a server that can reach out
(`NETWORK_OUT`, `COMMS_OUT`, `SHELL_EXEC`, `BROWSER`) is a fail even with the
sandbox on. A stdio server is *quiet* only when the **package its launch command
installs** (`npx`, `uvx`, `python -m`, ...) resolves to a registry entry with
declared capabilities and none of them reaches out; the server's name or a stray
argument (`node evil.js <known-package>`) never counts. Any other stdio
server, including one only a keyword heuristic tagged, is *unclassified*:
nothing authoritative says it cannot reach the network, so the answer is
`couldnt_check`, not "none". A `~/.claude.json` or managed MCP file that exists
but cannot be read is `couldnt_check` too. A readable `managed-mcp.json` takes
exclusive control (managed MCP doc), so only the managed servers are counted.

The state is **open** (a fail) also when: a `WebFetch(domain:...)` allow rule
adds a wildcard domain (a bare `*` or a top-level-domain wildcard; sandboxing doc:
domains from permission rules are merged into the sandbox's allowlist) or a bare
`WebFetch` allow rule lets any host through; a Bash allow rule exists and
`sandbox.allowUnsandboxedCommands` is not `false` in user or managed settings
(the unsandboxed retry then runs without a prompt; the documented default is not
stated, so it is read as allowing the retry); or `sandbox.excludedCommands` lists
a command that a Bash allow rule covers. It is **unknown** (`couldnt_check`) when
`sandbox.network.httpProxyPort` or `socksProxyPort` applies (any file, except
that `allowManagedDomainsOnly` limits them to managed settings and
`strictAllowlist` to managed and user settings): "your proxy is responsible for
filtering everything sent to it" and Claude Code's own network controls stop
applying. A hook, `apiKeyHelper` or `statusLine` command that runs `curl`, `wget`,
another HOOK-001 network tool or a `/dev/tcp` or `/dev/udp` redirect is a network
fail in any settings file (only the tool name is shown), and **not safe to allow**
when a credential store is readable. These commands run outside the sandbox, so
any of them that is not positively known to be local (one bare `echo`, `printf`,
`true`, `false`, `date`, `pwd`, `whoami`, `hostname` or `uname`: no `VAR=`
prefix, substitution, redirect, pipe or list; `git`, `sort`, scripts and
interpreters are not) makes the network answer `couldnt_check`,
and the credentials answer cannot be `pass` while one exists.

Hooks declared in skill and agent frontmatter (user, project and plugin) follow
the same rules. A hook, `apiKeyHelper` or `statusLine` command that names a
credential store path (`~/.ssh`, `~/.aws/credentials`, the REACH-001 list) makes
credentials a fail, known-local or not.

Hooks that installed plugins ship (`hooks/hooks.json`, or `hooks` in `plugin.json`)
follow the same rules when `enabledPlugins` is true for the plugin; a plugin
with no `enabledPlugins` entry is not known to be enabled, so any command hook it
ships makes network and credentials `couldnt_check`; `enabledPlugins` false skips it.

Network is also `couldnt_check` for **claude.ai connectors**: with a claude.ai
subscription login Claude Code fetches the account's connectors (remote MCP
servers) at startup and they are in no local file. They are ruled out only by
`disableClaudeAiConnectors`, `ENABLE_CLAUDEAI_MCP_SERVERS` set false in a
settings `env` block, a `managed-mcp.json` without the managed
`allowAllClaudeAiMcps`, or an API-key login (`apiKeyHelper`, or `ANTHROPIC_AUTH_TOKEN` in a
settings `env` block; `ANTHROPIC_API_KEY` does not count, as a declined key falls back to the login). The process environment is
not read. The state is also **open** when `sandbox.network.allowAllUnixSockets`
is true or `allowUnixSockets` lists a docker, podman or containerd socket (the
daemon runs outside the sandbox).

Credentials are `couldnt_check` too when an `mcp__<server>` allow rule (or
`bypassPermissions`) lets a local file-reading or shell MCP server run without a
prompt and its path arguments do not exclude home and the credential stores: MCP
servers are not bound by `Read` deny rules.

Only managed and user settings count for telemetry. Claude Code ignores the
OpenTelemetry variables in a repository's settings files (monitoring doc), and
the process environment and `--settings` files are not readable from here, so
nothing is ever claimed "logged" from an environment `reach` did not read.

### Codex

Vendor documentation (read 2026-11-04): the [Codex configuration reference](https://developers.openai.com/codex/config-reference)
(served from `learn.chatgpt.com/docs/config-file/config-reference`) and
[agent approvals and security](https://learn.chatgpt.com/docs/agent-approvals-security).

| Question | Source | Answer |
|---|---|---|
| Where it runs | `sandbox_mode` (`read-only`, `workspace-write`, `danger-full-access`), `approval_policy`, `default_permissions` | **pass** for `read-only` / `workspace-write`. **fail** (not safe to allow) for `danger-full-access`, `default_permissions = ":danger-full-access"` or `approval_policy = "never"`, from the user file or the project file. `couldnt_check` when `sandbox_mode` is unset (the reference does not state the default), has an unrecognised value, a permission profile (`default_permissions`) is selected, or a file cannot be read |
| Credentials | not modelled yet (Q-065/Q-066) | always `couldnt_check`, never "none" |
| Network | `sandbox_workspace_write.network_access`; the mode | `read-only` and `workspace-write` are restricted ("keeps network access turned off unless you enable it"); `network_access = true` and `danger-full-access` are not. Same MCP-server rule as above |
| Policy | Codex managed configuration (`requirements.toml`) is not read | `couldnt_check` |
| Logging | `[otel] exporter` in the **user** file (`none \| otlp-http \| otlp-grpc`; string or table form) | **pass** for `otlp-http` / `otlp-grpc` with an `endpoint` set (table form), **fail** for `none`, `couldnt_check` when unset or when an OTLP exporter has no endpoint (the reference does not state a default) |

Profiles ([advanced configuration](https://learn.chatgpt.com/docs/config-file/config-advanced)):
since Codex 0.134.0 `--profile` no longer reads `[profiles.<name>]` from
`config.toml` and the top-level `profile = "<name>"` selector is not supported
(project files ignore both). `reach` therefore reads neither: they are shown as
"legacy, ignored". A profile is `~/.codex/<name>.config.toml`, chosen on the
command line, which is not readable here; such a file is listed and makes the
answer `couldnt_check`. A config value that is a table or list is shown as
`(table)` / `(list)`, never printed.

Not read: command-line flags, which `--profile` is used, and Codex's
system-level configuration.

## Verdict

Per agent, worst first:

| Verdict | When |
|---|---|
| **not safe to allow** | bypass mode in effect (Claude Code `permissions.defaultMode` is `bypassPermissions` in managed or user settings and not disabled by `disableBypassPermissionsMode: "disable"`); Codex `danger-full-access` or approval `never`; a readable credential store (REACH-001) plus a network-capable MCP server; or an existing CRITICAL finding attributed to the agent (same client family, or a cross-server finding naming one of its servers) |
| **needs work** | an item on the sanctioned path fails: sandbox on, scoped credentials, network denied by default, logging on. A repository settings file asking for `bypassPermissions` is here too: Claude Code 2.1.257 and later ignore it, older releases honour it, and the installed version is not read (HARNESS-001 rates it MEDIUM for the same reason) |
| **couldn't check** | nothing fails, but a question that decides the verdict could not be answered. Unknown is never upgraded to ready |
| **ready** | all four items pass |

A failing item outranks an unanswered one, so a card never hides a known problem
behind "couldn't check"; the unanswered questions are listed in `reasons` either
way. Each reason carries `refs`: finding IDs (`REACH-001`), `file:key` pointers
(`~/.claude/settings.json:permissions.defaultMode`) and server entries
(`~/.claude.json#fetch`).

Policy (question 4) and approval mode are reported but are not one of the four
sanctioned-path items; approval mode only decides the verdict through the
bypass rules above. REACH-003 (`.env` files in the directory you ran from) is
listed under credentials but does not decide the verdict, because it depends on
where the command was run.

"Bypass mode reachable": `reach` treats bypass as in effect only when a setting
makes it the default. The `--dangerously-skip-permissions` flag can still be
chosen per session unless `permissions.disableBypassPermissionsMode` is
`"disable"`; the card shows that as a fact ("can still be chosen for a session")
and does not fail on it, since that would make every default install unsafe.

## Exit codes

`0` every agent is ready or couldn't-check-only, or no agent was found.
`1` any agent needs work or is not safe to allow. `2` error (bad option, a
`--fleet` path that is not a directory, a failed scan).

## JSON

`--format json` writes one document, validated in the test suite against
[`reach.schema.json`](reach.schema.json) (JSON Schema 2020-12,
`schema_version` `"1.0"`). Top level: `schema_version`, `tool`, `generated_at`,
`machine` (`hostname`, `os`, `os_version`, `asset_id`; the username is not
included), `summary` (`agents`, `verdicts`, `worst_verdict`), `agents`, `errors`.
Each agent has `id`, `name`, `kind` (`harness` or `client`), `verdict`,
`detected_in`, `servers`, `reasons` and `questions` (the five answers, each with
`status`, `summary`, `facts` and `refs`).

Every string is redacted for credentials (URL userinfo, token shapes, `Bearer`
and `Basic` values, credential headers, `password=` pairs) and the home
directory is `~`. Endpoint values and OTLP headers are never printed; only
whether they are set. Credential stores are found with `stat()` and never opened.

## PDF

`--report pdf` (`-o FILE`, `--org NAME`) writes a Letter-size PDF in the style of
`check --report pdf`: one page per machine, however many agents it has (the body
shrinks to fit; the JSON has the full text).

## Fleet

```bash
mcp-audit reach --format json -o "$(hostname).json"     # on each machine
mcp-audit reach --fleet ./reach-files/                  # on the collector
mcp-audit reach --fleet ./reach-files/ --format json    # docs/reach-fleet.schema.json
```

`--fleet DIR` reads the `*.json` files in `DIR` (not recursive): at most 1,000
files, 4 MiB each, regular files only (a symlink is not followed), opened without
blocking, at most 200 agents per file (a file with more is skipped and listed). A file that is not
a reach report (not valid JSON, not an object, no `schema_version` 1.x, an agent
without a name or with an unknown verdict) is skipped and listed with the reason.
It prints verdict counts per agent name and the machines that have an agent that
is not safe to allow. The exit code is 1 when any machine has an agent that needs
work or is not safe to allow; skipped files do not change it.

## What `reach` does not do

- It does not read server-managed Claude Code settings,
  Codex requirements, command-line flags, or the process environment.
- It does not know which Claude Code version is installed (only matters for a
  repository-level `bypassPermissions`).
- It does not model credentials for any agent but Claude Code (Q-065/Q-066).
- It does not run an agent, start an MCP server, or watch calls; "logged" means
  "configured to be", not "records exist".
- Writer detection for managed files uses owner and mode bits (POSIX). A
  group-writable file owned by root with a non-root group, ACLs, and Windows
  permissions are reported as unknown.

Ranking of managed policy sources is isolated in
`reach.claude.managed_policy_source`, so it can switch to the source ranking when
that lands.
