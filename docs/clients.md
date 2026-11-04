# Supported clients

Where mcp-audit looks for MCP servers, per client, and how each file is read.
A default `scan` / `check` reads the user-level files below plus the project
files at the root of the working directory; `scan --project <dir>` walks a
repository for the project files (depth 8, skipping `node_modules`, `.git`
and the like) and reports every server it finds there as TRUST-001.

| Client | User-level file | Project file(s) | Server key | Format |
|---|---|---|---|---|
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS), `%APPDATA%\Claude\claude_desktop_config.json` (Windows), `~/.config/Claude/claude_desktop_config.json` (Linux) | – | `mcpServers` | JSON |
| Cursor | `~/.cursor/mcp.json` | `.cursor/mcp.json`, `.cursor/settings.json` | `mcpServers` | JSON |
| VS Code | – | `.vscode/mcp.json` | `servers` | JSON |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` | – | `mcpServers` | JSON |
| Claude Code | `~/.claude.json`, `~/.claude/settings.json` | `.mcp.json`, `.claude/settings.json`, `.claude/settings.local.json` | `mcpServers` | JSON |
| GitHub Copilot CLI | `~/.copilot/mcp-config.json` | – | `mcpServers` | JSON |
| Augment Code | `~/.augment/settings.json` | – | `mcpServers` | JSON |
| Amazon Q Developer | – | `.amazonq/mcp.json` (`--project` only) | `mcpServers` | JSON |
| **Codex** | `$CODEX_HOME/config.toml` (default `~/.codex/config.toml`) | `.codex/config.toml` | `[mcp_servers.<name>]` | TOML |
| **Gemini CLI** | `~/.gemini/settings.json` | `.gemini/settings.json` | `mcpServers` | JSON with comments |
| **OpenCode** | `~/.config/opencode/opencode.json` or `.jsonc`; the file `$OPENCODE_CONFIG` names | `opencode.json`, `opencode.jsonc` | `mcp` | JSONC (comments, trailing commas) |

Client labels in findings and JSON output: a server from a user-level file
carries the client name (`codex`, `gemini-cli`, `opencode`); one from the
working directory's project file in a default scan carries `<client>-project`
(`codex-project`, `gemini-cli-project`, `opencode-project`, like
`claude-code-project`), so a
repository server never shares a rug-pull identity with a user server of the
same name. `scan --project` and `lock` use the plain client name.

## Codex (STORY-0110)

Confirmed from Codex's own source (openai/codex, `main`, 2026-10-28):

- **Where.** `codex-rs/utils/home-dir`: the user directory is `CODEX_HOME`
  when it is set, otherwise `~/.codex`. `codex-rs/config/src/loader/mod.rs`
  lists the layers: system `/etc/codex/config.toml`, user
  `${CODEX_HOME}/config.toml`, then "parent directories up to root looking for
  `./.codex/config.toml` (loaded but disabled when untrusted)". A project's
  `.codex/` directory that *is* `CODEX_HOME` is skipped; mcp-audit does the
  same (a scan from `$HOME` reads `~/.codex/config.toml` once, as the user's).
  `mcp_servers` is not on Codex's `PROJECT_LOCAL_CONFIG_DENYLIST`, so a
  trusted repository can add MCP servers.
- **Keys** (`codex-rs/config/src/mcp_types.rs`, `RawMcpServerConfig`).
  `command` makes a stdio server (`args`, `env`, `cwd`; `env_vars` names
  variables to pass through). Otherwise `url` makes a streamable-HTTP server;
  Codex has no SSE transport, so a `/sse` path is still read as HTTP.
  mcp-audit records `http_headers` as headers, `env_http_headers` as
  `Header: ${VAR}`, `bearer_token_env_var` as `Authorization: Bearer ${VAR}`,
  and the retired literal `bearer_token` (which Codex now refuses) as
  `Authorization: Bearer <value>`, because the secret is still in the file:
  CRED-003 reports it.
- **`http_headers_helper`** is "a local-only shell command that prints a JSON
  object of dynamic HTTP headers", run on each connection to a `url` server,
  and a project file may set it. In a project `.codex/config.toml` it is
  TRUST-008 (HIGH; CRITICAL when the command reaches the network), with the
  command quoted, secrets masked. In any file it counts as authentication for
  AUTH-001, as does `bearer_token_env_var`. `env_vars` names are recorded as
  `${NAME}` env references. A top-level `oauth_resource` counts as the
  audience binding for AUTH-002.
- **Entries Codex would not start.** An entry with both `command` and `url`
  (a Codex error) or `enabled = false` is still analysed: one edit makes it
  live.
- **TOML values.** Numbers and booleans in `args` / `env` are read as text;
  TOML dates in an entry become ISO 8601 strings in `raw`.

## Gemini CLI (STORY-0110)

Confirmed from Gemini CLI's docs and source (google-gemini/gemini-cli,
`main`, 2026-10-28):

- **Where.** `docs/reference/configuration.md`: user settings
  `~/.gemini/settings.json`; project settings `.gemini/settings.json` "within
  your project's root directory" (ignored in an untrusted folder).
- **Keys** (`docs/tools/mcp-server.md`, `MCPServerConfig` in
  `packages/core/src/config/config.ts`): `command`, `args`, `env`, `cwd`,
  `url`, `httpUrl`, `type` (`"http"` or `"sse"`), `headers`, `timeout`,
  `trust`, `includeTools`, `excludeTools`, `oauth`, `authProviderType`.
- **Transport order** (`packages/core/src/tools/mcp-client.ts`): `httpUrl`
  (streamable HTTP) wins; then `url` with `type`; then `url` alone (mcp-audit
  reads a `/sse` path as SSE, otherwise HTTP); then `command` (stdio). A
  `command` beside a URL never runs, but it is still analysed.
- **Comments.** Gemini CLI reads the file with `JSON.parse(stripJsonComments(…))`
  (`packages/cli/src/config/settings.ts`): `//` and `/* */` comments are
  allowed, trailing commas are not. mcp-audit reads it the same way; a file
  Gemini CLI would reject is reported in the scan's errors.
- **Auth.** `authProviderType` counts as authentication for AUTH-001, like
  `oauth`; `oauth.audiences` (a list with at least one non-wildcard value)
  counts as the audience binding for AUTH-002. `$VAR` / `${VAR}` references in `env` and `headers` are references,
  not literal secrets.

## OpenCode (STORY-0142)

- **Where.** User config `~/.config/opencode/opencode.json` or `.jsonc`;
  `$OPENCODE_CONFIG` names one more file (a path that does not exist is
  ignored without a message); a project's `opencode.json` / `opencode.jsonc`
  at the root of the working directory (a default scan; skipped when that
  directory is `$HOME`) and, with `scan --project`, in every directory of the
  walk. The walk skips your own user files, like Codex's and Gemini CLI's.
- **Format.** JSONC: `//` and `/* */` comments and trailing commas are read
  (comment markers inside strings are kept). The servers are the top-level
  `mcp` object.
- **Entries.** `{"type": "local", "command": [<argv>], "environment": {...}}`:
  `command[0]` is the command, the rest are its arguments, `environment` is the
  env. `{"type": "remote", "url": "...", "headers": {...}}`: `url` and
  `headers`, so TRANSPORT-001 and the credential-header checks apply as for any
  client. An entry with `"enabled": false` is still analysed (one edit makes it
  live), as for Codex. An entry with another `type`, no `type`, or the wrong
  shape (an empty `command`, a remote without `url`) is skipped and named in
  the scan's errors; the other servers are still read.
- **Lock and rug-pull identity.** As for Codex and Gemini CLI: `opencode-project`
  in a default scan, plain `opencode` in `scan --project` and `lock`.
- **Not read.** `{env:VAR}` / `{file:path}` substitutions are not expanded, and
  OpenCode's merge with config from parent directories and a `.opencode/`
  directory is not reproduced; each file is analysed alone.

## Limits

- Files over 4 MiB are not read; the scan's errors say so.
- JSON output redacts header values (`Bearer [REDACTED]`; `${VAR}` references
  are kept), Codex's `bearer_token`, the OAuth client secret and the credentials inside an
  `http_headers_helper` command (secret patterns, URL passwords, the token after
  an inline `Bearer`/`Basic`/`Token`) in `raw`, and
  credentials in launch arguments and URLs (STORY-0108). `env` values are
  printed as written, as for every client (GAPS.md).
- `mcp-audit fix` edits JSON only: it refuses Codex's `config.toml` and tells
  you to edit it by hand, and `check` never offers `fix` for it. A Gemini CLI
  `settings.json` with comments is refused too (rewriting it would drop them).
- See `GAPS.md` ("Codex and Gemini CLI MCP servers") for what is not read:
  system and admin layers, Codex profiles and plugins, Gemini CLI extensions,
  `mcp.allowed` / `mcp.excluded`, and per-server `trust`.
