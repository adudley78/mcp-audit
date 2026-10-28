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

Client labels in findings and JSON output: a server from a user-level file
carries the client name (`codex`, `gemini-cli`); one from the working
directory's project file in a default scan carries `<client>-project`
(`codex-project`, `gemini-cli-project`, like `claude-code-project`), so a
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
  `oauth`. `$VAR` / `${VAR}` references in `env` and `headers` are references,
  not literal secrets.

## Limits

- Files over 4 MiB are not read; the scan's errors say so.
- `mcp-audit fix` edits JSON only: it refuses Codex's `config.toml` and tells
  you to edit it by hand, and `check` never offers `fix` for it. A Gemini CLI
  `settings.json` with comments is refused too (rewriting it would drop them).
- See `GAPS.md` ("Codex and Gemini CLI MCP servers") for what is not read:
  system and admin layers, Codex profiles and plugins, Gemini CLI extensions,
  `mcp.allowed` / `mcp.excluded`, and per-server `trust`.
