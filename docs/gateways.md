# Servers behind an MCP gateway

An MCP gateway (also called an aggregator or proxy) is one entry in your
client's config that starts and fronts many other MCP servers. The agent
connects to the gateway and reaches the other servers, its *upstreams*,
through it. When a scan reads only the client config, it sees one server.
The upstream servers, and what they let the agent do, are listed in the
gateway's own config file.

Since STORY-0111, `mcp-audit scan`, `check`, `shadow`, `sbom` and
`scan --project` read the config files of three gateways and analyse each
upstream server like any other server. Each one is reported under the client
`<gateway>-upstream`:

| Gateway | Client name | User-level file | Project-level file |
|---|---|---|---|
| [mcptoon](https://github.com/activeing123/mcptoon) | `mcptoon-upstream` | `config.json` and `config.toml` in mcptoon's one config folder: `$MCPTOON_HOME`, else `$XDG_CONFIG_HOME/mcptoon` (when set, and it exists or `~/.mcptoon` does not), else `~/.mcptoon` | `.mcptoon.json`, `.mcptoon.toml` |
| [1MCP](https://docs.1mcp.app/reference/mcp-servers) | `1mcp-upstream` | `~/.config/1mcp/mcp.json` (macOS, Linux), `<home>\AppData\Roaming\1mcp\mcp.json` (Windows), or `mcp.json` in `$ONE_MCP_CONFIG_DIR`, or the file `$ONE_MCP_CONFIG` | none documented |
| [MCPHub.nvim](https://github.com/ravitemer/mcphub.nvim) (`mcp-hub`) | `mcphub-upstream` | `~/.config/mcphub/servers.json` | `.mcphub/servers.json` |

Environment overrides are read from the environment mcp-audit runs in, and
only when they hold an absolute path. The gateway may have been started with
a different environment; the default locations are always checked too.

## What changes for you

- **Every analyzer sees the upstreams.** Credentials, transport, supply
  chain, poisoning in the config, the community rules and config hygiene
  (CFHYG-001 for a world-readable gateway config, for example) run on each
  upstream server. Toxic flow and attack paths pair them with your other
  servers: a filesystem server behind mcptoon and a fetch server in Claude
  Desktop are reported as TOXIC-001, because the agent can reach both.
- **No new finding IDs.** Findings keep their usual IDs and severities; the
  `client` field says which gateway the server is behind.
- **A repository can carry a gateway config.** `scan --project` reports
  TRUST-001 (HIGH) for each server in a committed `.mcptoon.json`,
  `.mcptoon.toml` or `.mcphub/servers.json`. mcptoon reads its project file
  from the directory it runs in, so `mcptoon serve` launched by an agent with
  the repository as its working directory can start those servers; MCPHub.nvim
  reads `.mcphub/servers.json` when Neovim opens the project (its workspace
  detection is on by default). A default `scan` also reads these files in the
  working directory. A symlinked file, or one reached through a symlinked
  folder (`.mcphub -> /elsewhere`), is TRUST-002 like any project config.
- **Secrets stay out of the output.** For upstream servers, JSON output
  (`scan --format json`, `check --json`, native snapshots) redacts the values
  of `env` and `headers` as well as the launch command, arguments and URL:
  credential formats mcp-audit recognises and URL passwords become
  `[REDACTED]`, the value of a secret-named variable (`API_KEY`,
  `GITHUB_TOKEN`, `DB_PASSWORD`) becomes `[REDACTED-FLAG]`, and references
  such as `${TOKEN}` are kept. `mcp-audit diff` between two scan files reads
  either marker in `env` as a credential. Every other key the gateway wrote
  is kept in `raw` with secret-named values (1MCP `oauth.clientSecret`,
  `accessToken`, `bearer_token`, …) replaced by `[REDACTED]` unless they are
  a reference.
- **`fix` leaves gateway configs alone.** `mcp-audit fix` refuses a gateway
  config (exit 2) and never applies a gateway finding to another file;
  `check` does not suggest `fix --apply` for them.

## How each file is read

Files are read as text (at most 4 MiB each) and parsed as JSON, or TOML for a
`.toml` file. Nothing in them is run, expanded or fetched: mcptoon and 1MCP
`${VAR}` references, MCPHub `${cmd: ...}` placeholders and 1MCP Handlebars
templates stay literal. (A committed `.mcphub/servers.json` that holds a
`${cmd: ...}` placeholder is also reported as TRUST-008, HIGH, CRITICAL when the
command reaches the network; see `docs/agent-execution-surface.md`.) A file that cannot be read or parsed, or is too large
or too deeply nested, is reported in the scan's errors; at most 1,000 servers
per file are analysed and the rest are named in the errors.

- **mcptoon** (read from `mcptoon/config.py`, release 0.8.32): servers are
  under `servers`. `command` is an argument list (or a single string) that
  `args` is appended to, so `"command": ["npx", "-y"], "args": ["pkg"]` is
  the launch `npx -y pkg`. `transport` is `stdio` (the default) or `http`
  (`url`, `headers`). An entry named `mcptoon`, or one whose arguments run
  `mcptoon ... serve`, is skipped, as mcptoon itself skips it (it would start
  the gateway inside itself). Both the JSON and the TOML file are read; mcptoon
  merges them, later files overriding earlier ones by server name, and
  mcp-audit reports each file's servers separately.
- **1MCP**: `mcpServers` plus `mcpTemplates` (a template wins over a static
  server of the same name). `serverDefaults.env` is merged under each server's
  `env` (when both are lists, the server's list replaces the defaults', as
  1MCP documents), and `serverDefaults.headers` is used by a remote server
  that has none. `env` may be an object or a list of `KEY=value` items; a bare `NAME`
  item (inherited from 1MCP's environment) is recorded as `${NAME}`. `type`
  (`stdio`, `http`, `sse`, `streamableHttp`) sets the transport.
- **MCPHub**: `servers` (VS Code format, which MCPHub prefers when both are
  present) or `mcpServers`.

## Locks and rug-pull state

`mcp-audit lock` does not record gateway upstreams, so a lock written before
this change keeps verifying. When a scan finds a gateway project file under a
locked repository, its servers are listed in the warning "not covered by
mcp-lock.json" rather than reported as unrecorded (LOCK-002).

Rug-pull tracks a gateway server per file (`<client>/<name> @ <path>`), so
mcptoon's user and project files can name the same server and a change in
either is still RUGPULL-001. User-level gateway configs are not part of the
rug-pull state key, so a
machine that already had one keeps its rug-pull history; its upstream servers
are recorded in the same state file as the rest of the scan (the first scan
after upgrading reports each one as new, RUGPULL-002 INFO). A gateway project
file in the working directory is part of the key, so one repository's
upstreams never show up as removed in another repository's scan.

## Not covered

See GAPS.md, "MCP gateway upstreams (STORY-0111)": other gateways (Docker MCP
Gateway, MetaMCP, sparfenyuk and TBXark `mcp-proxy`, `mcp-hub` started with
its own `--config`), `MCPTOON_SERVERS`, and `--path` to a gateway file.
`mcp-audit watch` re-scans when a user-level or working-directory gateway
config changes.
