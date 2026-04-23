# Governance Policies

Governance policies let organisations enforce security requirements across all
MCP client configurations — Claude Desktop, Cursor, VS Code, Windsurf, Claude
Code, Copilot CLI, and Augment — from a single YAML file.

## Governance vs the Rule Engine

| | Rule Engine | Governance |
|---|---|---|
| **Purpose** | Pattern-match inside server configs | Enforce org-wide requirements |
| **Configured via** | YAML rule files (`rules/community/`) | `.mcp-audit-policy.yml` |
| **Finding source** | `analyzer: "rules"` | `analyzer: "governance"` |
| **Examples** | "This server name looks like a typosquat" | "This server is not on the approved list" |
| **License** | Fully open source (Apache 2.0) — all features available to every user | Fully open source (Apache 2.0) — all features available to every user |

The rule engine detects security-relevant patterns in configs. Governance
enforces organisational decisions: which servers are allowed, what score a
configuration must achieve, and how many findings are tolerable.

## Policy resolution order

When `--policy <path>` is not specified, mcp-audit searches for a policy
automatically in this order:

1. **Current working directory** — checks each of these filenames in order:
   `.mcp-audit-policy.yml`, `.mcp-audit-policy.yaml`, `mcp-audit-policy.yml`
2. **Git repository root** — walks up from cwd until a `.git` directory is
   found; if the git root differs from cwd, checks the same three filenames
   there
3. **User config directory** — `<user-config-dir>/mcp-audit/policy.yml`
   where `<user-config-dir>` is resolved by `platformdirs.user_config_dir("mcp-audit")`
   (e.g. `~/.config/mcp-audit/` on Linux, `~/Library/Application Support/mcp-audit/` on macOS)

Returns `None` (no governance check) if none of the above exist.

## Quickstart

```bash
# 1. Generate a commented template
mcp-audit policy init

# 2. Edit it to define your requirements
$EDITOR .mcp-audit-policy.yml

# 3. Validate syntax
mcp-audit policy validate .mcp-audit-policy.yml

# 4. Run a full scan — policy is auto-discovered
mcp-audit scan

# 5. Quick policy-only compliance check
mcp-audit policy check
```

## Full field reference

### Top-level fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `version` | int | `1` | Schema version (currently always `1`) |
| `name` | str | `"mcp-audit governance policy"` | Human-readable policy name |
| `approved_servers` | object | `null` | Approved/denied server list |
| `score_threshold` | object | `null` | Minimum scan score requirement |
| `transport_policy` | object | `null` | Transport type constraints |
| `registry_policy` | object | `null` | Known-Server Registry requirements |
| `finding_policy` | object | `null` | Finding count limits |
| `client_overrides` | map | `{}` | Per-client policy overrides |

---

### `approved_servers`

Controls which MCP servers are allowed or forbidden.

```yaml
approved_servers:
  mode: allowlist          # "allowlist" or "denylist"
  violation_severity: high # critical | high | medium | low | info
  message: "Server {server_name} is not on the approved server list"
  entries:
    - name: "@modelcontextprotocol/server-filesystem"
      source: npm          # npm | pip | github | null (any)
      notes: "Official filesystem server"
    - name: "@modelcontextprotocol/*"   # fnmatch glob supported
  additional: []           # used in client_overrides to add entries
```

- **`mode: allowlist`** — every server must match at least one entry or a
  finding is produced.
- **`mode: denylist`** — a finding is produced for any server that matches an
  entry.
- **`name`** supports `fnmatch` glob patterns, e.g. `@modelcontextprotocol/*`
  matches any server under that namespace.
- **`source`** restricts matching to a specific package ecosystem inferred from
  the server's launch command (`npx`/`node` → npm; `python`/`uvx` → pip).
  `null` (default) matches any source.

---

### `score_threshold`

Requires the numeric scan score to meet a minimum.

```yaml
score_threshold:
  minimum: 70              # 0–100; failing score produces a finding
  violation_severity: medium
  message: "Configuration scored {score} ({grade}), below minimum of {minimum}"
```

Template variables: `{score}`, `{grade}`, `{minimum}`.

The check runs per-client — each client's server group is evaluated against the
same shared score (the overall scan score). To run this check, you must pass a
completed `ScanResult` to `evaluate_governance()`.

---

### `transport_policy`

Controls which MCP transport types are permitted.

```yaml
transport_policy:
  require_tls: false    # block servers whose URL starts with http://
  allow_stdio: true     # local subprocess transport
  allow_sse: true       # Server-Sent Events transport
  allow_http: true      # streamable-http transport type (any URL)
  block_http: false     # explicitly block unencrypted http:// URLs
  violation_severity: high
```

`require_tls` and `block_http` both trigger a finding for any server whose URL
starts with `http://`. The difference is intent — `require_tls: true` expresses
"I need TLS", while `block_http: true` expresses "I want to block HTTP
explicitly".

---

### `registry_policy`

Requires servers to appear in the Known-Server Registry.

```yaml
registry_policy:
  require_known: false    # server must be in the registry
  require_verified: false # server must be marked verified: true in registry
  violation_severity: medium
  message: "Server {server_name} is not in the Known-Server Registry"
```

This check is skipped when no registry is provided (e.g. `policy check` with
no registry loaded).

---

### `finding_policy`

Caps the number of findings at each severity.

```yaml
finding_policy:
  max_critical: 0     # null = no limit
  max_high: null
  max_medium: null
  violation_severity: high
```

Counts exclude governance findings themselves to avoid circular amplification.
One finding is produced per exceeded severity limit.

---

### `client_overrides`

Per-client overrides that replace or supplement the base policy for a specific
MCP client. The key must match the `client` field on discovered server configs.

**Valid client keys:** `claude-desktop`, `cursor`, `vscode`, `windsurf`,
`claude-code`, `copilot-cli`, `augment`

```yaml
client_overrides:
  cursor:
    approved_servers:
      mode: allowlist
      entries:
        - name: "internal-dev-tool"
          notes: "Cursor-only internal server"
  claude-desktop:
    transport_policy:
      allow_stdio: true
      allow_http: false
      block_http: true
      violation_severity: high
```

Each override may set `approved_servers`, `transport_policy`, and/or
`score_threshold`. Omitted blocks fall back to the base policy.

When a client override sets `approved_servers`, the override's `entries` list
**replaces** the base entries for that client — it does not append to them. To
include base-policy servers plus additional ones, repeat them in the override's
`entries` or use the `additional` list in the base policy.

---

## Example: enforce an approved server list across a dev team

1. Create a policy at the repository root:

```yaml
# .mcp-audit-policy.yml
version: 1
name: "Acme Corp MCP policy"

approved_servers:
  mode: allowlist
  violation_severity: high
  entries:
    - name: "@modelcontextprotocol/server-filesystem"
      source: npm
    - name: "@modelcontextprotocol/server-github"
      source: npm
    - name: "acme-internal-tools"
      notes: "Our internal MCP server"
```

2. Commit it. Every developer running `mcp-audit scan` will see violations for
   unapproved servers because mcp-audit auto-discovers the policy from the repo root.

3. Violations appear in all output formats:
   - Terminal: a yellow "Policy Violations" panel
   - JSON: findings with `"analyzer": "governance"`
   - SARIF: rule IDs prefixed `GOV-`, tagged `governance-policy`

---

## Example: CI/CD governance gate

Combine with the [GitHub Action](github-action.md):

```yaml
# .github/workflows/mcp-governance.yml
on: [push, pull_request]

jobs:
  mcp-governance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: adudley78/mcp-audit@main
        with:
          severity-threshold: high
          # policy auto-discovered from repo root
```

The action fails the build when governance findings at or above the
`severity-threshold` are found (because they appear as normal findings with
`exit code 1`).

---

## Known limitations

- **Client name matching** uses string comparison against known `client` values
  in `ClientOverride` keys. Typos in client keys are silently ignored — the
  base policy applies. Valid keys are listed above.
- **Score threshold** requires a completed scan (`ScanResult` with a populated
  `score` field). It cannot run in isolation without analyzer output.
- **Approved server glob matching** uses Python's `fnmatch` module (shell-style
  wildcards), not full regex. `*` matches everything except `/`? No — fnmatch
  `*` matches any characters including `/`. Test your patterns with
  `mcp-audit policy check`.
- **Source detection** is inferred from the server's launch command
  (`npx`/`node` → npm, `python`/`uvx` → pip). Servers launched with custom
  scripts or absolute paths return `None` source, which never matches a
  source-restricted entry.
- **Finding policy counts** exclude governance findings to prevent circular
  amplification. If you have `max_critical: 0` and one governance finding is
  CRITICAL, it will not trigger another governance finding.
