# Writing Custom Detection Rules

mcp-audit includes a policy-as-code rule engine that lets security practitioners
write custom detection rules in YAML without modifying Python code. Rules produce
standard `Finding` objects that appear in all output formats (terminal, JSON,
SARIF, HTML dashboard, Nucleus FlexConnect).

**Bundled community rules run on every scan** for every user. Authoring tools
(`rule validate`, `rule test`) and custom rule directories (`--rules-dir`,
`~/.config/mcp-audit/rules/`) are also available to every user — mcp-audit is
fully open source (Apache 2.0).

---

## Rule format reference

A rule file is a YAML document containing a single rule mapping or a `rules:`
list of rule mappings.

```yaml
# Single rule per file (preferred for community contributions)
id: COMM-001
name: Prohibited network binary used as MCP server
description: >
  Detects netcat, socat, ncat used as the MCP server binary.
  These tools have no legitimate use as an MCP server command.
severity: HIGH
category: network
match:
  field: command
  pattern: "^(nc|ncat|socat|netcat)$"
  type: regex
message: "Server '{server_name}' uses prohibited network binary: {matched_value}"
tags:
  - network
  - exfiltration
enabled: true
```

### Fields

| Field | Required | Type | Description |
|-------|----------|------|-------------|
| `id` | ✓ | string | Unique rule identifier (e.g. `COMM-001`, `ACME-001`) |
| `name` | ✓ | string | Short human-readable rule name (used as Finding title) |
| `description` | ✓ | string | Longer explanation of what the rule detects and why |
| `severity` | ✓ | enum | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `INFO` |
| `category` | ✓ | string | Free-form category tag (e.g. `network`, `credentials`) |
| `match` | ✓ | object | Match condition — see [Match types](#match-types) |
| `message` | ✓ | string | Finding description template — see [Interpolation](#interpolation) |
| `tags` | | list[str] | Searchable tags (e.g. `[network, exfiltration]`) |
| `enabled` | | bool | Set to `false` to disable without deleting. Default: `true` |
| `exempt_known_servers` | | bool | Skip servers whose command, arg, or server_name matches a known-server registry entry. Default: `false`. See [Registry exemption](#registry-exemption) |

---

## Match types

The `match` block controls how the rule evaluates a server. Set `type` to one of
the five match strategies:

### `exact`

Case-sensitive exact string equality.

```yaml
match:
  field: command
  pattern: "curl"
  type: exact
```

Fires when `server.command == "curl"`.

### `contains`

Case-sensitive substring search.

```yaml
match:
  field: args
  pattern: "--no-sandbox"
  type: contains
```

Fires when `"--no-sandbox"` appears anywhere in the joined args string.

### `regex`

Python `re.search()` applied to the field value. Supports all standard Python
regex syntax.

```yaml
match:
  field: command
  pattern: "^(nc|ncat|socat|netcat)$"
  type: regex
```

The matched group is captured as `{matched_value}`. An invalid regex pattern
is silently skipped with a logged warning — it will never crash the scanner.

### `glob`

Unix shell-style glob matching using Python's `fnmatch.fnmatch()`.

```yaml
match:
  field: command
  pattern: "python*"
  type: glob
```

Fires for `python`, `python3`, `python3.11`, etc.

### `semver_range`

Checks if the field value is a semver version string within the range expressed
by `pattern`, using [PEP 440 specifier syntax](https://peps.python.org/pep-0440/#version-specifiers).

```yaml
match:
  field: args
  pattern: ">=1.0,<2.0"
  type: semver_range
```

> **Note:** Requires the `packaging` library. If not available, falls back to
> exact string comparison with a logged warning.

---

## Match fields

| Field | Extracts | Example value |
|-------|----------|---------------|
| `command` | `server.command` | `"node"`, `"python3"`, `"nc"` |
| `args` | `" ".join(server.args)` | `"server.js --port 3000"` |
| `env` | `" ".join(server.env.keys())` | `"AWS_KEY SSH_AUTH_SOCK"` |
| `server_name` | `server.name` | `"my-filesystem-server"` |
| `url` | `server.url` | `"https://example.com/mcp"` |
| `transport` | `server.transport` | `"stdio"`, `"sse"`, `"streamable-http"` |

**Security note on `env`:** The `env` field matches against environment variable
**key names only**, not values. This is intentional — matching values would expose
secret content in rule match output. Use the credentials analyzer for value-based
secret detection.

If a field is `None` (e.g. `url` on a stdio server), the match is skipped
and the rule produces no finding for that server.

---

## Negation

Set `negate: true` on any condition to invert the match: the rule fires when
the field **does not** match the pattern.

```yaml
match:
  field: command
  pattern: "node"
  type: exact
  negate: true
```

This fires for every server whose command is **not** `node`.

---

## Compound rules

Combine multiple conditions with `operator: and` or `operator: or`.

### AND — all conditions must match

```yaml
match:
  operator: and
  conditions:
    - field: command
      pattern: "^python"
      type: regex
    - field: args
      pattern: "--no-sandbox"
      type: contains
```

Fires only when both the command starts with `python` AND `--no-sandbox` is
present in args.

### OR — at least one condition must match

```yaml
match:
  operator: or
  conditions:
    - field: command
      pattern: "nc"
      type: exact
    - field: command
      pattern: "socat"
      type: exact
```

Fires when the command is either `nc` or `socat`.

### Negate inside compound

Individual conditions within a compound rule can also use `negate: true`:

```yaml
match:
  operator: and
  conditions:
    - field: command
      pattern: "^python"
      type: regex
    - field: args
      pattern: "--safe-mode"
      type: contains
      negate: true
```

Fires when command starts with `python` AND `--safe-mode` is **not** in args.

---

## Registry exemption

Set `exempt_known_servers: true` when a rule pattern is broad enough to fire
on legitimate MCP servers and you want it suppressed for packages that are
already vetted in the [known-server registry](../registry/known-servers.json).

```yaml
id: COMM-004
name: Unrecognized stdio server binary
severity: LOW
category: transport
match:
  field: transport
  pattern: "stdio"
  type: exact
message: "Server '{server_name}' uses stdio transport and is not in the registry"
exempt_known_servers: true
```

When the rule engine is constructed with a registry (the default scan
pipeline does this automatically), servers whose `command`, any `arg`, or
`server_name` matches a registry entry are skipped **before** match
evaluation. Servers that do not resolve to a registry entry still evaluate
against the rule normally.

Use this when:

- The match pattern is genuinely universal in the MCP ecosystem (e.g.
  `stdio` transport, `npx` command) and you only want to flag *unvetted*
  instances.
- You want a rule to surface "unknown-source" servers without duplicating
  the supply-chain analyzer's typosquat logic.

**Avoid** this flag when:

- The rule patterns a specific security-relevant command (e.g. `nc`,
  `socat`). Known registry servers don't use these binaries — registry
  membership is not what makes them dangerous.
- The rule is intentionally a "belt and braces" check that should fire
  even on vetted servers.

Without a registry (custom tooling instantiating `RuleEngine` directly and
passing `registry=None`), the flag has no effect — the rule falls back to
matching every server.

---

## Interpolation tokens

The `message` field supports two interpolation tokens:

| Token | Replaced with |
|-------|---------------|
| `{server_name}` | The server's name from the config |
| `{matched_value}` | The matched portion of the field value |

For `regex` matches, `{matched_value}` is the matched group (e.g. `"nc"` for
pattern `"^(nc|socat)$"`).

For `contains` and `exact` matches, `{matched_value}` is the full field value.

For compound rules, `{matched_value}` is all matched values joined with `"; "`.

---

## Multi-rule files

A single YAML file can contain multiple rules under a `rules:` key:

```yaml
rules:
  - id: MYTEAM-001
    name: Rule one
    ...
  - id: MYTEAM-002
    name: Rule two
    ...
```

If a rule in the list fails schema validation, it is skipped with a warning and
the remaining rules in the file are still loaded.

---

## Testing and validation

### Validate syntax

```bash
mcp-audit rule validate rules/community/COMM-001.yml
```

Parses the rule file and prints a table of loaded rules. Exits 0 if valid, 1 if
any errors.

### Test against a config

```bash
mcp-audit rule test my-rule.yml --against ~/.config/claude/claude_desktop_config.json
```

Shows a table of all rules × all servers with match results:

```
┌──────────────────┬─────────┬─────────────────┬──────────┬───────────────┐
│ Server           │ Rule ID │ Rule Name        │ Matched? │ Matched Value │
├──────────────────┼─────────┼─────────────────┼──────────┼───────────────┤
│ filesystem       │ MY-001  │ My custom rule   │ ✗ no     │               │
│ fetch            │ MY-001  │ My custom rule   │ ✓ YES    │ node          │
└──────────────────┴─────────┴─────────────────┴──────────┴───────────────┘
```

Exit code is always 0 — this is a development tool, not a gate.

### List all loaded rules

```bash
mcp-audit rule list
```

Shows all bundled community rules plus user-local rules.

---

## Where to put rules

### User-local rules

Place YAML files in `~/.config/mcp-audit/rules/`. They are loaded automatically
on every scan. User rules take precedence over community rules on ID conflicts.

```
~/.config/mcp-audit/rules/
  MYORG-001.yml
  MYORG-002.yml
```

### Temporary scan-time rules

Pass `--rules-dir PATH` to `mcp-audit scan` to load rules for a single scan
without installing them globally.

```bash
mcp-audit scan --rules-dir ./my-org-rules/
```

---

## Contributing community rules

Community rules in `rules/community/` ship with every mcp-audit installation and
run for every user. Every rule contributed makes the scanner better for everyone.

### Naming conventions

- Community rule IDs follow the format `COMM-NNN` (zero-padded three-digit number).
- Use the next available number when contributing.
- Organisational rules should use a team-specific prefix: `ACME-001`, `SEC-001`, etc.

### Required fields for contribution

All five required fields must be present: `id`, `name`, `description`, `severity`,
`category`, `match`, `message`.

### Severity guidelines

| Severity | When to use |
|----------|-------------|
| CRITICAL | Direct, immediate, exploitable risk with high impact |
| HIGH | Significant risk that should be fixed before production |
| MEDIUM | Notable risk worth investigating |
| LOW | Informational; worth reviewing but low urgency |
| INFO | Purely informational; no risk implied |

### Review criteria

The maintainers review PRs for:

1. **Security rationale** — clear explanation of why this is a risk.
2. **False-positive rate** — low FPR for production environments.
3. **Research basis** — new patterns should cite a source in PROVENANCE.md.
4. **Pattern quality** — `regex` patterns should be anchored where appropriate;
   `exact` patterns should not be used where `contains` would be more accurate.

### PR process

1. Fork the repo and create a branch named `rule/COMM-NNN-short-description`.
2. Add your rule at `rules/community/COMM-NNN.yml`.
3. Validate: `mcp-audit rule validate rules/community/COMM-NNN.yml`.
4. Open a PR with the table output from `rule validate` in the description.
5. Maintainers review and may request changes to severity, pattern, or message.

---

## Availability

Every rule-authoring command is available to every user — mcp-audit is
fully open source (Apache 2.0):

- Bundled community rules run automatically on every scan.
- `rule validate`, `rule test`, `rule list` all ship in the standard CLI.
- `--rules-dir` custom directories and `~/.config/mcp-audit/rules/`
  user-local rules are loaded by every install.
