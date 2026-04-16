# mcp-audit Community Rules

This directory contains YAML-based detection rules for the mcp-audit policy
engine. Rules in `community/` ship with every mcp-audit installation and run
for all users, including the free Community tier.

## Rule format

See [`docs/writing-rules.md`](../docs/writing-rules.md) for the complete
reference — field definitions, match types, compound operators, and examples.

Quick example:

```yaml
id: COMM-001
name: Prohibited network binary used as MCP server
description: Detects netcat/socat used as the server binary.
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

## Contributing

1. Fork the repo and create a branch.
2. Add your rule as `rules/community/COMM-NNN.yml` (use the next available number).
3. Required fields: `id`, `name`, `description`, `severity`, `category`, `match`, `message`.
4. Validate your rule: `mcp-audit rule validate rules/community/COMM-NNN.yml` (requires Pro).
5. Test against a real config: `mcp-audit rule test rules/community/COMM-NNN.yml --against path/to/config.json`.
6. Open a PR. The maintainers review for false-positive rate, accuracy, and research basis.

### Naming conventions

- Community rules: `COMM-NNN` (three-digit zero-padded number).
- Organisational rules: use your own prefix (e.g. `ACME-001`).
- IDs must be unique within a ruleset; duplicates are deduplicated with a warning.

### Review criteria

- The detection must have a clear security rationale.
- False-positive rate must be acceptable for production environments.
- Severity must match the actual risk (refer to existing rules for calibration).
- Each new pattern should cite a research source in PROVENANCE.md.

## User-local rules (Pro)

Place custom rules in `~/.config/mcp-audit/rules/` to have them loaded
automatically on every scan. Custom rule directories require a Pro license.

## Running rules

All rules in this directory run automatically during `mcp-audit scan`.
No configuration needed.
