# mcp-audit Community Rules

This directory contains YAML-based detection rules for the mcp-audit policy
engine. Rules in `community/` ship with every mcp-audit installation and run
for all users automatically — no configuration required.

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

See [docs/contributing-rules.md](../docs/contributing-rules.md) for the complete
contribution guide, including the step-by-step process, format spec, and bounty
program details.

Quick start:

1. Copy `TEMPLATE.yml` to `COMM-NNN.yml` (use the next available number).
2. Fill in all fields — every field has an inline comment explaining what to write.
3. Validate: `mcp-audit rule validate rules/community/COMM-NNN.yml`
4. Test: `mcp-audit rule test rules/community/COMM-NNN.yml --against path/to/config.json`
5. Open a PR. The maintainers review for false-positive rate, accuracy, and research basis.

The first 50 accepted contributors are listed in
[docs/contributors.md](../docs/contributors.md) — see
[BOUNTY.md](community/BOUNTY.md) for the full commitment.

### Naming conventions

- Community rules: `COMM-NNN` (three-digit zero-padded number).
- Organisational rules: use your own prefix (e.g. `ACME-001`).
- IDs must be unique within a ruleset; duplicates are deduplicated with a warning.

### Review criteria

- The detection must have a clear security rationale.
- False-positive rate must be acceptable for production environments.
- Severity must match the actual risk (refer to existing rules for calibration).
- Each new pattern should cite a research source in PROVENANCE.md.

## User-local rules

Place custom rules in `~/.config/mcp-audit/rules/` to have them loaded
automatically on every scan. No license or flag required — custom rules ship
in every build.

## Running rules

All rules in this directory run automatically during `mcp-audit scan`.
No configuration needed.
