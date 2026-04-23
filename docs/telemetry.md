# Telemetry & Privacy

mcp-audit collects **no telemetry, usage data, or analytics** — not even
crash reports.

## What this means

- Every scan runs entirely on your machine.
- No data is sent to mcp-audit servers, Anthropic, or any third party.
- No identifiers (machine ID, email, license key hash) are transmitted.
- `mcp-audit watch` continuous monitoring also runs fully locally.
- The HTML dashboard is a self-contained file — no beacons, no fonts loaded
  from external CDNs, no JavaScript that phones home.

## Why

mcp-audit is a **security tool that reads your MCP configuration files**,
which may contain environment variable names, server command paths, and other
sensitive context. Transmitting any portion of that data — even anonymised —
would undermine the tool's core value proposition.

The privacy-first design is also a practical trust signal: corporate security
teams and regulated-industry users can deploy mcp-audit without a network-policy
exception or a data-processing agreement.

## Trade-offs

We have no visibility into adoption, feature usage, or conversion rates. We
accept this cost. If you want to support the project, the most helpful thing
you can do is open a GitHub issue, star the repo, or share your experience
publicly.

## Future changes

Any future opt-in telemetry (if introduced) would require:
- Explicit `mcp-audit telemetry enable` command (off by default, always)
- Clear documentation of exactly what is sent
- A public data-retention policy
- A major version bump with a CHANGELOG entry

This file documents the current state and the bar any future change must clear.
