# ADR 0001 — Shadow MCP as Hero Feature: Architecture Decisions

**Date:** 2026-05-03
**Status:** Accepted
**Deciders:** Adam Dudley (product owner)

---

## Context

STORY-0012 adds `mcp-audit shadow`, a new top-level command that sweeps every
known MCP config location on a host, classifies each server as sanctioned or
shadow, scores risk, and emits structured events for syslog/SIEM ingestion.
Three architectural questions arose during design:

1. Should `shadow` be a separate top-level command or a flag on `scan`?
2. Should the allowlist reuse the governance policy YAML (`--policy`) or be its
   own file?
3. Should classification use a sanctioned/shadow binary or a multi-tier ladder?

---

## Decision 1 — Separate top-level command (`mcp-audit shadow`)

**Decision:** `shadow` is a distinct top-level Typer command, not a flag on
`scan`.

**Rationale:**

- `scan` has a well-defined contract: "given these configs, run all analyzers
  and return structured findings." Adding a `--shadow` flag would conflate two
  separate concerns: security analysis of known configs vs. host-wide continuous
  endpoint detection.
- `shadow` has a fundamentally different I/O shape: it emits event log records
  keyed by `(client, server_name, event_type)` and tracks temporal state
  (`first_seen`, `last_seen`). Shoehorning this into a `ScanResult` would
  require adding optional fields to the core data model and would break the
  single-responsibility principle of each output format.
- `shadow --continuous` (daemon mode) is meaningless in the context of a
  one-shot `scan` invocation.
- Positioning `shadow` as a distinct entry point makes the hero pitch crisp in
  `mcp-audit --help` and in marketing copy. A flag on `scan` buries the feature.

---

## Decision 2 — Separate allowlist file, not governance policy YAML

**Decision:** `shadow` reads from `.mcp-audit-allowlist.yml` (or `--allowlist`
path), not from the governance policy's `approved_servers` list.

**Rationale:**

- The governance policy enforces *organisational quality requirements* over a
  scan: minimum scores, transport constraints, approved packages. The allowlist
  for `shadow` answers a different question: "is this server known and
  intentionally deployed?"
- The governance `approved_servers` field was designed for CI pass/fail
  enforcement; it does not carry the temporal metadata (`first_seen`,
  `last_seen`) or capability-context that `shadow` tracks.
- Coupling the two systems at v0 would force anyone using `shadow` to also
  adopt a governance policy file, which is an unnecessary barrier for an entry
  point pitched at first-time CISO adoption.
- The allowlist schema (`sanctioned_servers`, `sanctioned_capabilities`) is
  deliberately minimal and YAML-idiomatic, matching governance YAML conventions
  stylistically without a hard dependency.

**Future work:** A later story may introduce `shadow allowlist sync --from-policy`
to project `approved_servers` entries into the allowlist format, or unify the
schemas. Parked for v0.8+.

---

## Decision 3 — Binary classification: `sanctioned` vs `shadow`

**Decision:** Classification is a binary `"sanctioned"` | `"shadow"` rather
than a multi-tier ladder (e.g. `approved` / `tolerated` / `shadow` /
`blocked`).

**Rationale:**

- The hero pitch is "everything is shadow until you say otherwise." A binary
  classification maps directly to the CISO mental model: something is either
  explicitly approved or it isn't.
- A multi-tier model requires policy to assign each tier, which is governance
  policy territory (see Decision 2). Conflating tiers into the allowlist would
  collapse the architectural separation.
- Risk information (capability tags, toxic-flow signals, severity levels) is
  surfaced separately via the `risk_level` field. An operator can combine
  `classification == "shadow"` AND `risk_level == "HIGH"` to triage the most
  dangerous unknowns first — this is more expressive than a fixed tier ladder.
- Binary is simpler to explain, simpler to test, and simpler to integrate into
  SIEM alert rules.

**Future work:** If operators need a "tolerated but not approved" state, that
can be modelled as an allowlist `tolerated_servers` section with a different
output classification. Parked for v0.8+.

---

## Consequences

- `shadow` can evolve independently of `scan` without risk of regressions in
  the core scan pipeline.
- The `shadow` module (`src/mcp_audit/shadow/`) is self-contained and has no
  circular dependencies with the `scan` pipeline.
- The governance engine and `shadow` allowlist are decoupled at v0 — operators
  who use both must maintain two files. This is a known UX debt.
- Tests for `shadow` are isolated in `tests/test_shadow.py` and do not require
  scanner infrastructure.
