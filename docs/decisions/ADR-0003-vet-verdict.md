# ADR-0003 — mcp-audit vet: pre-install verdict design

**Status:** Accepted  
**Date:** 2026-06-13  
**Author:** Adam Dudley  
**Supersedes:** `story/0016-mcp-audit-dev` `lookup` command (stale branch; different URL shape, included letter grades — do not merge or copy)

---

## Context

Developers want to check an MCP server package *before* installing it.
The existing `scan` and `check` commands operate on configs that are already installed.
A pre-install verdict command fills the gap: "Is this package trustworthy enough to configure?"

A stale branch (`story/0016-mcp-audit-dev`) had a `lookup` command with a different URL
shape and a letter grade in the output.  That branch was abandoned.  `vet` supersedes it.

---

## Decision

### Command: `mcp-audit vet <package>`

A new top-level command that:
1. Resolves the package against the bundled known-server registry (offline by default).
2. Reports **facts only** — no letter grade, no risk score.
3. Exits 0 (clean), 1 (concerns found), or 2 (error).

### Data sources

| Source | When used | Network? |
|---|---|---|
| Bundled `registry/known-servers.json` | Always (baseline) | No |
| User-cached registry (`update-registry`) | When present and `--offline-registry` not set | No (cached) |
| `mcp-audit.dev/v1/verdicts/{eco}/{slug}.json` | Only with `--online` flag | Yes (HTTPS GET) |

Plain `vet` makes **zero** network calls.  This is non-negotiable — the primary user is a
developer pasting a package name into their terminal before `npx`-ing it.

### Verdict document schema

The verdict document shape is sourced from `https://mcp-audit.dev/v1/schema.json`
(schema_version `"1.0.0"`).  `mcp_audit.verdict.build_verdict()` is the single
implementation; the mcp-audit.dev static-site generator re-uses the same function.

Required fields: `schema_version`, `generated_at`, `package`, `registry`,
`known_vulnerabilities`, `capabilities`, `attestation`.

### Facts, not grades

A letter grade (A–F) is a risk *verdict* that depends on deployment context:
- `@modelcontextprotocol/server-filesystem` with `file_write` capability is fine
  for a developer workstation, but unacceptable in a multi-tenant production environment.
- The registry cannot know the deployment context; only the operator can.

`vet` surfaces facts (capabilities, CVEs, verification status, hash pins) and leaves
the risk judgement to the operator.  The word "grade" must not appear in `vet` output.

### Typosquat detection

Reuses the Levenshtein threshold logic from `SupplyChainAnalyzer`:
- Names ≤5 chars: threshold = 1 edit
- Names > 5 chars: threshold = 3 edits

A typosquat suspicion exits 1, shows "did you mean X?", and emits the canonical name,
maintainer, and verification status.

### Ecosystem resolution

- `@scope/name` → npm (scoped packages are npm-only)
- Plain name without `--ecosystem` → try npm first, then pypi sub-index
- PEP 503 normalisation applied for pypi lookups (`mcp_atlassian` = `mcp-atlassian`)

### Exit codes

| Condition | Exit code |
|---|---|
| Known, no CVEs, no typosquat | 0 |
| Unknown, `--strict` not set | 0 |
| CVEs present | 1 |
| Typosquat suspicion | 1 |
| Unknown + `--strict` | 1 |
| Empty/invalid name, bad ecosystem flag, registry not found | 2 |

### Online mode caching

When `--online` is given, the fetched verdict is cached at
`<user-config-dir>/mcp-audit/verdict-cache.json` with `0o600` permissions
(registry-cache pattern).  Network failure falls back to the bundled registry with
a dim note — it never causes exit 2.

### Badge URL convention

```
https://img.shields.io/endpoint?url=https://mcp-audit.dev/v1/badge/{eco}/{slug}.json
```

Slug rules: `@scope/name` → `at-scope-name`, lowercased, `_` → `-`.

---

## Consequences

- **`mcp_audit.verdict`** is the single source of truth for the verdict document shape.
  Website generator must import from here, not duplicate the logic.
- **No new finding IDs** are introduced.  `vet` emits verdicts, not `Finding` objects.
  `validate_owasp_mapping.py` passes unchanged.
- **`story/0016-mcp-audit-dev`** is permanently superseded.  Do not merge it.
- The `_gate.py` / `licensing.py` patterns must not be re-introduced here — `vet` is
  available to every user (Apache 2.0).
