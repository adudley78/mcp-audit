# mcp-audit vet — Pre-install verdict

`mcp-audit vet <package>` checks a public MCP server package against the
known-server registry and tells you the facts before you install it:
verification status, known CVEs, declared capabilities, and hash pins.

**No letter grades** — risk depends on your deployment context.  `vet` gives
you the data; you make the call.

**Offline by default** — plain `vet` makes zero network calls.

---

## Quick start

```bash
# Check an npm package (scoped)
mcp-audit vet @modelcontextprotocol/server-filesystem

# Check a PyPI package
mcp-audit vet mcp-atlassian --ecosystem pypi

# Machine-readable JSON
mcp-audit vet @azure/mcp --format json

# Shields.io badge for your README
mcp-audit vet @modelcontextprotocol/server-filesystem --badge

# Live verdict from mcp-audit.dev (requires network)
mcp-audit vet @scope/name --online

# CI mode: exit 1 if package is unknown (not just CVE/typosquat)
mcp-audit vet @scope/name --strict
```

---

## Exit codes

| Code | Condition |
|------|-----------|
| 0 | Package known + no CVEs + no typosquat (or unknown without `--strict`) |
| 1 | CVEs present, typosquat suspicion, or unknown + `--strict` |
| 2 | Invalid/empty package name, bad `--ecosystem` flag, registry not found |

---

## Options

| Flag | Description |
|------|-------------|
| `--ecosystem npm\|pypi` | Force ecosystem lookup. Auto-detected when omitted (`@scope/name` → npm; plain names try npm then pypi). |
| `--format json` | Emit the full verdict document (conforms to `mcp-audit.dev/v1/schema.json`). |
| `--badge` | Print a Shields.io Markdown badge for the package and exit 0. |
| `--online` | Fetch a live verdict from `mcp-audit.dev` (HTTPS GET) and cache it at `<user-config-dir>/mcp-audit/verdict-cache.json` (0o600). Falls back to bundled registry on failure. |
| `--strict` | Exit 1 when the package is not in the registry (useful in CI). |
| `--offline-registry` | Use the bundled registry only; skip the user-local cache. |

---

## Output: known package

```
╭─ mcp-audit verdict ──────────────────────────────────────────╮
│ @modelcontextprotocol/server-filesystem  (npm)               │
│                                                              │
│   Registry:      Listed · Verified · Anthropic               │
│   Entry updated: 2026-04-15                                  │
│                                                              │
│   Capabilities:  file_read, file_write                       │
│   Hash pins:     yes                                         │
│   Sigstore attestation expected: yes                         │
│                                                              │
│   Known vulnerabilities: none                                │
│                                                              │
│   Repo: https://github.com/modelcontextprotocol/servers      │
│   Verdict page: https://mcp-audit.dev/v1/verdicts/npm/...   │
╰──────────────────────────────────────────────────────────────╯
```

## Output: CVEs present

```
╭─ mcp-audit verdict ──────────────────────────────────────────╮
│ mcp-atlassian  (pypi)                                        │
│                                                              │
│   Registry:      Listed · Verified · sooperset               │
│                                                              │
│   Known vulnerabilities: 1                                   │
│                                                              │
│   CVE-2026-27826 — Authentication bypass via crafted token   │
│   fixed in 0.9.4                                             │
│   https://nvd.nist.gov/vuln/detail/CVE-2026-27826            │
╰──────────────────────────────────────────────────────────────╯
```
Exit code: **1**

## Output: typosquat suspicion

```
╭─ Possible typosquat — vet exit 1 ────────────────────────────╮
│ Queried:  @modelcontextprotocol/server-filesytem             │
│ Closest:  @modelcontextprotocol/server-filesystem            │
│           (maintainer: Anthropic, verified: True)            │
│ Distance: 1 edit(s)                                          │
│                                                              │
│ Did you mean the known-legitimate package above?             │
│ Verify the name is intentional before installing.            │
╰──────────────────────────────────────────────────────────────╯
```
Exit code: **1**

## Output: unknown package

```
╭─ mcp-audit verdict — unknown package ────────────────────────╮
│ some-new-package  (npm)                                      │
│                                                              │
│ No verdict available. The registry covers 83 known servers;  │
│ this package is not among them.                              │
│                                                              │
│ Absence of registry data is NOT a safety signal.             │
│ The registry covers a curated corpus, not every MCP package. │
│                                                              │
│ After installing and configuring, run:                       │
│   mcp-audit scan                                             │
│                                                              │
│ Help grow the registry: https://mcp-audit.dev/contribute     │
╰──────────────────────────────────────────────────────────────╯
```
Exit code: **0** (1 with `--strict`)

---

## JSON output

`--format json` emits a verdict document conforming to
[mcp-audit.dev/v1/schema.json](https://mcp-audit.dev/v1/schema.json):

```json
{
  "schema_version": "1.0.0",
  "generated_at": "2026-06-13T12:00:00+00:00",
  "package": {
    "ecosystem": "npm",
    "name": "@modelcontextprotocol/server-filesystem"
  },
  "registry": {
    "listed": true,
    "verified": true,
    "maintainer": "Anthropic",
    "entry_updated": "2026-04-15",
    "registry_updated": "2026-05-30"
  },
  "known_vulnerabilities": [],
  "capabilities": ["file_read", "file_write"],
  "attestation": {
    "hash_pins_available": true,
    "attestation_expected": true
  },
  "typosquat_of": null,
  "tags": ["official", "filesystem", "local"],
  "links": {
    "repo": "https://github.com/modelcontextprotocol/servers",
    "verdict_page": "https://mcp-audit.dev/v1/verdicts/npm/at-modelcontextprotocol-server-filesystem.json"
  }
}
```

---

## Badge

`--badge` prints a Shields.io Markdown badge you can paste into your project README:

```
[![mcp-audit verdict](https://img.shields.io/endpoint?url=https://mcp-audit.dev/v1/badge/npm/at-modelcontextprotocol-server-filesystem.json)](https://mcp-audit.dev/v1/verdicts/npm/at-modelcontextprotocol-server-filesystem.json)
```

**Slug convention:** `@scope/name` → `at-scope-name`, lowercased, `_` → `-`.

The badge shows registry verification status and known CVE count for the package —
not a grade, not an endorsement, nothing about any deployment. See
[docs/badge.md](badge.md) for the full specification: what the badge asserts, what
it does not, and how badge data updates.

---

## Online mode

`--online` makes one HTTPS GET to `mcp-audit.dev/v1/verdicts/{eco}/{slug}.json`.
The response is cached at `<user-config-dir>/mcp-audit/verdict-cache.json` (0o600).
Network failure is non-fatal — it logs a dim note and falls back to the bundled registry.

Plain `vet` (without `--online`) makes **zero** network calls.

---

## Typosquat detection

`vet` reuses the same Levenshtein threshold as `mcp-audit scan`'s supply-chain analyzer:

| Name length | Edit-distance threshold |
|-------------|------------------------|
| ≤ 5 chars | 1 |
| > 5 chars | 3 |

A match exits 1 and shows a "did you mean?" panel.

---

## PEP 503 normalization

For PyPI lookups, package names are normalised per
[PEP 503](https://peps.python.org/pep-0503/):
`mcp_atlassian`, `MCP-Atlassian`, and `mcp-atlassian` all resolve to the same entry.

---

## Workflow

The three primary practitioner verbs are:

```
mcp-audit vet <package>    # Before installing
mcp-audit check            # After installing and configuring
mcp-audit fix --apply      # Fix detected issues automatically
```

See also:
- [`mcp-audit check`](check.md) — one-command verdict on your installed configuration
- [`mcp-audit fix`](fix.md) — apply safe remediations to MCP config files
- [`mcp-audit scan`](docs-usage.md) — full scan with all analyzers
