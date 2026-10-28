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
| 0 | Package known, every recorded CVE has a fix (or none recorded), no typosquat; or unknown without `--strict` |
| 1 | A recorded CVE has no fix, typosquat suspicion (edit distance or an unscoped twin), OSV lists the latest release as malicious, or unknown + `--strict` |
| 2 | Invalid/empty package name, bad `--ecosystem` flag, registry not found |

`vet` takes no version, so it answers for the latest release. A CVE with a
recorded fix is listed with its fixed version but does not fail `vet`
(STORY-0083, 2026-10-13); before that, any recorded CVE did, which made `vet` fail
for every package with a fixed past. The same rule applies to malicious
releases (STORY-0097): an OSV record that covers every release, or every release
from some version on, exits 1; a record that lists only specific past releases
is shown and exits 0.

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
│   Known vulnerabilities: 1 (all fixed; pin a version at or  │
│   above each fix)                                            │
│                                                              │
│   CVE-2026-27826 — Authentication bypass via crafted token   │
│   fixed in 0.9.4                                             │
│   https://nvd.nist.gov/vuln/detail/CVE-2026-27826            │
╰──────────────────────────────────────────────────────────────╯
```
Exit code: **0** (a CVE with no recorded fix exits 1)

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

## Output: unscoped twin

An unlisted name that copies a known package's name without its scope (the
`SC-007` rule in `scan`, see [supply-chain.md](supply-chain.md#sc-007-unscoped-twins))
is a typosquat suspicion too, explained by the relation instead of an edit
distance:

```
╭─ Possible unscoped twin — vet exit 1 ────────────────────────╮
│ Queried:  server-github                                      │
│ Twin of:  @modelcontextprotocol/server-github                │
│           (maintainer: Anthropic, verified: True)            │
│ Relation: the queried name is the name of                    │
│ '@modelcontextprotocol/server-github' without its scope      │
╰──────────────────────────────────────────────────────────────╯
```
Exit code: **1**

## Output: listed as malicious in OSV

`vet` checks the bundled OSV `MAL-*` mirror (`registry/known-malicious.json`,
the `SC-008` data) for the exact name, offline:

```
╭─ Listed as malicious in OSV — vet exit 1 ────────────────────╮
│ MAL-2025-47604 — Malicious code in postmark-mcp (npm)        │
│   every release from 1.0.16 on marked malicious              │
│   https://osv.dev/vulnerability/MAL-2025-47604               │
╰──────────────────────────────────────────────────────────────╯
```
Exit code: **1**. A record that lists only past releases
(`vet @browserbasehq/mcp`: release 2.1.1) is shown in a yellow panel and exits 0.

Without `--ecosystem`, `vet` also warns when the *other* registry's package of
the same name is malicious. `vet mcp-server-git` answers for Anthropic's PyPI
server (exit 0) and warns that the npm package `mcp-server-git` is
`MAL-2026-5478`; `vet mcp-server-git --ecosystem npm` answers for the npm one
(exit 1).

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
  "typosquat_basis": null,
  "malicious": [],
  "other_ecosystem_malicious": [],
  "tags": ["official", "filesystem", "local"],
  "links": {
    "repo": "https://github.com/modelcontextprotocol/servers",
    "verdict_page": "https://mcp-audit.dev/v1/verdicts/npm/at-modelcontextprotocol-server-filesystem.json"
  }
}
```

Fields added by STORY-0097 (the schema allows additional properties):

| Field | Meaning |
|---|---|
| `typosquat_basis` | `"edit-distance"` or `"unscoped-twin"` when `typosquat_of` is set, else `null` |
| `malicious` | OSV `MAL-*` records for this package in this ecosystem: `id`, `ecosystem`, `aliases`, `summary`, `versions`, `ranges` (OSV events), `latest_affected`, `blanket_range_ignored`, `link`, `note` |
| `other_ecosystem_malicious` | The same, for the other registry's package of this name (only without `--ecosystem`); never changes the exit code |

---

## Badge

`--badge` prints a Shields.io Markdown badge you can paste into your project README:

```
[![mcp-audit verdict](https://img.shields.io/endpoint?url=https://mcp-audit.dev/v1/badge/npm/at-modelcontextprotocol-server-filesystem.json)](https://mcp-audit.dev/v1/verdicts/npm/at-modelcontextprotocol-server-filesystem.json)
```

**Slug convention:** `@scope/name` → `at-scope-name`, lowercased, `_` → `-`.

**Ecosystem:** without `--ecosystem`, an unscoped name the registry lists only for
PyPI gets a PyPI badge (`vet mcptoon --badge` → `/v1/badge/pypi/mcptoon.json`),
spelled as the registry spells it (`MCP_Atlassian` → `mcp-atlassian`).  Every other
name, including one the registry doesn't list, gets the npm badge, as before.
Registry names are unique across ecosystems, so the choice is never ambiguous.

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

**Not yet surfaced here:** `mcp-audit lock`'s deprecated-package check
(`SC-005` — a registry-marked-deprecated version, npm's own `deprecated`
field) is not wired into `vet --online` or `scan --check-vulns`. It fires
only at `lock` resolution and `lock --verify --resolve` for now — see
[docs/lock.md](lock.md#whats-in-the-file) and `GAPS.md`. Tracked as
STORY-0074.

---

## Typosquat detection

`vet` reuses the same Levenshtein threshold as `mcp-audit scan`'s supply-chain analyzer:

| Name length | Edit-distance threshold |
|-------------|------------------------|
| ≤ 5 chars | 1 |
| > 5 chars | 3 |

A match exits 1 and shows a "did you mean?" panel. An unscoped twin is checked
first and, when it matches, replaces the edit-distance result, as in `scan`.

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
