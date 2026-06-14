# mcp-audit verdict badge

The mcp-audit badge lets MCP server authors signal registry status and CVE count to
anyone evaluating their package.

[![mcp-audit verdict](https://img.shields.io/endpoint?url=https://mcp-audit.dev/v1/badge/npm/at-modelcontextprotocol-server-filesystem.json)](https://mcp-audit.dev/v1/verdicts/npm/at-modelcontextprotocol-server-filesystem.json)

---

## What the badge asserts

The badge surface shows exactly two facts, both sourced directly from the
[mcp-audit known-server registry](../registry/known-servers.json):

| Field | What it shows |
|-------|---------------|
| **Verification status** | `verified` — the maintainer link between package name and source repo has been confirmed by a registry reviewer. `unverified` — a community entry; the package is listed but the maintainer link is not confirmed. `unknown` — the package is not in the registry at all. |
| **Known CVE count** | The number of CVEs recorded in the registry for this specific package (e.g. `0 known CVEs`, `2 known CVEs`). Only CVEs explicitly added to the registry entry are counted. |

**Badge colours:**

| Status | Colour |
|--------|--------|
| `verified · 0 known CVEs` | Green |
| `verified · N known CVEs` (N > 0) | Red |
| `unverified · 0 known CVEs` | Yellow |
| `unverified · N known CVEs` (N > 0) | Red |
| `unknown` | Grey |

---

## What the badge does NOT assert

The badge is a **registry-membership signal, not a security grade**. It makes no
claim about:

- **Any deployment.** The badge describes the package, not how it is configured on
  your machine. A verified server can still be misconfigured (plaintext credentials,
  overprivileged tokens, poisoned tool descriptions). Run `mcp-audit scan` to assess
  your actual deployment.
- **A security grade or endorsement.** `verified` means the maintainer link was
  confirmed — it does not mean the server is safe, well-audited, or recommended. A
  verified package with known CVEs will show a red badge.
- **Freedom from undiscovered vulnerabilities.** The registry only records CVEs that
  have been explicitly added. A `0 known CVEs` badge does not mean zero CVEs exist —
  only that none have been added to the registry for this package.
- **Configuration, transport, credentials, or policy compliance.** The badge has no
  knowledge of how the server is wired in an MCP config file.

---

## How to get the badge for your package

### Option 1 — CLI (recommended)

```bash
mcp-audit vet @your-scope/your-mcp-server --badge
```

Output:

```markdown
[![mcp-audit verdict](https://img.shields.io/endpoint?url=https://mcp-audit.dev/v1/badge/npm/at-your-scope-your-mcp-server.json)](https://mcp-audit.dev/v1/verdicts/npm/at-your-scope-your-mcp-server.json)
```

Paste this Markdown into your README.

### Option 2 — Copy from mcp-audit.dev

Visit `https://mcp-audit.dev/<eco>/<slug>` (e.g.
`https://mcp-audit.dev/npm/at-modelcontextprotocol-server-filesystem`) and copy the
badge snippet from the package page.

### URL structure

```
https://img.shields.io/endpoint?url=https://mcp-audit.dev/v1/badge/{eco}/{slug}.json
```

**Slug convention** — `@scope/name` → `at-scope-name`, lowercased, `_` → `-`:

| Package name | Slug |
|---|---|
| `@modelcontextprotocol/server-filesystem` | `at-modelcontextprotocol-server-filesystem` |
| `mcp_server_git` | `mcp-server-git` |
| `mcp-atlassian` | `mcp-atlassian` |

---

## How badge data updates

Badge data is **registry-driven**: the badge JSON served by `mcp-audit.dev` is
generated from `registry/known-servers.json` at the mcp-audit GitHub repository.

Update triggers:

1. **Registry PR merged** — when a PR adds, updates, or removes an entry from
   `registry/known-servers.json`, the CI pipeline regenerates the badge JSON files
   for all affected packages and deploys them to `mcp-audit.dev`. There is no
   scheduled refresh — updates are event-driven.
2. **CVE added to a registry entry** — when a maintainer adds a CVE to
   `known_vulns` or `known_vulnerabilities` in an existing registry entry, the badge
   regenerates and turns red on the next Shields.io cache expiry (typically 1–5
   minutes after deployment).

**Local freshness** — `mcp-audit vet --badge` reads the registry from your local
cache. Run `mcp-audit update-registry` to pull the latest registry before generating
a badge locally. The badge URL itself (rendered in the browser) always fetches live
from `mcp-audit.dev`.

---

## Your package is not in the registry?

If your package shows `unknown`, it has not been added to the registry yet. Add it
in about 5 minutes:

1. [Open a registry submission issue](https://github.com/adudley78/mcp-audit/issues/new?template=registry-submission.yml)
   — or edit `registry/known-servers.json` directly and open a PR.
2. Once merged, your badge will turn from grey (`unknown`) to green (`verified · 0 known CVEs`)
   on the next `mcp-audit.dev` deployment.

See [docs/registry-contributions.md](registry-contributions.md) for the full entry
format, required fields, and the verification standard.
