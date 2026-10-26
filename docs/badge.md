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
| **Registry status** | `verified` — a registry reviewer has confirmed the maintainer link between package name and source repo. `listed` — the package is in the registry but the maintainer link is not confirmed (most entries start here). A package that is not in the registry at all has no badge: its badge URL returns 404 (see [below](#your-package-is-not-in-the-registry)). |
| **Recorded CVEs** | The CVEs recorded in the registry entry for this package, split into fixed (a fixed-in version is recorded) and unfixed. Only CVEs explicitly added to the registry entry are counted. |

**What the badge says** (checked against the live badge files on 2026-10-25):

| Badge message | Colour | When |
|--------|--------|------|
| `N unfixed CVEs` | Red | At least one recorded CVE has no fixed-in version |
| `N fixed CVEs` | Yellow | CVEs are recorded and every one has a fixed-in version |
| `verified · 0 known CVEs` | Green | Verified entry, no recorded CVEs |
| `listed · 0 known CVEs` | Blue | Listed (not verified) entry, no recorded CVEs |
| _(no badge)_ | — | Not in the registry: the badge URL returns 404 and Shields.io shows `custom badge: resource not found` |

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
  verified package with recorded CVEs shows the CVE message (yellow or red), not
  `verified`.
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

Visit `https://mcp-audit.dev/servers/<eco>/<slug>/` (e.g.
`https://mcp-audit.dev/servers/npm/at-modelcontextprotocol-server-filesystem/`) and
copy the badge snippet from the package page.

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

mcp-audit.dev is rebuilt from the registry and deployed by the maintainer; there is
no scheduled refresh and no automatic deploy on merge. A registry change (a new
entry, a verification, or a CVE added to `known_vulns` / `known_vulnerabilities`)
reaches the badge on the next site deployment, and Shields.io picks it up when its
cache expires.

**Local freshness** — `mcp-audit vet --badge` reads the registry from your local
cache. Run `mcp-audit update-registry` to pull the latest registry before generating
a badge locally. The badge URL itself (rendered in the browser) always fetches live
from `mcp-audit.dev`.

---

## Your package is not in the registry?

`mcp-audit vet --badge` prints a snippet for any package name, but mcp-audit.dev
only publishes badge files for registry entries. For a package that is not listed,
the badge URL returns 404 and Shields.io renders `custom badge: resource not found`.
Add your package in about 5 minutes:

1. [Open a registry submission issue](https://github.com/adudley78/mcp-audit/issues/new?template=registry-submission.yml)
   — or edit `registry/known-servers.json` directly and open a PR.
2. Once merged, the badge appears on the next `mcp-audit.dev` deployment: blue
   `listed · 0 known CVEs` for a new entry, or green `verified · 0 known CVEs` when
   a reviewer has confirmed the maintainer link (assuming no recorded CVEs).

See [docs/registry-contributions.md](registry-contributions.md) for the full entry
format, required fields, and the verification standard.
