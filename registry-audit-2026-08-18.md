# Known-Server Registry Audit — 2026-08-18

**Scope:** every one of the 85 entries in `registry/known-servers.json`, checked live
against `registry.npmjs.org`, `api.npmjs.org` (download counts), and `pypi.org`.
**Method:** `scripts/audit_registry.py` (new, committable, re-runnable — see
"Methodology" at the end of this report). Sequential requests, ~0.4s apart,
descriptive User-Agent, one retry on rate-limit, never fabricated or guessed data.
**Status:** fact-finding only. **No registry entries were modified, added, or
removed as part of this task.**

---

## 1. Executive summary

| Bucket | Count | Meaning |
|---|---:|---|
| **MISSING** | **25** | Package does not exist (or no longer exists) under that name. Actively exploitable — anyone can register it today. |
| **UNCLAIMABLE_MISMATCH** | **18** | Package exists, but the real publisher/repo does not match what the registry claims. |
| **THIN** | **1** | Package exists but shows a placeholder/pre-1.0 signal (judged low-risk on inspection — see §4). |
| **UNCHECKED** | **0** | Every entry was successfully checked; no network blocks. |
| **OK** | **41** | Package exists and nothing contradicts the registry's claim. |
| **Total** | **85** | |

**Bottom line: this is not one bad batch — it is a systemic gap.** The originally
reported "26-entry community block" (confirmed to be **exactly 26 entries**, not
"roughly 26" — see §3) accounts for **25 of the 25 MISSING-or-mismatch findings in
that block**, but the audit also found **serious, previously unknown problems in
entries marked `verified: true` and attributed to Anthopic/major vendors**,
completely outside that block:

- **8 `verified: true`, `maintainer: "Anthropic"` npm entries no longer exist**
  (404) — including `@modelcontextprotocol/server-fetch`,
  `@modelcontextprotocol/server-git`, `@modelcontextprotocol/server-gmail`, and
  `@anthropic-ai/mcp-server-puppeteer`. mcp-audit is currently vouching for names
  that are free for anyone to register, under Anthropic's name, with `verified: true`
  — the single most trusted flag the schema has.
- A `verified: true` PyPI entry, `mcp-server-filesystem`, **also does not exist** (404).
- A `verified: true` PyPI entry, `mcp-server-postgres`, **does exist but is not
  Anthropic's package** — real author is a third-party Gmail address, summary is the
  literal placeholder text `"Add your description here"` (see §5).
- Outside the block, entries for **GitHub, Notion, Linear, and Microsoft** (all
  `verified: false` but attributed to those real companies) are also 404s the
  registry is vouching for on their behalf without their involvement.
- A `verified: false` entry (`@azure/mcp` → Microsoft) and two more
  (`@stripe/agent-toolkit`, `@supabase/mcp-server-supabase`) have real, clearly
  legitimate packages whose repo has simply moved — registry data drift, not fraud,
  but still a mismatch the registry currently reports as a match.
- Two more (`firecrawl-mcp`, `gemini-mcp-tool`) look exactly like the block's bad
  pattern — real vendor name implied, real package exists, but published by an
  unrelated individual account with no connection to the named vendor — and neither
  is in the labeled block.

**Conclusion for §4: the gap is systemic, confined neither to the one block nor to
unverified entries.** See §6 for full evidence.

---

## 2. Full MISSING list (the actively exploitable set)

These 25 names do not currently resolve to an installable package. **Anyone —
including an attacker — can register any of these exact names on the real registry
right now**, and the next `mcp-audit scan` on a machine that installs it would treat
it as a known-good, typosquat-immune name.

| # | Name | Ecosystem | Registry says | Why it's missing |
|---|---|---|---|---|
| 1 | `@modelcontextprotocol/server-google-drive` | npm | Anthropic, verified | 404 |
| 2 | `@modelcontextprotocol/server-sqlite` | npm | Anthropic, verified | 404 |
| 3 | `@modelcontextprotocol/server-fetch` | npm | Anthropic, verified | 404 |
| 4 | `@modelcontextprotocol/server-sequentialthinking` | npm | Anthropic, verified | 404 (see §6 — likely a typo'd duplicate of the real `server-sequential-thinking`) |
| 5 | `@modelcontextprotocol/server-sentry` | npm | Anthropic, verified | 404 |
| 6 | `@modelcontextprotocol/server-git` | npm | Anthropic, verified | 404 |
| 7 | `@modelcontextprotocol/server-gmail` | npm | Anthropic, verified | 404 |
| 8 | `@anthropic-ai/mcp-server-puppeteer` | npm | Anthropic, verified | 404 |
| 9 | `mcp-server-filesystem` | **pypi** | Anthropic, verified | 404 |
| 10 | `mcp-server-playwright` | npm | community, unverified | 404 |
| 11 | `mcp-server-obsidian` | npm | community, unverified | 404 |
| 12 | `mcp-server-jira` | npm | community, unverified | published once, fully unpublished — name is free |
| 13 | `mcp-server-confluence` | npm | community, unverified | published once, fully unpublished — name is free |
| 14 | `mcp-server-datadog` | npm | community, unverified | 404 |
| 15 | `mcp-server-mongodb` | npm | community, unverified | 404 |
| 16 | `mcp-server-time` | npm | community, unverified | published once, fully unpublished — name is free |
| 17 | `mcp-server-zendesk` | npm | community, unverified | 404 |
| 18 | `mcp-server-newrelic` | npm | community, unverified | 404 |
| 19 | `mcp-server-pagerduty` | npm | community, unverified | 404 |
| 20 | `mcp-server-firebase` | npm | community, unverified | 404 |
| 21 | `@linear/mcp-server` | npm | "Linear", unverified | 404 |
| 22 | `@notion/mcp-server` | npm | "Notion", unverified | 404 |
| 23 | `@github/github-mcp-server` | npm | "GitHub", unverified | 404 |
| 24 | `nginx-ui-mcp` | npm | "0xJacky", unverified | 404 |
| 25 | `@microsoft/mcp-server` | npm | "Microsoft", unverified | 404 |

Three of these (`mcp-server-jira`, `mcp-server-confluence`, `mcp-server-time`) return
HTTP 200 from the npm registry but carry **no installable version** — each was
published once (`1.0.0`) and then fully unpublished. npm frees such names for
reuse, so this is functionally identical to a 404: a squatter can `npm publish` a new
`1.0.0` under that exact name today.

---

## 3. The suspect block (`last_verified: "2026-04-15"`, `maintainer: "community"`, `repo: null`)

**Confirmed count: 26 entries**, not "roughly 26." One of the 26
(`mcp-perplexity`) was actually added later (`last_verified: "2026-04-23"`) but
carries the exact same unverified `repo: null` / `maintainer: "community"` shape
and, as shown below, the exact same red flags as the rest of the block — it is
part of the same pattern, just a later addition. The other 25 all share the literal
`last_verified: "2026-04-15"` date.

Breakdown of the 26:

| Sub-pattern | Count | Names |
|---|---:|---|
| **Security-research canary** (see below) | 3 | `mcp-server-notion`, `mcp-server-redis`, `mcp-server-supabase` |
| **Unrelated third-party "squat farm"** (see below) | 7 | `mcp-server-aws`, `mcp-server-gcp`, `mcp-server-azure`, `mcp-server-heroku`, `mcp-server-vercel`, `mcp-server-stripe`, `mcp-perplexity` |
| **Real but unrelated third-party package** | 3 | `mcp-server-docker`, `mcp-server-kubernetes`, `mcp-server-linear` |
| **Does not exist (404)** | 8 | `mcp-server-playwright`, `mcp-server-obsidian`, `mcp-server-datadog`, `mcp-server-mongodb`, `mcp-server-zendesk`, `mcp-server-newrelic`, `mcp-server-pagerduty`, `mcp-server-firebase` |
| **Claimed-then-abandoned (unpublished)** | 3 | `mcp-server-jira`, `mcp-server-confluence`, `mcp-server-time` |
| **Exists, no contradiction found** | 2 | `mcp-server-mysql`, `mcp-server-terraform` |

**26 total.** (The original brief said "one turned out to be a canary... two are
unrelated v0.0.1 packages" — the real numbers are worse: **3 canary entries**, not
one, and **7 identical-shaped v0.0.1 packages from the same unrelated account**, not
two. See below.)

### 3a. The canary (3 entries, not 1)

`mcp-server-notion`, `mcp-server-redis`, and `mcp-server-supabase` **all** resolve to
the same real npm package data:

- npm `repo`: `github.com/theinfosecguy/npx-canary`
- npm maintainer account: `node-canaries`
- npm description (verbatim): *"Security research canary — not for production use.
  Part of an authorized bug bounty research project."*
- version `0.0.2` for all three, published 2026-05-29

This is a single security researcher's canary package, published three times under
three different vendor-implied names, and the registry vouches for all three as
generic "community" entries for Notion, Redis, and Supabase respectively —
**zero relationship to any of those three companies.**

### 3b. The "hlos-ai" squat farm (7 entries, not 2)

`mcp-server-aws`, `mcp-server-gcp`, `mcp-server-azure`, `mcp-server-heroku`,
`mcp-server-vercel`, `mcp-server-stripe` (all in the labeled block) plus
`mcp-perplexity` (added 8 days later, same fingerprint) **all** resolve to:

- npm `repo`: `github.com/hlos-ai/mcp-servers` (a single monorepo)
- npm maintainer account: `ars923`
- version **`0.0.1` for all seven** — exactly the "unrelated v0.0.1 packages" pattern
  the brief warned about, but 3.5× larger than reported
- Descriptions are template-identical: `"MCP server for <vendor> integration"`
- Monthly npm downloads: 12–770 (near-zero across all seven)

This is a textbook typosquat/name-farming pattern: one unrelated account
(`hlos-ai`/`ars923`) registered a v0.0.1 stub under seven major vendor names
(AWS, GCP, Azure, Heroku, Vercel, Stripe, Perplexity) from a single templated repo.
`ars923` has **no plausible connection** to any of the seven vendors named. The
registry vouches for all seven as neutral "community" entries with `repo: null`,
hiding the fact that they all trace back to the same unrelated, low-download,
placeholder-shaped source.

### 3c. Real, unrelated third-party projects (3 entries)

`mcp-server-docker`, `mcp-server-kubernetes`, and `mcp-server-linear` are real,
independently-maintained, functioning open-source projects with meaningful adoption
(`mcp-server-kubernetes`: 71,210 monthly downloads; `mcp-server-linear`: 7,735) —
but each is a single individual's personal project (`aholsinger`/`adamdude828`,
`flux159`, `dvcrn` respectively) with **no corporate affiliation to
Docker/Kubernetes/Linear**. That may be acceptable as an honestly-labeled community
entry, but the registry's `repo: null` currently hides which project it actually is,
so a user reading the registry has no way to know this isn't official or
Docker/Linear-endorsed.

### 3d. Does not exist / abandoned (11 entries)

See the MISSING list in §2 — 8 straight 404s plus 3 unpublished-and-therefore-free
names, all from this block.

### 3e. No contradiction found (2 entries)

`mcp-server-mysql` (maintainer `lokesh14v25`, 3,780 monthly downloads, real
functioning code) and `mcp-server-terraform` (maintainer `supernova1234`, only 98
monthly downloads) exist and have no `repo` in the registry to contradict. These are
the only 2 of the 26 that show no red flag beyond "we never actually checked this."

---

## 4. Full results by bucket

### MISSING (25)

| Name | Ecosystem | Declared maintainer / verified | Evidence |
|---|---|---|---|
| `mcp-server-confluence` | npm | community / verified=False **[suspect-block]** | Published once, fully unpublished — no installable version remains; the name is free for anyone to re-register. Same practical risk as a 404. |
| `mcp-server-datadog` | npm | community / verified=False **[suspect-block]** | npm registry returned 404 — no such package exists. |
| `mcp-server-firebase` | npm | community / verified=False **[suspect-block]** | npm registry returned 404 — no such package exists. |
| `mcp-server-jira` | npm | community / verified=False **[suspect-block]** | Published once, fully unpublished — name is free. |
| `mcp-server-mongodb` | npm | community / verified=False **[suspect-block]** | npm registry returned 404 — no such package exists. |
| `mcp-server-newrelic` | npm | community / verified=False **[suspect-block]** | npm registry returned 404 — no such package exists. |
| `mcp-server-obsidian` | npm | community / verified=False **[suspect-block]** | npm registry returned 404 — no such package exists. |
| `mcp-server-pagerduty` | npm | community / verified=False **[suspect-block]** | npm registry returned 404 — no such package exists. |
| `mcp-server-playwright` | npm | community / verified=False **[suspect-block]** | npm registry returned 404 — no such package exists. |
| `mcp-server-time` | npm | community / verified=False **[suspect-block]** | Published once, fully unpublished — name is free. |
| `mcp-server-zendesk` | npm | community / verified=False **[suspect-block]** | npm registry returned 404 — no such package exists. |
| `@anthropic-ai/mcp-server-puppeteer` | npm | Anthropic / verified=True | npm registry returned 404 — no such package exists. |
| `@github/github-mcp-server` | npm | GitHub / verified=False | npm registry returned 404 — no such package exists. |
| `@linear/mcp-server` | npm | Linear / verified=False | npm registry returned 404 — no such package exists. |
| `@microsoft/mcp-server` | npm | Microsoft / verified=False | npm registry returned 404 — no such package exists. |
| `@modelcontextprotocol/server-fetch` | npm | Anthropic / verified=True | npm registry returned 404 — no such package exists (note: `mcp-server-fetch` on **PyPI** does exist and is real — this is npm-specific). |
| `@modelcontextprotocol/server-git` | npm | Anthropic / verified=True | npm registry returned 404 (note: `mcp-server-git` on **PyPI** does exist and is real — this is npm-specific). |
| `@modelcontextprotocol/server-gmail` | npm | Anthropic / verified=True | npm registry returned 404 — no such package exists. |
| `@modelcontextprotocol/server-google-drive` | npm | Anthropic / verified=True | npm registry returned 404 — no such package exists. |
| `@modelcontextprotocol/server-sentry` | npm | Anthropic / verified=True | npm registry returned 404 — no such package exists. |
| `@modelcontextprotocol/server-sequentialthinking` | npm | Anthropic / verified=True | npm registry returned 404 — likely a typo'd duplicate; the real, live package is `@modelcontextprotocol/server-sequential-thinking` (hyphenated), already a separate OK entry in this same registry. |
| `@modelcontextprotocol/server-sqlite` | npm | Anthropic / verified=True | npm registry returned 404 — no such package exists. |
| `@notion/mcp-server` | npm | Notion / verified=False | npm registry returned 404 — no such package exists. |
| `mcp-server-filesystem` | **pypi** | Anthropic / verified=True | pypi registry returned 404 — no such package exists (note: the **npm** entry with the same conceptual name, `@modelcontextprotocol/server-filesystem`, does exist and is real). |
| `nginx-ui-mcp` | npm | 0xJacky / verified=False | npm registry returned 404 — no such package exists. |

### UNCLAIMABLE_MISMATCH (18)

| Name | Ecosystem | Declared maintainer / verified | Evidence |
|---|---|---|---|
| `mcp-server-aws` | npm | community / verified=False **[suspect-block]** | Registry has `repo: null`; real npm repo is `hlos-ai/mcp-servers` (maintainer `ars923`) — no relationship to AWS. |
| `mcp-server-azure` | npm | community / verified=False **[suspect-block]** | Same `hlos-ai/mcp-servers` / `ars923` — no relationship to Microsoft Azure. |
| `mcp-server-docker` | npm | community / verified=False **[suspect-block]** | Registry has `repo: null`; real repo is `adamdude828/mcp-server-docker` (maintainer `aholsinger`) — independent project, not Docker Inc. |
| `mcp-server-gcp` | npm | community / verified=False **[suspect-block]** | Same `hlos-ai/mcp-servers` / `ars923` — no relationship to Google Cloud. |
| `mcp-server-heroku` | npm | community / verified=False **[suspect-block]** | Same `hlos-ai/mcp-servers` / `ars923` — no relationship to Heroku/Salesforce. |
| `mcp-server-kubernetes` | npm | community / verified=False **[suspect-block]** | Registry has `repo: null`; real repo is `Flux159/mcp-server-kubernetes` (maintainer `flux159`) — independent project, not CNCF/Kubernetes. |
| `mcp-server-linear` | npm | community / verified=False **[suspect-block]** | Registry has `repo: null`; real repo is `dvcrn/mcp-server-linear` (maintainer `dvcrn`) — independent project, not Linear. |
| `mcp-server-notion` | npm | community / verified=False **[suspect-block]** | Registry has `repo: null`; real repo is `theinfosecguy/npx-canary` (maintainer `node-canaries`) — security-research canary, not Notion. |
| `mcp-server-redis` | npm | community / verified=False **[suspect-block]** | Same canary as above — not Redis. |
| `mcp-server-stripe` | npm | community / verified=False **[suspect-block]** | Same `hlos-ai/mcp-servers` / `ars923` — no relationship to Stripe. |
| `mcp-server-supabase` | npm | community / verified=False **[suspect-block]** | Same canary as above — not Supabase. |
| `mcp-server-vercel` | npm | community / verified=False **[suspect-block]** | Same `hlos-ai/mcp-servers` / `ars923` — no relationship to Vercel. |
| `mcp-perplexity` | npm | community / verified=False | Same `hlos-ai/mcp-servers` / `ars923` — no relationship to Perplexity. Not in the labeled block (`last_verified: 2026-04-23`) but same signature. |
| `@azure/mcp` | npm | Microsoft / verified=False | Registry repo `Azure/azure-mcp`; real npm repo is `microsoft/mcp`. Maintainers (`azure-sdk`, `microsoft-oss-releases`, `microsoft1es`) are genuinely Microsoft — **this looks like stale data from a repo consolidation, not fraud**, but is a mismatch as declared. |
| `@stripe/agent-toolkit` | npm | Stripe / verified=False | Registry repo `stripe/agent-toolkit`; real npm repo is `stripe/ai`. Maintainer list is ~60 `*-stripe` accounts — genuinely Stripe. Same "stale repo pointer" pattern as `@azure/mcp`, not fraud. |
| `@supabase/mcp-server-supabase` | npm | Supabase / verified=False | Registry repo `supabase-community/supabase-mcp`; real npm repo is `supabase/mcp`. Maintainers `gregnr`/`mattrossman` are individual accounts (plausibility heuristic can't confirm they're Supabase staff, but the `@supabase` npm scope itself is access-controlled by Supabase) — most likely another stale-repo-pointer case, flagged here because the automated heuristic cannot independently confirm the maintainers' employer. |
| `firecrawl-mcp` | npm | Firecrawl / verified=False | Registry repo `mendableai/firecrawl-mcp-server`; real npm repo is `firecrawl/firecrawl-mcp-server`, maintained by a single account `hello_sideguide` with no visible tie to Firecrawl/Mendable. **This one reads as a genuine red flag**, not just drift — the package name is unscoped (anyone could have published it) and the single maintainer account name has no relation to "Firecrawl." |
| `gemini-mcp-tool` | npm | community / verified=False | Registry's own `repo` field points at `google-gemini/gemini-mcp-tool` (implying Google's official org) but the real npm package's repo is `jamubc/gemini-mcp-tool`, maintained by account `filecrop` — no connection to Google. **This is the most misleading entry outside the labeled block**: the registry itself asserts a Google-owned-looking repo URL for a package actually published by an unrelated individual. |

### THIN (1)

| Name | Ecosystem | Declared maintainer / verified | Evidence |
|---|---|---|---|
| `@playwright/mcp` | npm | Microsoft / verified=False | Latest version is `0.0.79` (matches the mechanical "0.0.x" placeholder rule) — **but** repo matches the registry exactly (`microsoft/playwright-mcp`), maintainers include `playwright-bot`/official Microsoft accounts, and monthly downloads are **25,988,876**. Judgment call: this is Microsoft's real, extremely widely-used package that simply hasn't crossed 1.0 in its versioning scheme yet — not a placeholder. Recommend treating this as OK on human review; flagged as THIN here only because it mechanically matches the version-number rule the task specified. |

### UNCHECKED (0)

No entry was blocked by rate-limiting or network failure severely enough to require guessing.

### OK (41)

| Name | Ecosystem | Declared maintainer / verified | Evidence |
|---|---|---|---|
| `mcp-server-mysql` | npm | community / verified=False **[suspect-block]** | Exists (v1.0.42, 3,780 monthly downloads); registry `repo: null`, package declares no repo either — nothing to contradict. |
| `mcp-server-terraform` | npm | community / verified=False **[suspect-block]** | Exists (v0.1.0, only 98 monthly downloads — worth a second look, but no positive contradiction found); registry `repo: null`, package declares no repo either. |
| `@agentdeskai/browser-tools-mcp` | npm | AgentDesk / verified=False | v2.0.2, repo confirmed matching registry. |
| `@browserbasehq/mcp` | npm | Browserbase / verified=False | v3.0.0, repo confirmed matching registry. |
| `@cloudflare/mcp-server-cloudflare` | npm | Cloudflare / verified=False | v0.2.0; npm metadata has no repo field, registry's repo unconfirmed but not contradicted; maintainer list includes 30+ `cf-*`/Cloudflare-branded accounts. |
| `@mcpjam/inspector` | npm | MCPJam / verified=False | v2.43.0, repo confirmed matching registry. |
| `@mintlify/mcp` | npm | Mintlify / verified=False | v1.1.216; npm metadata has no repo field, unconfirmed but not contradicted; maintainers are `*-mintlify` accounts. |
| `@modelcontextprotocol/inspector` | npm | Anthropic / verified=True | v2.3.0, repo confirmed matching registry. |
| `@modelcontextprotocol/sdk` | npm | Anthropic / verified=True | v1.30.0, repo confirmed matching registry. 204M monthly downloads. |
| `@modelcontextprotocol/server-aws-kb-retrieval` | npm | Anthropic / verified=True | v0.6.2; npm metadata has no repo field for this release — unconfirmed but not contradicted. |
| `@modelcontextprotocol/server-brave-search` | npm | Anthropic / verified=True | v0.6.2; repo unconfirmed but not contradicted. |
| `@modelcontextprotocol/server-everart` | npm | Anthropic / verified=True | v0.6.2; repo unconfirmed but not contradicted. |
| `@modelcontextprotocol/server-everything` | npm | Anthropic / verified=True | v2026.8.18, repo confirmed matching registry. |
| `@modelcontextprotocol/server-filesystem` | npm | Anthropic / verified=True | v2026.7.10, repo confirmed matching registry. 2,006,104 monthly downloads. |
| `@modelcontextprotocol/server-gdrive` | npm | Anthropic / verified=True | v2025.1.14; repo unconfirmed but not contradicted. |
| `@modelcontextprotocol/server-github` | npm | Anthropic / verified=True | v2025.4.8; repo unconfirmed but not contradicted. |
| `@modelcontextprotocol/server-gitlab` | npm | Anthropic / verified=True | v2025.4.25; repo unconfirmed but not contradicted. |
| `@modelcontextprotocol/server-google-maps` | npm | Anthropic / verified=True | v0.6.2; repo unconfirmed but not contradicted. |
| `@modelcontextprotocol/server-memory` | npm | Anthropic / verified=True | v2026.7.4, repo confirmed matching registry. |
| `@modelcontextprotocol/server-postgres` | npm | Anthropic / verified=True | v0.6.2; repo unconfirmed but not contradicted. |
| `@modelcontextprotocol/server-puppeteer` | npm | Anthropic / verified=True | v2025.5.12; repo unconfirmed but not contradicted. |
| `@modelcontextprotocol/server-redis` | npm | Anthropic / verified=True | v2025.4.25; repo unconfirmed but not contradicted. |
| `@modelcontextprotocol/server-sequential-thinking` | npm | Anthropic / verified=True | v2026.7.4, repo confirmed matching registry. This is the real package — see the MISSING entry for its unhyphenated, non-existent twin. |
| `@modelcontextprotocol/server-slack` | npm | Anthropic / verified=True | v2025.4.25; repo unconfirmed but not contradicted. |
| `@neondatabase/mcp-server-neon` | npm | Neon / verified=False | v0.6.5; repo unconfirmed but not contradicted; maintainers include `neonteam`. |
| `@notionhq/notion-mcp-server` | npm | community / verified=False | v2.5.1, repo confirmed matching registry (note: separate `@notion/mcp-server` entry above is a 404 — do not confuse the two). |
| `@palisadeemail/mcp` | npm | Palisade / verified=False | v0.1.2, repo confirmed matching registry. |
| `@shopify/dev-mcp` | npm | Shopify / verified=False | v1.14.5; repo unconfirmed but not contradicted; maintainers include `shopify-admin`/`shopify-dep`. |
| `@upstash/context7-mcp` | npm | Upstash / verified=False | v4.0.2, repo confirmed matching registry. |
| `docpull` | pypi | Raintree Technology / verified=False | v6.5.0, repo confirmed matching registry. |
| `exa-mcp-server` | npm | Exa / verified=False | v3.4.1, repo confirmed matching registry. |
| `flowise` | npm | FlowiseAI / verified=False | v3.1.4; repo unconfirmed but not contradicted. |
| `langchain-mcp-adapters` | pypi | LangChain / verified=False | v0.3.2, repo confirmed matching registry. |
| `mcp` | pypi | Anthropic / verified=True | v2.0.0, repo confirmed matching registry (`Repository` project URL — see §6 methodology note on the "Homepage vs Repository" bug this audit found and fixed). |
| `mcp-atlassian` | pypi | community / verified=False | v0.23.1; repo unconfirmed but not contradicted; known CVE-2026-27826 already tracked separately in this entry. |
| `mcp-server-fetch` | pypi | Anthropic / verified=True | v2026.8.18, repo confirmed matching registry (subdirectory deep-link into the same monorepo). |
| `mcp-server-git` | pypi | Anthropic / verified=True | v2026.8.18, repo confirmed matching registry (subdirectory deep-link into the same monorepo). |
| `mcp-server-postgres` | pypi | Anthropic / verified=True | **Technically OK per the mechanical rule (package exists, no `repo` to contradict) — but see §5, this is a manual override candidate.** |
| `mcp-server-qdrant` | pypi | Qdrant / verified=False | v0.8.1; repo unconfirmed but not contradicted. |
| `screenpipe-mcp` | npm | screenpipe / verified=True | v0.19.1; repo unconfirmed but not contradicted. |
| `tavily-mcp` | npm | Tavily / verified=False | v0.2.22, repo confirmed matching registry. |

---

## 5. `mcp-server-postgres` (PyPI) — a second `verified: true` entry that isn't Anthropic's

This entry is bucketed OK by the mechanical rule (package exists; registry has a
`repo` but the package declares none, so there's nothing to *contradict*) — but it
should not be trusted:

- Real PyPI summary field (verbatim): **`"Add your description here"`** — the
  literal unedited placeholder from a Python project template.
- Real author: `truskovskiyk <truskovskiyk@gmail.com>` — a personal Gmail address,
  not `Anthropic, PBC.` (compare with the genuinely-Anthropic `mcp-server-git` and
  `mcp-server-fetch` PyPI entries, both of which correctly show
  `author: "Anthropic, PBC."`).
- Version `0.1.0`, no maintainers, no project URLs at all.

This is functionally the same failure mode as the two 0.0.1 "hlos-ai" packages, just
outside the labeled block, on PyPI instead of npm, and marked `verified: true`
instead of unverified `community`. **Recommend treating this as a manual-override
UNCLAIMABLE_MISMATCH-equivalent, not OK**, pending human remediation.

---

## 6. Is this confined to the labeled block? No — evidence for systemic scope

The block (§3) accounts for 26 of the 85 entries. Excluding it entirely, the
remaining 59 entries still contain:

- **14 MISSING** (8 `verified: true` Anthropic npm 404s, 1 `verified: true`
  Anthropic PyPI 404, `@linear/mcp-server`, `@notion/mcp-server`,
  `@github/github-mcp-server`, `nginx-ui-mcp`, `@microsoft/mcp-server`)
- **6 UNCLAIMABLE_MISMATCH** (`mcp-perplexity`, `@azure/mcp`, `@stripe/agent-toolkit`,
  `@supabase/mcp-server-supabase`, `firecrawl-mcp`, `gemini-mcp-tool`)
- **1 THIN** (`@playwright/mcp`, judged low-risk on review)
- **1 manual-override candidate** (`mcp-server-postgres`, §5)

That is **22 of 59 non-block entries (37%)** with a finding, versus **24 of 26
block entries (92%)**. The block is denser with problems, but the non-block rate
is still far from zero, and — critically — **every one of the `verified: true`
Anthropic-npm 404s is outside the labeled block** (the block is entirely
`verified: false`). A CI guard that only distrusts `verified: false, repo: null`
entries would have missed all 9 of the `verified: true` MISSING findings, plus
`mcp-server-postgres`. **The gap is a whole-file problem, not a one-batch problem,
and `verified: true` is not a reliable signal that an entry was actually checked.**

---

## 7. Step 5 — proposed CI guard, tested against the current file

**Proposed invariant:** every registry entry must either (a) declare a non-null
`repo`, or (b) be explicitly, deliberately acknowledged as unverifiable.

**Checked against the current file before implementing anything:** 26 of 85
entries (31%) currently have `repo: null` (see §3/§6). A hard-failing test on "every
entry must have `repo != null`" would turn the suite red today for reasons
unrelated to any contributor's change — exactly the outcome the task instructions
say to avoid.

**Decision: implemented a softened, grandfathered version, not a hard rule and not
a new JSON schema field.**

- No new field was added to the registry schema. Per the DO-NOT constraints, a new
  field (e.g. `repo_unavailable_confirmed: true`) is *proposed* here as the ideal
  longer-term fix — it would force a human to affirmatively tick a box acknowledging
  "I looked and there is no repo," rather than silently defaulting — but implementing
  it is a schema change that touches `RegistryEntry` (Pydantic model),
  `docs/registry-contributions.md`, and every existing `repo: null` entry, which is
  beyond the "test only" scope of this task and is left as a recommendation for the
  human maintainer.
- Instead, `tests/test_registry.py::TestRepoNullRequiresDeliberateAcknowledgement`
  freezes the **current** 26 `repo: null` names in an explicit, named, commented
  allowlist (`_LEGACY_REPO_NULL_ALLOWLIST`). Behavior:
  - Adding a **new** entry with `repo: null` that is not in the allowlist **fails
    the build** — this is the part that "would have caught this batch at review
    time": a PR adding 26 new names to a hardcoded allowlist inside a test file is a
    conspicuous, reviewable diff that invites the question "why are all of these
    unverifiable?", instead of a silent JSON addition that passes CI without comment.
  - A companion test fails if a name is removed from the registry (or gets a real
    `repo`) but is still listed in the allowlist — so the allowlist can't silently
    rot into a set of already-fixed names shielding new bad ones.
  - Does **not** retroactively fix or fail on the 26 grandfathered entries — a human
    must still triage them using §3/§4 of this report.
- This test does not require network access (keeps the "core scanning works fully
  offline" invariant intact) and does not touch `registry/known-servers.json`.

**Result of implementing and running the full suite** (see §8): the new test
passes cleanly against the current file (26/26 names match exactly, no stale
entries), and the full suite remains green — **implemented as-is, not left as a
proposal only**.

---

## 8. Test suite run — actual results

```
$ uv run --extra dev --extra attestation pytest -q
2857 passed, 1 skipped, 74 warnings in 87.76s
```

The two new tests added in `tests/test_registry.py`
(`TestRepoNullRequiresDeliberateAcknowledgement::test_new_repo_null_entries_must_join_the_allowlist`,
`TestRepoNullRequiresDeliberateAcknowledgement::test_allowlist_does_not_contain_stale_names`)
both pass — confirmed individually:

```
$ uv run pytest tests/test_registry.py -v -k RepoNull
tests/test_registry.py::TestRepoNullRequiresDeliberateAcknowledgement::test_new_repo_null_entries_must_join_the_allowlist PASSED
tests/test_registry.py::TestRepoNullRequiresDeliberateAcknowledgement::test_allowlist_does_not_contain_stale_names PASSED
2 passed, 67 deselected in 0.20s
```

No existing test was broken by adding them (2857 passed / 1 skipped is the
same count as the pre-change baseline plus these 2 new tests). The 1 skip is
pre-existing and unrelated (an optional-dependency-gated test, not touched by
this change).

---

## 9. Recommendations for the human maintainer (not performed by this task)

1. **Remove or replace the 25 MISSING entries** (§2) — they are actively
   exploitable today. Highest priority: the 9 `verified: true` Anthropic ones,
   since `verified: true` carries the most trust weight in every downstream
   consumer (scan suppression, `vet`, badges).
2. **Remove the 3 canary entries** (`mcp-server-notion`, `mcp-server-redis`,
   `mcp-server-supabase`) and the **7 "hlos-ai" squat-farm entries**
   (`mcp-server-aws/gcp/azure/heroku/vercel/stripe`, `mcp-perplexity`) — these
   actively mislead users into trusting an unrelated third party's near-zero-download
   stub as if it were a "community"-reviewed Notion/Redis/Supabase/AWS/etc. server.
3. **Fix stale repo pointers** for `@azure/mcp`, `@stripe/agent-toolkit`, and
   `@supabase/mcp-server-supabase` — genuinely legitimate packages, just pointing at
   an old repo path.
4. **Investigate `firecrawl-mcp` and `gemini-mcp-tool`** more closely — both show
   the same "vendor-implied name, unrelated single maintainer" shape as the block,
   but were added outside it with an explicit named maintainer, which is more
   misleading, not less.
5. **Fix or remove `mcp-server-postgres` (PyPI)** — a second Anthropic-attributed,
   `verified: true` entry that is not Anthropic's package (§5).
6. **Remove the duplicate `@modelcontextprotocol/server-sequentialthinking`** (no
   hyphen) — dead weight vouching for a name that was seemingly never real; the
   correct hyphenated package is a separate, live entry.
7. Longer-term: consider the `repo_unavailable_confirmed` schema field proposed in
   §7 so `verified: false, repo: null` becomes an explicit, auditable decision
   instead of the default shape of "we didn't get around to checking."
8. Re-run `python scripts/audit_registry.py` periodically (e.g. quarterly, or on
   every registry PR in CI) — packages get unpublished, renamed, or handed off, and
   this file goes stale exactly the way the `@modelcontextprotocol/server-*` npm
   entries already have.

---

## 10. Methodology, caveats, and how to reproduce

- **Script:** `scripts/audit_registry.py` (new, meant to be committed and re-run;
  not committed as part of this task per instructions).
- **Reproduce:** `python scripts/audit_registry.py` from the repo root. Add
  `--refresh` to bypass the local cache. Raw per-entry JSON (not committed —
  gitignored) is written to `.registry_audit_raw.json`; a local cache
  `.registry_audit_cache.json` (also gitignored) avoids re-hitting the registries on
  repeated runs within 6 hours.
- **npm checks:** `GET https://registry.npmjs.org/<name>` (scoped names
  URL-encoded), plus one extra call to
  `https://api.npmjs.org/downloads/point/last-month/<name>` for a download-count
  THIN signal (this is a *monthly* figure, not weekly — the npm registry API has no
  native weekly endpoint).
- **PyPI checks:** `GET https://pypi.org/pypi/<name>/json`. No 403/429 was
  encountered during this run; had one occurred, the script marks the entry
  UNCHECKED rather than guessing (see `--refresh` retry/backoff logic).
- **Politeness:** sequential requests only, ~0.4s apart, descriptive User-Agent
  identifying the script and this repository, one retry with backoff on 429, then
  give up and mark UNCHECKED (never loops forever).
- **Repo URL comparison** tolerates: `git+`/`git://`/`ssh://git@`/scp-style prefixes,
  `http` vs `https`, trailing `.git`/slash, github.com case, and a package's repo
  URL being a deep link into a subdirectory of the registry's repo (common for
  npm/PyPI monorepos like `modelcontextprotocol/servers`).
- **Bugs found and fixed while building this script** (documented here since they
  affected which entries first looked like false mismatches):
  1. PyPI's `project_urls` can list both `"Homepage"` and `"Repository"` with
     different values (e.g. the `mcp` SDK: homepage is `modelcontextprotocol.io`,
     repository is the actual GitHub URL). An earlier version of this script treated
     any key containing "homepage" as equally good evidence as "repository"/"source",
     which produced a false mismatch for the `mcp` package. Fixed by tiering the key
     hints so an explicit repository/source link always wins.
  2. An npm name that was published once and then fully unpublished returns HTTP 200
     with empty `dist-tags` — a naive "status == 200 → exists" check misreports these
     as legitimate live packages. Fixed by detecting the `time.unpublished` marker
     and treating such names as MISSING (see §2's three unpublished entries).
- **Known limitation — no live GitHub API check for "monorepo of templated
  packages."** The task's THIN criteria mention a repo containing "many
  same-shaped/templated packages" as a signal. This script does not call the GitHub
  API to enumerate a repo's contents (would need authentication to avoid the 60
  req/hr unauthenticated rate limit, and is out of scope for an offline-first
  project). Where this pattern was found, it was inferred from identical repo URLs,
  identical maintainer accounts, and near-identical descriptions across multiple
  registry entries (see §3b, the "hlos-ai" farm) — not from a repo listing.
- **This audit is a snapshot.** npm/PyPI package state can change at any time
  (new versions, unpublishing, ownership transfer). Re-run before making removal
  decisions if significant time has passed.
