<!--
Template used by .github/workflows/release.yml to compose the body of every
v*.*.* GitHub Release.  The double-curly VERSION token below is replaced at
release time with the pushed git tag (set from $GITHUB_REF_NAME, e.g. v0.3.4)
via the "Compose release notes from template" step.

Keep this file in sync with README.md copy — CI does not verify it.
If the feature list or test count changes in README.md, update here too.
-->
## mcp-audit {{VERSION}} — Signed Advisory Feed (Experimental), Registry Cleanup, and a SARIF Path-Leak Fix

Security scanner for MCP (Model Context Protocol) server configurations.
Detects prompt injection, supply chain risks, credential exposure, toxic flow
combinations, transport vulnerabilities, and more — across Claude Desktop,
Cursor, VS Code, Zed, and any MCP-compatible host.

---

### Security — read this first

**If you run `mcp-audit scan --format sarif` in CI, upload the result to GitHub Code
Scanning, push to Nucleus, or run `mcp-audit snapshot`, this release fixes an
information-disclosure bug you were exposed to.**

- **Absolute path leak, fixed.** SARIF, the Nucleus FlexConnect push, and the
  snapshot export all copied this scanning host's absolute config path — which
  includes your home directory and OS username — verbatim into output meant to leave
  the machine. If that SARIF file went to GitHub Code Scanning, your home directory
  and username were published to GitHub, visible to anyone with read access to the
  repo. No credentials, secrets, or file contents were exposed — only the path string
  and the username it encodes. **Our assessment: low-severity information
  disclosure**, disclosed here rather than as a CVE/GHSA — see `CHANGELOG.md` for the
  full reasoning. Paths are now redacted to a relative form at all three sinks.
- **SARIF annotations, fixed.** The same absolute URI is also why `mcp-audit`'s SARIF
  output has never produced inline PR annotations in GitHub Code Scanning — GitHub's
  `upload-sarif` action matches results to files by reading `artifactLocation.uri`
  literally, and an absolute path never matches a repo-relative file. If you assumed
  the GitHub Action didn't support annotations, it does now.

Full detail, including exactly which fields were affected and what stays
intentionally unredacted (terminal output, the HTML dashboard): `CHANGELOG.md`.

---

### Highlights

- **`mcp-audit advise` — a signed, OSV-compatible advisory feed for MCP packages.
  EXPERIMENTAL.** Turns scan findings into OSV `schema_version` 1.6.0 records and
  publishes a verifiable feed. The record format is **not yet stable** and no
  mcp-audit-operated signing key exists yet — see "What's new" below.
- **Registry cleanup: 85 → 50 entries.** A full live audit against real npm/PyPI
  data found 35 entries — 9 of them `verified: true` and misattributed to Anthropic —
  that pointed at packages that don't exist, security-research canaries, or
  unrelated third-party placeholder stubs. All removed; a further 9 corrected in
  place. See "What's fixed" below.
- **The SARIF path leak and broken annotations, above.**

---

### What's new

**`mcp-audit advise <target>` / `mcp-audit feed verify <dir>` — signed advisory feed (EXPERIMENTAL)**

There is no CVE/OSV/NVD equivalent for MCP servers today. `mcp-audit advise` turns
scan findings into stock OSV `schema_version` 1.6.0 advisory records — deterministic,
content-derived `x_MCPSA-<12hex>` IDs, never a timestamp — and publishes them as a
signed, verifiable feed (`advisories/<id>.json`, `index.json`, an
osv-scanner-consumable `osv/all.json`/`.zip`). MCP-specific fields live under
`affected[].database_specific` so a generic OSV parser needs to know nothing about
MCP to consume it. `mcp-audit feed verify <dir>` checks a feed's integrity and
signatures.

**This is marked experimental on purpose.** The record format may still change
before it stabilizes, and `--sign` requires you to bring your own
`--key`/`$MCP_AUDIT_SIGNING_KEY` — there is no mcp-audit-operated project key yet.
Don't build automation against today's exact record shape. See
[`docs/advisory-feed.md`](docs/advisory-feed.md).

---

**Registry: 3 new community submissions**

`screenpipe-mcp` (npm, verified), `@palisadeemail/mcp` (npm — submitted unverified,
independently verified to `true` before this release shipped, see "What's fixed"),
and `docpull` (PyPI, unverified). Filed by
[@louis030195](https://github.com/louis030195)
([#39](https://github.com/adudley78/mcp-audit/issues/39)),
[@samuelchenardlovesboards](https://github.com/samuelchenardlovesboards)
([#38](https://github.com/adudley78/mcp-audit/issues/38)), and
[@zacharyr0th](https://github.com/zacharyr0th)
([#35](https://github.com/adudley78/mcp-audit/issues/35)) via the
registry-submission issue template. Every entry — verified or not — improves
typosquat detection for everyone running the scanner. See
[`docs/registry-contributions.md`](docs/registry-contributions.md) to submit your
own.

---

### What's fixed

**Registry: removed or corrected 35 of 85 entries following a full live audit**
against the real npm/PyPI registries. 25 entries pointed at packages that don't
exist in their declared ecosystem at all — 9 of them `verified: true` and
attributed to Anthropic — plus a security-research canary and an unrelated third
party's placeholder-stub "farm" registered under major-vendor-implied names. All 35
removed. A further 9 real-but-misattributed entries corrected in place and demoted
to `verified: false`. `entry_count`: **85 → 50**. Full detail:
`registry-audit-2026-08-18.md` and `CHANGELOG.md`.

**Registry: duplicate-name and ecosystem-blind lookup bugs closed.** A same-named npm
canary package and a legitimate PyPI entry could previously collide and resolve
inconsistently depending on file order; the registry now raises at load time on any
duplicate name instead of silently picking one. npm-scoped lookups (`is_known_npm`,
`get_npm`, `find_closest_npm`) now mirror the PyPI-scoped ones that already existed,
and `TRANSPORT-003` severity tiering is now ecosystem-scoped too.

**Advisory feed: pre-release security review fixes**, applied before this feature
ever shipped in a tagged release — RFC 8785 float canonicalization conformance,
advisory-ID stability (no year-boundary component), and gaps in the
non-advisory-finding exclusion list. Full detail in `CHANGELOG.md`.

**Registry: `@palisadeemail/mcp` verified `false → true`** on independently
re-checked evidence (npm's own publishing account is on the package's own domain;
the submitter demonstrated repo write access via a same-repo merged PR). This also
prompted a rewrite of the registry contribution docs' verification standard, which
previously didn't test the submitter at all.

---

### What changed

No breaking changes to existing scans, configs, baselines, policies, or rule files.
`Finding` and `ServerConfig` objects are never mutated by the new path-redaction
logic — it applies only at serialization time in SARIF, Nucleus, and snapshot output.
Terminal output, the HTML dashboard, and plain JSON output (`--format json` /
`-o file.json`) are unaffected by design; see `CHANGELOG.md` for why.

---

### Install

```bash
pip install --upgrade mcp-audit-scanner   # PyPI — CLI command: mcp-audit
```

Or grab a pre-built binary from **Assets** below (no Python required):

| Platform | Binary |
|---|---|
| macOS (Apple Silicon) | `mcp-audit-darwin-arm64` |
| macOS (Intel) | `mcp-audit-darwin-x86_64` |
| Linux x86-64 | `mcp-audit-linux-x86_64` |
| Windows x86-64 | `mcp-audit-windows-x86_64.exe` |

### Use as a GitHub Action

```yaml
- uses: adudley78/mcp-audit@{{VERSION}}
  with:
    severity-threshold: high
```

Full input/output reference in [`docs/github-action.md`](docs/github-action.md).

Pin to a specific release tag (as shown) until a `v1.0.0` ships;
after v1, `@v1` will track the latest 1.x release automatically.

If you upload SARIF to Code Scanning, this release is the one where inline PR
annotations start working — see "Security" above.

---

### Upgrading

No action needed. `pip install --upgrade mcp-audit-scanner` or download the new binary
from the release assets. If you have automation parsing SARIF, Nucleus, or snapshot
output for absolute paths, re-check it — those paths are now relative.

---

### Detection coverage

- **Prompt injection / tool poisoning** — 11 patterns, Unicode homoglyph-aware, depth-50 recursion
- **Credential exposure** — 9 patterns (AWS, GitHub, Stripe, Slack, and more)
- **Supply chain risk** — npm/PyPI provenance, Sigstore signature verification (`--verify-signatures`), SBOM + OSV.dev CVE scan (`--check-vulns`)
- **Toxic flow detection** — dangerous server *combinations* (e.g. database + web fetch)
- **SAST** — 89 rules across Python (46) and TypeScript (43)
- **Transport security** — insecure bindings, wildcard hosts, unverified TLS

### Integrations

- SARIF → GitHub Code Scanning (schema-validated, deduplication-safe, and — as of
  this release — annotations that actually attach)
- Nucleus Security FlexConnect (`mcp-audit push-nucleus`)
- Baseline diffing for CI regression gates (`mcp-audit baseline`)
- HTML dashboard — self-contained, no CDN dependencies
- VS Code / Cursor extension — inline squiggles and command palette
- Signed OSV advisory feed (`mcp-audit advise`) — **experimental**, see above

### Validated against

- 6 real-world exploit fixtures (Invariant Labs SSH exfiltration, CrowdStrike `add_numbers`, XML injection, cloud credential theft, behavioral override)
- 22-server false-positive benchmark — 0% poisoning FP rate on legitimate servers
- CVSS + OWASP MCP Top 10 severity mappings on every finding ID

**2,923 tests · Apache 2.0 · macOS · Linux · Windows**

---

### Full changelog

See [`CHANGELOG.md`](CHANGELOG.md).
