<!--
Evergreen GitHub Release body. Per-release prose does NOT live here.

.github/workflows/release.yml runs scripts/compose_release_notes.py, which:
  - replaces the VERSION placeholder with the pushed tag (e.g. v0.15.0)
  - splices the CHANGELOG.md section ## [X.Y.Z] at the CHANGELOG_SECTION marker
  - fails the release if that heading is missing or any placeholder survives

Keep Install / coverage / integrations in sync with README.md copy — CI
does not verify the prose. Test counts are patched by
scripts/update_test_count.py.

Do not put Highlights, a What's-new block, or a security banner in this
file. Those belong under the matching CHANGELOG heading (### Security is
the banner: it renders first in the spliced section). A forgotten
CHANGELOG promotion fails the tag; it does not republish the last
release's notes.
-->
## mcp-audit {{VERSION}}

Security scanner for MCP (Model Context Protocol) server configurations.
Detects prompt injection, supply chain risks, credential exposure, toxic flow
combinations, transport vulnerabilities, and more — across Claude Desktop,
Cursor, VS Code, Zed, and any MCP-compatible host.

---

{{CHANGELOG_SECTION}}

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

Each GitHub Release also attaches a CycloneDX SBOM per binary
(`mcp-audit-<platform>.cdx.json`) plus `mcp-audit-scanner-wheel.cdx.json`.

### Use as a GitHub Action

```yaml
- uses: adudley78/mcp-audit@{{VERSION}}
  with:
    severity-threshold: high
```

Full input/output reference in [`docs/github-action.md`](docs/github-action.md).

Pin to a specific release tag (as shown) until a `v1.0.0` ships;
after v1, `@v1` will track the latest 1.x release automatically.

---

### Upgrading

`pip install --upgrade mcp-audit-scanner` or download the new binary from
the release assets. Anything you must do for this version is in the
changelog section above.

---

### Detection coverage

- **Prompt injection / tool poisoning** — 11 patterns, Unicode homoglyph-aware, depth-50 recursion
- **Credential exposure** — 9 patterns (AWS, GitHub, Stripe, Slack, and more)
- **Supply chain risk** — npm/PyPI provenance, Sigstore signature verification (`--verify-signatures`), SBOM + OSV.dev CVE scan (`--check-vulns`)
- **Toxic flow detection** — dangerous server *combinations* (e.g. database + web fetch)
- **SAST** — 89 rules across Python (46) and TypeScript (43)
- **Transport security** — insecure bindings, wildcard hosts, unverified TLS

### Integrations

- SARIF → GitHub Code Scanning (schema-validated, deduplication-safe)
- Nucleus Security FlexConnect (`mcp-audit push-nucleus`)
- Baseline diffing for CI regression gates (`mcp-audit baseline`)
- HTML dashboard — self-contained, no CDN dependencies
- VS Code / Cursor extension — inline squiggles and command palette
- Signed OSV advisory feed (`mcp-audit advise`) — experimental until a project signing key ships

### Validated against

- 6 real-world exploit fixtures (Invariant Labs SSH exfiltration, CrowdStrike `add_numbers`, XML injection, cloud credential theft, behavioral override)
- 22-server false-positive benchmark — 0% poisoning FP rate on legitimate servers
- CVSS + OWASP MCP Top 10 severity mappings on every finding ID

**2,979 tests · Apache 2.0 · macOS · Linux · Windows**

---

### Full changelog

See [`CHANGELOG.md`](CHANGELOG.md).
