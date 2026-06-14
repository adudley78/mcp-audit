<!--
Template used by .github/workflows/release.yml to compose the body of every
v*.*.* GitHub Release.  The double-curly VERSION token below is replaced at
release time with the pushed git tag (set from $GITHUB_REF_NAME, e.g. v0.3.4)
via the "Compose release notes from template" step.

Keep this file in sync with README.md copy — CI does not verify it.
If the feature list or test count changes in README.md, update here too.
-->
## mcp-audit {{VERSION}} — IDE Extension, Automated Fixes, Compliance PDF

Security scanner for MCP (Model Context Protocol) server configurations.
Detects prompt injection, supply chain risks, credential exposure, toxic flow
combinations, transport vulnerabilities, and more — across Claude Desktop,
Cursor, VS Code, Zed, and any MCP-compatible host.

---

### Highlights

- **Security findings now appear as squiggles in VS Code and Cursor** — before you run a single command.
- **`mcp-audit fix` writes the fixes for you.** Dry-run by default. One flag to apply them.
- **`mcp-audit check --report pdf` produces an auditable compliance report** — grade, OWASP mapping, chain-of-custody hash. Something you can hand to a CISO.

---

### What's new

**VS Code / Cursor extension — inline diagnostics as you type**

Open a Claude, Cursor, or any MCP config file and red/yellow underlines appear on the
lines with problems. Hover over one to see the finding title, the evidence from your
config, and the remediation step. No terminal required to know something is wrong.

The status bar shows your current grade and finding count at a glance. The command
palette adds three commands: scan the current file, scan the workspace, and fix the
current file.

Install via the Open VSX Registry if you're on Cursor. For VS Code, install manually
from the `.vsix` file available at the `mcp-audit-vscode` releases page (VS Code
Marketplace listing is in progress). See `docs/ide-extension.md`.

The extension shells out to the `mcp-audit` binary. No detection logic lives in
TypeScript. The CLI is the source of truth.

---

**`mcp-audit fix` — apply safe remediations to your config file**

Run it and you get a unified diff showing proposed changes. Nothing is modified. Add
`--apply` and the changes are written atomically, with a `.bak` backup of the
original created first.

Three fix types ship in {{VERSION}}:

- **Credential redaction** (CRED-001, CRED-002): replaces plaintext secret values
  with `${ENV_KEY_NAME}` placeholders. Idempotent — skips values already using the
  `${...}` syntax.
- **Transport upgrade** (TRANSPORT-001): rewrites `http://` server URLs to `https://`.
  Idempotent — skips URLs already on HTTPS.
- **Package pinning** (SC-001, SC-002): replaces a typosquatted package name with the
  verified closest match from the known-server registry. Warns (non-blocking) if the
  replacement is not a registry-known entry.

`--fix-type` restricts which strategies run. `--input <scan.json>` skips re-scanning
and reads findings from an existing JSON file. `--offline` suppresses network calls
and skips pinning while credential and transport fixes still apply.

See [`docs/fix.md`](docs/fix.md).

---

**`mcp-audit check --report pdf` — PDF compliance report**

`mcp-audit check --report pdf --output-file report.pdf` produces a Letter-size PDF
you can include in an audit response or hand directly to a CISO without a terminal
explanation.

The report contains: a color-coded grade header (A/B green, C amber, D/F red), an
executive summary with per-severity counts, a paginated findings table with OWASP MCP
Top 10 category and remediation hint for each finding, and a SHA-256 content hash on
the last page. The hash covers the `ScanResult` JSON, so it is reproducible from a
scan export alone and does not change with re-rendering.

`--org "Name"` sets the organisation name in the header. Falls back to the registered
org from `mcp-audit register`, then "Not specified."

`mcp-audit scan --report pdf` is also supported for full-pipeline scans.

See [`docs/compliance-report.md`](docs/compliance-report.md).

---

**`mcp-audit register` — opt-in identification**

Developers and security engineers can now identify their org to receive weekly
new-rule notifications and an optional follow-up when their scan grade drops to C or
below.

Registration is entirely voluntary. An unregistered user sees no behaviour change and
no network traffic. The initial registration POST sends name, org, email, version,
grade, and follow-up preference. Nothing else. Subsequent pings from `mcp-audit check`
send version and grade only — no PII.

`mcp-audit register --status` shows current registration. `--clear` removes it and
stops all pings. If the registration endpoint is unreachable, the scan completes
normally with a dim one-liner at the bottom.

See [`docs/privacy.md`](docs/privacy.md) for the plain-English privacy policy.

---

**CVE registry additions**

Two entries added to `registry/known-servers.json` before this release shipped:

| CVE | Package | CVSS | Summary |
|-----|---------|------|---------|
| CVE-2026-33032 | nginx-ui-mcp | 9.8 | Unauthenticated RCE via nginx-ui admin API — do not expose publicly |
| CVE-2026-26118 | @microsoft/mcp-server | 8.1 | Tool hijacking via crafted tool description |

Users running `mcp-audit update-registry` will receive these entries immediately.

---

### What changed

No breaking changes. All existing scans, configs, baselines, policies, and rule files
carry forward without modification.

`RegistryEntry` in `registry/loader.py` gains an optional `known_vulns: list[dict]`
field (default `[]`). This is additive — existing registry entries without the field
are unaffected.

---

### Fixed

- `tests/test_network_policy.py`: fixed `click.exceptions.Exit` import that broke test
  collection when `typer >= 0.26` vendored Click internally rather than installing it
  as a standalone package. Changed to `typer.Exit` throughout.
- `registration/client.py`: suppression annotations now include both `# noqa: S310`
  (Ruff) and `# nosec B310` (Bandit) so both linters suppress cleanly.

---

### Security

| Advisory | What it is | Fix |
|----------|-----------|-----|
| CVE-2026-45409 | `idna` < 3.15: quadratic DoS bypass in `idna.encode()`. Surfaced as a direct dependency via the `[mcp]` extra path. | Bumped `idna` floor to `>=3.15` |
| CVE-2026-24408 | `sigstore` < 4.2.0 in the optional `[attestation]` extra. Does not affect the core runtime or any user who has not explicitly installed the attestation extra. | Bumped `sigstore` floor to `>=4.2.0` in the `[attestation]` extra |

SHA-pinning hardening: all 14 GitHub Actions workflow files now pin third-party actions
to full 40-character commit SHAs, preventing supply-chain substitution attacks. Thanks
to [@jsandov](https://github.com/jsandov) for the contribution, our first external PR.

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

---

### Upgrading

No action needed. `pip install --upgrade mcp-audit-scanner` or download the new binary
from the release assets.

If you use the VS Code / Cursor extension, download `mcp-audit-0.1.1.vsix` from the
`mcp-audit-vscode` releases page and install via "Extensions: Install from VSIX."

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

### Validated against

- 6 real-world exploit fixtures (Invariant Labs SSH exfiltration, CrowdStrike `add_numbers`, XML injection, cloud credential theft, behavioral override)
- 22-server false-positive benchmark — 0% poisoning FP rate on legitimate servers
- CVSS + OWASP MCP Top 10 severity mappings on every finding ID

**2,484 tests · Apache 2.0 · macOS · Linux · Windows**

---

### Full changelog

See [`CHANGELOG.md`](CHANGELOG.md).
