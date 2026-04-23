# Supply Chain Attestation

mcp-audit provides a layered approach to supply chain security for MCP servers. This document covers Layer 1: hash-based integrity verification.

---

## Why Supply Chain Attestation Matters

MCP servers are executed with broad access to your machine — filesystems, databases, APIs, shells. A compromised package tarball can introduce malicious behaviour indistinguishable from a legitimate server. Real-world precedents include:

- **Postmark BCC attack** — a package maintainer's npm credentials were stolen; the attacker published a backdoored version of a widely-used library under the legitimate name.
- **Smithery breach** — the MCP server registry was compromised, causing hundreds of server configs to reference attacker-controlled packages.
- **ClawHub poisoning** — a popular MCP tool distribution hub served modified tarballs after its CDN bucket was misconfigured for public write access.

Hash verification answers the question: *did this package change since we approved it?*

---

## How `--verify-hashes` Works

When you run:

```bash
mcp-audit scan --verify-hashes
```

mcp-audit:

1. Discovers all MCP server configs on your machine.
2. Cross-references each server name against the known-server registry.
3. For servers with `known_hashes` entries, extracts the installed version from the command invocation (e.g. `npx @modelcontextprotocol/server-filesystem@2026.1.14`).
4. Downloads the package tarball for that exact version.
5. Computes its SHA-256 digest.
6. Compares it against the pinned hash in the registry.

This is the static, offline-equivalent of rug-pull detection — but applied to the npm/pip package itself rather than the MCP config file.

### Finding Severities

| Outcome | Severity | Meaning |
|---|---|---|
| Computed hash matches expected | — | Clean; no finding produced |
| Computed hash **differs** from expected | **CRITICAL** | Package was modified after approval |
| Network error during download | INFO | Could not verify; retry when network is available |
| Version could not be extracted | INFO | Pin the package version explicitly in the config |
| No hash pinned for this version | INFO | Contribute the hash to the registry or pin a verified version |

CRITICAL findings indicate active tampering. Treat them as incidents.

---

## `mcp-audit verify` Command Reference

Verify one or more packages interactively without running a full scan.

### Synopsis

```
mcp-audit verify [SERVER_NAME|CONFIG_PATH] [--all] [--registry PATH]
```

### Arguments

| Argument / Option | Description |
|---|---|
| `SERVER_NAME` | Registry package name to verify, e.g. `@modelcontextprotocol/server-filesystem`. Verifies all pinned versions for that package. |
| `CONFIG_PATH` | Path to an MCP config file (e.g. `~/.cursor/mcp.json`). All servers in that config are looked up against the registry; those with pinned hashes are downloaded and verified. Servers not in the registry appear as `NOT IN REGISTRY`. Detected automatically when the argument starts with `/`, `.`, ends in `.json`, or exists on disk. |
| `--all` | Verify all servers currently configured on this machine that have pinned hashes. Automatically discovers configs and cross-references the registry. |
| `--registry PATH` | Use a specific registry file instead of the user cache or bundled registry. |

### Exit Codes

| Code | Meaning |
|---|---|
| 0 | All verifications passed, or no hashable packages found |
| 1 | One or more hash mismatches detected (possible tampering) |
| 2 | Error (registry not found, config file not found, invalid arguments) |

### Output

The command prints a Rich table with columns:

```
Server | Version | Expected Hash | Computed Hash | Status
```

`Expected Hash` and `Computed Hash` are truncated to 8 hex characters for readability. Status is one of:

- `✓ PASS` — hashes match
- `✗ FAIL` — hashes differ; **stop using this package immediately**
- `~ UNKNOWN` — version unknown or network error
- `~ NOT IN REGISTRY` — server is not in the known-server registry (config-path mode)
- `~ NO HASHES PINNED` — server is in the registry but has no pinned hashes yet

### Examples

Verify a specific package by name:

```bash
mcp-audit verify @modelcontextprotocol/server-filesystem
```

Verify all servers in a config file:

```bash
mcp-audit verify ~/.cursor/mcp.json
mcp-audit verify demo/configs/claude_desktop_config.json
```

Verify all configured servers with pinned hashes (auto-discovers all configs):

```bash
mcp-audit verify --all
```

Use a custom registry (e.g. your organisation's fork):

```bash
mcp-audit verify --all --registry /path/to/registry.json
```

---

## Tier Access

Hash verification ships in every install. Integrity checks should never be paywalled.

---

## How Hashes Get Into the Registry

The `registry/known-servers.json` file ships with the package and contains `known_hashes` for well-maintained, stable packages. The structure is:

```json
{
  "name": "@modelcontextprotocol/server-filesystem",
  "source": "npm",
  "known_hashes": {
    "2026.1.14": "sha256:e5635c070c21c4f5017260d2fb74df423d3339c2fa2eede862e5731aebf69eac"
  }
}
```

### Adding a Hash for a New Version

**For pip packages** — PyPI publishes authoritative SHA-256 digests in its JSON API. No download required:

```bash
curl -s "https://pypi.org/pypi/<package>/<version>/json" | \
  python3 -c "import json,sys; d=json.load(sys.stdin); \
  [print(u['digests']['sha256']) for u in d['urls'] \
  if u['packagetype']=='sdist' and u['filename'].endswith('.tar.gz')]"
```

**For npm packages** — download the tarball and compute SHA-256:

```bash
curl -sL "https://registry.npmjs.org/<name>/-/<basename>-<version>.tgz" | sha256sum
```

For scoped packages like `@scope/name`, the basename is `name` (without the `@scope/` prefix).

Once you have the hash, open `registry/known-servers.json`, find the entry, and add or update the `known_hashes` field:

```json
"known_hashes": {
  "2026.1.14": "sha256:<your-computed-hex-here>"
}
```

Submit a pull request to the mcp-audit repository to contribute hashes for widely-used packages.

---

## Known Limitations

- **Version extraction is best-effort.** mcp-audit currently recognises only the `npx package@version` invocation pattern. Servers installed via other mechanisms (pip, docker, system packages) cannot have their versions extracted automatically — an INFO finding is produced instead.

- **npm hashes are computed by mcp-audit on download**, not sourced from a signed manifest. PyPI publishes authoritative SHA-256 digests; npm's `integrity` field uses SHA-512 SRI format rather than SHA-256. mcp-audit normalises to SHA-256 by downloading and hashing.

- **`--verify-hashes` requires outbound network access.** The scan will not fail if the network is unavailable — INFO findings are produced for packages that could not be verified.

- **Only the exact pinned version is verified.** If the installed version differs from every pinned version, an INFO finding is produced (no hash to compare against). This is intentional — mcp-audit does not block unknown versions, it only confirms known-good ones.

---

---

## Layer 2: Sigstore Provenance Verification

Layer 2 verifies cryptographic provenance attestations published alongside
packages on npm and PyPI. Unlike hash verification (which answers *did this
tarball change?*), Sigstore provenance answers *who signed this release and
from which CI pipeline?*

### Usage

```bash
mcp-audit scan --verify-signatures
mcp-audit scan --verify-signatures --strict-signatures
```

`--verify-signatures` is **free for all tiers** and requires network access
(HTTPS to `registry.npmjs.org` and `pypi.org`). It cannot be combined with
`--offline`.

`--strict-signatures` raises packages with no attestation from INFO to MEDIUM
severity. Use this when you require provenance on all registry-known packages.

### How it works

1. For each server in the registry, the installed version is extracted from the
   config (same as `--verify-hashes`).
2. The npm or PyPI attestation API is queried for an SLSA provenance bundle.
3. The bundle is cryptographically verified using the `sigstore` Python library,
   which validates the Fulcio certificate chain, SCT, and Rekor transparency log
   inclusion proof against TUF-managed trust roots.
4. The OIDC subject from the signing certificate (typically a GitHub Actions
   workflow URI) is extracted and compared against the `repo` field in
   `registry/known-servers.json`.

### Finding IDs

| Finding ID   | Severity     | Meaning |
|--------------|--------------|---------|
| ATTEST-010   | INFO         | Valid attestation; signing repo matches expected |
| ATTEST-011   | HIGH         | Valid attestation; signing repo does **not** match expected |
| ATTEST-012   | CRITICAL     | Attestation present but cryptographically invalid |
| ATTEST-013   | MEDIUM       | Attestation absent for a package known to publish provenance |
| ATTEST-014   | INFO/MEDIUM  | Attestation absent (MEDIUM with `--strict-signatures`) |
| ATTEST-015   | INFO         | Network/API error; could not determine status |

### `attestation_expected` flag

Registry entries for packages maintained by Anthropic at
`github.com/modelcontextprotocol` have `attestation_expected: true` in
`registry/known-servers.json`. When `--verify-signatures` detects a missing
attestation for these entries, it produces **ATTEST-013** (MEDIUM) instead of
the default **ATTEST-014** (INFO), because these packages are known to publish
from a Sigstore-enabled CI pipeline.

### Tier access

Sigstore verification is **free for all tiers**. Attestation checks should
never be paywalled.

---

## Layer 3: Known-Vulnerability Scanning

Layer 3 extends supply chain security from *did this package change?* (Layer 1)
and *was this build provenance-signed?* (Layer 2) to *does this package have
known CVEs?* — including transitive dependencies.

### `--check-vulns`

```bash
mcp-audit scan --check-vulns
```

When this flag is set, mcp-audit:

1. Extracts the ecosystem (`npm` or `PyPI`), package name, and pinned version
   from each server config (same extraction logic as `--verify-hashes`).
2. Queries the [deps.dev](https://deps.dev) API for the full transitive
   dependency graph of each resolved package.
3. Submits all packages (top-level + transitive) to the
   [OSV.dev](https://osv.dev) batch API, which returns advisories from
   GitHub Advisory Database, NVD, PYSEC, and others.
4. Emits a `VULN-<OSV-ID>` finding for each matched advisory.

`--check-vulns` requires network access and cannot be combined with `--offline`.

### `--vuln-registry URL`

```bash
mcp-audit scan --check-vulns --vuln-registry https://your-osv-mirror.internal/v1/querybatch
```

Override the OSV API endpoint to point at an air-gapped or private mirror (for
example, an OSV-compatible proxy behind a corporate firewall). The URL must
implement the OSV `querybatch` POST contract.

### `mcp-audit sbom`

```bash
mcp-audit sbom                          # write CycloneDX 1.5 JSON to stdout
mcp-audit sbom --output sbom.json       # write to file
mcp-audit sbom --format terminal        # pretty-print dependency tree
mcp-audit sbom --offline                # top-level packages only (no deps.dev)
mcp-audit sbom path/to/config.json      # scan a specific config
```

Generates a [CycloneDX 1.5](https://cyclonedx.org) SBOM document listing all
MCP servers as components and any known VULN findings as CycloneDX
`Vulnerability` objects. The output is valid JSON containing `bomFormat`,
`specVersion`, `serialNumber`, `metadata`, `components`, and `vulnerabilities`
fields. Compatible with SBOM tooling such as `grype`, `trivy`, and GitHub
Dependency Review.

`mcp-audit sbom` is **free for all tiers**.

### Finding IDs

| Finding ID     | Severity  | Meaning |
|----------------|-----------|---------|
| `VULN-<OSV-ID>` | CRITICAL / HIGH / MEDIUM / LOW | Known CVE in a direct or transitive dependency; severity derived from the advisory's qualitative rating |
| `VULN-UNPINNED` | LOW | Server uses an unpinned (floating) version; vulnerability scan used the latest published version, which may differ from the actual runtime version |

### The `--offline` contract

`--check-vulns` and `mcp-audit sbom` (with transitive dep resolution) both
require network access and exit with code 2 if `--offline` is also supplied.
In offline mode, `mcp-audit sbom --offline` still produces a valid SBOM but
lists only top-level packages (no transitive deps fetched from deps.dev) and
includes no vulnerability entries.

---

## Roadmap

| Layer | Description | Status |
|---|---|---|
| Layer 1 | SHA-256 hash verification against registry pins | **Shipped** |
| Layer 2 | Sigstore signature verification (cosign / sigstore-python) | **Shipped** |
| Layer 3 | Known-CVE scanning via deps.dev + OSV.dev; CycloneDX SBOM | **Shipped** |
