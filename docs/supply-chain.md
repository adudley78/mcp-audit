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

`mcp-audit sbom` is **free for all tiers**. Requires `pip install 'mcp-audit-scanner[sbom]'`
(the `cyclonedx-python-lib` dependency is optional and not included in the default install
or the PyInstaller binary).

#### SBOM staleness

Every SBOM `mcp-audit sbom` writes carries a CycloneDX `metadata.timestamp`
set at generation time, so the document itself states when its dependency
graph was resolved. What it does not do is expire: an SBOM describes the
graph as resolved *at generation time*, and nothing re-validates that graph
against current advisories when the SBOM is read later. Scanning — or
re-reading — an old SBOM produces findings against versions that may no
longer be what is actually installed, and, in the other direction, misses
advisories that landed after generation.

The measured shape of this failure mode is the mirror image of the deps.dev
limitation documented below. In the same independent study, an advisory
scanner reading a dependency tree frozen at each root package's release date
flagged **130 of 249 MCP servers (52.2%) that are clean when installed**, and
none the other way round (affected when installed, clean frozen)
([spec §13, v3.16.1](https://github.com/prachetpoddar/mcp-supply-chain-study/blob/v3.16.1/spec/mcp-lock-spec.md#13-security-considerations);
recomputed 2026-10-09 with both arms through his corrected resolver, see
`RESOLVER-NOTES.md` at the same tag). Counts of individual findings are left
out on purpose: five packages carry 82% of them, so the rate is stable and the
count is not. The same study's decomposition says why the frozen tree
over-reports: of the findings it reports, the share whose advisory was
published after the root package shipped runs from 90.6% for roots 30 days old
or less to 100.0% for roots more than a year old. A frozen description
over-reports because advisories keep accruing against it, not because
publishers shipped versions an advisory already covered
(`PREREGISTRATION-6.md` and `code/gap_cause_split.py` at the same tag; the
bands between those endpoints are not monotone, so only the endpoints are
quoted). An SBOM generated at release and scanned a year later has
exactly this shape; it is the same
failure the advisory feed's `expires` field exists to prevent (see
`docs/advisory-feed.md`), applied to a document type that currently carries
no expiry mechanism at all.

This is a caveat, not a fix. `mcp-audit sbom` does not currently carry a TTL
or any other staleness signal beyond `metadata.timestamp`. Whether it should
is a separate design question, not addressed here.

### Finding IDs

| Finding ID     | Severity  | Meaning |
|----------------|-----------|---------|
| `VULN-<OSV-ID>` | CRITICAL / HIGH / MEDIUM / LOW | Known CVE in a direct or transitive dependency; severity derived from the advisory's qualitative rating |
| `VULN-UNPINNED` | LOW | Server uses an unpinned (floating) version; vulnerability scan used the latest published version, which may differ from the actual runtime version |

### The `--offline` contract

`--offline` is accepted for future compatibility. It enforces mutual exclusion
with network-touching opt-in flags: `--verify-hashes`, `--verify-signatures`,
`--check-vulns`, and `--connect` will all produce an error (exit code 2) if
combined with `--offline`. A plain scan makes no network calls regardless of
this flag, so `--offline` is currently a no-op for the default configuration.

### Known limitation: the published graph vs. the installed tree

`--check-vulns` and `mcp-audit sbom` answer a specific, narrower question
than "is this server vulnerable": for the exact `(name, version)` pinned in a
config, what does deps.dev say the *published* dependency graph looks like,
and does the OSV.dev batch API report advisories against that graph? They do
**not** answer what a given machine actually materializes when it runs
`npx` / `npm install` at a given moment. Semver-range resolution at install
time (including npm's own `latest`-dist-tag preference over a higher
satisfying version), lockfile state, and platform-specific optional
dependencies all live in the gap between "published graph" and "installed
tree," and mcp-audit models none of them. One measured instance: deps.dev's
graph carries `get-intrinsic@1.3.1`, while npm's `latest` tag for that package
is `1.3.0`, which is what npm picks when a range allows both. Version 1.3.1
declares three dependencies 1.3.0 does not (`async-function`, `async-generator-function`,
`generator-function`), so in Prachet Poddar's corpus deps.dev lists those three
for 158 to 159 of 248 MCP servers where his corrected resolver installs none of
them ([`RESOLVER-NOTES.md`, v3.16.1](https://github.com/prachetpoddar/mcp-supply-chain-study/blob/v3.16.1/RESOLVER-NOTES.md)).

**Measured divergence.** [Prachet Poddar's independent study of 250 MCP server configs](https://github.com/prachetpoddar/mcp-supply-chain-study/tree/v3.16.1)
compared deps.dev's published graph with the tree his corrected resolver
computes against the registry as of the date deps.dev's graphs were fetched
(2026-09-07/08), and scored both against the same npm advisory data. On that
comparison, keyed by package name and version, deps.dev's graph gives a
different advisory verdict for **2 of 248 servers (0.8%): eight missed
findings (four high, four moderate) and zero phantom findings**
([`data/verdict_recompute.json`](https://github.com/prachetpoddar/mcp-supply-chain-study/blob/v3.16.1/data/verdict_recompute.json),
pre-registered in [`PREREGISTRATION-8.md`](https://github.com/prachetpoddar/mcp-supply-chain-study/blob/v3.16.1/preregistrations/PREREGISTRATION-8.md)).
That is the measured bound this project can currently point to for how often
the published-graph shortcut produces a different verdict than a real install
would have. It comes with four qualifications, all his:

- It is a missed rate, not a two-way difference rate. The corrected tree is
  close to a superset of deps.dev's graph by construction, so the comparison
  shows what deps.dev misses and says little about what it adds.
- Two servers is a small count. The 95% Clopper–Pearson interval is 0.10% to
  2.88%.
- One package, `qs`, carries half of it. Set `qs` aside and the difference
  falls to 1 server.
- It ages. Against a tree resolved about a month later, the same deps.dev
  graphs give a different verdict for 15 of 248 servers (6.0%), with 17 missed
  and 30 phantom findings.

The figure this section quoted before, 2 of 249 servers with six findings
(measured 2026-09-08), is retracted. It was keyed by name only on both sides,
both arms predate his 11–17 September resolver corrections, and its inputs no
longer exist (`PREREGISTRATION-8.md`).

His graph recomputation points the same way
([`PREREGISTRATION-7.md`, v3.16.1](https://github.com/prachetpoddar/mcp-supply-chain-study/blob/v3.16.1/preregistrations/PREREGISTRATION-7.md),
`data/depsdev_recompute.json`). Once the `get-intrinsic` edge above and the
three packages it pulls in are set aside, deps.dev's graph is identical to the
corrected tree for 79.4% of 248 servers, against 67.7% for the pre-correction
tree. Both figures exclude, from both sides of both trees, the package names
the corrected tree carries at more than one version: 170 servers have one,
and the exclusion removes 763 of deps.dev's 21,134 nodes. An earlier pairing
of 79.4% against 62.1% is not comparable, because the 62.1% was scored on a
node set that lost nothing to that exclusion.

This is a limitation with a measured bound, **not an accuracy claim**. It is
a single study of one corpus, at one point in time, produced by one person —
treat it as a data point, not a guarantee. It is also easy to over-read in
the wrong direction. Matched to the fetch date and counting every version an
install nests, the two graphs are close in size (median 91 packages per server
in the corrected tree, 94 in deps.dev's), and the corrected tree carries 8.1%
more package instances, since deps.dev's graph holds one version per name by
construction. Yet they disagree on at least one package's version for
**66.1% of servers**; deps.dev's graph lacks a package the tree installs for
10.9% of servers and lists one the tree does not install for 64.9%, most of
those the three `get-intrinsic` packages above. The verdict-level gap is still
0.8%. Version-disagreement rate alone is therefore a poor proxy for whether a
graph gap matters; the small verdict gap is a fact about where advisory
boundaries happen to fall in this corpus, not evidence that the two graphs
generally agree.

**The failure class that does bite, and is worth watching for.** When a graph
gap does produce a wrong verdict, it has a specific, nameable shape: a
version resolves *up* into an advisory window whose lower bound sits above
the version the other arm holds (e.g. resolving to a version inside a
`>=X <=Y` advisory range, while the reference graph held an earlier, unaffected
version). **Pinning a version does not protect against this class** —
pinning forward to a newer version is exactly what causes it, since the
version you pinned to may itself already sit inside a later-disclosed
advisory window. The mitigation is re-scanning against current advisory data,
not pinning harder.

---

## Typosquatting Detection

The supply chain analyzer checks every MCP server that is invoked via a
package-manager command against the known-server registry.  A server whose
package name is suspiciously close to a known-good package — but not an exact
match — is flagged as a possible typosquat.

### Supported package managers

| Command pattern | Example | Ecosystem |
|---|---|---|
| `npx <pkg>`, `bunx <pkg>`, `pnpx <pkg>` | `npx @modelcontextprotocol/server-filesystem` | npm |
| `yarn dlx <pkg>` | `yarn dlx @modelcontextprotocol/server-filesystem` | npm |
| `uvx <pkg>[@ver]` | `uvx mcp-server-filesystem` | PyPI |
| `uvx --from <pkg> <exe>` | `uvx --from mcp-server-filesystem mcp-fs` | PyPI |
| `uvx --python 3.x <pkg>` | `uvx --python 3.11 mcp-server-git` | PyPI |
| `pipx run <pkg>` | `pipx run mcp-server-filesystem` | PyPI |
| `python -m <module>` | `python -m mcp_server_filesystem` | PyPI |

### Python name normalisation (PEP 503)

Before comparing Python package names, mcp-audit applies PEP 503 normalisation:
collapses runs of `-`, `_`, and `.` into a single `-` and lowercases the result.
This means `mcp_server_filesystem`, `mcp-server-filesystem`, and
`MCP.Server.Filesystem` are all treated as the same name.

### Finding IDs and severity

| Finding ID | Severity | Edit distance | Meaning |
|---|---|---|---|
| `SC-001` | CRITICAL | 1 | One character away from a known-good package |
| `SC-002` | HIGH | 2 | Two edits away — classic transposition typosquat |
| `SC-003` | MEDIUM | 3 | Three edits away |

**Short-name guard:** Package names ≤ 5 characters use a tighter threshold of 1
(not 3) to suppress false positives — short names are inherently close to many
other short names.

### Registry entries

The known-server registry (`registry/known-servers.json`) now carries a
`package_ecosystem` field per entry:

| Value | Meaning |
|---|---|
| `"npm"` | Entry is an npm package; used only for npm comparison pool (default) |
| `"pypi"` | Entry is a PyPI package; used only for PyPI comparison pool |
| `"any"` | Entry appears in both comparison pools |

Python packages in the registry (at time of writing): `mcp`, `mcp-server-fetch`,
`mcp-server-filesystem`, `mcp-server-git`, `mcp-server-postgres`,
`mcp-server-qdrant`, `mcp-atlassian`, `langchain-mcp-adapters`.

### Remediation

If a typosquat finding fires, verify the package name in the MCP config is
intentional.  If it is a typo, correct the name to the known-good package listed
in the finding's remediation text.  Before trusting any unexpected package, check
its PyPI or npm page and source repository for legitimacy signals (publication
date, download count, publisher history).

---

## SC-004: Offline CVE advisory check

`SC-004` (HIGH or MEDIUM, `CWE-1104`, OWASP MCP04) fires when an exact-match registry entry
carries CVE IDs in `RegistryEntry.known_vulnerabilities` and/or structured records
in `RegistryEntry.known_vulns` (`cve`, `cvss`, `description`, `fixed_in`).  No
network access is required — the check runs purely against the bundled registry.

**One finding per package** (STORY-0078, 2026-10-11).  A package with several
advisories produces a single SC-004 that lists them all, not one finding per CVE:

```
FINDING SC-004: Known CVE advisories: mcp-atlassian (30 CVEs)
  Severity: MEDIUM  Analyzer: supply_chain
  Package 'mcp-atlassian' has 30 public CVE advisories recorded in the mcp-audit
  known-server registry: CVE-2026-27826, CVE-2026-73498, ... and 20 more
  (`mcp-audit vet mcp-atlassian` lists them all). The config does not pin an
  exact version, so mcp-audit cannot tell offline whether the installed release
  is affected. Every advisory listed here is fixed in 0.22.0 or later. An
  unpinned launch normally installs a patched release, but npx and uvx can reuse
  a cached older install.
```

The description lists at most 10 advisory IDs; `vet` shows the full list.

**Severity** (STORY-0083, 2026-10-13):

| Launch | Recorded advisories | Severity |
|---|---|---|
| Pins an affected version | any | HIGH |
| Unpinned | at least one has no recorded fix | HIGH |
| Unpinned | every one has a recorded `fixed_in` | MEDIUM |
| Pins a version at or above every fix | — | no finding |

The MEDIUM row exists because the registry now carries each package's full
advisory history. Without it, long-fixed CVEs on official servers would raise
HIGH on every unpinned config.

A single advisory keeps the original title form:
`Known CVE advisory: @mcpjam/inspector (CVE-2026-23744)`.

**Version-aware when the config pins an exact version.**  When the launch command
pins one (`npx pkg@1.4.0`, `uvx pkg==0.21.1`, `uvx pkg@0.21.1`) and a `known_vulns`
record gives `fixed_in` for a CVE, that CVE is dropped if the pinned version is at
or above the fix.  If every CVE is dropped, no SC-004 fires.  A CVE with no
`fixed_in`, or a version that won't parse, is kept.

**What it still can't do:** mcp-audit never resolves ranges, so a range
(`pkg@^1.4.0`, `pkg>=0.21`) or no version at all is treated as unpinned and every
recorded CVE is reported.  Use `scan --check-vulns` for a network lookup against
OSV.dev.

Seeded data: CVE-2026-23744 (`@mcpjam/inspector`), CVE-2026-0755
(`gemini-mcp-tool`), CVE-2025-59528 (`flowise`), CVE-2026-26118 (`@azure/mcp`),
CVE-2026-33032 (`nginx-ui`) at v0.12.0; 24 CVEs for `mcp-atlassian` (all fixed by
0.22.0, from PyPI's vulnerability data) and CVE-2026-14540 for `@toolbox-sdk/server`
(fixed in 1.5.0) on 2026-10-11.

**Keeping it current** (STORY-0083, 2026-10-13). `scripts/sync_registry_advisories.py`
queries OSV for every registry package and merges missing advisories into
`known_vulnerabilities` and `known_vulns`, with `fixed_in` taken from OSV's ranges.
It only adds; it never removes or rewrites an entry. The first run added 144
advisories across 10 entries, including MCP Inspector's CVE-2025-49596,
server-filesystem's CVE-2025-53109/53110, the TypeScript SDK's CVE-2026-104850,
and 113 for `flowise`. It also added `mcp-remote` (614K weekly downloads) to
the registry with its six 2026 advisories, entered by hand because OSV did not
yet map them to the package.

The weekly `registry-advisory-sync.yml` workflow runs the script in `--check`
mode and fails when anything is missing. Like `registry-drift.yml`, it never
writes the registry; someone runs `--write` and opens a PR.

```bash
python scripts/sync_registry_advisories.py           # check; exit 1 if anything is missing
python scripts/sync_registry_advisories.py --write   # merge into registry/known-servers.json
```

What it can't see: unreviewed GitHub advisories carry no package data, so OSV
does not map them until GitHub reviews them; NVD-only CVEs; and `MAL-*`
malicious-release records, which it skips on purpose because a malicious release
is a different finding class from a CVE.

---

## Roadmap

| Layer | Description | Status |
|---|---|---|
| Layer 0 | Typosquatting detection via Levenshtein distance (npm + PyPI) | **Shipped** |
| Layer 0b | Offline CVE advisory (`SC-004`) against bundled registry | **Shipped v0.12.0** |
| Layer 1 | SHA-256 hash verification against registry pins | **Shipped** |
| Layer 2 | Sigstore signature verification (cosign / sigstore-python) | **Shipped** |
| Layer 3 | Known-CVE scanning via deps.dev + OSV.dev; CycloneDX SBOM | **Shipped** |
