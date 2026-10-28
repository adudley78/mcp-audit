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

1. Extracts the ecosystem (`npm` or `PyPI`), package name, and version from
   each server config (`npx`/`bunx`/`pnpx`/`yarn dlx` → npm, `uvx`/`pipx` →
   PyPI; `pkg@1.2.3`, `@scope/pkg@1.2.3` and `pkg==1.2.3` are read as exact
   pins). A launch with no version (`npx -y pkg`), `@latest`, or a range
   (`^1.2.3`) is resolved to the registry's latest release and reported as
   `VULN-UNPINNED`.
2. Queries the [deps.dev](https://deps.dev) API for the dependency graph of
   each resolved package, keeping each node's `relation` (`SELF`, `DIRECT`,
   `INDIRECT`; deps.dev marks a dependency that is both as direct).
3. Submits all packages (top-level + transitive) to the
   [OSV.dev](https://osv.dev) batch API (`/v1/querybatch`), which answers
   with advisory IDs only.
4. Fetches the full record of each distinct advisory once from
   `/v1/vulns/{id}` (at most 256 distinct IDs, 8 at a time, 10 s each, 120 s
   in total, 4 MiB per record) and reads its summary, aliases, CWEs, fixed
   versions for this package, and severity.
5. Emits a `VULN-<OSV-ID>` finding for each matched advisory, and a
   `VULN-UNRESOLVED` finding for each lookup that could not run.

`--check-vulns` requires network access and cannot be combined with `--offline`.

#### Where a `VULN-<OSV-ID>` severity comes from

From the advisory's own record, in this order, and the finding's evidence
says which (`severity_basis`):

| `severity_basis` | Read from | Example |
|---|---|---|
| `cvss_v3` | a CVSS v3 vector in `severity[]`; the base score is computed and banded (Critical ≥ 9.0, High ≥ 7.0, Medium ≥ 4.0, Low > 0). CVSS 3.0 vectors are scored with the 3.1 formula (the two differ only in rounding). | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` → 7.5 → HIGH |
| `database_specific` | the database's own rating in `database_specific.severity` (GitHub: `LOW`, `MODERATE`, `HIGH`, `CRITICAL`; `MODERATE` is reported as MEDIUM) | a record with only a CVSS v4 vector |
| `malicious-package` | an OSV `MAL-*` record (a malicious package) → CRITICAL, as SC-008 rates a listed release | `MAL-2026-5481` |
| `unrated` | none of the above, or the record could not be fetched → INFO, and the description says which | |

The evidence also carries `relation` (`self`, `direct`, `indirect`) and
`direct_dependency` (true for the server package itself and its direct
dependencies).

#### When a lookup cannot run: `VULN-UNRESOLVED`

A check that did not run is not a clean result. `VULN-UNRESOLVED` (INFO) is
reported for the server, and a line is added to the scan's `errors`, when:

| `stage` | Cause | What was still checked |
|---|---|---|
| `version` | no concrete version could be resolved for an unpinned or range launch | nothing |
| `dependencies` | deps.dev has no graph for the version (HTTP 404: deps.dev has not indexed a release published in the last few days yet) or the request failed | the server package itself, in OSV |
| `advisories` | the OSV query failed | the packages in other batches only |

A deps.dev graph that carries node errors, an OSV result with a further
page, and advisory records that could not be fetched are reported in
`errors` (the affected `VULN-<OSV-ID>` findings say so in their
description). `VULN-UNRESOLVED` never becomes an advisory-feed record and is
not listed as a vulnerability in `mcp-audit sbom`.

### `--vuln-registry URL`

```bash
mcp-audit scan --check-vulns --vuln-registry https://your-osv-mirror.internal/v1/querybatch
```

Override the OSV API endpoint to point at an air-gapped or private mirror (for
example, an OSV-compatible proxy behind a corporate firewall). The URL must
implement the OSV `querybatch` POST contract. When it ends in
`/querybatch`, full advisory records are fetched from the sibling `/vulns/`
path (`…/v1/querybatch` → `…/v1/vulns/{id}`); otherwise only what the mirror's
querybatch returned is used, and an advisory without a readable severity
says that the details endpoint is unknown.

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
| `VULN-<OSV-ID>` | CRITICAL / HIGH / MEDIUM / LOW / INFO | Known advisory against the server package or a direct or transitive dependency; severity read from the advisory's own record (see "Where a `VULN-<OSV-ID>` severity comes from"); INFO when the record carries no readable rating |
| `VULN-UNPINNED` | LOW | Server uses an unpinned (floating) version; vulnerability scan used the latest published version, which may differ from the actual runtime version |
| `VULN-UNRESOLVED` | INFO | A lookup could not run (no version resolved, no deps.dev graph, OSV query failed); says what was and was not checked |

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
| `SC-007` | MEDIUM | — | Unscoped twin of a registry entry (see below); replaces SC-001..003 |

**Any spelling of the launcher.** Every supply-chain check (SC-001..008) first
reduces the launcher to its bare name: the path is dropped (either `/` or `\`),
case is ignored, a Windows `.cmd`/`.exe`/`.bat`/`.ps1` wrapper is stripped, and
`cmd /c` or `cmd /k` (after switches such as `/d /s`) is unwrapped so the next
argument is the launcher. `C:\Program Files\nodejs\npx.cmd -y pkg` and
`cmd /c npx -y pkg` are checked exactly like `npx -y pkg`. When the whole command
line is one argument after `cmd /c` (`"\"C:\\Program Files\\nodejs\\npx.cmd\" -y pkg"`
in the JSON), or an argument carries double quotes, it is split the way Windows
programs split a command line ([Microsoft: Parsing C command-line
arguments](https://learn.microsoft.com/en-us/cpp/c-language/parsing-c-command-line-arguments)):
double quotes group, backslashes are literal except before a quote, and the first
argument (the program) keeps its backslashes. Only the first 32,767 characters
are read, the longest command line Windows can start. `pnpm dlx`, `npm exec`
and `uv run --with` are not recognised (see GAPS.md).

**Short-name guard:** Package names ≤ 5 characters use a tighter threshold of 1
(not 3) to suppress false positives — short names are inherently close to many
other short names.

**Unscoped twins come first.** When a name is an unscoped twin of a registry
entry (`SC-007`, below), that finding replaces SC-001..003 for the server: a
server never gets both. Example from the shipped registry: `uvx mcp-server-github`
is 3 edits from PyPI `mcp-server-git` (SC-003), but it is the PyPI spelling of
`@modelcontextprotocol/server-github`, and SC-007 says so.

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
does not map them until GitHub reviews them; and NVD-only CVEs. `MAL-*`
malicious-package records are not merged into `known-servers.json` (a malicious
release is a different finding class from a CVE); since STORY-0097 the same run
mirrors them into `registry/known-malicious.json` for SC-008, below.

---

## SC-007: Unscoped twins

`SC-007` (MEDIUM, `CWE-829`, OWASP MCP04, STORY-0097) fires when a configured
package copies a known package's name without its scope. Edit distance cannot
see this: `mcp-server-github` is many edits from
`@modelcontextprotocol/server-github`, because the difference is a scope and a
naming convention, not a few letters.

**Why it matters.** In June 2026 OSV published ten records for unscoped npm
names of exactly this shape (`MAL-2026-5476` to `MAL-2026-5485`): `mcp-server-github`,
`-git`, `-fetch`, `-figma`, `-notion`, `-postgres`, `-redis`, `-sentry`,
`-sequential-thinking` and `-supabase`. Each `postinstall` sent the host name,
working directory and platform to a Cloudflare Worker
([o3 on MAL-2026-5479](https://o3.security/malware/npm/mcp-server-github)).
`mcp-server-everything` (`MAL-2025-46986`) is an earlier one.

**What counts as a twin.** The rules are derived from the registry's own entries
and from the naming the 2026 squats actually used:

| Rule | Registry entry | Twin | Seen in the wild |
|---|---|---|---|
| name part, for `server-<x>` / `mcp-server-<x>` | `@modelcontextprotocol/server-github` | `server-github` | npm holds `server-github` as a `0.0.1-security` placeholder |
| | `@supabase/mcp-server-supabase` | `mcp-server-supabase` | `MAL-2026-5485` |
| `mcp-server-<x>` spelling of `server-<x>` / `<x>-mcp-server` | `@modelcontextprotocol/server-github` | `mcp-server-github` | `MAL-2026-5479` |
| | `@notionhq/notion-mcp-server` | `mcp-server-notion` | `MAL-2026-5480` |
| same `mcp-server-<x>` name, other registry | PyPI `mcp-server-git` | npm `mcp-server-git` | `MAL-2026-5478` |
| | npm `@modelcontextprotocol/server-memory` | PyPI `mcp-server-memory` | a 0.0.1 placeholder with ~450 installs a month |

Names are folded the PEP 503 way first (lowercase; runs of `-`, `_`, `.` become
`-`), so `mcp_server_github` is the same twin as `mcp-server-github` in npm and
in PyPI, even though npm itself treats the two as different packages. The
configured package must not itself be in the registry for its own ecosystem, so
`uvx mcp-server-git` (Anthropic's PyPI server) is never a twin.

**What is deliberately not a twin.** The plain name part of any other scoped
package: `@notionhq/notion-mcp-server` → `notion-mcp-server` (an unrelated
community server with about 2,500 weekly downloads), `@upstash/context7-mcp` →
`context7-mcp`, and generic name parts such as `@azure/mcp` → `mcp`,
`@autoposting.ai/cli` → `cli` or `@toolbox-sdk/server` → `server`. Scoped
lookalikes (`@evil/server-github`) are left to SC-001..003.

**Measured on 2026-10-25.** The shipped registry yields 37 twin keys. On npm,
21 of them have been published: 12 have since been taken down (10 are now
`0.0.1-security` placeholders, 2 are unpublished), 3 are `0.0.1` stubs from one
account (`mcp-server-cloudflare`, `-neon`, `-qdrant`; the account behind the
"squat farm" in `registry-audit-2026-08-18.md`), and 6 are small packages with 7
to 158 weekly downloads: four with no repository (two reuse the official
package's description), one fork of the official servers repository, and one
community Google Maps server. On PyPI, 5 of the npm-derived keys exist: three
`0.0.1` placeholders registered by Amazon, and two small community servers
(`mcp-server-notion`, `mcp-server-redis`; 85 and 179 downloads a month). So an
SC-007 hit is usually a squat or a takedown, and sometimes a small community
package that took the official server's name; the finding asks you to check
which. That mix is why SC-007 is MEDIUM: the twins OSV lists as malicious are
already CRITICAL under SC-008. If you meant the community package, record it in
your governance policy's `approved_servers` allowlist ([governance.md](governance.md));
that records the decision, and SC-007 keeps reporting the name. SC-007 fires on none of the 100 most-downloaded npm MCP servers
(`docs/research/2026-10-top100-npm/`; pinned by
`tests/test_supply_chain.py::TestScanLevelBehaviour`).

`vet` runs the same check: an unscoped twin exits 1 with a "Possible unscoped
twin" panel and `"typosquat_basis": "unscoped-twin"` in `--format json`.

---

## SC-008: Known malicious packages

`SC-008` (CRITICAL or MEDIUM, `CWE-506`, OWASP MCP04, STORY-0097) fires when the
configured package is an OSV `MAL-*` record: OpenSSF's malicious-packages data,
which OSV serves under `MAL-` IDs. The match is by exact name in one ecosystem
(npm names lowercased, PyPI names PEP 503-normalised), against
`registry/known-malicious.json`, which ships in the wheel and the binaries. A
plain `scan`, `check` or `vet` makes no network call. Before this, these records
were reachable only with `scan --check-vulns`.

| Launch | What OSV lists | Severity |
|---|---|---|
| Pins a listed version | any | CRITICAL |
| Unpinned | every release, or every release from a version on | CRITICAL |
| Unpinned | only specific past releases | MEDIUM |
| Pins a version the record does not cover | — | no finding |

The MEDIUM row follows SC-004's reasoning: the registry normally removes a
malicious release, but npx and uvx can reuse a cached copy. A version that won't
parse counts as covered. The two severities read differently on purpose: CRITICAL
is titled `Known malicious package: <name> (<IDs>)` and says to remove the server;
MEDIUM is titled `Malicious releases listed in OSV: <name> (<IDs>)` and says to pin
a release the record does not list, because it is often a real package that had one
release compromised (`mcp-use` 1.4.2/1.4.3, `@postman/postman-mcp-server`).

**One deliberate difference from OSV's range semantics.** For a package the
registry lists, a range covering every version (`introduced: "0"` and nothing
else) is ignored when the record also lists explicit versions. GitHub's malware
advisories use that blanket range even for one compromised release of a real
package: `MAL-2025-191195` lists `@browserbasehq/mcp` `2.1.1` beside a blanket
range, while npm still serves the clean `3.0.0`. The finding says when this
happened.

npm and PyPI records never cross: npm `mcp-server-git` (`MAL-2026-5478`) does not
fire for `uvx mcp-server-git`. SC-008 is reported alongside SC-007 or
SC-001..003, because it answers a different question (what OSV knows about this
exact package, not what its name resembles). `npx -y mcp-server-github` gives
both.

**The MAL-2026-5476..5485 note.** All ten records report the same beacon host,
`npx-canary-log.vulnerable-live.workers.dev`, and three of those npm packages,
read on 2026-08-18, named `theinfosecguy/npx-canary` as their repository
(`registry-audit-2026-08-18.md` §3a). Those two facts are what each record's
`note` field says; the note draws no conclusion about who published them or
why. OSV classifies the packages as malicious, and SC-008 reports them as OSV
states it.

**Measured on 2026-10-25:** 217 records (144 npm, 73 PyPI). On the 100
most-downloaded npm MCP servers, pinned as published, SC-008 fires on none;
launched unpinned, it fires MEDIUM on one (`@mastra/mcp-docs-server`, whose
release 1.1.47 is `MAL-2026-5956`).

**Keeping it current.** `scripts/sync_registry_advisories.py` reads OSV's bulk
export for npm and PyPI (about 260 MB, read once per run) and keeps every `MAL-`
record that is not withdrawn and names a package whose name contains `mcp` or
that the registry lists. The substring test is deliberate: a match is by exact
name, so an extra record can never cause a false positive. The file is a mirror,
not additive: a record OSV withdraws is removed. The weekly
`registry-advisory-sync.yml` check fails when the file has drifted; `--write`
updates it.

`vet` reports the same records: a record covering the latest release exits 1;
past releases only are listed and exit 0. Without `--ecosystem`, `vet` also warns
when the other registry's package of the same name is malicious
(`vet mcp-server-git` answers for Anthropic's PyPI server and warns that npm
`mcp-server-git` is `MAL-2026-5478`).

---

## Roadmap

| Layer | Description | Status |
|---|---|---|
| Layer 0 | Typosquatting detection via Levenshtein distance (npm + PyPI) | **Shipped** |
| Layer 0b | Offline CVE advisory (`SC-004`) against bundled registry | **Shipped v0.12.0** |
| Layer 1 | SHA-256 hash verification against registry pins | **Shipped** |
| Layer 2 | Sigstore signature verification (cosign / sigstore-python) | **Shipped** |
| Layer 3 | Known-CVE scanning via deps.dev + OSV.dev; CycloneDX SBOM | **Shipped** |
