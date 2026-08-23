# Advisory feed

> **EXPERIMENTAL.** The advisory record format below is not yet stable, and no
> mcp-audit-operated signing key exists — `--sign` requires you to supply your own
> `--key`/`$MCP_AUDIT_SIGNING_KEY`; there is no project key to trust yet. Fields may
> be added, renamed, or reshaped before signing ships with a key mcp-audit
> distributes, and today's records are not guaranteed to be byte-stable across that
> change. Do not build automation against the exact shape of a record yet.

`mcp-audit advise` turns scan findings into signed, OSV-compatible security advisories
for MCP server packages, and publishes them as a feed on disk. `mcp-audit feed verify`
checks one.

There is no CVE/OSV/NVD equivalent for MCP servers. This is the machine-readable
advisory format registries, gateways, and other scanners can reference — deliberately
built on OSV rather than as a bespoke schema, so `osv-scanner` and everything
compatible with it already know how to read it.

```bash
# Scan and publish signed advisories to ./feed
mcp-audit advise ~/Library/Application\ Support/Claude/

# Verify a feed someone handed you
mcp-audit feed verify ./feed --identity 'https://github.com/your-org/.*' \
                             --oidc-issuer 'https://token.actions.githubusercontent.com'
```

## Feed layout

```
feed/
├── index.json                          every advisory summarised + signing parameters
├── index.json.sig
├── index.json.sigstore.json
├── advisories/
│   ├── x_MCPSA-<12 hex>.json           one OSV 1.6.0 record
│   ├── x_MCPSA-<12 hex>.json.sig
│   └── x_MCPSA-<12 hex>.json.sigstore.json
└── osv/
    ├── all.json                        every record as a JSON array
    ├── all.zip                         every record, zipped
    └── osv-scanner/
        ├── npm/all.zip                 osv-scanner offline-database layout
        └── PyPI/all.zip
```

## The record format

Each advisory is a stock OSV `schema_version` 1.6.0 document. The core fields —
`id`, `modified`, `published`, `summary`, `details`, `severity[]`, `affected[]`,
`references[]`, `aliases[]` — carry their standard OSV meanings, so a generic OSV
parser needs to know nothing about MCP to consume the feed.

Everything MCP-specific lives under `affected[].database_specific`, the extension point
OSV reserves for exactly this:

```json
{
  "owasp_mcp": ["MCP01"],
  "mcp_transport": "stdio",
  "finding_class": "hardcoded-secret",
  "mcp_audit_rule_id": "CRED-001",
  "verified_patch": {
    "fixed_version": null,
    "pr_url": null,
    "cosign_bundle": null
  },
  "observation": "deployment",
  "cvss_basis": "finding-class-template",
  "cwe_ids": ["CWE-798"]
}
```

`verified_patch` is null-valued until a fix lands; `mcp-audit fix` populates it and
re-signs the record.

### `observation` — read this before acting on a record

An OSV record is keyed by package, which makes it read as a claim about that package.
Most mcp-audit findings are not: `CRED-001` fires because *an operator* put a token in
*their* config, not because the package is defective. Publishing that as "package X is
vulnerable" would be wrong, so every advisory says which kind it is:

| Value | Meaning | Who acts |
| --- | --- | --- |
| `package-intrinsic` | The defect is in the published package — poisoned tool descriptions, typosquats, failed attestation, source-level vulnerabilities | The maintainer |
| `deployment` | The defect is in how this installation was configured | The operator |

Filter with `--observation package-intrinsic` when publishing a feed about upstream
packages. Anything mcp-audit cannot confidently classify defaults to `deployment`,
because the conservative error is to under-claim.

### `owasp_mcp` — never invented

Codes come from `Finding.owasp_mcp_top_10`, which `scripts/validate_owasp_mapping.py`
holds to `docs/owasp-mapping.json` in CI. The feed publishes the bare `MCP01`..`MCP10`
form defined in `src/mcp_audit/owasp_mcp.py` — the repo's single definition of this
taxonomy, and the same spelling used by SARIF output and the mapping file — so a record
joins to the rest of mcp-audit's output without translation. The advisory package holds
no copy of the code list; `Advisory` rejects any code `owasp_mcp.py` does not recognise.

A finding with no clean mapping gets `"owasp_mcp": []` and an explicit `owasp_mcp_todo`
string. No code is ever guessed.

### `severity` — CVSS 3.1, and where it comes from

Vectors are *derived*, not independently assessed per record, and `cvss_basis` says how:

- `finding-class-template` — the vulnerability class has stable exploitation
  characteristics, so one vector describes every finding in it
- `severity-band` — no class template applies, or the template would have over-claimed;
  the vector encodes mcp-audit's own severity rubric (see `docs/severity-framework.md`)

A class template is used only when its CVSS base score fits inside the finding's own
severity band (Low ≤ 3.9, Medium ≤ 6.9, High ≤ 8.9, Critical ≤ 10.0). Otherwise it is
discarded for the severity-band vector. Without that check `COMM-010` — a LOW finding
about an unpinned `npx` invocation — would publish a High score off the
`unpinned-dependency` template, and a feed that inflates its own records is worth less
than no feed. The reconciliation only guards against over-claiming; under-claiming is
the conservative error and is allowed to stand.

Treat them as a starting point, not a scored analysis.

## Advisory IDs

Format: `x_MCPSA-<12 hex>`.

`MCPSA` is "MCP Security Advisory". The `x_` prefix is OSV's experimental namespace,
used because OSV restricts un-prefixed `id` values to registered home databases;
registering `MCPSA` upstream is the standards move that lets us drop it.

The hex suffix is a SHA-256 digest of package ecosystem, package name, rule ID, finding
class, introduced version, and — when present — the MCP tool name. Four consequences
follow:

1. **Two hosts observing the same issue mint the same ID.** Nothing host-specific
   enters the basis.
2. **No filesystem paths or usernames are involved.** mcp-audit is privacy-first, and a
   published ID derived from `/Users/<name>/...` would leak.
3. **Rewriting prose does not fork a record.** Only identity fields participate.
4. **No timestamp enters the basis either.** An earlier version embedded the
   publication year, so the same recurring vulnerability advised on either side of a
   UTC year boundary minted two different IDs — which breaks the exact thing an ID is
   for: letting a consumer answer "have I seen this before?". The ID is a pure
   function of identifying content, full stop.

Sequential numbering (e.g. `MCPSA-0001`) was rejected: it needs a central allocator,
which is exactly the coordination the digest avoids.

## Determinism

Given the same findings and the same timestamp, `advise` produces byte-identical files
— sorted keys, sorted advisories, fixed ZIP member timestamps. Pin the timestamp with
`SOURCE_DATE_EPOCH` (the [reproducible-builds](https://reproducible-builds.org/docs/source-date-epoch/)
convention) or `--published-at`:

```bash
SOURCE_DATE_EPOCH=1769817600 mcp-audit advise ./configs --out ./feed --no-sign
```

Anyone can then rebuild the feed from the same inputs and diff it against what you
published. Signatures are not reproducible; the payloads they cover are.

## Feed freshness

TUF's timestamp and snapshot roles are collapsed into `index.json`. There is one
publisher and one integrity root, so a second document would buy nothing. Advisory
records stay stock OSV 1.6.0 — `snapshot_version`, `published_at`, and `expires` live
only on the index. An OSV record does not stop being true when the feed that carries
it ages out.

`feed_version` is the schema (`1.1`). It is not a counter. `updated` is
`max(modified)` and is identical across republishes of the same set, which is exactly
the replay being defended against — so it is not reused as freshness.

`snapshot_version` is a monotonic integer. Gaps are allowed; decreases are not.
`--sign` will not silently default it to `1`; pass `--snapshot-version` or
`--previous-index`. Unsigned feeds may start at 1.

`expires` is publish time plus 14 days (2–3× a weekly publish cadence). Override with
`--expires` for the committed fixture only.

### What fails, and what does not

`mcp-audit feed verify` hard-fails on an expired feed. That command exists to answer
"is this feed trustworthy." There is no `--allow-expired`.

`mcp-audit scan --advisory-feed DIR` does not fail because the feed expired. It skips
advisory correlation, says so, and completes. JSON and SARIF carry a `feed_status`
object (`state`: `fresh` / `expired` / `absent`, plus `published_at`, `expires`,
`age_days`) so a CI that genuinely wants to fail on a stale feed can assert on the
field.

On success, `feed verify` prints the publish date and age:
`Verified. Published 2026-08-09, 13 days old.` On expiry it prints the client's
UTC clock next to the expiry so a fast clock is self-diagnosing:
`this feed expired on 2026-08-09T00:00:00Z; current time is 2027-01-14T00:00:00Z`.
Rollback is a different sentence: `this feed is older than one you have already seen`.

Client rollback state is `seen.json` under the user config directory, keyed on the
stable signing identity (workflow identity plus OIDC issuer), not a certificate
fingerprint. Changing the signing identity resets rollback protection for every
client — that is a consequence of rotation, not a fingerprint of an ephemeral cert.

A user who hits "this feed expired" is not under attack by default. The usual cause
is a missed publish or a client clock in the future. `scan` still runs. `feed verify`
refusing is the correct answer to "can I trust this snapshot."

### Residual gap (plain)

A **stateless** client (CI, first run) **accepts any unexpired validly-signed snapshot**, including last week’s, hiding yesterday’s advisories. The counter does nothing for them. **TTL is the only lever.** 14 days is the freeze window, not zero.

Also not covered: stolen key, publisher omitting advisories at a *new* version, client clock in the past, mix-and-match (already bound by `canonical_sha256`).

## Signing

The bytes that get signed are **not** the file on disk. Advisories are pretty-printed
so a human can read a diff, and two publishers who serialise the same record with
different indentation would otherwise produce incompatible signatures. So the signed
payload is the RFC 8785 (JCS) canonicalization of the *parsed* document, which
verification re-derives from scratch. Reformatting a file is harmless; changing any
value is not.

### A static project key, not keyless

A feed is signed with a long-lived project key. This is a deliberate departure from
`snapshot --sign`, which uses Sigstore keyless, and the difference is the threat model
rather than taste.

A snapshot is a one-off forensic artifact. The human identity *is* the evidence, and it
is verified online at investigation time — exactly what keyless is for. A feed is a
distributed data product that CI gates, MCP gateways, and the PyInstaller binary
consume: mostly offline, reproducibly, against a stable *project* identity rather than
whoever happened to run the build. Keyless provides none of those. It binds each
signature to an individual's OIDC account, cannot be produced by a reproducible build,
and needs a Rekor round-trip to verify.

So `advise --sign` requires a key, from `--key` or `$MCP_AUDIT_SIGNING_KEY`, and fails
with an actionable message if neither is set. Keyless remains reachable via `--keyless`
for one-off attestations where a human identity is the point; it is never the default
for a feed.

### Backends

| | `cosign` (default) | `minisign` (`--key-alt minisign`) |
| --- | --- | --- |
| Signing key | Static project key | Static project key |
| Transparency log | Skipped (offline by design) | None |
| Artifacts | `.sig` + `.sigstore.json` | `.sig` |
| Install footprint | Sigstore toolchain | One small binary |

Neither CLI is a hard dependency. When the chosen backend is not on `PATH`, the error
names the install step and the `--no-sign` escape hatch — the same graceful degradation
`mcp-audit sast` applies to a missing semgrep. This keeps the crypto out of the 16.6 MB
standalone binary, for the same reason the `sigstore` stack is excluded from it, while
offline `feed verify` still works wherever cosign is installed. If a zero-external-tool
verifier is ever needed, an Ed25519 verify via `cryptography` (already in the
`[attestation]` extra) drops in as a second backend without changing the artifact format.

Passphrases are read by the signing CLIs from their own environment variables
(`COSIGN_PASSWORD`, `MINISIGN_PASSWORD`) and are never handled or logged by mcp-audit.

Key paths can also come from the environment so they stay out of shell history:

| Variable | Purpose |
| --- | --- |
| `MCP_AUDIT_SIGNING_KEY` | Private key path |
| `MCP_AUDIT_SIGNING_PUBKEY` | Public key path |
| `MCP_AUDIT_SIGNING_IDENTITY` | Expected cosign certificate identity (regex) |
| `MCP_AUDIT_SIGNING_OIDC_ISSUER` | Expected cosign OIDC issuer (regex) |

### What `feed verify` actually checks

A signature alone does not make a feed sound, so four things are verified:

1. The index signature verifies over the index's canonical bytes.
2. Every advisory the index lists exists and its own signature verifies.
3. Each advisory's recomputed canonical digest matches the `canonical_sha256` recorded
   in the index. **This is what stops an attacker swapping in a record they signed
   themselves** — re-signing is not enough, because the index signature covers the
   digest of the original.
4. No advisory file is present that the index does not list.

Keyless verification requires `--identity` and `--oidc-issuer`. Without them a valid
signature only proves *someone* with a Sigstore account signed those bytes, which is
not a security property; the command refuses rather than passing vacuously.

### Unsigned feeds

A feed with no signatures at all is checked for integrity only — steps 3 and 4 above —
and the verdict says so explicitly, exiting 0 while stating that nothing attests to who
produced it. That is not a silent downgrade to a weaker guarantee: an unsigned feed is
an explicit publishing choice, and the caller is told which property it is getting.
Tampering is still caught, because `canonical_sha256` binds every record to the index.

A feed that *claims* to be signed still fails when a signature is missing or bad. The
index records its signing parameters under `signing`, so stripping the `.sig` files
from a signed feed produces a verification failure rather than an unsigned feed.

`examples/feed/` ships unsigned for exactly this reason: signing it reproducibly would
mean committing the private key that signed it, which is worse than not signing it. The
signing path is proven instead by `tests/test_advisory_sign.py`, which mints an
ephemeral key pair, signs a feed, verifies it, and asserts that a mutated record fails.

### Key custody and rotation

The signing key is generated once with `cosign generate-key-pair` and lives in exactly
two places: the private half as a GitHub Actions secret (`FEED_SIGNING_KEY`, with its
passphrase in `COSIGN_PASSWORD`), and the public half published in this repository and
at a stable well-known URL so consumers can pin it:

```
https://mcp-audit.dev/.well-known/mcp-audit-feed.pub
```

The private key is never committed, never printed, and never leaves the CI runner. The
publish job passes it by path:

```yaml
- name: Publish signed advisory feed
  env:
    MCP_AUDIT_SIGNING_KEY: ${{ runner.temp }}/feed.key
    COSIGN_PASSWORD: ${{ secrets.FEED_SIGNING_PASSWORD }}
  run: |
    printf '%s' "${{ secrets.FEED_SIGNING_KEY }}" > "$MCP_AUDIT_SIGNING_KEY"
    mcp-audit advise ./configs --out ./feed
```

**Rotation.** Generate a new pair, publish the new public key at the well-known URL
alongside the old one, and re-sign the current feed with the new key. Keep the previous
public key served for one release cycle so consumers pinning it do not break mid-upgrade,
then remove it and announce the change in the release notes. On suspected compromise,
rotate immediately and skip the overlap window; the digests in a previously published
`index.json` still let consumers detect whether any record was altered.

Changing the signing identity (the workflow ref plus the OIDC issuer that key
`seen.json`) resets rollback protection for every client. That is a consequence of
rotation: a new identity looks like a first run. Record it in the key-custody decision
alongside where the key lives.

Rotation does not rewrite a single advisory record. IDs, digests, and bytes are all
unchanged, so a mirror that tracks records rather than signatures sees no diff at all.
That is a consequence of two design choices rather than a coincidence, and it is
enforced by tests (`TestRotationLeavesRecordsUntouched`) because prose alone would not
survive a refactor:

- Signatures are **detached**. Nothing signature-shaped is ever stored inside a record,
  so re-signing only replaces the `.sig` files beside it. Inlining a signature or
  certificate into a record would make every rotation churn the entire feed.
- Signatures cover **canonical bytes**, not the file as it sits on disk. A mirror that
  re-serialises a record with different indentation still verifies, so rotation does
  not force every downstream copy into one exact byte layout.

## Which findings become advisories

Two filters, both deliberate:

**Only servers with a published package.** Advisories are minted for servers launched
via `npx`/`bunx`/`pnpx`/`yarn dlx` (npm) or `uvx`/`pipx` (PyPI). A server run from a
local path, a container, or reachable only at a URL has no coordinate to key an OSV
record on, so it is counted in the summary rather than given an invented one.

**Only findings that assert a vulnerability.** Positive signals (`CFHYG-004`,
`ATTEST-010`), first-run bookkeeping (`RUGPULL-000`), and operational errors
(`BL-001`) are excluded — an advisory that claims nothing cannot be remediated.

Findings that map to the same advisory ID collapse into one record. A feed keyed by
package describes the package, not each host that runs it.

Everything filtered out is reported:

```
23 advisories written to examples/feed
Skipped: 4 finding(s) on servers with no published package
Skipped: 11 finding(s) merged into an existing advisory
Skipped: 2 informational finding(s) that assert no vulnerability
```

## Secret redaction

Analyzers redact their own evidence, and `advise` runs every advisory's prose through
the credential patterns again before writing. An advisory is a published artifact; a
secret that reaches one cannot be un-published.

## CLI reference

### `mcp-audit advise [TARGET]`

| Option | Default | Purpose |
| --- | --- | --- |
| `--out`, `-o` | `feed` | Directory to write the feed into |
| `--input` | — | Reuse a `scan --format json` result instead of re-scanning |
| `--sign` / `--no-sign` | `--sign` | `--no-sign` writes an unsigned feed |
| `--key-alt` | `cosign` | Signing backend: `cosign` or `minisign` |
| `--key` | `$MCP_AUDIT_SIGNING_KEY` | Private project key to sign with (required by `--sign`) |
| `--keyless` | off | Sign via cosign ambient OIDC instead of a key (not for a published feed) |
| `--severity-threshold` | `medium` | Minimum finding severity to publish |
| `--observation` | `all` | `package-intrinsic`, `deployment`, or `all` |
| `--published-at` | — | Pin the timestamp (`YYYY-MM-DDTHH:MM:SSZ`) |
| `--snapshot-version` | — | Monotonic index counter. Required with `--sign` unless `--previous-index` is given |
| `--previous-index` | — | Previous `index.json`; next `snapshot_version` is previous + 1 |
| `--expires` | publish + 14 days | RFC 3339 expiry on the index (fixture override) |
| `--ttl-days` | `14` | Used when `--expires` is omitted |
| `--offline` | off | Fail rather than make any network call |

Exit codes: 0 success, 2 error.

### `mcp-audit feed verify DIRECTORY`

| Option | Default | Purpose |
| --- | --- | --- |
| `--key-alt` | `cosign` | Backend the feed was signed with |
| `--public-key` | — | Public key for key-based verification |
| `--identity` | — | Expected certificate identity regex (keyless) |
| `--oidc-issuer` | — | Expected OIDC issuer regex (keyless) |

Exit codes: 0 all verified, 1 one or more failed, 2 error.

## Consuming the feed with osv-scanner

`osv/` is already the offline-database directory `osv-scanner` resolves, so point it
there and scan — no files to move:

```bash
OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY="$PWD/feed/osv" \
  osv-scanner scan source --offline ./your-project
```

```
Loaded npm local db from feed/osv/osv-scanner/npm/all.zip
Total 1 package affected by 8 known vulnerabilities (0 Critical, 4 High, 3 Medium, 1 Low)

| https://osv.dev/x_MCPSA-2fa2713d0891 | 8.6 | npm | mcp-audit-fixture-github-server | 1.0.0 |
```

osv-scanner looks for `{cache_dir}/osv-scanner/{ecosystem}/all.zip`, which is why the
export is split per ecosystem rather than shipped as one archive. Verified against
osv-scanner 2.3.5.

`osv/all.json` is every record as a flat array and `osv/all.zip` is every record in one
archive, for consumers that want the whole feed without walking the tree.

## See also

- `examples/feed/` — a complete **unsigned** feed you can inspect and integrity-check today. It is unsigned by design (no private key in the repo).
- `fixtures/vulnerable-servers/` — the three configurations it was built from
- `docs/owasp-mapping.json` — the finding-ID to OWASP MCP Top 10 mapping CI enforces
- [OSV schema](https://ossf.github.io/osv-schema/) — vendored at
  `src/mcp_audit/advisory/osv_schema/osv-1.6.0.json`
- [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) — JSON Canonicalization Scheme
