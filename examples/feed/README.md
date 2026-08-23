# Example advisory feed

A complete feed produced by `mcp-audit advise`. It exists so you can inspect the
layout, wire up a consumer, and confirm your tooling works before pointing it at
anything that matters.

**This example is unsigned, deliberately.** Signing it reproducibly would require
committing the private key that signed it, which is strictly worse than shipping it
unsigned. The published feed *is* signed with the project key — see
"Signing" below — and the signing path is proven by `tests/test_advisory_sign.py`,
which mints an ephemeral key pair, signs a feed, verifies it, and asserts that a
mutated record fails.

## Verify it

```bash
mcp-audit feed verify examples/feed
```

Every record reports `OK`, the command exits 0, and the verdict states plainly that
the feed is unsigned: each record matches the digest `index.json` holds for it, but
nothing attests to *who* produced it.

Integrity checking works without signatures because the index records a
`canonical_sha256` per advisory. Edit any field in a file under `advisories/` and run
the command again — it exits 1 and names the record whose digest no longer matches.

## Consume it

`osv/` is already the offline-database directory `osv-scanner` resolves, so nothing
needs rearranging first:

```bash
OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY="$PWD/examples/feed/osv" \
  osv-scanner scan source --offline ./your-project
```

A project depending on `mcp-audit-fixture-github-server@1.0.0` is reported against the
records here. Verified against osv-scanner 2.3.5.

## What is in here

```
index.json                     every advisory summarised, with a digest per record
advisories/<id>.json           one OSV 1.6.0 record per advisory
osv/all.json                   every record as a single JSON array
osv/all.zip                    every record in one archive
osv/osv-scanner/<eco>/all.zip  the offline-database layout osv-scanner resolves
```

A signed feed additionally carries `<file>.sig` next to every advisory and the index,
plus `<file>.sigstore.json` when signed with cosign.

## Where the records came from

Scanning `fixtures/vulnerable-servers/`, a set of three deliberately insecure MCP
server configurations covering the finding classes `mcp-audit fix` remediates —
`hardcoded-secret`, `command-injection`, and `excessive-scope` — plus a typosquatted
package name and several unpinned dependencies.

Two of the three fixture packages (`mcp-audit-fixture-github-server`,
`mcp-audit-fixture-shell-runner`) are named so they cannot be mistaken for real
software. **These advisories make no claim about any real published package.** The
third names a typosquat of a genuine package, which is the vulnerability itself
rather than an allegation against its target.

Read `affected[].database_specific.observation` before acting on any record in a real
feed: `package-intrinsic` means the defect is in the published package, `deployment`
means it is in how an operator configured it. Only the former is the maintainer's
problem.

## Signing

The published feed is signed with a **static project key**, not Sigstore keyless.
A feed is consumed offline, reproducibly, and against a stable project identity —
keyless binds each signature to whoever ran the build and needs a Rekor round-trip to
verify. See the "Signing" and "Key custody" sections of `docs/advisory-feed.md`.

## Regenerating

`SOURCE_DATE_EPOCH` pins every timestamp, so these files are byte-reproducible:

```bash
SOURCE_DATE_EPOCH=1769817600 \
  mcp-audit advise fixtures/vulnerable-servers \
    --out examples/feed \
    --no-sign \
    --severity-threshold info \
    --expires 2099-01-01T00:00:00Z
```

`--expires 2099-01-01T00:00:00Z` is **fixture-only**. A real publish uses the 14-day
TTL (`published_at` + `--ttl-days`). Pinning a far-future expiry here keeps
`mcp-audit feed verify examples/feed` passing for as long as the committed copy is
meant to be inspectable; it is not the production SLA.

Regenerating replaces this file, so restore it from git afterwards.
