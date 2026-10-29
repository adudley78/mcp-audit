# Air-gapped use: scan and `affected` from a signed bundle

`mcp-audit scan` and `mcp-audit affected` already run with no network by default, but they use the registry, malicious-package list, research records and exploit signals (KEV, EPSS) that shipped inside the installed copy. On a machine that is updated once a quarter, those are a quarter old. A **bundle** is a directory you carry across the gap that holds current copies of the same four files, signed, so the far side can trust and date them.

## What a bundle holds

```
bundle/
  index.json, index.json.sig, advisories/…   the published advisory feed
  data/known-servers.json                    the registry
  data/known-malicious.json                  known-malicious packages
  data/research-records.json                 credited research records
  data/exploit-signals.json                  CISA KEV, FIRST EPSS, public-PoC flags
  bundle.json, bundle.json.sig               manifest: a SHA-256 for each data file and
                                             for the feed index, signed with the feed's key
```

## Use it

On the far side, install mcp-audit and [minisign](https://jedisct1.github.io/minisign/) (it is the only other thing needed), copy the bundle in, and run:

```bash
mcp-audit feed verify ./bundle --key-alt minisign       # optional: check it by itself
mcp-audit scan --bundle ./bundle
mcp-audit affected CVE-2026-59822 --bundle ./bundle
```

Every run starts with a line such as `Signed bundle 2026-10-29, 2 days old, feed snapshot 5 (verified, no network)`; `affected` also puts it in its `sources`. `--bundle-key PATH` (or `$MCP_AUDIT_SIGNING_PUBKEY`) names a different minisign public key than mcp-audit's own project key.

## What is checked, and what stops the run

`--bundle` verifies exactly as `feed verify` does, and then the manifest. If any of these fails, the command prints every reason and exits 2; it never falls back to the installed data.

- The feed is **signed**. An unsigned feed passes `feed verify` as "integrity only"; a bundle is refused.
- The feed's signatures and digests verify, it has not **expired**, and it is not older than a feed this machine has already accepted. There is no `--allow-expired`. A feed lives about 14 days, so a bundle carried across a long gap must be refreshed before it is used.
- `bundle.json` is signed and names this feed's index.
- Each of the four data files is present, a regular file inside the bundle (no symlinks), and matches its digest. A file the manifest does not list is refused.

`--bundle` cannot be combined with `--registry`, `--live`, `--check-vulns`, `--verify-hashes`, `--verify-signatures` or `--connect`: it is the no-network path, and mixing in a network flag would make "no network" untrue.

## Getting the published bundle

The weekly signed feed is also a bundle: every publish adds `data/` and a signed `bundle.json` to the `feed` branch, signed with mcp-audit's project key (the one `--bundle` uses by default). On a connected machine:

```bash
git clone --depth 1 --branch feed https://github.com/adudley78/mcp-audit.git bundle
mcp-audit affected CVE-2026-59822 --bundle ./bundle     # check it before you carry it
```

Then carry the `bundle` folder across. The registry, malicious list and research records are the ones on `main` when the feed was published; KEV and EPSS are fetched fresh at publish time, falling back to the committed copy when a source is down or returns less than it holds. A feed expires 14 days after it is published, so fetch a new one at least that often.

## Making your own

`scripts/build_bundle.py --feed ./feed --out ./bundle --private-key KEY --public-key KEY.pub` copies a signed feed and the four data files from a checkout and signs the manifest (`--in-place` adds them to the feed directory instead). `scripts/build_bundle.py --verify ./bundle --public-key KEY.pub` checks one. A bundle signed with your own key is verified with `--bundle-key your.pub`.

The bundle is copied to a private temporary directory before anything is checked, and both the checks and the scan use that copy, so changing the original while a command runs has no effect.

## Limits

- minisign only. A feed signed with cosign keyless is not supported here.
- Within one feed snapshot nothing orders two bundles: the manifest names the feed index, not a data version, so how current the data files are is up to whoever signs the bundle. `created_at` in `bundle.json` says when it was made.
- A bundle is as old as its feed; the published one is refreshed weekly. `scan` and `affected` print the date; read it.
- The bundle replaces the four data files only. `lock`, `vet` and the other commands still read the installed copies.
