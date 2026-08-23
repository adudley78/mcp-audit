# Offline Sigstore verification — empirical findings (R27)

## Scope: this is about cosign's keyless path, not mcp-audit's advisory feed

**mcp-audit's advisory feed is signed with a static project key** (see `CLAUDE.md` and
`src/mcp_audit/advisory/sign.py`), verified with:

```bash
cosign verify-blob --bundle <file>.sigstore.json --key <pubkey> --insecure-ignore-tlog <blob>
```

That command touches no Fulcio certificate, no Rekor transparency log, and no TUF trust root.
**It is offline by construction and always has been.** Nothing in this document changes that or
applies to it.

Everything below is about cosign's separate **keyless** path — ambient-OIDC signing, verified
with:

```bash
cosign verify-blob --bundle <file>.sigstore.json \
  --certificate-identity <identity> --certificate-oidc-issuer <issuer> \
  [--trusted-root <file>] <blob>
```

mcp-audit exposes this only as `--keyless` on `advise --sign`, for one-off attestations —
`CLAUDE.md` states it must never become the feed's default, and it remains that way. A
2026-08-20 decision briefly proposed keyless *for the feed itself*; that decision was reversed
on 2026-08-23 (`humans/decisions/2026-08-23-signing-key-custody-reversed.md` in the `marcus`
repo) precisely because of what this document found. Read what follows as "what keyless would
have cost," not as "what verifying mcp-audit's feed costs."

**This document records a test result. It is not a recommendation.** The decision it fed
is Adam's and is recorded in `humans/decisions/` (in the `marcus` repo), originally as an
update to `2026-08-20-signing-key-custody.md` and now folded into the 2026-08-23 reversal above.

## The question

`2026-08-20-signing-key-custody.md` chose Sigstore keyless signing for the advisory feed and
named its own load-bearing assumption: *"if it turns out offline bundle verification cannot be
made to work cleanly, that is a reason to revisit this decision."* That assumption had never
been tested against a real signed artifact in a real networkless environment. This experiment
tests it. It changes nothing under `src/`.

## Answer: YES, qualified

A user with no network access can fully verify a keyless Sigstore-signed artifact — **but only
using the explicit `--trusted-root <file>` flag with a trust-root file fetched in advance.**
`cosign verify-blob` without that flag makes a live network call **on every invocation**,
regardless of whether a local TUF cache already exists, and fails closed (not silently, not by
falling back to the cache) when that call cannot complete. There is no "it just works offline if
you've used it before" behavior — the offline path has to be deliberately chosen with a flag, or
it is not offline at all.

The good news is in the second qualification: the exported trust-root file itself, once fetched,
was **not** observed to expire on the short cadence its underlying TUF metadata does. See
"Trust-root expiry" below.

## Versions tested

| Component | Version | Source |
|---|---|---|
| cosign | **v3.0.6** (`GitCommit f1ad3ee952313be5d74a49d67ba0aa8d0d5e351f`, built 2026-04-06) | Installed via `sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6` (pinned tag `v4.1.2`) |
| cosign-installer | v4.1.2 | `sigstore/cosign-installer` |
| Runner | `ubuntu-latest` (GitHub-hosted) | GitHub Actions |
| sigstore-python | not tested | Out of scope — mcp-audit's own `attestation/sigstore_client.py` and the signing-key-custody decision are both built on **cosign**, not sigstore-python; that is the tool this decision actually depends on |

**This finding is pinned to cosign v3.0.6.** Cosign's own maintainers have stated in a public
issue that this exact behavior (`--offline` being non-functional, and default verification
requiring a live TUF fetch) changed across v2 and v3, and that they intend to keep changing it
(`sigstore/cosign#4454`). Re-test before relying on this document against a different version.

Docs read before testing: the current `cosign verify-blob` reference
(`https://github.com/sigstore/cosign/blob/main/doc/cosign_verify-blob.md`) and the cosign
README's own "airgapped verification" section, both of which already show `--trusted-root
<file>` as the offline recipe rather than the plain default invocation. The test below exists to
confirm the actual binary behaves that way, not to take the docs' word for it.

## How the networkless environment was constructed

**`unshare --net`**, not a documented flag. Every verification command ran under:

```bash
sudo --preserve-env=HOME unshare --net -- "$(command -v cosign)" verify-blob ...
```

`unshare --net` puts the process tree in a fresh network namespace with **no interfaces at
all** (not even a configured loopback route out) — functionally identical to `docker run
--network none`, chosen because the GitHub-hosted runner has no Docker-in-Docker `--network
none` primitive readily available but does have `unshare` (part of `util-linux`) and
passwordless `sudo`. `sudo` was invoked instead of an unprivileged user namespace because that
is the reliable path on a GitHub-hosted runner; the important property — zero routes, zero
interfaces reachable from inside the namespace — is unaffected by which of the two grants the
namespace.

This was verified as real, not assumed:

```console
$ curl --max-time 5 -sS -o /dev/null -w '%{http_code}\n' https://1.1.1.1
200                                                    # outside the namespace: works

$ sudo unshare --net -- curl --max-time 5 -sS -o /dev/null -w '%{http_code}\n' https://1.1.1.1
curl: (7) Failed to connect to 1.1.1.1 port 443 after 0 ms: Couldn't connect to server
000                                                    # inside: fails in 0ms, not a timeout
```

The 0ms failure time matters: it is `ENETUNREACH` — there is no route, so the kernel refuses the
connection immediately. It is not a slow DNS timeout that happened to expire, which would leave
open the possibility of a network call succeeding under slightly different timing.

Full harness: `.github/workflows/experiment-r27-offline-sigstore-verify.yml` (merged to `main`
in [#77](https://github.com/adudley78/mcp-audit/pull/77) — `workflow_dispatch` only, signs
nothing real, never runs on a schedule). The decisive run is
[actions/runs/32637908659](https://github.com/adudley78/mcp-audit/actions/runs/32637908659).

## Step 2 — the signed artifact

`sign-blob --yes --bundle artifact.sigstore.json artifact.txt` ran in a `workflow_dispatch` job
with `permissions: id-token: write`, using cosign's ambient-OIDC detection (no flags requesting a
specific identity provider — cosign recognized the GitHub Actions environment on its own). The
resulting Fulcio certificate (decoded with `openssl x509 -noout -text`):

```
Issuer: O=sigstore.dev, CN=sigstore-intermediate
Validity
    Not Before: Aug 23 11:55:42 2026 GMT
    Not After : Aug 23 12:05:42 2026 GMT          # 10-minute ephemeral cert — by design
X509v3 Subject Alternative Name: critical
    URI:https://github.com/adudley78/mcp-audit/.github/workflows/experiment-r27-offline-sigstore-verify.yml@refs/heads/main
1.3.6.1.4.1.57264.1.1 (OIDC issuer):
    https://token.actions.githubusercontent.com
1.3.6.1.4.1.57264.1.21 (run URL):
    https://github.com/adudley78/mcp-audit/actions/runs/32637908659/attempts/1
```

The bundle embeds a real, publicly-checkable Rekor entry:

```json
"tlogEntries": [{"logIndex": 2570989886, "kindVersion": {"kind": "hashedrekord", "version": "0.0.1"}, "integratedTime": 1787486143}]
```

This is the real keyless flow the custody decision proposes, not a simulation: ambient OIDC →
Fulcio-issued short-lived cert → Rekor transparency-log entry → a self-contained bundle.

## Step 3 — offline verification results

All seven commands below ran inside `unshare --net`, i.e. with genuinely zero network egress.
Full transcript: job `verify-offline` in
[run 32637908659](https://github.com/adudley78/mcp-audit/actions/runs/32637908659).

| # | Setup | Command (abbreviated) | Result | Why |
|---|---|---|---|---|
| 1 | Fresh install, **no** cached trust root, **no** `--trusted-root` flag | `verify-blob --bundle b.json --certificate-identity … --certificate-oidc-issuer … artifact.txt` | **FAIL** | `Error: trusted root is required when using new bundle format` — preceded by a network-lookup attempt and failure (`dial udp 127.0.0.53:53: connect: network is unreachable`) |
| 2 | `cosign initialize` run first (trust root cached), then same command with **no** `--trusted-root` | same | **FAIL** — identical error | The cached copy is never consulted. The default path always attempts a *live* TUF refresh and refuses to fall back to a local cache when that refresh fails |
| 3 | `--trusted-root <exported file>`, tampered artifact (1 byte flipped) | `verify-blob --bundle b.json --trusted-root trusted_root.json … artifact.tampered.txt` | **FAIL, correctly** | `failed to verify signature: could not verify message: invalid signature when validating ASN.1 encoded signature` |
| 4 | `--trusted-root <exported file>`, wrong `--certificate-identity` | same, with a fabricated identity string | **FAIL, correctly** | `failed to verify certificate identity: no matching CertificateIdentity found, last error: expected SAN value "https://github.com/someone-else/…", got "https://github.com/adudley78/mcp-audit/…"` |
| 5 | `--trusted-root <exported file>`, TUF cache **deleted entirely**, correct artifact | same, correct inputs | **PASS** — `Verified OK` | The exported file is sufficient on its own; no `~/.sigstore` cache needed at all |
| 6 | Cache re-populated, system clock advanced 3 days past the cached `timestamp.json`'s own `expires`, **no** `--trusted-root` | same as #1/#2 | **FAIL** — identical error | Same as #2: the implicit path never works offline, staleness is not the variable |
| 7 | Same advanced clock, **same exported file** from step 5 | `--trusted-root trusted_root.json`, correct inputs | **PASS** — `Verified OK` | The exported file was not affected by its parent TUF metadata's expiry — see below |

Tests 3 and 4 were deliberately re-run using `--trusted-root` (not the bare flags from the first
draft of this experiment) after tests 1–2 showed the no-flag path fails for an unrelated reason
(no trust root at all) that would have made a tamper/identity failure indistinguishable from a
missing-trust-root failure. Isolating the variable was necessary to make tests 3–4 mean anything.

## Required user-facing flags

The only invocation that verifies offline, in any of the seven configurations tested:

```bash
cosign verify-blob \
  --bundle artifact.sigstore.json \
  --trusted-root trusted_root.json \
  --certificate-identity "https://github.com/OWNER/REPO/.github/workflows/WORKFLOW.yml@refs/heads/main" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  artifact.txt
```

Two of these four flags are not optional extras — they are the entire offline story:

- **`--trusted-root <file>`** is the only thing that makes verification offline-capable at all.
  Omitting it (tests 1, 2, 6) fails closed with a network error every time, cache or no cache,
  fresh clock or advanced clock.
- **`--certificate-identity` and `--certificate-oidc-issuer`** are not optional hardening —
  keyless verification without them is not verification of anything in particular (cosign
  requires one identity flag or its regexp equivalent for keyless flows). A user must be told
  the exact expected identity string; there is no safe default.

A user (or mcp-audit, on their behalf) also has to have obtained `trusted_root.json` at some
point while online. That file was produced here with `cosign initialize` and copied out of
`~/.sigstore/root/<mirror>/targets/trusted_root.json`; a shipping product would bundle this file
directly rather than ask a user to run `cosign initialize` themselves.

## Trust-root findings (the residual-gap question)

Three sub-questions, answered in order:

**Does offline verification require a pre-fetched trust root?** Yes, unconditionally. There is
no configuration under which `cosign verify-blob` succeeds offline without either
`--trusted-root <file>` or (untested here, but implied by the same error text) an equivalent
embedded/pinned material. A local `~/.sigstore` cache from a prior `cosign initialize` does
**not** count — tests 2 and 6 prove the implicit path re-attempts a live fetch on every
invocation and refuses to use what it already has on disk.

**Does that root itself expire?** This is the one place this finding is a genuine *qualified*
yes rather than a clean yes. The **TUF metadata** governing the implicit/cached path has a short
expiry by design: in the live run, `timestamp.json` (2026-08-23) expired 7 days later
(`2026-08-30T01:53:45Z`), while `root.json` (~3 months) and `snapshot.json`/`targets.json`
(~10 years) were much longer-lived. But that expiry is irrelevant to the path that actually
works offline: test 7 took the exact same exported `trusted_root.json` file from test 5, advanced
the system clock 3 days past `timestamp.json`'s expiry, and verification still succeeded with no
warning or error. The exported file is a snapshot of `certificateAuthorities` / `tlogs` entries
with their own multi-year `validFor` windows (the active Fulcio intermediate CA in this run's
trust root was valid from `2022-04-13` with no `end` date set) — those are what `--trusted-root`
actually checks, not the TUF timestamp/snapshot freshness that governs *live* refreshes.

**What happens to a user whose cached root has aged out with no network?** Two different
failure shapes, depending on which path they were using, and the answer is better than R9's feed
expiry problem, not the same shape:

- If they were relying on the *implicit* path (no `--trusted-root`), they were never actually
  verifying offline in the first place — tests 2 and 6 show that path needs network regardless
  of cache state, so "aged out" isn't a distinct failure mode from "never worked offline."
- If they have an exported `trusted_root.json` file, this test found no evidence it expires on
  any timescale shorter than the underlying Sigstore CA/log key rotations — which are rare,
  multi-year, publicly announced events, not a rolling TTL a solo maintainer has to keep feeding.
  **This test only advanced the clock 3 days past the short TUF `timestamp.json` boundary, not
  months or years** — it did not probe the actual multi-year CA `validFor` boundary, since doing
  so would require either an already-expired historical trust root or waiting years. The absence
  of a short rolling expiry is demonstrated; the eventual multi-year boundary is inferred from
  the file's own contents, not independently tested.

## What this does not test

- sigstore-python was not exercised; this repository's Sigstore dependency is cosign.
- Container image signing/verification (`cosign sign` / `cosign verify`) was not tested — only
  `sign-blob` / `verify-blob`, which is the relevant path for a feed directory of files.
- The multi-year CA validity boundary itself was not crossed, per above.
- Sigstore service availability (Fulcio/Rekor being down at sign time) is a different failure
  mode from offline *verification* and was not in scope.
