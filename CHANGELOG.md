# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [Unreleased]

### Added

- **The advisory feed now has a real, fetchable publish destination.** `.github/workflows/advisory-feed-publish.yml` previously uploaded the weekly unsigned feed to a GitHub Actions artifact — reachable only with repository access, gone after 30 days. It now commits to a dedicated orphan `feed` branch, fetchable by anyone at `https://raw.githubusercontent.com/adudley78/mcp-audit/feed/index.json`. The workflow is split into `build` (`contents: read`; writes the candidate feed and diffs it against the currently-published one) and `publish` (`contents: write`; only runs when `build` found a real change, so a republish of identical findings under a new timestamp makes no commit — `scripts/feed_diff.py` ignores the `published`/`modified` fields every build stamps fresh, which a byte-for-byte diff cannot). `snapshot_version` reads the live `feed` branch's `index.json` via `--previous-index` on every run, not a local file, so it stays monotonic across runs. Still unsigned — no `--sign`, no key, no secret; see `docs/advisory-feed.md`. See `humans/decisions/2026-08-23-feed-signing-and-publishing.md` in the `marcus` repo.

### Security

- **`main` now has branch protection; the `pypi` deployment environment now has a branch/tag restriction. Both were previously conventions enforced by nobody.** `gh api` showed `main` with no branch protection at all (404) and the `pypi` environment with no protection rules and no branch restriction — while `release.yml` described that environment in a comment as "defence in depth against a forked workflow trying to impersonate the release pipeline." The control existed in the comment, not in the settings; this is the precondition the recommended signing-key custody model depends on (an environment secret restricted to `main` means nothing if anything can reach `main`). Enforced now: `main` requires 14 named status checks from `ci.yml` to pass (branches must be up to date) and blocks force-pushes and branch deletion; PR reviews, signed commits, and admin enforcement were deliberately left off — Adam self-merges, and admin enforcement is off so a wrong required-check name has an escape hatch rather than blocking every PR. The `pypi` environment now has a deployment branch/tag policy restricting it to `main` and `v*.*.*` tags, matching how `publish-pypi` already only runs on a tag push; no required reviewers, since that job is fully automated and tag-triggered. Proved both directions before merging anything: a throwaway PR with a failing check was rejected by GitHub ("the base branch policy prohibits the merge"), and a `workflow_dispatch` dry-run of `release.yml` still built all four binaries and skipped `Publish to PyPI` exactly as before. See `humans/decisions/2026-08-23-signing-key-custody-recommendation.md` in the `marcus` repo.

### Docs

- **README's `mcp-audit scan` flags table was missing `--verify-signatures` and `--check-vulns`.** R26 found and deliberately did not fix this while asserting other template/README facts; `--verify-signatures` was documented in README's Install prose but not its CLI flags table, and `--check-vulns` appeared in neither. Both added to the flags table. Docs only, no behaviour change.
- **The release template's Install / coverage / integrations copy now has an assertion, not just a comment asking someone to remember.** `.github/release-notes-template.md` duplicates a slice of README.md's copy because the GitHub Release page has to carry install instructions inline; its header comment admitted CI did not verify any of it. `tests/test_release_notes_facts.py` extracts and compares the facts that actually go stale between the two files — PyPI package name, CLI command name, binary asset filenames (checked against the PyInstaller specs, since README never enumerates them), SBOM filenames, the supported-host list, the test count (cross-checked against README, not re-derived from `scripts/update_test_count.py`), and the poisoning/credential/SAST/exploit-fixture/benchmark-server counts — as values, not prose, so a reworded sentence cannot fail it. Building the fact list surfaced a real, current bug: the template's tagline claimed support for **Zed**, which `discovery.py` documents as deliberately unsupported (different config schema) and which appears nowhere in README's actual 8-client table; replaced with Windsurf, an already-supported client. The template's header comment now states which facts are asserted and which prose remains unchecked, instead of a blanket disclaimer. No release workflow or template structure changed; see `#75`.
- **Offline Sigstore *keyless* verification, tested empirically, not assumed — and found not to apply to the advisory feed.** A short-lived proposal to sign the advisory feed with Sigstore keyless named its own condition: if offline bundle verification can't be made to work cleanly, that's a reason to revisit it. A real keyless-signed artifact (ambient GitHub OIDC → Fulcio cert → Rekor entry) was verified inside a network namespace with zero interfaces (`unshare --net`), both a correct-input and a tampered-input case. Result: keyless offline verification works, but only via `cosign verify-blob --trusted-root <file>` — the default/no-flag path makes a live network call on every invocation regardless of any local cache, and fails closed when it can't complete one. The exported trust-root file itself was not observed to expire on the short cadence its parent TUF metadata does. **The advisory feed does not use this path** — it signs with a static project key (`CLAUDE.md`; unchanged by this finding), verified with `cosign verify-blob --key <pubkey> --insecure-ignore-tlog`, which touches no Fulcio/Rekor/TUF machinery and was already offline by construction. The keyless-for-the-feed proposal was reversed as a result. No product code changed; see `docs/offline-verification-findings.md` (now scoped at the top) and the removed throwaway experiment workflow that produced the evidence.

### Added

- **Weekly read-only registry drift check** (`.github/workflows/registry-drift.yml`). Monday 14:00 UTC plus `workflow_dispatch`. Runs `scripts/audit_registry.py` in its default report-only mode, never `--stamp`, and fails the job if any entry is `MISSING` or if `attestation_expected: true` classifies `NO_PROVENANCE`. Does not fail on `THIN` or stale `last_verified`. Hashes `registry/known-servers.json` before and after and fails if the file moved. Each run uploads a counts artifact so provenance-adoption / disappearance is a time series without a bot commit. See `docs/registry.md`.
- **Advisory feed freshness** (`snapshot_version`, `published_at`, `expires` on `index.json` only; `feed_version` 1.1). `mcp-audit feed verify` hard-fails on expiry or rollback. `mcp-audit scan --advisory-feed DIR` skips matching on an expired feed, prints it, emits `feed_status` on JSON/SARIF, and still completes. No `--allow-expired`. Client `seen.json` is keyed on signing identity, not a certificate. Weekly unsigned publish job (`.github/workflows/advisory-feed-publish.yml`) — **does not `--sign`**; the first signed publish is gated on that job being the publisher plus a key-custody decision. See `docs/advisory-feed.md`.
- **CycloneDX 1.5 SBOMs on each GitHub Release.** Per-binary `mcp-audit-<platform>.cdx.json` inventories the PyInstaller PYZ (what that binary actually runs). `mcp-audit-scanner-wheel.cdx.json` inventories a default wheel install. Does not change `mcp-audit sbom`. See `docs/building-binaries.md`.

### Fixed

- **Registry: `attestation_expected: true` was never checked against a real provenance publish for 20 of 50 entries.** The flag turns a missing Sigstore attestation into a MEDIUM finding (`ATTEST-013`) for every user who scans that package — so a `true` the package does not actually publish is the same class of defect as vouching for a nonexistent name. `scripts/audit_registry.py` now queries the live npm attestations API / packument `dist.attestations` (SLSA only) and the PyPI PEP 740 integrity API for every flagged entry. This run: **11 flags cleared to `false`** (npm attestations API 404, including `@modelcontextprotocol/server-github` and `-postgres` despite hash pins); **9 kept** (real SLSA / PEP 740); **0 UNCHECKED**. The script never sets the flag to `true`.
- **Registry: 25 of 50 entries still advertised `last_verified: 2026-04-15` after the 2026-08-20 live audit that confirmed them as OK.** That field is published as `entry_updated` on every mcp-audit.dev verdict page. `--stamp` now writes today's date onto entries the *current* run classifies as OK, and only those. This run stamped **49** OK entries to `2026-08-22`; `@playwright/mcp` stayed THIN (version `0.0.79`, same bucket as PR #41) and was not stamped. Default remains report-only.
- **Smoke test leaked `mcp-audit watch` after Check 9.** `Popen.kill()` on `uv run` or a PyInstaller onefile parent left the watch child running; the local hang attributed to the watcher was leftover processes, not a `_scan_lock` deadlock. The smoke script now starts a process group and kills the tree, and each command has a 90s timeout.
- **The advisory feed's `publish` job skipped the commit when advisory content was unchanged — which froze `expires` on a feed with a 14-day TTL, since the feed is built from fixtures and content rarely changes.** R30 added that skip as an idempotence measure, treating `published`/`modified`/`expires` as metadata rather than content; it worked exactly as designed (`Feed unchanged`, no commit, twice) and the live published feed was on track to hard-fail every `mcp-audit feed verify` starting 2026-09-06 with nobody having touched anything. `expires` is content — a feed asserting "trust me until the 6th" is a different statement each week even when the advisory list is identical. `publish` now runs unconditionally on every scheduled execution; `scripts/feed_diff.py` still runs every build but only shapes the commit message (`feed: refresh expiry (snapshot N, K advisories, no content change)` vs. `feed: M advisories changed (snapshot N, K advisories)`), never gates it. `snapshot_version` therefore increments on every publish, including refresh-only ones, matching the R9 design's monotonic-counter guarantee (never reused, never decreasing). A new, independently-scheduled, read-only canary (`.github/workflows/advisory-feed-freshness-canary.yml`, `scripts/check_feed_freshness.py`) now fails loudly if the live published `expires` is ever less than one publish interval away — the signal that the publisher itself has stopped running, which nothing previously detected. Still no `--sign`, no key, no secret, and the `build`/`publish` permission split from R30 is unchanged.

### Changed

- **GitHub Release notes are composed from the evergreen template plus this file's section for the tag.** `.github/release-notes-template.md` no longer holds Highlights / What's new / a security banner. `scripts/compose_release_notes.py` splices `## [X.Y.Z]` at a marker and fails the release if that heading is missing, so one release's notes cannot silently become the next's. See `.github/workflows/release.yml`.
- **The standalone binary no longer bundles the MCP SDK.** `--connect` from a GitHub Release binary now prints an install hint instead of connecting. That was never a documented capability of the binary — it worked only because release used `uv sync --all-extras` and the specs did not exclude `mcp` and its server-side transitives (starlette, uvicorn, python-multipart, pydantic-settings). `--connect` is pip-install-only, same policy as `[attestation]`/`sigstore`. Users who need it should `pip install 'mcp-audit-scanner[mcp]'`.
- CI `binary-smoke` and the release `build` job now share `.github/actions/build-binary/` (CPython **3.12.14**, `uv sync --all-extras`, spec, PyInstaller). See `docs/building-binaries.md`.

### Docs

- **Standalone GitHub Release binaries take about ten seconds to start on each launch** (PyInstaller onefile unpack). Documented in `docs/building-binaries.md` and the README install note.
- **`docs/contributors.md`: added a Registry Contributors section** for the three maintainers who listed their servers (`screenpipe-mcp`, `@palisadeemail/mcp`, `docpull`). Separate from the detection-rule bounty. "How to get listed here" now covers rules, code/infra, and registry submissions.

---

## [0.15.0] - 2026-08-22

### Security

- **`scan --format sarif`, the Nucleus FlexConnect push, and the snapshot export (`mcp-audit snapshot`) leaked this scanning host's absolute config path — including your home directory and OS username — into output designed to leave the machine.** SARIF's `physicalLocation.artifactLocation.uri` and result message text, Nucleus's `finding_path` and description/remediation fields, and all three snapshot formats (native, CycloneDX AI/ML-BOM, `--stream` NDJSON) all copied the scanned config's real absolute path — e.g. `/Users/yourname/.cursor/mcp.json` — verbatim. If you ran `mcp-audit scan --format sarif` in CI and uploaded the result to GitHub Code Scanning, your home directory and OS username were published to GitHub and visible to anyone with read access to that repository; the same exposure applied to anything sent through `push-nucleus` or `mcp-audit snapshot`. **No credentials, secrets, or file contents were exposed — only the path string and the username embedded in it.** Fixed in this release: paths are now redacted to a repo/cwd-relative form (falling back to `~/...`) at all four of these sinks before serialization; see "Fixed" below for the full mechanics. Terminal output and the HTML dashboard are unaffected by design — you're looking at your own machine there, and the real path is what you'd paste into a follow-up command. **Our assessment: this is low-severity information disclosure** — a username and local directory layout, sent only to a destination the user already configured mcp-audit to send it to, with no credential or file-content exposure — so we're disclosing it plainly in this changelog entry rather than filing a CVE or GitHub Security Advisory. If you disagree with that severity call, please open an issue or use [SECURITY.md](SECURITY.md)'s private reporting channel.

- **SARIF annotations from `mcp-audit scan --format sarif` have never attached to files in GitHub pull requests, and this release fixes it.** The same absolute URI above is also why: GitHub's `upload-sarif` action matches a SARIF result to a repository file by reading `artifactLocation.uri` literally, and does not resolve the `uriBaseId` mechanism the SARIF spec provides for exactly this case. An absolute `file:///Users/...` URI never matches a repo-relative file, so every annotation was silently dropped — no error, just no inline comment on the PR. If you concluded the GitHub Action's Code Scanning integration didn't support inline annotations, that wasn't a limitation of the setup; it was this bug. `artifactLocation.uri` is now a genuine repo/cwd-relative path with forward slashes on every platform, and annotations now attach as intended.

### Added

- **`mcp-audit advise <target>` — OSV-based signed advisory feed. EXPERIMENTAL.** Turns scan findings into OSV `schema_version` 1.6.0 advisory records (stable, content-derived `x_MCPSA-<12hex>` IDs — never a timestamp; see Fixed below) and publishes them as a signed, verifiable feed (`advisories/<id>.json`, `index.json`, an osv-scanner-consumable `osv/all.json`/`.zip`); `mcp-audit feed verify <dir>` checks one. There is no CVE/OSV/NVD equivalent for MCP servers today — this is the canonical machine-readable feed other registries, gateways, and scanners can consume. **This feature is marked experimental in its own `--help` text and at the top of `docs/advisory-feed.md`: the record format is not yet stable, and no mcp-audit-operated signing key exists yet — `--sign` requires you to bring your own `--key`/`$MCP_AUDIT_SIGNING_KEY`.** Expect breaking changes to the record shape before mcp-audit distributes a project key to sign against; don't build automation on today's exact field layout. MCP-specific fields live under `affected[].database_specific` (`owasp_mcp`, `mcp_transport`, `finding_class`, `mcp_audit_rule_id`, `verified_patch`, `mcp_observation`, `cvss_basis`); `owasp_mcp.py` remains the single source of truth for OWASP MCP Top 10 codes. Records are deterministic (RFC 8785/JCS canonical bytes, no host paths or timestamps from `datetime.now()`) and signed with a static project key via cosign (default) or minisign — `--keyless` is opt-in, never the default. Publishing is two-phase (`write_feed` → `sign_feed`); `index.json` is the integrity root (`canonical_sha256` per advisory, itself signed) and `verify_feed` fails on any advisory present on disk but absent from the index. The committed `examples/feed/` is intentionally unsigned (no private key in the repo) — integrity is still checked via `canonical_sha256`. New package `src/mcp_audit/advisory/` (`schema.py`, `classify.py`, `canonical.py`, `feed.py`, `sign.py`, `validate.py`, vendored `osv_schema/osv-1.6.0.json`), `src/mcp_audit/cli/advise.py` + `feed` sub-app, `src/mcp_audit/output/advisory.py`. 326 new tests across `test_advisory_canonical/_feed/_schema/_sign`, `test_cli_advise`, `test_output_advisory`. See `docs/advisory-feed.md`.

- **Registry: added `screenpipe-mcp` (npm, verified), `@palisadeemail/mcp` (npm, unverified), and `docpull` (PyPI, unverified) to `registry/known-servers.json`.** Submitted via the registry-submission issue template by [@louis030195](https://github.com/louis030195) ([#39](https://github.com/adudley78/mcp-audit/issues/39)), [@samuelchenardlovesboards](https://github.com/samuelchenardlovesboards) ([#38](https://github.com/adudley78/mcp-audit/issues/38)), and [@zacharyr0th](https://github.com/zacharyr0th) ([#35](https://github.com/adudley78/mcp-audit/issues/35)). `entry_count` is now 85 (see Fixed below for the net count).

### Fixed

- **Registry: removed or corrected 35 of 85 entries following a full live audit against the real npm/PyPI registries (`scripts/audit_registry.py`, see `registry-audit-2026-08-18.md`).** The registry contained entries for packages that do not exist at all in their declared ecosystem — 25 entries, **9 of them marked `verified: true` and attributed to Anthropic** (including `@modelcontextprotocol/server-fetch`, `-git`, `-gmail`, `-google-drive`, `-sentry`, `-sqlite`, `@anthropic-ai/mcp-server-puppeteer`, and the PyPI `mcp-server-filesystem`) — plus entries where the real publisher did not match what the registry claimed: a **security-research canary** (`theinfosecguy/npx-canary`, maintainer `node-canaries`) registered three times as `mcp-server-notion`/`-redis`/`-supabase`, and an unrelated third party's **placeholder-stub "farm"** (`hlos-ai/mcp-servers`, maintainer `ars923`) registered under seven major-vendor-implied names (`mcp-server-aws`/`-gcp`/`-azure`/`-heroku`/`-vercel`/`-stripe`, `mcp-perplexity`). All 35 of these have been removed. A further 8 entries were real packages with wrong or stale metadata (e.g. `@azure/mcp`, `@stripe/agent-toolkit`, and `@supabase/mcp-server-supabase` pointing at old repo paths; `mcp-server-docker`/`-kubernetes`/`-linear` never recording which individual maintains them; `firecrawl-mcp` and `gemini-mcp-tool` implying vendor ownership that doesn't exist) — these were corrected in place with the real `repo`/`maintainer` and demoted to `verified: false`. A ninth entry, PyPI `mcp-server-postgres`, was `verified: true, maintainer: "Anthropic"` despite being an unrelated third party's placeholder package (`"Add your description here"`); it was demoted to `verified: false`, its `repo` cleared, and its `maintainer` set to an honest "unconfirmed" label rather than left implying Anthropic. `entry_count`: **85 → 50**. Deleted: 35. Corrected in place (kept, demoted/repaired): 9. Left untouched: 41 (including one `THIN`-flagged but legitimate high-adoption package, `@playwright/mcp`, re-verified and re-dated without a bucket change). None of this was invented for this pass — every disposition traces to a live registry lookup re-run on 2026-08-20 immediately before editing.
- **Registry CI guard (`tests/test_registry.py::TestRepoNullRequiresDeliberateAcknowledgement`) tightened from a 26-name grandfathered allowlist down to 3.** After the corrections above, only `mcp-server-mysql`, `mcp-server-postgres`, and `mcp-server-terraform` still have `repo: null` — the first two because the real package itself declares no repository at all, and `mcp-server-postgres` because its previous `repo` value was a false Anthropic attribution that has been deliberately nulled rather than left misleading.

- **Registry: `mcp-server-postgres` (PyPI) still carried three verified-only signals after being demoted to `verified: false`.** The initial demotion above fixed `maintainer`/`repo`/`verified`/`last_verified` but missed `tags: ["official", ...]` (rendered on the public mcp-audit.dev verdict page next to a maintainer field saying the attribution is false), `attestation_expected: true` (per its own docstring in `registry/loader.py`, this guarantees a false MEDIUM finding for a package with no established Sigstore pipeline), and `publisher_history: ["anthropic-bot", "modelcontextprotocol"]` (the account-takeover baseline — leaving Anthropic's real accounts there would read as a takeover the moment the real publisher appears). Removed the `official` tag, set `attestation_expected: false`, and set `publisher_history: null`. Added a general-case CI guard so this class of regression is caught automatically rather than by manual re-review: `tests/test_registry.py::TestDemotedEntriesDoNotCarryVerifiedSignals` asserts no `verified: false` entry anywhere in the registry carries the `official` tag or `attestation_expected: true`.

- **Registry: removed a bogus `mcp-server-git` npm entry that collided with the real, verified PyPI entry of the same name.** The npm package `mcp-server-git` is an unrelated security-research canary (repo `theinfosecguy/npx-canary`, "not for production use"), not an MCP git server — it should never have been added. Because `KnownServerRegistry._name_index` keyed lookups on name alone with no ecosystem component, the two same-named entries collided and `get()`/`is_known()` returned whichever one the JSON array happened to index last, so `mcp-audit vet mcp-server-git --ecosystem npm` and the toxic-flow capability tagger could report the wrong verification state and capability set depending on file order. Removed the bad entry (`entry_count` 86 → 85) and hardened `KnownServerRegistry.__init__` to raise `ValueError` at load time if any future registry file has two entries sharing a case-insensitive `name`, instead of silently picking one. New tests: `tests/test_registry.py::TestNameCollisionDetection` and `test_no_duplicate_names_across_ecosystems`.

- **Registry: npm-scoped lookups (`is_known_npm`, `get_npm`, `find_closest_npm`) close the other half of the ecosystem-blind indexing bug.** The PyPI side already had a filtered sub-index (`is_known_pypi`/`get_pypi`/`find_closest_pypi`); the npm side did not, so an npm-context lookup for a name that only exists as a PyPI entry (e.g. `mcp-server-git`, which is `package_ecosystem: "pypi"`-only after the fix above) would still resolve via the ecosystem-agnostic `get()`/`is_known()`/`find_closest()` used internally by the npm branches of `SupplyChainAnalyzer` and `vet`. Added a `package_ecosystem in ("npm", "any")`-filtered sub-index mirroring the PyPI one, and repointed `analyzers/supply_chain.py`'s npm branch and `cli/vet.py`'s npm-ecosystem branch (`_lookup`/`_typosquat_check`) at it. `get()`/`is_known()`/`find_closest()` are unchanged and remain the intentional ecosystem-agnostic fallback for callers with no ecosystem context (rule engine, governance, attestation, shadow-risk, toxic_flow). New tests: `tests/test_registry.py::TestNpmEcosystemScoping`, `TestNpmPypiSameNameDisambiguation`; `tests/test_supply_chain.py::TestRegistryNpmHelpers`, `test_npx_pypi_only_name_not_short_circuited_as_known`.

- **Advisory feed: fixed four issues found in a pre-release security review of the OSV feed (`advisory/`), before it ships in a tagged release.**
  - **RFC 8785 float canonicalization was not ECMAScript-conformant** for values roughly in `[1e-6, 1e-5)`: Python's `repr()` switches to scientific notation at `1e-5`, but ECMAScript's `Number::toString` only switches below `1e-6` (`1e-6` itself must still render fixed). `1e-5` canonicalized to `"1e-5"` instead of the spec-correct `"0.00001"`. This is a conformance bug, not a collision — no two different documents could canonicalize to the same bytes from it — but it meant an independent RFC 8785 implementation would compute different bytes than mcp-audit for any document containing such a value, breaking third-party signature verification. `advisory/canonical.py::_es_number_to_string` now implements ECMA-262's Number::toString steps 5–9 directly (verified byte-for-byte against real Node.js for the boundary cases). No currently-published advisory field is a float, so no existing record is affected.
  - **Advisory IDs were not a pure function of identifying content.** `Advisory.stable_id()` embedded `published[:4]` (the publication year), so the same recurring vulnerability advised on either side of a UTC year boundary minted two different IDs — breaking a consumer's ability to answer "have I seen this advisory?". The ID format is now `x_MCPSA-<12hex>` with no timestamp component. Separately, baseline-drift findings (`DRIFT-*`, feeding `mcp_audit_rule_id`) were numbered by list position (`DRIFT-{i:03d}`), which is not guaranteed stable across runs since `BaselineManager.compare()` builds part of that list from a set intersection; `_drift_to_findings` now derives the ID from the drift event's own identity (`DRIFT-<TYPE>-<12hex of client+server+drift_type>`).
  - **`NON_ADVISORY_IDS` had drifted from what mcp-audit actually treats as "not a vulnerability."** `RUGPULL-002` (new-server bookkeeping, the same class as the already-excluded `RUGPULL-000`/`RUGPULL-003`) was missing, and baseline drift's `SERVER_REMOVED` type had no way to be excluded at all (its ID wasn't stable enough for the static set). Both are masked by the CLI's default `--severity-threshold medium`, but `--severity-threshold info` is a supported flag and would have published them as vulnerability claims. Added `RUGPULL-002` to `NON_ADVISORY_IDS`; `is_advisable()` now also excludes any `DRIFT-SERVER_REMOVED-*` id by prefix.
  - **`Advisory.published`/`modified` had a dead-but-latent `datetime.now()` default.** The one production call site (`build_advisory`) always supplied both explicitly, so this never fired — but a non-deterministic default on fields whose output gets signed is exactly the class of bug CLAUDE.md's "never call `datetime.now()` in the call chain" invariant exists to prevent. Both fields are now required, keyword-only constructor arguments with no default; omitting either now fails loudly with `TypeError` at construction time instead of silently.

  New/updated tests: `tests/test_advisory_canonical.py::TestEcmaScriptNumberBoundary`, `tests/test_advisory_schema.py::TestNoWallClockDefault` and `TestStableIds` (updated), `tests/test_advisory_feed.py::TestClassification` (two new cases), `tests/test_baselines.py::TestDriftToFindingsIds`. The committed `examples/feed/` has been regenerated with the new `x_MCPSA-<12hex>` ID format (same digests, same 23 advisories — only the id string and everything that embeds it changed) using the exact reproducible command in `examples/feed/README.md`; `mcp-audit feed verify examples/feed` still passes. `tests/test_cli_advise.py::TestExamplesFeedIsCurrent` now regenerates the feed in CI and fails the build if the committed copy ever drifts from what current code produces again.

- **Advisory feed: `CFHYG-001`/`002`/`005` (config file hygiene) findings were leaking the operator's absolute, machine-specific config path — including their home-directory username — verbatim into published advisory text.** This is the RFC 8785 canonicalization bug's failure mode in different clothes rather than a new defect class: two hosts scanning the *same relative target* resolve it to two different absolute paths, so the same finding canonicalized (and would have signed) differently depending on where the scanning machine's checkout happened to live — which is exactly how `TestExamplesFeedIsCurrent` caught it (the regenerated `examples/feed/` differed between a local run and CI). It was also, independently, a privacy leak in the one component of mcp-audit explicitly designed to be published to the world, contradicting the project's own privacy-first premise. `advisory/feed.py::_redact_local_paths` now rewrites the scanned config path — and each of its ancestor directories up to (not including) `$HOME` — to a path relative to the current working directory before it reaches advisory text, falling back to `$HOME`-relative (`~/...`) when the working directory has itself escaped the home tree (e.g. a container mounting the repo outside the home volume) so the username can never leak regardless of topology; `$HOME` itself becomes `~`. A bare filename swap was deliberately rejected — it would make two same-named config files in different directories indistinguishable, costing the finding its usefulness. **This does not change any advisory ID**: `Advisory.stable_id()`'s `location` input comes solely from `finding.tool` (see `normalize_location`'s docstring), which `config_hygiene.py` never sets, so the leaking text was never part of any ID's hash basis; `tests/test_advisory_feed.py::TestLocalPathRedaction::test_path_redaction_does_not_change_the_advisory_id` pins this. The same three finding IDs still embed the equivalent absolute path in every other output that serialises `Finding.evidence`/`description`/`remediation` verbatim — SARIF, the CycloneDX/native snapshot export, and the Nucleus FlexConnect push — none of which are touched by this fix; the exposure there is unchanged and is tracked as a follow-up, not fixed in this change. New tests: `tests/test_advisory_feed.py::TestLocalPathRedaction` (8 cases, including a regression pinning that redaction never uses the filesystem root `/` as a match key — that string is one character and would otherwise rewrite every path separator in unrelated text). `examples/feed/` regenerated again to carry the redacted paths (same 3 advisory IDs, only `details` text and digests changed). Fixing this surfaced a second, unrelated pre-existing gap in the drift test added above: `CFHYG-001`/`002` are documented as POSIX-only in `config_hygiene.py` (skipped unconditionally on Windows — `st_mode` bits don't represent Windows ACL semantics) and the fixture set's 3 CFHYG-001 advisories can therefore never be reproduced by a fresh scan on a Windows runner. That's an intentional, pre-existing platform difference in the scan itself, not feed drift, so `TestExamplesFeedIsCurrent` is now `skipif(os.name == "nt")` with a comment pointing at `TestLocalPathRedaction` for the platform-independent coverage of the redaction logic it would otherwise also exercise; it still runs (and still enforces byte-identity) on Linux and macOS.

- **`analyzers/transport.py`: the last ecosystem-blind registry lookup (TRANSPORT-003 severity tiering) is now ecosystem-scoped.** `_build_runtime_fetch_finding` handles both npm-family launchers (`npx`, `bunx`, `yarn dlx`) and pip-family launchers (`uvx`, `pipx`) through the same code path, so simply swapping `get()` for `get_npm()` would have broken `uvx`/`pipx` tiering for verified PyPI packages (e.g. `mcp-server-fetch` via `uvx`). Instead, the lookup now dispatches on `server.command`: npm-family calls `get_npm()`, pip-family calls `get_pypi()`. Before this fix, an npx-launched server named after a PyPI-only package (e.g. `mcp-server-git`) was silently suppressed at TRANSPORT-003; it now correctly fires at MEDIUM. `fixer/strategies/pinning.py`'s advisory-only `is_known()` call is intentionally untouched (separate, lower-stakes call site). New tests: `tests/test_analyzers.py::TestTransportRuntimeFetchRegistryTiering::test_npx_pypi_only_package_not_suppressed`, `test_pipx_uses_pypi_scoped_lookup`.

- **The absolute-path leak fixed for the advisory feed above was still present, unchanged, in the three other output sinks that also leave the machine: SARIF, the Nucleus FlexConnect push, and the forensic snapshot export.** `Finding.finding_path`/`Finding.title`/`description`/`evidence`/`remediation` and `ServerConfig.config_path` are always this scanning host's own absolute path (home directory + username in the common case); SARIF, Nucleus, and snapshot all copied that text verbatim into a document meant to be uploaded, pushed, or ingested elsewhere. `advisory/feed.py`'s redaction helper is now a shared module, `src/mcp_audit/_redact.py` (`redact_local_paths` + a `redact_finding_path` convenience wrapper keyed on `Finding.finding_path`), imported by all four sinks; `advisory/feed.py` itself is unchanged in behaviour. Fixed at serialization time only — no `Finding`/`ServerConfig` object is ever mutated, so two sinks formatting the same scan in one process can't see each other's edits:
  - **SARIF** (`output/sarif.py`): `physicalLocation.artifactLocation.uri`, rule `shortDescription`/`fullDescription`/`help.text`, and result `message.text` are now redacted. This also **fixes a real, independently-discovered bug, not just a privacy leak**: `_finding_to_file_uri` previously emitted an absolute `file:///Users/...` URI. GitHub's `upload-sarif` action matches a result back to a repository file by reading `artifactLocation.uri` as a plain string — it does not resolve `uriBaseId` the way the SARIF spec allows — so every PR annotation from `mcp-audit scan --format sarif` was silently failing to appear in GitHub's Files Changed view before this fix, regardless of privacy concerns. The URI is now genuinely relative (repo-relative when run from the repo root, as CI does) with forward slashes on every platform.
  - **Nucleus FlexConnect** (`output/nucleus.py`): `finding_name`, `finding_description`, `finding_solution`, `finding_output`, and `finding_path` are now redacted.
  - **Snapshot export** (`output/snapshot.py`): redacted in all three formats — native JSON (`server.config_path`, `finding_path`, and finding text fields), CycloneDX AI/ML-BOM (`recommendation`/`description` on each `vulnerability`), and `--stream` NDJSON (per-line finding fields).
  - **Deliberately left unredacted:** terminal output and the HTML dashboard (`mcp-audit dashboard`) — the user is looking at their own machine, and the absolute path is the useful part (e.g. what you'd paste into `chmod`). Plain JSON output (`--format json` / `-o file.json`) is also left unredacted: unlike the four sinks above, it has no single fixed destination — it's consumed locally by `scan --baseline`/`diff`, by the VS Code extension's inline diagnostics, and by ad hoc scripts, all of which expect the real path — and redacting it would silently break that class of consumer. PDF reports (`output/pdf.py`) never included a raw path or finding evidence/remediation text to begin with. New tests: `TestLocalPathRedaction` in `tests/test_sarif_output.py`, `tests/test_nucleus_output.py`, and `tests/test_snapshot.py`; `TestTerminalOutputKeepsAbsolutePaths` in `tests/test_terminal_output.py` and `TestDashboardKeepsAbsolutePaths` in `tests/test_dashboard.py` pin that the two local-only sinks are untouched. The residual gap already disclosed for the advisory feed — a scan explicitly targeting another user's directory on a shared host (`--project /home/someone-else/...`) still emits that person's name, because recognising an arbitrary OS username is a different, open-ended problem from redacting this process's own `$HOME` — is now also documented in `docs/privacy.md` rather than only in PR history.

- **Registry: `@palisadeemail/mcp` moved from `verified: false` to `verified: true`** ([#38](https://github.com/adudley78/mcp-audit/issues/38)), on independently re-checked evidence: npm's own publishing account for the package is `ianbussieres` with an `@palisade.email` address, and the submitter (`samuelchenardlovesboards`) demonstrated write access to the declared repo via a same-repo (non-fork) merged PR, `palisadeemail/palisade-mcp#2`. The submitter's other offered evidence — a commit author email — deliberately did **not** factor into this decision; see the docs fix below. `publisher_history` (`["ianbussieres"]`) and `maintainer` (`"Palisade"`) are unchanged; no `official` tag was added and `attestation_expected` remains `false` (no provenance verified). `last_verified` → `2026-08-22`.
- **`docs/registry-contributions.md`'s "Verification standard" section described a weaker bar than mcp-audit actually applies, and didn't test the submitter at all.** The old text ("a confirmed link between the package name and the repository, and a named maintainer organization") could be satisfied by anyone submitting a package they don't control. Rewrote it to state the real bar: `verified: true` requires evidence that *the submitter* controls the package (publishing account on the project's own domain/org, demonstrated repo write access, or the publishing account commenting on the issue directly), `verified: false` is an ordinary outcome rather than a rejection, and — called out explicitly, since the case above is why this needed writing down — **a git commit author email is self-asserted and does not count as evidence on its own.** Added a short "Upgrading a `verified: false` entry" subsection.

---

## [0.14.0] - 2026-06-14

### Added

- **mcp-audit now scans the whole agent: skills, memory, and hooks join MCP configs and extensions.** New `src/mcp_audit/agent_files/` package (models, discovery, analyzer) mirroring the extensions/ structure. Seven new finding IDs: `SKILL-001` (HIGH — injection/exfiltration instruction in skill/command/instruction file), `SKILL-002` (MEDIUM — obfuscated or oversized block), `SKILL-003` (MEDIUM — unpinned external URL in instruction file), `HOOK-001` (HIGH — network egress in hook command), `HOOK-002` (HIGH — hook modifies agent config file, CVE-2026-30615 persistence channel), `MEM-001` (MEDIUM — imperative override in CLAUDE.md memory file), `MEM-002` (MEDIUM — injection pattern in memory file). Scanned surfaces: Claude Code custom commands (`~/.claude/commands/*.md`, `.claude/commands/*.md`), Claude Code memory (`CLAUDE.md`, `.claude/CLAUDE.md`, `~/.claude/CLAUDE.md`), Cursor rules (`~/.cursor/rules/*.mdc`, `.cursor/rules/*.mdc`), GitHub Copilot workspace instructions (`.github/copilot-instructions.md`), scoped instructions (`.github/instructions/*.instructions.md`), and prompt templates (`.github/prompts/*.prompt.md`). Hook analysis (`HOOK-001`, `HOOK-002`, and the updated `CFHYG-005`) now covers project-level `.claude/settings.json` and `.claude/settings.local.json` in addition to the user-global `~/.claude.json`. New CLI: `mcp-audit agent-files discover|scan [--project PATH]` and `mcp-audit scan --include-agent-files`. All detection patterns imported from `poisoning.py` — no forked regexes. Memory analysis uses restricted pattern subset (POISON-010/011/040/060 only) to control FP rate. Zero FPs on benign fixtures enforced by `tests/test_false_positive_benchmark.py::TestAgentFileFalsePositives`. All 7 new IDs mapped in `docs/owasp-mapping.json`. ADR: `docs/decisions/ADR-0004-agent-files-surface.md`. Docs: `docs/agent-files.md`. Provenance: PROVENANCE.md.

---

## [0.13.0] - 2026-06-14

### Added

- **README badges: show your MCP server's verdict (verification status + known CVEs) via mcp-audit.dev.** New `docs/badge.md` specifies precisely what the badge asserts (registry verification status and known CVE count for the package) and what it does not assert (nothing about any deployment; not a security grade; not an endorsement). `mcp-audit vet <package> --badge` prints the Shields.io Markdown snippet. New "For MCP server authors" section in README with badge embed, three-verbs quick-start (`vet` / `check` / `fix`), and "not listed?" call-to-action linking to `docs/registry-contributions.md`. Badge URL confirmed live (HTTP 200, renders correctly). Updated `docs/vet.md` Badge section and `docs/registry-contributions.md` with cross-links.

- **New COMM-034: detect MCP servers configured with overprivileged credentials (god key pattern).** Env var key name heuristics flag admin-level scope across three tiers: (1) ADMIN/ROOT/MASTER/SUPERUSER segment in any key name (e.g. `MY_ADMIN_KEY`, `ROOT_TOKEN`, `MASTER_SECRET`); (2) Kubernetes cluster credential names (`KUBE_TOKEN`, `KUBECONFIG`, `K8S_TOKEN`, `KUBERNETES_SERVICE_ACCOUNT_TOKEN`); (3) org-scoped GitHub tokens (`GITHUB_TOKEN`, `GH_TOKEN`, `GITHUB_PAT`, `GH_PAT`). Fully offline — no credential values are read, no IAM API calls. A god key turns any finding from interesting to catastrophic. Severity: MEDIUM. OWASP MCP06, CWE-250. Reference: CIS Controls v8.1; CoSAI RSAC 2026 Agentic IAM paper; Security Boulevard "Addressing the God Key Challenge" (March 2026). Differentiates from Snyk (presence only) and Lasso (runtime, not static). Per-condition registry exemption for GitHub tokens tracked as COMM-034b.

- **Registry submission issue template.** Server authors can now request a verdict and badge via a structured GitHub issue form (`.github/ISSUE_TEMPLATE/registry-submission.yml`). The form collects package name, ecosystem, repo URL, maintainer, capability declarations, and a confirmation checklist. Linked from `mcp-audit.dev/submit/`. Once a submission is merged into `registry/known-servers.json`, developers running `mcp-audit vet` get an offline verdict and the maintainer gets an embeddable Shields.io badge.

- **`mcp-audit vet <package>` — pre-install verdict on any public MCP server package.**
  Ask before you install. Registry-corpus-based, offline by default, facts not grades.
  Surfaces: verification status, known CVEs (with NVD links and fixed-in version),
  declared capabilities, hash-pin availability, and Sigstore attestation expectation.
  Typosquat detection reuses the same Levenshtein threshold as `mcp-audit scan`'s
  supply-chain analyzer (threshold=1 for names ≤5 chars, threshold=3 otherwise).
  Unknown packages exit 0 with an honest "no verdict available" panel — absence of
  registry data is NOT a safety signal.
  - `--ecosystem npm|pypi` — force ecosystem; auto-detected when omitted
    (`@scope/name` → npm; plain names try npm then pypi).
  - `--format json` — full verdict document conforming to
    `https://mcp-audit.dev/v1/schema.json` (schema_version `"1.0.0"`).
  - `--badge` — prints a Shields.io Markdown badge for the package.
  - `--online` — fetches a live verdict from `mcp-audit.dev/v1/verdicts/{eco}/{slug}.json`
    (HTTPS GET); caches result at `<user-config-dir>/mcp-audit/verdict-cache.json`
    (0o600); falls back to bundled registry on network failure.  Plain `vet` makes
    zero network calls.
  - `--strict` — exit 1 for unknown packages (CI mode).
  - Exit codes: 0 = known/unknown-without-strict; 1 = CVEs/typosquat/unknown+strict;
    2 = error.
  - PEP 503 normalisation for pypi lookups (`mcp_atlassian` = `mcp-atlassian`).
  - New module `src/mcp_audit/verdict.py` — pure `build_verdict()` builder shared by
    CLI and mcp-audit.dev website generator; `name_to_slug()` utility.
  - New module `src/mcp_audit/cli/vet.py` — Typer command.
  - 61 tests in `tests/test_vet.py`: clean/CVE/typosquat/unknown paths, all exit codes,
    JSON schema conformance (all required fields per `mcp-audit.dev/v1/schema.json`),
    CVE field normalisation (bare strings + rich dicts, deduplication), badge output,
    PEP 503 round-trip, `--online` mock + 0o600 cache + fallback, slug round-trip.
  - ADR: `docs/decisions/ADR-0003-vet-verdict.md`.
  - Docs: `docs/vet.md`.
  - Supersedes the stale `lookup` command on branch `story/0016-mcp-audit-dev`
    (different URL shape, included letter grades — do not merge).

---

## [0.12.0] - 2026-06-13

### Added

- **Registry: 4 new CVE advisories for known MCP packages (CVE-2026-23744, CVE-2026-0755, CVE-2025-59528, CVE-2026-26118).** Added `known_vulnerabilities` entries to `registry/known-servers.json` for confirmed public CVEs: `@mcpjam/inspector` (CVE-2026-23744, RCE via unauthenticated `/api/mcp/connect`, fixed in 1.4.3), `gemini-mcp-tool` (CVE-2026-0755, command injection via `execAsync`, no fix available as of disclosure), `flowise` (CVE-2025-59528, RCE via `Function()` constructor in CustomMCP node, fixed in 3.0.6), and `@azure/mcp` (CVE-2026-26118, SSRF privilege escalation, fixed in 1.0.2 / 2.0.0-beta.17). Also corrected CVE attribution: `CVE-2026-26118` moved to `@azure/mcp` (the affected package per OSV/NVD) from `@microsoft/mcp-server`.

- **SC-004 — Offline CVE advisory check for known-vulnerable packages.** The supply chain analyzer now checks `known_vulnerabilities` on exact registry matches and emits `SC-004` (HIGH) when the configured package has one or more CVE advisories recorded in the bundled registry. No network required — purely offline. This activates the previously-dormant `known_vulnerabilities` field in `RegistryEntry` and closes the gap between "registry has CVE data" and "scan surfaces it as a finding". CWE-1104 / OWASP MCP04. CVE-2026-32211 (`@azure-devops/mcp`) was **skipped** — NVD CPE is `azure_web_apps` (a hosted service); no npm package version to pin, fix was applied server-side with no client update available.

- **COLLIDE-001 — Tool-name collision detection across connected MCP servers.** New `detect_tool_collisions()` function (`analyzers/collision.py`) compares live `tools/list` results across all servers connected during `mcp-audit scan --connect`. When two or more distinct servers advertise the same tool name, the agent's tie-breaking behaviour is undocumented and order-dependent — an attacker registers a colliding name to shadow a trusted tool (the agentic analogue of PATH poisoning). Emits MEDIUM when names collide; HIGH when one claimant is verified in the known-server registry and another is not (unknown server shadowing a trusted name). Tool-name comparison is case-sensitive. Deduplication prevents the same logical server configured in multiple MCP client config files from self-colliding. Requires `--connect` — static configs don't carry tool lists. NSA CSI item 5; CWE-694; OWASP MCP01 + MCP09. No companion community rule (COMM-032 reserved/unissued): a static rule for collision detection cannot fire without tool-name data.

- **`scan --project <dir>` — Catch the TrustFall attack before you click "Trust this folder" (TRUST-001).** New `--project <dir>` flag on `mcp-audit scan` walks a repository directory tree looking for project-level MCP config files (`.mcp.json`, `.cursor/mcp.json`, `.claude/settings.json`, `.claude/settings.local.json`, `.cursor/settings.json`, `.vscode/mcp.json`) and emits `TRUST-001` (HIGH) for every server defined inside them. When a developer opens a repository in an AI editor (Claude Code, Cursor, VS Code/Copilot) and clicks "Trust this folder", any MCP server in a project-level config auto-spawns with the developer's full OS privileges before any project code runs — a supply-chain attacker, malicious contributor, or typosquatted package can backdoor every developer who trusts the repo (Adversa TrustFall, May 2026; corroborated by CVE-2026-30615). The full analyzer pipeline (credentials, poisoning, transport, supply-chain, auth) runs on project-scoped servers too. `ServerConfig` gains `is_project_scoped: bool` to track origin. `discover_project_configs()` in `discovery.py` drives discovery (separate from user-level `discover_configs()`). Tree walk caps at depth 8, skips `node_modules`/`.git`. Community rule COMM-033 fires as a lightweight config-path-pattern companion. CWE-829 / OWASP MCP09.

- **AUTH-001 — Remote MCP server configured without authentication.** New `AuthAnalyzer` (8th analyzer) flags remote HTTP/SSE/Streamable-HTTP servers that carry no authentication material in their configuration. A measurement study (arXiv 2605.22333) found 40.55% of 7,973 live remote MCP servers require no authentication; Censys counted 12,520 internet-exposed MCP services, the majority unauthenticated. Severity is HIGH for internet-routable hosts and MEDIUM for RFC 1918 / `*.local` private hosts. Localhost servers are exempt. Suppressed by any of: `Authorization`/`x-api-key`/`api-key` header (including `${ENV_VAR}` placeholder values), `token`/`apiKey`/`auth`/`bearer` raw fields, OAuth settings, or URL userinfo. `ServerConfig` gains a new `headers` field parsed from the `"headers"` key in MCP config entries (all supported clients). CWE-306 / OWASP MCP06. Community rule COMM-031 ships as a lighter-weight URL-pattern companion.

- **AUTH-002 — OAuth-configured server missing audience/resource binding.** Same `AuthAnalyzer` checks OAuth-enabled servers for RFC 8707 Resource Indicator compliance. A missing or wildcard `audience`/`resource` field allows tokens issued for one resource server to be replayed against any other server accepting the same issuer. Emits MEDIUM when an OAuth block is detected (flat `oauth`/`oauth2` key, `auth.type: oauth2` block, or flat `client_id`+`authorization_endpoint` fields) and neither a concrete audience value nor an audience-referencing env key name is present. CWE-346 / OWASP MCP06.

---

## [0.11.0] - 2026-05-30

### Added

- **`mcp-audit check --report pdf` — PDF compliance report (STORY-0047).**
  One command produces a Letter-size PDF that a CISO can hand directly to an
  auditor — letter grade, numeric score, OWASP-mapped findings table, and a
  SHA-256 content hash for chain-of-custody.  No other MCP security tool
  produces a signed, timestamped, auditable compliance artifact today.
  - `mcp-audit check --report pdf --output-file PATH` writes the report to PATH.
  - `--org "Name"` sets the organisation name in the PDF header.  Falls back
    to the registered org (from `registration.json`) then `"Not specified"`.
  - `mcp-audit scan --report pdf` is also supported for full-pipeline scans.
  - PDF contains: header (org, ISO 8601 timestamp, version), executive summary
    (colour-coded grade: A/B green, C amber, D/F red; score; verdict; per-severity
    counts), findings table (severity, ID, title, server, OWASP MCP Top 10
    category, remediation hint — paginated), and footer (mcp-audit credit + GitHub
    URL on every page, SHA-256 content hash on the last page).
  - SHA-256 is computed over `ScanResult.model_dump_json()` (the scan data,
    not the PDF binary), so the hash is reproducible from a JSON export alone.
  - New module: `src/mcp_audit/output/pdf.py` (`PdfReportFormatter`).
  - `reportlab>=4.0` added as a required runtime dependency (BSD licence,
    pure Python, no system dependencies); bundled in all four PyInstaller
    binaries via `hiddenimports`.
  - New docs: `docs/compliance-report.md` — usage guide and auditor
    interpretation instructions.
  - 18 new tests in `tests/test_pdf_report.py`.

- **`mcp-audit register` — opt-in registration flow (STORY-0046).**
  Developers and security engineers can choose to identify their org in exchange
  for weekly new-rule notifications and an optional follow-up when their scan grade
  is C or below.  Registration is entirely voluntary; an unregistered user
  experiences zero behaviour change and zero network traffic.
  - Interactive `mcp-audit register` flow collects name, org, email, and a
    follow-up preference; all fields optional except email (validated for `@`).
  - `registration.json` stored at `<user-config-dir>/mcp-audit/registration.json`
    with 0o600 permissions (consistent with baseline and rug-pull state storage).
  - Initial registration POST sends: name, org, email, version, grade,
    follow_up_requested — **nothing else**.  No config data, server names,
    credentials, or file paths are ever transmitted.
  - Subsequent `mcp-audit check` pings send only: version, grade,
    `registered=true` — **no PII**.
  - `mcp-audit register --status` shows current registration or "Not registered".
  - `mcp-audit register --clear` removes `registration.json` and stops pings.
  - `mcp-audit check --register` runs the scan then prompts registration if not
    already registered.
  - `Registered as: <org>` one-liner appears beneath the grade panel in
    `mcp-audit check` output when registered.
  - New modules: `src/mcp_audit/registration/` (models.py, manager.py, client.py),
    `src/mcp_audit/cli/register.py`.
  - New `docs/privacy.md` — plain-English registration privacy policy.

- **`mcp-audit fix` — apply safe remediations directly to MCP config files (STORY-0031).**
  Every scanner tells you what's wrong; `fix` tells you what to do *and does it*.
  Dry-run by default (unified diff to stdout, no files touched). Pass `--apply` to
  write changes atomically with a `.bak` backup of the original.
  Takes a **single config file** via `--path`; omit to auto-discover all configs.
  - **Credential redaction** (`CRED-001`, `CRED-002`): replaces plaintext secret
    values with `${ENV_KEY_NAME}` placeholders. Idempotent — skips values that
    already use `${…}` syntax.
  - **Transport upgrade** (`TRANSPORT-001`): rewrites `http://` server URLs to
    `https://`. Idempotent — skips URLs already using HTTPS.
  - **Package pinning** (`SC-001`, `SC-002`): replaces a typosquatted package name
    with the verified closest-match from the known-server registry and appends
    `@latest-version`. Falls back gracefully when npm/PyPI is unreachable.
  - `--fix-type` flag restricts which strategies run (`credentials`, `transport`,
    `pinning`); repeatable for multiple types.
  - `--input <scan.json>` reads findings from an existing scan JSON file instead
    of re-running a fresh scan.
  - `--offline` suppresses all version-resolution network calls.
  - Exit codes: `0` = success or no fixable findings; `2` = error.
  - See `docs/fix.md` for full documentation.

- **VS Code / Cursor extension — security findings appear as squiggles as you type (STORY-0032).**
  Open your Claude or Cursor config file in VS Code or Cursor — red/yellow underlines
  appear inline before you run a single command. Install
  [`mcp-audit.mcp-audit-vscode`](https://github.com/mcp-audit/mcp-audit-vscode)
  via the Open VSX Registry (Cursor) or manually from a `.vsix` file (VS Code —
  Marketplace listing pending); see [`docs/ide-extension.md`](docs/ide-extension.md).
  Includes hover cards showing finding title, description, evidence, and remediation.
  The extension shells out to the `mcp-audit` binary — no detection logic is
  reimplemented in TypeScript. Includes a status bar grade badge, command palette
  integration (`Scan current file`, `Scan workspace`, `Fix current file`), and
  `jsonc-parser`-based server-key line resolution. Works in both VS Code and Cursor.
  ADR: [`docs/decisions/ADR-0002`](docs/decisions/ADR-0002-extension-separate-repo.md).

### Security

- SHA-pin all third-party GitHub Actions to full 40-char commit SHAs across 14 workflow files, preventing supply-chain substitution attacks ([CVE-advisory: tj-actions/changed-files compromise](https://www.stepsecurity.io/blog/tj-actions-changed-files-action-compromised)). Thanks [@jsandov](https://github.com/jsandov) for the contribution — our first external PR.

- Bumped `idna` to `>=3.15` to resolve CVE-2026-45409 (quadratic DoS bypass in `idna.encode()`). Surfaced as a direct dependency so Dependabot tracks future upgrades explicitly. Transitive path: `[mcp]` extra → `httpx` → `anyio` → `idna`.

- Bumped `sigstore` floor to `>=4.2.0` in `[attestation]` extra to resolve CVE-2026-24408. Only affects users who opt into `pip install mcp-audit-scanner[attestation]`; core runtime unaffected.

---

## [0.10.0] — 2026-05-17

### Added

- **`mcp-audit diff --format pr-comment` promoted as the standard CI PR artifact
  (STORY-0040, v0.10.0).** The PR comment output is now the headline use case
  for `mcp-audit diff`. `docs/diff.md` restructured so "PR Comment Output" is
  the first full section (was buried after Input Formats and Output Formats).
  New copy-paste workflow at `examples/github-actions/diff-pr-comment.yml`
  demonstrates the recommended pattern: scan base commit → scan head commit →
  diff to Markdown → post via `actions/github-script`. README "Quick Start"
  gains a dedicated "PR-comment diff for team adoption" section. `action.yml`
  `mode` input description updated to reference the new explicit workflow.

- **Snyk Code integration guide — mcp-audit + Snyk SARIF in CI (STORY-0041,
  v0.10.0).** New `docs/snyk-integration.md` explains how mcp-audit (config
  layer) and Snyk Code (source layer) complement each other, how to run both
  in CI and surface findings in GitHub Code Scanning, and how Snyk Enterprise
  users see unified alerts without extra steps. All five sections: why they're
  complementary, generating mcp-audit SARIF, uploading both SARIF files to
  GitHub Code Scanning, interpreting findings side-by-side, and a complete
  example workflow. New `examples/github-actions/with-snyk.yml` is a
  copy-paste parallel CI workflow. README gains a "Works well with" table
  linking all integrations (Snyk, Nucleus, GitHub Code Scanning).

### Security

- Bumped transitive dependency `python-multipart` to `0.0.28` (≥ 0.0.27) to
  resolve CVE-2026-42561 (DoS via unbounded multipart part headers; fixed in
  0.0.27). Exposure is limited to the optional `--connect` path; mcp-audit
  does not use `python-multipart` directly. `pip-audit --path .` returns zero
  findings after this bump.

- **`setup-mcp-audit` GitHub Action — binary download, no pip (STORY-0033, v0.10.0).**
  New `setup-action/action.yml` composite action downloads the pre-built mcp-audit
  binary from GitHub Releases and adds it to `PATH` in under 5 seconds. The binary
  is cached by `version + OS + arch` using `actions/cache@v4` — repeat runs with
  the same version tag restore from cache in under 1 second, down from the previous
  20–30 second `pip install` path.

  Key details:
  - Supports `ubuntu-latest` (x86_64), `macos-latest` (ARM64), `macos-13` (x86_64),
    and `windows-latest` (x86_64); Windows uses PowerShell for the download step and
    a `.exe`-suffixed binary.
  - `version: 'latest'` resolves the current release tag via `gh release view` (uses
    `GITHUB_TOKEN` automatically); pinned tags (e.g. `version: 'v0.10.0'`) skip the
    API call entirely.
  - Outputs `mcp-audit-version` with the version string reported by `mcp-audit version`.
  - Error messages are actionable: rate-limit failure points to `GITHUB_TOKEN`;
    download failure includes the URL and instructs users to verify the tag.
  - Scanner `action.yml` updated to use `./setup-action` internally — users who
    use the scanner action get the speed improvement automatically with no workflow
    changes required.
  - New integration test workflow `.github/workflows/test-setup-action.yml` runs
    `latest` and a pinned version on all three OS targets on every push/PR.
  - 13 new tests added to `tests/test_action_yaml.py::TestSetupActionYaml`.

- **PyPI / uvx typosquat detection — extend supply chain to Python ecosystem (STORY-0034, v0.10.0).**
  Typosquatting detection now covers Python MCP packages installed via `uvx`, `pipx`, and
  `python -m` — not just npm.  The supply chain analyzer extracts the package name from
  these invocations, normalises it per PEP 503 (so `mcp_server_filesystem` and
  `mcp-server-filesystem` are treated identically), and runs the same Levenshtein-based
  registry comparison used for npm.  Findings use the existing SC-001 / SC-002 / SC-003 IDs
  and severity scale.

  Key implementation details:
  - `extract_pypi_package(command, args)` — public helper that parses `uvx --from <pkg>
    <exe>`, `uvx --python 3.x <pkg>`, `uvx <pkg>@<ver>`, `pipx run <pkg>`, and
    `python -m <module>` invocations.
  - `SupplyChainAnalyzer._check_pypi_typosquatting()` — internal method that queries
    the new PyPI sub-index of the registry and emits findings.
  - `RegistryEntry.package_ecosystem` — new field (`"npm"` default / `"pypi"` / `"any"`);
    all five existing `"source": "pip"` entries updated to `"package_ecosystem": "pypi"`.
  - `KnownServerRegistry.is_known_pypi()`, `find_closest_pypi()`, `get_pypi_names()` — new
    query methods that operate only on the PyPI sub-index using PEP 503-normalised names.
  - `normalize_pypi_name()` — new public helper in `registry/loader.py`.
  - Three new PyPI registry entries: `mcp-server-filesystem`, `mcp-server-git`,
    `mcp-server-postgres`.

- **Credential pattern expansion — GCP, Azure, DO, Vercel, PEM, Vault (STORY-0035, v0.10.0).**
  Closes V-17. `credentials.py` `SECRET_PATTERNS` extended with 8 new credential types:

  - **GCP service-account JSON key** — detects `"private_key":"-----BEGIN` embedded in env var values (e.g. `GOOGLE_APPLICATION_CREDENTIALS_JSON`).
  - **Azure SAS token** — requires both `sv=YYYY-MM-DD` and `&sig=<base64>` to be present in the same value; reduces false positives on unrelated URLs.
  - **DigitalOcean personal access token** — `dop_v1_` prefix + 64 hex chars.
  - **Vercel access token** — `vercel_` prefix + 20+ alphanumeric chars.
  - **PEM private key blocks** — RSA, EC, DSA, and OpenSSH variants (`-----BEGIN … PRIVATE KEY-----`).
  - **HashiCorp Vault service token** — `hvs.` prefix + 90+ base64url chars.
  - **HashiCorp Vault batch token** — `hvb.` prefix + 90+ base64url chars.
  - **GitHub fine-grained PAT** — `github_pat_` prefix + 82 alphanumeric/underscore chars (extends existing GitHub classic PAT patterns).

  Equivalent `pattern-regex` rules added to both
  `semgrep-rules/python/credentials/mcp-hardcoded-secrets.yml` and
  `semgrep-rules/typescript/credentials/mcp-hardcoded-secrets.yml`
  so SAST coverage matches analyzer coverage.
  13 new unit tests added to `tests/test_analyzers.py::TestCredentialsAnalyzerExpandedPatterns`.
  Zero false positives confirmed against all demo config fixtures.

- **Complete OWASP MCP Top 10 mapping (STORY-0038, v0.10.0).**
  Every mcp-audit finding ID now maps to at least one OWASP MCP Top 10 category.

  - `docs/owasp-mapping.json` — machine-readable JSON mapping all 60 static
    finding IDs and 5 dynamic ID patterns to MCP01–MCP10 categories. Citable
    and auditable; structure: `schema_version`, `mappings`, `dynamic_patterns`,
    `unmapped` (always empty).
  - `scripts/validate_owasp_mapping.py` — CI enforcement script. Exits 0 when
    all source finding IDs are mapped, 1 with the missing IDs listed otherwise.
    CI runs this on every PR (ubuntu/py3.12 leg).
  - `mcp-audit scan --owasp-report` polished: now shows **all 10 OWASP categories**
    in a Rich table with finding count and worst-finding summary per category.
    Zero-finding categories show a green ✓ check (clean signal). Ends with
    "Coverage: 10/10 OWASP MCP Top 10 categories checked."
  - TOXIC-007 (git + network) now correctly mapped to MCP10
    (Context Injection and Over-sharing) in both source and the mapping file.
  - `docs/severity-framework.md` updated: CFHYG-005/006 rows added, TOXIC-007
    row corrected, stale ATTEST-001/002 IDs replaced with accurate `ATT-{hash}`
    documentation, link to `owasp-mapping.json` added.

- **`mcp-audit check` — one-command practitioner verdict (STORY-0037, v0.10.0).**
  New entry-point command for developers who want a quick answer to "is my
  setup safe?" without learning `scan` flags or SARIF.

  - Runs the **full scan pipeline** internally — same detection as `mcp-audit scan`,
    no shortcuts.
  - Presents a concise one-page verdict: letter grade, numeric score, top 5
    findings sorted by severity (CRITICAL first), and a one-line remediation
    hint per finding.
  - **Remediation hints** are plain English, no OWASP codes or analyzer names.
    Auto-fixable IDs (CRED-001, CRED-002, TRANSPORT-001, SC-001, SC-002)
    print "Run `mcp-audit fix --apply` to fix automatically." All other IDs
    map to specific manual instructions via `output/check.py::_HINTS`.
  - Grade F + active attack path → "⛔ Active attack path detected" line appended.
  - `--verbose`: full `mcp-audit scan` terminal output.
  - `--json`: full `ScanResult` JSON to stdout, no summary text.
  - `--path FILE`: scan a specific config file.
  - **Exit codes:** 0 = grade A/B (score ≥ 70, no CRIT/HIGH); 1 = grade C/D/F
    or any CRIT/HIGH finding; 2 = error. This is intentionally different from
    `scan` (which exits 1 on any finding) — `check` is designed for use as a
    developer-facing health check, not a strict CI gate.
  - Edge cases: no configs found → friendly message, exit 0; invalid `--path` →
    "File not found", exit 2; scan exception → "Scan error", exit 2.
  - 38 unit and integration tests in `tests/test_check.py`.
  - New modules: `src/mcp_audit/cli/check.py`, `src/mcp_audit/output/check.py`.
  - `README.md` Quick Start updated to feature `mcp-audit check` first.
  - `docs/check.md` written.

### Fixed

- **V-16: `discovery.py` Windows branch now uses `_home()` consistently.**
  `_get_client_specs()` called `Path.home()` directly on the Windows `AppData`
  path (line 40), bypassing the `_home()` indirection that every other branch
  uses. This meant tests that patch `mcp_audit.discovery._home` to redirect home
  to a temp directory did not intercept the Windows Claude Desktop path, risking
  path leakage on CI. Fixed by replacing the one direct call with `_home()`.
  Regression test `TestHomeHelperConsistency::test_discovery_uses_home_helper`
  added to `tests/test_discovery.py`.

### Docs

- **Docs cleanup pass (STORY-0036):** resolved stale "planned" / "not implemented"
  claims across `GAPS.md`, `CLAUDE.md`, and `docs/`. All numeric counts verified
  against `scripts/update_test_count.py --check` (exits 0). Key changes:
  - `GAPS.md`: fleet HTML simplified-table and `--dir` non-recursive items marked
    resolved; community rule count corrected (12 → 15); SAST TypeScript parity
    counts updated (34 Python / 29 TypeScript → 38 / 35) to reflect v0.9.0
    additions; "Missing capabilities" items for multi-arch binary and PyPI publish
    marked resolved; "Enterprise" tier reference removed from extension inventory
    item; **Closed gaps** reference table added at the bottom.
  - `CLAUDE.md`: project-layout community rule count corrected (13 → 15, COMM-015);
    registry entry count updated (64 → 75); "What's next (non-code)" trimmed to
    remove completed smoke-test and binary-size-gate items; "What's next (code)"
    trimmed to remove shipped GitHub Actions CI and docs items.
  - `docs/supply-chain.md`: removed stale "> **Note:** `mcp-audit sbom` is not yet
    implemented" annotation (shipped v0.6.0).
  - `docs/sast-rules.md`: rule count headers updated (Python 34 → 38,
    TypeScript 29 → 35; sub-section counts 9 → 10 injection, 5 → 6 poisoning);
    partial-catalog note added; Roadmap trimmed of two shipped items (GitHub Action
    `sast` input, OSV.dev integration).
  - V-16 (`_home()` inconsistency in `discovery.py`, line 40) confirmed still open.

---

## [0.9.1] - 2026-05-16 — Patch

### Fixed

- **CFHYG-005** now fires on `.claude.json` files that contain only a `hooks`
  section with no `mcpServers` key. The check was silently skipped when no MCP
  servers were configured because it ran per `ServerConfig`; it has been
  promoted to a config-level check (`analyze_config`) that runs once per file
  regardless of server count.
- Section 24 manual-test-matrix assertion updated to account for the synthetic
  `mcp-attack-surface` aggregate component (`type=data`) in CycloneDX output.
- Manual test matrix updated for v0.9.0 new detection surfaces (Sections 28–30,
  Section 15 rule count, Section 25 sampling SAST fixture).

---

## [0.9.0] - 2026-05-16 — MCP Attack Surface 2026

### Added

- **COMM-014 — MCP Sampling capability detection** (config layer): flags servers that
  declare the `sampling` capability, which allows server-initiated LLM calls —
  the attack surface Unit42 documented in May 2026.
- **Sampling SAST rules** (code layer, hero): 4 new Semgrep rules detecting prompt
  injection via MCP Sampling in Python and TypeScript — f-string/template-literal
  patterns fire at ERROR; variable-text patterns fire at WARNING. First scanner to
  detect MCP Sampling attacks at the code layer. (Unit42 MCP Sampling research anchor)
- **SSRF validation-path SAST**: 4 new Semgrep rules for CVE-2026-44284,
  CVE-2026-39974, and CVE-2026-27826 — detects unvalidated URL construction before
  HTTP requests in Python and TypeScript MCP servers.
- **SDK singleton transport SAST** (TypeScript): detects the CVE-2026-25536 pattern
  where a shared `StdioServerTransport` instance is reused across multiple clients,
  enabling cross-client data leakage.
- **Claude Code hooks RCE + ANTHROPIC_BASE_URL exfil** (CFHYG-005/006): detects
  CVE-2025-59536 (arbitrary command in `.claude/hooks`) and CVE-2026-21852
  (ANTHROPIC_BASE_URL env var pointing to attacker-controlled host) in Claude Code
  config files.
- **COMM-015 — Args-array shell metacharacter injection**: detects CVE-2026-30623
  pattern where MCP server `args` arrays contain shell metacharacters (`$`, `` ` ``,
  `|`, `;`, `&&`) that expand dangerously in shell-wrapped process execution.
- **Registry CVE anchoring**: `RegistryEntry` now carries a `known_vulnerabilities`
  field; mcp-atlassian CVE-2026-27826 anchored in the registry; COMM-005 and COMM-007
  cross-reference registry CVE data for richer finding context.

---

## [0.8.1] - 2026-05-03

### Fixed

- **Empty-state messages now distinguish "no config files found" from "config file exists
  but no servers defined"** in `mcp-audit shadow`, `mcp-audit pin`, and `mcp-audit sbom`.
  Previously all three printed a generic "No MCP servers found" message regardless of
  whether the config file was absent or simply empty. Commands now report:
  - `configs_found == 0` → "No MCP config files found on this host."
  - `configs_found > 0, servers == 0` → "Found N MCP config file(s) but no servers are
    configured in them."
  Full audit confirmed all other commands already handle this correctly or are not
  applicable (scan, discover, baseline, snapshot, killchain, diff, registry, rules).

- **`mcp-audit snapshot --path` no longer crashes** with `TypeError: run_scan() got an
  unexpected keyword argument 'skip_auto_discovery'`. Stale keyword argument removed —
  the scanner handles discovery internally.

- **`mcp-audit diff --path` stale invocation removed from manual test matrix.**
  The `--path` flag on the rug-pull `diff` command was removed in v0.8.0. The manual
  test matrix (`docs/manual-test-matrix.md`) has been updated to reflect the current
  interface. Manual test matrix also expanded from 20 to 27 sections, adding coverage
  for `shadow`, `killchain`, the MCP-aware `diff <base> <head>`, `snapshot`, `sast`,
  and `extensions` — all passing.

---

## [0.8.0] - 2026-05-03

### Added

- **`mcp-audit snapshot`** — time-stamped, sigstore-signed forensic exports of
  every MCP server on a host.  CycloneDX 1.5 AI/ML-BOM by default; native JSON
  optional (`--format native`).  Every server becomes a CycloneDX `component` of
  `type: application`; every finding becomes a `vulnerability` entry with ratings,
  CWEs, OWASP MCP Top 10 mappings, and a custom `properties` block.  `--sign`
  produces a `.snapshot.json.sig` sigstore bundle alongside the snapshot (requires
  ambient OIDC identity and `pip install 'mcp-audit-scanner[attestation]'`).
  `--rehydrate <old-snapshot.json>` reconstructs the historical attack-path graph
  as it was at snapshot time — forensic re-analysis even after the config is gone.
  `--stream` emits one JSON object per finding on stdout (NDJSON), suitable for
  piping into `vector`, a Splunk HEC forwarder, or a Sentinel DCR ingestor.
  `--input <scan.json>` accepts a previous scan result and skips live discovery.
  New modules: `src/mcp_audit/snapshot/` (`rehydrate.py`, `diff.py`),
  `src/mcp_audit/output/snapshot.py`, `src/mcp_audit/cli/snapshot.py`.
  56 tests in `tests/test_snapshot.py` (CycloneDX schema validation, rehydrate,
  diff, stream, sign error paths, CLI integration).  SIEM ingestion recipes in
  `docs/integrations/splunk.md` and `docs/integrations/sentinel.md`.
  See `docs/snapshot.md`.

- **`mcp-audit diff <base> <head>`** — MCP-aware diff for PR review and CI gates.
  Compares two MCP configuration states (directories, JSON scan files, or git refs)
  and surfaces added, removed, and changed servers, tools, capabilities, env-var
  references, external endpoints, and credentials with risk classification (CRITICAL /
  HIGH / MEDIUM / LOW / INFO).  PR-comment-grade Markdown output (`--format pr-comment`)
  is ready to pipe into `gh pr comment` or a GitHub Actions step.  JSON output
  (`--format json`) provides a flat list of change records with `change_type`,
  `entity_type`, `entity_name`, `before`, `after`, `severity`, and `owasp_mcp_top_10`
  fields.  Exit codes mirror `mcp-audit scan` (0 = no findings at threshold, 1 =
  findings, 2 = error).  `action.yml` extended with a `mode: diff` input that runs
  diff mode and posts the result as a PR comment when running in a `pull_request` event.
  New modules: `src/mcp_audit/diff/` (`loader.py`, `comparator.py`, `risk.py`,
  `render.py`), `src/mcp_audit/cli/diff.py`.  `examples/github-actions/diff-mode.yml`
  reference workflow added.  See `docs/diff.md`.

- **`mcp-audit killchain`** — opinionated remediation view of the attack-path graph.
  Decision engine that identifies the top N configuration changes (default 3) that cut
  the largest blast radius, ranked by incremental attack-path reduction.  Uses the
  existing greedy hitting-set algorithm in `analyzers/attack_paths.py` and wraps each
  step with human-readable target, rationale, and severity-reduction metadata.
  Outputs a prescriptive Markdown report (copy-paste into Slack/email) or JSON
  (`--format json`).  `--patch yaml` emits a YAML governance-policy denylist patch
  (with schema-gap note); `--patch pr` emits a PR-comment stub.  `--input <scan.json>`
  accepts an existing scan result; default behaviour re-runs the full pipeline.
  What-if simulation re-runs `summarize_attack_paths` against the modified server list
  — the math is identical to a real re-scan, not an approximation.  New modules:
  `src/mcp_audit/killchain/` (`recommender.py`, `simulator.py`, `patches.py`,
  `render.py`), `src/mcp_audit/cli/killchain.py`.  46 new tests in
  `tests/test_killchain.py`.  See `docs/killchain.md`.

- **`mcp-audit shadow`** — new top-level command for continuous detection of shadow MCP servers
  (OWASP MCP09). Sweeps every known MCP config location on the host; classifies each server as
  `sanctioned` (matches an optional operator allowlist) or `shadow` (does not); attaches a
  structured risk summary (capability tags, toxic-flow signals, OWASP MCP09 mapping); emits
  structured events in `--continuous` daemon mode (`new_shadow_server`, `server_drift`,
  `server_removed`); supports `--format json` for syslog/SIEM piping; persists `first_seen` /
  `last_seen` state with `0o600` file permissions. New modules:
  `src/mcp_audit/shadow/` (`allowlist.py`, `classifier.py`, `risk.py`, `events.py`, `state.py`),
  `src/mcp_audit/cli/shadow.py`. Introduces new `RiskLevel` enum (mirrors Severity + `UNKNOWN`).
  See `docs/shadow-mcp.md`.

- **CI: synthetic install-tree integration tests** (`tests/integration/test_synthetic_install.py`,
  `.github/workflows/synthetic-install.yml`) — new `synthetic-install` CI workflow runs on
  `ubuntu-latest` and `windows-latest` on every PR and push; validates the full
  `discover` → `scan` → `baseline` pipeline against realistic per-OS fixture trees.
  Covers: canonical-path discovery for all six auto-discovered clients (Claude Desktop,
  Cursor, Windsurf, Claude Code, Copilot CLI, Augment) via `HOME`/`USERPROFILE` env-var
  injection; credential-finding detection to prove scanning ran; paths with spaces; non-ASCII
  filenames (`配置/мcp.json`); `baseline save`/`compare` round-trip on non-ASCII paths; and
  Windows >260-char path graceful handling (`xfail` when OS rejects the path, never a
  Python traceback). No changes to `discovery.py` required — `Path.home()` already reads
  `HOME`/`USERPROFILE` from the subprocess environment.

---

## [0.7.0] - 2026-05-02

### Added

- **User-configurable scoring weights via governance policy YAML** — add a
  `scoring:` block to `.mcp-audit-policy.yml` to override per-severity
  deductions and positive-signal bonuses. Absent keys fall back to their
  hardcoded defaults, so existing scans are unaffected. Deduction values
  must be `<= 0`; bonus values must be `>= 0`; `policy validate` enforces
  both constraints. See `docs/governance.md#scoring-weights` and the new
  example policy at `examples/policies/custom-scoring-weights.yml`.
- **`ScanScore.weights_source` audit field** — set to `"default"` when
  hardcoded weights are used, `"policy:<absolute-path>"` when a governance
  policy supplies custom weights. Present in JSON and SARIF output; the
  terminal score panel shows a dim `Weights: policy:<path>` line when custom
  weights are active. Existing JSON consumers that do not read this field
  are unaffected (additive, non-breaking).

### Changed

- **Scoring defaults recalibrated**: HIGH −10 (was −15), MEDIUM −5 (was −8),
  LOW −2 (was −3), poisoning-free bonus +4 (was +2). Users upgrading from
  v0.6.x may see numeric grades shift upward on identical configurations.
  The CRITICAL deduction (−25), INFO deduction (−1), credential-free bonus
  (+3), and max-bonus cap (+10) are unchanged.

- **CI: smoke test extended with three new steps** (`scripts/smoke_test.py`):
  - **Watcher round-trip** (Check 9): launches `mcp-audit watch` as a subprocess,
    modifies a temp fixture, and asserts the watcher detects the change and re-scans
    within 10 s — exercises inotify (Linux), ReadDirectoryChangesW (Windows), and
    FSEvents (macOS).
  - **Rug-pull two-scan** (Check 10): runs two consecutive scans on a fixture whose
    `command`/`args` change between scans, then asserts a `RUGPULL-*` finding appears
    in scan 2 — confirms rug-pull state is written to and read from
    `platformdirs.user_config_dir("mcp-audit")/state/` on all platforms.
  - **Canonical-path discovery** (Check 11): writes a minimal MCP config to the
    OS-canonical Claude Desktop config path (`~/Library/Application Support/Claude/…`
    on macOS, `~/.config/Claude/…` on Linux, `%APPDATA%\Claude\…` on Windows), runs
    `mcp-audit discover --json`, and asserts the path appears in output; fixture is
    always removed in a `finally` block.
- **CI: `windows-latest` added to PR smoke matrix** — new `source-smoke` job in
  `.github/workflows/ci.yml` runs `python scripts/smoke_test.py uv run mcp-audit` on
  both `ubuntu-latest` and `windows-latest` on every PR and push to `main`, without
  the cost of a PyInstaller build (uses the source install via `uv run`).
- **Smoke test accepts multi-word binary invocations** — `smoke_test.py` now collects
  all `sys.argv[1:]` as the binary command list, so `python scripts/smoke_test.py uv run
  mcp-audit` and `python scripts/smoke_test.py dist/mcp-audit-linux-x86_64` are both
  valid; existing release workflow invocations are unchanged.

- **Registry grown to 75 known legitimate servers** — reduces false-positive SC-002
  (unknown server) and TRANSPORT-003 (unverified package) findings for common
  community packages. Eleven new entries added covering major ecosystem integrations:
  `@github/github-mcp-server` (GitHub), `@playwright/mcp` (Microsoft), `tavily-mcp`
  (Tavily AI), `firecrawl-mcp` (Firecrawl), `mcp-server-qdrant` (Qdrant),
  `@neondatabase/mcp-server-neon` (Neon), `@shopify/dev-mcp` (Shopify),
  `mcp-atlassian` (community Atlassian connector), `@agentdeskai/browser-tools-mcp`
  (AgentDesk), `@azure/mcp` (Microsoft Azure), and `langchain-mcp-adapters`
  (LangChain). Registry size: 64 → 75.

- **`semgrep` added to dev extras** — contributors can now run
  `uv sync --extra dev && semgrep --config semgrep-rules/ src/mcp_audit/` without
  a separate Semgrep install. Semgrep self-scan result: 34 Python rules, 73 files,
  0 findings. See `GAPS.md` § "Self-scan results" for full details.

- **TypeScript SAST: 7 new rule categories (11 rules) close the gap with Python** —
  TS rule count: 18 → 29 (total SAST pack: 52 → 63 rules).
  - `mcp-ts-credential-default-param` (CWE-798/HIGH): hardcoded string used as
    default value for a credential-named function parameter; covers `function`,
    `async function`, and arrow function forms.
  - `mcp-ts-console-log-sensitive` (CWE-532/HIGH): sensitive identifier (name
    matching `key|token|secret|password|auth|credential`) passed to
    `console.log`, `console.debug`, or `console.warn`; string literals excluded.
  - `mcp-ts-console-error-sensitive` (CWE-532/HIGH): same as above for
    `console.error`.
  - `mcp-ts-description-contains-url` (CWE-1336/HIGH): HTTP/HTTPS URL embedded
    in a variable or object property named `description` or `desc`.
  - `mcp-ts-description-base64-content` (CWE-1336/HIGH): 20+ consecutive base64
    characters in a description variable or object property.
  - `mcp-ts-description-unicode-escape` (CWE-1336/MEDIUM): `\uXXXX` escape
    sequence in a description string assignment or object literal.
  - `mcp-ts-no-type-check-before-use` (CWE-20/MEDIUM): MCP tool argument accessed
    via `args[key]` and passed directly to a function inside an async handler
    without a `typeof` guard; high FP rate — suppress with `// nosemgrep` when
    Zod/Joi validation is present.
  - `mcp-ts-error-stack-in-return` (CWE-209/HIGH): `err.stack` returned from an
    async function — stack trace disclosure.
  - `mcp-ts-error-tostring-in-return` (CWE-209/MEDIUM): `String(err)` or
    `err.toString()` returned from an async function — raw exception disclosure.
  - `mcp-ts-express-listen-all` (CWE-605/HIGH): `$APP.listen(port, "0.0.0.0")`
    or `$APP.listen(port, "")` — server binds to all interfaces.
  - `mcp-ts-http-listen-all` (CWE-605/HIGH): `listen({host: "0.0.0.0"})` — Fastify
    or Node HTTP/HTTPS server binds to all interfaces.
  New test fixtures in `semgrep-rules/tests/typescript/<category>/<rule>/` (14
  files: one `vulnerable/test.ts` and one `safe/test.ts` per rule file). All 7
  rule files pass `semgrep --validate`; each vulnerable fixture triggers the rule
  and each safe fixture produces zero findings.
  Sources: CWE-798, CWE-532, CWE-1336, CWE-20, CWE-209, CWE-605, OWASP A07/A09/
  A05:2021, CVE-2026-41495 (n8n-MCP), CVE-2026-33032. See `PROVENANCE.md`.

---

## [0.6.0] - 2026-04-30

### Added
- **Fleet merge: D3-powered HTML dashboard** — `mcp-audit merge --format html`
  now produces a polished, self-contained fleet dashboard (replacing the previous
  Rich-table HTML export).  The new dashboard includes:
  - Header with fleet-level grade badge (worst-case machine grade A–F),
    total machines, total findings, Crit+High count, average score, and
    generation timestamp.
  - Machine grid — one card per machine with hostname, colour-coded grade badge,
    per-severity finding counts, and a mini severity-distribution bar chart.
    Click a card to filter the findings table to that machine.
  - Filterable, sortable findings table — filter by severity (pill buttons),
    machine (dropdown), or analyzer (dropdown); sort by any column.
  - Light/dark mode toggle (matching the per-scan dashboard).
  - Fully self-contained — D3 v7 bundled inline, zero CDN references, renders
    offline.
  Files changed: `src/mcp_audit/fleet/merger.py` (replaced `_FLEET_HTML`
  template and `generate_fleet_html()`), `docs/fleet-scanning.md`.

- **SAST: 7 new TypeScript rules** — path traversal (3), SQL injection (2), SSRF (2) —
  bringing the TypeScript rule count from 11 to 18 (total SAST pack: 52 rules).
  - `mcp-ts-fs-readfile-traversal` (HIGH/CWE-22): `fs.readFile`/`readFileSync` with
    unvalidated variable path.
  - `mcp-ts-fs-writefile-traversal` (HIGH/CWE-22): `fs.writeFile`/`appendFile` with
    unvalidated variable path.
  - `mcp-ts-path-join-traversal` (MEDIUM/CWE-22): `path.join()` with variable
    component and no inline `path.resolve()`.
  - `mcp-ts-string-concat-sql` (CRITICAL/CWE-89): string concatenation of a SQL
    keyword string into `db.query()`/`pool.query()`.
  - `mcp-ts-unsafe-query-variable` (HIGH/CWE-89): non-literal (template literal or
    variable) first argument to SQL query functions — catches template literal
    interpolation (`\`SELECT ... ${userId}\``) that the concat rule cannot detect.
  - `mcp-ts-fetch-ssrf` (HIGH/CWE-918): `fetch()`/`axios` called with a non-literal
    URL — SSRF risk.
  - `mcp-ts-http-request-ssrf` (HIGH/CWE-918): `https.request()`/`http.request()`
    called with a non-literal URL — SSRF risk.
  New Semgrep test fixtures in `semgrep-rules/tests/typescript/vulnerable/`
  (`path_traversal_examples.ts`, `sqli_examples.ts`, `ssrf_examples.ts`).
  Safe patterns for all new rules added to
  `semgrep-rules/tests/typescript/clean/safe_server.ts`.
  11 new unit tests in `tests/test_sast.py` covering severity mapping, analyzer tag,
  CWE propagation, and finding ID format for each new rule.
  Sources: OWASP Path Traversal, OWASP SQLi Prevention, OWASP SSRF Prevention,
  CWE-22, CWE-89, CWE-918. See `PROVENANCE.md`.

- Live connection (`--connect`): server stderr is now captured and suppressed
  from the terminal.  Use `--verbose` (new flag) to print captured server output
  under a "Server output" header after the scan.  Captured logs also appear in
  the `server_logs` array in JSON output.  Prevents MCP server startup messages
  from interleaving with mcp-audit's Rich output.
- `--connect-token TOKEN` (new flag): passes `Authorization: Bearer <token>` on
  SSE/HTTP MCP server connections.  Enables scanning of enterprise MCP servers
  that require authentication.  Silently ignored for stdio servers.  Token is
  never stored, logged, or included in any output format.
- 401/403 HTTP responses from SSE servers now produce a clear, actionable error
  message (e.g. `"401 Unauthorized — use --connect-token to provide credentials"`)
  instead of a raw Python traceback.
- `ScanResult.server_logs` field: `list[str]` of captured stdio server stderr,
  populated during `--connect` runs; empty for static-only scans.
- `docs/live-connection.md`: new documentation covering `--connect`, stderr
  suppression, `--connect-token`, auth error messages, and troubleshooting.

---

## [0.5.1] - 2026-04-30

### Added
- Fleet merge: `--dir` now recurses into subdirectories to collect JSON scan
  outputs from nested CI artifact layouts (e.g. `dir/team-a/machine1.json`,
  `dir/team-b/machine2.json`). Existing flat-directory usage is unchanged.
  `_collect_json_paths_from_dir()` changed from `glob("*.json")` to
  `rglob("*.json")`; four new unit/integration tests added in `test_fleet.py`.
- Extension scanner: add Windows paths for VS Code (`%APPDATA%\Code\extensions`),
  VS Code Insiders (`%APPDATA%\Code - Insiders\extensions`), Cursor
  (`%USERPROFILE%\.cursor\extensions`), and Windsurf
  (`%USERPROFILE%\.windsurf\extensions`).  Paths are resolved at call time from
  environment variables and silently skipped when the variable is absent.
  Covered by five new unit tests in `tests/test_extensions.py`
  (`TestWindowsExtensionPaths`) that run on all CI platforms via monkeypatching.
- `scripts/update_test_count.py` now also validates SAST rule count (total,
  Python, TypeScript breakdown), community rule count, and concrete analyzer
  count in addition to the existing test-count check — prevents v0.5.0-style
  doc drift in CI.

### Fixed
- `--offline` flag help text now accurately describes current behaviour: the
  flag prevents combining with `--verify-hashes`, `--verify-signatures`,
  `--check-vulns`, and `--connect` (exit code 2 if combined), but a plain scan
  already makes no network calls so the flag is a no-op for the default
  configuration. Updated `docs/enterprise-deployment.md`,
  `docs/supply-chain.md`, and `CLAUDE.md` to match.
- Stale feature counts in `README.md` and `CLAUDE.md` after v0.5.0: SAST rules
  37→45 (28→34 Python, 9→11 TypeScript), community rules 12→13, analyzer count
  6→7; added `ConfigHygieneAnalyzer` and `Finding.cve` / CVE tagging mentions to
  the README Features section.
- Supply chain: tighten Levenshtein typosquatting threshold for short package
  names (≤5 chars) from 3→1 to reduce false positives. Names of 6+ characters
  keep the existing threshold of 3. Legitimate typosquats differing by exactly 1
  character (e.g., `mcq` vs `mcp`) still fire SC-001 at CRITICAL severity.

---

## [0.5.0] - 2026-04-27 — April 2026 Security Sweep

> **Lead:** CVE-tagged findings, a new auth SAST category catching MCPwn and the
> n8n-MCP token-logging class, and a config-file hygiene analyzer anchored to
> the Bitwarden supply-chain incident.

### Added
- **`Finding.cve` field.** Every finding can now carry a list of CVE identifiers.
  Populated on TRANSPORT-004, COMM-002, COMM-006, COMM-010, COMM-012, COMM-013,
  and all new auth SAST rules. Surfaces in terminal output (dim red badge), JSON,
  and SARIF `result.properties["cve"]`.
- **COMM-013: npx auto-confirm flag.** New community rule — HIGH / MCP04+MCP05 —
  fires when `npx`/`bunx`/`pnpx` is invoked with `--yes` or `-y`, bypassing the
  user-confirmation prompt. This is the silent-execution pattern from the OX
  Security STDIO disclosure. Tagged with all six OX CVEs (CVE-2025-49596,
  CVE-2026-22252, CVE-2026-22688, CVE-2025-54994, CVE-2025-54136, CVE-2026-30615).
- **CVE cross-references on existing findings.** TRANSPORT-004 and COMM-012 now
  carry `CVE-2026-33032` (MCPwn, CVSS 9.8); COMM-002 carries `CVE-2026-22252`;
  COMM-006 carries `CVE-2026-22688`; COMM-010 carries `CVE-2025-49596`.
- **Auth SAST category (`semgrep-rules/*/auth/`).** New 6th category, 8 rules
  across Python and TypeScript:
  - `mcp-route-missing-auth-middleware` — parallel `/mcp*` route with no auth
    dependency (MCPwn pattern, CVE-2026-33032). ERROR.
  - `mcp-empty-allowlist-allow-all` — `if not allowlist: return True/pass`
    (empty-allowlist-means-allow-all, CVE-2026-33032). WARNING.
  - `mcp-wellknown-route-no-auth` — `/.well-known/` route with no auth. WARNING.
  - `mcp-authorization-header-logged` — `logging.*(request.headers)` before auth
    check (n8n-MCP class, CVE-2026-41495, CWE-532). WARNING.
  - `mcp-api-key-header-logged` — logger call where variable name matches
    API key / bearer token patterns (CWE-532). WARNING.
  - `mcp-full-request-body-logged-on-fail` — request body logged inside an except
    block (CWE-532). INFO.
  - TypeScript equivalents for route-missing-auth and auth-header-logged.
- **`ConfigHygieneAnalyzer` (`analyzers/config_hygiene.py`).** New default-pipeline
  analyzer grading MCP config file posture. Anchored to the Bitwarden supply-chain
  incident (2026-04-22) — malware explicitly targeted `~/.claude.json`,
  `~/.claude/mcp.json`, and `~/.kiro/settings/mcp.json`. Four new finding IDs:
  - `CFHYG-001` HIGH — config file is world-readable (POSIX `o+r`). CWE-732.
  - `CFHYG-002` HIGH — config file in a world-writable ancestor directory. CWE-732.
  - `CFHYG-003` HIGH — plaintext secret inline (Bitwarden malware target profile). CWE-312.
  - `CFHYG-004` INFO — all env values use env-var references (positive signal).
  - Runs in the default pipeline with no flag required. Windows ACL checking deferred.

### Changed
- `PolicyRule` now accepts a `cve:` list; the rule engine threads it through to
  emitted `Finding` objects.
- TRANSPORT-004 description names CVE-2026-33032 (MCPwn) explicitly.
- COMM-012 description and message updated to reference MCPwn.
- `mcp-listen-all-interfaces.yml` metadata includes `cve: CVE-2026-33032` and
  a references URL.
- `docs/severity-framework.md` updated with COMM-013 row, CVE annotations, and
  new config hygiene and auth SAST tables.
- SAST rule count: 37 → 45 (28 → 34 Python, 9 → 11 TypeScript), 5 → 6 categories.
- Test count: 1,361 → 1,391.

---

## [0.4.0] - 2026-04-25 — OWASP MCP Top 10 field alignment

> **Lead:** OWASP MCP Top 10 mapping on every finding — `owasp_mcp_top_10` field
> in JSON, SARIF taxonomy block + per-rule relationships for Code Scanning, and
> `mcp-audit scan --owasp-report` for a category-level aggregated view.

### Added
- **OWASP MCP Top 10 mapping on every finding.** `Finding.owasp_mcp_top_10`
  carries a list of `MCP01`–`MCP10` category codes. Every shipped finding ID
  is pre-populated; empty list = unmapped. Single source of truth lives in
  `src/mcp_audit/owasp_mcp.py`.
- **SARIF taxonomy block.** SARIF output now includes a `runs[0].taxonomies`
  `toolComponent` for the OWASP MCP Top 10 (stable GUID
  `f1a3c4d5-9e6b-4a7d-8b2c-1f9e0a3d5c7e`). Each rule gains a `relationships`
  array referencing applicable taxa, plus a `properties["owasp-mcp-top-10"]`
  mirror for consumers that don't honour the taxonomy mechanism.
- **Terminal inline codes.** The per-finding terminal renderer now shows
  `[MCP03, MCP06]` in dim cyan next to the title when codes are present.
  Unmapped findings (positive signals, etc.) are unaffected.
- **`mcp-audit scan --owasp-report`.** After the normal scan output, prints
  a category-level summary table — how many findings triggered each MCP Top
  10 category and their severity breakdown. Suppressed when no findings carry
  codes. Does not affect exit codes, severity threshold, or score.
- **Community rule and governance YAML** both accept `owasp_mcp_top_10:` and
  propagate it through to emitted `Finding` objects.
- **Semgrep SAST rules** carry `metadata.owasp-mcp-top-10`; `sast/runner.py`
  copies the field onto the resulting `Finding`.
- **`docs/owasp-mcp-top-10.md`** — new reference page covering terminal, JSON,
  SARIF output, the `--owasp-report` flag, and implementation notes.
- **`docs/severity-framework.md`** updated with an OWASP MCP Top 10 column in
  every per-analyzer mapping table and a new reference section at the bottom.

### Fixed
- Added `# nosec B104` suppression to the `_WILDCARD_HOSTS` detection-pattern
  string in `analyzers/transport.py`, eliminating a bandit false positive that
  had been silently leaking into scans.

---

## [0.3.3] - 2026-04-24 — Patch: close the PyPI publish gap

The release pipeline has been tagging versions and attaching
PyInstaller binaries to GitHub Releases since `v0.1.1` — but it never
published to PyPI. `pip install mcp-audit-scanner` still resolved to
`0.1.0` (the last manual upload), and the composite `action.yml`
silently installed `0.1.0` at runtime on every `@v0.3.x` invocation
because its `pip install mcp-audit-scanner` step had no newer version
to find.

No schema / API changes — drop-in patch. Bump
`adudley78/mcp-audit@v0.3.2` → `@v0.3.3`. From this release forward,
every `v*.*.*` tag push automatically publishes to PyPI; users can
`pip install --upgrade mcp-audit-scanner` normally.

### Added
- **PyPI Trusted Publishing (OIDC) pipeline** in `.github/workflows/release.yml`.
  Runs in parallel with the GitHub Release job so a transient PyPI
  outage never withholds the binary release (and vice versa). No
  `PYPI_API_TOKEN` secret to manage or rotate; PyPI mints a
  short-lived credential for each workflow run via GitHub's OIDC
  issuer, scoped to the `pypi` GitHub Environment.
- **PEP 740 sigstore attestations** (`attestations: true`) —
  published alongside the wheel and sdist, binding each artefact to
  the workflow run that produced it. Surfaced on the PyPI project
  page so downstream consumers can verify provenance.
- **Supply-chain-hardened action pinning** — `pypa/gh-action-pypi-publish`
  pinned to the v1.14.0 commit SHA (`cef221092ed1bacb1cc03d23a2d87d1d172e277b`,
  signed tag, PGP-verified by @webknjaz) rather than the floating
  `release/v1` branch. A floating ref could be silently moved to a
  malicious commit; a SHA cannot.

### Skipped
- **Backfilling `0.1.1`–`0.3.2` to PyPI.** PyPI versions are
  effectively immutable (you can yank, not delete), so publishing
  `0.3.0` and `0.3.1` now would permanently put two known-broken
  releases in the registry — the opposite of what the "superseded"
  banners on their GitHub Releases are trying to prevent. Users go
  directly from `0.1.0` → `0.3.3` via `pip install --upgrade`.

---

## [0.3.2] - 2026-04-24 — Patch: isolate Semgrep install from mcp-audit deps

Supersedes `v0.3.1`, which fixed the `v0.3.0` "Semgrep not installed"
error by invoking `pip install semgrep` inside the composite action's
`run-sast` step — but that plain-pip install downgrades `click` from
`8.2.x` to `8.1.8` (Semgrep pins `click<8.2`), which then breaks
`typer>=0.24` at import with:

```
TypeError: type 'Choice' is not subscriptable
  at typer/_types.py:9 → class TyperChoice(click.Choice[...])
```

Drop-in patch — no schema / API changes. Bump
`adudley78/mcp-audit@v0.3.1` → `@v0.3.2`.

### Fixed
- **`run-sast: 'true'` broke mcp-audit itself** via dep conflict.
  Switched the composite action from `pip install semgrep` to
  `pipx install semgrep`.  `pipx` ships pre-installed on every
  GitHub-hosted Ubuntu runner, installs Semgrep into its own isolated
  venv, and places the `semgrep` binary on PATH without touching the
  `mcp-audit-scanner` environment — zero dep pollution.

---

## [0.3.1] - 2026-04-24 — Patch: unbreak action self-tests and example pinning

Fixes three independent regressions that shipped with `v0.3.0` and surfaced
as CI failures on `main` minutes after the tag landed. `v0.3.1` is a
drop-in replacement — users should bump `adudley78/mcp-audit@v0.3.0` →
`@v0.3.1` in their workflows. No input / output schema changes.

### Fixed
- **`run-sast: 'true'` failed at runtime** with `semgrep is not installed`.
  The Semgrep CLI is intentionally not bundled in `mcp-audit-scanner` (the
  ~15 MB dependency would bloat the wheel and the PyInstaller binary for
  the ~95% of users who never opt into SAST). The composite action now
  installs Semgrep inside the `run-sast: 'true'` step
  (`pip install semgrep --quiet`), so the cost is pay-for-what-you-use and
  SAST is zero-config for opt-in users.
- **`@v1` tag references everywhere** — `.github/workflows/mcp-audit-example.yml`,
  `docs/github-action.md`, `docs/docs-usage.md`, `examples/github-actions/*.yml`
  — pointed at a non-existent tag. Users copying our docs verbatim would
  see `Unable to resolve action adudley78/mcp-audit@v1`. Pinned everything
  to a real release tag (`@v0.3.1`) and added a **Version pinning** section
  to `docs/github-action.md` documenting the convention: pin to a specific
  release tag today; `@v1` will track the latest 1.x release once v1.0.0
  ships (standard GitHub Marketplace floating-tag pattern).
- **Test-count drift check** failed on `ubuntu-latest/3.12` — docs said
  `1,342 tests` (macOS collection count) but the CI canonical is `1,308`.
  Commit `12bcd3c` already established that the docs track the CI
  canonical to avoid the long-standing macOS↔Linux skipif-import delta.
  Realigned `CLAUDE.md` and `README.md`.

### Docs
- Corrected a stale CLAUDE.md / `docs/github-action.md` line that claimed
  Semgrep ships bundled in `mcp-audit-scanner`. Only the Semgrep rule pack
  (`semgrep-rules/`, 37 rules) is bundled; the CLI binary is not.

---

## [0.3.0] - 2026-04-24 — GitHub Marketplace Action

### Added
- **GitHub Action wrapper** (`action.yml`) — composite action ready for
  Marketplace listing. No Docker; installs `mcp-audit-scanner` from PyPI and
  invokes the CLI via `shell: bash`. Uploads SARIF to GitHub Code Scanning
  via `github/codeql-action/upload-sarif@v4` (continue-on-error so repos
  without Code Scanning still run cleanly).
- **New input schema** — `config-paths`, `severity-threshold`, `sarif-output`,
  `upload-sarif`, `check-vulns`, `verify-signatures`, `run-sast`, `sast-path`,
  `baseline-name`, `fail-on-findings`, `version`. The composite action writes
  SARIF via `--format sarif --output` (never the non-existent `--sarif` flag)
  and invokes `mcp-audit baseline compare <name>` positionally.
- **New outputs** — `findings-count`, `grade`, `sarif-path`. Consumable by
  downstream steps via `steps.<id>.outputs.<name>`.
- **`.github/workflows/action-ci.yml`** — self-tests the composite on every
  push / PR: one run against `demo/configs/` and one with `run-sast: true`
  against `src/`.
- **`docs/github-action.md`** — rewritten against the new schema. Quick-start,
  full example, inputs / outputs tables, permissions, scenarios, exit-code
  behaviour, troubleshooting, and SARIF-upload verification checklist.
- **`tests/test_action_yaml.py`** — 13 structure + security guardrails
  covering branding, required top-level keys, input/output schema stability,
  old-name removal, hardcoded-secret patterns, `--sarif` flag typo, and the
  `upload-sarif@v4` pin.

### Changed
- **`tests/test_github_action.py`** — migrated to the v1 input schema;
  two new guardrails assert old names (`format`, `sast`, `baseline`,
  `finding-count`) remain absent.
- **Example workflows** — `examples/github-actions/with-baseline.yml` now
  uses `baseline-name:`; the commented-out SAST block in
  `.github/workflows/mcp-audit-example.yml` uses `run-sast:`.
- **`README.md` / `docs/enterprise-deployment.md`** — stray
  `github/codeql-action/upload-sarif@v3` references bumped to `@v4` (v3
  runs on Node 20, deprecated 2026-06-02).
- **`pyproject.toml`** — author email switched to a GitHub noreply address;
  Homepage / Documentation URLs now point at the GitHub repository.
- **`SECURITY.md`** — security disclosure channel switched to GitHub's
  private vulnerability reporting.
- **`CLAUDE.md`** — repo-map and feature blurb synced to the v1 action
  schema; test count bumped to 1,342.

---

## [0.2.0] - 2026-04-24 — Remove paid-license infrastructure

mcp-audit has been Apache-2.0-licensed since the first public release, but
the codebase kept the full paid-license machinery around "just in case" —
Ed25519 key verification, a bundled certificate revocation list, a feature
gate helper, and the `activate` / `license` CLI commands. There are no
paying users and no plan to add any, so that entire layer is now gone.
This is a semver-major change because it deletes two CLI commands.

### Removed
- **`src/mcp_audit/licensing.py`** — Ed25519 license-key verification, `LicenseInfo` model, `is_pro_feature_available()`, `generate_license_key()`, bundled revocation list loading. Gone in one shot.
- **`src/mcp_audit/_license_cache.py`** — `lru_cache`'d wrapper around `get_active_license` / `is_pro_feature_available` that shaved repeated disk reads per scan. No longer needed.
- **`src/mcp_audit/_gate.py`** — the `gate(feature, console)` shim that used to print upsell panels. Every call site is deleted (five CLI modules: `extensions`, `fleet`, `policy`, `registry`, `rules`).
- **`src/mcp_audit/cli/license.py`** — `activate` / `license` Typer commands. The `version` command lived here too and was moved to `src/mcp_audit/cli/version.py`.
- **`scripts/generate_license.py`** — dev-only Ed25519 key issuance and revocation-list signer.
- **`src/mcp_audit/data/revoked.json`** — bundled certificate revocation list (signed by the placeholder key, effectively inert).
- **Test modules:** `tests/test_licensing.py`, `tests/test_licensing_revocation.py`, `tests/test_license_cache.py`, `tests/test_gate.py` (50 tests total). Every remaining test file that patched `mcp_audit.cli.cached_is_pro_feature_available` or `mcp_audit.licensing.get_active_license` now invokes the real (un-gated) code path.
- **`tests/conftest.py::_clear_license_cache`** autouse fixture.
- Documentation references to Pro / Enterprise tiers, `_FEATURE_TIERS`, the paid-tier landing page, Lemon Squeezy / Gumroad issuance, and the "Legacy License Commands" section of `docs/docs-usage.md`.

### Changed
- **`pyproject.toml`:** `cryptography>=46.0.6,<47.0` moved from core dependencies to the `[attestation]` optional extra. It is now only needed by `attestation/sigstore_client.py` for Fulcio-certificate X.509 parsing, and `sigstore` pulls it in transitively anyway — the explicit pin in `[attestation]` keeps the floor intact against future sigstore upgrades.
- **`build.py` and all four `.spec` files:** dropped the `mcp_audit.licensing` hidden import and the three `cryptography.hazmat.*` / `cryptography.exceptions` hidden imports that only existed for the licensing module. Added `mcp_audit.cli.version` as a replacement for the retired `mcp_audit.cli.license`.
- **`src/mcp_audit/cli/__init__.py`:** no longer re-exports `cached_is_pro_feature_available`; submodule import list now pulls `version` instead of `license`.
- **CLI docstrings:** stripped every "Requires a Pro or Enterprise license" line from `cli/extensions.py`, `cli/fleet.py`, `cli/policy.py`, `cli/registry.py`, `cli/rules.py`. The `rule list` command now shows user-local rules whenever `<user-config-dir>/mcp-audit/rules/` exists — the `cached_is_pro_feature_available("custom_rules")` guard that used to wrap it is gone.

### Added
- **`.github/workflows/ci.yml` — `test-all-extras` job.** Installs the project with `.[dev,sbom,attestation,mcp]` on `ubuntu-latest` / Python 3.12 and runs the full test suite, so the nine SBOM tests and the attestation / live-MCP paths that the default `[dev]`-only matrix silently skipped are now actually exercised on every PR.

### Version
- `pyproject.toml` and the `__version__` fallback bumped to `0.2.0`. The previous `0.1.2` binary remains the last gated-code-complete build; anyone who needs the `activate` / `license` commands for reasons unknown can still run v0.1.2 — it does nothing useful, but it works.

---

## [0.1.2] - 2026-04-24 — Release infrastructure fix, dependency widening

The `v0.1.1` tag was cut on 2026-04-24 but never produced a GitHub release: the `Build darwin-x86_64` matrix leg targeted the `macos-13` runner image, which GitHub [retired on 2025-12-08](https://github.blog/changelog/2025-09-19-github-actions-macos-13-runner-image-is-closing-down/). Jobs requesting that label queue indefinitely instead of erroring, so every v0.1.1 release run hung. `0.1.2` is the first successful release under the new semver line; no user-facing code changed between 0.1.0 and 0.1.2.

### Fixed
- **`.github/workflows/release.yml`:** migrated the `darwin-x86_64` matrix leg from the retired `macos-13` runner to `macos-15-intel` (GitHub's replacement x86_64 label, supported through 2027-08). After that date, Actions drops x86_64 macOS entirely and this leg will need to be removed — Apple Silicon Macs run the x86_64 binary transparently via Rosetta in the meantime.
- **`src/mcp_audit/__init__.py`:** `__version__` now looks up the correct PyPI distribution name (`mcp-audit-scanner`, not `mcp-audit`). Every prior release silently fell through to the hard-coded `"0.1.0"` fallback because the metadata lookup used the CLI command name instead of the wheel name, so the embedded version string on released binaries was always stale. Fallback bumped to `"0.1.2"` for source installs.

### Changed
- **`pyproject.toml`:** `cyclonedx-python-lib>=7.0,<12.0` (was `<8.0`) — the `[sbom]` extra now installs against v7 or v8–v11 transparently. `src/mcp_audit/output/cyclonedx.py` was ported to the v8+ `cyclonedx.model.tool.Tool` location and `ToolRepository` metadata API with a v7 fallback, and all cyclonedx imports are now deferred into `format()` so the module imports cleanly when the extra is absent (previously raised `NameError` on any import with the extra missing — the no-extra fallback path was silently broken). Added `tests/test_cyclonedx_output.py` (9 cases) covering both the extra-missing path and formatter output against v7–v11.
- **`pyproject.toml`:** `sigstore>=3.0,<5.0` (was `<4.0`), `rich>=13.0,<16.0` (was `<14.0`), `watchdog>=4.0,<7.0` (was `<6.0`). Dependabot updates; no code changes required.

### Tooling
- **`actions/checkout@v6`** (was v5) across all four workflows.
- **`github/codeql-action@v4`** (was v3).
- **`softprops/action-gh-release@v3`** (was v2).

---

## [0.1.0] - 2026-04-23 — First public PyPI release

Version set to `0.1.0` (clean-slate public semver; internal development milestones tracked separately in `[0.11.x]` entries below).

**PyPI package name: `mcp-audit-scanner`** — the `mcp-audit` name was already
claimed on PyPI. The CLI command remains `mcp-audit` in all cases.

```bash
pip install mcp-audit-scanner
uv add mcp-audit-scanner
```

### Changed
- `pyproject.toml`: Development Status bumped from Alpha → Beta.
- `pyproject.toml`: Keywords expanded for PyPI search discoverability.
- `pyproject.toml`: URLs block updated — Homepage, Documentation, and Changelog links added.
- `README.md`: Install instructions updated to `pip install mcp-audit-scanner`; git+ source install removed.

---

## [0.11.0-internal] - 2026-04-23 — Open Source Conversion (internal dev milestone)

### Changed
- **All features are now free.** mcp-audit is fully open source under Apache 2.0. There are no paid tiers. `is_pro_feature_available()` always returns `True`; `gate()` is a permanent no-op. This removes the Community / Pro / Enterprise split entirely.
- **`sast.py`** — dropped `gate("sast", ...)` call and "(Pro feature)" wording from command docstring.
- **`dashboard.py`** — dropped `gate(...)` calls, "(Pro/Enterprise)" help text on `--rules-dir`, and the `html is None` dead branch (unreachable since `generate_html()` always returns a string).
- **`scan.py`** — removed `vuln_mirror`, `sast`, `extensions`, and `custom_rules` gates; dropped "(Pro)" from `--format` help text.
- **`license.py`** — `version` no longer prints a tier; `activate` / `license` commands label themselves as legacy key handling on an open-source build and no longer reference the paid-tier landing page.
- **`CLAUDE.md`** — "Business model" section rewritten; all "Pro/Enterprise" / `_FEATURE_TIERS` references removed; `_gate.py` reframed as a permanent no-op shim.
- **`CONTRIBUTING.md`** — "Adding a new Pro feature" section replaced with open-source workflow; "won't accept" list bars re-introducing paid tiers.
- **`rules/README.md`** — dropped "(requires Pro)" from `rule validate` instruction.

### Removed
- 43 gate-specific tests deleted across `test_license_cache.py`, `test_dashboard.py`, `test_push_nucleus.py`, `test_fleet.py`, `test_governance.py`, `test_sast.py`, `test_extensions.py`, `test_registry.py`, `test_scanner.py`, `test_rules.py`. These tested behaviour that no longer exists. **1355 tests passing** (down from 1398; all removals are intentional).

### Notes
- `activate` and `license` commands are retained to honour any previously issued keys — they do nothing harmful on an open-source build.
- `scripts/generate_license.py` is retained (not shipped in the wheel) for the same reason.
- `push-nucleus` is ungated — it is the natural workflow for teams with a Nucleus instance, not a paywall.

---

## [0.10.1] - 2026-04-23 — SARIF 2.1.0 Schema Fixes

### Fixed
- **`invocation` extra fields** (`src/mcp_audit/output/sarif.py`, commit `46d9a34`): `machine`, `account`, and `operatingSystem` were placed directly on the `invocation` object. The SARIF 2.1.0 schema declares `invocation` with `additionalProperties: false`, making these unrecognised keys a hard schema violation. Fixed by moving all three into `invocation.properties` — a `propertyBag` (free-form key→value map) that the spec explicitly permits on every SARIF object.
- **`fixes` without `artifactChanges`** (`src/mcp_audit/output/sarif.py`, commit `46d9a34`): `result.fixes[*]` contained only `{"description": {"text": remediation}}`. The SARIF schema requires `artifactChanges` in every `fix` object, as `fixes` is designed for structured byte-level code patches, not free-text advice. Removed `fixes` entirely and moved the remediation string to `rule.help.text` (SARIF §3.49.11), the correct field for human-readable fix guidance.

### Changed
- **Playwright browser tests now pass** (previously skipped): `test_dashboard_compat.py` cross-browser tests (Chromium, Firefox, WebKit) run fully with browsers installed. Full suite: **1398 passed, 0 failed, 0 skipped**.

---

## [0.10.0] - 2026-04-23 — Nucleus FlexConnect Integration

### Added
- **`mcp-audit push-nucleus` command** (`src/mcp_audit/cli/push_nucleus.py`): Enterprise-gated command that runs a full scan and pushes results directly to a Nucleus Security project via the FlexConnect API. Multipart/form-data upload via `urllib.request` (no third-party HTTP lib). Polls job to completion with configurable timeout. Prints a Rich success panel with project ID, job ID, finding count, asset name, and a direct UI link. `--output-file` writes the FlexConnect JSON locally alongside the push. 11 tests in `tests/test_push_nucleus.py`.
- **Validated FlexConnect schema** (`src/mcp_audit/output/nucleus.py`): corrected from placeholder format to the live-validated schema. Top-level `assets` array defines the host asset; top-level `findings` array references it via `host_name`; `scan_type` is `"Host"`. Previously the formatter used a flat `host_name`/`asset_name` structure that was rejected by Nucleus ingestion ("Scan did not have any assets defined"). Validated end-to-end against a live Nucleus instance.
- **`scripts/validate_nucleus.py`**: retained as a standalone regression/validation tool for testing the FlexConnect shape against a live instance without running a full scan.

### Changed
- `_finding_to_nucleus()` now sets `host_name` per finding (linking to the `assets` entry) instead of `asset_name` with `{prefix}/{client}/{server}` formatting.
- `format_nucleus()`: `scan_type` changed from `"Application"` to `"Host"`; top-level `host_name`/`operating_system_name` envelope fields replaced by the `assets` array.
- `tests/test_nucleus_output.py`: 3 tests updated, 4 new tests added for the `assets` array structure.
- `tests/test_machine_info.py`: 7 stale `TestNucleusFormatter` tests updated to match the corrected format.

---

## [0.9.0] - 2026-04-23 — License Revocation & Commercial Infrastructure

### Added
- **Bundled certificate revocation list** (`src/mcp_audit/data/revoked.json`): signed with the same Ed25519 keypair as license keys; `_load_revoked_kids()` reads and verifies the list once at module import and caches the result in `_REVOKED_KIDS: frozenset[str]`. Returns an empty frozenset on any parse, missing-file, or signature failure — scans never hard-fail because the CRL is unsigned or corrupt (graceful degradation during development with the placeholder key).
- **`kid` and `sub` fields in license key payload**: `kid` (8-char lowercase hex, auto-generated via `secrets.token_hex(4)` if omitted) is the primary revocation handle, always included in new keys. `sub` (Lemon Squeezy order ID) is included when provided. Both fields are optional in `LicenseInfo` (`kid: str | None = None`, `subscription_id: str | None = None`) — existing keys without these fields are backward-compatible and treated as non-revocable (they expire naturally on their existing schedule).
- **Revocation check in `verify_license()`**: if `kid` is present in `_REVOKED_KIDS`, the function returns `None` immediately. Legacy keys without a `kid` field bypass the revocation check.
- **Thread-local failure discriminator** (`_set_last_verify_failure()` / `get_last_verify_failure()`): allows the CLI to surface `MCPA-LIC-REVOKED` vs `MCPA-LIC-EXPIRED` vs generic-invalid without leaking the reason into `LicenseInfo`. Error codes follow the `GOV-*` / `COMM-*` convention.
- **Discriminated error messages in `cli/license.py`**: `activate` command checks `get_last_verify_failure()` after a failed key save and prints the appropriate message: "License revoked. Contact the project's support alias with your order ID. [MCPA-LIC-REVOKED]", "License expired. [MCPA-LIC-EXPIRED]", or generic invalid.
- **`sign-revocation-list` sub-command in `scripts/generate_license.py`**: emits a signed `revoked.json` ready to commit. Usage: `python scripts/generate_license.py sign-revocation-list --kids a1b2c3d4,deadbeef --key-file ~/.mcp-audit-signing-key.pem --out src/mcp_audit/data/revoked.json`.
- **Operator audit log**: every key issuance appends a JSONL row to `~/.mcp-audit-issued-keys.jsonl` (permissions 0o600). Fields: `kid`, `email`, `sub`, `issued`, `expires`, `revoked`.
- **`tests/test_licensing_revocation.py`**: 12 new tests covering backward compat, `_load_revoked_kids` (empty list, revoked kid, tampered signature, missing file, malformed JSON, placeholder empty signature), `verify_license` revocation paths (valid-unrevoked, revoked kid, legacy key without kid), and the 90-day default issuance window.
- **No telemetry policy** (`docs/telemetry.md`): authoritative no-telemetry statement — what isn't collected, why, trade-offs accepted, and the bar any future opt-in change must clear. Linked from `docs/README.md` and `README.md`.

### Changed
- **Default key issuance window: 365 → 90 days** in `scripts/generate_license.py`. Natural expiry is the primary revocation mechanism; the bundled CRL is the break-glass for the 90-day window between a refund event and expiry.
- `generate_license_key()` gains `kid` and `sub` optional kwargs; both conditionally included in the signed payload.
- `GAPS.md` telemetry references consolidated to a single pointer to `docs/telemetry.md`.

### Notes
- The Cloudflare Worker webhook (Lemon Squeezy `order_created` → auto-issue, `order_refunded` → stop re-issuing) and the nightly GitHub Actions re-issue cron are a separate PR, pending domain and purchase URL going live.
- `src/mcp_audit/data/revoked.json` ships with `"signature": ""` until the real Ed25519 private key is available; `_load_revoked_kids()` returns `frozenset()` for this case — no scan impact.

---

## [0.8.0] - 2026-04-23 — Integration Validation: SARIF Hardening & Browser Compatibility

### Fixed
- **SARIF `%SRCROOT%` resolution** (`output/sarif.py`): Added `originalUriBaseIds` to the SARIF run object, anchoring `%SRCROOT%` to `file:///` per SARIF 2.1.0 §3.14.14. GitHub's code scanning API requires this definition to resolve relative artifact paths to repo-root-relative links in the Security tab.
- **SARIF `file:///unknown` fallback** (`output/sarif.py`): `_finding_to_file_uri` now returns the relative sentinel `"unknown"` instead of `"file:///unknown"` when `finding_path` is `None`. GitHub's SARIF uploader rejects the invalid absolute URI when `uriBaseId` is set; the relative form is accepted and gracefully omitted from source links.
- Updated 3 assertions in `tests/test_sarif_output.py` to match the corrected `"unknown"` sentinel.

### Added
- **`automationDetails.id` in SARIF output** (`output/sarif.py`): Run ID derived from scan timestamp. Prevents GitHub from creating duplicate code scanning alerts on repeated uploads of the same findings.
- **SARIF schema validation tests** (`tests/test_sarif_schema.py`): 10 tests validating mcp-audit SARIF output against the official OASIS SARIF 2.1.0 JSON schema (fetched once and cached at `tests/fixtures/sarif-schema-2.1.0.json`; tests skip gracefully if neither cache nor network is available). Covers run structure, `originalUriBaseIds` presence, `automationDetails`, finding shape, `uriBaseId` values, and version field.
- **`jsonschema>=4.0` and `playwright>=1.40`** added to `[project.optional-dependencies] dev` in `pyproject.toml`.
- **`docs/github-action.md` — SARIF upload verification guide**: 5-step manual checklist for confirming SARIF output reaches the GitHub Security tab, including common failure causes (`%SRCROOT%` unresolved, `file:///unknown` rejection, missing `write` permission on `security-events`).
- **Dashboard browser compatibility tests** (`tests/test_dashboard_compat.py`): 7 tests total. Three parametrised Playwright tests (Chromium / Firefox / WebKit) verify no JS console errors, grade badge visible (`.grade-badge`), finding rows present (`.findings-table`), dark-mode toggle works (`.theme-toggle`), and SVG attack graph rendered (`#graph-svg`). Four structural tests run without a browser: no external CDN references in dashboard HTML, D3 bundled inline, scan data JSON embedded, grade letter present. Playwright tests skip gracefully when browser binaries are not installed.
- **Playwright browser install step** in `.github/workflows/ci.yml`: runs `playwright install --with-deps chromium firefox webkit` on the `ubuntu-latest / 3.12` leg only, before the test step. Browser tests are skipped on all other matrix legs.
- `GAPS.md` — "SARIF not tested with GitHub" and "Dashboard browser compatibility untested" items resolved (2026-04-23).

---

## [0.7.0] - 2026-04-23 — Platform Coverage & CI Hardening

### Added
- **End-to-end binary smoke test** (`scripts/smoke_test.py`): cross-platform Python script (stdlib only) that runs 8 checks against the built binary: `version`, `discover`, scan of a malicious fixture (asserts exit 1), JSON output validity (findings, score, per-finding keys), clean scan (asserts exit 0), `--severity-threshold critical` filtering, SARIF 2.1.0 structure, and baseline save/list/delete roundtrip.
- **Smoke test fixture** (`tests/fixtures/smoke_test_config.json`): self-contained config with a poisoned server (triggers POISON-001) and a credential server (triggers credential finding via `sk-[A-Za-z0-9]{20,}` pattern). Used by both the binary smoke test and `tests/test_smoke_fixture.py`.
- **`tests/test_smoke_fixture.py`**: 4 unit tests that keep the smoke fixture honest without requiring a binary build — verifies POISON-001, a credential finding, and at least one finding overall.
- **Binary size gate** in `release.yml`: warns at 25 MB, fails at 35 MB. Actual size post-sigstore is ~22–24 MB; thresholds will be tightened after first rebuild measurement.
- **Release job summary** (`report` job in `release.yml`): posts a binary-size table to the GitHub job summary after every release build.
- **PR-level binary build** (`binary-smoke` job in `ci.yml`): builds the Linux x86_64 binary with PyInstaller and runs the full smoke test on every PR and push to `main`. Catches PyInstaller breakage before tagging.

### Fixed
- `release.yml` — replaced one-line `mcp-audit version` smoke test with the full 8-check `smoke_test.py` workflow on all four platforms.

---

## [0.6.0] - 2026-04-23 — Supply Chain Layers 2 & 3

### Added
- **Layer 2: Sigstore provenance verification** (`attestation/sigstore_client.py`, `attestation/sigstore_findings.py`): opt-in `--verify-signatures` flag (free, default OFF) verifies Sigstore provenance bundles for registry-known npm and PyPI packages. Fetches bundles from the npm attestations API and PyPI PEP 740 provenance API; verifies with the `sigstore` Python library (Fulcio cert chain, SCT, Rekor inclusion proof); extracts OIDC issuer (OID `1.3.6.1.4.1.57264.1.1`) and SAN URI from the signing certificate; compares signing repo against `RegistryEntry.repo`. `--strict-signatures` raises "absent" findings from INFO to MEDIUM. Six new finding IDs: `ATTEST-010` (valid match, INFO), `ATTEST-011` (valid but wrong repo, HIGH), `ATTEST-012` (invalid signature, CRITICAL), `ATTEST-013` (expected attestation absent, MEDIUM), `ATTEST-014` (absent, INFO/MEDIUM), `ATTEST-015` (network error, INFO). `attestation_expected: bool = False` field added to `RegistryEntry`; set to `true` for all 26 Anthropic-maintained entries in the registry.
- `sigstore>=3.0,<4.0` added to package dependencies.
- `docs/supply-chain.md` — Layer 2 section documenting all finding IDs, flag behaviour, and `--strict-signatures` usage.
- `docs/severity-framework.md` — `ATTEST-010` through `ATTEST-015` severity table.

- **Layer 3: Known-vulnerability scanning** (`vulnerability/` module): opt-in `--check-vulns` flag (free, default OFF) resolves transitive dependencies via the deps.dev API and checks them against OSV.dev in a single batched call. Full transitive graph coverage (not just direct deps). Graceful degradation on network failure per batch — scan never crashes. `VULN-<OSV-ID>` findings (severity from CVSS score), `VULN-UNPINNED` (LOW) for unversioned packages. Supports npx/bunx/pnpx/uvx/pipx/yarn-dlx ecosystems via the shared `vulnerability/resolver.py`. `--vuln-registry URL` (Pro soft-gate) for air-gapped OSV mirrors.
- **`mcp-audit sbom` command** (`cli/sbom.py`): generates a CycloneDX 1.5 JSON SBOM for all configured MCP servers and their transitive dependencies. `cyclonedx-python-lib` is an optional `[sbom]` extra (not bundled in the PyInstaller binary); the command prints a clear install instruction if absent. Supports `--format cyclonedx` (default) and `--format terminal` (Rich dependency tree). `--output PATH` writes to file.
- **`_network.py` — unified `--offline` contract**: `NetworkPolicy` dataclass + `require_offline_compatible()` replaces all scattered `if offline and <flag>` guards in `_preflight_checks`. Now covers `--verify-hashes`, `--verify-signatures`, `--check-vulns`, and `--connect` in one place.
- `"vuln_mirror": frozenset({"pro", "enterprise"})` feature key added to `licensing.py`.

### Notes
- Binary size advisory: the `sigstore` dependency tree (`betterproto`, `tuf`, `rfc3161-client`, `securesystemslib`) is expected to push the PyInstaller binary above the 22 MB target. Three mitigation options documented in `attestation/sigstore_client.py`; a rebuild is required before the next release cut to measure actual impact. `cyclonedx-python-lib` excluded from PyInstaller specs to contain further growth.

---

## [0.5.0] - 2026-04-23 — Detection Validity, Hardening & Supply Chain Depth

### Security
- **V-07 — Unicode homoglyph bypass closed** (`poisoning.py`): Added `POISON-060` pattern matching Cyrillic, Greek, general-punctuation lookalike, and fullwidth-ASCII Unicode blocks. All patterns now run against NFKD-normalised ASCII text; `POISON-060` runs against the original bytes. Deduplication on `(id, server, evidence)` prevents duplicate findings when both the raw and normalised text match.
- **V-08 — Depth-11 nesting bypass closed** (`poisoning.py`): Recursion limit in `_extract_text_fields` and `_extract_description_fields` raised from `depth > 10` to `depth > 50`, making the depth-bypass impractical while still guarding against infinite recursion.
- **V-09 — Wildcard interface binding** (`transport.py`): New `TRANSPORT-004` finding (HIGH, CWE-1327) fires when the server URL hostname is `0.0.0.0`, `::`, `[::]`, or their equivalents. `_WILDCARD_BINDINGS` frozenset added.
- **V-10 — Privilege escalation coverage expanded** (`transport.py`): `TRANSPORT-002` now catches `pkexec`, `su`, and `run0` in addition to `sudo` and `doas`. Absolute-path forms (e.g. `/usr/bin/sudo`) detected via `_PRIV_ESC_SUFFIXES`. Privilege-escalation binary appearing as `args[0]` (e.g. `command=sh, args=["sudo", …]`) now also fires.
- **V-11 — Supply chain coverage expanded** (`transport.py`, `supply_chain.py`): `pipx` added to `_RUNTIME_FETCH_COMMANDS`. `yarn dlx` detected in both `TransportAnalyzer` (TRANSPORT-003) and `SupplyChainAnalyzer` (typosquatting); `args[1:]` slicing used when extracting the package name to skip the `dlx` token.

### Added
- **Exploit validation test suite** (`tests/test_exploit_validation.py`): Six test classes reconstruct real published attack PoCs — Invariant Labs SSH exfiltration, CrowdStrike `add_numbers`, fake Postmark base64 exfiltration, CyberArk XML `<OVERRIDE>` injection, Palo Alto Unit 42 cloud credential targeting, and MINJA behavioral override. Each class asserts specific finding IDs and severities; `TestExploitCoverage` enforces all six fixture files are present and valid JSON.
- **Exploit fixtures** (`tests/fixtures/exploits/`): Six JSON fixtures reconstructing the above PoCs from published research sources cited in `PROVENANCE.md`.
- **False-positive benchmark** (`tests/test_false_positive_benchmark.py`): Runs poisoning and credentials analyzers against 22 real-world MCP server configs (12 official `@modelcontextprotocol/*`, 10 popular community servers). Asserts 0% poisoning false-positive rate across the full set. Parametrised per-server to pinpoint regressions immediately. Acts as a merge gate — any pattern change that fires on a legitimate server fails CI.
- **Real-server fixtures** (`tests/fixtures/real_servers/`): `official_mcp_servers.json` (12 servers) and `community_mcp_servers.json` (10 servers) with realistic production configs and empty env-var values.
- **Severity framework** (`docs/severity-framework.md`): CVSS base scores and OWASP Agentic Top 10 (ASI01–ASI10) mappings for every finding ID across all six analyzers (POISON-*, CRED-*, TRANSPORT-*, SC-*, RUG-*, TOXIC-*, ATTEST-*). Includes a decision tree for calibrating new findings.
- `TRANSPORT-004` added to `docs/severity-framework.md` under the Transport analyzer table.

### Added (continued)
- **Registry metadata enrichment** (`registry/loader.py`, `registry/known-servers.json`): Three optional fields added to `RegistryEntry` — `first_published` (ISO date), `weekly_downloads` (integer), `publisher_history` (list of publisher account names, most-recent first). Populated for 10 entries; registry grew from 60 to 64 entries with four new community servers (`@linear/mcp-server`, `exa-mcp-server`, `@notion/mcp-server`, `mcp-perplexity`). SC-001/SC-002 finding descriptions now append publish date, download count, and known publishers when data is present, giving users signal about package legitimacy. `scripts/enrich_registry.py` maintainer tool added (not shipped in wheel) to refresh metadata from the npm registry API; supports `--dry-run`.

### Fixed
- `GAPS.md` — three Detection Validity gaps closed (exploit validation, false-positive rate, severity framework); V-07 through V-11 marked resolved; registry metadata enrichment marked resolved; `--offline --verify-hashes` conflict confirmed already blocked by `_preflight_checks`.

---

## [0.4.0] - 2026-04-17 — Security Hardening & CI

### Security
- Resolved all Bandit medium+ findings; suppressed three `B310` (`urllib` URL-open) calls with inline `# nosec B310` comments and one-line justifications — no blanket suppressions.
- Bumped `cryptography` to `>=46.0.6,<47.0` to fix CVE-2026-26007 (EC subgroup validation) and CVE-2026-34073 (DNS name constraint bypass); lockfile resolves to `cryptography==46.0.7`. `pip-audit` now returns zero findings.
- Pre-launch hardening pass (V-01 through V-06): path-traversal fix via `_safe_baseline_path` + `Path.resolve()`, state file permission enforcement (`0o600`/`0o700`), bare `except:` removal, CLI input validation for `--path`/`--registry`/`--sast`/`--policy`, `subprocess.run()` converted to list form everywhere (`shell=False`).
- Converted `subprocess` calls in `sast/runner.py` to list form; introduced `SEMGREP_TIMEOUT_SECONDS = 300` constant — hardcoded timeout integers are now forbidden.

### Added
- `scripts/build-linux.sh` — Docker-based Linux x86_64 binary build inside `python:3.11-slim`; installs `binutils` via `apt-get`; prints file size and SHA-256 on success.
- `sast` and `sast-path` inputs wired into `action.yml` (GitHub Action).
- `ci.yml` — 3×2 CI matrix (Ubuntu / macOS / Windows × Python 3.11 / 3.12); `fail-fast: false`.
- `release.yml` — binary release workflow; builds four PyInstaller executables in parallel on tag push (`v*.*.*`); creates a GitHub Release with auto-generated notes.
- Four portable PyInstaller spec files (`mcp-audit-darwin-x86_64.spec`, `mcp-audit-darwin-arm64.spec`, `mcp-audit-linux-x86_64.spec`, `mcp-audit-windows-x86_64.spec`) using `SPECPATH`-relative roots.
- Full PyInstaller `hiddenimports` list; complete bundled `datas` (5 entries).
- Test coverage for PyInstaller path resolution (`_MEIPASS` monkeypatching) and license key storage path shape.
- 13 additional edge-case tests covering scanner integration scenarios, raising `scanner.py` line coverage from ~50 % to 89 %.
- Replaced hardcoded `~/.config/mcp-audit` paths with `platformdirs.user_config_dir("mcp-audit")` across all modules (baselines, registry cache, policy, rules); `licensing.py` deferred (marked do-not-modify).
- `packaging>=21.0` declared as an explicit dependency.
- Clean commit-history audit recorded before public release (credentials, private keys, internal URLs — all categories clean).

### Fixed
- `malformed JSON` errors now surfaced to the user rather than silently swallowed.
- `--no-score` correctly suppresses the `run.properties` score block in SARIF output.
- GitHub Action: workflow-level `permissions` added for SARIF upload; `codeql-action` bumped to v4; double-scan removed; SARIF path guarded.
- `httpx` moved to the `mcp` optional-dependency group (resolves V-12).

---

## [0.3.0] - 2026-04-10 — Moat Deepening

### Added
- **Governance policy engine** — YAML-based organisational requirements: approved server lists, minimum scan scores, transport constraints, registry membership, finding tolerances. New CLI commands: `policy validate`, `policy init` (Pro), `policy check` (Pro). `scan --policy PATH` flag (free) with auto-discovery (cwd → repo root → user config dir). Governance findings rendered in a distinct yellow "Policy Violations" panel in terminal output; SARIF findings tagged `governance-policy` with `GOV-` rule IDs. `governance` and `fleet_governance` feature keys.
- **Supply chain attestation — Layer 1** — hash-based integrity verification via `attestation/hasher.py` and `attestation/verifier.py`. `scan --verify-hashes` downloads package tarballs and computes SHA-256 against `known_hashes` pins in `RegistryEntry`. `mcp-audit verify` standalone free-tier command. Five registry entries seeded with real hashes. Attestation findings use `analyzer="attestation"` (CRITICAL for mismatches, INFO for unverifiable).
- **Semgrep SAST rule pack** — 37 rules (28 Python, 9 TypeScript) across 5 categories (injection, poisoning, credential, protocol, transport). Runnable standalone (`semgrep --config semgrep-rules/ <path>`) or integrated (`mcp-audit scan --sast <path>`). `mcp-audit sast <path>` standalone command. Pro-gated integration; `sast` feature key. Bundled in pip wheel and PyInstaller binary. `SastResult` model; Semgrep auto-discovery; severity mapping.
- **IDE extension security scanner** — discovers extensions across VS Code, Cursor, Windsurf, and Augment. Six analysis layers: known-vuln registry, dangerous capability combos, wildcard activation, unknown publisher, sideloaded VSIX, stale AI extensions. `mcp-audit extensions discover` (free) and `mcp-audit extensions scan` (Pro). `scan --include-extensions` flag (Pro). `registry/known-extension-vulns.json` seed dataset (5 entries). `extensions` and `fleet_extensions` feature keys. Findings use `analyzer="extensions"`.

---

## [0.2.0] - 2026-04-07 — Chain Reaction

### Added
- **Scan score & grade** — every scan produces a numeric score (0–100) and letter grade (A–F) via `scoring.py`. Grade panel rendered in terminal output. `scan --no-score` suppresses the terminal panel only; score still present in JSON/HTML. JSON output includes top-level `score` and `grade` fields. SARIF `run.properties` block carries `mcp-audit/grade`, `mcp-audit/numericScore`, `mcp-audit/positiveSignals`, and `mcp-audit/deductions`.
- **Known-server registry** — `registry/known-servers.json` curated dataset (57 entries) replaces hardcoded YAML in the supply chain analyzer. `KnownServerRegistry` loader with Levenshtein typosquatting detection. `update-registry` command (Pro) fetches latest registry from GitHub to user-local cache. `scan --registry PATH` override; `scan --offline-registry` flag. Registry stats dim one-liner appended to terminal output.
- **Baseline snapshot & drift detection** — five `baseline` sub-commands: `save`, `list`, `compare`, `delete`, `export`. `scan --baseline NAME` (or `--baseline latest`) injects `DriftFinding`s (converted to `Finding` objects with `analyzer="baseline"`) into all output formats. Storage at `<user-config-dir>/mcp-audit/baselines/` with `0o700`/`0o600` permissions. Environment variable values never stored, only key names.
- **GitHub Action** (`action.yml`) — composite action; inputs: `severity-threshold`, `format`, `config-paths`, `baseline`, `upload-sarif`; outputs: `finding-count`, `grade`, `sarif-path`. Uploads SARIF to GitHub Security tab; writes job summary. Exit-1-safe design.
- **Fleet merge** (`mcp-audit merge`) — consolidates JSON scan outputs from multiple machines into a single fleet report. Deduplicates findings by `(analyzer, server_name, title)`. Supports terminal, JSON, and HTML output. Enterprise-gated via `fleet_merge` feature key.
- **Policy-as-code rule engine** — YAML-based custom detection rules. 12 community rules (`COMM-001` through `COMM-012`) bundled and run for all users (free tier). `rule validate`, `rule test`, `rule list` sub-commands. `scan --rules-dir PATH` and user-local rules directory for Pro users. `custom_rules` feature key. Rule findings use `analyzer="rules"`. Community rules always run regardless of license tier.
- **Pre-commit hook** (`.pre-commit-hooks.yaml`) — `language: python`, `entry: mcp-audit`, `pass_filenames: false`, `types: [json]`. Default threshold is HIGH. Example configs in `examples/pre-commit/` (basic and strict).
- **Ed25519 license key system** — fully offline verification (public key hardcoded in `licensing.py`; private key never ships). `mcp-audit activate <key>` and `mcp-audit license` commands. License stored at `~/.config/mcp-audit/license.key` (permissions `0o600`). Three tiers: Community, Pro, Enterprise. `scripts/generate_license.py` (not shipped in package).
- `scan --policy PATH` auto-discovery: cwd → git repo root → user config dir → `None` (no check).
- `scan --output-file PATH` (alias `--output` / `-o`) with automatic parent directory creation.
- `scan --severity-threshold LEVEL` filters findings and drives exit code.
- Terminal output: dim registry stats one-liner after summary.
- Machine identification (`MachineInfo`) embedded in scan output; `--asset-prefix` flag for fleet deployments.
- `offline-registry` flag; SARIF score properties block.
- Example workflows: `examples/github-actions/basic.yml`, `strict.yml`, `with-baseline.yml`.
- Example pre-commit configs: `examples/pre-commit/basic.yaml`, `strict.yaml`.
- `examples/policies/` — sample governance policy files.

### Fixed
- `html_report` proxy gate replaced with dedicated `update_registry` feature key.

---

## [0.1.0] - 2026-04-01 — Prototype

### Added
- Initial working CLI scaffold using Typer + Rich, Pydantic v2 data models, pytest suite.
- **Six security analyzers:**
  - `poisoning.py` — tool-description poisoning detection (14 regex patterns).
  - `credentials.py` — secret/API-key exposure in configs (9 patterns).
  - `transport.py` — transport security (TLS, localhost binding).
  - `supply_chain.py` — package provenance and typosquatting via Levenshtein distance.
  - `rug_pull.py` — description-change detection using stateful config hashing; state scoped per config-set at `~/.mcp-audit/state.json`.
  - `toxic_flow.py` — cross-server capability tagging and dangerous pair detection; live MCP server enumeration via `--connect`.
- **Attack path engine** (`attack_paths.py`) — multi-hop detection (up to 4 servers), greedy hitting set algorithm, `summarize_attack_paths()`.
- **Eight supported MCP clients** — Claude Desktop, Cursor, VS Code, Windsurf, Claude Code (user-scoped), Claude Code (project-scoped), GitHub Copilot CLI, Augment Code.
- **Five output formats** — terminal (Rich), JSON, SARIF 2.1.0, Nucleus FlexConnect, self-contained HTML dashboard.
- **Interactive HTML dashboard** — embedded D3 v7 attack graph, light/dark mode toggle, grade badge, empty-state handling. D3 bundled from `data/d3.v7.min.js`.
- `mcp-audit watch` — filesystem watcher for continuous monitoring; re-scans on config change.
- `mcp-audit discover` — lists discovered MCP config paths across all clients.
- **Demo environment** (`demo/`) — produces 27+ findings across all analyzer categories.
- PyInstaller build pipeline (`build.py`) — 16.6 MB standalone binary, no Python required.
- `BaseAnalyzer` abstract class; `BaseFormatter` abstract class.
- `Finding`, `ServerConfig`, `ScanResult`, `ScanScore`, `Severity`, `AttackPath`, `MachineInfo` Pydantic models.
- Security review and patch pass — six vulnerabilities fixed (V-01 through V-06); internal findings V-07 through V-17 documented in `GAPS.md`.
- `GAPS.md` — known detection-quality limitations, severity calibration issues, untested areas.
- `PROVENANCE.md` — research attribution for all detection patterns.

---

_This changelog covers the full pre-release development history. The first public version tag will be added here when the initial release is cut._
