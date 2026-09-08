# The release.yml blind spot (R42)

`release.yml` runs on two triggers: a `v*.*.*` tag push, and
`workflow_dispatch` (a dry-run of the `build` job only — see the comments at
the top of the workflow). **Neither is a `pull_request` trigger.** That
means every action pinned in `release.yml` is only as tested as whatever
*other* workflow happens to exercise the same action, on a PR, before the
next tag.

## Corrected execution table

For each action `release.yml` pins, whether it is actually **executed**
(not merely present in a file with a `pull_request` trigger) on a normal PR:

| Action | Used in `release.yml` for | Executed on PR? | Evidence |
|---|---|---|---|
| `actions/checkout` | every job | **Yes** | Same pinned SHA is checked out, unconditionally, in `ci.yml` (`test`, `test-all-extras`, `wheel-check`, `binary-smoke`, `source-smoke`), `action-ci.yml`, `registry-drift.yml`, and `mcp-audit-example.yml` — all `pull_request`-triggered with no blocking job/step `if:`. |
| `astral-sh/setup-uv` | `release`, `publish-pypi` jobs | **Yes** | Directly, unconditionally, in `ci.yml`'s `wheel-check` job (every push/PR, no `if:`). Also transitively via `.github/actions/build-binary`, which `ci.yml`'s `binary-smoke` job invokes under `if: github.event_name == 'pull_request' || github.ref == 'refs/heads/main'` — true for every PR. |
| `actions/upload-artifact` | `build` job | **Partially** | Also pinned in `registry-drift.yml`, whose job runs on `pull_request` but is **path-filtered** (only PRs touching `registry/known-servers.json`, `scripts/audit_registry.py`, `scripts/check_registry_drift.py`, or the workflow file itself). Most PRs never execute it. Not exercised by `ci.yml` at all. |
| `actions/download-artifact` | `release`, `report` jobs | **No** | Not referenced by any `pull_request`-triggered workflow anywhere in the repo. `report` itself only runs `needs: [build, release]`, and `release` is `if: github.event_name == 'push'`. |
| `softprops/action-gh-release` | `release` job | **No** | Appears only in `release.yml`. No other workflow references it. |
| `pypa/gh-action-pypi-publish` | `publish-pypi` job | **No direct execution, but contract-checked** | `ci.yml`'s `wheel-check` job parses this exact pinned SHA out of `release.yml`, fetches its `requirements/runtime.txt` from that SHA, and runs the matching Twine version against a freshly built wheel — on every PR. This does not invoke the action itself, but it does prove the one historical failure mode (`hatchling` emitting a `Metadata-Version` the bundled Twine rejects) can't recur silently. |

**Net: three of six pinned actions (`download-artifact`, `action-gh-release`,
and — for most PRs — `upload-artifact`) have zero PR-time exercise of any
kind**, and a fourth (`gh-action-pypi-publish`) has a narrow, one-dimensional
bridge rather than a real invocation. A version bump to any of these (e.g.
[#94](https://github.com/adudley78/mcp-audit/pull/94), a routine Dependabot
bump of `softprops/action-gh-release`) is validated by nothing before the
next tag push actually runs `release.yml` for real.

## What actually closes the gap: an input-contract check, not an execution check

Running these jobs on every PR is not the fix — `release`, `publish-pypi`,
and `tag-major` are deliberately `if: github.event_name == 'push'` because
they create a GitHub Release, publish to PyPI, and move a floating tag;
none of that is something a PR should ever be able to trigger, dry-run or
not.

What a version bump can silently break without any of that is the **input
contract**: the exact set of `with:` keys a step passes must still be a
subset of what the action declares, and every input the action now
`required`s (with no `default`) must still be passed. SHA-pinning proves the
bytes that run are the reviewed ones; it says nothing about whether the
*inputs* still line up.

`scripts/check_release_action_contracts.py` closes this, generalizing the
precedent `ci.yml`'s `wheel-check` job already established for
`pypa/gh-action-pypi-publish` (fetch the pinned SHA's own metadata from
GitHub rather than keeping an independent copy of "correct"). For every
`owner/repo@<40-hex-sha>` usage in `release.yml`, it fetches that exact
commit's `action.yml`/`action.yaml` and checks two directions:

1. Every `with:` key the step passes is a declared input of the action at
   that SHA (catches a renamed/removed input).
2. Every input the action declares `required: true` with no `default` is
   passed under `with:` (catches a newly-required input the bump introduced).

It runs as the `action-input-contracts` job in `ci.yml`, unconditionally, on
every push and PR — see the job's own comment in `ci.yml` for why living
there (accepting the same "a GitHub outage briefly fails an unrelated PR"
trade `wheel-check` already accepts) beats living somewhere true but unread.

Local composite actions (`uses: ./.github/actions/build-binary`) are out of
scope: their `action.yml` is repo-reviewed source, never Dependabot-bumped,
so the specific failure mode this script targets — contract drift riding in
silently on a version-bump PR — does not apply to them.

## The version-pairing question: `upload-artifact` vs. `download-artifact`

`release.yml` (and `advisory-feed-publish.yml`, `registry-drift.yml`) pin
`actions/upload-artifact@…v7.0.1` and `actions/download-artifact@…v8.0.1` —
different major version numbers. The real historical precedent for this
being dangerous is the **v3 → v4** boundary: `download-artifact@v4`
introduced an entirely incompatible storage backend from v3, and GitHub's
own deprecation notice for `upload-artifact@v3` states the v3/v4 lines do
not interoperate.

That boundary does not apply here. Since v4, `upload-artifact` and
`download-artifact` have shipped independently and their major version
numbers no longer move in lockstep by design — v7 upload paired with v8
download is the current, documented, expected combination (confirmed
against `download-artifact`'s own v8.0.0 release notes and third-party 2026
usage examples pairing the two exactly this way). The one new v7→v8-relevant
feature, `upload-artifact`'s `archive: false` (single-file, unzipped
upload), does require a v8+ downloader to fetch it without unzipping — but
no step in this repo sets `archive: false`; every usage uploads one or more
files with the default (zipped) archive behavior, which any v4+ downloader
handles.

**Conclusion: no version-pairing hazard applies to the pins as they stand.**
Nothing in CI currently asserts "both majors are ≥ 4" (the actual boundary
that would matter), and nothing needs to yet — there is no live risk to
guard against, and asserting a made-up constraint (e.g. "majors must match")
would fail the *correct* v7/v8 pairing shown in GitHub's own current
examples. Revisit only if a step ever adopts `archive: false`, at which
point the real constraint (`download-artifact` major ≥ 8) becomes concrete
enough to assert.
