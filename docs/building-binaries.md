# Building the standalone binary

The artifact users download from GitHub Releases is built **one way**:
[`.github/actions/build-binary/`](../.github/actions/build-binary/action.yml).
`ci.yml` (`binary-smoke`) and `release.yml` (`build`) both call that
composite. Do not copy its steps into a workflow to add a flag — add the
flag to the composite so both callers pick it up.

Pinned interpreter: **CPython 3.12.14**, owned by the composite's
`python-version` input default. `publish-pypi` copies that pin (it cannot
invoke the composite). Bump the default, then the copy; pytest fails if
they diverge. Not `actions/setup-python`, and not a floating `3.12`.

Prove the release-side path with `workflow_dispatch` on the Release
workflow (dry-run: build + artifact upload, no GitHub Release / PyPI).
Do not wait for the next `v*.*.*` tag to be the first execution.

## Why this exists

Three CI/release mismatches were found in sequence because the recipe
was written twice:

| # | Drift | CI did | Release did | Cost |
|---|-------|--------|-------------|------|
| 1 | Extras (#53) | `uv pip install -e ".[dev]"` | `uv sync --all-extras` | CI never tested spec excludes against a venv that actually contained the optional extras |
| 2 | Platforms (#57) | linux only | four targets | A darwin/windows spec or exclude regression would ship until the next tag |
| 3 | Interpreter (#58) | `actions/setup-python` (hostedtoolcache libpython) | `uv python install` (uv's CPython) | Same 3.12.14, ~10 MB apart on linux (47.5 vs 37.5), different libpython / OpenSSL / hooks |

A floating `3.12` would reopen (3) on the next CPython patch: release
picks up 3.12.15 while a cached CI runner still has 3.12.14.

## Knowingly not shared

Listed on the composite itself so it does not live only in a PR body:

- **Job matrix** (`os` / `target` / `spec` / `binary`). A composite cannot
  own a job strategy. `tests/test_ci_binary_smoke.py` asserts the two
  matrices **and** the `with:` block each caller passes to the composite.
- **`actions/checkout` SHA.** Every job checkouts independently.
  Dependabot updates both; a drift is visible and harmless.
- **`publish-pypi` `uv python install`.** Copies the composite default;
  pytest-locked. Cannot call the composite.
- **`hatchling` in `build-system.requires`.** Still unpinned. Combined
  with a floating interpreter, that re-cut the v0.15.0 tag (Core-Metadata
  2.5 vs Twine 6). Pin hatchling in lockstep with
  `pypa/gh-action-pypi-publish`.
- **CI `if:` / timeout vs release `upload-artifact`.** Policy, not recipe.

Local binaries: `uv python install 3.12.14 && uv sync --all-extras && uv pip install pyinstaller && uv run pyinstaller mcp-audit-<target>.spec --distpath dist/`. There is no `scripts/build-linux.sh` and no `build.py`; those used Python 3.11 + pip and skipped the specs' `excludes=`.

Size limits (40 MB warn / 50 MB fail) live in the composite. Do not raise
the soft limit to hide a packaging regression; change the specs' excludes
instead.
