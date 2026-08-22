# Building the standalone binary

The artifact users download from GitHub Releases is built **one way**:
[`.github/actions/build-binary/`](../.github/actions/build-binary/action.yml).
`ci.yml` (`binary-smoke`) and `release.yml` (`build`) both call that
composite. Do not copy its steps into a workflow to add a flag — add the
flag to the composite so both callers pick it up.

Pinned interpreter: **CPython 3.12.14** via `uv python install` (the
`python-version` input default). Not `actions/setup-python`, and not a
floating `3.12`. Bump the pin the same way Action SHAs are bumped:
deliberately, in one place, after checking the changelog.

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

## What is still duplicated, and why

- **Job matrix** (`os` / `target` / `spec` / `binary`). A composite cannot
  own a job strategy. `tests/test_ci_binary_smoke.py` asserts the two
  matrices stay equal. A reusable `workflow_call` could share the matrix
  but would also mix CI policy (`if:`, timeout) with release upload.
- **`actions/checkout` SHA.** Every job checkouts independently; it is
  not a build parameter.
- **`publish-pypi`** still runs `uv python install 3.12` for the
  wheel/sdist. That job does not produce the standalone binary (pure
  Python, hatchling).
- **`scripts/build-linux.sh`** is a local Docker convenience
  (`python:3.11-slim` + pip + `build.py`). It is not the shipped path.

Size limits (40 MB warn / 50 MB fail) live in the composite. Do not raise
the soft limit to hide a packaging regression; change the specs' excludes
instead.
