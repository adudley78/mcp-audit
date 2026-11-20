# Pre-Commit Hook

`credenzo` ships as a [pre-commit](https://pre-commit.com) hook. It catches MCP server misconfigurations before they land in the repository, integrating security scanning into the developer commit workflow without requiring any CI infrastructure.

## What the hook does

When a JSON file is staged for commit, the hook runs `credenzo scan` against all MCP server configurations discovered on the developer's machine. If any findings at or above the configured severity threshold exist, the commit is blocked with exit code 1. Commits that touch only Python files, Markdown, YAML, or any non-JSON file type skip the hook entirely — no false triggers.

The hook uses `pass_filenames: false`, meaning it does **not** receive individual staged filenames from pre-commit. Instead, `credenzo` uses its own client-aware discovery logic to locate and parse complete MCP config files. This is intentional: MCP config files are structured JSON documents that describe entire server sets — passing individual filenames would result in incomplete partial parses.

As a consequence, the hook re-scans **all** MCP configs on the machine, not only those that changed in the current commit. See [Known limitations](#known-limitations) for details.

## Install

**1. Install pre-commit:**

```bash
pip install pre-commit
```

Or via Homebrew on macOS:

```bash
brew install pre-commit
```

**2. Add Credenzo to your `.pre-commit-config.yaml`** (create this file at your repo root if it doesn't already exist):

```yaml
repos:
  - repo: https://github.com/adudley78/credenzo
    rev: v0.36.0
    hooks:
      - id: credenzo
```

`rev` must be an existing release tag. The examples on this page show the current release (each release PR updates them); `pre-commit autoupdate` moves your copy to the latest tag from [https://github.com/adudley78/credenzo/releases](https://github.com/adudley78/credenzo/releases).

**3. Install the hooks into your local repo:**

```bash
pre-commit install
```

From this point on, `credenzo scan` runs automatically on every `git commit` that stages at least one JSON file.

## Configuring the severity threshold

The default hook args run `scan --severity-threshold high`, blocking only on HIGH or CRITICAL findings. To lower the threshold:

```yaml
repos:
  - repo: https://github.com/adudley78/credenzo
    rev: v0.36.0
    hooks:
      - id: credenzo
        args: [scan, --severity-threshold, medium]
```

Valid threshold values (lowest to highest): `info`, `low`, `medium`, `high`, `critical`.

## Running the hook manually

Run the hook without committing anything:

```bash
pre-commit run credenzo
```

Run against all files (not just staged):

```bash
pre-commit run credenzo --all-files
```

## Skipping the hook for a single commit

If you need to bypass the hook for one commit (e.g., an emergency fix):

```bash
git commit --no-verify
```

This skips all pre-commit hooks, not only Credenzo. Use sparingly and follow up with a scan after the commit lands.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Clean — no findings at or above threshold, or no MCP configs found |
| 1 | Findings at or above the severity threshold — commit blocked |
| 2 | Error (invalid arguments, scan error) |

Repos with no MCP configs always exit 0. The hook is safe to install on any repo, not only those that use MCP servers.

## Config examples

See [`examples/pre-commit/`](../examples/pre-commit/) for ready-to-copy configs:

- [`basic.yaml`](../examples/pre-commit/basic.yaml) — minimal setup, blocks on HIGH+
- [`strict.yaml`](../examples/pre-commit/strict.yaml) — blocks on MEDIUM+

## `credenzo-lock-verify` — block commits that drift from `mcp-lock.json`

If you've adopted [`credenzo lock`](lock.md), a second hook enforces it:

```yaml
repos:
  - repo: https://github.com/adudley78/credenzo
    rev: v0.36.0  # the credenzo hook ids need v0.33.0 or later
    hooks:
      - id: credenzo
      - id: credenzo-lock-verify
```

The hook ids from before the rename, `mcp-audit` and `mcp-audit-lock-verify`, continue to work and run the same checks.

This hook runs `credenzo lock --verify --if-present` whenever a commit
touches a known MCP config path or `mcp-lock.json`. It is safe to add to a
repo that has not run `credenzo lock` yet — `--if-present` makes a missing
lock file a no-op, not a failure, so this hook only starts blocking commits
once you've written a lock file with `credenzo lock`.

A drifted commit is blocked. Review the drift, then run:

```bash
credenzo lock --accept
git add mcp-lock.json
git commit
```

`--accept` re-writes the lock from the current state (preserving each
surviving entry's `first_locked`) — the explicit "I reviewed this" step.

## Known limitations

**Re-scans all configs, not just staged files.** Because `pass_filenames: false` is set, the hook runs `credenzo scan` with its default discovery. It scans every MCP config file found on the machine — across all supported clients (Claude Desktop, Cursor, VS Code, Windsurf, etc.) — not only the files staged in the current commit. On machines with many MCP clients configured this may be slightly slower than expected, but ensures that a config file that was modified outside the repo is still caught.

**Not tested with `--from-ref`/`--to-ref` diff modes.** The pre-commit framework supports running hooks in diff mode (e.g., `pre-commit run --from-ref HEAD~1 --to-ref HEAD`). This mode is not tested and may not interact correctly with `pass_filenames: false`.

**Only fires on JSON-staged commits.** Commits that touch only non-JSON files (Python, Markdown, YAML, shell scripts, etc.) do not trigger the hook. If your MCP configs are stored as `.yaml` or in a non-standard format, the `types: [json]` filter will not catch them. Adjust the hook's `types` field if needed for non-standard config formats.
