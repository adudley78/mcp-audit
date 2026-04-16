# Pre-Commit Hook

`mcp-audit` ships as a [pre-commit](https://pre-commit.com) hook. It catches MCP server misconfigurations before they land in the repository, integrating security scanning into the developer commit workflow without requiring any CI infrastructure.

## What the hook does

When a JSON file is staged for commit, the hook runs `mcp-audit scan` against all MCP server configurations discovered on the developer's machine. If any findings at or above the configured severity threshold exist, the commit is blocked with exit code 1. Commits that touch only Python files, Markdown, YAML, or any non-JSON file type skip the hook entirely — no false triggers.

The hook uses `pass_filenames: false`, meaning it does **not** receive individual staged filenames from pre-commit. Instead, `mcp-audit` uses its own client-aware discovery logic to locate and parse complete MCP config files. This is intentional: MCP config files are structured JSON documents that describe entire server sets — passing individual filenames would result in incomplete partial parses.

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

**2. Add mcp-audit to your `.pre-commit-config.yaml`** (create this file at your repo root if it doesn't already exist):

```yaml
repos:
  - repo: https://github.com/adudley78/mcp-audit
    rev: v0.1.0  # Replace with the latest release tag
    hooks:
      - id: mcp-audit
```

Replace `v0.1.0` with the latest release tag from [https://github.com/adudley78/mcp-audit/releases](https://github.com/adudley78/mcp-audit/releases).

**3. Install the hooks into your local repo:**

```bash
pre-commit install
```

From this point on, `mcp-audit scan` runs automatically on every `git commit` that stages at least one JSON file.

## Configuring the severity threshold

The default hook args run `scan --severity-threshold high`, blocking only on HIGH or CRITICAL findings. To lower the threshold:

```yaml
repos:
  - repo: https://github.com/adudley78/mcp-audit
    rev: v0.1.0
    hooks:
      - id: mcp-audit
        args: [scan, --severity-threshold, medium]
```

Valid threshold values (lowest to highest): `info`, `low`, `medium`, `high`, `critical`.

## Running the hook manually

Run the hook without committing anything:

```bash
pre-commit run mcp-audit
```

Run against all files (not just staged):

```bash
pre-commit run mcp-audit --all-files
```

## Skipping the hook for a single commit

If you need to bypass the hook for one commit (e.g., an emergency fix):

```bash
git commit --no-verify
```

This skips all pre-commit hooks, not only mcp-audit. Use sparingly and follow up with a scan after the commit lands.

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

## Known limitations

**Re-scans all configs, not just staged files.** Because `pass_filenames: false` is set, the hook runs `mcp-audit scan` with its default discovery. It scans every MCP config file found on the machine — across all supported clients (Claude Desktop, Cursor, VS Code, Windsurf, etc.) — not only the files staged in the current commit. On machines with many MCP clients configured this may be slightly slower than expected, but ensures that a config file that was modified outside the repo is still caught.

**Not tested with `--from-ref`/`--to-ref` diff modes.** The pre-commit framework supports running hooks in diff mode (e.g., `pre-commit run --from-ref HEAD~1 --to-ref HEAD`). This mode is not tested and may not interact correctly with `pass_filenames: false`.

**Only fires on JSON-staged commits.** Commits that touch only non-JSON files (Python, Markdown, YAML, shell scripts, etc.) do not trigger the hook. If your MCP configs are stored as `.yaml` or in a non-standard format, the `types: [json]` filter will not catch them. Adjust the hook's `types` field if needed for non-standard config formats.
