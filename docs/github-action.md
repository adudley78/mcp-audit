# Using mcp-audit as a GitHub Action

Scan your MCP server configurations in CI and surface findings in GitHub Code
Scanning — no Python install required.

> **Note for contributors:** `.github/workflows/ci.yml` is this project's own
> test matrix (pytest + ruff across OS/Python combinations), and
> `.github/workflows/action-ci.yml` is the action self-test. Neither file is
> the composite action itself. This document covers `action.yml`, the
> composite action that *users* drop into their own repositories.

## Quick start

Add `.github/workflows/mcp-audit.yml` to your repository:

```yaml
name: MCP Security Scan

on: [push, pull_request]

jobs:
  mcp-audit:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # required for SARIF upload
    steps:
      - uses: actions/checkout@v4
      - uses: adudley78/mcp-audit@v0.3.0
```

Findings appear in **Security → Code scanning alerts** within ~2 minutes.

The `permissions` block is **required** for the SARIF upload. Composite
actions inherit workflow-token permissions; declare `security-events: write`
at either the workflow or the job level (as shown above).

### Version pinning

Until `v1.0.0` ships, pin to a specific release tag (e.g. `@v0.3.0`).
Once the first `v1.x` release is published, you will be able to pin to
`@v1` and automatically track the latest `1.x` minor/patch release — the
standard GitHub Marketplace major-version convention. The `latest`
git tag is deliberately **not** published; pinning to it would silently
break reproducibility on release day.

## Full example

```yaml
- uses: adudley78/mcp-audit@v0.3.0
  with:
    config-paths: 'path/to/claude_desktop_config.json path/to/cursor_config.json'
    severity-threshold: high
    sarif-output: mcp-audit.sarif
    upload-sarif: 'true'
    check-vulns: 'false'
    verify-signatures: 'false'
    run-sast: 'false'
    sast-path: src/
    baseline-name: ''
    fail-on-findings: 'true'
    version: latest
```

## Inputs

| Input | Default | Description |
|---|---|---|
| `config-paths` | _(auto-discover)_ | Space-separated paths to MCP config files or directories. Leave empty to scan every known client-config location. |
| `severity-threshold` | `high` | Minimum severity to fail the build. One of: `critical`, `high`, `medium`, `low`, `info`. |
| `sarif-output` | `mcp-audit.sarif` | Path to write the SARIF file. Set to empty string to skip SARIF generation entirely. |
| `upload-sarif` | `'true'` | Upload SARIF to GitHub Code Scanning. Requires `security-events: write`. |
| `check-vulns` | `'false'` | Run the OSV.dev dependency CVE scan (Layer 3). Requires network access. |
| `verify-signatures` | `'false'` | Run Sigstore signature verification (Layer 2). Requires network access. |
| `run-sast` | `'false'` | Also run `mcp-audit sast <sast-path>` after the config scan. |
| `sast-path` | `src/` | Path passed to `mcp-audit sast`. Only used when `run-sast: 'true'`. |
| `baseline-name` | _(empty)_ | Saved baseline name. When non-empty, runs `mcp-audit baseline compare <name>` and writes the diff to the step summary. |
| `fail-on-findings` | `'true'` | Fail the workflow step if the scan finds anything at or above `severity-threshold`. Set to `'false'` for visibility-only mode. |
| `version` | `latest` | `mcp-audit-scanner` version to install from PyPI (e.g. `0.10.1`). |

### Severity threshold behaviour

The threshold controls both what is **reported** and whether the **build
fails** when `fail-on-findings: 'true'`:

- `severity-threshold: high` (default): only HIGH and CRITICAL findings cause
  the build to fail; MEDIUM and lower are reported but do not fail.
- `severity-threshold: medium`: MEDIUM, HIGH, and CRITICAL findings cause the
  build to fail.
- `severity-threshold: info`: any finding at all causes the build to fail.
- `severity-threshold: critical`: only CRITICAL findings cause the build to
  fail; everything else is reported but non-blocking.

## Outputs

| Output | Description |
|---|---|
| `findings-count` | Total findings at or above `severity-threshold`. |
| `grade` | Overall scan grade (A–F). |
| `sarif-path` | Absolute path to the generated SARIF file (empty string if `sarif-output` was empty). |

Use outputs in downstream steps:

```yaml
- name: Run mcp-audit
  id: mcp
  uses: adudley78/mcp-audit@v0.3.0

- name: Print results
  run: |
    echo "Grade: ${{ steps.mcp.outputs.grade }}"
    echo "Findings: ${{ steps.mcp.outputs.findings-count }}"
```

## Permissions

```yaml
permissions:
  contents: read
  security-events: write   # required for SARIF upload to Code Scanning
```

If Code Scanning isn't enabled on your repo, the upload step skips gracefully
(`continue-on-error: true`) — the rest of the action still runs and writes
output files.

## Disabling SARIF upload

```yaml
- uses: adudley78/mcp-audit@v0.3.0
  with:
    upload-sarif: 'false'
```

## Pinning to a specific version

```yaml
- uses: adudley78/mcp-audit@v0.10.1
```

`@v1` tracks the latest `1.x` release. Pin to a full version tag for fully
reproducible CI runs.

## Example scenarios

### Basic (visibility only, never fails)

Good when first adopting mcp-audit. Get findings in the Security tab without
blocking any build. Tighten the threshold once you've worked through the
existing findings.

```yaml
- uses: adudley78/mcp-audit@v0.3.0
  with:
    severity-threshold: info
    fail-on-findings: 'false'
```

Full file: [`examples/github-actions/basic.yml`](../examples/github-actions/basic.yml)

### Strict (fail on MEDIUM or higher)

Suitable for security-conscious teams or new projects with no existing
findings.

```yaml
- uses: adudley78/mcp-audit@v0.3.0
  with:
    severity-threshold: medium
    fail-on-findings: 'true'
```

Full file: [`examples/github-actions/strict.yml`](../examples/github-actions/strict.yml)

### With baseline drift detection

`baseline-name` runs `mcp-audit baseline compare <name>` after the scan and
writes the drift table to the step summary. Set up the baseline locally and
commit the exported JSON before enabling this.

Full file: [`examples/github-actions/with-baseline.yml`](../examples/github-actions/with-baseline.yml)

### SAST scanning

`run-sast: 'true'` runs `mcp-audit sast <sast-path>` after the config scan
using the 37 bundled MCP-aware Semgrep rules that ship with
`mcp-audit-scanner`. The action installs the Semgrep CLI automatically
inside the SAST step (`pip install semgrep --quiet`), so no separate
install step is required — the dependency is only pulled in when you
opt in.

```yaml
- uses: adudley78/mcp-audit@v0.3.0
  with:
    run-sast: 'true'
    sast-path: src/
    severity-threshold: medium
```

Narrow `sast-path` to the directory containing your MCP server source code
rather than the repository root to reduce scan time and avoid false positives.

## How findings appear in the Security tab

When `upload-sarif: 'true'` and `security-events: write` are both set,
findings are uploaded via
[`github/codeql-action/upload-sarif@v4`](https://github.com/github/codeql-action).
Each finding becomes a code-scanning alert with:

- **Severity** mapped from CRITICAL/HIGH → `error`, MEDIUM → `warning`,
  LOW/INFO → `note`.
- **Location** pointing to the MCP config file where the server is defined.
- **Rule** linking to the mcp-audit documentation.
- **Fix description** from the finding's remediation field.

Alerts appear in the **Security → Code scanning** tab and as annotations on
pull-request diffs.

## Exit code behaviour

`mcp-audit` uses three distinct exit codes:

| Exit code | Meaning | Action effect |
|-----------|---------|---------------|
| `0` | Clean scan — no findings at or above the threshold | Job continues |
| `1` | Findings found at or above the threshold | `fail-on-findings: 'true'` → step fails; `'false'` → step succeeds |
| `2` | Tool error (bad args, unreadable config, etc.) | Step always fails |

Exit code `2` always propagates as a real failure regardless of
`fail-on-findings`.

## Action version requirements

The action uses `github/codeql-action/upload-sarif@v4`, which runs on
Node.js 24. GitHub is deprecating actions that run on Node.js 20 starting
**2026-06-02**. If you pin the composite action yourself, use `@v4` or later.

`actions/checkout@v4` runs on Node.js 20 but is not affected by the
2026-06-02 deprecation (GitHub will update it transparently).

## Troubleshooting

### "Resource not accessible by integration" on the SARIF upload step

**Cause:** `security-events: write` permission missing.

**Fix:** add a `permissions` block at the workflow or job level:

```yaml
permissions:
  contents: read
  security-events: write
```

### "No MCP configurations found"

**Cause:** the runner has no MCP config files at the standard discovery
paths (`.cursor/mcp.json`, `~/.claude.json`, etc.). Expected on CI runners
that don't use MCP clients.

**Fix:** point `config-paths` at your repo-committed configs or test
fixtures:

```yaml
with:
  config-paths: '.mcp.json'
```

### Build fails on existing HIGH findings

Temporarily lower the threshold or disable failure:

```yaml
with:
  severity-threshold: critical   # fail only on CRITICAL
  # or
  fail-on-findings: 'false'      # visibility only
```

### `pip install mcp-audit-scanner` fails on self-hosted runners

**Cause:** the runner doesn't expose a Python 3.11+ interpreter or uses a
restricted index.

**Fix:** the action pins `actions/setup-python@v5` to Python 3.11 as the
first step, which resolves most cases. For restricted indexes, configure
`PIP_INDEX_URL` in the workflow environment.

### Windows runners: bash-script errors

The action uses `shell: bash` on all steps; on Windows runners this resolves
to Git Bash. Ensure Git for Windows is installed on self-hosted Windows
runners — the GitHub-hosted `windows-latest` image already has it.

### Baseline not detected on CI

**Cause:** the baseline JSON file was not copied to the expected directory
before the scan step.

**Fix:** copy the exported baseline before the action runs:

```bash
mkdir -p ~/.config/mcp-audit/baselines/
cp .mcp-audit-baseline.json ~/.config/mcp-audit/baselines/ci-baseline.json
```

## Testing the SARIF upload

Automated schema validation runs in CI (`tests/test_sarif_schema.py`). To
verify that findings appear in the GitHub Security tab end-to-end:

1. Use a repository with Code Scanning enabled (free for public repos;
   available on private repos with GitHub Advanced Security).
2. Add the quick-start workflow above.
3. Ensure `permissions: security-events: write` is set at the workflow or
   job level.
4. Push and check **Security → Code scanning** alerts within ~2 minutes.

Common failure causes:

- Missing `security-events: write` permission.
- Code Scanning not enabled (**Settings → Code security → Code scanning**).
- No MCP config files found — specify `config-paths` explicitly.

## Known limitations

- The action installs `mcp-audit-scanner` via `pip install`, adding 20–30
  seconds per run. A binary-based variant using prebuilt release assets is
  a planned future optimisation — see [GAPS.md](../GAPS.md).
- `config-paths` is passed verbatim to the CLI as positional arguments.
  Each path is space-separated; paths containing spaces are not supported.
- The action has not been validated on Windows runners or self-hosted
  runners without a standard Python environment.
