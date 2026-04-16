# GitHub Action reference

`mcp-audit` ships a composite GitHub Action (`action.yml`) that lets any repository scan its MCP server configurations as part of CI. Findings appear in the GitHub Security tab, the build fails only at your chosen severity threshold, and a findings table is written to the job summary on every run.

## Quick start

Add this file to `.github/workflows/mcp-audit.yml` in your repository:

```yaml
name: MCP Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

# Required for SARIF upload to the GitHub Security tab.
# Must be at the workflow level — job-level alone is not sufficient
# for composite actions that call github/codeql-action/upload-sarif.
permissions:
  contents: read
  security-events: write

jobs:
  mcp-audit:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Run mcp-audit
        uses: adudley78/mcp-audit@main
        with:
          severity-threshold: high
          upload-sarif: 'true'
```

The `permissions` block is **required** for the SARIF upload. It must appear at the **workflow level** (before `jobs:`) — not only at the job level. Without it, the upload step fails with "Resource not accessible by integration" and no findings appear in the Security tab.

```yaml
permissions:
  contents: read
  security-events: write   # required for SARIF upload to GitHub Security tab
```

## Inputs

| Input | Default | Required | Description |
|-------|---------|----------|-------------|
| `severity-threshold` | `high` | No | Fail the build if any finding at or above this level exists. Accepted: `critical`, `high`, `medium`, `low`, `info`. |
| `format` | `sarif` | No | Output format written to disk: `sarif`, `json`, or `terminal`. The SARIF upload step always uses the SARIF file regardless of format. |
| `config-paths` | _(auto-discover)_ | No | Single MCP config file path to scan. Leave empty to auto-discover across all supported clients. |
| `baseline` | _(none)_ | No | Baseline name to compare against for drift detection. See [Baseline drift detection in CI](#baseline-drift-detection-in-ci). |
| `upload-sarif` | `true` | No | Set to `'false'` to skip the GitHub Security tab upload (e.g., if you don't have `security-events: write` permission). |

### Severity threshold behaviour

The threshold controls both what is **reported** and whether the **build fails**:

- `--severity-threshold high` (action default): only HIGH and CRITICAL findings are reported; the build fails if any of those exist.
- `--severity-threshold medium`: MEDIUM, HIGH, and CRITICAL findings are reported; the build fails if any of those exist.
- `--severity-threshold info`: all findings are reported; the build fails if any finding exists at all.
- `--severity-threshold critical`: only CRITICAL findings trigger a failure; HIGH and lower are reported but do not fail the build.

## Outputs

| Output | Description |
|--------|-------------|
| `finding-count` | Total number of findings at or above the threshold |
| `grade` | Letter grade (A–F) for the scanned configuration |
| `sarif-path` | Path to the generated SARIF file (`mcp-audit-results.sarif`) |

Use outputs in downstream steps:

```yaml
- name: Run mcp-audit
  id: mcp
  uses: adudley78/mcp-audit@main

- name: Print grade
  run: echo "MCP security grade: ${{ steps.mcp.outputs.grade }}"
```

## Example scenarios

### Basic (visibility only, never fails)

Use this when first adopting mcp-audit. Get visibility into findings without blocking any builds. Tighten the threshold once you've resolved existing issues.

```yaml
- name: Run mcp-audit
  uses: adudley78/mcp-audit@main
  with:
    severity-threshold: info   # report everything, exit 0 always
    upload-sarif: 'true'
```

Full file: [`examples/github-actions/basic.yml`](../examples/github-actions/basic.yml)

### Strict (fail on MEDIUM or higher)

Suitable for security-conscious teams or new projects with no existing findings.

```yaml
- name: Run mcp-audit
  uses: adudley78/mcp-audit@main
  with:
    severity-threshold: medium
    upload-sarif: 'true'
```

Full file: [`examples/github-actions/strict.yml`](../examples/github-actions/strict.yml)

### With baseline drift detection

Compare the current scan against a committed baseline to detect unauthorised server additions, removals, and description changes.

Full file: [`examples/github-actions/with-baseline.yml`](../examples/github-actions/with-baseline.yml)

## How findings appear in the Security tab

When `upload-sarif: 'true'` and `permissions: security-events: write` are both set, findings are uploaded to GitHub's code scanning results using the [github/codeql-action/upload-sarif](https://github.com/github/codeql-action) action (v4, Node.js 24). Each finding becomes a code scanning alert with:

- **Severity** mapped from CRITICAL/HIGH → error, MEDIUM → warning, LOW/INFO → note
- **Location** pointing to the MCP config file where the server is defined
- **Rule** linking to the mcp-audit documentation
- **Fix description** from the finding's remediation field

Alerts appear in the **Security → Code scanning** tab of your repository and as annotations on pull request diff views.

## Baseline drift detection in CI

Drift detection compares the current scan against a named baseline to surface servers that have been added, removed, or had their descriptions changed since the baseline was taken.

### Setup

1. **Create the baseline locally** after reviewing your current configs:
   ```bash
   mcp-audit baseline save ci-baseline
   ```

2. **Export it to a file** that can be committed:
   ```bash
   mcp-audit baseline export ci-baseline > .mcp-audit-baseline.json
   git add .mcp-audit-baseline.json
   git commit -m "chore: add mcp-audit ci baseline"
   ```

3. **Copy it into the baselines directory on CI** before the scan step (see [`examples/github-actions/with-baseline.yml`](../examples/github-actions/with-baseline.yml)):
   ```yaml
   - name: Load baseline
     shell: bash
     run: |
       if [ -f .mcp-audit-baseline.json ]; then
         mkdir -p ~/.config/mcp-audit/baselines/
         cp .mcp-audit-baseline.json ~/.config/mcp-audit/baselines/ci-baseline.json
       fi
   ```

4. **Pass `baseline: ci-baseline`** to the action input.

### What drift findings look like

Drift findings appear alongside normal security findings in SARIF output and the job summary. They have `analyzer: baseline` and IDs in the `DRIFT-NNN` range. Drift finding severity follows the baseline drift rules:
- Server added: MEDIUM
- Server removed: INFO
- Hash changed (description/config content): HIGH
- Command changed: HIGH
- Args changed: MEDIUM
- Env changed: MEDIUM

Update the committed baseline whenever you make intentional config changes:
```bash
mcp-audit baseline save ci-baseline
mcp-audit baseline export ci-baseline > .mcp-audit-baseline.json
git add .mcp-audit-baseline.json && git commit -m "chore: update mcp-audit baseline"
```

## Exit code behaviour

`mcp-audit` uses three distinct exit codes:

| Exit code | Meaning | Action effect |
|-----------|---------|---------------|
| `0` | Clean scan — no findings at or above the threshold | Job continues normally |
| `1` | Findings found at or above the threshold | Job continues; SARIF is uploaded; step exits 0 |
| `2` | Tool error (bad args, unreadable config, etc.) | Step fails immediately; job fails |

Exit code `1` is **not an error** — it is the normal signal that findings exist. The action's scan step explicitly converts exit `1` into a step exit `0` so that SARIF upload and the job summary always run. Only exit code `2` propagates as a real failure.

## Action version requirements

The action uses `github/codeql-action/upload-sarif@v4`, which runs on Node.js 24. GitHub is deprecating actions that run on Node.js 20 starting 2026-06-02. If you pin the composite action yourself, use `@v4` or later.

`actions/checkout@v4` runs on Node.js 20 but is not affected by the 2026-06-02 deprecation (GitHub will update it transparently).

## Troubleshooting

### "Path does not exist: mcp-audit-results.sarif"

**Cause**: the scan step exited with code `1` (findings found) or `2` (error) before writing the SARIF file, and the upload step ran without a file present.

**Fix**: this is resolved in the current action version. The scan step now captures the exit code with `|| SCAN_EXIT=$?` instead of letting the shell abort on non-zero. A `Verify SARIF output` step (runs with `if: always()`) writes an empty valid SARIF file if the scan step produced none, so the upload never fails due to a missing file. Ensure you are using the latest `action.yml`.

### "Resource not accessible by integration" on the SARIF upload step

**Cause**: the `security-events: write` permission is missing at the workflow level. GitHub Actions composite actions inherit the calling workflow's token permissions, but the permission must be declared at the **workflow level** (before `jobs:`) to propagate correctly.

**Fix**: add a `permissions` block before `jobs:` in your workflow file:
```yaml
permissions:
  contents: read
  security-events: write

jobs:
  mcp-audit:
    ...
```

Job-level permissions alone are not sufficient for composite actions that perform SARIF uploads via `github/codeql-action`.

### SARIF upload silently fails with no Security tab results

**Cause**: missing `permissions: security-events: write` at the workflow level.

**Fix**: add the workflow-level permissions block as shown above.

### "No MCP configurations found" in the job summary

**Cause**: the runner has no MCP config files in the standard discovery paths (`.cursor/mcp.json`, `~/.claude.json`, etc.). This is expected on CI runners that don't use MCP clients locally.

**Fix**: if you have MCP configs in your repository (e.g. `.mcp.json` project-level config or test fixtures), pass the path explicitly:
```yaml
with:
  config-paths: '.mcp.json'
```

If your project doesn't use MCP, the action exits cleanly with grade A and zero findings.

### Build fails on HIGH findings I haven't fixed yet

**Fix**: lower the threshold to `critical` temporarily while you work through existing findings:
```yaml
with:
  severity-threshold: critical
```

Or use `severity-threshold: info` to get visibility without build failures.

### `pip install mcp-audit` fails on self-hosted runners

**Cause**: Python may not be in the PATH, or the runner uses a restricted package index.

**Fix**: add `actions/setup-python@v5` before the mcp-audit step:
```yaml
- uses: actions/setup-python@v5
  with:
    python-version: '3.11'

- uses: adudley78/mcp-audit@main
```

### Windows runners: bash script errors

The action uses `shell: bash` on all steps, which on Windows runners resolves to Git Bash. If Git Bash is not available (unlikely on GitHub-hosted runners but possible on self-hosted), the script steps will fail.

**Fix**: ensure Git for Windows is installed on self-hosted Windows runners, or add a setup step to install it.

### Baseline not detected on CI

**Cause**: the baseline JSON file was not copied to the expected directory before the scan step.

**Fix**: copy the exported baseline to the baselines directory:
```bash
mkdir -p ~/.config/mcp-audit/baselines/
cp .mcp-audit-baseline.json ~/.config/mcp-audit/baselines/ci-baseline.json
```

## Known limitations

- The action installs mcp-audit via `pip install`, adding ~20–30 seconds per run. A binary-based action using prebuilt releases is a planned future optimization. See [GAPS.md](../GAPS.md).
- `config-paths` accepts a single path only. Multiple paths are not currently supported via the action input.
- The action has not been validated on Windows runners or self-hosted runners without standard Python environments.
