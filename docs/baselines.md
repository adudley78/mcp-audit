# Baseline Snapshot and Drift Detection

`mcp-audit` can capture a point-in-time snapshot of your MCP server configuration
and alert you when future scans diverge from it.  This is useful for:

- **Change management** — enforce a known-good configuration in CI/CD pipelines.
- **Incident response** — confirm whether a configuration was tampered with.
- **Auditing** — prove a configuration was stable across a time window.

Baselines are architecturally separate from the rug-pull analyzer.  The rug-pull
analyzer tracks automatic per-scan hash state and detects silent changes between
consecutive runs.  Baselines are explicit, user-named snapshots that you control.

---

## Workflow overview

```
mcp-audit baseline save              # capture current state
mcp-audit scan --baseline latest     # scan + compare in one step
mcp-audit baseline compare           # standalone drift report
```

---

## Commands

### `mcp-audit baseline save [NAME]`

Runs discovery, parses all MCP config files, and saves a snapshot to
`~/.config/mcp-audit/baselines/{NAME}.json`.

- `NAME` is optional.  If omitted, an auto-generated timestamp name is used:
  `baseline-20260416-142500`.
- Use `--path` to limit discovery to a specific file or directory.

**Example output:**

```
Baseline saved: baseline-20260416-142500 (4 servers captured)
```

---

### `mcp-audit baseline list`

Displays all saved baselines, newest first.

**Example output:**

```
┏━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━━━━━┓
┃ Name                     ┃ Created                 ┃ Servers ┃ Scanner Version ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━━━━━┩
│ baseline-20260416-142500 │ 2026-04-16 14:25:00 UTC │       4 │ 0.1.0           │
│ production-2026q1        │ 2026-03-31 09:00:00 UTC │       3 │ 0.1.0           │
└──────────────────────────┴─────────────────────────┴─────────┴─────────────────┘
```

---

### `mcp-audit baseline compare [NAME]`

Compares the current live configuration against a saved baseline.

- `NAME` (positional) selects a specific baseline by name.
- If omitted, the most recent baseline is used automatically.
- Exit code 0 = no drift.  Exit code 1 = drift detected.

**Example: no drift**

```
No drift detected — configuration matches baseline 'production-2026q1'
```

**Example: drift detected**

```
Drift against baseline 'production-2026q1' (created 2026-03-31 09:00 UTC)

┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Severity ┃ Type            ┃ Client         ┃ Server    ┃ Detail                               ┃
┡━━━━━━━━━━╇━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ HIGH     │ command_changed │ claude-desktop │ github    │ 'npx' → 'bunx'                       │
│ HIGH     │ hash_changed    │ claude-desktop │ github    │ 'a1b2c3d4…' → 'e5f6a7b8…'            │
│ MEDIUM   │ server_added    │ cursor         │ new-tool  │ now: 'uvx mcp-server-newtool'        │
│ INFO     │ server_removed  │ claude-desktop │ old-fetch │ was: 'npx mcp-server-fetch'          │
└──────────┴─────────────────┴────────────────┴──────────┴──────────────────────────────────────┘

4 drift finding(s) detected.
```

---

### `mcp-audit baseline delete NAME`

Prompts for confirmation, then deletes the named baseline file.

```
Delete baseline 'production-2026q1'? [y/N]: y
Baseline 'production-2026q1' deleted.
```

---

### `mcp-audit baseline export NAME`

Writes the raw JSON of the named baseline to stdout.  No Rich formatting —
designed for piping to files or other tools.

```bash
mcp-audit baseline export production-2026q1 > baseline.json
```

---

## Using `--baseline` with `scan`

The `scan` command accepts a `--baseline` flag that loads a baseline and runs
drift detection after the normal security scan completes.  Drift findings appear
as `analyzer="baseline"` findings in all output formats (terminal, JSON, SARIF,
HTML dashboard).

```bash
mcp-audit scan --baseline production-2026q1
mcp-audit scan --baseline latest
mcp-audit scan --baseline latest --format json | jq '.findings[] | select(.analyzer=="baseline")'
```

The `--baseline latest` shorthand selects the most recently created baseline
without needing to remember its auto-generated name.

---

## Drift severity mapping

| Drift type        | Severity | Rationale                                                    |
|-------------------|----------|--------------------------------------------------------------|
| `hash_changed`    | HIGH     | The full config was modified; anything could have changed.   |
| `command_changed` | HIGH     | The executable path changed — a common supply-chain attack.  |
| `server_added`    | MEDIUM   | New servers appear without explanation; may be malicious.    |
| `args_changed`    | MEDIUM   | Arguments changed; could change server behavior or targets.  |
| `env_changed`     | MEDIUM   | Environment variable keys changed; may indicate new secrets. |
| `server_removed`  | INFO     | Removal is often intentional; warrants awareness only.       |

---

## Security: env values are never stored

When capturing a baseline, `mcp-audit` stores environment variable **key names
only** — never their values.  The baseline JSON for a server configured with
`{"OPENAI_API_KEY": "sk-…", "DEBUG": "true"}` records `{"OPENAI_API_KEY": "",
"DEBUG": ""}` — empty strings for all values.

This prevents secrets from being persisted to disk in the baseline files, which
are stored in `~/.config/mcp-audit/baselines/` with 0o700 directory permissions
and 0o600 file permissions.

Drift detection for `env_changed` compares the **set of key names**, not values,
so it fires when keys are added or removed without ever reading secret values.

---

## CI/CD usage example

Export a baseline at release time and commit it to your repository.  In CI,
run a headless scan against that baseline to detect any drift in the deployed
environment.

```bash
# At release time (run once, commit the output):
mcp-audit baseline save release-v1.2.3
mcp-audit baseline export release-v1.2.3 > .mcp-baseline.json

# In CI (headless environment):
# 1. Import the baseline from the committed file
TMPDIR=$(mktemp -d)
mkdir -p "$TMPDIR/.config/mcp-audit/baselines"
install -m 0600 .mcp-baseline.json "$TMPDIR/.config/mcp-audit/baselines/release-v1.2.3.json"
HOME="$TMPDIR" mcp-audit scan --baseline release-v1.2.3 --format json > scan-output.json
exit_code=$?

# exit_code 1 = findings (including drift); 0 = clean
if [ $exit_code -ne 0 ]; then
  echo "Drift or security findings detected — blocking deployment"
  cat scan-output.json | jq '.findings[] | select(.analyzer=="baseline")'
  exit 1
fi
```

> **Note:** The `HOME` override forces `BaselineManager` to read from `$TMPDIR`
> rather than the CI runner's home directory.  Alternatively, copy the baseline
> file directly to `~/.config/mcp-audit/baselines/` on the CI agent.

---

## Known limitations

See [GAPS.md](../GAPS.md#baselines) for known limitations, including:

- Server matching uses exact `(client, name)` pair — a renamed server appears as
  removed + added, not modified.
- Trend tracking across multiple baselines is not yet implemented (planned).
