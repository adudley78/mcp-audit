# mcp-audit Manual Test Matrix

Paste this file into Cursor (or run each section manually) to validate a release
candidate.  Run all sections in order on a clean machine (or reset `$SCRATCH`
between runs).  Each section states its expected exit code and observable output.

```bash
# Set up a scratch directory once at the top of the session
SCRATCH=$(mktemp -d)
echo "Scratch dir: $SCRATCH"
```

---

## Section 1 — version / help smoke test

```bash
mcp-audit --version
mcp-audit --help
mcp-audit scan --help
```

**Expected:** version string prints, help text lists all commands, exit 0.

---

## Section 2 — discover (auto-detect)

```bash
mcp-audit discover
```

**Expected:** lists any MCP configs found on the machine; prints count of servers;
exit 0 regardless of whether any configs exist.

---

## Section 3 — basic scan (terminal output, demo configs)

```bash
mcp-audit scan --path demo/configs
```

**Expected:** findings printed with severity levels; scan score (F grade); exit 1
(findings present).  Must not crash or print a Python traceback.

---

## Section 4 — SARIF output and score property key validation

```bash
mcp-audit scan --path demo/configs --format sarif --output "$SCRATCH/results.sarif"
echo "exit: $?"

# Verify the SARIF file was written
test -f "$SCRATCH/results.sarif" && echo "SARIF file exists" || echo "MISSING"

# Validate score properties use the correct namespace keys
python3 - "$SCRATCH/results.sarif" <<'PYEOF'
import json, sys
with open(sys.argv[1]) as f:
    sarif = json.load(f)
props = sarif["runs"][0].get("properties", {})
grade = props.get("mcp-audit/grade")
score = props.get("mcp-audit/numericScore")
print(f"mcp-audit/grade:        {grade}")
print(f"mcp-audit/numericScore: {score}")
if grade is None or score is None:
    print("FAIL — expected mcp-audit/grade and mcp-audit/numericScore in run.properties")
    sys.exit(1)
print("PASS — score properties present with correct key names")
PYEOF
```

**Expected:** `mcp-audit/grade` is a letter grade (A–F); `mcp-audit/numericScore` is
an integer 0–100.  Both keys use the `mcp-audit/` namespace prefix.  **Do not use**
`score` or `grade` as bare keys — those are the stale names from before 2026-04-16.
Exit 1 from the scan (findings); exit 0 from the python verification block.

---

## Section 5 — JSON output and score fields

```bash
mcp-audit scan --path demo/configs --format json --output "$SCRATCH/results.json"
python3 -c "
import json
d = json.load(open('$SCRATCH/results.json'))
print('score:', d.get('score'))
print('grade:', d.get('grade'))
print('finding_count:', len(d.get('findings', [])))
"
```

**Expected:** `score` (integer) and `grade` (letter) present at the top level of the
JSON object; finding_count > 0.

---

## Section 6 — --no-score suppresses terminal panel but not JSON score

```bash
mcp-audit scan --path demo/configs --no-score --format json --output "$SCRATCH/no-score.json"
python3 -c "
import json
d = json.load(open('$SCRATCH/no-score.json'))
print('score in JSON:', d.get('score'))  # should be absent / null
"
```

**Expected:** terminal output has no "Scan Score" panel; JSON output has `score: null`
(score is nulled before formatting when `--no-score` is passed).

---

## Section 7 — severity threshold filtering

```bash
# Should exit 0: no CRITICAL findings in demo configs beyond what exists
mcp-audit scan --path demo/configs --severity-threshold critical
echo "exit: $?"

# Should exit 1: HIGH+ findings present
mcp-audit scan --path demo/configs --severity-threshold high
echo "exit: $?"
```

**Expected:** first command exits 1 (there are CRITICAL findings in demo configs);
second exits 1 (HIGH+ findings present).  Adjust expectation if demo configs change.

---

## Section 8 — single config scan (positional path)

```bash
mcp-audit scan demo/configs/claude_desktop_config.json
echo "exit: $?"
```

**Expected:** scans only `claude_desktop_config.json`; prints ~8 findings; exit 1.

---

## Section 9 — --path flag equivalent to positional

```bash
mcp-audit scan --path demo/configs/cursor_mcp.json
echo "exit: $?"
```

**Expected:** scans only `cursor_mcp.json`; exit 1.

---

## Section 10 — pin and diff (no drift)

```bash
mcp-audit pin --path demo/configs
mcp-audit diff --path demo/configs
echo "exit: $?"
```

**Expected:** `pin` prints "Pinned N servers"; `diff` prints "No changes detected" and
exits 0.

---

## Section 11 — baseline save / list / compare / delete

```bash
mcp-audit baseline save --path demo/configs --name test-baseline
mcp-audit baseline list
mcp-audit scan --path demo/configs --baseline test-baseline
mcp-audit baseline delete test-baseline
```

**Expected:** save prints confirmation; list shows `test-baseline`; scan with
`--baseline` shows drift panel (empty if nothing changed since save); delete confirms.

---

## Section 12 — Nucleus FlexConnect output

```bash
mcp-audit scan --path demo/configs --format nucleus --output "$SCRATCH/results.nucleus.json"
python3 -c "
import json
d = json.load(open('$SCRATCH/results.nucleus.json'))
print('type:', type(d))
print('keys (if dict):', list(d.keys())[:5] if isinstance(d, dict) else 'list of', len(d))
"
```

**Expected:** valid JSON; list of asset objects or dict with `findings` key; exit 1
from scan.

---

## Section 13 — policy validate (free tier)

```bash
mcp-audit policy validate examples/policies/starter.yml
echo "exit: $?"
```

**Expected:** "Policy is valid" or similar; exit 0.

---

## Section 14 — policy check positional path (Pro gate, cosmetic)

```bash
mcp-audit policy check examples/policies/starter.yml
echo "exit: $?"
```

**Expected:** Pro upsell panel printed (not a raw Typer error); clean exit (2 for
hard-gated commands, not an unhandled exception).  Must not show "Got unexpected
extra argument".

---

## Section 15 — rule list (community rules, free)

```bash
mcp-audit rule list
echo "exit: $?"
```

**Expected:** lists 12 bundled community rules (COMM-001 through COMM-012); exit 0.

---

## Section 16 — governance policy scan (free execution)

```bash
mcp-audit scan --path demo/configs --policy examples/policies/starter.yml
echo "exit: $?"
```

**Expected:** scan runs; governance findings appear in "Policy Violations" yellow
panel; exit 1.

---

## Section 17 — error on non-existent path (exit 2)

```bash
mcp-audit scan /tmp/does-not-exist-mcp-audit-test-12345.json
echo "exit: $?"
```

**Expected:** human-readable error message (no Python traceback); exit 2.

---

## Section 18 — clean config produces exit 0 ("No security issues found")

```bash
# Clean config: empty server list — the only reliably clean config at default threshold.
# Do NOT use a config with node/npx servers — COMM-004 fires on unrecognised stdio
# binaries and COMM-010 fires on unpinned npx, so those are not clean at default INFO threshold.
echo '{"mcpServers": {}}' > "$SCRATCH/clean.json"
mcp-audit scan "$SCRATCH/clean.json"
echo "exit: $?"
```

**Expected:** "No security issues found" (or equivalent clean message); exit 0.

---

## Section 19 — multiple positional args rejected with user-friendly message

```bash
mcp-audit scan demo/configs/claude_desktop_config.json demo/configs/cursor_mcp.json
echo "exit: $?"
```

**Expected:** friendly error explaining that `scan` accepts a single config path and
suggesting `discover` or `--path` for multiple configs; exit 2.  Must not show raw
Typer "Got unexpected extra argument" message.

---

## Section 20 — discover then scan all discovered configs

```bash
mcp-audit discover --path demo/configs
mcp-audit scan --path demo/configs --format json --output "$SCRATCH/full.json"
python3 -c "
import json
d = json.load(open('$SCRATCH/full.json'))
print('servers scanned:', len(set(f.get('server_name','') for f in d.get('findings',[]))))
print('total findings:', len(d.get('findings',[])))
"
```

**Expected:** discover lists 3 config files and 8 servers; scan produces JSON with
findings from all three configs; total findings ≥ 24.

---

## Teardown

```bash
rm -rf "$SCRATCH"
echo "Scratch cleaned up."
```
