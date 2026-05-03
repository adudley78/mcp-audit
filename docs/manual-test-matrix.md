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
mcp-audit version
mcp-audit --help
mcp-audit scan --help
```

**Expected:** `mcp-audit version` outputs version string, exits 0; help text lists all commands.

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

> **Note:** `mcp-audit/numericScore` is `0` (integer) for an F-grade scan against
> demo/configs. The Python check uses `is None` — a score of `0` is valid and must
> not be treated as absent.

---

## Section 5 — JSON output and score fields

```bash
mcp-audit scan --path demo/configs --format json --output "$SCRATCH/results.json"
python3 -c "
import json
d = json.load(open('$SCRATCH/results.json'))
score = d.get('score') or {}
print('score.numeric:', score.get('numeric'))
print('score.grade:', score.get('grade'))
print('finding_count:', len(d.get('findings', [])))
"
```

**Expected:** `score` is a nested object `{"numeric": <int 0–100>, "grade": "<A–F>",
"positive_signals": [...], "deductions": [...]}` — accessed as `score.numeric` and
`score.grade`, not as bare top-level keys. `finding_count` > 0.

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
# Should exit 1: CRITICAL findings exist in demo configs
mcp-audit scan --path demo/configs --severity-threshold critical
echo "exit: $?"

# Should exit 1: HIGH+ findings present
mcp-audit scan --path demo/configs --severity-threshold high
echo "exit: $?"
```

**Expected:** both commands exit 1.  demo/configs currently contains 4 CRITICAL and
30 HIGH findings.  Adjust expectation only if demo configs change.

---

## Section 8 — single config scan (positional path)

```bash
mcp-audit scan demo/configs/claude_desktop_config.json
echo "exit: $?"
```

**Expected:** scans only `claude_desktop_config.json`; prints findings (count varies with active rules); exit 1.

---

## Section 9 — --path flag equivalent to positional

```bash
mcp-audit scan --path demo/configs/cursor_mcp.json
echo "exit: $?"
```

**Expected:** scans only `cursor_mcp.json`; exit 1.

---

## Section 10 — pin (rug-pull baseline) and empty-state message

```bash
mcp-audit pin --path demo/configs
echo "exit: $?"
```

**Expected:** prints "Pinned baseline for N server(s)" with a state-file reference;
exit 0.

> **Note — rug-pull detection:** `pin` records a SHA-256 hash of each server's
> description. On the next `mcp-audit scan`, the rug-pull analyzer compares live
> descriptions against these hashes and emits a finding if any description changed.
> The old `mcp-audit diff --path` command (rug-pull diff) was **removed** in v0.8.0
> when the `diff` command was repurposed for MCP-aware base/head comparison
> (Section 23).  Rug-pull changes are now surfaced inline in `scan` output.

```bash
# Empty-state: config file exists but has no servers
echo '{"mcpServers": {}}' > "$SCRATCH/empty.json"
mcp-audit pin --path "$SCRATCH/empty.json"
echo "exit: $?"
```

**Expected:** message reads "Found N MCP config file(s) but no servers are configured
in them — nothing to pin." (not the old bare "No MCP servers found" message); exit 0.

---

## Section 11 — baseline save / list / compare / delete

```bash
mcp-audit baseline save --path demo/configs test-baseline
mcp-audit baseline list
mcp-audit scan --path demo/configs --baseline test-baseline
mcp-audit baseline delete test-baseline --yes
```

**Expected:** save prints confirmation; list shows `test-baseline`; scan with
`--baseline` shows drift panel (empty if nothing changed since save); delete confirms
non-interactively (no prompt).

---

## Section 12 — Nucleus FlexConnect output

```bash
mcp-audit scan --path demo/configs --format nucleus --output "$SCRATCH/results.nucleus.json"
echo "exit: $?"

# Verify the output file was written and has the correct schema shape
python3 - "$SCRATCH/results.nucleus.json" <<'PYEOF'
import json, sys
with open(sys.argv[1]) as f:
    doc = json.load(f)
assert "assets" in doc, "FAIL — missing top-level 'assets' array"
assert "findings" in doc, "FAIL — missing top-level 'findings' array"
assert doc.get("scan_type") == "Host", f"FAIL — scan_type should be 'Host', got {doc.get('scan_type')}"
assert len(doc["assets"]) == 1, f"FAIL — expected 1 asset entry, got {len(doc['assets'])}"
host = doc["assets"][0]["host_name"]
assert all(f["host_name"] == host for f in doc["findings"]), "FAIL — finding host_name mismatch"
print(f"PASS — {len(doc['findings'])} findings, asset: {host}, scan_type: {doc['scan_type']}")
PYEOF
```

**Expected:** FlexConnect JSON written to output file; exit 1 from scan (findings
present).  Schema must have top-level `assets` array and `findings` array with
`scan_type: "Host"`.  No gate — available to all users.

---

## Section 13 — policy validate (free tier)

```bash
mcp-audit policy validate examples/policies/starter.yml
echo "exit: $?"
```

**Expected:** "Policy is valid" or similar; exit 0.

---

## Section 14 — policy check positional path

```bash
mcp-audit policy check examples/policies/starter.yml
echo "exit: $?"
```

**Expected:** policy check runs (no gate — available to all users); prints a
compliance summary or "Policy is valid"; exit 0.  Must not show "Got unexpected
extra argument" and must not show any Pro/Enterprise upsell panel.

---

## Section 15 — rule list (community rules, free)

```bash
mcp-audit rule list
echo "exit: $?"
```

**Expected:** lists 13 bundled community rules (COMM-001 through COMM-013); exit 0.

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
print('servers scanned:', len(d.get('servers', [])))
print('total findings:', len(d.get('findings', [])))
"
```

**Expected:** discover lists 3 config files; scan produces JSON with 8 servers and
≥ 50 total findings from all three configs.

> **Note:** finding count grows over time as new community rules are added. The
> bound `≥ 50` reflects the count as of v0.8.0 (currently 51). Update this bound
> after any release that intentionally changes the demo-config finding count.

---

## Section 21 — shadow (OWASP MCP09 — shadow server detection)

```bash
# Default text output: all servers are shadow (no allowlist configured)
mcp-audit shadow --path demo/configs/claude_desktop_config.json
echo "exit: $?"
```

**Expected:** Rich table showing servers found; header reads "Servers found: N  Shadow:
N  Sanctioned: 0"; each server has a `risk_level` and `capability_tags`; note
"No allowlist configured — all servers are shadow by default."; exit 1 (shadow
servers present).

```bash
# JSON format
mcp-audit shadow --path demo/configs/claude_desktop_config.json --format json
echo "exit: $?"
```

**Expected:** JSON array; each record has `classification`, `risk_level`,
`capability_tags`, `first_seen`, `last_seen`; exit 1.

```bash
# Empty-state: config file exists but has no servers
echo '{"mcpServers": {}}' > "$SCRATCH/empty.json"
mcp-audit shadow --path "$SCRATCH/empty.json"
echo "exit: $?"
```

**Expected:** message reads "Found N MCP config file(s) but no servers are configured
in them." (not "No MCP configs found on this host."); exit 0.

---

## Section 22 — killchain (blast-radius remediation engine)

```bash
# Live scan + ranked recommendations
mcp-audit killchain --path demo/configs
echo "exit: $?"
```

**Expected:** Markdown report with "Current blast radius" heading and "Top 3
recommended changes"; each recommendation labelled `KS-001`, `KS-002`, `KS-003`
with path-reduction counts; exit 0.

```bash
# From existing scan JSON (no re-scan)
mcp-audit killchain --input "$SCRATCH/results.json"
echo "exit: $?"
```

**Expected:** same ranked output loaded from the saved JSON; no re-scan performed
(no "running scan…" line on stderr); exit 0.

```bash
# JSON format
mcp-audit killchain --input "$SCRATCH/results.json" --format json
echo "exit: $?"
```

**Expected:** JSON object with top-level `kill_switches` array, `original_blast_radius`,
and `simulated_blast_radius` keys; exit 0.

```bash
# YAML governance patch
mcp-audit killchain --input "$SCRATCH/results.json" --patch yaml
echo "exit: $?"
```

**Expected:** Markdown report followed by a YAML governance-policy denylist patch
that lists the flagged servers; exit 0.

---

## Section 23 — diff (MCP-aware base/head comparison)

> **Note:** this is the `mcp-audit diff <base> <head>` command introduced in
> v0.8.0 (STORY-0014). It compares two MCP config states (directories, JSON scan
> files, or git refs) and surfaces structural changes. It is **not** the rug-pull
> description-change detector — see Section 10 for rug-pull coverage.

```bash
mcp-audit diff demo/configs/claude_desktop_config.json demo/configs/cursor_mcp.json
echo "exit: $?"
```

**Expected:** terminal output listing added and removed servers between the two
configs; severity classification per change (HIGH for `shell-exec` added); exit 1
(changes at INFO threshold present).

```bash
mcp-audit diff demo/configs/claude_desktop_config.json demo/configs/cursor_mcp.json \
  --format pr-comment
echo "exit: $?"
```

**Expected:** GitHub-flavored Markdown output starting with `## MCP Security Diff:`
heading; `<details>` collapsibles per changed server; total ≤ 100 lines; exit 1.

```bash
mcp-audit diff demo/configs/claude_desktop_config.json demo/configs/cursor_mcp.json \
  --format json
echo "exit: $?"
```

**Expected:** JSON array; each record has `change_type`, `entity_type`,
`entity_name`, `severity` keys; exit 1.

---

## Section 24 — snapshot (CycloneDX AI/ML-BOM)

```bash
mcp-audit snapshot --path demo/configs --output "$SCRATCH/snapshot.json"
echo "exit: $?"

# Verify CycloneDX structure
python3 - "$SCRATCH/snapshot.json" <<'PYEOF'
import json, sys
with open(sys.argv[1]) as f:
    doc = json.load(f)
assert doc.get("bomFormat") == "CycloneDX", f"FAIL — bomFormat={doc.get('bomFormat')}"
comps = doc.get("components", [])
vulns = doc.get("vulnerabilities", [])
assert len(comps) > 0, "FAIL — no components"
assert all(c.get("type") == "application" for c in comps if c.get("type")), \
    "FAIL — component type not 'application'"
assert len(vulns) > 0, "FAIL — no vulnerabilities"
print(f"PASS — {len(comps)} component(s), {len(vulns)} vulnerability/vulnerabilities")
PYEOF
```

**Expected:** CycloneDX 1.5 JSON written; `bomFormat` == `"CycloneDX"`; each server
is a `component` of `type: application`; each finding is a `vulnerability` entry;
exit 0.

```bash
# NDJSON stream mode
mcp-audit snapshot --path demo/configs --stream | head -3
echo "exit: $?"
```

**Expected:** one JSON object per line on stdout (NDJSON); each line is valid JSON;
exit 0.

```bash
# Empty-state: produces valid empty BOM (not an error)
echo '{"mcpServers": {}}' > "$SCRATCH/empty.json"
mcp-audit snapshot --path "$SCRATCH/empty.json" --output "$SCRATCH/empty-snap.json"
echo "exit: $?"
python3 -c "
import json
d = json.load(open('$SCRATCH/empty-snap.json'))
print('components:', len(d.get('components', [])))
print('vulnerabilities:', len(d.get('vulnerabilities', [])))
print('PASS' if d.get('bomFormat') == 'CycloneDX' else 'FAIL')
"
```

**Expected:** exit 0; valid CycloneDX document with `components: []` and
`vulnerabilities: []`; summary line on stderr reads `servers=0 findings=0`.

---

## Section 25 — sast (Semgrep SAST rule pack)

```bash
# Scan own source tree — should be clean
mcp-audit sast src/
echo "exit: $?"
```

**Expected:** "✓ No SAST findings." printed; exit 0.  If Semgrep is not installed,
a clean "semgrep is not installed" message is printed and exit 2 — no Python
traceback.

> **Note:** `mcp-audit sast` requires Semgrep to be installed (`pip install semgrep`
> or `brew install semgrep`). The bundled `semgrep-rules/` directory is resolved
> automatically; no `--rules-dir` flag is needed.

```bash
# Scan demo configs directory — no Python/TypeScript source, expect no findings
mcp-audit sast demo/
echo "exit: $?"
```

**Expected:** exit 0 (JSON configs are not Semgrep targets); no crash.

---

## Section 26 — extensions discover

```bash
mcp-audit extensions discover
echo "exit: $?"
```

**Expected:** table of installed IDE extensions from VS Code / Cursor paths, or a
"No extensions found" message if none are installed; exit 0 (discover never exits
non-zero for an empty result).

---

## Section 27 — extensions scan

```bash
mcp-audit extensions scan
echo "exit: $?"
```

**Expected:** security analysis of discovered extensions; each finding shows the
extension ID, client, severity, and description; exit 1 if any findings exist,
exit 0 if none.  Must not crash even if no IDE is installed.

---

## Teardown

```bash
rm -rf "$SCRATCH"
echo "Scratch cleaned up."
```
