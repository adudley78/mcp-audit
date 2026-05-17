# `mcp-audit check` — One-command security verdict

`mcp-audit check` is the recommended entry point for anyone who has just
installed an MCP client and wants to know: **"is my setup safe?"**

It runs a full scan internally (identical detection to `mcp-audit scan`) and
presents the result as a concise one-page verdict: a letter grade, the top
findings, and a numbered fix list.

---

## Usage

```bash
mcp-audit check                    # Auto-discover all MCP configs on this machine
mcp-audit check --path config.json # Scan a specific config file
mcp-audit check --verbose          # Full scan output (equivalent to mcp-audit scan)
mcp-audit check --json             # Output full ScanResult JSON
```

---

## Sample output

**With findings:**

```
mcp-audit — Security Check
───────────────────────────────────────────────────────────────────────────────
  Grade: C  (Score: 61/100)

  ⚠  3 issues need your attention:

  1. [CRITICAL] Exposed API key in GITHUB_TOKEN env var
     → Run `mcp-audit fix --apply` to redact automatically.

  2. [HIGH] Server "fetch" uses unencrypted HTTP
     → Run `mcp-audit fix --apply` to upgrade to HTTPS automatically.

  3. [MEDIUM] "mcp-server-data" is not pinned to a version
     → Pin the package to an explicit version (e.g. @2.1.0) to prevent unexpected updates.

  2 of 3 issues can be fixed with mcp-audit fix --apply

───────────────────────────────────────────────────────────────────────────────
To see all findings:  mcp-audit scan
To apply auto-fixes:  mcp-audit fix --apply
```

**Clean config:**

```
mcp-audit — Security Check
───────────────────────────────────────────────────────────────────────────────
  Grade: A  ✓ No issues found

  Your MCP configuration looks clean.

───────────────────────────────────────────────────────────────────────────────
```

**Grade F with attack path:**

```
  Grade: F  (Score: 0/100)

  ⛔ Active attack path detected.  Run mcp-audit scan for full details.
  ...
```

---

## Behaviour

| Situation | Behaviour |
|-----------|-----------|
| Auto-discovers configs (no `--path`) | Identical to `mcp-audit scan` with no `--path` flag |
| More than 5 findings | Shows top 5 by severity; footer says "and N more — run mcp-audit scan to see all" |
| No MCP configs found | Prints a friendly message and exits 0 |
| `--verbose` | Prints full scan output (Rich panels, OWASP codes, attack paths) |
| `--json` | Outputs the full `ScanResult` JSON to stdout; no summary text |
| `--path /nonexistent` | Prints "File not found" and exits 2 |

---

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Grade A or B (score ≥ 70) **and** no CRITICAL or HIGH findings |
| 1 | Grade C, D, or F — or any CRITICAL/HIGH finding present |
| 2 | Error: invalid path, config parse failure, or unexpected exception |

This differs intentionally from `mcp-audit scan`, which exits 1 whenever
*any* findings are present regardless of severity. `check` uses a higher
threshold so scripts can use it as a pass/fail gate on severity level.

---

## Detection

`check` runs the **same full pipeline** as `mcp-audit scan`:

- All 7 built-in analyzers (poisoning, credentials, transport, supply chain,
  rug-pull, toxic flow, config hygiene)
- Community rules (COMM-001 through COMM-015)
- Attack path engine

No detection shortcuts are applied. The grade shown by `check` is the same
grade `scan` would produce for the same configuration.

---

## Auto-fixable findings

The following finding IDs are handled by `mcp-audit fix --apply`. When
present, the remediation hint says "Run `mcp-audit fix --apply` to fix
automatically."

| ID | Meaning |
|----|---------|
| `CRED-001` | API key or secret in env var |
| `CRED-002` | Hardcoded credential |
| `TRANSPORT-001` | HTTP instead of HTTPS |
| `SC-001` | Likely-typosquatted package (edit distance 1) |
| `SC-002` | Possible-typosquatted package (edit distance 2) |

All other findings receive a specific manual instruction derived from a
per-ID lookup table in `output/check.py::_HINTS`.

---

## Relationship to `mcp-audit scan`

| Feature | `check` | `scan` |
|---------|---------|--------|
| Detection | Full pipeline | Full pipeline |
| Output | One-page verdict, ≤ 5 findings | All findings, OWASP codes, attack paths |
| SARIF / Nucleus output | No | Yes (`--format sarif/nucleus`) |
| OWASP codes shown | No | Yes |
| Analyzer names shown | No | Yes |
| Exit 0 threshold | Grade A/B (score ≥ 70, no CRIT/HIGH) | No findings |
| Intended audience | Developers, first-time users | Security engineers, CI/CD |

Use `mcp-audit scan` for CI/CD pipelines, SARIF uploads, and full-detail
forensics. Use `mcp-audit check` for quick interactive checks.
