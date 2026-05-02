# Fleet Scanning

`mcp-audit merge` consolidates JSON scan outputs from multiple machines into a
single fleet-wide security report. It is the standard workflow for security
teams that manage many developer machines.

Available to every user — mcp-audit is fully open source, no license required.

---

## Workflow overview

### 1. Distribute the binary

Copy `mcp-audit` to each machine. The PyInstaller binary requires no Python
installation. See the [releases page](https://github.com/adudley78/mcp-audit/releases)
for the platform-specific download.

For fleet deployment you may want to use an asset prefix to give each machine a
meaningful identifier in reports:

```bash
# On each machine, set an asset tag that reflects the team / role / hostname
export MCP_AUDIT_ASSET_PREFIX="prod-macbook-adam"
```

### 2. Scan each machine and save JSON output

Run this on every machine you want to include in the fleet report:

```bash
mcp-audit scan --format json --output-file ~/results/$(hostname).json
```

The output file contains all findings, the machine's hostname, scanner version,
and an optional scan score.

### 3. Collect JSON files to a central location

Copy the per-machine JSON files to one directory on the analysis machine:

```bash
# Example: collect via SSH
for host in prod-01 prod-02 prod-03; do
  scp "$host:~/results/${host}.json" ./fleet-results/
done
```

Or pull from an artifact store, S3 bucket, or CI artifact download — any
mechanism that lands all the JSON files in one directory.

### 4. Merge into a fleet report

```bash
# Merge everything in a directory (recurses into subdirectories automatically)
mcp-audit merge --dir ./fleet-results/

# Or pass files explicitly (supports shell glob expansion)
mcp-audit merge ./fleet-results/*.json

# JSON output — pipe or write to file
mcp-audit merge --dir ./fleet-results/ --format json -o fleet-report.json

# HTML report
mcp-audit merge --dir ./fleet-results/ --format html -o fleet-report.html
```

The merge command prints a Fleet Summary panel and a deduplicated finding
breakdown sorted by the number of machines affected.

---

## Filtering with `--asset-prefix`

Security teams often want to view prod machines separately from dev machines.
Because `asset_prefix` is not persisted inside the scan JSON, filtering is
applied against the machine's **hostname** (the `machine_id` field in the
fleet report).

Name your machines with a meaningful prefix when scanning:

```bash
# On a prod machine — give it a recognisable hostname or alias:
mcp-audit scan --format json --output-file results.json
# The hostname is captured automatically from the OS.
```

Then filter at merge time:

```bash
# Only include machines whose hostname starts with "prod-"
mcp-audit merge --dir ./fleet-results/ --asset-prefix prod-

# Engineering team only
mcp-audit merge --dir ./fleet-results/ --asset-prefix eng-
```

Machines whose hostname does not start with the prefix are silently excluded
from the merged report.

---

## Handling invalid or outdated scan files

When using `--dir`, files that are not valid mcp-audit JSON are **skipped with a
warning** rather than aborting the merge:

- `.txt`, `.yaml`, or other non-JSON files are silently ignored (only `*.json`
  files are considered).
- JSON files that lack the required mcp-audit fields (`version`, `timestamp`,
  `machine`, `findings`) are skipped with a warning that identifies the file.
- JSON files produced by a different scanner version trigger a warning in both
  the terminal output and the `version_mismatches` list in the JSON report.

To resolve version mismatch warnings, upgrade all machines to the same
`mcp-audit` binary version and re-collect scan outputs.

---

## Version mismatch warnings

If machines in the fleet ran different versions of mcp-audit, the report
includes warnings such as:

```
Warning: prod-laptop-dave: ran version '0.0.9' (majority is '0.1.0')
```

This matters because:
- Detection patterns may differ between versions.
- A finding present in the newer version's patterns may not have been detected
  by the older scanner.
- Deduplication works correctly across versions, but false-negative gaps are
  possible.

**Action:** Re-scan the flagged machines with the current binary and re-merge.

---

## CI/CD integration

You can collect scan results as build artifacts and merge them in a final job.
Below is a GitHub Actions example.

### `.github/workflows/fleet-scan.yml`

```yaml
name: Fleet MCP Scan

on:
  schedule:
    - cron: "0 6 * * 1"   # weekly on Monday at 06:00 UTC
  workflow_dispatch:

jobs:
  scan:
    strategy:
      matrix:
        runner: [ubuntu-latest, macos-latest]
    runs-on: ${{ matrix.runner }}
    steps:
      - uses: actions/checkout@v4

      - name: Install mcp-audit
        run: pip install mcp-audit

      - name: Scan and save JSON
        run: |
          mcp-audit scan --format json \
            --output-file results-${{ matrix.runner }}.json

      - name: Upload scan artifact
        uses: actions/upload-artifact@v4
        with:
          name: scan-${{ matrix.runner }}
          path: results-${{ matrix.runner }}.json

  merge:
    needs: scan
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Download all scan artifacts
        uses: actions/download-artifact@v4
        with:
          path: fleet-results/
          merge-multiple: true

      - name: Install mcp-audit
        run: pip install mcp-audit

      - name: Merge fleet report
        run: |
          mcp-audit merge --dir ./fleet-results/ \
            --format json \
            --output-file fleet-report.json

      - name: Upload fleet report
        uses: actions/upload-artifact@v4
        with:
          name: fleet-report
          path: fleet-report.json
```

---

## Output formats

| Format     | Command flag         | Description                                                         |
|------------|----------------------|---------------------------------------------------------------------|
| `terminal` | (default)            | Rich tables: Fleet Summary panel + finding table                    |
| `json`     | `--format json`      | Full `FleetReport` as JSON; pipeable                                |
| `html`     | `--format html`      | Self-contained D3 fleet dashboard; open in any browser with no CDN  |

### HTML fleet dashboard

`--format html` produces a fully self-contained, offline-capable HTML file
with no CDN dependencies (D3 v7 is bundled inline). Open it in any browser:

```bash
mcp-audit merge --dir ./fleet-results/ --format html -o fleet-report.html
open fleet-report.html   # macOS
```

The dashboard includes:

- **Header** — fleet-level grade badge (worst-case machine grade), total
  machines, total findings, Crit+High count, average score, and generation
  timestamp.
- **Fleet Summary grid** — one card per machine showing hostname, grade badge
  (A–F colour-coded), finding count by severity, and a mini severity
  distribution bar.  Click a card to filter the findings table to that machine.
- **Filterable findings table** — deduplicated findings sorted by severity
  (most critical first).  Filter by severity (pill buttons), machine (dropdown),
  or analyzer (dropdown).  Click column headers to sort ascending/descending.
- **Light/dark mode toggle** — matches the per-scan dashboard aesthetic.

#### Grade colour coding

| Grade | Colour  | Meaning                    |
|-------|---------|----------------------------|
| A     | Green   | 90–100 / minimal risk      |
| B     | Blue    | 80–89 / low risk           |
| C     | Yellow  | 70–79 / moderate risk      |
| D     | Orange  | 50–69 / elevated risk      |
| F     | Red     | < 50 / critical risk       |

The **fleet grade** shown in the header is the worst grade across all machines
in the fleet (e.g., if one machine scores F, the fleet grade is F).

#### Offline use

The HTML file is entirely self-contained: all JavaScript (D3 v7), CSS, and scan
data are embedded inline.  It renders correctly with no network access and can
be emailed, archived, or attached to a ticket.

---

## FleetReport JSON schema (key fields)

```json
{
  "generated_at": "2026-04-16T10:00:00+00:00",
  "scanner_version": "0.1.0",
  "machine_count": 15,
  "machines": [
    {
      "machine_id": "prod-laptop-adam",
      "scanner_version": "0.1.0",
      "scan_timestamp": "2026-04-16T09:45:00+00:00",
      "server_count": 4,
      "score": { "numeric_score": 72, "grade": "C", ... },
      "findings": [ ... ],
      "source_file": "/results/prod-laptop-adam.json"
    }
  ],
  "deduplicated_findings": [
    {
      "finding_id": "a1b2c3d4e5f60001",
      "analyzer": "credentials",
      "server_name": "filesystem",
      "severity": "HIGH",
      "title": "Hardcoded API key",
      "affected_machines": ["prod-laptop-adam", "prod-laptop-jane"],
      "affected_count": 2,
      "first_seen": "2026-04-15T08:00:00+00:00"
    }
  ],
  "stats": {
    "total_machines": 15,
    "total_findings": 47,
    "unique_findings": 12,
    "most_common_finding": "Hardcoded API key",
    "riskiest_machine": "prod-laptop-adam",
    "severity_breakdown": { "CRITICAL": 2, "HIGH": 8, "MEDIUM": 15, "LOW": 22, "INFO": 0 },
    "average_score": 68.3,
    "lowest_score_machine": "prod-laptop-dave"
  },
  "version_mismatches": []
}
```

---

## Known limitations

See [GAPS.md](../GAPS.md#fleet-merge) for a full list. Key points:

- `--dir` recurses into all subdirectories automatically; no depth limit.
- The fleet HTML dashboard shows deduplicated findings; per-machine raw finding
  lists are available in the JSON output only.
- No cross-machine attack path graph — fleet-level attack path analysis is not
  yet implemented (requires a fleet-wide attack path engine).
- Deduplication requires an exact `(analyzer, server_name, title)` match;
  findings with different evidence strings are not collapsed.
- `asset_prefix` is not stored in scan JSON; prefix filtering applies to
  machine hostname.
