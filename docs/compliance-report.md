# Compliance Report

`mcp-audit check --report pdf` produces a PDF compliance artifact that a CISO can hand to an auditor — one command, one file, no interpretation required.

## Quick start

```bash
# Scan and write report to cwd
mcp-audit check --report pdf

# Specify output path and organisation name
mcp-audit check --report pdf --output-file /tmp/acme-mcp-audit.pdf --org "Acme Corp"

# Scan a specific config file
mcp-audit check --report pdf --path ~/Library/Application\ Support/Claude/claude_desktop_config.json --org "IBM Security"
```

The `scan` command also accepts `--report pdf`:

```bash
mcp-audit scan --report pdf --output-file report.pdf --org "Contoso"
```

## What the report contains

| Section | Content |
|---|---|
| **Header** | Organisation name, scan timestamp (ISO 8601 UTC), mcp-audit version |
| **Executive Summary** | Letter grade (colour-coded), numeric score (0–100), one-line verdict, finding counts by severity |
| **Findings Table** | All findings: severity, ID, title, server, OWASP MCP Top 10 category, plain-English remediation hint |
| **Footer** | mcp-audit credit and URL, page numbers, SHA-256 content hash (last page) |

## Grade colour coding

| Grade | Score | Colour |
|---|---|---|
| A | 90–100 | Green |
| B | 80–89 | Green |
| C | 70–79 | Amber |
| D | 60–69 | Red |
| F | 0–59 | Red |

## Organisation name resolution

The org name in the header is resolved in this order:

1. `--org "Name"` CLI flag
2. Registered organisation from `registration.json` (if you have run `mcp-audit register`)
3. `"Not specified"` (default)

## Output path

- Default: `mcp-audit-report-<YYYY-MM-DD>.pdf` in the current working directory
- Override with `--output-file PATH`; parent directories are created automatically

## SHA-256 content hash

The footer on the last page prints:

```
Content hash: sha256:<hex>
```

This hash is computed over the JSON-serialised `ScanResult` — not the PDF binary — so it is reproducible without the PDF itself. An auditor can verify it by:

1. Re-running the scan against the same configuration
2. Exporting JSON: `mcp-audit check --json > scan.json`
3. Computing `sha256(scan.json content)` and comparing

The hash proves the scan data has not been altered since the report was generated. It is not a cryptographic signature (signing is a future story requiring a key management solution).

## How auditors should interpret the report

- **Grade A or B** (score ≥ 80): The AI agent infrastructure meets baseline security hygiene. No immediate action required.
- **Grade C** (score 70–79): Minor issues present. Review the findings table and address MEDIUM and above within your next sprint.
- **Grade D or F** (score < 70, or any CRITICAL/HIGH): Remediation required before this configuration is used in production. Follow the remediation hints in the findings table.

The OWASP Category column maps each finding to the [OWASP MCP Top 10 (2025 beta)](https://owasp.org/www-project-mcp-top-10/), providing a standard risk taxonomy for GRC cross-referencing.

## Filing in a GRC system

The PDF is a self-contained audit artifact. When filing:

- Record the **scan timestamp** (ISO 8601, in the header) as the assessment date
- Record the **letter grade** and **numeric score** as the assessment result
- Attach the PDF and note the **SHA-256 content hash** for chain-of-custody purposes
- Re-run `mcp-audit check --report pdf` at each review cycle (quarterly recommended)

## Dependencies

`reportlab` (BSD licence, pure Python) is a required dependency added in v0.11.0. It is installed automatically with `pip install mcp-audit-scanner` and is bundled in the PyInstaller binary — no additional setup is needed.
