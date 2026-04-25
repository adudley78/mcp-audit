# OWASP MCP Top 10

mcp-audit maps every finding to the
[OWASP MCP Top 10 (2025 beta)](https://owasp.org/www-project-mcp-top-10/) —
a risk framework specific to the Model Context Protocol. This is parallel to,
and independent of, the [OWASP Agentic Top 10](https://genai.owasp.org/)
(ASI01–ASI10) mapping that already appears in `docs/severity-framework.md`.

## Why both frameworks?

| Framework | Scope | Codes |
|-----------|-------|-------|
| OWASP Agentic Top 10 | Agentic AI systems broadly | ASI01–ASI10 |
| OWASP MCP Top 10 | MCP protocol specifically | MCP01–MCP10 |

The MCP Top 10 is becoming the lingua franca for MCP security research, blog
posts, and CI integrations. Mapping to it makes mcp-audit findings immediately
recognisable to practitioners already familiar with the framework.

## Categories

| Code   | Risk category |
|--------|---------------|
| MCP01  | Token Mismanagement and Secret Exposure |
| MCP02  | Privilege Escalation via Scope Creep |
| MCP03  | Tool Poisoning |
| MCP04  | Software Supply Chain Attacks |
| MCP05  | Command Injection and Execution |
| MCP06  | Intent Flow Subversion |
| MCP07  | Insufficient Authentication and Authorization |
| MCP08  | Lack of Audit and Telemetry |
| MCP09  | Shadow MCP Servers |
| MCP10  | Context Injection and Over-sharing |

## Where the mapping appears

### Terminal output

When a finding maps to one or more MCP Top 10 categories, the codes are
shown inline next to the finding title in dim cyan:

```
HIGH  POISON-010  [MCP03, MCP06]  XML instruction injection in description
```

Findings with no mapping (e.g. informational positive-signal findings) show
no badge.

### JSON output

The `owasp_mcp_top_10` field is present on every finding in the JSON output.
Empty list means the finding has not been categorised yet.

```json
{
  "id": "POISON-010",
  "severity": "HIGH",
  "owasp_mcp_top_10": ["MCP03", "MCP06"],
  ...
}
```

### SARIF output

The SARIF output uses SARIF 2.1.0's first-class taxonomy mechanism:

- `runs[0].taxonomies` contains an `OWASP-MCP-Top-10` `toolComponent` with
  all ten taxa.
- Each rule's `relationships` array references the applicable taxa by code.
- Each rule's `properties["owasp-mcp-top-10"]` mirrors the codes for
  consumers that don't support the taxonomy mechanism.

```json
{
  "runs": [{
    "taxonomies": [{
      "name": "OWASP-MCP-Top-10",
      "guid": "f1a3c4d5-9e6b-4a7d-8b2c-1f9e0a3d5c7e",
      "taxa": [
        {"id": "MCP01", "name": "Token Mismanagement and Secret Exposure"},
        ...
      ]
    }],
    "tool": {
      "driver": {
        "rules": [{
          "id": "POISON-010",
          "relationships": [
            {"target": {"id": "MCP03", "toolComponent": {"name": "OWASP-MCP-Top-10"}}, "kinds": ["relevant"]},
            {"target": {"id": "MCP06", "toolComponent": {"name": "OWASP-MCP-Top-10"}}, "kinds": ["relevant"]}
          ],
          "properties": {"owasp-mcp-top-10": ["MCP03", "MCP06"]}
        }]
      }
    }
  }]
}
```

The taxonomy GUID `f1a3c4d5-9e6b-4a7d-8b2c-1f9e0a3d5c7e` is stable and
mcp-audit-issued. Do not change it — downstream SARIF consumers may cache
the taxonomy by GUID.

## `--owasp-report` flag

`mcp-audit scan --owasp-report` appends an aggregated category-level summary
after the normal scan output:

```
OWASP MCP Top 10 — coverage in this scan
─────────────────────────────────────────
MCP01 Token Mismanagement and Secret Exposure         3 findings (1 HIGH, 2 MEDIUM)
MCP03 Tool Poisoning                                  7 findings (2 CRITICAL, 5 HIGH)
MCP04 Software Supply Chain Attacks                   1 finding  (1 LOW)
MCP05 Command Injection and Execution                 2 findings (2 HIGH)
─────────────────────────────────────────
4 of 10 categories triggered.
```

The report is suppressed if no findings carry any OWASP MCP codes (i.e. the
scan produced only unmapped findings). The flag does not affect exit codes,
severity thresholds, or the numeric score.

## Community rules and governance

Community rules (`rules/community/*.yml`) carry an `owasp_mcp_top_10:` field
in their YAML metadata. Custom governance policies (`governance/`) expose the
same field in the policy YAML — codes set there are propagated to all findings
emitted by that policy.

## Finding-level mapping

The full per-finding-ID mapping table (with both OWASP Agentic Top 10 and
OWASP MCP Top 10 columns) lives in `docs/severity-framework.md`.

## Implementation notes

- Single source of truth for codes and names: `src/mcp_audit/owasp_mcp.py`.
- `Finding.owasp_mcp_top_10` is a `list[str]` with `default_factory=list`.
  Empty list = not yet categorised, not an error.
- Semgrep SAST findings inherit codes from `metadata.owasp-mcp-top-10` in
  each rule's YAML.
- The framework version constant (`OWASP_MCP_TOP_10_VERSION = "2025-beta"`)
  lives in `owasp_mcp.py`. Bump it when OWASP publishes a stable v1.0 and
  re-verify that no category codes or names have shifted.

## Beta status

The OWASP MCP Top 10 is in beta as of April 2026. Category rankings and
descriptions may shift before the stable release. mcp-audit treats the
[project page](https://owasp.org/www-project-mcp-top-10/) as authoritative
and will update codes, names, and mappings when a stable version ships.
