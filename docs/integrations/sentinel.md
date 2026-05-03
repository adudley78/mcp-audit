# Microsoft Sentinel Ingestion — mcp-audit snapshot

Ingest `mcp-audit snapshot --stream` output into Microsoft Sentinel via the
Logs Ingestion API (DCR-based) or the legacy Data Collector API.

---

## Option 1 — Logs Ingestion API (recommended, Azure Monitor DCR)

The [Logs Ingestion API](https://learn.microsoft.com/azure/azure-monitor/logs/logs-ingestion-api-overview)
is the modern path for custom log tables in Sentinel.

### 1. Create a DCE + DCR

In the Azure portal:
1. Create a **Data Collection Endpoint** (DCE) in your workspace region.
2. Create a **Data Collection Rule** (DCR) targeting a custom table
   `MCP_Audit_CL` in your Log Analytics workspace.
3. Configure the DCR's stream with the mcp-audit JSON schema (key fields:
   `id`, `severity`, `server`, `analyzer`, `title`, `host_id`, `timestamp`).
4. Grant the service principal or managed identity **Monitoring Metrics Publisher**
   on the DCR.

### 2. Push findings

```python
#!/usr/bin/env python3
"""Push mcp-audit snapshot stream to Sentinel Logs Ingestion API."""
import json
import subprocess
import sys
from azure.monitor.ingestion import LogsIngestionClient
from azure.identity import DefaultAzureCredential

DCE_ENDPOINT = "https://<dce-name>.<region>.ingest.monitor.azure.com"
DCR_IMMUTABLE_ID = "dcr-<id>"
STREAM_NAME = "Custom-MCP_Audit_CL"

client = LogsIngestionClient(
    endpoint=DCE_ENDPOINT,
    credential=DefaultAzureCredential(),
)

proc = subprocess.Popen(
    ["mcp-audit", "snapshot", "--stream"],
    stdout=subprocess.PIPE,
    text=True,
)

batch: list[dict] = []
for line in proc.stdout:
    line = line.strip()
    if line:
        batch.append(json.loads(line))
    if len(batch) >= 100:
        client.upload(DCR_IMMUTABLE_ID, STREAM_NAME, batch)
        batch.clear()

if batch:
    client.upload(DCR_IMMUTABLE_ID, STREAM_NAME, batch)

print(f"Ingested to Sentinel: {STREAM_NAME}", file=sys.stderr)
```

Install dependencies:
```bash
pip install azure-monitor-ingestion azure-identity
```

### 3. Sentinel analytic rule (KQL)

Detect new CRITICAL findings:
```kql
MCP_Audit_CL
| where severity_s == "CRITICAL"
| where TimeGenerated > ago(1h)
| project TimeGenerated, host_id_s, server_s, title_s, remediation_s, owasp_mcp_top_10_s
| order by TimeGenerated desc
```

---

## Option 2 — Legacy HTTP Data Collector API

For workspaces not yet on DCR, use the legacy Data Collector API:

```bash
#!/usr/bin/env bash
# Push mcp-audit findings to Sentinel via HTTP Data Collector API.
set -euo pipefail

WORKSPACE_ID="<your-workspace-id>"
SHARED_KEY="<your-primary-key>"
LOG_TYPE="McpAuditFindings"

BODY=$(mcp-audit snapshot --stream | jq -sc '.')
CONTENT_LENGTH=${#BODY}
DATE=$(date -u +"%a, %d %b %Y %H:%M:%S GMT")
STRING_TO_SIGN="POST\n${CONTENT_LENGTH}\napplication/json\nx-ms-date:${DATE}\n/api/logs"
SIGNATURE=$(printf '%s' "$STRING_TO_SIGN" \
  | openssl dgst -sha256 -hmac "$(printf '%s' "$SHARED_KEY" | base64 -d)" -binary \
  | base64)

curl -s -X POST \
  "https://${WORKSPACE_ID}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01" \
  -H "Authorization: SharedKey ${WORKSPACE_ID}:${SIGNATURE}" \
  -H "Content-Type: application/json" \
  -H "Log-Type: ${LOG_TYPE}" \
  -H "x-ms-date: ${DATE}" \
  --data "$BODY"
```

The legacy API creates a `McpAuditFindings_CL` table automatically.

---

## Recommended table schema

| Column | Type | Source |
|---|---|---|
| `TimeGenerated` | datetime | Set to `timestamp` from stream |
| `host_id_s` | string | `host_id` |
| `server_s` | string | `server` |
| `severity_s` | string | `severity` |
| `analyzer_s` | string | `analyzer` |
| `id_s` | string | `id` (finding ID) |
| `title_s` | string | `title` |
| `remediation_s` | string | `remediation` |
| `owasp_mcp_top_10_s` | string | `owasp_mcp_top_10` (comma-sep) |
| `mcp_audit_version_s` | string | `mcp_audit_version` |

---

## Workbook / dashboard

Import the [Azure Monitor Workbook template](https://learn.microsoft.com/azure/azure-monitor/visualize/workbooks-overview)
to visualise MCP server risk over time.  Use KQL aggregations on
`MCP_Audit_CL` to drive a timeline chart of finding counts by severity.
