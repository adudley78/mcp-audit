# Splunk Ingestion — mcp-audit snapshot

Ingest `mcp-audit snapshot --stream` output into Splunk via HTTP Event Collector
(HEC) or a Universal Forwarder.

---

## Option 1 — Direct HEC pipe (simplest)

Requires `curl` and a Splunk HEC token.

```bash
mcp-audit snapshot --stream \
  | while IFS= read -r line; do
      curl -s -o /dev/null \
        -H "Authorization: Splunk $SPLUNK_HEC_TOKEN" \
        -H "Content-Type: application/json" \
        --data "{\"event\": $line, \"sourcetype\": \"mcp-audit\"}" \
        "$SPLUNK_HEC_URL/services/collector/event"
    done
```

Set `SPLUNK_HEC_URL` (e.g. `https://splunk.corp.example.com:8088`) and
`SPLUNK_HEC_TOKEN` in your environment or CI secrets.

---

## Option 2 — Write to file, pick up with Universal Forwarder

```bash
# Write NDJSON to a monitored file
mcp-audit snapshot --stream >> /var/log/mcp-audit/findings.ndjson

# Splunk inputs.conf — monitor the file
[monitor:///var/log/mcp-audit/findings.ndjson]
sourcetype = mcp-audit-findings
index = security
```

Configure the sourcetype's `LINE_BREAKER` as `([\r\n]+)` (default) since each
line is already one complete JSON event.

---

## Option 3 — Vector pipeline

[Vector](https://vector.dev) is a lightweight data pipeline that handles
backpressure and buffering for you.

```toml
# /etc/vector/mcp_audit.toml

[sources.mcp_audit_stdin]
type = "stdin"

[transforms.parse_mcp]
type = "remap"
inputs = ["mcp_audit_stdin"]
source = '''
. = parse_json!(.message)
.index = "security"
.source = "mcp-audit"
'''

[sinks.splunk_hec]
type = "splunk_hec_logs"
inputs = ["parse_mcp"]
endpoint = "https://splunk.corp.example.com:8088"
token = "${SPLUNK_HEC_TOKEN}"
index = "security"
sourcetype = "mcp-audit"
```

Run:
```bash
mcp-audit snapshot --stream | vector --config /etc/vector/mcp_audit.toml
```

---

## Splunk search examples

Find all CRITICAL findings from the last 24 hours:
```spl
index=security sourcetype="mcp-audit" severity="CRITICAL"
| table _time host_id server title remediation
```

Track score over time:
```spl
index=security sourcetype="mcp-audit-findings"
| stats latest(mcp_audit_version) AS version, avg(eval(if(severity="CRITICAL",1,0))) AS critical_rate BY host_id
```

---

## Recommended index

Create a `security` index (or `mcp_audit`) with a 90-day retention policy.
Use the `mcp-audit` sourcetype to take advantage of automatic JSON key
extraction in Splunk 8+.
