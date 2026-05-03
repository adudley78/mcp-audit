# `mcp-audit snapshot` — Forensic Snapshot Export

Time-stamped, sigstore-signed forensic exports of every MCP server on a host.
CycloneDX 1.5 AI/ML-BOM by default; mcp-audit-native JSON optional.
SIEM/EDR-ready via `--stream` mode.

---

## What it does

`mcp-audit snapshot` runs the full analysis pipeline (or loads a previous scan
result) and emits a single self-contained JSON document capturing:

- **Timestamp** (ISO 8601 UTC) and host identifier
- **MCP server inventory** — name, transport, client, capabilities, credential references
- **Security findings** — all analyzers, OWASP MCP Top 10 mappings, CWE numbers
- **Attack-path summary** — multi-hop paths, minimum hitting set
- **Scan score** — numeric (0–100) and letter grade (A–F)

Optional sigstore signing (`--sign`) produces a `.snapshot.json.sig` bundle that
verifies with `sigstore verify`.

---

## Quick start

```bash
# Generate CycloneDX snapshot (default)
mcp-audit snapshot --output snapshot.json

# Generate native JSON snapshot
mcp-audit snapshot --format native --output snapshot.native.json

# Stream one finding per line to a SIEM forwarder
mcp-audit snapshot --stream | vector --config /etc/vector/mcp.toml

# Sign with sigstore (requires ambient OIDC — e.g. GitHub Actions id-token)
mcp-audit snapshot --output snapshot.json --sign

# Load a previous scan result instead of re-running discovery
mcp-audit snapshot --input scan.json --output snapshot.json

# Rehydrate a saved snapshot to see the historical attack-path graph
mcp-audit snapshot --rehydrate old-snapshot.json
```

---

## Options

| Option | Default | Description |
|---|---|---|
| `--output / -o` | stdout | Destination file. Required for `--sign`. |
| `--format / -f` | `cyclonedx` | `cyclonedx` (CycloneDX 1.5 AI/ML-BOM) or `native` (mcp-audit JSON). |
| `--input / -i` | — | Use a previous `mcp-audit scan --output-file` JSON instead of running a new scan. |
| `--path / -p` | auto-discover | Restrict config discovery to this path. |
| `--sign` | off | Sign the snapshot with sigstore ambient OIDC identity. Requires `pip install 'mcp-audit-scanner[attestation]'`. |
| `--rehydrate` | — | Path to a saved snapshot. Reconstructs the historical attack-path graph. |
| `--stream` | off | Emit one JSON object per finding on stdout (NDJSON). Ignores `--format`. |

---

## CycloneDX output format

The default CycloneDX output conforms to [CycloneDX 1.5](https://cyclonedx.org/docs/1.5/).

### Top-level structure

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:<uuid>",
  "version": 1,
  "metadata": { ... },
  "components": [ ... ],
  "vulnerabilities": [ ... ]
}
```

### `metadata.timestamp`

ISO 8601 UTC timestamp of the snapshot (e.g. `"2026-05-03T12:34:56Z"`).

### `metadata.tools`

```json
[
  {
    "vendor": "mcp-audit",
    "name": "mcp-audit",
    "version": "0.8.0",
    "externalReferences": [
      { "type": "website", "url": "https://github.com/adudley78/mcp-audit" }
    ]
  }
]
```

### `metadata.properties`

| Property name | Description |
|---|---|
| `mcp-audit:host_id` | Hostname at snapshot time |
| `mcp-audit:scan_grade` | Letter grade (A–F) |
| `mcp-audit:scan_numeric_score` | Numeric score (0–100) |
| `mcp-audit:owasp_mcp_top_10_categories` | Comma-separated OWASP MCP codes that fired |
| `mcp-audit:finding_count` | Total findings |
| `mcp-audit:server_count` | Total MCP servers |

### Components (per server)

Each MCP server becomes a `component` of `type: application`:

```json
{
  "type": "application",
  "bom-ref": "mcp-server-filesystem",
  "name": "filesystem",
  "description": "MCP server: npx -y @modelcontextprotocol/server-filesystem /data",
  "properties": [
    { "name": "mcp-audit:capability_tags",  "value": "file_read" },
    { "name": "mcp-audit:transport",        "value": "stdio" },
    { "name": "mcp-audit:client",           "value": "claude_desktop" },
    { "name": "mcp-audit:finding_ids",      "value": "CRED-001,SUPPLY-003" },
    { "name": "mcp-audit:command",          "value": "npx -y @modelcontextprotocol/server-filesystem /data" }
  ]
}
```

The attack-path summary is appended as a synthetic `data` component named
`mcp-attack-surface` with per-path properties (`mcp-audit:attack_path:PATH-001`).

### Vulnerabilities (per finding)

Each finding becomes a `vulnerability` entry:

```json
{
  "bom-ref": "finding-CRED-001-filesystem",
  "id": "CRED-001",
  "source": { "name": "mcp-audit", "url": "https://github.com/adudley78/mcp-audit" },
  "ratings": [{ "source": { "name": "mcp-audit" }, "severity": "high", "method": "other" }],
  "cwes": [312],
  "description": "Exposed API key",
  "detail": "An API key was found in the server environment.",
  "recommendation": "Move the key to a secrets manager.",
  "affects": [{ "ref": "mcp-server-filesystem" }],
  "properties": [
    { "name": "mcp-audit:analyzer",           "value": "credentials" },
    { "name": "mcp-audit:evidence",           "value": "OPENAI_API_KEY=sk-..." },
    { "name": "mcp-audit:owasp_mcp_top_10",   "value": "MCP01" }
  ]
}
```

---

## Native JSON format

`--format native` wraps the existing `ScanResult` serialisation with the same
`metadata` block:

```json
{
  "format": "mcp-audit-native",
  "format_version": "1",
  "metadata": { "timestamp": "...", "tools": [...], "properties": [...] },
  "snapshot_data": { ... }  // full ScanResult JSON
}
```

`snapshot_data` is the identical shape produced by `mcp-audit scan --output-file`.

---

## Sigstore signing

```bash
# Requires sigstore optional dep and an ambient OIDC credential:
pip install 'mcp-audit-scanner[attestation]'
mcp-audit snapshot --output snapshot.json --sign
```

Produces `snapshot.json.sig` — a JSON wrapper containing:
- `sha256`: SHA-256 hex digest of `snapshot.json`
- `bundle`: Sigstore bundle JSON

Verify with:
```bash
sigstore verify artifact --bundle snapshot.json.sig snapshot.json
```

If no ambient OIDC credential is available (e.g. non-CI environment without
Workload Identity), `--sign` exits 2 with a clear error.  The unsigned snapshot
is still written to `--output`.

---

## `--rehydrate` — historical attack-path reconstruction

Incident response often requires answering "what attack paths were possible at
the time the alert fired?"  `--rehydrate` does this by loading a saved snapshot
and re-running `summarize_attack_paths` against the recorded servers and
findings — without touching the live filesystem.

```bash
mcp-audit snapshot --rehydrate old-snapshot.json
```

Output includes:
- Snapshot timestamp and host
- Reconstructed attack-path graph
- Delta vs the current live state ("2 servers added, 1 removed since …")

---

## `--stream` — NDJSON for SIEM/EDR

`--stream` emits one JSON object per finding on stdout, with `timestamp` and
`host_id` injected:

```json
{"timestamp": "2026-05-03T12:34:56Z", "host_id": "workstation-1", "id": "CRED-001", "severity": "HIGH", ...}
{"timestamp": "2026-05-03T12:34:56Z", "host_id": "workstation-1", "id": "POISON-002", "severity": "CRITICAL", ...}
```

Suitable for piping into `vector`, Cribl, Fluentd, or a direct Splunk HEC or
Sentinel DCR forwarder.  See the integration recipes in
[docs/integrations/splunk.md](integrations/splunk.md) and
[docs/integrations/sentinel.md](integrations/sentinel.md).

---

## CI integration (GitHub Actions)

```yaml
- name: Snapshot MCP configs
  run: |
    mcp-audit snapshot \
      --output mcp-snapshot.json \
      --sign
  env:
    # GitHub Actions automatically provides ACTIONS_ID_TOKEN_REQUEST_URL and
    # ACTIONS_ID_TOKEN_REQUEST_TOKEN when id-token: write is set.
    ACTIONS_ID_TOKEN_REQUEST_URL: ${{ env.ACTIONS_ID_TOKEN_REQUEST_URL }}
    ACTIONS_ID_TOKEN_REQUEST_TOKEN: ${{ env.ACTIONS_ID_TOKEN_REQUEST_TOKEN }}

- uses: actions/upload-artifact@v4
  with:
    name: mcp-snapshot
    path: mcp-snapshot.json
```

Grant `id-token: write` permission to the job for sigstore signing.

---

## Edge cases

| Scenario | Behaviour |
|---|---|
| No MCP configs on host | Snapshot generated with `components: []`; metadata preserved |
| Corrupt `--rehydrate` snapshot | Exit 2 with the failing field name |
| `--sign` without network / credential | Exit 2; unsigned snapshot written to `--output` |
| `--sign` without `--output` | Exit 2 (cannot sign stdout) |
| `--stream` with no findings | Zero lines written; exit 0 |
