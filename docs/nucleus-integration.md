# Nucleus Security Integration

mcp-audit has native integration with [Nucleus Security](https://nucleussec.com/) via the FlexConnect universal ingestion API. After a scan, findings are pushed directly into a Nucleus project where they appear as assets and vulnerabilities — no manual file uploads required.

> **Validated 2026-04-23** against `nucleus-demo.nucleussec.com`. The FlexConnect shape, multipart/form-data upload, and job polling have all been confirmed against the live API.

---

## Prerequisites

- **mcp-audit** installed (see [README](../README.md) — no license required; `push-nucleus` is available to all users).
- **Nucleus API key** — generate one in Nucleus under *Settings → API Keys*.
- **Project ID** — visible in the Nucleus project URL: `…/nucleus/ui/projects/{project_id}/findings`.

---

## Quick start

```bash
export NUCLEUS_API_KEY="your-api-key-here"

mcp-audit push-nucleus \
  --url https://your-nucleus-instance.nucleussec.com \
  --project-id 42
```

mcp-audit will:
1. Run a full scan of all detected MCP configurations on the machine
2. Format results as Nucleus FlexConnect JSON
3. Upload via multipart/form-data to `/nucleus/api/projects/{id}/scans`
4. Poll the import job until it completes (or times out)
5. Print a summary panel with job ID, finding count, and a direct link to your findings view

---

## All options

```
mcp-audit push-nucleus [OPTIONS]
```

| Flag | Type | Default | Description |
|---|---|---|---|
| `--url` | str | **required** | Nucleus instance base URL, e.g. `https://nucleus-demo.nucleussec.com` |
| `--project-id` | int | **required** | Target Nucleus project ID |
| `--api-key` | str | `NUCLEUS_API_KEY` env | API key (flag takes precedence over env var) |
| `--asset-prefix` | str | machine hostname | Override the asset identifier in Nucleus. Use an asset tag or employee ID when hostnames are not meaningful (e.g. `"MacBookAir"`). |
| `--config-paths` | path | auto-discover | Limit the scan to specific config files. Repeatable. |
| `--severity-threshold` | level | `INFO` (all) | Filter findings before pushing. `HIGH` pushes only HIGH and CRITICAL. |
| `--timeout` | int | 120 s | Maximum seconds to poll the import job before giving up (exit 2). |
| `--output-file` | path | — | Also write the FlexConnect JSON to disk — useful for debugging or audit trails. |

---

## Examples

**Push with an explicit asset tag:**

```bash
mcp-audit push-nucleus \
  --url https://nucleus.corp.example.com \
  --project-id 7 \
  --asset-prefix "LAPTOP-$(id -un)" \
  --api-key "$NUCLEUS_API_KEY"
```

**Push only HIGH and CRITICAL findings and keep a local copy:**

```bash
mcp-audit push-nucleus \
  --url https://nucleus.corp.example.com \
  --project-id 7 \
  --severity-threshold HIGH \
  --output-file /tmp/mcp-audit-pushed.json
```

**Scan a specific config file only:**

```bash
mcp-audit push-nucleus \
  --url https://nucleus.corp.example.com \
  --project-id 7 \
  --config-paths ~/.cursor/mcp.json
```

---

## API key

The API key is resolved in this order:

1. `--api-key` flag
2. `NUCLEUS_API_KEY` environment variable

If neither is set, the command exits with code 2 and a clear error message.

For automated deployments, set `NUCLEUS_API_KEY` in your CI/CD secrets or endpoint management tooling rather than passing it as a CLI flag.

---

## FlexConnect JSON format

The pushed document conforms to the Nucleus FlexConnect schema (validated 2026-04-23):

```json
{
  "nucleus_import_version": "1",
  "scan_tool": "mcp-audit",
  "scan_type": "Host",
  "scan_date": "2026-04-23 14:30:00",
  "assets": [
    {
      "host_name": "LAPTOP-alice",
      "operating_system_name": "Darwin"
    }
  ],
  "findings": [
    {
      "host_name": "LAPTOP-alice",
      "finding_number": "POISON-001",
      "finding_name": "Tool description poisoning: SSH key exfiltration",
      "finding_severity": "Critical",
      "finding_description": "...",
      "finding_solution": "...",
      "finding_output": "...",
      "finding_path": "~/.config/claude/claude_desktop_config.json",
      "finding_result": "Fail",
      "finding_type": "Vulnerability",
      "finding_cve": "CWE-94"
    }
  ]
}
```

Use `--output-file` to capture the exact JSON that was pushed.

---

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Import job completed successfully (`DONE`) |
| 1 | Nucleus import job ended in `ERROR` or `DESCHEDULED` |
| 2 | Configuration error (missing key, bad path) or network/timeout error |

---

## Fleet deployment

For fleet-wide use, run `push-nucleus` on each developer machine via your endpoint management tooling:

**Ansible example:**
```yaml
- name: Push mcp-audit scan to Nucleus
  ansible.builtin.command:
    cmd: >
      mcp-audit push-nucleus
      --url {{ nucleus_url }}
      --project-id {{ nucleus_project_id }}
      --asset-prefix "{{ inventory_hostname }}"
      --severity-threshold HIGH
  environment:
    NUCLEUS_API_KEY: "{{ vault_nucleus_api_key }}"
  register: mcp_audit_result
  failed_when: mcp_audit_result.rc not in [0, 1]
```

Exit code 1 means findings exist (not a tool failure) — adjust `failed_when` to match your alerting policy.

**Cron (macOS/Linux):**
```bash
# /etc/cron.d/mcp-audit or launchd plist
0 9 * * * /usr/local/bin/mcp-audit push-nucleus \
  --url https://nucleus.corp.example.com \
  --project-id 7 \
  --asset-prefix "$(hostname)" \
  --severity-threshold HIGH \
  >> /var/log/mcp-audit.log 2>&1
```

See [enterprise-deployment.md](enterprise-deployment.md) for a complete fleet deployment guide including license distribution, scheduling across platforms, and Nucleus project organisation.

---

## Differences from `scan --format nucleus`

`scan --format nucleus` writes FlexConnect JSON to stdout or `--output-file` only — you still need to upload it manually. `push-nucleus` combines the scan, format, upload, and job polling into a single command:

| | `scan --format nucleus` | `push-nucleus` |
|---|---|---|
| Produces FlexConnect JSON | ✓ | ✓ |
| Uploads to Nucleus automatically | — | ✓ |
| Polls import job to completion | — | ✓ |
| Suitable for CI / scheduled runs | Manual curl step needed | Single command |
