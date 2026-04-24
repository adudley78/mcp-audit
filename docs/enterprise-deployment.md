# Team / Fleet Deployment Guide

> **Validated 2026-04-23** — FlexConnect output and the `push-nucleus` upload
> path have been confirmed against a live Nucleus instance. The
> multipart/form-data upload, job polling, and JSON schema are all verified.
>
> **Note:** mcp-audit is fully open source (Apache 2.0). Every feature
> described below — the dashboard, FlexConnect output, `push-nucleus`, fleet
> merge, governance — is available to every user with no license key
> required. This guide is kept as "enterprise-deployment.md" for URL
> stability but applies to any team rolling out mcp-audit across multiple
> machines.

## Overview

mcp-audit is a CLI scanner that runs on individual developer machines to
discover and assess MCP server configurations. MCP servers give AI agents
(Claude, Cursor, VS Code Copilot) access to file systems, databases, and
external APIs. Misconfigured or compromised MCP servers are an endpoint-level
risk — they live on developer laptops, not in your data center.

For fleet-wide visibility:

1. Deploy mcp-audit to every developer machine.
2. Run it on a schedule (daily is sufficient for most teams).
3. Collect results into your vulnerability management platform.

Each scan result is tagged with the originating machine (`hostname`, `username`,
`os`, and a unique `scan_id`). When you use Nucleus FlexConnect output, each
machine's MCP servers appear as distinct assets, so findings can be triaged,
assigned, and tracked per-endpoint.

---

## Prerequisites

- **mcp-audit** binary or Python package installed on target machines
  (see Step 1).
- **A vulnerability management platform** for central aggregation. Nucleus
  Security is recommended — native FlexConnect ingestion is built in.
- **An orchestration method** for deployment and scheduling. Choose one:
  - MDM: Jamf (macOS), Microsoft Intune (Windows/macOS)
  - Configuration management: Ansible, Chef, Puppet
  - Direct SSH access (for smaller fleets)

---

## Step 1: Deploy the Scanner

Choose one installation method per your environment.

### Option A — Binary download (when available)

```bash
curl -sSL https://raw.githubusercontent.com/adudley78/mcp-audit/main/scripts/install.sh | sh
```

### Option D — Standalone binary (no Python required)

Download the pre-built binary for your platform from the GitHub Releases page:

```bash
# macOS (Apple Silicon)
curl -sSL https://github.com/adudley78/mcp-audit/releases/latest/download/mcp-audit-darwin-arm64 \
  -o /usr/local/bin/mcp-audit && chmod +x /usr/local/bin/mcp-audit

# macOS (Intel)
curl -sSL https://github.com/adudley78/mcp-audit/releases/latest/download/mcp-audit-darwin-x86_64 \
  -o /usr/local/bin/mcp-audit && chmod +x /usr/local/bin/mcp-audit

# Linux (x86_64)
curl -sSL https://github.com/adudley78/mcp-audit/releases/latest/download/mcp-audit-linux-x86_64 \
  -o /usr/local/bin/mcp-audit && chmod +x /usr/local/bin/mcp-audit
```

No Python installation required. The binary bundles the Python runtime and all dependencies.

### Option B — Python package (when published to PyPI)

```bash
pip install mcp-audit
```

Pin to a specific version in production:

```bash
pip install mcp-audit==0.1.0
```

### Option C — Source install (current method for internal alpha)

```bash
git clone https://github.com/adudley78/mcp-audit.git /opt/mcp-audit
cd /opt/mcp-audit
uv tool install -e ".[mcp]"
```

Verify the install on any machine:

```bash
mcp-audit version
```

---

## Step 2: Run a Scan

The standard fleet command:

```bash
mcp-audit scan \
  --format nucleus \
  --asset-prefix "$(hostname)" \
  -o /tmp/mcp-audit-results.json
```

**Flag reference:**

| Flag | Purpose |
|------|---------|
| `--format nucleus` | Emit Nucleus FlexConnect JSON (for upload to Nucleus or batch ingestion). |
| `--asset-prefix "$(hostname)"` | Tag every finding's asset name with the machine identity. Nucleus uses this to group assets per endpoint. Replace `$(hostname)` with an asset tag or employee ID when hostnames are not meaningful (e.g., `--asset-prefix "ASSET-1042"`). |
| `-o /path/to/file.json` | Write results to a file instead of stdout. Required for automated collection. |
| `--severity-threshold HIGH` | Optional. Only report HIGH and CRITICAL findings. Reduces noise in initial rollouts. |
| `--connect` | Optional. Attempt live MCP protocol connections to enumerate server tools at runtime. Adds latency (5–30 s per server). Not recommended for scheduled scans unless you need runtime poisoning detection. |
| `--offline` | Ensure zero network calls. Use this if your endpoints have no internet access or if you want fully deterministic output. |

**Example with asset tag and severity filter:**

```bash
mcp-audit scan \
  --format nucleus \
  --asset-prefix "ASSET-1042" \
  --severity-threshold HIGH \
  --offline \
  -o /tmp/mcp-audit-results.json
```

---

## Step 3: Collect Results

Choose a collection method that fits your infrastructure.

### Option A — Direct push with `push-nucleus`

The simplest integration: `push-nucleus` runs the scan, uploads, and polls
the import job in a single command — no manual curl required.

```bash
export NUCLEUS_API_KEY="$NUCLEUS_API_KEY"

mcp-audit push-nucleus \
  --url https://<your-nucleus-url> \
  --project-id 7 \
  --asset-prefix "$(hostname)" \
  --severity-threshold HIGH
```

Replace `--url` and `--project-id` with your instance URL and project ID.
Use `--severity-threshold HIGH` in the initial rollout to reduce noise; drop
the flag once triage workflows are established.

**Exit code behaviour:** exit 0 = job succeeded; exit 1 = import job ERROR;
exit 2 = network / config error. Treat exit 1 as informational (findings exist),
not as a tool failure.

### Option B — File drop to shared storage

Write results to a shared location for batch ingestion:

```bash
# S3
aws s3 cp /tmp/mcp-audit-results.json \
  "s3://your-security-bucket/mcp-audit/$(hostname)/$(date +%Y%m%d).json"

# Network share
cp /tmp/mcp-audit-results.json \
  "/mnt/security/mcp-audit/$(hostname)/$(date +%Y%m%d).json"
```

Set up a scheduled ingestion job on the collection server to pull from the
shared location into Nucleus.

### Option C — Direct Nucleus connector

If a native mcp-audit connector is available in the Nucleus connector
marketplace, configure it to pull from your shared storage location. This
automates ingestion without a separate push script.

---

## Step 4: Schedule Recurring Scans

### macOS — launchd plist (daily at 09:00)

Save to `/Library/LaunchDaemons/com.mcpaudit.scan.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.mcpaudit.scan</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/mcp-audit</string>
    <string>scan</string>
    <string>--format</string>
    <string>nucleus</string>
    <string>--asset-prefix</string>
    <string>ASSET-1042</string>
    <string>--offline</string>
    <string>-o</string>
    <string>/tmp/mcp-audit-results.json</string>
  </array>
  <key>StartCalendarInterval</key>
  <dict>
    <key>Hour</key>
    <integer>9</integer>
    <key>Minute</key>
    <integer>0</integer>
  </dict>
  <key>StandardOutPath</key>
  <string>/var/log/mcp-audit.log</string>
  <key>StandardErrorPath</key>
  <string>/var/log/mcp-audit.log</string>
</dict>
</plist>
```

Load it:

```bash
sudo launchctl load /Library/LaunchDaemons/com.mcpaudit.scan.plist
```

### Linux — cron

Add to root crontab (`sudo crontab -e`):

```bash
# Option A — direct push (recommended; no file collection step needed)
0 9 * * * NUCLEUS_API_KEY=your-key /usr/local/bin/mcp-audit push-nucleus \
  --url https://<your-nucleus-url> --project-id 7 \
  --asset-prefix "$(hostname)" --severity-threshold HIGH \
  >> /var/log/mcp-audit.log 2>&1

# Option B — write to file for batch collection
0 9 * * * /usr/local/bin/mcp-audit scan --format nucleus --asset-prefix "$(hostname)" --offline -o /tmp/mcp-audit-results.json >> /var/log/mcp-audit.log 2>&1
```

### Windows — Task Scheduler

```powershell
$action = New-ScheduledTaskAction `
  -Execute "mcp-audit" `
  -Argument "scan --format nucleus --asset-prefix $env:COMPUTERNAME --offline -o C:\Temp\mcp-audit-results.json"

$trigger = New-ScheduledTaskTrigger -Daily -At 9am

Register-ScheduledTask `
  -TaskName "mcp-audit-daily" `
  -Action $action `
  -Trigger $trigger `
  -RunLevel Highest
```

### Jamf — Recurring policy

1. In Jamf Pro, create a new **Policy** → **Scripts**.
2. Upload a shell script containing the scan command and upload step (Option A or B above).
3. Set **Frequency** to **Once per day**.
4. Scope to the target computer group.

### Ansible — cron module

```yaml
- name: Schedule mcp-audit daily scan
  ansible.builtin.cron:
    name: mcp-audit-daily
    minute: "0"
    hour: "9"
    job: >
      /usr/local/bin/mcp-audit scan
      --format nucleus
      --asset-prefix "{{ ansible_hostname }}"
      --offline
      -o /tmp/mcp-audit-results.json
      >> /var/log/mcp-audit.log 2>&1
    user: root
```

---

## Step 5: Review Results in Nucleus

Once FlexConnect files are ingested:

- **Each machine appears as an asset.** The asset name is the value you passed
  to `--asset-prefix` (e.g., `ASSET-1042`) or the hostname.
- **Each MCP server appears as a sub-asset.** The format is
  `ASSET-1042/cursor/filesystem`, so you can filter by client (Cursor, Claude,
  VS Code) or by server name across the fleet.
- **Findings are deduplicated across scans** using `finding_number`. Re-running
  a scan on a clean machine updates the existing record rather than creating
  duplicates.
- **Severity mapping** aligns with Nucleus risk scoring:
  - `CRITICAL` → Critical
  - `HIGH` → High
  - `MEDIUM` → Medium
  - `LOW` → Low
  - `INFO` → Informational
- **Use Nucleus automation rules** to assign findings to the responsible
  developer (by username in the asset metadata), create Jira/ServiceNow
  tickets for HIGH+ findings, and set remediation SLA deadlines.

---

## Optional: Continuous Monitoring

For high-security environments, `mcp-audit watch` runs as a background daemon
that re-scans every time a config file changes. This catches supply-chain
compromises and tool-poisoning attacks within seconds of a config modification.

### macOS — launchd persistent service

Save to `/Library/LaunchDaemons/com.mcpaudit.watch.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.mcpaudit.watch</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/mcp-audit</string>
    <string>watch</string>
    <string>--format</string>
    <string>json</string>
  </array>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>/var/log/mcp-audit/events.json</string>
  <key>StandardErrorPath</key>
  <string>/var/log/mcp-audit/watch-error.log</string>
</dict>
</plist>
```

```bash
sudo launchctl load /Library/LaunchDaemons/com.mcpaudit.watch.plist
```

### Linux — systemd unit

Save to `/etc/systemd/system/mcp-audit-watch.service`:

```ini
[Unit]
Description=mcp-audit continuous config watcher
After=network.target

[Service]
ExecStart=/usr/local/bin/mcp-audit watch --format json
Restart=on-failure
RestartSec=5
StandardOutput=append:/var/log/mcp-audit/events.json
StandardError=append:/var/log/mcp-audit/watch-error.log

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now mcp-audit-watch
```

Log rotation: add `/var/log/mcp-audit/*.json` to your logrotate config with
`copytruncate` so the running process is not interrupted.

---

## Optional: CI/CD Integration

For repositories that contain project-level MCP configs (`.vscode/mcp.json`,
`.mcp.json`), add a scan step to your CI pipeline to catch poisoned configs
before they reach developer machines.

### GitHub Actions starter workflow

Save to `.github/workflows/mcp-audit.yml`:

```yaml
name: mcp-audit

on:
  push:
    paths:
      - "**/.vscode/mcp.json"
      - "**/.mcp.json"
      - "**/mcp.json"
  pull_request:
    paths:
      - "**/.vscode/mcp.json"
      - "**/.mcp.json"
      - "**/mcp.json"

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install mcp-audit
        run: pip install mcp-audit

      - name: Scan MCP configs
        run: |
          mcp-audit scan \
            --severity-threshold HIGH \
            --offline \
            --format sarif \
            -o mcp-audit.sarif
        # Exit code 1 = findings found; exit code 2 = scan error
        continue-on-error: true

      - name: Upload SARIF to GitHub Security tab
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: mcp-audit.sarif
        if: always()
```

SARIF output surfaces findings as Security tab alerts and pull-request
annotations. Set `--severity-threshold HIGH` to block only on HIGH/CRITICAL
findings; use `--severity-threshold MEDIUM` to catch more.

---

## Appendix: What the Scanner Checks

| Analyzer | What it detects |
|----------|----------------|
| **Poisoning** | Tool descriptions that contain data exfiltration commands, prompt injection markers, or instructions targeting SSH keys, cloud credentials, or `.env` files. |
| **Credentials** | API keys, tokens, passwords, and database connection strings hardcoded in server environment variables or command arguments. |
| **Transport** | Insecure transport configurations: HTTP (non-TLS) remote URLs, servers bound to all interfaces, and runtime package fetchers (`npx`, `uvx`) that download arbitrary code. |
| **Supply Chain** | Typosquatted package names detected via Levenshtein distance against the known-server registry. Packages with no version pin and known-malicious package names. |
| **Rug Pull** | Detects changes to server descriptions since the last pinned baseline — the mechanism used in supply-chain substitution attacks. |
| **Toxic Flow** | Multi-hop attack paths where a server with read capability (file system, database) is co-installed with a server with write/network capability, enabling data exfiltration chains. |
