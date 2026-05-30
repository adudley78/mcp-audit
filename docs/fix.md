# `mcp-audit fix` — Apply Safe Remediations to MCP Configs

`mcp-audit fix` closes the loop between scanning and remediation. It reads
findings from a scan, computes targeted changes to your MCP config files, shows
you a diff, and (optionally) writes the changes atomically with a backup.

---

## Quick start

```bash
# Dry run — shows a unified diff, no files touched
mcp-audit fix

# Apply to a specific config file
mcp-audit fix --path ~/.config/claude/claude_desktop_config.json

# Apply and write changes (creates a .bak backup first)
mcp-audit fix --apply

# Apply only credential fixes, skip others
mcp-audit fix --apply --fix-type credentials
```

---

## How it works

1. **Scan** — `fix` runs the full scan pipeline internally (or reads from
   `--input <scan.json>` to avoid re-scanning).
2. **Match** — Each finding is matched to a fix strategy based on its ID.
3. **Diff** — The proposed changes are serialised and shown as a unified diff.
4. **Write** (with `--apply`) — The original file is backed up to `<file>.bak`,
   then the new content is written atomically via a `.tmp` rename.

---

## Supported fix types

| Fix type      | Finding IDs        | What it does                                                  |
|---------------|--------------------|---------------------------------------------------------------|
| `credentials` | CRED-001, CRED-002 | Replaces plaintext secret values with `${ENV_VAR_NAME}`       |
| `transport`   | TRANSPORT-001      | Rewrites `http://` server URLs to `https://`                  |
| `pinning`     | SC-001, SC-002     | Replaces a typosquatted package name with the verified name and pins to `@latest-version` |

All three strategies are **idempotent** — re-running `fix` after `--apply`
produces no further diff.

---

## Options

| Flag | Description |
|------|-------------|
| `--path PATH` | Scan a **single config file** (not a directory — pass the `.json` path directly, e.g. `~/.config/claude/claude_desktop_config.json`). Omit to auto-discover all configs. |
| `--input FILE` | Read findings from an existing scan JSON file (skips fresh scan) |
| `--apply` | Write changes to disk (atomic rename + `.bak` backup) |
| `--fix-type TYPE` | Restrict to one fix type: `credentials`, `transport`, or `pinning`. Repeatable |
| `--offline` | Suppress all network calls; version resolution for SC-001/002 is skipped with a warning |

---

## Fix type details

### Credentials (`CRED-001`, `CRED-002`)

The credentials analyzer emits CRED-001 when a secret is found in a server's
`env` dict, and CRED-002 when it appears in `args`.

**What `fix` does:**

- **CRED-001** — replaces the secret value with `${KEY_NAME}` where `KEY_NAME`
  is the environment variable key. The key is preserved so the config is still
  structurally valid. You must export the real secret in your shell or process
  manager separately.
- **CRED-002** — applies a regex substitution on the matching arg token,
  replacing the matched secret substring with `${REDACTED_SECRET}`.

**Before:**
```json
"env": {
  "GITHUB_TOKEN": "ghp_abc123..."
}
```

**After:**
```json
"env": {
  "GITHUB_TOKEN": "${GITHUB_TOKEN}"
}
```

> **Note:** After running `fix --apply`, export the real token in your environment:
> ```bash
> export GITHUB_TOKEN=ghp_abc123...
> ```
> Many MCP clients (Claude Desktop, Cursor) expand `${VAR}` references from the
> process environment when launching servers.

---

### Transport (`TRANSPORT-001`)

TRANSPORT-001 fires when a server URL uses `http://` to a non-localhost
remote host.

**What `fix` does:** replaces `http://` with `https://` in the `"url"` field.

**Before:**
```json
"url": "http://my-mcp-server:8080/sse"
```

**After:**
```json
"url": "https://my-mcp-server:8080/sse"
```

> **Note:** Ensure the target server actually has a valid TLS certificate
> before applying this fix. If the server is self-hosted and uses a
> self-signed certificate, you may need additional client configuration.

---

### Package pinning (`SC-001`, `SC-002`)

SC-001 and SC-002 fire when a package name in `npx` or `uvx` args is
suspiciously close to a known-legitimate MCP package (typosquatting).

**What `fix` does:**

1. Extracts the verified package name from the finding evidence (the closest
   match in the known-server registry).
2. Resolves the latest published version from npm (for `npx`) or PyPI (for `uvx`).
3. Replaces the typosquatted package token in `args` with
   `verified-package@version`.

**Before:**
```json
"command": "npx",
"args": ["@modelcontextprotocol/server-filesytem"]
```

**After:**
```json
"command": "npx",
"args": ["@modelcontextprotocol/server-filesystem@1.2.3"]
```

**Registry safety signal:** if the replacement package is not in the
mcp-audit known-server registry, a warning is printed but the fix proceeds:

```
⚠  Warning: 'some-package' is not in the mcp-audit known-server registry.
   Pinning to latest version anyway — verify this package is legitimate
   before committing.
```

When `--offline` is active or the npm/PyPI registry is unreachable, the
pinning fix is skipped with a warning and other fix types still apply.

---

## Using with an existing scan output

If you already ran `mcp-audit scan --format json --output scan.json`, you can
pass that file directly to skip re-scanning:

```bash
mcp-audit fix --input scan.json
mcp-audit fix --input scan.json --apply
```

The config file path is resolved from the `servers[0].config_path` field in
the scan JSON. If your scan covered multiple config files, run `fix` separately
for each file using `--path`.

---

## Atomic write and backup

When `--apply` is passed:

1. The original config is written verbatim to `<config-file>.bak`.
2. The new content is written to `<config-file>.tmp`.
3. `<config-file>.tmp` is atomically renamed to `<config-file>`.

To manually revert a fix:

```bash
cp ~/.config/claude/claude_desktop_config.json.bak \
   ~/.config/claude/claude_desktop_config.json
```

---

## Exit codes

| Code | Meaning |
|------|---------|
| `0`  | Success (dry run shown, or changes applied), or no fixable findings |
| `2`  | Error: file not found, unreadable JSON, write permission denied, etc. |

---

## CI usage

Add `mcp-audit fix` as an auto-remediation step after a failing scan gate:

```yaml
- name: Scan MCP configs
  uses: adudley78/mcp-audit@v0.11.0
  with:
    severity-threshold: high
    fail-on-findings: 'true'

- name: Auto-fix credential and transport findings
  if: failure()
  run: |
    mcp-audit fix --apply --fix-type credentials --fix-type transport
    git diff --exit-code || (git add -A && git commit -m "chore: mcp-audit auto-fix")
```

---

## Out of scope (MVP)

The following are intentionally not handled by `fix` in v0.11.0:

- SAST source-code fixes (modifying MCP server source files, not configs)
- Rug-pull state resets
- Governance policy auto-patching (use `mcp-audit killchain --patch yaml`)
- Interactive mode / per-finding prompts
- `--revert` flag (use the `.bak` file)
