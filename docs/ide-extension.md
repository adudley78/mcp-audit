# IDE Extension — VS Code / Cursor

mcp-audit ships a companion VS Code extension (`mcp-audit-vscode`) that surfaces
scan results as inline diagnostics — the same red/yellow squiggles developers
already know from ESLint and Pyright.

**Extension repo:** [mcp-audit/mcp-audit-vscode](https://github.com/mcp-audit/mcp-audit-vscode)

---

## Install

1. **Install the mcp-audit binary** (the extension shells out to it — it does
   not bundle it):

   ```bash
   pip install mcp-audit
   # or download a standalone binary from the Releases page
   ```

2. **Install the VS Code extension** from the Marketplace:

   ```
   ext install mcp-audit.mcp-audit-vscode
   ```

   Or via the command palette: `Extensions: Install from VSIX…` for a
   locally-built `.vsix` file.

3. Open any MCP config file — diagnostics appear automatically.

---

## Cursor

Cursor is a VS Code fork. The extension works without modification — install
from the VS Code Marketplace or via `Extensions: Install from VSIX…` in Cursor.
The Cursor Marketplace submission is tracked separately (see STORY-0042).

---

## What you see

| Feature | Behaviour |
|---|---|
| **Squiggles** | Red (CRITICAL/HIGH) or yellow (MEDIUM) underlines on the offending server key |
| **Hover card** | Finding title, severity, description, evidence, remediation, OWASP tags |
| **Status bar** | `mcp-audit: B (3 findings)` — click to open Problems panel |
| **Problems panel** | All findings listed with source `mcp-audit` and code (e.g. `CRED-001`) |

---

## Supported config files

| File | Client |
|---|---|
| `claude_desktop_config.json` | Claude Desktop |
| `mcp.json` | Cursor, generic |
| `.cursor/mcp.json` | Cursor (project) |
| `.claude/settings.json` | Claude Code |
| `claude_code_config.json` | Claude Code (alternate) |
| `mcp_config.json` | Generic MCP |

---

## Command palette

| Command | Action |
|---|---|
| `mcp-audit: Scan current file` | Manual re-scan of the active file |
| `mcp-audit: Scan workspace` | Scan all open MCP config files |
| `mcp-audit: Fix current file` | Run `mcp-audit fix --path <file>` (dry-run diff shown in Output channel) |

---

## Settings

| Setting | Default | Description |
|---|---|---|
| `mcp-audit.binaryPath` | `""` | Absolute path to the binary. Empty = auto-detect from PATH. |
| `mcp-audit.severityThreshold` | `"info"` | Minimum severity to show as a diagnostic. |
| `mcp-audit.runOnSave` | `true` | Re-scan on every save. |
| `mcp-audit.runOnOpen` | `true` | Scan when a config file is opened. |

---

## Architecture

The extension is a **thin wrapper** — it:

1. Detects MCP config files by name.
2. Spawns `mcp-audit scan --path <file> --format json` in a subprocess.
3. Parses the JSON output into `Finding[]`.
4. Uses `jsonc-parser` to locate each server key's line in the document.
5. Converts findings to `vscode.Diagnostic` objects.

No detection logic is reimplemented in TypeScript. The extension tech stack is:
TypeScript, VS Code Extension API, `esbuild` for bundling, `jsonc-parser` for
line resolution. Target engine: VS Code `>=1.85.0`.

See [ADR-0002](decisions/ADR-0002-extension-separate-repo.md) for the
architectural decision record on the separate-repo approach.

---

## Known limitations

- **Line precision:** Squiggles point to the server *key block*, not the exact
  offending line within it. A follow-up story (Finding.line_number) will add
  per-finding line numbers to the model and allow the extension to be precise.
- **Large files:** Files over 5 MB are skipped.
- **Scan timeout:** Scans that take more than 10 seconds are cancelled.

---

## Development

```bash
git clone https://github.com/mcp-audit/mcp-audit-vscode
cd mcp-audit-vscode
npm install
npm run build          # esbuild bundle → dist/extension.js
npm test               # VS Code test electron (needs display / Xvfb on Linux)
npx @vscode/vsce package  # produce mcp-audit-vscode-0.1.0.vsix
```
