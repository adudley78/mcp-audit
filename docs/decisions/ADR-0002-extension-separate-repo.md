# ADR-0002 — VS Code extension lives in a separate repository

**Date:** 2026-05-18  
**Status:** Accepted  
**Story:** STORY-0032

---

## Context

STORY-0032 introduces a VS Code / Cursor extension that surfaces `mcp-audit`
findings as inline diagnostics. Two options were considered:

**Option A — Subdirectory:** `extensions/vscode/` inside the main
`mcp-audit` Python repo. TypeScript build tooling (npm, esbuild, `vsce`) added
to the same repo; CI would need to run both Python (`uv run pytest`) and
Node.js (`npm test`) legs.

**Option B — Separate repo:** `mcp-audit-vscode` as a standalone GitHub
repository. Independent CI, versioning, and Marketplace publishing pipeline.
The extension calls the `mcp-audit` binary via `child_process.spawn` — there
is no Python import or build-time dependency.

---

## Decision

**Option B (separate repo)** was chosen.

Reasons:

1. **Clean toolchain boundary.** The VS Code Marketplace toolchain (`vsce`,
   `@vscode/test-electron`) is Node-centric. Adding it to a Python monorepo
   would require npm scripts alongside `uv run` commands, increasing cognitive
   load for contributors unfamiliar with one half.

2. **Independent versioning.** The extension starts at `0.1.0` and may ship
   patch releases to fix squiggle rendering or hover-card wording without
   coupling to a mcp-audit Python release. The extension consumes the CLI's
   *JSON output schema* as its contract — not Python package versions.

3. **No cross-language build dependency.** The extension does not import any
   Python code; it spawns the `mcp-audit` binary at runtime. A separate repo
   makes this explicit: nothing in `mcp-audit-vscode/` requires Python to
   build or test.

4. **Marketplace artifact isolation.** `vsce package` produces a `.vsix` that
   must not bundle unrelated Python source, test fixtures, or Semgrep rules.
   A dedicated `.vscodeignore` in a standalone repo is simpler than expressing
   "exclude everything except the TS bundle" from within a Python monorepo.

5. **STORY-0042 (Cursor Marketplace) readiness.** The Cursor Marketplace
   requires a manual submission form with a standalone VSIX artifact. Keeping
   the extension in its own repo makes CI artifact upload straightforward.

---

## Constraint: wrapper, not reimplementation

The extension **must not** reimplement any detection logic in TypeScript.
All detection runs in the `mcp-audit` binary. The extension's only job is:

- Detect MCP config files by name.
- Spawn `mcp-audit scan --path <file> --format json`.
- Parse the JSON output.
- Render `vscode.Diagnostic` objects.

Any new detection rule or analyzer belongs in the main `mcp-audit` repo.

---

## Consequences

- Main repo (`mcp-audit`): no npm/Node changes; only `docs/ide-extension.md`
  and a README link are added.
- Extension repo (`mcp-audit-vscode`): its own CI (TypeScript lint + unit test
  + VSIX build on 3 OSes), its own `CHANGELOG.md`, its own Marketplace listing.
- JSON output schema of `mcp-audit scan --format json` becomes a **public
  API**. Breaking changes to `ScanResult` or `Finding` field names require a
  coordinated bump and extension update. The `types.ts` file in the extension
  repo serves as the schema contract; keep it in sync with `models.py`.
