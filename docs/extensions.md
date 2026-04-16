# IDE Extension Security Scanner

## Why extension security matters

AI coding assistants (GitHub Copilot, Cursor, Windsurf) run inside VS Code-based
IDEs.  Those IDEs load arbitrary third-party extensions from the Marketplace — giving
those extensions the same access to your filesystem, network, and terminal that the
IDE itself has.

Two recent incidents illustrate the risk:

- **CVE-2025-65717 — Live Server remote file exfiltration** (72M+ downloads): any
  device on the same network could silently read arbitrary workspace files via the
  extension's built-in HTTP server, with no authentication required.  This affected
  VS Code, Cursor, and Windsurf users.

- **GlassWorm** (2024 PoC): demonstrated that a malicious VS Code extension can
  silently exfiltrate credentials via activation events that fire before the user
  interacts with the workspace, evading content-security policies.

- **OpenVSX namespace hijacking** (2023): the OpenVSX Registry had insufficient
  publisher verification, allowing attackers to claim well-known publisher namespaces
  and serve backdoored extensions under familiar names.

mcp-audit's extension scanner performs static manifest analysis to surface these
issues before they are exploited.

---

## Supported clients and discovery paths

| Client    | Discovery paths (macOS)                                          |
|-----------|------------------------------------------------------------------|
| VS Code   | `~/.vscode/extensions/`, `~/.vscode-server/extensions/`         |
| Cursor    | `~/.cursor/extensions/`, `~/.cursor-server/extensions/`         |
| Windsurf  | `~/.windsurf/extensions/`, `~/Library/Application Support/Windsurf/extensions/` |
| Augment   | `~/.augment/extensions/`, `~/Library/Application Support/Augment/extensions/`   |

Discovery probes all candidate paths and silently skips those that don't exist.
The same extension installed in multiple clients is reported once per client instance
(both instances are relevant to scan).

> **Note:** Windsurf and Augment paths are included for portability but were not
> found on the build machine (macOS).  VS Code and Cursor are confirmed present.

---

## Commands

### `mcp-audit extensions discover` (free, all tiers)

```bash
mcp-audit extensions discover [--client <name>] [--format terminal|json]
```

Discovers all installed extensions without analysis.  Use this to understand your
extension surface before running a full scan.

**Options:**

| Flag | Description |
|------|-------------|
| `--client` | Filter to a specific client: `vscode`, `cursor`, `windsurf`, `augment` |
| `--format` | `terminal` (Rich table, default) or `json` (array of `ExtensionManifest` objects) |

**Exit code:** always 0 (informational).

**Example output:**

```
┏━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━┓
┃ Client ┃ Extension ID                   ┃ Publisher ┃ Version ┃ Last Updated         ┃
┡━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━┩
│ cursor │ GitHub.copilot                 │ GitHub    │ 1.195.0 │ 2024-05-26T16:53:00Z │
│ vscode │ ritwickdey.LiveServer          │ ritwickdey│ 5.7.9   │ 2024-05-12T11:52:00Z │
└────────┴────────────────────────────────┴───────────┴─────────┴──────────────────────┘

Found 2 extension(s) across 2 client(s)
```

---

### `mcp-audit extensions scan` (Pro / Enterprise)

```bash
mcp-audit extensions scan [--client <name>] [--format terminal|json|sarif]
```

Discovers extensions and runs all analysis layers, producing security findings.

**Options:**

| Flag | Description |
|------|-------------|
| `--client` | Filter to a specific client |
| `--format` | `terminal` (Rich table, default), `json`, or `sarif` |

**Exit codes:** 0 if no findings; 1 if any findings.

---

### `mcp-audit scan --include-extensions` (Pro / Enterprise)

```bash
mcp-audit scan --include-extensions [all other scan flags]
```

Runs the standard MCP config scan **and** the extension scanner in a single pass.
Extension findings are appended to the same `ScanResult` and flow through all output
formatters (terminal, JSON, SARIF, HTML dashboard, Nucleus).

A summary line is printed after the scan:

```
Extensions: 34 extension(s) scanned, 2 issue(s) found
```

If unlicensed, the flag is silently ignored and the MCP config scan completes normally.

---

## Analysis layers

### 1. Known-vulnerability registry

Compares each extension's `publisher.name` ID and installed version against
`registry/known-extension-vulns.json`.  A match produces a finding with:

- Severity from the registry entry (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`)
- CVE number in evidence when available
- Remediation link to the advisory

**Version matching** uses a simplified `<X.Y.Z` prefix comparison (see Limitations).
`"*"` in `affected_versions` matches any installed version.

### 2. Dangerous capability combinations

Extensions can implicitly declare powerful capabilities through their `package.json`
manifest (activation events, contributes, keywords, description).  mcp-audit
classifies each extension into capability buckets and flags dangerous combinations:

| Combination | Severity | Risk |
|-------------|----------|------|
| `filesystem` + `network` | HIGH | Data exfiltration path |
| `terminal` + `network` | HIGH | Credential exfiltration |
| `debuggers` + `network` | MEDIUM | Code execution + network |

### 3. Wildcard activation event

`activationEvents: ["*"]` causes the extension to load on **every** VS Code event.
Legitimate extensions declare specific activation events (e.g. `onLanguage:python`).
Wildcard activation is a common red flag in malicious or poorly-written extensions.

Severity: **MEDIUM**.

### 4. Unknown publisher (AI-related extensions)

AI coding extensions from publishers not in the known-publishers list are flagged.
The check is restricted to AI-related extensions to avoid excessive noise on
harmless community utilities.

Known publishers include: `microsoft`, `github`, `redhat`, `anthropic`, `getcursor`,
`codeium`, `tabnine`, and a curated set of high-volume community publishers.

Severity: **LOW**.

### 5. Sideloaded extensions (VSIX)

Extensions installed from a `.vsix` file bypass the Marketplace publisher verification
step.  Detection heuristic: install path contains `.vsix`.

Severity: **MEDIUM**.

### 6. Stale AI-related extensions

AI extensions whose `package.json` mtime is older than 365 days may lack security
patches and use outdated model APIs.  Only AI-related extensions are flagged to
avoid noise from unmaintained but harmless utilities.

Severity: **INFO**.

---

## Known limitations

- **Capability classification is heuristic.** False positives are possible on complex
  extensions with unconventional manifests.  Capability inference is based on keywords,
  description, contributes keys, and activation events — not runtime behavior.

- **Version matching uses simplified prefix comparison, not full semver ranges.**
  `"<1.2.3"` is compared by splitting on `.` and comparing integer tuples.
  Ranges like `">=1.0.0 <2.0.0"` or `"^1.0.0"` are not supported.
  See `GAPS.md` for the full caveat.

- **Discovery paths are hardcoded per-client.**  Paths that differ by OS version,
  client version, or custom install location may not be found.

- **Windows extension paths are not validated.**  The paths listed in
  `EXTENSION_PATHS` for Windows clients are untested.

- **No runtime behavior monitoring.**  The scanner analyzes static manifest data
  only.  Extensions that conceal capabilities in their JS bundle are not detected.

- **Fleet extension inventory** via `mcp-audit merge` is not yet implemented
  (Enterprise, post-launch roadmap).

---

## Contributing to `known-extension-vulns.json`

The vulnerability registry lives at `registry/known-extension-vulns.json`.  Each
entry follows this schema:

```json
{
  "extension_id": "publisher.name",
  "affected_versions": "<1.2.3",
  "cve": "CVE-YYYY-NNNNN",
  "severity": "high",
  "title": "Short human-readable title",
  "description": "Full description of the vulnerability and impact.",
  "reference": "https://link-to-advisory",
  "reported_date": "YYYY-MM-DD"
}
```

To add a new entry:

1. Verify the CVE or advisory against the source.
2. Add the entry to `known-extension-vulns.json`.
3. Add a test in `tests/test_extensions.py` (at minimum: `test_matches_known_vuln_exact_id`).
4. Update `PROVENANCE.md` with the research source.

---

## Roadmap

- **Fleet extension inventory** — `mcp-audit merge` aggregating extension findings
  across machines (Enterprise tier, post-launch).
- **OpenVSX Registry cross-check** — validate publisher identity against the
  OpenVSX API.
- **Full semver range matching** — replace the simplified `<X.Y.Z` comparison with
  a proper semver range parser.
- **Windows path validation** — confirm and test extension discovery on Windows.
