# mcp-audit Semgrep Rules

A curated pack of Semgrep rules that detect security vulnerabilities in MCP
(**Model Context Protocol**) **server source code** — the Python and TypeScript
implementations that handle tool calls from AI agents.

This is complementary to mcp-audit's config scanning (which audits client-side
JSON configurations). These rules scan the server implementation itself.

---

## Usage

### Standalone (no mcp-audit required)

Run the full rule pack against a directory:

```bash
semgrep --config semgrep-rules/ path/to/mcp-server/
```

Run only a category subset:

```bash
# Injection rules only
semgrep --config semgrep-rules/python/injection/ path/to/server/

# Python poisoning rules only
semgrep --config semgrep-rules/python/poisoning/ path/to/server/

# All TypeScript rules
semgrep --config semgrep-rules/typescript/ path/to/server/
```

### Via mcp-audit

```bash
mcp-audit scan --sast path/to/mcp-server/
```

SAST findings are merged into the unified scan output alongside config-scanning
findings. Available in all output formats: terminal, JSON, SARIF, HTML dashboard.

Standalone SAST scan (no config scanning):

```bash
mcp-audit sast path/to/mcp-server/
mcp-audit sast path/to/mcp-server/ --format json
```

For full reference, see [docs/sast-rules.md](../docs/sast-rules.md).

---

## Rule Categories

### Python

| Category | Rules | What it detects |
|---|---|---|
| `python/injection` | 9 | subprocess injection, eval/exec, path traversal, SSRF, SQL injection |
| `python/poisoning` | 5 | Hidden instructions, exfiltration URLs, base64/unicode obfuscation in descriptions |
| `python/credentials` | 5 | Hardcoded API keys, connection strings, secrets in logs, credentials in args |
| `python/protocol` | 3 | Missing input validation, stack trace exposure |
| `python/transport` | 4 | uvicorn/Flask without TLS, binding to all interfaces |

### TypeScript

| Category | Rules | What it detects |
|---|---|---|
| `typescript/injection` | 10 | child_process.exec injection, eval(), path traversal (read/write/join), SQL injection (concat/template), SSRF (fetch/axios/http) |
| `typescript/poisoning` | 3 | Hidden instructions, exfiltration keywords in descriptions |
| `typescript/credentials` | 2 | Hardcoded API keys and tokens |
| `typescript/transport` | 1 | http.createServer() without TLS |
| `typescript/auth` | 2 | Missing auth middleware on MCP routes (MCPwn/CVE-2026-33032), auth headers logged (n8n-MCP/CVE-2026-41495) |

---

## Installation Requirements

```bash
pip install semgrep
```

Semgrep 1.0+ required. Rules use standard Semgrep YAML format.

---

## False Positive Guidance

The following rules have elevated false positive rates and are marked `INFO`
or have `fp-guidance` in their metadata:

- **`mcp-open-path-traversal`** — fires on any `open($var)` in async functions,
  including validated paths. Suppress when path is checked with
  `Path.is_relative_to()` or `os.path.commonpath()`.
- **`mcp-pathlib-open-traversal`** — same as above for `Path($x).open()`.
- **`mcp-no-type-check-before-use`** — heuristic for missing validation; fires
  when MCP SDK's own type validation handles the check.
- **`mcp-bare-exception-return`** — fires on all `except E: return str(e)` in
  async functions, including cases where error messages contain no sensitive data.

To suppress a specific rule for a single line:

```python
result = open(user_path, "r")  # nosemgrep: mcp-open-path-traversal
```

To suppress for an entire file, add a comment at the top:

```python
# nosemgrep
```

---

## Contributing New Rules

1. Create a YAML file in the appropriate category directory.
2. Every rule **must** include: `id`, `message`, `severity`, `languages`,
   `pattern` (or `patterns`/`pattern-regex`), and `metadata` with at minimum
   `category`, `cwe`, and `description`.
3. Add a test fixture: a vulnerable example to `tests/<lang>/vulnerable/` and
   verify it fires, and ensure `tests/<lang>/clean/safe_server.*` stays clean.
4. Validate: `semgrep --config semgrep-rules/ --validate`
5. Open a PR with the rule file, test fixture updates, and a brief description
   of the vulnerability being detected and its research source.

See [docs/contributing-rules.md](../docs/contributing-rules.md) for the full
PR checklist and metadata schema reference.

---

## Severity Mapping

When used via `mcp-audit scan --sast`, Semgrep severities map to mcp-audit
finding severities as follows:

| Semgrep | mcp-audit |
|---|---|
| ERROR | CRITICAL |
| WARNING | HIGH |
| INFO | MEDIUM |
