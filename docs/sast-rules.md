# SAST Rules Reference

mcp-audit ships a curated pack of [Semgrep](https://semgrep.dev) rules that
detect security vulnerabilities in MCP **server source code** — the Python and
TypeScript implementations that handle tool calls from AI agents.

This is complementary to mcp-audit's config scanning (which audits JSON
client configurations). These rules scan the server implementation itself.

---

## Installation

```bash
pip install semgrep
```

Semgrep 1.0+ required.

---

## Usage Modes

### Standalone (no mcp-audit required)

Run the full rule pack against a directory or file:

```bash
semgrep --config semgrep-rules/ path/to/mcp-server/
```

Run only a subset by category:

```bash
semgrep --config semgrep-rules/python/injection/ path/to/server/
semgrep --config semgrep-rules/python/credentials/ path/to/server/
semgrep --config semgrep-rules/typescript/ path/to/server/
```

### Via mcp-audit

Merge SAST findings into the unified scan output:

```bash
mcp-audit scan --sast path/to/mcp-server/
mcp-audit scan --sast path/to/mcp-server/ --format json
mcp-audit scan --sast path/to/mcp-server/ --format sarif --output results.sarif
```

Standalone SAST scan (no config scanning):

```bash
mcp-audit sast path/to/mcp-server/
mcp-audit sast path/to/mcp-server/ --format json
mcp-audit sast path/to/mcp-server/ --rules-dir /custom/rules/
```

---

## Severity Mapping

| Semgrep | mcp-audit |
|---|---|
| ERROR | CRITICAL |
| WARNING | HIGH |
| INFO | MEDIUM |

---

## Rule Catalog

### Python Rules (28 rules)

#### `python/injection/` — 9 rules

| Rule ID | Severity | CWE | Description |
|---|---|---|---|
| `mcp-subprocess-string-cmd` | HIGH | CWE-78 | subprocess.run/Popen with string command in async function |
| `mcp-os-system-call` | CRITICAL | CWE-78 | os.system() in async function |
| `mcp-shell-true-injection` | HIGH | CWE-78 | subprocess called with shell=True |
| `mcp-eval-tool-arg` | CRITICAL | CWE-95 | eval()/exec() with variable in async function |
| `mcp-open-path-traversal` | HIGH | CWE-22 | open() with variable path in async function |
| `mcp-pathlib-open-traversal` | HIGH | CWE-22 | Path($x).open/read_text/write_text with variable |
| `mcp-requests-variable-url` | HIGH | CWE-918 | requests/httpx with variable URL — SSRF risk |
| `mcp-aiohttp-variable-url` | HIGH | CWE-918 | aiohttp session with variable URL — SSRF risk |
| `mcp-fstring-sql` | CRITICAL | CWE-89 | f-string SQL query in async function |
| `mcp-string-concat-sql` | CRITICAL | CWE-89 | String-concatenated SQL query |

#### `python/poisoning/` — 5 rules

| Rule ID | Severity | CWE | Description |
|---|---|---|---|
| `mcp-tool-description-injection-keywords` | CRITICAL | CWE-1336 | "ignore previous instructions" in tool description |
| `mcp-tool-description-injection-keywords-2` | CRITICAL | CWE-1336 | Hidden action keywords in tool description |
| `mcp-tool-description-exfiltration-keywords` | CRITICAL | CWE-1336 | Exfiltration keywords in tool description |
| `mcp-description-contains-url` | HIGH | CWE-1336 | URL embedded in tool description |
| `mcp-description-base64-content` | HIGH | CWE-1336 | Base64-encoded content in tool description |
| `mcp-description-unicode-escape` | MEDIUM | CWE-1336 | Unicode escape sequences in tool description |

#### `python/credentials/` — 5 rules

| Rule ID | Severity | CWE | Description |
|---|---|---|---|
| `mcp-hardcoded-api-key` | CRITICAL | CWE-798 | Hardcoded API key, token, or password assignment |
| `mcp-hardcoded-connection-string` | CRITICAL | CWE-798 | Database connection string with embedded credentials |
| `mcp-print-sensitive-var` | HIGH | CWE-532 | Sensitive variable printed in async handler |
| `mcp-logging-sensitive-var` | HIGH | CWE-532 | Sensitive variable passed to logging call |
| `mcp-env-var-not-used` | HIGH | CWE-798 | Credential hardcoded as default argument value |

#### `python/protocol/` — 3 rules

| Rule ID | Severity | CWE | Description |
|---|---|---|---|
| `mcp-no-type-check-before-use` | MEDIUM | CWE-20 | arguments.get() result used without validation |
| `mcp-traceback-in-return` | HIGH | CWE-209 | traceback.format_exc() returned from async function |
| `mcp-bare-exception-return` | MEDIUM | CWE-209 | except E: return str(e) in async function |

#### `python/transport/` — 4 rules

| Rule ID | Severity | CWE | Description |
|---|---|---|---|
| `mcp-fastapi-no-ssl` | HIGH | CWE-319 | uvicorn.run() without ssl_certfile/ssl_keyfile |
| `mcp-flask-no-ssl` | HIGH | CWE-319 | app.run() without ssl_context |
| `mcp-uvicorn-listen-all` | HIGH | CWE-605 | uvicorn.run() binding to 0.0.0.0 |
| `mcp-fastapi-listen-all` | HIGH | CWE-605 | app.run(host="0.0.0.0") |

### TypeScript Rules (9 rules)

#### `typescript/injection/` — 3 rules

| Rule ID | Severity | CWE | Description |
|---|---|---|---|
| `mcp-ts-exec-injection` | CRITICAL | CWE-78 | child_process.exec() with variable command |
| `mcp-ts-execsync-injection` | CRITICAL | CWE-78 | execSync() with variable command |
| `mcp-ts-eval-variable` | CRITICAL | CWE-95 | eval() with variable argument |

#### `typescript/poisoning/` — 3 rules

| Rule ID | Severity | CWE | Description |
|---|---|---|---|
| `mcp-ts-tool-description-injection` | CRITICAL | CWE-1336 | Injection keywords in TS tool description |
| `mcp-ts-tool-description-injection-2` | CRITICAL | CWE-1336 | Hidden action keywords in TS tool description |
| `mcp-ts-tool-description-exfiltration` | CRITICAL | CWE-1336 | Exfiltration keywords in TS tool description |

#### `typescript/credentials/` — 2 rules

| Rule ID | Severity | CWE | Description |
|---|---|---|---|
| `mcp-ts-hardcoded-api-key` | CRITICAL | CWE-798 | Hardcoded credential in const declaration |
| `mcp-ts-hardcoded-api-key-let` | CRITICAL | CWE-798 | Hardcoded credential in let declaration |

#### `typescript/transport/` — 1 rule

| Rule ID | Severity | CWE | Description |
|---|---|---|---|
| `mcp-ts-express-no-https` | HIGH | CWE-319 | http.createServer() — plain HTTP, no TLS |

---

## False Positive Guidance

The following rules have elevated false positive rates due to their heuristic nature.

### High FP Risk

**`mcp-open-path-traversal`** and **`mcp-pathlib-open-traversal`**

These fire on ANY `open()` or `Path().read_text()` call in an async function
where the path is a variable. This includes well-written code that validates
paths using `Path.is_relative_to()` or `os.path.commonpath()`.

Suppress when path is validated:

```python
async def read_file(user_path: str) -> str:
    full = (BASE_DIR / user_path).resolve()
    if not full.is_relative_to(BASE_DIR):
        raise ValueError("Path traversal blocked")
    return full.read_text()  # nosemgrep: mcp-pathlib-open-traversal
```

**`mcp-no-type-check-before-use`**

Fires when `arguments.get()` result is passed directly to a function call.
The MCP SDK's own type validation for typed tool definitions handles this
at the protocol level — suppress accordingly:

```python
value = arguments.get("name")  # nosemgrep: mcp-no-type-check-before-use
```

**`mcp-flask-no-ssl`**

The pattern `$APP.run(...)` is broad. It excludes `subprocess.run` and
`asyncio.run` but may fire on other `.run()` methods. Suppress when the
server is behind a TLS-terminating proxy:

```python
app.run(port=5000)  # nosemgrep: mcp-flask-no-ssl — TLS terminated at nginx
```

### Medium FP Risk

**`mcp-requests-variable-url`** and **`mcp-aiohttp-variable-url`**

Fire on any HTTP request with a variable URL. Suppress when the URL is
validated against an allowlist:

```python
resp = requests.get(url, ...)  # nosemgrep: mcp-requests-variable-url
```

**`mcp-hardcoded-api-key`**

Fires when a variable named `api_key`, `token`, `secret` etc. is assigned
a string of 20+ characters. May fire on test fixtures or placeholder values.
Review each finding manually.

---

## Suppressing Rules

### Per-line suppression

```python
result = subprocess.run(cmd_list, ...)  # nosemgrep: mcp-subprocess-string-cmd
```

### Per-file suppression

Add at the top of the file:

```python
# nosemgrep
```

### Per-rule suppression via semgrepignore

Add to `.semgrepignore` in the target project root:

```
path/to/file/with/false/positives.py
```

---

## Contributing New Rules

See [contributing-rules.md](contributing-rules.md) for the full guide including
rule structure reference, test fixture requirements, and PR checklist.

---

## Roadmap

- GitHub Action `sast: true` input — run SAST alongside config scanning in CI
- Go language rules for MCP servers written in Go
- Rust language rules
- Taint analysis rules (track data flow from `arguments.get()` to sinks)
- OSV.dev integration for dependency vulnerability scanning
