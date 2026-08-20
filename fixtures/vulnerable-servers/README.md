# Vulnerable MCP server fixtures

Three deliberately insecure MCP server configurations. `mcp-audit advise` scans them to
seed the example advisory feed in `examples/feed/`, and `tests/test_cli_advise.py`
asserts against the advisories they produce.

| File | Package | Demonstrates |
| --- | --- | --- |
| `typosquat-filesystem.json` | `@modelcontextprotocol/server-filesytem` (npm) | Typosquat one edit from a real package (`SC-001`), unpinned runtime fetch |
| `hardcoded-secret-github.json` | `mcp-audit-fixture-github-server` (npm) | Plaintext token in `env` (`CRED-001`), over-scoped credential (`COMM-034`), cleartext API endpoint |
| `unsafe-shell-runner.json` | `mcp-audit-fixture-shell-runner` (PyPI) | Shell metacharacters and `sh -c` in args (`COMM-006`, `COMM-007`, `COMM-015`), `--allow-all` scope |

Between them they cover all three finding classes `mcp-audit fix` remediates:
`hardcoded-secret`, `command-injection`, and `excessive-scope`.

## These are not accusations

Two of the three package names are prefixed `mcp-audit-fixture-` so they cannot be
confused with real software. The third is a *misspelling* of a real package — naming a
typosquat is describing the attack, not alleging anything about its target.

The credential values are synthetic and match no real account. They are shaped to trip
the detector patterns in `analyzers/credentials.py` and nothing more.

## Scanning them

```bash
mcp-audit scan fixtures/vulnerable-servers
mcp-audit advise fixtures/vulnerable-servers --out /tmp/feed --no-sign
```
