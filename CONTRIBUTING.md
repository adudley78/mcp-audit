# Contributing to mcp-audit

Thank you for your interest in contributing. mcp-audit is an open-core
project — the community scanner is Apache 2.0, and we welcome contributions
to detection rules, the known-server registry, and the core scanner.

## Ways to contribute

### Submit a detection rule

See [docs/writing-rules.md](docs/writing-rules.md) for the rule format
and [docs/registry-contributions.md](docs/registry-contributions.md)
for registry contributions. Use the pull request template when submitting.

### Report a false positive

Open an issue with:

- The MCP server configuration that triggered it
- The finding ID and description
- Why you believe it is a false positive

### Report a bug

Open an issue with:

- mcp-audit version (`mcp-audit version`)
- OS and Python version
- The command you ran
- The full output including any error messages

### Improve detection patterns

Detection patterns are in `src/mcp_audit/analyzers/`. Each analyzer has
a corresponding test file in `tests/`. All PRs must:

- Pass the full test suite: `pytest tests/ -x -q`
- Pass ruff: `ruff check src/ tests/` and `ruff format src/ tests/`
- Include tests for any new detection patterns

## Development setup

```bash
git clone https://github.com/adudley78/mcp-audit
cd mcp-audit
pip install -e ".[dev]"
pytest tests/ -x -q
```

## Code conventions

- All source code in `src/mcp_audit/`
- Analyzers inherit from `BaseAnalyzer` and implement `analyze()`
- Pydantic v2 for all data models
- Rich for all terminal output
- No new dependencies without discussion in an issue first
- Every new module needs a corresponding test file

## Adding a new analyzer

Use `src/mcp_audit/analyzers/transport.py` as the reference — it is the
simplest single-server analyzer in the codebase.

### 1. Create the file

Create `src/mcp_audit/analyzers/your_name.py` with this import structure:

```python
from __future__ import annotations

from mcp_audit.analyzers.base import BaseAnalyzer
from mcp_audit.models import Finding, ServerConfig, Severity
```

### 2. Inherit from `BaseAnalyzer` and implement `analyze()`

```python
class YourAnalyzer(BaseAnalyzer):
    @property
    def name(self) -> str:
        return "your_name"  # used as Finding.analyzer

    @property
    def description(self) -> str:
        return "One-line description of what this analyzer checks"

    def analyze(self, server: ServerConfig) -> list[Finding]:
        findings: list[Finding] = []
        # ... detection logic ...
        return findings
```

`analyze()` is called once per server. Return an empty list when the server
is clean.

### 3. `analyze_all()` — when to use it instead

Two analyzers override `analyze_all(servers)` instead: `rug_pull.py` and
`toxic_flow.py`. They need the **full server list** to do their work (rug-pull
compares state across runs; toxic-flow looks for dangerous cross-server
capability pairs). Their `analyze()` is a no-op.

Use `analyze_all()` only when your detection logic is inherently
cross-server. Single-server checks always belong in `analyze()`.

### 4. Register the analyzer in `scanner.py`

Add your class to `get_default_analyzers()` in
`src/mcp_audit/scanner.py`:

```python
from mcp_audit.analyzers.your_name import YourAnalyzer

def get_default_analyzers() -> list[BaseAnalyzer]:
    return [
        PoisoningAnalyzer(),
        CredentialsAnalyzer(),
        TransportAnalyzer(),
        SupplyChainAnalyzer(),
        YourAnalyzer(),   # add here
    ]
```

Cross-server analyzers (`analyze_all()` variants) are called separately
inside `_run_static_pipeline()` — wire them there, not in
`get_default_analyzers()`.

### 5. Required `Finding` fields

Every `Finding` must set these fields:

| Field | Type | Notes |
|---|---|---|
| `id` | `str` | Uppercase, e.g. `"YOURNAME-001"` |
| `severity` | `Severity` | See severity conventions below |
| `analyzer` | `str` | Must equal `self.name` |
| `client` | `str` | Pass `server.client` |
| `server` | `str` | Pass `server.name` |
| `title` | `str` | Short one-line description |
| `description` | `str` | Full explanation |
| `evidence` | `str` | The specific config value that triggered this |
| `remediation` | `str` | Actionable fix |
| `cwe` | `str \| None` | CWE reference, e.g. `"CWE-319"` (see [mitre.org/cwe](https://cwe.mitre.org)) |
| `finding_path` | `str \| None` | Pass `str(server.config_path)` when relevant |

### 6. Severity assignment conventions

Consult `GAPS.md` (the "Severity calibration" section) before assigning a
severity level. The general heuristic: CRITICAL = confirmed exploitation
path; HIGH = strong indicator of compromise or privilege escalation; MEDIUM
= likely misconfiguration with clear attack surface; LOW / INFO = hygiene or
informational. When in doubt, go one level lower — false positives erode trust.

### 7. Document detection pattern provenance

Every new detection pattern must cite its research source. Add an entry to
`PROVENANCE.md` before opening a PR. Do not add patterns without attribution.

### 8. Write the test file

Create `tests/test_your_analyzer.py`. Tests must cover:

- The **happy path** (clean server, empty findings list).
- Each **detection pattern** (at least one positive case per finding ID).
- The **crash path**: verify that `_analyzer_crash_finding` is emitted when
  the analyzer raises an unexpected exception. The scanner catches exceptions
  per-analyzer and wraps them in a `SCAN-ERR` finding — your tests should
  confirm that a malformed input does not propagate an unhandled exception.

## Adding a new Pro feature

Pro/Enterprise feature gating lives at the CLI layer only — analyzers and
`scanner.py` never check license state.  When you wire a new Pro-gated flag
or subcommand into `src/mcp_audit/cli.py`:

1. **Add the feature key** to `_FEATURE_TIERS` in `src/mcp_audit/licensing.py`
   mapping your key (e.g. `"my_feature"`) to the tiers that unlock it
   (typically `("pro", "enterprise")`).

2. **Gate the call site through `gate()`**, never inline:

   ```python
   from mcp_audit._gate import gate

   # Soft gate — skip the feature and continue the scan:
   if not gate("my_feature", console, message="--my-flag skipped."):
       return  # or: fall through to skip the feature block

   # Hard gate — exit the command:
   if not gate("my_feature", console):
       raise typer.Exit(2)  # pick the right exit code for your command
   ```

   The `gate()` helper prints a single standardised Pro upsell panel so the
   wording stays consistent across the whole CLI.  Never print your own
   upsell message — it will drift out of sync with the rest of the tool.

3. **Add two gate tests** — one positive (`pro_enabled` fixture from
   `tests/conftest.py`, expect the feature to run) and one negative (patch
   `mcp_audit.cli.cached_is_pro_feature_available` to return `False`, expect
   the upsell panel and the feature to be skipped).  The patch target is the
   attribute on the `cli` module — `gate()` resolves its license check
   through that attribute so a single patch intercepts every call site.

4. **Never call `gate()` from analyzers, `scanner.py`, or any output
   formatter helper other than the CLI layer.**  Scans always execute in
   full regardless of licence tier; gating only restricts CLI surface area.

## Testing conventions

### Pro/Enterprise output formatter tests

The `pro_enabled` fixture in `tests/conftest.py` patches
`is_pro_feature_available` to return `True`. It is **opt-in** — tests that
do not request it run against the real (unlicensed) gating logic.

When adding a new Pro or Enterprise output formatter:

1. Add a **negative gate test** to `tests/test_pro_gating.py` that patches
   `is_pro_feature_available` to return `False` per-test and asserts the
   formatter returns `None` (or the expected upsell response).
2. Add a **positive gate test** in the same file that requests `pro_enabled`
   and asserts the formatter returns valid output.
3. In the formatter's own test file, request `pro_enabled` on every test (or
   fixture) that calls the formatter — either as a direct parameter or via a
   class-level `@pytest.fixture(autouse=True)` method that accepts
   `pro_enabled`.

**Do not** make `pro_enabled` `autouse=True` or `scope="session"`. Doing so
would silently disable the negative gate tests in `test_pro_gating.py` and
defeat the purpose of the fixture.

## What we won't accept

- PRs that remove or weaken existing detection patterns without strong justification
- New dependencies that require network access during scanning
- Changes to the licensing or Pro/Enterprise gating logic
