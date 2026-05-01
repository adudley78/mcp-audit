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
uv sync --extra dev   # installs all dev dependencies including pytest-asyncio
pre-commit install    # registers the git pre-commit hooks (see below)
pytest tests/ -x -q
```

> **Note:** Use `uv sync --extra dev`, not a bare `uv sync`. A plain `uv sync`
> omits the `dev` optional-dependency group, so `pytest-asyncio` will not be
> installed and all async tests will fail with
> `PytestUnknownMarkWarning: Unknown pytest.mark.asyncio`.

### Pre-commit hooks

The repo ships a `.pre-commit-config.yaml` that enforces three gates locally
before a commit is created:

| Hook | What it does |
|---|---|
| `ruff` | Lint with auto-fix |
| `ruff-format` | Auto-format source and tests |
| `update-test-count` | Patches test/rule/analyzer counts in `README.md`, `CLAUDE.md`, and `.github/release-notes-template.md` |

Run `pre-commit install` once after cloning. After that, every `git commit`
runs all three hooks automatically — the same checks CI enforces, so you never
push a commit that fails the format or count-drift gate.

If `pre-commit` is not yet installed on your machine:

```bash
pip install pre-commit
pre-commit install
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
    supply_chain = SupplyChainAnalyzer()
    return [
        PoisoningAnalyzer(),
        CredentialsAnalyzer(),
        TransportAnalyzer(registry=supply_chain.registry),
        supply_chain,
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

## Adding a new feature

mcp-audit is fully open source (Apache 2.0) and every feature is available
to every user.  All paid-license plumbing (Ed25519 key verification,
`activate` / `license` commands, `_FEATURE_TIERS`, the `gate()` shim,
`cached_is_pro_feature_available`) was removed in v0.2.0.

When wiring a new flag or subcommand into `src/mcp_audit/cli/`:

1. **Do not re-introduce gating.**  No license checks, no tier-based
   branching, no "Pro" / "Enterprise" docstrings.

2. **Tests cover the feature working end-to-end**, never via license patches.

## What we won't accept

- PRs that remove or weaken existing detection patterns without strong justification
- New dependencies that require network access during scanning
- PRs that re-introduce paid tiers or conditional feature availability
