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
