# Project: mcp-audit

## Stack
- Python 3.11+, managed with uv
- CLI: Typer + Rich
- Data models: Pydantic v2
- Testing: pytest + pytest-asyncio

## Code conventions
- Type hints on all function signatures
- Docstrings on all public functions
- Run `uv run pytest` after each change
- Run `uv run ruff check src/ tests/` before committing

## Key directories
- `src/mcp_audit/` — main package
- `tests/` — test suite
- `docs/` — documentation
