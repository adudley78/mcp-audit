"""docs/contributing-rules.md must agree with the code it tells contributors about."""

from __future__ import annotations

import re
from pathlib import Path

from mcp_audit.owasp_mcp import OWASP_MCP_TOP_10

DOC = Path(__file__).resolve().parent.parent / "docs" / "contributing-rules.md"
_ROW = re.compile(r"^\|\s*`(MCP\d\d)`\s*\|\s*([^|]+?)\s*\|", re.MULTILINE)


def _table_rows() -> dict[str, str]:
    """Return the OWASP quick-reference table as {code: name}."""
    text = DOC.read_text(encoding="utf-8")
    section = text.split("### OWASP MCP Top 10 quick reference", 1)[1]
    section = section.split("\n---\n", 1)[0]
    return dict(_ROW.findall(section))


def test_owasp_table_names_match_owasp_mcp_module() -> None:
    """Every code in the guide's table carries the name owasp_mcp.py defines."""
    rows = _table_rows()
    assert rows, "OWASP quick-reference table not found in contributing-rules.md"
    for code, name in rows.items():
        assert OWASP_MCP_TOP_10.get(code) == name, f"{code}: guide says {name!r}"


def test_owasp_table_lists_every_code() -> None:
    """The table covers all ten codes, so no contributor has to guess one."""
    assert set(_table_rows()) == set(OWASP_MCP_TOP_10)


def test_guide_names_the_files_ci_checks() -> None:
    """The guide tells contributors about both doc files a new rule ID must touch."""
    text = DOC.read_text(encoding="utf-8")
    assert "docs/owasp-mapping.json" in text
    assert "docs/manual-test-matrix.md" in text
    assert "uv run pytest" in text
