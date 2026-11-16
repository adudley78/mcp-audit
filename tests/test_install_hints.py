"""Install hints must name the real PyPI distribution and survive Rich markup."""

from __future__ import annotations

from io import StringIO

from rich.console import Console
from rich.markup import escape

from mcp_audit.mcp_client import MCP_NOT_INSTALLED


def _render(text: str) -> str:
    buf = StringIO()
    console = Console(file=buf, force_terminal=True, width=120, color_system=None)
    console.print(f"[red]Error:[/red] {escape(text)}")
    return buf.getvalue()


def test_connect_hint_names_the_mcp_extra() -> None:
    assert "credenzo[mcp]" in MCP_NOT_INSTALLED
    rendered = _render(MCP_NOT_INSTALLED)
    assert "credenzo[mcp]" in rendered


def test_sbom_hint_keeps_bracketed_extra() -> None:
    hint = (
        "The 'sbom' extra is required for CycloneDX output. "
        "Install it with: pip install 'credenzo[sbom]'"
    )
    assert "credenzo[sbom]" in _render(hint)
