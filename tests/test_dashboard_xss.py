"""Regression tests: XSS injection via finding fields in the HTML dashboard.

json.dumps() does not HTML-escape <, >, or & by default.  Without explicit
escaping, a malicious MCP server description containing </script> would close
the inline <script> block early and allow arbitrary HTML/JS injection in the
generated dashboard file.  generate_html() must Unicode-escape these chars.
"""

from __future__ import annotations

from mcp_audit.models import Finding, ScanResult, Severity
from mcp_audit.output.dashboard import generate_html

# ── Fixtures ──────────────────────────────────────────────────────────────────


def _result_with_description(description: str) -> ScanResult:
    """Return a ScanResult containing one finding with *description*."""
    finding = Finding(
        id="XSS-001",
        severity=Severity.HIGH,
        analyzer="poisoning",
        client="cursor",
        server="evil-server",
        title="XSS test finding",
        description=description,
        evidence=description,
        remediation="Remove the server.",
    )
    return ScanResult(
        clients_scanned=1,
        servers_found=1,
        findings=[finding],
    )


# ── Tests ─────────────────────────────────────────────────────────────────────


def test_script_tag_injection_in_description_is_neutralised() -> None:
    """A description containing </script> must not appear unescaped in the HTML."""
    payload = "</script><script>alert(1)</script>"
    html = generate_html(_result_with_description(payload))

    # The raw injection string must not appear verbatim inside the HTML.
    assert "</script><script>" not in html
    # The data must still be present, encoded as Unicode escapes.
    assert "\\u003c" in html


def test_ampersand_in_description_is_neutralised() -> None:
    """& must be escaped to \\u0026 to prevent entity injection."""
    html = generate_html(_result_with_description("foo & bar"))
    assert "\\u0026" in html
    # The literal ampersand must not appear inside the script block.  We check
    # the full HTML rather than trying to isolate the script tag, because any
    # occurrence of & in the JSON blob is dangerous.
    script_start = html.find("<script>")
    script_end = html.rfind("</script>")
    assert script_start != -1 and script_end != -1
    script_content = html[script_start:script_end]
    assert "foo & bar" not in script_content
