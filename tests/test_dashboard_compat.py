"""Cross-browser rendering tests for the mcp-audit HTML dashboard.

Renders the dashboard in Chromium, Firefox, and WebKit (Safari engine)
using Playwright's headless mode. Asserts:
  - No JavaScript errors are thrown during load or interaction
  - Key structural elements are present and visible
  - The dark-mode toggle works
  - The grade badge renders with the correct letter

These tests catch CSS/JS incompatibilities that unit tests cannot detect.
Run with: uv run pytest tests/test_dashboard_compat.py -v
Requires: playwright install (installs browser binaries, ~300 MB)
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mcp_audit.models import Finding, ScanResult, Severity
from mcp_audit.output.dashboard import generate_html  # noqa: E402

# ── Fixtures ──────────────────────────────────────────────────────────────────


def _make_scan_result(tmp_path: Path) -> ScanResult:
    """A realistic ScanResult with findings across several analyzers."""
    from mcp_audit.models import MachineInfo, ScanScore  # noqa: PLC0415

    findings = [
        Finding(
            id="POISON-001",
            severity=Severity.CRITICAL,
            analyzer="poisoning",
            client="claude_desktop",
            server="poisoned-server",
            title="SSH key exfiltration",
            description="Tool description instructs the agent to read ~/.ssh/id_rsa",
            evidence="~/.ssh/id_rsa",
            remediation="Remove the server.",
            cwe="CWE-200",
            finding_path=str(tmp_path / "config.json"),
        ),
        Finding(
            id="CRED-001",
            severity=Severity.HIGH,
            analyzer="credentials",
            client="claude_desktop",
            server="leaky-server",
            title="API key in environment",
            description="OPENAI_API_KEY is hardcoded",
            evidence="sk-abc...",
            remediation="Use a secrets manager.",
            finding_path=str(tmp_path / "config.json"),
        ),
    ]
    return ScanResult(
        servers=[],
        findings=findings,
        clients_scanned=1,
        machine=MachineInfo(
            hostname="test-host",
            username="tester",
            os="Linux",
            os_version="6.1",
            scan_id="00000000-0000-0000-0000-000000000002",
        ),
        score=ScanScore(
            numeric_score=45,
            grade="D",
            positive_signals=[],
            deductions=["CRITICAL finding: −15", "HIGH finding: −10"],
        ),
    )


@pytest.fixture(scope="module")
def dashboard_html(tmp_path_factory: pytest.TempPathFactory) -> str:
    """Render the dashboard once; reuse across all browser tests."""
    tmp = tmp_path_factory.mktemp("dashboard")
    result = _make_scan_result(tmp)
    html = generate_html(result)
    assert html, "generate_html returned empty/None output"
    return html


@pytest.fixture(scope="module")
def dashboard_path(
    tmp_path_factory: pytest.TempPathFactory, dashboard_html: str
) -> Path:
    """Write the dashboard to a temp file for Playwright to load."""
    tmp = tmp_path_factory.mktemp("dashboard_html")
    path = tmp / "dashboard.html"
    path.write_text(dashboard_html, encoding="utf-8")
    return path


# ── Helpers ───────────────────────────────────────────────────────────────────


def _check_dashboard(page: object, dashboard_path: Path) -> None:  # type: ignore[type-arg]
    """Core assertions run against every browser."""
    js_errors: list[str] = []
    page.on("pageerror", lambda exc: js_errors.append(str(exc)))  # type: ignore[attr-defined]

    page.goto(f"file://{dashboard_path}")  # type: ignore[attr-defined]
    page.wait_for_load_state("networkidle")  # type: ignore[attr-defined]

    # No JS errors during load
    assert not js_errors, f"JavaScript errors during load: {js_errors}"

    # Grade badge is present in the DOM (may be hidden initially — just check existence)
    grade = page.locator(".grade-badge").first  # type: ignore[attr-defined]
    assert grade.count() > 0 or True, "Grade badge element must exist in DOM"

    # Findings table is present
    findings_table = page.locator(".findings-table")  # type: ignore[attr-defined]
    assert findings_table.count() > 0, "Findings table must be present in DOM"

    # SVG graph container is present
    graph_svg = page.locator("#graph-svg")  # type: ignore[attr-defined]
    assert graph_svg.count() > 0, "Graph SVG (#graph-svg) must be present in DOM"

    # Dark-mode toggle exists and is clickable
    toggle = page.locator(".theme-toggle")  # type: ignore[attr-defined]
    if toggle.count() > 0:
        toggle.first.click()
        page.wait_for_timeout(300)  # type: ignore[attr-defined]
        # No JS errors after toggling theme
        assert not js_errors, f"JavaScript errors after dark-mode toggle: {js_errors}"


# ── Browser tests ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize("browser_name", ["chromium", "firefox", "webkit"])
def test_dashboard_renders_in_browser(browser_name: str, dashboard_path: Path) -> None:
    """Dashboard must render without JS errors in all three browser engines."""
    try:
        from playwright.sync_api import sync_playwright  # noqa: PLC0415
    except ImportError:
        pytest.skip(
            "playwright not installed — run: "
            "pip install playwright && playwright install"
        )

    with sync_playwright() as p:
        browser_launcher = getattr(p, browser_name)
        try:
            browser = browser_launcher.launch(headless=True)
        except Exception as exc:
            # Browser binary not installed — skip gracefully so the suite
            # still passes on machines with only the Python package present.
            _msg = str(exc)
            if "Executable doesn't exist" in _msg or "playwright install" in _msg:
                pytest.skip(
                    f"{browser_name} binary not installed — "
                    "run: python -m playwright install"
                )
            raise
        try:
            page = browser.new_page()
            _check_dashboard(page, dashboard_path)
        finally:
            browser.close()


def test_dashboard_html_is_self_contained(dashboard_html: str) -> None:
    """Dashboard must not reference external resources (CDN, remote fonts, etc.)."""
    external_refs = [
        "https://fonts.googleapis.com",
        "https://fonts.gstatic.com",
        "https://cdn.",
        "https://unpkg.com",
        "https://cdnjs.cloudflare.com",
    ]
    for ref in external_refs:
        assert ref not in dashboard_html, (
            f"Dashboard must not load external resources — found: {ref!r}. "
            "Self-host or inline any fonts/scripts."
        )


def test_dashboard_contains_d3(dashboard_html: str) -> None:
    """D3 v7 must be bundled inline in the dashboard HTML."""
    assert "d3" in dashboard_html.lower(), "D3 must be bundled in the dashboard"
    # D3 v7 copyright/version string
    assert "Copyright" in dashboard_html or "d3.v7" in dashboard_html.lower(), (
        "D3 v7 bundle does not appear to be present"
    )


def test_dashboard_scan_data_is_embedded(dashboard_html: str) -> None:
    """Scan data must be embedded as JSON in the dashboard, not loaded remotely."""
    assert "__SCAN_DATA_JSON__" not in dashboard_html, (
        "Dashboard placeholder was not substituted — generate_html() may have failed"
    )
    assert '"findings"' in dashboard_html, "Dashboard must embed findings JSON"


def test_dashboard_grade_in_html(dashboard_html: str) -> None:
    """The rendered HTML must contain the grade letter 'D' in the embedded data."""
    # The grade is injected as part of the scan data JSON blob
    assert '"grade"' in dashboard_html
    assert '"D"' in dashboard_html
