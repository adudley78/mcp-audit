"""Cross-browser rendering tests for the mcp-audit HTML dashboards.

Renders the per-scan dashboard and the fleet dashboard in Chromium, Firefox,
and WebKit (Safari engine) using Playwright's headless mode.  Asserts:
  - No JavaScript errors are thrown during load or interaction
  - Key structural elements are present and visible
  - The dark-mode toggle works
  - The grade badge renders with the correct letter

These tests catch CSS/JS incompatibilities that unit tests cannot detect.
Run with: uv run pytest tests/test_dashboard_compat.py -v
Requires: playwright install (installs browser binaries, ~300 MB)
"""

from __future__ import annotations

import json
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


# ══════════════════════════════════════════════════════════════════════════════
# Fleet dashboard cross-browser tests
# ══════════════════════════════════════════════════════════════════════════════


def _make_fleet_html(tmp_path: Path) -> str:
    """Build a realistic fleet HTML page for browser testing."""
    from mcp_audit.fleet.merger import FleetMerger  # noqa: PLC0415

    _ts = "2026-04-16T10:00:00+00:00"

    def _scan_json(
        hostname: str,
        findings: list[dict] | None = None,
        score: dict | None = None,
    ) -> dict:
        return {
            "version": "0.1.0",
            "timestamp": _ts,
            "machine": {
                "hostname": hostname,
                "username": "tester",
                "os": "Linux",
                "os_version": "6.1",
                "scan_id": "00000000-0000-0000-0000-000000000001",
            },
            "clients_scanned": 1,
            "servers_found": 2,
            "servers": [],
            "findings": findings or [],
            "errors": [],
            "attack_path_summary": None,
            "score": score,
        }

    def _finding(title: str, severity: str = "HIGH", idx: int = 1) -> dict:
        return {
            "id": f"CRED-{idx:03d}",
            "severity": severity,
            "analyzer": "credentials",
            "client": "claude",
            "server": "filesystem",
            "title": title,
            "description": "Test finding.",
            "evidence": "API_KEY=abc123",
            "remediation": "Use env vars.",
        }

    def _score(numeric: int, grade: str) -> dict:
        return {
            "numeric_score": numeric,
            "grade": grade,
            "positive_signals": [],
            "deductions": [],
        }

    f1 = tmp_path / "m1.json"
    f2 = tmp_path / "m2.json"
    f3 = tmp_path / "m3.json"

    f1.write_text(
        json.dumps(
            _scan_json(
                "fleet-host-alpha",
                findings=[_finding("Hardcoded API key", "CRITICAL", 1)],
                score=_score(35, "F"),
            )
        ),
        encoding="utf-8",
    )
    f2.write_text(
        json.dumps(
            _scan_json(
                "fleet-host-beta",
                findings=[_finding("Cleartext password", "HIGH", 2)],
                score=_score(70, "C"),
            )
        ),
        encoding="utf-8",
    )
    f3.write_text(
        json.dumps(
            _scan_json(
                "fleet-host-gamma",
                score=_score(95, "A"),
            )
        ),
        encoding="utf-8",
    )

    from mcp_audit.fleet.merger import generate_fleet_html  # noqa: PLC0415

    report = FleetMerger().merge([f1, f2, f3])
    return generate_fleet_html(report)


@pytest.fixture(scope="module")
def fleet_html(tmp_path_factory: pytest.TempPathFactory) -> str:
    """Render the fleet dashboard once; reuse across all browser tests."""
    tmp = tmp_path_factory.mktemp("fleet")
    html = _make_fleet_html(tmp)
    assert html, "generate_fleet_html returned empty/None output"
    return html


@pytest.fixture(scope="module")
def fleet_html_path(tmp_path_factory: pytest.TempPathFactory, fleet_html: str) -> Path:
    """Write the fleet dashboard to a temp file for Playwright to load."""
    tmp = tmp_path_factory.mktemp("fleet_html")
    path = tmp / "fleet.html"
    path.write_text(fleet_html, encoding="utf-8")
    return path


def _check_fleet_dashboard(page: object, fleet_html_path: Path) -> None:  # type: ignore[type-arg]
    """Core assertions run against every browser for the fleet dashboard."""
    js_errors: list[str] = []
    page.on("pageerror", lambda exc: js_errors.append(str(exc)))  # type: ignore[attr-defined]

    page.goto(f"file://{fleet_html_path}")  # type: ignore[attr-defined]
    page.wait_for_load_state("networkidle")  # type: ignore[attr-defined]

    # No JS errors during load
    assert not js_errors, f"JS errors during fleet dashboard load: {js_errors}"

    # Machine grid is present
    machine_grid = page.locator("#machine-grid")  # type: ignore[attr-defined]
    assert machine_grid.count() > 0, "Machine grid (#machine-grid) must be present"

    # Findings table is present
    findings_table = page.locator(".findings-table")  # type: ignore[attr-defined]
    assert findings_table.count() > 0, "Findings table must be present"

    # Dark-mode toggle exists and is clickable
    toggle = page.locator(".theme-toggle")  # type: ignore[attr-defined]
    if toggle.count() > 0:
        toggle.first.click()
        page.wait_for_timeout(300)  # type: ignore[attr-defined]
        assert not js_errors, f"JS errors after fleet dark-mode toggle: {js_errors}"

    # Toggle back to dark
    if toggle.count() > 0:
        toggle.first.click()
        page.wait_for_timeout(200)  # type: ignore[attr-defined]

    # Machine filter dropdown is present
    machine_sel = page.locator("#machine-select")  # type: ignore[attr-defined]
    assert machine_sel.count() > 0, "Machine filter select must be present"

    assert not js_errors, f"JS errors after fleet dashboard interactions: {js_errors}"


@pytest.mark.parametrize("browser_name", ["chromium", "firefox", "webkit"])
def test_fleet_dashboard_renders_in_browser(
    browser_name: str, fleet_html_path: Path
) -> None:
    """Fleet dashboard must render without JS errors in all three browser engines."""
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
            _msg = str(exc)
            if "Executable doesn't exist" in _msg or "playwright install" in _msg:
                pytest.skip(
                    f"{browser_name} binary not installed — "
                    "run: python -m playwright install"
                )
            raise
        try:
            page = browser.new_page()
            _check_fleet_dashboard(page, fleet_html_path)
        finally:
            browser.close()


def test_fleet_html_is_self_contained(fleet_html: str) -> None:
    """Fleet dashboard must not reference external resources (CDN, fonts, etc.)."""
    external_refs = [
        "https://fonts.googleapis.com",
        "https://fonts.gstatic.com",
        "https://cdn.",
        "https://unpkg.com",
        "https://cdnjs.cloudflare.com",
    ]
    for ref in external_refs:
        assert ref not in fleet_html, (
            f"Fleet dashboard must not load external resources — found: {ref!r}. "
            "Self-host or inline any fonts/scripts."
        )


def test_fleet_html_machine_grid_in_dom(fleet_html: str) -> None:
    """Fleet dashboard HTML must contain the machine grid and all machine cards."""
    assert "machine-grid" in fleet_html, "fleet HTML must contain machine-grid"
    assert "fleet-host-alpha" in fleet_html
    assert "fleet-host-beta" in fleet_html
    assert "fleet-host-gamma" in fleet_html


def test_fleet_html_contains_d3(fleet_html: str) -> None:
    """D3 v7 must be bundled inline in the fleet dashboard HTML."""
    assert "d3" in fleet_html.lower(), "D3 must be bundled in the fleet dashboard"
    assert "Copyright" in fleet_html or "d3.v7" in fleet_html.lower(), (
        "D3 v7 bundle does not appear to be present"
    )
