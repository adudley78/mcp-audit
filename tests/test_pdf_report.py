"""Tests for ``mcp_audit.output.pdf`` and ``mcp-audit check --report pdf``."""

from __future__ import annotations

import hashlib
import stat
from datetime import UTC
from pathlib import Path
from unittest.mock import patch

from typer.testing import CliRunner

from mcp_audit.cli import app
from mcp_audit.models import Finding, ScanResult, ScanScore, Severity
from mcp_audit.output.pdf import PdfReportFormatter, _content_hash

runner = CliRunner()


def _story_text(flowables: list) -> str:
    """Extract all plain text from a list of reportlab flowables.

    Walks Paragraphs (which expose ``.text``) and Tables (which contain rows
    of cells that may themselves be Paragraphs) recursively.  Returns a
    single concatenated string suitable for simple ``in`` checks.
    """
    from reportlab.platypus import Paragraph, Table  # noqa: PLC0415

    parts: list[str] = []

    def _walk(items: list) -> None:
        for item in items:
            if isinstance(item, Paragraph):
                parts.append(item.getPlainText())
            elif isinstance(item, Table):
                for row in item._cellvalues:
                    _walk(row)
            elif isinstance(item, list):
                _walk(item)

    _walk(flowables)
    return " ".join(parts)


# ── Fixtures ──────────────────────────────────────────────────────────────────


def _make_finding(
    finding_id: str = "CRED-001",
    severity: Severity = Severity.HIGH,
    title: str = "Credential in config",
    server: str = "test-server",
    owasp: list[str] | None = None,
) -> Finding:
    return Finding(
        id=finding_id,
        severity=severity,
        analyzer="credentials",
        client="claude-desktop",
        server=server,
        title=title,
        description="A credential was found in the config.",
        evidence="API_KEY=sk-...",
        remediation="Remove the credential from the config.",
        owasp_mcp_top_10=owasp or ["MCP01"],
    )


def _make_score(numeric: int = 55, grade: str = "D") -> ScanScore:
    return ScanScore(
        numeric_score=numeric,
        grade=grade,
        positive_signals=[],
        deductions=[],
    )


def _clean_result() -> ScanResult:
    result = ScanResult()
    result.clients_scanned = 1
    result.servers_found = 2
    result.score = _make_score(100, "A")
    return result


def _findings_result(
    findings: list[Finding] | None = None,
    numeric: int = 55,
    grade: str = "D",
) -> ScanResult:
    result = ScanResult()
    result.clients_scanned = 1
    result.servers_found = 3
    result.findings = findings or [_make_finding()]
    result.score = _make_score(numeric, grade)
    return result


# ── Unit tests: PdfReportFormatter ────────────────────────────────────────────


class TestPdfReportFormatter:
    def test_generate_returns_non_empty_bytes(self) -> None:
        """generate() returns a non-empty bytes object."""
        result = _findings_result()
        formatter = PdfReportFormatter(result, org_name="Test Corp")
        pdf_bytes = formatter.generate()
        assert isinstance(pdf_bytes, bytes)
        assert len(pdf_bytes) > 1024  # a real PDF is always larger than 1 KB

    def test_pdf_has_valid_header(self) -> None:
        """Output begins with the PDF magic bytes %PDF."""
        result = _clean_result()
        formatter = PdfReportFormatter(result)
        pdf_bytes = formatter.generate()
        assert pdf_bytes.startswith(b"%PDF")

    def test_org_name_appears_in_story(self) -> None:
        """Org name is present in the header flowables."""
        result = _findings_result()
        formatter = PdfReportFormatter(result, org_name="Acme Security")
        story = formatter._build_story()
        all_text = _story_text(story)
        assert "Acme Security" in all_text

    def test_org_name_defaults_to_not_specified(self) -> None:
        """Empty org_name defaults to 'Not specified' in the story."""
        result = _clean_result()
        formatter = PdfReportFormatter(result, org_name="")
        assert formatter._org_name == "Not specified"
        all_text = _story_text(formatter._build_story())
        assert "Not specified" in all_text

    def test_grade_a_no_findings_body_text(self) -> None:
        """Clean scan (grade A) findings section contains 'No security issues'."""
        result = _clean_result()
        formatter = PdfReportFormatter(result)
        findings_flowables = formatter._findings_section()
        text = _story_text(findings_flowables)
        assert "No security issues" in text

    def test_findings_table_contains_finding_id(self) -> None:
        """Findings section flowables contain the finding ID."""
        finding = _make_finding(finding_id="CRED-001")
        result = _findings_result(findings=[finding])
        formatter = PdfReportFormatter(result)
        text = _story_text(formatter._findings_section())
        assert "CRED-001" in text

    def test_content_hash_matches_scan_result_json(self) -> None:
        """_content_hash() == sha256(ScanResult.model_dump_json())."""
        result = _findings_result()
        expected = hashlib.sha256(
            result.model_dump_json(by_alias=True).encode("utf-8")
        ).hexdigest()
        assert _content_hash(result) == expected

    def test_sha256_hash_used_in_formatter(self) -> None:
        """The formatter stores the content hash matching ScanResult JSON."""
        result = _findings_result()
        formatter = PdfReportFormatter(result)
        expected_hash = _content_hash(result)
        # The formatter's stored hash must match the direct computation.
        assert formatter._content_hash == expected_hash

    def test_multiple_findings_all_ids_present(self) -> None:
        """All finding IDs appear in the findings-section flowables."""
        findings = [
            _make_finding("CRED-001", Severity.HIGH, "High finding"),
            _make_finding("TRANSPORT-001", Severity.MEDIUM, "Medium finding"),
            _make_finding("SC-003", Severity.LOW, "Low finding"),
        ]
        result = _findings_result(findings=findings, numeric=40, grade="F")
        formatter = PdfReportFormatter(result)
        text = _story_text(formatter._findings_section())
        assert "CRED-001" in text
        assert "TRANSPORT-001" in text
        assert "SC-003" in text

    def test_version_in_header_story(self) -> None:
        """mcp-audit version appears in the header section flowables."""
        from mcp_audit import __version__

        result = _clean_result()
        formatter = PdfReportFormatter(result)
        header_text = _story_text(formatter._header_section())
        assert __version__ in header_text

    def test_findings_column_widths_fill_usable_width(self) -> None:
        """Column widths sum to usable_width — regression for the unit-mismatch bug.

        Previously the remainder column subtracted bare floats (inches) instead
        of points, making the table ~1.7× the page width.
        """
        from reportlab.lib.pagesizes import LETTER  # noqa: PLC0415
        from reportlab.lib.units import inch  # noqa: PLC0415
        from reportlab.platypus import Table  # noqa: PLC0415

        finding = _make_finding()
        result = _findings_result(findings=[finding])
        formatter = PdfReportFormatter(result)
        flowables = formatter._findings_section()
        # The findings Table is always the last Table in the section flowables;
        # earlier Tables belong to the section-heading widget.
        tables = [f for f in flowables if isinstance(f, Table)]
        assert len(tables) >= 2, "Expected heading table + findings table"
        findings_table = tables[-1]
        actual_total = sum(findings_table._colWidths)
        width, _ = LETTER
        usable = width - 1.5 * inch
        assert abs(actual_total - usable) < 0.1, (
            f"Column total {actual_total:.2f} pt != usable width {usable:.2f} pt"
        )

    def test_findings_table_has_five_columns(self) -> None:
        """Findings table uses 5 columns (Severity/ID merged) — not 6."""
        from reportlab.platypus import Table  # noqa: PLC0415

        finding = _make_finding()
        result = _findings_result(findings=[finding])
        formatter = PdfReportFormatter(result)
        flowables = formatter._findings_section()
        tables = [f for f in flowables if isinstance(f, Table)]
        assert len(tables) >= 2, "Expected heading table + findings table"
        assert len(tables[-1]._colWidths) == 5


# ── Integration tests: CLI check --report pdf ─────────────────────────────────


class TestCheckReportPdfCli:
    def _mock_run_scan(self) -> ScanResult:
        result = _findings_result()
        return result

    def test_pdf_created_in_cwd(self, tmp_path: Path) -> None:
        """``check --report pdf`` creates a PDF file in the current directory."""
        out_file = tmp_path / "mcp-audit-report-test.pdf"
        with patch("mcp_audit.cli.check.run_scan", return_value=self._mock_run_scan()):
            result = runner.invoke(
                app,
                ["check", "--report", "pdf", "--output-file", str(out_file)],
            )
        assert result.exit_code in (0, 1), result.output
        assert out_file.exists()
        assert out_file.stat().st_size > 0

    def test_pdf_output_file_creates_parent_dirs(self, tmp_path: Path) -> None:
        """``--output-file`` with nested path creates parent directories."""
        out_file = tmp_path / "nested" / "deep" / "report.pdf"
        assert not out_file.parent.exists()
        with patch("mcp_audit.cli.check.run_scan", return_value=self._mock_run_scan()):
            result = runner.invoke(
                app,
                ["check", "--report", "pdf", "--output-file", str(out_file)],
            )
        assert result.exit_code in (0, 1), result.output
        assert out_file.exists()

    def test_pdf_file_permissions(self, tmp_path: Path) -> None:
        """Generated PDF is written with 0o644 permissions (POSIX only).

        Windows NTFS does not honour Unix permission bits — the assertion is
        skipped there to keep the test matrix green.
        """
        import sys  # noqa: PLC0415

        out_file = tmp_path / "report.pdf"
        with patch("mcp_audit.cli.check.run_scan", return_value=self._mock_run_scan()):
            result = runner.invoke(
                app,
                ["check", "--report", "pdf", "--output-file", str(out_file)],
            )
        assert result.exit_code in (0, 1), result.output
        if sys.platform != "win32":
            mode = stat.S_IMODE(out_file.stat().st_mode)
            assert mode == 0o644

    def test_org_name_from_flag(self, tmp_path: Path) -> None:
        """``--org`` flag sets the org name; it appears in the PDF bytes."""
        out_file = tmp_path / "report.pdf"
        with patch("mcp_audit.cli.check.run_scan", return_value=self._mock_run_scan()):
            result = runner.invoke(
                app,
                [
                    "check",
                    "--report",
                    "pdf",
                    "--output-file",
                    str(out_file),
                    "--org",
                    "IBM Security",
                ],
            )
        assert result.exit_code in (0, 1), result.output
        assert b"IBM Security" in out_file.read_bytes()

    def test_org_name_from_registration(self, tmp_path: Path) -> None:
        """When ``--org`` is absent, the registered org name is used."""
        from datetime import datetime

        from mcp_audit.registration.models import RegistrationConfig

        reg = RegistrationConfig(
            name="Alice",
            org="Registered Corp",
            email="alice@example.com",
            registered_at=datetime.now(tz=UTC),
        )
        out_file = tmp_path / "report.pdf"
        with (
            patch("mcp_audit.cli.check.run_scan", return_value=self._mock_run_scan()),
            patch(
                "mcp_audit.cli.check._reg_manager.load_registration", return_value=reg
            ),
        ):
            result = runner.invoke(
                app,
                ["check", "--report", "pdf", "--output-file", str(out_file)],
            )
        assert result.exit_code in (0, 1), result.output
        assert b"Registered Corp" in out_file.read_bytes()

    def test_org_name_default_when_no_flag_and_no_registration(
        self, tmp_path: Path
    ) -> None:
        """When neither ``--org`` nor registration is present, uses 'Not specified'."""
        out_file = tmp_path / "report.pdf"
        with (
            patch("mcp_audit.cli.check.run_scan", return_value=self._mock_run_scan()),
            patch(
                "mcp_audit.cli.check._reg_manager.load_registration", return_value=None
            ),
        ):
            result = runner.invoke(
                app,
                ["check", "--report", "pdf", "--output-file", str(out_file)],
            )
        assert result.exit_code in (0, 1), result.output
        assert b"Not specified" in out_file.read_bytes()

    def test_grade_a_clean_scan_pdf(self, tmp_path: Path) -> None:
        """Grade A scan produces a valid, non-empty PDF and exits 0."""
        clean = _clean_result()
        out_file = tmp_path / "clean.pdf"
        with patch("mcp_audit.cli.check.run_scan", return_value=clean):
            result = runner.invoke(
                app,
                ["check", "--report", "pdf", "--output-file", str(out_file)],
            )
        assert result.exit_code == 0, result.output
        assert out_file.exists()
        pdf_bytes = out_file.read_bytes()
        assert pdf_bytes.startswith(b"%PDF")
        assert len(pdf_bytes) > 1024

    def test_unknown_report_format_exits_2(self, tmp_path: Path) -> None:
        """Unsupported ``--report`` value exits with code 2."""
        with patch("mcp_audit.cli.check.run_scan", return_value=self._mock_run_scan()):
            result = runner.invoke(
                app,
                ["check", "--report", "docx"],
            )
        assert result.exit_code == 2
