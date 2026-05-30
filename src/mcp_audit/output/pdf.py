"""PDF compliance report formatter for ``mcp-audit check --report pdf``.

Produces a Letter-size PDF containing:
- Header: org name, scan timestamp, mcp-audit version
- Executive summary: letter grade (colour-coded), numeric score, finding counts
- Findings table: severity, ID, title, server, OWASP category, remediation hint
- Footer on each page: mcp-audit credit, page numbers
- Content hash on the last page: sha256 of the serialised ScanResult JSON

SHA-256 approach: hash ``ScanResult.model_dump_json()`` bytes, not the PDF
binary itself.  This avoids a circular dependency (hashing the PDF would require
knowing the hash before building it) and is equally auditable — an auditor can
re-run the scan, export JSON, and reproduce the hash independently.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.lib.utils import ImageReader
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from mcp_audit import __version__
from mcp_audit._paths import data_dir
from mcp_audit.models import Severity

if TYPE_CHECKING:
    import io

    from mcp_audit.models import Finding, ScanResult

# ── Palette (matches terminal output colours) ─────────────────────────────────

_GREEN = colors.HexColor("#2d7a2d")
_AMBER = colors.HexColor("#b45309")
_RED = colors.HexColor("#b91c1c")

# Brand accent — used for section-heading underlines and divider rules.
_BRAND_TEAL = colors.HexColor("#00C9B1")

# Header band height (points).  The PNG is 1024×311; dividing the height by 4
# yields ~78 pt, which fills the full Letter width at a comfortable visual weight.
_HEADER_HEIGHT_PT: int = 78

_SEV_BG: dict[Severity, colors.Color] = {
    Severity.CRITICAL: colors.HexColor("#fef2f2"),  # very light red
    Severity.HIGH: colors.HexColor("#fff7ed"),  # very light orange
    Severity.MEDIUM: colors.HexColor("#fefce8"),  # very light yellow
    Severity.LOW: colors.HexColor("#eff6ff"),  # very light blue
    Severity.INFO: colors.HexColor("#f9fafb"),  # very light grey
}

_SEVERITY_ORDER: list[Severity] = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]


# Remediation hints re-used from output/check.py (kept in sync manually).
# Import lazily to avoid a circular-module dependency at PDF formatter import
# time (check.py imports models, models has no dep on output, so it is safe,
# but keeping the import local makes the dependency explicit).
def _get_remediation_hint(finding: Finding) -> str:
    """Return a short plain-English remediation hint for *finding*."""
    from mcp_audit.output.check import _remediation_hint  # noqa: PLC0415

    return _remediation_hint(finding)


def _owasp_label(finding: Finding) -> str:
    """Return a compact OWASP category string for the findings table."""
    if not finding.owasp_mcp_top_10:
        return "—"
    from mcp_audit.owasp_mcp import OWASP_MCP_TOP_10  # noqa: PLC0415

    parts = []
    for code in finding.owasp_mcp_top_10:
        name = OWASP_MCP_TOP_10.get(code, code)
        # Short label: "MCP03 Tool Poisoning"
        parts.append(f"{code} {name}")
    return "; ".join(parts)


def _grade_color(grade: str) -> colors.Color:
    """Return the reportlab Color for a letter grade."""
    if grade in ("A", "B"):
        return _GREEN
    if grade == "C":
        return _AMBER
    return _RED


def _content_hash(result: ScanResult) -> str:
    """Compute the SHA-256 of the serialised ScanResult JSON.

    The hash covers the scan *data*, not the PDF binary, avoiding any
    circular dependency.  An auditor can reproduce it by running:
        echo -n '<json>' | sha256sum
    """
    json_bytes = result.model_dump_json(by_alias=True).encode("utf-8")
    return hashlib.sha256(json_bytes).hexdigest()


# ── Page-level callbacks (header image + footer) ───────────────────────────────


def _make_page_callback(
    version: str,
    content_hash: str,
    total_pages_ref: list[int],
    header_path: str | None,
) -> object:
    """Return a canvas callback that draws the brand header and footer on every page.

    Args:
        version: mcp-audit version string embedded in the footer credit line.
        content_hash: SHA-256 hex digest printed on the last page.
        total_pages_ref: Single-element list whose value is updated after the
            first build pass so the last-page hash line is positioned correctly.
        header_path: Absolute path to ``header_dark.png``, or ``None`` when the
            file is absent (header is silently skipped so tests stay fast).
    """
    _img: ImageReader | None = None
    if header_path is not None:
        try:
            _img = ImageReader(header_path)
        except Exception:
            _img = None

    def _draw(canvas, doc) -> None:  # type: ignore[no-untyped-def]
        page_num = canvas.getPageNumber()
        width, height = doc.pagesize
        footer_y = 0.4 * inch

        canvas.saveState()

        # Brand header band — dark background fills the full page width; the
        # logo is drawn on top at the correct aspect ratio for _HEADER_HEIGHT_PT,
        # centred horizontally so it doesn't appear squashed.
        if _img is not None:
            canvas.setFillColor(colors.HexColor("#0d1117"))
            canvas.rect(
                0,
                height - _HEADER_HEIGHT_PT,
                width,
                _HEADER_HEIGHT_PT,
                fill=1,
                stroke=0,
            )
            img_px_w, img_px_h = _img.getSize()
            natural_w = _HEADER_HEIGHT_PT * (img_px_w / img_px_h)
            x_offset = (width - natural_w) / 2
            canvas.drawImage(
                _img,
                x=x_offset,
                y=height - _HEADER_HEIGHT_PT,
                width=natural_w,
                height=_HEADER_HEIGHT_PT,
                preserveAspectRatio=True,
                mask="auto",
            )

        # Footer credit (two lines) + page number
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(colors.HexColor("#6b7280"))
        canvas.drawString(
            0.75 * inch,
            footer_y + 0.10 * inch,
            f"Generated by mcp-audit v{version} — open-source MCP security scanner",
        )
        canvas.drawString(
            0.75 * inch,
            footer_y,
            "https://github.com/mcp-audit/mcp-audit-scanner",
        )
        canvas.drawRightString(
            width - 0.75 * inch,
            footer_y,
            f"Page {page_num}",
        )

        # Content hash on the last page only — above the two-line footer.
        total = total_pages_ref[0]
        if total > 0 and page_num == total:
            canvas.setFont("Courier", 6.5)
            canvas.drawString(
                0.75 * inch,
                footer_y + 0.28 * inch,
                f"Content hash: sha256:{content_hash}",
            )

        canvas.restoreState()

    return _draw


# ── Main formatter ─────────────────────────────────────────────────────────────


class PdfReportFormatter:
    """Produce a compliance PDF from a completed :class:`~mcp_audit.models.ScanResult`.

    Args:
        result: The completed scan result from the scan pipeline.
        org_name: Organisation name printed in the PDF header.  Defaults to
            ``"Not specified"`` when falsy.

    Usage::

        formatter = PdfReportFormatter(result, org_name="Acme Corp")
        pdf_bytes = formatter.generate()
        Path("report.pdf").write_bytes(pdf_bytes)
    """

    def __init__(self, result: ScanResult, org_name: str = "") -> None:
        self._result = result
        self._org_name = org_name.strip() or "Not specified"
        self._version = __version__
        self._styles = getSampleStyleSheet()
        self._content_hash = _content_hash(result)

    def generate(self, compress: bool = True) -> bytes:
        """Build the PDF and return its raw bytes.

        Args:
            compress: When ``True`` (default), compress content streams for
                smaller file size.  Set ``False`` in tests to keep content
                readable as plain ASCII so that text assertions work on the
                raw PDF bytes.

        Returns:
            A ``bytes`` object containing a valid PDF document.
        """
        import io  # noqa: PLC0415

        # topMargin must accommodate the brand header band on every page.
        _top_margin = _HEADER_HEIGHT_PT + 0.2 * inch

        def _make_doc(buf: io.BytesIO) -> SimpleDocTemplate:
            return SimpleDocTemplate(
                buf,
                pagesize=LETTER,
                leftMargin=0.75 * inch,
                rightMargin=0.75 * inch,
                topMargin=_top_margin,
                bottomMargin=0.85 * inch,  # leave room for footer
                title=f"MCP Security Compliance Report \u2014 {self._org_name}",
                author=f"mcp-audit v{self._version}",
                compress=compress,
            )

        # Resolve the header image path once; silently absent → header skipped.
        _hdr = data_dir() / "header_dark.png"
        header_path: str | None = str(_hdr) if _hdr.exists() else None

        # total_pages_ref is a mutable list so the page callback (defined
        # before build() runs) can read the final page count after build().
        total_pages_ref: list[int] = [0]

        # First pass: determine actual page count.
        buf1 = io.BytesIO()
        doc1 = _make_doc(buf1)
        page_cb = _make_page_callback(
            self._version, self._content_hash, total_pages_ref, header_path
        )
        doc1.build(self._build_story(), onFirstPage=page_cb, onLaterPages=page_cb)
        total_pages_ref[0] = doc1.page  # type: ignore[attr-defined]

        # Second pass: rebuild with the correct page count so the hash line
        # is rendered on the last page only.
        buf2 = io.BytesIO()
        doc2 = _make_doc(buf2)
        page_cb2 = _make_page_callback(
            self._version, self._content_hash, total_pages_ref, header_path
        )
        doc2.build(self._build_story(), onFirstPage=page_cb2, onLaterPages=page_cb2)

        return buf2.getvalue()

    # ── Story builders ────────────────────────────────────────────────────────

    def _build_story(self) -> list:
        """Assemble the reportlab flowable list for this report."""
        story: list = []
        story.extend(self._header_section())
        story.append(Spacer(1, 0.2 * inch))
        story.extend(self._executive_summary_section())
        story.append(Spacer(1, 0.25 * inch))
        story.extend(self._findings_section())
        return story

    def _style(self, name: str, **kwargs) -> ParagraphStyle:  # type: ignore[no-untyped-def]
        """Clone a base style with overrides."""
        base = self._styles[name]
        return ParagraphStyle(name + "_custom", parent=base, **kwargs)

    def _section_heading(self, text: str) -> list:
        """Return a section heading flowable with a teal brand-accent underline rule.

        Args:
            text: Heading text to display.

        Returns:
            A two-element list: a Table (heading + LINEBELOW in ``_BRAND_TEAL``)
            followed by a small ``Spacer``.
        """
        width, _ = LETTER
        usable_width = width - 1.5 * inch
        heading_style = self._style(
            "Heading2",
            fontSize=12,
            textColor=colors.HexColor("#111827"),
            spaceAfter=0,
            spaceBefore=4,
        )
        heading_table = Table(
            [[Paragraph(text, heading_style)]],
            colWidths=[usable_width],
        )
        heading_table.setStyle(
            TableStyle(
                [
                    ("LINEBELOW", (0, 0), (-1, -1), 1.5, _BRAND_TEAL),
                    ("TOPPADDING", (0, 0), (-1, -1), 0),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ("LEFTPADDING", (0, 0), (-1, -1), 0),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 0),
                ]
            )
        )
        return [heading_table, Spacer(1, 0.08 * inch)]

    def _header_section(self) -> list:
        """Return the report header flowables."""
        width, _ = LETTER
        usable_width = width - 1.5 * inch

        title_style = self._style(
            "Title",
            fontSize=18,
            textColor=colors.HexColor("#111827"),
            spaceAfter=4,
            alignment=TA_LEFT,
        )
        subtitle_style = self._style(
            "Normal",
            fontSize=9,
            textColor=colors.HexColor("#6b7280"),
            spaceAfter=2,
            leading=13,
        )

        now = datetime.now(tz=UTC).isoformat(timespec="seconds")

        items = [
            Paragraph("MCP Security Compliance Report", title_style),
            Paragraph(f"Organisation: {self._org_name}", subtitle_style),
            Paragraph(f"Scan timestamp: {now}", subtitle_style),
            Paragraph(f"mcp-audit version: {self._version}", subtitle_style),
        ]

        # Horizontal rule under the header — teal brand accent.
        rule_data = [[""]]
        rule_style = TableStyle(
            [
                ("LINEBELOW", (0, 0), (-1, -1), 1.5, _BRAND_TEAL),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
        rule_table = Table(rule_data, colWidths=[usable_width])
        rule_table.setStyle(rule_style)
        items.append(rule_table)
        return items

    def _executive_summary_section(self) -> list:
        """Return the executive summary flowables."""
        result = self._result
        grade = result.score.grade if result.score else "?"
        score_num = result.score.numeric_score if result.score else 0
        grade_color = _grade_color(grade)

        items: list = self._section_heading("Executive Summary")

        # Grade badge table — grade in large coloured text, score alongside
        grade_style = ParagraphStyle(
            "grade_big",
            fontSize=36,
            fontName="Helvetica-Bold",
            textColor=grade_color,
            alignment=TA_CENTER,
            leading=40,
        )
        score_label_style = ParagraphStyle(
            "score_label",
            fontSize=10,
            textColor=colors.HexColor("#374151"),
            alignment=TA_CENTER,
            leading=14,
        )

        grade_cell = Paragraph(grade, grade_style)
        score_cell = Paragraph(f"Score: {score_num}/100", score_label_style)

        # Finding counts by severity
        counts: dict[Severity, int] = dict.fromkeys(_SEVERITY_ORDER, 0)
        for f in result.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        total = len(result.findings)
        servers = result.servers_found if hasattr(result, "servers_found") else 0

        immediate = counts[Severity.CRITICAL] + counts[Severity.HIGH]
        if total == 0:
            verdict = "No security issues detected. Configuration looks clean."
        else:
            s_findings = "finding" if total == 1 else "findings"
            s_servers = "server" if servers == 1 else "servers"
            verdict = f"{total} {s_findings} detected across {servers} {s_servers}."
            if immediate > 0:
                s_imm = "requires" if immediate == 1 else "require"
                verdict += f" {immediate} {s_imm} immediate attention."

        verdict_style = self._style(
            "Normal",
            fontSize=10,
            textColor=colors.HexColor("#374151"),
            leading=15,
        )
        verdict_para = Paragraph(verdict, verdict_style)

        # Severity count row
        count_style = ParagraphStyle(
            "count_cell",
            fontSize=9,
            alignment=TA_CENTER,
            leading=12,
        )

        count_row_data = [
            [
                Paragraph(
                    f"<font color='#b91c1c' fontName='Helvetica-Bold'>"
                    f"CRITICAL: {counts[Severity.CRITICAL]}</font>",
                    count_style,
                ),
                Paragraph(
                    f"<font color='#c2410c' fontName='Helvetica-Bold'>"
                    f"HIGH: {counts[Severity.HIGH]}</font>",
                    count_style,
                ),
                Paragraph(
                    f"<font color='#a16207'>MEDIUM: {counts[Severity.MEDIUM]}</font>",
                    count_style,
                ),
                Paragraph(
                    f"<font color='#1d4ed8'>LOW: {counts[Severity.LOW]}</font>",
                    count_style,
                ),
                Paragraph(
                    f"<font color='#374151'>INFO: {counts[Severity.INFO]}</font>",
                    count_style,
                ),
            ]
        ]

        width, _ = LETTER
        usable = width - 1.5 * inch
        col_w = usable / 5

        count_table = Table(count_row_data, colWidths=[col_w] * 5)
        count_table.setStyle(
            TableStyle(
                [
                    ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#f3f4f6")),
                    ("TOPPADDING", (0, 0), (-1, -1), 7),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                    ("BACKGROUND", (0, 0), (0, 0), colors.HexColor("#fef2f2")),
                    ("BACKGROUND", (1, 0), (1, 0), colors.HexColor("#fff7ed")),
                    ("BACKGROUND", (2, 0), (2, 0), colors.HexColor("#fefce8")),
                    ("BACKGROUND", (3, 0), (3, 0), colors.HexColor("#eff6ff")),
                    ("BACKGROUND", (4, 0), (4, 0), colors.HexColor("#f9fafb")),
                ]
            )
        )

        summary_data = [[grade_cell, score_cell]]
        summary_table = Table(summary_data, colWidths=[1.2 * inch, usable - 1.2 * inch])
        summary_table.setStyle(
            TableStyle(
                [
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("LEFTPADDING", (0, 0), (0, 0), 4),
                    ("RIGHTPADDING", (0, 0), (0, 0), 12),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ]
            )
        )

        items.append(summary_table)
        items.append(Spacer(1, 0.1 * inch))
        items.append(verdict_para)
        items.append(Spacer(1, 0.1 * inch))
        items.append(count_table)
        return items

    def _findings_section(self) -> list:
        """Return the findings table flowables."""
        items: list = self._section_heading("Findings")

        findings = sorted(
            self._result.findings,
            key=lambda f: _SEVERITY_ORDER.index(f.severity),
        )

        if not findings:
            no_findings_style = self._style(
                "Normal",
                fontSize=10,
                textColor=_GREEN,
                leading=14,
            )
            items.append(
                Paragraph(
                    "No security issues found. Your MCP configuration looks clean.",
                    no_findings_style,
                )
            )
            return items

        # Table header
        header_style = ParagraphStyle(
            "th",
            fontSize=8,
            fontName="Helvetica-Bold",
            textColor=colors.HexColor("#111827"),
            leading=11,
        )
        cell_style = ParagraphStyle(
            "td",
            fontSize=7.5,
            textColor=colors.HexColor("#374151"),
            leading=10,
        )
        width, _ = LETTER
        usable = width - 1.5 * inch
        # Five columns: Severity/ID (merged two-line), Title, Server, OWASP,
        # Remediation.  All fixed widths are in points (n * inch); the remainder
        # for Remediation subtracts the fixed total in points — not bare floats.
        _fixed_cols = (1.1 + 1.75 + 1.0 + 1.35) * inch
        col_widths = [
            1.1 * inch,  # Severity / ID (two-line merged cell)
            1.75 * inch,  # Title
            1.0 * inch,  # Server
            1.35 * inch,  # OWASP
            usable - _fixed_cols,  # Remediation (remainder)
        ]

        header_row = [
            Paragraph("Severity / ID", header_style),
            Paragraph("Title", header_style),
            Paragraph("Server", header_style),
            Paragraph("OWASP Category", header_style),
            Paragraph("Remediation", header_style),
        ]
        table_data = [header_row]

        ts_commands: list = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f3f4f6")),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e5e7eb")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("FONTSIZE", (0, 0), (-1, 0), 8),
        ]

        # Inline hex colours for severity badges — must use # + 6-digit hex.
        _sev_hex: dict[Severity, str] = {
            Severity.CRITICAL: "#b91c1c",
            Severity.HIGH: "#c2410c",
            Severity.MEDIUM: "#a16207",
            Severity.LOW: "#1d4ed8",
            Severity.INFO: "#374151",
        }

        sev_id_style = ParagraphStyle(
            "sev_id",
            fontSize=7.5,
            leading=10,
            alignment=TA_CENTER,
        )

        for row_idx, finding in enumerate(findings, start=1):
            sev = finding.severity
            sev_bg = _SEV_BG[sev]
            sev_color_hex = _sev_hex[sev]

            # Two-line merged cell: severity badge on top, ID in smaller grey text.
            sev_id_para = Paragraph(
                f"<font color='{sev_color_hex}' fontName='Helvetica-Bold'>"
                f"{sev.value}</font><br/>"
                f"<font color='#6b7280' fontSize='6.5'>{finding.id}</font>",
                sev_id_style,
            )
            owasp_text = _owasp_label(finding)
            hint = _get_remediation_hint(finding)

            row = [
                sev_id_para,
                Paragraph(finding.title, cell_style),
                Paragraph(finding.server or "—", cell_style),
                Paragraph(owasp_text, cell_style),
                Paragraph(hint, cell_style),
            ]
            table_data.append(row)

            # Severity background in the first (Severity/ID) column only.
            ts_commands.append(("BACKGROUND", (0, row_idx), (0, row_idx), sev_bg))
            # Alternate row shading for readability.
            if row_idx % 2 == 0:
                ts_commands.append(
                    (
                        "BACKGROUND",
                        (1, row_idx),
                        (-1, row_idx),
                        colors.HexColor("#fafafa"),
                    )
                )

        table = Table(table_data, colWidths=col_widths, repeatRows=1)
        table.setStyle(TableStyle(ts_commands))
        items.append(table)
        return items
