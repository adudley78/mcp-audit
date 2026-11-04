"""One-page-per-machine PDF for ``mcp-audit reach --report pdf`` (STORY-0145).

Reuses the page furniture of :mod:`mcp_audit.output.pdf` (brand header band,
footer, content-hash line, palette) and adds the reach body: the machine, one
block per agent with its verdict and the five answers, and the reasons.  The
body is wrapped in a shrink-to-fit frame, so one machine is always one page
however many agents it has.

Reads :meth:`MachineReach.to_dict`: strings are already redacted and home-masked,
and are escaped here for reportlab's markup parser.
"""

from __future__ import annotations

import hashlib
import io
import json

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    KeepInFrame,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from mcp_audit import __version__
from mcp_audit._paths import data_dir
from mcp_audit.output.pdf import (
    _AMBER,
    _BRAND_TEAL,
    _GREEN,
    _HEADER_HEIGHT_PT,
    _RED,
    _make_page_callback,
    _text,
)
from mcp_audit.reach.models import QUESTION_IDS, VERDICT_LABELS, MachineReach, Verdict

_BLUE = colors.HexColor("#1d4ed8")
_VERDICT_COLOR = {
    Verdict.READY.value: _GREEN,
    Verdict.NEEDS_WORK.value: _AMBER,
    Verdict.NOT_SAFE.value: _RED,
    Verdict.COULDNT_CHECK.value: _BLUE,
}
_STATUS_TEXT = {
    "pass": ("PASS", _GREEN),
    "fail": ("FAIL", _RED),
    "couldnt_check": ("COULDN'T CHECK", _BLUE),
    "info": ("INFO", colors.grey),
}
#: Longest answer / reason text in the PDF; the full text is in the JSON.
_CLIP = 260
_MAX_REASONS = 6


def _clip(text: str, limit: int = _CLIP) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _hex(color: colors.Color) -> str:
    return "#" + color.hexval()[2:]


class ReachPdfFormatter:
    """Produce the reach PDF for one machine.

    Args:
        report: The machine's :class:`MachineReach`.
        org_name: Organisation printed under the title.
    """

    def __init__(self, report: MachineReach, org_name: str = "") -> None:
        self._doc = report.to_dict()
        self._summary = report.summary_line()
        self._org = org_name.strip() or "Not specified"
        styles = getSampleStyleSheet()
        self._base = styles["Normal"]
        self._h = ParagraphStyle(
            "reach_h", parent=styles["Heading2"], textColor=colors.HexColor("#0d1117")
        )
        self._small = ParagraphStyle(
            "reach_s", parent=self._base, fontSize=7.5, leading=9.5, alignment=TA_LEFT
        )
        self._tiny = ParagraphStyle(
            "reach_t",
            parent=self._small,
            fontSize=6.5,
            leading=8,
            textColor=colors.HexColor("#4b5563"),
        )
        canonical = json.dumps(self._doc, sort_keys=True, separators=(",", ":"))
        self._hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def generate(self, compress: bool = True) -> bytes:
        """Build the PDF (always one page) and return its bytes."""
        buf = io.BytesIO()
        top = _HEADER_HEIGHT_PT + 0.2 * inch
        doc = SimpleDocTemplate(
            buf,
            pagesize=LETTER,
            leftMargin=0.75 * inch,
            rightMargin=0.75 * inch,
            topMargin=top,
            bottomMargin=0.85 * inch,
            title=f"Agent reach report — {_text(self._doc['machine']['hostname'])}",
            author=f"mcp-audit v{__version__}",
            compress=compress,
        )
        hdr = data_dir() / "header_dark.png"
        callback = _make_page_callback(
            __version__, self._hash, [1], str(hdr) if hdr.exists() else None
        )
        width = LETTER[0] - 1.5 * inch - 12
        height = LETTER[1] - top - 0.85 * inch - 12
        frame = KeepInFrame(width, height, self._story(width), mode="shrink")
        doc.build([frame], onFirstPage=callback, onLaterPages=callback)
        return buf.getvalue()

    def _story(self, width: float) -> list:
        d = self._doc
        machine = d["machine"]
        story: list = [
            Paragraph("What can the agents on this machine touch?", self._h),
            Paragraph(
                f"Organisation: {_text(self._org)} &nbsp;|&nbsp; Host:"
                f" {_text(machine['hostname'])} ({_text(machine['os'])})"
                f" &nbsp;|&nbsp; {_text(d['generated_at'])}"
                f" &nbsp;|&nbsp; mcp-audit v{_text(d['tool']['version'])}",
                self._small,
            ),
            Spacer(1, 4),
            Paragraph(f"<b>{_text(self._summary)}</b>", self._base),
            Spacer(1, 6),
        ]
        if not d["agents"]:
            story.append(Paragraph("No agents found on this machine.", self._base))
        for agent in d["agents"]:
            story.append(self._agent_block(agent, width))
            story.append(Spacer(1, 6))
        story.append(
            Paragraph(
                "Static read of settings files and one default scan; no agent was"
                " run and no live call was watched. COULDN'T CHECK means the"
                " answer is not known, never that it is fine.",
                self._tiny,
            )
        )
        return story

    def _agent_block(self, agent: dict, width: float) -> Table:
        color = _VERDICT_COLOR.get(agent["verdict"], colors.black)
        label = VERDICT_LABELS.get(Verdict(agent["verdict"]), agent["verdict"])
        head = Paragraph(
            f"<b>{_text(agent['name'])}</b> &nbsp; "
            f'<font color="{_hex(color)}"><b>{_text(label)}</b></font>'
            f" &nbsp; <font size=7>{agent['servers']} MCP server(s)</font>",
            self._base,
        )
        rows: list[list] = [[head, ""]]
        for qid in QUESTION_IDS:
            q = agent["questions"].get(qid)
            if q is None:
                continue
            tag, tag_color = _STATUS_TEXT.get(q["status"], (q["status"], colors.black))
            rows.append(
                [
                    Paragraph(
                        f'<font color="{_hex(tag_color)}"><b>{_text(tag)}</b></font>',
                        self._small,
                    ),
                    Paragraph(
                        f"<b>{_text(q['title'])}</b> {_text(_clip(q['summary']))}",
                        self._small,
                    ),
                ]
            )
        for reason in agent["reasons"][:_MAX_REASONS]:
            refs = ", ".join(reason["refs"][:4])
            tail = f" <i>({_text(_clip(refs, 120))})</i>" if refs else ""
            rows.append(
                [
                    Paragraph(_text(reason["kind"].replace("_", " ")), self._tiny),
                    Paragraph(_text(_clip(reason["text"])) + tail, self._tiny),
                ]
            )
        extra = len(agent["reasons"]) - _MAX_REASONS
        if extra > 0:
            rows.append(
                [
                    "",
                    Paragraph(
                        f"... and {extra} more reason(s) in the JSON", self._tiny
                    ),
                ]
            )
        table = Table(rows, colWidths=[78, width - 78])
        table.setStyle(
            TableStyle(
                [
                    ("SPAN", (0, 0), (1, 0)),
                    ("LINEBELOW", (0, 0), (-1, 0), 1.2, _BRAND_TEAL),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("TOPPADDING", (0, 0), (-1, -1), 2),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                    ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")),
                ]
            )
        )
        return table
