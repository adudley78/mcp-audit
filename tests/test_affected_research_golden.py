"""Golden regression for ``affected`` research-record rows (STORY-0142).

The JSON ``affected`` prints for the three research records that existed
before ``introduced``/``platforms`` were added, under fixed harness fixtures,
must stay byte-identical.  Regenerate deliberately with
``MCP_AUDIT_UPDATE_GOLDEN=1 pytest tests/test_affected_research_golden.py``
and review the diff: a change here is a change in what users are told.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from mcp_audit import harness_versions as hv
from mcp_audit.affected import match as m
from mcp_audit.affected.query import parse_query
from mcp_audit.affected.render import render_json
from mcp_audit.harness_versions import HarnessScan
from mcp_audit.registry.research import load_research_records

GOLDEN = Path(__file__).parent / "golden" / "affected_research_rows.json"
RECORDS = (
    "x_MCPRS-4ad8c07d80d7",  # Plugin4Shell (4 products, 2 with fixes, 2 checks)
    "x_MCPRS-32fc646f6f96",  # Context7 (fixed-server-side)
    "x_MCPRS-c83726dd3047",  # Claude Code, unfixed
)


def _inst(
    harness: str,
    product: str,
    version: str,
    kind: str = "npm",
    *,
    target: bool = False,
) -> hv.HarnessInstall:
    return hv.HarnessInstall(
        harness,
        product,
        version,
        f"/fixture/{harness}/{version}",
        kind,
        launcher_target=target,
    )


def _scenarios() -> dict[str, HarnessScan]:
    cc, cx = ("claude-code", "Claude Code"), ("codex", "Codex")
    return {
        "none-installed": HarnessScan(),
        "below-the-fix": HarnessScan(
            installs=[_inst(*cc, "2.1.100"), _inst(*cx, "0.100.0")]
        ),
        "at-or-above-the-fix": HarnessScan(
            installs=[_inst(*cc, "2.1.179"), _inst(*cx, "0.146.0")]
        ),
        "native-launcher": HarnessScan(
            installs=[
                _inst(*cc, "2.1.100", "native"),
                _inst(*cc, "2.1.200", "native", target=True),
            ]
        ),
    }


def render_all() -> str:
    index = load_research_records()
    out: list[str] = []
    for name, scan in _scenarios().items():
        for rid in RECORDS:
            record = index.lookup(rid)
            assert record is not None
            notes: list[str] = []
            report = m.Report(query=parse_query(rid))
            report.rows = m.research_rows(record, lambda: [], notes, scan)
            report.notes = notes
            out.append(f"### {name} / {rid}\n{render_json(report)}")
    return "".join(out)


def test_existing_records_output_is_byte_identical() -> None:
    actual = render_all()
    if os.environ.get("MCP_AUDIT_UPDATE_GOLDEN") == "1":
        GOLDEN.write_text(actual, encoding="utf-8")
        pytest.skip("golden regenerated")
    assert GOLDEN.read_text(encoding="utf-8") == actual
