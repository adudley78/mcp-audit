"""The session checks on a set that another agent wrote blind (STORY-0174).

Dev tool, never run in CI.  ``blind_set.json`` holds 40 sessions with one
impersonating tool each and 40 sessions of honest servers.  An agent wrote it
from a description of the attack class.  It did not see Credenzo's code or
the rule of COLLIDE-003.  The text in it is invented and mundane.

For each attack session the script asks: does a session check (COLLIDE-001,
COLLIDE-002, COLLIDE-003, DELEG-001..003) name the impersonating tool, and
does a POISON-* text check fire on its description?  For each honest session
it counts the findings.

Usage::

    uv run python docs/research/copy-checks/measure_blind.py
"""

from __future__ import annotations

import collections
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "scripts"))

import bench_poisoning as bp  # noqa: E402

from mcp_audit.analyzers import collision  # noqa: E402

HERE = Path(__file__).resolve().parent


def _findings(servers: dict[str, list[dict[str, str]]]) -> list:
    pairs = [
        (
            bp._bench_server(name),
            bp.ServerEnumeration(
                tools=[
                    bp._tool_info(bp.ToolDef(t["name"], t.get("description", ""), {}))
                    for t in tools
                ]
            ),
        )
        for name, tools in servers.items()
    ]
    return (
        collision.detect_tool_collisions(pairs)
        + collision.detect_tool_name_squats(pairs)
        + collision.detect_description_copies(pairs)
        + bp._delegation.detect_delegation(pairs)
    )


def _severity(finding: object) -> str:
    return str(finding.severity).rsplit(".", 1)[-1]  # type: ignore[attr-defined]


def measure() -> dict[str, Any]:
    """Return the counts for the blind set."""
    data = json.loads((HERE / "blind_set.json").read_text(encoding="utf-8"))
    by: dict[str, collections.Counter[str]] = collections.defaultdict(
        collections.Counter
    )
    total: collections.Counter[str] = collections.Counter()
    for session in data["attack_sessions"]:
        who = session["impersonator"]
        quoted = f"'{who['tool']}'"
        hits = [
            f
            for f in _findings(session["servers"])
            if (f.tool == who["tool"] and who["server"] in f.server)
            or (f.id.startswith("COLLIDE-") and quoted in f.title)
        ]
        text = next(
            t.get("description", "")
            for t in session["servers"][who["server"]]
            if t["name"] == who["tool"]
        )
        row = by[session["strategy"]]
        for counter in (row, total):
            counter["sessions"] += 1
            counter["session_checks"] += bool(hits)
            counter["session_checks_high"] += any(_severity(f) == "HIGH" for f in hits)
            counter["text_checks"] += bool(
                bp.poison_findings(bp.ToolDef(who["tool"], text, {}))
            )
    honest: collections.Counter[str] = collections.Counter()
    for session in data["honest_sessions"]:
        found = _findings(session["servers"])
        honest["sessions"] += 1
        honest["sessions_with_a_finding"] += bool(found)
        honest["sessions_with_a_high_finding"] += any(
            _severity(f) == "HIGH" for f in found
        )
        for finding_id in {f.id for f in found}:
            honest[f"sessions_with:{finding_id}"] += 1
    return {
        "attack_sessions": dict(total),
        "attack_sessions_by_strategy": {k: dict(v) for k, v in sorted(by.items())},
        "honest_sessions": dict(sorted(honest.items())),
    }


if __name__ == "__main__":
    print(json.dumps(measure(), indent=1))
