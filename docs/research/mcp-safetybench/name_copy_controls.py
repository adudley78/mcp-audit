"""False-alarm controls for COLLIDE-002 on real tool names (STORY-0173).

Dev tool, never run in CI.  Two controls, names only:

1. MCPTox's 353 clean tools from 45 real servers, all in one session.
2. Tool names of the servers in HISTOR's record of changes: 5,000 sessions of
   5 servers drawn at random (``random.Random(173)``) from the servers with
   three or more known tool names.

Usage::

    uv run python docs/research/mcp-safetybench/name_copy_controls.py MCPTOX_DIR CHANGES_GZ
"""

from __future__ import annotations

import collections
import gzip
import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "scripts"))

import bench_poisoning as bp  # noqa: E402

from mcp_audit.analyzers import collision  # noqa: E402


def _pairs(session: dict[str, list[str]]) -> list:
    return [
        (
            bp._bench_server(name),
            bp.ServerEnumeration(
                tools=[bp._tool_info(bp.ToolDef(t, "", {})) for t in tools]
            ),
        )
        for name, tools in session.items()
    ]


def main() -> None:
    """Print the two controls as JSON."""
    files = bp.load_mcptox(sys.argv[1])
    clean = bp.clean_tools_by_server(json.loads(files["response_all.json"]))
    found = collision.detect_tool_name_squats(
        _pairs({s: [t.name for t in tools] for s, tools in clean.items()})
    )
    out: dict = {
        "mcptox_clean_one_session": {
            "servers": len(clean),
            "tools": sum(len(v) for v in clean.values()),
            "findings": len(found),
            "by_severity": dict(collections.Counter(str(f.severity) for f in found)),
        }
    }
    names: dict[str, set[str]] = collections.defaultdict(set)
    with gzip.open(sys.argv[2], "rt", encoding="utf-8") as handle:
        for line in handle:
            record = json.loads(line)
            summary = json.loads(record["summaryJson"])
            for key in ("added", "removed", "modified"):
                for tool in summary.get(key) or []:
                    name = tool.get("tool") if isinstance(tool, dict) else tool
                    if isinstance(name, str):
                        names[record["serverId"]].add(name)
    keys = sorted(k for k, v in names.items() if len(v) >= 3)
    rng = random.Random(173)  # noqa: S311 - a sample, not a secret
    sessions = with_finding = with_high = 0
    by_sev: collections.Counter[str] = collections.Counter()
    for _ in range(5000):
        pick = rng.sample(keys, 5)
        found = collision.detect_tool_name_squats(
            _pairs({k: sorted(names[k]) for k in pick})
        )
        sessions += 1
        with_finding += bool(found)
        with_high += any(str(f.severity).upper().endswith("HIGH") for f in found)
        by_sev.update(str(f.severity) for f in found)
    out["histor_random_sessions"] = {
        "servers_with_3_or_more_names": len(keys),
        "sessions": sessions,
        "sessions_with_a_finding": with_finding,
        "sessions_with_a_high_finding": with_high,
        "findings_by_severity": dict(by_sev),
    }
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
