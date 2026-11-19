"""Credenzo on MCP Security Bench, with controls on real tools (STORY-0174).

Dev tool, never run in CI.  It reads the benchmark's server sources with
``ast`` and never runs them.  It commits no benchmark text: the output is
counts.

MSB (Zhang et al., arXiv 2510.15994, https://github.com/dongsenzhang/MSB, MIT)
holds an honest server and attack copies of it for each of six servers.  For
each tool that an attack file adds or changes, the script builds a session of
the honest server and one more server that holds the tool, and runs:

- the POISON-* text checks on the tool,
- the checks that read the session: COLLIDE-001, COLLIDE-002, COLLIDE-003 and
  DELEG-001..003.

Controls for COLLIDE-003 (it needs real descriptions):

1. MSB's six honest servers in one session.
2. MCPTox's 353 clean tools from 45 servers in one session.
3. HISTOR's record of changes: the newest description of each tool that the
   record shows a change for.  5,000 sessions of five servers drawn at random
   (``random.Random(174)``), and every server in one session.

Usage::

    uv run python docs/research/msb/measure.py MSB_REPO MCPTOX_DIR CHANGES_GZ
"""

from __future__ import annotations

import ast
import collections
import gzip
import json
import random
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "scripts"))

import bench_poisoning as bp  # noqa: E402

from mcp_audit.analyzers import collision  # noqa: E402

ATTACK_DIR = "data/tools/attack_tools"
Session = dict[str, list[tuple[str, str]]]


def tools_of(path: Path) -> dict[str, str] | None:
    """Return ``{tool name: static description}`` of one server source."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    except SyntaxError:
        return None
    out: dict[str, str] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        for dec in node.decorator_list:
            call = dec if isinstance(dec, ast.Call) else None
            target = call.func if call else dec
            if not (isinstance(target, ast.Attribute) and target.attr == "tool"):
                continue
            name, text = node.name, ast.get_docstring(node) or ""
            for kw in call.keywords if call else []:
                if kw.arg == "name" and isinstance(kw.value, ast.Constant):
                    name = str(kw.value.value)
                if kw.arg == "description":
                    text = " ".join(
                        n.value
                        for n in ast.walk(kw.value)
                        if isinstance(n, ast.Constant) and isinstance(n.value, str)
                    )
            out[name] = text
    return out


def load_msb(root: Path) -> dict[str, dict[str, Any]]:
    """Return each server's honest tools and the tools each attack file changes."""
    out: dict[str, dict[str, Any]] = {}
    for config in sorted((root / ATTACK_DIR).glob("*/*/mcp_config.json")):
        files = sorted(config.parent.glob("*.py"))
        stems = {p.stem.split("-", 1)[0] for p in files if "-" in p.stem}
        base = [p for p in files if "-" not in p.stem and p.stem in stems]
        if len(base) != 1:
            continue
        honest = tools_of(base[0]) or {}
        attacks: dict[str, dict[str, str]] = {}
        for path in files:
            if "-" not in path.stem:
                continue
            found = tools_of(path)
            if found is not None:
                attacks[path.stem.split("-", 1)[1]] = {
                    n: t for n, t in found.items() if honest.get(n) != t
                }
        out[f"{config.parent.parent.name}/{config.parent.name}"] = {
            "honest": honest,
            "attacks": attacks,
        }
    return out


def _pairs(session: Session) -> list:
    return [
        (
            bp._bench_server(name),
            bp.ServerEnumeration(
                tools=[bp._tool_info(bp.ToolDef(n, t, {})) for n, t in tools]
            ),
        )
        for name, tools in session.items()
    ]


def session_findings(session: Session) -> list:
    """Run each check that reads the session."""
    pairs = _pairs(session)
    return (
        collision.detect_tool_collisions(pairs)
        + collision.detect_tool_name_squats(pairs)
        + collision.detect_description_copies(pairs)
        + bp._delegation.detect_delegation(pairs)
    )


def _high(severity: object) -> bool:
    return str(severity).upper().rsplit(".", 1)[-1] in {"HIGH", "CRITICAL"}


def measure_attacks(msb: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Count detections for each attack file's tools."""
    out: dict[str, collections.Counter[str]] = {}
    for server, entry in msb.items():
        honest = list(entry["honest"].items())
        for kind, changed in entry["attacks"].items():
            row = out.setdefault(kind, collections.Counter())
            for name, text in changed.items():
                found = [
                    f
                    for f in session_findings(
                        {server: honest, "attacker": [(name, text)]}
                    )
                    if (f.tool == name and f.server == "attacker")
                    or (f.id == "COLLIDE-001" and f"'{name}'" in f.title)
                ]
                texts = bp.poison_findings(bp.ToolDef(name, text, {}))
                row["tools"] += 1
                row["text_checks"] += bool(texts)
                row["session_checks"] += bool(found)
                row["either"] += bool(texts or found)
                row["either_high_or_above"] += any(
                    s in bp.HIGH_OR_ABOVE for _, s in texts
                ) or any(_high(f.severity) for f in found)
                for finding_id in {f.id for f in found}:
                    row[f"by_id:{finding_id}"] += 1
    return {k: dict(sorted(v.items())) for k, v in sorted(out.items())}


def _copies(session: Session) -> collections.Counter[str]:
    found = collision.detect_description_copies(_pairs(session))
    return collections.Counter(str(f.severity).rsplit(".", 1)[-1] for f in found)


def histor_descriptions(path: str) -> dict[str, dict[str, str]]:
    """Return ``{server: {tool: newest description}}`` from the record."""
    out: dict[str, dict[str, str]] = collections.defaultdict(dict)
    with gzip.open(path, "rt", encoding="utf-8") as handle:
        for line in handle:
            record = json.loads(line)
            for tool in json.loads(record["summaryJson"]).get("modified") or []:
                if not isinstance(tool, dict):
                    continue
                parts = (tool.get("fields") or {}).get("description")
                if isinstance(parts, list):
                    out[record["serverId"]][str(tool.get("tool"))] = "".join(
                        str(p[1])
                        for p in parts
                        if isinstance(p, list) and len(p) == 2 and p[0] in "=+"
                    )
    return out


def main() -> None:
    """Print the counts as JSON."""
    msb = load_msb(Path(sys.argv[1]))
    out: dict[str, Any] = {
        "msb_servers": {k: {"honest_tools": len(v["honest"])} for k, v in msb.items()},
        "msb_attacks": measure_attacks(msb),
    }
    honest = {k: list(v["honest"].items()) for k, v in msb.items()}
    out["msb_honest_one_session"] = {
        "session_findings": len(session_findings(honest)),
        "text_findings": sum(
            bool(bp.poison_findings(bp.ToolDef(n, t, {})))
            for tools in honest.values()
            for n, t in tools
        ),
    }
    files = bp.load_mcptox(sys.argv[2])
    clean = bp.clean_tools_by_server(json.loads(files["response_all.json"]))
    out["mcptox_clean_one_session"] = {
        "servers": len(clean),
        "tools": sum(len(v) for v in clean.values()),
        "collide_003": dict(
            _copies(
                {
                    s: [(t.name, t.description or "") for t in v]
                    for s, v in clean.items()
                }
            )
        ),
    }
    described = histor_descriptions(sys.argv[3])
    keys = sorted(k for k, v in described.items() if len(v) >= 2)
    rng = random.Random(174)  # noqa: S311 - a sample, not a secret
    with_copy = with_high = 0
    for _ in range(5000):
        found = _copies({k: list(described[k].items()) for k in rng.sample(keys, 5)})
        with_copy += bool(found)
        with_high += bool(found.get("HIGH"))
    whole = collision.detect_description_copies(
        _pairs({k: list(v.items()) for k, v in described.items()})
    )
    out["histor"] = {
        "servers_with_a_described_tool": len(described),
        "described_tools": sum(len(v) for v in described.values()),
        "random_sessions": 5000,
        "random_sessions_with_collide_003": with_copy,
        "random_sessions_with_collide_003_high": with_high,
        "every_server_in_one_session": {
            "findings_capped_at": collision.MAX_DESCRIPTION_COPY_FINDINGS,
            "findings": len(whole),
        },
    }
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
