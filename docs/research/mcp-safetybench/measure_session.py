"""Run Credenzo's session checks (DELEG-*, COLLIDE-002) on MCP-SafetyBench.

Dev tool, never run in CI.  ``measure.py`` in this folder checks each
poisoned description alone, the way a text scanner does.  This script puts
each poisoned tool in a session with the servers of its task domain, the way
``credenzo scan --connect`` sees it, and runs the delegation checks
(``analyzers/delegation.detect_delegation``) too.

Usage::

    uv run python docs/research/mcp-safetybench/measure_session.py PATH

What the session holds.  Each domain folder has a YAML file that names its
servers.  For the servers whose source is in the benchmark repository, the
script reads the tool names from the source (names only; the descriptions
are left empty).  ``filesystem`` and ``calculator`` are not in the
repository and are left out, so a missing tool can only lower the counts.

A modified tool (``mcp_server_modifications``) stays on its own server, with
its sibling tools.  An added tool (``mcp_server_additions``) goes on a server
of its own.  When no server lists the modified tool's name, it also goes on a
server of its own (counted in ``modified_tool_owner_unknown``).
"""

from __future__ import annotations

import argparse
import collections
import json
import re
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "scripts"))

import bench_poisoning as bp  # noqa: E402

from mcp_audit.analyzers import collision  # noqa: E402

CONFIG_DIR = "mcpuniverse/benchmark/configs/test"


def _entries(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    return []


SERVERS_DIR = "mcpuniverse/mcp/servers"
#: YAML server name -> folder under ``SERVERS_DIR``.
SERVER_FOLDERS = {
    "yfinance": "yahoo_finance",
    "google-search": "google_search",
    "google-maps": "google_maps",
    "fetch": "url_fetch",
}
NOT_SERVERS = {"ReAct-agent", "gpt-4o", "llm-1"}
_TOOL_DEF = re.compile(
    r"@\w+(?:\.\w+)*\.tool\([^)]*\)\s*(?:async\s+)?def\s+(\w+)"
    r"|Tool\(\s*name\s*=\s*[\"']([\w-]+)[\"']"
)


def server_tools(root: Path) -> dict[str, list[str]]:
    """Return ``{server folder: tool names}`` read from the server sources."""
    out: dict[str, list[str]] = {}
    for folder in sorted((root / SERVERS_DIR).iterdir()):
        if not folder.is_dir():
            continue
        names: set[str] = set()
        for path in folder.rglob("*.py"):
            text = path.read_text(encoding="utf-8", errors="replace")
            names.update(a or b for a, b in _TOOL_DEF.findall(text))
        out[folder.name] = sorted(names)
    return out


def domain_servers(root: Path, tools: dict[str, list[str]]) -> dict[str, list[str]]:
    """Return ``{domain: server folders}`` from the domain YAML files."""
    out: dict[str, list[str]] = {}
    for path in sorted((root / CONFIG_DIR).glob("*.yaml")):
        names = set(re.findall(r"name:\s*([\w-]+)", path.read_text(encoding="utf-8")))
        folders = {
            SERVER_FOLDERS.get(n, n.replace("-", "_")) for n in names - NOT_SERVERS
        }
        out[path.stem] = sorted(f for f in folders if tools.get(f))
    return out


def load(root: Path) -> tuple[list[dict[str, Any]], dict[str, set[str]]]:
    """Return the distinct poisoned tools and each domain's tool names."""
    cases: dict[str, dict[str, Any]] = {}
    inventory: dict[str, set[str]] = collections.defaultdict(set)
    base = root / CONFIG_DIR
    for path in sorted(base.rglob("*.json")):
        task = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(task, dict):
            continue
        domain = path.relative_to(base).parts[0]
        for entry in _entries(task.get("mcp_server_modifications")):
            name = str(entry.get("tool_name") or "")
            if name:
                inventory[domain].add(name)
            text = entry.get("modification_description")
            if isinstance(text, str) and text.strip():
                cases.setdefault(
                    text,
                    {"kind": "modified", "domain": domain, "name": name,
                     "text": text, "schema": {},
                     "category": str(task.get("attack_category", ""))},
                )  # fmt: skip
        for entry in _entries(task.get("mcp_server_additions")):
            text = entry.get("description")
            if isinstance(text, str) and text.strip():
                params = entry.get("input_parameters") or {}
                schema = {
                    "type": "object",
                    "properties": {str(k): {"type": str(v)} for k, v in params.items()}
                    if isinstance(params, dict) else {},
                }  # fmt: skip
                cases.setdefault(
                    text,
                    {"kind": "added", "domain": domain,
                     "name": str(entry.get("tool_name") or "added_tool"),
                     "text": text, "schema": schema,
                     "category": str(task.get("attack_category", ""))},
                )  # fmt: skip
    return list(cases.values()), inventory


def measure(root: Path) -> dict[str, Any]:
    """Count detections with each poisoned tool in its domain's session."""
    cases, _ = load(root)
    tools = server_tools(root)
    domains = domain_servers(root, tools)
    out: dict[str, Any] = {
        "distinct_poisoned_tools": len(cases),
        "domain_servers": {
            d: {s: len(tools[s]) for s in servers} for d, servers in domains.items()
        },
    }
    unknown_owner = 0
    rows: list[tuple[dict[str, Any], list[tuple[str, str]], list[tuple[str, str]]]] = []
    for case in cases:
        poisoned = bp.ToolDef(case["name"], case["text"], case["schema"])
        owner = bp.ATTACKER_SERVER
        if case["kind"] == "modified":
            owners = [s for s in domains[case["domain"]] if case["name"] in tools[s]]
            if owners:
                owner = owners[0]
            else:
                unknown_owner += 1
        pairs = []
        for server in domains[case["domain"]]:
            listed = [
                bp._tool_info(bp.ToolDef(n, "", {}))
                for n in tools[server]
                if not (server == owner and n == case["name"])
            ]
            if server == owner:
                listed.insert(0, bp._tool_info(poisoned))
            pairs.append((bp._bench_server(server), bp.ServerEnumeration(tools=listed)))
        if owner == bp.ATTACKER_SERVER:
            pairs.append(
                (
                    bp._bench_server(owner),
                    bp.ServerEnumeration(tools=[bp._tool_info(poisoned)]),
                )
            )
        found = bp._delegation.detect_delegation(pairs)
        found += collision.detect_tool_name_squats(pairs)
        deleg = sorted(
            {
                (f.id, str(f.severity))
                for f in found
                if f.tool == poisoned.name and owner in f.server
            }
        )
        rows.append((case, bp.poison_findings(poisoned), deleg))
    out["modified_tool_owner_unknown"] = unknown_owner
    # Control: each domain's session with no poisoned tool.  Names only (the
    # benchmark's own tool text is not read here), so it tests COLLIDE-002.
    out["sessions_without_an_attack"] = {
        domain: len(
            collision.detect_tool_name_squats(
                [
                    (
                        bp._bench_server(server),
                        bp.ServerEnumeration(
                            tools=[
                                bp._tool_info(bp.ToolDef(n, "", {}))
                                for n in tools[server]
                            ]
                        ),
                    )
                    for server in servers
                ]
            )
        )
        for domain, servers in domains.items()
    }
    for kind in ("added", "modified", "all"):
        sub = [r for r in rows if kind in ("all", r[0]["kind"])]
        by_id: collections.Counter[str] = collections.Counter()
        by_cat: dict[str, list[int]] = collections.defaultdict(lambda: [0, 0])
        for case, pf, df in sub:
            by_id.update({i for i, _ in df})
            by_cat[case["category"]][1] += 1
            by_cat[case["category"]][0] += bool(pf + df)
        out[kind] = {
            "n": len(sub),
            "text_checks": sum(bool(pf) for _, pf, _ in sub),
            "session_checks": sum(bool(df) for _, _, df in sub),
            "either": sum(bool(pf + df) for _, pf, df in sub),
            "either_high_or_above": sum(
                any(sev in bp.HIGH_OR_ABOVE for _, sev in pf + df) for _, pf, df in sub
            ),
            "session_checks_by_id": dict(sorted(by_id.items())),
            "either_by_attack_category": {
                k: f"{v[0]}/{v[1]}" for k, v in sorted(by_cat.items())
            },
        }
    return out


def main() -> None:
    """Print the counts as JSON."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repo", help="path of a clone of MCP-SafetyBench")
    args = parser.parse_args()
    print(json.dumps(measure(Path(args.repo)), indent=1))


if __name__ == "__main__":
    main()
