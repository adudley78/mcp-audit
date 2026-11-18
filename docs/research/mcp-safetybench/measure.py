"""Run Credenzo's poisoning text checks on MCP-SafetyBench's poisoned tool text.

Dev tool, not part of the package and never run in CI.  It reads a local clone
of MCP-SafetyBench (https://github.com/xjzzzzzzzz/MCPSafety, arXiv 2512.15163)
and prints the counts that ``results.json`` pins.  No text of the benchmark is
committed here: the result holds counts and SHA-256 values only.

Usage::

    git clone https://github.com/xjzzzzzzzz/MCPSafety PATH
    uv run python docs/research/mcp-safetybench/measure.py PATH

What is checked.  Each task file under ``mcpuniverse/benchmark/configs/test``
may change the description of a tool (``mcp_server_modifications``, field
``modification_description``) or add a tool (``mcp_server_additions``, field
``description``).  The script takes each distinct text of those two fields and
checks it as one tool description, the way ``scripts/bench_poisoning.py``
checks an MCPTox description.  Attacks that do not change tool text (a changed
implementation, a tampered result, a replayed call) are not text and are not
counted.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "scripts"))

import bench_poisoning  # noqa: E402

CONFIG_DIR = "mcpuniverse/benchmark/configs/test"
FIELDS: tuple[tuple[str, str], ...] = (
    ("mcp_server_modifications", "modification_description"),
    ("mcp_server_additions", "description"),
)


def _entries(value: Any) -> list[dict[str, Any]]:
    """Return the dict entries of a section that is a dict or a list of dicts."""
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    return []


def poisoned_texts(root: Path) -> dict[str, str]:
    """Return each distinct poisoned description and its attack category."""
    texts: dict[str, str] = {}
    for path in sorted((root / CONFIG_DIR).rglob("*.json")):
        task = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(task, dict):
            continue
        for section, field in FIELDS:
            for entry in _entries(task.get(section)):
                text = entry.get(field)
                if isinstance(text, str) and text.strip():
                    texts.setdefault(text, str(task.get("attack_category", "")))
    return texts


def measure(root: Path) -> dict[str, Any]:
    """Check each distinct text and return the counts."""
    texts = poisoned_texts(root)
    by_check: collections.Counter[str] = collections.Counter()
    by_category: dict[str, list[int]] = collections.defaultdict(lambda: [0, 0])
    flagged = high = 0
    for text, category in texts.items():
        findings = bench_poisoning.poison_findings(
            bench_poisoning.ToolDef("t", text, {})
        )
        by_category[category][1] += 1
        if findings:
            flagged += 1
            by_category[category][0] += 1
        if any(sev in bench_poisoning.HIGH_OR_ABOVE for _, sev in findings):
            high += 1
        by_check.update({check for check, _ in findings})
    digests = sorted(hashlib.sha256(t.encode("utf-8")).hexdigest() for t in texts)
    return {
        "distinct_poisoned_descriptions": len(texts),
        "sha256_of_sorted_text_sha256_lines": hashlib.sha256(
            "\n".join(digests).encode("utf-8")
        ).hexdigest(),
        "flagged_any_severity": flagged,
        "flagged_high_or_above": high,
        "descriptions_by_check": dict(sorted(by_check.items())),
        "flagged_of_total_by_attack_category": {
            k: f"{v[0]}/{v[1]}" for k, v in sorted(by_category.items())
        },
    }


def main() -> None:
    """Print the counts as JSON."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repo", help="path of a clone of MCP-SafetyBench")
    args = parser.parse_args()
    print(json.dumps(measure(Path(args.repo)), indent=1))


if __name__ == "__main__":
    main()
