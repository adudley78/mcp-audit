"""Export every text of the comparison with Credenzo's verdict.

Run from the repository root in Credenzo's environment::

    uv run python docs/research/head-to-head/cisco-yara/export.py OUT MCPTOX_DIR CHANGES_GZ SAFETYBENCH_REPO

OUT must be outside the repository: the files hold third-party text.
"""
import gzip, hashlib, json, sys
sys.path.insert(0, "scripts"); 
import bench_poisoning as B
from pathlib import Path
from mcp_audit.lock.tool_digests import TEXT_FIELDS
from mcp_audit.lock.tool_text import poison_ids
from mcp_audit.analyzers import poisoning as P
import importlib.util
spec = importlib.util.spec_from_file_location("sbm", "docs/research/mcp-safetybench/measure.py"); sbm = importlib.util.module_from_spec(spec); spec.loader.exec_module(sbm)
spec2 = importlib.util.spec_from_file_location("hm", "docs/research/histor-changes/measure.py"); H = importlib.util.module_from_spec(spec2); spec2.loader.exec_module(H)
OUT = Path(sys.argv[1])
SEV = {p.id: p.severity.value.upper() for p in P.PATTERNS}
def verdict(tool):
    f = B.poison_findings(tool)
    return sorted({i for i, _ in f}), any(s in B.HIGH_OR_ABOVE for _, s in f)
rows = []
files = B.load_mcptox(sys.argv[2])
ra = json.loads(files["response_all.json"]); pt = json.loads(files["pure_tool.json"])
pois, _ = B.benchmark_cases(ra)
for i, (_, _, t) in enumerate(pois): rows.append(("mcptox_poisoned", i, t))
for i, (_, t) in enumerate(B.clean_tools(ra)): rows.append(("mcptox_clean", i, t))
for i, (_, t) in enumerate(B.unwrapped_descriptions(pt)): rows.append(("mcptox_unwrapped", i, t))
for i, t in enumerate(sbm.poisoned_texts(Path(sys.argv[4]))): rows.append(("safetybench", i, B.ToolDef("t", t, {})))
for n in ("development", "heldout"):
    d = json.load(open(f"tests/fixtures/directives/{n}.json"))
    for k in ("poisoned", "benign"):
        for i, it in enumerate(d[k]): rows.append((f"directive_{k}", f"{n}-{i}", B.ToolDef("t", it[-1], {})))
with open(OUT / "sets.jsonl", "w") as fh:
    for s, i, t in rows:
        ids, high = verdict(t)
        fh.write(json.dumps({"set": s, "id": i, "description": t.description, "schema": getattr(t, "input_schema", None) or getattr(t, "inputSchema", None) or {}, "credenzo": ids, "credenzo_high": high}) + "\n")
print("sets", len(rows))
texts = {}; nchanges = 0
with gzip.open(sys.argv[3], "rt") as fh, open(OUT / "histor_map.jsonl", "w") as mp:
    for line in fh:
        r = json.loads(line); nchanges += 1
        summ = json.loads(r["summaryJson"]); items = []
        for tool in summ.get("modified") or []:
            for field, value in (tool.get("fields") or {}).items():
                text = H.added_text(value)
                if not text.strip(): continue
                d = hashlib.sha256(text.encode()).hexdigest()
                if d not in texts:
                    ids = poison_ids(text)
                    texts[d] = (text, ids, any(SEV.get(i, "MEDIUM") in ("HIGH", "CRITICAL") for i in ids))
                items.append((d, field in TEXT_FIELDS))
        if items: mp.write(json.dumps({"id": r["id"], "server": r["serverId"], "items": items}) + "\n")
with open(OUT / "histor_texts.jsonl", "w") as fh:
    for d, (text, ids, high) in texts.items():
        fh.write(json.dumps({"sha": d, "text": text, "credenzo": ids, "credenzo_high": high}) + "\n")
print("histor changes", nchanges, "distinct texts", len(texts), "flagged texts", sum(1 for v in texts.values() if v[1]))
