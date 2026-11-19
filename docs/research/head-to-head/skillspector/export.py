"""Write each comparison text as a skill folder for SkillSpector (run in Credenzo's venv, cwd = repo)."""
import json, random, sys, hashlib
from pathlib import Path
sys.path.insert(0, "scripts")
import bench_competitors as BC, bench_poisoning as B
SRC, OUT = Path(sys.argv[1]), Path(sys.argv[2])  # SRC = the OUT of cisco-yara/export.py
index = []
def put(group, key, description, schema):
    d = OUT / group / key; d.mkdir(parents=True, exist_ok=True)
    (d / "SKILL.md").write_text(BC.skill_text_for_tool(key, B.ToolDef(key, description, schema or {})), encoding="utf-8")
for line in open(SRC / "sets.jsonl"):
    r = json.loads(line)
    if r["set"].startswith("directive"): continue
    key = f"{r['set']}-{r['id']}".replace("_", "-")
    put(r["set"], key, r["description"], r["schema"]); index.append({"group": r["set"], "key": key, "credenzo": bool(r["credenzo"]), "credenzo_high": r["credenzo_high"]})
rows = [json.loads(l) for l in open(SRC / "histor_texts.jsonl")]
rows.sort(key=lambda r: r["sha"]); random.Random(172).shuffle(rows)
for r in rows[:2000]:
    key = "h-" + r["sha"][:16]
    put("histor_sample", key, r["text"], {}); index.append({"group": "histor_sample", "key": key, "sha": r["sha"], "credenzo": bool(r["credenzo"]), "credenzo_high": r["credenzo_high"]})
json.dump(index, open(OUT / "index.json", "w"))
print(len(index))
