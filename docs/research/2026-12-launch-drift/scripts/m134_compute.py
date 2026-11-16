"""M1 (tool drift), M3 (POISON-* on live descriptions, before labelling) and M4 (toxic flows
inside one server's default install) from the snapshot records.

M1 compares each package's lock digests (lock/tool_digests.py) on 2026-10-22, 2026-10-29 and the
current snapshot. A change is counted per consecutive pair of dates where the package connected
with tools on both. "Without a version bump" = same version string on both dates.
M3 runs PoisoningAnalyzer over build_runtime_server_config, exactly as `scan --connect` does.
M4 runs ToxicFlowAnalyzer over each server alone (self-pairs), with its live tools in `raw` so
tag_server reads tool names and descriptions, and the shared registry."""
import json, sys
from collections import Counter
from pathlib import Path
from mcp_audit.models import ServerConfig, ServerEnumeration, TransportType
from mcp_audit.mcp_client import build_runtime_server_config
from mcp_audit.analyzers.poisoning import PoisoningAnalyzer
from mcp_audit.analyzers.toxic_flow import ToxicFlowAnalyzer
from mcp_audit.registry.loader import load_registry
old_versions, cur_versions, old_dir, cur_dir, cur_label, out, findings_out = sys.argv[1:8]
def slug(t, n, v): return f"{t}__{n.replace('/', '__').replace('@', '')}@{v}"
def load(d, t, n, v):
    f = Path(d) / (slug(t, n, v) + ".json")
    if not f.exists(): return None
    r = json.load(open(f))
    return r if not r.get("error") and r.get("digests") else None
old = {(p["type"], p["package"]): p for p in json.load(open(old_versions))["packages"]}
cur = {(p["type"], p["package"]): p for p in json.load(open(cur_versions))["packages"]}
DATES = ["2026-10-22", "2026-10-29", cur_label]
rows, m1 = [], Counter()
for k, p in old.items():
    vers = dict(p["versions"]); vers.update(cur.get(k, {}).get("versions", {}))
    snap = {}
    for dt in DATES:
        v = vers.get(dt, {}).get("version")
        if v:
            r = load(cur_dir if dt == cur_label else old_dir, k[0], k[1], v)
            if r: snap[dt] = (v, r["digests"])
    steps = []
    for a, b in zip(DATES, DATES[1:]):
        if a in snap and b in snap:
            (va, da), (vb, db) = snap[a], snap[b]
            added = sorted(set(db) - set(da)); removed = sorted(set(da) - set(db))
            changed = sorted(t for t in set(da) & set(db) if da[t] != db[t])
            contract = sorted(t for t in changed if da[t]["contract"] != db[t]["contract"])
            steps.append({"from": a, "to": b, "version_from": va, "version_to": vb, "bumped": va != vb,
                          "changed": bool(added or removed or changed), "added": added, "removed": removed,
                          "definition_changed": changed, "contract_changed": contract})
    rows.append({"stratum": p["stratum"], "type": k[0], "package": k[1], "connected_on": sorted(snap), "steps": steps})
def m1_agg(rs):
    st = [s for r in rs for s in r["steps"]]
    servers_all3 = [r for r in rs if len(r["connected_on"]) == 3]
    return {"connected_all_three_dates": len(servers_all3),
            "servers_changed_any_step": sum(any(s["changed"] for s in r["steps"]) for r in rs if r["steps"]),
            "servers_with_a_step": sum(1 for r in rs if r["steps"]),
            "steps": len(st), "steps_changed": sum(s["changed"] for s in st),
            "steps_changed_with_bump": sum(s["changed"] and s["bumped"] for s in st),
            "steps_changed_without_bump": sum(s["changed"] and not s["bumped"] for s in st),
            "steps_bumped_unchanged": sum(s["bumped"] and not s["changed"] for s in st),
            "steps_with_tool_added_or_removed": sum(bool(s["added"] or s["removed"]) for s in st),
            "steps_description_only": sum(s["changed"] and not s["added"] and not s["removed"] and not s["contract_changed"] for s in st)}
M1 = {s: m1_agg([r for r in rows if r["stratum"] == s]) for s in ("npm", "pypi", "registry")}; M1["all"] = m1_agg(rows)
reg = load_registry(); pa = PoisoningAnalyzer(); tf = ToxicFlowAnalyzer(registry=reg)
poison, toxic, connected = [], [], Counter()
for k, p in cur.items():
    v = p["versions"].get(cur_label, {}).get("version")
    r = load(cur_dir, k[0], k[1], v) if v else None
    if not r or "enumeration" not in r: continue
    connected[p["stratum"]] += 1
    en = ServerEnumeration(**{a: b for a, b in r["enumeration"].items() if a in ServerEnumeration.model_fields})
    base = ServerConfig(name=k[1], client="corpus", config_path=Path("/corpus/mcp.json"), transport=TransportType.STDIO,
                        command="npx" if k[0] == "npm" else "uvx", args=["-y", k[1]] if k[0] == "npm" else [k[1]], env={})
    rc = build_runtime_server_config(base, en)
    if rc is None: continue
    for f in pa.analyze(rc):
        d = f.model_dump(mode="json"); d.update(stratum=p["stratum"], package=k[1], version=v); poison.append(d)
    for f in tf.analyze_all([rc]):
        toxic.append({"stratum": p["stratum"], "package": k[1], "id": f.id, "severity": str(f.severity)})
def sev(fs): return dict(Counter(str(f["severity"]) for f in fs))
def m3(s):
    fs = [f for f in poison if s in (None, f["stratum"])]
    return {"findings": len(fs), "servers_with_findings": len({f["package"] for f in fs}), "by_id": dict(Counter(f["id"] for f in fs)), "by_severity": sev(fs)}
def m4(s):
    fs = [f for f in toxic if s in (None, f["stratum"])]
    return {"servers_connected": sum(connected.values()) if s is None else connected[s],
            "servers_with_any_toxic_self_pair": len({f["package"] for f in fs}),
            "servers_with_TOXIC_001": len({f["package"] for f in fs if f["id"] == "TOXIC-001"}),
            "by_id": dict(Counter(f["id"] for f in fs))}
res = {"snapshot": cur_label, "M1": M1, "M3_unlabelled": {s or "all": m3(s) for s in ("npm", "pypi", "registry", None)},
       "M4": {s or "all": m4(s) for s in ("npm", "pypi", "registry", None)}, "m1_rows": rows}
json.dump(res, open(out, "w"), indent=1)
json.dump(poison, open(findings_out, "w"), indent=1)
print(json.dumps({k: v for k, v in res.items() if k != "m1_rows"}, indent=1))
