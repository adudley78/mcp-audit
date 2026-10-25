"""Build the public MCP server corpus from npm search, ranked by weekly downloads."""
import json, sys, urllib.request, urllib.parse, time, re
from concurrent.futures import ThreadPoolExecutor

OUT = sys.argv[1]
QUERIES = ["mcp server", "keywords:mcp", "mcp-server", "model context protocol server", "keywords:mcp-server", "keywords:modelcontextprotocol"]

def get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "mcp-audit-corpus/1.0"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)

seen = {}
for q in QUERIES:
    for frm in range(0, 1000, 250):
        url = f"https://registry.npmjs.org/-/v1/search?text={urllib.parse.quote(q)}&size=250&from={frm}"
        try:
            data = get(url)
        except Exception as e:
            print("ERR", url, e, file=sys.stderr); break
        objs = data.get("objects", [])
        if not objs: break
        for o in objs:
            p = o["package"]
            name = p["name"]
            if name in seen: continue
            seen[name] = {
                "name": name,
                "version": p.get("version"),
                "description": p.get("description", ""),
                "keywords": p.get("keywords", []),
                "weekly": (o.get("downloads") or {}).get("weekly"),
                "monthly": (o.get("downloads") or {}).get("monthly"),
                "links": p.get("links", {}),
                "publisher": (p.get("publisher") or {}).get("username"),
                "date": p.get("date"),
            }
        time.sleep(0.2)
print("search candidates:", len(seen), file=sys.stderr)

# Keep names/keywords/descriptions that indicate an MCP server.
def looks_mcp(e):
    blob = (e["name"] + " " + e["description"] + " " + " ".join(e["keywords"] or [])).lower()
    return "mcp" in blob or "model context protocol" in blob

cands = [e for e in seen.values() if looks_mcp(e)]
cands.sort(key=lambda e: -(e["weekly"] or 0))
cands = cands[:400]
print("mcp-ish candidates:", len(cands), file=sys.stderr)

def enrich(e):
    try:
        pk = get("https://registry.npmjs.org/" + urllib.parse.quote(e["name"], safe="@"))
    except Exception as ex:
        e["error"] = str(ex); return e
    latest = pk.get("dist-tags", {}).get("latest")
    v = pk.get("versions", {}).get(latest, {})
    e["latest"] = latest
    e["bin"] = v.get("bin")
    e["deprecated"] = bool(v.get("deprecated"))
    e["repository"] = (v.get("repository") or {}).get("url") if isinstance(v.get("repository"), dict) else v.get("repository")
    e["dependencies"] = sorted((v.get("dependencies") or {}).keys())
    e["has_mcp_sdk_dep"] = any(d in ("@modelcontextprotocol/sdk", "fastmcp", "mcp-framework", "@mastra/mcp", "xmcp") for d in e["dependencies"])
    e["time_latest"] = (pk.get("time") or {}).get(latest)
    e["version_count"] = len(pk.get("versions", {}))
    e["dist_integrity"] = (v.get("dist") or {}).get("integrity")
    e["attestations"] = bool((v.get("dist") or {}).get("attestations"))
    return e

with ThreadPoolExecutor(16) as ex:
    cands = list(ex.map(enrich, cands))
json.dump(cands, open(OUT, "w"), indent=1)
print("written", OUT, file=sys.stderr)
