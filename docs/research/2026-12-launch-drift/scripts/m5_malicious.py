"""M5: malicious-package hits (SC-008 logic) across every package in the three strata.

Two sources, reported separately:
  bundled: mcp-audit's registry/known-malicious.json (OSV MAL-* mirror), matched by exact name
           with registry.malicious.assess() at the version the registry lists (SC-008's logic).
  osv:     a fresh OSV.dev querybatch for every (ecosystem, name, listed version); MAL-* IDs only.
The OSV pass catches records newer than the bundled mirror."""
import gzip, json, sys, time, urllib.request
from mcp_audit.registry.malicious import assess, load_known_malicious
from mcp_audit.registry.loader import load_registry
npm_c, pypi_c, reg_all, out = sys.argv[1:5]
items = {}
for e in json.load(open(npm_c))["entries"]:
    items[("npm", e["name"])] = {"stratum": "npm", "version": e.get("latest")}
for e in json.load(open(pypi_c))["entries"]:
    items[("pypi", e["name"])] = {"stratum": "pypi", "version": e.get("latest")}
for e in json.load(gzip.open(reg_all, "rt"))["entries"]:
    items.setdefault((e["type"], e["package"]), {"stratum": "registry", "version": e.get("version")})
km = load_known_malicious(); reg = load_registry()
bundled = []
for (eco, name), m in items.items():
    curated = reg.get(name) is not None
    for rec in km.lookup(eco, name):
        hit = assess(rec, m["version"] or None, curated=curated)
        if hit is not None:
            bundled.append({"type": eco, "package": name, "stratum": m["stratum"], "version": m["version"],
                            "id": rec.id, "affects_listed_version": hit.affects_this_launch})
ECO = {"npm": "npm", "pypi": "PyPI"}
keys = sorted(items); osv = []; errors = 0
def post(body):
    for a in range(5):
        try:
            req = urllib.request.Request("https://api.osv.dev/v1/querybatch", data=json.dumps(body).encode(),
                                         headers={"Content-Type": "application/json", "User-Agent": "mcp-audit-research/1.0"})
            with urllib.request.urlopen(req, timeout=120) as r: return json.load(r)
        except Exception:
            time.sleep(2 ** a)
    return None
for i in range(0, len(keys), 500):
    chunk = keys[i:i+500]
    q = [{"package": {"name": n, "ecosystem": ECO[t]}} for t, n in chunk]
    d = post({"queries": q})
    if d is None: errors += 1; continue
    for (t, n), res in zip(chunk, d["results"]):
        mal = sorted({v["id"] for v in res.get("vulns", []) if v["id"].startswith("MAL-")})
        if mal:
            osv.append({"type": t, "package": n, "stratum": items[(t, n)]["stratum"], "version": items[(t, n)]["version"], "ids": mal})
json.dump({"built": time.strftime("%Y-%m-%d"), "packages_checked": len(items),
           "bundled_mirror_last_updated": km.last_updated, "bundled_records": len(km),
           "osv_batch_errors": errors, "bundled_hits": bundled, "osv_hits": osv}, open(out, "w"), indent=1)
print("checked", len(items), "bundled hits", len(bundled), "osv name hits", len(osv), "errors", errors)
