"""The version each live-pass package resolves to today (npm `latest` dist-tag, PyPI info.version),
in the same plan shape as snapshot-versions.json, under the label given (the snapshot date)."""
import json, sys, urllib.parse, urllib.request
from concurrent.futures import ThreadPoolExecutor
src, label, out = sys.argv[1:4]
def get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "mcp-audit-corpus/1.0"})
    with urllib.request.urlopen(req, timeout=120) as r: return json.load(r)
def one(p):
    q = {k: p[k] for k in ("stratum", "type", "package")}; q["versions"] = {}
    try:
        if p["type"] == "npm":
            v = get("https://registry.npmjs.org/" + urllib.parse.quote(p["package"], safe="@") + "/latest")["version"]
        else:
            v = get(f"https://pypi.org/pypi/{p['package']}/json")["info"]["version"]
        q["versions"][label] = {"version": v, "source": "npm latest dist-tag / PyPI info.version on the snapshot date"}
    except Exception as ex:
        q["error"] = str(ex)
    return q
plan = json.load(open(src))["packages"]
with ThreadPoolExecutor(12) as ex:
    res = list(ex.map(one, plan))
json.dump({"built": label, "dates": [label], "packages": res}, open(out, "w"), indent=1)
print("packages", len(res), "resolved", sum(bool(r["versions"]) for r in res))
