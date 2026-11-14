"""Which version of each live-pass package was current on 2026-10-22 and 2026-10-29.

Source, in order: the version a past study recorded for that date (10-22 or 10-29 corpus.json),
else the highest non-prerelease version published on or before the end of that day
(npm `time`, PyPI upload times). A package that did not exist yet gets no version.
"""
import json, re, sys, urllib.parse, urllib.request
from concurrent.futures import ThreadPoolExecutor
npm_c, pypi_c, live, old22, old29, out = sys.argv[1:7]
DATES = {"2026-10-22": "2026-10-22T23:59:59Z", "2026-10-29": "2026-10-29T23:59:59Z"}
rec = {"2026-10-22": {e["name"]: e["latest"] for e in json.load(open(old22))["entries"]},
       "2026-10-29": {e["name"]: e["latest"] for e in json.load(open(old29))["entries"]}}
def get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "mcp-audit-corpus/1.0"})
    with urllib.request.urlopen(req, timeout=120) as r: return json.load(r)
STABLE = re.compile(r"\d+(\.\d+)*(\.post\d+)?")
def vkey(v):
    return [int(x) if x.isdigit() else -1 for x in re.split(r"[.\-+]", v)[:4]]
items = [("npm", "npm", e["name"]) for e in json.load(open(npm_c))["entries"]] + \
        [("pypi", "pypi", e["name"]) for e in json.load(open(pypi_c))["entries"]]
lv = json.load(open(live))
items += [("registry", e["type"], e["package"]) for e in lv["ranked"] + lv["random"]]
def one(it):
    stratum, eco, name = it
    r = {"stratum": stratum, "type": eco, "package": name, "versions": {}}
    try:
        if eco == "npm":
            d = get("https://registry.npmjs.org/" + urllib.parse.quote(name, safe="@"))
            live = set(d.get("versions") or {})  # `time` keeps unpublished versions; only installable ones count
            times = {v: t for v, t in (d.get("time") or {}).items() if v in live}
            r["latest_now"] = (d.get("dist-tags") or {}).get("latest")
        else:
            d = get(f"https://pypi.org/pypi/{name}/json")
            times = {v: min(f["upload_time_iso_8601"] for f in fs) for v, fs in d["releases"].items()
                     if fs and not all(f.get("yanked") for f in fs)}
            r["latest_now"] = d["info"]["version"]
    except Exception as ex:
        r["error"] = str(ex); return r
    for label, cut in DATES.items():
        if eco == "npm" and name in rec[label]:
            r["versions"][label] = {"version": rec[label][name], "source": f"recorded in the {label} corpus"}; continue
        ok = [v for v, t in times.items() if t and t <= cut and STABLE.fullmatch(v)]
        if ok:
            r["versions"][label] = {"version": max(ok, key=vkey), "source": "highest stable release published by end of day"}
    return r
with ThreadPoolExecutor(12) as ex:
    res = list(ex.map(one, items))
json.dump({"built": "2026-11-14", "dates": list(DATES), "packages": res}, open(out, "w"), indent=1)
print("packages", len(res), "errors", sum("error" in r for r in res),
      "with 10-22", sum("2026-10-22" in r["versions"] for r in res), "with 10-29", sum("2026-10-29" in r["versions"] for r in res))
