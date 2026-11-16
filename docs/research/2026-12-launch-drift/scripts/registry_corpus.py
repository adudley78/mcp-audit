"""Freeze the official MCP Registry stratum.

All: every active server's npm/PyPI package (latest server version), deduplicated by package and
against the npm and PyPI corpora. Static measurements (M2, M4, M5) run on all of them.
Live: the registry is too large to install and run every package before 11-19, so the live
measurements (M1, M3) use 100 packages ranked by downloads (npm last-week downloads from
scripts/npm_downloads.py; PyPI from the 30-day list, where known) plus 100 drawn at random (seed 20261114) from the rest.
"""
import gzip, json, random, re, sys
reg, npm_raw, toppypi, npm_c, pypi_c, out_all, out_live, npm_dl = sys.argv[1:9]
def norm(t, n): return n.lower() if t == "npm" else re.sub(r"[-_.]+", "-", n).lower()
taken = {("npm", e["name"].lower()) for e in json.load(open(npm_c))["entries"]} | \
        {("pypi", norm("pypi", e["name"])) for e in json.load(open(pypi_c))["entries"]}
dl = {("npm", e["name"].lower()): e.get("weekly") for e in json.load(open(npm_raw))}
dl.update({("npm", n.lower()): c for n, c in json.load(open(npm_dl))["downloads"].items() if c is not None})
dl.update({("pypi", norm("pypi", r["project"])): r["download_count"] for r in json.load(open(toppypi))["rows"]})
pk, dup = {}, 0
for p in json.load(open(reg))["packages"]:
    if not p.get("identifier"): continue
    k = (p["registry_type"], norm(p["registry_type"], p["identifier"]))
    if k in taken: dup += 1; continue
    if k in pk: continue
    pk[k] = {"type": k[0], "package": p["identifier"], "version": p.get("package_version"),
             "server": p["server"], "transport": p.get("transport"), "downloads": dl.get(k),
             "downloads_unit": None if dl.get(k) is None else ("npm weekly" if k[0] == "npm" else "pypi 30-day")}
allp = sorted(pk.values(), key=lambda e: (e["type"], e["package"].lower()))
with gzip.open(out_all, "wt") as f:
    json.dump({"built": "2026-11-14", "deduplicated_against_npm_and_pypi_corpora": dup, "entries": allp}, f)
ranked = sorted([e for e in allp if e["downloads"] and e["transport"] == "stdio"],
                key=lambda e: -e["downloads"])[:100]
rest = [e for e in allp if e not in ranked and e["transport"] == "stdio"]
sample = random.Random(20261114).sample(rest, 100)
json.dump({"built": "2026-11-14", "seed": 20261114, "ranked": ranked, "random": sample}, open(out_live, "w"), indent=1)
print("registry packages", len(allp), "deduped", dup, "with downloads", sum(1 for e in allp if e["downloads"]),
      "live ranked", len(ranked), "random", len(sample))
