"""M2: do README install snippets launch an exact version, or whatever is latest?

For each live-pass package (npm 100, PyPI 48, registry 200), read the README the registry serves
(npm `readme`, PyPI `info.description`) and find every launch of the package: `npx`, `bunx`,
`pnpm dlx`, `yarn dlx`, `uvx`, `pipx run`, in shell form or as a client-config `"command"`/`"args"`
pair. A launch is pinned when the spec carries an exact version (`pkg@1.2.3`, `pkg==1.2.3`),
unpinned otherwise (no version, `@latest`, a range). `npm install -g` lines are not launches."""
import json, re, sys, urllib.parse, urllib.request
from concurrent.futures import ThreadPoolExecutor
plan, out = sys.argv[1:3]
LAUNCH = re.compile(r'(npx|bunx|pnpm\s+dlx|yarn\s+dlx|uvx|pipx\s+run|"npx"|"uvx"|"bunx")', re.I)
EXACT = re.compile(r'^(@|==)v?\d+(\.\d+){1,3}([-.+][0-9A-Za-z.-]+)?$')
def get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "mcp-audit-research/1.0"})
    with urllib.request.urlopen(req, timeout=120) as r: return json.load(r)
def readme(t, n):
    if t == "npm":
        d = get("https://registry.npmjs.org/" + urllib.parse.quote(n, safe="@"))
        return d.get("readme") or ""
    return get(f"https://pypi.org/pypi/{n}/json")["info"].get("description") or ""
def launches(text, t, n):
    found = []
    name = re.escape(n)
    if t == "pypi":
        name = "[-_.]".join(re.escape(p) for p in re.split(r"[-_.]+", n))
    for m in re.finditer(r'(?<![A-Za-z0-9._/@-])' + name + r'((?:@|==)[^\s"\'`,\]\)]+)?(?![A-Za-z0-9_/-])', text, re.I):
        before = text[max(0, m.start() - 160):m.start()]
        line_start = before.rfind("\n")
        same_line = before[line_start + 1:]
        lm = list(LAUNCH.finditer(same_line))
        ctx = same_line
        if not lm:  # JSON config: "command": "npx" on a nearby line, package in "args"
            lm = list(LAUNCH.finditer(before)); ctx = before
            if not lm or '"args"' not in before[lm[-1].start():]: continue
        if re.search(r'\bnpm\s+(i|install)\b|\bpip\s+install\b', ctx[lm[-1].start():]): continue
        suffix = m.group(1) or ""
        found.append({"spec": m.group(0), "pinned": bool(EXACT.match(suffix))})
    return found
items = {(p["type"], p["package"]): p["stratum"] for p in json.load(open(plan))["packages"]}
def one(k):
    t, n = k
    try:
        f = launches(readme(t, n), t, n)
    except Exception as ex:
        return {"type": t, "package": n, "stratum": items[k], "error": str(ex)[:120]}
    return {"type": t, "package": n, "stratum": items[k], "launches": len(f),
            "pinned": sum(x["pinned"] for x in f), "unpinned": sum(not x["pinned"] for x in f),
            "examples": sorted({x["spec"] for x in f})[:5]}
with ThreadPoolExecutor(8) as ex:
    rows = list(ex.map(one, sorted(items)))
def agg(rs):
    w = [r for r in rs if r.get("launches")]
    return {"packages": len(rs), "readme_errors": sum("error" in r for r in rs), "with_launch_snippet": len(w),
            "all_unpinned": sum(r["pinned"] == 0 for r in w), "any_pinned": sum(r["pinned"] > 0 for r in w),
            "snippets": sum(r["launches"] for r in w), "unpinned_snippets": sum(r["unpinned"] for r in w)}
summary = {s: agg([r for r in rows if r["stratum"] == s]) for s in ("npm", "pypi", "registry")}
summary["all"] = agg(rows)
json.dump({"summary": summary, "rows": rows}, open(out, "w"), indent=1)
print(json.dumps(summary, indent=1))
