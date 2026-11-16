"""Install, run and remove each (package, version) the old-date snapshots need.

Install as the unprivileged `probe` user, each pair in its own prefix: npm with
--ignore-scripts, PyPI wheels only (--only-binary :all:), so no package code runs at install
time. The prefix is deleted after the run, so disk use stays at a few pairs at a time.

Isolation as on 2026-10-29: the server runs as the unprivileged `probe` user, under
`unshare --net` (no network interface) with an empty environment (env -i). The 10-22 and
10-29 launch overrides (args, env, bin) are applied to the same npm packages.
Output per pair: the tool definitions and their lock digests (lock/tool_digests.py)."""
import asyncio, json, os, shutil, sys, time
from pathlib import Path
from mcp_audit.models import ServerConfig, TransportType
from mcp_audit.mcp_client import connect_and_enumerate
from mcp_audit.lock.tool_digests import tool_digests, tool_definition
plan = json.load(open(sys.argv[1]))["packages"]
out = Path(sys.argv[2]); out.mkdir(parents=True, exist_ok=True)
OV = {}
for f in sys.argv[3:]:
    OV.update(json.load(open(f)))
BASE = {"HOME": "/srv/probe", "PATH": "/opt/node22/bin:/usr/local/bin:/usr/bin:/bin",
        "HTTPS_PROXY": os.environ.get("HTTPS_PROXY", ""), "HTTP_PROXY": os.environ.get("HTTP_PROXY", ""),
        "npm_config_cafile": "/srv/probe/ca.crt", "npm_config_cache": "/srv/probe/.npm",
        "SSL_CERT_FILE": "/srv/probe/ca.crt", "UV_CACHE_DIR": "/srv/probe/.uv", "UV_NO_CONFIG": "1"}
async def as_probe(cmd, timeout=900):
    full = ["runuser", "-u", "probe", "--", "env", "-i", *[f"{k}={v}" for k, v in BASE.items()], *cmd]
    p = await asyncio.create_subprocess_exec(*full, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE)
    try:
        _, err = await asyncio.wait_for(p.communicate(), timeout)
    except asyncio.TimeoutError:
        p.kill(); await p.wait(); return 124, f"timed out after {timeout}s"
    return p.returncode, err.decode(errors="replace")[-600:]
async def install(t, n, v, prefix):
    if t == "npm":
        return await as_probe(["npm", "install", "--ignore-scripts", "--no-audit", "--no-fund", "--loglevel=error",
                               "--prefix", prefix, f"{n}@{v}"])
    rc, err = await as_probe(["uv", "venv", "-q", "--python", "/usr/bin/python3.13", prefix + "/venv"])
    if rc: return rc, err
    return await as_probe(["uv", "pip", "install", "-q", "--only-binary", ":all:", "--python", prefix + "/venv/bin/python", f"{n}=={v}"])
TIMEOUT = float(os.environ.get("MCP_TIMEOUT", "60"))
meta = {}
for p in plan:
    for label, v in p["versions"].items():
        k = (p["type"], p["package"], v["version"]); meta.setdefault(k, {"labels": [], "p": p})["labels"].append(label)
def slug(t, n, v): return f"{t}__{n.replace('/', '__').replace('@', '')}@{v}"
def npm_bin(prefix, name, o):
    if o.get("bin"): return o["bin"]
    pj = json.load(open(f"{prefix}/node_modules/{name}/package.json"))
    b = pj.get("bin"); unscoped = name.split("/")[-1]
    if isinstance(b, str): return pj.get("name", name).split("/")[-1]
    if isinstance(b, dict):
        if len(b) == 1: return next(iter(b))
        if unscoped in b: return unscoped
    return None
def py_bin(prefix, name):
    import glob, configparser
    eps = glob.glob(f"{prefix}/venv/lib/python*/site-packages/*.dist-info/entry_points.txt")
    want = name.lower().replace("_", "-")
    for ep in eps:
        dist = os.path.basename(os.path.dirname(ep)).removesuffix(".dist-info").rsplit("-", 1)[0].lower().replace("_", "-")
        if dist != want: continue
        cp = configparser.ConfigParser(); cp.read(ep)
        if "console_scripts" not in cp: return None
        scripts = list(cp["console_scripts"])
        for s in scripts:
            if s == want: return s
        mcp = [s for s in scripts if "mcp" in s]
        return (mcp or scripts)[0]
    return None
def cfg(t, n, v):
    prefix = f"/srv/probe/pkgs/{slug(t, n, v)}"; o = OV.get(n, {}) if t == "npm" else {}
    if t == "npm":
        b = npm_bin(prefix, n, o); binpath = f"{prefix}/node_modules/.bin/{b}" if b else None
    else:
        b = py_bin(prefix, n); binpath = f"{prefix}/venv/bin/{b}" if b else None
    if not binpath: return None, None
    home = f"/srv/probe/home/{slug(t, n, v)}"; os.makedirs(home, exist_ok=True); os.system(f"chown probe:probe '{home}'")
    envs = [f"{k}={val}" for k, val in o.get("env", {}).items()]
    args = ["--net", "--", "runuser", "-u", "probe", "--", "env", "-i", f"HOME={home}",
            "PATH=/opt/node22/bin:/usr/local/bin:/usr/bin:/bin", *envs, binpath, *o.get("args", [])]
    return ServerConfig(name=n, client="corpus", config_path=Path("/corpus/mcp.json"), transport=TransportType.STDIO,
                        command="unshare", args=args, env={}), b
async def one(k):
    t, n, v = k; f = out / (slug(t, n, v) + ".json")
    if f.exists(): return
    prefix = f"/srv/probe/pkgs/{slug(t, n, v)}"
    async with sem:
        try:
            rc, err = await install(t, n, v, prefix)
            if rc:
                f.write_text(json.dumps({"type": t, "package": n, "version": v, "labels": meta[k]["labels"],
                                         "error": "install failed", "install_error": err}))
                print(n, v, "install failed", flush=True); return
            s, b = cfg(t, n, v)
            if s is None:
                f.write_text(json.dumps({"type": t, "package": n, "version": v, "labels": meta[k]["labels"],
                                         "error": "no unambiguous entry point"})); return
            t0 = time.time(); en = await connect_and_enumerate(s, timeout=TIMEOUT)
        finally:
            shutil.rmtree(prefix, ignore_errors=True)
    rec = {"type": t, "package": n, "version": v, "labels": meta[k]["labels"], "bin": b, "elapsed": round(time.time() - t0, 1),
           "error": en.error, "tools_error": en.tools_error,
           "definitions": [tool_definition(x) for x in en.tools], "digests": tool_digests(en.tools) if en.tools else {},
           "enumeration": en.model_dump(mode="json")}
    f.write_text(json.dumps(rec, indent=1)); print(n, v, "tools", len(en.tools), "err", en.error, flush=True)
async def main():
    global sem; sem = asyncio.Semaphore(int(os.environ.get("MCP_CONC", "4")))
    await asyncio.gather(*(one(k) for k in meta))
    recs = [json.load(open(p)) for p in sorted(out.glob("*.json")) if not p.name.startswith("_")]
    print("pairs", len(recs), "connected", sum(1 for r in recs if not r.get("error") and r.get("digests")))
asyncio.run(main())
