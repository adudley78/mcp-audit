"""Connect to every corpus server with mcp-audit's own MCP client and record what it exposes.

Uses mcp_audit.mcp_client.connect_and_enumerate (the --connect path) with a 60s timeout
instead of the CLI's 10s, so slow cold starts are not mistaken for broken servers. Then
runs the same runtime poisoning analysis scan --connect runs, and COLLIDE-001 across all
successfully connected servers.
"""
import asyncio, json, sys, os, time
from pathlib import Path
from mcp_audit.models import ServerConfig, TransportType
from mcp_audit.mcp_client import connect_and_enumerate, build_runtime_server_config
from mcp_audit.analyzers.poisoning import PoisoningAnalyzer
from mcp_audit.analyzers.collision import detect_tool_collisions
from mcp_audit.registry.loader import load_registry

corpus = json.load(open(sys.argv[1]))["entries"]
if os.environ.get("MCP_OVERRIDES"):
    _ov = json.load(open(os.environ["MCP_OVERRIDES"])); corpus = [e for e in corpus if e["name"] in _ov]
out = Path(sys.argv[2]); out.mkdir(parents=True, exist_ok=True)
TIMEOUT = float(os.environ.get("MCP_TIMEOUT", "60"))
CONC = int(os.environ.get("MCP_CONC", "6"))

OV = json.load(open(os.environ["MCP_OVERRIDES"])) if os.environ.get("MCP_OVERRIDES") else {}
PKGS = "/srv/probe/pkgs"


def slug(n):
    return n.replace("/", "__").replace("@", "")


def pick_bin(e, o):
    """The executable `npx -y <spec>` would run (or the override's), else None."""
    if o.get("bin"):
        return o["bin"]
    b = e.get("bin")
    unscoped = e["name"].split("/")[-1]
    if isinstance(b, str):
        return unscoped
    if isinstance(b, dict):
        if len(b) == 1:
            return next(iter(b))
        if unscoped in b:
            return unscoped
    return None


def cfg(e):
    """Q-045 isolation: run the installed bin with no network (unshare --net), as the
    unprivileged `probe` user, with an empty environment (env -i). No account,
    no API key and no repository credential is reachable from the server."""
    o = OV.get(e["name"], {})
    b = pick_bin(e, o) or "__ambiguous_bin__"
    binpath = f"{PKGS}/{slug(e['name'])}/node_modules/.bin/{b}"
    home = f"/srv/probe/home/{slug(e['name'])}"
    envs = [f"{k}={v}" for k, v in o.get("env", {}).items()]
    args = ["--net", "--", "runuser", "-u", "probe", "--", "env", "-i",
            f"HOME={home}", "PATH=/opt/node22/bin:/usr/bin:/bin", *envs,
            binpath, *o.get("args", [])]
    return ServerConfig(name=e["name"], client="corpus", config_path=Path("/corpus/mcp.json"),
                        transport=TransportType.STDIO, command="unshare", args=args, env={})

sem = asyncio.Semaphore(CONC)
async def one(e):
    f = out / (e["name"].replace("/", "__").replace("@", "") + ".json")
    if f.exists():
        return e, None
    async with sem:
        t = time.time()
        en = await connect_and_enumerate(cfg(e), timeout=TIMEOUT)
        rec = en.model_dump(mode="json"); rec["elapsed"] = round(time.time() - t, 1); rec["package"] = e["name"]; rec["version"] = e["latest"]
        f.write_text(json.dumps(rec, indent=1))
        print(f"{e['name']}: tools={len(en.tools)} err={en.error!r} tools_err={en.tools_error!r} {rec['elapsed']}s", flush=True)
    return e, en

async def main():
    results = await asyncio.gather(*(one(e) for e in corpus))
    pairs = []; poison = []; pa = PoisoningAnalyzer()
    from mcp_audit.models import ServerEnumeration
    for e, en in results:
        if en is None:
            en = ServerEnumeration(**{k: v for k, v in json.load(open(out / (e["name"].replace("/", "__").replace("@", "") + ".json"))).items() if k in ServerEnumeration.model_fields})
        if en.error: continue
        s = cfg(e); pairs.append((s, en))
        rc = build_runtime_server_config(s, en)
        if rc is None: continue
        for fd in pa.analyze(rc):
            d = fd.model_dump(mode="json"); d["package"] = e["name"]; poison.append(d)
    reg = load_registry()
    coll = [f.model_dump(mode="json") for f in detect_tool_collisions(pairs, registry=reg)]
    json.dump({"runtime_poisoning": poison, "collisions": coll, "connected": len(pairs)}, open(out / "_runtime_findings.json", "w"), indent=1)
    print("connected", len(pairs), "poison findings", len(poison), "collisions", len(coll))

asyncio.run(main())
