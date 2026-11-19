"""Run Cisco mcp-scanner's YARA analyzer on the exported texts.

Run in an environment that has ``cisco-ai-mcp-scanner`` (4.8.7 was measured)::

    python -I cisco_run.py OUT

It calls ``YaraAnalyzer.analyze`` on each description, on the JSON of each
input schema and on each added text of a HISTOR change.  It sends nothing to
a remote service.
"""
import asyncio, collections, json, sys
from mcpscanner.core.analyzers.yara_analyzer import YaraAnalyzer
D = sys.argv[1].rstrip("/") + "/"
an = YaraAnalyzer()
HIGH = {"HIGH", "CRITICAL"}
async def scan(text):
    if not text: return [], False
    f = await an.analyze(text, {"tool_name": "t", "content_type": "description"})
    rules = sorted({x.details["raw_response"]["rule"] for x in f})
    return rules, any(str(x.severity).upper() in HIGH for x in f)
async def main():
    out = open(D + "cisco_sets.jsonl", "w"); n = 0
    for line in open(D + "sets.jsonl"):
        r = json.loads(line)
        rd, hd = await scan(r["description"])
        rs, hs = await scan(json.dumps(r["schema"]) if r["schema"] else "")
        out.write(json.dumps({"set": r["set"], "id": r["id"], "cisco": sorted(set(rd + rs)), "cisco_desc": rd, "cisco_high": hd or hs, "credenzo": r["credenzo"], "credenzo_high": r["credenzo_high"]}) + "\n"); n += 1
    out.close(); print("sets", n)
    out = open(D + "cisco_histor.jsonl", "w"); n = fl = 0
    for line in open(D + "histor_texts.jsonl"):
        r = json.loads(line); rules, high = await scan(r["text"]); n += 1; fl += bool(rules)
        out.write(json.dumps({"sha": r["sha"], "cisco": rules, "cisco_high": high}) + "\n")
    out.close(); print("histor texts", n, "flagged", fl)
asyncio.run(main())
