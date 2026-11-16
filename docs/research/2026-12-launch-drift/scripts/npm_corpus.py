"""Apply the 2026-10-29 inclusion rule to a fresh npm search and keep the top 100.

Prior decisions (10-22, 10-29) stand. New candidates get a decision in NEW_EXCLUDED
or NEW_INCLUDED below; the script fails if a candidate inside the top 100 has none.
"""
import json, re, sys
raw, prev_path, out = sys.argv[1], sys.argv[2], sys.argv[3]
cands = json.load(open(raw))
prev = json.load(open(prev_path))
prev_names = {e["name"] for e in prev["entries"]}

NEW_EXCLUDED = {
    "@cargo-ai/cli": "description does not say MCP server",
    "dsh-free-search": "description does not say MCP server",
    "@microsoft/powerbi-modeling-mcp-win32-x64": "platform-binary duplicate of @microsoft/powerbi-modeling-mcp",
    "@k2b/fibel": "documentation runtime; description does not say MCP server",
    "@docmd/core": "documentation compiler; description does not say MCP server",
    "@coinbase/cdp-cli": "API CLI; description does not say MCP server",
    "dynoxide": "DynamoDB emulator; description does not say MCP server",
    "@commonlyai/cli": "agent CLI; description does not say MCP server",
    "@nanonets/graft": "description does not say MCP server",
    "@mcpjam/cli": "inspector / test tool for MCP servers",
    "task-master-ai": "description does not say MCP server (ships one as a second bin)",
    "mockserver-node": "HTTP mock server; description does not say MCP server",
    "@letterstory/cli": "blog CLI; description does not say MCP server",
    "@nextscope/mcp": "MCP bridge (proxy)",
    "ai-rulez": "config tool",
    "hlims-mcp": "stdio proxy for a remote MCP service",
}
NEW_INCLUDED_BY_NAME = {"@perplexity-ai/mcp-server", "@sendinel/mcp-server", "@brightdata/mcp",
                        "@google-cloud/cloud-run-mcp", "@mastergo/magic-mcp"}

def says(e):
    d = (e.get("description") or "").lower()
    return bool(re.search(r"\bmcp\b|model context protocol", d)) and ("server" in d or " over mcp" in d)

excluded = dict(prev["excluded_manual"]); excluded.update(NEW_EXCLUDED)
entries, undecided = [], []
for e in cands:
    if not e.get("bin") or e.get("error"):
        continue
    n = e["name"]
    if n in excluded:
        continue
    if n in prev_names or n in NEW_INCLUDED_BY_NAME or says(e):
        entries.append(e)
    else:
        undecided.append(n)
    if len(entries) == 100:
        break
late = [n for n in undecided]
if late:
    sys.exit(f"undecided inside the top 100: {late}")
json.dump({
    "built": "2026-11-14",
    "source": prev["source"].replace("4378 candidates", "candidates as reported by scripts/npm_search.py"),
    "rule": prev["rule"],
    "excluded_manual": excluded,
    "excluded_new_2026-11-14": NEW_EXCLUDED,
    "entries": entries,
}, open(out, "w"), indent=1)
print("entries", len(entries), "cutoff weekly", entries[-1]["weekly"],
      "carried over from 10-29", sum(e["name"] in prev_names for e in entries))
