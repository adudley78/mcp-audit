"""Apply the npm rule to PyPI: keep a package that ships a console_scripts entry point and whose
summary says it is (or ships) an MCP server, or whose name does. Ranking source: the
hugovk/top-pypi-packages 30-day list (top 15,000 projects), so the floor is that list's cutoff."""
import json, sys
probe = json.load(open(sys.argv[1]))
INCLUDED = {"mcp-for-blender", "mcp-server-fetch", "mcp-atlassian", "mcp-server-time", "postgres-mcp",
    "lean-lsp-mcp", "mcp-grafana", "awslabs-aws-api-mcp-server", "ha-mcp", "mcp-server-git", "mcp-server-appwrite",
    "opensearch-mcp-server-py", "awslabs-aws-documentation-mcp-server", "mcpforunityserver", "workspace-mcp",
    "chroma-mcp", "mcp-clickhouse", "excel-mcp-server", "langsmith-mcp-server", "awslabs-cloudwatch-mcp-server",
    "serena-agent", "awslabs-aws-pricing-mcp-server", "jcodemunch-mcp", "pagerduty-mcp", "analytics-mcp",
    "logfire-mcp", "exomem", "dbt-mcp", "mcp-google-sheets", "duckduckgo-mcp-server",
    "awslabs-billing-cost-management-mcp-server", "awslabs-aws-iac-mcp-server", "markitdown-mcp",
    "prometheus-mcp-server", "elevenlabs-mcp", "falcon-mcp", "serper-mcp-server", "freecad-mcp", "windows-mcp",
    "arxiv-mcp-server", "awslabs-redshift-mcp-server", "tilt-mcp", "astro-airflow-mcp", "notebooklm-mcp-cli",
    "unifi-network-mcp", "yandex-cli", "edgescaleai-cube-mcp", "meilisearch-mcp"}
EXCLUDED = {"mcp": "SDK", "mcp-types": "SDK", "fastmcp": "framework", "fastmcp-slim": "framework",
    "browser-use": "agent harness", "langchain-mcp-adapters": "adapter, no entry point", "fastapi-mcp": "framework, no entry point",
    "opentelemetry-instrumentation-mcp": "instrumentation", "mcpo": "proxy", "seleniumbase": "framework; summary does not say MCP server",
    "openai-mcp-extensions": "SDK extension", "mcp-proxy-for-aws": "proxy", "edgartools": "library; summary does not say MCP server",
    "scrapling": "framework; summary does not say MCP server", "databricks-mcp": "helpers, no entry point",
    "fastmcp-tasks": "framework extension", "mcp-proxy": "proxy", "llm-sandbox": "sandbox library; summary does not say MCP server",
    "django-mcp-server": "framework, no entry point", "blender-mcp": "rename shim for mcp-for-blender (duplicate)",
    "sling": "not MCP", "cisco-ai-mcp-scanner": "scanner", "mcp-proxy-for-aws-cli": "proxy", "fastmcp-extensions": "framework extension",
    "truthound": "summary does not say MCP server", "arxyne": "summary does not say MCP server",
    "ha-mcp-dev": "dev-channel duplicate of ha-mcp", "arcade-mcp-server": "framework, no entry point", "uipath-mcp": "SDK",
    "openinference-instrumentation-mcp": "instrumentation", "bernstein": "agent governance tool", "hol-guard": "security tool",
    "ouroboros-ai": "agent harness", "fast-agent-mcp": "agent harness", "mcpadapt": "adapter", "fastmcp-dishka": "framework extension",
    "skylos": "scanner", "llama-index-tools-mcp": "adapter", "praisonai": "agent framework", "unifi-mcp-shared": "library, no entry point",
    "mcp-use": "framework", "arcade-mcp": "platform CLI; summary does not say MCP server",
    "tooluniverse": "tool collection; summary does not say MCP server", "dcc-mcp-core": "library",
    "nvidia-nat-mcp": "client integration", "dcc-mcp-server": "gateway/bridge, no entry point"}
names = [e["name"] for e in probe]
undecided = [n for n in names if n not in INCLUDED and n not in EXCLUDED]
assert not undecided, undecided
entries = [e for e in probe if e["name"] in INCLUDED]
for e in entries:
    assert e.get("console_scripts"), e["name"]
entries.sort(key=lambda e: -e["downloads_30d"])
entries = entries[:50]
json.dump({"built": "2026-11-14",
    "source": "hugovk/top-pypi-packages 30-day list (last_update 2026-11-01, 15,000 projects): every project whose name contains 'mcp' or that the official MCP Registry lists as a PyPI package; wheel entry points read from the latest wheel",
    "rule": "Kept: ships a console_scripts entry point and its PyPI summary says it is (or ships) an MCP server, or its name does. Excluded: SDKs, frameworks and their extensions, adapters, instrumentation, proxies and bridges, scanners, agent harnesses, rename shims and dev-channel duplicates.",
    "note": f"{len(entries)} projects qualify inside the 15,000-project list; the scope asked for 50. Packages below the list's floor have no comparable download count, so the corpus stops here rather than mix ranking sources.",
    "excluded_manual": EXCLUDED, "entries": entries}, open(sys.argv[2], "w"), indent=1)
print("pypi entries", len(entries), "floor", entries[-1]["downloads_30d"])
