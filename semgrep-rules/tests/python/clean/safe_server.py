"""Safe MCP server example — for Semgrep rule testing ONLY.

This file should produce zero findings when scanned with the mcp-audit Semgrep rules.
"""
from __future__ import annotations

import logging
import os
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

# Safe: credentials from environment variables
api_key = os.environ.get("API_KEY", "")
db_url = os.environ.get("DATABASE_URL", "")

# Safe: subprocess with list (not string) command
async def run_command_safe(filename: str) -> str:
    # List form is not vulnerable to shell injection
    result = subprocess.run(["ls", "-la", filename], capture_output=True, text=True)
    return result.stdout


# Safe: shell=False (default) with list
async def process_file(path: str) -> str:
    result = subprocess.run(["cat", path], shell=False, capture_output=True, text=True)
    return result.stdout


# Safe: eval with string literal only
async def evaluate_static() -> int:
    return eval("1 + 1")  # nosemgrep: mcp-eval-tool-arg


# Safe: path validated against base dir before open
BASE_DIR = Path("/app/data")


async def read_file_safe(user_path: str) -> str:
    full_path = (BASE_DIR / user_path).resolve()
    if not full_path.is_relative_to(BASE_DIR):
        raise ValueError("Path traversal attempt blocked")
    return full_path.read_text()  # nosemgrep: mcp-pathlib-open-traversal


# Safe: open() with string literal
async def read_config() -> str:
    with open("/app/config/settings.json", "r") as f:
        return f.read()


# Safe: HTTP request to a hardcoded URL
async def fetch_known_endpoint() -> str:
    import httpx
    resp = httpx.get("https://api.known-service.com/status")
    return resp.text


# Safe: parameterized SQL query
async def query_db_safe(conn, user_id: int) -> list:
    return await conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))


# Safe: plain exception message with no sensitive data
async def safe_tool(query: str) -> str:
    try:
        return f"result: {query}"
    except ValueError as err:
        logger.error("Validation error: %s", str(err))
        return "Invalid input"


# Safe: descriptive text with no injection keywords or URLs
tool_description = "Searches the local filesystem for files matching a pattern"
tool_description2 = "Executes a database query and returns the results"

# Safe: non-credential variable names with string values
short_val = "hello"
base_url = "https://api.example.com"

# Safe: uvicorn with TLS
import uvicorn  # type: ignore[import]  # noqa: E402

# ssl args present — should not fire
# uvicorn.run(app, ssl_certfile="/certs/cert.pem", ssl_keyfile="/certs/key.pem")

# Safe: uvicorn bound to localhost
# uvicorn.run(app, host="127.0.0.1", port=8080)
