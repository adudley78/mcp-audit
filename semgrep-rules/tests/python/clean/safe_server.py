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


# ---------------------------------------------------------------------------
# Safe auth patterns (should produce zero findings from auth rules)
# ---------------------------------------------------------------------------

from fastapi import Depends, Request  # noqa: E402


async def get_current_user(request: Request) -> dict:
    token = request.headers.get("Authorization", "")
    if not token:
        raise ValueError("Unauthorized")
    return {"user": "authenticated"}


# Safe: route with explicit auth dependency — not flagged by mcp-route-missing-auth-middleware
@app.get("/mcp_endpoint", dependencies=[Depends(get_current_user)])
async def safe_mcp_route(request: Request) -> dict:
    return {"ok": True}


# Safe: empty allowlist → deny all — not flagged by mcp-empty-allowlist-allow-all
def check_allowlist_safe(ip_allowlist: list[str], client_ip: str) -> bool:
    if not ip_allowlist:
        return False  # deny all when allowlist is unconfigured
    return client_ip in ip_allowlist


# Safe: allowlist raises on empty — not flagged by mcp-empty-allowlist-allow-all
def check_allowlist_strict(trusted_callers: list[str], caller_id: str) -> bool:
    if not trusted_callers:
        raise ValueError("Allowlist must not be empty; deny-by-default requires at least one entry")
    return caller_id in trusted_callers


# Safe: logs only request ID, not headers — not flagged by mcp-authorization-header-logged
async def log_request_id(request: Request) -> dict:
    request_id = request.headers.get("X-Request-ID", "unknown")
    logger.info("Processing request %s", request_id)
    return {"ok": True}


# Safe: logs a fixed error message in except, not the request body
async def process_safe_request(request: Request) -> dict:
    try:
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            raise ValueError("Missing Authorization header")
        return {"ok": True}
    except Exception:
        logger.error("Auth check failed — see request ID for correlation")
        return {"error": "auth failed"}
