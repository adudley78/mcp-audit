"""Vulnerable MCP server auth examples — for Semgrep rule testing ONLY.

DO NOT deploy or run this code. It intentionally contains security vulnerabilities
that map to CVE-2026-33032 (MCPwn) and CVE-2026-41495 (n8n-MCP log exposure).
"""
from __future__ import annotations

import logging

from fastapi import Depends, FastAPI, Request

app = FastAPI()
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Shared handler — the MCPwn pattern: two routes, same handler, only one
# has an auth guard. The unguarded route is flagged below.
# ---------------------------------------------------------------------------


async def get_current_user(request: Request) -> dict:
    token = request.headers.get("Authorization", "")
    if not token:
        raise ValueError("Unauthorized")
    return {"user": "authenticated"}


async def _handle_mcp_message(request: Request) -> dict:
    return {"status": "ok"}


# Safe sibling — has auth dependency (should NOT be flagged)
@app.get("/mcp", dependencies=[Depends(get_current_user)])
async def mcp_authenticated(request: Request) -> dict:
    return await _handle_mcp_message(request)


# ruleid: mcp-route-missing-auth-middleware
# Vulnerable leg — same handler, no auth dependency in the decorator call
@app.get("/mcp_message")
async def mcp_unauthenticated(request: Request) -> dict:
    return await _handle_mcp_message(request)


# ---------------------------------------------------------------------------
# Empty-allowlist treated as "allow all"
# ---------------------------------------------------------------------------


# ruleid: mcp-empty-allowlist-allow-all
def check_ip_allowlist(ip_allowlist: list[str], client_ip: str) -> bool:
    if not ip_allowlist:
        return True  # BUG: empty allowlist should deny, not allow
    return client_ip in ip_allowlist


# ruleid: mcp-empty-allowlist-allow-all
def check_trusted_callers(trusted_callers: list[str], caller_id: str) -> bool:
    if len(trusted_callers) == 0:
        pass  # BUG: falls through; caller proceeds without allowlist check
    return caller_id in trusted_callers


# ---------------------------------------------------------------------------
# Authorization header logged before auth check (CVE-2026-41495)
# ---------------------------------------------------------------------------


# ruleid: mcp-authorization-header-logged
async def debug_incoming_request(request: Request) -> dict:
    logging.info(request.headers)  # logs Authorization header
    return {"ok": True}


# ruleid: mcp-authorization-header-logged
async def trace_request(request: Request) -> dict:
    logger.debug(str(request.headers))  # same issue via logger instance
    return {"ok": True}


# ---------------------------------------------------------------------------
# API-key variable logged (CVE-2026-41495)
# ---------------------------------------------------------------------------


# ruleid: mcp-api-key-header-logged
async def authenticate_request(request: Request) -> dict:
    api_key = request.headers.get("x-api-key", "")
    logger.debug(api_key)  # logs the raw API key value before validation
    if not api_key:
        raise ValueError("Missing API key")
    return {"key": api_key}


# ---------------------------------------------------------------------------
# Full request body logged inside an except block (CVE-2026-41495)
# ---------------------------------------------------------------------------


# ruleid: mcp-full-request-body-logged-on-fail
async def process_mcp_request(request: Request) -> dict:
    try:
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            raise ValueError("Missing Authorization header")
        return {"ok": True}
    except Exception:
        logging.error(request.body)  # body may contain retry bearer token
        return {"error": "auth failed"}


# ruleid: mcp-full-request-body-logged-on-fail
async def handle_mcp_tool_call(request: Request) -> dict:
    try:
        payload = await request.json()
        if "token" not in payload:
            raise KeyError("token")
        return payload
    except Exception:
        logger.error(await request.body())  # async body in except — still flagged
        return {"error": "bad request"}
