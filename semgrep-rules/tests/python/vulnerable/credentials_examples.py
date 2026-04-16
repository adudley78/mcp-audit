"""Vulnerable MCP server credentials examples — for Semgrep rule testing ONLY.

DO NOT deploy or run this code. It intentionally contains security vulnerabilities.
"""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# --- hardcoded credentials ---

# ruleid: mcp-hardcoded-api-key
api_key = "sk-abcdefghijklmnopqrstuvwxyz12345678"

# ruleid: mcp-hardcoded-api-key
secret_key = "super_secret_value_that_is_very_long_and_should_not_be_here"

# ruleid: mcp-hardcoded-api-key
password = "my_hardcoded_password_for_the_mcp_server"

# ruleid: mcp-hardcoded-connection-string
DB_URL = "postgresql://admin:password123@db.internal:5432/production"

# --- secrets logged ---

async def handle_tool(api_key: str, token: str) -> str:
    # ruleid: mcp-print-sensitive-var
    print(api_key)

    # ruleid: mcp-logging-sensitive-var
    logging.debug(token)

    # ruleid: mcp-logging-sensitive-var
    logger.info(api_key)

    return "done"


# --- credentials in function args ---

# ruleid: mcp-env-var-not-used
async def tool_with_default(query: str, password="hardcoded_default_pass_123") -> str:
    return f"result for {query}"


# --- transport ---

import uvicorn
from flask import Flask

app = Flask(__name__)

# ruleid: mcp-fastapi-no-ssl
uvicorn.run(app, host="127.0.0.1", port=8080)

# ruleid: mcp-uvicorn-listen-all
uvicorn.run(app, host="0.0.0.0", port=8080)

# ruleid: mcp-flask-no-ssl
app.run(port=5000)

# ruleid: mcp-fastapi-listen-all
app.run(host="0.0.0.0", port=5000)
