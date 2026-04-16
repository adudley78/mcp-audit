"""Vulnerable MCP server injection examples — for Semgrep rule testing ONLY.

DO NOT deploy or run this code. It intentionally contains security vulnerabilities.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

import aiohttp
import httpx
import requests


# --- subprocess injection ---

async def run_command(user_cmd: str) -> str:
    # ruleid: mcp-subprocess-string-cmd
    result = subprocess.run(user_cmd, capture_output=True)
    return result.stdout.decode()


async def open_process(cmd: str) -> None:
    # ruleid: mcp-subprocess-string-cmd
    proc = subprocess.Popen(cmd, shell=False)
    proc.wait()


async def system_call(cmd: str) -> int:
    # ruleid: mcp-os-system-call
    return os.system(cmd)


def shell_true_example(args: list[str]) -> None:
    # ruleid: mcp-shell-true-injection
    subprocess.run(args, shell=True)


# --- eval injection ---

async def execute_code(code: str) -> None:
    # ruleid: mcp-eval-tool-arg
    eval(code)


async def exec_dynamic(script: str) -> None:
    # ruleid: mcp-eval-tool-arg
    exec(script)


# --- path traversal ---

async def read_file(path: str) -> str:
    # ruleid: mcp-open-path-traversal
    with open(path, "r") as f:
        return f.read()


async def read_pathlib(user_path: str) -> str:
    # ruleid: mcp-pathlib-open-traversal
    return Path(user_path).read_text()


async def write_pathlib(user_path: str, content: str) -> None:
    # ruleid: mcp-pathlib-open-traversal
    Path(user_path).write_text(content)


# --- SSRF ---

async def fetch_url(url: str) -> str:
    # ruleid: mcp-requests-variable-url
    resp = requests.get(url)
    return resp.text


async def post_url(url: str, data: dict) -> str:
    # ruleid: mcp-requests-variable-url
    resp = httpx.post(url, json=data)
    return resp.text


async def aiohttp_fetch(url: str) -> str:
    # ruleid: mcp-aiohttp-variable-url
    async with aiohttp.ClientSession() as session:
        resp = await session.get(url)
        return await resp.text()


# --- SQL injection ---

async def query_db(conn, user_id: str) -> list:
    # ruleid: mcp-fstring-sql
    return await conn.execute(f"SELECT * FROM users WHERE id = {user_id}")


async def update_db(conn, table: str, value: str) -> None:
    # ruleid: mcp-string-concat-sql
    await conn.execute("UPDATE records SET name = " + value)
