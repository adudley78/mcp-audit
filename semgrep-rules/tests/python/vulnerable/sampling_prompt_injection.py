"""Vulnerable MCP sampling prompt injection examples — for Semgrep rule testing ONLY.

DO NOT deploy or run this code. It intentionally contains security vulnerabilities.
"""

from __future__ import annotations

# --- mcp-sampling-fstring-prompt-injection ---


# ruleid: mcp-sampling-fstring-prompt-injection
async def handle_fetch_tool(ctx, arguments: dict) -> str:
    user_url = arguments.get("url")
    result = await ctx.sample(prompt=f"Fetch and summarize: {user_url}")
    return str(result)


# ruleid: mcp-sampling-fstring-prompt-injection
async def handle_analyze_tool(ctx, arguments: dict) -> str:
    user_input = arguments.get("input")
    result = await ctx.sample(f"Analyze this content: {user_input}", max_tokens=200)
    return str(result)


# ruleid: mcp-sampling-fstring-prompt-injection
async def handle_concat_prompt(ctx, arguments: dict) -> str:
    user_data = arguments.get("data", "")
    prompt = "Process the following: " + user_data
    result = await ctx.sample(prompt, max_tokens=100)
    return str(result)


# ruleid: mcp-sampling-fstring-prompt-injection
async def handle_concat_kwarg_prompt(ctx, arguments: dict) -> str:
    user_text = arguments.get("text", "")
    prompt = "Summarize: " + user_text
    result = await ctx.sample(prompt=prompt, max_tokens=100)
    return str(result)


# --- mcp-sampling-variable-text-injection ---


# ruleid: mcp-sampling-variable-text-injection
async def handle_variable_prompt(ctx, user_prompt: str) -> str:
    result = await ctx.sample(user_prompt, max_tokens=500)
    return str(result)


# ruleid: mcp-sampling-variable-text-injection
async def handle_variable_kwarg_prompt(ctx, arguments: dict) -> str:
    prompt_text = arguments.get("prompt", "")
    result = await ctx.sample(prompt=prompt_text, max_tokens=300)
    return str(result)
