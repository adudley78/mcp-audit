"""Safe MCP sampling examples — for Semgrep rule testing ONLY.

These patterns should produce zero findings from mcp-sampling-fstring-prompt-injection
and mcp-sampling-variable-text-injection.
"""

from __future__ import annotations


# ok: mcp-sampling-fstring-prompt-injection — literal-only prompt
async def handle_tool_safe(ctx, arguments: dict) -> str:
    result = await ctx.sample(prompt="Summarize the latest news.")
    return str(result)


# ok: mcp-sampling-fstring-prompt-injection — fixed keyword prompt, no interpolation
async def analyze_data_safe(session) -> str:
    result = await session.create_message(
        messages=[
            {
                "role": "user",
                "content": {"type": "text", "text": "List the top 5 priorities."},
            }
        ],
        max_tokens=100,
    )
    return str(result)


# ok: mcp-sampling-variable-text-injection — literal string positional arg
async def literal_positional(ctx) -> str:
    result = await ctx.sample("What are the security best practices?", max_tokens=200)
    return str(result)


# ok: mcp-sampling-variable-text-injection — literal keyword prompt
async def literal_keyword(ctx) -> str:
    result = await ctx.sample(prompt="Explain MCP server security.", max_tokens=150)
    return str(result)
