# demo/run — `mcp-audit run` in enforce mode

EPIC-0009 Phase 1 demo. One small MCP server (`server.py`, one `add` tool),
locked with its tools and wrapped by `mcp-audit wrap --mode enforce`, then
three cases:

1. **Approved.** The agent sees `add`, and `add(2, 3)` returns 5, exactly as
   without the wrapper.
2. **Rug pull.** The server's config entry stays the same, but its tool
   description now tells the agent to read `~/.ssh/id_rsa` and hide it.
   Launched directly, the agent reads that text. Through `mcp-audit run`,
   the tool is withheld (LOCK-008): it's left out of `tools/list` and a call
   to it gets mcp-audit's error, so the injected text never reaches the agent.
3. **Drift.** Someone edits the server's launch in the config. `mcp-audit
   run` refuses to start it (LOCK-001, exit 78) and says how to approve it.

```bash
uv sync --all-extras        # or: pip install 'mcp-audit-scanner[mcp]'
bash demo/run/run.sh
```

Offline; it works on a copy in a temp directory and changes nothing in the
repository. `client.py` plays the agent: it launches the server from its
config entry the way a client does and prints what the agent would see.
`tests/test_demo_run.py` runs the script and checks every step.

What Claude Code shows for cases 2 and 3 is in
[docs/run.md](../../docs/run.md#what-a-refused-server-looks-like-in-each-client).
