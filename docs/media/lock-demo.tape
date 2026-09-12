# docs/media/lock-demo.tape
#
# Deterministic terminal recording of `mcp-audit lock` -> drift -> `verify` ->
# `accept` -> `verify`. Produces docs/media/lock-demo.gif.
#
# Run from the mcp-audit repo root, on a scratch branch (this tape's own
# commands `git add` + `git commit` inside demo/lock, and `mcp-audit lock`
# writes demo/lock/mcp-lock.json — neither should land on main):
#
#   git switch -c content/lock-demo-recording
#   vhs docs/media/lock-demo.tape
#   git checkout -- demo/lock && rm -f demo/lock/mcp-lock.json
#   # keep only docs/media/lock-demo.gif (and this .tape file); discard the
#   # throwaway commit and drift edit made inside demo/lock above.
#
# The drift edit below (`args[-1] += "@1.0.0"`) must match the one
# demo/lock/run.sh makes (see STORY-0072/R57, updated to target 'notion' in
# STORY-0073/R58 — the demo no longer uses the deprecated server-github
# package) so the README, the GIF, and this script all show the same
# LOCK-001 output.
#
# If recording inside this repo's own dev checkout (rather than a plain
# clone), temporarily move .git/hooks/pre-commit out of the way first — its
# ruff/format/count-sync output has no relevance to an end-user demo and
# will visibly clutter the `git commit` frame. Restore it afterward.

Output docs/media/lock-demo.gif
Set FontSize 16
Set Width 1100
Set Height 620
Set Theme "Catppuccin Mocha"
Set TypingSpeed 40ms
Set Padding 20
Set Framerate 20

Hide
Type "export PS1='$ ' TERM=xterm-256color"
Enter
Type "clear"
Enter
Show

Type "cat demo/lock/.cursor/mcp.json"
Enter
Sleep 2.5s

Type "mcp-audit lock demo/lock"
Enter
Sleep 4s

Type "git add demo/lock/mcp-lock.json && git commit -qm 'Lock approved MCP servers' && echo committed"
Enter
Sleep 2s

# the drift: pin the notion server to a different version (same edit demo/lock/run.sh makes)
Type "python3 - <<'PY'"
Enter
Type "import json,pathlib;p=pathlib.Path('demo/lock/.cursor/mcp.json');d=json.loads(p.read_text())"
Enter
Type "d['mcpServers']['notion']['args'][-1]+='@1.0.0';p.write_text(json.dumps(d,indent=2))"
Enter
Type "PY"
Enter
Sleep 1.5s

Type "mcp-audit lock --verify demo/lock; echo exit=$?"
Enter
Sleep 5s

Type "mcp-audit lock --accept demo/lock && mcp-audit lock --verify demo/lock; echo exit=$?"
Enter
Sleep 4s
