"""Claude Code plugin inventory and integrity (STORY-0080).

Reads only what Claude Code documents and records on disk under the plugins
root (``~/.claude/plugins`` unless ``CLAUDE_CODE_PLUGIN_CACHE_DIR`` is set):
``installed_plugins.json``, ``known_marketplaces.json``, each marketplace's
``.claude-plugin/marketplace.json``, and the installed plugin directories.
Fully offline.  Never executes git, a package manager, or the agent.
"""
