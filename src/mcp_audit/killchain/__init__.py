"""Decision engine: opinionated remediation view of the attack-path graph.

``mcp-audit killchain`` identifies the top N configuration changes that cut
the largest blast radius from the attack-path graph already computed by the
static analysis pipeline.  It wraps the greedy hitting-set algorithm in
:mod:`mcp_audit.analyzers.attack_paths` with human-readable metadata, a
what-if simulator, optional governance-policy patch generation, and Markdown /
JSON output formatters.

Public entry points
-------------------
- :func:`~mcp_audit.killchain.recommender.recommend` — rank kill switches.
- :func:`~mcp_audit.killchain.simulator.simulate` — what-if path reduction.
- :func:`~mcp_audit.killchain.patches.generate_yaml_patch` — policy patch.
- :func:`~mcp_audit.killchain.render.render_markdown` — Markdown report.
- :func:`~mcp_audit.killchain.render.render_json` — JSON report.
"""
