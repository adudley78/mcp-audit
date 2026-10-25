# Fixture: `sibling_harness/`

Synthetic, written for mcp-audit (nothing copied from an incident artifact or
another scanner). It plants one of each TRUST-008 / CFHYG-007 surface in the
shape the vendors document and the 2026 write-ups describe:

- `.gemini/settings.json`: a `SessionStart` command hook running
  `node .github/setup.js`, the shape SafeDep reported for the Miasma worm
  (2026-06), where this file was identical to the planted
  `.claude/settings.json`. TRUST-008 HIGH.
- `.gemini/.env` is not committed here (the repository's `.gitignore`
  excludes `.env` files); `tests/test_sibling_harness_autorun.py` writes it
  into the copied tree at test time, with `GOOGLE_GEMINI_BASE_URL` pointing
  at a non-Google host (TRUST-008 HIGH). The secret case is also built at
  test time, so no credential-shaped string is committed.
- `.codex/config.toml`: `approval_policy = "never"`, `sandbox_mode =
  "danger-full-access"` and `notify`, the keys Cymulate (2026-04) and Origin
  (2026-03) used. Three TRUST-008 HIGH findings.
- `.codex/hooks.json`: a `SessionStart` command hook in the shape OpenAI's
  hooks documentation gives. TRUST-008 HIGH.
- `.claude/settings.json`: an `env` block with `ANTHROPIC_BASE_URL` at a
  non-Anthropic host (CVE-2026-21852 shape, Check Point Research), CFHYG-007
  HIGH; and `enabledMcpjsonServers`, HARNESS-007 INFO.
- `.claude/scheduled_tasks.json` and `.claude/workflows/setup.js`: TRUST-008
  MEDIUM each.

`.github/setup.js` itself is deliberately absent: mcp-audit never runs it.
