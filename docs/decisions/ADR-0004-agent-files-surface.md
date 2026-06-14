# ADR-0004: Agent-file security scanning surface

**Date:** 2026-06-14  
**Status:** Accepted  
**Deciders:** Adam (product), Claude (implementation)  

---

## Context

mcp-audit v0.13.0 scans MCP server configurations and IDE extensions.  A threat
actor who cannot directly attack a user's MCP config can instead attack the
*instruction files* the AI agent reads — custom slash commands, workspace rules,
Copilot instruction files, and project memory files (CLAUDE.md).

Published research (OWASP GenAI Top 10, May 2026; Unit 42 "Agentic Attack
Surfaces", Q1 2026) identifies three distinct surfaces:

1. **Skill / instruction files** — text read at agent startup or on-demand as
   slash commands.  Attacker writes a malicious `*.md` into `.claude/commands/`
   or `.cursor/rules/` in a repo the victim clones.
2. **Memory / context files** — injected verbatim into every session
   (CLAUDE.md, .claude/CLAUDE.md).  A persistent foothold for behavioral override.
3. **Hook command injection** — Claude Code lifecycle hooks execute shell commands;
   a hook that calls out to the network or modifies another config file provides
   both exfiltration and persistence channels (CVE-2026-30615).

The question was: how do we scan these surfaces while keeping the architecture
clean and the default scan byte-identical?

---

## Decision

### New package: `src/mcp_audit/agent_files/`

Mirror the structure of `extensions/`:

```
agent_files/
├── __init__.py
├── models.py      — AgentFile dataclass, AgentFileSurface StrEnum
├── discovery.py   — discover_agent_files(project_root)
└── analyzer.py    — analyze_agent_files(files) → list[Finding]
```

### Finding IDs

| ID | Severity | Surface | Pattern source |
|---|---|---|---|
| SKILL-001 | HIGH | skills/commands/instructions | poisoning.PATTERNS (non-obfuscation) |
| SKILL-002 | MEDIUM | skills/commands | obfuscation patterns + ≥2000-char body |
| SKILL-003 | MEDIUM | skills/instructions | raw http(s):// URL in instruction text |
| MEM-001 | MEDIUM | memory (CLAUDE.md) | POISON-012 (behavioral override) only |
| MEM-002 | MEDIUM | memory (CLAUDE.md) | POISON-010/011/040/060 restricted set |
| HOOK-001 | HIGH | hooks (any claude config) | curl/wget/nc/URL in hook command |
| HOOK-002 | HIGH | hooks (any claude config) | agent config path in hook command |

### Pattern import policy

Analyzers **import** constants from `poisoning.py` — patterns are never forked
or duplicated.  This keeps the single source of truth intact.

### Hook analysis placement

`HOOK-001` and `HOOK-002` extend `ConfigHygieneAnalyzer.analyze_config()`.
Hook responsibility stays with the existing config-hygiene analyzer rather than
splitting into a new analyzer.  Rationale: hook commands are found in the same
JSON config files that `ConfigHygieneAnalyzer` already reads; reusing the
`analyze_config` call in the pipeline avoids a second file parse.

### Memory pattern restriction

Memory analysis uses a **restricted** pattern subset (POISON-010/011/040/060)
to control false-positive rate on innocuous project `CLAUDE.md` files.  The
full poisoning pattern set — especially POISON-050 (excessive length) — would
produce too many FPs on legitimate large context files.

### CLI integration

- `mcp-audit agent-files discover|scan` — standalone subapp
- `mcp-audit scan --include-agent-files` — additive flag (default scan
  byte-identical; no new findings without the flag)
- `--project PATH` already triggers project-tree walking; `--include-agent-files`
  also passes the resolved project root to the agent-file discoverer

---

## Rejected alternatives

### Alternative: separate `hooks_analyzer.py`

Splitting hook analysis into a new `BaseAnalyzer` subclass would require
running it in `_run_static_pipeline()` with a `ServerConfig` argument — but
hooks are config-file-level, not server-level.  Using the existing
`analyze_config()` path is cleaner.

### Alternative: full poisoning patterns for memory

Running all PATTERNS on CLAUDE.md produces FPs on project context files that
mention SSH keys in troubleshooting notes, reference external URLs in
documentation, or describe behavioral guidelines in neutral language.  The
restricted set eliminates these while preserving high-signal patterns.

### Alternative: single `agent-files` analyzer class

Matching the `BaseAnalyzer` interface would require wrapping files in fake
`ServerConfig` objects.  The flat function approach (`analyze_agent_files(files)`)
is simpler and avoids adapter code.

---

## Consequences

- Default scan is byte-identical — no new findings unless `--include-agent-files`
  is passed.
- Zero FPs on benign agent files is the ship bar (enforced by
  `test_false_positive_benchmark.py::TestAgentFileFalsePositives`).
- CFHYG-005 now fires on project-level `.claude/settings.json` and
  `.claude/settings.local.json` in addition to user-global `~/.claude.json`.
- HOOK-001/002 are the first finding IDs to cite CVE-2026-30615.
- Unconfirmed surfaces (Windsurf, Augment, Kiro, `.claude/skills/`) are tracked
  in GAPS.md — no code written for unconfirmed paths.
