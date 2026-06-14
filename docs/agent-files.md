# mcp-audit: agent-file security scanning

mcp-audit v0.14.0 extends scanning beyond MCP config files to cover the other
instruction surfaces an AI agent reads: custom slash commands, workspace rules,
Copilot instruction files, and project memory files.

---

## Why agent files matter

A threat actor who cannot write to your MCP config can instead modify an
instruction file you load into your agent on every session.  Published attacks
(Unit 42, OWASP GenAI Top 10 2026, CVE-2026-30615) demonstrate three vectors:

1. **Instruction injection** — a malicious repo includes a `.claude/commands/*.md`
   or `.cursor/rules/*.mdc` with a hidden override directive.  When you open the
   repo in your AI editor, the agent reads the file and its behavior is compromised.

2. **Memory poisoning** — if your `CLAUDE.md` is modified (e.g., via a supply-chain
   attack or a compromised project), every subsequent session includes the injected
   instruction.

3. **Hook command injection** (CVE-2026-30615) — Claude Code lifecycle hooks
   execute shell commands.  A hook that calls `curl` can exfiltrate session
   content; a hook that writes to another config file survives a config reset.

---

## Scanned surfaces

| Surface | Client | Location |
|---|---|---|
| Custom slash commands | Claude Code | `~/.claude/commands/*.md` |
| Project commands | Claude Code | `.claude/commands/*.md` (project) |
| User memory | Claude Code | `~/.claude/CLAUDE.md` |
| Project memory | Claude Code | `CLAUDE.md`, `.claude/CLAUDE.md` |
| AI rules | Cursor | `~/.cursor/rules/*.mdc` |
| Project rules | Cursor | `.cursor/rules/*.mdc` |
| Workspace instructions | GitHub Copilot | `.github/copilot-instructions.md` |
| Scoped instructions | GitHub Copilot | `.github/instructions/*.instructions.md` |
| Prompt templates | GitHub Copilot | `.github/prompts/*.prompt.md` |

Hook analysis covers `~/.claude.json`, `.claude/settings.json`, and
`.claude/settings.local.json` (all Claude Code config files that can contain
a `hooks` section).

---

## Finding IDs

### SKILL-001 (HIGH): injection/exfiltration instruction in skill file

Fires when any of the standard poisoning patterns (XML injection markers,
LLM format markers, behavioral override, data exfiltration references, etc.)
match the body of a skill, command, or instruction file.

Patterns are **imported** from `analyzers/poisoning.py` — no duplicated logic.

### SKILL-002 (MEDIUM): obfuscated or oversized block

Fires on:
- Zero-width Unicode characters (invisible to human reviewers; visible to LLMs)
- Homoglyph substitution (look-alike characters hiding instructions)
- File body ≥ 2 000 characters (potential hidden content via excessive padding)

### SKILL-003 (MEDIUM): skill file references external URL

Fires when the body contains a raw `https?://` URL.  Instruction files that
reference external content could pull in attacker-controlled instructions at
runtime.

### MEM-001 (MEDIUM): imperative override instruction in memory file

Fires when the behavioral-override pattern (`POISON-012`) matches a `CLAUDE.md`
memory file.  Memory files are injected into every session — a single injected
override provides persistent agent control.

### MEM-002 (MEDIUM): injection pattern in memory file

Fires on the **restricted** pattern subset for memory:
- `POISON-010` — XML injection markers (`<SYSTEM>`, `<INST>`, etc.)
- `POISON-011` — LLM format markers (`[INST]`, `<<SYS>>`, etc.)
- `POISON-040` — zero-width Unicode
- `POISON-060` — homoglyphs

Exfiltration, cross-tool, and excessive-length patterns are **excluded** to
control false-positive rate on legitimate project context files.

### HOOK-001 (HIGH): hook command contains network egress

Fires when a Claude Code hook command contains a network-egress primitive:
`curl`, `wget`, `nc`, `socat`, `Invoke-WebRequest`, or a raw `https?://` URL.

A network-egress hook can exfiltrate tool outputs, conversation content, or
credentials to an attacker-controlled server without any user interaction.

### HOOK-002 (HIGH): hook command references agent config file path

Fires when a hook command references an MCP or agent config file path
(`.claude.json`, `claude_desktop_config.json`, `.cursor/mcp.json`, etc.).

This matches the CVE-2026-30615 persistence pattern: a hook that modifies
another agent config file can inject new servers or hooks that survive
user-initiated configuration resets.

---

## Usage

### Standalone scan

```bash
# Scan user-global agent files
mcp-audit agent-files scan

# Scan user-global + project-level files
mcp-audit agent-files scan --project /path/to/repo

# JSON output
mcp-audit agent-files scan --project . --format json
```

### Discovery only

```bash
mcp-audit agent-files discover --project /path/to/repo
```

### Integrated with full scan

```bash
# Additive — default scan is byte-identical without this flag
mcp-audit scan --include-agent-files

# Combined with project-level scan
mcp-audit scan --project /path/to/repo --include-agent-files
```

---

## Known limitations

- **Windsurf, Augment, Kiro** agent file locations are unconfirmed — tracked
  in `GAPS.md`, not yet scanned.
- **`.claude/skills/`** (a distinct path from `.claude/commands/`) — format
  unconfirmed, tracked in `GAPS.md`.
- **User-global Copilot instructions** (`~/.config/GitHub Copilot/`) — path
  unconfirmed across OS versions, tracked in `GAPS.md`.
- **False positives** — Copilot instruction and Cursor rule files that
  legitimately reference external URLs will trigger SKILL-003.  Use the
  `--severity-threshold medium` flag to suppress if the FP rate is too high
  for your workflow.

---

## References

- OWASP GenAI Top 10 for LLM Risks (2026) — "Memory is a feature. It is also
  an attack surface" (May 2026)
- Unit 42, "Agentic Attack Surfaces: From Config to Memory" (Q1 2026)
- CVE-2026-30615 — Claude Code hook injection via config file write
- CVE-2025-59536 — Claude Code hook section command injection
- Adversa AI TrustFall (May 2026) — project-level instruction file attacks
