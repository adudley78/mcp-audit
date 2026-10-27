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
| User skills | Claude Code | `~/.claude/skills/**/SKILL.md` (any nesting depth) |
| Project skills | Claude Code | `.claude/skills/**/SKILL.md` (project, any nesting depth) |
| User memory | Claude Code | `~/.claude/CLAUDE.md` |
| Project memory | Claude Code | `CLAUDE.md`, `.claude/CLAUDE.md` |
| AI rules | Cursor | `~/.cursor/rules/*.mdc` |
| Project rules | Cursor | `.cursor/rules/*.mdc` |
| Workspace instructions | GitHub Copilot | `.github/copilot-instructions.md` |
| Scoped instructions | GitHub Copilot | `.github/instructions/*.instructions.md` |
| Prompt templates | GitHub Copilot | `.github/prompts/*.prompt.md` |
| User subagents | Claude Code | `~/.claude/agents/**/*.md` (files with frontmatter) |
| Project subagents | Claude Code | `.claude/agents/**/*.md` (project, files with frontmatter) |

Hook analysis covers `~/.claude.json`, `.claude/settings.json`, and
`.claude/settings.local.json` (all Claude Code config files that can contain
a `hooks` section).

A skill is more than its `SKILL.md`. Every other file in each skill folder
(scripts, reference files, archives, `bin/`, `.git/`, and the plugin
components of a skill folder that holds `.claude-plugin/plugin.json`) is read
in the default `scan` and `check` and reported as SKILL-005..008; with
`--include-agent-files` the `SKILL.md` rules below also run on the skill's
other prose files. See [skill-packages.md](skill-packages.md).

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

### POISON-041 (HIGH) / POISON-042 (LOW): concealment channels

Fires on skill, command, and memory files alike when the file body contains
a **concealment channel** — content hidden from a human reviewer while fully
present to a language model reading the raw text:

- A contiguous run of Unicode TAG characters (U+E0000–U+E007F) that decodes
  to ASCII. TAG characters render as nothing in every renderer, and each one
  in the printable range mirrors an ASCII character at `codepoint - 0xE0000`
  — the "ASCII smuggling" technique (Rehberger, 2024).
- An HTML comment (`<!-- ... -->`), invisible when this file is rendered as
  Markdown.

The concealed content is extracted into its own string and rescanned against
the full poisoning `PATTERNS` list as an independent pass — it is never
spliced back into the file body, so a match can never span the concealed
content and its surroundings.

- **POISON-041 (HIGH)** — the decoded/extracted content matches an existing
  pattern. Evidence shows the decoded/extracted ASCII text, explicitly
  labelled, since the concealed bytes themselves would render as nothing.
- **POISON-042 (LOW)** — TAG characters are present but decode to nothing
  that matches. **HTML comments never trigger this tier on their own** —
  an ordinary editorial comment (`<!-- TODO: ... -->`) is common and
  legitimate in Markdown and must stay silent; only a TAG-character run's
  bare presence is anomalous enough to report without a matched payload.

Both findings carry `analyzer="poisoning"`, not `analyzer="agent_files"` —
a deliberate exception, shared unchanged with the config-surface analyzer
(`PoisoningAnalyzer`) so the detection logic and finding text never drift
between the two surfaces.

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

### HARNESS-001..006: settings that switch human approval off, and what replaced it

Claude Code settings files (`~/.claude/settings.json`, a project's
`.claude/settings.json` and `.claude/settings.local.json`, and `~/.claude.json`)
can turn off the approval prompts that stand between an injected instruction and
an executed one. HarnessSecurity-Bench (arXiv 2610.07639, October 2026) measured
attack success on coding agents rising from 29.2% to 95.6% with auto-approve on.
Keys and semantics follow code.claude.com/docs/en/permissions.

| ID | Severity | Fires when |
|---|---|---|
| HARNESS-001 | HIGH | `permissions.defaultMode` is `bypassPermissions` |
| HARNESS-002 | HIGH | `enableAllProjectMcpServers` is `true` (every server in a repo's `.mcp.json` approved without a prompt) |
| HARNESS-003 | MEDIUM | `skipDangerousModePermissionPrompt` is `true` |
| HARNESS-004 | HIGH | `permissions.allow` contains bare `Bash`, `Bash(*)`, `PowerShell` or `PowerShell(*)` |
| HARNESS-005 | MEDIUM | `permissions.allow` approves every argument to a command that can write, run code or reach the network: an interpreter or shell, `curl`/`wget`/`ssh`/…, `gh`/`aws`/`gcloud`/`az`/`kubectl`/`docker`/`terraform`, a package runner or manager, `rm`, `find`, `xargs`, `env`, `sudo`, bare `git`; plus `git push`, `npm publish` and `gh api` even when narrowed (STORY-0087); an environment runner left open (`devbox run *`, `docker exec <container> *`, `uv run *`, …) and PowerShell `Invoke-Expression`/`iex`, `Start-Process`, `Invoke-WebRequest` (STORY-0092) |
| HARNESS-006 | MEDIUM | Approval is off in this file (as HARNESS-001 or HARNESS-003) and the same file has no `permissions.deny` rule for recursive deletes (`rm -r`/`-rf`, `Remove-Item -Recurse`, `rd /s`, `rmdir /s`) and no PreToolUse hook matching shell commands (STORY-0087) |

HARNESS-005 and HARNESS-006 ask what replaced the approval prompt. People who turn
approval off rely on allow rules and hooks instead; a rule like `Bash(gh:*)` approves
`gh api` writes too, and bypass mode with nothing denying recursive deletes leaves the
filesystem unguarded. `permissions.disableBypassPermissionsMode: "disable"` in the
same file suppresses HARNESS-001, HARNESS-003 and HARNESS-006. Each file is checked on its own; Claude Code's
precedence across user, project, local and managed settings is not modelled (see
`GAPS.md`). `~/.claude/settings.json` is discovered for these checks from
STORY-0079 on, which also brings user-level hooks under HOOK-001/002 and CFHYG-005.
From STORY-0082 on, a scan run inside a repository also reads that repository's
`.claude/settings.json` and `.claude/settings.local.json` (client
`claude-code-project`), so the GitHub Action's default run fails a pull request
that switches approval off. An explicit `--path` still scans only what it names.

The same files are also linted for rules that don't do what they say
(PERM-001..007: ignored rule forms, misanchored paths, deny rules that aren't a
boundary without the sandbox, `mcp__` allow rules on flagged servers); see
[permission-rules.md](permission-rules.md).

### AGENT-001..004: subagent definitions as a config surface (STORY-0094)

A Claude Code subagent definition is a Markdown file under `.claude/agents/`
(project) or `~/.claude/agents/` (user), read recursively, whose YAML
frontmatter changes what the subagent may do. Semantics come from
[Anthropic's sub-agents doc](https://code.claude.com/docs/en/sub-agents), the
[permissions doc](https://code.claude.com/docs/en/permissions) and the Claude
Code CHANGELOG, read 2026-10-25.

| ID | Severity | Fires when |
|---|---|---|
| AGENT-001 | MEDIUM (project) / LOW (user) | `permissionMode: bypassPermissions`. Since Claude Code 2.1.267 a subagent runs in bypass mode only when your main session already does; before that it skipped every prompt even from a default-mode session (HIGH). |
| AGENT-001 | MEDIUM | `permissionMode: acceptEdits` or `auto` in a **project** subagent: from a default or dontAsk session, Claude Code runs that subagent with fewer prompts than you chose. |
| AGENT-002 | INFO | `disallowedTools` has an entry with a `(…)` specifier such as `Bash(git push *)`, which removes the whole tool, not only the matching calls. Put the specifier in `permissions.deny` instead. |
| AGENT-003 | MEDIUM (project) / INFO (user) | Frontmatter `hooks:`. Since 2.1.218 a project subagent's hooks run only once the folder holding the file is trusted (HIGH before, when they ran from untrusted folders). Each hook command also goes through HOOK-001/002. |
| AGENT-004 | INFO / LOW / MEDIUM | One per inline `mcpServers` item (a repeated name is kept as `fs`, `fs#2`…, since Claude Code starts every item). LOW when the server name contains `__` or ends in `_`, which `mcp__<server>` permission rules read as a different server. MEDIUM for a project subagent's server when the repository has an `mcp-lock.json`: the lock does not cover it. |

The same IDs also report two things about the frontmatter itself, at the
severity the key would get in that scope (`permissionMode` → AGENT-001,
`tools`/`disallowedTools` → AGENT-002, `hooks` → AGENT-003, `mcpServers` →
AGENT-004): a security key that appears more than once ("Subagent frontmatter
repeats '…'"; every value is checked), and a security key that is present but
unreadable by mcp-audit ("Claude Code may load it").

**Not flagged:** `permissionMode: dontAsk` auto-denies anything that would
prompt, so it is stricter than `default` despite its name; `plan`, `default`
and `manual` loosen nothing; `acceptEdits`/`auto` in your own
`~/.claude/agents/` file is the documented feature working as you set it.

**Where these run.** Subagent definitions are part of default discovery, like
Claude Code plugins: a plain `mcp-audit scan` or `mcp-audit check` reads
`~/.claude/agents/` and the current directory's `.claude/agents/`, and
`scan --project <dir>` walks every `.claude/agents/` under `<dir>`.
AGENT-001..004 and HOOK-001/002 come from that discovery, so the GitHub
Action's default run sees them with no new input. An explicit `--path` scans
only what it names. The **body** of each definition (the subagent's system
prompt) gets the same rules as commands and skills (SKILL-001/002/003,
POISON-041/042), without the SKILL-002 length check, wherever skills are
scanned: `scan --include-agent-files` and `mcp-audit agent-files scan`.

**Inline servers are servers.** Each inline `mcpServers` entry joins
discovery as client `claude-code-agent`, so it gets every per-server check,
appears in `mcp-audit shadow`, `discover`, the attack graph and `killchain`,
and gets TRUST-001 under `scan --project`. Like plugin servers they are never
written to `mcp-lock.json` and never verified against it, and agent files do
not change the rug-pull state key, so an existing lock keeps verifying. A
project subagent server under a lock root is listed in `lock_status.not_covered`,
`scan` and `check` print a `WARN` line for it, and its AGENT-004 is MEDIUM.
String entries (`- github`) name a server configured elsewhere and add nothing;
a mapping item with more than one key is ignored, as Claude Code ignores it.

**Version notes.** mcp-audit never runs Claude Code, so it cannot see which
version you have. Each version-dependent finding uses the severity that holds
on current Claude Code and says what changes on older versions. The boundaries
quoted: 2.1.267 (subagent `bypassPermissions` no longer escalates), 2.1.218
(frontmatter hooks need folder trust), 2.1.153 (inline servers honour
`--strict-mcp-config`, `--bare` and managed MCP policy), 2.1.238 (a project
agent file's inline servers need folder trust).

**Parsing.** The frontmatter is read the way Claude Code 2.1.310's loader reads
it: files over 1 MiB are skipped (as Claude Code skips them, and the scan's
`errors` say so); a BOM is dropped; the frontmatter runs from the opening `---`
to the **first** `---` anywhere after it, even mid-line, so `# ---` or `----`
ends it. If the YAML does not parse, one-line `key: value` entries whose value
holds YAML syntax characters or `: ` are quoted, leading tabs become two
spaces, and the whole block is parsed again. Claude Code's retry pattern does not
match a line that ends in `\r`, so mcp-audit also retries a file with Windows
(CRLF) line endings using LF endings, as a Mac or Linux checkout of the same
file would be read. mcp-audit also reads the block up
to the first line that is exactly `---` and keeps the findings of both
readings, so a value placed after a mid-line `---` is still checked. YAML 1.2
scalars stay strings (`=`, dates). Aliases are resolved under a 100,000-value
budget; more than 20,000 YAML nodes, nesting deeper than 256 levels, or YAML
that still does not parse makes the frontmatter unreadable, and every security
key it names becomes a "present but unreadable" finding. A scan reads at most
500 definitions and 16 MiB per discovery pass in full and says so in `errors`;
Claude Code has no such limit, so the next 5,000 are pre-screened (first
64 KiB) and every security key their frontmatter names is a "present but
unreadable" finding with the reason "per-scan limit reached": HIGH for
`permissionMode`, `hooks` and `mcpServers` in a project directory, where a
repository could pad its agents directory to push a definition past the
limit, and the key's usual severity in `~/.claude/agents/`. A frontmatter
that runs past the 64 KiB window is reported for `permissionMode`, `hooks` and
`mcpServers` whether or not they were seen. Past that, one
AGENT-003 counts the definitions not read at all (HIGH in a project). A
`.md` file without frontmatter (a README) is not a definition. Credential-shaped
text in any finding (a token in a hook command or a `disallowedTools` entry)
is replaced with `[REDACTED]`.

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
- **User-global Copilot instructions** (`~/.config/GitHub Copilot/`) — path
  unconfirmed across OS versions, tracked in `GAPS.md`.
- **False positives** — Copilot instruction and Cursor rule files that
  legitimately reference external URLs will trigger SKILL-003.  Use the
  `--severity-threshold medium` flag to suppress if the FP rate is too high
  for your workflow.
- **Subagents**: plugin `agents/` directories are not read (Claude Code
  ignores `permissionMode`, `hooks` and `mcpServers` there); a default scan
  reads only the current directory's `.claude/agents/`, not the ones between
  it and the repository root (use `--project`); agents passed with `--agents`
  or the SDK are not files and are not seen. See `GAPS.md`.
- **SKILL-004** lists a skill's bundled `scripts/` filenames only — it never
  reads script contents and never executes them. A malicious script that a
  skill's prose merely *references* by name (without the file being present)
  is not caught by SKILL-004; it may still trip SKILL-001/002/003 on the
  `SKILL.md` body itself.

## Symlinked agent files (TRUST-002 / TRUST-004)

A matched file (or an intermediate directory segment such as `.claude` or
`.claude/skills/<name>`) that is itself a symlink is no longer dropped
silently — it is read normally (the OS follows the link transparently, so
coverage is unaffected) and reported: `TRUST-002` (HIGH outside the scanned
project root, MEDIUM inside, INFO if broken) for a project-scoped match,
`TRUST-004` (always INFO) for a user-global match — this is exactly how
dotfile managers (GNU Stow, chezmoi, yadm, dotbot) manage `~/.claude/` and
`~/.cursor/`, so it must never read as an accusation. A symlinked directory
encountered mid-walk is still never traversed (loop/blow-up protection,
unchanged) but now emits `TRUST-005` (LOW) naming it instead of the entire
subtree vanishing with no explanation. See
`humans/decisions/2026-09-08-trust-002-symlink-sites.md` (marcus repo).

**Exception: a symlinked skill folder** (decision 2026-10-26, marcus repo
`humans/decisions/2026-10-26-follow-symlinked-skill-folders.md`). A symlink
directly under `~/.claude/skills/` or `.claude/skills/` that points at a skill
is followed one level, because Claude Code reads skills that way and the skills
CLI installs them that way by default. The skill is read at its target and the
link is reported as `TRUST-004` (INFO); `SKILL-001..004`, the sidecar pass and
`SKILL-005..008` all run on it, and no `TRUST-005` is reported for that link.
In a repository the target must stay inside the repository: a link that leaves
it is `TRUST-002` HIGH and is not read. A link to the skills directory itself
or one of its ancestors, or to a folder with no skill in it, is still
`TRUST-005`. Nothing inside a followed skill is followed. See
[skill-packages.md](skill-packages.md).

---

## References

- OWASP GenAI Top 10 for LLM Risks (2026) — "Memory is a feature. It is also
  an attack surface" (May 2026)
- Unit 42, "Agentic Attack Surfaces: From Config to Memory" (Q1 2026)
- CVE-2026-30615 — Claude Code hook injection via config file write
- CVE-2025-59536 — Claude Code hook section command injection
- Adversa AI TrustFall (May 2026) — project-level instruction file attacks
