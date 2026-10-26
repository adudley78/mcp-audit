# Permission rules that don't do what they say (PERM-001..007)

Claude Code's permission rules (`permissions.allow`, `permissions.ask`,
`permissions.deny` in `settings.json`) have a grammar with sharp edges. Anthropic
documents a set of rule forms that Claude Code ignores at load time, anchors
somewhere other than where they appear to point, or that are "not a security
boundary". mcp-audit reads every Claude Code settings file the scan already reads
for HARNESS-001..006 and reports each such rule, with the documented reason, the
form that gets past it, and what to write instead.

No new flags: these checks run in `mcp-audit check`, `mcp-audit scan`,
`mcp-audit scan --project <dir>` and the GitHub Action's default run. Nothing is
executed; the settings files are read as JSON.

Every rule below comes from Anthropic's documentation, quoted in the finding:
[permissions](https://code.claude.com/docs/en/permissions),
[sandboxing](https://code.claude.com/docs/en/sandboxing),
[settings reference](https://code.claude.com/docs/en/settings-reference),
[MCP](https://code.claude.com/docs/en/mcp), and the Claude Code
[CHANGELOG](https://github.com/anthropics/claude-code/blob/main/CHANGELOG.md)
for 2.1.299. Read on 2026-10-25.

## The checks

| ID | Severity | Fires when | Write instead |
|---|---|---|---|
| PERM-001 | HIGH in `deny`, MEDIUM in `ask`, INFO in `allow` | A rule Claude Code skips or never matches: a rule on a tool's primary content field (`Bash(command:rm *)`, `Read(file_path:…)`, `WebFetch(url:…)`, …); an `mcp__` rule with parentheses; a path rule for `Write`, `NotebookEdit`, `Glob` or `MultiEdit`; `:*` in the middle of a pattern (`Bash(git:* push)`); an unanchored allow glob (`*`, `B*`, `mcp__*`) | `Bash(rm *)`, `Read(./path)`, `WebFetch(domain:host)`; the `mcp__` name with no parentheses; `Edit(path)` / `Read(path)`; `Bash(git push *)`; named tools or `mcp__<server>__*` |
| PERM-002 | MEDIUM in `deny`/`ask`, INFO in `allow` | A `Read(/…)` or `Edit(/…)` rule with one leading slash that names a filesystem-root path (`/Users/…`, `/home/…`, `/etc/…`, `/c/Users/…`). One slash anchors at the settings source: the project root for project and local settings, `~/.claude` for user settings. Skipped when that anchored directory exists | `Read(//Users/…)` |
| PERM-003 | LOW | An allow rule whose trailing `*` has no space before it and extends the program name: `Bash(ls*)` also matches `lsof`. A rule HARNESS-005 already reports is not repeated | `Bash(ls *)` |
| PERM-004 | MEDIUM, or INFO | A Bash `deny` or `ask` rule on a network or delete command (`curl`, `wget`, `ssh`, `rsync`, `rm`, `dd`, `git push`, …) while this file doesn't set `sandbox.enabled: true`. It doesn't stop `/usr/bin/curl …` or `sh -c 'curl …'` (for `git push`: `git -C . push`, `git -c push.default=current push`, `git 'push'`). MEDIUM when this file also runs those forms without a prompt: an allow rule that approves any shell form (`Bash`, `Bash(*)`, `Bash(sh -c *)`, `Bash(bash:*)`, `Bash(env *)`, `Bash(sudo -E *)`, `Bash(* --version)`, `Bash(/usr/bin/*)`), or, in user settings only, `defaultMode` `bypassPermissions` or `auto` (the settings reference: those modes "don't take effect from project or local settings" since 2.1.257). INFO when they would still prompt, including narrow allows such as `Bash(./scripts/*)` or `Bash(bash scripts/test.sh *)` | `sandbox.enabled: true` with a network allowlist, or a PreToolUse hook |
| PERM-005 | HIGH with `sandbox.enabled: true` in the file, LOW otherwise | `WebFetch(domain:*)` in `allow`: "Claude fetches without prompting you, and sandboxed commands can reach any host" | A bare `WebFetch` allow rule, or `WebFetch(domain:<host>)` per host |
| PERM-006 | MEDIUM | A bare `Bash` or `Bash(*)` `ask` rule in a file that turns the sandbox on and leaves `autoAllowBashIfSandboxed` at its default (`true`), outside plan mode. "A bare `Bash` ask rule, or the equivalent `Bash(*)` form, is skipped for commands that run sandboxed" | `sandbox.autoAllowBashIfSandboxed: false`, or content-scoped ask rules such as `Bash(git push *)` |
| PERM-007 | HIGH | A whole-server allow rule (`mcp__<server>` or `mcp__<server>__*`) for a Claude Code MCP server that the same scan indicts with a HIGH or CRITICAL poisoning, rug-pull or supply-chain finding (an SC-004 CVE finding counts only when the configured version is known to be affected). The server is matched by its whole normalized name, as Claude Code 2.1.299 does. Under `scan --project`, a user-settings rule and a repository's server (and the reverse) are paired too | Remove the rule until the findings are fixed, or allow only the tools you checked (`mcp__<server>__<tool>`) |

Findings are grouped: one finding per check and severity in each settings file,
listing every rule it covers (up to 20, then "+N more"). PERM-007 is one finding
per settings file and server, attached to that server.

## How each rule is grounded

**PERM-001.** "You can't match a tool's primary content field this way:
`command` for Bash and PowerShell, `file_path` for Read, Edit, and Write, `path`
for Grep and Glob, `notebook_path` for NotebookEdit, and `url` for WebFetch. A
rule like `Bash(command:rm *)` would be bypassable by a compound command, so
Claude Code ignores it and emits a startup warning." "When Claude Code loads a
settings file, it skips any `mcp__` rule that has parentheses." "If you write a
path rule for `Write`, `NotebookEdit`, `Glob`, or legacy `MultiEdit`, Claude
Code accepts the rule but never matches a read or edit against it." "The `:*`
form is only recognized at the end of a pattern. In a pattern like
`Bash(git:* push)`, the colon is treated as a literal character and won't match
git commands." "An unanchored allow glob such as `"*"`, `"B*"`, or `"mcp__*"`
is skipped and doesn't auto-approve anything." A deny the author relies on is
HIGH; an allow that approves nothing is only INFO, because it fails safe.
Parameter rules that are valid (`Agent(model:opus)`, `Bash(run_in_background:true)`)
are not reported. `Bash(command:*)` is left alone because it is also the
documented `:*` prefix form for a program named `command`.

**PERM-002.** "A pattern like `/Users/alice/file` isn't an absolute path. The
single leading slash anchors at the settings source, not the filesystem root.
Use `//Users/alice/file` for absolute paths." And for user settings: "A deny
rule such as `Read(/secrets/**)` in user settings blocks `~/.claude/secrets/**`,
not a `secrets` directory in your project." `Edit(/src/**)` in project settings
is the documented way to anchor at the project root and is not reported; in
project and local settings only root-directory names are checked, and any rule
whose anchored directory exists on disk is skipped.

**PERM-003.** "The space before a trailing `*` is part of the rule.
`Bash(ls *)` requires a space after `ls`, so `lsof` doesn't match. `Bash(ls*)`
has no space, so it matches `lsof` too." Only the shape where the `*` extends
the program name is reported; `Bash(npm run test*)` stays within one program.

**PERM-004.** "A Bash rule matches the command text Claude writes … It doesn't
match the same program invoked in a different form, so a deny or ask rule
covers the invocation Claude usually produces and isn't a security boundary
around the program." The table that follows names `/usr/bin/curl`,
`sh -c 'curl …'`, `/bin/rm`, `bash -c 'rm …'`, `git -C . push`,
`git -c push.default=current push` and `git 'push'`. "Your other rules and the
permission mode decide the commands in the last column", which is why the
severity depends on whether this file would run those forms unprompted. A
`defaultMode` counts only in user settings: the settings reference says "`auto`
and `bypassPermissions` don't take effect from project or local settings, so
set them in `~/.claude/settings.json` instead. Before v2.1.257,
`bypassPermissions` took effect from any file." "For
filesystem and network enforcement that doesn't depend on the command text,
use sandboxing."

**PERM-005.** In the permissions doc's "Allow or deny every fetch" table, a
`WebFetch(domain:*)` allow means "Claude fetches without prompting you, and
sandboxed commands can reach any host", while a bare `WebFetch` allow
"Doesn't change which hosts sandboxed commands can reach". The sandboxing doc:
"In a `WebFetch(domain:...)` rule, the sandbox honors two wildcard forms: a
leading `*.` … and a bare `*`."

**PERM-006.** Sandboxing doc, auto-allow mode: "A bare `Bash` ask rule, or the
equivalent `Bash(*)` form, is skipped for commands that run sandboxed; it still
applies to commands that run outside the sandbox. In plan mode, the rule isn't
skipped." Settings reference: `autoAllowBashIfSandboxed` "Default: `true`".

**PERM-007.** CHANGELOG 2.1.299: "Changed MCP allow rules to reach only the
server they name: `mcp__a` no longer allows a server named `a__b` or `a_`;
write `mcp__<server>__*` with the server's whole normalized name." Permissions
doc: the bare `mcp__reports__v2` and `mcp__reports` "don't match its tools as
allow rules, because Claude Code reads both as rules for a server named
`reports`". Names are normalized the way Claude Code builds tool names: "any
character outside `A-Z`, `a-z`, `0-9`, `_`, and `-` is replaced with `_`", and
a plugin's server is `plugin_<plugin-name>_<server-name>` (MCP doc). PERM-007
runs after every other analyzer, because it needs their findings, and under
`scan --project` once more across the default and project scans, so a
`~/.claude/settings.json` rule meets a repository's `.mcp.json` server.

## What is deliberately not reported

- **`ask` rules in `auto` or `bypassPermissions` mode.** The permission-modes doc
  lists "Tools matched by an explicit ask rule" among the "Actions no mode
  auto-approves", including `bypassPermissions`; in `dontAsk` mode a matching
  call is denied instead of prompting, which is stricter, not weaker. The
  compound-command gaps that once let an ask rule through in auto mode were fixed
  in Claude Code 2.1.98 and 2.1.257.
- **PowerShell `Invoke-Expression`, `iex`, `Start-Process` allow rules** are not
  a PERM-* finding: Anthropic documents no special behaviour for them. They are
  rules that approve running code, so they are reported as HARNESS-005 (MEDIUM),
  next to `Bash(python *)`.
- **Label-vs-canonical tool names** (`Stop Task` vs `TaskStop`): Anthropic
  publishes no canonical tool list to check against.
- **Findings that don't indict the server** do not make PERM-007 fire:
  config-file permissions (CFHYG-001 fires on any world-readable file),
  credentials stored in the config, transport, authentication, community rules
  (COMM-013 fires on every `npx -y` server, the documented install form),
  toxic-flow findings (TOXIC-*/INTEG-* describe capability combinations many
  legitimate servers have, and already carry their own severity), an SC-004 on
  an unpinned launch (the scan can't tell offline whether the installed release
  is affected), and hash or signature findings, which are added after the scan
  pipeline. On a 34-server fixture of commonly configured servers with every
  server allow-listed, this took PERM-007 from 6 findings to 0; a typosquatted
  server is still reported.

## Environment runners in HARNESS-005

STORY-0092 also extended HARNESS-005 ("an allow rule that approves commands that
can write files, run code or reach the network"; meaning and severity unchanged)
with the forms the permissions doc calls out: "Development environment runners
such as `direnv exec`, `devbox run`, `mise exec`, `npx`, and `docker exec` are
not in the list. Because these tools execute their arguments as a command, a
rule like `Bash(devbox run *)` matches whatever comes after `run`, including
`devbox run rm -rf .`." Now reported: `devbox run`, `mise exec`/`mise x`,
`direnv exec`, `docker exec|run`, `podman exec|run`, `kubectl exec`, `nix run`,
`npm exec`, `pnpm dlx|exec`, `yarn dlx|exec`, `bun x`, `pipx run`, `uv run`,
`poetry run` and `pdm run`, when the rule ends in a wildcard right after the
runner (a container, image, pod or directory argument and `--` are skipped) or
names a broad inner command. The doc's recommended fix,
`Bash(devbox run npm test)`, is not reported. PowerShell cmdlets that run a
string as code, start any program, or reach the network (`Invoke-Expression`/
`iex`, `Invoke-Command`/`icm`, `Start-Process`/`saps`,
`Invoke-WebRequest`/`iwr`, `Invoke-RestMethod`/`irm`) are in the same table.

## Limits

See `GAPS.md`, "PERM-001..007 read rules, not the effective policy". In short:
each settings file is checked on its own (Claude Code's merge of user, project,
local and managed settings is not modelled), the installed Claude Code version
is not read, and managed settings are not discovered.

## For tools that build on this

The parser is public: `mcp_audit.analyzers.permissions.load_claude_settings()`
returns the parsed rules (`PermissionRule`: list, tool, specifier), the
`sandbox` block, scope (`user`, `project`, `local`, `global`) and the directory
a `/path` rule anchors at.
