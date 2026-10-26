# Permission rules that don't do what they say (PERM-001..007) and sandbox settings a repository can loosen (SANDBOX-001..005)

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

## Sandbox settings a repository can loosen (SANDBOX-001..005)

Claude Code's Bash sandbox is configured by the `sandbox` block of any settings
file, and Claude Code merges that block across user, project and local settings.
Anthropic's sandboxing doc says a repository's settings can turn on keys that
weaken it, and that some keys a repository can't set at all. mcp-audit reads the
same settings files as PERM-* and reports both, plus a local settings file that
is headed for git. Read on 2026-10-26:
[sandboxing](https://code.claude.com/docs/en/sandboxing),
[settings reference](https://code.claude.com/docs/en/settings-reference) (the
settings index gives each key's scope: `Any file`, `User or managed`, `Managed`),
[settings](https://code.claude.com/docs/en/settings) and
[permissions](https://code.claude.com/docs/en/permissions).

"Repository settings" means `.claude/settings.json` and
`.claude/settings.local.json` outside your home directory, the sandboxing doc's
"a repository's `.claude/settings.json` and `.claude/settings.local.json`". Your
own `~/.claude/settings.json` is your choice and gets only SANDBOX-004.

| ID | Severity | Fires when | Write instead |
|---|---|---|---|
| SANDBOX-001 | HIGH | A repository file sets `enableWeakerNestedSandbox`, `enableWeakerNetworkIsolation`, `network.allowAllUnixSockets` or `network.allowLocalBinding` to `true`, or the shared `.claude/settings.json` sets `enabled: false` | Remove them; a machine that needs one sets it in `~/.claude/settings.json` |
| SANDBOX-001 | MEDIUM | The shared `.claude/settings.json` sets `failIfUnavailable: false`, or a repository file sets `network.httpProxyPort` or `network.socksProxyPort` | Remove them; a proxy port belongs in managed or user settings |
| SANDBOX-002 | HIGH | A repository file's `excludedCommands` leaves a shell or interpreter (`python *`, `bash -c *`, `node *`), a package or environment runner (`npx *`, `uv run *`, `pnpm dlx *`), or a container runtime (`docker *`, `docker compose *`, `docker run *`, `podman *`) open with a trailing wildcard, or starts with `*`; or `network.allowUnixSockets` lists `docker.sock`, `podman.sock` or `containerd.sock` | Keep the tool sandboxed and grant one path (`filesystem.allowWrite`) or host (`network.allowedDomains`); put the narrowest exclusion in your own settings |
| SANDBOX-003 | MEDIUM | A repository file's `network.allowedDomains` admits a code host (`github.com`, `gitlab.com`, `bitbucket.org`), a paste site (`pastebin.com`, `paste.ee`, `hastebin.com`, `dpaste.com`, `dpaste.org`, `rentry.co`, `termbin.com`), a webhook receiver (`discord.com`, `discordapp.com`, `hooks.slack.com`, `webhook.site`), a subdomain of one, or `*` | The narrow hosts a tool needs (`registry.npmjs.org`); `deniedDomains` for upload hosts |
| SANDBOX-004 | INFO | A key this file can't set, with a value that would act: in project and local files the "User or managed" keys (`allowAppleEvents`, `allowNestedUserNamespaces: true`, `filesystem.disabled`, `network.strictAllowlist`, `network.tlsTerminate`, `ripgrep`, `credentials.allowPlaintextInject`/`awsPairs`/`sigv4`, credential `mask` entries) and the "Managed" keys (`bwrapPath`, `socatPath`, `filesystem.allowManagedReadPathsOnly`, `network.allowManagedDomainsOnly`); in user settings the Managed keys | Move the key to managed or user settings, or delete it |
| SANDBOX-005 | MEDIUM | `.claude/settings.local.json` inside a git work tree that no ignore file covers | Add it to `.gitignore`; `git rm --cached` it if it is already committed |
| SANDBOX-005 | LOW | A project or local settings file headed for git contains home-directory paths naming a person (`/Users/<name>`, `/home/<name>`, `C:\Users\<name>`, `/c/Users/<name>`) | `~/…` paths, or keep machine-specific entries in an ignored file |

**SANDBOX-001.** "Unless managed settings set them, a developer's user settings
or `--settings` can turn on the following keys. A repository's
`.claude/settings.json` can too, unless the sandbox is admin-required. Each one
weakens the sandbox" (`enableWeakerNestedSandbox`, `enableWeakerNetworkIsolation`,
`network.allowAllUnixSockets`, `network.allowLocalBinding`). What each does, from
the settings reference: the nested sandbox "exposes process information that a
fresh mount would hide" (Linux and WSL2); the weaker network isolation opens "a
potential data exfiltration path through the trust service" (macOS); every Unix
socket, including on WSL2 the interop socket that launches Windows binaries; and
on macOS, any port on localhost, where "A localhost service that doesn't require
authentication, such as a debugger, can then act for the command outside the
sandbox" (no effect on Linux and WSL2). The admin-required table lists `enabled`
and `failIfUnavailable` ("`false`, when the developer's `~/.claude/settings.json`
sets `true`") and the proxy ports among "the settings that loosen it"; for a port,
"Your proxy takes over filtering, and Claude Code stops applying its domain lists
and network prompts to traffic sent there". `enabled` and `failIfUnavailable`
are checked in the shared file only: Claude Code's own `/sandbox` panel writes
`enabled` to `.claude/settings.local.json`, so a `false` there is usually your own
choice. While managed settings or `--settings` make the sandbox admin-required
(Claude Code 2.1.285 or later), Claude Code ignores these keys in a repository's
files; the scan can't see managed settings, so the finding says so.

**SANDBOX-002.** "An excluded command runs with your full access. A broad entry
such as `docker *` covers everything that tool can do. If you write a pattern
that covers an interpreter, a script inside your working directory, or a tool
that acts on a file there, as `docker compose` does with its compose file, Claude
can write that file and then run it outside the sandbox." And: "allowing access
to `/var/run/docker.sock` effectively grants access to the host system through
the Docker socket" (`allowUnixSockets` applies on macOS only). Entries use
`Bash(...)` rule syntax, where "a pattern with no wildcard is an exact match", so
only entries whose arguments are left open are reported: `python *` is,
`python scripts/load_orders.py *` (the doc's own narrowed example) and
`uv run pytest *` are not. `sudo`, `eval` and `xargs` entries are not reported:
calls starting with them stay sandboxed. An excluded command still goes through
the permission flow ("Bash command (unsandboxed)" prompt), except in
`bypassPermissions` mode or when an allow rule covers it.

**SANDBOX-003.** "Allowing broad domains such as `github.com` can create paths
for data exfiltration. Because the proxy makes its allow decision from the
client-supplied hostname without inspecting TLS, code running inside the sandbox
can potentially use domain fronting", and "a project can add domains to your user
list unless a repository lock applies". The other hosts come from MITRE ATT&CK
[T1567.001](https://attack.mitre.org/techniques/T1567/001/) (code repository,
"https://api.github.com"), [T1567.003](https://attack.mitre.org/techniques/T1567/003/)
(text storage sites, "pastebin[.]com") and
[T1567.004](https://attack.mitre.org/techniques/T1567/004/) (webhooks, "Discord,
Slack, and webhook.site"). `*` is reported as every host: `WebFetch(domain:…)`
allow rules feed the same allowlist, and the sandbox honours "a bare `*`" there.
`github.example.com` (Anthropic's HIPAA example) is not a match.

**SANDBOX-004.** The settings reference gives these keys the scope "User or
managed" or "Managed", and says, for example, "Claude Code ignores a `true` in a
project's `.claude/settings.json` or `.claude/settings.local.json`"
(`allowNestedUserNamespaces`), "A repository can't turn it on or off"
(`strictAllowlist`), "Claude Code reads it only from managed settings so that a
user, project, or local file can't point the sandbox at a different binary"
(`bwrapPath`), and "Claude Code honors `mask` entries, `allowPlaintextInject`,
`awsPairs`, and `sigv4` only from user settings, managed settings, and the
`--settings` flag." A key at its default (`false`, empty) is not reported. The
finding names the keys that look like locks, because those are the ones whose
author believes something holds. Anthropic's HIPAA example, which is meant for
managed settings, gets this INFO when committed as project settings.

**SANDBOX-005.** The settings doc: Claude Code "keeps it out of git when it
creates the file; if you create it by hand, add it to `.gitignore` yourself", and
it does so by adding `**/.claude/settings.local.json` to "your global git excludes
file ... `core.excludesFile` when your global git config sets it to an absolute
or `~`-prefixed path; otherwise it's `$XDG_CONFIG_HOME/git/ignore`, or
`~/.config/git/ignore`". The permissions doc: "When the file is tracked in git, or
`.claude` is a symlink, Claude Code treats it as repository-supplied instead and
holds its rules until you trust the folder." mcp-audit never runs `git` (a
checkout can carry `core.fsmonitor`, STORY-0089). It finds the nearest `.git`
entry at or above the project, then reads, in git's order of precedence, the
global excludes file, `.git/info/exclude`, and every `.gitignore` from the
work-tree root down to `.claude/`, and applies gitignore(5) matching (negation,
directory-only patterns, anchoring, `**`, and "It is not possible to re-include a
file if a parent directory of that file is excluded"). A `.gitignore` that is a
symlink is skipped, as git does since 2.32. If an ignore file can't be read
(permissions, larger than 1 MiB, or the scan's 512-file / 8 MiB budget), the file
is skipped and the reason goes to the scan's errors, without absolute paths.
Placeholder and shared-account names (`/Users/you`, `/home/runner`,
`C:\Users\Public`, `$USER`) are not counted as a person. UpGuard collected 18,470
committed `.claude/settings.local.json` files from public GitHub and found 8,341
permission entries containing usernames
([UpGuard](https://www.upguard.com/blog/yolo-mode-hidden-risks-in-claude-code-permissions)).

**Precision.** Anthropic's four example settings files (`settings-strict`,
`-lax`, `-bash-sandbox`, `-hipaa`), checked as project, local and user settings,
produce nothing above INFO (the HIPAA file's two managed-only locks give
SANDBOX-004 INFO). Across those files plus every settings-shaped JSON block in
the sandboxing, settings, settings-reference, permissions and permission-modes
pages (283 configs, 58 with a `sandbox` block), every finding above INFO is a doc
snippet that demonstrates exactly one loosening key (`excludedCommands:
["docker *"]`, `allowedDomains: ["github.com"]`, `allowLocalBinding: true`, a
proxy port), which is what the check is for when the file is a repository's. As
user settings the same configs give five SANDBOX-004 INFO notes and nothing else.

**Not reported** (see `GAPS.md`): `filesystem.allowWrite` entries that reach
shell startup files or `$PATH` directories (the doc's "Filesystem permission
escalation" warning), `ignoreViolations`, `allowMachLookup`, a repository's
`autoAllowBashIfSandboxed: true` or `allowUnsandboxedCommands: true` (the second
overrode a user's `false` before 2.1.285), content hosts added through
`WebFetch(domain:…)` allow rules, and managed-only keys outside the `sandbox`
block.

## Limits

See `GAPS.md`, "PERM-001..007 read rules, not the effective policy" and
"SANDBOX-001..005". In short: each settings file is checked on its own (Claude
Code's merge of user, project, local and managed settings is not modelled), the
installed Claude Code version is not read, and managed settings are not
discovered, so a sandbox that managed settings make admin-required is not seen.
SANDBOX-005 decides ignore state from ignore files, not from `.git/index`.

## For tools that build on this

The parser is public: `mcp_audit.analyzers.permissions.load_claude_settings()`
returns the parsed rules (`PermissionRule`: list, tool, specifier), the
`sandbox` block, scope (`user`, `project`, `local`, `global`) and the directory
a `/path` rule anchors at.
