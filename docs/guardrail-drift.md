# Guardrail drift: flag when an agent's safety settings got weaker

mcp-audit already tracks MCP servers (`pin`, `baseline`, `lock`) and instruction files
([INSTR-001/002](agent-files.md)) over time. Guardrail drift does the same for the settings that
decide what an agent may do without asking: permission rules and modes, sandbox settings, hooks,
approval policy and MCP server approval, for Claude Code, Codex and Gemini CLI.

Why it exists: a text file in a download folder made Codex and Claude Code change their own
settings and install malware (reported by The Cyber News and aviatrixtrc), a malicious `AGENTS.md`
made both rewrite their configs, and OpenAI disclosed internal coding agents weakening their own
monitoring. A loosening is visible in the files alone, so mcp-audit says so the next time it looks.

Everything here is offline and read-only. mcp-audit reads the files, keeps a small record, and never
executes a hook or contacts a vendor.

## What is checked

Every scan with no explicit path (`scan`, `check`, `scan --project`) reads:

| Agent | Files |
|---|---|
| Claude Code | `~/.claude/settings.json` (or `$CLAUDE_CONFIG_DIR/settings.json`), and the working directory's `.claude/settings.json` and `.claude/settings.local.json` |
| Codex | `$CODEX_HOME/config.toml` (default `~/.codex/config.toml`) and the working directory's `.codex/config.toml` |
| Gemini CLI | `~/.gemini/settings.json` and the working directory's `.gemini/settings.json` |
| Claude Code managed policy | `managed-settings.json`, `managed-settings.d/*.json` and `managed-mcp.json` in the managed settings directory: a SHA-256 each, never the content |

`scan --project <dir>` adds every such file the project walk finds under `<dir>`. A scan with
`--path`, and `pin` / `diff`, does not run this step. When the working directory is your home
directory only the user files are read. A project file that is a symlink is not read here (it is
reported as TRUST-002/TRUST-004 elsewhere).

For each file mcp-audit keeps a normalised record of only the settings in the table below, as sorted
sets. **No secret value is stored**: strings are masked with the credential patterns, a Gemini
`tools.sandbox` command is stored only as "on", and each hook is stored as the event, the matcher and
the SHA-256 of the command string, never the command.

## What counts as loosening

One table, in `src/mcp_audit/guardrails.py` (`LOOSENING_TABLE`), each row with its source. **A change
that is not in this table is not a loosening**, whatever else it does. Only keys quoted by the
vendor's documentation (read 2026-11-04) or already quoted in this repository's analyzers are in it.
The orderings of `defaultMode`, Codex `approval_policy` and Gemini `defaultApprovalMode` are the
project's: the vendor pages list the values and say what each does, but do not rank them (see
`GAPS.md`). A value outside an ordering (for example Claude Code `dontAsk`, or a Codex `granular`
policy) is reported beside a loosening as "changed, not judged" and is never a loosening itself.

#### Claude Code

| Key | Loosening | HIGH? | Source |
|---|---|---|---|
| `permissions.allow` | gained an entry | no | https://code.claude.com/docs/en/permissions: "Rules are evaluated in order: deny, then ask, then allow." A new allow rule approves calls that would have prompted. |
| `permissions.deny` | lost an entry | yes | https://code.claude.com/docs/en/permissions: "Rules are evaluated in order: deny, then ask, then allow. The first match in that order determines the outcome." A lost deny rule lifts the first block. |
| `permissions.ask` | lost an entry | no | https://code.claude.com/docs/en/permissions (same evaluation order); https://code.claude.com/docs/en/permission-modes: tools matched by an explicit ask rule are among the actions no mode auto-approves (docs/permission-rules.md). |
| `permissions.additionalDirectories` | gained an entry | no | https://code.claude.com/docs/en/settings-reference: "Give Claude file access to directories outside the current one"; https://code.claude.com/docs/en/permissions: acceptEdits accepts edits "for paths in the working directory or additionalDirectories". |
| `permissions.defaultMode` | moved toward bypassPermissions (plan < default < acceptEdits < auto < bypassPermissions) | only when the new value is `bypassPermissions` | https://code.claude.com/docs/en/permission-modes, what runs without asking: default "Reads only"; acceptEdits "Reads, file edits, and common filesystem commands"; auto "Everything, with background safety checks"; bypassPermissions "Everything". The page does not rank the modes; this order is that table's. plan is placed lowest (exploration; it edits nothing) and dontAsk is not ranked: a change to or from it is not judged (GAPS.md). |
| `permissions.disableBypassPermissionsMode` | "disable" removed | no | https://code.claude.com/docs/en/settings-reference: "Prevent anyone from entering bypassPermissions mode"; https://code.claude.com/docs/en/permission-modes: set to "disable". |
| `sandbox.enabled` | true -> false/absent | yes | https://code.claude.com/docs/en/sandboxing: "The sandbox is off by default. To turn it on, run /sandbox ... or set sandbox.enabled to true". |
| `sandbox.failIfUnavailable` | true -> false/absent | no | https://code.claude.com/docs/en/sandboxing: "if the sandbox can't start ... Claude Code runs commands without sandboxing. To make Claude Code exit at startup instead, set sandbox.failIfUnavailable to true." |
| `sandbox.enableWeakerNestedSandbox` | false/absent -> true | no | https://code.claude.com/docs/en/settings-reference (sandbox.*; analyzers/sandbox.py, docs/permission-rules.md: "Each one weakens the sandbox") |
| `sandbox.enableWeakerNetworkIsolation` | false/absent -> true | no | https://code.claude.com/docs/en/settings-reference (sandbox.*; analyzers/sandbox.py, docs/permission-rules.md: "Each one weakens the sandbox") |
| `sandbox.network.allowAllUnixSockets` | false/absent -> true | no | https://code.claude.com/docs/en/settings-reference (sandbox.*; analyzers/sandbox.py, docs/permission-rules.md: "Each one weakens the sandbox") |
| `sandbox.network.allowLocalBinding` | false/absent -> true | no | https://code.claude.com/docs/en/settings-reference (sandbox.*; analyzers/sandbox.py, docs/permission-rules.md: "Each one weakens the sandbox") |
| `sandbox.autoAllowBashIfSandboxed` | explicit false lifted | no | https://code.claude.com/docs/en/sandboxing: "autoAllowBashIfSandboxed still defaults to true, so sandboxed commands keep running without prompts. Set it to false to prompt for sandboxed commands." An explicit false lifted is a loosening. |
| `sandbox.allowUnsandboxedCommands` | explicit false lifted | no | https://code.claude.com/docs/en/sandboxing: setting it to false means "Claude Code ignores the dangerouslyDisableSandbox parameter"; an explicit false lifted lets Claude retry a blocked command outside the sandbox. |
| `sandbox.network.allowedDomains` | gained an entry | no | https://code.claude.com/docs/en/sandboxing: "Your allowed domains start empty."; https://code.claude.com/docs/en/settings-reference: "Pre-allow domains so sandboxed commands don't prompt for them". |
| `sandbox.network.deniedDomains` | lost an entry | no | https://code.claude.com/docs/en/sandboxing: "A connection to a host in deniedDomains is refused in every permission mode too." |
| `sandbox.network.allowUnixSockets` | gained an entry | no | https://code.claude.com/docs/en/settings-reference: "List Unix socket paths sandboxed commands can use on macOS"; analyzers/sandbox.py quotes that allowing a Docker socket "effectively grants access to the host system". |
| `sandbox.network.httpProxyPort` | unset -> set | no | https://code.claude.com/docs/en/sandboxing: "Once either port applies, your proxy is responsible for filtering everything sent to it." |
| `sandbox.network.socksProxyPort` | unset -> set | no | https://code.claude.com/docs/en/sandboxing: "Once either port applies, your proxy is responsible for filtering everything sent to it." |
| `sandbox.excludedCommands` | gained an entry | no | https://code.claude.com/docs/en/sandboxing: "List a command pattern in sandbox.excludedCommands to run matching commands outside the sandbox, which means no filesystem restrictions and no network proxy." |
| `sandbox.filesystem.allowWrite` | gained an entry | no | https://code.claude.com/docs/en/sandboxing: "use sandbox.filesystem.allowWrite to grant access to specific paths" outside the working directory. |
| `sandbox.filesystem.allowRead` | gained an entry | no | https://code.claude.com/docs/en/sandboxing: allowRead "re-allows paths inside a denied region" (denyRead); https://code.claude.com/docs/en/settings-reference: "Re-open reading inside a region denyRead blocks". |
| `sandbox.filesystem.denyRead` | lost an entry | yes | https://code.claude.com/docs/en/sandboxing: denyRead blocks reads ("read access to the entire computer, except certain denied directories"); a lost entry re-opens the path. |
| `sandbox.filesystem.denyWrite` | lost an entry | no | https://code.claude.com/docs/en/settings-reference: "Block sandboxed commands from writing to specific paths"; a lost entry re-opens the path. |
| `hooks` | hook removed or command hash changed | no | https://code.claude.com/docs/en/permissions: "A blocking hook also takes precedence over allow rules. A hook that exits with code 2 stops the tool call before permission rules are evaluated"; a removed or replaced hook removes that stop until a person re-accepts it. |
| `enableAllProjectMcpServers` | false/absent -> true | no | https://code.claude.com/docs/en/settings-reference: "Approve every server in project .mcp.json files without a prompt" (HARNESS-002). |
| `enabledMcpjsonServers` | gained an entry | no | https://code.claude.com/docs/en/settings-reference: "Approve specific servers from a project's .mcp.json" (HARNESS-007). |
| `disabledMcpjsonServers` | lost an entry | no | https://code.claude.com/docs/en/settings-reference: "Reject specific servers from a project's .mcp.json". |

#### Codex

| Key | Loosening | HIGH? | Source |
|---|---|---|---|
| `approval_policy` | moved toward never (untrusted < on-request < on-failure < never) | only when the new value is `never` | https://learn.chatgpt.com/docs/config-file/config-reference: approval_policy "Controls when Codex pauses for approval before executing commands"; never "The agent doesn't stop for approval prompts" (https://learn.chatgpt.com/docs/sandboxing). The pages do not rank the values (on-failure is "deprecated", untrusted "unsupported"); the order untrusted < on-request < on-failure < never is the story's (GAPS.md). A granular policy is not ranked. |
| `sandbox_mode` | moved toward danger-full-access (read-only < workspace-write < danger-full-access) | only when the new value is `danger-full-access` | https://learn.chatgpt.com/docs/config-file/config-reference: "read-only / workspace-write / danger-full-access"; https://learn.chatgpt.com/docs/sandboxing: danger-full-access "The agent runs without sandbox restrictions"; read-only "can inspect files, but it can't edit files or run commands without approval". |
| `sandbox_workspace_write.network_access` | false/absent -> true | no | https://learn.chatgpt.com/docs/config-file/config-reference: "Allow outbound network access inside the workspace-write sandbox." |
| `sandbox_workspace_write.writable_roots` | gained an entry | no | https://learn.chatgpt.com/docs/config-file/config-reference: "Additional writable roots when sandbox_mode = "workspace-write". |
| `hooks` | hook removed or command hash changed | no | https://learn.chatgpt.com/docs/config-file/config-reference: "hooks (table): Lifecycle hooks configured inline in config.toml"; a removed or replaced hook is a loosening until a person re-accepts it. |

#### Gemini CLI

| Key | Loosening | HIGH? | Source |
|---|---|---|---|
| `tools.allowed` | gained an entry | no | https://github.com/google-gemini/gemini-cli/blob/main/docs/reference/configuration.md: tools.allowed "Tool names that skip the confirmation dialog". |
| `tools.exclude` | lost an entry | no | https://github.com/google-gemini/gemini-cli/blob/main/docs/reference/configuration.md: tools.exclude "Tool names excluded from discovery." |
| `tools.sandbox` | true -> false/absent | yes | https://github.com/google-gemini/gemini-cli/blob/main/docs/reference/configuration.md: tools.sandbox "Legacy full-process sandbox. Accepts a boolean, a path to a sandbox profile, or a sandbox command such as docker, podman, lxc, or windows-native." |
| `security.toolSandboxing` | true -> false/absent | yes | https://github.com/google-gemini/gemini-cli/blob/main/docs/reference/configuration.md: security.toolSandboxing "Isolates individual tools rather than the whole CLI process." |
| `general.defaultApprovalMode` | moved toward auto_edit (plan < default < auto_edit) | no | https://github.com/google-gemini/gemini-cli/blob/main/docs/reference/configuration.md: general.defaultApprovalMode "default": prompts for approval; "auto_edit": auto-approves edit tools; "plan": read-only mode. "YOLO ... can only be enabled from the command line", so no settings value is YOLO-equivalent and none is HIGH (GAPS.md). |
| `security.disableYoloMode` | true -> false/absent | no | https://github.com/google-gemini/gemini-cli/blob/main/docs/reference/configuration.md: security.disableYoloMode "Disables YOLO mode even when a flag enables it." |
| `security.disableAlwaysAllow` | true -> false/absent | no | https://github.com/google-gemini/gemini-cli/blob/main/docs/reference/configuration.md: security.disableAlwaysAllow "Removes \"Always allow\" options from tool confirmation dialogs." |
| `security.enablePermanentToolApproval` | false/absent -> true | no | https://github.com/google-gemini/gemini-cli/blob/main/docs/reference/configuration.md: security.enablePermanentToolApproval "Shows an option to allow a tool for all future sessions." |
| `security.autoAddToPolicyByDefault` | false/absent -> true | no | https://github.com/google-gemini/gemini-cli/blob/main/docs/reference/configuration.md: security.autoAddToPolicyByDefault "Makes the \"all future sessions\" option the default for low-risk tools in trusted workspaces." |
| `security.folderTrust.enabled` | -> explicit false | no | https://github.com/google-gemini/gemini-cli/blob/main/docs/reference/configuration.md: security.folderTrust.enabled (default true) "Tracks whether folder trust is enabled." |
| `hooks` | hook removed or command hash changed | no | analyzers/config_hygiene.py (TRUST-008): Gemini CLI fingerprints project hooks and warns before running a new or changed one; a removed or replaced hook is a loosening until a person re-accepts it. |

Tightening (a deny rule gained, a mode moved down, a hook added) and neutral changes report nothing.

## Findings

* **GUARD-001**, MEDIUM, "Agent guardrail loosened since the last scan". **HIGH** when a change is
  bypass-equivalent: `bypassPermissions`, Codex `danger-full-access` or approval `never`, the sandbox
  turned off, or a deny rule or sandbox `denyRead` entry removed. Evidence names the file (the home
  directory shown as `~`), each loosened key, and old to new; a hook is only ever "hook for
  `<event>` removed" or "changed".
* **GUARD-002**, INFO: a managed settings file's bytes changed. mcp-audit keeps only a hash, so it
  does not judge the direction.

The first sighting of a file is recorded silently. A file that disappears is reported (GUARD-001)
only when it was the only tracked source of a deny rule or a hook for that agent; otherwise it is
silent. A loosening is reported once: the record is updated after every scan, so the next scan is
quiet. That is also how you accept an intended change: do nothing.

Both are non-advisory (`NON_ADVISORY_IDS`). OWASP MCP Top 10: MCP02 (Privilege Escalation via Scope
Creep): the agent's scope grows without a person granting it. MCP09 is not used: the subject is not
an unsanctioned server.

## State

Records live in `<user-config-dir>/mcp-audit/state/guardrails.json`, beside `instruction-files.json`
(or `<stem>.guardrails.json` beside an explicit rug-pull state path), with the instruction-file rules:
mode 0o600 in a 0o700 directory, written atomically (temporary file plus `os.replace`) under a lock
after re-reading the file so concurrent scans merge, an unreadable file never overwritten, a file that
is not a record file kept as `.corrupt` and started again, and at most 10,000 records (least recently
seen dropped). The code is shared with `agent_files/drift.py`.

## `lock`: guardrails in the repository

`mcp-audit lock` also records the **repository's own** guardrail files in a `guardrails` section of
`mcp-lock.json`: `.claude/settings.json`, `.codex/config.toml` and `.gemini/settings.json` (nested
roots included). Never `settings.local.json`, never a file in your home directory. See
[lock.md](lock.md#guardrails-section-story-0143). `lock --verify` reports **LOCK-014** (HIGH, fails
the exit code) for each file that now allows more than its record; `lock --accept` re-records.

## Limits

* Settings that arrive another way (managed server settings, MDM, environment variables, command-line
  flags such as Gemini `--yolo`) are not files and are not seen.
* mcp-audit compares the keys above only. A file can change in other ways without a finding.
* A file changed and changed back between two scans shows nothing.
* Sources and unconfirmed items: `GAPS.md` ("Guardrail drift").
