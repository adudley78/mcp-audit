# Secrets a Claude Code session can reach (REACH-001..003)

A plain `mcp-audit scan` or `mcp-audit check` (no explicit path) asks one
question about the machine it runs on: **which credential files could a Claude
Code session read without asking you?** It answers without opening any of
them.

## Why this matters

From Anthropic's Claude Code documentation (read 2026-10-28):

- [Permissions, "Read-only commands"](https://code.claude.com/docs/en/permissions):
  Claude Code "runs them without a permission prompt in every mode, except as
  `permissions.blockReadsOutsideWorkingDirectories` changes for paths outside
  your working directories. The set includes `ls`, `cat`, ... `head`, `tail`".
- [Sandboxing](https://code.claude.com/docs/en/sandboxing): the sandbox's
  default read access is "Most of the machine, including credential files such
  as `~/.ssh` and `~/.aws/credentials`", and "There is no built-in credential
  deny list".
- File reads need no approval "within the working directory and additional
  directories" (permissions table).

So `cat ~/.aws/credentials` runs without a prompt unless something says
otherwise, and a `.env` file in the project is read without a prompt. A
prompt-injected session (a poisoned issue, skill, web page or tool result) can
then send what it read anywhere it can write. Incidents: a Cursor agent found
and used a production token "in an unrelated file" (PocketOS, April 2026);
Claude Code uploaded credentials to a public repository after a hidden issue
instruction (Roblox, Black Hat USA 2026); a trojanized skill's harvester
checked 127 Unix secret paths (Zenity Labs, August 2026).

## What protects a file

A credential file counts as covered when any settings file the session loads
(managed `managed-settings.json` and `managed-settings.d/*.json`, your
`~/.claude/settings.json` or `$CLAUDE_CONFIG_DIR/settings.json`, and the
working directory's `.claude/settings.json` and `.claude/settings.local.json`)
has:

- a `permissions.deny` `Read(...)` rule that matches the file or a directory
  above it. When the store itself is a symlink (GNU Stow, chezmoi), the rule
  must match the file it points to: a rule on the link name alone leaves the
  target readable by its own path. A rule written with spaces inside the
  parentheses is not counted. Read deny rules "apply to Claude's
  built-in file tools, to file commands Claude Code recognizes in Bash, such as
  `cat`, `head`, `tail`". Pattern anchoring follows the permissions doc:
  `//path` absolute, `~/path` home, `/path` relative to the settings file (user
  settings: `~/.claude`; project and local settings: the working directory),
  `path` relative to the working directory, and a bare name matches at any
  depth below it; a `!` carve-out in the same file reopens a relative rule.
  When managed settings set `allowManagedPermissionRulesOnly: true`, only
  managed rules count, as in Claude Code;
- `permissions.blockReadsOutsideWorkingDirectories: true` (home-directory stores
  only, and only when the working directory is not the home directory or above
  it); or
- the sandbox, on macOS, Linux or WSL2 (never on native Windows), when the
  highest-precedence settings file that sets `sandbox.enabled` sets it to
  `true` (managed, then `.claude/settings.local.json`, where the `/sandbox`
  panel writes it, then the project's `.claude/settings.json`, then your user
  settings), `sandbox.filesystem.disabled` is not true in your user or managed
  settings (its documented scope; a repository's value is ignored), and a
  `sandbox.filesystem.denyRead` path or a `sandbox.credentials.files` entry
  with `"mode": "deny"` covers the file without a narrower
  `sandbox.filesystem.allowRead` entry re-opening it (the sandboxing doc's
  overlap rule; with a managed `allowManagedReadPathsOnly`, only managed
  `allowRead` entries count).

  **The sandbox covers Bash commands only.** "A `denyRead` entry doesn't stop
  the Read tool." mcp-audit still counts it, because the Read tool asks before
  reading outside the working directory in the default permission modes, but
  not when `permissions.defaultMode` is `bypassPermissions` in your user or
  managed settings (there the Read tool reads without asking). A mode chosen on
  the command line (`--dangerously-skip-permissions`) and the sandbox's
  unsandboxed-retry path are not visible to a scan; see GAPS.md.

## Findings

| ID | Severity | What it means |
|---|---|---|
| REACH-001 | LOW | Credential stores under your home directory that nothing above covers. One finding lists them all. |
| REACH-002 | MEDIUM | Claude Code's own login store (`.credentials.json`, written with mode 0600) can be read by another local account: the file has a group or other read bit and every directory above it lets that class through. A group that is your private group (same name as you) does not count. |
| REACH-003 | LOW | Non-empty `.env` / `.env.*` files at the working directory's root that no `Read` deny rule covers. `.env.example`, `.env.sample`, `.env.template` and similar are skipped. |

Stores checked for REACH-001 (each path from the tool's own documentation):
SSH default private keys (`~/.ssh/id_rsa`, `id_ecdsa`, `id_ecdsa_sk`,
`id_ed25519`, `id_ed25519_sk`), `~/.aws/credentials`, Google Cloud application
default credentials, `~/.git-credentials`, `~/.netrc` (and `_netrc` on
Windows), `~/.pypirc`, Claude Code's `.credentials.json`; and, labelled "may
hold", `~/.npmrc`, `~/.docker/config.json`, `~/.kube/config`,
`~/.config/gh/hosts.yml`, Gemini CLI's `~/.gemini/.env` and GitHub Copilot
CLI's `config.json` (`~/.copilot/config.json`, or `$COPILOT_HOME/config.json`).
Other coding agents' login files are not listed unless the vendor's own
documentation names them (see GAPS.md).

**Nested user namespaces (Linux).** A sandbox `denyRead` or
`sandbox.credentials` `deny` entry is not counted as protection when
`sandbox.allowNestedUserNamespaces` is `true` in your user settings or in
managed settings, on Linux: Claude Code 2.1.305's CHANGELOG says the setting
lets sandboxed commands get around the sandbox's file protections. REACH-001
then lists the store and its evidence names the key. A `true` in a project or
local settings file is ignored by Claude Code and by this check; macOS and
Windows are unchanged. `Read` deny rules still count.

## Exit code

On a developer machine with Claude Code and unprotected credential files, a
plain `mcp-audit scan` now exits 1 with one LOW finding (REACH-001): `scan`
exits 1 on any finding, INFO included. Use `--severity-threshold medium` to
ignore it. `check`, the GitHub Action and the pre-commit hook are unaffected:
they gate on grade or on HIGH and above.

## Fix

Add Read deny rules to your user settings, for example:

```json
{
  "permissions": {
    "deny": ["Read(~/.ssh/**)", "Read(~/.aws/**)", "Read(//**/.env)"]
  }
}
```

or set `"blockReadsOutsideWorkingDirectories": true`. With the sandbox on, list
credential directories in `sandbox.credentials.files` with `"mode": "deny"`, as
Anthropic's sandboxing guide recommends. For a project, commit
`"Read(./.env)"` and `"Read(./.env.*)"` in `.claude/settings.json`.

## Privacy

- No credential store is ever opened: each is checked with `stat()` (exists,
  regular file, non-empty, mode bits). The home directory and `~/.ssh` are not
  listed; the store paths are a fixed list. Only the working directory's root is
  listed, by entry name, to find `.env` files.
- More than 4,096 sandbox path entries in all, or more than 256 with
  wildcards, makes mcp-audit count the sandbox as protecting nothing (and say
  so in the scan's errors), so a cut-off list never reads as protected.
- Only the settings keys above are read from settings files (1 MiB per file,
  256 drop-ins, 8 MiB per scan); a file over the limit is reported in the
  scan's errors and its rules are not counted.
- Finding titles, descriptions, evidence and remediation name files as `~/...`
  or by file name. The `finding_path` field holds the store's absolute path,
  like every other finding: `--format json` output carries it as is (the
  terminal report does not print it), and the outputs meant to leave the machine (SARIF, Nucleus, snapshots)
  rewrite it without your home directory. REACH findings are never turned
  into advisories (`mcp-audit advise`).
- Runs only in a default scan, and only when a Claude Code config directory
  exists; an explicit path or `demo/configs/` produces none.

## Measured

Six benign machine profiles (all parent directories searchable, the strictest
case for REACH-002): Linux developer defaults (SSH keys, AWS credentials 0600,
`~/.npmrc`, login store 0600, `.env.example` only), macOS with Keychain login
and Docker `credsStore`, the same Linux machine configured as Anthropic's docs
show (`blockReadsOutsideWorkingDirectories` plus project `.env` deny rules),
the same with `sandbox.credentials.files` deny entries, a 0640 login store in
the owner's private group, and Claude Code with no stores. Result: 0 MEDIUM or
higher; REACH-001 LOW on three; silent on the hardened and sandboxed profiles.

Limits: see `GAPS.md` ("Secrets a Claude Code session can reach").
