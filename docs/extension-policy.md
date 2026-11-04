# Editor extension allowlist policy (EXTPOL-001..003)

Admins ask whether an editor honours an extension allowlist before allowing it on a
managed machine. VS Code, Cursor and Windsurf (now Devin Desktop) can restrict which
extensions load with the `AllowedExtensions` policy and the matching user setting
`extensions.allowed`. The policy overrides the setting at every level, so an allowlist
that lives only in the user's `settings.json` is a default the user can change, not a
control. mcp-audit tells you which of the two you have.

The check runs in every default `scan` and `check`, for each of VS Code, Cursor and
Windsurf whose extension directory or user settings directory exists. It is offline and
read-only, and is skipped when you pass an explicit config path.

## Where it looks

Only the locations the vendors document. Where a location is not documented, the
finding says "policy location not documented; not read" and never "absent".

| Editor | Windows | macOS | Linux |
|---|---|---|---|
| VS Code ([policies](https://code.visualstudio.com/docs/enterprise/policies)) | registry `Software\Policies\Microsoft\VSCode`, value `AllowedExtensions`: computer configuration (HKLM), then user (HKCU); computer wins | configuration profile; **domain not named, not read** | `/etc/vscode/policy.json` (VS Code 1.106+), key `AllowedExtensions` |
| Cursor ([enterprise settings](https://docs.cursor.com/account/teams/enterprise-settings), 1.2+) | Group Policy; **registry path not documented, not read** | profile; **domain not documented, not read** | "Linux policy not supported (Cursor docs)" |
| Windsurf / Devin Desktop ([enterprise policies](https://docs.devin.ai/desktop/enterprise-policies)) | registry `Software\Policies\Windsurf\Devin`, value `AllowedExtensions` (the page names no hive; both policy hives are read, computer first) | **domain not named, not read** | `/etc/vscode/policy.json` (shared with VS Code) |

The user setting is `extensions.allowed` in each editor's user `settings.json`
(`~/.config/<Code|Cursor|Windsurf>/User/` on Linux, `~/Library/Application Support/...`
on macOS, `%APPDATA%\...` on Windows), read as JSONC with a 1 MiB cap. The value is an
object, or a string holding one.

## Findings

| ID | Severity | Fires when |
|---|---|---|
| EXTPOL-001 | INFO | Inventory of an allowlist that **is** enforced by a documented policy source: which source, the entry count and shape. Not scored and left out of `check`'s verdict. Not an advisory. |
| EXTPOL-002 | LOW | `extensions.allowed` is set in user settings and no documented policy source was found. When a policy location could not be read ("policy location not documented; not read", "Linux policy not supported (Cursor docs)"), the finding says a policy delivered that way would not be seen. Not an advisory. |
| EXTPOL-003 | LOW | An enforced `AllowedExtensions` policy contains `"*": true`: it allows every extension. Not an advisory. |

**Silence is the answer for "nothing found".** An installed editor with no allowlist, or
whose policy location the vendor does not document, produces no finding: almost every
developer machine looks like that, and it would otherwise cost score points and change
`check`'s verdict on every machine. EXTPOL-001 is in `scoring.INVENTORY_ONLY_IDS`: it
does not lower the score and `check` treats it as neither an issue nor a reason to show
more than "No MCP config files found".

**Shape** is counted, not interpreted: entries with no dot (publishers), entries with a
dot (specific extension IDs), entries whose value is a list (version lists), a `"*"`
entry, and entries set to `false`. How each vendor matches publishers, extension IDs and
version lists is not stated on its policy page, so mcp-audit does not say what an entry
allows or blocks.

## What it can't tell

- Whether an editor build honours the policy (that is the vendor's behaviour, not
  something a file read can prove).
- A policy delivered through a location the vendor does not document (macOS profiles,
  Cursor on Windows).
- Anything about extensions already installed; `mcp-audit extensions scan` covers those.
