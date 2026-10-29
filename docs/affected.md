# `mcp-audit affected`

*Is this advisory in my agent stack?* One command, one answer per server.

```bash
mcp-audit affected CVE-2025-53109                 # an advisory ID
mcp-audit affected MAL-2026-4068                  # an OSV malicious-package ID
mcp-audit affected x_MCPRS-4ad8c07d80d7           # a research record (Plugin4Shell)
mcp-audit affected litellm@==1.107.0              # a package and a version range
mcp-audit affected '@modelcontextprotocol/server-filesystem@<2025.7.1'
```

It reads every MCP server mcp-audit discovers (all supported clients, Codex and Gemini CLI, gateway upstreams, plugin and subagent servers) and prints one of three answers for each:

| Answer | Meaning |
|---|---|
| **AFFECTED** | The server runs the package at a version the advisory covers. The row says which version, where it came from, and the fixed version if there is one. |
| **NOT AFFECTED** | mcp-audit can show why: the server runs the package at a version the advisory does not cover (at or above the fix, or outside the listed range), or it runs a different package. |
| **COULDN'T CHECK** | mcp-audit cannot tell. The row says why. This is never reported as not affected. |

Exit code: `0` nothing affected, `1` something affected, `2` error. `--fail-on-unknown` also exits `1` when a server that runs the package could not be checked.

## Where the version comes from

1. The launch command's exact pin (`npx -y pkg@1.2.3`, `uvx pkg==1.2.3`).
2. Otherwise the `resolved_version` in `mcp-lock.json` for that server: the nearest lock beside the config, plus any you pass with `--lock PATH` (repeatable). The `mcp-lock.json` of an older commit works the same way; mcp-audit never runs `git` to read history.
3. Otherwise nothing: `npx -y pkg` with no pin and no lock is **COULDN'T CHECK**, with "pin it or run `mcp-audit lock`". mcp-audit does not guess what an unpinned launch will install.

## What it checks against

All offline, from files that ship with mcp-audit:

- **The registry** (`registry/known-servers.json`): CVEs recorded against a package, with the version each was fixed in. A pin below the fix is AFFECTED; at or above is NOT AFFECTED. When the fix uses calendar numbering and the pin uses semantic numbering (or the reverse), the answer comes from the entry's `semver_resumed_at` when it has one, and is COULDN'T CHECK when not (the same rule as SC-009).
- **The malicious-package mirror** (`registry/known-malicious.json`, OSV `MAL-*`): listed versions and `ranges[].events`, evaluated the way SC-008 does.
- **Research records** (`research-records.json`, see [research-records.md](research-records.md)): see below.
- **Your own range**, for `package@range`: a PEP 440 specifier set (`==1.107.0`, `<2025.7.1`, `>=1,<2`; a comma means *and*). npm's `^` and `~` shorthands are refused rather than guessed at. A bare `pkg@1.2.3` means `==1.2.3`.

An ID that none of these knows is an error (exit `2`); it does not produce a column of "couldn't check". Add `--live` to fetch it from OSV.dev (see below).

## Research records

A research record is about products (Claude Code, Codex...), not MCP servers, so the rows are per product. mcp-audit does not yet read which Claude Code or Codex version is installed, so every product row is **COULDN'T CHECK**, with what the write-up says about that product's fix. The checks the record names (for Plugin4Shell, PLUGIN-003 and PLUGIN-004) are run too; a HIGH or CRITICAL result is an AFFECTED row, and a milder one is listed as COULDN'T CHECK. Those checks look at Claude Code's plugin directory only, only for installs that kept their `.git`, and are not run with `--path`. No research record ever produces NOT AFFECTED.

## What it lists

By default the terminal output lists AFFECTED, COULDN'T CHECK and the NOT AFFECTED rows that run the package. Servers on other packages, and servers whose launch names no package mcp-audit can read (a remote URL, a local script), are counted in one line; `--all` lists them. A server with no readable package is COULDN'T CHECK, but never fails `--fail-on-unknown`, because there is no package to compare.

## Output

`--format terminal` (default), `--format json`, `--format sarif`, with `-o FILE`. SARIF has one result per AFFECTED server and the query as the rule ID. JSON and SARIF paths are redacted like every other output that leaves the machine.

## `--live`

`--live` fetches an advisory that is not bundled from OSV.dev (`/v1/vulns/{id}`, the endpoint `scan --check-vulns` already uses) and evaluates its npm and PyPI ranges. It is refused with `--offline`. Without it, nothing leaves the machine.

## Measured error

The comparison itself is exact (PEP 440 ordering, OSV event order). The error is in the data, and these are the counts today:

- **Registry:** 14 packages carry advisories, in 180 structured records. 17 of them record no fixed version, so a pinned server on one of those is AFFECTED ("no fixed version recorded") and can never be shown as fixed.
- **Malicious mirror:** 217 records; 150 list explicit versions and 99 carry a blanket "every version" range. For a package in the registry, the blanket range is ignored when the record also lists versions (the SC-008 rule).
- **Coverage:** an advisory the registry, the mirror and the research records do not hold is not answered offline. The registry's CVE history is curated, not NVD; a package missing a CVE here is not evidence that it has none.
- **Version:** a version mcp-audit cannot parse, or order against the fix, is COULDN'T CHECK. An unpinned launch is COULDN'T CHECK; the floating spec's installed version can differ from a lock's if the lock is stale.

## Not in this version

- `--transitive` (walking the dependency graph) and `--fleet` (reading `merge` reports) are queued; the `merge` JSON does not carry per-server launch versions today.
- Reading the installed version of Claude Code, Codex and the other harnesses, so a research record's product rows can be answered.
- Fixing (`affected --fix`), exploit signals, reachability and VEX output come in later EPIC-0008 stories.
