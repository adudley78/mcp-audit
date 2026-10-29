# Research records

Some of the most important findings about coding agents and MCP clients are published as research write-ups, not CVEs: a named attack, a bypass, a campaign. They often have no CVE or GHSA for weeks or never. A **research record** is mcp-audit's machine-readable, credited copy of one of those findings, so a command that answers "am I affected" can answer for it the way it does for a CVE.

The records are in `src/mcp_audit/data/research-records.json`. They ship inside the wheel and all four binaries and are read offline.

## What a record says, and does not say

A record states what the write-up reported: who found it, which products it affected, where each was fixed, and which mcp-audit checks test the condition. It does not say that you are affected. That comes from running the checks (or `mcp-audit affected`) on your machine.

Nothing is inferred. A field the write-up does not give is empty, not guessed:

- **Products are named as the write-up names them** (for example "Claude Code", "Codex"). mcp-audit does not read which harness version is installed, so for a record about harness versions it says "could not check", and points at the checks that test the condition directly.
- **No CVE is invented.** An alias is added only when an authority assigns one.
- **A fix is "fixed" only with a first fixed version.** Otherwise the status is `unfixed` (no fix yet) or `wontfix` (the vendor said none will ship), with who said so.

## Credit

Every record names the finders, by person and company, in the record, in `PROVENANCE.md` and in the CHANGELOG. A record never implies the finders endorse mcp-audit.

## Record format

OSV-shaped (schema 1.6.0 fields, validated in tests), with mcp-audit's fields under `database_specific.mcp_audit`:

| Field | Meaning |
|---|---|
| `id` | `x_MCPRS-<12 hex>`: the first 12 hex digits of `sha256("research\0" + source URL + "\0" + sorted product names joined by "\|")`. The same finding has the same ID on every host, and rewording the text does not change it. `x_` is OSV's experimental namespace. |
| `credits` | Who found it (`type: FINDER`). |
| `references` | The write-ups; the first is the primary source. |
| `aliases` | CVE or GHSA IDs once one exists. |
| `database_specific.mcp_audit.kind` | `research`. |
| `database_specific.mcp_audit.products` | Product, vendor, `status` (`fixed`, `unfixed`, `wontfix`), `fixed_in`, and a note saying who reported it. |
| `database_specific.mcp_audit.checks` | mcp-audit finding IDs that test the condition. |

A record that is malformed is skipped and reported; one bad record never breaks a scan.

## Records today

| ID | Finding | Credited to |
|---|---|---|
| `x_MCPRS-4ad8c07d80d7` | **Plugin4Shell** (2026-09-17): a plugin's pinned commit replaced by a branch named like the SHA, or by `FETCH_HEAD`. Fixed in Claude Code 2.1.179 and Codex 0.146.0; not fixed in GitHub Copilot; Google will not fix Gemini CLI (deprecated). Tested by PLUGIN-003 and PLUGIN-004. | Or Nevo, Dor Granat and Niv Hoffman, [AIR Security](https://www.air.security/blog-posts/plugin4shell) |

## Adding one

1. Read the primary write-up and the vendors' own notices. Record only what they state, with the date.
2. Compute the ID with `mcp_audit.registry.research.research_id(source_url, product_names)`; a test fails if the ID does not match.
3. Name the checks that test the condition. If none exists, say so in `details`; do not name a check that does not test it.
4. Credit the finders by name. Add a PROVENANCE entry and a CHANGELOG line.
