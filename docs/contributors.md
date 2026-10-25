# mcp-audit Community Contributors

Thank you to everyone who has contributed detection rules, research citations, or
bug reports that improved mcp-audit's accuracy.

---

## Detection Rule Contributors

Contributors whose rules have been accepted into the community pack are listed
below. See [rules/community/BOUNTY.md](../rules/community/BOUNTY.md) for the
full bounty program terms.

| Contributor | Rule ID | Rule Name | Accepted |
|---|---|---|---|
| Adam Dudley ([@adudley78](https://github.com/adudley78)) | COMM-001–COMM-030 | Founding rule pack | 2026-05-17 |

---

## Founding Contributors

Contributors who improved the project through code, infrastructure, or security hardening.

| Contributor | Contribution | Accepted |
|---|---|---|
| [@jsandov](https://github.com/jsandov) | SHA-pinned all third-party GitHub Actions across 14 workflow files (supply-chain hardening) | 2026-05-22 |

---

## Research and Design Contributors

Independent researchers whose measurements or format design the project cites in its
own documentation.

| Contributor | Contribution | Cited in | Since |
|---|---|---|---|
| Prachet Poddar ([@prachetpoddar](https://github.com/prachetpoddar)) | Independent measurement of 250 npm MCP servers: the deps.dev-versus-install divergence bound (recomputed against his corrected resolver in v3.16), the 184-of-250 registry-drift result, and npm resolver behaviour. Author of the install-tree (`trees`) layer of `mcp-lock.json` and of format proposals adopted or queued in ADR-0005. | [supply-chain.md](supply-chain.md), [lock.md](lock.md), [ADR-0005](decisions/ADR-0005-mcp-audit-lock.md), [GAPS.md](../GAPS.md) | 2026-09-07 ([#88](https://github.com/adudley78/mcp-audit/issues/88)) |

---

## Registry Contributors

Maintainers who listed their own MCP servers in the known-server registry.
Every entry improves typosquat detection for everyone using the scanner. This
is not a bounty, and it is not equivalent to contributing a detection rule.

| Contributor | Package | Ecosystem | Listed |
|---|---|---|---|
| Louis Beaumont ([@louis030195](https://github.com/louis030195)) | `screenpipe-mcp` | npm | 2026-08-18 |
| [@samuelchenardlovesboards](https://github.com/samuelchenardlovesboards) | `@palisadeemail/mcp` | npm | 2026-08-18 |
| Zachary Roth ([@zacharyr0th](https://github.com/zacharyr0th)) | `docpull` | PyPI | 2026-08-18 |
| [@kantorcodes](https://github.com/kantorcodes) | `hol-guard` | PyPI | 2026-10-06 |
| [@uditgoenka](https://github.com/uditgoenka) | `@autoposting.ai/cli` | npm | 2026-10-06 |
| [@activeing123](https://github.com/activeing123) | `mcptoon` | PyPI | 2026-10-25 |

See [docs/registry-contributions.md](registry-contributions.md) to list a server.

---

## How to get listed here

There are four routes:

1. **An accepted detection rule.** See [docs/contributing-rules.md](contributing-rules.md).
   The first 50 accepted contributors are named here as part of the bounty program
   described in [rules/community/BOUNTY.md](../rules/community/BOUNTY.md).
2. **A code, infrastructure, or security contribution** that lands in the project
   (the Founding Contributors section above).
3. **Research or format design the project cites** in its own documentation
   (the Research and Design Contributors section above).
4. **A registry submission** that is accepted into `registry/known-servers.json`.
   See [docs/registry-contributions.md](registry-contributions.md). Registry
   listings are not part of the bounty program.
