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

## Registry Contributors

Maintainers who listed their own MCP servers in the known-server registry.
Every entry improves typosquat detection for everyone using the scanner. This
is not a bounty, and it is not equivalent to contributing a detection rule.

| Contributor | Package | Ecosystem | Listed |
|---|---|---|---|
| Louis Beaumont ([@louis030195](https://github.com/louis030195)) | `screenpipe-mcp` | npm | 2026-08-18 |
| [@samuelchenardlovesboards](https://github.com/samuelchenardlovesboards) | `@palisadeemail/mcp` | npm | 2026-08-18 |
| Zachary Roth ([@zacharyr0th](https://github.com/zacharyr0th)) | `docpull` | PyPI | 2026-08-18 |

See [docs/registry-contributions.md](registry-contributions.md) to list a server.

---

## How to get listed here

There are three routes:

1. **An accepted detection rule.** See [docs/contributing-rules.md](contributing-rules.md).
   The first 50 accepted contributors are named here as part of the bounty program
   described in [rules/community/BOUNTY.md](../rules/community/BOUNTY.md).
2. **A code, infrastructure, or security contribution** that lands in the project
   (the Founding Contributors section above).
3. **A registry submission** that is accepted into `registry/known-servers.json`.
   See [docs/registry-contributions.md](registry-contributions.md). Registry
   listings are not part of the bounty program.
