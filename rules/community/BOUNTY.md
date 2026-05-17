# mcp-audit Community Rule Bounty Program

The detection rules are the flywheel. Every practitioner who contributes a rule
based on a real MCP attack pattern makes mcp-audit more accurate for everyone.

This document describes how contributors are recognized.

---

## Recognition tiers

### Founding Contributors

Everyone who gets a rule accepted before the v1.0 release will be named as a
**Founding Contributor** in the v1.0 changelog — a permanent record of the people
who shaped the detection corpus before the project reached stability.

Founding Contributors are also listed in [docs/contributors.md](../docs/contributors.md)
with their rule ID, rule name, and acceptance date.

The founding cohort closes when v1.0 ships — not at a contributor count. Contribute
before v1.0 and you're in it.

### Contributors

Everyone whose rule is accepted after v1.0 receives the same recognition: named in
the CHANGELOG entry for the release that ships their rule, and permanently listed in
[docs/contributors.md](../docs/contributors.md).

There is no deadline and no cap. The program is open-ended.

---

## What every accepted contributor receives

1. Named in [docs/contributors.md](../docs/contributors.md) with rule ID and acceptance date.
2. Credited in the CHANGELOG entry for the release that ships the rule.
3. A personal thank-you from Adam (X / email / GitHub comment — your preference).

Adam personally reviews every rule PR.

---

## What makes a rule acceptable

A rule PR is accepted when **all** of the following are true:

| Criterion | Detail |
|---|---|
| **Real attack pattern** | The rule detects a genuine MCP attack technique, misconfiguration, or threat. Not a theoretical edge case — something that appears in the wild or in published PoC research. |
| **Research citation** | The rule's `description` field cites a source: CVE, OWASP MCP Top 10 entry, published PoC, or incident report. See [PROVENANCE.md](../PROVENANCE.md). |
| **Tested** | The contributor ran `mcp-audit rule validate` (exits 0) and `mcp-audit rule test` against at least one config that triggers it. |
| **Zero false positives on demo configs** | Running the rule against `demo/configs/` produces no unexpected findings on clean servers. |
| **Follows the template** | The rule file passes schema validation (all required fields present, correct types, valid severity). |
| **No duplicate** | The rule doesn't substantially duplicate an existing `COMM-NNN` rule. Check `mcp-audit rule list` before submitting. |

---

## How to contribute

1. Read [docs/contributing-rules.md](../docs/contributing-rules.md) — the full guide.
2. Copy `rules/community/TEMPLATE.yml` to `rules/community/COMM-NNN.yml`
   (use the next available number).
3. Fill in every field. Add your GitHub handle to the `author:` field.
4. Validate: `mcp-audit rule validate rules/community/COMM-NNN.yml`
5. Test: `mcp-audit rule test rules/community/COMM-NNN.yml --against <config>`
6. Open a pull request. Title format: `feat(rules): add COMM-NNN — <short description>`

---

## Review timeline

Adam aims to review rule PRs within **7 days**. Complex rules (high false-positive
risk, unusual patterns) may take longer. If a rule needs revision, Adam will
comment on the PR with specific feedback.

---

## Questions

Open a GitHub issue with the label `community-rules` or start a discussion in
the GitHub Discussions tab.
