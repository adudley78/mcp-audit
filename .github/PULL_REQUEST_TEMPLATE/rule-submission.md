---
name: Community Rule Submission
about: Submit a new detection rule to the mcp-audit community ruleset
---

## Rule submission checklist

- [ ] Rule ID follows the `COMM-NNN` format and does not conflict with an
      existing rule in `rules/community/`
- [ ] Rule file is named `{RULE-ID}.yml` and placed in `rules/community/`
- [ ] Rule passes `mcp-audit rule validate rules/community/{RULE-ID}.yml`
      with no errors
- [ ] Rule has been tested with `mcp-audit rule test` against at least one
      real MCP config
- [ ] Severity is justified in the PR description (why high vs medium vs low)
- [ ] Tags are drawn from existing tag vocabulary where possible
- [ ] Rule does not duplicate an existing community rule
- [ ] Description explains what attacker behavior or misconfiguration this
      detects and why it matters

## Rule summary

**Rule ID:** COMM-NNN  
**Name:**  
**Severity:**  
**What it detects:**  
**Why it matters:**  
**Tested against:** (describe the config you tested it on)
