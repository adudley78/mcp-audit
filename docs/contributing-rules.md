# Contributing Detection Rules to mcp-audit

You found an attack pattern in the wild. Maybe a tool description that quietly
instructs the model to exfiltrate tokens. Maybe a server command pointing at
`/tmp`. Maybe a credential key name that no legitimate config would use.

This guide shows you how to turn that observation into a community rule that
protects everyone — in about 30 minutes.

---

## What are community rules?

Community rules are YAML files in `rules/community/`. They ship with every
mcp-audit installation and run automatically on every `mcp-audit scan` — no
flags required. Each rule describes a single attack pattern and produces a
`Finding` when that pattern is present in an MCP server configuration.

There are currently 30 bundled community rules (COMM-001 through COMM-030).
Every accepted contributor is named in [docs/contributors.md](contributors.md).
The first 50 contributors whose rules are accepted get additional recognition —
see [rules/community/BOUNTY.md](../rules/community/BOUNTY.md).

---

## What makes a good rule?

A good community rule is based on a **real attack pattern** you have observed or
that appears in published security research. The Unit42 Sampling MCP security
analysis (2025) is a strong example of the kind of source that inspires a good
rule: it documented specific strings found in malicious tool descriptions that
instruct the AI to perform privileged actions. Any pattern from that class of
research is welcome.

Good patterns to look for:

- Strings in server args or configurations that re-direct model behavior
- Environment variable key names that suggest hardcoded secrets
- Command paths that indicate sideloaded or staged binaries
- Transport configurations that bypass TLS unexpectedly

**Not useful:** rules that fire on every MCP config, rules that duplicate an
existing COMM-NNN rule, or rules without a clear security justification.

---

## Step 1 — Validate and test the tooling

Make sure `mcp-audit` is installed:

```bash
mcp-audit --version
```

Check the existing rules so you don't duplicate one:

```bash
mcp-audit rule list
```

---

## Step 2 — Copy the template

```bash
cp rules/community/TEMPLATE.yml rules/community/COMM-NNN.yml
```

Replace `NNN` with the next available three-digit number (check the existing
files to find it — the template itself is not numbered).

Open the file. Every field has an inline comment explaining what to write.

---

## Step 3 — Write your rule

The key fields:

| Field | What to write |
|---|---|
| `id` | `COMM-NNN` — the number you chose above |
| `name` | Short title (≤ 60 chars, title case) |
| `description` | What the rule detects and why it matters. **Include a citation.** |
| `severity` | `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO` |
| `category` | `poisoning` / `credentials` / `transport` / `supply-chain` / `injection` / `filesystem` / `governance` / `hygiene` |
| `match` | The detection condition — see below |
| `message` | Text shown in findings. Use `{server_name}` and `{matched_value}`. |
| `owasp_mcp_top_10` | One or more codes: `MCP01`–`MCP10`. See the table below. |
| `author` | Your GitHub handle or name. Shown in `mcp-audit rule list`. |

### Choosing the right match field

The `field` in your match condition maps to a part of the server configuration:

| `field` value | What it contains |
|---|---|
| `command` | The server binary (e.g. `node`, `npx`, `/usr/local/bin/server`) |
| `args` | All argument strings joined by a space |
| `env` | All environment variable key names joined by a space |
| `server_name` | The server's key in the config (e.g. `filesystem`, `github`) |
| `url` | The server's URL (SSE/HTTP transport only; absent for stdio servers) |
| `transport` | Transport type string (e.g. `stdio`, `sse`, `http`) |
| `capabilities` | Capability key names joined by a space |

### Match types

| `type` value | Behaviour |
|---|---|
| `exact` | Full-string equality |
| `contains` | Substring match |
| `regex` | Python `re.search` — partial match, case-sensitive by default; use `(?i)` for case-insensitive |
| `glob` | Shell-style wildcard (`*`, `?`) |

### Compound rules (AND / OR)

When your detection requires matching two conditions at once:

```yaml
match:
  operator: and   # or: or
  conditions:
    - field: command
      pattern: "^http://"
      type: regex
    - field: url
      pattern: ":443"
      type: contains
```

### OWASP MCP Top 10 quick reference

| Pattern type | Suggested code |
|---|---|
| Prompt injection / poisoning | `MCP01` |
| Credential / secret exposure | `MCP02` |
| Supply chain / package integrity | `MCP04` |
| Server misconfiguration | `MCP05` |
| Transport security | `MCP06` |
| Shadow / unauthorised server | `MCP09` |

---

## Step 4 — Validate the rule

```bash
mcp-audit rule validate rules/community/COMM-NNN.yml
```

This must exit 0. It checks that all required fields are present and correctly
typed. Fix any errors it reports before continuing.

---

## Step 5 — Test against a real config

Use `mcp-audit rule test` to see exactly which servers your rule matches:

```bash
mcp-audit rule test rules/community/COMM-NNN.yml --against path/to/your-config.json
```

The output shows every server × rule combination and whether it matched. You
want:

- **At least one "YES"** on a config that contains the pattern (true positive)
- **Zero "YES"** on a clean config (no false positives)

The demo configs in `demo/configs/` are a useful clean-ish baseline:

```bash
# Should produce zero findings from your new rule on clean servers
mcp-audit scan demo/configs/ --rules-dir rules/community/
```

If your rule fires on a clean server, revise the pattern to be more specific.

---

## Step 6 — Update PROVENANCE.md

Add a brief entry to `PROVENANCE.md` citing the research that justifies your
pattern:

```
## COMM-NNN
Source: <URL — CVE page, research paper, blog post, OWASP MCP entry>
Pattern: <one sentence describing what the rule detects>
```

This is a hard requirement. Rules without a citation are not accepted.

---

## Step 7 — Open a pull request

Title format: `feat(rules): add COMM-NNN — <short description>`

In the PR description, include:

- What attack pattern this rule detects
- The research source (same as your PROVENANCE.md entry)
- The config you tested against (you can paste the relevant snippet)
- Output of `mcp-audit rule validate` (should be "✓ Valid")

---

## Attribution

Every contributor whose rule is accepted gets a line in
[docs/contributors.md](contributors.md). If you add your GitHub handle to
the `author:` field in the rule YAML, it will also appear in
`mcp-audit rule list` output for every user.

For the first 50 accepted contributors, see the full commitment in
[rules/community/BOUNTY.md](../rules/community/BOUNTY.md).

---

## Questions?

Open a GitHub issue with the label `community-rules`, or start a thread in
GitHub Discussions. The maintainer (Adam) reviews rule PRs within 7 days.
