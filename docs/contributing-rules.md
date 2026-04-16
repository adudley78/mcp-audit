# Contributing SAST Rules

This guide covers how to write, test, and submit new Semgrep rules for the
mcp-audit rule pack (`semgrep-rules/`).

---

## Rule Structure

Every rule file is a YAML file in one of the category directories
under `semgrep-rules/python/` or `semgrep-rules/typescript/`.

### Required Fields

```yaml
rules:
  - id: mcp-your-rule-name         # kebab-case, start with "mcp-" or "mcp-ts-"
    message: >
      One-sentence description of the vulnerability.
      Include what the attacker can do if this is exploited.
    severity: ERROR                 # ERROR | WARNING | INFO
    languages: [python]             # or [typescript, javascript]
    metadata:
      category: injection           # injection | poisoning | credentials | protocol | transport
      cwe: CWE-78                   # Primary CWE
      owasp: A03:2021               # OWASP Top 10 mapping (optional)
      owasp-mcp: MCP03              # OWASP MCP mapping (optional)
      description: Short one-liner  # Used in tooling
      confidence: HIGH              # HIGH | MEDIUM | LOW
      likelihood: MEDIUM
      impact: HIGH
      fp-guidance: >                # Optional — add when FP risk is non-trivial
        Explain when this rule fires on correct code and how to suppress.
    pattern: ...                    # or patterns:, pattern-regex:, pattern-either:
```

### Severity Guidelines

| Semgrep Severity | mcp-audit Severity | When to use |
|---|---|---|
| ERROR | CRITICAL | Definite vulnerability if exploited: RCE, SQL injection, hardcoded creds |
| WARNING | HIGH | Likely vulnerability, may need user-controlled input to exploit |
| INFO | MEDIUM | Heuristic or defensive coding practice |

---

## Pattern Writing Tips

### Match async tool handlers specifically

Use `pattern-inside` to scope findings to async functions:

```yaml
patterns:
  - pattern: eval($X)
  - pattern-not: eval("...")
  - pattern-inside: |
      async def $FUNC(...):
          ...
```

**Important:** Use `...` (not `$ARGS`) for function parameter lists.
`$ARGS` matches a single parameter, `...` matches any number.

### Match string content with metavariable-regex

`metavariable-regex` uses **anchored** matching (like `re.match` in Python).
Prefix with `(?s).*` when the pattern does not appear at the start of the string:

```yaml
# WRONG — only matches if URL is at position 0
- metavariable-regex:
    metavariable: $VALUE
    regex: https?://\S+

# CORRECT — matches URL anywhere in the string
- metavariable-regex:
    metavariable: $VALUE
    regex: (?s).*https?://\S+.*
```

### Avoid overly broad attribute patterns

`$OBJ.run(...)` matches `subprocess.run(...)`, `asyncio.run(...)`, and
any other `.run()` call. Add `pattern-not` exclusions for known false positives:

```yaml
patterns:
  - pattern: $APP.run(...)
  - pattern-not: $APP.run(..., ssl_context=..., ...)
  - pattern-not: subprocess.run(...)
  - pattern-not: asyncio.run(...)
```

---

## Test Fixture Requirement

Every rule **must** have a test fixture demonstrating it fires. Add a
vulnerable example to the appropriate test file in
`semgrep-rules/tests/<lang>/vulnerable/`.

### Vulnerable fixture format

```python
# ruleid: mcp-your-rule-name
the_vulnerable_code()
```

The `# ruleid:` comment documents which rule is expected to fire.

### Clean fixture

Verify that `semgrep-rules/tests/<lang>/clean/safe_server.*` produces **zero
findings** after your change. If your rule fires on the clean fixture, either
fix the rule or add a `# nosemgrep: mcp-your-rule-name` comment with explanation.

---

## Validation

```bash
# Validate all rules parse correctly
semgrep --config semgrep-rules/ --validate

# Run against vulnerable fixtures (expect findings)
semgrep --config semgrep-rules/python/ semgrep-rules/tests/python/vulnerable/ \
  --no-git-ignore --json | python3 -c "
import json, sys
d = json.load(sys.stdin)
print(f'{len(d[\"results\"])} findings')
"

# Run against clean fixtures (expect zero findings)
semgrep --config semgrep-rules/python/ semgrep-rules/tests/python/clean/ \
  --no-git-ignore --json | python3 -c "
import json, sys
d = json.load(sys.stdin)
assert len(d['results']) == 0, f'Clean fixture has {len(d[\"results\"])} findings!'
print('Clean: 0 findings')
"
```

---

## PR Checklist

Before opening a pull request, verify:

- [ ] Rule file is in the correct category directory
- [ ] `id` starts with `mcp-` (Python) or `mcp-ts-` (TypeScript)
- [ ] All required metadata fields are present: `category`, `cwe`, `description`
- [ ] `semgrep --config semgrep-rules/ --validate` passes with 0 errors
- [ ] Vulnerable test fixture demonstrates the rule fires
- [ ] Clean fixture (`safe_server.*`) still produces zero findings
- [ ] Rule has a `fp-guidance` note if false positive rate is non-trivial
- [ ] PROVENANCE.md updated with research source for new detection patterns
- [ ] `message` clearly explains the vulnerability and its impact
- [ ] `severity` follows the guidelines table above

### Research source requirement

mcp-audit's PROVENANCE.md requires that every detection pattern cite its
research source. When adding a new rule, add a line to PROVENANCE.md:

```
## mcp-your-rule-name
Source: <link to CVE, research paper, blog post, or MCP security advisory>
Pattern: <brief description of what the rule detects>
```

---

## Rule Metadata Schema

Full metadata reference:

```yaml
metadata:
  # Required
  category: injection           # injection | poisoning | credentials | protocol | transport
  cwe: CWE-78                   # Primary CWE ID
  description: string           # Short one-liner for tooling display

  # Recommended
  owasp: A03:2021               # OWASP Top 10 2021 mapping
  owasp-mcp: MCP03              # OWASP MCP Top 10 mapping (MCP01–MCP10)
  confidence: HIGH              # HIGH | MEDIUM | LOW — how often this indicates a real bug
  likelihood: MEDIUM            # HIGH | MEDIUM | LOW — how often it's exploited
  impact: HIGH                  # HIGH | MEDIUM | LOW — severity if exploited

  # Optional
  fp-guidance: string           # When/how to suppress false positives
  references:                   # List of external references
    - https://example.com/cve
```
