# mcp-audit Community Rule Format Specification

**Version:** 1.0  
**Status:** Stable  
**License:** Apache 2.0 — see §7

---

## 1. Purpose

This document specifies the YAML schema for mcp-audit community detection rules.
A rule file conforming to this spec can be validated with `mcp-audit rule validate`
and will produce structured `Finding` objects when matched during an MCP
configuration scan.

This specification is published as a standalone document so that other tools in
the MCP security ecosystem can implement the same format and claim compatibility
with the mcp-audit community rule corpus.

---

## 2. File format

- Encoding: UTF-8
- Extension: `.yml` or `.yaml`
- A file may contain **one rule** (a YAML mapping at the document root) or
  **multiple rules** (a YAML mapping with a top-level `rules:` list key)

Single-rule example:

```yaml
id: COMM-001
name: Prohibited network binary
# ... remaining fields
```

Multi-rule example:

```yaml
rules:
  - id: CUSTOM-001
    name: First rule
    # ...
  - id: CUSTOM-002
    name: Second rule
    # ...
```

---

## 3. Rule schema

### 3.1 Required fields

| Field | Type | Description |
|---|---|---|
| `id` | `string` | Unique rule identifier. Community rules use `COMM-NNN` format (three-digit zero-padded). Custom rules may use any prefix. Must be unique within a loaded ruleset. |
| `name` | `string` | Short human-readable name. Shown in findings, CLI output, and SARIF. Maximum 120 characters recommended. |
| `description` | `string` | One or more sentences describing what the rule detects and why it matters. Should include a research citation when a published source exists. |
| `severity` | `enum` | One of: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` (case-insensitive). |
| `category` | `string` | Logical grouping. Recommended values: `poisoning`, `credentials`, `transport`, `supply-chain`, `network`, `injection`, `filesystem`, `governance`, `hygiene`. Custom values are accepted. |
| `match` | `RuleMatch` | Detection condition(s). See §4. |
| `message` | `string` | Template string for the finding description. May use `{server_name}` and `{matched_value}` placeholders. |

### 3.2 Optional fields

| Field | Type | Default | Description |
|---|---|---|---|
| `tags` | `list[string]` | `[]` | Arbitrary labels for filtering. Lowercase, hyphen-separated tokens recommended. |
| `enabled` | `boolean` | `true` | When `false`, the rule is loaded but never evaluated. |
| `exempt_known_servers` | `boolean` | `false` | When `true` and a registry is loaded, the rule is suppressed for servers whose command, args, or name matches a known-legitimate registry entry. |
| `owasp_mcp_top_10` | `list[string]` | `[]` | OWASP MCP Top 10 category codes (e.g. `["MCP01"]`). Propagated to emitted `Finding` objects and SARIF taxonomies. |
| `cve` | `list[string]` | `[]` | CVE identifiers (e.g. `["CVE-2026-30623"]`). Propagated to emitted findings. |
| `author` | `string` | `null` | Contributor identifier (GitHub handle or full name). Shown in `mcp-audit rule list`. |
| `bounty_accepted` | `string` | `null` | ISO-8601 date string set by maintainers when the rule is accepted into the bounty program (e.g. `"2026-05-17"`). |

---

## 4. RuleMatch schema

A `RuleMatch` is either a **simple match** (one field/pattern pair) or a
**compound match** (logical combination of two or more conditions).

### 4.1 Simple match

```yaml
match:
  field: <MatchField>
  pattern: <string>
  type: <MatchType>
  negate: <boolean>   # optional, default false
```

### 4.2 Compound match

```yaml
match:
  operator: and   # or: or
  conditions:
    - field: <MatchField>
      pattern: <string>
      type: <MatchType>
      negate: <boolean>    # optional
    - field: <MatchField>
      pattern: <string>
      type: <MatchType>
# At least 2 conditions required
```

---

## 5. Field and type enumerations

### 5.1 MatchField

| Value | Extracted content |
|---|---|
| `command` | Server binary string (e.g. `"node"`, `"/usr/local/bin/server"`) |
| `args` | All argument strings joined by a single space |
| `env` | All environment variable **key** names joined by a single space |
| `server_name` | The server's identifier key in the MCP config |
| `url` | The server's transport URL; absent (`null`) for stdio servers |
| `transport` | Transport type string (`"stdio"`, `"sse"`, `"http"`) |
| `capabilities` | Capability key names joined by a single space; absent when no capabilities are declared |

**Note:** `env` exposes key names only, not values. Rules that need to reason
about env values should match on key name patterns as a signal.

### 5.2 MatchType

| Value | Behaviour |
|---|---|
| `exact` | Full-string equality (`field_value == pattern`) |
| `contains` | Substring containment (`pattern in field_value`) |
| `regex` | `re.search(pattern, field_value)` — partial match; use `(?i)` prefix for case-insensitive matching |
| `glob` | Shell-style wildcard via `fnmatch.fnmatch` |
| `semver_range` | PEP 440 version specifier applied to the field value (e.g. `">=1.2,<2.0"`) |

---

## 6. Validation

A conforming validator must:

1. Parse the file as YAML and normalise to a list of rule dicts.
2. For each rule dict, verify all required fields are present and have correct types.
3. Verify `severity` is one of the five allowed values.
4. Verify `match` is a valid `RuleMatch` (simple: all of `field`, `pattern`, `type`
   present; compound: `operator` present, `conditions` has ≥ 2 entries, each entry
   is a valid `MatchCondition`).
5. Verify `field` values in every condition are valid `MatchField` values.
6. Verify `type` values in every condition are valid `MatchType` values.
7. Exit with a non-zero status code if any rule fails validation.
8. Unknown fields (e.g. `author`, `bounty_accepted`) **must be silently ignored**
   to allow forward-compatible extension.

Reference implementation: `mcp-audit rule validate <file>` (Python, Apache 2.0).

---

## 7. License

This specification is licensed **Apache 2.0**.

Any tool that implements this schema can claim compatibility with the mcp-audit
community rule format. No permission from the mcp-audit maintainers is required.
We welcome cross-tool adoption — if your scanner implements this format, open an
issue or PR to add it to the ecosystem compatibility list in `docs/registry.md`.

---

## 8. Versioning

This specification follows semantic versioning. Breaking changes (removed fields,
changed semantics) increment the major version. Additive changes (new optional
fields) increment the minor version.

The version is embedded in this document header and in the mcp-audit release
notes whenever the spec changes.

---

## 9. References

- mcp-audit rule engine implementation: `src/mcp_audit/rules/engine.py`
- Community rule contribution guide: `docs/contributing-rules.md`
- Rule authoring reference: `docs/writing-rules.md`
- Bundled community rules: `rules/community/COMM-001.yml` through `COMM-030.yml`
