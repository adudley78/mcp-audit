# Example Governance Policies

These files demonstrate the Credenzo governance policy format. Copy and customise
one as a starting point for your organisation.

## Files

| File | Description |
|------|-------------|
| `starter.yml` | Minimal policy — score threshold + TLS requirement. Safe default. |
| `strict.yml` | Full allowlist, high score threshold, registry membership, zero critical findings. |
| `enterprise.yml` | Like `strict.yml` but with per-client overrides for Cursor and Claude Desktop. |

## Quick start

```bash
# Validate a policy file
credenzo policy validate examples/policies/starter.yml

# Run a scan with an explicit policy
credenzo scan --policy examples/policies/starter.yml

# Auto-discovered: copy a policy to your project root
cp examples/policies/starter.yml .mcp-audit-policy.yml
credenzo scan   # picks up .mcp-audit-policy.yml automatically
```

## Policy resolution order

When `--policy` is not specified, Credenzo searches for a policy file in this order:

1. Current working directory (checks `.mcp-audit-policy.yml`, `.mcp-audit-policy.yaml`, `mcp-audit-policy.yml`)
2. Git repository root (walks up from cwd)
3. `~/.config/mcp-audit/policy.yml`

Commit `.mcp-audit-policy.yml` to your repository root so CI and every developer's
machine picks it up automatically.

## Authoring tools (Pro/Enterprise)

```bash
# Generate a commented template
credenzo policy init

# Quick compliance check (no full security scan)
credenzo policy check
```

See [docs/governance.md](../../docs/governance.md) for the full field reference.
