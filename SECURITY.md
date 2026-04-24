# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in mcp-audit, please report it
responsibly. **Do not open a public GitHub issue for security vulnerabilities.**

**Email:** security@mcp-audit.dev  
**Response time:** We aim to acknowledge reports within 48 hours.  
**Disclosure timeline:** We follow a 90-day coordinated disclosure policy.
After 90 days (or earlier if a fix is available and deployed), the issue
may be disclosed publicly.

We also accept reports via GitHub's private vulnerability reporting feature —
see the "Report a vulnerability" button in the Security tab.

## Scope

In scope:
- The `mcp-audit` CLI scanner (`src/mcp_audit/`)
- Bundled detection rules (`rules/community/`, `semgrep-rules/`)
- Bundled registry data (`registry/`)
- The GitHub Action (`action.yml`)

Out of scope:
- Third-party MCP servers or configurations that mcp-audit scans
- Vulnerabilities in mcp-audit's own dependencies (report those to the
  upstream project; we track them via Dependabot and `pip-audit`)
- Issues that require physical access to the target machine

## What to Include

A useful report includes:
- A description of the vulnerability and its potential impact
- Steps to reproduce (config files, commands, or a minimal test case)
- Your assessment of severity (CVSS score if possible)
- Whether you have a suggested fix

## Recognition

We don't have a formal bug bounty programme, but we acknowledge researchers
by name in the CHANGELOG and release notes unless you prefer to remain
anonymous. Please let us know your preference.
