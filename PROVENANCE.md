# Provenance

This document explains where mcp-audit's detection logic, patterns, and architecture decisions come from. Transparency matters — especially for a security tool. No code was copied from any existing scanner. All detection patterns were built from scratch based on published security research.

## Detection patterns

### Tool poisoning (analyzers/poisoning.py)

The poisoning analyzer detects malicious instructions hidden in MCP tool descriptions — text visible to the AI model but often hidden from the user in client UIs.

**Research sources:**

- **Invariant Labs** — First published disclosure of MCP tool poisoning attacks (April 2025). Demonstrated that tool descriptions are an injection surface and that agents don't need to *call* a poisoned tool to be infected; merely reading its metadata during tool discovery is sufficient. ([Blog post](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks))
- **CrowdStrike** — Demonstrated an MCP tool called `add_numbers` that performed math correctly while silently exfiltrating SSH private keys through hidden metadata instructions. This is the basis for our POISON-001 (SSH key exfiltration) pattern.
- **CyberArk** — Research showing that every part of a tool schema — parameter names, types, examples, not just descriptions — is an injection surface.
- **arXiv 2601.17549** — "Breaking the Protocol: Security Analysis of the Model Context Protocol Specification and Prompt Injection Vulnerabilities in Tool-Integrated LLM Agents." Academic analysis of MCP-specific prompt injection vectors.
- **arXiv 2601.17548** — "Prompt Injection Attacks on Agentic Coding Assistants." Systematic analysis of injection vulnerabilities in skills, tools, and protocol ecosystems.
- **Palo Alto Unit 42** — Demonstrated Amazon Bedrock agent memory poisoning via malicious webpages, causing silent data exfiltration in future sessions.
- **NeurIPS 2025 (MINJA)** — "Memory Injection Attacks Against AI Agents." Demonstrated >95% injection success rates through query-only interaction.
- **The Vulnerable MCP Project** ([vulnerablemcp.info](https://vulnerablemcp.info)) — Community-maintained database of MCP security vulnerabilities and CVEs.
- **OWASP Top 10 for Agentic Applications (December 2025)** — Risk categories ASI01 (Agent Goal Hijack) through ASI10 (Rogue Agents), developed by 100+ security researchers. ([OWASP](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/))
- **OWASP Agentic Skills Top 10** — Documents real-world supply chain attacks on agent tool registries, including the ClawHub registry poisoning. ([OWASP](https://owasp.org/www-project-agentic-skills-top-10/))

### Credential exposure (analyzers/credentials.py)

The credentials analyzer uses regex patterns to detect common API key formats in environment variables and command arguments.

**Pattern sources:**

- API key format documentation from AWS, GitHub, OpenAI, Anthropic, Stripe, and Slack developer docs (all public).
- General secret detection patterns are well-established in the security community and used by tools like truffleHog, detect-secrets, and GitLeaks. Our patterns were written independently but follow the same publicly documented key format conventions.

### Transport security (analyzers/transport.py)

The transport analyzer checks for insecure network configurations and elevated privilege execution.

**Research sources:**

- **MCP specification** ([modelcontextprotocol.io](https://modelcontextprotocol.io)) — Transport documentation covering stdio, SSE, and streamable HTTP modes.
- **WorkOS** — "Securing agentic apps: How to vet the tools your AI agents depend on." Analysis of MCP supply chain risks via runtime package fetching (npx/uvx). ([Blog post](https://workos.com/blog/mcp-supply-chain-security))
- **Snyk** — "How Clinejection Turned an AI Bot into a Supply Chain Attack." Demonstrated that natural-language prompt injection in a GitHub issue could compromise Cline's GitHub Actions pipeline. ([Blog post](https://snyk.io/blog/cline-supply-chain-attack-prompt-injection-github-actions/))

## Config file locations

Client configuration paths are sourced from each client's public documentation:

| Client | Source |
|--------|--------|
| Claude Desktop | Anthropic MCP documentation |
| Cursor | Cursor MCP setup docs |
| VS Code | VS Code MCP configuration docs (note: uses `"servers"` root key, not `"mcpServers"`) |
| Windsurf | Codeium MCP integration docs |
| Claude Code | Anthropic Claude Code configuration docs |

## Architecture

The project architecture (Typer CLI, Rich output, Pydantic models, analyzer-pattern abstraction) was designed from scratch for this project. It was not derived from any existing MCP scanner.

For reference, the existing MCP security tools we studied during design (but did not copy code from):

- **Snyk Agent Scan** (formerly Invariant Labs mcp-scan) — Python, proxy-based approach, sends tool descriptions to external API for analysis, MIT license. ([GitHub](https://github.com/invariantlabs-ai/mcp-scan))
- **Cisco MCP Scanner** — Python, multi-engine approach using YARA rules and LLM-as-judge, Apache 2.0 license. ([GitHub](https://github.com/cisco-ai-defense/mcp-scanner))
- **Golf Scanner** — Go, offline-only, numeric risk scoring, MIT license. ([GitHub](https://github.com/golf-mcp/golf-scanner))

## Frameworks and standards

Detection rules are mapped to these public standards where applicable:

- **CWE** (Common Weakness Enumeration) — Findings include CWE references where a direct mapping exists (e.g., CWE-200 for information exposure, CWE-798 for hardcoded credentials, CWE-74 for injection).
- **MITRE ATLAS** — Agent-specific attack techniques added in late 2025 (AI Agent Context Poisoning, Exfiltration via AI Agent Tool Invocation, Publish Poisoned AI Agent Tool) inform our detection categories.
- **OWASP Agentic Top 10** — Risk categories (ASI01–ASI10) inform our analyzer scope and severity mapping.

## Contributing detection patterns

If you want to add new detection patterns, please include in your PR:

1. The pattern itself (regex or heuristic)
2. A reference to the published research, CVE, or real-world incident that motivates it
3. A test case with both a true positive and true negative fixture
4. A CWE mapping if one exists

We don't accept detection patterns based on undisclosed or private research.
