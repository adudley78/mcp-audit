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

**Severity calibration:** `TRANSPORT-003` (runtime package fetching) tiers its severity by `KnownServerRegistry` membership (rescoped 2026-04-20, see GAPS.md). Verified registry entries suppress the finding entirely (COMM-010 retains the pinning reminder at LOW); known-but-unverified entries surface at LOW with a pointer to `--verify-hashes`; unknown packages continue to fire at MEDIUM. The tiering is implemented in `TransportAnalyzer._build_runtime_fetch_finding`.

## Config file locations

Client configuration paths are sourced from each client's public documentation:

| Client | Source |
|--------|--------|
| Claude Desktop | Anthropic MCP documentation |
| Cursor | Cursor MCP setup docs |
| VS Code | VS Code MCP configuration docs (note: uses `"servers"` root key, not `"mcpServers"`) |
| Windsurf | Codeium MCP integration docs |
| Claude Code | Anthropic Claude Code configuration docs |
| GitHub Copilot CLI | GitHub Copilot CLI documentation |
| Augment Code | Augment Code documentation |

## Architecture

The project architecture (Typer CLI, Rich output, Pydantic models, analyzer-pattern abstraction) was designed from scratch for this project. It was not derived from any existing MCP scanner.

For reference, the existing MCP security tools we studied during design (but did not copy code from):

- **Snyk Agent Scan** (formerly Invariant Labs mcp-scan) — Python, proxy-based approach, sends tool descriptions to external API for analysis, MIT license. ([GitHub](https://github.com/invariantlabs-ai/mcp-scan))
- **Cisco MCP Scanner** — Python, multi-engine approach using YARA rules and LLM-as-judge, Apache 2.0 license. ([GitHub](https://github.com/cisco-ai-defense/mcp-scanner))
- **Golf Scanner** — Go, offline-only, numeric risk scoring, MIT license. ([GitHub](https://github.com/golf-mcp/golf-scanner))

### Supply chain (analyzers/supply_chain.py)

The supply chain analyzer detects typosquatted npm package names by computing Levenshtein edit distance between the package name in a config and every name in a curated registry of 64 known-legitimate MCP servers.

**Research sources:**

- **Vu et al., "Typosquatting in the npm Ecosystem," NDSS 2021** ([Paper](https://www.ndss-symposium.org/ndss-paper/detecting-node-js-package-name-squatting/)) — Academic basis for Levenshtein distance-based typosquatting detection. Demonstrates that single-edit-distance substitutions, additions, and deletions are the dominant technique in real npm package name squatting attacks. Distance-1 is flagged CRITICAL and distance-2 HIGH in our analyzer, reflecting their finding that single-character changes are almost always malicious.
- **WorkOS** — Analysis of MCP supply chain risks via runtime package fetching (npx/uvx). ([Blog post](https://workos.com/blog/mcp-supply-chain-security))
- **OWASP Agentic Skills Top 10** — Documents real-world supply chain attacks on agent tool registries, including the ClawHub registry poisoning incident.

### Rug-pull detection (analyzers/rug_pull.py)

The rug-pull analyzer detects changes to MCP server configurations between scans by maintaining SHA-256 hashes of each server's configuration state and comparing them across scan invocations.

**Research sources:**

- **Invariant Labs** — Coined the "rug pull" terminology in the MCP context: a server publishes clean, trusted tool descriptions during initial review, then silently swaps them for malicious versions after developers have granted access. This is the server-side analog of the npm/PyPI typosquatting lifecycle — gain trust, then exploit.
- **Trail of Bits** — Research on software supply chain integrity verification, establishing the pattern of cryptographic hash comparison for detecting unauthorized modifications to trusted artifacts.
- The SHA-256 hash-and-compare approach is a standard integrity verification technique. The novel contribution is applying it to MCP tool description metadata rather than to package binaries or source code.

### Toxic flow (analyzers/toxic_flow.py)

The toxic flow analyzer tags each MCP server with capability labels sourced (in priority order) from the known-server registry (`RegistryEntry.capabilities` in `registry/known-servers.json`) and — as a fallback for servers not in the registry — from package-name and command keyword matching. It then checks every server pair (and single servers) for known-dangerous capability combinations that form multi-hop attack paths. Capability tag values for the 14 official `@modelcontextprotocol/*` servers were originally hand-curated in `KNOWN_SERVERS` and have since been migrated to the registry JSON; the in-module `KNOWN_SERVERS` table remains as a deterministic fallback when no registry is injected.

**Research sources:**

- **OWASP Agentic Top 10, ASI04 — Inadequate Sandboxing** ([OWASP](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)) — Defines the risk of agents operating across system boundaries without isolation. Our TOXIC-003 (secrets + network) and TOXIC-006 (shell + network) patterns are direct implementations of the ASI04 risk category.
- **arXiv 2601.17549** and **arXiv 2601.17548** (cited in poisoning section above) — Both papers analyze multi-server chaining as an amplification technique. A prompt injection in one server can trigger tool calls on other servers, traversing the toxic pair.
- **Invariant Labs cross-server interaction research** — The same group that disclosed tool poisoning also demonstrated that agents do not maintain trust boundaries between servers: a compromised server can instruct the agent to call tools on other servers. This motivates the pair-based (not just individual-server) threat model in our toxic flow analyzer.

### Attack path engine (analyzers/attack_paths.py)

The attack path engine performs multi-hop reachability analysis across server capability graphs and uses a greedy set cover algorithm to compute the minimum hitting set — the smallest number of servers to remove to break all identified attack paths.

**Algorithmic basis:**

- **Greedy set cover / hitting set approximation** — This is a well-known polynomial-time approximation for a classic NP-hard combinatorial optimization problem. The greedy algorithm achieves a ln(n) approximation bound (where n is the number of attack paths), which is optimal assuming P ≠ NP. No specific security research paper is cited here; this is standard computer science applied to a novel domain. The algorithm is described in any algorithms textbook (e.g., Cormen et al., *Introduction to Algorithms*, §35.3 — Set Cover).
- The framing of "minimum set of assets to remove to break all attack paths" is analogous to network interdiction problems in operations research, applied here to MCP server dependency graphs.

### SAST rules — TypeScript path traversal, SQL injection, SSRF (semgrep-rules/typescript/injection/)

New TypeScript detection rules added in v0.6.0: `mcp-ts-fs-readfile-traversal`,
`mcp-ts-fs-writefile-traversal`, `mcp-ts-path-join-traversal`,
`mcp-ts-string-concat-sql`, `mcp-ts-template-literal-sql`,
`mcp-ts-fetch-ssrf`, `mcp-ts-http-request-ssrf`.

**Research sources:**

- **OWASP Path Traversal** ([OWASP](https://owasp.org/www-community/attacks/Path_Traversal)) — Documents the CWE-22 (Improper Limitation of a Pathname to a Restricted Directory) attack class; motivates checking `fs.readFile()`/`fs.writeFile()` and `path.join()` sinks for unvalidated path inputs.
- **CWE-22 — Improper Limitation of a Pathname to a Restricted Directory** ([MITRE CWE](https://cwe.mitre.org/data/definitions/22.html)) — Canonical weakness definition; remediation guidance (resolve + boundary check) mirrors the CWE mitigation section.
- **OWASP SQL Injection Prevention Cheat Sheet** ([OWASP](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)) — Documents string concatenation and template literal interpolation as primary SQLi vectors; parameterized query syntax used in rule messages is taken directly from this cheat sheet.
- **CWE-89 — Improper Neutralization of Special Elements used in an SQL Command** ([MITRE CWE](https://cwe.mitre.org/data/definitions/89.html)) — Canonical weakness definition for SQL injection.
- **OWASP Server-Side Request Forgery Prevention Cheat Sheet** ([OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)) — Documents SSRF via unvalidated URLs in HTTP client calls (fetch, axios, http.request); allowlist-based remediation is taken from this cheat sheet.
- **CWE-918 — Server-Side Request Forgery** ([MITRE CWE](https://cwe.mitre.org/data/definitions/918.html)) — Canonical weakness definition for SSRF.
- **MCP Specification — Tool Input Handling** ([modelcontextprotocol.io](https://modelcontextprotocol.io)) — Tool argument values are the primary source of untrusted data in MCP server handlers; these rules target the most common high-impact sinks that receive tool arguments without validation.

All seven rules are original pattern-only implementations (no taint analysis).
They follow the same sink-matching approach as the existing Python SAST rules.
Taint/dataflow analysis to reduce false positives is a documented future gap.



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

## Community rules (rules/community/)

13 bundled community detection rules (COMM-001 through COMM-013) ship with
mcp-audit and run for all users regardless of license tier.

| Rule | Description | Basis |
|------|-------------|-------|
| COMM-001 | Netcat binary in server command | Original — common security practice (netcat as a lateral movement / exfiltration tool) |
| COMM-002 | Eval in command arguments | Original — CWE-95 (eval injection); standard static analysis pattern |
| COMM-003 | Curl piped to shell | Original — common supply chain risk pattern (arbitrary code execution via pipe-to-shell) |
| COMM-004 | Unrecognized stdio server binary | Original — fires only for stdio servers whose command/args/name do not resolve to a known-server registry entry (rescoped 2026-04-20, see GAPS.md); stdio servers inherit the parent process's full environment |
| COMM-005 | Wildcard environment variables | Original — excessive environment exposure reduces isolation |
| COMM-006 | World-writable config path | Original — CWE-732 (incorrect permission assignment); standard filesystem security check |
| COMM-007 | Known-malicious package name | Community-sourced — based on published MCP supply chain incident reports |
| COMM-008 | Insecure binding (0.0.0.0) | Original — common network security practice; see V-09 in GAPS.md |
| COMM-009 | Debug mode enabled | Original — debug flags in production expose internal state |
| COMM-010 | Excessive argument count | Original — heuristic for overly complex server invocations |
| COMM-011 | Temporary directory as working directory | Original — CWE-377 (insecure temporary file); /tmp is world-writable |
| COMM-012 | Non-HTTPS remote URL | Original — transport security; mirrors TRANSPORT-001 for rule-engine coverage |
| COMM-013 | npx auto-confirm flag (silent execution) | Original — OX Security STDIO disclosure (CVE-2025-49596 and related CVEs); npx `-y`/`--yes` bypasses interactive confirmation, enabling silent RCE when an attacker controls the package name |

All community rules are original implementations based on common security
practice and published CWE categories. None are derived from proprietary
research or other scanner rulesets.
