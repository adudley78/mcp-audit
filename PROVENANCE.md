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
- **Johann Rehberger (Embrace The Red), "ASCII Smuggling and Hidden Prompt Instructions"** (Feb 2024) and follow-up "Microsoft Copilot: From prompt injection to exfiltration of personal information via ASCII smuggling" (Aug 2024) — first published the technique of encoding hidden instructions in the Unicode Tags block (U+E0000–U+E007F), which mirrors the ASCII set but renders as nothing in virtually every UI. wunderwuzzi's ASCII Smuggler tool (Jan 2024) demonstrated the encode/decode round-trip. Basis for POISON-041/042 (STORY-0068; design doc `humans/decisions/2026-09-09-poison-041-design.md` in the marcus repo): TAG characters are category `Cf` and are correctly dropped by `normalize_for_detection()`'s existing zero-width-splitting defence, but dropping a *payload* (rather than a separator) silently destroys the evidence instead of revealing it — POISON-041/042 extract the TAG run into its own string, decode it, and rescan it against the existing `PATTERNS` list as an independent pass. ([Blog post](https://embracethered.com/blog/posts/2024/ascii-smuggling-and-hidden-prompt-instructions/))
- **Cloud Security Alliance, "Unicode Instruction Injection in AI Skills"** (research note) — extends the ASCII-smuggling threat model specifically to MCP tool descriptions and agent skill files, and documents confirmed exploitation via hidden Unicode Tags payloads across Claude Code, GitHub Copilot, OpenAI Codex Skills, and Gemini CLI. Corroborates scoping POISON-041/042 to both the config surface and the agent-file surface (`agent_files/analyzer.py`) in one shared implementation. ([Cloud Security Alliance](https://labs.cloudsecurityalliance.org/research/csa-research-note-unicode-instruction-injection-ai-skills-20/))

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

The supply chain analyzer detects typosquatted npm package names by computing Levenshtein edit distance between the package name in a config and every name in a curated registry of 83 known-legitimate MCP servers.  It also emits `SC-004` (HIGH) when an exact-match registry entry carries `known_vulnerabilities` CVE IDs — an offline advisory check requiring no network access — `SC-007` for an unscoped twin of a registry entry, and `SC-008` for an exact-name OSV `MAL-*` record (STORY-0097, below).

**Research sources:**

- **Vu et al., "Typosquatting in the npm Ecosystem," NDSS 2021** ([Paper](https://www.ndss-symposium.org/ndss-paper/detecting-node-js-package-name-squatting/)) — Academic basis for Levenshtein distance-based typosquatting detection. Demonstrates that single-edit-distance substitutions, additions, and deletions are the dominant technique in real npm package name squatting attacks. Distance-1 is flagged CRITICAL and distance-2 HIGH in our analyzer, reflecting their finding that single-character changes are almost always malicious.
- **WorkOS** — Analysis of MCP supply chain risks via runtime package fetching (npx/uvx). ([Blog post](https://workos.com/blog/mcp-supply-chain-security))
- **OWASP Agentic Skills Top 10** — Documents real-world supply chain attacks on agent tool registries, including the ClawHub registry poisoning incident.
- **NVD / GitHub Security Advisories** — Source for all `known_vulnerabilities` CVE entries in `registry/known-servers.json`. Each entry was confirmed against the official NVD record or GitHub GHSA before seeding. CVEs confirmed and seeded for v0.12.0: CVE-2026-23744 (`@mcpjam/inspector`), CVE-2026-0755 (`gemini-mcp-tool`), CVE-2025-59528 (`flowise`), CVE-2026-26118 (`@azure/mcp`), CVE-2026-33032 (`nginx-ui`). CVE-2026-32211 was not seeded — NVD CPE is `azure_web_apps` (hosted service; no pinnable package version).

**SC-007 unscoped twins and SC-008 known-malicious packages (STORY-0097, 2026-10-25):**

- **o3.security, "mcp-server-github" malware analysis** ([o3.security](https://o3.security/malware/npm/mcp-server-github)) and the OSV record it summarises, **MAL-2026-5479 / GHSA-95pj-hrh5-27gq** ([OSV](https://osv.dev/vulnerability/MAL-2026-5479), [GitHub](https://github.com/advisories/GHSA-95pj-hrh5-27gq)) — an unscoped npm name intercepting installs meant for `@modelcontextprotocol/server-github`, with an install-time beacon. The basis for SC-007: edit distance cannot see a scope difference.
- **OSV MAL-2026-5476 to MAL-2026-5485 and MAL-2025-46986** (read from OSV's npm bulk export on 2026-10-25) — the full family of unscoped twins (`mcp-server-fetch`, `-figma`, `-git`, `-github`, `-notion`, `-postgres`, `-redis`, `-sentry`, `-sequential-thinking`, `-supabase`, `-everything`). The SC-007 naming rules (name part of `server-<x>`/`mcp-server-<x>`, the `mcp-server-<x>` spelling of `server-<x>`/`<x>-mcp-server`, and the same `mcp-server-<x>` name across npm and PyPI) are the shapes this family and the registry's own entries show; each rule was then measured against live npm and PyPI on 2026-10-25 (`docs/supply-chain.md`). Rules not seen in the data (e.g. `mcp-server-<x>` → `server-<x>`, every name was absent on npm) were not adopted.
- **`registry-audit-2026-08-18.md` §3a and §3b** (this repository) — three of the same npm packages named `theinfosecguy/npx-canary` as their repository (the source of the note attached to MAL-2026-5476..5485, which states only that and the shared beacon host), and one account's `0.0.1` stubs under vendor names (three of which are SC-007 twins today).
- **Panguard, "npm MCP security findings"** ([panguard.ai](https://panguard.ai/blog/npm-mcp-security-findings)) — SANDWORM_MODE, a 19-package typosquat cluster of MCP-adjacent npm packages harvesting SSH keys at install; context for exact-name matching of known-bad names.
- **OpenSSF malicious-packages** ([GitHub](https://github.com/ossf/malicious-packages)) via **OSV's data dumps** ([OSV docs](https://google.github.io/osv.dev/data/): per-ecosystem `all.zip` in `gs://osv-vulnerabilities`, "including withdrawn records") — the source of `registry/known-malicious.json`. `scripts/sync_registry_advisories.py` keeps non-withdrawn `MAL-*` records whose package name contains `mcp` or that the registry lists.
- **OSV schema, "Evaluation"** ([ossf.github.io/osv-schema](https://ossf.github.io/osv-schema/)) — the range semantics `registry/malicious.py` implements (`introduced` / `fixed` / `last_affected` walked in version order, plus the explicit `versions` list). The one deliberate deviation (a blanket all-versions range is ignored for a registry-listed package when the record also lists explicit versions) is documented in that module and in `docs/supply-chain.md`, with `MAL-2025-191195` (`@browserbasehq/mcp`) as the measured case.
- **PEP 503** ([peps.python.org](https://peps.python.org/pep-0503/)) — the name folding SC-007 applies to both ecosystems' names before comparing.

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

### Authentication checks (analyzers/auth.py)

AUTH-001 (remote server without authentication) and AUTH-002 (OAuth audience
binding) were added in v0.12.0 based on the following published research.

**Research sources:**

- **arXiv 2605.22333** — Zhou et al., "A First Measurement Study on
  Authentication Security in Real-World Remote MCP Servers" (May 2026,
  <https://arxiv.org/abs/2605.22333>). Measurement study of live remote MCP
  servers: identified 7,973 servers and found 40.55% expose tools without
  authentication. Also
  evaluated 119 OAuth-enabled MCP servers and found every one had at least one
  flaw (325 total); dynamic-client-registration (DCR) vulnerabilities affected
  96.6% of the OAuth-enabled sample. Both AUTH-001 and AUTH-002 cite this study
  directly in their finding descriptions.
- **Censys** — "MCP Servers on the Internet" (published May 27, 2026; data
  as of April 28, 2026; <https://censys.com/blog/mcp-servers-on-the-internet/>).
  Counted 12,520 internet-accessible MCP services across 8,758 IP addresses.
  The post gives no unauthenticated percentage: it says the protocol does not
  enforce authentication and that many deployments operate without it. Cited
  in the AUTH-001 description to quantify internet exposure.
- **RFC 8707** — "Resource Indicators for OAuth 2.0" (IETF, 2020). Defines the
  `resource` parameter and audience binding requirements that AUTH-002 checks
  for. The missing-audience attack (token cross-resource replay) is documented
  in Section 2.2 of the RFC.
- **CWE-306** — "Missing Authentication for Critical Function" (MITRE). AUTH-001
  is a direct instance: every MCP tool call is a critical function invocable
  by anyone who can reach the URL without authentication.
- **CWE-346** — "Origin Validation Error" (MITRE). AUTH-002 maps here: a missing
  audience binding allows tokens from any origin that shares the issuer to be
  accepted.
- **OWASP MCP Top 10 MCP06** — "Intent Flow Subversion" (insufficient
  authentication/authorization). Both AUTH-001 and AUTH-002 are MCP06 findings.

No code was copied from any existing authentication scanner. The host-visibility
classification (public / private-RFC-1918 / localhost), auth-signal detection,
and OAuth-block extraction logic are original implementations.

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

### SAST rules — TypeScript credential default params, secrets logged, description obfuscation, input validation, stack trace exposure, listen-all-interfaces (semgrep-rules/typescript/)

Seven new TypeScript rule files added in v0.7.0 (11 rules total), porting categories
that existed in Python to TypeScript.

**`mcp-ts-credential-default-param` (CWE-798):**

- **OWASP A07:2021 — Identification and Authentication Failures** ([OWASP](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)) — Hardcoded credentials in default parameter values are equivalent to hardcoded credentials in environment configuration; both are in-band secrets visible in source code and stack traces.
- **CWE-798 — Use of Hard-coded Credentials** ([MITRE CWE](https://cwe.mitre.org/data/definitions/798.html)) — Canonical weakness definition; the remediation guidance (use environment variables or a secrets manager) mirrors the CWE-798 mitigation section.

**`mcp-ts-console-log-sensitive` / `mcp-ts-console-error-sensitive` (CWE-532):**

- **CWE-532 — Insertion of Sensitive Information into Log File** ([MITRE CWE](https://cwe.mitre.org/data/definitions/532.html)) — Canonical weakness definition for logging credentials. The same source motivates the Python `mcp-print-sensitive-var` and `mcp-logging-sensitive-var` rules.
- **OWASP A09:2021 — Security Logging and Monitoring Failures** ([OWASP](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/)) — Logging sensitive data is a direct instance of this category; MCP server logs forwarded to cloud aggregators (Datadog, Splunk, CloudWatch) amplify the exposure.
- **CVE-2026-41495 (n8n-MCP)** — Real-world disclosure where request headers (including Bearer tokens) were logged via `console.log(req.headers)`. This CVE motivates the identifier-name-based heuristic used in the TypeScript rule; the same approach catches the pattern class even when the vulnerable expression is a different variable name.

**`mcp-ts-description-contains-url`, `mcp-ts-description-base64-content`, `mcp-ts-description-unicode-escape` (CWE-1336):**

- Same research sources as the Python poisoning rules and the existing TypeScript hidden-instructions rules (Invariant Labs, CrowdStrike, arXiv 2601.17549, OWASP Agentic Top 10 MCP03). TypeScript implementations of MCP servers are subject to identical description-based attack vectors.
- **CWE-1336 — Improper Neutralization of Special Elements Used in a Template Engine** ([MITRE CWE](https://cwe.mitre.org/data/definitions/1336.html)) — Applied here to tool description content that is consumed by AI models rather than by a traditional template engine; the injection surface (model-readable text that bypasses human review) is analogous.

**`mcp-ts-no-type-check-before-use` (CWE-20):**

- **CWE-20 — Improper Input Validation** ([MITRE CWE](https://cwe.mitre.org/data/definitions/20.html)) — Canonical weakness definition. In TypeScript MCP servers, tool arguments arrive as `Record<string, unknown>`; accessing a property without a `typeof` guard or schema parse is CWE-20 instantiated at the MCP argument boundary.
- **MCP TypeScript SDK documentation** ([github.com/modelcontextprotocol/typescript-sdk](https://github.com/modelcontextprotocol/typescript-sdk)) — Documents that tool arguments are untyped at the protocol level and must be validated by the server implementation before use.

**`mcp-ts-error-stack-in-return`, `mcp-ts-error-tostring-in-return` (CWE-209):**

- **CWE-209 — Generation of Error Message Containing Sensitive Information** ([MITRE CWE](https://cwe.mitre.org/data/definitions/209.html)) — Canonical weakness definition. Stack traces expose file paths, module structure, and line numbers; `String(err)` exposes the raw exception message which may contain connection strings or internal state.
- **OWASP A05:2021 — Security Misconfiguration** ([OWASP](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)) — Returning raw exception detail to clients is a misconfiguration finding in the OWASP framework; the MCP model context is the effective "client" in an AI tool call.

**`mcp-ts-express-listen-all`, `mcp-ts-http-listen-all` (CWE-605):**

- Same research source as the Python `mcp-uvicorn-listen-all` and `mcp-fastapi-listen-all` rules: **CVE-2026-33032** (nginx UI wildcard bind), **CWE-605** ([MITRE CWE](https://cwe.mitre.org/data/definitions/605.html)), and the **OWASP A05:2021 Security Misconfiguration** category. The TS rules cover the Express/Node HTTP/Fastify equivalent of the Python uvicorn/Flask pattern.

All eleven rules are original pattern-only implementations. They follow the same
metavariable-regex and `patterns:` AND-logic approach as the existing TypeScript
and Python SAST rules. No taint analysis.

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

37 `.yml` files ship in `rules/community/`: 36 real (non-template) detection
rules plus `TEMPLATE.yml` itself (loads as the always-inert `COMM-000`
contribution template; `BOUNTY.md` ships alongside but is not a rule file).
Of the 36 real rules, **35 run for every user automatically** and **1**
(`STDIO-001`) ships `enabled: false` with no governance-policy mechanism to
turn it on (see `GAPS.md`) — a rule nobody can enable does not count toward
a community-rule capability claim, so counts used for that purpose should
read 35, not 36 or 37.
(`COMM-032` is intentionally reserved and unissued; the next new numbered
rule will be `COMM-035` (`COMM-034` already exists — see the god-key
credential-scope entry in the table below).
See the COLLIDE-001 section below for why `COMM-032` was skipped.)

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
| COMM-014 | MCP Sampling capability declared | Palo Alto Unit42 MCP Security Analysis, May 2026 — documents Sampling-based resource theft, conversation hijacking, and covert invocation attack vectors |
| COMM-015 | Shell metacharacters in server args | OX Security advisory / CVE-2026-30623 (CVSS 9.8) — config tampering enables shell command injection at server spawn time |
| COMM-016 | Role-claim poisoning in server args | OWASP MCP Top 10 MCP01 (Prompt Injection); adversarial MCP PoC research 2025-2026; role-directive strings in args are a canonical injection delivery mechanism |
| COMM-017 | Authority-claim / AI identity impersonation | OWASP MCP Top 10 MCP01; targeted MCP phishing toolkit research 2025-2026; highest-risk impersonation pattern — "I am Anthropic / I am Claude" overrides user trust calibration |
| COMM-018 | Output-format hijack instruction | OWASP MCP Top 10 MCP01; format-override directives in tool descriptions are a standard persistent injection technique across multiple published PoCs |
| COMM-019 | Side-channel data exfiltration instruction | OWASP MCP Top 10 MCP01 and MCP02; Invariant Labs MCP Security Analysis (2026-04-01) documents exfiltration via covert tool description instructions |
| COMM-020 | Confabulation trigger in server args | OWASP MCP Top 10 MCP01; "always say / never admit / pretend that" directives are documented in adversarial AI suppression research and MCP red-team reports |
| COMM-021 | Env key name suggests private/secret key | OWASP MCP Top 10 MCP02 (Sensitive Data Exposure); CWE-312 (cleartext storage of sensitive information in process environment); complements CRED-001/CRED-002 value-pattern detection |
| COMM-022 | Env key name suggests access token | OWASP MCP Top 10 MCP02; CWE-312; captures non-standard token formats that evade CRED-001 value-pattern matching |
| COMM-023 | Env key name suggests password | OWASP MCP Top 10 MCP02; CWE-256 (plaintext password storage); passwords in process environments are accessible to co-running processes and appear in `/proc/<pid>/environ` |
| COMM-024 | HTTP on sensitive/production port | OWASP MCP Top 10 MCP06 (Transport Security); CWE-319 (cleartext transmission); HTTP on port 443 is a canonical TLS downgrade / interception indicator |
| COMM-025 | Localhost endpoint with explicit URL | OWASP MCP Top 10 MCP06 and MCP05; explicit localhost URLs in SSE/HTTP server configs are unusual and may indicate SSRF gadgets or misconfigured cloud deployments |
| COMM-026 | Unencrypted WebSocket in server args | OWASP MCP Top 10 MCP06; CWE-319; ws:// in hardcoded startup args transmits MCP protocol messages in plaintext |
| COMM-027 | Generic or unnamed server key | OWASP MCP Top 10 MCP07 (Weak Governance); unnamed servers produce no audit trail and cannot be traced in fleet reports |
| COMM-028 | Command is an absolute path | OWASP MCP Top 10 MCP04 (Supply Chain Risk); absolute paths bypass PATH-based discovery and may indicate sideloaded binaries; CWE-114 (process control) |
| COMM-029 | Command references temp/volatile directory | OX Security / CVE-2026-30623 (CVSS 9.8); OWASP MCP Top 10 MCP04; malware writing rogue MCP servers to /tmp is a documented installation vector; CWE-377 |
| COMM-030 | Generic-named server with network URL | OWASP MCP Top 10 MCP09 (Shadow Servers) and MCP07; unnamed network servers resist discovery, fleet auditing, and access-review workflows |
| COMM-031 | Remote MCP server configured without authentication | arXiv 2605.22333 (40.55% of live remote MCP servers unauthenticated); Censys (12,520 internet-exposed MCP services); CWE-306; OWASP MCP Top 10 MCP06. Lightweight URL-pattern companion to AUTH-001 in auth.py. |
| COMM-033 | Project-level MCP config file present in repository | Adversa TrustFall (May 2026) — first published demonstration that committing project-level MCP config causes AI editors to auto-spawn MCP servers with developer OS privileges on "trust folder". CVE-2026-30615 config-tamper channel. CWE-829; OWASP MCP Top 10 MCP09. Lightweight config_path-pattern companion to TRUST-001 in cli/scan.py. |
| STDIO-002a | Hidden (dotfile) launcher binary | Pillar Security "Deadbugz" MCP supply-chain campaign disclosure, 2026-08-12 (https://www.pillar.security/blog/deadbugz-currently-active-mcp-supply-chain-campaign) — four of 23 GitHub pull requests the campaign opened configured a local MCP server at `~/.config/.cache/.sys/.deadbug-mcp.py`; the leaf, not merely a containing directory, is hidden. OWASP MCP Top 10 MCP04/MCP05. |
| STDIO-002b | Inline script launcher | Original — closes a gap COMM-015 (shell metacharacters) leaves open: an interpreter invoked with `-c`/`-e`/`--eval`/`-Command` executes code with no character in COMM-015's metacharacter class present and no file on disk to review. OWASP MCP Top 10 MCP05. |
| STDIO-001 | Launcher binary not in allowlist | Original — policy-gated allowlist derived from this project's own demo/fixture corpus; ships `enabled: false` (see GAPS.md). OWASP MCP Top 10 MCP04/MCP09. |

See `humans/decisions/2026-09-09-stdio-001-002-design.md` (marcus repo) for the
full STDIO-001/002a/002b design, including the amendment dropping an
"outside the scanned repository" criterion from STDIO-002 (unbuildable in the
rule engine's `MatchField` vocabulary — see GAPS.md).

All community rules are original implementations based on common security
practice and published CWE categories. None are derived from proprietary
research or other scanner rulesets.

## Project-level config scan (cli/scan.py, discovery.py)

The `mcp-audit scan --project` feature and its `TRUST-001` finding are based on:

- **Adversa "TrustFall" (May 2026)** — Adversa AI's published research demonstrating
  that committing a project-level MCP config file (`.mcp.json`, `.cursor/mcp.json`,
  `.vscode/mcp.json`) causes AI editors (Claude Code, Cursor, VS Code/Copilot) to
  auto-spawn the named MCP servers with the trusting developer's full OS privileges
  the moment they click "Trust this folder".  The attack requires no code execution
  prior to trust and bypasses OS permission dialogs.
  ([Adversa AI TrustFall blog post](https://adversa.ai/blog/trustfall/))

- **CVE-2026-30615** — Published CVE in the Claude Code CLI demonstrating a
  config-tamper channel.  The config-tamper vector (attacker modifies `.mcp.json`
  before the developer opens the repo) is the second exploitation path corroborating
  the TrustFall mechanism.

- **OWASP MCP Top 10 MCP09 — Shadow MCP Servers** — TRUST-001 maps to MCP09
  because the attacker introduces a *hidden* server (the developer does not know
  the server is present in the repo they are trusting) with elevated capability
  access (full OS privileges).

- **CWE-829 — Inclusion of Functionality from Untrusted Control Sphere**
  ([MITRE CWE](https://cwe.mitre.org/data/definitions/829.html)) — The
  project-level config is the "untrusted control sphere"; the AI editor includes
  the MCP server it defines in its execution environment without requiring the
  developer to inspect or approve the config file's contents.

The discovery logic (`discover_project_configs()`) and the confirmed per-client
project-file paths were verified against official 2026 documentation from
Anthropic (Claude Code), Cursor, and Microsoft (VS Code / GitHub Copilot).
See `src/mcp_audit/discovery.py` for inline references and coverage notes.

## Tool-name collision detection (analyzers/collision.py — COLLIDE-001)

The `COLLIDE-001` finding and its detection logic in
`src/mcp_audit/analyzers/collision.py` are based on:

- **NSA Cybersecurity Information Sheet "Generative AI and LLM Cybersecurity
  Risks"** (April 2025), item 5 — *Namespace Shadowing / Tool Collision*.
  The NSA CSI explicitly names namespace shadowing as a control that
  organisations deploying MCP servers should mitigate: when multiple servers
  expose a tool with the same name, the AI agent's tie-breaking behaviour is
  undocumented, creating a pathway for a malicious server to intercept calls
  intended for a trusted one.
  ([NSA CSI PDF](https://media.defense.gov/2025/Apr/14/2003500458/-1/-1/0/CSI-CYBERSECURITY-FOR-AI.PDF))

- **OWASP MCP Top 10 MCP01 — Token Mismanagement and Secret Exposure** —
  When a rogue tool intercepts an agent call, it receives the tool arguments
  (which may include tokens, credentials, or sensitive data) instead of the
  legitimate server.

- **OWASP MCP Top 10 MCP09 — Shadow MCP Servers** — A server that shadows a
  trusted tool name is, by definition, a shadow server: it is present in the
  agent's namespace without the user's knowledge or consent.

- **CWE-694 — Target of Evaluation Not Clearly Defined**
  ([MITRE CWE](https://cwe.mitre.org/data/definitions/694.html)) — When
  multiple targets (tools) share the same identifier (name), the evaluation
  target is ambiguous; the agent cannot reliably determine which implementation
  it is invoking.

**Why COMM-032 was not issued:** A companion community rule for COLLIDE-001 was
evaluated and rejected.  Static MCP config files do not contain tool lists —
tool names are returned dynamically by running servers via the MCP `tools/list`
RPC.  A rule that fires on static config content cannot detect tool-name
collisions; any static heuristic (e.g. flagging two servers with the same server
*name*) would produce misleading findings.  Shipping a dead or misleading rule
inflates the corpus count and weakens trust in the rule pack.  COMM-032 is
therefore reserved as an unissued ID; the next new community rule will be
COMM-035 (COMM-034 already exists).

---

## Agent-file scanner (SKILL-001/002/003, MEM-001/002, HOOK-001/002)

Added 2026-06-14. Original implementation based on the research below.
No code copied from existing scanners.

### Detection patterns

The agent-file analyzer **imports** detection patterns from
`src/mcp_audit/analyzers/poisoning.py` (the existing `PATTERNS` list) rather
than duplicating them.  The research sourcing for those patterns is already
documented in the `Poisoning Analyzer (POISON-NNN)` section above.

POISON-041/POISON-042 (concealment channels, STORY-0068) follow the same
import-not-fork rule: `scan_concealed_channels()` and
`build_concealment_finding()` live in `analyzers/poisoning.py` and are called
by this module unchanged, so they carry `analyzer="poisoning"` even when the
finding is produced from a skill or memory file — see the "documented
exception" note in this module's own docstring. Research sourcing is in the
`Poisoning Analyzer` section above.

The **new** patterns specific to the agent-file surface are:

- **Unpinned external URL in instruction files (SKILL-003)**: original
  pattern.  Derived from the general supply-chain principle that instruction
  files referencing external, unpinned URLs introduce an external-content
  injection risk, analogous to dependency pinning.  No single paper cited;
  this is an application of CWE-829 (Inclusion of Functionality from
  Untrusted Control Sphere) to the instruction-file surface.

- **Network-egress hook commands (HOOK-001)** and
  **agent config reference in hooks (HOOK-002)**:
  patterns derived from the CVE-2026-30615 disclosure.  The CVE describes
  how a malicious `~/.claude.json` hook command can exfiltrate data and
  persist changes by writing to other config files.  Our regex patterns
  detect the command types that enable these attacks.

### Research sources

1. **OWASP GenAI Top 10 for LLM Risks — "Memory is a feature. It is also an
   attack surface"** (May 2026)
   ([https://owasp.org/www-project-gen-ai-red-teaming/](https://owasp.org/www-project-gen-ai-red-teaming/))
   — Source for MEM-001/MEM-002 threat model: persistent memory injection as
   a high-impact vector because it affects every future agent session.  The
   restricted pattern subset (POISON-010/011/040/060 only) is calibrated to
   the risk profile described in this document.

2. **Unit 42, "Agentic Attack Surfaces: From Config to Memory"** (Q1 2026)
   — Source for the general threat model: AI agent instruction files as attack
   surfaces distinct from MCP configs.  Confirms that `.claude/commands/` and
   `.cursor/rules/` are live attack vectors in wild-caught incidents.  Our
   SKILL-001/002/003 finding categories map directly to Unit 42's taxonomy of
   instruction-injection, obfuscation, and external-content-injection attacks.

3. **CVE-2026-30615** — Claude Code hook injection via config file write.
   Describes the persistence channel exploited by HOOK-002.  The hook command
   regex in `_HOOK_CONFIG_WRITE_RE` covers all MCP config file paths known to
   be targeted in this CVE's proof-of-concept.

4. **CVE-2025-59536** (Check Point Research) — Claude Code hooks section
   command injection.  Source for CFHYG-005 (already documented); HOOK-001
   and HOOK-002 extend the same analysis to cover the specific command classes
   that make hooks dangerous beyond mere presence.

5. **Adversa AI TrustFall** (May 2026) — Project-level MCP config and
   instruction file attacks via freshly-cloned repositories.  Source for the
   `--project` / `--include-agent-files` cloned-repo threat model.

## Harness posture (HARNESS-001..004, analyzers/config_hygiene.py — STORY-0079)

- **HarnessSecurity-Bench** — Zhu, Huang, Ji et al., "HarnessSecurity-Bench: Do
  Security Mechanisms Really Protect Coding Agent Harnesses?", arXiv 2610.07639
  (2026-10-06). Six harnesses (Claude Code, Codex CLI, Gemini CLI, gptme, Qwen Code,
  GitHub Copilot), a ten-mechanism taxonomy, 2,500 trials: about half of confirmed
  mechanism implementations are opt-in, and enabling auto-approve raised attack
  success from 29.2% to 95.6%. Source for treating approval-disabling settings as
  findings and for the severity of HARNESS-001 and HARNESS-004.
- **Claude Code permissions and settings documentation** (code.claude.com/docs/en/
  permissions, settings-reference) — the exact keys and values: `defaultMode`
  values including `bypassPermissions`, `disableBypassPermissionsMode`,
  `skipDangerousModePermissionPrompt`, `enableAllProjectMcpServers`, and
  "`Bash(*)` is equivalent to `Bash` and matches all Bash commands".
- **HARNESS-005/006 practitioner signal (STORY-0087)** — a bare `gh` allow entry let an
  agent post a review on another organization's repository (Cursor forum, thread
  173328, 2026-09-29, staff-confirmed: "covers every gh subcommand, including gh api
  graphql calls that write"); allow rules wider than they read (HN, Luker88,
  2026-10-01, item 49918997); a user running bypass mode in every session lost a drive
  and then added global hooks blocking deletes outside the workspace (X,
  @PerceptualPeak, 2026-10-06/08, 1.04M views). Brief:
  products/mcp-audit/discovery/briefs/2026-10-12-signal-sweep.md (Marcus).
- All six checks are original implementations; no code was copied.

## Other harnesses' auto-run files and settings that redirect API traffic (TRUST-008, CFHYG-007, HARNESS-007 — STORY-0090)

Every key, file and behaviour below was confirmed from the vendor's own
documentation on 2026-10-25; incidents and research are cited for why each
matters. `docs/agent-execution-surface.md` is the per-harness table.

- **Gemini CLI** — hooks live in `hooks.<Event>[].hooks[]` with `type: "command"`
  in project `.gemini/settings.json`, which Gemini CLI fingerprints and warns about
  before running a new or changed hook
  ([hooks](https://geminicli.com/docs/hooks/)); `tools.enableHooks` existed with
  default `false` in 0.18–0.22 and default `true` in 0.24–0.26, replaced by
  `hooksConfig.enabled` (`docs/get-started/configuration.md` at tags v0.18.0–v0.26.0
  and `docs/reference/configuration.md` on `main`, github.com/google-gemini/gemini-cli);
  `.gemini/.env` is preferred over `.env` when the folder is trusted
  (`packages/cli/src/config/settings.ts::findEnvFile`) and its variables "are never
  excluded" ([configuration reference](https://geminicli.com/docs/reference/configuration/));
  untrusted folders load neither (`docs/cli/trusted-folders.md`);
  `GOOGLE_GEMINI_BASE_URL` / `GOOGLE_VERTEX_BASE_URL` override the API endpoints.
- **Codex** — `.codex/config.toml` loads only for trusted projects; `notify`,
  `approval_policy` (`on-request | never | granular`), `sandbox_mode`
  (`read-only | workspace-write | danger-full-access`), inline `[hooks]`, and
  `<repo>/.codex/hooks.json`; current Codex ignores `notify` (and base-URL and
  provider keys) in a project-local config with a startup warning
  ([config reference](https://learn.chatgpt.com/docs/config-file/config-reference),
  [advanced config](https://learn.chatgpt.com/docs/config-file/config-advanced),
  [hooks](https://learn.chatgpt.com/docs/hooks); `developers.openai.com/codex/*`
  redirects there).
- **Claude Code** — `.claude/scheduled_tasks.json` (saved scheduled tasks; copied
  files list but do not run) ([scheduled tasks](https://code.claude.com/docs/en/scheduled-tasks));
  `.claude/workflows/` (saved workflow scripts "shared with everyone who clones the
  repo"; prompts per run by permission mode)
  ([workflows](https://code.claude.com/docs/en/workflows)); both listed as "files
  Claude Code runs on its own" and write-protected
  ([sandboxing](https://code.claude.com/docs/en/sandboxing)); the settings `env` block,
  applied from project settings after workspace trust and at startup in `-p` mode,
  and the variables project settings cannot set
  ([settings reference `env`](https://code.claude.com/docs/en/settings-reference#env));
  `enabledMcpjsonServers` ignored in the shared project file until the folder is
  trusted ([settings reference](https://code.claude.com/docs/en/settings-reference));
  the `ANTHROPIC_*_BASE_URL` endpoint variables, `HTTP_PROXY`, `HTTPS_PROXY` and each
  provider's default host ([env vars](https://code.claude.com/docs/en/env-vars),
  [Bedrock](https://code.claude.com/docs/en/amazon-bedrock),
  [Agent Platform](https://code.claude.com/docs/en/google-vertex-ai),
  [Foundry](https://code.claude.com/docs/en/microsoft-foundry),
  [Claude Platform on AWS](https://code.claude.com/docs/en/claude-platform-on-aws)).
  `OPENAI_BASE_URL` from the [openai-python README](https://github.com/openai/openai-python).
  Bedrock's FIPS and interface-VPC-endpoint host shapes
  (`bedrock-runtime-fips`, `vpce-<id>.bedrock-runtime.<region>.vpce.amazonaws.com`) from
  the [AWS Bedrock user guide](https://docs.aws.amazon.com/bedrock/latest/userguide/vpc-interface-endpoints.html).
  URLs are read the way the WHATWG URL Standard (Node) reads them, with `\` as a path
  separator for special schemes and leading slashes skipped
  ([URL Standard](https://url.spec.whatwg.org/)), as well as literally.
- **Incidents and research** — Miasma worm: `.gemini/settings.json` identical to the
  planted `.claude/settings.json` SessionStart hook, ≥123 repositories
  ([SafeDep](https://safedep.io/miasma-worm-ai-coding-agent-config-injection/));
  CVE-2026-21852: `ANTHROPIC_BASE_URL` in a repository's `.claude/settings.json` sent
  the API key before the trust dialog, fixed 2025-12-28
  ([Check Point Research](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/));
  Codex project `notify` ran outside the sandbox, closed informational 2026-02-24, and
  Gemini `tools.enableHooks` + `hooks.SessionStart` ran on the host
  ([Cymulate](https://cymulate.com/blog/the-race-to-ship-ai-tools-left-security-behind/));
  GHSA-wpqr-6v78-jr5g (CVSS 10.0): headless Gemini CLI trusted the workspace and
  loaded `.gemini/` environment files from a pull request, fixed in 0.39.1 /
  run-gemini-cli 0.1.22 ([advisory](https://github.com/google-github-actions/run-gemini-cli/security/advisories/GHSA-wpqr-6v78-jr5g));
  instruction privilege escalation through harness scheduled tasks and persistent
  goals on six harnesses ([arXiv 2608.27299](https://arxiv.org/abs/2608.27299));
  one agent writing another's security config, including Codex
  `approval_policy = "never"` / `sandbox_mode = "danger-full-access"`
  ([Origin, 2026-03-23](https://www.originhq.com/research/escaping-the-sandbox-confused-deputies),
  via the 2026-10-25 research scan; not re-fetched).
- All checks are original implementations; fixtures are synthetic. No code was copied.

## Tool-definition digests in mcp-lock.json (LOCK-006..009, lock/tool_digests.py — STORY-0086)

- **Invariant Labs** — tool poisoning and the MCP "rug pull" (see Rug-pull detection above), and
  pinning tool descriptions by hash as the countermeasure. mcp-audit's version is an original
  implementation: digests go into the committed `mcp-lock.json`, not a local state file.
- **AAtomless, [github/github-mcp-server#3466](https://github.com/github/github-mcp-server/issues/3466)**
  (2026-10-09) — measured 124 of 131 tool definitions changing in v2.0.0 with no new capability,
  and proposed a two-tier digest that separates a description change from a schema change. The
  `definition` / `contract` split follows that idea; no code was taken.
- **Practitioner signal** — surfacepin and mcp-pin (home-built tool-pinning tools), kenneives on
  [OWASP/CheatSheetSeries#2756](https://github.com/OWASP/CheatSheetSeries/issues/2756), yellowgram on
  [modelcontextprotocol/typescript-sdk#2880](https://github.com/modelcontextprotocol/typescript-sdk/issues/2880).
  Ledger PAIN-2026-007 and brief 2026-10-12 §2.2 (Marcus). Their code was not read.
- **MCP specification** — `tools/list` (cursor pagination) and the Tool fields `name`, `title`,
  `description`, `inputSchema`, `outputSchema`, `annotations`; **RFC 8785** for the canonical
  JSON that is hashed (`advisory/canonical.py`, shared with the advisory feed).

## Permission rules that don't do what they say (PERM-001..007, analyzers/permissions.py — STORY-0092)

Every rule semantic comes from Anthropic's documentation, read 2026-10-25, and is
quoted in the finding text and in `docs/permission-rules.md`:

- **Claude Code permissions doc** (https://code.claude.com/docs/en/permissions) —
  PERM-001: "You can't match a tool's primary content field this way … Claude Code
  ignores it and emits a startup warning"; "When Claude Code loads a settings file, it
  skips any `mcp__` rule that has parentheses"; "If you write a path rule for `Write`,
  `NotebookEdit`, `Glob`, or legacy `MultiEdit`, Claude Code accepts the rule but never
  matches a read or edit against it"; "The `:*` form is only recognized at the end of a
  pattern"; "An unanchored allow glob such as `"*"`, `"B*"`, or `"mcp__*"` is skipped
  and doesn't auto-approve anything". PERM-002: "A pattern like `/Users/alice/file`
  isn't an absolute path. The single leading slash anchors at the settings source, not
  the filesystem root" and the "Where a pattern anchors" table. PERM-003: "The space
  before a trailing `*` is part of the rule … `Bash(ls*)` has no space, so it matches
  `lsof` too." PERM-004: "a deny or ask rule covers the invocation Claude usually
  produces and isn't a security boundary around the program", the `/usr/bin/curl`,
  `sh -c`, `/bin/rm`, `git -C . push` table, and "Your other rules and the permission
  mode decide the commands in the last column". PERM-005: the "Allow or deny every
  fetch" table. PERM-007 and the HARNESS-005 runner forms: the MCP section (`mcp__`
  rules, names with `__`, normalized names) and "Wrappers" ("Development environment
  runners such as `direnv exec`, `devbox run`, `mise exec`, `npx`, and `docker exec`
  are not in the list").
- **Claude Code sandboxing doc** (https://code.claude.com/docs/en/sandboxing) —
  PERM-006: "A bare `Bash` ask rule, or the equivalent `Bash(*)` form, is skipped for
  commands that run sandboxed … In plan mode, the rule isn't skipped"; PERM-005: the
  sandbox honours a bare `*` in a `WebFetch(domain:...)` rule.
- **Claude Code settings reference** (https://code.claude.com/docs/en/settings-reference)
  — defaults: `sandbox.enabled` false, `sandbox.autoAllowBashIfSandboxed` true; and
  `permissions.defaultMode`: "`auto` and `bypassPermissions` don't take effect from
  project or local settings … Before v2.1.257, `bypassPermissions` took effect from any
  file" (why PERM-004 counts a mode only in user settings).
- **Claude Code permission modes doc** (https://code.claude.com/docs/en/permission-modes)
  — "Tools matched by an explicit ask rule" are among the "Actions no mode
  auto-approves", which is why queue item Q-018 (ask rules under auto/bypass mode) was
  not built as a finding.
- **Claude Code MCP doc** (https://code.claude.com/docs/en/mcp) — tool names replace
  "any character outside `A-Z`, `a-z`, `0-9`, `_`, and `-`" with `_`; plugin servers are
  `mcp__plugin_<plugin-name>_<server-name>__<tool-name>`.
- **Claude Code CHANGELOG 2.1.299**
  (https://raw.githubusercontent.com/anthropics/claude-code/main/CHANGELOG.md) —
  "Changed MCP allow rules to reach only the server they name: `mcp__a` no longer allows
  a server named `a__b` or `a_`; write `mcp__<server>__*` with the server's whole
  normalized name" (PERM-007 matching; Q-019).
- **Why it matters** — UpGuard, "YOLO Mode: Hidden Risks in Claude Code Permissions"
  (https://www.upguard.com/blog/yolo-mode-hidden-risks-in-claude-code-permissions,
  2026-01-16): of 18,470 committed `.claude/settings.local.json` files, 1.1% carried
  any deny rule; NCC Group, "An Introduction to AI Coding Agent Security" v2.0
  (https://www.nccgroup.com/media/jtepwx1t/nccgroup_codingagentswhitepaper.pdf):
  permission-prompt bypass history through `find`, `sed`, `rg`, `echo`, `cd`. Research
  scan 2026-10-25 §A2 and ledger PAIN-008/PAIN-016 (Marcus).
- All seven checks and the HARNESS-005 additions are original implementations; no code
  or fixtures were copied. Anthropic's example settings files
  (github.com/anthropics/claude-code/tree/main/examples/settings) were used only to
  measure precision locally and are not committed.

## Claude Code mods (MOD-001..006, plugins/mods.py — STORY-0085)

- **Claude Code mods documentation** — code.claude.com/docs/en/plugins/mods/overview,
  /reference (files, every event and mods API method), /admin ("Review what a mod can
  do", the sec-default guard and its options), /create (static analysis rules that make
  a literal read sound). The MOD-* rules are that review checklist, applied offline.
- **Practitioner signal** — @ClaudeDevs launch post, 2026-10-01 (4.46M views); @zouyanjian,
  2026-10-05 ("Read it, pin it, watch anything that hooks permission events"); @LacorteMichele,
  2026-10-06; @alekdobrohotov and @deeponailabs, 2026-10-09. Brief:
  products/mcp-audit/discovery/briefs/2026-10-12-signal-sweep.md (Marcus).

## Claude Code plugins (PLUGIN-001/002, plugins/ — STORY-0080)

- **Plugin4Shell** — Or Nevo, Dor Granat, Niv Hoffman, AIR Security, 2026-09-17
  (https://www.air.security/blog-posts/plugin4shell). Agents checked out a
  marketplace-pinned commit without verifying `HEAD`; a branch named like the SHA, or a
  default branch named `FETCH_HEAD`, swapped the code. Patched in Claude Code 2.1.179.
  Background and remediation source for PLUGIN-001; PLUGIN-001 compares install records
  with the current pin and does not detect a swap recorded at the requested commit.
- **Claude Code plugin documentation** — code.claude.com/docs/en/plugins/loading
  (plugins root, `installed_plugins.json`, `known_marketplaces.json`, cache layout, "How
  Claude Code computes the version") and plugins/marketplace-reference (plugin source
  types and the `ref`/`sha` fields).
- **`installed_plugins.json` shape** — anthropics/claude-code issues #45997 and #17032,
  which quote the `{"version": 2, "plugins": {"<id>": [records]}}` structure.
- Original implementation; no code was copied.


## SAST: SSRF guards that only block IP literals (STORY-0081)

`semgrep-rules/python/injection/mcp-ssrf-ip-literal-guard.yml`
(`mcp-ssrf-ip-literal-only-guard`) and
`semgrep-rules/typescript/injection/mcp-ts-ssrf-ip-literal-guard.yml`
(`mcp-ts-ssrf-ip-literal-only-guard`).

- **Wazuh MCP server advisory GHSA-pw2j-pj4h-f5vg** (published 2026-09-03,
  https://github.com/INFOKOM-KI/Wazuh-MCP-Server/security/advisories/GHSA-pw2j-pj4h-f5vg).
  A tool advertised SSRF protection, but the check only blocked literal IP
  addresses and never resolved hostnames, so a name pointing at an internal
  address passed. Source for both rules' shape.
- **The Next Web, 2026-10-06**
  (https://thenextweb.com/news/mcp-flaw-ssrf-google-jpmorgan-dinum-protocol-pivoting).
  Coverage of the October 2026 MCP SSRF wave (Google MCP Toolbox, JPMorgan,
  DINUM, Wazuh) that pointed to the Wazuh advisory. Its note that Google's
  Toolbox fix added a DNS-rebinding guard is why the rules' remediation text
  says to connect to the checked address.
- **OWASP Server-Side Request Forgery Prevention Cheat Sheet** (already cited
  above): resolve, then validate every resolved address.
- Original implementation; no code was copied.

## Poisoning benchmark (scripts/bench_poisoning.py — STORY-0088)

Measures the existing POISON-* patterns; adds or changes none. Results:
`docs/poisoning.md`, `docs/research/poisoning-benchmark/results.json`.

- **MCPTox: A Benchmark for Tool Poisoning Attack on Real-World MCP Servers**
  (AAAI 2026, [arXiv 2508.14925](https://arxiv.org/html/2508.14925v1)). The recall
  corpus: 1,312 valid poisoned test cases over 45 real servers and 353 tools, three
  paradigms (P1 explicit trigger function hijacking, P2 implicit trigger function
  hijacking, P3 implicit trigger parameter tampering) and two keyword "enhanced
  settings". Data from the authors' anonymized repository
  (https://anonymous.4open.science/r/AAAI26-7C02), read at run time and never
  committed, because it states no licence; `results.json` records the files' SHA-256.
  The wrapper split follows the substring tests in the repository's own
  `analysis.ipynb`.
- **Machine Learning-Based Detection of MCP Attacks** (Mattsson, Nyberg, Borg,
  Britto, [arXiv 2604.10534](https://arxiv.org/html/2604.10534v1)). Cisco MCP
  Scanner YARA rules at 20.8% recall on MCPTox-derived descriptions; quoted for
  comparison only.
- **Rethinking MCP Security: A Large-Scale Study of Runtime MCP Servers and Security
  Scanner Reliability** ([arXiv 2607.11086](https://arxiv.org/html/2607.11086v1)).
  45.5% mean precision and 15.7% average pairwise agreement across eight scanners on
  37,288 MCPZoo servers; quoted for comparison only.
- **The 2026-10-22 top-100 npm scan** (`docs/research/2026-10-top100-npm/`). The
  precision corpus; its findings are labelled in
  `docs/research/poisoning-benchmark/top100-labels.json`.
- The MCPTox-shaped records in `tests/test_bench_poisoning.py` were written for the
  test; no dataset text was copied. Original implementation; no code was copied.
