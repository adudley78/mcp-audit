# Severity Framework

This document defines how mcp-audit assigns severity levels to findings and maps
them to established industry frameworks. Prior to this document, severity
assignments were intuition-based (see GAPS.md). This framework provides
reproducible rationale for each level.

## Severity levels

mcp-audit uses four severity levels, aligned with CVSS base score bands and
OWASP Agentic Top 10 risk categories:

| Level    | CVSS Range | Decision criteria |
|----------|------------|-------------------|
| CRITICAL | 9.0–10.0   | Active exfiltration of credentials or private keys; attack confirmed to succeed against real LLM agents in published research; immediate remediation required |
| HIGH     | 7.0–8.9    | Instruction injection or behavioral override confirmed in research; data exfiltration channel present; no immediate credential exposure but agent is compromised |
| MEDIUM   | 4.0–6.9    | Strong indicator of malicious intent; unconfirmed or context-dependent risk; meaningful reduction in security posture without confirmed exploit path |
| LOW      | 0.1–3.9    | Hygiene issue or weak signal; legitimate use cases exist; informational for practitioners |
| INFO     | 0.0        | Observation only; no security impact on its own; surfaces context for other findings |

---

## Finding ID → severity mapping

Each finding is mapped to **both** the [OWASP Agentic Top 10](https://genai.owasp.org/)
(ASI01–ASI10, a broad agentic AI framework) and the
[OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/) (MCP01–MCP10,
MCP-specific). See the reference tables at the bottom of this document.

### Poisoning analyzer (`analyzers/poisoning.py`)

| Finding ID  | Severity | OWASP Agentic Top 10 | OWASP MCP Top 10 | Rationale |
|-------------|----------|----------------------|------------------|-----------|
| POISON-001  | CRITICAL | ASI01, ASI06 | MCP03, MCP01 | SSH key exfiltration. CrowdStrike confirmed this exact pattern succeeds against production LLM agents. Direct credential theft with no ambiguity. CVSS: 9.3 |
| POISON-002  | CRITICAL | ASI01, ASI06 | MCP03, MCP01 | Cloud credential file exfiltration (.aws/credentials, .kube/config, .gcloud). Same threat model as POISON-001 — confirmed attack vector. CVSS: 9.3 |
| POISON-003  | CRITICAL | ASI01, ASI06 | MCP03, MCP01 | .env file exfiltration. High-value target containing secrets for all services. CVSS: 9.3 |
| POISON-010  | HIGH     | ASI01 | MCP03, MCP06 | XML instruction injection (`<IMPORTANT>`, `<OVERRIDE>`, etc.). Confirmed injection vector in CrowdStrike and CyberArk research; allows arbitrary agent goal replacement. CVSS: 8.1 |
| POISON-011  | HIGH     | ASI01 | MCP03, MCP06 | LLM prompt format injection markers (`[INST]`, `<<SYS>>`, etc.). Targets specific model instruction formats; high success rate. CVSS: 7.5 |
| POISON-012  | HIGH     | ASI01, ASI08 | MCP03, MCP06 | Behavioral override and stealth instructions ("ignore previous instructions", "do not mention"). MINJA paper documented >95% success rate. CVSS: 8.1 |
| POISON-020  | HIGH     | ASI06 | MCP03, MCP10 | Data exfiltration via encoding or side channel ("encode in base64", "send to endpoint"). Establishes a covert channel — confirmed exfiltration technique. CVSS: 7.5 |
| POISON-021  | HIGH     | ASI06 | MCP03, MCP10 | Hidden parameter exfiltration. Channels data through legitimate-looking request parameters. CVSS: 7.5 |
| POISON-030  | MEDIUM   | ASI03, ASI07 | MCP03, MCP06 | Cross-tool manipulation ("before using this tool", "instead use"). Enables tool shadowing and confused deputy attacks. CVSS: 5.3 |
| POISON-040  | MEDIUM   | ASI08 | MCP03 | Zero-width Unicode characters. Stealth technique used to hide instructions from users while preserving LLM readability. CVSS: 4.6 |
| POISON-050  | LOW      | ASI08 | MCP03 | Excessive description length (≥2000 chars). Oversized descriptions can pad context windows and conceal instructions. CVSS: 2.6 |
| POISON-060  | MEDIUM   | ASI08 | MCP03 | Unicode homoglyph characters (Cyrillic, Greek, fullwidth ASCII). Used to bypass ASCII-only regex detection while the LLM still interprets the instruction. CWE-116. CVSS: 4.6 |

### Credentials analyzer (`analyzers/credentials.py`)

| Finding ID | Severity | OWASP Agentic Top 10 | OWASP MCP Top 10 | Rationale |
|------------|----------|----------------------|------------------|-----------|
| CRED-001   | HIGH     | ASI06 | MCP01 | API key or secret in environment variable. Key is stored in plaintext and accessible to any process reading the config file. Credential types detected: AWS access/secret keys, GitHub tokens (classic `ghp_/gho_/ghu_/ghs_/ghr_` and fine-grained `github_pat_`), OpenAI keys (`sk-`), Anthropic keys (`sk-ant-`), Stripe keys, Slack tokens, GCP service-account JSON keys (`"private_key":"-----BEGIN`), Azure SAS tokens (`sv=…&sig=`), DigitalOcean tokens (`dop_v1_`), Vercel tokens (`vercel_`), PEM private key blocks (RSA/EC/DSA/OpenSSH), HashiCorp Vault service tokens (`hvs.`) and batch tokens (`hvb.`), generic secrets, and database URLs with inline credentials. CWE-798. CVSS: 7.5 |
| CRED-002   | HIGH     | ASI06 | MCP01 | API key or secret in command arguments. Command lines are visible in process listings (`ps aux`) — wider exposure than env vars. Same credential patterns as CRED-001. CWE-798. CVSS: 7.5 |

### Transport analyzer (`analyzers/transport.py`)

| Finding ID    | Severity | OWASP Agentic Top 10 | OWASP MCP Top 10 | Rationale |
|---------------|----------|----------------------|------------------|-----------|
| TRANSPORT-001 | MEDIUM   | ASI05 | MCP07 | Unencrypted remote endpoint (HTTP, not HTTPS). MCP protocol data is transmitted in plaintext; susceptible to MITM. CVSS: 7.4 |
| TRANSPORT-002 | HIGH     | ASI09 | MCP02, MCP05 | Elevated privilege execution (sudo, doas, pkexec, etc.). MCP servers should not require root. CVSS: 7.8 |
| TRANSPORT-003 | MEDIUM / LOW / suppressed | ASI04 | MCP04 | Runtime package fetching (npx, uvx, bunx, pipx, yarn dlx). Tiered by registry membership. |
| TRANSPORT-004 | HIGH     | ASI05 | MCP07 | Wildcard interface binding (0.0.0.0 / [::]). Exposes server on all interfaces. CVSS: 7.5. CWE-1327. **CVE-2026-33032** (MCPwn) — network-exposure precondition. |

### Supply chain analyzer (`analyzers/supply_chain.py`)

| Finding ID | Severity | OWASP Agentic Top 10 | OWASP MCP Top 10 | Rationale |
|------------|----------|----------------------|------------------|-----------|
| SC-001     | CRITICAL | ASI02, ASI10 | MCP04 | Levenshtein distance 1 from a known-good package. Single-character substitutions are almost exclusively malicious per Vu et al. (NDSS 2021). CVSS: 9.1 |
| SC-002     | HIGH     | ASI10 | MCP04 | Levenshtein distance 2. Still very likely malicious; two-character substitutions are a common squatting technique. CVSS: 7.5 |
| SC-003     | MEDIUM   | ASI10 | MCP04 | Levenshtein distance 3. Possible innocent mismatch; warrants review. CVSS: 4.3 |
| SC-004     | HIGH     | ASI10 | MCP04 | Exact registry match with `known_vulnerabilities` entries. Package is a known-legitimate server with a public CVE advisory. Operator must verify installed version is in the affected range. No network required (offline bundled registry). CWE-1104. |

### Rug-pull analyzer (`analyzers/rug_pull.py`)

| Finding ID  | Severity | OWASP Agentic Top 10 | OWASP MCP Top 10 | Rationale |
|-------------|----------|----------------------|------------------|-----------|
| RUGPULL-000 | INFO     | — | — | First scan — baseline recorded. No prior state; no security violation. |
| RUGPULL-001 | HIGH     | ASI10, ASI01 | MCP03, MCP04 | Configuration changed since last scan. Server was previously trusted; silent modification is a strong indicator of a rug-pull. CVSS: 7.5 |
| RUGPULL-002 | INFO     | ASI10 | MCP09 | New server detected since last scan. Adds an unrecognised server to the install surface. |
| RUGPULL-003 | INFO     | — | — | Previously tracked server no longer configured. Removal is typically benign; surfaced for situational awareness. |

### Toxic flow analyzer (`analyzers/toxic_flow.py`)

Toxic flow findings use a pair-based model: severity reflects the risk of the
capability combination, not any individual server.

| Finding ID | Severity | OWASP Agentic Top 10 | OWASP MCP Top 10 | Rationale |
|------------|----------|----------------------|------------------|-----------|
| TOXIC-001  | HIGH     | ASI04, ASI03 | MCP05, MCP10 | File read + network exfiltration. Prompt injection can chain these to exfiltrate sensitive files. |
| TOXIC-002  | HIGH     | ASI04, ASI06 | MCP05, MCP10 | File read + email exfiltration. Sensitive files could be emailed out. |
| TOXIC-003  | CRITICAL | ASI06 | MCP01, MCP10 | Secrets store + network access. Credentials can be exfiltrated directly. |
| TOXIC-004  | HIGH     | ASI04 | MCP10 | File read + shell execution. Malicious content read from a file could be executed. |
| TOXIC-005  | HIGH     | ASI03 | MCP05, MCP10 | Database + network. Database contents could be exfiltrated. |
| TOXIC-006  | CRITICAL | ASI04 | MCP05, MCP10 | Shell execution + network. Arbitrary command execution with exfiltration capability. |
| TOXIC-007  | MEDIUM   | — | MCP10 | Git access + network. Source code or commit history could be exfiltrated via outbound requests. |

### Attestation (`attestation/`)

**Layer 1 — hash verification (`--verify-hashes`)**

| Finding ID  | Severity | OWASP MCP Top 10 | Rationale |
|-------------|----------|------------------|-----------|
| ATT-{hash}  | CRITICAL | MCP04 | Hash mismatch — downloaded tarball does not match pinned SHA-256. Strong indicator of supply chain tampering. Dynamic ID: `ATT-{8-char hex}` derived from package:version:kind. |
| ATT-{hash}  | INFO     | — | Package could not be verified (version unextractable or no hash pin). Informational; surfaces candidates for manual pinning. |

**Layer 2 — Sigstore provenance verification (`--verify-signatures`)**

| Finding ID   | Severity | OWASP MCP Top 10 | Rationale |
|--------------|----------|------------------|-----------|
| ATTEST-010   | INFO     | — | Valid Sigstore attestation; OIDC subject matches the expected repository. Positive signal — confirms provenance. |
| ATTEST-011   | HIGH     | MCP04 | Valid signature but OIDC subject does not match expected repo. Could indicate a supply chain attack. CWE-494. CVSS: 8.1 |
| ATTEST-012   | CRITICAL | MCP04 | Sigstore signature cryptographically invalid (tampered or forged attestation). CWE-494. CVSS: 9.1 |
| ATTEST-013   | MEDIUM   | MCP04 | Attestation absent for a package that is known to publish provenance. May indicate a compromised publish pipeline. CWE-494. CVSS: 5.3 |
| ATTEST-014   | INFO / MEDIUM | MCP04 | No attestation found. INFO by default; raised to MEDIUM with `--strict-signatures`. |
| ATTEST-015   | INFO     | — | Network or API error prevented verification. Retry when network is available. |

### Governance (`governance/`)

Governance findings use GOV- prefixes and derive severity from the policy
configuration — a policy violation is always at least MEDIUM, and can be
escalated to HIGH by the policy author. OWASP MCP Top 10 codes can be set
in the policy YAML via the `owasp_mcp_top_10` field and are propagated to
all findings emitted by that policy.

### SAST auth analyzer (`semgrep-rules/*/auth/`)

These rules detect authentication bypass and credential-logging patterns in MCP
server source code. They target two CVE-anchored bug classes:
- **CVE-2026-33032 (MCPwn)**: endpoint-parity / asymmetric-auth — a second route
  bypasses auth by pointing at the same handler without a middleware guard; empty
  allowlist treated as "allow all".
- **CVE-2026-41495 (n8n-MCP)**: auth-header / token-in-logs — bearer tokens and
  API keys written to log files or stdout before or without the auth check running.

| Rule ID                              | Severity | CWE      | OWASP MCP Top 10 | Rationale |
|--------------------------------------|----------|----------|------------------|-----------|
| mcp-route-missing-auth-middleware    | HIGH     | CWE-306  | MCP07            | MCPwn (CVE-2026-33032) pattern: parallel route bypasses auth middleware entirely. CVSS: 8.6 |
| mcp-empty-allowlist-allow-all        | MEDIUM   | CWE-183  | MCP07            | Empty-allowlist bug: treat missing config as "allow everything." Half of CVE-2026-33032. CVSS: 7.5 |
| mcp-wellknown-route-no-auth          | MEDIUM   | CWE-306  | MCP07            | Discovery endpoint without auth — capability information leakage risk. CVSS: 5.3 |
| mcp-authorization-header-logged      | MEDIUM   | CWE-532  | MCP01            | Bearer token logged before auth check (n8n-MCP class, CVE-2026-41495). CVSS: 6.5 |
| mcp-api-key-header-logged            | MEDIUM   | CWE-532  | MCP01            | API key variable passed to log call. CVSS: 6.5 |
| mcp-full-request-body-logged-on-fail | LOW      | CWE-532  | MCP01            | Request body logged on auth failure — tokens in error logs. CVSS: 3.1 |
| mcp-ts-route-missing-auth-middleware | HIGH     | CWE-306  | MCP07            | TypeScript equivalent of MCPwn route pattern (Express/Fastify/Hono). CVSS: 8.6 |
| mcp-ts-auth-header-logged            | MEDIUM   | CWE-532  | MCP01            | TypeScript equivalent of n8n-MCP logging pattern (console.log/winston/pino). CVSS: 6.5 |

Severity mapping to the mcp-audit framework:
- SAST `ERROR` → mcp-audit **HIGH** (confirmed auth-bypass pattern; direct exploit path)
- SAST `WARNING` → mcp-audit **MEDIUM** (strong indicator; context-dependent risk)
- SAST `INFO` → mcp-audit **LOW** (hygiene; requires specific auth-failure retry path to exploit)

### Config hygiene analyzer (`analyzers/config_hygiene.py`)

This analyzer grades each discovered MCP config **file** for filesystem security
posture — not its parsed contents (credentials.py handles that layer).

**Anchor incident:** On 2026-04-22, supply-chain malware embedded in the Bitwarden
npm package explicitly enumerated `~/.claude.json`, `~/.claude/mcp.json`, and
`~/.kiro/settings/mcp.json` as its primary credential-cache targets. These files
are now confirmed targets in the wild. CFHYG-001 and CFHYG-002 directly address
the two exploitation pre-conditions that malware relied on.

| Finding ID  | Severity | OWASP Agentic Top 10 | OWASP MCP Top 10 | Rationale |
|-------------|----------|----------------------|------------------|-----------|
| CFHYG-001   | HIGH     | ASI06 | MCP01 | Config file is world-readable (POSIX `o+r`). Any process on the machine — including supply-chain malware — can harvest credentials embedded in the file. Bitwarden incident (2026-04-22) confirmed this attack path. CWE-732. CVSS: 7.5 |
| CFHYG-002   | HIGH     | ASI06, ASI10 | MCP01, MCP09 | Config file resides in a world-writable ancestor directory. Any process can atomically replace the file — a filesystem-level rug-pull. `/tmp` is the canonical case. Bitwarden incident (2026-04-22) exploited this pre-condition to inject malicious server definitions. CWE-732. CVSS: 7.5 |
| CFHYG-003   | HIGH     | ASI06 | MCP01 | Config file stores a plaintext secret inline. The file itself becomes a high-value harvesting target. Complements CRED-001/002 with a file-level signal and explicit malware-targeting context. CWE-312. CVSS: 7.5 |
| CFHYG-004   | INFO     | — | MCP01 | Config uses env-var references for all credentials (e.g., `${VAR}`, `$VAR`, `%(VAR)s`). Positive signal — reinforces correct practice. No security impact. |
| CFHYG-005   | MEDIUM   | ASI06 | MCP01, MCP07 | Claude Code hooks section detected in `.claude.json`. Hooks execute as shell commands — a write-access threat actor can inject arbitrary commands. CVE-2025-59536. CWE-78. CVSS: 6.5 |
| CFHYG-006   | MEDIUM   | ASI06 | MCP01, MCP08 | `ANTHROPIC_BASE_URL` overrides the Anthropic API endpoint. All API traffic (including the API key) is routed to the configured domain. CVE-2026-21852. CWE-441. CVSS: 7.5 |

**Windows note:** CFHYG-001 and CFHYG-002 are skipped on Windows because POSIX
`st_mode` bits do not map to Windows ACL semantics. Windows ACL checking
(`pywin32` / `icacls`) is planned but not yet implemented.

---

### Auth analyzer (`analyzers/auth.py`)

The auth analyzer checks remote MCP server configurations for the presence of
authentication material (AUTH-001) and checks OAuth-configured servers for
audience/resource binding per RFC 8707 (AUTH-002).

**Research basis:**
- **arXiv 2605.22333** — Measurement study that scanned 7,973 live remote MCP
  servers and found 40.55% require no authentication. Also tested 119
  OAuth-enabled servers and found every one had at least one flaw (325 total;
  dynamic-client-registration flaws in 96.6%).
- **Censys** — Internet-scanning report counting 12,520 internet-exposed MCP
  services, the majority unauthenticated.
- **RFC 8707** — Resource Indicators for OAuth 2.0. Absence of a concrete
  audience/resource binding creates token cross-resource replay risk.

| Finding ID | Severity              | OWASP Agentic Top 10 | OWASP MCP Top 10 | Rationale |
|------------|----------------------|----------------------|------------------|-----------|
| AUTH-001   | HIGH (public host)   | ASI05 | MCP06 | Remote server with no auth material. Public-routable host: anyone on the internet can call every tool. 40.55% of measured live remote MCP servers unauthenticated (arXiv 2605.22333). CWE-306. CVSS: 8.2 |
| AUTH-001   | MEDIUM (private host) | ASI05 | MCP06 | Same check for RFC 1918 / `*.local` hosts — reachable within the network segment. CWE-306. CVSS: 5.3 |
| AUTH-002   | MEDIUM               | ASI05 | MCP06 | OAuth configured but audience/resource binding absent or wildcard. RFC 8707 violation; token cross-resource replay risk. CWE-346. CVSS: 5.3 |

**Coverage limits (AUTH-002):**
OAuth config shapes vary widely across MCP clients. The analyzer covers:
`oauth`/`oauth2` dict blocks, `auth.type: oauth2` nested blocks, and
flat top-level `client_id` + `authorization_endpoint` co-occurrence. Formats
not matching these patterns will not fire (prefer false negatives over noise).
See GAPS.md — *AUTH-002 coverage limits*.

**Suppression rules for AUTH-001** (any one suppresses):
- `Authorization`, `x-api-key`, `api-key`, `x-auth-token`, `x-access-token`,
  `api_key`, or `token` header in `server.headers` (case-insensitive).
- `token`, `apiKey`, `api_key`, `auth`, `bearer`, `authorization`,
  `access_token`, or `secret` field at the top level of the raw server entry.
- Any OAuth-related field (`oauth`, `oauth2`, `authorization_endpoint`,
  `client_id`, `token_endpoint`).
- URL userinfo component (`https://user:pass@host` or `https://token@host`).
- `stdio` transport — local trust boundary, never fires.

### Trust analyzer (`cli/scan.py::_apply_project_scan`, finding ID `TRUST-001`)

TRUST-001 fires once per MCP server found in a **project-level** config file
(`.mcp.json`, `.cursor/mcp.json`, `.claude/settings.json`,
`.claude/settings.local.json`, `.cursor/settings.json`, `.vscode/mcp.json`)
discovered by `mcp-audit scan --project <dir>`.  The finding fires on
**origin** (the file's location in the repo), not on the server's content.
Content-based analysis (credentials, poisoning, transport, auth) runs
separately via the full analyzer pipeline.

| Finding ID | Severity | OWASP Agentic Top 10 | OWASP MCP Top 10 | Rationale |
|------------|----------|----------------------|------------------|-----------|
| TRUST-001  | HIGH     | ASI07 | MCP09 | MCP server defined in project-level config. Auto-spawns with developer's full OS privileges on "Trust this folder". Supply-chain attacker or malicious contributor can silently backdoor all developers who trust the repo. Adversa TrustFall (May 2026); CVE-2026-30615 config-tamper channel. CWE-829. CVSS: 7.8 |

**Supported project-level config paths** (discovered by `discover_project_configs()`):

| Path | Client | Root key |
|------|--------|----------|
| `.mcp.json` | Claude Code | `mcpServers` |
| `.claude/settings.json` | Claude Code | `mcpServers` |
| `.claude/settings.local.json` | Claude Code | `mcpServers` |
| `.cursor/mcp.json` | Cursor | `mcpServers` |
| `.cursor/settings.json` | Cursor | `mcpServers` |
| `.vscode/mcp.json` | VS Code / GitHub Copilot | `servers` |

Windsurf has no project-level MCP config (global only). Zed uses a different
schema (`context_servers`). See GAPS.md — *Project scan coverage limits*.

---

### Collision analyzer (`analyzers/collision.py`, finding ID `COLLIDE-001`)

`COLLIDE-001` fires when live `tools/list` enumeration (via `--connect`)
reveals that two or more **distinct** MCP servers advertise the same tool name.
The finding does not fire in static-only scans — MCP config files do not
declare tool names.

| Finding ID   | Severity | OWASP MCP Top 10 | Rationale |
|--------------|----------|------------------|-----------|
| COLLIDE-001  | MEDIUM   | MCP01 + MCP09 | Two or more distinct servers expose the same tool name. Agent tie-break is undocumented/order-dependent; attacker can register a colliding name to intercept calls. NSA CSI item 5. CWE-694. |
| COLLIDE-001  | HIGH     | MCP01 + MCP09 | Same collision, AND one claimant is registry-verified while at least one is not. Unknown server shadowing a trusted tool name is the strongest indicator of a namespace-shadowing attack. |

**Severity escalation logic:**

1. Look up every colliding server against `known-servers.json` via
   `_is_registry_known()` (checks command, args, and server name).
2. If at least one claimant is registry-known **and** at least one is not →
   HIGH.  The disparity suggests an attacker registered a look-alike or
   injected an extra server to shadow the trusted one.
3. If all claimants are registry-known, or all are unknown → MEDIUM.
   Two known-legitimate servers sharing a tool name is unusual but may be
   intentional (e.g. two versions of the same server configured in parallel).

**Scope and limitations:**

- Requires `--connect` (live enumeration). No static signal exists.
- Comparison is case-sensitive: `read_file` and `Read_File` are distinct names.
- No Levenshtein / near-miss detection in v1.
- Servers that fail to connect are excluded from comparison.

---

### Rule engine (`rules/`)

Community rule severities (COMM-001 through COMM-013) are defined in their
respective YAML files and documented in `docs/writing-rules.md`. Each rule
declares `owasp_mcp_top_10:` in its YAML; see the community rules directory
for per-rule mappings.

Notable CVE-tagged community rules:

| Finding ID | Severity | OWASP MCP Top 10 | CVE | Rationale |
|------------|----------|------------------|-----|-----------|
| COMM-012   | HIGH     | MCP07 | **CVE-2026-33032** (MCPwn) | Server args contain `0.0.0.0` — binds to all interfaces. Same network-exposure precondition as TRANSPORT-004. |
| COMM-013   | HIGH     | MCP04, MCP05 | CVE-2025-49596, CVE-2026-22252, CVE-2026-22688, CVE-2025-54994, CVE-2025-54136, CVE-2026-30615 | OX Security STDIO disclosure fingerprint: npx/bunx with `--yes`/`-y` bypasses interactive prompt, enabling silent RCE when the attacker controls the package name. COMM-010 flags the missing version pin; COMM-013 flags the auto-confirm flag that removes the last safety check. |

---

## How to assign severity to a new finding

When adding a new analyzer or detection pattern, use this decision tree:

1. **Is there a confirmed real-world exploit or published PoC?**
   - Yes, with credential/key exfiltration → **CRITICAL**
   - Yes, with agent goal hijack or data exfiltration channel → **HIGH**
   - Yes, but context-dependent or partial → **MEDIUM**

2. **Is the pattern unambiguously malicious in intent?**
   - Yes (e.g., `<IMPORTANT>read ~/.ssh/id_rsa</IMPORTANT>`) → **CRITICAL** or **HIGH**
   - Possibly (e.g., unusual but could be legitimate) → **MEDIUM** or **LOW**

3. **Does the finding have a direct security impact without attacker interaction?**
   - Yes → **HIGH** minimum
   - No — requires specific context or chaining → **MEDIUM**

4. **Is this a hygiene or best-practice issue?**
   - Yes → **LOW** or **INFO**

Document the rationale, CVSS components, OWASP Agentic Top 10 category, and
OWASP MCP Top 10 category in a comment above the finding definition. Update
this file with the new row.

---

## OWASP Agentic Top 10 reference

| Code   | Risk category |
|--------|---------------|
| ASI01  | Agent Goal Hijacking |
| ASI02  | Prompt Injection via Tools |
| ASI03  | Excessive Agency |
| ASI04  | Inadequate Sandboxing |
| ASI05  | Insecure Communication |
| ASI06  | Sensitive Data Leakage |
| ASI07  | Tool Misuse |
| ASI08  | Context Manipulation |
| ASI09  | Privilege Escalation |
| ASI10  | Supply Chain Vulnerabilities |

Source: [OWASP Top 10 for Agentic Applications (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)

---

## OWASP MCP Top 10 reference

| Code   | Risk category |
|--------|---------------|
| MCP01  | Token Mismanagement and Secret Exposure |
| MCP02  | Privilege Escalation via Scope Creep |
| MCP03  | Tool Poisoning |
| MCP04  | Software Supply Chain Attacks |
| MCP05  | Command Injection and Execution |
| MCP06  | Intent Flow Subversion |
| MCP07  | Insufficient Authentication and Authorization |
| MCP08  | Lack of Audit and Telemetry |
| MCP09  | Shadow MCP Servers |
| MCP10  | Context Injection and Over-sharing |

Source: [OWASP MCP Top 10 (2025 beta)](https://owasp.org/www-project-mcp-top-10/)

Note: this framework is in beta as of April 2026; category rankings and
descriptions may shift. mcp-audit follows the project page as authoritative.
See `docs/owasp-mcp-top-10.md` for how mcp-audit exposes this mapping in
terminal output, JSON, and SARIF.

A machine-readable version of the complete finding-ID → OWASP MCP Top 10 mapping
is published at [`docs/owasp-mapping.json`](owasp-mapping.json). Every finding ID
(static and dynamic-pattern) is documented there. Use
`python scripts/validate_owasp_mapping.py` to verify completeness; CI runs this
check automatically on the ubuntu/py3.12 leg.

## Shadow MCP Risk Levels (`mcp-audit shadow`)

The `mcp-audit shadow` command uses the same severity rubric as the scan
pipeline but expresses it through a `RiskLevel` enum that adds an `UNKNOWN`
state for servers whose capability data is unavailable.

| RiskLevel | Maps to | When assigned |
|-----------|---------|---------------|
| CRITICAL  | Severity.CRITICAL | Single server holds both SHELL_EXEC + NETWORK_OUT, or SECRETS + NETWORK_OUT |
| HIGH      | Severity.HIGH | Single server holds DATABASE + NETWORK_OUT, FILE_READ + NETWORK_OUT, FILE_READ + EMAIL, or FILE_READ + SHELL_EXEC |
| MEDIUM    | Severity.MEDIUM | Single server holds GIT + NETWORK_OUT |
| LOW       | Severity.LOW | Capabilities detected but no toxic pair fires |
| INFO      | Severity.INFO | Registry-verified server with an explicitly empty capability set |
| UNKNOWN   | (no Severity analogue) | Registry entry exists with `capabilities: null`, or no capability data at all |

All shadow server records carry `owasp_mcp_top_10: ["MCP09"]`.
See `docs/shadow-mcp.md` for the full `shadow` command documentation.
