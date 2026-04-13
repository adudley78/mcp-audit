# Known gaps and improvement areas

This document catalogs the known limitations of mcp-audit in its current prototype state. These are areas that need work before the tool is ready for production use by security practitioners. Contributions and feedback welcome.

## Detection quality

**False positive rate is unknown.** The poisoning analyzer has been tested against intentionally vulnerable fixtures and one real MCP server (the official filesystem server), which produced a false positive on "base64 encode" — a legitimate technical term in that server's tool description. The patterns have not been validated against a broad sample of real-world MCP server configurations. Before launch, the scanner should be tested against the 20-30 most popular MCP servers to establish a baseline false positive rate and tune patterns accordingly.

**No validation against real exploits.** The detection patterns are based on published security research (see PROVENANCE.md) but are regex approximations of documented attacks, not exact replicas. Nobody has verified that the patterns correspond to prompts that actually cause LLMs to follow injected instructions. A validation suite should reconstruct known attack PoCs (Invariant Labs SSH exfiltration, CrowdStrike `add_numbers`, fake Postmark server) as test fixtures and confirm detection.

**Pattern coverage is thin.** The poisoning analyzer has 14 patterns. The credential analyzer has 9. Production secret scanners like truffleHog and detect-secrets use 700+ credential patterns. The poisoning patterns cover the most-cited attack techniques but will miss novel or obfuscated injection methods. Pattern count should grow based on practitioner feedback and new published research.

## Severity calibration

**Severity assignments are intuition-based.** There is no formal framework mapping findings to severity levels. Levenshtein distance 1 is CRITICAL and distance 2 is HIGH because those felt right, not because of a quantified risk model. Before production use, severity should be mapped to an established framework — CVSS base scores, OWASP Agentic Top 10 risk categories, or a documented internal rubric with justification for each level.

## Supply chain coverage

**Only npm packages are checked for typosquatting.** The MCP ecosystem includes Python servers (installed via uvx/pip), Docker containers, Go binaries, and other package managers. The current analyzer only checks npm package names against 43 known-legitimate servers. PyPI typosquatting, Docker image verification, and other ecosystems are not covered.

**No registry metadata enrichment.** The scanner does not query npm or PyPI registries for package metadata (publish date, download count, author history, version count). A package published yesterday with 3 downloads is riskier than one published two years ago with 100,000 weekly downloads, but the scanner can't distinguish them without network calls.

## Live connection (`--connect`)

**Tested against one server.** The `--connect` feature has been tested against the official `@modelcontextprotocol/server-filesystem` server only. Behavior against the broader ecosystem of MCP servers (different transports, authentication requirements, non-standard handshakes) is unknown.

**Server stderr output leaks to terminal.** When `--connect` launches a stdio server, the server's stderr output (warnings, logs, startup messages) appears in the user's terminal interleaved with mcp-audit output. This should be captured and suppressed or redirected.

**No authentication support.** Some MCP servers (particularly SSE/HTTP servers) require authentication tokens or headers. The current `--connect` implementation doesn't support passing authentication credentials to remote servers.

## Toxic flow analysis

**Capability tagging is heuristic.** Server capabilities are inferred from package names and keyword matching, not from actual permission analysis. A server tagged as `FILE_READ` might not actually read files, and a server with no matching keywords might have dangerous capabilities that aren't detected. Live enumeration via `--connect` improves this by analyzing actual tool names, but coverage depends on the keyword lists being comprehensive.

**No weighting or scoring.** All toxic pairs of the same severity are treated equally. In practice, a filesystem + fetch combination on a developer laptop is less risky than a database + shell-exec combination on a production server. Context-aware risk scoring is not implemented.

## Output formats

**Nucleus FlexConnect not validated.** The FlexConnect output formatter was built from publicly available documentation snippets, not from the official Nucleus API specification (Swagger docs). The JSON structure has not been tested against a real Nucleus instance. Field mappings may be incorrect or incomplete. Validation against the actual ingestion API is required before claiming Nucleus integration.

**SARIF not tested with GitHub.** The SARIF output follows the 2.1.0 specification but has not been uploaded to GitHub's code scanning API to verify it renders correctly in the Security tab and pull request annotations.

## Platform coverage

**Windows not tested.** Config discovery includes Windows paths but the tool has only been tested on macOS. Path handling, file encoding, and process spawning may behave differently on Windows.

**Linux not tested.** Same as Windows — paths are defined but not validated on actual Linux systems.

## Internal security findings

Self-audit conducted 2026-04-12. Criticals and highs were patched in commit `18bbf66`. The medium and low findings below are tracked for future hardening — normal for a prototype.

### Medium

**V-07: Poisoning detection bypassed by Unicode homoglyphs.** All poisoning regex patterns match ASCII only. An attacker can use visually identical Unicode characters (Cyrillic 'а' for Latin 'a', etc.) in tool descriptions to bypass detection while the LLM still interprets the instruction. Fix: normalize text to ASCII via `unicodedata.normalize('NFKD', ...)` before pattern matching. Add a dedicated homoglyph-presence pattern. CWE-116.

**V-08: Poisoning detection bypassed by nesting depth > 10.** `_extract_text_fields` in `poisoning.py` stops recursing at depth 10. A malicious config can nest poisoned text at depth 11+ to evade extraction entirely. Fix: raise the limit significantly or remove it with a stack-depth guard.

**V-09: Transport analyzer misses `0.0.0.0` as insecure binding.** `0.0.0.0` binds to all interfaces — worse than a remote endpoint — but is not flagged. IPv6 equivalents `[::]` and `[0:0:0:0:0:0:0:0]` are also unchecked. Fix: add these to the insecure-binding check, possibly as HIGH.

**V-10: Privilege escalation check is trivially bypassable.** Only catches `sudo`, `doas`, and `/usr/sbin` prefix. Misses `pkexec`, `su`, `run0`, absolute paths to sudo (`/usr/bin/sudo`), and `sudo` appearing in args rather than command. Fix: expand the set and check `args[0]`.

**V-11: Supply chain analyzer only covers npm; misses `yarn dlx`.** The `_NPX_LIKE` set is `{"npx", "bunx", "pnpx"}` — misses `yarn dlx`. No detection for Python-based MCP servers launched via `uvx` or `pipx`. Fix: add yarn support and consider a parallel PyPI known-packages list.

**V-12: Resolved.** `httpx` moved from `dependencies` to the `mcp` optional group (`pip install 'mcp-audit[mcp]'`). It is not installed in the default distribution and carries no transitive attack surface for users who don't need live server connections.

### Low

**V-13: Version string hardcoded in 4 locations.** `"0.1.0"` appears in `pyproject.toml`, `models.py`, `cli.py`, `terminal.py`, and `sarif.py`. These will drift. Fix: use `importlib.metadata.version("mcp-audit")` or a single `__version__` constant.

**V-14: License metadata contradiction.** `pyproject.toml` declares `LicenseRef-Proprietary` but the classifiers list `Apache Software License`. PyPI will reject or misclassify. Fix: align before publishing.

**V-15: Placeholder URLs in SARIF and pyproject.toml.** `yourusername` placeholder URLs appear in `sarif.py` and `pyproject.toml`. If SARIF is uploaded to GitHub, broken links appear in the Security tab. Fix: replace before release.

**V-16: `_home()` inconsistency in discovery.py.** `_home()` wraps `Path.home()` for test mocking, but `_get_client_specs()` calls `Path.home()` directly on one line, defeating the indirection. Fix: use `_home()` consistently.

**V-17: Credential regex overlap and gaps.** The OpenAI pattern `sk-[A-Za-z0-9]{20,}` also matches Anthropic keys (`sk-ant-*`), causing double detection. No coverage for Google service account JSON, Azure SAS tokens, DigitalOcean tokens, Vercel tokens, or PEM-encoded keys. Generic secret pattern requires quotes around values, missing unquoted secrets. Fix: refine patterns and expand coverage incrementally.

## Binary distribution

**Binary distribution is architecture-specific.** The PyInstaller build pipeline produces a single-file binary for the platform it is built on. The current build produces `mcp-audit-darwin-x86_64` only. Apple Silicon (arm64) Macs require Rosetta 2 or a native arm64 build; Linux and Windows users need their own platform builds. GitHub Actions matrix builds across `[macos-13 (x86_64), macos-14 (arm64), ubuntu-latest, windows-latest]` are needed to produce the full platform matrix automatically on each release.

**Dashboard browser compatibility untested.** The D3 v7 force-directed graph dashboard has been developed and tested in Chrome and Safari on macOS only. Behavior in Firefox, Edge, mobile browsers, and WebView-based environments (Electron, VS Code webview) is unknown. CSS custom properties and D3's SVG rendering should be broadly compatible, but this has not been verified.

## Missing capabilities (not started)

- **GitHub Actions CI workflow** — no automated testing on push/PR; no multi-arch binary release matrix
- **pip packaging and TestPyPI dry run** — installable from source only (PyInstaller binary available as alternative)
- **Documentation beyond README** — no usage guide, rule-writing guide, or Nucleus integration guide
- **Telemetry or usage analytics** — no way to measure adoption (intentional for privacy-first positioning, but limits success measurement)
- **Auto-update of known server lists** — the known npm packages YAML and known server capability mappings are static and require manual updates as the MCP ecosystem grows
