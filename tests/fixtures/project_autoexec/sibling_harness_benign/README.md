# Fixture: `sibling_harness_benign/`

Synthetic negative control for `sibling_harness/`: ordinary Gemini CLI,
Codex and Claude Code project settings that a real repository might commit.
Gemini preferences with no hooks (and the hook switch off), Codex with
`approval_policy = "on-request"` and the `workspace-write` sandbox, and a
Claude Code `env` block whose endpoints are first-party (`api.anthropic.com`,
Bedrock, Agent Platform), whose proxy is loopback, and whose
`API_BASE_URL` is an application setting rather than an AI API endpoint.
Scanning it must produce no TRUST-008, CFHYG-007 or HARNESS-007 finding.
