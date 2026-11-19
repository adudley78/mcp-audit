# Credenzo beside other scanners (2026-11-19)

Read with [README.md](README.md) (the benchmark harness) and `GAPS.md`.

This page says where Credenzo leads, where it is level and where it does not
lead. Each row states its basis: **measured** (we ran the tool; the numbers
and scripts are in this repository), **documented** (the vendor's own page,
read on the date above) or **not run**.

Credenzo's thesis: check the facts that an attack cannot avoid (a change, a
copy, what a tool can reach), locally, and say what the checks miss. Other
scanners judge the text of one tool, by rules or with a language model.

## The tools

| Tool | What it is | How it decides | Runs with no account, key or upload |
|---|---|---|---|
| Credenzo | CLI, Apache-2.0 | Rules and comparisons on files and live tool lists | Yes, by default |
| Snyk Agent Scan (before: Invariant Labs mcp-scan) | CLI of a commercial platform | Analysis on Snyk's service; a language-model classifier | No for `scan` (documented: it sends the discovered components to Snyk's API; `inspect` is local and gives no risk result) |
| Cisco AI Defense mcp-scanner | CLI and REST server, Apache-2.0 | YARA rules; a language-model judge; Cisco's API; code analysis with a model | Partly: YARA, readiness, prompt-defense and package checks need no key; the others need a key |
| NVIDIA SkillSpector | CLI | Static rules; a language-model mode | Yes in `--no-llm` mode |
| Tencent AI-Infra-Guard | Platform with MCP and skill scanners, Apache-2.0 | Agents that use a language model | No for the skill scan (documented: it needs a model key) |
| MCP-Shield | CLI, npm | Rules on tool descriptions; optional Claude analysis | Yes without the optional key |
| Pipelock | Runtime proxy, Apache-2.0 | Scans traffic in the data path | Yes |
| heldfast | Lock file and guard, Apache-2.0 | Refuses a changed tool | Yes |

## Measured

Each tool in this table was run on the same text, in a mode that sends nothing away.

| Measurement | Credenzo | Cisco YARA 4.8.7 | SkillSpector 2.12.0 static | Basis |
|---|---|---|---|---|
| MCP Security Bench, 96 tools that impersonate a tool: found | 96 (session checks); 0 (text checks) | 0 | 0 | [`../copy-checks/`](../copy-checks/README.md) |
| The same 96 tools: kept away from the agent | 96 (lock guard, honest server approved first) | no guard | no guard | [`../copy-checks/`](../copy-checks/README.md) |
| Blind set, 40 impersonating tools: found | 33 | 0 | not run | [`../copy-checks/`](../copy-checks/README.md) |
| Blind set: kept away from the agent | 27 | no guard | no guard | [`../copy-checks/`](../copy-checks/README.md) |
| Real changes to tool text (HISTOR, 126,105): changes flagged | 489 | 3,435 | not run on the full record | [`cisco-yara/`](cisco-yara/README.md), [`../histor-changes/`](../histor-changes/README.md) |
| 2,000 real added texts: flagged at each tool's own verdict level | 1 | 20 | 1 | [`skillspector/`](skillspector/README.md) |
| MCPTox, 485 poisoned descriptions with no wrapper: any finding | 149 | 99 | 111 | in-sample for Credenzo |
| MCP-SafetyBench, 154 poisoned descriptions: any finding | 88 (56 when the other two were run; the later checks were written from this set) | 36 | 30 | in-sample for Credenzo; [`../mcp-safetybench/`](../mcp-safetybench/README.md) |

Read the table with these limits:

- The two "in-sample" rows are sets that Credenzo's text checks were written
  from. They show that the checks read those texts, not what they catch next.
  On MCP Security Bench, a set that nobody had looked at, Credenzo's word
  lists found 0 of 42 tools. That failure is why the copy checks exist.
- Credenzo's 489 on HISTOR is after corrections that used that record (487
  when Cisco's rules were measured; 489 since POISON-083). The number before
  the corrections was 784. The like-for-like number is 784 against 3,435.
- Snyk Agent Scan, Tencent AI-Infra-Guard, MCP-Shield, Pipelock and heldfast
  were **not run**. Snyk's and Tencent's scanners need a remote service or a
  model key, and this project does not send benchmark text to a service.

## Kinds of check on a folder of config files

`demo/configs/` holds three client config files with planted problems. It is
Credenzo's own demo, so this is not a detection rate. It shows which kinds of
check each tool has when it reads config files and starts no server.

| Tool, mode | Result (2026-11-19) |
|---|---|
| Credenzo `scan --path demo/configs/`, in a network namespace with no network | 75 findings in 2.4 s: tool poisoning 4, credentials 3, supply chain 5 (typosquat SC-001, unscoped twin SC-007, known-malicious package SC-008, known CVE SC-004, SC-010), toxic combinations 18, transport 5, authentication 1, config hygiene 11, community rules 20, first-scan records 8 |
| SkillSpector 2.12.0 `scan demo/configs --no-llm` | 7 issues: 1 HIGH "Privilege Escalation" (the poisoned tool description), 6 MEDIUM "MCP Rug Pull". No credential, package or combination finding |
| Cisco mcp-scanner 4.8.7 | Not run. Its `config` mode starts each server in the file ("Scan an MCP server via stdio (local command execution)", from its `--help`). The demo names packages that must not be started |

```text
$ unshare -rn credenzo scan --path demo/configs/ --format json --no-score   # no network
exit 1, 2417 ms
servers 8 findings 75
{'rules': 20, 'toxic_flow': 18, 'config_hygiene': 11, 'rug_pull': 8, 'supply_chain': 5,
 'transport': 5, 'poisoning': 4, 'credentials': 3, 'auth': 1}
{'HIGH': 36, 'MEDIUM': 14, 'LOW': 11, 'INFO': 8, 'CRITICAL': 6}
```

## Capabilities

| Capability | Credenzo | Others (documented) |
|---|---|---|
| Works offline by default, no account | Yes | SkillSpector static, Cisco YARA, MCP-Shield, Pipelock, heldfast: yes. Snyk `scan`, Tencent skill scan: no |
| Reads config files without starting a server | Yes (default scan) | Cisco `static`, SkillSpector: yes. MCP-Shield connects to the servers |
| Finds a tool that copies another server's tool | Yes: same name, another spelling, copied description | Snyk: "cross reference analysis" with fuzzy similarity, on its service. MCP-Shield: tool shadowing and cross-origin rules. Cisco: not documented |
| Keeps a copied or changed tool away from the agent | Local servers: `lock` + `run --mode enforce` (names and definitions). Claude Code sessions: `guard`, a hook that denies a call to a tool that is not in the lock (names only; project servers and locked user servers by default, every server with `--strict`) | Snyk: Agent Guard hooks and a proxy. Pipelock: proxy. heldfast: guard for changed tools |
| Asks a server under the agent's own name, so the server cannot show a scanner other tools by name | Yes for Claude Code servers (the identity a live Claude Code session sent); `--identify-as` for others. It does not copy capabilities and does not connect two times to compare | MCP-Shield: `--identify-as`. Others: not documented |
| Lock file and drift of tool definitions | Yes (`mcp-lock.json`, tool digests, saved text) | heldfast: yes. Snyk: partial (documented by a third party). Cisco, SkillSpector, MCP-Shield: not documented |
| Agent files: skills, memory, hooks, subagents, plugins | Yes | SkillSpector, Snyk, Tencent: skills. Cisco: not documented |
| What an agent can reach (`reach`), credentials, sandbox and permission settings | Yes | Not documented for the others |
| Supply chain: typosquats, known-malicious packages, CVE lookup, SBOM, VEX | Yes | Cisco: package vulnerability check, registry package scan in Docker. Snyk: its platform |
| SARIF, GitHub Action, pre-commit | Yes | Snyk: `--ci`, JSON. Cisco: several formats, SARIF not documented |
| Published false-alarm numbers on real data, with the misses | Yes (`GAPS.md`, `docs/research/`) | Not found for the others |

## Where Credenzo does not lead

- **Meaning of text.** Credenzo has no language model. A copy with a
  description in new words gets no finding (6 of 40 in the blind set). A
  scanner with a model can judge such text. Snyk, Cisco's model judge and
  Tencent's scanner work this way; we did not measure them.
- **Server source code.** Cisco's behavioral analysis reads a server's code
  with a model. Credenzo has Semgrep rules only.
- **Runtime traffic.** Pipelock and Snyk's proxy scan tool calls and results.
  Credenzo's `run` checks the tool list of a local server and does not read
  tool results. Three attack types of MCP Security Bench act in tool results.
- **Agent hooks.** Snyk has hooks for Claude Code, Cursor, Codex and Copilot.
  Credenzo has a hook for Claude Code only (`guard`). Its hook compares names
  with the lock; it does not read tool text or tool results.
- **A hosted service.** Credenzo has no dashboard and no policy server.

## Sources

- Snyk Agent Scan changelog: <https://raw.githubusercontent.com/snyk/agent-scan/main/CHANGELOG.md>
- Cisco mcp-scanner: <https://github.com/cisco-ai-defense/mcp-scanner>
- Tencent AI-Infra-Guard: <https://github.com/Tencent/AI-Infra-Guard>
- MCP-Shield: <https://www.npmjs.com/package/mcp-shield>
- Pipelock's comparison (written by its author): <https://dev.to/luckypipewrench/mcp-scanner-comparison-cisco-vs-snyk-vs-pipelock-32kd>
- heldfast: <https://github.com/rufat325/heldfast>
- MCP Security Bench: <https://arxiv.org/abs/2510.15994>

## How to read a claim on this page

- A number is a count that a script in this repository gives. The script and
  the data hashes are in the linked folder.
- "Documented" is what the vendor's page said on the date above. A product
  can do more than its page says, and it can change.
- "Not run" is not zero. It means that we have no number.
