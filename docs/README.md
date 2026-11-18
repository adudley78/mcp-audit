# Credenzo documentation

Every file in this folder is listed once. `tests/test_docs_index.py` fails when a file is missing here.

## Start

| File | What it covers |
|---|---|
| [docs-usage.md](docs-usage.md) | Getting started, every command and flag |
| [clients.md](clients.md) | Supported clients and the config files read for each |
| [check.md](check.md) | `check`: the one-page verdict |
| [scoring.md](scoring.md) | Score and grade method |
| [severity-framework.md](severity-framework.md) | Severity, CVSS and OWASP mapping for every finding ID |
| [owasp-mcp-top-10.md](owasp-mcp-top-10.md) | Coverage of the OWASP MCP Top 10 |
| [privacy.md](privacy.md) · [telemetry.md](telemetry.md) | What Credenzo collects (nothing by default) |

## Commands

| File | What it covers |
|---|---|
| [affected.md](affected.md) | `affected`: is this advisory in any server here |
| [vet.md](vet.md) · [badge.md](badge.md) | `vet`: pre-install verdict, and the README badge |
| [fix.md](fix.md) | `fix`: safe remediations |
| [lock.md](lock.md) | `lock`: the committable record of approved servers |
| [run.md](run.md) | `run`, `wrap`, `unwrap`: the launch gate |
| [reach.md](reach.md) · [secret-reach.md](secret-reach.md) | `reach`: what the agents on this machine can touch; REACH-001..003 |
| [diff.md](diff.md) | `diff`: MCP-aware diff for pull requests |
| [killchain.md](killchain.md) | `killchain`: the changes that cut the most attack paths |
| [shadow-mcp.md](shadow-mcp.md) | `shadow`: servers outside the allowlist |
| [snapshot.md](snapshot.md) | `snapshot`: signed forensic export |
| [baselines.md](baselines.md) | `baseline`: snapshots and drift |
| [live-connection.md](live-connection.md) | `--connect`: live tool enumeration |
| [compliance-report.md](compliance-report.md) | `scan --report pdf` |

## What is checked

| File | What it covers |
|---|---|
| [poisoning.md](poisoning.md) | POISON-* and DELEG-*: measured recall and precision |
| [annotations.md](annotations.md) | ANNOT-001: annotations that contradict the tool schema |
| [agent-files.md](agent-files.md) · [skill-packages.md](skill-packages.md) | Instruction files, memory and skills |
| [plugins.md](plugins.md) | Claude Code plugins and mods |
| [agent-execution-surface.md](agent-execution-surface.md) | Repository files that an agent harness runs or obeys |
| [git-exec.md](git-exec.md) | TRUST-006/007: git config and hooks that run code |
| [permission-rules.md](permission-rules.md) | PERM, SANDBOX and CRED-004..006: permission rules and sandbox settings |
| [guardrail-drift.md](guardrail-drift.md) | GUARD-001/002: safety settings that got weaker |
| [managed-policy.md](managed-policy.md) | MANAGED-*: Claude Code managed MCP policy |
| [gateways.md](gateways.md) | Servers behind an MCP gateway |
| [extensions.md](extensions.md) · [extension-policy.md](extension-policy.md) | IDE extensions and the extension allowlist |
| [ci-workflows.md](ci-workflows.md) | WORKFLOW-*: AI agent steps in GitHub Actions |
| [sast-rules.md](sast-rules.md) | The Semgrep rule pack |

## Supply chain and advisories

| File | What it covers |
|---|---|
| [supply-chain.md](supply-chain.md) | Hash and signature verification |
| [registry.md](registry.md) · [registry-contributions.md](registry-contributions.md) | The known-server registry and how to add to it |
| [advisory-feed.md](advisory-feed.md) | The signed OSV advisory feed |
| [research-records.md](research-records.md) | Credited research findings with no CVE |
| [exploit-signals.md](exploit-signals.md) | KEV, EPSS and public PoC signals |
| [air-gapped.md](air-gapped.md) | Use from a signed offline bundle |
| [dependency-reachability.md](dependency-reachability.md) | Why some transitive Dependabot findings are unused |

## Teams, CI and integrations

| File | What it covers |
|---|---|
| [governance.md](governance.md) | Governance policy |
| [fleet-scanning.md](fleet-scanning.md) · [enterprise-deployment.md](enterprise-deployment.md) | Fleet merge and deployment |
| [github-action.md](github-action.md) · [pre-commit.md](pre-commit.md) | GitHub Action and pre-commit hook |
| [ide-extension.md](ide-extension.md) | VS Code and Cursor extension |
| [nucleus-integration.md](nucleus-integration.md) · [snyk-integration.md](snyk-integration.md) | Nucleus and Snyk Code |
| [integrations/](integrations/) | Splunk and Sentinel recipes |

## Contributing

| File | What it covers |
|---|---|
| [writing-rules.md](writing-rules.md) · [community-rule-spec.md](community-rule-spec.md) | Policy rule format and its specification |
| [contributing-rules.md](contributing-rules.md) · [contributing-sast-rules.md](contributing-sast-rules.md) | How to contribute rules |
| [contributors.md](contributors.md) | Contributor credits |

## Maintainers

| File | What it covers |
|---|---|
| [building-binaries.md](building-binaries.md) | How the binaries are built |
| [manual-test-matrix.md](manual-test-matrix.md) · [manual-test-matrix-gaps-2026-09-13.md](manual-test-matrix-gaps-2026-09-13.md) | Release validation checklist and its gap audit |
| [release-ci-blind-spot.md](release-ci-blind-spot.md) | Record: the release.yml blind spot (R42) |
| [offline-verification-findings.md](offline-verification-findings.md) | Record: cosign keyless verification with no network |
| [adr/](adr/) · [decisions/](decisions/) · [archive/](archive/) | Decision records and archived docs |

## Research

| Folder | What it covers |
|---|---|
| [research/2026-10-top100-npm/](research/2026-10-top100-npm/README.md) · [research/2026-10-29-top100-npm/](research/2026-10-29-top100-npm/README.md) | The 100 most-downloaded MCP servers on npm, two measurements |
| [drift-index.md](drift-index.md) | The weekly record of which popular MCP servers changed their tools |
| [research/2026-12-launch-drift/](research/2026-12-launch-drift/README.md) | The launch drift study: corpus, method and results |
| [research/poisoning-benchmark/](research/poisoning-benchmark/) | POISON-* labels and results |
| [research/head-to-head/](research/head-to-head/README.md) | Benchmark beside other scanners |
| [research/histor-changes/](research/histor-changes/README.md) | False alarms of POISON-* on a public record of real changes |
| [research/mcp-safetybench/](research/mcp-safetybench/README.md) | Recall of POISON-* on MCP-SafetyBench's poisoned tool descriptions |
| [research/mem006/](research/mem006/) · [research/mem008/](research/mem008/) | MEM-006 and MEM-008 measurements |
