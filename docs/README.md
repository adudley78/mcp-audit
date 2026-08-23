# mcp-audit Documentation

| File | Description |
|------|-------------|
| [docs-usage.md](docs-usage.md) | Getting started, all CLI commands and flags, common workflows |
| [github-action.md](github-action.md) | GitHub Action setup, example workflows, exit code behaviour |
| [building-binaries.md](building-binaries.md) | How the shipped PyInstaller binary is built (one composite, CI and release); per-release CycloneDX SBOMs |
| [scoring.md](scoring.md) | Scan score methodology, grade thresholds, score/filter interaction |
| [telemetry.md](telemetry.md) | Privacy policy: what mcp-audit does and does not collect |
| [baselines.md](baselines.md) | Baseline snapshot workflow, drift detection, commands |
| [governance.md](governance.md) | Governance policy schema, quickstart, worked examples |
| [writing-rules.md](writing-rules.md) | Policy-as-code YAML rule format, match types, contributing |
| [sast-rules.md](sast-rules.md) | Semgrep rule catalog, severity rationale, false positive guidance |
| [extensions.md](extensions.md) | IDE extension scanner overview, supported clients, analysis layers |
| [supply-chain.md](supply-chain.md) | Supply chain attestation, hash verification, contribution guide |
| [dependency-reachability.md](dependency-reachability.md) | Why Dependabot findings in transitives are unused, and which call-site changes invalidate those dismissals |
| [severity-framework.md](severity-framework.md) | CVSS base scores and OWASP Agentic Top 10 mappings for every finding ID; decision tree for calibrating new findings |
| [registry.md](registry.md) | Known-server registry reference, contributing entries |
| [registry-contributions.md](registry-contributions.md) | How to submit new registry entries |
| [nucleus-integration.md](nucleus-integration.md) | push-nucleus command, FlexConnect API, fleet push examples |
| [fleet-scanning.md](fleet-scanning.md) | Fleet merge workflow, asset prefix, enterprise deployment |
| [enterprise-deployment.md](enterprise-deployment.md) | Fleet deployment guide for IT/security teams |
| [pre-commit.md](pre-commit.md) | Pre-commit hook setup and configuration |
| [contributing-rules.md](contributing-rules.md) | Community detection rule contribution guide (template, bounty, attribution) |
| [contributing-sast-rules.md](contributing-sast-rules.md) | Semgrep SAST rule authoring guide |
| [community-rule-spec.md](community-rule-spec.md) | Community rule YAML format specification (Apache 2.0; ecosystem-adoptable) |
| [contributors.md](contributors.md) | Attribution list for accepted community contributors |
| [manual-test-matrix.md](manual-test-matrix.md) | Release-candidate manual validation checklist |
