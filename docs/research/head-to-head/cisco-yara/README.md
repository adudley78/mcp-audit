# Credenzo and Cisco mcp-scanner on the same text (STORY-0172)

Measured 2026-11-18. On a public record of 126,105 real changes to MCP tool
definitions, Cisco mcp-scanner's YARA rules flag 3,435 changes and Credenzo's
text checks flag 487. On the two public sets of poisoned tool descriptions,
Credenzo flags more of them.

## What was compared

- **Credenzo:** the POISON-* text checks of this repository (the code that
  `scan --connect` and `lock --verify` run on tool text).
- **Cisco mcp-scanner:** `cisco-ai-mcp-scanner` 4.8.7 from PyPI, its YARA
  analyzer with the default rules. Its default analyzer set is `api,yara,llm`,
  and YARA is the one of the three that runs with no key and sends nothing to
  a remote service. No other analyzer was run. That includes the local
  `schema`, `prompt_defense` and `readiness` analyzers, so this is not a
  measure of the whole product.
- NVIDIA SkillSpector and Snyk agent-scan were not run. SkillSpector could not
  be installed in the measurement environment. Snyk agent-scan needs remote
  analysis.

Each tool got the same text: the description of each tool (and the JSON of its
input schema), or the added text of each changed field in HISTOR's record, as
`docs/research/histor-changes/measure.py` reads it.

## Result

| Set | Credenzo | Cisco YARA |
|---|---|---|
| MCPTox, 1,312 poisoned cases, flagged | 1,005 (76.6%) | 277 (21.1%) |
| MCPTox, 485 poisoned descriptions with no wrapper | 149 (30.7%) | 99 (20.4%) |
| MCP-SafetyBench, 154 poisoned descriptions | 56 (36.4%) | 36 (23.4%) |
| MCPTox, 353 clean tools, flagged | 2 | 3 |
| HISTOR, 126,105 real changes: changes flagged | 487 | 3,435 |
| HISTOR: servers flagged | 389 | 2,889 |
| HISTOR: changes flagged at HIGH or above (each vendor's own scale) | 46 | 3,259 |

Before any correction made with this record in view, Credenzo flagged 784
changes (STORY-0169). That is the like-for-like number against Cisco's 3,435.

On real changes, a flag is almost never an attack. In Credenzo's labelled set
(280 flagged rows, STORY-0169) 0 are malicious. In a random sample of 150
texts that Cisco's rules flagged, 0 are malicious, 146 are honest and 4 steer
the agent (`labels.json`). Honest text that Cisco's rules flag: the word
"assert" in schema text, "run (" and "function (" in prose, and notes such as
"never include credentials".

## Limits. Read these before you quote a number.

- **The attack sets are not independent of Credenzo.** Credenzo's checks were
  written with MCPTox in view. POISON-080..082 were written on 2026-11-18
  after this comparison showed what Cisco's rules caught on MCP-SafetyBench
  and Credenzo did not. Before them Credenzo flagged 30 of 154 on
  MCP-SafetyBench, fewer than Cisco's 36, and 124 of 485 on MCPTox. No public
  attack set remains that Credenzo has not been tuned on.
- **The HISTOR numbers are not independent now.** They were on the first run
  (Credenzo 784). STORY-0170 and STORY-0171 then corrected Credenzo's checks
  with HISTOR's flagged rows in view, and that took it to 487. Cisco's rules
  had no such correction. The like-for-like number is 784 and 3,435.
- **The scopes differ.** Cisco's rules also name risky capabilities (code
  execution, SQL injection strings, script injection). Credenzo's POISON-*
  checks look for text that attacks the agent. A flag on "this tool runs a
  shell command" is a false alarm for poisoning, and may be a useful note for
  another purpose.
- An AI model labelled the 150 Cisco flags. It read the matched words and about
  300 characters round each match, and the full text for 20 rows. No person
  checked the labels. A second agent checked 25 of them and agreed with each.
- Severity scales are each vendor's own.
- The two directive sets (93 poisoned, 95 benign phrases) are Credenzo's own
  test fixtures. They are in `results.json` and not in the table.

## Run it again

```
uv run python docs/research/head-to-head/cisco-yara/export.py OUT MCPTOX_DIR CHANGES_GZ SAFETYBENCH_REPO
python -I docs/research/head-to-head/cisco-yara/cisco_run.py OUT     # in an environment with cisco-ai-mcp-scanner
python -I docs/research/head-to-head/cisco-yara/tab.py OUT
```

`OUT` must be outside the repository. `sample.py OUT` draws the labelled
sample. No third-party text is committed here: `labels.json` holds SHA-256
values, rule names and labels.
