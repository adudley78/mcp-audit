# Credenzo, SkillSpector and Cisco mcp-scanner on the same text (STORY-0172)

Measured 2026-11-19. NVIDIA SkillSpector in its static mode flags fewer
poisoned tool descriptions than Credenzo. On honest text the answer depends on
the reading: SkillSpector lists more issues than Credenzo, and at the level of
its own verdict it flags as few texts as Credenzo does at HIGH.

## What was compared

- **SkillSpector** v2.12.0 (<https://github.com/NVIDIA/SkillSpector>, commit
  `ee4576e`), `scan --recursive --no-llm`. No language model and no remote
  service. SkillSpector reads skill folders, so each text was written as one
  `SKILL.md`, the way `scripts/bench_competitors.py` does it. A tool
  description is not the input SkillSpector was built for.
- **Credenzo**: the POISON-* text checks of `main`.
- **Cisco mcp-scanner** 4.8.7, YARA analyzer only (see `../cisco-yara/`).

## Result

| Set | Reading | Credenzo | SkillSpector | Cisco YARA |
|---|---|---|---|---|
| MCP-SafetyBench, 154 poisoned descriptions | any finding | 56 | 30 | 36 |
| | verdict level | 40 | 12 | 36 |
| MCPTox, 485 poisoned descriptions with no wrapper | any finding | 149 | 111 | 99 |
| | verdict level | 53 | 34 | 99 |
| MCPTox, 353 clean tools, flagged | any finding | 2 | 6 | 3 |
| | verdict level | 0 | 2 | 3 |
| HISTOR, sample of 2,000 distinct added texts, flagged | any finding | 6 | 23 | 31 |
| | verdict level | 1 | 1 | 20 |

"Verdict level" is each tool's own line for "act on this": HIGH or above for Credenzo (what `check` and the pre-commit hook fail on) and for Cisco, and a recommendation other than SAFE for SkillSpector. SkillSpector rates most skills that have a listed issue as SAFE: 18 of 30, 77 of 111, 4 of 6 and 22 of 23.

SkillSpector and Credenzo flag different texts: of the 30 MCP-SafetyBench
texts that SkillSpector flags, Credenzo flags 18. On MCPTox it is 51 of 111.

## Limits. Read these before you quote a number.

- **The attack sets are not independent of Credenzo.** Its checks were written
  with MCPTox in view, and POISON-080..082 were written from MCP-SafetyBench
  texts. Before those three checks Credenzo flagged 30 of 154 there, the same
  count as SkillSpector.
- **The HISTOR sample is not independent of Credenzo.** STORY-0170 and
  STORY-0171 corrected Credenzo's checks with HISTOR's flagged rows in view.
  Credenzo's count on this sample before those corrections was not measured.
- The HISTOR unit here is a distinct added text, not a change. The Cisco
  comparison in `../cisco-yara/` counts changes.
- No one labelled the texts that SkillSpector flagged on the sample. On the
  same record, 0 of 280 Credenzo flags and 0 of 150 Cisco flags were
  malicious, so a flag there is almost never an attack.
- SkillSpector scans 32 skills of a folder by default and reports the others
  as omitted. The runs here used folders of 30; `results.json` records 0
  omitted and 0 errors.
- Only the static mode ran. SkillSpector with a language model was not
  measured.
- The 1,312 wrapped MCPTox cases were not run through SkillSpector.

## Run it again

```
uv run python docs/research/head-to-head/cisco-yara/export.py OUT MCPTOX_DIR CHANGES_GZ SAFETYBENCH_REPO
uv run python docs/research/head-to-head/skillspector/export.py OUT SKILLS_OUT
# then, in an environment with SkillSpector, for each folder of at most 30 skills:
skillspector scan FOLDER --recursive --max-skills 32 --no-llm --format json --output FILE
```

`OUT` and `SKILLS_OUT` must be outside the repository.
