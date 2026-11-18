# POISON-* checks on MCP-SafetyBench (STORY-0171)

Measured 2026-11-18. Credenzo's poisoning text checks flag 30 of the 154
distinct poisoned tool descriptions of MCP-SafetyBench (19.5%). 17 are flagged
at HIGH or above. Before STORY-0171 the counts were 26 (16.9%) and 13.

## The benchmark

MCP-SafetyBench is a benchmark of attacks on agents that use real MCP servers
(Zong et al., [arXiv 2512.15163](https://arxiv.org/abs/2512.15163)). The
measurement used <https://github.com/xjzzzzzzzz/MCPSafety> at commit
`7872437b6369aac1150e3a19e350a981dc554f81`. Its `pyproject.toml` states the
3-Clause BSD licence. No text of the benchmark is committed here.
`results.json` holds counts and one SHA-256 value.

## What was counted

The benchmark has 245 task files. A task can replace the description of a tool
(`mcp_server_modifications`) or add a tool (`mcp_server_additions`).
`measure.py` takes each distinct text of those two fields: 154 texts. It checks
each text as one tool description, the way `scripts/bench_poisoning.py` checks
an MCPTox description.

Tasks that attack by another route are not counted: a changed implementation,
a tampered tool result, a replayed call, a spoofed identity. Those are not
tool text and the POISON-* checks do not read them.

## Result

| Attack category | Flagged |
|---|---|
| Tool Poisoning, Parameter Poisoning | 12 of 18 |
| Tool Poisoning, Function Dependency Injection | 10 of 23 |
| Tool Poisoning, Command Injection | 4 of 29 |
| Tool Shadowing | 4 of 21 |
| Function Overlapping | 0 of 20 |
| Preference Manipulation | 0 of 20 |
| Tool Poisoning, Tool Redirection | 0 of 10 |
| Tool Poisoning, FileSystem Poisoning | 0 of 7 |
| Tool Poisoning, Network Request Poisoning | 0 of 6 |
| All | 30 of 154 |

By check: POISON-030 on 13 texts, POISON-070 on 13, POISON-001 on 4.

## Limits

- The benchmark has no clean descriptions of its own. It gives no false-alarm
  number.
- The category of a text is the `attack_category` of the first task file that
  holds it.
- The checks read literal phrases. A description that states a preference or
  a plausible reason, with none of those phrases, gets no finding.
- STORY-0171 widened POISON-070. Two of its forms were written after two of
  these texts lost their POISON-012 finding; for those two texts the result
  is in-sample. The 4 texts that the change added were not the target of a
  form: the forms that catch them were written from a reviewer's examples.

## Run it again

```
git clone https://github.com/xjzzzzzzzz/MCPSafety PATH
uv run python docs/research/mcp-safetybench/measure.py PATH
```
