# Credenzo on MCP-SafetyBench (STORY-0171, STORY-0173)

Measured 2026-11-19. With each poisoned tool in the session of its domain,
Credenzo flags 108 of the 154 distinct poisoned tools of MCP-SafetyBench
(70.1%), 51 at HIGH or above. The text checks alone flag 88 (57.1%), 40 at
HIGH or above. The text count was 26 before STORY-0171, 30 before STORY-0172
and 56 before STORY-0173. STORY-0172 and STORY-0173 wrote checks from these
texts, so the current counts are in-sample. They did not hold on a new set:
on MCP Security Bench the word lists of STORY-0173 found 0 of 42 tools
(`docs/research/copy-checks/`).

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

`measure.py` checks each text alone. `measure_session.py` builds the session
of the task's domain from the benchmark's own server sources (for example
`github`, `terminal` and `url_fetch` for repository management). A changed
tool stays on its server. An added tool is on a server of its own. The other
tools of the session have their names and no description. The script then
runs the text checks and the checks that need the session: COLLIDE-002 and
DELEG-001..003.

| Attack category | Text checks | Text and session checks |
|---|---|---|
| Preference Manipulation | 18 of 20 | 20 of 20 |
| Tool Poisoning, Parameter Poisoning | 12 of 18 | 18 of 18 |
| Tool Shadowing | 11 of 21 | 19 of 21 |
| Function Overlapping | 14 of 20 | 17 of 20 |
| Tool Poisoning, Tool Redirection | 6 of 10 | 6 of 10 |
| Tool Poisoning, Command Injection | 16 of 29 | 16 of 29 |
| Tool Poisoning, Function Dependency Injection | 10 of 23 | 10 of 23 |
| Tool Poisoning, FileSystem Poisoning | 1 of 7 | 1 of 7 |
| Tool Poisoning, Network Request Poisoning | 0 of 6 | 1 of 6 |
| All | 88 of 154 | 108 of 154 |

Text checks by ID: POISON-083 on 32 texts, POISON-080 on 17, POISON-030 on
13, POISON-070 on 13, POISON-081 on 12, POISON-001 on 4, POISON-082 on 3.
Session checks by ID: DELEG-001 on 17 tools, COLLIDE-002 on 13, DELEG-003 on
8, DELEG-002 on 6.

## Controls for COLLIDE-002

`name_copy_controls.py` runs COLLIDE-002 on real tool names.

| Control | Result |
|---|---|
| The five MCP-SafetyBench sessions with no attack | 0 findings |
| MCPTox, 353 clean tools of 45 servers in one session | 1 MEDIUM finding |
| HISTOR's tool names, 5,000 random sessions of five servers | 21 sessions with a MEDIUM finding, 0 with a HIGH finding |

The MEDIUM findings are honest servers that list the same words in two
spellings (MCPTox: `searchEmails` and `search-emails`). The first list of decoration words
held "new" and "tool". It gave 2 HIGH findings on honest pairs in the HISTOR
control, so those words were removed. The benchmark count did not change.
The "0 HIGH" number is therefore fitted to this control. The control draws
servers at random; two servers for one job share more names. A review then
showed HIGH on honest pairs such as `send_secure_message` beside
`send_message`, so a copy is HIGH only when each added word praises ("best",
"premium", "enhanced") and stands before or after the whole name, and
MEDIUM in the other cases. The count at HIGH or above went from 54 to 51.

## Limits

- The benchmark has no clean descriptions of its own. It gives no false-alarm
  number for text. The controls above are for names only.
- POISON-083 and COLLIDE-002 were written from this benchmark's Preference
  Manipulation, Function Overlapping and Tool Shadowing cases. Their counts
  here show that the checks read those cases, not what they catch elsewhere.
- The session count needs the tool lists of every server (`scan --connect`).
  A scanner that reads one description at a time cannot make it, so the
  session column is not a like-for-like number against such a scanner.
- The category of a text is the `attack_category` of the first task file that
  holds it.
- The checks read literal phrases. A description that states a preference or
  a plausible reason, with none of those phrases, gets no finding.
- STORY-0171 widened POISON-070. One form ("Do not mention this change.")
  was written after two of these texts lost their POISON-012 finding; for
  those two texts the result is in-sample. The 4 texts that the change added
  ("must not inform the user about the change") were first caught by a form
  written from a reviewer's examples, and the form was kept because these
  texts need it.

## Run it again

```
git clone https://github.com/xjzzzzzzzz/MCPSafety PATH
uv run python docs/research/mcp-safetybench/measure.py PATH
uv run python docs/research/mcp-safetybench/measure_session.py PATH
uv run python docs/research/mcp-safetybench/name_copy_controls.py \
    MCPTOX_DIR HISTOR_CHANGES_GZ
```
