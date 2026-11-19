# Checks on facts: a tool that copies another tool (STORY-0174)

Measured 2026-11-19. On three sets that the checks were not written from,
the text checks of three scanners find almost none of the impersonating
tools. The checks that compare the tools of a session find most of them.

| Set | Tools | Credenzo, session checks | Credenzo, text checks | Cisco YARA | SkillSpector static |
|---|---|---|---|---|---|
| MCP Security Bench, attack tools | 96 | 91 | 0 | 0 | 0 |
| Blind set, impersonating tools | 40 | 33 | 2 | 0 | not run |

The session checks are COLLIDE-001 (the same name on two servers),
COLLIDE-002 (the same words in another spelling), COLLIDE-003 (a tool carries
another server's tool description) and DELEG-001..003. They need
`scan --connect`. Cisco's YARA rules and SkillSpector's static mode read one
description at a time, and the description of a copy is honest text.

## Why this was measured

STORY-0173 added two checks that work from word lists (POISON-083 and the
decoration words of COLLIDE-002). On the set that they were written from
(MCP-SafetyBench) Credenzo found 108 of 154 tools. On MCP Security Bench,
which nobody had looked at, the two checks found 0 of the 24 name-overlap
tools and 0 of the 18 preference tools. A copy there is `execute_command_v1`,
and the list had `v2`. The text that sells a tool there is in another order
of words. A list of words finds the cases that it was written from.

Each of those 42 tools has one property that it cannot avoid. It must look
like the tool that it copies, or the agent does not pick it. COLLIDE-003
checks that property: the copy carries the description of the original.

## COLLIDE-003

Tool A on one server copies tool B on another server when the names differ
and each long sentence of B's description (five words or more, ten words or
more in all) is a sentence of A's description. When A's name is B's name plus
one or two words, four words of description are enough.

- HIGH: the description is copied and the name is the other name plus one or
  two words.
- MEDIUM: the description is copied under a name of its own.

The finding does not hold the copied text.

## MCP Security Bench

MSB (Zhang et al., [arXiv 2510.15994](https://arxiv.org/abs/2510.15994),
<https://github.com/dongsenzhang/MSB>, MIT, commit `c1d6a70`) has an honest
server and attack copies of it for five servers with attack files.
`measure_msb.py` reads the sources with `ast` and does not run them. No
benchmark text is committed.

| Attack file | Tools | Session checks | HIGH or above | Text checks |
|---|---|---|---|---|
| Name overlap | 24 | 24 | 24 | 0 |
| Preference manipulation | 18 | 18 | 12 | 0 |
| Preference manipulation with an out-of-scope parameter | 18 | 18 | 13 | 0 |
| Out-of-scope parameter | 18 | 18 | 6 | 0 |
| Tool transfer | 18 | 13 | 13 | 0 |
| All | 96 | 91 | 68 | 0 |

The out-of-scope-parameter and tool-transfer attacks act in a parameter or in
a tool result. The session checks find those tools because they also take the
name or the description of the honest tool, not because they read the attack.
The 5 tools that no check finds keep their own name and description.

MSB's five honest servers (18 tools) in one session get no finding.

## Blind set

`blind_set.json` holds 40 sessions with one impersonating tool each and 40
sessions of honest servers. A separate agent wrote it from a description of
the attack class. It did not see the code or the rule. `measure_blind.py`
gives:

- Attack sessions: a session check names the impersonating tool in 33 of 40,
  7 at HIGH. A text check fires on 2 of 40 (a Cyrillic letter in the name).
- The 7 misses: a name of its own with a description in new words (6), and
  one tool that only claims to be the vendor's own.
- Honest sessions: 0 of 40 get a HIGH finding. 17 of 40 get a MEDIUM finding.
  16 of those are COLLIDE-001: two servers for one job that use the same tool
  name (`create_issue` on two git hosts). One is a gateway beside the server
  that it fronts.

The agent wrote the honest sessions to be hard for a scanner, so 17 of 40 is
not a rate for real sessions.

## False alarms of COLLIDE-003 on real descriptions

HISTOR's record of changes (Artamokhov, A., 2026,
<https://doi.org/10.5281/zenodo.23512759>) gives the newest description of
95,698 tools on 13,684 servers.

| Control | COLLIDE-003 findings |
|---|---|
| 5,000 random sessions of five servers | 0 sessions with a finding |
| MCPTox, 353 clean tools of 45 servers in one session | 0 |
| MSB, five honest servers in one session | 0 |
| Each of the 13,684 servers in one session | about 90 servers share a description with another server |

In the last row most pairs are servers of one vendor that share helper tools
under a prefix (`brain_update_coupon`, `cypher_update_coupon`). Those get
MEDIUM. A user who installs two such servers gets that finding.

## MCPSecBench

MCPSecBench ([arXiv 2508.13220](https://arxiv.org/abs/2508.13220),
<https://github.com/AIS2Lab/MCPSecBench>, MIT, commit `7612c5a`) is small: two
honest servers and two malicious ones. The text checks fire on none of the 13
tools of the malicious server. COLLIDE-001 finds the tools that take a name
of the honest servers, and COLLIDE-002 finds one spelling variant. The honest
servers alone get no finding.

## The guard

`lock --connect` leaves a tool with a HIGH COLLIDE-002 or COLLIDE-003 finding
out of the lock. `lock --verify --connect` then reports the tool (LOCK-006)
and `run --mode enforce` withholds it, so the agent sees the original only.
`--allow-copies` records the tool.

## Limits

- The rule of COLLIDE-003 was written after a first look at MSB. MSB is a
  test of the word lists, not a blind test of COLLIDE-003. The blind set is.
- A copy with a description in new words gets no finding. Nothing in the
  text ties it to the original.
- A fact is the same for an attack and for an honest duplicate. Two servers
  for one job share tool names. The finding says that the agent cannot tell
  the two tools apart. It does not say which one is the copy when the two are
  equal.
- The guard withholds HIGH findings only: 7 of the 40 blind attacks.
- SkillSpector was not run on the blind set.

## Run it again

```
uv run python docs/research/copy-checks/measure_msb.py \
    MSB_REPO MCPTOX_DIR HISTOR_CHANGES_GZ
uv run python docs/research/copy-checks/measure_blind.py
```
