# Checks on facts: a tool that copies another tool (STORY-0174)

Measured 2026-11-19. On two sets that the checks were not written from, the
text checks of three scanners find almost none of the impersonating tools.
The checks that compare the tools of a session find most of them, and the
lock guard keeps most of them away from the agent.

| Set | Tools | Session checks name the tool | Lock guard withholds it | Credenzo, text checks | Cisco YARA | SkillSpector static |
|---|---|---|---|---|---|---|
| MCP Security Bench, attack tools | 96 | 96 | 96 | 0 | 0 | 0 |
| Blind set, impersonating tools | 40 | 33 | 27 | 2 | 0 | not run |

The session checks are COLLIDE-001 (the same name on two servers),
COLLIDE-002 (the same words in another spelling), COLLIDE-003 (two tools on
two servers carry one description) and DELEG-001..003. They need
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
checks that property.

## COLLIDE-003: a fact with no direction

Tool A holds tool B's description when each long sentence of B (five words or
more, ten words or more in all) is a sentence of A. When one name is the other
name plus one or two words, four words of description are enough.

The finding is MEDIUM and names both tools. The text does not show which tool
was first: a hostile server can take the short name `read_file` and copy the
text of an honest `read_file_safe`. A first version of this check made the
longer name the copy and rated it HIGH. A reviewer showed that the hostile
server then gets the honest tool reported, and that 28 of 30 honest sessions
with a fork, a gateway or two servers of one vendor got a HIGH finding. A
second version rated a tool HIGH when the registry knew the other server; a
hostile server that put a registry name in its own name or arguments then
turned the finding round. Nothing that a server chooses changes the severity
now. The finding is always MEDIUM, and the lock guard is what acts.

The finding does not hold the copied text.

## The lock guard: the order comes from the lock

`lock --connect` knows what the text cannot know: which tools you approved
before. A tool that is not in the lock and carries the description of a tool
of another server that is in the lock is left out (same name or another
name). `lock --verify --connect` then reports it (LOCK-006) and
`run --mode enforce` withholds it, so the agent sees the approved tool only.
`--allow-copies` records it.

- No launch detail excuses a pair. The same package name, command line or
  environment can still run other code (`--package`, `--registry`, another
  version, `NODE_OPTIONS`). One product installed two times under two names
  is stopped one time, like each honest duplicate.
- The guard compares each new tool with the approved tools only, so text
  that honest servers share among their own tools stops nothing. When its
  work budget runs out, a new tool that was not compared is not approved.
- A first lock has no earlier record, so it has no order. It records both
  tools, and `scan --connect` reports the pair.

## MCP Security Bench

MSB (Zhang et al., [arXiv 2510.15994](https://arxiv.org/abs/2510.15994),
<https://github.com/dongsenzhang/MSB>, MIT, commit `c1d6a70`) has an honest
server and attack copies of it for five servers. `measure_msb.py` reads the
sources with `ast` and does not run them. No benchmark text is committed.

| Attack file | Tools | Session checks name the tool | Lock guard withholds it | Text checks |
|---|---|---|---|---|
| Name overlap | 24 | 24 | 24 | 0 |
| Preference manipulation | 18 | 18 | 18 | 0 |
| Preference manipulation with an out-of-scope parameter | 18 | 18 | 18 | 0 |
| Out-of-scope parameter | 18 | 18 | 18 | 0 |
| Tool transfer | 18 | 18 | 18 | 0 |
| All | 96 | 96 | 96 | 0 |

The guard column has the honest server approved first and the attack server
added after it, with a launch command of its own. The out-of-scope-parameter and tool-transfer attacks act in a
parameter or in a tool result. The checks find those tools because they also
take the name or the description of the honest tool, not because they read
the attack. An attack of that kind with a name and a description of its own
gets no finding.

MSB's five honest servers (18 tools) in one session get no finding.

## Blind set

`blind_set.json` holds 40 sessions with one impersonating tool each and 40
sessions of honest servers. A separate agent wrote it from a description of
the attack class. It did not see the code or the rule. `measure_blind.py`
gives, for the 40 attack sessions:

| Result | Sessions |
|---|---|
| A session check names the impersonating tool | 33 |
| Found by COLLIDE-001 only (a check that existed before) | 11 |
| Found by COLLIDE-003 | 20 |
| Found by COLLIDE-003 and by no other check | 15 |
| The lock guard withholds the impersonating tool | 27 |
| The lock guard withholds another tool | 0 |
| A text check fires on the description | 2 |
| A finding at HIGH | 0 |

- The 7 sessions with no finding: a name of its own with a description in
  new words (6), and one tool that only claims to be the vendor's own.
- The guard does not withhold a copy with a shortened or edited description
  (4 sessions) or a tool that only names the tool that it replaces (2).
- No finding is HIGH, because the fact is the same for an attack and for an
  honest duplicate. The guard is what acts.
- The guard numbers hold for this order: the target's server was approved
  first.

For the 40 honest sessions:

- 17 get a MEDIUM finding and 0 get a HIGH finding. 16 of them are COLLIDE-001:
  two servers for one job that use the same tool name (`create_issue` on two
  git hosts).
- With the first server approved and the others added after it, the guard
  withholds a tool in 6 sessions: a fork beside the original, a gateway beside
  the server that it fronts, and servers that share a helper tool. The user
  approves those one time with `--allow-copies`.

The agent wrote the honest sessions to be hard for a scanner, so these are
not rates for real sessions.

On real descriptions the guard stops more than that. In 5,000 random
sessions of five servers from HISTOR's record, with the first server
approved and the four others added after it, the guard withholds a tool in
495 sessions (`random.Random(175)`). Each of the 1,167 withheld tools has the
same name and the same description as an approved tool. A few vendors in
that record publish hundreds of servers that each carry the vendor's shared
tools (`company_register_search` with one 450-word description), so two of
five random servers are often from one vendor. The guard cannot tell a
vendor's second server from a copy: a name, a package or a host can be
another party's. The user allows it one time, and `--allow-copies` lists
each tool that it allows.

## False alarms of COLLIDE-003 on real descriptions

HISTOR's record of changes (Artamokhov, A., 2026,
<https://doi.org/10.5281/zenodo.23512759>) gives the newest description of
95,698 tools on 13,684 servers.

| Control | COLLIDE-003 findings |
|---|---|
| 5,000 random sessions of five servers | 0 sessions with a finding |
| MCPTox, 353 clean tools of 45 servers in one session | 0 |
| MSB, five honest servers in one session | 0 |
| Each of the 13,684 servers in one session | 100 pairs listed (the cap) |

In the last row most pairs are servers of one vendor that share helper tools
under a prefix (`brain_update_coupon`, `cypher_update_coupon`). A random
session almost never holds two such servers, so the first row does not
measure a user who installs a fork or a gateway. The blind set's honest
sessions do.

## MCPSecBench

MCPSecBench ([arXiv 2508.13220](https://arxiv.org/abs/2508.13220),
<https://github.com/AIS2Lab/MCPSecBench>, MIT, commit `7612c5a`) is small: two
honest servers and two malicious ones. The text checks fire on none of the 13
tools of the malicious server. COLLIDE-001 finds the tools that take a name
of the honest servers, and COLLIDE-002 finds one spelling variant. The honest
servers alone get no finding.

## Limits

- The rule of COLLIDE-003 was written after a first look at MSB. MSB is a
  test of the word lists, not a blind test of COLLIDE-003. The blind set is.
- A copy with a description in new words gets no finding. Nothing in the
  text ties it to the original.
- The guard needs an earlier lock. A copy that is there at the first lock is
  recorded like each other tool.
- The guard also stops an honest duplicate one time, until the user allows
  it: 6 of 40 hard honest sessions, and 495 of 5,000 random sessions of real
  servers, where most cases are two servers of one vendor with a shared tool.
- A hostile server that is locked before the honest one is the "original"
  for the guard. The order of approval is the user's, not the truth.
- SkillSpector was not run on the blind set.

## Run it again

```
uv run python docs/research/copy-checks/measure_msb.py \
    MSB_REPO MCPTOX_DIR HISTOR_CHANGES_GZ
uv run python docs/research/copy-checks/measure_blind.py
```
