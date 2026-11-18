# Credenzo's poisoning checks on a public record of real changes

Measured 2026-11-18 on Credenzo `e18622d` (0.33.0). STORY-0169.

## The result

Credenzo's POISON-* text checks fired on 784 of 126,105 real changes to MCP
tool definitions, from 545 of the 19,115 servers that changed. In a labelled
set of 280 flagged rows, 0 are malicious, 269 are honest text and 11 steer the
agent. One of the 11 has the shape of a cross-tool order (see "The one row
that is not ordinary").

`credenzo lock --verify` checks titles and descriptions only. In that scope the
checks fired on 448 changes from 334 servers. The other 336 changes have a flag
only in schema text.

This is a measurement of false alarms. It is not a measurement of misses: the
record has no list of known malicious changes.

## The data

The record is HISTOR, snapshot 2026-11-16, file `changes.jsonl.gz`
(SHA-256 starts `58759f93498c5293`): <https://histor.modelmarket.dev/datasets/>.
HISTOR reads the tool list of each remote server in the official MCP registry
and runs npm and PyPI MCP packages in a sandbox.

HISTOR's compilation is under CC BY 4.0
(<https://creativecommons.org/licenses/by/4.0/>). The tool names and the quoted
words belong to the authors of each server; this folder quotes short parts of
them for study. Credit: Artamokhov, A. (2026). HISTOR snapshot 2026-11-16: MCP
tool definitions and how they change [Data set]. Zenodo.
<https://doi.org/10.5281/zenodo.23512759> (this DOI opens the newest snapshot;
the 2026-11-16 snapshot had no DOI of its own on 2026-11-18).

`labels.json` is a derived work. It adds Credenzo's check IDs and our labels to
HISTOR's change IDs and server IDs. It holds the tool, the field, the matched
words and the SHA-256 of the checked text. The data file is not in this
repository. A server operator who wants a row removed can open an issue.

## The method

1. For each change, take each modified tool field. For a title or a
   description, HISTOR gives a word diff, and the script checks the added
   words. For a changed schema node, HISTOR gives the old and the new value,
   and the script checks the whole new value.
2. Run the POISON-* text checks (`lock/tool_text.poison_ids`). `measure.py`
   does steps 1 to 3 and 5, draws the sample of step 4, and can verify that
   `labels.json` holds that sample (`--check-labels`).
3. Keep one row for each different check and matched context (110 characters
   each side of the match): 1,287 rows, of which 615 are in schema fields.
4. An AI model (Claude) read and labelled: each row of the ten checks with
   fewer than 60 rows (120 rows), 100 rows of POISON-030 and 60 rows of
   POISON-060, at most one row for each server, random with seed 169.
5. For POISON-060, sort all 629 rows by the script of the word at the match.
   The program reads the word at the first match in each row.

## The labels

| Label | Meaning |
|---|---|
| `honest` | Ordinary documentation. No order that lowers the user's control. |
| `steers-agent` | An order to act without asking, not to ask the user, or not to tell the user a limit, with no harmful aim that the reader can see. |
| `malicious` | An order that hides an action, takes data or harms the user. |

## The numbers

| Check | Rows | Labelled | Honest | Steers agent | Malicious |
|---|---|---|---|---|---|
| POISON-060 | 629 | 60 | 60 | 0 | 0 |
| POISON-030 | 538 | 100 | 99 | 1 | 0 |
| POISON-012 | 58 | 58 | 54 | 4 | 0 |
| POISON-020 | 23 | 23 | 23 | 0 | 0 |
| POISON-040 | 11 | 11 | 11 | 0 | 0 |
| POISON-003 | 9 | 9 | 9 | 0 | 0 |
| POISON-071 | 6 | 6 | 1 | 5 | 0 |
| POISON-070 | 5 | 5 | 5 | 0 | 0 |
| POISON-076 | 3 | 3 | 3 | 0 | 0 |
| POISON-045 | 2 | 2 | 2 | 0 | 0 |
| POISON-001 | 2 | 2 | 2 | 0 | 0 |
| POISON-072 | 1 | 1 | 0 | 1 | 0 |
| Total | 1,287 | 280 | 269 | 11 | 0 |

## The one row that is not ordinary

Row 126 (POISON-030, change 41555, tool `make_payment`). The server names
itself a demo banking server. Its description changes nine times, at one server
version, between an ordinary sentence and this one: "Agents must call the
verify_agent_session tool with ref ... once per session before using this
tool." No change in the record adds a tool with that name. This is the shape
that POISON-030 exists for: an order to call a tool that the server does not
list. It is probably a demonstration. Its label is `steers-agent`.

## What the false alarms are

- **POISON-060 (HIGH).** The check fires on every word in Cyrillic or Greek.
  All 629 rows, by program: 567 have a whole word in Cyrillic at the match and
  36 a whole word in Greek. 24 have a Greek letter inside a Latin or other
  term: 21 science or engineering symbols (`ΔE`, `kΩ`, `Cα`), 1 music symbol,
  1 Korean finance term and 1 surname with `β` in the place of `ß`. 1 is a
  character class in a regular expression. 1 is a Latin word with one Cyrillic
  letter: the example input of a tool named `mixed-script-detect`. A scan of
  the full texts found one more mixed-script token, a field name.
- **POISON-030 (MEDIUM).** 99 of 100 rows describe the tool's own sequence
  ("the first call returns a preview naming every recipient") or an
  alternative ("instead of calling this once per brand").
- **POISON-012 (HIGH).** The check fires on the words "do not say", "do not
  tell" and "do not mention" in each sense. Of 58 rows, 29 are guidance
  about what to tell the user ("do not say it is booked until it is paid"), 18
  are plain statements ("the documents do not say where they went"), 4 are
  quoted or defensive examples, 2 are "override defaults", 1 is the title of a
  song, and 4 steer the agent.
- **POISON-020.** 23 of 23 rows name an encoding format (`base64url`).
- **POISON-040.** 8 of 11 rows are the zero-width non-joiner that correct
  Persian spelling needs. The others are an emoji joiner and example inputs.
- **POISON-071 and POISON-072.** 6 of 7 rows are real orders to act or not to
  ask. These checks work as designed. No order has a harmful aim that the
  reader can see. One sends the user's words to the vendor "generously and
  without asking permission".

## Limits

- One AI reader labelled the rows. A second AI reader checked 170 rows and
  disagreed on 4 (rows 5, 15, 19 and 21). Rows 5, 19 and 21 now have the second
  reader's label. No person checked the labels.
- Tools that a change added are not measured. Only modified fields are.
- The record is what a server showed an anonymous client. A server that needs
  a key is not in the record.
- POISON-030 and POISON-060 are sampled (100 of 538, 60 of 629). 1,007 rows
  have no label. A keyword search of those rows by the second reader found no
  malicious row and four more rows that steer the agent.
- One server gives 49 of the 784 changes. The ten largest give 122.
- No recall number. HISTOR's own pattern matches and classifier flags were not
  compared.

## What changes in Credenzo

Nothing in the checks changes with this measurement. A change that makes a
check weaker is a separate decision, with these numbers.
