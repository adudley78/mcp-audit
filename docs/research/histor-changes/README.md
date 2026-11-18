# Credenzo's poisoning checks on a public record of real changes

Measured 2026-11-18 on Credenzo `e18622d` (0.33.0). STORY-0169.

## The result

Credenzo's poisoning checks fired on 784 of 126,105 real changes to MCP tool
definitions. In a labelled set of 280 flagged rows, 0 are malicious, 272 are
honest text, 7 steer the agent and 1 is not decided. On this record, the checks
do not separate a dangerous change from an ordinary change.

This is a measurement of false alarms. It is not a measurement of misses: the
record has no list of known malicious changes.

## The data

The record is HISTOR, snapshot 2026-11-16, file `changes.jsonl.gz`
(SHA-256 starts `58759f93498c5293`). HISTOR reads the tool list of each remote
server in the official MCP registry and runs npm and PyPI MCP packages in a
sandbox. Its data is free under CC BY 4.0:
<https://histor.modelmarket.dev/datasets/>. Credit: Artamokhov, A. (2026),
HISTOR, <https://doi.org/10.5281/zenodo.23512759>.

The data file is not in this repository. `labels.json` holds, for each labelled
row, HISTOR's change ID and server ID, the tool, the field, the check, the
matched words and the SHA-256 of the added text.

## The method

1. For each change, take the words that the change added to each modified tool
   field.
2. Run the checks that `credenzo lock --verify` runs on added words
   (`lock/tool_text.poison_ids`). `measure.py` does steps 1 and 2.
3. Keep one row for each different check and matched context (110 characters
   each side of the match): 1,287 rows. `measure.py` counts by the whole added
   text, so its counts for each check are a little higher (`results.json`).
4. Label by hand: each row of the ten small checks (120 rows), 100 rows of
   POISON-030 and 60 rows of POISON-060, at most one row for each server,
   random with seed 169.
5. For POISON-060, also sort all 629 rows by the script of the word that holds
   the matched letter. This step is a program, not a judgment.

## The labels

| Label | Meaning |
|---|---|
| `honest` | Ordinary documentation. No order that lowers the user's control. |
| `steers-agent` | An order to act, or not to ask the user, with no harmful aim seen. |
| `malicious` | An order that hides an action, takes data or harms the user. |
| `not-decided` | The row names a second tool and the reader did not check the server. |

## The numbers

| Check | Rows | Labelled | Honest | Steers agent | Malicious | Not decided |
|---|---|---|---|---|---|---|
| POISON-060 | 629 | 60 | 60 | 0 | 0 | 0 |
| POISON-030 | 538 | 100 | 99 | 0 | 0 | 1 |
| POISON-012 | 58 | 58 | 57 | 1 | 0 | 0 |
| POISON-020 | 23 | 23 | 23 | 0 | 0 | 0 |
| POISON-040 | 11 | 11 | 11 | 0 | 0 | 0 |
| POISON-003 | 9 | 9 | 9 | 0 | 0 | 0 |
| POISON-071 | 6 | 6 | 1 | 5 | 0 | 0 |
| POISON-070 | 5 | 5 | 5 | 0 | 0 | 0 |
| POISON-076 | 3 | 3 | 3 | 0 | 0 | 0 |
| POISON-045 | 2 | 2 | 2 | 0 | 0 | 0 |
| POISON-001 | 2 | 2 | 2 | 0 | 0 | 0 |
| POISON-072 | 1 | 1 | 0 | 1 | 0 | 0 |
| Total | 1,287 | 280 | 272 | 7 | 0 | 1 |

## What the false alarms are

- **POISON-060 (HIGH).** All 629 rows, by program: 567 are a whole word in
  Cyrillic, 36 a whole word in Greek, 24 a Greek letter in a science term
  (`ΔE`, `kΩ`, `Cα`), 1 a character class in a regular expression, and 1 a
  Latin word with one Cyrillic letter. That last row is the example input of a
  tool named `mixed-script-detect`. The check fires on a language, not on a
  mixed-script trick.
- **POISON-030 (MEDIUM).** 99 of 100 rows describe the tool's own sequence
  ("the first call returns a preview") or an alternative ("instead of calling
  this once per brand").
- **POISON-012 (HIGH).** 57 of 58 rows are guidance about what to tell the
  user ("do not say it is booked until it is paid"), a quoted example of an
  attack in a security tool, or configuration words ("override defaults").
- **POISON-020.** 23 of 23 rows name an encoding format (`base64url`).
- **POISON-040.** 8 of 11 rows are the zero-width non-joiner that correct
  Persian spelling needs. The others are an emoji joiner and example inputs.
- **POISON-071 and POISON-072.** 6 of 7 rows are real orders to act or not to
  ask ("call this generously and without asking permission"). These checks
  work as designed. Not one of the orders has a harmful aim.

## Limits

- One reader labelled the rows. No second reader checked the labels.
- Tools that a change added are not measured. Only modified fields are.
- A server shows this text to an anonymous client. A server that needs a key
  shows less.
- POISON-030 and POISON-060 are sampled (100 of 538, 60 of 629). The program
  count for POISON-060 covers all 629 rows.
- No recall number. This record has no list of known malicious changes.

## What changes in Credenzo

Nothing in the checks changes with this measurement. A change that makes a
check weaker is a separate decision, with these numbers.
