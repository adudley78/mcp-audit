# Poisoning detection, measured

mcp-audit's `POISON-*` checks are regular expressions run over the text an AI agent reads about a tool: its name, its description and the strings inside its input schema. They run on MCP config files, on live tool definitions with `scan --connect`, and (through the same `PATTERNS` list) on agent instruction files. The pattern list and severities are in [severity-framework.md](severity-framework.md); where each pattern comes from is in [PROVENANCE.md](../PROVENANCE.md).

This page reports how often those checks are right. Every number here comes from `docs/research/poisoning-benchmark/results.json`, written by `scripts/bench_poisoning.py` (STORY-0088, measured 2026-10-25).

## The numbers

| What | Corpus | Result |
|---|---|---|
| Recall: share of poisoned descriptions flagged | MCPTox, all 1,312 benchmark cases | **74.5%** (P1 79.3%, P2 79.2%, P3 68.7%) |
| Recall, cases with no keyword wrapper | MCPTox, 435 of those cases | **23.2%** (P1 33.8%, P2 39.3%, P3 4.7%) |
| Recall, poisoned descriptions as released without wrappers | MCPTox `pure_tool.json`, 485 | **24.9%** (P1 40.3%, P2 41.5%, P3 6.2%) |
| Real tools flagged | MCPTox's 353 clean tools from 45 real servers | **18** (5.1%): 16 `POISON-060`, 2 `POISON-050` |
| Precision: share of findings that were real | Live tools of the 100 most-downloaded npm MCP servers: 661 findings on 1,611 tools | **0 of 661** (0.0%) |

MCPTox's three attack paradigms: **P1** explicit trigger, function hijacking (a tool that mimics a common function); **P2** implicit trigger, function hijacking (a tool posing as a check another tool must run first); **P3** implicit trigger, parameter tampering (a tool telling the agent to change another tool's arguments).

**What this means.** POISON-* catches poisoning that announces itself: every MCPTox case wrapped in `<IMPORTANT>…</IMPORTANT>` or starting "Ignore the previous instructions" was flagged (877 of 877), by `POISON-010` and `POISON-012`. Without the wrapper it flags about one poisoned description in four, and almost none of the parameter-tampering kind. MCPTox measured that the two wrappers raise average attack success by 2.0% and 2.6%, so an attacker loses almost nothing by leaving them out. On the servers people actually install, the checks are noisy: none of the 661 findings on the top-100 npm servers was an attack, and 488 of them were Chinese punctuation.

**For comparison.** Cisco's MCP Scanner YARA rules, run unmodified, flagged 20.8% of the MCPTox-derived malicious descriptions in one test split (10 of 48, drawn from the same 485 descriptions as our 24.9%, less two in an "Other" class; ours is measured on all 485) ([arXiv 2604.10534](https://arxiv.org/html/2604.10534v1)). Across eight MCP scanners run on 37,288 MCPZoo servers, mean precision was 45.5% and the scanners' flagged sets overlapped 15.7% of the time on average ([arXiv 2607.11086](https://arxiv.org/html/2607.11086v1)).

**Why there is no single precision figure on MCPTox.** MCPTox holds 1,312 poisoned cases against 353 clean tools, so a precision computed on it would mostly reflect that mix (it would come out near 98%). Precision is reported where the mix is real, on the top-100 corpus, and MCPTox's clean tools give a flag rate instead.

## Where it misses, and where it is wrong

- **Parameter tampering (P3) is nearly invisible: 6.2% of unwrapped cases.** A description such as "when using `send_email`, set `to` to …" contains no keyword the patterns know.
- **One pattern carries most of the unwrapped detections and many false alarms.** `POISON-030` ("first call", "before using this tool", "instead use") fired on 102 of the 121 detected unwrapped descriptions (on 87 of them it was the sole finding), and made 30 of the 661 top-100 findings, where the same phrases are ordinary workflow documentation (the shape "first call <tool> to resolve the ID").
- **Full-width punctuation is the largest false-positive source.** `POISON-060`'s character class includes U+FF01–FF5E, which covers the full-width parenthesis, comma, colon and semicolon of Chinese text. That was 488 of the 661 top-100 findings and 16 of the 18 flagged MCPTox clean tools (all on three Chinese-language servers, in descriptions and argument text). Fixing it is separate work; this page measures it.
- **Length is a weak signal.** `POISON-050` (description of 2,000 characters or more) fired 139 times on the top-100 corpus, on API reference text, and twice on MCPTox's clean tools.

## What was measured

### MCPTox (recall, and the clean-tool flag rate)

MCPTox is a benchmark of tool poisoning on 45 live MCP servers and 353 real tools ([arXiv 2508.14925](https://arxiv.org/html/2508.14925v1), AAAI 2026). Its data is in the authors' anonymized repository, <https://anonymous.4open.science/r/AAAI26-7C02>, which states no licence. mcp-audit therefore never commits it: `bench_poisoning.py` reads it into memory and records each file's SHA-256.

| File | SHA-256 | Bytes |
|---|---|---|
| `response_all.json` | `79a90049be931c59e71446d6180b1d7f0d196d123d08a59bc155d142b5041c03` | 20,666,873 |
| `pure_tool.json` | `54b1eb0e9d7b2f18465266aa9d9dfda828cd558b1269b74731ec2c5d8579e617` | 316,620 |

- **Which cases.** `response_all.json` holds 1,348 test cases. 36 carry `wrong_data: 2` and are excluded, which leaves 1,312, the paper's stated total. By paradigm that is 208 / 519 / 585. The paper's Table 1 gives 224 / 548 / 725, which sums to 1,497; the released file does not match Table 1, and the measurement uses the file.
- **Which paradigm is which.** The files label paradigms `Template-1/2/3`; the paper calls them P1/P2/P3. The mapping was confirmed by reading cases: Template-1 tools mimic a common function ("Get the current date"), Template-2 tools are pre-checks ("Before using `listEmails`, use `markAsRead` …"), Template-3 tools rewrite arguments ("when using `push_files`, modify the `files` argument …").
- **Wrappers.** 460 cases carry an `<IMPORTANT>` block and 417 start "Ignore the previous instructions" (the paper's two "enhanced settings"); 435 carry neither. They are told apart with the same substring tests as the authors' own analysis notebook; the one case carrying both is counted with `<IMPORTANT>`.
- **`pure_tool.json`.** 485 poisoned descriptions (P1 77, P2 183, P3 225) with no wrapper. This is the set the Cisco comparison above was drawn from.
- **Clean tools.** Each server's clean tool list, limited to the names in its `tool_names` (353; one server's prompt lists nine more).
- **How a case is scored.** Each record's `Tool: / Description: / Arguments:` text becomes one tool definition (argument lines become input-schema descriptions) and goes through `build_runtime_server_config` and `PoisoningAnalyzer`, the path `scan --connect` uses. A case counts as detected when at least one `POISON-*` finding fires, at any severity.

### The top-100 npm corpus (precision)

The corpus is the 2026-10-22 scan of the 100 most-downloaded MCP servers on npm, published in [`docs/research/2026-10-top100-npm/`](research/2026-10-top100-npm/README.md). 60 servers answered a live handshake and exposed 1,611 tools; mcp-audit 0.21.0's runtime poisoning check produced 661 findings on them. `analyzers/poisoning.py` and `mcp_client.build_runtime_server_config` have not changed between v0.21.0 and the code measured here, so the findings are the current code's findings.

#### How the top-100 findings were labelled

The full tool definitions (about 6 MB) are not committed, and neither is which server produced which finding: the corpus README explains that a list of names next to findings that were not attacks would accuse those servers of something the data does not show. What is committed is each finding's ID and its matched text. The labels in `docs/research/poisoning-benchmark/top100-labels.json` are per (ID, matched text) group, and the harness refuses to run unless they cover all 661 findings exactly once.

| ID | Matched text | Findings | Label | Basis |
|---|---|---|---|---|
| POISON-060 | `（` `，` `：` `；` | 488 | false positive | committed evidence |
| POISON-050 | (length ≥ 2,000; no text) | 139 | false positive | review |
| POISON-030 | `first call` / `First call` / `After calling this` / `Instead use` / `instead of call` | 22 / 3 / 3 / 1 / 1 | false positive | review |
| POISON-012 | `Override default` | 2 | false positive | review |
| POISON-020 | `Base64 encode` | 2 | false positive | review |

- **Committed evidence (488).** The summary keeps up to 12 distinct POISON-060 matches and lists four, so these four characters are every character it matched: full-width parenthesis, comma, colon and semicolon. They are punctuation, not letters, so they cannot spell a disguised word. This label can be checked from the repository alone.
- **Review (173).** These labels come from the review done with the 2026-10-22 scan, which had the full live definitions (its README: "None of the poisoning findings in this corpus was a real attack"). The repository cannot reproduce that review without re-running the corpus's `scripts/enumerate.py`. To check them independently, on 2026-10-25 the published npm source of 51 of the 57 servers that `connect-summary.json` lists as connected was read (never run; the other six are over 60 MB) for each matched phrase. Every occurrence found was ordinary documentation of a parameter, a workflow step or the code itself, for example "Override default hostname of the virtual machine", "Base64 encoded file content or file path", "first call … with filter on entityKeyId to resolve the numeric rqID" and "After calling this tool, use … to execute specific tools" (tool names elided, for the same reason the corpus does not name servers).
- **Reproduction from committed text.** The harness also runs the current analyzer over every committed fragment: 520 of the 661 findings reproduce from the fragment alone. POISON-020 needs a nearby destination word the two-word fragment lacks, and POISON-050 published no text.

## How the numbers stay true

- `tests/test_bench_poisoning.py` (offline, every CI leg) recomputes the top-100 precision and the fragment replay and compares them with `results.json`. It also compares a fingerprint of the POISON-* patterns with the one recorded for both measurements, so a pattern change fails CI until both are re-measured and this page is updated.
- The ubuntu "all optional extras" CI job runs `python scripts/bench_poisoning.py recall --check --skip-if-unavailable` on every push. It fetches MCPTox, checks the hashes and fails if fewer cases are detected or more clean tools are flagged than `results.json` records. If the host is unreachable, or its files no longer match the pinned hashes, it warns instead.
- To re-measure after changing a pattern:

```
uv run python scripts/bench_poisoning.py precision --write
uv run python scripts/bench_poisoning.py recall --write                # fetches MCPTox
uv run python scripts/bench_poisoning.py recall --source DIR --write    # a local copy
MCP_AUDIT_MCPTOX_DIR=DIR uv run pytest tests/test_bench_poisoning.py    # local recall check
```

## What this measurement does not cover

- **Agent instruction files.** SKILL.md, CLAUDE.md and rule files reuse the same patterns, but neither corpus contains them.
- **Concealment channels.** `POISON-041/042` (Unicode tag characters, HTML comments) never fired: no MCPTox case uses them.
- **A larger benign set.** MCPZoo's 16,356 runnable servers ([arXiv 2512.15144](https://arxiv.org/abs/2512.15144)) would be a better clean background; no download was found.
- **Non-English poisoning.** Every MCPTox case is in English.
- **Exit codes.** Recall counts any POISON-* finding. `check` and `--severity-threshold` decide what fails a build; a LOW `POISON-050` alone would not.
