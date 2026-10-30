# Tool annotations that contradict the tool's own schema (ANNOT-001)

MCP servers describe each tool with optional **annotations** (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`). Clients use them to decide what to approve without asking. The MCP maintainers are clear about what they are: "Every property is a hint", "They aren't enforcement", and "A server can claim `readOnlyHint: true` and delete your files anyway" ([Tool Annotations as Risk Vocabulary: What Hints Can and Can't Do](https://blog.modelcontextprotocol.io/posts/2026-03-16-tool-annotations/), 2026-03-16). actlint, a linter that compares a server's labels with its schema, found 4 of 31 popular servers (541 tools) carrying a label that denies something the tool's own schema says it can do ([DEV Community write-up](https://dev.to/formael/are-your-mcp-servers-safety-labels-honest-a-one-command-check-and-what-it-found-on-31-popular-1ml3)).

`ANNOT-001` checks that one thing and nothing else: does a tool's own input schema contradict the label it carries?

## What fires

| Claim | A parameter that contradicts it |
|---|---|
| `readOnlyHint: true` | runs commands (`command`, `cmd`, `script`, `shell`, `exec`, `execute`, `bash`, `powershell`; or a description such as "shell command" / "command to run"), runs SQL that writes (a `sql`/`query`/`statement` parameter whose description names INSERT, UPDATE, CREATE, GRANT, DELETE, DROP, TRUNCATE or ALTER), a write or delete switch (`overwrite`, `delete`, `drop`, `truncate`, `write`, `append`), or a `content`/`text`/`data`/`body` parameter described as content to write, beside a `path`/`file` parameter |
| `destructiveHint: false` (and not read-only) | runs commands, runs destructive SQL, or a delete / overwrite switch. Additive writes are not counted: the spec lets a non-destructive tool write |

Never counted: a `path` or `url` alone (reading is what read-only tools do); a name that is a reference (`script_path`, `command_name`); a boolean or numeric `command`; a SQL parameter whose description forbids writes ("read-only", "not", "only", "select"); `remove*` (`removeBase64Images` and `remove_background` are options, not deletes). A non-boolean hint (`"true"`, `1`) is ignored. The claim only raises a finding; it never lowers or hides anything else.

One finding per tool, naming up to three parameters. Evidence is control-character-stripped, length-capped and redacted with `supply_chain.redact_command`.

## Where it runs

- `scan --connect` (and `dashboard --connect`), right after DELEG-*, over the tools each server listed.
- A default scan reads `mcp-lock.tools.json` (saved tool text, `lock --connect --save-tool-text`) from the working directory, when present. A file that cannot be read is reported in the scan's errors. The file is not checked against the lock here: its text is only read.

Nothing connects to or starts a server, and no scanned code runs.

## Severity and measurement

**LOW.** The rule: LOW if precision is unmeasured or under 50%; MEDIUM only with measured precision of at least 50% on at least 10 hits.

Corpus: tool definitions regenerated from the 100 most-downloaded MCP servers on npm ([2026-10-29 corpus](research/2026-10-29-top100-npm/README.md)), with the committed scripts and their isolation: `npm install --ignore-scripts` as an unprivileged user, each server run under `unshare --net` with an empty environment (`scripts/install.py`, `scripts/enumerate_isolated.py`). MCPTox was not available locally and was not measured. The default invocation only was run (the `overrides` files that adjusted arguments for 15 servers in the original run were not available), so 48 of 100 servers connected, against 61 originally. Tool definitions are not committed.

| Measure | Count |
|---|---|
| Servers connected | 48 |
| Tools | 989 |
| Tools with annotations | 732 |
| `readOnlyHint: true` | 349 |
| `destructiveHint: false` | 341 |
| ANNOT-001 hits | 6 tools on 3 servers |

First pass: 17 hits on 13 tools. 11 were false positives from the `remove` token (`removeBase64Images`, `remove_lighting`, `remove_background`: options that strip image data); `remove` was dropped from the detector and a test pins it. The table is the re-run.

Hand labels (each read in the tool's full live definition):

| Server | Tool | Claim | Parameter | Label | Why |
|---|---|---|---|---|---|
| `@cloudbase/cloudbase-mcp` | `downloadTemplate` | destructiveHint=false | `overwrite` | true positive | A flag that overwrites existing files on download; the tool says it is not destructive |
| `firecrawl-mcp` | `firecrawl_search` | readOnlyHint=true | `script` | true positive | `scrapeOptions.actions[].script` runs caller-supplied JavaScript (`executeJavascript`) in Firecrawl's browser; the tool says it is read-only. The code runs remotely, not on the host |
| `firecrawl-mcp` | `firecrawl_scrape` | destructiveHint=false | `script` | true positive | same parameter |
| `firecrawl-mcp` | `firecrawl_crawl` | destructiveHint=false | `script` | true positive | same parameter |
| `firecrawl-mcp` | `firecrawl_interact` | destructiveHint=false | `script` | true positive | same parameter |
| `@statelyai/mcp` | `analyze_stately_test_report` | readOnlyHint=true | `command` | false positive | `command` is a field of a recorded test report passed in as data; the tool says it does not execute code |

**5 of 6 hits are true by that reading (83%), but that is 6 hits, under the 10 the rule needs, and four of the five true positives are one parameter on one server.** By server it is 2 of 3. The severity stays LOW, and the precision is a small-sample figure, not a rate to rely on. The five true positives are also mild: JavaScript in a hosted browser, and a documented overwrite flag defaulting to false. No hit is a read-only tool that runs host commands.

## Limits

- Name and description tokens, not behaviour: a parameter called `command` that is data (the Stately case) fires. A tool that hides a write behind a neutral parameter name does not.
- A `$ref` in a schema is not followed. The walk is capped (depth 8, 5,000 nodes, 256 properties per object, 2,000 characters of description).
- `idempotentHint` and `openWorldHint` are not checked.
- ANNOT-001 is not published as an advisory (`NON_ADVISORY_IDS`) until its precision is measured on enough hits to defend it.
