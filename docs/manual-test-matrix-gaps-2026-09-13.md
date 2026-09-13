# Manual test matrix — gap audit, 2026-09-13

Audit of `docs/manual-test-matrix.md` (last run green at
`6143455c55d6ff35ffce00ab68dccde5386c18e1`, 2026-09-08) against the shipped
`v0.18.1` surface. The matrix stopped at Section 46; everything STORY-0070
onward landed after the last green run.

Method: build a coverage set from the code (live Typer/Click introspection for
the command tree, `git diff 6143455..HEAD -- docs/owasp-mapping.json` for new
finding IDs, `action.yml` inputs, `.pre-commit-hooks.yaml` args, README claims,
exit-code contracts), then grep the matrix for each literal option / finding ID
/ claim. Every "missing" below was confirmed absent by grep, and every
behaviour below was confirmed by running it — nothing here is inferred from
reading code alone.

---

## Part 1 — Coverage sets built from the code

### 1a. Command tree

47 commands/groups registered on the live `app`. All 27 top-level command names
already appear in the matrix (`tests/test_manual_test_matrix.py` enforces
this). The gaps are **options**, which that test does not and cannot check.

Options on shipped commands that appear nowhere in the matrix:

| Command | Un-exercised options |
|---|---|
| `lock` | `--verify`*, `--accept`*, `--resolve`, `--allow-unverified`, `--if-present`, `--include-user`, `--registry`, `--format` |
| `scan` | `--no-lock`, `--org`, `--include-agent-files`, `--advisory-feed`, `--check-vulns`, `--verify-signatures`, `--strict-signatures`, `--vuln-registry`, `--reset-state`, `--connect-token` |
| `check` | `--no-lock`, `--org`, `--register` |
| `snapshot` | `--rehydrate` |
| `shadow` | `--allowlist`, `--continuous` |
| `verify` | `--all` |
| `vet` | `--online`, `--badge`, `--strict`, `--ecosystem` |
| `advise` | `--sign`, `--key-alt`, `--keyless`, `--previous-index`, `--ttl-days` |
| `baseline` | `compare`, `export` |
| `rule` | `test`, `validate` |

\* `--verify` / `--accept` are exercised in Section 46 but only on the happy
path and `LOCK-001`; the other five lock finding IDs are untested.

### 1b. Finding IDs added since `6143455`

`git diff 6143455..HEAD -- docs/owasp-mapping.json` adds 17 IDs:

`CRED-003`, `LOCK-001`, `LOCK-002`, `LOCK-003`, `LOCK-004`, `LOCK-005`,
`POISON-041`, `POISON-042`, `SC-005`, `SKILL-004`, `STDIO-001`, `STDIO-002a`,
`STDIO-002b`, `TRUST-002`, `TRUST-003`, `TRUST-004`, `TRUST-005`.

`INTEG-001` (R37, `da692de`) predates the last green run but is also
uncovered, so it is audited here too — 18 IDs in scope.

Matrix grep result:

- **13 appear nowhere at all** (grep count 0): `LOCK-002`, `LOCK-003`,
  `LOCK-004`, `LOCK-005`, `POISON-041`, `POISON-042`, `SC-005`, `SKILL-004`,
  `TRUST-002`, `TRUST-003`, `TRUST-004`, `TRUST-005`, `INTEG-001`.
- **4 appear in prose only**, never with a fixture or assertion: `CRED-003`
  (named in a list of auto-fixable IDs at L746), `STDIO-001`/`STDIO-002a`/
  `STDIO-002b` (named in Section 15's rule-count explanation at L301).
  `HOOK-001`/`HOOK-002` are likewise prose-only (L940).
- **1 is genuinely exercised**: `LOCK-001`, in Section 46.

So **17 of 18 in-scope finding IDs had no executable coverage.** `STDIO-001`
is a special case: it ships `enabled: false` with no governance toggle, so it
cannot fire for anyone and is untestable by design (see `GAPS.md`).

### 1c. `action.yml` inputs

`lock-verify` and `lock-resolve` are shipped inputs that gate CI on
`LOCK-001/002/004/005`. Neither appears in the matrix, and no section runs the
composite action's lock mode.

### 1d. `.pre-commit-hooks.yaml`

`mcp-audit-lock-verify` (`lock --verify --if-present`) is a shipped hook id.
Not in the matrix.

### 1e. README / Show HN claims

The README first screen and the Show HN draft are both
`lock` → drift → `lock --verify` → `lock --accept`, reproduced by
`demo/lock/run.sh`. The matrix never runs `demo/lock/run.sh`, so the exact
byte sequence users will copy on launch day was unvalidated.

### 1f. Exit-code contracts

`docs/lock.md` specifies distinct exit codes per lock state (0 clean / 1
findings-or-unwaived-unverified / 2 tamper-or-missing-lock). The matrix
asserts exit codes only for `LOCK-001` and the happy path.

---

## Part 2 — Gaps, with the one-line section proposed for each

Each of these became a real section in `docs/manual-test-matrix.md`
(Sections 47–58). Status is the result of actually running it against the
shipped wheel (Run A) and binary (Run B).

| # | Gap | Proposed section | Status |
|---|---|---|---|
| G01 | `SC-005` deprecated-package detection | Lock a server resolving to a deprecated package; assert `SC-005` at lock time and again under `--verify --resolve` | **PASS** |
| G02 | `lock --verify --allow-unverified` waiver | Offline-locked (unresolved) entry: exit 1 without the flag, exit 0 with it, waiver line printed | **PASS** |
| G03 | `lock --verify --resolve` + `LOCK-004` | Offline lock then online verify; assert `LOCK-004` `locked=None now=<version>` and exit 1 | **PASS** |
| G04 | `lock --accept` re-lock | Drift, accept, re-verify clean; assert redaction grep prints 0 | **PASS** |
| G05 | `LOCK-002` unlocked server present | Add a server not in the lock; assert `LOCK-002` HIGH and exit 1 | **PASS** |
| G06 | `LOCK-003` locked server missing | Remove a locked server; assert `LOCK-003` reported and **exit 0** (does not fail by itself) | **PASS** |
| G07 | `LOCK-005` hand-edited lock | Mutate a field under the checksum; assert `LOCK-005` and exit 2 | **PASS** |
| G08 | `--if-present` vs strict when no lock exists | No lock file: strict exits 2, `--if-present` exits 0 | **PASS** |
| G09 | `scan`/`check` auto-verify of nearest `mcp-lock.json` | Locked project; assert `check` agrees with `lock --verify` | **FAIL — R60-01** |
| G10 | Monorepo with two lock files | Two apps each with their own lock; assert each server verifies against its nearest ancestor lock | **FAIL — R60-01** |
| G11 | `--offline` lock → unresolved → verify exit 1 | Assert the unresolved-at-lock-time warning and non-zero exit | **PASS** |
| G12 | `TRUST-002` symlinked config, target outside root | Assert HIGH | **PASS** |
| G13 | `TRUST-002` symlinked config, target inside root | Assert MEDIUM | **PASS** |
| G14 | `TRUST-002` broken symlink | Assert INFO | **PASS** |
| G15 | `TRUST-004` symlinked explicit/user-global candidate | Assert INFO (dotfile-manager shape) | **PASS** |
| G16 | `TRUST-005` symlinked directory not followed | Assert LOW and that the directory is named, not silently skipped | **PASS** |
| G17 | `POISON-041` TAG-character run on a config | Assert HIGH when decoded content matches a poisoning pattern | **PASS** |
| G18 | `POISON-042` concealment-only channel | TAG run decoding to benign text; assert LOW | **PASS** |
| G19 | `POISON-041/042` on an agent file | Skill + memory file; assert `analyzer="poisoning"`, not `agent_files` | **PASS** |
| G20 | Benign HTML comment stays silent | `<!-- TODO -->`; assert no POISON finding | **PASS** |
| G21 | `CRED-003` secret in an auth header | Assert HIGH | **PASS** |
| G22 | `CRED-003` + `fix` preserving the scheme prefix | Assert `Bearer ${...}` survives the redaction | **FAIL — R60-02** |
| G23 | `CRED-003` placeholder → INFO | `Bearer <your-token>`; CHANGELOG says INFO | **FAIL — R60-03** |
| G24 | `INTEG-001` file_write + shell_exec | Two-server config; assert HIGH and an `INTEG-` (not `TOXIC-`) ID | **PASS** |
| G25 | `SKILL-004` bundled scripts inventory | Skill with `scripts/`; assert INFO and filenames only | **PASS** |
| G26 | `STDIO-002a` / `STDIO-002b` launcher trust boundary | Dotfile launcher and inline `python -c`; assert both fire | **PASS** |
| G27 | `TRUST-003` | Assert CRITICAL | **PASS** |
| G28 | `demo/lock/run.sh` end-to-end | Run it; assert exit 0 and no 80-column overflow | **PASS** |
| G29 | 80-column render of `scan`, `check`, `lock --verify` | R54/R55 width regressions; assert no line over 80 display columns | **PASS** |
| G30 | Released binary smoke | Sections 1–3, 46 and `demo/lock/run.sh` with the release binary on `$PATH` | **PASS (x86_64); arm64 NOT RUN — R60-06** |
| G31 | Degraded-extra install hints | `sbom` / `snapshot --sign` / `scan --connect` without the extra; assert the printed install command is copy-pasteable | **FAIL — R60-04, R60-05** |

---

## Part 3 — Failures found, classified

Full classification, reproduction, and impact analysis for each `R60-*` is in
the PR description and summarised here.

| ID | Classification | Severity |
|---|---|---|
| R60-01 | REGRESSION | **LAUNCH-BLOCKING** |
| R60-02 | REGRESSION | POST-LAUNCH |
| R60-03 | REGRESSION | POST-LAUNCH |
| R60-04 | MATRIX-GAP (long-standing defect, predates `6143455`) | POST-LAUNCH |
| R60-05 | MATRIX-GAP (long-standing defect, predates `6143455`) | POST-LAUNCH |
| R60-06 | ENV | n/a — needs an Apple Silicon host |
| R60-07 | REGRESSION (docs contradict behaviour) | POST-LAUNCH |

### R60-01 — `scan`/`check` lock auto-verify contradicts `lock --verify` (LAUNCH-BLOCKING)

On a project that `lock --verify` reports as **clean**, `check` reports
**Grade F** with `Server not in lock` for the server just locked, and exits 1.

Reproduced with the **literal README commands** — no path arguments, which is
the form the first screen actually shows:

```
$ mcp-audit lock
Locked 1 server(s).   claude-code/notion  2.5.1              [exit 0]

$ mcp-audit lock --verify
Lock: 1 servers verified; not verified: tools, trees          [exit 0]

$ mcp-audit check
  Grade: D  (Score: 55/100)
  Lock: 2 finding(s) across 1 locked server
  4. [HIGH]   Server not in lock: 'notion'
     -> This server is not in the lock. Run `mcp-audit lock` to add it once
        you've reviewed it.
  5. [MEDIUM] Locked server missing: 'notion'
     -> This server is in the lock but no longer in your config. Run
        `mcp-audit lock` to remove it, or restore the server.    [exit 1]
```

The two remediation hints contradict each other about the same server, and
both tell the user to run `mcp-audit lock` — which changes nothing, because
the lock is already correct. There is no escape from the loop except
`--no-lock`.

Root cause: the lock key is `<client>/<name>`, and the client label for the
same server differs per entry point — `lock` writes `claude-code`, `scan
--path <file>` labels it `custom`, `scan --project` labels it
`claude-code-project`. No label matches, so every server is simultaneously
`LOCK-002` ("not in lock", HIGH, against the scan's label) and `LOCK-003`
("locked server missing", MEDIUM, against the lock's label).

Compounding defect: `discovery.py`'s `resolved.glob("*.json")` for an explicit
directory picks up `mcp-lock.json` itself, whose top-level `servers` key
collides with VS Code's MCP config root key — so each lock entry is re-parsed
as a phantom server named `claude-code/github`, analyzed, and fires its own
`LOCK-002`.

Why launch-blocking: `lock` → `lock --verify` is the README first screen and
the Show HN opening, `check` is the README's "recommended entry point for new
users", and the two contradict each other on a correct configuration. The exit
code flips 0 → 1, so `check` in CI red-builds a correctly locked repo. The
only way to a truthful result is `--no-lock`, i.e. turning the feature off.

### R60-02 — `fix` cannot remediate `CRED-003` (POST-LAUNCH)

`check` prints "Run `mcp-audit fix --apply` to auto-remediate [CRED-003]";
`fix --apply --fix-type credentials` replies "No fixable findings in this
scan." and exits 0. `_FIX_TYPE_IDS["credentials"]` in `fixer/fixer.py` is
`{"CRED-001", "CRED-002"}` — `CRED-003` is filtered out before
`CredentialsFixStrategy.can_fix()` (which does accept it) is consulted, so the
implemented `_fix_header()` scheme-prefix logic is unreachable. G22 cannot be
tested until this is fixed.

### R60-03 — `CRED-003` placeholder severity depends on a scheme prefix (POST-LAUNCH)

`Authorization: <your-token-here>` → `CRED-003` **INFO** "Placeholder value in
authentication header" (correct, matches CHANGELOG).
`Authorization: Bearer <your-token-here>` → `CRED-003` **HIGH** "Live
credential embedded in authentication header" (wrong). `_PLACEHOLDER_RE` is
applied to the raw value, so the scheme prefix defeats placeholder detection —
and `Bearer <token>` is the form the MCP docs themselves use.

### R60-04 / R60-05 — degraded-extra install hints are not copy-pasteable (POST-LAUNCH)

`console.print(f"[red]Error:[/red] {exc}")` renders exception text as Rich
markup, so `[sbom]` / `[attestation]` / `[mcp]` are parsed as style tags and
**deleted** from the user's install command:

| Command | Printed | Should print |
|---|---|---|
| `sbom` | `pip install 'mcp-audit-scanner'` | `pip install 'mcp-audit-scanner[sbom]'` |
| `snapshot --sign` | `pip install 'mcp-audit-scanner'` | `pip install 'mcp-audit-scanner[attestation]'` |
| `scan --connect` | `pip install 'mcp-audit'` | `pip install 'mcp-audit-scanner[mcp]'` |

The source strings are correct; the print sites never pass `markup=False` or
escape the bracket. `cli/scan.py:408` and `cli/scan.py:1162` already escape
with `\\[`, so the codebase knows about this hazard — the raised-exception
paths just never got the same treatment.

R60-05 is the separate, sharper half: `scan --connect` names distribution
**`mcp-audit`**, which is **unclaimed on PyPI** (`/pypi/mcp-audit/json` → 404;
ours is `mcp-audit-scanner`). A supply-chain scanner that detects typosquatting
is telling users to `pip install` a name it does not own. Also at
`mcp_client.py:66` and `scanner.py:412`.

### R60-07 — README says the published feed is unsigned; it is signed (POST-LAUNCH)

`README.md:86` states the advisory feed is "a weekly **unsigned** build … 
(signing is not live yet)". The live feed disagrees:

```
$ curl -fsSL .../feed/index.json | …
feed_version: 1.1
snapshot_version: 5
signing block present: True
signing: {"backend": "minisign", "mode": "key", …}

$ curl -sI .../feed/index.json.sig     # → 200
```

Section 37 of the matrix verifies the live feed *as signed*
(`feed verify --key-alt minisign`) and it passes. This is R32's work
(real minisign project key, `feed-signing` environment, first signed publish
2026-09-07, corrected `index.json.sig` copy at snapshot_version 5) — the
README was simply never updated.

Unusually, this drift **understates** the product: "Signed advisory feed" is a
headline bullet whose own body says signing is not live, on a launch where a
reader could reasonably ding the project for shipping an unsigned feed it
already signs. Not edited here because this prompt forbids touching
`README.md`; flagged for a separate decision.

### R60-06 — `mcp-audit-darwin-arm64` not validated (ENV)

The prompt specifies the `darwin-arm64` binary; this host is an **Intel**
Mac (`x86_64`, i5-10600, macOS 26.6.2), so the arm64 binary fails with "bad
CPU type in executable" before any check runs. Run B used
`mcp-audit-darwin-x86_64` from the same release instead (all four specs differ
only in `EXE(name=...)`, so bundled-data resolution is exercised identically).
**The arm64 artifact remains unvalidated and needs an Apple Silicon host** —
that is the binary `scripts/install.sh` serves to every Apple Silicon user.

---

## Part 4 — Verified-good (no gap, recorded so the next audit doesn't re-derive it)

- **80-column rendering is clean.** `scan`, `check`, `lock`, `lock --verify`
  (clean and drifted), `shadow`, and `vet` all render within 80 display
  columns. `killchain` exceeds it, but emits Markdown for pasting into
  Slack/GitHub where long lines are correct — not a width regression.
- **`demo/lock/run.sh` exits 0** with no overflow at `COLUMNS=80`, under both
  the wheel and the binary. The README first screen is sound.
- **Two `POISON-041` findings for one HTML comment is by design** — one per
  matched pattern, differing only in `description` (`Cloud credential
  exfiltration` vs `Behavioral override instructions`). The titles are
  identical, so terminal output reads as a duplicate; cosmetic, recorded in
  Section 53 so the next runner does not file it.
- **Redaction holds** across SARIF, Nucleus, snapshot, and `mcp-lock.json`
  (`grep -c "$(whoami)"` → 0 in all four).
- **`agent-files scan --format json` emits a bare JSON array**, not a
  `ScanResult` object like `scan --format json`. It also has no `--output`.
  Both are consumer-contract inconsistencies rather than defects; noted here,
  not filed.
