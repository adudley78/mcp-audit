# ADR-0005 — `mcp-audit lock`: a committable, reviewable record of approved MCP servers

**Status:** Accepted
**Date:** 2026-09-10
**Deciders:** Adam (product), Cursor (implementation)
**Story:** STORY-0069 (epic EPIC-0006, decisions #2–#4 and #7); design inputs:
`humans/decisions/2026-09-10-decision-7-format-convergence.md` (format convergence, "B"),
`humans/inbox/2026-09-08-pmm-to-po-lock-registry-anchor.md` (ANSWERED 2026-09-10, resolution
provenance),
`humans/decisions/2026-09-10-adr-0005-checkpoint-review.md` (checkpoint review — three changes
folded into §2, §3, §10 below; see "Checkpoint review" note at the end of each affected section)

---

## Context

`pin` and `baseline save` already record MCP server state, but both write to the user config
directory (`<user-config-dir>/mcp-audit/{state,baselines}/`), keyed or scoped by a hash of the
scanning machine's *absolute* config paths. Neither is committable: two developers on the same repo
produce different files, and there is nothing to `git diff` in a pull request. Meanwhile:

- Issue [#88](https://github.com/adudley78/mcp-audit/issues/88) measured that a floating spec
  (`npx -y foo`) resolves to whatever `foo@latest` is on the day the agent happens to launch it — a
  median of 97 transitive installs per server, none pinned anywhere reviewable.
- The Deadbugz campaign showed a server that is clean at review time and rewrites its own tool list
  after the third call — the exact silent-drift shape a review artifact is supposed to catch.
- A contributor (Prachet Poddar) built a working `mcp-lock.json` generator/verifier for the
  *materialised install tree* layer, independently, against the same file name. Decision #7
  (2026-09-10, "B") ratifies format convergence: one file, two independent producers, neither
  vendoring the other.

This ADR is the first step of STORY-0069, written before any lockfile code, per the story's own
instruction and the epic's decision that a wrong format is expensive to unwind once files exist in
the wild.

---

## Decision

### File: `mcp-lock.json`, project root, committed

Not `.mcp.lock` (taken by `mcpguards/mcp-lock`, an incompatible, inactive format — see epic decision
#2). Written by `mcp-audit lock`, read by `mcp-audit lock --verify` and (STORY-0070) `check`/`scan`.

### Top-level shape

```jsonc
{
  "lock_version": 1,
  "generated_by": "mcp-audit/0.17.0",
  "generated_at": "2026-09-10T13:00:00Z",
  "servers": {
    "cursor/github": {
      "client": "cursor",
      "name": "github",
      "config": ".cursor/mcp.json",
      "identity": {
        "command": "npx",
        "args": ["-y", "@modelcontextprotocol/server-github"]
      },
      "package": {
        "ecosystem": "npm",
        "name": "@modelcontextprotocol/server-github",
        "spec_as_written": "latest",
        "range_spec": false,
        "resolved_version": "2026.7.10",
        "resolution": { "method": "dist-tag:latest", "resolved_at": "2026-09-07T09:00:00Z" },
        "integrity": "sha256:e563…",
        "source": "registry"
      },
      "env_keys": ["GITHUB_TOKEN"],
      "header_keys": [],
      "capabilities": ["network_out", "shell_exec"],
      "first_locked": "2026-09-07T09:00:00Z",
      "hashes": { "command": "sha256:…", "args": "sha256:…", "env_keys": "sha256:…" }
    }
  },
  "trees": {},
  "tools": null,
  "checksum": "sha256:<hex>"
}
```

**Ownership boundary, stated once up front because §2/§10 both depend on it:** mcp-audit *owns*
`lock_version`, `generated_by`, `generated_at`, and `servers` — it may write, checksum, and verify
these. `trees`, `tools`, and any top-level key it does not recognise are *foreign* — mcp-audit
preserves them, reports their presence, and never includes them in its own `checksum` or claims to
have verified their contents. Ownership, not schema position, is what `checksum` covers (§10) and
what "byte preservation" (§2) is checked against.

### 1. Section provenance (decision #7, MUST)

Every top-level section that is not part of the fixed schema header carries an explicit producer and
schema version, so a reader identifies a section by its declared identity, never by position or by
guessing which tool wrote it:

```jsonc
"trees": { "_producer": "mcp-lock-tree-gen", "_schema_version": 1, "...": "..." }
```

`mcp-audit` writes `servers` (this story) and the empty `trees: {}` stub (a section it declares but
does not populate — see §5). Any section mcp-audit did not write and does not recognise is preserved
under its own key, untouched, and reported by `lock --verify` as `unknown section: <key> (preserved,
not validated)`. This is deliberately more explicit than the story's plain `"trees": {}"` placeholder:
the `_producer`/`_schema_version` pair is what lets `lock` (mcp-audit's own regeneration path)
distinguish "empty because nobody has run the tree generator yet" from "written by some other tool
under a name mcp-audit doesn't recognise," so it never overwrites the latter.

### 2. Byte preservation (decision #7, MUST)

**Checkpoint review, item 2 — folded in.** The original draft defined preservation as "re-serialise
the parsed value" and tested it against a fixture (non-ASCII, mixed key order, a float) narrow
enough to pass anyway. Re-serialising *any* parsed JSON value — through a bespoke writer or through
`canonicalize()` — is not byte preservation in general: `1.20` parses to the same number as `1.2`
and both re-emit as `1.2`; a bespoke writer with `ensure_ascii=True` changes `é`'s bytes even though
the value is unchanged. A test built on a fixture that happens not to exercise those cases passes
for a narrower reason than the claim it is meant to guard — exactly the failure shape this project
has been cataloguing all quarter, now caught before it shipped instead of after.

**The fix: preservation is defined at the canonical-value layer, and the on-disk format commits to
being canonical, so there is no other layer for it to be lost at.** Concretely, two rules:

1. **The invariant that is checked is canonical-form equality, not raw-substring equality.** For any
   top-level section mcp-audit does not own (§ownership boundary above), preservation means
   `canonicalize(new_value) == canonicalize(old_value)` whenever mcp-audit did not intend to touch
   it — reusing the exact `advisory/canonical.canonicalize()` the checksum already uses. RFC 8785
   pins precisely the two things that bite here (ECMAScript number formatting, JCS string escaping),
   so this is a real, checkable invariant: any RFC 8785–conformant implementation, in any language,
   computes the same canonical bytes for the same value. That is what makes Prachet Poddar's offline
   replay of `trees` verifiably byte-identical against mcp-audit's own output for the sections
   neither tool touches, without either side needing to match the other's pretty-printer.
2. **mcp-audit's on-disk write of the whole file is itself produced by rendering every top-level
   section through this canonical form** — not through an ad hoc `json.dumps(indent=2)` pass over
   a re-derived model. Because canonical form is a pure function of value, a section neither
   producer has touched since it was last written reproduces identical bytes on every subsequent
   write, by construction, regardless of which producer (or language) wrote it originally. There is
   no longer an "original formatting" for a re-serialisation to diverge from, because the format
   itself has exactly one valid serialisation per value.
3. **Size-bound failure mode (ties into §10's checkpoint-review item 3):** `servers` is
   canonicalized directly — it is proportional to server count (tens, not thousands) and never
   approaches `advisory/canonical.MAX_NODES`. Assembling the whole on-disk document (rule 2) does
   canonicalize `trees` along with everything else; if `trees` alone is large enough to raise
   `CanonicalError` (a legitimately huge materialised install tree), `lock` and `lock --verify` both
   fail cleanly — one message naming the oversized section and stating this is mcp-audit's own
   processing limit, not a defect in the lock file, exit 2 — **never a bare traceback, and never a
   silent write of a corrupted or truncated file.** A future release may add a documented
   `--exclude-trees`-style escape hatch if this bound is hit in practice; this story does not
   speculatively build one.

Implementation: the writer parses the existing file (if present), replaces only `servers` (and,
outside the checksummed body, `generated_at`) with newly-derived values, and re-emits the resulting
document through `canonicalize()` as a whole, catching `CanonicalError` at that single call site to
produce the clean, section-naming failure in rule 3 rather than letting it propagate as a
traceback. `docs/lock.md` states rule 2 as a requirement on the *file format*
itself — any producer targeting `mcp-lock.json`, not just mcp-audit's own writer, is expected to
serialise sections in RFC 8785 canonical form for the same cross-implementation guarantee, so
Prachet Poddar's generator can meet the same bar rather than mcp-audit's writer being the only thing
that honours it. `test_lock_writer.py::test_unknown_section_canonical_form_preserved` asserts
canonical-form equality (not raw-byte equality) across a `lock` run that adds one server, against a
fixture chosen specifically to include a value RFC 8785 normalises differently from Python's default
`json.dumps` (a trailing-zero float, a non-ASCII key) — the case the narrower original test would
have missed. `test_lock_writer.py::test_oversized_foreign_section_fails_cleanly` pins the failure
path with a synthetic `trees` block sized past a monkeypatched `MAX_NODES`, asserting a clean
`typer.Exit(2)` naming the section rather than an uncaught `CanonicalError`.

### 3. Honest partial verification (decision #7, MUST — "the one that matters")

`lock --verify`'s output and exit code MUST NOT imply anything about `trees` was checked. Concretely:

- `lock --verify` validates that `trees` (if present) parses as an object and carries a `_producer`
  key; it does **not** open a `node_modules`-equivalent, does not hash any file inside `trees`, and
  does not compare it to a live install.
- **Checkpoint review, item "smaller, worth fixing" — folded in.** The rule is general, not
  `trees`-specific: the verify summary line names **every** top-level section present that is not
  in mcp-audit's owned set (`servers` — see ownership boundary above), not a hardcoded string. A
  future foreign section (e.g. a `resolutions` sidecar some other tool adopts) is caught by the same
  rule instead of silently falling back to `Lock: N servers verified` unqualified, which is the
  exact misreading §3 exists to prevent. Concretely: `unverified = sorted(top_level_keys -
  OWNED_KEYS - STRUCTURAL_KEYS)` (`STRUCTURAL_KEYS = {lock_version, generated_by, generated_at,
  checksum}`); when `unverified` is empty the line is `Lock: N servers verified`; otherwise
  `Lock: N servers verified; not verified: trees (see docs/lock.md)` naming each entry in
  `unverified`. `docs/lock.md` names the external command for `trees` specifically (Prachet
  Poddar's generator, credited as author) once it has a documented invocation; until then the
  section-level message says "see docs/lock.md#trees" rather than naming an unpublished command.
- `mcp-audit lock` (mcp-audit's own tool) never produces `trees` content and never claims to. It is
  structurally incapable of doing so — populating it needs a real package-manager install, and
  mcp-audit executes nothing (epic decision #7's stated reason for the split). This constraint is
  what makes it safe to run against a repository you do not trust, and the ADR treats it as a
  feature, not a gap to apologize for.

This closes the defect class named in decision #7: a verifier returning clean over a section it
cannot read (his deprecated-version fallback, our own swallowed deps.dev 404 — PR #96 — his
vanishing conflicts block, his `resolvedVersions` collision). `test_lock_verifier.py` includes a
test that asserts the summary string names every unverified section present (parametrized over
`trees` today and a synthetic second foreign key, to keep the rule proven general rather than
`trees`-specific), so a silent, all-clear-looking exit is a caught regression, not a shipped one.

### 4. Forward compatibility (decision #7, MUST)

An unrecognised top-level key is preserved verbatim (§2) and reported as `unknown section: <key>`
at INFO level — never an error, never a reason to fail `lock` or `--verify`. `tools` is reserved
(schema stub, `null` when absent) for a future `--connect`-derived tool-contract-hash layer; writing
it is out of scope for this story (STORY-0069's "Out-of-bounds").

### 5. `generated_at` outside the checksummed body (resolves STORY-0069 Open Question #2)

The `checksum` field is computed over the JCS-canonical bytes (reusing
`advisory/canonical.canonicalize`) of mcp-audit's *owned* sub-document — `{lock_version,
generated_by, servers}` — with `generated_at` never part of that sub-document in the first place
(see §10 for why the body is a sub-document rather than the whole file). Reasoning:

- The lock's entire value is being reviewable in a pull request. A field that changes on every
  no-op regeneration (a scheduled CI re-lock that finds nothing different) spends exactly the
  property the format was bought with — every such run would otherwise produce a one-line diff with
  no security content, training reviewers to skip the file.
- Re-dating detection is not lost by this choice, it is *correctly absent*: a re-dated file with an
  unchanged body has an unchanged body checksum, because the body did not change. That is the right
  answer, not a gap — "someone re-ran the tool with no drift" and "someone tampered with the
  timestamp alone" are the same non-event from a security standpoint.
- `checksum` still catches the case that matters within its own scope: any change to `servers`
  invalidates it. It does **not** catch an edit inside `trees` — that is by design, not a gap; see
  §10's checkpoint-review note for why a single whole-document checksum was rejected.

Implementation: `writer.py` builds `{lock_version, generated_by, servers}` as its own value (never
including `generated_at` or `checksum`), canonicalizes and hashes that sub-document, then assembles
the full on-disk document (owned fields + `generated_at` + foreign sections + `checksum`) around it
for the write.

### 6. `resolved_at` changes only on an actual version change (resolves STORY-0069 §"Given `lock`
runs twice with no changes")

Per-entry `resolution.resolved_at` is a **write-on-change** field, not a write-on-run field. The
writer diffs the newly-resolved `resolved_version` against the existing entry's value before
deciding whether to touch `resolved_at`:

- Same version resolved again → the entire `package` sub-object (including `resolved_at`) is
  copied byte-for-byte from the existing entry. Nothing in that server's record changes.
  `resolution.method` is also left untouched even if it would resolve identically via a different
  path (e.g. `known_hashes` became available where it previously fell back to `registry`) — a
  method change with no version change is deferred to the next version change, so a re-lock's diff
  never shows two fields moving for the reason "time passed" alone.
- Different version resolved → `resolved_version`, `resolution.resolved_at`, `integrity`, and
  `resolution.method` are all rewritten to the new resolution, and `hashes` is recomputed from the
  current `ServerConfig`.

This is the fix for the churn the ANSWERED inbox note identifies: a weekly CI re-lock against an
unpinned `latest` spec that has not actually moved must be a no-op diff, or the diff trains
reviewers to stop reading it — the identical failure mode as putting `generated_at` inside the
checksum. `test_lock_writer.py::test_resolved_at_stable_when_version_unchanged` pins this;
`test_lock_writer.py::test_resolved_at_updates_on_version_change` pins the other side so the
write-on-change branch itself stays exercised.

### 7. Per-entry resolution provenance, no sidecar (resolves the registry-anchor inbox note)

Each entry's `package.resolution` object records **how** the version was reached and **when**:

```jsonc
"resolution": { "method": "dist-tag:latest", "resolved_at": "2026-09-07T09:00:00Z" }
```

`method` ∈ `{"dist-tag:latest", "exact-pin", "known_hashes", "unresolved"}` (`"exact-pin"` when
`spec_as_written` was already an exact version — no resolution needed, `resolved_at` is
`first_locked`; `"unresolved"` under `--offline` or network failure — `resolved_version: null`).

No sidecar file. The inbox note's own corrected reasoning is adopted verbatim: Prachet Poddar's
964 KB snapshot artifact is proportionate to a full dependency-tree lock (thousands of transitive
versions per lock, `playwright` alone contributing 5,676); mcp-audit locks named top-level servers,
so the equivalent state is a handful of dist-tag resolutions — a field per entry, not a file beside
it. Adopting a sidecar would import a cost that only the *trees* layer's scale justifies, onto a
layer that does not have that scale.

**Correction the note made against itself, restated here because it changes what `--verify` MUST
do:** default `lock --verify` is fully offline (epic decision #4) and compares the lock only against
the current configs — it never asks the registry, so registry/dist-tag movement cannot cause a
default `--verify` to fail. That failure mode belongs to **`lock` regeneration**, not verification:
re-running `lock` a week later against an unchanged config can legitimately produce a version bump
because `latest` moved, and §6 above is what keeps that bump from also being timestamp noise.
`--resolve` is the opt-in path that asks "has anything drifted, including the registry" at verify
time (§8), under its own finding ID, never merged with offline config-drift findings.

### 8. What `--verify` checks, offline and with `--resolve`

| Mode | Compares lock against | Network | Finding IDs on drift |
|---|---|---|---|
| `lock --verify` (default) | current on-disk configs only: identity, env/header key names, presence/absence | none | LOCK-001 (drifted), LOCK-002 (unlocked server present), LOCK-003 (locked server missing) |
| `lock --verify --resolve` | the above, **plus** the current registry resolution of every floating/range spec vs. the locked `resolved_version`/`integrity` | npm/PyPI (same policy as `fix --fix-type pinning` / `vet`) | adds LOCK-004 (resolution drifted; CRITICAL when the *same* version now hashes differently — a republished artifact) |
| always | mcp-audit's own owned-section `checksum` (§10) against its recomputed value | none | LOCK-005 (mcp-audit's own record — header + `servers` — tampered or hand-edited) — short-circuits all other checks, exit 2 |

A person reading a red CI job can tell which row produced it from the finding ID alone: LOCK-001/002
/003 are config drift (a human changed something and it wasn't approved through the lock); LOCK-004
only exists under `--resolve` and is registry drift (the ecosystem moved under an unpinned spec).
`docs/lock.md` states this table verbatim, per the ANSWERED note's requirement #3.

**Checkpoint review, item 1 — folded in.** LOCK-005 evaluates mcp-audit's own `checksum` only, which
covers `{lock_version, generated_by, servers}` (§10) — never `trees` or any other foreign section.
A run of Prachet Poddar's generator that (as designed) rewrites only `trees` never changes anything
`checksum` covers, so it never trips LOCK-005. Regenerating `trees` is not tampering; it is the
other producer doing its job. If a foreign section carries its own producer-defined integrity field,
mcp-audit preserves that field byte-for-byte (§2) and never evaluates it — verifying it is that
producer's tool's job, not `lock --verify`'s, and `docs/lock.md` says so explicitly so nobody expects
LOCK-005 to catch a `trees` edit.

An `unresolved` entry (`source: "unresolved"`, e.g. written under `--offline`) is never silently
treated as verified: every `lock --verify` run (default or `--resolve`) prints one WARN line per
unresolved entry alongside the `ok`/finding lines, so a lock that was written offline can never
present a clean summary indistinguishable from a fully resolved one. This is the same "plausible
answer instead of a complaint" failure decision #7 names from the #88 correspondence, applied to
mcp-audit's own resolution state instead of `trees`.

### 9. Identity canonicalization

- **stdio**: `identity = {"command": ..., "args": [...]}`, exact match, mirroring GitHub's
  `serverCommand` semantics (`npx -y evil-mcp` and `npx -y evil-mcp --flag` are different
  identities — no prefix matching, stated so STORY-0071's export/evaluation and this lock never
  disagree on what "the same server" means).
- **remote**: `identity = {"url": <canonical>}` — scheme lowercased, default port dropped, trailing
  slash normalized, query string stripped *after* credential redaction (a token in the query string
  is redacted before canonicalization touches it, not silently dropped as a side effect of stripping
  the query). One pure, exported, unit-tested function (`lock/identity.py::canonicalize_url`) —
  STORY-0071 imports it rather than re-implementing GitHub's matcher semantics a second time.

### 10. Checksum — scoped to what mcp-audit owns

**Checkpoint review, item 1 — folded in, this is "the one that has to change."** The original draft
checksummed the *whole document*, including `trees`, and mapped any mismatch to LOCK-005
(tampered, exit 2). Walk the sequence the format was designed for: `mcp-audit lock` writes the file
and its checksum; Prachet Poddar's generator runs exactly as designed and writes `trees`;
`mcp-audit lock --verify` recomputes the whole-document checksum, finds a mismatch because `trees`
changed, and reports **tampered**. The first legitimate use of the two-independent-producer format
that decision #7 exists to enable would fail closed and call the other producer an attacker — the
"security event and a Tuesday reported identically" failure, this time built into the format rather
than found in it later.

**The fix: checksum scope matches ownership scope.** `checksum` is `sha256:<hex>` of
`advisory/canonical.canonicalize()` applied to the sub-document `{lock_version, generated_by,
servers}` only — never the whole file, never `generated_at` (§5), never `trees`/`tools`/any foreign
or unrecognised key. Consequences of this scoping:

- Regenerating `trees` never disturbs mcp-audit's `checksum` — it is not in the input at all, so
  there is nothing for that regeneration to invalidate.
- LOCK-005 keeps one, single, unambiguous meaning: *someone edited mcp-audit's own record.* It
  cannot also mean "someone edited a section mcp-audit does not read," because that section is
  outside its input by construction.
- §3's honest-partial-verification rule gets stronger, not weaker, from this: mcp-audit is no
  longer implicitly claiming to detect tampering in a section (`trees`) that §3 already says it
  cannot validate. The original draft claimed both — "an edit to `trees` invalidates `checksum`"
  in §10, and "mcp-audit never validates `trees`" in §3 — and those two claims contradict each
  other. Scoping `checksum` to owned sections removes the contradiction instead of leaving it for
  someone to notice at incident time.
- **Size bound (checkpoint review, item 3 — confirmed here, not left unexamined).** Because
  `checksum`'s `canonicalize()` call only ever sees `{lock_version, generated_by, servers}`, its
  input is bounded by server count — tens, not thousands — and can never approach
  `advisory/canonical.MAX_NODES` (100,000) regardless of how large a populated `trees` section is
  (Prachet Poddar's own file is 206 KB at fourteen servers; a monorepo with ten times the servers
  populating `trees` plausibly would exceed that bound if `trees` were in scope, and previously it
  was). The only remaining path that touches `trees`'s content at all is the byte-preservation
  write path (§2, rule 3), which has its own explicit `CanonicalError` catch and fails cleanly
  (naming the oversized section, exit 2) rather than with a bare traceback or a silently corrupted
  file — a deliberately simpler response than attempting a partial write, chosen because a failed
  `lock` run is recoverable and a corrupted one is not.

`docs/lock.md` states the ownership boundary plainly: an edit inside a foreign section is that
producer's business, not mcp-audit's, and `lock --verify` says so rather than being silent about
the scope of what it just checked.

### 11. What is deliberately excluded from this story

- **`trees`**: reserved key, schema-validated for shape only, never populated by mcp-audit, never
  diffed against a real install. Credited to Prachet Poddar in `docs/lock.md` once a documented
  external command exists to point at.
- **`tools`**: reserved as `null`; needs `--connect`-derived tool-contract hashes, not in scope.
- **Signing**: git history is the audit trail for a committed file; a signed lock is a future,
  separate decision, not blocked by anything here.
- **Runtime enforcement**: permanent non-goal (epic decision #6). The lock is a record checked at
  `lock`/`scan`/`check`/CI time; enforcing it against a running client is explicitly out of lane.
- **Semver range resolution**: `lock` never computes a highest-satisfying version. A range spec
  (`foo@^1.2.3`) is recorded verbatim in `spec_as_written`, resolved exactly like `latest` via
  `vulnerability/resolver.resolve_latest_version()`, and flagged `range_spec: true` (PR #96's
  `is_version_range()` — the one resolver, not the unverified duplicate in
  `fixer/strategies/pinning.py`, which this story must not add a third copy of).

---

## Consequences

- `mcp-lock.json` is safe to commit: no absolute paths, no env/header values, no `raw` config block,
  no machine hostname. A test greps the written file for `$HOME`, the OS username, and any
  `SECRET_PATTERNS` match and fails on a hit (same class as the v0.15.0 SARIF leak fix).
- Two no-op `lock` runs in a row produce a byte-identical file except `generated_at` (§5) and, only
  for entries whose resolved version actually changed, `resolution.resolved_at`/`integrity` (§6).
  This is the property that makes the file diff-reviewable rather than diff-noisy.
- `lock --verify`'s exit code and message vocabulary are permanently scoped to what it can see
  offline unless `--resolve` is passed; a green default `--verify` never implies the registry was
  consulted, and a green result on a lock with a populated `trees` (or any other foreign) section
  never implies that section was checked — the summary line names every unverified section present,
  generically, not `trees` by name (§3). Both are enforced by dedicated tests, not by convention
  alone.
- `checksum`'s scope matches `lock --verify`'s validation scope exactly: both cover
  `{lock_version, generated_by, servers}` and neither covers `trees`/`tools`/foreign keys. This
  means a legitimate run of the #88 generator against a locked repo — write `trees`, nothing else —
  never trips LOCK-005, and LOCK-005 keeps one meaning (mcp-audit's own record was tampered) instead
  of two contradictory ones.
- Byte preservation of a foreign section is a checkable, cross-language invariant (canonical-form
  equality via `advisory/canonical.canonicalize()`), not a byte-identical-output claim resting on
  matching some particular writer's incidental formatting choices — with a clean, section-naming
  failure (never a traceback, never a partial write) when a foreign section is too large to
  canonicalize safely.
- STORY-0070 (auto-verify in `check`/`scan`, `fix --fix-type pinning` writing the resolved version
  into the config) and STORY-0071 (allowlist export using the same `identity` canonicalization) build
  directly on §9 and the `verify(root) -> list[Finding]` function shape without needing a second ADR
  — this ADR is the durable record for all three stories per the epic's sequencing.
- `EXPERIMENTAL` for one release (v0.17.0): `lock_version` may change before it is frozen at 2;
  `docs/lock.md` and `--help` both say so, matching how the advisory feed shipped.
- **Trade-off, stated plainly:** RFC 8785 canonical form has no insignificant whitespace, so the
  on-disk `mcp-lock.json` is compact rather than indented — a real cost against "reviewable like
  `package-lock.json`" for a human reading a raw `git diff`. This is accepted because the
  alternative (pretty-printing) is not a cross-language standard and reintroduces exactly the
  byte-divergence risk §2 exists to close, the moment a second implementation writes the file.
  `docs/lock.md` documents a `git diff` `textconv` (`jq` or `python -m json.tool`) so reviewers get
  an indented view without the on-disk format giving up its determinism guarantee.

## Rejected alternatives

- **Registry-state sidecar** (Prachet Poddar's own snapshot shape, considered per the inbox note):
  rejected — proportionate to a full transitive-tree lock, not to a named-server lock; would add a
  cost with no matching benefit at this layer (§7).
- **`generated_at` inside the checksum**: rejected — makes every no-op re-lock a diff with no
  security content, the exact plurality-instability failure raised (from the other direction) in
  the inbox note (§5).
- **A single whole-document checksum** (original draft; rejected at the 2026-09-10 checkpoint
  review): reports a legitimate `trees` regeneration by an independent producer as tampering
  (LOCK-005), the first real use of decision #7's two-producer format failing closed and calling
  the other producer an attacker. Rejected in favor of scoping `checksum` to `{lock_version,
  generated_by, servers}` only (§10), which also incidentally bounds the checksum's
  `canonicalize()` call away from `MAX_NODES` regardless of `trees` size.
- **"Byte preservation" defined as re-serialising parsed values** (original draft; rejected at the
  same checkpoint review): passes a narrow fixture (trailing-zero floats, non-ASCII bytes) for a
  reason unrelated to the general claim it purports to guard. Rejected in favor of defining
  preservation as canonical-form equality (§2), which is real, checkable across independent
  implementations, and — because the on-disk format itself commits to canonical serialisation —
  leaves no "original formatting" layer for a re-write to diverge from.
- **Vendoring or reimplementing Prachet Poddar's tree generator**: rejected outright by decision #7;
  not reconsidered here. mcp-audit structurally cannot produce `trees` (no package-manager
  execution), so implementing it would mean building the one capability the tool promises not to
  have.
- **A single `BaseAnalyzer` subclass for lock verification**: rejected in favor of a plain
  `verify(root) -> list[Finding]` function — lock verification operates on the lock file plus the
  full discovered server list, not a single `ServerConfig`, the same shape reason `rug_pull.py` and
  `toxic_flow.py` already use `analyze_all` instead of `analyze`.

---

## Addendum (STORY-0070, EPIC-0006 v0.17.0 R49): lock adoption surface

This section extends the decision above rather than replacing any of it. STORY-0070 wires `lock`
into the commands practitioners already run daily (`fix`, `check`, `scan`), plus CI/pre-commit
adoption paths, without a second ADR — the story's own scope note says this addendum is sufficient.

- **`fix --fix-type pinning` gains VULN-UNPINNED/LOCK-004.** The existing `PackagePinningStrategy`
  (SC-001/002 typosquat replacement) is extended, not forked: a new `lock_doc` constructor parameter
  lets the strategy read a server's `package.resolved_version` from the nearest ancestor lock (via
  a new `lock/discovery.py::find_lock_for()`) with zero network calls, falling back to the existing
  live npm/PyPI resolution helpers when no lock entry covers the server. **Decision, not literal
  compliance:** STORY-0070's acceptance-criteria text said `uvx foo` should pin as `foo==<version>`;
  the shipped code pins `foo@<version>` instead, for both npm and uvx, because
  `tests/test_fixer.py::test_apply_with_mocked_pypi_registry` (pre-existing, passing) and
  `analyzers/supply_chain.py::extract_pypi_package`'s own docstring already establish `@`-syntax as
  the one pin grammar every other reader in this codebase (`vulnerability/resolver.py` included)
  assumes. Introducing a second, inconsistent `==` syntax alongside it would have silently broken
  round-trip parsing elsewhere for no benefit; the acceptance text was read as directional intent
  ("pin to an exact version"), not as a literal byte-for-byte spec.
- **`check`/`scan` auto-verify `mcp-lock.json`, no flag required; `--no-lock` opts out.** A new
  `lock/auto_verify.py::auto_verify()` groups a scan's servers by nearest ancestor lock (monorepo-safe
  — a subtree's own lock is used, never a parent's) and merges every group's `VerifyResult` into one
  `LockStatus` (a new model on `ScanResult`, added the same way `FeedStatus` was for the advisory
  feed). **Deliberate deviation from every other post-score `_apply_*` scan stage**
  (baseline/governance/SAST/extensions/agent-files/project — all appended *after*
  `calculate_score()` runs and never affect the grade, per `cli/scan.py`'s own documented
  convention): STORY-0070's acceptance criteria explicitly require LOCK findings to affect the
  grade, so `_apply_lock_verification` recomputes `result.score` after appending LOCK-* findings,
  using whatever scoring weights the main pipeline already resolved from a governance policy.
  `check` has no governance-weight plumbing today, so its copy of the same logic always uses
  `calculate_score`'s bare defaults — matching the weights `run_scan` itself used for the
  un-recomputed score.
- **`--if-present` (new `lock --verify` flag) is the mechanism behind safe CI/pre-commit adoption.**
  A missing lock file becomes a dim, exit-0 informational skip instead of the normal exit-2 error.
  Considered and rejected: a `language: script` pre-commit hook with a bash wrapper checking
  `[ -f mcp-lock.json ]` before invoking `mcp-audit` — pre-commit does not guarantee two hooks with
  different `language:` values share an isolated venv/PATH, risking a `command not found` failure
  for the wrapper, whereas today's single hook works only because `language: python` triggers
  pre-commit's own isolated-venv install for that specific hook. `--if-present` keeps `entry:
  mcp-audit`/`language: python` unchanged for the new `mcp-audit-lock-verify` hook and the Action's
  `lock-verify` step alike, and is a generically useful, independently testable CLI addition rather
  than duplicated ad hoc logic in two YAML files.
- **The Action's `lock-verify` step fails regardless of `severity-threshold` "for free."**
  `lock --verify` has no severity-threshold concept of its own — every finding it can produce
  (`LOCK-001/002/004/005`) is already fail-worthy drift — so no special-casing was needed to satisfy
  that acceptance criterion; `fail-on-findings` is still honoured, matching the existing scan step's
  gating pattern exactly.
- **`diff` lock-awareness was split into a follow-up, not shipped in this PR.** The story explicitly
  pre-authorised this ("if `diff` turns out larger than S, split it into its own PR and say so").
  Wiring `mcp-lock.json` as a first-class `diff` input touches `loader.py` (a third load path
  alongside directory/JSON-file/git-SHA), `comparator.py` (a new comparison axis: locked vs. current
  resolution, independent of config-level changes), `risk.py`, and `render.py` (MCP-terms rendering
  plus the "lock updated to match" consistent-change wording) — enough surface, with its own
  fixture/test needs, to warrant its own review rather than riding along with the fixer/check/scan/
  Action/pre-commit surface above. Tracked as an open follow-up, not a dropped requirement.
- **Addendum (R56, v0.18.0): §4's "never a reason to fail" MUST is refined, not reversed.**
  §3/§4 above establish that `lock --verify` never *claims* to have checked a foreign section, and
  §4 says an unrecognised key is never a reason to fail. Issue [#88](https://github.com/adudley78/mcp-audit/issues/88)
  (Finding 2) pointed out this MUST had a gap in practice: the printed summary and JSON already
  named an unresolved entry or a populated foreign section honestly, but the *exit code* — the only
  thing CI reads — stayed 0 regardless, reproducing the exact "clean result over a section it
  cannot read" defect this ADR exists to prevent. The fix distinguishes two cases §4's original text
  did not: mcp-audit's own default stub (`trees: {}`, `tools: null`, written on every `lock` run —
  §1/§11) still never fails the exit code, because mcp-audit *did* write that value and there is
  nothing outstanding to flag; a section genuinely populated by another producer, or an unresolved
  package version, now does fail the exit code (`1`) unless explicitly waived with
  `--allow-unverified`, which names exactly what it waives and never waives an actual LOCK-001/
  002/004/005 finding. See `docs/lock.md`'s "Unverified state now fails the exit code" section for
  the practitioner-facing detail and the CHANGELOG for the exact behaviour-change note.
- **The `trees`-introspection acceptance criterion ("`check` reports `trees: N servers, M packages`
  in the `Lock:` line") was declined, not implemented.** Counting servers/packages inside `trees`
  would require assuming a specific internal shape for Prachet Poddar's independently-owned,
  undocumented format — precisely the boundary §3/§7 of the original decision (above) already
  drew mcp-audit back from ("mcp-audit structurally cannot produce `trees`... implementing it would
  mean building the one capability the tool promises not to have" extends naturally to *parsing* it
  with assumed internal structure, not just to *writing* it). What ships instead is the existing,
  already-general `unverified_sections` mechanism from STORY-0069 (`lock/model.py`) — `check`'s
  `Lock:` line surfaces "not verified: trees" when the section is present, with no assumption about
  its contents. Tracked as a declined-with-reasoning gap, consistent with `CLAUDE.md`'s
  established pattern for scope boundaries the codebase has already drawn once and should not
  redraw quietly a second time.
