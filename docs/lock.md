# `mcp-audit lock` — a committable, reviewable record of approved MCP servers

> **EXPERIMENTAL for v0.17.0.** `lock_version` (currently `1`) may change before the format is
> frozen at version `2`. Treat `mcp-lock.json`'s shape as subject to change across a minor release
> until this note is removed — the same posture the advisory feed shipped with.

`mcp-audit lock` writes `mcp-lock.json` at your project root: a small, deterministic, git-committable
record of exactly which MCP servers your team has approved, what package version each one resolved
to, and a checksum that catches unreviewed edits. `mcp-audit lock --verify` checks the current
configuration against it and is the command CI runs to fail a pull request that changes an MCP
server without updating the lock.

See [ADR-0005](decisions/ADR-0005-mcp-audit-lock.md) for the full design rationale. This document is
the practitioner-facing how-to.

---

## Why this exists, and how it differs from `pin` / `baseline`

`pin` and `baseline save` already record MCP server state — but both write to the **user config
directory** (`<user-config-dir>/mcp-audit/{state,baselines}/`), keyed by a hash of the scanning
machine's absolute config paths. Two developers on the same repo produce different files, and there
is nothing to put in a pull request. `lock` closes that gap:

| | `pin` | `baseline save` | `lock` |
|---|---|---|---|
| Storage | user config dir (machine-local) | user config dir (machine-local) | **project root, committed to git** |
| Compared by | `diff` (single latest pin) | `baseline compare` / `scan --baseline` (named, multiple) | `lock --verify` (offline by default) |
| Reviewable in a PR | no | no | **yes** — deterministic, diff-friendly |
| Package version resolution | no | no | **yes** — resolves floating specs (`latest`, `^1.2.3`) to a concrete version and (optionally) verifies it against the registry |
| Env/header values | not applicable | key names only, never values | key names only, never values |
| Runtime enforcement | no | no | no — checked at `lock`/CI time only, never enforced against a running client |

Use `pin`/`baseline` for machine-local, ad hoc drift checks. Use `lock` when you want the set of
approved MCP servers to be part of your repository's review history, the same way `package-lock.json`
or `poetry.lock` is.

`lock` does not replace `pin` or `baseline` — their behavior is unchanged by this feature.

---

## Quick start

```bash
# Write mcp-lock.json from the project's MCP configs
mcp-audit lock

# Commit it
git add mcp-lock.json && git commit -m "Lock approved MCP servers"

# In CI, or before opening a PR, verify nothing drifted
mcp-audit lock --verify
```

`lock` (no flags) discovers project-scoped MCP config files under the given path (same walk as
`scan --project`: `.mcp.json`, `.cursor/mcp.json`, `.claude/settings.json`,
`.claude/settings.local.json`, `.vscode/mcp.json`, `.amazonq/mcp.json`, etc.), resolves each server's
package version, and writes `mcp-lock.json` next to the project root.

---

## What's in the file

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
      "identity": { "command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"] },
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

**Never in the file:** environment variable *values*, header *values*, absolute filesystem paths,
the scanning machine's hostname or username, or the raw config block. Only key names (`env_keys`,
`header_keys`) and hashes are recorded — the same secrecy posture as `baseline save`. A dedicated
test (`test_no_absolute_paths_home_username_or_secrets_in_output`) greps every written lock file for
`$HOME`, the current OS username, and any `SECRET_PATTERNS` match, and fails the build on a hit.

**On-disk format:** `mcp-lock.json` is written in [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785)
JCS canonical form — the same canonicalizer the advisory feed uses (`advisory/canonical.py`) — so the
file has no insignificant whitespace and is compact rather than indented. This is a deliberate
trade-off (see ADR-0005 Consequences): canonical form is the only way to guarantee two independent,
possibly non-Python implementations produce byte-identical output for a section neither one touched.
For a readable `git diff`, add a `textconv` filter:

```gitattributes
# .gitattributes
mcp-lock.json diff=json-pretty
```

```ini
# .git/config or ~/.gitconfig
[diff "json-pretty"]
    textconv = python3 -m json.tool
```

### Ownership boundary: `servers` vs. `trees`/`tools`

mcp-audit **owns** `lock_version`, `generated_by`, `generated_at`, and `servers` — it writes,
checksums, and verifies these. `trees` and `tools` are **reserved, foreign** sections:

- `trees` is reserved for [Prachet Poddar](https://github.com/pracheteer)'s independent
  `mcp-lock-tree-gen` project, which materializes the full transitive install tree (the equivalent of
  `package-lock.json`'s dependency graph). **mcp-audit never populates `trees`** — it has no
  package-manager execution capability and does not attempt to build one. `mcp-audit lock` always
  writes it as an empty `{}` stub if absent, and preserves it byte-for-byte (in canonical form) if
  another tool has already populated it. Once that generator has a documented public invocation,
  it will be linked here.
- `tools` is reserved as `null` for a future `--connect`-derived tool-contract-hash layer — not
  written by this release.
- Any other top-level key mcp-audit does not recognize is preserved the same way: untouched,
  reported by `--verify`, never checksummed.

`mcp-audit lock`'s own `checksum` field covers **only** `{lock_version, generated_by, servers}` —
never `trees`, `tools`, or any other foreign section. This means running the `trees` generator
against a locked repository never trips `LOCK-005` (tampering) — it is the other producer doing its
job, not an edit to anything mcp-audit owns or verifies.

---

## `mcp-audit lock --verify`

| Mode | Compares lock against | Network | Finding IDs on drift |
|---|---|---|---|
| `lock --verify` (default) | current on-disk configs only: identity, env/header key names, presence/absence | none | `LOCK-001` (drifted), `LOCK-002` (unlocked server present), `LOCK-003` (locked server missing) |
| `lock --verify --resolve` | the above, **plus** the current registry resolution of every floating/range spec vs. the locked `resolved_version`/`integrity` | npm/PyPI (same policy as `fix --fix-type pinning` / `vet`) | adds `LOCK-004` (resolution drifted; **CRITICAL** when the *same* version now hashes differently — a republished artifact) |
| always | mcp-audit's own owned-section `checksum` against its recomputed value | none | `LOCK-005` (mcp-audit's own record — header + `servers` — tampered or hand-edited) — short-circuits all other checks, exit 2 |

`lock --verify`'s exit code and message vocabulary are permanently scoped to what it can see offline
unless `--resolve` is passed. A green default `--verify` never implies the registry was consulted.
A green result never implies a foreign section (`trees`, or any other) was checked — the summary
line names every unverified section present, generically:

```
Lock: 4 servers verified; not verified: tools, trees (see docs/lock.md)
```

or, when there is nothing foreign present:

```
Lock: 4 servers verified
```

An entry that was locked while offline (`source: "unresolved"`, no `resolved_version`) is never
silently treated as verified: every `--verify` run (default or `--resolve`) prints one `WARN` line
per unresolved entry alongside the pass/finding lines, so an offline-written lock can never present
a clean summary indistinguishable from a fully resolved one.

### Unverified state now fails the exit code (R56)

> **Behaviour change, v0.18.0.** Before this change, an unresolved entry or a genuinely populated
> foreign section (e.g. a real `trees` payload from another producer) was reported honestly in the
> printed summary and in JSON — but never affected the exit code, so a CI job reading only the exit
> code saw a clean pass. A pipeline that was green because of this gap **may start failing** after
> upgrading. See [Finding 2 of issue #88](https://github.com/adudley78/mcp-audit/issues/88).

`lock --verify`'s exit code is now `1` when either of the following is true, in addition to an
actual LOCK-001/002/004 drift finding:

- one or more locked entries have `package.source == "unresolved"` (locked while offline, never
  confirmed against the registry), or
- a foreign top-level section (`trees`, `tools`, or any other key mcp-audit does not write) is
  genuinely **populated** — i.e. holds something other than mcp-audit's own default stub
  (`trees: {}`, `tools: null`).

**mcp-audit's own default stubs never trip this.** Every lock file mcp-audit writes always includes
the empty `trees: {}` / `null` `tools` stubs (ADR-0005 §1/§4/§11), and ADR-0005 §4's MUST — "never a
reason to fail `lock` or `--verify`" — still holds for that default case: a project that has never
run a `trees` generator sees no change in exit code from this release.

Use `--allow-unverified` to waive unresolved entries and populated foreign sections from the exit
code, explicitly:

```bash
mcp-audit lock --verify --allow-unverified
```

The waiver **never** hides an actual LOCK-001/002/004/005 finding — only the unresolved/foreign-content
condition. Terminal output names exactly what was waived:

```
WAIVED by --allow-unverified: entry 'cursor/github' — locked with an unresolved version (offline at
lock time) — never confirmed against the registry
```

`--format json` carries the same detail structurally, per item, rather than a single true/false flag:

```jsonc
{
  "waived": true,
  "unverified": [
    {
      "kind": "entry",
      "name": "cursor/github",
      "reason": "locked with an unresolved version (offline at lock time) — never confirmed against the registry"
    }
  ],
  "exit_code": 0
}
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--verify` | off | Verify the existing lock instead of writing a new one |
| `--resolve` | off | With `--verify`, also re-resolve floating specs against the registry (network; produces `LOCK-004`) |
| `--allow-unverified` | off | With `--verify`, waive unresolved entries and populated foreign sections from the exit code (restores exit 0), printing exactly what was waived. Never waives an actual LOCK-001/002/004/005 finding. See "Unverified state now fails the exit code" above. |
| `--accept` | off | Re-write the lock from the current state, preserving each surviving entry's `first_locked` — the explicit "I reviewed the drift" step after a failed `--verify` |
| `--include-user` | off | Also lock user-global configs (for dotfiles repositories) |
| `--offline` | off | Never touch the network while writing the lock |
| `--output / -o` | `<root>/mcp-lock.json` | Write to a custom path |
| `--registry` | bundled | Override the known-server registry |
| `--format / -f` | `terminal` | Output format for `--verify`: `terminal`, `json`, `sarif` |

`--verify` and `--accept` are mutually exclusive (exit 2 if both are given).

---

## CI usage

```yaml
# .github/workflows/mcp-audit-lock.yml
- name: Verify MCP server lock
  run: mcp-audit lock --verify
```

A non-zero exit fails the job, naming exactly which server drifted (`LOCK-001`), which configured
server was never locked (`LOCK-002`), or whether the lock file itself was hand-edited (`LOCK-005`).
`LOCK-003` (a locked server missing from the current config) is reported but does not by itself fail
the exit code — removal is not automatically suspicious.

---

## Two no-op runs produce (almost) the same file

Re-running `mcp-audit lock` when nothing changed reproduces the same `servers` content and the same
`checksum`. Only `generated_at` always changes (it records when the tool ran, deliberately excluded
from the checksum — see ADR-0005 §5), and `resolution.resolved_at`/`integrity` for a given entry only
change if that server's resolved package version actually changed (ADR-0005 §6). This is what keeps
a scheduled CI re-lock producing a diff with real security content instead of training reviewers to
skip the file.

---

## Adoption surface (STORY-0070): fix, check, scan, Action, pre-commit, diff

`lock` composes with the rest of mcp-audit rather than living in its own silo:

- **`mcp-audit fix --fix-type pinning`** now also remediates `VULN-UNPINNED` and `LOCK-004`.
  When a lock exists for the server being fixed, the fix uses the lock's own
  `package.resolved_version` — no network call — so the fix pins to the exact version already
  reviewed at lock time. Without a lock (or offline with no lock entry), it falls back to live
  registry resolution, identical to the existing `SC-001`/`SC-002` typosquat-pinning behaviour. A
  semver range collapsed to an exact pin is called out explicitly in the fix message.
- **`mcp-audit check` and `mcp-audit scan`** auto-verify the nearest ancestor `mcp-lock.json` for
  every scanned server, when one exists — no flag required. `--no-lock` opts out entirely. A
  project with no lock file anywhere sees zero change in behaviour or output. Unlike every other
  post-scoring finding source (baseline drift, governance, SAST, extensions, agent-files), LOCK
  findings **do** recompute the scan score and grade — this is deliberate, not an inconsistency.
  `check`'s one-page verdict gets a `Lock: verified (N servers)` line (or a finding-count summary on
  drift), plus one `WARN` per entry that was locked offline and never confirmed. `check --json` gets
  a `lock_status: {present, verified, findings, checked_servers, lock_paths, unresolved_entries}`
  object mirroring `feed_status`'s shape. A monorepo with several `mcp-lock.json` files verifies each
  project config against its own nearest ancestor lock, never a sibling's.
- **The GitHub Action** (`action.yml`) gains `lock-verify` (default `false`) and `lock-resolve`
  (default `false`). When `lock-verify: true`, the action runs `mcp-audit lock --verify --if-present`
  and fails the step on `LOCK-001`/`002`/`004`/`005` regardless of `severity-threshold` (still
  honouring `fail-on-findings`). A repo with no `mcp-lock.json` yet gets a warning and a passing step
  — turning this input on can never break an existing workflow. When `sarif-output` is also set, lock
  findings are merged into the same SARIF file so Code Scanning shows them alongside everything else.
- **A new `mcp-audit-lock-verify` pre-commit hook** (`.pre-commit-hooks.yaml`) runs
  `mcp-audit lock --verify --if-present` on any commit touching a known MCP config path or
  `mcp-lock.json`. `always_run: false`, so it is silent on unrelated commits. A drifted commit is
  blocked; run `mcp-audit lock --accept` after reviewing the drift to unblock it.
- **`--if-present`** is the flag underpinning both of the above: `lock --verify --if-present` treats
  a missing lock file as a soft, exit-0 skip instead of the normal exit-2 error, so an adoption path
  (Action input, pre-commit hook) can be turned on unconditionally without breaking a repo that has
  not run `mcp-audit lock` yet. Plain `lock --verify` (no flag) keeps its strict exit-2 behaviour for
  direct/explicit CI use.
- **`mcp-audit diff`** lock-awareness (comparing `mcp-lock.json` across two refs in MCP terms) is
  tracked as a follow-up, not shipped in the same change as the above — see the STORY-0070 PR
  description for why it was split out.

---

## Known limitations

- No semver range resolution: a range spec (`foo@^1.2.3`) is recorded verbatim in `spec_as_written`
  and resolved the same way an unpinned `latest` spec is (via the registry's own `latest` dist-tag /
  PyPI's latest-stable), never by computing a highest-satisfying version. `range_spec: true` flags
  this in the entry.
- PyPI package `integrity` is not yet populated (npm tarball hashes are, via the same hasher
  `--verify-hashes` uses); left `null` until a PyPI equivalent ships.
- No signing. Git history is the audit trail for a committed file; a signed lock is a possible future
  addition, not blocked by anything here.
- No runtime enforcement — `lock` is a record checked at `lock`/CI time, never enforced against a
  running MCP client. This is a permanent design decision, not a gap.

See [GAPS.md](../GAPS.md) for the authoritative, continuously updated list.
