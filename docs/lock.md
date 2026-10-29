# `mcp-audit lock` — a committable, reviewable record of approved MCP servers

> **EXPERIMENTAL.** `lock` writes `lock_version` `2` (see [lock_version 2](#lock_version-2)) and
> verifies both `1` and `2`. The name of the `section_digests` field is pending confirmation with
> the `trees` producer ([#88](https://github.com/adudley78/mcp-audit/issues/88)) and may change
> before it is released. Treat `mcp-lock.json`'s shape as subject to change across a minor release
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
`.claude/settings.local.json`, `.vscode/mcp.json`, `.amazonq/mcp.json`, Codex's `.codex/config.toml`,
Gemini CLI's `.gemini/settings.json`, etc.; see [clients.md](clients.md)), resolves each server's
package version, and writes `mcp-lock.json` next to the project root.

Codex and Gemini CLI project files are locked and verified like the others
(STORY-0110). A lock written by an earlier release has no entries for them, so
`lock --verify` (and the automatic check in `scan`/`check`) reports their servers
as LOCK-002 until you review them and re-run `mcp-audit lock`.

Try it: [`demo/lock/`](../demo/lock/) — a small, reproducible fixture that runs this exact sequence
(`bash demo/lock/run.sh`) and asserts every exit code along the way.

---

## What's in the file

```jsonc
{
  "lock_version": 2,
  "generated_by": "mcp-audit/0.23.0",
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
        "spec_as_written": "*",
        "range_spec": true,
        "resolved_version": "2026.7.10",
        "resolution": {
          "method": "dist-tag:latest",
          "resolved_at": "2026-09-07T09:00:00Z",
          "resolution_context": {
            "resolved_at": "2026-09-07T09:00:00Z",
            "latest": "2026.7.10",
            "latest_deprecated": null,
            "npm_major": null,
            "node_version": null
          }
        },
        "integrity": "sha256:e563…",
        "source": "registry",
        "deprecated": null
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
  "section_digests": { "servers": "sha256:<hex>" },
  "checksum": "sha256:<hex>"
}
```

**`package.deprecated`** (added in v0.18.1, STORY-0073): the package registry's own deprecation
notice for `resolved_version`, or `null`. Populated only when resolution actually made a network
call — `resolution.method == "dist-tag:latest"` (a plain `mcp-audit lock` on an unpinned spec, or
`lock --verify --resolve`) — never for an exact pin (no manifest is fetched to read it from) and
never under `--offline`. npm's own `deprecated` field on `dist-tags.latest` is the source; an empty
deprecation string is normalised to `"(no message)"` so a finding always has readable text. PyPI's
JSON API exposes "yanked" only per-release, not on the latest-version object this reads, so it is
never populated for PyPI packages — see `GAPS.md`. A non-null value emits one `SC-005` (MEDIUM,
`analyzer: "supply_chain"`) naming the package, version, and message, printed by both `lock` and
`lock --verify --resolve`. Like every other field in `package`, `deprecated` is owned by mcp-audit
and covered by the `checksum`; `lock_version` stays `1` (an additive field, not a schema break).
Running `lock --accept` after a package goes deprecated re-resolves and records it, exactly like any
other lock update.

### Credentials in a launch line (STORY-0118)

`identity.args` records a stdio server's command and arguments as written, with
one exception: a credential in them (`--api-key VALUE`, URL user info such as
`git+https://user:TOKEN@host/…`, `Password=…` in a connection string, a secret
header, `?token=…`) is recorded as `[REDACTED]` or `[REDACTED-FLAG]`, and the
`package` section never quotes a URL. A launch without a credential is recorded
exactly as before.

`lock --verify` compares the locked identity and the current one in this
redacted form on both sides, so a lock written by an earlier mcp-audit, which
holds the credential verbatim, still verifies without LOCK-001 (run `lock
--accept` to rewrite it without the credential). The cost is that changing only
a credential's value is not drift; `LOCK-013` (LOW) says so for each locked
server whose launch carries one, and `mcp-audit lock` prints the same warning
when it writes the lock. Move the credential to an `env` entry to fix both.
`hashes` in a lock entry are SHA-256 digests of the real values and are not
compared by `lock --verify`.

## lock_version 2

Version 2 (STORY-0116) is the set of changes agreed with the `trees` producer on
[#88](https://github.com/adudley78/mcp-audit/issues/88) (ADR-0005's R59 and R62 addenda). It is
additive: every version-1 field keeps its meaning.

- **`spec_as_written` records a bare spec as `"*"`.** `npx -y foo`, `uvx pkg`, `pipx run pkg` and
  `foo@` name no version. npm reads such a name as the range `*`
  ([npm-package-arg `lib/npa.js`](https://github.com/npm/npm-package-arg/blob/v14.0.0/lib/npa.js),
  `spec = '*'`), not as the `latest` tag, so version 1's `"latest"` overstated what the config said.
  `foo@latest` stays `"latest"`. Resolution is unchanged: both still resolve through the registry's
  `latest` dist-tag, and mcp-audit still implements no range resolver. A spec `lock` does not parse
  (`uvx pkg==1.2.3`, `uvx pkg>=1`) keeps version 1's `"latest"` and resolution, so re-reading it
  can never turn an untouched config into `LOCK-004`.
- **`package.resolution.resolution_context`** records what the registry said when the version was
  picked: `resolved_at`, `latest` (the version `latest` pointed at) and `latest_deprecated` (its
  deprecation notice), plus `npm_major` and `node_version`. Those last two are always `null` in the
  section mcp-audit writes: mcp-audit reads the dist-tag over HTTPS and runs neither npm nor Node.
  As agreed on #88 (ADR-0005 R62), the `trees` producer, which does run npm, is to record its own
  context in its own section; his published spec does not have these fields yet. Context is never
  copied across sections. `resolution_context` is `null` for an exact pin and for an entry locked offline
  (the registry was not consulted). **The context explains why two locks differ; only the resolved
  versions and integrity hashes can regenerate one.** Dist-tags and deprecation flags have no
  queryable history, so a recorded context is not a coordinate anyone can return to.
- **`section_digests`** is a top-level map from section name to `sha256:` + the SHA-256 of that
  section's RFC 8785 encoding. Each producer writes the entries for the sections it produced and
  copies every other entry verbatim (even one that no longer matches: that is the other producer's
  evidence). mcp-audit writes `servers`, and `tools` once `lock --connect` has populated it; it
  never writes `trees`. Any tool can recompute any entry. The map is outside mcp-audit's own
  `checksum`, so another producer adding its entry never trips `LOCK-005`. A `section_digests`
  that is not an object stops `lock` (exit 2) rather than be overwritten.

**Interop limits of the canonical form.** Both the digests and LOCK-012 rely on every producer
writing the same RFC 8785 bytes. Two inputs cannot round-trip between languages and are kept out of
any section a producer digests: integers beyond ±2^53 (mcp-audit writes them exactly; a JavaScript
producer parses them into doubles and writes a different number, so the digest differs), and
strings with a lone UTF-16 surrogate (`"\ud800"`), which have no UTF-8 encoding at all. mcp-audit
never writes either; a section holding a lone surrogate cannot be digested or re-encoded and is
listed as unverified (never passed), and in mcp-audit's own sections it is `LOCK-005`.

Verifying a version-2 lock adds three findings:

| ID | Severity | When | Fails the exit code |
|---|---|---|---|
| `LOCK-010` | INFO | `--verify --resolve`: an entry's `resolution_context` differs from a fresh resolution (`latest`, `latest_deprecated`, `npm_major`, `node_version`) | no; any change to the resolved version or hash is `LOCK-004`, separately |
| `LOCK-011` | HIGH | every verify, including `scan`/`check`: a `section_digests` entry is missing for a section mcp-audit wrote, malformed, names a section that is gone or the envelope (`lock_version`, `checksum`…), or does not match its section | yes, and `--allow-unverified` does not waive it |
| `LOCK-012` | LOW | every verify: the file is not byte-identical to its canonical form (someone pretty-printed it, or an editor added a newline); names up to 16 reformatted sections (then `…`; none above 8 MiB), or `<layout>` | no |

A section matching its digest is still a foreign section mcp-audit has not verified the contents
of: a populated `trees` keeps failing the exit code under R56 (below) unless waived. A section too
large to digest is listed as unverified, never passed.

**Compatibility.** A version-1 lock is verified exactly as before: none of the three checks run,
and a `section_digests` key in a version-1 file is an unrecognised section like any other. The next
`lock` or `lock --accept` rewrites it as version 2 without changing any `first_locked`,
`resolved_at`, `resolved_version` or `integrity`. A lock declaring a version above 2 is refused:
`lock --verify` exits 2 and `scan`/`check` list it as not verified; `lock` will not overwrite it.
mcp-audit 0.22 and earlier read a version-2 lock without error and without `LOCK-005`, but report
`section_digests` as an unverified section, so `lock --verify` there exits 1 unless
`--allow-unverified`. **Upgrade every place that runs `lock --verify` (CI, pre-commit) before you
commit a version-2 lock.**

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

### Ownership boundary: `servers` and `tools` vs. `trees`

mcp-audit **owns** `lock_version`, `generated_by`, `generated_at`, and `servers` — it writes,
checksums, and verifies these — and, once `lock --connect` has populated it, the `tools` section
(see [Tool definitions](#tool-definitions---connect)). `trees` is a **reserved, foreign** section:

- `trees` is reserved for [Prachet Poddar](https://github.com/prachetpoddar)'s independent
  install-tree generator ([`code/mcp_lock.py`](https://github.com/prachetpoddar/mcp-supply-chain-study/blob/v3.16.1/code/mcp_lock.py),
  specified in [`spec/mcp-lock-spec.md`](https://github.com/prachetpoddar/mcp-supply-chain-study/blob/v3.16.1/spec/mcp-lock-spec.md),
  both in his `mcp-supply-chain-study` repository), which materializes the full transitive install tree (the equivalent of
  `package-lock.json`'s dependency graph). **mcp-audit never populates `trees`** — it has no
  package-manager execution capability and does not attempt to build one. `mcp-audit lock` always
  writes it as an empty `{}` stub if absent, and preserves it byte-for-byte (in canonical form) if
  another tool has already populated it.
- `tools` is `null` until `lock --connect` records tool definitions. From then on it is
  mcp-audit's own section, identified by `"_producer": "mcp-audit"` and protected by its own
  `_checksum` (ADR-0005, STORY-0086 amendment). A `tools` section written by any other producer
  stays foreign: preserved untouched, reported by `--verify`, and never overwritten
  (`lock --connect` refuses with exit 2 rather than replace it).
- Any other top-level key mcp-audit does not recognize is preserved the same way: untouched,
  reported by `--verify`, never checksummed.

`mcp-audit lock`'s own `checksum` field covers **only** `{lock_version, generated_by, servers}` —
never `trees`, `tools`, or any other section. (`tools` carries its own `_checksum` instead; see
[Tool definitions](#tool-definitions---connect) for why.) This means running the `trees` generator
against a locked repository never trips `LOCK-005` (tampering) — it is the other producer doing its
job, not an edit to anything mcp-audit owns or verifies.

---

## `mcp-audit lock --verify`

| Mode | Compares lock against | Network | Finding IDs on drift |
|---|---|---|---|
| `lock --verify` (default) | current on-disk configs only: identity, env/header key names, presence/absence | none | `LOCK-001` (drifted), `LOCK-002` (unlocked server present), `LOCK-003` (locked server missing) |
| `lock --verify --resolve` | the above, **plus** the current registry resolution of every floating/range spec vs. the locked `resolved_version`/`integrity` | npm/PyPI (same policy as `fix --fix-type pinning` / `vet`) | adds `LOCK-004` (resolution drifted; **CRITICAL** when the *same* version now hashes differently — a republished artifact), `SC-005` (MEDIUM; `latest` for the package is deprecated on npm) and, on a version-2 lock, `LOCK-010` (INFO; the recorded resolution context changed) |
| `lock --verify --connect` | the above, **plus** each server's live tool list vs. the digests in `tools` | starts each configured server (same as `scan --connect`) | adds `LOCK-006` (tool added, HIGH), `LOCK-007` (schema or annotations changed, HIGH), `LOCK-008` (only the description or title changed, MEDIUM), `LOCK-009` (tool removed, LOW) |
| always | mcp-audit's own owned-section `checksum`, and `tools._checksum` when `tools` is populated, against their recomputed values | none | `LOCK-005` (mcp-audit's own record — header + `servers`, or the `tools` section — tampered or hand-edited) — short-circuits all other checks, exit 2 |
| always, version-2 lock | `section_digests` against each section; the file's bytes against their canonical form | none | `LOCK-011` (a section changed without its digest, HIGH), `LOCK-012` (file reformatted, LOW) |

**Remote host moves (STORY-0135).** When a remote server's canonical URL changes, LOCK-001's evidence leads with what moved: `remote host changed from a.example to b.example`, or `remote port changed from 443 to 8443 on host a.example` when only the port differs (the default port for the scheme counts as the port). A path-only change is still LOCK-001 but names no host; a change confined to userinfo, query string or fragment is not drift at all, because the lock records none of them. Only the hostname and port are ever quoted. No lock format change: the sentence is derived from the locked `identity.url` and the current config.

`lock --verify`'s exit code and message vocabulary are permanently scoped to what it can see offline
unless `--resolve` is passed. A green default `--verify` never implies the registry was consulted.
A green result never implies a foreign section (`trees`, or any other) was checked — the summary
line names every unverified section present, generically:

```
Lock: 4 servers verified; not verified: trees (see docs/lock.md)
```

When `tools` holds tool records but `--connect` was not passed, a second line says so — a green
default `--verify` never implies tool definitions were compared either:

```
Tool definitions are recorded for 4 server(s) but were not compared (add --connect).
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
- a foreign top-level section (`trees`, a `tools` section from another producer, or any other key
  mcp-audit does not write) is genuinely **populated** — i.e. holds something other than
  mcp-audit's own default stub (`trees: {}`, `tools: null`), or
- under `--connect`, a locked server's tools could not be compared: it has no tool record yet, or
  its tool list could not be read in full this run.

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
| `--connect` | off | Start each configured server and list its tools. Writing: record a digest of every tool definition in `tools`. With `--verify`: report `LOCK-006`..`LOCK-009`. Needs the `mcp` extra (`pip install 'mcp-audit-scanner[mcp]'`); not available in the standalone binary. Cannot be combined with `--offline`. |
| `--save-tool-text` | off | With `--connect`: also write the tool definitions to `mcp-lock.tools.json` beside the lock. `mcp-lock.json` is unchanged. See [Saved tool text](#saved-tool-text---save-tool-text). |
| `--tool-text-path` | `<lock dir>/mcp-lock.tools.json` | Where the tool-text file is written (with `--save-tool-text`) or read (with `--verify --connect`) |
| `--connect-token` | none | Bearer token sent to remote (SSE/HTTP) servers during `--connect`. Never stored or logged. |
| `--include-user` | off | Also lock user-global configs (for dotfiles repositories) |
| `--offline` | off | Never touch the network while writing the lock |
| `--output / -o` | `<root>/mcp-lock.json` | Write to a custom path |
| `--registry` | bundled | Override the known-server registry |
| `--format / -f` | `terminal` | Output format for `--verify`: `terminal`, `json`, `sarif` |

`--verify` and `--accept` are mutually exclusive (exit 2 if both are given).

---

## Tool definitions (`--connect`)

`servers` pins *which* server runs and which package version it resolved to. It says nothing about
what that server tells the model once it starts: its tools, their descriptions, and their schemas.
Those can change under a pinned server (a new release behind a floating spec, a remote server
redeployed, a server that builds its tool list at runtime). In github-mcp-server v2.0.0, 124 of 131
tool definitions changed with no new capability advertised
([github/github-mcp-server#3466](https://github.com/github/github-mcp-server/issues/3466)).

```bash
mcp-audit lock --connect              # record the current tool definitions
git add mcp-lock.json && git commit -m "Lock MCP tool definitions"

mcp-audit lock --verify --connect     # later, or in a scheduled job
```

```
LOCK-006  Tool added since lock: 'notes'
  added: 'send_email'
LOCK-007  Tool contract changed since lock: 'notes'
  changed: 'list_notes'
LOCK-008  Tool description changed since lock: 'notes'
  changed: 'read_note'
LOCK-009  Tool removed since lock: 'notes'
  removed: 'delete_note'
Lock: 1 servers checked; not verified: trees (see docs/lock.md)
Tool definitions compared for 1 server(s).
```

**What is recorded.** For each tool, two SHA-256 digests of the RFC 8785 canonical JSON of what the
server sent over the protocol (`tools/list`, every page):

- `definition` covers `name`, `title`, `description`, `inputSchema`, `outputSchema`, and
  `annotations`;
- `contract` covers the same minus the free text (`title`, `description`).

Only tool names and digests are written, never the tool text:

```jsonc
"tools": {
  "_producer": "mcp-audit",
  "_schema_version": 1,
  "servers": {
    "claude-code/notes": {
      "tools": {
        "read_note": { "contract": "sha256:c301…", "definition": "sha256:974f…" }
      }
    }
  },
  "_checksum": "sha256:8d1b…"
}
```

The digests are taken over the protocol's own wire format, so they do not depend on the `mcp`
package version doing the listing: the same server digests identically under `mcp` 1.27 and 2.3.

**What `--verify --connect` reports.** One finding per kind of change per server, naming the tools:

| ID | Severity | Meaning | Fails the exit code |
|---|---|---|---|
| `LOCK-006` | HIGH | The server lists a tool that was not there when its tools were locked | yes |
| `LOCK-007` | HIGH | A tool's `inputSchema`, `outputSchema`, or `annotations` changed: what it accepts, returns, or declares about itself (for example read-only or destructive). A parameter description lives inside `inputSchema`, so it lands here | yes |
| `LOCK-008` | MEDIUM | Only a tool's `description` or `title` changed | yes |
| `LOCK-009` | LOW | A locked tool is gone | no (like `LOCK-003`) |

`LOCK-008` is not "cosmetic". The description is the text the model reads, and it is where tool
poisoning arrives. It is ranked below a schema change because the tool still accepts and returns
the same things, but it still fails the build until someone reads the new text and re-locks.
`mcp-audit scan --connect` runs the poisoning checks over the current text.

A server that cannot be compared is reported, never passed: no tool record yet (run
`lock --connect`), the connection failed, or the tool list could not be read to the last page. Each
is an unverified entry in the sense of R56 above: exit 1 unless `--allow-unverified`. A server that
drifted (`LOCK-001`) is not compared; approve the config change first.

**Re-locking.** `lock --accept --connect` replaces the records for every server it could list. A
server that could not be listed keeps its previous record (a timeout never erases an approval) and
gets a `WARN` line. `lock` or `lock --accept` without `--connect` keeps the existing records and
drops records for servers no longer in the lock. If the `tools` section fails its own checksum,
`lock` without `--connect` refuses (exit 2) rather than re-checksum a hand edit into a valid record;
`lock --accept --connect` discards every old record and writes only what it listed. After approving a launch change with
`lock --accept`, run `lock --accept --connect` too, or the next `--verify --connect` compares the
new server's tools against the old record.

**Why `tools` has its own checksum.** The top-level `checksum` still covers
`{lock_version, generated_by, servers}` only. If `tools` were folded into it, every mcp-audit from
0.17 to 0.20 would recompute the old scope on a lock written with `--connect`, find a mismatch, and
report `LOCK-005` "tampered" — a false security event for any team on mixed versions, or CI pinned
to an older Action. With a section-local `_checksum`, 0.18–0.20 see a populated section they cannot
verify and say so (exit 1 under R56, waivable with `--allow-unverified`); 0.17 ignores it. Upgrade
CI before the first `lock --connect` is committed. A hand edit inside `tools` is caught by
`tools._checksum` and reported as `LOCK-005`. Like the top-level `checksum`, it is an unkeyed hash:
it catches hand edits and corruption, not someone who recomputes it, and renaming `_producer` or
bumping `_schema_version` makes the section foreign (exit 1 unless waived). Review changes to
`mcp-lock.json` in the pull request like any other change.

**Running servers.** `lock --connect` starts every configured stdio server, the same as
`scan --connect`. `lock --verify --connect` starts only the servers it can compare: matched to a
locked entry, no `LOCK-001` drift, with a tool record, and only when both checksums pass. A server
the lock does not approve, or whose launch line changed, is reported and never run. Only an allowlisted set of host environment variables is passed through (the
same `SAFE_ENV_VARS` as `scan --connect`), plus the server's own `env` from its config. Remote
servers that need a bearer token take `--connect-token`. The GitHub Action's `lock-verify` input
does not pass `--connect`; whether CI should start MCP servers is your call, made explicitly in
your own workflow step.

---

## Saved tool text (`--save-tool-text`)

The tools section stores digests, so `LOCK-007` and `LOCK-008` can say that a tool changed but not
what changed. `lock --connect --save-tool-text` also writes the definitions themselves to
`mcp-lock.tools.json` next to the lock:

```bash
mcp-audit lock --connect --save-tool-text        # writes mcp-lock.json and mcp-lock.tools.json
mcp-audit lock --verify --connect                # reads the second file when it is there
mcp-audit lock --verify --connect --format pr-comment
```

What verify shows with the file:

| Finding | Added detail |
|---|---|
| `LOCK-006` | The new tool's description (shown even without the file; it was just listed) |
| `LOCK-007` | One line per changed path: `read: annotations.readOnlyHint: true → false` |
| `LOCK-008` | A word diff of the description or title: `Read a note [-from disk-] {+and send it to evil.example+}` |

The poisoning checks run over the **added words only**. A match is named in the evidence; the finding's severity is the same with or without the file. The terminal view is capped per tool (eight field changes, about 700 characters of
word diff); `--format json` has the full diff under `tool_diffs`, and `--format pr-comment` prints
each changed description before and after in code fences (capped at 4,000 characters each, 60,000 for the comment), since tool text comes from the server. Credentials found in tool text are redacted in every display; the file itself stores the text as sent, and `lock` warns when a description looks like it holds one. A very long changed stretch (over 1,500 words) is reported as "too long to align" instead of diffed.

**It is a companion, not part of the lock.** `mcp-lock.json` is the same with or without it, its
checksum does not cover it, and no verdict depends on it. Each stored definition is shown only if it
hashes to the digest the lock holds for that tool. If any does not (hand edit, or the file is from an
older run), verify prints a note that the file is out of step with the lock, shows no diff for that
server, and the exit code is whatever the digests say. A name collision (two tools under one name)
is never shown as a single definition. The file is never overwritten if it is not one mcp-audit wrote, and `--tool-text-path` alone writes nothing (it needs `--save-tool-text`). Without the file, `--verify --connect` prints what it always
did plus one line saying `--save-tool-text` would show the change.

**What is in it.** The definition each tool is digested from: name, title, description,
`inputSchema`, `outputSchema`, `annotations`. It never sees your server's `env` or `headers`. It does
contain every tool description the server sent, so review it like the lock before committing. A
`WARN` prints when the file passes 1 MB; the 2026-10-22 top-100 corpus held about 6 MB of definitions
across 60 servers that answered (about 100 KB per server on average; the corpus does not commit the
definitions, so a median and maximum are not published). Re-run with `--save-tool-text` to refresh
it; a server that could not be listed keeps its previous text.

Not to be confused with `mcp-audit snapshot`, which is the forensic export.

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
  project with no lock file anywhere sees zero change in behaviour or output. Matching is by
  **(config path relative to the lock root, server name)**, not by the `<client>/<name>` string
  used as the entry's id in the file — that string is a label, not identity (R61). A discovered
  config whose path is not under the lock root produces **no** LOCK findings and one `WARN`
  ("outside the lock root"). `mcp-lock.json` itself is never ingested as an MCP config. Unlike every
  other post-scoring finding source (baseline drift, governance, SAST, extensions, agent-files),
  LOCK findings **do** recompute the scan score and grade — this is deliberate, not an inconsistency.
  `check`'s one-page verdict gets a `Lock: verified (N servers)` line (or a finding-count summary on
  drift), plus one `WARN` per entry that was locked offline and never confirmed. `scan` prints the
  same lines; with `--format json`, `sarif` or `nucleus` they go to stderr (as does every other
  status line), so stdout is only the document. `lock --verify --format json|sarif` does the same. `check --json` gets
  a `lock_status: {present, verified, findings, checked_servers, lock_paths, unresolved_entries,
  unverified_sections, outside_root, not_covered}` object mirroring `feed_status`'s shape.
  `not_covered` (STORY-0094) lists MCP servers declared inline in a project
  subagent definition (`.claude/agents/**/*.md`, client `claude-code-agent`)
  under a lock root: `mcp-audit lock` never records them and verification skips
  them, so an existing lock keeps passing, but `check` and `scan` print a `WARN`
  that the lock does not cover them, and their AGENT-004 is MEDIUM. A repository's
  skills-directory plugin servers (`.claude/skills/<name>/.mcp.json`, client
  `claude-code-plugin`, STORY-0095) are verified against the entry `mcp-audit lock` wrote for
  that `.mcp.json` (matched by config path and name, so drift is LOCK-001 in `check` as in
  `lock --verify`); one the lock has no entry for, such as an inline `plugin.json` server, is
  listed in `not_covered`. A monorepo with several
  `mcp-lock.json` files verifies each project config against its own nearest ancestor lock, never a
  sibling's.
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

- A bare spec (`"*"`) and an explicit `@latest` are both resolved through the registry's `latest`
  dist-tag, but npm does not treat them alike: for a bare or range spec, npm 10.8.2 and later
  (bundling [npm-pick-manifest](https://github.com/npm/npm-pick-manifest/blob/v12.0.0/lib/index.js)
  9.1.0 or later, whose `latest` fast path checks `!mani.deprecated` and the engines) skip a
  deprecated or engine-incompatible `latest` and then prefer the highest version that is neither,
  when one exists. mcp-audit does not model this; SC-005 says so in its message.
- No semver range resolution: a range spec (`foo@^1.2.3`) is recorded verbatim in `spec_as_written`
  and resolved the same way an unpinned `latest` spec is (via the registry's own `latest` dist-tag /
  PyPI's latest-stable), never by computing a highest-satisfying version. `range_spec: true` flags
  this in the entry.
- PyPI package `integrity` is not yet populated (npm tarball hashes are, via the same hasher
  `--verify-hashes` uses); left `null` until a PyPI equivalent ships.
- `package.deprecated` is npm-only for the same reason: PyPI's JSON API exposes "yanked" only
  per-release inside `releases`, not on the latest-version object this reads, and none of the
  bundled `registry/known-servers.json` entries carry a separate maintenance-status field mcp-audit
  could fall back on. `vet --online` and `scan --check-vulns` do not surface `deprecated` at all yet
  — tracked as STORY-0074, not this release.
- No signing. Git history is the audit trail for a committed file; a signed lock is a possible future
  addition, not blocked by anything here.
- Tool definitions are compared at the moment `--verify --connect` lists them. A server that changes
  its tool list later in a session (after the handshake, after a few calls, or by sending
  `notifications/tools/list_changed`) is not caught by this; the lock is a review-time check, not a
  runtime monitor. Tools that differ by caller (per-user or per-token tool lists) digest differently
  for different callers.
- Only tools are recorded. Resources and prompts are not, yet.
- No runtime enforcement — `lock` is a record checked at `lock`/CI time, never enforced against a
  running MCP client. This is a permanent design decision, not a gap.

See [GAPS.md](../GAPS.md) for the authoritative, continuously updated list.
