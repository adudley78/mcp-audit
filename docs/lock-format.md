# `mcp-lock.json`: what will not change

`mcp-lock.json` is a stable format from Credenzo 0.35.0. You can commit it,
check it in CI and build on it. This page is the list of promises. A release
that breaks one of them is a bug.

How to write and check a lock is in [lock.md](lock.md).

## The promises

1. **A lock that verifies today verifies with every later release.** Credenzo
   reads `lock_version` 1 and `lock_version` 2. A later release can read more
   versions. It never reads fewer.

2. **A field keeps its name and its meaning.** In a version-2 lock these
   names are frozen:

   | Where | Names |
   |---|---|
   | Top level | `lock_version`, `generated_by`, `generated_at`, `servers`, `trees`, `tools`, `section_digests`, `checksum` |
   | A server entry | `client`, `name`, `config`, `identity`, `package`, `env_keys`, `header_keys`, `capabilities`, `first_locked`, `hashes` |
   | `identity` | `command`, `args`, `url` |
   | `package` | `ecosystem`, `name`, `spec_as_written`, `range_spec`, `resolved_version`, `resolution`, `integrity`, `source`, `deprecated` |
   | `package.resolution` | `method`, `resolved_at`, `resolution_context` |
   | `hashes` | `command`, `args`, `env_keys`, `raw` |

   The optional sections that `lock --connect` and the guardrail record write
   (`tools`, `guardrails`) follow the same rule for the names that they hold.

3. **A release adds. It does not rename, remove or change.** A new fact about
   a server is a new optional field. A lock with no such field stays valid.
   The release notes name each new field.

4. **A change that cannot be an addition gets a new `lock_version`.** Credenzo
   then writes the new version and still reads the old ones (promise 1).

5. **The bytes are RFC 8785.** The file is canonical JSON. A second tool that
   writes RFC 8785 produces the same bytes for the same content.

6. **The digests do not change.** `checksum` is `sha256:` plus the SHA-256 of
   the RFC 8785 encoding of `{lock_version, generated_by, servers}`. Each
   `section_digests` entry is `sha256:` plus the SHA-256 of the RFC 8785
   encoding of its section. Any tool can recompute them.

7. **A finding ID keeps its condition.** `LOCK-001` is always "this entry
   changed after it was locked". An ID is not used again for a different
   condition. The table is in [lock.md](lock.md).

8. **The exit codes keep their meaning.** `lock --verify` exits 0 when the
   lock holds, 1 on drift or unverified state, 2 when it cannot check (no
   lock, a damaged lock, a `lock_version` that it does not know).

9. **`credenzo run` and `credenzo guard` read the same file** with the same
   rules. There is no second format for enforcement.

## `section_digests` is the final name

Releases before 0.35.0 said that the name `section_digests` could change. It
does not change. It is the name in every version-2 lock. If a different name
is ever agreed with another tool that writes a section, it arrives as a new
`lock_version` under promise 4.

## What can change

- The wording of a finding, its evidence text and its severity.
- The value of `generated_by` (it holds the version that wrote the file).
- The order of lines in terminal output. For a script, use `--format json`.
- The content of a section that another tool wrote. Credenzo keeps it and
  does not read it.
- `mcp-lock.tools.json` (the saved tool text) is a second file with its own
  version field. These promises are about `mcp-lock.json`.

## An older Credenzo and a newer lock

An older release does not know a top-level section that a newer release
added. It reports the section as not verified, and `lock --verify` exits 1.
So upgrade every place that runs `lock --verify` (CI, pre-commit, the guard)
before you commit a lock that a newer release wrote. A lock is never made
invalid by an upgrade of Credenzo alone.

## How the promises are held

- `tests/fixtures/lock_v1_corpus/` holds locks that the last version-1 code
  wrote. `tests/test_lock_v2.py` verifies them with the current code and
  expects the same result.
- `tests/fixtures/lock_v2_frozen/mcp-lock.json` was written by Credenzo
  0.34.0. `tests/test_lock_format_stability.py` verifies it with the current
  code, expects no finding, and fails when a frozen name is missing from a
  lock that the current code writes or from this page.
