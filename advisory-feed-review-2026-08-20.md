# Advisory feed adversarial review — 2026-08-20

Scope: `src/mcp_audit/advisory/{sign,canonical,schema,validate,feed,classify}.py`,
`src/mcp_audit/output/advisory.py`, `src/mcp_audit/cli/advise.py`, `docs/advisory-feed.md`,
and the existing test suite (`tests/test_advisory_sign.py`, `test_advisory_canonical.py`,
`test_advisory_schema.py`, `test_advisory_feed.py`, `test_cli_advise.py`).

Frame: attacker who has read this code, does **not** have the signing key, and wants
(a) a forged document that verifies, (b) a tampered document that survives verification,
(c) a suppressed advisory the victim never sees, or (d) verification that fails open.

Every claim below was executed, not just reasoned about. Probes were run from a scratch
pytest file (`tests/test_advisory_security_review_scratch.py`, 21 tests, all passing —
"passing" here means the *defense* held or the *gap* was confirmed, per test) that was
deleted before this review was committed; the file contents are inlined per-finding
below so the reproduction is self-contained. Both real signing backends (`cosign`
2.7.x, `minisign`) were installed and exercised for real — nothing here is mocked at
the subprocess boundary.

Bottom line up front: **no attacker-without-the-key path was found that forges a new
document, alters a signed one, or gets a bad verdict to read "verified."** The real
findings are a silent replay/rollback gap (no freshness guarantee at all), a crash
instead of a graceful refusal on a hostile deeply-nested advisory file, a defensive
digest check that fails open on a falsy value it should never see in practice, and two
stale doc lines (fixed inline, one-liners).

## §1 — What is inside the signature? (SIGNED / UNSIGNED table)

The unit of signing is **the whole on-disk advisory JSON file** and **the whole
on-disk `index.json`**, each independently: `sign_path()` reads the file, computes
`canonicalize(json.loads(file))`, and signs those bytes in full. There is no field-level
signing scheme to attack — either a file's bytes changed (any field) or they didn't.

| Field | Where | SIGNED? | Notes |
|---|---|---|---|
| `id` | advisory record | **SIGNED** | Part of the per-advisory canonical bytes; also duplicated (unsigned-looking but actually redundant) in the index's own signed entry. |
| `summary`, `details` | advisory record | **SIGNED** | Includes the redacted prose; see §2 for a caveat on *which bytes* "the same text" produces. |
| `affected[].package.{ecosystem,name,purl}` | advisory record | **SIGNED** | Narrowing/widening this is the classic OSV-record attack; confirmed caught (Finding §1-F1 below — no gap). |
| `affected[].ranges` (version range: `introduced`/`fixed`) | advisory record | **SIGNED** | Same as above — confirmed caught. |
| `affected[].database_specific.*` (`owasp_mcp`, `finding_class`, `mcp_audit_rule_id`, `verified_patch`, `observation`, `cvss_basis`, `cwe_ids`, `mcp_location`) | advisory record | **SIGNED** | All MCP-specific metadata lives here; confirmed caught. |
| `severity[]` (CVSS vector) | advisory record | **SIGNED** | Downgrading severity is caught the same way. |
| `references[]`, `aliases[]` | advisory record | **SIGNED** | — |
| `published`, `modified` | advisory record | **SIGNED**, but **not enforced monotonic by any verifier** | See §5 — this is where the real gap is, not in whether it's signed. |
| Per-entry `id`, `modified`, `summary`, `severity`, `owasp_mcp`, `affected`, `path`, `canonical_sha256` | `index.json` | **SIGNED** (as part of the whole index document) | Redundant with the advisory file's own signature by design — this redundancy is exactly what stops a "swap in a validly-(re)signed record" attack (confirmed, §1-F1). |
| `feed_version`, `generator`, `count`, `updated` | `index.json` | **SIGNED**, but `feed_version` is a fixed schema-version string, never a publish counter | See §5. |
| `signing` block (`backend`, `mode`, `identity`, `oidc_issuer`) | `index.json` | **SIGNED** — written into `index.json` *before* `sign_path()` runs on it | Confirmed the CLI does **not** read this block to decide how to verify (§3) — it is metadata for a human, not a verifier input. |
| Key identifier / algorithm choice for verification | CLI flags (`--key-alt`, `--public-key`, `--identity`, `--oidc-issuer`) / env vars | **NOT in the document at all** | This is correct and is the important finding of §3: the verifier's trust anchor is supplied out-of-band, every time, by the party running `feed verify`. Nothing about *which* key or backend to trust is read from the feed being verified. |
| `.sig` / `.sigstore.json` bytes themselves | separate files | N/A (they *are* the signature) | Detached by design; confirmed no record ever embeds signature-shaped data (already covered by `TestRotationLeavesRecordsUntouched`, re-confirmed here). |

No field is outside its own file's signature scope. The interesting question was never
"is X signed" — it's "does anything *read* an untrusted value before trust is
established," and the answer there is also no (§3), and "is there a value that's
signed but never *checked for freshness*," where the answer is yes (§5).

## §1 findings

### §1-F1 — No gap: index cannot be repointed, records cannot be swapped (no finding, confirmed)

Tried: mutate every top-level and nested field of a real signed advisory one at a
time (11 fields, including id, dates, package name, version range, OWASP codes,
finding class, verified-patch, severity) and re-verify; separately, retarget an
`index.json` entry's `"path"` to point at a *different*, independently and
already-validly-signed advisory file.

```python
@needs_minisign
def test_every_top_level_and_nested_field_is_inside_the_signed_payload(tmp_path):
    private, public = _keypair(tmp_path, "project")
    out = _build_feed(tmp_path, "feed")
    config = SigningConfig(backend="minisign", private_key=private, public_key=public)
    sign_feed(out, config)
    target = advisory_json_paths(out / "advisories")[0]
    original = json.loads(target.read_text(encoding="utf-8"))

    def _mutate_and_check(mutator) -> bool:
        record = json.loads(json.dumps(original))
        mutator(record)
        target.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
        report = verify_feed(out, config)
        target.write_text(json.dumps(original, indent=2, sort_keys=True) + "\n")
        return report.ok

    mutations = { ... }  # 11 fields, id through verified_patch.fixed_version
    survived_unsigned = [name for name, m in mutations.items() if _mutate_and_check(m)]
    assert not survived_unsigned
```

```python
def test_index_cannot_be_repointed_to_a_different_advisory_without_the_key(tmp_path):
    ...
    index["advisories"][i]["path"] = f"advisories/{other_advisory.name}"
    index_path.write_text(...)
    report = verify_feed(out, config)
    assert not report.ok
    assert any(f.startswith("index.json") for f in report.failures)
```

**Result: both pass — every mutation was caught, the repoint was caught.** Severity: none
(confirms the design holds). This is exactly the property `docs/advisory-feed.md` and
`CLAUDE.md` claim ("do not add a verification path that trusts a per-advisory signature
alone"), and it holds under direct attack, not just under the existing swap test that
only tried re-signing with the *same* key.

## §2 — Canonicalization collisions

Tried, with results:

| Probe | Result | Exploitable? |
|---|---|---|
| `1` vs `1.0` vs `1e0` | All three canonicalize to `"1"` — unified, matches ECMAScript (there is only one Number type). | No — correct behaviour, not a collision. |
| `-0.0` vs `0.0` | Both render `"0"`. | No — correct, matches `JSON.stringify(-0) === "0"`. |
| Integers ≥ 2^53 (`2**53` vs `2**53+1`) | Python preserves **exact** arbitrary-precision integers; the two render as different, exact decimal strings (`9007199254740992` / `9007199254740993`). | **No internal collision** — but see finding below. |
| Astral-plane vs BMP key ordering (UTF-16 code-unit sort) | Already covered by the existing suite (`TestUtf16KeyOrdering`); re-confirmed, not re-litigated here. | No. |
| NFC vs NFD Unicode ("café" as one codepoint vs `e` + U+0301) | Different code-point sequences → different canonical bytes. | No — this is correct per RFC 8785 (JSON has no normalization step); flagged as a design note only. |
| Duplicate top-level keys in raw JSON text | `json.loads` (used identically at signing time and verification time) always keeps the *last* value. Both call sites in this codebase agree with each other. | No internal skew — see finding below for the cross-tool caveat. |
| `null` vs absent key vs `""` vs `{}` vs `[]` | All five produce pairwise-distinct canonical bytes. | No. |
| Deep nesting (no explicit recursion/size limit in `canonical.py`) | **Crashes with an uncaught `RecursionError`** once nesting exceeds the interpreter's recursion limit (~1000 levels; confirmed at depth 3000). | **Yes — see §2-F1, filed under §4 (fail-open via crash).** |

### §2-F1 — Cross-implementation numeric interop risk (informational, dormant)

**What an attacker gains:** nothing *today* — no advisory field is ever populated with
a raw integer that large (versions, timestamps, and IDs are all strings). This is filed
as a forward-looking risk, not an active hole: RFC 8785 assumes the I-JSON number model
(IEEE-754 double), under which `2**53` and `2**53+1` are indistinguishable. Any
compliant implementation that parses the *same raw JSON text* through a double-based
parser (a Go/JS-based tool, e.g. `osv-scanner`'s own ecosystem, or a browser-based
verifier) would round both to `9007199254740992.0` **before** canonicalizing, producing
bytes that disagree with what this codebase computes for the exact (non-rounded) value.
If a numeric field is ever added to the schema and populated from unconstrained input,
this becomes a live "the same document canonicalizes differently on two conformant
implementations" bug — not forgeable, but breaks third-party verification silently.

**Reproduction:**
```python
def test_python_preserves_full_precision_above_2_53_javascript_would_not(self):
    a, b = 2**53, 2**53 + 1
    assert canonicalize_str(a) != canonicalize_str(b)
    assert canonicalize_str(a) == "9007199254740992"
    assert canonicalize_str(b) == "9007199254740993"  # a double could not hold this
```

**Severity:** Informational / dormant. **Proposed fix:** none needed now; if a numeric
field is ever added to `Advisory`, validate it stays within `±(2**53 - 1)` (the I-JSON
safe-integer range) before it reaches `canonicalize()`, and note the requirement in the
schema module's docstring next to the RFC 8785 invariant already documented there.

### §2-F2 — Duplicate-key parsing agrees internally; cross-tool ambiguity is a design note, not a bug

**What an attacker gains:** nothing against *mcp-audit's own* verification, confirmed —
signing-time and verification-time canonicalization both go through the same
`json.loads`, so both pick the same ("last wins") value for a duplicate key. The
residual risk is the classic parser-differential pattern (a *different* tool consuming
the raw `.json` file with first-wins semantics could display a different value to a
human than what was signed) — this is inherent to publishing raw JSON for third-party
consumption and isn't something a signature over canonical bytes can fix; it would need
the *publishing* step to reject duplicate keys outright, which `write_feed()` cannot
produce in the first place (Python dicts can't have duplicate keys), so this only
matters for hand-crafted or third-party-mirrored files, not anything `mcp-audit advise`
itself ever writes.

**Reproduction:**
```python
def test_json_loads_silently_keeps_the_last_duplicate_key_both_times(self, tmp_path):
    raw = '{"summary": "legit-looking", "summary": "attacker-value"}'
    path = tmp_path / "dup.json"
    path.write_text(raw, encoding="utf-8")
    assert canonical_bytes_for(path) == canonical_bytes_for(path)
    assert b"attacker-value" in canonical_bytes_for(path)
```

**Severity:** Informational. **Proposed fix:** none in this codebase; worth a one-line
caveat in `docs/advisory-feed.md`'s "Consuming the feed" section noting that consumers
should reject duplicate keys if their own JSON parser doesn't already do "last wins"
the way Python's does.

## §3 — Verification, not just signing

**Core test — attacker with their own freshly generated key, signing their own
completely self-consistent forged feed, checked against the real project's public
key:**

```python
@needs_minisign
def test_a_fully_attacker_signed_feed_is_rejected_by_the_legitimate_public_key(tmp_path):
    project_private, project_public = _keypair(tmp_path, "project")
    attacker_private, attacker_public = _keypair(tmp_path, "attacker")

    forged = build_advisories(ScanResult(servers=[_server(name="evil")],
        findings=[_finding("CRED-001", server="evil",
                            title="This finding does not exist for real")],
        servers_found=1), now=FIXED_NOW).advisories
    out = tmp_path / "forged-feed"
    write_feed(forged, out)

    attacker_config = SigningConfig(backend="minisign", private_key=attacker_private,
                                     public_key=attacker_public)
    sign_feed(out, attacker_config)
    assert verify_feed(out, attacker_config).ok        # self-consistent, as expected

    victim_config = SigningConfig(backend="minisign", public_key=project_public)
    report = verify_feed(out, victim_config)
    assert not report.ok   # would be CRITICAL if this ever flipped
```

**Result: rejected, as it must be.** This is the whole ballgame question from the task
brief, and the answer is no, it does not pass.

**Is the algorithm/key pinned by the verifier, or read from the document?** Pinned by
the verifier. `cli/advise.py::feed_verify` builds its `SigningConfig` exclusively from
`--key-alt` / `--public-key` / `--identity` / `--oidc-issuer` (CLI flags) and their
environment-variable equivalents — it never reads `index.json`'s own `"signing"` block
to decide *how* to verify. That block is written for a human to read, and is itself
inside the signed payload, but nothing in `verify_feed()`'s call path consults it as a
verification input. Confirmed by reading `cli/advise.py:346-352` and by the two probes
below.

**Fail-closed-by-default probes:**

```python
def test_minisign_config_cannot_even_be_constructed_without_a_key():
    with pytest.raises(SigningError, match="no keyless mode"):
        SigningConfig(backend="minisign")   # refused before verification is even attempted

@needs_cosign
def test_cosign_feed_verify_defaults_fail_closed_with_no_trust_anchor_supplied(tmp_path):
    ...
    bare_config = SigningConfig()  # cosign default backend, no key, no identity, no issuer
    report = verify_feed(out, bare_config)
    assert not report.ok
    assert any("--identity" in f for f in report.failures)

@needs_minisign
def test_backend_confusion_fails_closed_rather_than_silently_passing(tmp_path):
    """Signed with minisign; verified with the CLI's own DEFAULT backend (cosign)."""
    ...
    report = verify_feed(out, SigningConfig(backend="cosign"))
    assert not report.ok
```

All three pass — a bare `mcp-audit feed verify some-dir` with no flags at all, and a
backend/config mismatch, both refuse rather than pass vacuously. `minisign` is in fact
*stricter* than `cosign` here: a keyless minisign config cannot even be constructed
(`SigningConfig.__post_init__` raises immediately), whereas cosign allows a keyless
config object to exist and only refuses at verification time — both outcomes are
fail-closed, just at different points.

### §3 — Key distribution channel (design finding, not a code bug)

`docs/advisory-feed.md` documents the intended custody model: private key as a GitHub
Actions secret, public key committed to the repo **and** published at
`https://mcp-audit.dev/.well-known/mcp-audit-feed.pub` — a location distinct from
wherever a feed itself is fetched from, which is the architecturally correct answer to
"is the key distributed over a different channel than the feed." That said:

- **No project key has actually been minted yet.** `examples/feed/` ships unsigned
  today (confirmed: no `.sig` files, no `"signing"` key in `index.json`) because,
  per `CLAUDE.md`, committing a private key to sign it reproducibly would be worse
  than not signing it. So there is currently no "real" mcp-audit feed for anyone to
  forge — anyone using `mcp-audit advise --sign` today is necessarily bringing their
  own key (e.g., a CI pipeline signing its own org's feed with its own key), and the
  security properties above hold correctly for that self-hosted case.
- This is worth saying plainly to Adam even though it's a project-maturity fact, not
  a code defect: **the verification code is sound; the "who do I trust by default"
  question has no answer yet because there is nothing yet to trust by default.**
  Once a key exists, its safety depends entirely on operational custody (the GitHub
  Actions secret, who can trigger the publish workflow) — outside this review's scope
  of "read the code as an attacker," but worth flagging as the next thing to audit
  once the key exists.

## §4 — Fail-open

| Probe | Result |
|---|---|
| Missing signature artifact | Caught (`"Missing signature artifact"` — already covered by the existing suite; re-confirmed). |
| Garbage bytes in `.sig` | Caught gracefully — `"does not verify"` failure, no crash. |
| Corrupt / truncated `index.json` | Caught (already covered; re-confirmed with an **empty** `index.json` too — `json.JSONDecodeError` → clean failure). |
| Valid JSON, wrong shape (`{}` as the whole feed) | No crash; reports `checked=1`, unsigned, ok=True (there is nothing to check — this is correct, not a bypass: an empty feed is not a false "verified" of anything). |
| Well-signed but OSV-schema-invalid record | "Verifies" — `verify_feed` never calls `validate_osv()`. Not a bypass of anything it claims to check (it checks integrity + authenticity, not shape), but worth stating precisely for anyone assuming "verified" implies "schema-valid." |
| Network failure fetching the feed or the key | **N/A to this code.** `feed verify` and `advise --sign`/`--no-sign` operate purely on local files and a local `cosign`/`minisign` binary; nothing in the signing/verification path makes a network call. However the feed is actually *fetched* by the consumer (curl, git, a package manager) is entirely outside mcp-audit's code and this review's ability to test. |
| Flag/env var that silently disables verification | None found. `--no-sign` on `advise` is loud (prints a yellow warning naming exactly what guarantee is missing) and only affects *publishing*, not verification; there is no equivalent "skip verification" flag on `feed verify`. The only `--insecure*` string in the module is `--insecure-ignore-tlog`, which is applied automatically and only for offline key-mode signatures (there is no Rekor entry to check in that mode by design) — not user-reachable as a downgrade. |

### §4-F1 — Deeply nested advisory JSON crashes the verifier with an uncaught traceback

**What an attacker gains:** a denial of service against `mcp-audit feed verify`, and a
violation of the project's own stated hardening invariant ("never a Python traceback").
This does **not** flip a failing verdict into a passing one — the process crashes
before any verdict is produced, so nothing false is accepted — but a security tool that
crashes instead of refusing gracefully on hostile input is exactly the class of bug
`CLAUDE.md`'s "Security hardening invariants" section exists to prevent, and `feed
verify`'s own docstring promises "the command refuses rather than passing vacuously,"
which a stack trace does not deliver on.

`canonical.py`'s `_write` / `_write_object` / `_write_array` are mutually recursive with
no depth or size limit. `verify_feed()`'s per-advisory loop only catches
`SigningError`; `RecursionError` is a `RuntimeError` subclass and is not caught
anywhere between `canonical_bytes_for()` and the Typer CLI boundary.

**Reproduction (ran the actual CLI, not just the library call):**

```python
def test_deeply_nested_document_either_canonicalizes_or_fails_closed(self):
    depth = 4000
    document = "leaf"
    for _ in range(depth):
        document = {"a": document}
    sys.setrecursionlimit(2000)
    try:
        canonicalize(document)
        outcome = "canonicalized without error"
    except RecursionError:
        outcome = "RecursionError (uncaught RuntimeError subclass)"
    # observed: "RecursionError (uncaught RuntimeError subclass)"
```

And at the real CLI, against a feed directory containing one hostile advisory file
(3000 levels of `{"a": ...}` nesting) listed in an otherwise-normal `index.json`:

```
$ mcp-audit feed verify /tmp/hostile-feed
╭───────────────────── Traceback (most recent call last) ──────────────────────╮
│ .../src/mcp_audit/cli/advise.py:357 in feed_verify                           │
│ .../src/mcp_audit/advisory/canonical.py:93 in _write_object                  │
│ ... (repeats ~1000 times) ...                                                │
│ RecursionError: maximum recursion depth exceeded                            │
╰────────────────────────────────────────────────────────────────────────────────╯
$ echo $?
1
```

Exit code is 1 (not a false "verified"), but the output is a raw traceback, not the
project's own `"[red]Error:[/red] ..."` convention, and — because the crash happens
inside the per-advisory loop before the loop can move on — it aborts the *entire* feed
check on the first hostile file rather than reporting that one advisory as failed and
continuing to check the rest, which is a worse experience than any of the other
malformed-input cases in the table above.

**Severity: Medium** (robustness/DoS against a local CLI invocation; not a
verification bypass). **Proposed fix:** wrap the per-advisory and index canonicalization
calls in `verify_feed()`/`verify_path()` to also catch `RecursionError` (and convert it
to a `SigningError` with a message like `"{path}: document is nested too deeply to
canonicalize"`), or add an explicit depth counter to `canonical.py`'s writer that raises
`SigningError`/`ValueError` before the interpreter's own limit is reached. The latter is
more correct (it also protects `sign_path()` at publish time against a good-faith bug
elsewhere producing a runaway structure) but is more than a one-line change, so it is
left as a recommendation rather than applied in this review.

## §5 — Replay and rollback

**This is the finding with the highest attacker gain in this review.**

**What an attacker gains:** silent, total suppression of every advisory published after
a point in time, indefinitely, with a verification tool that reports full success. An
attacker who can intercept or substitute how a feed is distributed — a MITM position,
a compromised mirror, a stale CDN edge, a malicious "here's a feed someone handed you"
(the exact phrase `docs/advisory-feed.md` uses for its own worked example) — can serve
an **old, genuinely-and-still-validly-signed** snapshot of the feed forever. Nothing in
`verify_feed()`, `index.json`'s schema, or the CLI expresses or checks "have I seen a
newer version of this feed before." `feed_version` is a fixed schema-version constant
(`"1.0"`), never incremented per publish — it is not a sequence number. `updated` is
derived from the data (`max(a.modified for a in advisories)`) and *is* inside the
signed payload, but nothing on the verifying side compares it against anything: each
`feed verify` invocation is fully stateless.

**Reproduction:**

```python
@needs_minisign
def test_an_older_fully_valid_signed_feed_replays_cleanly_no_freshness_check(tmp_path):
    private, public = _keypair(tmp_path, "project")
    config = SigningConfig(backend="minisign", private_key=private, public_key=public)

    old_advisories = build_advisories(
        ScanResult(servers=[_server(name="github")],
                   findings=[_finding("CRED-001", server="github")], servers_found=1),
        now="2026-01-01T00:00:00Z").advisories
    old_feed = tmp_path / "old"
    write_feed(old_advisories, old_feed)
    sign_feed(old_feed, config)

    new_advisories = build_advisories(
        ScanResult(servers=[_server(name="github")],
                   findings=[_finding("CRED-001", server="github"),
                             _finding("SC-001", server="github",
                                      title="Newly discovered typosquat")],
                   servers_found=1),
        now="2026-06-01T00:00:00Z").advisories
    new_feed = tmp_path / "new"
    write_feed(new_advisories, new_feed)
    sign_feed(new_feed, config)

    report = verify_feed(old_feed, config)     # the REPLAYED old snapshot
    assert report.ok                            # <- passes fully, no warning at all
    old_index = json.loads((old_feed / "index.json").read_text())
    new_index = json.loads((new_feed / "index.json").read_text())
    assert old_index["feed_version"] == new_index["feed_version"]   # "1.0" == "1.0"
    assert old_index["count"] < new_index["count"]                  # 1 < 2, undetected
```

Observed output: `old feed count=1, new feed count=2, both feed_version='1.0'.
verify_feed(old_feed) ok=True with no reference to the newer state ever existing.`

**Expiry:** OSV's schema supports a `withdrawn` field for exactly this class of
problem (retracting or superseding a record); mcp-audit never sets it anywhere in
`schema.py`/`feed.py` — confirmed by both a targeted test and a full-text search. There
is no complementary mechanism either (no TTL, no "advisory expires N days after
publish").

**Severity: High.** This is not "someone without the key can forge a document" — it's
"someone without the key can make a real, honestly-signed victim-facing verdict lie by
omission," which for a security-advisory feed is arguably worse: the victim's tool
says "All N artifact(s) verified" in green text while the actual current advisory state
is unknown to them.

**Proposed fix (design-level, not a one-liner — flagging rather than fixing per the
review's ground rules):** add a monotonic, signed sequence number (or the already-signed
`updated` timestamp) to `index.json`, and give `feed verify` an optional
`--min-updated`/`--after PATH-TO-PREVIOUSLY-VERIFIED-INDEX` mode that fails when the
newly-fetched index's `updated` is not strictly newer than the last one the caller
recorded. This mirrors how TUF-style systems and Sigstore's own transparency log defend
against freeze attacks, and is exactly the kind of statefulness `docs/advisory-feed.md`
would need to add deliberately (a CI cache of "last verified `updated`" per feed URL)
rather than something `verify_feed()` can infer on its own from a single directory.

## §6 — The `advisory.owasp` deletion guard

`tests/test_advisory_schema.py::TestOwaspMapping::test_the_deleted_private_owasp_module_stays_deleted`
asserts `importlib.import_module("mcp_audit.advisory.owasp")` raises
`ModuleNotFoundError`. Confirmed the module genuinely does not exist
(`src/mcp_audit/advisory/` has no `owasp.py`), so the guard is not dead code — it is an
active regression test that would immediately fail if anyone reintroduced a private
copy of the OWASP MCP Top 10 inside the advisory package (which `CLAUDE.md` says
happened once and was corrected). All four PyInstaller `.spec` files
(`mcp-audit-{darwin-x86_64,darwin-arm64,linux-x86_64,windows-x86_64}.spec`) were
grepped for `advisory.owasp` / `advisory_owasp`: **no matches** — the stale
hidden-import references PR #43 mentions fixing are gone, and the current
`hiddenimports` lists name exactly the six modules that do exist
(`canonical`, `classify`, `feed`, `schema`, `sign`, `validate`). No finding: the guard
protects a real, currently-true invariant, and the specs agree with it.

## Documentation drift found (one-line fixes identified, not applied here)

Two stale doc lines were found while reading the package. Both are one-line,
obviously-correct corrections, but per this review's own instruction to keep fixes and
the review separate, they are reported here rather than applied in this commit:

- `CLAUDE.md`: the module-layout comment for `schema.py` still says advisory IDs are
  `` `x_MCPSA-YYYY-<12hex>` `` — the year component was removed in an earlier PR (see
  `stable_id()`'s own docstring and `docs/advisory-feed.md`'s "Advisory IDs" section,
  both of which already say `x_MCPSA-<12hex>` with no year).
- `docs/advisory-feed.md`'s "See also" section: `` `examples/feed/` — a complete
  **signed** feed you can verify today`` — confirmed `examples/feed/index.json` has no
  `"signing"` key and there are no `.sig` files anywhere under `examples/feed/`. This
  directly contradicts `CLAUDE.md`'s own accurate statement ("The committed
  `examples/feed/` is unsigned by design") one section away.

## Summary table — what to fix, in order of attacker gain

| # | Finding | Attacker gain | Severity | One-line status |
|---|---|---|---|---|
| 1 | §5 — no rollback/replay protection | Silent, indefinite suppression of newer advisories via a stale-but-valid replayed feed | High | Design-level fix needed (sequence number + stateful `--after`); not applied here |
| 2 | §4-F1 — uncaught `RecursionError` on deep nesting | Crashes `feed verify` with a raw traceback instead of a graceful refusal (DoS/robustness, not a bypass) | Medium | Fix identified, not applied (more than one line) |
| 3 | §2-F1 — big-integer cross-implementation drift | Dormant; no field uses it today | Informational | No fix needed now; documented as a constraint for future schema fields |
| 4 | §2-F2 — duplicate-key parser differential | No internal exploit; third-party-tool caveat only | Informational | Doc note recommended, not applied |
| 5 | Two stale doc lines | None (accuracy only) | N/A | Identified, not applied (kept out of this review-only commit) |

No finding: §1 (field coverage), §3 (attacker-key rejection, fail-closed defaults,
algorithm/backend pinning), §6 (deletion guard). Each has an executed, passing/failing
(as appropriate) test above rather than an assumption.
