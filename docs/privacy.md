# Privacy Policy — mcp-audit

**Short version:** mcp-audit collects no data by default.
Every scan runs entirely on your machine.  Nothing is sent anywhere unless you opt in: by registering (below), or by using a flag or command whose job is to reach the network.

---

## Default behaviour (no registration)

- **No telemetry.** mcp-audit never phones home, sends usage statistics, or contacts any remote server during a normal scan.
- **No crash reports.** Errors are written to your terminal only.
- **Fully offline.** A plain `mcp-audit scan` makes zero network connections.  Network-touching flags (`--verify-hashes`, `--verify-signatures`, `--check-vulns`, `--connect`) are explicitly opt-in.  Commands whose job is to fetch or send something (for example `update-registry`, `vet --online`, `push-nucleus` and `register`) use the network only when you run them.

---

## Opt-in registration (`mcp-audit register`)

Registration is **opt-in and completely optional**.  Nothing is sent unless you run `mcp-audit register` (or pass `--register` to `mcp-audit check`) and answer its prompts.  An unregistered user has identical functionality to a registered one.

### What registration does

Running `mcp-audit register` starts an interactive prompt that:

1. Asks for your name (or handle), org, and email.  Name and org can be left blank.
2. Asks whether you want a follow-up if your scan grade is C or below.
3. Stores a `registration.json` file locally (see [Local storage](#local-storage)).
4. Sends a single HTTPS POST with your registration details to this address:

```
https://eo4jvaanlkuohuc.m.pipedream.net
```

That address is the `_REGISTER_ENDPOINT` constant in `src/mcp_audit/registration/client.py`, and a test fails if this page and the constant ever disagree.  It is a [Pipedream](https://pipedream.com) webhook (a hosted service that receives the request and runs a small workflow on it), not an `mcp-audit.dev` address.

### What the initial registration POST sends

The request body is JSON with exactly these fields:

| Field | Example | Where the value comes from |
|---|---|---|
| `name` | `"Sarah Chen"` | Your answer to the name prompt (may be blank) |
| `org` | `"IBM Security"` | Your answer to the org prompt (may be blank) |
| `email` | `"sarah.chen@ibm.com"` | Your answer to the email prompt |
| `version` | `"0.21.1"` | The installed mcp-audit version |
| `grade` | `"?"` | Always `"?"` in this POST: the registration flow runs no scan of its own, so there is no grade to send |
| `follow_up_requested` | `true` | Your answer to the follow-up prompt |

**Nothing else is in the body.** The payload is defined in `src/mcp_audit/registration/models.py` as `RegistrationPostPayload`, and you can audit it directly.  Like any HTTPS request, it also carries two standard headers (`Content-Type: application/json` and `User-Agent: mcp-audit/<version>`), and the receiving service can see the IP address the request comes from.

### What the initial registration POST does NOT send

- Config file contents
- Server names, commands, or arguments
- Tool names or descriptions
- Environment variable names or values
- File paths

### Subsequent pings (after scan runs)

After you register, every completed `mcp-audit check` run sends a brief ping to the same address (a run that finds no MCP configs at all exits before it).  `mcp-audit scan` and every other command never ping.

| Field | Example |
|---|---|
| `version` | `"0.21.1"` |
| `grade` | `"B"` |
| `registered` | `true` |

**No PII is ever included in a ping.** Name, org, and email are deliberately excluded.  The ping carries no identifier that links it to your registration; the receiving service sees only the same two headers and your IP address.  The ping payload is defined as `RegistrationPingPayload` in `src/mcp_audit/registration/models.py`.

### Where the data goes

Both requests go to the `_REGISTER_ENDPOINT` address above and nowhere else.  The code comment beside that constant in `src/mcp_audit/registration/client.py` describes the webhook as routing each request to an email notification and a Google Sheets log.  mcp-audit itself keeps no copy beyond the local `registration.json` described next.

### Local storage

`registration.json` is written to:

```
<user-config-dir>/mcp-audit/registration.json
```

On macOS: `~/Library/Application Support/mcp-audit/registration.json`
On Linux: `~/.config/mcp-audit/registration.json`
On Windows: `%LOCALAPPDATA%\mcp-audit\mcp-audit\registration.json` (the directory library mcp-audit uses, `platformdirs`, repeats the app name on Windows)

The file is created with `0o600` permissions (owner read/write only), in a directory created with `0o700` if it does not already exist.

### Removing your registration

```bash
mcp-audit register --clear
```

This deletes the local `registration.json`.  No further pings will be sent.  It does not delete records the webhook has already received.  You can verify the file is gone:

```bash
mcp-audit register --status
# Not registered.
```

### Network failure behaviour

If the registration endpoint is unreachable (you're offline, the address doesn't resolve, or the service is down), the request gives up after 5 seconds and the command completes normally.  A dim one-liner appears at the bottom of `mcp-audit check` output:

```
Registration ping failed (offline?)
```

(`mcp-audit register` prints the same line and adds that your local file is saved.)  This is not an error.  Your scan result is unaffected.

---

## Local file paths in published output

Every scan resolves the absolute path to each MCP config file it reads
(``ServerConfig.config_path``), and most findings carry it too
(``Finding.finding_path`` — a SAST source file, an extension manifest, or the
scanned config itself). On the overwhelmingly common single-user desktop,
that absolute path is rooted under your home directory and therefore encodes
your OS username (e.g. ``/Users/sarah/.cursor/mcp.json``).

**In terminal output, the HTML dashboard, and plain JSON output
(`--format json` / `-o result.json`), that absolute path is shown as-is.**
You are looking at your own machine, or you explicitly chose where the JSON
goes — the real path is the useful part (it's what you'd paste into
`chmod`, an editor, or a follow-up script), and several integrations
(the mcp-audit VS Code extension's inline diagnostics, `scan --baseline`
drift comparison) resolve it directly.

**In the four outputs designed to leave the machine — the advisory feed
(`mcp-audit advise`), SARIF (`scan --format sarif`), Nucleus FlexConnect
(`push-nucleus` / `scan --format nucleus`), and the forensic snapshot export
(`mcp-audit snapshot`, all formats including `--stream`) — the path is
rewritten to a form relative to the current working directory (or, when that
isn't safely possible, to `~/...`) before it is serialised.** This both
protects your username and, for SARIF specifically, is what makes GitHub's
`upload-sarif` action able to match a result back to a file in your
repository at all — it reads the `uri` field literally rather than resolving
`uriBaseId`, so an absolute path there was already silently failing to
annotate pull requests. See `src/mcp_audit/_redact.py` and
`docs/github-action.md` for the mechanics.

**PDF reports** (`mcp-audit check --report pdf`) never include a raw file
path or the finding's evidence/remediation text at all — only a canned,
per-finding-ID remediation hint and a SHA-256 content hash — so there is
nothing to redact there.

### A stated limit, not a silent one

This redaction protects *this invocation's own* `$HOME` — which is what "does
mcp-audit leak my username" means for the overwhelming majority of scans,
where you're scanning your own client configs. It does **not** scrub an
unrelated username that happens to appear in a *different* account's
directory named in an explicitly-scanned path outside your own `$HOME` — for
example, running `mcp-audit scan --project /home/someone-else/shared-repo` on
a shared multi-user host still emits `someone-else` in the published output.
Recognising an arbitrary OS username anywhere in a string is a fundamentally
different, open-ended problem from redacting the one home directory a
process can name authoritatively as its own. If you publish scan output from
a shared host, treat any path outside your own home directory as
unredacted.

---

## Open source audit

mcp-audit is fully open source (Apache 2.0).  You can verify every privacy claim above by reading the source:

- `src/mcp_audit/registration/models.py` — exact payload schemas
- `src/mcp_audit/registration/client.py` — what is sent and when
- `src/mcp_audit/registration/manager.py` — how the local file is stored
- `src/mcp_audit/_redact.py` — the local-path redaction applied to every
  output sink designed to leave the machine
- `tests/test_registration.py` — automated tests that enforce privacy invariants
- `tests/test_advisory_feed.py`, `tests/test_sarif_output.py`,
  `tests/test_nucleus_output.py`, `tests/test_snapshot.py` — `TestLocalPathRedaction`
  in each file pins the path-redaction behaviour per sink
- `tests/test_terminal_output.py`, `tests/test_dashboard.py` — pin that the two
  local-only outputs deliberately keep absolute paths

---

*Last updated: 2026-10-25*
