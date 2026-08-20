# Privacy Policy — mcp-audit

**Short version:** mcp-audit collects no data by default.
Every scan runs entirely on your machine.  Nothing leaves unless you explicitly choose to register.

---

## Default behaviour (no registration)

- **No telemetry.** mcp-audit never phones home, sends usage statistics, or contacts any remote server during a normal scan.
- **No crash reports.** Errors are written to your terminal only.
- **Fully offline.** A plain `mcp-audit scan` makes zero network connections.  Network-touching flags (`--verify-hashes`, `--verify-signatures`, `--check-vulns`, `--connect`) are explicitly opt-in.

---

## Opt-in registration (`mcp-audit register`)

Registration is **completely optional**.  An unregistered user has identical functionality to a registered one.

### What registration does

Running `mcp-audit register` starts an interactive prompt that:

1. Asks for your name (or handle), org, and email.
2. Asks whether you want a follow-up if your scan grade falls below C.
3. Stores a `registration.json` file locally.
4. Sends a single HTTPS POST to `https://register.mcp-audit.dev/ping` with your registration details.

### What the initial registration POST sends

| Field | Example | Why |
|---|---|---|
| `name` | `"Sarah Chen"` | So we can address you by name |
| `org` | `"IBM Security"` | So we know who's using mcp-audit |
| `email` | `"sarah.chen@ibm.com"` | To send you new-rule notifications |
| `version` | `"0.11.0"` | To know which release you're on |
| `grade` | `"C"` | To contextualise your scan result |
| `follow_up_requested` | `true` | Your explicit preference |

**Nothing else.** The POST payload is defined in `src/mcp_audit/registration/models.py` as `RegistrationPostPayload` — you can audit it directly.

### What the initial registration POST does NOT send

- Config file contents
- Server names, commands, or arguments
- Tool names or descriptions
- Environment variable names or values
- File paths
- IP address (the server may log your IP as a standard HTTP header — this is unavoidable for any HTTPS request)

### Subsequent pings (after scan runs)

After you register, every `mcp-audit check` run sends a brief anonymous ping:

| Field | Example |
|---|---|
| `version` | `"0.11.0"` |
| `grade` | `"B"` |
| `registered` | `true` |

**No PII is ever included in a ping.** Name, org, and email are deliberately excluded.  The ping payload is defined as `RegistrationPingPayload` in `src/mcp_audit/registration/models.py`.

### Where the data goes

Registration data is received by a Cloudflare Worker or equivalent lightweight endpoint controlled by the project author (Adam Dudley, <https://github.com/adudley78>).  It is used solely to:

- Send new community rule notifications.
- Identify Fortune 500 / consulting firm users who may want to give design-partner feedback.
- Follow up (only if you opted in) when your scan grade is C or below.

It is **not** sold, shared with third parties, or used for advertising.

### Local storage

`registration.json` is written to:

```
<user-config-dir>/mcp-audit/registration.json
```

On macOS: `~/Library/Application Support/mcp-audit/registration.json`
On Linux: `~/.config/mcp-audit/registration.json`
On Windows: `%APPDATA%\mcp-audit\registration.json`

The file is created with `0o600` permissions (owner read/write only).

### Removing your registration

```bash
mcp-audit register --clear
```

This deletes `registration.json`.  No further pings will be sent.  You can verify the file is gone:

```bash
mcp-audit register --status
# Not registered.
```

### Network failure behaviour

If the registration endpoint is unreachable (you're offline, the domain doesn't resolve, or the service is down), the scan completes normally.  A dim one-liner appears at the bottom of `mcp-audit check` output:

```
Registration ping failed (offline?)
```

This is not an error.  Your scan result is unaffected.

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

*Last updated: 2026-08-20*
