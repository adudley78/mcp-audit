# ADR-0002 — Privacy Model for Opt-in Registration

**Date:** 2026-05-17
**Status:** Accepted
**Deciders:** Adam Dudley (product owner)

---

## Context

mcp-audit is positioned as a privacy-first tool — all scans run offline by default and no telemetry is collected.  However, the product has no visibility into who is using it.  When a CISO at a Fortune 500 runs the tool and gets a grade C, there is no inbound signal Adam can act on to offer design-partner outreach or a follow-up.

STORY-0046 adds an opt-in registration flow.  Three questions arose during design:

1. Should registration be opt-in or opt-out?
2. Should subsequent scans send PII (name, org, email) in every ping, or only in the initial POST?
3. Should the registration endpoint be a full backend service or a lightweight webhook?

---

## Decision 1 — Explicit opt-in only; zero data by default

**Decision:** Registration is an explicit user action (`mcp-audit register`).  An unregistered user sends no data whatsoever.  There is no passive enrollment, no anonymous telemetry, and no opt-out banner.

**Rationale:**

- mcp-audit's privacy-first brand is a core differentiator.  Any passive data collection — even fully anonymised — would undermine it and invite community backlash.
- The target audience (security engineers, CISOs) is unusually sensitive to telemetry.  Opt-out or silent enrollment would be discovered, blogged about, and damage trust permanently.
- The value exchange is asymmetric: the user gets new rule notifications and optionally a follow-up; Adam gets an inbound signal.  This exchange only works if the user consciously chooses it.
- Consistency with `docs/telemetry.md`, which states: "mcp-audit collects no telemetry."  Opt-in registration does not contradict this because it requires affirmative action.

---

## Decision 2 — PII in initial POST only; anonymous pings thereafter

**Decision:** The initial registration POST sends: `name`, `org`, `email`, `version`, `grade`, `follow_up_requested`.  All subsequent scan pings send only `version`, `grade`, `registered=True` — no PII.

**Rationale:**

- The goal of subsequent pings is to track adoption trends (grade distribution, version spread), not to re-identify users.  Grade + version is sufficient for this purpose.
- Sending name/org/email on every scan ping would create a large corpus of PII logs server-side.  Minimising PII surface reduces breach risk.
- The separation is enforced at the code level via two distinct Pydantic models (`RegistrationPostPayload` vs. `RegistrationPingPayload`) — it cannot be accidentally conflated.
- This model is disclosed transparently in `docs/privacy.md`, making it auditable.

**Privacy invariants that must be maintained:**
- `RegistrationPingPayload` must never add `name`, `org`, or `email` fields.
- `client.post_ping()` must call only `post_ping`, never `post_registration`, so the payloads stay separate.
- The HTTPS-only guard in `_post_json()` prevents accidental PII transmission over plaintext HTTP.

---

## Decision 3 — Lightweight endpoint; graceful silent failure

**Decision:** The registration endpoint is a single HTTPS URL (`https://register.mcp-audit.dev/ping`) handled by a lightweight service (Cloudflare Worker, Airtable webhook, or similar) that the project owner controls.  The client side uses `urllib.request` (no third-party HTTP library), times out in 5 seconds, and returns `False` on any error without raising an exception.

**Rationale:**

- The scan must never be blocked by a network call.  A 5-second timeout ensures the worst-case latency impact is bounded.
- Silent failure is preferable to a visible error — a registration ping failing should not alarm the user or interrupt their workflow; the dim warning line ("Registration ping failed (offline?)") is informational only.
- Using `urllib.request` (standard library only) is consistent with `attestation/hasher.py` and `cli/registry.py` and avoids adding a new dependency for a non-critical feature.
- A lightweight endpoint (vs. a full backend) is sufficient for v1 because the data volume is small and the only operation is write.  A more capable backend (with deduplication, querying, etc.) is a separate non-Cursor project.
- Shipping the constant `_REGISTER_ENDPOINT` in code even before the domain resolves means the feature is complete and testable before infrastructure is provisioned.

---

## Consequences

- Users who never run `mcp-audit register` experience zero behaviour change — no new network calls, no new files, no new output.
- The `registration/` module is self-contained and has no circular dependencies with the scan pipeline.
- `tests/test_registration.py` enforces the privacy invariants (ping payload contains no PII, HTTP URLs rejected) as automated regression guards.
- The dual-payload design (`RegistrationPostPayload` vs. `RegistrationPingPayload`) is a permanent constraint — any future change that merges them or adds PII to the ping payload requires a new ADR and a `docs/privacy.md` update.
- The endpoint infrastructure (domain, TLS cert, Worker code, KV store) is Adam's responsibility and is out of scope for the mcp-audit codebase.
