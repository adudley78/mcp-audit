"""Opt-in registration package for mcp-audit.

Users who choose to register share contact details so they can be contacted
about project updates, and may opt in to a follow-up when their scan grade is
C or below.  Registration is entirely voluntary; an unregistered user
experiences no behaviour change (every feature works without it).

Privacy invariants (non-negotiable):
- No config data, server names, tool names, credentials, or file paths ever
  leave the machine as part of any registration or ping payload.
- The initial POST carries: name, org, email, version, grade,
  follow_up_requested — nothing else.
- Subsequent pings carry: version, grade, registered=True — no PII.
"""
