"""Pydantic models for opt-in registration."""

from __future__ import annotations

import re
from datetime import datetime

from pydantic import BaseModel, field_validator

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class RegistrationConfig(BaseModel):
    """Persisted registration record stored in ``registration.json``.

    Only identity/contact fields are stored — no scan data, server names,
    credentials, or config paths are ever written here.
    """

    name: str = ""
    org: str = ""
    email: str
    follow_up_requested: bool = False
    registered_at: datetime

    @field_validator("email")
    @classmethod
    def email_must_contain_at(cls, v: str) -> str:
        """Validate that *email* contains an ``@`` and looks like an address."""
        if not _EMAIL_RE.match(v):
            raise ValueError(
                f"'{v}' does not look like a valid email address (must contain @)"
            )
        return v


class RegistrationPingPayload(BaseModel):
    """Payload for the anonymous post-scan ping (no PII).

    Sent after every ``check`` / ``scan`` run when the user is registered.
    Deliberately omits name, org, and email to keep pings PII-free.
    """

    version: str
    grade: str
    registered: bool = True


class RegistrationPostPayload(BaseModel):
    """Payload for the initial registration POST (contains PII).

    Sent once, at registration time, to ``_REGISTER_ENDPOINT``.
    Deliberately limited to identity + grade + follow-up preference.
    Config data, server names, and credentials are never included.
    """

    name: str
    org: str
    email: str
    version: str
    grade: str
    follow_up_requested: bool
