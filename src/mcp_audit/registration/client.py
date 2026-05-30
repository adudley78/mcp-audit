"""HTTPS client for opt-in registration pings.

Two separate methods handle two separate payloads — the privacy model is
enforced at the code level:

* :func:`post_registration` — called once at registration time; sends name,
  org, email, version, grade, and follow_up_requested.
* :func:`post_ping` — called on subsequent ``check`` / ``scan`` runs; sends
  only version, grade, and registered=True.  **No PII is ever included.**

Both methods fail silently on network errors so the scan always completes.
"""

from __future__ import annotations

import json
import logging
import urllib.request
from urllib.error import URLError

from mcp_audit import __version__
from mcp_audit.registration.models import (
    RegistrationConfig,
    RegistrationPingPayload,
    RegistrationPostPayload,
)

logger = logging.getLogger(__name__)

# Pipedream webhook — routes to email notification + Google Sheets log;
# update to register.mcp-audit.dev when that domain is live
_REGISTER_ENDPOINT = "https://eo4jvaanlkuohuc.m.pipedream.net"

_TIMEOUT_SECONDS = 5


def post_registration(
    config: RegistrationConfig,
    grade: str,
    *,
    endpoint: str = _REGISTER_ENDPOINT,
) -> bool:
    """POST the initial registration record to *endpoint*.

    Payload fields: name, org, email, version, grade, follow_up_requested.
    No config data, server names, tool names, or credentials are included.

    Args:
        config: The local :class:`~mcp_audit.registration.models.RegistrationConfig`.
        grade: Letter grade from the most-recent scan (e.g. ``"C"``).
        endpoint: Override the default endpoint (used by tests).

    Returns:
        ``True`` on HTTP 2xx, ``False`` on any network/HTTP error.
    """
    payload = RegistrationPostPayload(
        name=config.name,
        org=config.org,
        email=config.email,
        version=__version__,
        grade=grade,
        follow_up_requested=config.follow_up_requested,
    )
    return _post_json(payload.model_dump(), endpoint, label="registration")


def post_ping(
    grade: str,
    *,
    endpoint: str = _REGISTER_ENDPOINT,
) -> bool:
    """POST an anonymous ping to *endpoint* (no PII).

    Payload fields: version, grade, registered=True.
    Name, org, and email are deliberately excluded.

    Args:
        grade: Letter grade from the current scan.
        endpoint: Override the default endpoint (used by tests).

    Returns:
        ``True`` on HTTP 2xx, ``False`` on any network/HTTP error.
    """
    payload = RegistrationPingPayload(
        version=__version__,
        grade=grade,
    )
    return _post_json(payload.model_dump(), endpoint, label="ping")


def _post_json(data: dict, url: str, *, label: str) -> bool:
    """POST *data* as JSON to *url*.

    Enforces HTTPS-only to prevent accidental plaintext PII transmission.
    Uses ``urllib.request`` exclusively (no third-party HTTP libraries) —
    consistent with ``attestation/hasher.py`` and ``cli/registry.py``.

    Args:
        data: Dictionary to serialise as JSON.
        url: Target URL.  Must start with ``https://``.
        label: Human-readable label for log messages.

    Returns:
        ``True`` on HTTP 2xx, ``False`` on any error.
    """
    if not url.startswith("https://"):
        logger.warning("Registration %s skipped: non-HTTPS URL rejected", label)
        return False

    body = json.dumps(data).encode("utf-8")
    user_agent = f"mcp-audit/{__version__}"
    req = urllib.request.Request(  # noqa: S310  # nosec B310 — HTTPS-only guard enforced above; scheme validated in caller
        url,
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": user_agent},
        method="POST",
    )
    try:
        with urllib.request.urlopen(  # noqa: S310  # nosec B310 — HTTPS-only guard enforced above; scheme validated in caller
            req, timeout=_TIMEOUT_SECONDS
        ) as resp:
            return 200 <= resp.status < 300
    except URLError as exc:
        logger.debug("Registration %s failed (network): %s", label, exc)
        return False
    except Exception as exc:  # noqa: BLE001
        logger.debug("Registration %s failed (unexpected): %s", label, exc)
        return False
