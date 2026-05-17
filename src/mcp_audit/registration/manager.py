"""Read, write, and clear the local registration file.

The registration file lives at::

    <user-config-dir>/mcp-audit/registration.json

It is written with 0o600 permissions (owner read/write only).  The parent
directory is created with 0o700 if it does not exist — consistent with the
baseline and rug-pull state storage patterns used elsewhere in mcp-audit.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import UTC, datetime
from pathlib import Path

from platformdirs import user_config_dir

from mcp_audit.registration.models import RegistrationConfig

logger = logging.getLogger(__name__)

_DEFAULT_CONFIG_DIR = Path(user_config_dir("mcp-audit"))
_REGISTRATION_FILENAME = "registration.json"


def _registration_path(config_dir: Path | None = None) -> Path:
    """Return the absolute path to ``registration.json``."""
    base = config_dir if config_dir is not None else _DEFAULT_CONFIG_DIR
    return base / _REGISTRATION_FILENAME


def load_registration(config_dir: Path | None = None) -> RegistrationConfig | None:
    """Return the persisted :class:`RegistrationConfig`, or ``None`` if absent.

    Args:
        config_dir: Override the default ``<user-config-dir>/mcp-audit``
            directory.  Used by tests to inject a temporary path.

    Returns:
        A :class:`RegistrationConfig` instance when the file exists and parses
        cleanly, otherwise ``None``.
    """
    path = _registration_path(config_dir)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return RegistrationConfig.model_validate(data)
    except Exception:  # noqa: BLE001
        logger.debug("Failed to parse registration.json — treating as unregistered")
        return None


def save_registration(
    config: RegistrationConfig,
    config_dir: Path | None = None,
) -> Path:
    """Persist *config* to ``registration.json`` with 0o600 permissions.

    The parent directory (``<user-config-dir>/mcp-audit``) is created with
    0o700 if it does not exist.

    Args:
        config: The :class:`RegistrationConfig` to persist.
        config_dir: Override directory (used by tests).

    Returns:
        The resolved :class:`~pathlib.Path` that was written.
    """
    path = _registration_path(config_dir)
    _ensure_dir(path.parent)

    payload = config.model_dump_json(indent=2)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, payload.encode("utf-8"))
    finally:
        os.close(fd)

    return path


def clear_registration(config_dir: Path | None = None) -> bool:
    """Delete ``registration.json`` if it exists.

    Args:
        config_dir: Override directory (used by tests).

    Returns:
        ``True`` when the file existed and was removed, ``False`` otherwise.
    """
    path = _registration_path(config_dir)
    if path.exists():
        path.unlink()
        return True
    return False


def build_registration(
    name: str,
    org: str,
    email: str,
    follow_up_requested: bool,
) -> RegistrationConfig:
    """Construct a :class:`RegistrationConfig` stamped with the current UTC time.

    Args:
        name: Display name or handle (may be empty).
        org: Organisation name (may be empty).
        email: Contact email (validated by the Pydantic model).
        follow_up_requested: Whether the user opted in to a follow-up.

    Returns:
        A validated :class:`RegistrationConfig`.
    """
    return RegistrationConfig(
        name=name,
        org=org,
        email=email,
        follow_up_requested=follow_up_requested,
        registered_at=datetime.now(UTC),
    )


def _ensure_dir(directory: Path) -> None:
    """Create *directory* at 0o700 if it does not already exist."""
    if not directory.exists():
        directory.mkdir(parents=True, mode=0o700, exist_ok=True)
