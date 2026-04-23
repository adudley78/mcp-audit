"""License key management for mcp-audit Pro and Enterprise features.

License keys are Ed25519-signed tokens with the format:

    <base64url-payload>.<base64url-signature>

The payload is compact JSON, e.g.:

    {"tier":"pro","email":"user@example.com","issued":"2026-04-14","expires":"2027-04-14"}

The signature covers the raw UTF-8 payload bytes.  Verification uses a public
key hardcoded in this module; the corresponding private key is kept offline and
used only by ``scripts/generate_license.py``.

No network calls are made at any point — verification is fully offline.
"""

from __future__ import annotations

import base64
import json
import stat
from datetime import date, timedelta
from pathlib import Path
from typing import Literal

from pydantic import BaseModel

# ── Configuration ─────────────────────────────────────────────────────────────

_LICENSE_FILE = Path.home() / ".config" / "mcp-audit" / "license.key"

# Replace with your actual Ed25519 public key bytes (exactly 32 bytes) after
# running:  python scripts/generate_license.py --generate-keypair
# Until replaced, verify_license() will always return None for every key.
_PUBLIC_KEY_BYTES: bytes = (
    b"\xdcO\xb72w\x9e4\x1d\r\xdb\xce/\xaa\x16\x94x"
    b"\xc4g\x92\xea\x17 9\xff 5sy\xb7\x97\xcd("
)

# Maps each feature name to the set of tier names that include it.
_FEATURE_TIERS: dict[str, frozenset[str]] = {
    "dashboard": frozenset({"pro", "enterprise"}),
    "nucleus": frozenset({"enterprise"}),
    "html_report": frozenset({"pro", "enterprise"}),
    "policy": frozenset({"pro", "enterprise"}),
    "fleet": frozenset({"enterprise"}),
    "fleet_merge": frozenset({"enterprise"}),
    "custom_rules": frozenset({"pro", "enterprise"}),
    "update_registry": frozenset({"pro", "enterprise"}),
    "governance": frozenset({"pro", "enterprise"}),
    "fleet_governance": frozenset({"enterprise"}),
    "sast": frozenset({"pro", "enterprise"}),
    "extensions": frozenset({"pro", "enterprise"}),
    "fleet_extensions": frozenset({"enterprise"}),
    "vuln_mirror": frozenset({"pro", "enterprise"}),
}


# ── Data model ────────────────────────────────────────────────────────────────


class LicenseInfo(BaseModel):
    """A verified, parsed license key payload."""

    tier: Literal["pro", "enterprise"]
    email: str
    issued: date
    expires: date
    is_valid: bool  # True when today <= expires


# ── Core functions ────────────────────────────────────────────────────────────


def verify_license(key_string: str) -> LicenseInfo | None:
    """Verify an Ed25519-signed license key string.

    Args:
        key_string: A license key in ``<base64url-payload>.<base64url-signature>``
            format as returned by :func:`generate_license_key`.

    Returns:
        A :class:`LicenseInfo` if the signature is valid and the payload is
        well-formed.  ``is_valid`` reflects whether the key has not yet expired.
        Returns ``None`` for any structural or cryptographic failure.
    """
    try:
        from cryptography.exceptions import InvalidSignature  # noqa: PLC0415
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: PLC0415
            Ed25519PublicKey,
        )
    except ImportError:
        return None

    if len(_PUBLIC_KEY_BYTES) != 32:
        return None

    parts = key_string.strip().split(".")
    if len(parts) != 2:
        return None

    payload_b64, sig_b64 = parts
    try:
        # urlsafe_b64decode requires padding to a multiple of 4.
        payload_bytes = base64.urlsafe_b64decode(payload_b64 + "==")
        sig_bytes = base64.urlsafe_b64decode(sig_b64 + "==")
    except ValueError:
        return None

    try:
        public_key = Ed25519PublicKey.from_public_bytes(_PUBLIC_KEY_BYTES)
        public_key.verify(sig_bytes, payload_bytes)
    except InvalidSignature:
        return None
    except (ValueError, TypeError):
        return None

    try:
        payload = json.loads(payload_bytes)
    except json.JSONDecodeError:
        return None

    try:
        tier = payload["tier"]
        email = str(payload["email"])
        issued = date.fromisoformat(payload["issued"])
        expires = date.fromisoformat(payload["expires"])
    except (KeyError, ValueError, TypeError):
        return None

    if tier not in {"pro", "enterprise"}:
        return None

    return LicenseInfo(
        tier=tier,
        email=email,
        issued=issued,
        expires=expires,
        is_valid=date.today() <= expires,
    )


def get_active_license() -> LicenseInfo | None:
    """Read and verify the stored license key.

    Reads from ``~/.config/mcp-audit/license.key``.  Returns ``None`` if the
    file does not exist, cannot be read, or contains an invalid key.
    """
    if not _LICENSE_FILE.exists():
        return None

    try:
        key_string = _LICENSE_FILE.read_text(encoding="utf-8").strip()
    except OSError:
        return None

    return verify_license(key_string)


def save_license(key_string: str) -> LicenseInfo:
    """Validate and persist a license key to ``~/.config/mcp-audit/license.key``.

    Creates the config directory if it does not exist.  Sets file permissions
    to 0o600 (owner read/write only).

    Args:
        key_string: The license key string to save.

    Returns:
        The parsed :class:`LicenseInfo` for the saved key.

    Raises:
        ValueError: If ``key_string`` fails verification.
    """
    info = verify_license(key_string)
    if info is None:
        raise ValueError("Invalid license key.")

    _LICENSE_FILE.parent.mkdir(parents=True, exist_ok=True)
    _LICENSE_FILE.write_text(key_string.strip() + "\n", encoding="utf-8")
    _LICENSE_FILE.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 0o600

    return info


def is_pro_feature_available(feature_name: str) -> bool:
    """Return True if the active license tier includes the named feature.

    Always returns False if no license is active, the license has expired,
    or the feature name is unrecognised.

    Args:
        feature_name: One of ``"dashboard"``, ``"nucleus"``, ``"html_report"``,
            ``"policy"``, ``"fleet"``, ``"fleet_merge"``, ``"custom_rules"``,
            or ``"update_registry"``.
    """
    required_tiers = _FEATURE_TIERS.get(feature_name)
    if required_tiers is None:
        return False

    info = get_active_license()
    if info is None or not info.is_valid:
        return False

    return info.tier in required_tiers


# ── Key generation (offline dev utility only) ─────────────────────────────────


def generate_license_key(
    tier: str,
    email: str,
    duration_days: int,
    private_key_path: str | Path,
) -> str:
    """Generate a signed Ed25519 license key.

    This is an offline utility function used by ``scripts/generate_license.py``
    to issue keys for customers.  The private key must never ship with the
    package.

    Args:
        tier: ``"pro"`` or ``"enterprise"``.
        email: Purchaser's email address.
        duration_days: Validity period in days from today.
        private_key_path: Path to a PEM-encoded Ed25519 private key file.

    Returns:
        A license key string: ``<base64url-payload>.<base64url-signature>``.

    Raises:
        TypeError: If the key file does not contain an Ed25519 private key.
        FileNotFoundError: If the key file does not exist.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: PLC0415
        Ed25519PrivateKey,
    )
    from cryptography.hazmat.primitives.serialization import (  # noqa: PLC0415
        load_pem_private_key,
    )

    today = date.today()
    expires = today + timedelta(days=duration_days)

    payload_dict = {
        "tier": tier,
        "email": email,
        "issued": today.isoformat(),
        "expires": expires.isoformat(),
    }
    payload_bytes = json.dumps(payload_dict, separators=(",", ":")).encode("utf-8")

    pem_data = Path(private_key_path).read_bytes()
    private_key = load_pem_private_key(pem_data, password=None)
    if not isinstance(private_key, Ed25519PrivateKey):
        raise TypeError("Key file must contain an Ed25519 private key.")

    signature = private_key.sign(payload_bytes)

    payload_b64 = base64.urlsafe_b64encode(payload_bytes).rstrip(b"=").decode()
    sig_b64 = base64.urlsafe_b64encode(signature).rstrip(b"=").decode()

    return f"{payload_b64}.{sig_b64}"
