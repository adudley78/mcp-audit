"""Tests for the mcp-audit license key system."""

from __future__ import annotations

import base64
import json
from collections.abc import Generator
from datetime import date, timedelta
from pathlib import Path

import pytest

import mcp_audit.licensing as lic_mod
from mcp_audit.licensing import (
    LicenseInfo,
    generate_license_key,
    get_active_license,
    is_pro_feature_available,
    save_license,
    verify_license,
)

# ── Fixtures ───────────────────────────────────────────────────────────────────


@pytest.fixture()
def ed25519_keypair() -> tuple[object, bytes]:
    """Return (Ed25519PrivateKey, raw_public_key_bytes_32)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    private_key = Ed25519PrivateKey.generate()
    pub_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return private_key, pub_bytes


@pytest.fixture()
def patched_pubkey(
    ed25519_keypair: tuple[object, bytes],
    monkeypatch: pytest.MonkeyPatch,
) -> bytes:
    """Patch _PUBLIC_KEY_BYTES with a freshly generated key and return the bytes."""
    _, pub_bytes = ed25519_keypair
    monkeypatch.setattr(lic_mod, "_PUBLIC_KEY_BYTES", pub_bytes)
    return pub_bytes


@pytest.fixture()
def private_key_pem_file(
    ed25519_keypair: tuple[object, bytes],
    tmp_path: Path,
) -> Path:
    """Write the private key to a temp PEM file and return its path."""
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
    )

    private_key, _ = ed25519_keypair
    pem = private_key.private_bytes(  # type: ignore[attr-defined]
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
    )
    key_file = tmp_path / "signing.pem"
    key_file.write_bytes(pem)
    return key_file


@pytest.fixture()
def patched_license_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Generator[Path, None, None]:
    """Redirect _LICENSE_FILE to a temp location so tests don't touch ~."""
    fake_path = tmp_path / ".config" / "mcp-audit" / "license.key"
    monkeypatch.setattr(lic_mod, "_LICENSE_FILE", fake_path)
    yield fake_path


# ── Helper ─────────────────────────────────────────────────────────────────────


def _sign_payload(private_key: object, payload_dict: dict) -> str:
    """Directly sign a payload dict with the given private key."""
    payload_bytes = json.dumps(payload_dict, separators=(",", ":")).encode("utf-8")
    sig = private_key.sign(payload_bytes)  # type: ignore[attr-defined]
    p = base64.urlsafe_b64encode(payload_bytes).rstrip(b"=").decode()
    s = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
    return f"{p}.{s}"


# ── verify_license ─────────────────────────────────────────────────────────────


class TestVerifyLicense:
    def test_valid_pro_license(
        self,
        ed25519_keypair: tuple[object, bytes],
        patched_pubkey: bytes,
    ) -> None:
        private_key, _ = ed25519_keypair
        today = date.today()
        key = _sign_payload(
            private_key,
            {
                "tier": "pro",
                "email": "user@example.com",
                "issued": today.isoformat(),
                "expires": (today + timedelta(days=365)).isoformat(),
            },
        )
        info = verify_license(key)
        assert info is not None
        assert info.tier == "pro"
        assert info.email == "user@example.com"
        assert info.is_valid is True

    def test_valid_enterprise_license(
        self,
        ed25519_keypair: tuple[object, bytes],
        patched_pubkey: bytes,
    ) -> None:
        private_key, _ = ed25519_keypair
        today = date.today()
        key = _sign_payload(
            private_key,
            {
                "tier": "enterprise",
                "email": "corp@example.com",
                "issued": today.isoformat(),
                "expires": (today + timedelta(days=730)).isoformat(),
            },
        )
        info = verify_license(key)
        assert info is not None
        assert info.tier == "enterprise"
        assert info.is_valid is True

    def test_expired_license_returns_is_valid_false(
        self,
        ed25519_keypair: tuple[object, bytes],
        patched_pubkey: bytes,
    ) -> None:
        private_key, _ = ed25519_keypair
        yesterday = date.today() - timedelta(days=1)
        key = _sign_payload(
            private_key,
            {
                "tier": "pro",
                "email": "expired@example.com",
                "issued": (yesterday - timedelta(days=365)).isoformat(),
                "expires": yesterday.isoformat(),
            },
        )
        info = verify_license(key)
        assert info is not None
        assert info.is_valid is False

    def test_corrupted_key_returns_none(self, patched_pubkey: bytes) -> None:
        assert verify_license("notavalidkey") is None
        assert verify_license("garbage.garbage") is None
        assert verify_license("") is None

    def test_tampered_payload_returns_none(
        self,
        ed25519_keypair: tuple[object, bytes],
        patched_pubkey: bytes,
    ) -> None:
        private_key, _ = ed25519_keypair
        today = date.today()
        key = _sign_payload(
            private_key,
            {
                "tier": "pro",
                "email": "original@example.com",
                "issued": today.isoformat(),
                "expires": (today + timedelta(days=365)).isoformat(),
            },
        )
        # Tamper with the payload portion of the key.
        parts = key.split(".")
        evil_payload = json.dumps(
            {
                "tier": "enterprise",  # upgraded tier
                "email": "original@example.com",
                "issued": today.isoformat(),
                "expires": (today + timedelta(days=3650)).isoformat(),
            },
            separators=(",", ":"),
        ).encode()
        tampered = (
            base64.urlsafe_b64encode(evil_payload).rstrip(b"=").decode()
            + "."
            + parts[1]
        )
        assert verify_license(tampered) is None

    def test_wrong_public_key_returns_none(
        self,
        ed25519_keypair: tuple[object, bytes],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        private_key, _ = ed25519_keypair

        # Patch in a *different* public key.
        other_private = Ed25519PrivateKey.generate()
        other_pub = other_private.public_key().public_bytes(  # type: ignore[union-attr]
            Encoding.Raw, PublicFormat.Raw
        )
        monkeypatch.setattr(lic_mod, "_PUBLIC_KEY_BYTES", other_pub)

        today = date.today()
        key = _sign_payload(
            private_key,
            {
                "tier": "pro",
                "email": "user@example.com",
                "issued": today.isoformat(),
                "expires": (today + timedelta(days=365)).isoformat(),
            },
        )
        assert verify_license(key) is None

    def test_placeholder_public_key_returns_none(
        self,
        ed25519_keypair: tuple[object, bytes],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Empty placeholder key rejects all keys without crashing."""
        monkeypatch.setattr(lic_mod, "_PUBLIC_KEY_BYTES", b"")
        private_key, _ = ed25519_keypair
        today = date.today()
        key = _sign_payload(
            private_key,
            {
                "tier": "pro",
                "email": "user@example.com",
                "issued": today.isoformat(),
                "expires": (today + timedelta(days=365)).isoformat(),
            },
        )
        assert verify_license(key) is None

    def test_unknown_tier_returns_none(
        self,
        ed25519_keypair: tuple[object, bytes],
        patched_pubkey: bytes,
    ) -> None:
        private_key, _ = ed25519_keypair
        today = date.today()
        key = _sign_payload(
            private_key,
            {
                "tier": "superadmin",  # not a known tier
                "email": "user@example.com",
                "issued": today.isoformat(),
                "expires": (today + timedelta(days=365)).isoformat(),
            },
        )
        assert verify_license(key) is None


# ── generate_license_key ───────────────────────────────────────────────────────


class TestGenerateLicenseKey:
    def test_generates_valid_pro_key(
        self,
        patched_pubkey: bytes,
        private_key_pem_file: Path,
    ) -> None:
        key = generate_license_key(
            "pro", "buyer@example.com", 365, private_key_pem_file
        )
        info = verify_license(key)
        assert info is not None
        assert info.tier == "pro"
        assert info.email == "buyer@example.com"
        assert info.is_valid is True

    def test_generates_valid_enterprise_key(
        self,
        patched_pubkey: bytes,
        private_key_pem_file: Path,
    ) -> None:
        key = generate_license_key(
            "enterprise", "corp@bigco.com", 730, private_key_pem_file
        )
        info = verify_license(key)
        assert info is not None
        assert info.tier == "enterprise"

    def test_expiry_date_is_correct(
        self,
        patched_pubkey: bytes,
        private_key_pem_file: Path,
    ) -> None:
        key = generate_license_key("pro", "test@example.com", 90, private_key_pem_file)
        info = verify_license(key)
        assert info is not None
        expected_expires = date.today() + timedelta(days=90)
        assert info.expires == expected_expires

    def test_wrong_key_type_raises(self, tmp_path: Path) -> None:
        """RSA key file should raise TypeError."""
        from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
        )

        rsa_key = generate_private_key(65537, 2048)
        pem = rsa_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
        key_file = tmp_path / "rsa.pem"
        key_file.write_bytes(pem)

        with pytest.raises(TypeError, match="Ed25519"):
            generate_license_key("pro", "test@example.com", 365, key_file)


# ── save_license / get_active_license round-trip ──────────────────────────────


class TestSaveLicenseRoundTrip:
    def test_save_and_retrieve(
        self,
        patched_pubkey: bytes,
        private_key_pem_file: Path,
        patched_license_file: Path,
    ) -> None:
        key = generate_license_key("pro", "user@example.com", 365, private_key_pem_file)
        info_saved = save_license(key)
        assert info_saved.tier == "pro"

        info_loaded = get_active_license()
        assert info_loaded is not None
        assert info_loaded.tier == "pro"
        assert info_loaded.email == "user@example.com"
        assert info_loaded.is_valid is True

    def test_file_permissions_are_600(
        self,
        patched_pubkey: bytes,
        private_key_pem_file: Path,
        patched_license_file: Path,
    ) -> None:
        key = generate_license_key("pro", "user@example.com", 365, private_key_pem_file)
        save_license(key)
        mode = patched_license_file.stat().st_mode
        assert (mode & 0o777) == 0o600

    def test_save_invalid_key_raises(self, patched_license_file: Path) -> None:
        with pytest.raises(ValueError, match="Invalid license key"):
            save_license("completely-invalid-garbage")

    def test_no_license_file_returns_none(self, patched_license_file: Path) -> None:
        assert not patched_license_file.exists()
        assert get_active_license() is None

    def test_creates_directory_if_needed(
        self,
        patched_pubkey: bytes,
        private_key_pem_file: Path,
        patched_license_file: Path,
    ) -> None:
        assert not patched_license_file.parent.exists()
        key = generate_license_key("pro", "user@example.com", 365, private_key_pem_file)
        save_license(key)
        assert patched_license_file.exists()

    def test_save_enterprise_key(
        self,
        patched_pubkey: bytes,
        private_key_pem_file: Path,
        patched_license_file: Path,
    ) -> None:
        key = generate_license_key(
            "enterprise", "admin@corp.com", 365, private_key_pem_file
        )
        info = save_license(key)
        assert info.tier == "enterprise"
        retrieved = get_active_license()
        assert retrieved is not None
        assert retrieved.tier == "enterprise"


# ── is_pro_feature_available ───────────────────────────────────────────────────


class TestIsProFeatureAvailable:
    """Test every feature × tier combination."""

    def _activate(
        self,
        tier: str,
        private_key_pem_file: Path,
        patched_license_file: Path,
    ) -> None:
        key = generate_license_key(tier, "user@example.com", 365, private_key_pem_file)
        save_license(key)

    # --- No license ---

    def test_no_license_blocks_all_features(
        self,
        monkeypatch: pytest.MonkeyPatch,
        patched_license_file: Path,
    ) -> None:
        monkeypatch.setattr(lic_mod, "_PUBLIC_KEY_BYTES", b"")
        for feature in ("dashboard", "nucleus", "html_report", "policy", "fleet"):
            assert is_pro_feature_available(feature) is False

    # --- Pro tier ---

    def test_pro_dashboard_available(
        self,
        patched_pubkey: bytes,
        private_key_pem_file: Path,
        patched_license_file: Path,
    ) -> None:
        self._activate("pro", private_key_pem_file, patched_license_file)
        assert is_pro_feature_available("dashboard") is True

    def test_pro_html_report_available(
        self,
        patched_pubkey: bytes,
        private_key_pem_file: Path,
        patched_license_file: Path,
    ) -> None:
        self._activate("pro", private_key_pem_file, patched_license_file)
        assert is_pro_feature_available("html_report") is True

    def test_pro_policy_available(
        self,
        patched_pubkey: bytes,
        private_key_pem_file: Path,
        patched_license_file: Path,
    ) -> None:
        self._activate("pro", private_key_pem_file, patched_license_file)
        assert is_pro_feature_available("policy") is True

    def test_pro_nucleus_unavailable(
        self,
        patched_pubkey: bytes,
        private_key_pem_file: Path,
        patched_license_file: Path,
    ) -> None:
        self._activate("pro", private_key_pem_file, patched_license_file)
        assert is_pro_feature_available("nucleus") is False

    def test_pro_fleet_unavailable(
        self,
        patched_pubkey: bytes,
        private_key_pem_file: Path,
        patched_license_file: Path,
    ) -> None:
        self._activate("pro", private_key_pem_file, patched_license_file)
        assert is_pro_feature_available("fleet") is False

    # --- Enterprise tier ---

    def test_enterprise_all_features_available(
        self,
        patched_pubkey: bytes,
        private_key_pem_file: Path,
        patched_license_file: Path,
    ) -> None:
        self._activate("enterprise", private_key_pem_file, patched_license_file)
        for feature in ("dashboard", "nucleus", "html_report", "policy", "fleet"):
            assert is_pro_feature_available(feature) is True, feature

    # --- Expired license ---

    def test_expired_license_blocks_all_features(
        self,
        ed25519_keypair: tuple[object, bytes],
        monkeypatch: pytest.MonkeyPatch,
        patched_license_file: Path,
    ) -> None:
        private_key, pub_bytes = ed25519_keypair
        monkeypatch.setattr(lic_mod, "_PUBLIC_KEY_BYTES", pub_bytes)

        yesterday = date.today() - timedelta(days=1)
        key = _sign_payload(
            private_key,
            {
                "tier": "enterprise",
                "email": "expired@example.com",
                "issued": (yesterday - timedelta(days=365)).isoformat(),
                "expires": yesterday.isoformat(),
            },
        )
        patched_license_file.parent.mkdir(parents=True, exist_ok=True)
        patched_license_file.write_text(key + "\n")

        for feature in ("dashboard", "nucleus", "html_report", "policy", "fleet"):
            assert is_pro_feature_available(feature) is False, feature

    # --- Unknown feature ---

    def test_unknown_feature_returns_false(
        self,
        patched_pubkey: bytes,
        private_key_pem_file: Path,
        patched_license_file: Path,
    ) -> None:
        self._activate("enterprise", private_key_pem_file, patched_license_file)
        assert is_pro_feature_available("nonexistent_feature") is False


# ── LicenseInfo model ──────────────────────────────────────────────────────────


class TestLicenseInfoModel:
    def test_model_fields(self) -> None:
        info = LicenseInfo(
            tier="pro",
            email="test@example.com",
            issued=date(2026, 1, 1),
            expires=date(2027, 1, 1),
            is_valid=True,
        )
        assert info.tier == "pro"
        assert info.email == "test@example.com"
        assert info.is_valid is True

    def test_expired_model(self) -> None:
        info = LicenseInfo(
            tier="enterprise",
            email="corp@example.com",
            issued=date(2025, 1, 1),
            expires=date(2025, 12, 31),
            is_valid=False,
        )
        assert info.is_valid is False
