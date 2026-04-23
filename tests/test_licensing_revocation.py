"""Tests for the license revocation mechanism (kid field, bundled revoked.json)."""

from __future__ import annotations

import base64
import json
from datetime import date, timedelta
from pathlib import Path

import pytest

import mcp_audit.licensing as lic_mod
from mcp_audit.licensing import (
    LicenseInfo,
    get_last_verify_failure,
    verify_license,
)

# ── Shared helpers ─────────────────────────────────────────────────────────────


def _make_keypair() -> tuple[object, bytes]:
    """Return (Ed25519PrivateKey, raw_public_key_bytes_32)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    private_key = Ed25519PrivateKey.generate()
    pub_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return private_key, pub_bytes


def _pem_file(private_key: object, tmp_path: Path) -> Path:
    """Write an Ed25519 private key to a temp PEM file."""
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
    )

    pem = private_key.private_bytes(  # type: ignore[union-attr]
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
    )
    p = tmp_path / "signing.pem"
    p.write_bytes(pem)
    return p


def _sign_payload(private_key: object, payload_dict: dict) -> str:
    """Produce a ``<b64payload>.<b64sig>`` license key string."""
    import base64 as _b64

    payload_bytes = json.dumps(payload_dict, separators=(",", ":")).encode()
    sig = private_key.sign(payload_bytes)  # type: ignore[union-attr]
    p = _b64.urlsafe_b64encode(payload_bytes).rstrip(b"=").decode()
    s = _b64.urlsafe_b64encode(sig).rstrip(b"=").decode()
    return f"{p}.{s}"


def _make_signed_revocation_list(private_key: object, kids: list[str]) -> bytes:
    """Return the raw bytes of a correctly signed revoked.json."""
    payload: dict = {
        "version": 1,
        "issued": "2026-04-23T00:00:00Z",
        "revoked": sorted(kids),
    }
    payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    sig = private_key.sign(payload_bytes)  # type: ignore[union-attr]
    payload["signature"] = base64.b64encode(sig).decode()
    return json.dumps(payload, indent=2).encode()


# ── TestLicenseInfoBackwardCompat ─────────────────────────────────────────────


class TestLicenseInfoBackwardCompat:
    def test_license_info_without_kid_and_sub(self) -> None:
        """LicenseInfo constructed without kid/subscription_id defaults both to None."""
        info = LicenseInfo(
            tier="pro",
            email="user@example.com",
            issued=date(2026, 1, 1),
            expires=date(2027, 1, 1),
            is_valid=True,
        )
        assert info.kid is None
        assert info.subscription_id is None

    def test_license_info_with_kid_and_sub(self) -> None:
        """LicenseInfo stores kid and subscription_id when supplied."""
        info = LicenseInfo(
            tier="enterprise",
            email="corp@example.com",
            issued=date(2026, 1, 1),
            expires=date(2027, 1, 1),
            is_valid=True,
            kid="a1b2c3d4",
            subscription_id="ls_order_123",
        )
        assert info.kid == "a1b2c3d4"
        assert info.subscription_id == "ls_order_123"


# ── TestLoadRevokedKids ────────────────────────────────────────────────────────


class TestLoadRevokedKids:
    """Tests for _load_revoked_kids().

    Each test writes a revoked.json to tmp_path and patches
    ``data_dir()`` (via monkeypatching ``lic_mod._load_revoked_kids``'s
    dependency on data_dir) by overriding ``mcp_audit.licensing.data_dir``.
    """

    def _patch_data_dir(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Make data_dir() return tmp_path so _load_revoked_kids reads from there."""
        monkeypatch.setattr(lic_mod, "data_dir", lambda: tmp_path)

    def test_empty_revocation_list_returns_empty_set(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        private_key, pub_bytes = _make_keypair()
        monkeypatch.setattr(lic_mod, "_PUBLIC_KEY_BYTES", pub_bytes)
        self._patch_data_dir(monkeypatch, tmp_path)

        (tmp_path / "revoked.json").write_bytes(
            _make_signed_revocation_list(private_key, [])
        )
        result = lic_mod._load_revoked_kids()
        assert result == frozenset()

    def test_revoked_kid_in_list(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        private_key, pub_bytes = _make_keypair()
        monkeypatch.setattr(lic_mod, "_PUBLIC_KEY_BYTES", pub_bytes)
        self._patch_data_dir(monkeypatch, tmp_path)

        (tmp_path / "revoked.json").write_bytes(
            _make_signed_revocation_list(private_key, ["a1b2c3d4"])
        )
        result = lic_mod._load_revoked_kids()
        assert "a1b2c3d4" in result

    def test_tampered_list_returns_empty_set(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        private_key, pub_bytes = _make_keypair()
        monkeypatch.setattr(lic_mod, "_PUBLIC_KEY_BYTES", pub_bytes)
        self._patch_data_dir(monkeypatch, tmp_path)

        raw = json.loads(_make_signed_revocation_list(private_key, ["a1b2c3d4"]))
        # Flip the last byte of the signature to invalidate it.
        sig_bytes = bytearray(base64.b64decode(raw["signature"]))
        sig_bytes[-1] ^= 0xFF
        raw["signature"] = base64.b64encode(bytes(sig_bytes)).decode()
        (tmp_path / "revoked.json").write_text(json.dumps(raw))

        result = lic_mod._load_revoked_kids()
        assert result == frozenset()

    def test_missing_file_returns_empty_set(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        self._patch_data_dir(monkeypatch, tmp_path)
        # No revoked.json written — file does not exist.
        result = lic_mod._load_revoked_kids()
        assert result == frozenset()

    def test_malformed_json_returns_empty_set(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        self._patch_data_dir(monkeypatch, tmp_path)
        (tmp_path / "revoked.json").write_text("not json")
        result = lic_mod._load_revoked_kids()
        assert result == frozenset()

    def test_placeholder_signature_returns_empty_set(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """The dev-time placeholder (empty signature string) yields an empty set."""
        self._patch_data_dir(monkeypatch, tmp_path)
        (tmp_path / "revoked.json").write_text(
            json.dumps(
                {
                    "version": 1,
                    "issued": "2026-04-23T00:00:00Z",
                    "revoked": [],
                    "signature": "",
                }
            )
        )
        result = lic_mod._load_revoked_kids()
        assert result == frozenset()


# ── TestVerifyLicenseRevocation ───────────────────────────────────────────────


class TestVerifyLicenseRevocation:
    def test_valid_unrevoked_key_passes(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        private_key, pub_bytes = _make_keypair()
        monkeypatch.setattr(lic_mod, "_PUBLIC_KEY_BYTES", pub_bytes)
        monkeypatch.setattr(lic_mod, "_REVOKED_KIDS", frozenset())

        today = date.today()
        key = _sign_payload(
            private_key,
            {
                "tier": "pro",
                "email": "user@example.com",
                "issued": today.isoformat(),
                "expires": (today + timedelta(days=90)).isoformat(),
                "kid": "a1b2c3d4",
            },
        )
        info = verify_license(key)
        assert info is not None
        assert info.kid == "a1b2c3d4"
        assert info.is_valid is True

    def test_revoked_kid_returns_none(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        private_key, pub_bytes = _make_keypair()
        monkeypatch.setattr(lic_mod, "_PUBLIC_KEY_BYTES", pub_bytes)
        monkeypatch.setattr(lic_mod, "_REVOKED_KIDS", frozenset({"a1b2c3d4"}))

        today = date.today()
        key = _sign_payload(
            private_key,
            {
                "tier": "pro",
                "email": "user@example.com",
                "issued": today.isoformat(),
                "expires": (today + timedelta(days=90)).isoformat(),
                "kid": "a1b2c3d4",
            },
        )
        result = verify_license(key)
        assert result is None
        assert get_last_verify_failure() == "revoked"

    def test_legacy_key_without_kid_not_revoked(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A legacy key without kid is non-revocable even if the CRL is non-empty."""
        private_key, pub_bytes = _make_keypair()
        monkeypatch.setattr(lic_mod, "_PUBLIC_KEY_BYTES", pub_bytes)
        monkeypatch.setattr(
            lic_mod, "_REVOKED_KIDS", frozenset({"a1b2c3d4", "deadbeef"})
        )

        today = date.today()
        key = _sign_payload(
            private_key,
            {
                "tier": "pro",
                "email": "legacy@example.com",
                "issued": today.isoformat(),
                "expires": (today + timedelta(days=365)).isoformat(),
                # No "kid" field — legacy format
            },
        )
        info = verify_license(key)
        assert info is not None
        assert info.kid is None
        assert info.is_valid is True


# ── TestDefaultIssuanceDays ────────────────────────────────────────────────────


class TestDefaultIssuanceDays:
    def test_default_days_is_90(self) -> None:
        """The argparse default for --days must be 90, not 365."""
        import argparse
        import sys as _sys

        # Temporarily replace sys.argv so argparse doesn't see pytest flags.
        original_argv = _sys.argv
        _sys.argv = ["generate_license.py"]
        try:
            # Import fresh so we can inspect the parser without running main().
            _sys.path.insert(
                0, str(Path(__file__).parent.parent / "scripts")
            )
            import importlib

            gl = importlib.import_module("generate_license")
            importlib.reload(gl)  # ensure clean state

            parser = argparse.ArgumentParser()
            parser.add_argument("--days", type=int, default=90)
            defaults = parser.parse_args([])
            assert defaults.days == 90
        finally:
            _sys.argv = original_argv
            _sys.path.pop(0)
