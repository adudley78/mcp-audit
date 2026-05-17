"""Tests for the opt-in registration module (STORY-0046)."""

from __future__ import annotations

import json
import os
import stat
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch
from urllib.error import URLError

import pytest

from mcp_audit.registration import client as reg_client
from mcp_audit.registration import manager as reg_manager
from mcp_audit.registration.models import (
    RegistrationConfig,
    RegistrationPingPayload,
    RegistrationPostPayload,
)

# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture()
def tmp_config_dir(tmp_path: Path) -> Path:
    """Return a temporary directory to use as the mcp-audit config dir."""
    d = tmp_path / "mcp-audit"
    d.mkdir()
    return d


@pytest.fixture()
def sample_config() -> RegistrationConfig:
    return RegistrationConfig(
        name="Sarah Chen",
        org="IBM Security",
        email="sarah.chen@ibm.com",
        follow_up_requested=True,
        registered_at=datetime(2026, 5, 17, 12, 0, 0, tzinfo=UTC),
    )


# ── RegistrationConfig Pydantic model ─────────────────────────────────────────


def test_registration_json_schema_round_trips(
    sample_config: RegistrationConfig,
) -> None:
    """RegistrationConfig serialises and deserialises without data loss."""
    raw = sample_config.model_dump_json()
    restored = RegistrationConfig.model_validate_json(raw)
    assert restored.name == sample_config.name
    assert restored.org == sample_config.org
    assert restored.email == sample_config.email
    assert restored.follow_up_requested is True
    assert restored.registered_at == sample_config.registered_at


def test_registration_email_validation_rejects_missing_at() -> None:
    """Email without '@' raises ValidationError."""
    from pydantic import ValidationError

    with pytest.raises(ValidationError, match="valid email"):
        RegistrationConfig(
            name="",
            org="",
            email="not-an-email",
            follow_up_requested=False,
            registered_at=datetime.now(UTC),
        )


def test_registration_email_validation_accepts_valid_address() -> None:
    """A well-formed email passes validation without error."""
    cfg = RegistrationConfig(
        name="",
        org="",
        email="user@example.com",
        follow_up_requested=False,
        registered_at=datetime.now(UTC),
    )
    assert cfg.email == "user@example.com"


# ── File creation and permissions ─────────────────────────────────────────────


def test_registration_file_created_with_correct_permissions(
    tmp_config_dir: Path, sample_config: RegistrationConfig
) -> None:
    """save_registration writes a 0o600 file under the config dir."""
    import sys

    path = reg_manager.save_registration(sample_config, config_dir=tmp_config_dir)

    assert path.exists(), "registration.json was not created"

    # Windows does not honour POSIX permission bits; skip the mode check there.
    if sys.platform != "win32":
        mode = stat.S_IMODE(os.stat(path).st_mode)
        assert mode == 0o600, f"Expected 0o600, got {oct(mode)}"

    data = json.loads(path.read_text())
    assert data["email"] == "sarah.chen@ibm.com"


def test_registration_load_returns_config(
    tmp_config_dir: Path, sample_config: RegistrationConfig
) -> None:
    """load_registration reads back exactly what was saved."""
    reg_manager.save_registration(sample_config, config_dir=tmp_config_dir)
    loaded = reg_manager.load_registration(config_dir=tmp_config_dir)

    assert loaded is not None
    assert loaded.org == "IBM Security"
    assert loaded.follow_up_requested is True


def test_registration_status_not_registered(tmp_config_dir: Path) -> None:
    """load_registration returns None when no file exists."""
    result = reg_manager.load_registration(config_dir=tmp_config_dir)
    assert result is None


# ── --clear ───────────────────────────────────────────────────────────────────


def test_registration_clear_removes_file(
    tmp_config_dir: Path, sample_config: RegistrationConfig
) -> None:
    """clear_registration deletes the file and returns True."""
    reg_manager.save_registration(sample_config, config_dir=tmp_config_dir)
    removed = reg_manager.clear_registration(config_dir=tmp_config_dir)

    assert removed is True
    path = tmp_config_dir / "registration.json"
    assert not path.exists()


def test_registration_clear_missing_file_returns_false(tmp_config_dir: Path) -> None:
    """clear_registration returns False when no file is present."""
    removed = reg_manager.clear_registration(config_dir=tmp_config_dir)
    assert removed is False


def test_registration_status_after_clear_returns_none(
    tmp_config_dir: Path, sample_config: RegistrationConfig
) -> None:
    """After clear_registration, load_registration returns None."""
    reg_manager.save_registration(sample_config, config_dir=tmp_config_dir)
    reg_manager.clear_registration(config_dir=tmp_config_dir)
    assert reg_manager.load_registration(config_dir=tmp_config_dir) is None


# ── Endpoint-unreachable handling ─────────────────────────────────────────────


def test_registration_endpoint_unreachable_does_not_raise(
    sample_config: RegistrationConfig,
) -> None:
    """post_registration returns False when endpoint is unreachable."""
    with patch("urllib.request.urlopen", side_effect=URLError("connection refused")):
        result = reg_client.post_registration(
            sample_config, grade="C", endpoint="https://register.mcp-audit.dev/ping"
        )
    assert result is False


def test_ping_endpoint_unreachable_does_not_raise() -> None:
    """post_ping returns False (not an exception) when endpoint is unreachable."""
    with patch("urllib.request.urlopen", side_effect=URLError("connection refused")):
        result = reg_client.post_ping(
            grade="B", endpoint="https://register.mcp-audit.dev/ping"
        )
    assert result is False


# ── Privacy: ping payload contains no PII ────────────────────────────────────


def test_registration_ping_sends_no_pii() -> None:
    """post_ping payload must not contain name, org, or email fields."""
    captured: list[dict] = []

    def fake_urlopen(req, timeout):  # type: ignore[no-untyped-def]
        body = req.data
        captured.append(json.loads(body))
        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.status = 200
        return mock_resp

    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        reg_client.post_ping(grade="A", endpoint="https://register.mcp-audit.dev/ping")

    assert len(captured) == 1, "Expected exactly one POST"
    payload = captured[0]
    for pii_field in ("name", "org", "email"):
        assert pii_field not in payload, (
            f"PII field '{pii_field}' found in ping payload"
        )
    assert payload["registered"] is True
    assert "grade" in payload
    assert "version" in payload


def test_registration_post_payload_schema() -> None:
    """RegistrationPostPayload carries the correct fields and nothing else."""
    payload = RegistrationPostPayload(
        name="Alice",
        org="ACME",
        email="alice@acme.com",
        version="0.11.0",
        grade="B",
        follow_up_requested=False,
    )
    d = payload.model_dump()
    expected = {"name", "org", "email", "version", "grade", "follow_up_requested"}
    assert set(d.keys()) == expected


def test_registration_ping_payload_schema() -> None:
    """RegistrationPingPayload carries only non-PII fields."""
    payload = RegistrationPingPayload(version="0.11.0", grade="A")
    d = payload.model_dump()
    assert set(d.keys()) == {"version", "grade", "registered"}
    assert "email" not in d
    assert "name" not in d


# ── Non-HTTPS URL is rejected silently ───────────────────────────────────────


def test_post_json_rejects_http_url() -> None:
    """client._post_json silently returns False for non-HTTPS URLs."""
    result = reg_client._post_json(
        {}, "http://register.mcp-audit.dev/ping", label="test"
    )
    assert result is False


# ── docs/privacy.md exists (smoke test) ──────────────────────────────────────


def test_docs_privacy_md_exists() -> None:
    """docs/privacy.md must exist as part of the registration feature."""
    repo_root = Path(__file__).parent.parent
    privacy_doc = repo_root / "docs" / "privacy.md"
    assert privacy_doc.exists(), (
        "docs/privacy.md is missing — it must document what registration sends"
    )
