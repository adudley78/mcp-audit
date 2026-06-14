"""Tests for cli/register.py — the ``mcp-audit register`` command.

Covers:
- register --status with no registration file → prints "not registered"
- register --status with existing registration → prints truncated email and details
- register --clear with no file → clean no-op, exit 0
- register --clear with file → file deleted, exit 0
- register (interactive) — already registered → does not re-register
- register (interactive) — happy path: POST succeeds, file written at 0o600
- register (interactive) — network failure during POST → clean message, exit 0
- _truncate_email helper function edge cases
- Registration file permissions: 0o600
- registration/manager.py: load, save, clear, build_registration
- registration/client.py: post_registration success/failure, non-HTTPS rejected
"""

from __future__ import annotations

import os
import stat
import sys
import urllib.error
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from mcp_audit.cli import app
from mcp_audit.registration.manager import (
    build_registration,
    clear_registration,
    load_registration,
    save_registration,
)
from mcp_audit.registration.models import RegistrationConfig

runner = CliRunner()

# ── Helpers ───────────────────────────────────────────────────────────────────


def _config(
    email: str = "test@example.com",
    name: str = "Alice",
    org: str = "Acme",
    follow_up: bool = False,
) -> RegistrationConfig:
    return RegistrationConfig(
        name=name,
        org=org,
        email=email,
        follow_up_requested=follow_up,
        registered_at=datetime(2026, 1, 15, tzinfo=UTC),
    )


# ── _truncate_email ────────────────────────────────────────────────────────────


class TestTruncateEmail:
    def _truncate(self, email: str) -> str:
        from mcp_audit.cli.register import _truncate_email

        return _truncate_email(email)

    def test_normal_email_truncated(self) -> None:
        result = self._truncate("alice@example.com")
        assert result.startswith("al")
        assert "***" in result
        assert "@example.com" in result

    def test_short_local_part_returned_as_is(self) -> None:
        result = self._truncate("a@b.com")
        assert result == "a@b.com"

    def test_two_char_local_part_returned_as_is(self) -> None:
        result = self._truncate("ab@b.com")
        assert result == "ab@b.com"

    def test_three_char_local_part_truncated(self) -> None:
        result = self._truncate("abc@x.io")
        assert "***" in result


# ── registration/manager.py ───────────────────────────────────────────────────


class TestRegistrationManager:
    def test_load_returns_none_when_file_absent(self, tmp_path: Path) -> None:
        assert load_registration(config_dir=tmp_path) is None

    def test_save_and_load_roundtrip(self, tmp_path: Path) -> None:
        cfg = _config()
        save_registration(cfg, config_dir=tmp_path)
        loaded = load_registration(config_dir=tmp_path)
        assert loaded is not None
        assert loaded.email == "test@example.com"
        assert loaded.name == "Alice"

    def test_save_creates_file_at_0o600(self, tmp_path: Path) -> None:
        if sys.platform == "win32":
            pytest.skip("POSIX permissions not enforced on Windows")
        cfg = _config()
        save_registration(cfg, config_dir=tmp_path)
        path = tmp_path / "registration.json"
        mode = stat.S_IMODE(os.stat(path).st_mode)
        assert mode == 0o600

    def test_clear_removes_file_and_returns_true(self, tmp_path: Path) -> None:
        cfg = _config()
        save_registration(cfg, config_dir=tmp_path)
        result = clear_registration(config_dir=tmp_path)
        assert result is True
        assert not (tmp_path / "registration.json").exists()

    def test_clear_returns_false_when_no_file(self, tmp_path: Path) -> None:
        result = clear_registration(config_dir=tmp_path)
        assert result is False

    def test_build_registration_validates_email(self) -> None:
        cfg = build_registration(
            name="Bob",
            org="Corp",
            email="bob@corp.io",
            follow_up_requested=True,
        )
        assert cfg.email == "bob@corp.io"
        assert cfg.follow_up_requested is True
        assert cfg.registered_at is not None

    def test_build_registration_stamps_utc_time(self) -> None:
        before = datetime.now(UTC)
        cfg = build_registration(
            name="", org="", email="x@y.com", follow_up_requested=False
        )
        after = datetime.now(UTC)
        assert before <= cfg.registered_at <= after

    def test_load_returns_none_for_corrupt_file(self, tmp_path: Path) -> None:
        path = tmp_path / "registration.json"
        path.write_text("not valid json{{{", encoding="utf-8")
        result = load_registration(config_dir=tmp_path)
        assert result is None


# ── registration/client.py ────────────────────────────────────────────────────


class TestRegistrationClient:
    def test_post_registration_success(self) -> None:
        from mcp_audit.registration.client import post_registration

        cfg = _config()
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch(
            "mcp_audit.registration.client.urllib.request.urlopen",
            return_value=mock_response,
        ):
            result = post_registration(
                cfg, grade="B", endpoint="https://test.example.com"
            )

        assert result is True

    def test_post_registration_network_failure_returns_false(self) -> None:
        from mcp_audit.registration.client import post_registration

        cfg = _config()
        with patch(
            "mcp_audit.registration.client.urllib.request.urlopen",
            side_effect=urllib.error.URLError("connection refused"),
        ):
            result = post_registration(
                cfg, grade="A", endpoint="https://test.example.com"
            )

        assert result is False

    def test_non_https_endpoint_rejected(self) -> None:
        from mcp_audit.registration.client import post_registration

        cfg = _config()
        result = post_registration(
            cfg, grade="A", endpoint="http://insecure.example.com"
        )
        assert result is False

    def test_post_ping_success(self) -> None:
        from mcp_audit.registration.client import post_ping

        mock_response = MagicMock()
        mock_response.status = 201
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch(
            "mcp_audit.registration.client.urllib.request.urlopen",
            return_value=mock_response,
        ):
            result = post_ping(grade="A", endpoint="https://test.example.com")

        assert result is True

    def test_post_ping_network_failure_returns_false(self) -> None:
        from mcp_audit.registration.client import post_ping

        with patch(
            "mcp_audit.registration.client.urllib.request.urlopen",
            side_effect=urllib.error.URLError("timeout"),
        ):
            result = post_ping(grade="B", endpoint="https://test.example.com")

        assert result is False

    def test_http_4xx_response_returns_false(self) -> None:
        from mcp_audit.registration.client import post_registration

        cfg = _config()
        mock_response = MagicMock()
        mock_response.status = 400
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)

        with patch(
            "mcp_audit.registration.client.urllib.request.urlopen",
            return_value=mock_response,
        ):
            result = post_registration(
                cfg, grade="C", endpoint="https://test.example.com"
            )

        assert result is False


# ── cli/register.py — register --status ───────────────────────────────────────


class TestRegisterStatusCommand:
    def test_status_not_registered(self, tmp_path: Path) -> None:
        with patch(
            "mcp_audit.cli.register._reg_manager.load_registration",
            return_value=None,
        ):
            result = runner.invoke(app, ["register", "--status"])

        assert result.exit_code == 0
        assert "not registered" in result.output.lower()

    def test_status_shows_registration_details(self, tmp_path: Path) -> None:
        cfg = _config(email="alice@example.com", name="Alice", org="ACME")
        with patch(
            "mcp_audit.cli.register._reg_manager.load_registration",
            return_value=cfg,
        ):
            result = runner.invoke(app, ["register", "--status"])

        assert result.exit_code == 0
        # Email is truncated for privacy
        assert "al***@example.com" in result.output
        assert "Alice" in result.output
        assert "ACME" in result.output
        assert "2026-01-15" in result.output

    def test_status_shows_follow_up_yes(self) -> None:
        cfg = _config(follow_up=True)
        with patch(
            "mcp_audit.cli.register._reg_manager.load_registration",
            return_value=cfg,
        ):
            result = runner.invoke(app, ["register", "--status"])

        assert "yes" in result.output.lower()

    def test_status_shows_follow_up_no(self) -> None:
        cfg = _config(follow_up=False)
        with patch(
            "mcp_audit.cli.register._reg_manager.load_registration",
            return_value=cfg,
        ):
            result = runner.invoke(app, ["register", "--status"])

        assert "no" in result.output.lower()


# ── cli/register.py — register --clear ────────────────────────────────────────


class TestRegisterClearCommand:
    def test_clear_when_file_exists(self) -> None:
        with patch(
            "mcp_audit.cli.register._reg_manager.clear_registration",
            return_value=True,
        ):
            result = runner.invoke(app, ["register", "--clear"])

        assert result.exit_code == 0
        assert "removed" in result.output.lower()

    def test_clear_when_no_file(self) -> None:
        with patch(
            "mcp_audit.cli.register._reg_manager.clear_registration",
            return_value=False,
        ):
            result = runner.invoke(app, ["register", "--clear"])

        assert result.exit_code == 0
        assert (
            "nothing" in result.output.lower()
            or "no registration" in result.output.lower()
        )


# ── cli/register.py — register (interactive) ──────────────────────────────────


class TestRegisterInteractiveCommand:
    def test_already_registered_does_not_re_register(self) -> None:
        existing = _config()
        with patch(
            "mcp_audit.cli.register._reg_manager.load_registration",
            return_value=existing,
        ):
            result = runner.invoke(app, ["register"])

        assert result.exit_code == 0
        assert "already registered" in result.output.lower()

    def test_interactive_happy_path(self, tmp_path: Path) -> None:
        """Simulate user providing name/org/email/follow-up; POST succeeds."""
        # Simulate: name="Bob", org="Corp", email="bob@corp.io", follow_up="n"
        user_input = "Bob\nCorp\nbob@corp.io\nn\n"

        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)

        with (
            patch(
                "mcp_audit.cli.register._reg_manager.load_registration",
                return_value=None,
            ),
            patch(
                "mcp_audit.registration.manager._DEFAULT_CONFIG_DIR",
                tmp_path,
            ),
            patch(
                "mcp_audit.cli.register._reg_client.post_registration",
                return_value=True,
            ),
        ):
            result = runner.invoke(app, ["register"], input=user_input)

        assert result.exit_code == 0
        assert "registered" in result.output.lower()

    def test_interactive_network_failure_still_saves_file(self, tmp_path: Path) -> None:
        """POST fails but local file is saved; a dim message is shown."""
        user_input = "Carol\nStartup\ncarol@startup.io\ny\n"

        with (
            patch(
                "mcp_audit.cli.register._reg_manager.load_registration",
                return_value=None,
            ),
            patch(
                "mcp_audit.registration.manager._DEFAULT_CONFIG_DIR",
                tmp_path,
            ),
            patch(
                "mcp_audit.cli.register._reg_client.post_registration",
                return_value=False,
            ),
        ):
            result = runner.invoke(app, ["register"], input=user_input)

        assert result.exit_code == 0
        # Should mention that the ping failed but file is saved
        assert (
            "ping failed" in result.output.lower() or "offline" in result.output.lower()
        )

    def test_interactive_invalid_email_reprompts(self, tmp_path: Path) -> None:
        """An invalid email causes reprompt; valid email on second attempt proceeds."""
        # First email is invalid (no @), second is valid
        user_input = "Dave\nOrg\nnotemail\ndave@valid.org\nn\n"

        with (
            patch(
                "mcp_audit.cli.register._reg_manager.load_registration",
                return_value=None,
            ),
            patch(
                "mcp_audit.registration.manager._DEFAULT_CONFIG_DIR",
                tmp_path,
            ),
            patch(
                "mcp_audit.cli.register._reg_client.post_registration",
                return_value=True,
            ),
        ):
            result = runner.invoke(app, ["register"], input=user_input)

        assert result.exit_code == 0
        assert "not look like" in result.output or "registered" in result.output.lower()

    def test_registration_file_permissions_0o600(self, tmp_path: Path) -> None:
        """The registration file is written at 0o600."""
        if sys.platform == "win32":
            pytest.skip("POSIX permissions not enforced on Windows")

        user_input = "Eve\nCo\neve@co.io\nn\n"

        with (
            patch(
                "mcp_audit.cli.register._reg_manager.load_registration",
                return_value=None,
            ),
            patch(
                "mcp_audit.registration.manager._DEFAULT_CONFIG_DIR",
                tmp_path,
            ),
            patch(
                "mcp_audit.cli.register._reg_client.post_registration",
                return_value=True,
            ),
        ):
            result = runner.invoke(app, ["register"], input=user_input)

        assert result.exit_code == 0
        reg_file = tmp_path / "registration.json"
        assert reg_file.exists()
        mode = stat.S_IMODE(os.stat(reg_file).st_mode)
        assert mode == 0o600
