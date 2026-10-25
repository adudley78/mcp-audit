"""Tests for the opt-in registration module (STORY-0046)."""

from __future__ import annotations

import json
import os
import re
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


# ── docs/privacy.md matches the code (STORY-0102) ─────────────────────────────

_PRIVACY_DOC = Path(__file__).parent.parent / "docs" / "privacy.md"


def _doc_table_fields(heading: str) -> set[str]:
    """Return the backticked first-column names of the table under *heading*."""
    text = _PRIVACY_DOC.read_text(encoding="utf-8")
    section = text.split(heading, 1)[1].split("\n### ", 1)[0]
    return {
        m.group(1)
        for line in section.splitlines()
        if (m := re.match(r"^\|\s*`([a-z_]+)`\s*\|", line))
    }


def test_privacy_doc_names_the_endpoint_the_code_posts_to() -> None:
    """The page once named register.mcp-audit.dev while the code posted elsewhere."""
    text = _PRIVACY_DOC.read_text(encoding="utf-8")
    assert reg_client._REGISTER_ENDPOINT in text
    assert "register.mcp-audit.dev" not in text
    assert f"after {reg_client._TIMEOUT_SECONDS} seconds" in text


def test_privacy_doc_post_table_matches_post_payload_model() -> None:
    """Every field the doc lists is sent, and every field sent is listed."""
    documented = _doc_table_fields("### What the initial registration POST sends")
    assert documented == set(RegistrationPostPayload.model_fields)


def test_privacy_doc_ping_table_matches_ping_payload_model() -> None:
    documented = _doc_table_fields("### Subsequent pings")
    assert documented == set(RegistrationPingPayload.model_fields)


def test_wire_request_matches_what_the_doc_says_is_sent(
    sample_config: RegistrationConfig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Capture the real request on a local server: headers and body as sent.

    mcp-audit sets two headers; Python's HTTP library adds four protocol
    headers. The doc must name all six, and the body must be exactly the
    RegistrationPostPayload fields. The HTTPS connection is redirected to a
    plain local socket so nothing leaves the machine; everything above the
    socket (urllib's handlers, http.client) runs for real.
    """
    import http.client
    import http.server
    import threading
    import urllib.parse
    import urllib.request

    captured: list[tuple[str, list[tuple[str, str]], bytes]] = []

    class _Capture(http.server.BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802 - http.server naming
            body = self.rfile.read(int(self.headers["Content-Length"]))
            captured.append((self.path, list(self.headers.items()), body))
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args: object) -> None:
            return

    server = http.server.HTTPServer(("127.0.0.1", 0), _Capture)
    port = server.server_address[1]
    thread = threading.Thread(target=server.handle_request, daemon=True)
    thread.start()

    class _ToLocalPlainSocket(http.client.HTTPConnection):
        def __init__(self, host: str, *args: object, context: object = None, **kw):
            super().__init__("127.0.0.1", port, *args, **kw)

    for var in (
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "ALL_PROXY",
        "all_proxy",
    ):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("NO_PROXY", "*")
    monkeypatch.setattr(urllib.request, "_opener", None)
    monkeypatch.setattr(http.client, "HTTPSConnection", _ToLocalPlainSocket)

    try:
        assert reg_client.post_registration(sample_config, grade="?") is True
    finally:
        thread.join(timeout=10)
        server.server_close()

    from mcp_audit import __version__

    assert len(captured) == 1
    path, headers, body = captured[0]
    endpoint = urllib.parse.urlsplit(reg_client._REGISTER_ENDPOINT)
    assert path == (endpoint.path or "/")
    sent = {name.lower(): value for name, value in headers}
    assert sent == {
        # set by mcp-audit
        "content-type": "application/json",
        "user-agent": f"mcp-audit/{__version__}",
        # added by Python's HTTP library
        "host": endpoint.netloc,
        "content-length": str(len(body)),
        "connection": "close",
        "accept-encoding": "identity",
    }
    assert set(json.loads(body)) == set(RegistrationPostPayload.model_fields)

    text = _PRIVACY_DOC.read_text(encoding="utf-8")
    for named in (
        "`Content-Type: application/json`",
        "`User-Agent: mcp-audit/<version>`",
        "`Host`",
        "`Content-Length`",
        "`Connection: close`",
        "`Accept-Encoding: identity`",
    ):
        assert named in text, f"docs/privacy.md does not name {named}"


def test_register_flow_posts_placeholder_grade(tmp_config_dir: Path) -> None:
    """The doc says the initial POST's grade is always "?": no scan runs first."""
    from typer.testing import CliRunner

    from mcp_audit.cli import app

    with (
        patch.object(reg_manager, "_DEFAULT_CONFIG_DIR", tmp_config_dir),
        patch.object(reg_client, "post_registration", return_value=True) as post,
    ):
        result = CliRunner().invoke(
            app, ["register"], input="Sarah\nACME\nsarah@acme.com\nn\n"
        )

    assert result.exit_code == 0, result.output
    post.assert_called_once()
    assert post.call_args.kwargs["grade"] == "?"
    assert '| `grade` | `"?"` |' in _PRIVACY_DOC.read_text(encoding="utf-8")
