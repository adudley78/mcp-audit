"""Launch credentials never leave in clear (STORY-0108, queue Q-038).

A server's launch command, args or URL can carry a credential: a database
connection string (``postgresql://user:pass@host/db``, the form
``@modelcontextprotocol/server-postgres`` documents) or a token flag.  Before
STORY-0108, TRANSPORT-003 evidence and ``servers[].args`` / ``raw.args`` in
JSON output quoted them verbatim.  These tests run the real scan and every
output format against such a config.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from mcp_audit.analyzers.supply_chain import redact_args, redact_url
from mcp_audit.analyzers.transport import TransportAnalyzer
from mcp_audit.cli import app
from mcp_audit.models import ServerConfig, TransportType
from mcp_audit.output.snapshot import format_cyclonedx_aibom, format_native
from mcp_audit.scanner import run_scan

runner = CliRunner()

# Built at test time so no credential-shaped string is committed to the repo.
_DB_PASSWORD = "hunter2" + "Zq9" * 3
_GH_TOKEN = "ghp_" + "aB3" * 12
_URL_PASSWORD = "s3cr3t" + "Wx" * 4


def _config(tmp_path: Path) -> Path:
    path = tmp_path / "mcp.json"
    path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "pg": {
                        "command": "npx",
                        "args": [
                            "-y",
                            "@acme/postgres-mcp",
                            f"postgresql://admin:{_DB_PASSWORD}@db.internal:5432/app",
                        ],
                    },
                    "tokened": {
                        "command": "npx",
                        "args": ["-y", "some-mcp-server", "--token", _GH_TOKEN],
                    },
                    "remote": {
                        "url": f"http://ops:{_URL_PASSWORD}@mcp.example.com/sse",
                    },
                }
            }
        ),
        encoding="utf-8",
    )
    return path


def _assert_clean(text: str) -> None:
    flat = "".join(text.split())  # immune to Rich wrapping
    for secret in (_DB_PASSWORD, _GH_TOKEN, _URL_PASSWORD):
        assert secret not in flat
    assert "[REDACTED]" in flat


# ── Helpers ───────────────────────────────────────────────────────────────────


class TestRedactArgs:
    def test_userinfo_and_secret_patterns(self) -> None:
        out = redact_args(
            ["-y", "pkg", f"postgresql://u:{_DB_PASSWORD}@h/db", "--t", _GH_TOKEN]
        )
        assert out == [
            "-y",
            "pkg",
            "postgresql://[REDACTED]@h/db",
            "--t",
            "[REDACTED]",
        ]

    def test_password_with_at_sign_and_space(self) -> None:
        assert redact_args(["postgres://admin:p@ss w0rd@db/x"]) == [
            "postgres://[REDACTED]@db/x"
        ]

    def test_clean_args_are_unchanged(self) -> None:
        args = ["-y", "@modelcontextprotocol/server-filesystem", "/Users/me/projects"]
        assert redact_args(args) == args
        assert redact_args([]) == []

    def test_same_length_and_never_truncated(self) -> None:
        args = ["x" * 5000, _GH_TOKEN, "tail"]
        out = redact_args(args)
        assert len(out) == 3
        assert out[0] == "x" * 5000
        assert out[1] == "[REDACTED]"
        assert out[2] == "tail"

    def test_redact_url(self) -> None:
        assert redact_url(None) is None
        assert (
            redact_url(f"https://ops:{_URL_PASSWORD}@mcp.example.com/sse")
            == "https://[REDACTED]@mcp.example.com/sse"
        )
        assert redact_url("https://mcp.example.com/sse") == (
            "https://mcp.example.com/sse"
        )

    def test_pathological_input_is_linear(self) -> None:
        args = ["://" + "@" * 20000 + "/" * 20000, "a://" * 20000]
        start = time.monotonic()
        redact_args(args)
        assert time.monotonic() - start < 2.0


# ── Evidence ──────────────────────────────────────────────────────────────────


class TestTransportEvidence:
    def test_transport_003_evidence_is_redacted(self, tmp_path: Path) -> None:
        server = ServerConfig(
            name="pg",
            client="claude-desktop",
            config_path=tmp_path / "c.json",
            transport=TransportType.STDIO,
            command="npx",
            args=[
                "-y",
                "@acme/postgres-mcp",
                f"postgresql://admin:{_DB_PASSWORD}@db/app",
            ],
        )
        (finding,) = [
            f for f in TransportAnalyzer().analyze(server) if f.id == "TRANSPORT-003"
        ]
        assert finding.evidence == (
            "Command: npx -y @acme/postgres-mcp postgresql://[REDACTED]@db/app"
        )
        # The object the analyzers see is untouched.
        assert _DB_PASSWORD in server.args[2]

    def test_transport_001_url_evidence_is_redacted(self, tmp_path: Path) -> None:
        server = ServerConfig(
            name="remote",
            client="claude-desktop",
            config_path=tmp_path / "c.json",
            transport=TransportType.SSE,
            url=f"http://ops:{_URL_PASSWORD}@mcp.example.com/sse",
        )
        (finding,) = [
            f for f in TransportAnalyzer().analyze(server) if f.id == "TRANSPORT-001"
        ]
        assert finding.evidence == "URL: http://[REDACTED]@mcp.example.com/sse"


# ── Serialisation and every output format ───────────────────────────────────


class TestServerSerialisation:
    def test_model_dump_json_redacts_and_python_dump_does_not(
        self, tmp_path: Path
    ) -> None:
        server = ServerConfig(
            name="pg",
            client="c",
            config_path=tmp_path / "c.json",
            command="npx",
            args=["-y", "pkg", f"postgresql://a:{_DB_PASSWORD}@h/db"],
            url=f"https://ops:{_URL_PASSWORD}@h/mcp",
            raw={
                "command": "npx",
                "args": ["-y", "pkg", f"postgresql://a:{_DB_PASSWORD}@h/db"],
                "url": f"https://ops:{_URL_PASSWORD}@h/mcp",
                "serverUrl": f"https://ops:{_URL_PASSWORD}@h/mcp",
                "disabled": False,
            },
        )
        data = json.loads(server.model_dump_json())
        _assert_clean(json.dumps(data))
        assert data["args"][:2] == ["-y", "pkg"]
        assert data["raw"]["disabled"] is False
        # Python-mode dumps (used in memory) keep the real values.
        assert _DB_PASSWORD in server.model_dump()["args"][2]

    def test_raw_args_with_non_strings_survive(self, tmp_path: Path) -> None:
        server = ServerConfig(
            name="x",
            client="c",
            config_path=tmp_path / "c.json",
            raw={"args": ["--port", 8080, _GH_TOKEN]},
        )
        data = json.loads(server.model_dump_json())
        assert data["raw"]["args"] == ["--port", 8080, "[REDACTED]"]

    def test_round_trip_through_scan_result(self, tmp_path: Path) -> None:
        from mcp_audit.models import ScanResult  # noqa: PLC0415

        result = run_scan(extra_paths=[_config(tmp_path)], skip_rug_pull=True)
        reloaded = ScanResult.model_validate_json(result.model_dump_json())
        assert {s.name for s in reloaded.servers} == {"pg", "tokened", "remote"}


@pytest.mark.parametrize("fmt", ["terminal", "json", "sarif", "nucleus"])
def test_scan_output_never_quotes_launch_credentials(tmp_path: Path, fmt: str) -> None:
    config = _config(tmp_path)
    with patch("mcp_audit.discovery._get_client_specs", return_value=[]):
        r = runner.invoke(app, ["scan", "--path", str(config), "--format", fmt])
    # TRANSPORT-003 fires on the unregistered postgres server in every format;
    # SARIF carries rule IDs and messages, not the evidence text.
    if fmt == "sarif":
        assert "TRANSPORT-003" in r.output
    else:
        assert "postgresql://[REDACTED]@db.internal" in "".join(r.output.split())
    flat = "".join(r.output.split())
    for secret in (_DB_PASSWORD, _GH_TOKEN, _URL_PASSWORD):
        assert secret not in flat


def test_json_output_servers_args_are_redacted(tmp_path: Path) -> None:
    config = _config(tmp_path)
    out = tmp_path / "scan.json"
    runner.invoke(
        app, ["scan", "--path", str(config), "--format", "json", "-o", str(out)]
    )
    data = json.loads(out.read_text(encoding="utf-8"))
    _assert_clean(out.read_text(encoding="utf-8"))
    by_name = {s["name"]: s for s in data["servers"]}
    assert by_name["pg"]["args"] == [
        "-y",
        "@acme/postgres-mcp",
        "postgresql://[REDACTED]@db.internal:5432/app",
    ]
    assert by_name["pg"]["raw"]["args"] == by_name["pg"]["args"]
    assert by_name["tokened"]["args"][-1] == "[REDACTED]"
    assert by_name["remote"]["url"] == "http://[REDACTED]@mcp.example.com/sse"
    evidence = [f["evidence"] for f in data["findings"] if f["id"] == "TRANSPORT-003"]
    assert any("postgresql://[REDACTED]@db.internal" in e for e in evidence)


def test_check_json_is_redacted(tmp_path: Path) -> None:
    config = _config(tmp_path)
    with patch("mcp_audit.discovery._get_client_specs", return_value=[]):
        r = runner.invoke(app, ["check", "--path", str(config), "--json"])
    _assert_clean(r.output)


def test_snapshots_are_redacted(tmp_path: Path) -> None:
    result = run_scan(extra_paths=[_config(tmp_path)], skip_rug_pull=True)
    _assert_clean(json.dumps(format_cyclonedx_aibom(result, "host")))
    _assert_clean(json.dumps(format_native(result, "host")))


# ── diff between two JSON scan files (reviewer #202) ────────────────────────


def _scan_json(tmp_path: Path, name: str, args: list[str]) -> Path:
    cfg = tmp_path / f"{name}-mcp.json"
    cfg.write_text(
        json.dumps({"mcpServers": {"pg": {"command": "npx", "args": args}}}),
        encoding="utf-8",
    )
    out = tmp_path / f"{name}-scan.json"
    out.write_text(
        run_scan(extra_paths=[cfg], skip_rug_pull=True).model_dump_json(),
        encoding="utf-8",
    )
    return out


@pytest.mark.parametrize(
    "secret_arg",
    [f"postgresql://admin:{_DB_PASSWORD}@db/app", _GH_TOKEN],
)
def test_diff_of_two_json_scans_still_reports_an_added_credential(
    tmp_path: Path, secret_arg: str
) -> None:
    """A redacted argument still counts as a hardcoded credential in diff."""
    from mcp_audit.diff.comparator import EntityType, compare  # noqa: PLC0415
    from mcp_audit.diff.loader import load_input  # noqa: PLC0415

    base = _scan_json(tmp_path, "base", ["-y", "@acme/postgres-mcp"])
    head = _scan_json(tmp_path, "head", ["-y", "@acme/postgres-mcp", secret_arg])
    assert secret_arg not in head.read_text(encoding="utf-8")

    changes = compare(load_input(str(base)), load_input(str(head)))
    creds = [c for c in changes if c.entity_type == EntityType.CREDENTIAL]
    assert creds, changes
    assert creds[0].severity.value == "CRITICAL"

    r = runner.invoke(app, ["diff", str(base), str(head), "--format", "json"])
    assert '"credential"' in r.output
    assert secret_arg not in r.output


def test_diff_of_two_clean_json_scans_reports_no_credential(tmp_path: Path) -> None:
    from mcp_audit.diff.comparator import EntityType, compare  # noqa: PLC0415
    from mcp_audit.diff.loader import load_input  # noqa: PLC0415

    base = _scan_json(tmp_path, "base", ["-y", "@acme/postgres-mcp"])
    head = _scan_json(tmp_path, "head", ["-y", "@acme/postgres-mcp", "--port=5432"])
    changes = compare(load_input(str(base)), load_input(str(head)))
    assert not [c for c in changes if c.entity_type == EntityType.CREDENTIAL]


def test_secret_flag_values_are_redacted_in_their_own_position() -> None:
    """``--password VALUE`` is redacted with the weaker flag marker."""
    from mcp_audit.analyzers.supply_chain import redact_command  # noqa: PLC0415

    args = ["-y", "@acme/db-mcp", "--password", "plainPass99", "--api-key=abcd1234"]
    assert redact_args(args) == [
        "-y",
        "@acme/db-mcp",
        "--password",
        "[REDACTED-FLAG]",
        "--api-key=[REDACTED-FLAG]",
    ]
    assert redact_args(["--apiKey", "zzzz9999"]) == ["--apiKey", "[REDACTED-FLAG]"]
    text = redact_command("npx", args)
    assert "plainPass99" not in text and "abcd1234" not in text
    # A value SECRET_PATTERNS knows keeps the strong marker.
    assert redact_args(["--token", _GH_TOKEN]) == ["--token", "[REDACTED]"]


@pytest.mark.parametrize(
    "args",
    [
        # Reviewer #202: the value of a flag must never be replaced inside
        # another argument (``oauth`` inside the issuer URL).
        ["--auth-type", "oauth", "--issuer", "https://oauth.example.com"],
        ["--auth-mode", "none", "--keys-dir", "./keys"],
        ["--api-key-file", "/etc/app/key", "--token-url", "https://x.example/t"],
        ["--token", "$GITHUB_TOKEN", "--secret", "${SECRET}"],
        ["--auth", "on", "--monkey", "banana99", "--keystore", "default"],
        ["--password-file", "C:/secrets/pw.txt"],
    ],
)
def test_benign_flags_are_not_redacted(args: list[str]) -> None:
    assert redact_args(args) == args


def test_community_rule_evidence_uses_the_rule_engine_redaction(
    tmp_path: Path,
) -> None:
    """COMM-031 quotes the URL it matched; #200's _redact_matched_value redacts it."""
    result = run_scan(extra_paths=[_config(tmp_path)], skip_rug_pull=True)
    comm = [f for f in result.findings if f.id == "COMM-031"]
    assert comm
    for finding in comm:
        _assert_clean(finding.evidence + finding.description)


def _scan_json_servers(tmp_path: Path, name: str, servers: dict) -> Path:
    cfg = tmp_path / f"{name}-mcp.json"
    cfg.write_text(json.dumps({"mcpServers": servers}), encoding="utf-8")
    out = tmp_path / f"{name}-scan.json"
    out.write_text(
        run_scan(extra_paths=[cfg], skip_rug_pull=True).model_dump_json(),
        encoding="utf-8",
    )
    return out


_BASE = {"base": {"command": "npx", "args": ["-y", "@acme/base-mcp"]}}


def _diff_credentials(base: Path, head: Path) -> list:
    from mcp_audit.diff.comparator import EntityType, compare  # noqa: PLC0415
    from mcp_audit.diff.loader import load_input  # noqa: PLC0415

    changes = compare(load_input(str(base)), load_input(str(head)))
    return [c for c in changes if c.entity_type == EntityType.CREDENTIAL]


@pytest.mark.parametrize(
    "args",
    [
        [
            "-y",
            "@acme/x-mcp",
            "--auth-type",
            "oauth",
            "--issuer",
            "https://oauth.example.com",
        ],
        ["-y", "@acme/x-mcp", "--auth-mode", "none", "--keys-dir", "./keys"],
    ],
)
def test_diff_of_scan_files_with_benign_flags_reports_no_credential(
    tmp_path: Path, args: list[str]
) -> None:
    """Reviewer #202: no crash, no false credential on benign flag values."""
    base = _scan_json_servers(tmp_path, "base", _BASE)
    head = _scan_json_servers(
        tmp_path, "head", {**_BASE, "new": {"command": "npx", "args": args}}
    )
    assert _diff_credentials(base, head) == []
    r = runner.invoke(app, ["diff", str(base), str(head), "--format", "json"])
    assert r.exit_code in (0, 1), r.output
    assert "Traceback" not in r.output


def test_diff_of_scan_files_reports_a_secret_flag_value_as_high(
    tmp_path: Path,
) -> None:
    base = _scan_json_servers(tmp_path, "base", _BASE)
    head = _scan_json_servers(
        tmp_path,
        "head",
        {
            **_BASE,
            "new": {
                "command": "npx",
                "args": ["-y", "@acme/x-mcp", "--password", "plainPass99"],
            },
        },
    )
    (cred,) = _diff_credentials(base, head)
    assert cred.severity.value == "HIGH"
    assert cred.entity_name == "Possible credential flag value"


def test_diff_of_scan_files_reports_a_known_token_flag_as_critical(
    tmp_path: Path,
) -> None:
    base = _scan_json_servers(tmp_path, "base", _BASE)
    head = _scan_json_servers(
        tmp_path,
        "head",
        {
            **_BASE,
            "new": {
                "command": "npx",
                "args": ["-y", "@acme/x-mcp", "--token", _GH_TOKEN],
            },
        },
    )
    (cred,) = _diff_credentials(base, head)
    assert cred.severity.value == "CRITICAL"


def test_diff_survives_an_unparsable_url(tmp_path: Path) -> None:
    from mcp_audit.diff.comparator import (  # noqa: PLC0415
        _extract_external_urls,
        compare,
    )

    server = ServerConfig(
        name="x",
        client="c",
        config_path=tmp_path / "c.json",
        command="npx",
        args=["-y", "@acme/x-mcp", "https://[bad-host/mcp"],
    )
    assert _extract_external_urls(server) == ["https://[bad-host/mcp"]
    changes = compare([], [server])
    assert any(c.entity_name == "https://[bad-host/mcp" for c in changes)
