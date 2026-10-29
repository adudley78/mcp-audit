"""Redaction gaps (STORY-0118): headers, connection strings, curl -u, query
strings, Base64 userinfo, env values in every output, diff output and the lock.

Synthetic secrets are built at test time; none is a valid credential.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from mcp_audit.analyzers.supply_chain import (
    FLAG_REDACTION_MARKER,
    REDACTION_MARKER,
    redact_args,
    redact_command,
    redact_command_text,
    redact_env_values,
    redact_url,
)
from mcp_audit.cli import app
from mcp_audit.diff.comparator import EntityType, compare
from mcp_audit.diff.loader import load_input
from mcp_audit.diff.render import render_json, render_pr_comment, render_terminal
from mcp_audit.lock.identity import build_identity, comparable_identity
from mcp_audit.lock.model import compute_checksum
from mcp_audit.lock.verifier import verify
from mcp_audit.lock.writer import regenerate, write_lock
from mcp_audit.models import ScanResult, ServerConfig
from mcp_audit.output.sarif import format_sarif
from mcp_audit.output.snapshot import format_cyclonedx_aibom, format_native
from mcp_audit.scanner import run_scan

runner = CliRunner()

PW = "Zq9" * 2 + "hunter2"  # synthetic password
KEY = "k3y" + "Vx" * 5  # synthetic key
SECRETS = (PW, KEY)


def _gone(text: str, *secrets: str) -> None:
    flat = "".join(text.split())
    for secret in secrets or SECRETS:
        assert secret not in flat, secret


# ── S1: headers, connection strings, curl -u, password flags ─────────────────


class TestHeaders:
    @pytest.mark.parametrize(
        ("arg", "kept"),
        [
            (f"X-API-Key: {KEY}", "X-API-Key:"),
            (f"x-api-key:{KEY}", "x-api-key:"),
            (f"Cookie: session={KEY}; other=1", "Cookie:"),
            (f"COOKIE: session={KEY}", "COOKIE:"),
            (f"Authorization: Digest {KEY}", "Authorization:"),
            (f"authorization: ApiKey {KEY}", "authorization:"),
            (f"Proxy-Authorization: Negotiate {KEY}", "Proxy-Authorization:"),
            (f"X-Custom-Token: {KEY}", "X-Custom-Token:"),
            (f"--header=X-API-Key: {KEY}", "--header=X-API-Key:"),
        ],
    )
    def test_header_values_are_redacted(self, arg: str, kept: str) -> None:
        out = redact_args(["--header", arg])
        assert KEY not in "".join(out)
        assert kept in out[1]
        assert REDACTION_MARKER in out[1]

    def test_scheme_word_is_kept(self) -> None:
        assert redact_args([f"Authorization: Bearer {KEY}"]) == [
            "Authorization: Bearer [REDACTED]"
        ]

    @pytest.mark.parametrize(
        "arg",
        [
            "Authorization: Bearer ${TOKEN}",
            "X-API-Key: ${API_KEY}",
            "Cookie: $COOKIE",
            "Accept: application/json",
            "Content-Type: text/plain",
            "http://localhost:8080/path",
        ],
    )
    def test_references_and_plain_headers_are_kept(self, arg: str) -> None:
        assert redact_args([arg]) == [arg]

    def test_two_argument_form(self) -> None:
        out = redact_args(["-H", f"X-API-Key: {KEY}", "-H", "Accept: text/html"])
        assert out == ["-H", "X-API-Key: [REDACTED]", "-H", "Accept: text/html"]

    def test_redact_command_covers_headers(self) -> None:
        text = redact_command("npx", ["mcp-remote", "--header", f"X-API-Key: {KEY}"])
        assert KEY not in text


class TestConnectionStrings:
    @pytest.mark.parametrize(
        "arg",
        [
            f"Server=h;Database=d;Password={PW};User Id=sa",
            f"Server=h;Pwd={PW}",
            f"Server=h;secret={PW};",
            f"DefaultEndpointsProtocol=https;AccountKey={KEY};EndpointSuffix=x",
            f"host=h dbname=d password={PW}",
        ],
    )
    def test_secret_pairs_are_redacted(self, arg: str) -> None:
        (out,) = redact_args([arg])
        _gone(out)
        assert REDACTION_MARKER in out
        assert out.split("=")[0] == arg.split("=")[0]  # structure kept

    def test_non_secret_pairs_and_references_are_kept(self) -> None:
        arg = "Server=h;Database=d;Password=${DB_PASSWORD};User Id=sa"
        assert redact_args([arg]) == [arg]
        arg = "Server=h;Database=d;Timeout=30;Encrypt=true"
        assert redact_args([arg]) == [arg]

    def test_short_password_is_still_redacted(self) -> None:
        assert "abc" not in redact_args(["Server=h;Password=abc"])[0]


class TestBasicAuthFlags:
    def test_curl_u(self) -> None:
        out = redact_args(["curl", "-u", f"admin:{PW}", "https://h/x"])
        assert out == ["curl", "-u", "admin:[REDACTED]", "https://h/x"]

    def test_long_forms(self) -> None:
        assert redact_args(["--user", f"a:{PW}"]) == ["--user", "a:[REDACTED]"]
        assert redact_args([f"--user=a:{PW}"]) == ["--user=a:[REDACTED]"]
        assert redact_args(["--proxy-user", f"a:{PW}"]) == [
            "--proxy-user",
            "a:[REDACTED]",
        ]

    def test_docker_user_is_not_a_credential(self) -> None:
        args = ["run", "-u", "1000:1000", "-i", "img"]
        assert redact_args(args) == args

    def test_inline_text(self) -> None:
        out = redact_command_text(f"curl -u admin:{PW} https://h/x")
        _gone(out)
        assert "admin" in out
        assert redact_command_text("docker run -u 1000:1000 img") == (
            "docker run -u 1000:1000 img"
        )


class TestPasswordFlags:
    def test_dash_leading_value(self) -> None:
        out = redact_args(["--password", "-v"])
        assert out[1].startswith("[REDACTED")

    def test_next_long_option_is_a_flag_not_a_value(self) -> None:
        assert redact_args(["--password", "--verbose"]) == ["--password", "--verbose"]

    def test_token_flag_does_not_swallow_a_following_short_flag(self) -> None:
        assert redact_args(["--token", "-v"]) == ["--token", "-v"]

    def test_short_password_value(self) -> None:
        assert redact_args(["--password=ab"])[0] != "--password=ab"

    def test_redaction_is_idempotent(self) -> None:
        cases = [
            ["--api-key", KEY, "--password", "-v"],
            ["--header", f"X-API-Key: {KEY}", f"Server=h;Password={PW}"],
            ["curl", "-u", f"a:{PW}", f"https://x/y?token={KEY}"],
            [f"https://dXNlcjpwYXNzd29yZA@host/{KEY}"],
            ["--token=abcdef123456", "--password", "xyzzy-secret"],
        ]
        for args in cases:
            once = redact_args(args)
            assert redact_args(once) == once, args


class TestInlineText:
    @pytest.mark.parametrize(
        "text",
        [
            f"curl -H 'COOKIE: a={KEY}; c=d' https://h",
            f"curl -H 'x-api-key: {KEY}' https://h",
            f"curl -H 'Authorization: Digest {KEY}' https://h",
            f"curl -H Authorization:Digest {KEY} https://h",
            f"printf 'authorization: ApiKey {KEY}'",
            f"echo Server=h;Password={PW}",
            f"export DB_PASSWORD={PW} && run",
        ],
    )
    def test_command_text(self, text: str) -> None:
        _gone(redact_command_text(text))

    def test_references_kept(self) -> None:
        kept = "curl -H 'X-API-Key: $KEY' -H 'Authorization: Bearer ${T}' https://h"
        assert redact_command_text(kept) == kept


# ── S1: managed_policy shares the helpers ────────────────────────────────────


def test_managed_policy_uses_supply_chain_helpers() -> None:
    from mcp_audit.analyzers import managed_policy, supply_chain  # noqa: PLC0415

    assert managed_policy.redact_query_secrets is supply_chain.redact_query_secrets
    assert managed_policy.redact_assignment is supply_chain.redact_assignment
    assert managed_policy.redact_auth_scheme is supply_chain.redact_auth_scheme
    out = managed_policy._redact_parts(
        [
            "curl",
            "--header",
            f"X-API-Key: {KEY}",
            f"Server=h;Password={PW}",
            "-u",
            f"a:{PW}",
        ]
    )
    _gone(out)


# ── ReDoS: every pass is linear (200 KB) ─────────────────────────────────────

_BIG = 200_000
_PATHOLOGICAL = {
    "colons": ":" * _BIG,
    "header-name": "x-api-key" + " " * _BIG,
    "header-value": "Authorization:" + "a b " * (_BIG // 4),
    "semis": "a=b;" * (_BIG // 4),
    "eq": "=" * _BIG,
    "pw-pieces": ("password=" + "x" * 10 + ";") * (_BIG // 20),
    "dash-user": "-u " + "a:" * (_BIG // 2),
    "query": "https://h/?" + "token=a&" * (_BIG // 8),
    "userinfo": "https://" + "a" * _BIG,
    "userinfo-at": "https://" + "@" * _BIG,
    "b64": "https://" + "A" * _BIG + "@h",
    "quotes": "'" * _BIG,
    "tabs": "Cookie:" + "\t" * _BIG,
    "bearer": "bearer " + "a" * _BIG,
}


@pytest.mark.parametrize("name", sorted(_PATHOLOGICAL))
def test_redaction_is_linear_on_200kb(name: str) -> None:
    text = _PATHOLOGICAL[name]
    start = time.perf_counter()
    redact_args([text])
    redact_args(["--header", text, "-u", text])
    redact_command("npx", [text, text])
    redact_command_text(text)
    redact_url(text)
    assert time.perf_counter() - start < 10, name


def test_redaction_precedes_truncation() -> None:
    """A secret straddling the 300-character cap never leaves a prefix."""
    pad = "a" * 280
    text = redact_command("npx", [pad, f"--api-key={KEY}"])
    assert KEY[:6] not in text
    text = redact_command("npx", [f"Server=h;Password={PW}" + ";x=" + "y" * 400])
    _gone(text)


# ── S5: query-string secrets ─────────────────────────────────────────────────


class TestQuerySecrets:
    @pytest.mark.parametrize(
        "name",
        [
            "token",
            "key",
            "api_key",
            "apikey",
            "access_token",
            "sig",
            "signature",
            "secret",
            "password",
            "auth",
            "X-Amz-Signature",
        ],
    )
    def test_secret_parameters(self, name: str) -> None:
        out = redact_url(f"https://h.example/sse?a=1&{name}={KEY}&b=2")
        assert out == f"https://h.example/sse?a=1&{name}=[REDACTED]&b=2"

    def test_fragment(self) -> None:
        assert redact_url(f"https://h/cb#access_token={KEY}") == (
            "https://h/cb#access_token=[REDACTED]"
        )

    def test_benign_and_reference_queries_kept(self) -> None:
        for url in (
            "https://h/sse?page=2&sort=asc",
            "https://h/sse?token=${TOKEN}",
        ):
            assert redact_url(url) == url

    def test_in_an_argument_of_a_stdio_server(self) -> None:
        out = redact_args(["mcp-remote", f"https://h/sse?token={KEY}"])
        _gone("".join(out))


# ── S6: Base64 userinfo, case-insensitive schemes ────────────────────────────


class TestUserinfo:
    def test_base64_userinfo_is_redacted(self) -> None:
        assert redact_url("https://dXNlcjpwYXNzd29yZA@host/x") == (
            "https://[REDACTED]@host/x"
        )

    @pytest.mark.parametrize(
        "userinfo", ["dXNlcjpwYXNzd29yZA==", "abc%3Adef", "AbCdEfGhIjKlMnOpQrSt"]
    )
    def test_encoded_shapes(self, userinfo: str) -> None:
        assert redact_url(f"https://{userinfo}@host/") == "https://[REDACTED]@host/"

    @pytest.mark.parametrize(
        "userinfo", ["git", "deploy", "x-access-token", "oauth2", "ci-bot.svc"]
    )
    def test_plain_accounts_stay(self, userinfo: str) -> None:
        url = f"git+ssh://{userinfo}@github.com/o/r.git"
        assert redact_url(url) == url

    @pytest.mark.parametrize("word", ["bearer", "BEARER", "Bearer", "basic", "TOKEN"])
    def test_scheme_words_any_case(self, word: str) -> None:
        _gone(redact_command_text(f"echo {word} {KEY}"))


# ── S2: env values in every output ───────────────────────────────────────────


def _env_config(tmp_path: Path) -> Path:
    path = tmp_path / "mcp.json"
    path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "svc": {
                        "command": "npx",
                        "args": ["-y", "@acme/svc"],
                        "env": {
                            "API_KEY": KEY,
                            "DB_PASSWORD": PW,
                            "AUTH": KEY + "zz",
                            "REF": "${HOME}",
                            "NODE_ENV": "production",
                        },
                    },
                    "remote": {
                        "url": f"https://h.example/mcp?token={KEY}",
                        "headers": {"X-API-Key": KEY},
                    },
                }
            }
        ),
        encoding="utf-8",
    )
    return path


def test_env_values_are_redacted_for_every_client(tmp_path: Path) -> None:
    result = run_scan(extra_paths=[_env_config(tmp_path)], skip_rug_pull=True)
    dumped = json.loads(result.model_dump_json())
    svc = next(s for s in dumped["servers"] if s["name"] == "svc")
    assert svc["env"]["API_KEY"] == FLAG_REDACTION_MARKER
    assert svc["env"]["DB_PASSWORD"] == FLAG_REDACTION_MARKER
    assert svc["env"]["AUTH"] == FLAG_REDACTION_MARKER
    assert svc["env"]["REF"] == "${HOME}"
    assert svc["env"]["NODE_ENV"] == "production"
    assert svc["raw"]["env"] == svc["env"]
    # fields stay: only values change
    assert set(svc["env"]) == {"API_KEY", "DB_PASSWORD", "AUTH", "REF", "NODE_ENV"}
    # in memory the real values are untouched
    mem = next(s for s in result.servers if s.name == "svc")
    assert mem.env["API_KEY"] == KEY


def test_every_output_format_is_clean(tmp_path: Path) -> None:
    config = _env_config(tmp_path)
    result = run_scan(extra_paths=[config], skip_rug_pull=True)
    outputs = {
        "json": result.model_dump_json(),
        "sarif": format_sarif(result),
        "cyclonedx": json.dumps(format_cyclonedx_aibom(result, "host")),
        "native": json.dumps(format_native(result, "host")),
    }
    for fmt in ("terminal", "json", "sarif", "nucleus"):
        with patch("mcp_audit.discovery._get_client_specs", return_value=[]):
            r = runner.invoke(app, ["scan", "--path", str(config), "--format", fmt])
        outputs[f"cli-{fmt}"] = r.output
    with patch("mcp_audit.discovery._get_client_specs", return_value=[]):
        r = runner.invoke(app, ["check", "--path", str(config), "--json"])
    outputs["check-json"] = r.output
    for kind, text in outputs.items():
        for secret in (KEY, PW):
            assert secret not in "".join(text.split()), (kind, secret)


def test_pdf_and_dashboard_are_clean(tmp_path: Path) -> None:
    from mcp_audit.output.dashboard import generate_html  # noqa: PLC0415
    from mcp_audit.output.pdf import PdfReportFormatter  # noqa: PLC0415

    result = run_scan(extra_paths=[_env_config(tmp_path)], skip_rug_pull=True)
    assert KEY not in generate_html(result)
    pdf = PdfReportFormatter(result).generate(compress=False)
    assert KEY.encode() not in pdf
    assert PW.encode() not in pdf


def test_redact_env_values_is_idempotent() -> None:
    env = {"API_KEY": KEY, "REF": "$X", "NODE_ENV": "production", "T": 3}
    once = redact_env_values(env)
    assert redact_env_values(once) == once


def test_json_round_trip_and_diff_do_not_flag_benign_env(tmp_path: Path) -> None:
    """A redacted scan file diffed against another does not read every env value
    as a credential: benign values keep their text; secrets are the flag marker."""
    config = _env_config(tmp_path)
    scan = tmp_path / "scan.json"
    scan.write_text(
        run_scan(extra_paths=[config], skip_rug_pull=True).model_dump_json(),
        encoding="utf-8",
    )
    ScanResult.model_validate_json(scan.read_text(encoding="utf-8"))
    servers = load_input(str(scan))
    changes = compare(servers, servers)
    assert changes == []
    base = [s for s in servers if s.name == "remote"]
    added = compare([], servers)
    creds = [c for c in added if c.entity_type == EntityType.CREDENTIAL]
    # secrets in env are reported as possible credentials (HIGH), never CRITICAL,
    # and NODE_ENV=production alone contributes nothing
    assert all(
        c.severity.value != "CRITICAL"
        for c in creds
        if c.after["provider"] == "redacted-flag"
    )
    assert base


def test_lock_baseline_rugpull_use_key_names_not_values(tmp_path: Path) -> None:
    """Redaction is serialisation only: hashes and lock fields read the real value."""
    from mcp_audit.analyzers.rug_pull import compute_hashes  # noqa: PLC0415

    server = ServerConfig(
        name="s",
        client="c",
        config_path=tmp_path / "m.json",
        command="npx",
        env={"API_KEY": KEY},
    )
    before = compute_hashes(server)
    server.model_dump_json()
    assert compute_hashes(server) == before
    assert server.env["API_KEY"] == KEY


# ── S3: diff output ──────────────────────────────────────────────────────────


def _dir_with(tmp_path: Path, name: str, servers: dict) -> Path:
    d = tmp_path / name
    d.mkdir()
    (d / ".mcp.json").write_text(json.dumps({"mcpServers": servers}), encoding="utf-8")
    return d


@pytest.fixture
def diff_inputs(tmp_path: Path) -> tuple[Path, Path]:
    base = _dir_with(
        tmp_path,
        "base",
        {
            "a": {
                "command": "npx",
                "args": ["-y", "@acme/a", "--api-key", "oldkey12345"],
            }
        },
    )
    head = _dir_with(
        tmp_path,
        "head",
        {
            "a": {
                "command": "npx",
                "args": [
                    "-y",
                    "@acme/a",
                    "--api-key",
                    KEY,
                    f"Server=h;Password={PW}",
                    f"https://h.example/x?token={KEY}",
                ],
            },
            "b": {
                "command": "uvx",
                "args": [
                    "--from",
                    f"git+https://user:{PW}@host/r.git",
                    "b",
                    "--header",
                    f"X-API-Key: {KEY}",
                ],
            },
        },
    )
    return base, head


def test_diff_changes_never_hold_a_credential(diff_inputs: tuple[Path, Path]) -> None:
    base, head = diff_inputs
    changes = compare(load_input(str(base)), load_input(str(head)))
    assert changes
    blob = json.dumps(
        [(c.before, c.after, c.command_diff, c.entity_name) for c in changes],
        default=str,
    )
    _gone(blob, KEY, PW, "oldkey12345")


@pytest.mark.parametrize("fmt", ["terminal", "json", "pr-comment"])
def test_diff_cli_output_is_redacted(diff_inputs: tuple[Path, Path], fmt: str) -> None:
    base, head = diff_inputs
    r = runner.invoke(app, ["diff", str(base), str(head), "--format", fmt])
    assert r.output
    _gone(r.output, KEY, PW, "oldkey12345")


def test_diff_renderers_directly(diff_inputs: tuple[Path, Path]) -> None:
    from io import StringIO  # noqa: PLC0415

    from rich.console import Console  # noqa: PLC0415

    base, head = diff_inputs
    changes = compare(load_input(str(base)), load_input(str(head)))
    buf = StringIO()
    render_terminal(changes, "base", "head", console=Console(file=buf, width=300))
    for text in (
        buf.getvalue(),
        render_json(changes),
        render_pr_comment(changes, "base", "head"),
    ):
        _gone(text, KEY, PW)


# ── S4: lock ─────────────────────────────────────────────────────────────────


def _server(tmp_path: Path, args: list[str], command: str = "npx") -> ServerConfig:
    return ServerConfig(
        name="s",
        client="claude-code",
        config_path=tmp_path / ".mcp.json",
        command=command,
        args=args,
    )


def _lock(tmp_path: Path, servers: list[ServerConfig], *, legacy: bool = False) -> Path:
    doc = regenerate(None, servers, tmp_path, offline=True, registry=None)
    if legacy:
        # What mcp-audit before STORY-0118 wrote: identity args verbatim.
        for entry, server in zip(doc["servers"].values(), servers, strict=True):
            entry["identity"] = {
                "command": server.command or "",
                "args": list(server.args),
            }
        doc["lock_version"] = 1
        doc.pop("section_digests", None)
        doc["checksum"] = compute_checksum(doc)
    path = tmp_path / "mcp-lock.json"
    write_lock(path, doc)
    return path


def test_non_secret_identity_is_unchanged(tmp_path: Path) -> None:
    server = _server(tmp_path, ["-y", "@acme/svc@1.2.3", "--port=8080", "--debug"])
    assert build_identity(server) == {
        "command": "npx",
        "args": ["-y", "@acme/svc@1.2.3", "--port=8080", "--debug"],
    }


def test_secret_launch_is_kept_out_of_the_lock(tmp_path: Path) -> None:
    server = _server(
        tmp_path,
        ["--from", f"git+https://user:{PW}@host/o/r.git", "srv", "--api-key", KEY],
        command="uvx",
    )
    path = _lock(tmp_path, [server])
    text = path.read_text(encoding="utf-8")
    _gone(text, KEY, PW, PW.lower())
    assert "[REDACTED" in text
    findings = verify(path, [server], root=tmp_path).findings
    assert [f.id for f in findings] == ["LOCK-013"]
    assert findings[0].severity.value == "LOW"
    _gone(json.dumps([f.model_dump(mode="json") for f in findings]), KEY, PW)


def test_lock_written_before_the_change_still_verifies(tmp_path: Path) -> None:
    clean = _server(tmp_path, ["-y", "@acme/svc@1.2.3"])
    path = _lock(tmp_path, [clean], legacy=True)
    assert verify(path, [clean], root=tmp_path).findings == []

    secret = _server(tmp_path, ["-y", "pkg@1.0.0", "--api-key", KEY])
    path = _lock(tmp_path, [secret], legacy=True)
    assert KEY in path.read_text(encoding="utf-8")  # the old lock held it verbatim
    ids = [f.id for f in verify(path, [secret], root=tmp_path).findings]
    assert "LOCK-001" not in ids
    assert ids == ["LOCK-013"]


def test_real_drift_is_still_reported_and_evidence_is_redacted(tmp_path: Path) -> None:
    locked = _server(tmp_path, ["-y", "pkg@1.0.0", "--api-key", KEY])
    path = _lock(tmp_path, [locked])
    changed = _server(tmp_path, ["-y", "pkg@2.0.0", "--api-key", KEY + "x"])
    findings = verify(path, [changed], root=tmp_path).findings
    drift = [f for f in findings if f.id == "LOCK-001"]
    assert drift
    _gone(drift[0].evidence + drift[0].description, KEY)


def test_comparable_identity_is_idempotent(tmp_path: Path) -> None:
    ident = {"command": "npx", "args": ["--api-key", KEY, f"https://h/?token={KEY}"]}
    once = comparable_identity(ident)
    assert comparable_identity(once) == once
    assert comparable_identity({"url": "https://h/"}) == {"url": "https://h/"}
    assert comparable_identity("not-a-dict") == "not-a-dict"


def test_lock_cli_warns_and_never_writes_the_secret(
    tmp_path: Path, monkeypatch
) -> None:
    cfg = tmp_path / ".mcp.json"
    cfg.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "p": {
                        "command": "npx",
                        "args": ["-y", "pkg@1.0.0", "--api-key", KEY],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    r = runner.invoke(app, ["lock", "--offline"])
    assert r.exit_code == 0, r.output
    assert "carries a credential" in r.output
    _gone((tmp_path / "mcp-lock.json").read_text(encoding="utf-8"), KEY)
    v = runner.invoke(app, ["lock", "--verify"])
    assert v.exit_code == 0, v.output
    assert "LOCK-013" in v.output


# ── Review fixes ─────────────────────────────────────────────────────────────


def test_env_flag_with_inner_assignment_is_redacted() -> None:
    assert redact_args(["--env=API_KEY=abcdef12"]) == ["--env=API_KEY=[REDACTED]"]
    assert redact_args(["--env=NODE_ENV=production"]) == ["--env=NODE_ENV=production"]
    assert redact_args(["-e", "API_KEY=abcdef12"]) == ["-e", "API_KEY=[REDACTED]"]


@pytest.mark.parametrize(
    ("arg", "expected"),
    [
        (
            "Server=h;User Id=sa;Password=se cret;Encrypt=true",
            "Server=h;User Id=sa;Password=[REDACTED];Encrypt=true",
        ),
        ("Data Source=x;Password='my pass'", "Data Source=x;Password=[REDACTED]"),
        ('Pwd="a b;c";X=1', "Pwd=[REDACTED];X=1"),
        ("host=h password=abc dbname=x", "host=h password=[REDACTED] dbname=x"),
    ],
)
def test_passwords_with_spaces_are_redacted_whole(arg: str, expected: str) -> None:
    assert redact_args([arg]) == [expected]
    assert redact_command_text(arg) == expected


def test_query_names_match_whole_tokens() -> None:
    url = "https://h/x?author=a&keyword=k&monkey=m&sort_key=1&primary_key=2&page=3"
    assert redact_url(url) == url
    assert redact_url("https://h/x?apiKey=zzzz&X-Amz-Credential=c") == (
        "https://h/x?apiKey=[REDACTED]&X-Amz-Credential=[REDACTED]"
    )


def test_short_env_password_is_redacted() -> None:
    assert redact_env_values({"PASSWORD": "x1"})["PASSWORD"] == FLAG_REDACTION_MARKER


def test_directory_vs_its_own_scan_file_is_no_change(tmp_path: Path) -> None:
    d = tmp_path / "a"
    d.mkdir()
    (d / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "plain": {
                        "command": "npx",
                        "args": ["-y", "@acme/p", "--port=80"],
                        "env": {
                            "GITHUB_TOKEN": KEY,
                            "DB_PASSWORD": PW,
                            "NODE_ENV": "x",
                        },
                    },
                    "sec": {
                        "command": "npx",
                        "args": ["-y", "p", "--password", "hunter22"],
                    },
                    "conn": {
                        "command": "npx",
                        "args": ["p", f"Server=h;Password={PW} x;Encrypt=true"],
                    },
                    "remote": {"url": f"https://u:{PW}@h.example/mcp?token={KEY}"},
                }
            }
        ),
        encoding="utf-8",
    )
    scan = tmp_path / "a.json"
    scan.write_text(
        run_scan(extra_paths=[d], skip_rug_pull=True).model_dump_json(),
        encoding="utf-8",
    )
    assert compare(load_input(str(d)), load_input(str(scan))) == []
    assert compare(load_input(str(scan)), load_input(str(d))) == []


# ── Re-review fixes ──────────────────────────────────────────────────────────

_N = 200_000
_QUADRATIC_SHAPES = {
    "A=": "A=" * (_N // 2),
    "--env=": "--env=" * (_N // 6),
    "--e=": "--e=" * (_N // 4),
    "-e ": "-e " * (_N // 3),
    "quoted": "A='" * (_N // 3),
    "key=": "key=" * (_N // 4),
    "password=": "password=" * (_N // 9),
    "password-quoted": "password='" * (_N // 10),
    "password-space": "password= " * (_N // 10),
}


@pytest.mark.parametrize("name", sorted(_QUADRATIC_SHAPES))
def test_assignment_shapes_are_linear_on_200kb(name: str) -> None:
    text = _QUADRATIC_SHAPES[name]
    for call in (
        lambda: redact_args([text]),
        lambda: redact_command_text(text),
        lambda: redact_url(text),
        lambda: redact_env_values({"X": text, text[:40]: "value"}),
    ):
        start = time.perf_counter()
        call()
        assert time.perf_counter() - start < 1.0, name


def test_secret_value_longer_than_the_search_window_leaks_no_tail() -> None:
    tail = "TAILSECRET" * 3
    out = redact_args(["password=" + "x" * 10_000 + tail])[0]
    assert tail not in out
    assert out == "password=[REDACTED]"


def _two_dirs(tmp_path: Path, base: dict, head: dict) -> tuple[Path, Path]:
    return (
        _dir_with(tmp_path, "rbase", base),
        _dir_with(tmp_path, "rhead", head),
    )


@pytest.mark.parametrize(
    ("before", "after"),
    [
        (
            {"command": "npx", "args": ["p", "--api-key", "oldvalue1234"]},
            {"command": "npx", "args": ["p", "--api-key", "newvalue5678"]},
        ),
        (
            {"command": "npx", "args": ["p", "Server=h;Password=oldpass1"]},
            {"command": "npx", "args": ["p", "Server=h;Password=newpass2"]},
        ),
        (
            {
                "command": "npx",
                "args": ["p"],
                "env": {"GITHUB_TOKEN": "ghp_" + "a" * 36},
            },
            {
                "command": "npx",
                "args": ["p"],
                "env": {"GITHUB_TOKEN": "ghp_" + "b" * 36},
            },
        ),
        (
            {"command": "npx", "args": ["p", "https://h.example/x?token=oldtoken123"]},
            {"command": "npx", "args": ["p", "https://h.example/x?token=newtoken456"]},
        ),
        (
            {"url": "https://h.example/mcp?token=oldtoken123"},
            {"url": "https://h.example/mcp?token=newtoken456"},
        ),
    ],
)
def test_dir_vs_dir_rotation_is_still_a_change(
    tmp_path: Path, before: dict, after: dict
) -> None:
    base, head = _two_dirs(tmp_path, {"s": before}, {"s": after})
    changes = compare(load_input(str(base)), load_input(str(head)))
    assert changes, "a rotated credential is a change between two directories"
    blob = json.dumps(
        [(c.before, c.after, c.command_diff, c.entity_name) for c in changes],
        default=str,
    )
    for secret in (
        "oldvalue1234",
        "newvalue5678",
        "oldpass1",
        "newpass2",
        "oldtoken123",
        "newtoken456",
        "a" * 36,
        "b" * 36,
    ):
        assert secret not in blob
    out = runner.invoke(app, ["diff", str(base), str(head), "--format", "json"])
    assert out.output.strip() not in ("", "[]")


def test_scan_json_vs_dir_with_changed_command_is_reported(tmp_path: Path) -> None:
    base = _dir_with(
        tmp_path,
        "mbase",
        {"s": {"command": "npx", "args": ["p", "--api-key", "secretvalue99"]}},
    )
    scan = tmp_path / "m.json"
    scan.write_text(
        run_scan(extra_paths=[base], skip_rug_pull=True).model_dump_json(),
        encoding="utf-8",
    )
    head = _dir_with(
        tmp_path,
        "mhead",
        {"s": {"command": "uvx", "args": ["p", "--api-key", "secretvalue99"]}},
    )
    changes = compare(load_input(str(scan)), load_input(str(head)))
    assert any(c.entity_type == EntityType.SERVER for c in changes)
    assert compare(load_input(str(scan)), load_input(str(base))) == []


@pytest.mark.parametrize("key", ["Password", "Pwd", "secret"])
@pytest.mark.parametrize("gap", [100, 4090, 5000, 20000])
@pytest.mark.parametrize("semi", [True, False])
def test_spaced_password_never_leaks_tail_past_window(
    key: str, gap: int, semi: bool
) -> None:
    text = f"Server=h;{key}=sec rot pass" + "X" * gap + (";Database=d" if semi else "")
    out = redact_args([text])[0]
    assert "rot" not in out and "XXXX" not in out
    assert out.startswith(f"Server=h;{key}=[REDACTED]")
    if semi:
        assert out.endswith(";Database=d")


def test_quoted_spaced_password_past_window() -> None:
    out = redact_args(["Password='sec rot " + "X" * 6000 + "';Database=d"])[0]
    assert "XXXX" not in out and "rot" not in out


def test_many_spaced_passwords_without_semicolon_is_linear() -> None:
    text = "password=a b " * 15000
    start = time.perf_counter()
    redact_args([text])
    assert time.perf_counter() - start < 1.0
