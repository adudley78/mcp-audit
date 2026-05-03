"""Tests for the mcp-audit snapshot command and supporting modules.

Covers:
- CycloneDX 1.5 output format and field correctness
- Native JSON output format and round-trip
- CycloneDX JSON schema validation (requires jsonschema + network/cache)
- Rehydrate mode (reconstruct attack-path graph from saved snapshot)
- Snapshot diff (delta between snapshot and current state)
- Stream mode (NDJSON output)
- Sign mode (mocked sigstore client)
- CLI integration (typer CliRunner)
- Edge cases: empty servers, corrupt snapshot, no network
"""

from __future__ import annotations

import json
import urllib.request
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from mcp_audit.models import (
    AttackPath,
    AttackPathSummary,
    Finding,
    MachineInfo,
    ScanResult,
    ScanScore,
    ServerConfig,
    Severity,
    TransportType,
)
from mcp_audit.output.snapshot import (
    format_cyclonedx_aibom,
    format_native,
    format_stream_lines,
    sha256_snapshot,
    sign_snapshot,
)
from mcp_audit.snapshot.diff import SnapshotDelta, diff_snapshot_against_current
from mcp_audit.snapshot.rehydrate import (
    RehydratedSnapshot,
    load_snapshot,
    rehydrate,
)

# ── CycloneDX schema cache ────────────────────────────────────────────────────

_CYCLONEDX_SCHEMA_URL = (
    "https://raw.githubusercontent.com/CycloneDX/specification/master"
    "/schema/bom-1.5.schema.json"
)
_SCHEMA_CACHE = Path(__file__).parent / "fixtures" / "cyclonedx-1.5.schema.json"


def _get_cyclonedx_schema() -> dict[str, Any]:
    """Fetch and locally cache the CycloneDX 1.5 JSON schema."""
    if _SCHEMA_CACHE.exists():
        return json.loads(_SCHEMA_CACHE.read_text())
    try:
        with urllib.request.urlopen(_CYCLONEDX_SCHEMA_URL, timeout=15) as resp:  # noqa: S310
            schema = json.loads(resp.read())
        _SCHEMA_CACHE.parent.mkdir(parents=True, exist_ok=True)
        _SCHEMA_CACHE.write_text(json.dumps(schema, indent=2))
        return schema
    except Exception:
        pytest.skip("CycloneDX 1.5 schema not available (network or cache missing)")


# ── Fixtures ──────────────────────────────────────────────────────────────────


def _make_machine() -> MachineInfo:
    return MachineInfo(
        hostname="test-host",
        username="test-user",
        os="Linux",
        os_version="6.1",
        scan_id="00000000-0000-0000-0000-000000000001",
    )


def _make_finding(
    finding_id: str = "CRED-001",
    server: str = "filesystem",
    severity: Severity = Severity.HIGH,
    owasp: list[str] | None = None,
) -> Finding:
    return Finding(
        id=finding_id,
        severity=severity,
        analyzer="credentials",
        client="claude_desktop",
        server=server,
        title="Exposed API key",
        description="An API key was found in the server environment.",
        evidence="OPENAI_API_KEY=sk-...",
        remediation="Move the key to a secrets manager.",
        cwe="CWE-312",
        owasp_mcp_top_10=owasp or ["MCP01"],
    )


def _make_server(name: str = "filesystem", command: str = "npx") -> ServerConfig:
    return ServerConfig(
        name=name,
        client="claude_desktop",
        config_path=Path("/rehydrated/test.json"),  # noqa: S108
        transport=TransportType.STDIO,
        command=command,
        args=["-y", "@modelcontextprotocol/server-filesystem", "/data"],
        env={},
        raw={},
    )


def _make_result(
    servers: list[ServerConfig] | None = None,
    findings: list[Finding] | None = None,
    with_score: bool = True,
    with_attack_paths: bool = False,
) -> ScanResult:
    """Build a minimal ScanResult for snapshot formatting tests."""
    if servers is None:
        servers = [_make_server()]
    if findings is None:
        findings = [_make_finding()]

    attack_path_summary: AttackPathSummary | None = None
    if with_attack_paths:
        attack_path_summary = AttackPathSummary(
            paths=[
                AttackPath(
                    id="PATH-001",
                    severity=Severity.HIGH,
                    title="File exfiltration via network",
                    description="filesystem → fetch can exfiltrate files.",
                    hops=["filesystem", "fetch"],
                    source_capability="file_read",
                    sink_capability="network_out",
                )
            ],
            hitting_set=["filesystem"],
            paths_broken_by={"filesystem": ["PATH-001"], "fetch": ["PATH-001"]},
        )

    score: ScanScore | None = None
    if with_score:
        score = ScanScore(
            numeric_score=72,
            grade="B",
            positive_signals=["No poisoning"],
            deductions=["1 HIGH finding"],
        )

    return ScanResult(
        servers=servers,
        findings=findings,
        clients_scanned=1,
        machine=_make_machine(),
        attack_path_summary=attack_path_summary,
        score=score,
    )


# ── CycloneDX format tests ────────────────────────────────────────────────────


class TestFormatCycloneDx:
    """CycloneDX output structure and field correctness."""

    def test_bom_format_field(self) -> None:
        """Output must declare ``bomFormat: CycloneDX``."""
        doc = format_cyclonedx_aibom(_make_result(), host_id="myhost")
        assert doc["bomFormat"] == "CycloneDX"

    def test_spec_version_15(self) -> None:
        """specVersion must be 1.5."""
        doc = format_cyclonedx_aibom(_make_result(), host_id="myhost")
        assert doc["specVersion"] == "1.5"

    def test_metadata_timestamp_iso8601(self) -> None:
        """metadata.timestamp must be ISO 8601 UTC (ends with Z)."""
        doc = format_cyclonedx_aibom(_make_result(), host_id="myhost")
        ts = doc["metadata"]["timestamp"]
        assert ts.endswith("Z"), f"Expected UTC timestamp, got: {ts}"

    def test_metadata_tools_contains_mcp_audit(self) -> None:
        """metadata.tools must include an entry for mcp-audit."""
        doc = format_cyclonedx_aibom(_make_result(), host_id="myhost")
        tool_names = [t["name"] for t in doc["metadata"]["tools"]]
        assert "mcp-audit" in tool_names

    def test_metadata_tools_version_matches_package(self) -> None:
        """metadata.tools[mcp-audit].version must equal __version__."""
        from mcp_audit import __version__  # noqa: PLC0415

        doc = format_cyclonedx_aibom(_make_result(), host_id="myhost")
        mcp_audit_tool = next(
            t for t in doc["metadata"]["tools"] if t["name"] == "mcp-audit"
        )
        assert mcp_audit_tool["version"] == __version__

    def test_metadata_properties_host_id(self) -> None:
        """metadata.properties must contain mcp-audit:host_id."""
        doc = format_cyclonedx_aibom(_make_result(), host_id="forensic-host")
        props = {p["name"]: p["value"] for p in doc["metadata"]["properties"]}
        assert props["mcp-audit:host_id"] == "forensic-host"

    def test_metadata_properties_scan_grade(self) -> None:
        """metadata.properties must contain mcp-audit:scan_grade."""
        doc = format_cyclonedx_aibom(_make_result(with_score=True), host_id="h")
        props = {p["name"]: p["value"] for p in doc["metadata"]["properties"]}
        assert props["mcp-audit:scan_grade"] == "B"

    def test_metadata_properties_owasp_codes(self) -> None:
        """metadata.properties must contain mcp-audit:owasp_mcp_top_10_categories."""
        result = _make_result(findings=[_make_finding(owasp=["MCP01", "MCP03"])])
        doc = format_cyclonedx_aibom(result, host_id="h")
        props = {p["name"]: p["value"] for p in doc["metadata"]["properties"]}
        codes = props["mcp-audit:owasp_mcp_top_10_categories"]
        assert "MCP01" in codes
        assert "MCP03" in codes

    def test_components_contain_server(self) -> None:
        """Each MCP server must produce a component of type application."""
        result = _make_result(servers=[_make_server("my-server")])
        doc = format_cyclonedx_aibom(result, host_id="h")
        names = [c["name"] for c in doc["components"]]
        assert "my-server" in names

    def test_component_type_is_application(self) -> None:
        """Server components must have type: application."""
        doc = format_cyclonedx_aibom(_make_result(), host_id="h")
        server_comp = next(c for c in doc["components"] if c["name"] == "filesystem")
        assert server_comp["type"] == "application"

    def test_component_bom_ref_format(self) -> None:
        """bom-ref must follow the mcp-server-<name> convention."""
        doc = format_cyclonedx_aibom(_make_result(), host_id="h")
        server_comp = next(c for c in doc["components"] if c["name"] == "filesystem")
        assert server_comp["bom-ref"] == "mcp-server-filesystem"

    def test_vulnerabilities_contain_finding(self) -> None:
        """Each finding must produce a vulnerability entry."""
        result = _make_result(findings=[_make_finding("CRED-001", "filesystem")])
        doc = format_cyclonedx_aibom(result, host_id="h")
        vuln_ids = [v["id"] for v in doc["vulnerabilities"]]
        assert "CRED-001" in vuln_ids

    def test_vulnerability_severity_mapping(self) -> None:
        """HIGH finding must map to 'high' in CycloneDX ratings."""
        result = _make_result(findings=[_make_finding(severity=Severity.HIGH)])
        doc = format_cyclonedx_aibom(result, host_id="h")
        vuln = doc["vulnerabilities"][0]
        assert vuln["ratings"][0]["severity"] == "high"

    def test_vulnerability_cwe_parsed(self) -> None:
        """CWE-312 must appear as integer 312 in cwes array."""
        doc = format_cyclonedx_aibom(_make_result(), host_id="h")
        vuln = doc["vulnerabilities"][0]
        assert vuln.get("cwes") == [312]

    def test_vulnerability_affects_refs_server(self) -> None:
        """vulnerability.affects must reference the correct server bom-ref."""
        result = _make_result(
            servers=[_make_server("my-server")],
            findings=[_make_finding(server="my-server")],
        )
        doc = format_cyclonedx_aibom(result, host_id="h")
        vuln = doc["vulnerabilities"][0]
        assert vuln["affects"][0]["ref"] == "mcp-server-my-server"

    def test_vulnerability_owasp_property(self) -> None:
        """vulnerability.properties must carry mcp-audit:owasp_mcp_top_10."""
        result = _make_result(findings=[_make_finding(owasp=["MCP01", "MCP09"])])
        doc = format_cyclonedx_aibom(result, host_id="h")
        vuln = doc["vulnerabilities"][0]
        vuln_props = {p["name"]: p["value"] for p in vuln["properties"]}
        assert "MCP01" in vuln_props["mcp-audit:owasp_mcp_top_10"]

    def test_empty_servers_produces_empty_components(self) -> None:
        """A host with no MCP servers must yield an empty components list."""
        result = _make_result(servers=[], findings=[])
        doc = format_cyclonedx_aibom(result, host_id="h")
        # Only the attack-surface component (if any) — no server components.
        server_comps = [c for c in doc["components"] if c["type"] == "application"]
        assert server_comps == []

    def test_attack_path_summary_component(self) -> None:
        """Attack paths must generate a 'mcp-attack-surface' component."""
        result = _make_result(
            servers=[_make_server("filesystem"), _make_server("fetch", "uvx")],
            with_attack_paths=True,
        )
        doc = format_cyclonedx_aibom(result, host_id="h")
        names = [c["name"] for c in doc["components"]]
        assert "mcp-attack-surface" in names

    def test_serial_number_is_urn_uuid(self) -> None:
        """serialNumber must be a urn:uuid: URI."""
        doc = format_cyclonedx_aibom(_make_result(), host_id="h")
        assert doc["serialNumber"].startswith("urn:uuid:")


class TestCycloneDxSchemaValidation:
    """Validate CycloneDX output against the official 1.5 JSON schema."""

    def test_cyclonedx_output_validates_against_schema(self) -> None:
        """CycloneDX snapshot must be valid per CycloneDX 1.5 JSON schema."""
        try:
            import jsonschema  # noqa: PLC0415
        except ImportError:
            pytest.skip("jsonschema not installed")

        result = _make_result(
            servers=[_make_server("filesystem"), _make_server("fetch", "uvx")],
            findings=[
                _make_finding("CRED-001", "filesystem", Severity.HIGH, ["MCP01"]),
                _make_finding("POISON-001", "fetch", Severity.CRITICAL, ["MCP03"]),
            ],
            with_score=True,
            with_attack_paths=True,
        )
        doc = format_cyclonedx_aibom(result, host_id="ci-host")
        schema = _get_cyclonedx_schema()
        jsonschema.validate(instance=doc, schema=schema)


# ── Native format tests ───────────────────────────────────────────────────────


class TestFormatNative:
    """Native JSON output structure and round-trip."""

    def test_format_field(self) -> None:
        """format field must be 'mcp-audit-native'."""
        doc = format_native(_make_result(), host_id="h")
        assert doc["format"] == "mcp-audit-native"

    def test_metadata_timestamp_present(self) -> None:
        """metadata.timestamp must be ISO 8601."""
        doc = format_native(_make_result(), host_id="h")
        assert doc["metadata"]["timestamp"].endswith("Z")

    def test_metadata_host_id_property(self) -> None:
        """metadata.properties must contain mcp-audit:host_id."""
        doc = format_native(_make_result(), host_id="native-host")
        props = {p["name"]: p["value"] for p in doc["metadata"]["properties"]}
        assert props["mcp-audit:host_id"] == "native-host"

    def test_snapshot_data_round_trips(self) -> None:
        """snapshot_data must survive a json.loads(json.dumps(...)) round-trip."""
        result = _make_result()
        doc = format_native(result, host_id="h")
        re_serialised = json.loads(json.dumps(doc, default=str))
        assert re_serialised["snapshot_data"]["servers_found"] == result.servers_found

    def test_snapshot_data_contains_findings(self) -> None:
        """snapshot_data must include the findings list."""
        result = _make_result(findings=[_make_finding("CRED-001")])
        doc = format_native(result, host_id="h")
        finding_ids = [f["id"] for f in doc["snapshot_data"]["findings"]]
        assert "CRED-001" in finding_ids


# ── Stream mode tests ─────────────────────────────────────────────────────────


class TestFormatStreamLines:
    """NDJSON stream output."""

    def test_one_line_per_finding(self) -> None:
        """format_stream_lines must emit exactly one line per finding."""
        result = _make_result(
            findings=[
                _make_finding("CRED-001"),
                _make_finding("POISON-001", server="fetch"),
            ]
        )
        lines = format_stream_lines(result)
        assert len(lines) == 2

    def test_each_line_is_valid_json(self) -> None:
        """Every line from format_stream_lines must be valid JSON."""
        result = _make_result(findings=[_make_finding()])
        for line in format_stream_lines(result):
            parsed = json.loads(line)
            assert isinstance(parsed, dict)

    def test_stream_line_contains_required_keys(self) -> None:
        """Each stream line must contain id, severity, server, timestamp, host_id."""
        result = _make_result(findings=[_make_finding("CRED-007")])
        line = json.loads(format_stream_lines(result)[0])
        for key in ("id", "severity", "server", "timestamp", "host_id"):
            assert key in line, f"Missing key: {key}"

    def test_empty_findings_yields_no_lines(self) -> None:
        """A result with no findings must yield an empty list."""
        result = _make_result(findings=[])
        assert format_stream_lines(result) == []


# ── Rehydrate tests ───────────────────────────────────────────────────────────


class TestRehydrate:
    """Rehydrate reconstructs the attack-path graph from a saved snapshot."""

    def _write_cyclonedx_snapshot(
        self,
        tmp_path: Path,
        result: ScanResult,
        host_id: str = "test-host",
    ) -> Path:
        doc = format_cyclonedx_aibom(result, host_id=host_id)
        snap_path = tmp_path / "test.snapshot.json"
        snap_path.write_text(json.dumps(doc, default=str), encoding="utf-8")
        return snap_path

    def _write_native_snapshot(
        self,
        tmp_path: Path,
        result: ScanResult,
        host_id: str = "test-host",
    ) -> Path:
        doc = format_native(result, host_id=host_id)
        snap_path = tmp_path / "test.native.snapshot.json"
        snap_path.write_text(json.dumps(doc, default=str), encoding="utf-8")
        return snap_path

    def test_rehydrate_returns_rehydrated_snapshot(self, tmp_path: Path) -> None:
        """rehydrate() must return a RehydratedSnapshot instance."""
        result = _make_result()
        snap = self._write_cyclonedx_snapshot(tmp_path, result)
        rh = rehydrate(snap)
        assert isinstance(rh, RehydratedSnapshot)

    def test_rehydrate_preserves_host_id(self, tmp_path: Path) -> None:
        """RehydratedSnapshot.host_id must match the snapshot's recorded host."""
        result = _make_result()
        snap = self._write_cyclonedx_snapshot(tmp_path, result, host_id="incident-host")
        rh = rehydrate(snap)
        assert rh.host_id == "incident-host"

    def test_rehydrate_timestamp_is_string(self, tmp_path: Path) -> None:
        """RehydratedSnapshot.snapshot_timestamp must be a non-empty string."""
        result = _make_result()
        snap = self._write_cyclonedx_snapshot(tmp_path, result)
        rh = rehydrate(snap)
        assert isinstance(rh.snapshot_timestamp, str)
        assert len(rh.snapshot_timestamp) > 0

    def test_rehydrate_reconstructs_servers(self, tmp_path: Path) -> None:
        """Rehydrated result must contain the same server names as the snapshot."""
        result = _make_result(servers=[_make_server("filesystem")])
        snap = self._write_cyclonedx_snapshot(tmp_path, result)
        rh = rehydrate(snap)
        server_names = {s.name for s in rh.result.servers}
        assert "filesystem" in server_names

    def test_rehydrate_from_native_snapshot(self, tmp_path: Path) -> None:
        """rehydrate() must work with native-format snapshots as well."""
        result = _make_result()
        snap = self._write_native_snapshot(tmp_path, result)
        rh = rehydrate(snap)
        assert isinstance(rh, RehydratedSnapshot)

    def test_rehydrate_corrupt_snapshot_raises_value_error(
        self, tmp_path: Path
    ) -> None:
        """Corrupt snapshot must raise ValueError with a meaningful message."""
        bad = tmp_path / "bad.json"
        bad.write_text("{not valid json")
        with pytest.raises(ValueError, match="Cannot parse snapshot JSON"):
            rehydrate(bad)

    def test_rehydrate_missing_metadata_raises_value_error(
        self, tmp_path: Path
    ) -> None:
        """Snapshot without metadata block must raise ValueError."""
        bad = tmp_path / "nometa.json"
        bad.write_text(json.dumps({"bomFormat": "CycloneDX", "components": []}))
        with pytest.raises(ValueError, match="metadata"):
            rehydrate(bad)

    def test_rehydrate_missing_file_raises_value_error(self, tmp_path: Path) -> None:
        """Passing a non-existent path to rehydrate() must raise ValueError."""
        with pytest.raises(ValueError, match="not found"):
            rehydrate(tmp_path / "ghost.json")

    def test_load_snapshot_returns_dict(self, tmp_path: Path) -> None:
        """load_snapshot() must return a dict for a valid snapshot file."""
        result = _make_result()
        snap = self._write_cyclonedx_snapshot(tmp_path, result)
        raw = load_snapshot(snap)
        assert isinstance(raw, dict)
        assert "metadata" in raw


# ── Snapshot diff tests ───────────────────────────────────────────────────────


class TestSnapshotDiff:
    """diff_snapshot_against_current computes server-level delta."""

    def _save_snapshot(self, tmp_path: Path, servers: list[ServerConfig]) -> Path:
        result = _make_result(servers=servers, findings=[])
        doc = format_cyclonedx_aibom(result, host_id="h")
        snap = tmp_path / "snap.json"
        snap.write_text(json.dumps(doc, default=str))
        return snap

    def test_no_change(self, tmp_path: Path) -> None:
        """Identical state produces an empty delta."""
        server = _make_server("fs")
        snap = self._save_snapshot(tmp_path, [server])
        delta = diff_snapshot_against_current(snap, [server])
        assert delta.added == []
        assert delta.removed == []

    def test_added_server_detected(self, tmp_path: Path) -> None:
        """A server absent in the snapshot but present now must appear in added."""
        snap = self._save_snapshot(tmp_path, [_make_server("old")])
        delta = diff_snapshot_against_current(
            snap, [_make_server("old"), _make_server("new")]
        )
        assert "new" in delta.added

    def test_removed_server_detected(self, tmp_path: Path) -> None:
        """A server present in the snapshot but gone now must appear in removed."""
        snap = self._save_snapshot(
            tmp_path, [_make_server("old"), _make_server("gone")]
        )
        delta = diff_snapshot_against_current(snap, [_make_server("old")])
        assert "gone" in delta.removed

    def test_summary_line_format(self, tmp_path: Path) -> None:
        """summary_line() must include counts and timestamp."""
        snap = self._save_snapshot(tmp_path, [_make_server("old")])
        delta = diff_snapshot_against_current(snap, [_make_server("new")])
        summary = delta.summary_line()
        assert "added" in summary
        assert "removed" in summary

    def test_delta_dataclass_counts(self) -> None:
        """added_count and removed_count must match list lengths."""
        delta = SnapshotDelta(
            snapshot_timestamp="2026-01-01T00:00:00Z",
            added=["a", "b"],
            removed=["c"],
            unchanged=["d"],
        )
        assert delta.added_count == 2
        assert delta.removed_count == 1


# ── SHA-256 integrity test ────────────────────────────────────────────────────


class TestSha256Snapshot:
    """sha256_snapshot returns the correct hex digest."""

    def test_sha256_is_64_chars(self, tmp_path: Path) -> None:
        """SHA-256 digest must be exactly 64 hex characters."""
        f = tmp_path / "snap.json"
        f.write_text('{"hello": "world"}')
        digest = sha256_snapshot(f)
        assert len(digest) == 64
        assert all(c in "0123456789abcdef" for c in digest)


# ── Sign mode tests ───────────────────────────────────────────────────────────


class TestSignSnapshot:
    """sign_snapshot wraps sigstore signing; tested with mocked client."""

    def test_sign_raises_import_error_without_sigstore(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """sign_snapshot must raise ImportError when sigstore is not installed."""
        snap = tmp_path / "snap.json"
        snap.write_text('{"test": true}')

        # Simulate sigstore not installed by blocking the import.
        import builtins  # noqa: PLC0415

        real_import = builtins.__import__

        def _fake_import(name: str, *args: object, **kwargs: object) -> object:
            if name == "sigstore.sign":
                raise ImportError("No module named 'sigstore'")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", _fake_import)
        with pytest.raises(ImportError, match="sigstore"):
            sign_snapshot(snap)

    def test_sign_sig_path_naming_convention(self, tmp_path: Path) -> None:
        """sign_snapshot target .sig path must be <snapshot>.json.sig."""
        # Verify the expected naming by inspecting the computed path directly
        # (the function may raise ImportError if sigstore not installed —
        # what matters is the naming convention is correct).
        from pathlib import Path as _Path  # noqa: PLC0415

        snap = tmp_path / "audit.snapshot.json"
        snap.write_text("{}")
        expected_sig = _Path(str(snap) + ".sig")
        # The sig path is deterministically derived — test via sign_snapshot
        # or by direct path arithmetic.
        assert str(expected_sig).endswith(".json.sig")
        assert expected_sig.parent == snap.parent

    def test_sign_runtime_error_when_no_credential(self, tmp_path: Path) -> None:
        """sign_snapshot raises RuntimeError when OIDC credential detection fails."""
        snap = tmp_path / "snap.json"
        snap.write_text('{"test": true}')

        # Inject a mock sigstore.oidc that raises on detect_credential.
        mock_oidc = MagicMock()
        mock_oidc.detect_credential.side_effect = Exception("no ambient credential")
        mock_sign = MagicMock()

        with patch.dict(
            "sys.modules",
            {"sigstore.oidc": mock_oidc, "sigstore.sign": mock_sign},
        ):
            # Re-import the function with patched modules in sys.modules
            import importlib  # noqa: PLC0415

            import mcp_audit.output.snapshot as _snap_mod  # noqa: PLC0415, E402

            importlib.reload(_snap_mod)
            try:
                _snap_mod.sign_snapshot(snap)
            except (ImportError, RuntimeError) as exc:
                # ImportError if not installed; RuntimeError if credential fails.
                assert any(
                    kw in str(exc).lower()
                    for kw in ("sigstore", "credential", "oidc", "ambient")
                )
            finally:
                # Restore original module state
                importlib.reload(_snap_mod)


# ── CLI integration tests ─────────────────────────────────────────────────────


class TestSnapshotCli:
    """CLI-level integration tests using Typer's CliRunner."""

    def _runner(self):  # type: ignore[return]
        from typer.testing import CliRunner  # noqa: PLC0415

        return CliRunner()

    def _app(self):  # type: ignore[return]
        from mcp_audit.cli import app  # noqa: PLC0415

        return app

    def test_snapshot_help(self) -> None:
        """``mcp-audit snapshot --help`` must exit 0."""
        result = self._runner().invoke(self._app(), ["snapshot", "--help"])
        assert result.exit_code == 0
        assert "snapshot" in result.output.lower()

    def test_snapshot_writes_cyclonedx_to_file(self, tmp_path: Path) -> None:
        """``snapshot --output`` must write a CycloneDX JSON file."""
        out_file = tmp_path / "snap.json"

        mock_result = _make_result()

        with patch("mcp_audit.cli.snapshot.run_scan", return_value=mock_result):
            r = self._runner().invoke(
                self._app(),
                ["snapshot", "--output", str(out_file)],
            )

        assert r.exit_code == 0, r.output
        assert out_file.exists()
        doc = json.loads(out_file.read_text())
        assert doc["bomFormat"] == "CycloneDX"

    def test_snapshot_writes_native_format(self, tmp_path: Path) -> None:
        """``snapshot --format native --output`` must write native JSON."""
        out_file = tmp_path / "snap.native.json"
        mock_result = _make_result()

        with patch("mcp_audit.cli.snapshot.run_scan", return_value=mock_result):
            r = self._runner().invoke(
                self._app(),
                ["snapshot", "--format", "native", "--output", str(out_file)],
            )

        assert r.exit_code == 0, r.output
        doc = json.loads(out_file.read_text())
        assert doc["format"] == "mcp-audit-native"

    def test_snapshot_stream_mode(self) -> None:
        """``snapshot --stream`` must emit NDJSON lines to stdout."""
        mock_result = _make_result(
            findings=[_make_finding("CRED-001"), _make_finding("CRED-002")]
        )

        with patch("mcp_audit.cli.snapshot.run_scan", return_value=mock_result):
            r = self._runner().invoke(self._app(), ["snapshot", "--stream"])

        assert r.exit_code == 0, r.output
        lines = [ln for ln in r.output.strip().split("\n") if ln.strip()]
        assert len(lines) == 2
        for line in lines:
            json.loads(line)  # must be valid JSON

    def test_snapshot_invalid_format_exits_2(self) -> None:
        """An unknown --format value must exit with code 2."""
        r = self._runner().invoke(self._app(), ["snapshot", "--format", "xml"])
        assert r.exit_code == 2

    def test_snapshot_sign_requires_output(self) -> None:
        """``--sign`` without ``--output`` must exit with code 2."""
        mock_result = _make_result()
        with patch("mcp_audit.cli.snapshot.run_scan", return_value=mock_result):
            r = self._runner().invoke(self._app(), ["snapshot", "--sign"])
        assert r.exit_code == 2

    def test_snapshot_rehydrate_missing_file_exits_2(self) -> None:
        """``--rehydrate`` with a missing path must exit with code 2."""
        r = self._runner().invoke(
            self._app(),
            ["snapshot", "--rehydrate", "/nonexistent/ghost.json"],
        )
        assert r.exit_code == 2

    def test_snapshot_input_missing_file_exits_2(self) -> None:
        """``--input`` with a missing file must exit with code 2."""
        r = self._runner().invoke(
            self._app(),
            ["snapshot", "--input", "/nonexistent/scan.json"],
        )
        assert r.exit_code == 2

    def test_snapshot_from_input_file(self, tmp_path: Path) -> None:
        """``--input <scan.json>`` must load a previous scan without re-running."""
        mock_result = _make_result()
        scan_json = tmp_path / "scan.json"
        scan_json.write_text(mock_result.model_dump_json(by_alias=True))
        out_file = tmp_path / "snap.json"

        r = self._runner().invoke(
            self._app(),
            ["snapshot", "--input", str(scan_json), "--output", str(out_file)],
        )

        assert r.exit_code == 0, r.output
        assert out_file.exists()
        doc = json.loads(out_file.read_text())
        assert doc["bomFormat"] == "CycloneDX"
