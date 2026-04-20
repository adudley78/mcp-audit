"""Tests for MachineInfo model population and formatter integration."""

from __future__ import annotations

import json
import uuid
from unittest.mock import patch

import pytest
from rich.console import Console

from mcp_audit.models import (
    Finding,
    MachineInfo,
    ScanResult,
    Severity,
    _collect_machine_info,
)
from mcp_audit.output.dashboard import _build_scan_data
from mcp_audit.output.nucleus import format_nucleus
from mcp_audit.output.sarif import format_sarif
from mcp_audit.output.terminal import print_results

# ── Fixtures ──────────────────────────────────────────────────────────────────


def _make_machine(
    hostname: str = "test-host",
    username: str = "alice",
    os: str = "Linux",
    os_version: str = "5.15.0",
    scan_id: str | None = None,
) -> MachineInfo:
    return MachineInfo(
        hostname=hostname,
        username=username,
        os=os,
        os_version=os_version,
        scan_id=scan_id or str(uuid.uuid4()),
    )


def _make_finding(
    *,
    finding_id: str = "POISON-001",
    severity: Severity = Severity.HIGH,
    client: str = "cursor",
    server: str = "filesystem",
) -> Finding:
    return Finding(
        id=finding_id,
        severity=severity,
        analyzer="poisoning",
        client=client,
        server=server,
        title="Test finding",
        description="A test finding.",
        evidence="evidence string",
        remediation="Remediation text.",
        finding_path="/home/alice/.cursor/mcp.json",
    )


def _make_result(
    *,
    machine: MachineInfo | None = None,
    findings: list[Finding] | None = None,
) -> ScanResult:
    result = ScanResult(
        clients_scanned=1,
        servers_found=1,
        findings=findings or [],
    )
    if machine is not None:
        result.machine = machine
    return result


# ── MachineInfo model ─────────────────────────────────────────────────────────


class TestMachineInfoModel:
    def test_fields_present(self) -> None:
        m = _make_machine()
        assert m.hostname == "test-host"
        assert m.username == "alice"
        assert m.os == "Linux"
        assert m.os_version == "5.15.0"
        assert isinstance(m.scan_id, str)

    def test_scan_id_is_uuid_format(self) -> None:
        m = _make_machine()
        # Should not raise
        uuid.UUID(m.scan_id)

    def test_round_trip(self) -> None:
        m = _make_machine()
        restored = MachineInfo(**m.model_dump())
        assert restored == m


class TestCollectMachineInfo:
    """Verify _collect_machine_info populates all fields from platform APIs."""

    def test_uses_platform_node_for_hostname(self) -> None:
        with patch("platform.node", return_value="my-laptop"):
            info = _collect_machine_info()
        assert info.hostname == "my-laptop"

    def test_uses_platform_system_for_os(self) -> None:
        with patch("platform.system", return_value="Darwin"):
            info = _collect_machine_info()
        assert info.os == "Darwin"

    def test_uses_platform_version_for_os_version(self) -> None:
        with patch("platform.version", return_value="Darwin Kernel 24.0"):
            info = _collect_machine_info()
        assert info.os_version == "Darwin Kernel 24.0"

    def test_uses_os_getlogin_for_username(self) -> None:
        with patch("os.getlogin", return_value="bob"):
            info = _collect_machine_info()
        assert info.username == "bob"

    def test_falls_back_to_getpass_when_getlogin_raises(self) -> None:
        with (
            patch("os.getlogin", side_effect=OSError("no tty")),
            patch("getpass.getuser", return_value="fallback-user"),
        ):
            info = _collect_machine_info()
        assert info.username == "fallback-user"

    def test_scan_id_is_unique_per_call(self) -> None:
        info_a = _collect_machine_info()
        info_b = _collect_machine_info()
        assert info_a.scan_id != info_b.scan_id

    def test_scan_id_is_valid_uuid(self) -> None:
        info = _collect_machine_info()
        uuid.UUID(info.scan_id)  # raises ValueError if invalid


class TestScanResultMachineDefault:
    """ScanResult.machine is always auto-populated."""

    def test_machine_is_populated(self) -> None:
        result = ScanResult()
        assert isinstance(result.machine, MachineInfo)
        assert result.machine.hostname  # non-empty

    def test_machine_has_valid_scan_id(self) -> None:
        result = ScanResult()
        uuid.UUID(result.machine.scan_id)

    def test_each_scan_result_has_distinct_scan_id(self) -> None:
        a = ScanResult()
        b = ScanResult()
        assert a.machine.scan_id != b.machine.scan_id


# ── JSON output ───────────────────────────────────────────────────────────────


class TestJsonOutput:
    """model_dump_json automatically includes machine as a nested object."""

    def test_machine_present_in_json(self) -> None:
        result = _make_result(machine=_make_machine(hostname="json-host"))
        data = json.loads(result.model_dump_json())
        assert "machine" in data

    def test_machine_fields_in_json(self) -> None:
        m = _make_machine(hostname="json-host", username="carol", os="Windows")
        result = _make_result(machine=m)
        data = json.loads(result.model_dump_json())
        assert data["machine"]["hostname"] == "json-host"
        assert data["machine"]["username"] == "carol"
        assert data["machine"]["os"] == "Windows"

    def test_machine_scan_id_in_json(self) -> None:
        fixed_id = str(uuid.uuid4())
        m = _make_machine(scan_id=fixed_id)
        result = _make_result(machine=m)
        data = json.loads(result.model_dump_json())
        assert data["machine"]["scan_id"] == fixed_id


# ── Nucleus formatter ─────────────────────────────────────────────────────────


class TestNucleusFormatter:
    @pytest.fixture(autouse=True)
    def _pro(self, pro_enabled: None) -> None:
        """Activate the Pro gate for all nucleus MachineInfo tests."""

    def test_host_name_in_envelope(self) -> None:
        result = _make_result(machine=_make_machine(hostname="nucleus-host"))
        doc = json.loads(format_nucleus(result))
        assert doc["host_name"] == "nucleus-host"

    def test_operating_system_name_in_envelope(self) -> None:
        result = _make_result(machine=_make_machine(os="Linux"))
        doc = json.loads(format_nucleus(result))
        assert doc["operating_system_name"] == "Linux"

    def test_asset_name_prefixed_with_hostname(self) -> None:
        result = _make_result(
            machine=_make_machine(hostname="prod-host"),
            findings=[_make_finding(client="cursor", server="filesystem")],
        )
        doc = json.loads(format_nucleus(result))
        assert doc["findings"][0]["asset_name"] == "prod-host/cursor/filesystem"

    def test_asset_prefix_overrides_hostname(self) -> None:
        result = _make_result(
            machine=_make_machine(hostname="MacBookAir"),
            findings=[_make_finding(client="cursor", server="filesystem")],
        )
        doc = json.loads(format_nucleus(result, asset_prefix="ASSET-1042"))
        assert doc["findings"][0]["asset_name"] == "ASSET-1042/cursor/filesystem"

    def test_asset_prefix_does_not_change_host_name_field(self) -> None:
        """host_name in envelope always reflects the real hostname."""
        result = _make_result(machine=_make_machine(hostname="real-host"))
        doc = json.loads(format_nucleus(result, asset_prefix="override"))
        assert doc["host_name"] == "real-host"

    def test_no_prefix_arg_uses_hostname(self) -> None:
        result = _make_result(
            machine=_make_machine(hostname="my-mac"),
            findings=[_make_finding()],
        )
        doc = json.loads(format_nucleus(result))
        assert doc["findings"][0]["asset_name"].startswith("my-mac/")

    def test_empty_findings_still_has_envelope_fields(self) -> None:
        result = _make_result(machine=_make_machine())
        doc = json.loads(format_nucleus(result))
        assert "host_name" in doc
        assert "operating_system_name" in doc


# ── SARIF formatter ───────────────────────────────────────────────────────────


class TestSarifFormatter:
    def _doc(self, result: ScanResult, **kwargs: object) -> dict:
        return json.loads(format_sarif(result, **kwargs))  # type: ignore[arg-type]

    def test_invocations_present(self) -> None:
        result = _make_result(machine=_make_machine())
        doc = self._doc(result)
        assert "invocations" in doc["runs"][0]
        assert len(doc["runs"][0]["invocations"]) == 1

    def test_machine_in_invocation(self) -> None:
        result = _make_result(machine=_make_machine(hostname="sarif-host"))
        doc = self._doc(result)
        inv = doc["runs"][0]["invocations"][0]
        assert inv["machine"] == "sarif-host"

    def test_account_in_invocation(self) -> None:
        result = _make_result(machine=_make_machine(username="dave"))
        doc = self._doc(result)
        inv = doc["runs"][0]["invocations"][0]
        assert inv["account"] == "dave"

    def test_operating_system_in_invocation(self) -> None:
        result = _make_result(machine=_make_machine(os="Darwin", os_version="24.0.0"))
        doc = self._doc(result)
        inv = doc["runs"][0]["invocations"][0]
        assert "Darwin" in inv["operatingSystem"]
        assert "24.0.0" in inv["operatingSystem"]

    def test_asset_prefix_overrides_machine_in_invocation(self) -> None:
        result = _make_result(machine=_make_machine(hostname="MacBookAir"))
        doc = self._doc(result, asset_prefix="ASSET-9999")
        inv = doc["runs"][0]["invocations"][0]
        assert inv["machine"] == "ASSET-9999"

    def test_execution_successful_flag(self) -> None:
        result = _make_result(machine=_make_machine())
        doc = self._doc(result)
        inv = doc["runs"][0]["invocations"][0]
        assert inv["executionSuccessful"] is True

    def test_no_prefix_arg_uses_hostname(self) -> None:
        result = _make_result(machine=_make_machine(hostname="real-machine"))
        doc = self._doc(result)
        assert doc["runs"][0]["invocations"][0]["machine"] == "real-machine"


# ── Terminal formatter ────────────────────────────────────────────────────────


class TestTerminalFormatter:
    def _capture(self, result: ScanResult) -> str:
        console = Console(width=120, highlight=False)
        with console.capture() as cap:
            print_results(result, console=console)
        return cap.get()

    def test_machine_line_present(self) -> None:
        result = _make_result(
            machine=_make_machine(hostname="term-host", username="eve", os="Linux")
        )
        output = self._capture(result)
        assert "term-host" in output
        assert "eve@Linux" in output

    def test_machine_line_after_header(self) -> None:
        result = _make_result(
            machine=_make_machine(hostname="abc", username="u", os="Darwin")
        )
        output = self._capture(result)
        header_pos = output.find("mcp-audit")
        machine_pos = output.find("abc")
        assert machine_pos > header_pos

    def test_machine_line_format(self) -> None:
        result = _make_result(
            machine=_make_machine(hostname="host42", username="frank", os="Windows")
        )
        output = self._capture(result)
        assert "Machine:" in output
        assert "frank@Windows" in output


# ── Dashboard scan data ───────────────────────────────────────────────────────


class TestDashboardFormatter:
    @pytest.fixture(autouse=True)
    def _pro(self, pro_enabled: None) -> None:
        """Activate the Pro gate for dashboard MachineInfo tests."""

    def test_machine_present_in_scan_data(self) -> None:
        result = _make_result(machine=_make_machine(hostname="dash-host"))
        data = _build_scan_data(result)
        assert "machine" in data

    def test_machine_hostname_in_scan_data(self) -> None:
        result = _make_result(machine=_make_machine(hostname="dash-host"))
        data = _build_scan_data(result)
        assert data["machine"]["hostname"] == "dash-host"

    def test_machine_username_in_scan_data(self) -> None:
        result = _make_result(machine=_make_machine(username="grace"))
        data = _build_scan_data(result)
        assert data["machine"]["username"] == "grace"

    def test_machine_os_in_scan_data(self) -> None:
        result = _make_result(machine=_make_machine(os="Darwin"))
        data = _build_scan_data(result)
        assert data["machine"]["os"] == "Darwin"

    def test_machine_scan_id_in_scan_data(self) -> None:
        fixed_id = str(uuid.uuid4())
        result = _make_result(machine=_make_machine(scan_id=fixed_id))
        data = _build_scan_data(result)
        assert data["machine"]["scan_id"] == fixed_id

    def test_machine_bar_element_in_html(self) -> None:
        from mcp_audit.output.dashboard import generate_html

        result = _make_result(machine=_make_machine(hostname="html-host"))
        html = generate_html(result)
        assert "machine-bar" in html
        assert "html-host" in html
