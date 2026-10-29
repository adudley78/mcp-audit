"""STORY-0128: LiteLLM's MCP gateway in the registry (CVE-2026-59822, MAL-2026-2144)."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from mcp_audit.cli import app

REPO = Path(__file__).resolve().parent.parent
runner = CliRunner()

# The shapes that reach LiteLLM's MCP gateway from a discovered MCP config:
# the gateway launched as a package (floating, pinned old, pinned malicious),
# and a client pointed at a gateway somebody else runs (a URL).
CONFIG = {
    "mcpServers": {
        "gateway-local": {
            "command": "uvx",
            "args": ["litellm[proxy]==1.83.0", "--port", "4000"],
        },
        "gateway-fixed": {"command": "uvx", "args": ["litellm[proxy]==1.106.6"]},
        "gateway-bad": {"command": "uvx", "args": ["litellm==1.107.0"]},
        "gateway-remote": {"url": "http://litellm.internal:4000/mcp"},
    }
}


def _entry() -> dict:
    data = json.loads((REPO / "registry" / "known-servers.json").read_text())
    return next(e for e in data["entries"] if e["name"] == "litellm")


def _affected(tmp_path: Path, query: str) -> dict[str, dict]:
    cfg = tmp_path / "mcp.json"
    cfg.write_text(json.dumps(CONFIG))
    result = runner.invoke(
        app, ["affected", query, "-p", str(cfg), "--all", "-f", "json"]
    )
    assert result.exit_code in (0, 1), result.output
    return {
        r["subject"].split("/")[-1]: r for r in json.loads(result.output)["results"]
    }


class TestRegistryEntry:
    def test_entry_is_unverified_pypi_gateway(self) -> None:
        e = _entry()
        assert e["verified"] is False
        assert e["package_ecosystem"] == "pypi"
        assert e["repo"] == "https://github.com/BerriAI/litellm"
        assert "gateway" in e["tags"]

    def test_gateway_cve_has_its_fix(self) -> None:
        rec = next(v for v in _entry()["known_vulns"] if v["cve"] == "CVE-2026-59822")
        assert rec["fixed_in"] == "1.84.0"
        assert "CVE-2026-59822" in _entry()["known_vulnerabilities"]

    def test_malware_advisories_are_not_recorded_as_vulnerabilities(self) -> None:
        # A fix-less record would flag every litellm version; the compromise is
        # matched by exact version through known-malicious.json instead.
        ids = {v["cve"] for v in _entry()["known_vulns"]} | set(
            _entry()["known_vulnerabilities"]
        )
        assert not ids & {"GHSA-5mg7-485q-xm76", "PYSEC-2026-2"}

    def test_malicious_mirror_lists_the_compromised_versions(self) -> None:
        data = json.loads((REPO / "registry" / "known-malicious.json").read_text())
        rec = next(e for e in data["entries"] if e["id"] == "MAL-2026-2144")
        assert rec["name"] == "litellm" and rec["ecosystem"] == "PyPI"
        assert {"1.82.7", "1.82.8", "1.107.0"} <= set(rec["versions"])


class TestConfigShapes:
    def test_old_pin_is_affected_fixed_pin_is_not(self, tmp_path: Path) -> None:
        rows = _affected(tmp_path, "CVE-2026-59822")
        assert rows["gateway-local"]["status"] == "AFFECTED"
        assert rows["gateway-local"]["fixed_in"] == "1.84.0"
        assert rows["gateway-fixed"]["status"] == "NOT AFFECTED"

    def test_remote_gateway_url_is_couldnt_check_never_clean(
        self, tmp_path: Path
    ) -> None:
        rows = _affected(tmp_path, "CVE-2026-59822")
        assert rows["gateway-remote"]["status"] == "COULDN'T CHECK"

    def test_compromised_release_is_caught_by_version_only(
        self, tmp_path: Path
    ) -> None:
        rows = _affected(tmp_path, "MAL-2026-2144")
        assert rows["gateway-bad"]["status"] == "AFFECTED"
        assert rows["gateway-local"]["status"] == "NOT AFFECTED"
        assert rows["gateway-fixed"]["status"] == "NOT AFFECTED"
