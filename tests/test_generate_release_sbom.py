"""Release-artifact SBOMs (scripts/generate_release_sbom.py).

These documents are not ``mcp-audit sbom`` output. They inventory the
PyInstaller PYZ or a wheel install.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import jsonschema
import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import generate_release_sbom as sbom  # noqa: E402

SCHEMA = ROOT / "tests" / "fixtures" / "cyclonedx-1.5.schema.json"


def test_pep503_normalizes_pillow() -> None:
    assert sbom.pep503("Pillow") == "pillow"
    assert sbom.pep503("mcp_audit_scanner") == "mcp-audit-scanner"


def test_pyz_mapping_keeps_only_frozen_distributions() -> None:
    pyz = {"PIL.Image", "reportlab.pdfgen", "pydantic.main", "json", "os"}
    module_to_dists = {
        "PIL": ["pillow"],
        "reportlab": ["reportlab"],
        "pydantic": ["pydantic"],
        "sigstore": ["sigstore"],
        "mcp": ["mcp"],
    }
    versions = {
        "pillow": "12.3.0",
        "reportlab": "4.5.1",
        "pydantic": "2.11.0",
        "sigstore": "4.2.0",
        "mcp": "1.9.0",
    }
    found = sbom.distributions_from_pyz(pyz, module_to_dists, versions.__getitem__)
    assert found == {
        "pillow": "12.3.0",
        "pydantic": "2.11.0",
        "reportlab": "4.5.1",
    }
    assert "sigstore" not in found
    assert "mcp" not in found


def test_bom_schema_and_required_packages(tmp_path: Path) -> None:
    packages = {
        "pillow": "12.3.0",
        "reportlab": "4.5.1",
        "pydantic": "2.11.0",
    }
    doc = sbom.build_bom(
        packages=packages,
        app_name="mcp-audit-linux-x86_64",
        app_version="0.15.0",
        covers="pyinstaller-pyz",
        timestamp="2026-08-22T00:00:00Z",
    )
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    jsonschema.validate(doc, schema)
    text = sbom.bom_json(doc)
    assert sbom.find_path_leaks(text) == []
    assert "site-packages" not in text
    assert "/Users/" not in text
    assert sbom.require_packages(packages, ("pillow", "reportlab")) == []
    names = {c["name"] for c in doc["components"]}
    assert names == {"pillow", "reportlab", "pydantic"}
    assert doc["metadata"]["component"]["properties"][0]["value"] == "pyinstaller-pyz"


def test_require_packages_reports_missing() -> None:
    missing = sbom.require_packages({"pydantic": "2.0"}, ("pillow", "reportlab"))
    assert missing and "pillow" in missing[0] and "reportlab" in missing[0]


def test_path_leak_detector_catches_unix_and_windows() -> None:
    assert sbom.find_path_leaks('{"x": "/Users/MacBookAir/Projects/foo"}')
    assert sbom.find_path_leaks('{"x": "C:\\\\Users\\\\runner\\\\work"}')
    assert sbom.find_path_leaks('{"p": "/opt/hostedtoolcache/Python/3.12"}')
    home_site = "/home/runner/work/.venv/lib/python3.12/site-packages/rich"
    assert sbom.find_path_leaks(home_site)
    assert sbom.find_path_leaks('{"name": "pillow", "version": "12.3.0"}') == []


def test_from_environment_filename_must_say_wheel(tmp_path: Path) -> None:
    bad = tmp_path / "sbom.json"
    rc = sbom.main(
        [
            "--from-environment",
            "--output",
            str(bad),
        ]
    )
    assert rc == 2
    assert not bad.exists()


def test_from_environment_writes_wheel_named_file(tmp_path: Path) -> None:
    out = tmp_path / "mcp-audit-scanner-wheel.cdx.json"
    rc = sbom.main(
        [
            "--from-environment",
            "--name",
            "mcp-audit-scanner",
            "--output",
            str(out),
            "--schema",
            str(SCHEMA),
            "--require",
            "pydantic",
        ]
    )
    assert rc == 0
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["metadata"]["component"]["properties"][0]["value"] == "wheel-install"
    names = {c["name"] for c in doc["components"]}
    assert "pydantic" in names
    assert sbom.find_path_leaks(out.read_text(encoding="utf-8")) == []


@pytest.mark.skipif(
    not (ROOT / "dist" / "mcp-audit-darwin-x86_64").is_file(),
    reason="no local frozen binary",
)
def test_binary_mode_against_local_archive(tmp_path: Path) -> None:
    out = tmp_path / "mcp-audit-darwin-x86_64.cdx.json"
    rc = sbom.main(
        [
            "--binary",
            str(ROOT / "dist" / "mcp-audit-darwin-x86_64"),
            "--target",
            "darwin-x86_64",
            "--output",
            str(out),
            "--schema",
            str(SCHEMA),
            "--require",
            "pillow,reportlab",
        ]
    )
    assert rc == 0
    doc = json.loads(out.read_text(encoding="utf-8"))
    names = {c["name"] for c in doc["components"]}
    assert "pillow" in names
    assert "reportlab" in names
    assert "mcp" not in names
    assert "sigstore" not in names
    assert doc["metadata"]["component"]["properties"][0]["value"] == "pyinstaller-pyz"
