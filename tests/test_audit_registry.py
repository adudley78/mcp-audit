"""Tests for scripts/audit_registry.py (provenance check + opt-in stamp)."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import audit_registry as mod  # noqa: E402


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(mod, "_sleep", lambda *_a, **_k: None)


def _entry(
    name: str,
    *,
    repo: str | None = "https://github.com/example/repo",
    attestation_expected: bool = False,
    last_verified: str = "2026-04-15",
    source: str = "npm",
) -> dict[str, Any]:
    return {
        "name": name,
        "source": source,
        "repo": repo,
        "maintainer": "Example",
        "verified": True,
        "last_verified": last_verified,
        "attestation_expected": attestation_expected,
    }


def _registry(tmp_path: Path, entries: list[dict]) -> Path:
    path = tmp_path / "known-servers.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "last_updated": "2026-04-15",
                "entry_count": len(entries),
                "entries": entries,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return path


class TestNpmProvenance:
    def test_has_provenance_from_dist_attestations(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def fail_get(_url: str, timeout: int = 15) -> tuple[int, Any]:
            raise AssertionError("attestations API must not be called")

        monkeypatch.setattr(mod, "_get_json", fail_get)
        status, detail = mod.check_npm_provenance(
            "pkg",
            "1.0.0",
            {"provenance": {"predicateType": "https://slsa.dev/provenance/v1"}},
        )
        assert status == "HAS_PROVENANCE"
        assert "dist.attestations" in detail

    def test_no_provenance_on_api_404(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(mod, "_get_json", lambda *_a, **_k: (404, None))
        status, detail = mod.check_npm_provenance("pkg", "1.0.0", None)
        assert status == "NO_PROVENANCE"
        assert "404" in detail

    def test_publish_only_attestation_is_no_provenance(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """npm publish attestation without SLSA is not enough to keep the flag."""
        monkeypatch.setattr(
            mod,
            "_get_json",
            lambda *_a, **_k: (
                200,
                {
                    "attestations": [
                        {
                            "predicateType": (
                                "https://github.com/npm/attestation/publish/v0.1"
                            )
                        }
                    ]
                },
            ),
        )
        status, _detail = mod.check_npm_provenance("pkg", "1.0.0", None)
        assert status == "NO_PROVENANCE"

    def test_api_slsa_is_has_provenance(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            mod,
            "_get_json",
            lambda *_a, **_k: (
                200,
                {"attestations": [{"predicateType": "https://slsa.dev/provenance/v1"}]},
            ),
        )
        status, _detail = mod.check_npm_provenance("pkg", "1.0.0", None)
        assert status == "HAS_PROVENANCE"


class TestPypiProvenance:
    def test_has_from_integrity_200(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            mod,
            "_get_json",
            lambda *_a, **_k: (
                200,
                {"attestation_bundles": [{"attestations": [{"dsse": {}}]}]},
            ),
        )
        status, detail = mod.check_pypi_provenance(
            "mcp", "2.0.0", ["mcp-2.0.0.tar.gz", "mcp-2.0.0-py3-none-any.whl"]
        )
        assert status == "HAS_PROVENANCE"
        assert "whl" in detail

    def test_unchecked_on_network_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(mod, "_get_json", lambda *_a, **_k: (-1, None))
        status, detail = mod.check_pypi_provenance(
            "mcp", "2.0.0", ["mcp-2.0.0-py3-none-any.whl"]
        )
        assert status == "UNCHECKED"
        assert "http_-1" in detail

    def test_json_api_absence_is_not_used(self) -> None:
        """The JSON project API is never the provenance predicate."""
        src = Path(mod.__file__).read_text(encoding="utf-8")
        assert "pypi.org/integrity/" in src
        # Bias: we query integrity even though urls[].provenance is always null.
        assert "does not expose a ``provenance`` field" in src


class TestApplyStamp:
    def test_stamps_only_ok_dates(self, tmp_path: Path) -> None:
        path = _registry(
            tmp_path,
            [
                _entry("ok-pkg", last_verified="2026-04-15"),
                _entry("thin-pkg", last_verified="2026-04-15"),
            ],
        )
        results = [
            {"name": "ok-pkg", "bucket": "OK", "provenance": "NOT_CHECKED"},
            {"name": "thin-pkg", "bucket": "THIN", "provenance": "NOT_CHECKED"},
        ]
        stats = mod.apply_stamp(path, results, "2026-08-22")
        data = json.loads(path.read_text(encoding="utf-8"))
        by_name = {e["name"]: e for e in data["entries"]}
        assert by_name["ok-pkg"]["last_verified"] == "2026-08-22"
        assert by_name["thin-pkg"]["last_verified"] == "2026-04-15"
        assert stats["stamped"] == ["ok-pkg"]
        assert stats["skipped_non_ok"] == ["thin-pkg"]
        assert data["last_updated"] == "2026-08-22"

    def test_clears_no_provenance(self, tmp_path: Path) -> None:
        path = _registry(
            tmp_path,
            [_entry("no-prov", attestation_expected=True)],
        )
        results = [
            {
                "name": "no-prov",
                "bucket": "OK",
                "provenance": "NO_PROVENANCE",
            }
        ]
        stats = mod.apply_stamp(path, results, "2026-08-22")
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["entries"][0]["attestation_expected"] is False
        assert stats["cleared"] == ["no-prov"]

    def test_keeps_has_provenance(self, tmp_path: Path) -> None:
        path = _registry(
            tmp_path,
            [_entry("has-prov", attestation_expected=True)],
        )
        results = [
            {
                "name": "has-prov",
                "bucket": "OK",
                "provenance": "HAS_PROVENANCE",
            }
        ]
        stats = mod.apply_stamp(path, results, "2026-08-22")
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["entries"][0]["attestation_expected"] is True
        assert stats["kept"] == ["has-prov"]

    def test_leaves_unchecked(self, tmp_path: Path) -> None:
        path = _registry(
            tmp_path,
            [_entry("maybe", attestation_expected=True)],
        )
        results = [{"name": "maybe", "bucket": "OK", "provenance": "UNCHECKED"}]
        stats = mod.apply_stamp(path, results, "2026-08-22")
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["entries"][0]["attestation_expected"] is True
        assert stats["unchecked"] == ["maybe"]

    def test_never_sets_attestation_expected_true(self, tmp_path: Path) -> None:
        path = _registry(
            tmp_path,
            [_entry("plain", attestation_expected=False)],
        )
        results = [
            {
                "name": "plain",
                "bucket": "OK",
                "provenance": "HAS_PROVENANCE",
            }
        ]
        mod.apply_stamp(path, results, "2026-08-22")
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["entries"][0]["attestation_expected"] is False

    def test_does_not_stamp_unverified_bucket(self, tmp_path: Path) -> None:
        path = _registry(tmp_path, [_entry("gone")])
        results = [{"name": "gone", "bucket": "MISSING", "provenance": "NOT_CHECKED"}]
        mod.apply_stamp(path, results, "2026-08-22")
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["entries"][0]["last_verified"] == "2026-04-15"


class TestDefaultIsReadOnly:
    def test_main_without_stamp_does_not_write(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = _registry(tmp_path, [_entry("ok-pkg")])
        original = path.read_text(encoding="utf-8")
        out = tmp_path / "out.json"
        cache = tmp_path / "cache.json"
        monkeypatch.setattr(
            mod,
            "audit_registry",
            lambda *_a, **_k: [
                {
                    "name": "ok-pkg",
                    "bucket": "OK",
                    "provenance": "NOT_CHECKED",
                    "declared_attestation_expected": False,
                }
            ],
        )
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "audit_registry.py",
                "--registry",
                str(path),
                "--out",
                str(out),
                "--cache",
                str(cache),
            ],
        )
        mod.main()
        assert path.read_text(encoding="utf-8") == original
        assert out.is_file()
