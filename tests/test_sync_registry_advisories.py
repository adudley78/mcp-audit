"""Tests for scripts/sync_registry_advisories.py (STORY-0083). No network."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location(
    "sync_registry_advisories", ROOT / "scripts" / "sync_registry_advisories.py"
)
assert _SPEC and _SPEC.loader
sync_mod = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(sync_mod)

WORKFLOW = ROOT / ".github" / "workflows" / "registry-advisory-sync.yml"


def _vuln(
    vid: str,
    *,
    aliases: list[str] | None = None,
    name: str = "acme-mcp",
    eco: str = "npm",
    events: list[list[dict]] | None = None,
    summary: str = "Bad thing",
    withdrawn: str | None = None,
) -> dict:
    ranges = [
        {"type": "SEMVER", "events": ev}
        for ev in (events or [[{"introduced": "0"}, {"fixed": "1.2.0"}]])
    ]
    rec: dict = {
        "id": vid,
        "aliases": aliases or [],
        "summary": summary,
        "affected": [{"package": {"name": name, "ecosystem": eco}, "ranges": ranges}],
    }
    if withdrawn:
        rec["withdrawn"] = withdrawn
    return rec


def _entry(**extra: object) -> dict:
    entry: dict = {"name": "acme-mcp", "source": "npm"}
    entry.update(extra)
    return entry


class TestFixedVersion:
    def test_single_fixed_range(self) -> None:
        assert sync_mod.fixed_version(_vuln("GHSA-1"), "acme-mcp", "npm") == "1.2.0"

    def test_highest_fix_across_ranges(self) -> None:
        v = _vuln(
            "GHSA-1",
            events=[
                [{"introduced": "0"}, {"fixed": "1.2.0"}],
                [{"introduced": "2.0.0"}, {"fixed": "2.0.5"}],
            ],
        )
        assert sync_mod.fixed_version(v, "acme-mcp", "npm") == "2.0.5"

    def test_open_ended_range_means_no_fix(self) -> None:
        v = _vuln("GHSA-1", events=[[{"introduced": "0"}]])
        assert sync_mod.fixed_version(v, "acme-mcp", "npm") is None

    def test_last_affected_range_is_bounded(self) -> None:
        """server-filesystem's shape: an old 0.6.x line that stopped, then a fix."""
        v = _vuln(
            "GHSA-1",
            events=[
                [{"introduced": "0"}, {"last_affected": "0.6.2"}],
                [{"introduced": "2025.1.14"}, {"fixed": "2025.7.1"}],
            ],
        )
        assert sync_mod.fixed_version(v, "acme-mcp", "npm") == "2025.7.1"

    def test_only_last_affected_has_no_known_fix(self) -> None:
        v = _vuln("GHSA-1", events=[[{"introduced": "0"}, {"last_affected": "1.0.0"}]])
        assert sync_mod.fixed_version(v, "acme-mcp", "npm") is None

    def test_other_packages_ranges_are_ignored(self) -> None:
        v = _vuln("GHSA-1", name="someone-else")
        assert sync_mod.fixed_version(v, "acme-mcp", "npm") is None

    def test_pypi_names_are_normalized(self) -> None:
        v = _vuln("PYSEC-1", name="Acme_MCP", eco="PyPI")
        assert sync_mod.fixed_version(v, "acme-mcp", "PyPI") == "1.2.0"


class TestMissingForEntry:
    def test_records_the_cve_alias(self) -> None:
        new, fills = sync_mod.missing_for_entry(
            _entry(), [_vuln("GHSA-aaaa", aliases=["CVE-2026-1"])]
        )
        assert fills == {}
        assert new == [
            {
                "cve": "CVE-2026-1",
                "cvss": None,
                "description": "Bad thing",
                "fixed_in": "1.2.0",
            }
        ]

    def test_ghsa_id_when_there_is_no_cve(self) -> None:
        new, _ = sync_mod.missing_for_entry(_entry(), [_vuln("GHSA-bbbb")])
        assert new[0]["cve"] == "GHSA-bbbb"

    def test_an_alias_already_listed_counts_as_present(self) -> None:
        entry = _entry(known_vulnerabilities=["GHSA-aaaa"])
        new, _ = sync_mod.missing_for_entry(
            entry, [_vuln("GHSA-aaaa", aliases=["CVE-2026-1"])]
        )
        assert new == []

    def test_withdrawn_and_malicious_records_are_skipped(self) -> None:
        new, _ = sync_mod.missing_for_entry(
            _entry(),
            [_vuln("GHSA-w", withdrawn="2026-01-01T00:00:00Z"), _vuln("MAL-2026-1")],
        )
        assert new == []

    def test_fills_a_missing_fixed_in_on_an_existing_record(self) -> None:
        entry = _entry(
            known_vulnerabilities=["CVE-2026-1"],
            known_vulns=[
                {
                    "cve": "CVE-2026-1",
                    "cvss": None,
                    "description": "x",
                    "fixed_in": None,
                }
            ],
        )
        new, fills = sync_mod.missing_for_entry(
            entry, [_vuln("GHSA-aaaa", aliases=["CVE-2026-1"])]
        )
        assert new == []
        assert fills == {"CVE-2026-1": "1.2.0"}

    def test_never_overwrites_a_recorded_fix(self) -> None:
        entry = _entry(
            known_vulns=[
                {
                    "cve": "CVE-2026-1",
                    "cvss": None,
                    "description": "x",
                    "fixed_in": "9.9.9",
                }
            ]
        )
        _, fills = sync_mod.missing_for_entry(
            entry, [_vuln("GHSA-aaaa", aliases=["CVE-2026-1"])]
        )
        assert fills == {}

    def test_long_summaries_are_truncated(self) -> None:
        new, _ = sync_mod.missing_for_entry(
            _entry(), [_vuln("GHSA-1", summary="x" * 500)]
        )
        assert len(new[0]["description"]) == 200


class TestSyncAndCli:
    def _registry(self, tmp_path: Path) -> Path:
        path = tmp_path / "known-servers.json"
        data = {
            "schema_version": "1.0",
            "last_updated": "2026-10-01",
            "entry_count": 2,
            "entries": [
                _entry(known_vulnerabilities=["CVE-2026-1"]),
                {"name": "other", "source": "pip"},
            ],
        }
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        return path

    @staticmethod
    def _fake_osv(name: str, ecosystem: str) -> list[dict]:
        if name == "acme-mcp":
            return [
                _vuln("GHSA-old", aliases=["CVE-2026-1"]),
                _vuln("GHSA-new", aliases=["CVE-2026-2"]),
            ]
        return []

    def test_check_reports_and_does_not_write(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = self._registry(tmp_path)
        before = path.read_bytes()
        monkeypatch.setattr(sync_mod, "query_osv", self._fake_osv)
        summary = tmp_path / "summary.md"
        out = tmp_path / "proposed.json"
        code = sync_mod.main(
            ["--registry", str(path), "--summary", str(summary), "--out", str(out)]
        )
        assert code == 1
        assert path.read_bytes() == before
        assert "CVE-2026-2" in summary.read_text(encoding="utf-8")
        proposed = json.loads(out.read_text(encoding="utf-8"))
        assert proposed["entries"][0]["known_vulnerabilities"] == [
            "CVE-2026-1",
            "CVE-2026-2",
        ]

    def test_write_then_check_is_clean(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = self._registry(tmp_path)
        monkeypatch.setattr(sync_mod, "query_osv", self._fake_osv)
        assert (
            sync_mod.main(["--registry", str(path), "--write", "--today", "2026-10-13"])
            == 0
        )
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["last_updated"] == "2026-10-13"
        assert data["entries"][0]["known_vulns"][0]["cve"] == "CVE-2026-2"
        assert path.read_text(encoding="utf-8").endswith("}\n")
        assert sync_mod.main(["--registry", str(path)]) == 0

    def test_osv_failure_is_exit_2(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = self._registry(tmp_path)

        def boom(name: str, ecosystem: str) -> list[dict]:
            raise RuntimeError("OSV unreachable")

        monkeypatch.setattr(sync_mod, "query_osv", boom)
        assert sync_mod.main(["--registry", str(path)]) == 2


class TestBundledRegistry:
    def test_bundled_registry_carries_the_story_examples(self) -> None:
        data = json.loads(
            (ROOT / "registry" / "known-servers.json").read_text(encoding="utf-8")
        )
        by_name = {e["name"]: e for e in data["entries"]}
        assert (
            "CVE-2025-49596"
            in by_name["@modelcontextprotocol/inspector"]["known_vulnerabilities"]
        )
        assert "CVE-2026-51996" in by_name["mcp-remote"]["known_vulnerabilities"]
        assert data["entry_count"] == len(data["entries"])


class TestWorkflow:
    def _load(self) -> dict:
        return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))

    def test_weekly_and_on_demand(self) -> None:
        wf = self._load()
        on = wf.get("on", wf.get(True))
        assert on["schedule"] == [{"cron": "0 10 * * 1"}]
        assert "workflow_dispatch" in on

    def test_read_only(self) -> None:
        wf = self._load()
        text = WORKFLOW.read_text(encoding="utf-8")
        assert wf["permissions"] == {"contents": "read"}
        runs = [
            step.get("run", "") for job in wf["jobs"].values() for step in job["steps"]
        ]
        assert any("sync_registry_advisories.py --check" in r for r in runs)
        assert not any("--write" in r for r in runs)
        assert "gh pr" not in text
        assert "git push" not in text
