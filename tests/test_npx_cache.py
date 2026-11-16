"""Tests for SC-011: known-malicious packages in the npx cache (STORY-0158)."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

from mcp_audit.analyzers import npx_cache
from mcp_audit.analyzers.npx_cache import (
    iter_cached_packages,
    npm_cache_dir,
    npx_cache_findings,
)
from mcp_audit.models import Severity
from mcp_audit.registry.malicious import KnownMaliciousPackages, MaliciousRecord


def _index() -> KnownMaliciousPackages:
    return KnownMaliciousPackages(
        records=[
            MaliciousRecord(
                id="MAL-2026-18192",
                ecosystem="npm",
                name="agentic-awesome-skills",
                summary="Malicious code in agentic-awesome-skills (npm)",
                ranges=((("introduced", "0"),),),
            ),
            MaliciousRecord(
                id="MAL-2026-90001",
                ecosystem="npm",
                name="@evil/skills",
                versions=("1.0.1",),
            ),
            MaliciousRecord(
                id="MAL-2026-90002",
                ecosystem="pypi",
                name="same-name",
                versions=("1.0.0",),
            ),
        ]
    )


def _install(
    cache: Path, digest: str, name: str, version: str, *, body: str | None = None
) -> Path:
    package_dir = cache / "_npx" / digest / "node_modules" / name
    package_dir.mkdir(parents=True, exist_ok=True)
    manifest = package_dir / "package.json"
    manifest.write_text(
        body
        if body is not None
        else json.dumps({"name": name, "version": version, "bin": "x.js"}),
        encoding="utf-8",
    )
    return manifest


def test_cache_dir_env_override_any_case(tmp_path: Path) -> None:
    assert npm_cache_dir({"NPM_CONFIG_CACHE": str(tmp_path)}, tmp_path / "h") == (
        tmp_path
    )
    assert npm_cache_dir({"npm_config_cache": str(tmp_path)}, tmp_path / "h") == (
        tmp_path
    )


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX default")
def test_cache_dir_posix_default(tmp_path: Path) -> None:
    assert npm_cache_dir({}, tmp_path) == tmp_path / ".npm"


def test_cache_dir_windows_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(npx_cache.sys, "platform", "win32")
    local = tmp_path / "Local"
    assert npm_cache_dir({"LOCALAPPDATA": str(local)}, tmp_path) == local / "npm-cache"


def test_malicious_package_fires_critical(tmp_path: Path) -> None:
    manifest = _install(tmp_path, "a1b2", "agentic-awesome-skills", "2.3.0")
    errors: list[str] = []
    findings = npx_cache_findings(errors, cache_dir=tmp_path, malicious=_index())
    assert errors == []
    assert len(findings) == 1
    f = findings[0]
    assert f.id == "SC-011"
    assert f.severity is Severity.CRITICAL
    assert f.client == "npx-cache"
    assert f.server == "agentic-awesome-skills"
    assert "MAL-2026-18192" in f.title
    assert "version: 2.3.0" in f.evidence
    assert f.finding_path == str(manifest)
    assert f.owasp_mcp_top_10 == ["MCP04"]


def test_scoped_package_listed_version_fires(tmp_path: Path) -> None:
    _install(tmp_path, "c3d4", "@evil/skills", "1.0.1")
    findings = npx_cache_findings([], cache_dir=tmp_path, malicious=_index())
    assert [f.server for f in findings] == ["@evil/skills"]


def test_unlisted_version_does_not_fire(tmp_path: Path) -> None:
    _install(tmp_path, "c3d4", "@evil/skills", "1.0.2")
    assert npx_cache_findings([], cache_dir=tmp_path, malicious=_index()) == []


def test_unknown_name_and_other_ecosystem_do_not_fire(tmp_path: Path) -> None:
    _install(tmp_path, "e5f6", "agentic-awesome-skills-docs", "1.0.0")
    _install(tmp_path, "e5f6", "same-name", "1.0.0")  # record is PyPI only
    assert npx_cache_findings([], cache_dir=tmp_path, malicious=_index()) == []


def test_name_is_read_from_manifest_not_directory(tmp_path: Path) -> None:
    # The finding follows the package's own name field.
    _install(
        tmp_path,
        "f7a8",
        "renamed-dir",
        "",
        body=json.dumps({"name": "agentic-awesome-skills", "version": "1.0.0"}),
    )
    findings = npx_cache_findings([], cache_dir=tmp_path, malicious=_index())
    assert [f.server for f in findings] == ["agentic-awesome-skills"]


def test_same_package_in_two_installs_reported_once(tmp_path: Path) -> None:
    _install(tmp_path, "aaaa", "agentic-awesome-skills", "1.0.0")
    _install(tmp_path, "bbbb", "agentic-awesome-skills", "1.0.0")
    _install(tmp_path, "cccc", "agentic-awesome-skills", "1.1.0")
    findings = npx_cache_findings([], cache_dir=tmp_path, malicious=_index())
    assert sorted(f.evidence.split(" | ")[1] for f in findings) == [
        "version: 1.0.0",
        "version: 1.1.0",
    ]


def test_dependency_in_cache_fires(tmp_path: Path) -> None:
    # npx installs dependencies flat beside the package it ran.
    _install(tmp_path, "dddd", "harmless-cli", "1.0.0")
    _install(tmp_path, "dddd", "agentic-awesome-skills", "1.0.0")
    findings = npx_cache_findings([], cache_dir=tmp_path, malicious=_index())
    assert [f.server for f in findings] == ["agentic-awesome-skills"]


@pytest.mark.parametrize(
    "body",
    [
        "not json",
        json.dumps(["agentic-awesome-skills"]),
        json.dumps({"name": "agentic-awesome-skills"}),
        json.dumps({"name": 1, "version": "1.0.0"}),
        json.dumps({"name": "agentic-awesome-skills", "version": "1.0.0"})
        + " " * (70 * 1024),
    ],
)
def test_bad_manifests_are_skipped(tmp_path: Path, body: str) -> None:
    _install(tmp_path, "eeee", "agentic-awesome-skills", "", body=body)
    errors: list[str] = []
    assert npx_cache_findings(errors, cache_dir=tmp_path, malicious=_index()) == []
    assert errors == []


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="needs symlinks")
def test_symlinks_are_not_followed(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    real = _install(outside, "ffff", "agentic-awesome-skills", "1.0.0")
    cache = tmp_path / "cache"
    modules = cache / "_npx" / "1111" / "node_modules"
    modules.mkdir(parents=True)
    # A symlinked package directory and a symlinked package.json.
    (modules / "agentic-awesome-skills").symlink_to(real.parent)
    other = modules / "linked-manifest"
    other.mkdir()
    (other / "package.json").symlink_to(real)
    # A symlinked install directory.
    (cache / "_npx" / "2222").symlink_to(outside / "_npx" / "ffff")
    assert npx_cache_findings([], cache_dir=cache, malicious=_index()) == []


def test_no_cache_is_silent(tmp_path: Path) -> None:
    errors: list[str] = []
    assert (
        npx_cache_findings(errors, cache_dir=tmp_path / "missing", malicious=_index())
        == []
    )
    assert errors == []


def test_empty_index_reads_nothing(tmp_path: Path) -> None:
    _install(tmp_path, "a1b2", "agentic-awesome-skills", "1.0.0")
    assert (
        npx_cache_findings([], cache_dir=tmp_path, malicious=KnownMaliciousPackages())
        == []
    )


def test_package_budget_is_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(npx_cache, "MAX_PACKAGES", 2)
    for name in ("a-pkg", "b-pkg", "c-pkg"):
        _install(tmp_path, "9999", name, "1.0.0")
    errors: list[str] = []
    packages = list(iter_cached_packages(tmp_path, errors))
    assert [p.name for p in packages] == ["a-pkg", "b-pkg"]
    assert errors == ["npx cache: stopped after 2 packages"]


def test_install_dir_budget_is_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(npx_cache, "MAX_INSTALL_DIRS", 1)
    _install(tmp_path, "0001", "a-pkg", "1.0.0")
    _install(tmp_path, "0002", "b-pkg", "1.0.0")
    errors: list[str] = []
    assert [p.name for p in iter_cached_packages(tmp_path, errors)] == ["a-pkg"]
    assert "only the first 1 were read" in errors[0]


def test_never_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*args: object, **kwargs: object) -> None:
        raise RuntimeError("x")

    monkeypatch.setattr(npx_cache, "iter_cached_packages", boom)
    errors: list[str] = []
    assert npx_cache_findings(errors, cache_dir=tmp_path, malicious=_index()) == []
    assert errors == ["npx cache: check failed: RuntimeError"]


def test_shipped_mirror_matches_known_skill_collection(tmp_path: Path) -> None:
    # The bundled mirror carries MAL-2026-18192 (STORY-0152); 19.0.1 is listed.
    _install(tmp_path, "a1b2", "agentic-awesome-skills", "19.0.1")
    findings = npx_cache_findings([], cache_dir=tmp_path)
    assert [f.id for f in findings] == ["SC-011"]
    assert "MAL-2026-18192" in findings[0].title


def test_default_scan_reports_sc011(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from mcp_audit.scanner import run_scan

    cache = tmp_path / "npm"
    _install(cache, "a1b2", "agentic-awesome-skills", "19.0.1")
    monkeypatch.setattr(
        "mcp_audit.analyzers.npx_cache.npm_cache_dir",
        lambda environ=None, home=None: cache,
    )
    result = run_scan()
    assert "SC-011" in {f.id for f in result.findings}


def test_explicit_path_scan_skips_cache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from mcp_audit.scanner import run_scan

    cache = tmp_path / "npm"
    _install(cache, "a1b2", "agentic-awesome-skills", "19.0.1")
    monkeypatch.setattr(
        "mcp_audit.analyzers.npx_cache.npm_cache_dir",
        lambda environ=None, home=None: cache,
    )
    config = tmp_path / "mcp.json"
    config.write_text(json.dumps({"mcpServers": {}}), encoding="utf-8")
    result = run_scan(extra_paths=[config])
    assert "SC-011" not in {f.id for f in result.findings}
