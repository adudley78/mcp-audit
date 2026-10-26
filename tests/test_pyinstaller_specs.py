"""Guards on the four PyInstaller spec files.

Release builds with ``uv sync --all-extras``, so anything *not* in
``excludes=`` is frozen into the artifact users download.  These checks
pin the product decision that the ``[mcp]`` and ``[attestation]`` extras
are pip-install-only.
"""

from __future__ import annotations

from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_SPECS = [
    _ROOT / "mcp-audit-darwin-arm64.spec",
    _ROOT / "mcp-audit-darwin-x86_64.spec",
    _ROOT / "mcp-audit-linux-x86_64.spec",
    _ROOT / "mcp-audit-windows-x86_64.spec",
]

# Must stay out of the binary.  Adding a module here without adding it to
# every spec's excludes= will fail CI rather than silently shipping it.
_EXCLUDED_EXTRAS = (
    "sigstore",
    "mcp",
    "starlette",
    "python_multipart",
    "pydantic_settings",
    "httpx",
    "cyclonedx",
)


def test_all_four_specs_exist() -> None:
    missing = [p.name for p in _SPECS if not p.is_file()]
    assert missing == [], f"missing spec files: {missing}"


def test_optional_extras_are_excluded_from_every_spec() -> None:
    for spec in _SPECS:
        text = spec.read_text(encoding="utf-8")
        for name in _EXCLUDED_EXTRAS:
            assert f"'{name}'" in text, f"{spec.name} does not exclude {name!r}"


# STORY-0097: SC-008 and `vet` read registry/known-malicious.json offline, so
# every distribution must carry it.  A missing file would not crash a scan
# (the loader reports it in ScanResult.errors), it would leave SC-008 blind.
_BUNDLED_REGISTRY_FILES = (
    "registry/known-servers.json",
    "registry/known-extension-vulns.json",
    "registry/known-malicious.json",
)


def test_every_spec_bundles_the_registry_data_files() -> None:
    for spec in _SPECS:
        text = spec.read_text(encoding="utf-8")
        for rel in _BUNDLED_REGISTRY_FILES:
            assert f"(os.path.join(root, '{rel}'), 'registry')" in text, (
                f"{spec.name} does not bundle {rel}"
            )


def test_wheel_force_includes_the_registry_data_files() -> None:
    import tomllib

    pyproject = tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    force = pyproject["tool"]["hatch"]["build"]["targets"]["wheel"]["force-include"]
    for rel in _BUNDLED_REGISTRY_FILES:
        assert force.get(rel) == f"mcp_audit/{rel}", rel
        assert (_ROOT / rel).is_file(), rel
