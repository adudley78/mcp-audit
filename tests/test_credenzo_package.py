"""The `credenzo` package on PyPI must track the release exactly.

`packaging/credenzo/` holds no code: it pins mcp-audit-scanner and declares
the `credenzo` command. If its version or pin differs from the root version,
`pip install credenzo` installs a different release than the one its own
version number names.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _load(path: Path) -> dict:
    with path.open("rb") as fh:
        return tomllib.load(fh)["project"]


def test_version_and_pin_equal_the_release_version() -> None:
    root = _load(ROOT / "pyproject.toml")
    meta = _load(ROOT / "packaging" / "credenzo" / "pyproject.toml")
    assert meta["version"] == root["version"]
    assert meta["dependencies"] == [f"mcp-audit-scanner=={root['version']}"]


def test_every_user_extra_is_forwarded_at_the_same_pin() -> None:
    root = _load(ROOT / "pyproject.toml")
    meta = _load(ROOT / "packaging" / "credenzo" / "pyproject.toml")
    expected = {
        name: [f"mcp-audit-scanner[{name}]=={root['version']}"]
        for name in root["optional-dependencies"]
        if name != "dev"
    }
    assert meta["optional-dependencies"] == expected


def test_the_command_is_the_same_entry_point() -> None:
    root = _load(ROOT / "pyproject.toml")
    meta = _load(ROOT / "packaging" / "credenzo" / "pyproject.toml")
    assert meta["scripts"] == {"credenzo": root["scripts"]["credenzo"]}
    assert root["scripts"]["mcp-audit"] == root["scripts"]["credenzo"]
