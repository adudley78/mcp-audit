"""One JSONC reader for every surface (2026-11 DRY/differential fix)."""

from __future__ import annotations

from mcp_audit.analyzers import config_hygiene
from mcp_audit.config_parser import strip_json_comments, strip_trailing_commas


def test_tasks_json_commas_inside_strings_survive() -> None:
    """The old regex pass turned "echo a,}" into "echo a}" before TRUST-003."""
    raw = '{"tasks": [{"command": "echo a,}", "args": ["x,]"],}], // c\n}'
    assert config_hygiene.parse_jsonc(raw) == {
        "tasks": [{"command": "echo a,}", "args": ["x,]"]}]
    }


def test_config_hygiene_has_no_private_jsonc_copy() -> None:
    assert not hasattr(config_hygiene, "_strip_jsonc_comments")
    assert not hasattr(config_hygiene, "_strip_trailing_commas")
    assert config_hygiene.strip_json_comments is strip_json_comments
    assert config_hygiene.strip_trailing_commas is strip_trailing_commas
