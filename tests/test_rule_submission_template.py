"""Pin the rule-submission issue template to the rule engine's vocabulary.

The template asks a submitter which config field a rule looks at and what
severity it should have. Both lists are copies of enums in the code
(``MatchField`` and ``Severity``); if either side changes without the other,
a submitter could pick an option no rule can express, or miss one that
exists. Same reasoning as ``test_registry_submission_template.py`` (R34).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from mcp_audit.models import Severity
from mcp_audit.rules.engine import MatchField

REPO_ROOT = Path(__file__).resolve().parent.parent
TEMPLATE_PATH = REPO_ROOT / ".github" / "ISSUE_TEMPLATE" / "rule-submission.yml"
NOT_SURE = "not sure"


def _template() -> dict[str, Any]:
    """Load the template YAML."""
    return yaml.safe_load(TEMPLATE_PATH.read_text(encoding="utf-8"))


def _field(field_id: str) -> dict[str, Any]:
    """Return the body element with the given id."""
    for element in _template()["body"]:
        if element.get("id") == field_id:
            return element
    raise AssertionError(f"template has no {field_id!r} field")


def _options(field_id: str) -> list[str]:
    """Return a dropdown's options without the 'not sure' escape hatch."""
    options = _field(field_id)["attributes"]["options"]
    return [opt for opt in options if opt != NOT_SURE]


def test_field_options_match_match_field_enum() -> None:
    assert _options("field") == [member.value for member in MatchField]


def test_severity_options_match_severity_enum() -> None:
    assert _options("severity") == [member.value for member in Severity]


def test_template_applies_the_rule_submission_label() -> None:
    assert _template()["labels"] == ["rule-submission"]


def test_source_and_both_examples_are_required() -> None:
    """A rule needs a citation (PROVENANCE.md) and a negative example."""
    for field_id in ("pattern", "source", "should_fire", "should_not_fire"):
        assert _field(field_id)["validations"]["required"] is True, field_id


def test_rule_yaml_is_optional() -> None:
    """Describing the pattern must be enough; writing YAML is not required."""
    assert _field("rule_yaml")["validations"]["required"] is False
