"""Pin the 1:1 mapping between the registry-submission issue template's
capability checkboxes and ``mcp_audit.analyzers.toxic_flow.Capability``.

R34 fixed a real defect: the template offered checkboxes ("Persist data
across sessions (memory)", "Execute code", "Access cloud resources") that
could not be recorded because no matching ``Capability`` enum value existed,
and omitted a checkbox for ``git`` even though that value did exist. A
submitter who checked one of the unrepresentable boxes had disclosed
something the registry silently dropped — nobody told, nobody informed. This
is exactly the class of bug that produced the R33 comment correction on
issue #35 (docpull): a checkbox/vocabulary mismatch that under-declared what
a package's own source actually reveals.

This test does not re-litigate wording; it pins the structural invariant so
a future edit to either side (template or enum) cannot silently reintroduce
the mismatch: every checkbox must map to a real Capability, and every real
Capability must be reachable via some checkbox.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from mcp_audit.analyzers.toxic_flow import Capability

REPO_ROOT = Path(__file__).resolve().parent.parent
TEMPLATE_PATH = REPO_ROOT / ".github" / "ISSUE_TEMPLATE" / "registry-submission.yml"

# The canonical label -> Capability mapping this template is built against.
# Keep in sync with the template's `capabilities` checkboxes field by hand —
# that's the point: a change to either side without updating this mapping
# fails the bijection tests below.
LABEL_TO_CAPABILITY: dict[str, Capability] = {
    "Read files on the user's machine": Capability.FILE_READ,
    "Write or modify files on the user's machine": Capability.FILE_WRITE,
    "Execute shell commands or run arbitrary code": Capability.SHELL_EXEC,
    "Make network requests or fetch content from the internet": Capability.NETWORK_OUT,
    "Query databases": Capability.DATABASE,
    "Handle credentials or secrets": Capability.SECRETS,
    "Send or read email": Capability.EMAIL,
    "Control a web browser": Capability.BROWSER,
    "Access git repositories or version history": Capability.GIT,
    "Access cloud resources (AWS, GCP, Azure, etc.)": Capability.CLOUD,
}


def _capability_checkbox_labels() -> list[str]:
    """Extract the `capabilities` field's checkbox labels from the template."""
    data = yaml.safe_load(TEMPLATE_PATH.read_text(encoding="utf-8"))
    for field in data["body"]:
        if field.get("id") == "capabilities":
            return [opt["label"] for opt in field["attributes"]["options"]]
    raise AssertionError("template has no 'capabilities' checkboxes field")


class TestTemplateCapabilityBijection:
    def test_every_checkbox_maps_to_a_known_capability(self) -> None:
        labels = _capability_checkbox_labels()
        unmapped = [label for label in labels if label not in LABEL_TO_CAPABILITY]
        assert not unmapped, (
            f"Checkbox(es) with no Capability mapping: {unmapped}. Every "
            "checkbox must map to a recordable capability — see R34."
        )

    def test_every_template_label_still_exists_in_template(self) -> None:
        """Catches the mapping going stale if a label is reworded."""
        labels = set(_capability_checkbox_labels())
        stale = [label for label in LABEL_TO_CAPABILITY if label not in labels]
        assert not stale, f"Mapping references removed/renamed labels: {stale}"

    def test_every_capability_is_reachable_from_some_checkbox(self) -> None:
        mapped_caps = set(LABEL_TO_CAPABILITY.values())
        all_caps = set(Capability)
        missing = all_caps - mapped_caps
        assert not missing, (
            f"Capability value(s) with no submittable checkbox: {missing}. "
            "Every enum value must be submittable — see R34."
        )

    def test_no_unrepresentable_legacy_checkboxes(self) -> None:
        """Pins the specific R34 regression: none of the three checkboxes
        that could not be recorded (because no Capability existed for them)
        may reappear without a corresponding enum addition."""
        labels = _capability_checkbox_labels()
        assert "Persist data across sessions (memory)" not in labels
        assert "Execute code" not in labels

    def test_description_states_source_derived_precedence(self) -> None:
        """The description must say what we actually do (derive from source
        and docs) rather than implying verification only happens when the
        submitter leaves the checklist blank."""
        data = yaml.safe_load(TEMPLATE_PATH.read_text(encoding="utf-8"))
        for field in data["body"]:
            if field.get("id") == "capabilities":
                description = field["attributes"]["description"]
                break
        else:
            raise AssertionError("template has no 'capabilities' checkboxes field")
        assert "starting point" in description.lower()
        assert "derived from the package" in description.lower()
