"""Policy-as-code rule engine for mcp-audit.

Loads YAML rule files and evaluates them against MCP server configurations,
producing standard Finding objects that flow through all output formatters.

Bundled rules live under ``rules/community/``; additional rule directories
can be supplied via ``--rules-dir`` or dropped into
``<user-config-dir>/mcp-audit/rules/``. No license or flag gating.
"""

from __future__ import annotations

import fnmatch
import logging
import re
from enum import StrEnum
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, model_validator

from mcp_audit.models import Finding, ServerConfig, Severity
from mcp_audit.registry.loader import KnownServerRegistry

logger = logging.getLogger(__name__)

# ── Enums ──────────────────────────────────────────────────────────────────────


class MatchType(StrEnum):
    """How a pattern is applied against a field value."""

    REGEX = "regex"
    EXACT = "exact"
    CONTAINS = "contains"
    GLOB = "glob"
    SEMVER_RANGE = "semver_range"


class MatchField(StrEnum):
    """Which part of a ServerConfig is extracted for matching."""

    COMMAND = "command"
    ARGS = "args"
    ENV = "env"
    SERVER_NAME = "server_name"
    URL = "url"
    TRANSPORT = "transport"


class CompoundOperator(StrEnum):
    """Logical operator for compound match rules."""

    AND = "and"
    OR = "or"


# ── Match models ───────────────────────────────────────────────────────────────


class MatchCondition(BaseModel):
    """A single match clause applied to one field."""

    field: MatchField
    pattern: str
    type: MatchType
    negate: bool = False


class RuleMatch(BaseModel):
    """Either a single match condition or a compound (AND/OR) combination.

    If ``conditions`` is present, this is a compound match.
    Otherwise, ``field``, ``pattern``, and ``type`` must all be set.
    """

    # Compound fields
    operator: CompoundOperator | None = None
    conditions: list[MatchCondition] | None = None
    # Single-condition fields (mirrors MatchCondition)
    field: MatchField | None = None
    pattern: str | None = None
    type: MatchType | None = None
    negate: bool = False

    @model_validator(mode="after")
    def _validate_structure(self) -> RuleMatch:
        if self.conditions is not None:
            if self.operator is None:
                raise ValueError(
                    "Compound RuleMatch requires 'operator' when 'conditions' is set"
                )
            if len(self.conditions) < 2:
                raise ValueError("Compound RuleMatch requires at least 2 conditions")
        else:
            if self.field is None or self.pattern is None or self.type is None:
                raise ValueError(
                    "Simple RuleMatch requires 'field', 'pattern', and 'type'"
                )
        return self

    @property
    def is_compound(self) -> bool:
        """Return True when this is a compound (multi-condition) match."""
        return self.conditions is not None


# ── Policy rule ────────────────────────────────────────────────────────────────


class PolicyRule(BaseModel):
    """A single detection rule in the policy engine."""

    id: str
    name: str
    description: str
    severity: Severity
    category: str
    match: RuleMatch
    message: str
    tags: list[str] = Field(default_factory=list)
    enabled: bool = True
    # When True, the rule engine skips servers whose command, any arg, or server
    # name resolves to an entry in the known-server registry.  Used to suppress
    # findings that would otherwise fire on every legitimate MCP server (e.g.
    # COMM-004 `stdio transport`).  Requires the engine to have been constructed
    # with a registry; has no effect otherwise.
    exempt_known_servers: bool = False
    # OWASP MCP Top 10 category codes for this rule (e.g., ["MCP05"]).
    # Set in rule YAML; propagated to emitted Finding objects.
    owasp_mcp_top_10: list[str] = Field(default_factory=list)


# ── Rule engine ────────────────────────────────────────────────────────────────


class RuleEngine:
    """Evaluates a set of PolicyRules against MCP server configurations.

    Args:
        rules: List of loaded and validated PolicyRule objects.
        registry: Optional known-server registry.  When supplied, rules
            with ``exempt_known_servers=True`` are suppressed for servers
            whose command, any arg, or server name matches a registry
            entry.  Pass ``None`` to disable the exemption entirely.
    """

    def __init__(
        self,
        rules: list[PolicyRule],
        registry: KnownServerRegistry | None = None,
    ) -> None:
        self._rules = rules
        self._registry = registry

    def match_server(self, server: ServerConfig) -> list[Finding]:
        """Evaluate all enabled rules against a single server.

        Args:
            server: The MCP server configuration to evaluate.

        Returns:
            List of Finding objects for every rule that matched.
        """
        findings: list[Finding] = []
        server_is_known = _server_in_registry(server, self._registry)
        for rule in self._rules:
            if not rule.enabled:
                continue
            if rule.exempt_known_servers and server_is_known:
                continue
            matched, matched_value = _evaluate_rule_match(rule.match, server)
            if not matched:
                continue

            description = rule.message.replace(
                "{matched_value}", matched_value
            ).replace("{server_name}", server.name)

            findings.append(
                Finding(
                    id=rule.id,
                    severity=rule.severity,
                    analyzer="rules",
                    client=server.client,
                    server=server.name,
                    title=rule.name,
                    description=description,
                    evidence=f"rule:{rule.id}; matched: {matched_value}",
                    remediation=(
                        f"Review the rule '{rule.id}' ({rule.name}) and the "
                        f"server configuration for '{server.name}'."
                    ),
                    finding_path=str(server.config_path),
                    owasp_mcp_top_10=rule.owasp_mcp_top_10,
                )
            )
        return findings


# ── Registry exemption ─────────────────────────────────────────────────────────


def _server_in_registry(
    server: ServerConfig, registry: KnownServerRegistry | None
) -> bool:
    """Return ``True`` when *server* resolves to a known-server registry entry.

    Consults the registry by checking the command, every argument, and the
    server name against :meth:`KnownServerRegistry.get` (case-insensitive
    exact match).  Mirrors the token-based lookup already used by
    :func:`mcp_audit.analyzers.toxic_flow.tag_server` so that a server which
    toxic-flow recognises as a registry entry is also exempt from
    registry-exempt rules.

    Returns ``False`` immediately when *registry* is ``None`` — callers that
    did not wire a registry get the historical "no exemption" behaviour.
    """
    if registry is None:
        return False
    for token in (server.command, *server.args, server.name):
        if not token:
            continue
        if registry.get(token) is not None:
            return True
    return False


# ── Match evaluation ───────────────────────────────────────────────────────────


def _extract_field(field: MatchField, server: ServerConfig) -> str | None:
    """Extract the string value of a field from a ServerConfig.

    Returns:
        Field value as a string, or ``None`` when the field is not set
        (e.g. ``url`` on a stdio server).  Callers skip the match when
        ``None`` is returned.
    """
    if field == MatchField.COMMAND:
        return server.command
    if field == MatchField.ARGS:
        return " ".join(server.args)
    if field == MatchField.ENV:
        return " ".join(server.env.keys())
    if field == MatchField.SERVER_NAME:
        return server.name
    if field == MatchField.URL:
        return server.url
    if field == MatchField.TRANSPORT:
        return str(server.transport) if server.transport else None
    return None  # pragma: no cover


def _apply_match_type(
    match_type: MatchType, field_value: str, pattern: str
) -> tuple[bool, str]:
    """Apply a single match type to a field value.

    Returns:
        ``(matched, matched_value)`` where ``matched_value`` is the
        field value on success, or ``""`` when the match fails.
    """
    if match_type == MatchType.EXACT:
        if field_value == pattern:
            return True, field_value
        return False, ""

    if match_type == MatchType.CONTAINS:
        if pattern in field_value:
            return True, field_value
        return False, ""

    if match_type == MatchType.REGEX:
        try:
            m = re.search(pattern, field_value)
        except re.error as exc:
            logger.warning("Invalid regex pattern %r in rule: %s", pattern, exc)
            return False, ""
        if m:
            return True, m.group(0)
        return False, ""

    if match_type == MatchType.GLOB:
        if fnmatch.fnmatch(field_value, pattern):
            return True, field_value
        return False, ""

    if match_type == MatchType.SEMVER_RANGE:
        return _match_semver_range(field_value, pattern)

    return False, ""  # pragma: no cover


def _match_semver_range(field_value: str, pattern: str) -> tuple[bool, str]:
    """Match a field value against a semver range expression."""
    from packaging.specifiers import InvalidSpecifier, SpecifierSet  # noqa: PLC0415
    from packaging.version import Version  # noqa: PLC0415

    try:
        spec = SpecifierSet(pattern)
        version = Version(field_value)
        if version in spec:
            return True, field_value
        return False, ""
    except (InvalidSpecifier, ValueError):
        logger.warning(
            "semver_range: invalid version %r or specifier %r — skipping match",
            field_value,
            pattern,
        )
        return False, ""


def _evaluate_condition(
    condition: MatchCondition, server: ServerConfig
) -> tuple[bool, str]:
    """Evaluate a single MatchCondition against a server.

    Args:
        condition: The condition to evaluate.
        server: Server configuration to test.

    Returns:
        ``(matched, matched_value)`` tuple.  ``matched_value`` is the
        relevant portion of the field that triggered the match (empty
        string when not matched).
    """
    field_value = _extract_field(condition.field, server)
    if field_value is None:
        # Field is not set on this server (e.g. url on stdio server).
        result, value = False, ""
    else:
        result, value = _apply_match_type(
            condition.type, field_value, condition.pattern
        )

    if condition.negate:
        # Inverted match: succeed when the underlying match *fails*.
        # Use the field value as matched_value so callers have context.
        if not result:
            return True, field_value or ""
        return False, ""

    return result, value


def _evaluate_rule_match(
    rule_match: RuleMatch, server: ServerConfig
) -> tuple[bool, str]:
    """Evaluate a RuleMatch (simple or compound) against a server.

    Returns:
        ``(matched, matched_value)`` where ``matched_value`` for compound
        rules is the individual matched values joined with ``"; "``.
    """
    if not rule_match.is_compound:
        # Build a MatchCondition from the flat fields.
        assert rule_match.field is not None  # validated by RuleMatch  # noqa: S101
        assert rule_match.pattern is not None  # noqa: S101
        assert rule_match.type is not None  # noqa: S101
        cond = MatchCondition(
            field=rule_match.field,
            pattern=rule_match.pattern,
            type=rule_match.type,
            negate=rule_match.negate,
        )
        return _evaluate_condition(cond, server)

    # Compound evaluation
    assert rule_match.conditions is not None  # noqa: S101
    assert rule_match.operator is not None  # noqa: S101

    results: list[tuple[bool, str]] = [
        _evaluate_condition(c, server) for c in rule_match.conditions
    ]

    if rule_match.operator == CompoundOperator.AND:
        if all(r for r, _ in results):
            matched_values = [v for _, v in results if v]
            return True, "; ".join(matched_values)
        return False, ""

    # OR: at least one must match
    matched_values = [v for r, v in results if r and v]
    if any(r for r, _ in results):
        return True, "; ".join(matched_values)
    return False, ""


# ── YAML loading ───────────────────────────────────────────────────────────────


def load_rules_from_file(path: Path) -> list[PolicyRule]:
    """Load and validate PolicyRule objects from a YAML file.

    A file may contain a single rule dict OR a list of rule dicts under a
    ``rules:`` top-level key.  Invalid rules are skipped with a warning so
    that one malformed entry does not abort a multi-rule file.

    Args:
        path: Path to a YAML file containing one or more rules.

    Returns:
        List of valid, parsed PolicyRule objects.
    """
    try:
        raw_text = path.read_text(encoding="utf-8")
    except OSError as exc:
        logger.warning("Cannot read rule file %s: %s", path, exc)
        return []

    try:
        data: Any = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        logger.warning("YAML parse error in %s: %s", path, exc)
        return []

    if data is None:
        return []

    # Normalise to a list of raw rule dicts.
    if isinstance(data, dict) and "rules" in data and isinstance(data["rules"], list):
        raw_rules: list[Any] = data["rules"]
    elif isinstance(data, dict):
        raw_rules = [data]
    elif isinstance(data, list):
        raw_rules = data
    else:
        logger.warning("Unexpected YAML structure in %s (expected dict or list)", path)
        return []

    rules: list[PolicyRule] = []
    for i, raw in enumerate(raw_rules):
        if not isinstance(raw, dict):
            logger.warning("Rule #%d in %s is not a mapping — skipping", i, path)
            continue
        try:
            rule = PolicyRule.model_validate(raw)
            rules.append(rule)
        except Exception as exc:  # noqa: BLE001
            rule_id = raw.get("id", f"<rule #{i}>")
            logger.warning("Invalid rule %r in %s: %s", rule_id, path, exc)

    return rules


def load_rules_from_dir(directory: Path) -> list[PolicyRule]:
    """Load all ``.yml`` and ``.yaml`` rule files from a directory (non-recursive).

    Deduplicates by rule ID: if two files define the same ID, the first one
    encountered (alphabetical file order) is kept and a warning is logged.

    Args:
        directory: Path to a directory containing YAML rule files.

    Returns:
        Deduplicated list of valid PolicyRule objects.
    """
    if not directory.is_dir():
        logger.warning("Rules directory not found: %s", directory)
        return []

    yaml_files = sorted(
        p for p in directory.iterdir() if p.suffix in {".yml", ".yaml"} and p.is_file()
    )

    seen_ids: dict[str, Path] = {}
    rules: list[PolicyRule] = []

    for yaml_file in yaml_files:
        file_rules = load_rules_from_file(yaml_file)
        for rule in file_rules:
            if rule.id in seen_ids:
                logger.warning(
                    "Duplicate rule ID %r: defined in %s and %s — keeping %s",
                    rule.id,
                    seen_ids[rule.id],
                    yaml_file,
                    seen_ids[rule.id],
                )
                continue
            seen_ids[rule.id] = yaml_file
            rules.append(rule)

    return rules


def merge_rules(
    primary: list[PolicyRule], secondary: list[PolicyRule]
) -> list[PolicyRule]:
    """Merge two rule lists, with primary taking precedence on ID conflicts.

    Args:
        primary: Rules that take priority (e.g. user-supplied rules).
        secondary: Fallback rules (e.g. bundled community rules).

    Returns:
        Combined deduplicated list.
    """
    seen_ids = {r.id for r in primary}
    merged = list(primary)
    for rule in secondary:
        if rule.id not in seen_ids:
            seen_ids.add(rule.id)
            merged.append(rule)
    return merged


# ── Bundled community rules ────────────────────────────────────────────────────


def _resolve_bundled_community_dir() -> Path:
    """Locate the bundled ``rules/community/`` directory.

    Resolution order (delegated to :func:`~mcp_audit._paths.resolve_bundled_resource`):

    1. PyInstaller frozen binary (``sys._MEIPASS/rules/community/``).
    2. importlib.resources (pip-installed wheel at ``mcp_audit/rules/community/``).
    3. Dev / editable install fallback (repo-root ``rules/community/``).
    """
    from mcp_audit._paths import resolve_bundled_resource  # noqa: PLC0415

    _dev_fallback = Path(__file__).parent.parent.parent.parent / "rules" / "community"
    result = resolve_bundled_resource(
        package="mcp_audit.rules",
        subdir="community",
        frozen_subpath="rules/community",
        dev_fallback=_dev_fallback,
    )
    # Always return a Path; if nothing was found, the dev fallback is the last resort.
    return result if result is not None else _dev_fallback


def load_bundled_community_rules() -> list[PolicyRule]:
    """Load the bundled community rules shipped with mcp-audit.

    Returns:
        List of valid PolicyRule objects from ``rules/community/``.
    """
    community_dir = _resolve_bundled_community_dir()
    rules = load_rules_from_dir(community_dir)
    logger.debug("Loaded %d bundled community rules from %s", len(rules), community_dir)
    return rules
