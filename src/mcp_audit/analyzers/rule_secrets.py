"""Secrets saved inside Claude Code permission rules (CRED-004, STORY-0149).

Anthropic's permissions doc: "When you choose "Yes, and don't ask again" and
the approval saves permanently, such as for a Bash command or a WebFetch
domain, Claude Code saves the rule to ``.claude/settings.local.json`` at the
root of the git repository".  The rule is the command string itself, so a
command approved with a token, a password or a connection string in it puts
that secret in a settings file.  GitGuardian (Guillaume Valadon, 2026-11-09)
counted 31,088 distinct secrets in public ``settings.local.json`` files
(5,343 valid at detection) and 8,271 in ``settings.json``; Apiiro (via The
Hacker News, 2026-11-07) found a secret in 1,122 of 104,185 public
``settings.local.json`` copies, 215 of which neither gitleaks nor TruffleHog
flagged.

This module is the pure, per-file part: :func:`rule_secret_hits` finds the
rules and :func:`rule_secret_finding` builds the finding.  Step 0b of the scan
pipeline (:func:`mcp_audit.analyzers.sandbox.analyze_sandbox_files`) calls it
for every Claude Code settings file and decides the severity from git state:
HIGH when the file is committed or headed for git, MEDIUM otherwise.

What counts as a secret is what the shared command redactor removes
(:func:`mcp_audit.analyzers.supply_chain.redact_command_text`: URL userinfo,
every ``SECRET_PATTERNS`` match, ``Bearer``/``Basic``/``Token`` credentials,
credential headers, ``curl -u user:pass``, ``password=``-style pairs), plus
upper-case ``*PASSWORD*``/``*PASSWD*`` assignments (``PGPASSWORD=…``), npm
``_authToken=``/``_auth=`` and npm access tokens.  A value that is only a
``*`` wildcard, an environment reference (``$VAR``, ``${VAR}``) or a
``${{ … }}`` template is not a secret.  Nothing is printed unredacted: the
finding quotes each rule with the secret replaced by ``[REDACTED]``.
Nothing is executed and no network is used.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from mcp_audit.analyzers.supply_chain import (
    _is_secret_flag_name,  # the redactor's own name test, so both agree
    redact_command_text,
)
from mcp_audit.models import Finding, Severity

FINDING_ID = "CRED-004"
TITLE = "Secret saved in a permission rule"
CWE = "CWE-312"
OWASP = ("MCP01",)

#: The rule lists Claude Code reads (settings reference, ``permissions``).
RULE_LISTS = ("allow", "ask", "deny")
#: Rules examined per list, and characters per rule; more is reported as cut.
MAX_RULES_PER_LIST = 5_000
MAX_RULE_CHARS = 4_096
#: Rules quoted in one finding before "(+N more)", and characters per quote.
_LIST_CAP = 20
_QUOTE_CHARS = 160

_REDACTED = "[REDACTED]"
#: ``Tool(specifier)``: the specifier is what holds a command or URL.
_RULE_RE = re.compile(r"\A\s*([A-Za-z][A-Za-z0-9_.-]{0,63})\((.*)\)\s*\Z", re.S)
#: ``${{ secrets.X }}`` and ``{{ x }}`` templates are references, not values.
_TEMPLATE_RE = re.compile(r"\$?\{\{[^{}\n]{0,200}\}\}")
#: A value that is only ``*`` wildcards after ``=``, ``:`` or a space.
_WILDCARD_VALUE_RE = re.compile(r"(?<=[=:\s])\*+(?=[\s'\"),;]|\Z)")
_WILDCARD_REF = "$MCPAUDITWILDCARD"
_TEMPLATE_REF = "$MCPAUDITTEMPLATE"
#: Upper-case env assignments with a password word inside the name
#: (``PGPASSWORD=``, ``DB_PASSWD=``), and npm's ``_authToken=``/``_auth=``.
#: The redactor's own name list covers ``*_PASSWORD``, ``*_TOKEN``,
#: ``*_API_KEY`` and the like; these are the compound forms it splits wrongly.
_EXTRA_NAME = (
    r"[A-Z0-9_]*(?:PASSWORD|PASSWD)"
    r"(?:_(?!FILE\b|PATH\b|DIR\b|CMD\b|COMMAND\b|HELPER\b)[A-Z0-9]+)*"
    r"|_authToken|_auth"
)
_EXTRA_NAME_RE = re.compile(_EXTRA_NAME)
_EXTRA_ASSIGN_RE = re.compile(
    rf"(?<![A-Za-z0-9_])({_EXTRA_NAME})"
    r"=(?!\$|\[REDACTED)(['\"]?)([^\s'\";&|)]{4,})"
)
#: ``Authorization: token key:secret`` (ERPNext, Frappe): the redactor stops
#: at ``:``; the rest of the word is the secret too.
_AFTER_MARKER_RE = re.compile(r"\[REDACTED\]:[^\s'\"]+")
#: A value word that names a secret instead of holding one.
_REFERENCE_WORD_RE = re.compile(
    r"(?:\$\{[^}]*\}|\$\(?[A-Za-z_][A-Za-z0-9_]*\)?|%[A-Za-z0-9_]+%|\*+)+"
)
#: npm access tokens (``npm_`` and 36 characters).
_NPM_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9_])npm_[A-Za-z0-9]{36}(?![A-Za-z0-9])")


@dataclass(frozen=True)
class RuleSecretHit:
    """One permission rule that holds a secret.

    Attributes:
        location: JSON location, e.g. ``permissions.allow[3]``.
        redacted: The rule with each secret replaced by ``[REDACTED]``, cut to
            a quotable length.
    """

    location: str
    redacted: str


@dataclass
class RuleSecretScan:
    """Hits for one settings file, and whether the search stopped early."""

    hits: list[RuleSecretHit]
    truncated: bool = False


def redact_rule(rule: str) -> str:
    """Return *rule* with every secret this check recognises redacted.

    The redactor's output is compared with its input span by span: a span it
    replaced whose original value is only a reference (``$VAR``, ``${VAR}``,
    ``%VAR%``), a ``${{ … }}`` template, a ``*`` wildcard or nothing (an
    empty assignment) is put back, so those never count as secrets.
    """
    match = _RULE_RE.match(rule)
    if match:
        head, inner = f"{match.group(1)}(", match.group(2)
        tail = ")"
    else:
        head, inner, tail = "", rule, ""
    templates: list[str] = []

    def keep_template(m: re.Match[str]) -> str:
        templates.append(m.group(0))
        return _TEMPLATE_REF

    prepared = _TEMPLATE_RE.sub(keep_template, inner)
    wildcards: list[str] = []

    def keep_wildcard(m: re.Match[str]) -> str:
        wildcards.append(m.group(0))
        return _WILDCARD_REF

    prepared = _WILDCARD_VALUE_RE.sub(keep_wildcard, prepared)
    cleaned = _keep_references(prepared, redact_command_text(prepared))
    cleaned = _AFTER_MARKER_RE.sub(_REDACTED, cleaned)
    cleaned = _EXTRA_ASSIGN_RE.sub(rf"\1=\2{_REDACTED}", cleaned)
    cleaned = _NPM_TOKEN_RE.sub(_REDACTED, cleaned)
    for wildcard in wildcards:
        cleaned = cleaned.replace(_WILDCARD_REF, wildcard, 1)
    for template in templates:
        cleaned = cleaned.replace(_TEMPLATE_REF, template, 1)
    return head + cleaned + tail


def _is_reference(value: str) -> bool:
    """True when the first word of a replaced span holds no literal secret."""
    word = value.strip().split(maxsplit=1)[0] if value.strip() else ""
    word = word.strip("'\"`;,)")
    return not word or bool(_REFERENCE_WORD_RE.fullmatch(word))


#: ``NAME=`` (optionally quoted) at the end of the text before a span.
_NAME_BEFORE_RE = re.compile(r"([A-Za-z0-9_.-]{1,64})=['\"]?\Z")


def _not_a_secret_name(before: str) -> bool:
    """True when the span follows ``=`` but not ``<secret name>=``.

    The shared redactor reads a whole rule as one argument, so a long command
    with a secret word anywhere before an ``=`` (a PR body's ``>= 44px``) can
    read as ``NAME=value``.  Here only the word right before ``=`` counts.
    """
    if not before.endswith(("=", "='", '="')):
        return False
    match = _NAME_BEFORE_RE.search(before)
    if match is None:
        return True
    name = match.group(1).lstrip("-")
    return not _is_secret_flag_name(name) and not _EXTRA_NAME_RE.fullmatch(name)


def _keep_references(original: str, redacted: str) -> str:
    """*redacted*, with each replaced span that held only a reference restored.

    The redactor keeps every character it does not replace, so the text
    between two ``[REDACTED]`` markers appears in *original* in order; the
    original span of each marker lies between them.  When that alignment
    fails, *redacted* is returned as is (every marker counts).
    """
    if original == redacted:
        return redacted
    pieces = redacted.split(_REDACTED)
    if not original.startswith(pieces[0]):
        return redacted
    out = [pieces[0]]
    pos = len(pieces[0])
    for index, piece in enumerate(pieces[1:], start=1):
        last = index == len(pieces) - 1
        if piece:
            end = original.find(piece, pos)
            if end < 0:
                return redacted
        elif last:
            end = len(original)
        else:
            out.append(_REDACTED)  # two markers in a row: span unknown, keep
            continue
        span = original[pos:end]
        keep = _is_reference(span) or _not_a_secret_name(original[:pos])
        out.append(span if keep else _REDACTED)
        out.append(piece)
        pos = end + len(piece)
    return "".join(out)


def holds_secret(rule: str) -> bool:
    """True when :func:`redact_rule` changes *rule*."""
    return redact_rule(rule) != rule


def _quote(text: str) -> str:
    if len(text) > _QUOTE_CHARS:
        text = text[:_QUOTE_CHARS] + "…"
    return repr(text)


def rule_secret_hits(raw: object) -> RuleSecretScan:
    """Every ``permissions.allow/ask/deny`` string in *raw* that holds a secret.

    Non-object settings, a ``permissions`` value that is not an object and
    rule lists that are not lists contribute nothing.  Non-string entries are
    skipped.  Only the first :data:`MAX_RULES_PER_LIST` entries of each list
    and :data:`MAX_RULE_CHARS` of each string are examined; ``truncated``
    says when that cut anything.
    """
    scan = RuleSecretScan(hits=[])
    if not isinstance(raw, dict):
        return scan
    permissions = raw.get("permissions")
    if not isinstance(permissions, dict):
        return scan
    for list_name in RULE_LISTS:
        entries = permissions.get(list_name)
        if not isinstance(entries, list):
            continue
        if len(entries) > MAX_RULES_PER_LIST:
            scan.truncated = True
        for index, entry in enumerate(entries[:MAX_RULES_PER_LIST]):
            if not isinstance(entry, str):
                continue
            text = entry
            if len(text) > MAX_RULE_CHARS:
                scan.truncated = True
                text = text[:MAX_RULE_CHARS]
            redacted = redact_rule(text)
            if redacted != text:
                scan.hits.append(
                    RuleSecretHit(f"permissions.{list_name}[{index}]", redacted)
                )
    return scan


def rule_secret_finding(
    path: Path,
    client: str,
    hits: list[RuleSecretHit],
    *,
    headed_for_git: bool | None,
    git_note: str,
    analyzer: str,
) -> Finding:
    """CRED-004 for one settings file.

    Args:
        path: The settings file.
        client: Client label for the finding.
        hits: From :func:`rule_secret_hits`; must not be empty.
        headed_for_git: ``True`` when the file is committed or will be (HIGH),
            ``False`` when it is the user's own or git ignores it (MEDIUM),
            ``None`` when its git state could not be read (MEDIUM).
        git_note: One sentence on the file's git state, ending in a period.
        analyzer: Analyzer label.
    """
    severity = Severity.HIGH if headed_for_git else Severity.MEDIUM
    label = f"{path.parent.name}/{path.name}"
    quoted = [f"{hit.location}: {_quote(hit.redacted)}" for hit in hits[:_LIST_CAP]]
    if len(hits) > _LIST_CAP:
        quoted.append(f"(+{len(hits) - _LIST_CAP} more)")
    return Finding(
        id=FINDING_ID,
        severity=severity,
        analyzer=analyzer,
        client=client,
        server="(config-level)",
        title=TITLE,
        description=(
            f"'{label}' has {len(hits)} permission rule(s) that contain a"
            " credential (a token, key, password or connection string). Claude"
            ' Code saves a rule when you choose "Yes, and don\'t ask again", and'
            " the rule is the approved command word for word, secret included"
            ' (permissions doc: Claude Code "saves the rule to'
            ' .claude/settings.local.json at the root of the git repository").'
            f" {git_note} Anyone who can read this file can read the secret."
            " GitGuardian (Guillaume Valadon, 2026-11-09) found 31,088 distinct"
            " secrets in public settings.local.json files, 5,343 still valid,"
            " and 8,271 in settings.json; Apiiro (via The Hacker News,"
            " 2026-11-07) found a secret in 1,122 of 104,185 public"
            " settings.local.json copies, 215 of which neither gitleaks nor"
            " TruffleHog flagged."
        ),
        evidence=f"{path}: " + "; ".join(quoted),
        remediation=(
            "Rotate each credential first: if the file was ever committed or"
            " copied, the old value is in git history or in the copy. Then delete"
            " the rule, and approve the command again with the secret read from"
            " an environment variable or a credential helper (for example"
            ' Bash(psql "$DATABASE_URL" *) instead of the connection string).'
            " Keep .claude/settings.local.json in .gitignore."
        ),
        cwe=CWE,
        owasp_mcp_top_10=list(OWASP),
        finding_path=str(path),
    )
