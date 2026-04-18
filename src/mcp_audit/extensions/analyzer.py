"""Analyze installed IDE extensions for security issues.

Analysis layers:
  1. Known-vulnerability registry check
  2. Dangerous permission combinations
  3. Wildcard activation event
  4. Unknown publisher (AI-related extensions only)
  5. Sideloaded extensions (installed from VSIX)
  6. Stale AI-related extensions
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path

from mcp_audit.extensions.models import ExtensionManifest, ExtensionVulnEntry
from mcp_audit.models import Finding, Severity

# ── Known-vulnerability check ──────────────────────────────────────────────────


def _resolve_vuln_registry_path() -> Path:
    """Locate ``known-extension-vulns.json`` regardless of execution context.

    Resolution order (delegated to :func:`~mcp_audit._paths.resolve_bundled_resource`):

    1. PyInstaller frozen binary (``sys._MEIPASS/registry/known-extension-vulns.json``).
    2. importlib.resources (pip-installed wheel at
       ``mcp_audit/registry/known-extension-vulns.json``).
    3. Dev / editable install fallback (repo-root
       ``registry/known-extension-vulns.json``).
    """
    from mcp_audit._paths import resolve_bundled_resource  # noqa: PLC0415

    _dev_fallback = (
        Path(__file__).parent.parent.parent.parent
        / "registry"
        / "known-extension-vulns.json"
    )
    result = resolve_bundled_resource(
        package="mcp_audit.registry",
        subdir="known-extension-vulns.json",
        frozen_subpath="registry/known-extension-vulns.json",
        dev_fallback=_dev_fallback,
    )
    return result if result is not None else _dev_fallback


def load_vuln_registry(path: Path | None = None) -> list[ExtensionVulnEntry]:
    """Load ``known-extension-vulns.json`` from *path* or auto-resolved location.

    Resolution order:
    1. Explicit *path* argument
    2. PyInstaller ``_MEIPASS``
    3. ``importlib.resources`` (installed wheel)
    4. Repo-root fallback

    Returns an empty list if the file cannot be found or parsed.
    """
    resolved = path if path is not None else _resolve_vuln_registry_path()
    if not resolved.exists():
        return []
    try:
        data = json.loads(resolved.read_text(encoding="utf-8"))
        raw_entries = data.get("entries", [])
        return [ExtensionVulnEntry.model_validate(e) for e in raw_entries]
    except Exception:  # noqa: BLE001
        return []


def _finding_id(*parts: str) -> str:
    """Produce a short, deterministic finding ID from the given string parts."""
    digest = hashlib.sha256("|".join(parts).encode()).hexdigest()[:12]
    return f"EXT-{digest}"


def check_known_vulns(
    extension: ExtensionManifest,
    vuln_registry: list[ExtensionVulnEntry],
) -> list[Finding]:
    """Compare extension ID and version against the known-vuln registry.

    ID matching is case-insensitive.  Version matching: ``"*"`` matches any
    version; otherwise a simple ``<`` prefix comparison is used (full semver
    range parsing is out of scope — see GAPS.md).
    """
    findings: list[Finding] = []
    ext_id_lower = extension.extension_id.lower()

    for entry in vuln_registry:
        if entry.extension_id.lower() != ext_id_lower:
            continue
        if not _version_matches(extension.version, entry.affected_versions):
            continue

        sev = _parse_severity(entry.severity)
        evidence = json.dumps(
            {
                "extension_id": extension.extension_id,
                "version": extension.version,
                "cve": entry.cve,
                "reference": entry.reference,
                "affected_versions": entry.affected_versions,
            }
        )
        findings.append(
            Finding(
                id=_finding_id(extension.extension_id, entry.cve or entry.title),
                severity=sev,
                analyzer="extensions",
                client=extension.client_name,
                server=extension.extension_id,
                title=entry.title,
                description=entry.description,
                evidence=evidence,
                remediation=(
                    f"Update {extension.extension_id} to a patched version. "
                    + (f"See: {entry.reference}" if entry.reference else "")
                ).strip(),
                cwe=None,
                finding_path=extension.manifest_path or None,
            )
        )
    return findings


def _version_matches(installed: str, affected: str) -> bool:
    """Return True if *installed* version falls within the *affected* range.

    Supports:
      - ``"*"`` — matches any version
      - ``"<X.Y.Z"`` — installed version is lexicographically / numerically
        less than X.Y.Z (simplified; full semver not implemented)
    """
    if affected == "*":
        return True
    if affected.startswith("<"):
        threshold = affected[1:].strip()
        return _version_lt(installed, threshold)
    # Exact match (not commonly used, but handle it)
    return installed == affected


def _version_lt(a: str, b: str) -> bool:
    """Return True if version string *a* is less than *b* using tuple comparison."""
    try:

        def _to_tuple(v: str) -> tuple[int, ...]:
            return tuple(int(x) for x in v.split(".") if x.isdigit())

        return _to_tuple(a) < _to_tuple(b)
    except Exception:  # noqa: BLE001
        return a < b  # fallback to lexicographic


def _parse_severity(raw: str) -> Severity:
    mapping = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
    }
    return mapping.get(raw.lower(), Severity.MEDIUM)


# ── Permission / capability audit ──────────────────────────────────────────────

DANGEROUS_COMBOS: list[tuple[str, str, Severity, str]] = [
    (
        "filesystem",
        "network",
        Severity.HIGH,
        "Extension declares both filesystem and network access"
        " — potential data exfiltration path",
    ),
    (
        "terminal",
        "network",
        Severity.HIGH,
        "Extension declares both terminal and network access"
        " — potential credential exfiltration",
    ),
    (
        "debuggers",
        "network",
        Severity.MEDIUM,
        "Extension registers a debug adapter and declares network access",
    ),
]

_AI_KEYWORDS = frozenset(
    {
        "ai",
        "copilot",
        "llm",
        "gpt",
        "claude",
        "cursor",
        "assistant",
        "autocomplete",
        "intellicode",
        "tabnine",
        "codeium",
        "github copilot",
    }
)

# Word-boundary regex for AI keyword detection; prevents "ai" matching "plain".
_AI_KW_RE = re.compile(
    r"\b(?:"
    + "|".join(re.escape(kw) for kw in sorted(_AI_KEYWORDS, key=len, reverse=True))
    + r")\b"
)


def classify_extension_capabilities(extension: ExtensionManifest) -> set[str]:
    """Derive a set of capability tags from an extension manifest.

    Tags returned: ``"filesystem"``, ``"network"``, ``"terminal"``,
    ``"authentication"``, ``"debuggers"``, ``"ai_related"``.
    """
    caps: set[str] = set()
    name_lower = extension.name.lower()
    desc_lower = (extension.description or "").lower()
    keywords_lower = {k.lower() for k in extension.keywords}
    categories_lower = {c.lower() for c in extension.categories}
    display_lower = (extension.display_name or "").lower()

    # filesystem
    file_terms = {"file", "explorer", "fs", "filesystem", "folder", "workspace"}
    cmd_names_lower = {
        cmd.get("command", "").lower()
        for cmd in (extension.contributes.get("commands") or [])
        if isinstance(cmd, dict)
    }
    cmd_text = " ".join(cmd_names_lower)
    if (
        any(t in cmd_text for t in ("open", "save", "read", "write"))
        or keywords_lower & file_terms
        or any(t in name_lower for t in file_terms)
    ):
        caps.add("filesystem")

    # network
    net_terms = {
        "http",
        "api",
        "request",
        "fetch",
        "webhook",
        "remote",
        "rest",
        "graphql",
    }
    if (
        "*" in extension.activation_events
        or keywords_lower & net_terms
        or any(t in desc_lower for t in net_terms)
        or any(t in name_lower for t in net_terms)
    ):
        caps.add("network")

    # terminal
    terminal_terms = {"terminal", "shell", "bash", "zsh", "cmd", "powershell"}
    if (
        "terminal" in extension.contributes
        or keywords_lower & terminal_terms
        or any(t in name_lower for t in terminal_terms)
        or any(t in display_lower for t in terminal_terms)
    ):
        caps.add("terminal")

    # authentication
    auth_terms = {
        "auth",
        "oauth",
        "token",
        "credential",
        "login",
        "ssh",
        "key",
        "password",
    }
    if (
        keywords_lower & auth_terms
        or any(t in desc_lower for t in auth_terms)
        or any(t in name_lower for t in auth_terms)
    ):
        caps.add("authentication")

    # debuggers
    if "debuggers" in extension.contributes:
        caps.add("debuggers")

    # ai_related
    all_text = " ".join(
        [name_lower, display_lower, desc_lower]
        + list(keywords_lower)
        + list(categories_lower)
    )
    if _AI_KW_RE.search(all_text):
        caps.add("ai_related")

    return caps


def check_permissions(extension: ExtensionManifest) -> list[Finding]:
    """Flag extensions with dangerous capability combinations.

    Returns one :class:`Finding` per matched combo.
    """
    caps = classify_extension_capabilities(extension)
    findings: list[Finding] = []
    for cap_a, cap_b, severity, message in DANGEROUS_COMBOS:
        if cap_a in caps and cap_b in caps:
            findings.append(
                Finding(
                    id=_finding_id(extension.extension_id, f"combo:{cap_a}:{cap_b}"),
                    severity=severity,
                    analyzer="extensions",
                    client=extension.client_name,
                    server=extension.extension_id,
                    title=f"Dangerous permission combination: {cap_a} + {cap_b}",
                    description=message,
                    evidence=json.dumps(
                        {"capabilities": sorted(caps), "combo": [cap_a, cap_b]}
                    ),
                    remediation=(
                        f"Review whether {extension.extension_id} requires both "
                        f"{cap_a} and {cap_b} access. "
                        "Disable or replace if not needed."
                    ),
                    finding_path=extension.manifest_path or None,
                )
            )
    return findings


def check_wildcard_activation(extension: ExtensionManifest) -> list[Finding]:
    """Flag extensions with ``activationEvents: ["*"]``.

    Wildcard activation loads the extension for every VS Code event, which is
    suspicious for extensions that don't need global activation.
    """
    if "*" not in extension.activation_events:
        return []
    return [
        Finding(
            id=_finding_id(extension.extension_id, "wildcard-activation"),
            severity=Severity.MEDIUM,
            analyzer="extensions",
            client=extension.client_name,
            server=extension.extension_id,
            title="Extension uses wildcard activation event",
            description=(
                f"{extension.extension_id} activates on every VS Code event "
                "(activationEvents: ['*']).  Legitimate extensions should declare "
                "specific activation events.  Wildcard activation is a common "
                "indicator of malicious or poorly-written extensions."
            ),
            evidence=json.dumps({"activation_events": extension.activation_events}),
            remediation=(
                "Review whether this extension needs to load on every event. "
                "If not, report it to the publisher or disable it."
            ),
            finding_path=extension.manifest_path or None,
        )
    ]


# ── Provenance check ───────────────────────────────────────────────────────────

KNOWN_PUBLISHERS: frozenset[str] = frozenset(
    {
        "microsoft",
        "github",
        "redhat",
        "vmware",
        "salesforce",
        "googlecloudtools",
        "amazonwebservices",
        "hashicorp",
        "dbaeumer",
        "esbenp",
        "eamodio",
        "anthropic",
        "getcursor",
        "codeium",
        "tabnine",
    }
)


def check_provenance(extension: ExtensionManifest) -> list[Finding]:
    """Flag AI-related extensions from unknown publishers.

    Non-AI extensions are not flagged to avoid excessive noise on
    community-developed utilities.
    """
    if extension.publisher.lower() in KNOWN_PUBLISHERS:
        return []
    caps = classify_extension_capabilities(extension)
    if "ai_related" not in caps:
        return []
    return [
        Finding(
            id=_finding_id(extension.extension_id, "unknown-publisher"),
            severity=Severity.LOW,
            analyzer="extensions",
            client=extension.client_name,
            server=extension.extension_id,
            title="AI-related extension from unknown publisher",
            description=(
                f"{extension.extension_id} is an AI-related extension published by "
                f"'{extension.publisher}', which is not in the known-publishers list. "
                "Unvetted AI extensions may exfiltrate code or credentials."
            ),
            evidence=json.dumps(
                {
                    "publisher": extension.publisher,
                    "extension_id": extension.extension_id,
                    "ai_related": True,
                }
            ),
            remediation=(
                "Verify the publisher's identity on the VS Code Marketplace or "
                "OpenVSX Registry before trusting this extension with AI-assisted "
                "coding."
            ),
            finding_path=extension.manifest_path or None,
        )
    ]


def check_sideloaded(extension: ExtensionManifest) -> list[Finding]:
    """Flag extensions installed from a VSIX file (sideloaded).

    Heuristic: the install path contains ``.vsix`` anywhere in the path.
    """
    if ".vsix" not in extension.install_path:
        return []
    return [
        Finding(
            id=_finding_id(extension.extension_id, "sideloaded"),
            severity=Severity.MEDIUM,
            analyzer="extensions",
            client=extension.client_name,
            server=extension.extension_id,
            title="Extension appears to be sideloaded (installed from VSIX)",
            description=(
                f"{extension.extension_id} appears to have been installed from a VSIX "
                "file rather than the VS Code Marketplace or OpenVSX Registry.  "
                "Sideloaded extensions bypass publisher verification."
            ),
            evidence=json.dumps({"install_path": extension.install_path}),
            remediation=(
                "Install extensions only from the official VS Code Marketplace or "
                "OpenVSX Registry.  Remove sideloaded extensions unless you built "
                "and signed them yourself."
            ),
            finding_path=extension.manifest_path or None,
        )
    ]


# ── Stale extension check ──────────────────────────────────────────────────────

STALE_THRESHOLD_DAYS: int = 365


def check_stale(extension: ExtensionManifest) -> list[Finding]:
    """Flag stale AI-related extensions (not updated in > STALE_THRESHOLD_DAYS days).

    Non-AI extensions are skipped to avoid noisy findings on unmaintained but
    harmless utilities.  Returns no finding when ``last_updated`` is ``None``.
    """
    if extension.last_updated is None:
        return []
    caps = classify_extension_capabilities(extension)
    if "ai_related" not in caps:
        return []
    try:
        mtime = datetime.fromisoformat(extension.last_updated.replace("Z", "+00:00"))
        age_days = (datetime.now(tz=UTC) - mtime).days
    except Exception:  # noqa: BLE001
        return []
    if age_days < STALE_THRESHOLD_DAYS:
        return []
    return [
        Finding(
            id=_finding_id(extension.extension_id, "stale"),
            severity=Severity.INFO,
            analyzer="extensions",
            client=extension.client_name,
            server=extension.extension_id,
            title=f"AI-related extension not updated in {age_days} days",
            description=(
                f"{extension.extension_id} is an AI-related extension whose manifest "
                f"has not been updated in {age_days} days.  Stale AI extensions may "
                "lack security patches and use outdated model APIs."
            ),
            evidence=json.dumps(
                {
                    "last_updated": extension.last_updated,
                    "age_days": age_days,
                    "threshold_days": STALE_THRESHOLD_DAYS,
                }
            ),
            remediation=(
                f"Update {extension.extension_id} or replace it with an actively "
                "maintained alternative."
            ),
            finding_path=extension.manifest_path or None,
        )
    ]


# ── Main entry point ───────────────────────────────────────────────────────────


def analyze_extensions(
    extensions: list[ExtensionManifest],
    vuln_registry: list[ExtensionVulnEntry] | None = None,
) -> list[Finding]:
    """Run all analysis layers against a list of discovered extensions.

    Returns a flat list of findings across all extensions and all checks.
    Order: known vulns first, then permissions, wildcard activation,
    provenance, sideloaded, stale.
    """
    if vuln_registry is None:
        vuln_registry = load_vuln_registry()
    findings: list[Finding] = []
    for ext in extensions:
        findings.extend(check_known_vulns(ext, vuln_registry))
        findings.extend(check_permissions(ext))
        findings.extend(check_wildcard_activation(ext))
        findings.extend(check_provenance(ext))
        findings.extend(check_sideloaded(ext))
        findings.extend(check_stale(ext))
    return findings
