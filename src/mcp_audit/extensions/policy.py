"""Is the editor's extension allowlist actually enforced? (STORY-0144)

VS Code, Cursor and Windsurf (now Devin Desktop) can restrict which extensions
load with the ``AllowedExtensions`` policy and the matching user setting
``extensions.allowed``.  The policy overrides the setting at every level, so an
allowlist that lives only in the user's ``settings.json`` is a default the user
can change, not a control.  This module reports, per installed editor:

* EXTPOL-001 (INFO) — inventory of an allowlist that IS enforced by policy
  (which source), with the entry count and shape (publishers only, specific
  extension IDs, version lists).  Not scored and kept out of ``check``'s verdict
  (``scoring.INVENTORY_ONLY_IDS``).  Nothing is reported for an editor with no
  allowlist, or whose policy location the vendor does not document ("policy
  location not documented; not read" is shown inside EXTPOL-002 when it applies)
  — no finding is the answer for "nothing found".
* EXTPOL-002 (LOW) — ``extensions.allowed`` set only in the user's settings, with
  no documented policy source found.
* EXTPOL-003 (LOW) — an enforced allowlist that allows everything (``"*": true``).

Locations are exactly the ones the vendors document; nothing else is read or
guessed:

* VS Code, https://code.visualstudio.com/docs/enterprise/policies — Windows
  registry ``Software\\Policies\\Microsoft\\VSCode`` (computer or user
  configuration; computer wins), Linux ``/etc/vscode/policy.json`` (VS Code
  1.106+); the macOS profile domain is not named.
* Cursor, https://docs.cursor.com/account/teams/enterprise-settings —
  ``AllowedExtensions`` (Cursor 1.2+) through Windows Group Policy and macOS
  profiles; registry path and macOS domain are not documented; Linux is not
  supported.
* Windsurf / Devin Desktop, https://docs.devin.ai/desktop/enterprise-policies —
  Windows ``Software\\Policies\\Windsurf\\Devin``, Linux ``/etc/vscode/policy.json``
  (shared with VS Code); the macOS domain is not named.  The page does not name
  the registry hive; as for VS Code both policy hives (computer, then user) are
  read.

Read-only and offline: files are read with a 1 MiB cap, the registry through
``policy_sources`` (``KEY_READ`` only), nothing is executed or written.  How the
vendors interpret the entries (version lists, ``false`` values, publisher
matching) is not stated on those pages, so the shape is counted, never
interpreted.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

from mcp_audit.extensions import discovery
from mcp_audit.models import Finding, Severity
from mcp_audit.policy_sources import (
    MAX_VALUE_BYTES,
    PlatformSources,
    default_platform_sources,
)

ANALYZER = "extension_policy"
_SERVER = "extension-policy"

LINUX_POLICY_FILE = Path("/etc/vscode/policy.json")
POLICY_NAME = "AllowedExtensions"
SETTING_NAME = "extensions.allowed"

DOCS = {
    "vscode": "https://code.visualstudio.com/docs/enterprise/policies",
    "cursor": "https://docs.cursor.com/account/teams/enterprise-settings",
    "windsurf": "https://docs.devin.ai/desktop/enterprise-policies",
}
DISPLAY = {"vscode": "VS Code", "cursor": "Cursor", "windsurf": "Windsurf"}
# User-data directory name under the OS application-data location.
_USER_DIR = {"vscode": "Code", "cursor": "Cursor", "windsurf": "Windsurf"}
# Windows registry subkey per editor; ``None`` = the docs do not name one.
_REGISTRY_KEY: dict[str, str | None] = {
    "vscode": "Software\\Policies\\Microsoft\\VSCode",
    "cursor": None,
    "windsurf": "Software\\Policies\\Windsurf\\Devin",
}
_LINUX_FILE = {"vscode": True, "cursor": False, "windsurf": True}

NOT_DOCUMENTED = "policy location not documented; not read"
CURSOR_LINUX = "Linux policy not supported (Cursor docs)"


@dataclass(frozen=True)
class Environment:
    """Where to look; injectable so tests run anywhere.

    Attributes:
        home: The user's home directory.
        platform: ``sys.platform`` value.
        appdata: ``%APPDATA%`` (Windows).
        userprofile: ``%USERPROFILE%`` (Windows).
        sources: Registry reader for Windows policy.
        linux_policy_file: The Linux policy file (``/etc/vscode/policy.json``).
    """

    home: Path
    platform: str
    appdata: str | None
    userprofile: str | None
    sources: PlatformSources
    linux_policy_file: Path = LINUX_POLICY_FILE


def default_environment() -> Environment:
    """The real machine (patched out in the test suite's conftest)."""
    import os  # noqa: PLC0415

    return Environment(
        home=Path.home(),
        platform=sys.platform,
        appdata=os.environ.get("APPDATA"),
        userprofile=os.environ.get("USERPROFILE"),
        sources=default_platform_sources(),
    )


@dataclass(frozen=True)
class Shape:
    """What an allowlist's entries look like (counted, not interpreted)."""

    entries: int
    publishers: int
    extension_ids: int
    version_lists: int
    wildcard: bool
    wildcard_value: object | None
    false_entries: int

    def describe(self) -> str:
        """One-line summary, e.g. ``3 entries: 2 publishers, 1 extension ID``."""
        if self.entries == 0:
            return "0 entries (empty)"
        bits = []
        if self.wildcard:
            bits.append('a "*" entry')
        if self.publishers:
            bits.append(f"{self.publishers} publisher" + _s(self.publishers))
        if self.extension_ids:
            bits.append(
                f"{self.extension_ids} specific extension ID" + _s(self.extension_ids)
            )
        if self.version_lists:
            bits.append(f"{self.version_lists} with version lists")
        if self.false_entries:
            bits.append(f"{self.false_entries} set to false")
        return (
            f"{self.entries} entr{'y' if self.entries == 1 else 'ies'}: "
            + ", ".join(bits)
        )


def _s(n: int) -> str:
    return "" if n == 1 else "s"


def allowlist_shape(value: dict) -> Shape:
    """Count the entry kinds of an allowlist object.

    A key with a dot is an extension ID (``publisher.name``), ``*`` is the
    wildcard, any other key a publisher; a list value is a version list.
    """
    publishers = ids = versions = false = 0
    wildcard = False
    wildcard_value: object | None = None
    for key, val in value.items():
        if key == "*":
            wildcard, wildcard_value = True, val
        elif "." in str(key):
            ids += 1
        else:
            publishers += 1
        if isinstance(val, list):
            versions += 1
        if val is False:
            false += 1
    return Shape(len(value), publishers, ids, versions, wildcard, wildcard_value, false)


@dataclass
class EditorPolicy:
    """What mcp-audit learned about one editor's extension allowlist."""

    editor: str
    # "enforced" | "user-only" | "absent" | "unknown"
    state: str = "absent"
    source: str | None = None
    location: str | None = None
    shape: Shape | None = None
    # Why a policy source was not read (undocumented / unsupported).
    unread: list[str] = field(default_factory=list)
    user_settings: Path | None = None
    user_shape: Shape | None = None
    problems: list[str] = field(default_factory=list)


def _read_text(path: Path, problems: list[str]) -> str | None:
    try:
        if not path.is_file():
            return None
        with path.open("rb") as handle:
            data = handle.read(MAX_VALUE_BYTES + 1)
    except OSError as exc:
        problems.append(f"{path}: cannot read ({type(exc).__name__})")
        return None
    if len(data) > MAX_VALUE_BYTES:
        problems.append(f"{path}: over the {MAX_VALUE_BYTES}-byte limit; not read")
        return None
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        problems.append(f"{path}: not UTF-8; not read")
        return None


def _allowlist_value(raw: object) -> dict | None:
    """An allowlist is a JSON object, or a string holding one (registry, plist)."""
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except (json.JSONDecodeError, RecursionError):
            return None
    return raw if isinstance(raw, dict) else None


def _user_settings_path(editor: str, env: Environment) -> Path | None:
    name = _USER_DIR[editor]
    if env.platform == "darwin":
        return (
            env.home
            / "Library"
            / "Application Support"
            / name
            / "User"
            / "settings.json"
        )
    if env.platform.startswith("win"):
        return (
            Path(env.appdata) / name / "User" / "settings.json" if env.appdata else None
        )
    return env.home / ".config" / name / "User" / "settings.json"


def _extension_dirs(editor: str, env: Environment) -> list[Path]:
    """The editor's extension directories (``discovery.EXTENSION_PATHS``)."""
    paths = [
        env.home / raw[2:] if raw.startswith("~/") else Path(raw)
        for raw in discovery.EXTENSION_PATHS.get(editor, [])
    ]
    win = discovery._get_windows_paths(
        platform=env.platform, appdata=env.appdata, userprofile=env.userprofile
    )
    paths += [Path(p) for p in win.get(editor, [])]
    return paths


def editor_installed(editor: str, env: Environment) -> bool:
    """True when an extension directory or the user settings directory exists."""
    try:
        if any(p.is_dir() for p in _extension_dirs(editor, env)):
            return True
        settings = _user_settings_path(editor, env)
        return settings is not None and settings.parent.is_dir()
    except OSError:
        return False


def _registry_policy(editor: str, env: Environment, out: EditorPolicy) -> None:
    key = _REGISTRY_KEY[editor]
    reader = env.sources.registry
    if reader is None or key is None:
        return
    for hive, label in (("HKLM", "computer"), ("HKCU", "user")):
        read = reader(hive, key, POLICY_NAME)
        if not read.found:
            continue
        location = f"{hive}\\{key}\\{POLICY_NAME}"
        if read.text is None:
            out.problems.append(f"{location}: {read.problem}")
            continue
        value = _allowlist_value(read.text)
        if value is None:
            out.problems.append(f"{location}: not a JSON object")
            out.state, out.source, out.location = (
                "enforced",
                f"Windows registry policy ({hive}, {label} configuration)",
                location,
            )
            return
        out.state = "enforced"
        out.source = f"Windows registry policy ({hive}, {label} configuration)"
        out.location = location
        out.shape = allowlist_shape(value)
        return  # computer wins over user


def _linux_policy(env: Environment, out: EditorPolicy) -> None:
    path = env.linux_policy_file
    text = _read_text(path, out.problems)
    if text is None:
        return
    try:
        doc = json.loads(text)
    except (json.JSONDecodeError, RecursionError):
        out.problems.append(f"{path}: not valid JSON")
        return
    if not isinstance(doc, dict) or POLICY_NAME not in doc:
        return
    out.state = "enforced"
    out.source = "Linux policy file"
    out.location = str(path)
    value = _allowlist_value(doc[POLICY_NAME])
    if value is None:
        out.problems.append(f"{path}: {POLICY_NAME} is not a JSON object")
    else:
        out.shape = allowlist_shape(value)


def read_editor_policy(editor: str, env: Environment) -> EditorPolicy:
    """Determine one editor's allowlist state from the documented locations."""
    out = EditorPolicy(editor)
    plat = env.platform
    if plat.startswith("win"):
        if _REGISTRY_KEY[editor] is None:
            out.unread.append(NOT_DOCUMENTED)
        else:
            _registry_policy(editor, env, out)
    elif plat == "darwin":
        out.unread.append(NOT_DOCUMENTED)
    elif _LINUX_FILE[editor]:
        _linux_policy(env, out)
    else:
        out.unread.append(CURSOR_LINUX)

    settings = _user_settings_path(editor, env)
    if settings is not None:
        text = _read_text(settings, out.problems)
        if text is not None:
            from mcp_audit.analyzers.config_hygiene import parse_jsonc  # noqa: PLC0415

            parsed = parse_jsonc(text)
            if not isinstance(parsed, dict):
                out.problems.append(f"{settings}: not valid JSONC; not read")
            elif SETTING_NAME in parsed:
                out.user_settings = settings
                value = _allowlist_value(parsed[SETTING_NAME])
                if value is None:
                    out.problems.append(f"{settings}: {SETTING_NAME} is not an object")
                else:
                    out.user_shape = allowlist_shape(value)
    if out.state != "enforced":
        if out.user_shape is not None:
            out.state = "user-only"
        elif out.unread:
            out.state = "unknown"
    return out


def _finding(
    fid: str,
    severity: Severity,
    pol: EditorPolicy,
    title: str,
    description: str,
    evidence: str,
    remediation: str,
    path: str | None,
    owasp: list[str],
    cwe: str,
) -> Finding:
    return Finding(
        id=fid,
        severity=severity,
        analyzer=ANALYZER,
        client=pol.editor,
        server=_SERVER,
        title=title,
        description=description,
        evidence=evidence,
        remediation=remediation,
        cwe=cwe,
        finding_path=path,
        owasp_mcp_top_10=owasp,
    )


def _state_text(pol: EditorPolicy) -> str:
    if pol.state == "enforced":
        return f"enforced ({pol.source})"
    if pol.state == "user-only":
        return "set only in the user's settings.json (not enforced)"
    if pol.state == "unknown":
        return "not determined"
    return "absent"


def _inventory(pol: EditorPolicy) -> Finding:
    name = DISPLAY[pol.editor]
    shape = pol.shape or pol.user_shape
    parts = [f"allowlist state: {_state_text(pol)}"]
    if pol.state == "enforced" and pol.shape is not None:
        parts.append(f"policy {POLICY_NAME}: {pol.shape.describe()}")
    elif pol.state == "enforced":
        parts.append(f"policy {POLICY_NAME} could not be read as an object")
    if pol.user_shape is not None:
        parts.append(f"user setting {SETTING_NAME}: {pol.user_shape.describe()}")
    parts.extend(pol.unread)
    parts.extend(pol.problems)
    evidence_bits = [f"editor: {pol.editor}", f"state: {_state_text(pol)}"]
    if pol.location:
        evidence_bits.append(f"policy: {pol.location}")
    if pol.user_settings:
        evidence_bits.append(f"settings: {pol.user_settings}")
    if shape is not None:
        evidence_bits.append(f"shape: {shape.describe()}")
    evidence_bits.extend(pol.unread)
    return _finding(
        "EXTPOL-001",
        Severity.INFO,
        pol,
        f"{name} extension allowlist: {_state_text(pol)}",
        f"{name} extension allowlist ({POLICY_NAME} policy, {SETTING_NAME}"
        " setting): "
        + "; ".join(parts)
        + ". The policy overrides the setting at every level. Entry shape is"
        " counted, not interpreted: how each vendor matches publishers, extension"
        " IDs and version lists is not stated on its policy page. Reference: "
        + DOCS[pol.editor],
        " | ".join(evidence_bits),
        "Confirm this is the allowlist your organization intends. To enforce one,"
        f" deploy {POLICY_NAME} through the editor's policy mechanism"
        f" ({DOCS[pol.editor]}).",
        pol.location or (str(pol.user_settings) if pol.user_settings else None),
        ["MCP04"],
        "CWE-1188",
    )


def _user_only(pol: EditorPolicy) -> Finding:
    name = DISPLAY[pol.editor]
    assert pol.user_shape is not None  # noqa: S101
    caveat = (
        f" mcp-audit could not look for a policy: {'; '.join(pol.unread)}, so a"
        " policy delivered that way would not be seen."
        if pol.unread
        else ""
    )
    return _finding(
        "EXTPOL-002",
        Severity.LOW,
        pol,
        f"{name} extension allowlist is set only in user settings",
        f"{name}'s {SETTING_NAME} is set in {pol.user_settings} "
        f"({pol.user_shape.describe()}) and no {POLICY_NAME} policy was found at"
        " a documented location. A setting in the user's own settings.json is a"
        " default the user (or anything that writes the file) can change; only"
        f" the {POLICY_NAME} policy overrides it at every level, so this list is"
        " set, not enforced." + caveat,
        f"editor: {pol.editor} | settings: {pol.user_settings} | "
        f"shape: {pol.user_shape.describe()}"
        + (" | " + "; ".join(pol.unread) if pol.unread else ""),
        f"Deploy the allowlist as the {POLICY_NAME} policy (Group Policy, MDM or"
        f" the Linux policy file). Reference: {DOCS[pol.editor]}",
        str(pol.user_settings),
        ["MCP04"],
        "CWE-284",
    )


def _allow_all(pol: EditorPolicy) -> Finding:
    name = DISPLAY[pol.editor]
    assert pol.shape is not None  # noqa: S101
    return _finding(
        "EXTPOL-003",
        Severity.LOW,
        pol,
        f"{name} extension allowlist policy allows everything",
        f"The enforced {POLICY_NAME} policy for {name} ({pol.source}) contains"
        ' "*": true, which allows every extension, so the policy is on but'
        " restricts nothing.",
        f"editor: {pol.editor} | policy: {pol.location} | "
        f"shape: {pol.shape.describe()}",
        'Replace "*": true with the publishers or extensions your organization'
        f" approves. Reference: {DOCS[pol.editor]}",
        pol.location,
        ["MCP04"],
        "CWE-284",
    )


def analyze_editor_policy(pol: EditorPolicy) -> list[Finding]:
    """EXTPOL findings for one editor's :class:`EditorPolicy`.

    Silent for ``absent`` and ``unknown`` (policy location not documented or
    unsupported): almost every developer machine has no allowlist, and "nothing
    found" is not a finding.  An *enforced* allowlist gets the EXTPOL-001
    inventory (plus EXTPOL-003 when it allows everything); an allowlist set only
    in user settings gets EXTPOL-002.
    """
    if pol.state == "user-only":
        return [_user_only(pol)]
    if pol.state != "enforced":
        return []
    out = [_inventory(pol)]
    if (
        pol.shape is not None
        and pol.shape.wildcard
        and pol.shape.wildcard_value is True
    ):
        out.append(_allow_all(pol))
    return out


def extension_policy_findings(
    errors: list[str], env: Environment | None = None
) -> list[Finding]:
    """EXTPOL-001..003 for every editor that is installed; never raises.

    The entry point for ``scan`` / ``check`` (``scanner._discover_and_parse``).
    An editor that is not installed produces nothing.  Read problems go to
    *errors*; a crash is reported there and yields no findings.
    """
    try:
        environment = env if env is not None else default_environment()
        findings: list[Finding] = []
        for editor in ("vscode", "cursor", "windsurf"):
            if not editor_installed(editor, environment):
                continue
            pol = read_editor_policy(editor, environment)
            errors.extend(f"extension policy ({editor}): {p}" for p in pol.problems)
            findings.extend(analyze_editor_policy(pol))
        return findings
    except Exception as exc:  # noqa: BLE001 — never fail the scan over policy files
        errors.append(f"extension policy check error: {type(exc).__name__}: {exc}")
        return []
