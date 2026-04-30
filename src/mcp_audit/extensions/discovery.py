"""Discover installed IDE extensions across supported AI coding clients.

Only paths confirmed present on macOS (from environment probe 2026-04-16):
  - ~/.vscode/extensions        (VS Code)
  - ~/.cursor/extensions        (Cursor)

Windsurf and Augment paths are included for portability but were not found
on the probe machine.

Windows paths are gated behind ``sys.platform == "win32"`` and resolved
from the ``APPDATA`` and ``USERPROFILE`` environment variables at call time
via :func:`_get_windows_paths`.  If an environment variable is absent the
corresponding paths are silently skipped — same behaviour as a non-existent
macOS directory.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

from mcp_audit.extensions.models import ExtensionManifest

# Map client name → candidate extension directories (macOS / Linux).
# Path.expanduser() is called at runtime, not at module load.
# Windows paths are merged in dynamically by _get_windows_paths() so that
# monkeypatching sys.platform / os.environ in tests works correctly.
EXTENSION_PATHS: dict[str, list[str]] = {
    "vscode": [
        "~/.vscode/extensions",
        "~/.vscode-server/extensions",
    ],
    "cursor": [
        "~/.cursor/extensions",
        "~/.cursor-server/extensions",
    ],
    "windsurf": [
        "~/.windsurf/extensions",
        "~/Library/Application Support/Windsurf/extensions",
        "~/.config/windsurf/extensions",
    ],
    "augment": [
        "~/.augment/extensions",
        "~/Library/Application Support/Augment/extensions",
    ],
}


def _get_windows_paths() -> dict[str, list[str]]:
    """Return Windows extension paths resolved from environment variables.

    Called at runtime inside :func:`discover_extensions` so that
    monkeypatching ``sys.platform`` and ``os.environ`` in tests takes effect
    correctly.  Returns an empty dict on non-Windows platforms or when a
    required environment variable is absent — the caller skips missing paths
    silently (same as non-existent macOS directories).

    Clients covered (mirrors the macOS/Linux entries in :data:`EXTENSION_PATHS`):

    - ``vscode``: ``%APPDATA%\\Code\\extensions`` and
      ``%APPDATA%\\Code - Insiders\\extensions``
    - ``cursor``: ``%USERPROFILE%\\.cursor\\extensions``
    - ``windsurf``: ``%USERPROFILE%\\.windsurf\\extensions``
    """
    if sys.platform != "win32":
        return {}

    result: dict[str, list[str]] = {}
    appdata = os.environ.get("APPDATA")
    userprofile = os.environ.get("USERPROFILE")

    if appdata:
        result["vscode"] = [
            str(Path(appdata) / "Code" / "extensions"),
            str(Path(appdata) / "Code - Insiders" / "extensions"),
        ]

    if userprofile:
        result["cursor"] = [str(Path(userprofile) / ".cursor" / "extensions")]
        result["windsurf"] = [str(Path(userprofile) / ".windsurf" / "extensions")]

    return result


def discover_extensions(
    clients: list[str] | None = None,
    extra_paths: dict[str, list[str]] | None = None,
) -> list[ExtensionManifest]:
    """Discover installed IDE extensions across supported clients.

    Args:
        clients: Client names to probe.  ``None`` probes all known clients.
        extra_paths: Additional paths keyed by client name (merged with
            :data:`EXTENSION_PATHS`).

    Returns:
        List of :class:`ExtensionManifest` objects, one per installed
        extension.  The same extension may appear multiple times if installed
        in more than one client — both instances are returned.
    """
    effective_paths: dict[str, list[str]] = dict(EXTENSION_PATHS)

    # Merge in Windows-specific paths (no-op on macOS / Linux).
    for client, win_paths in _get_windows_paths().items():
        effective_paths[client] = effective_paths.get(client, []) + win_paths

    if extra_paths:
        for client, paths in extra_paths.items():
            if client in effective_paths:
                effective_paths[client] = effective_paths[client] + paths
            else:
                effective_paths[client] = paths

    target_clients = list(effective_paths.keys()) if clients is None else clients
    results: list[ExtensionManifest] = []
    seen_install_paths: set[str] = set()

    for client in target_clients:
        candidate_dirs = effective_paths.get(client, [])
        for raw_dir in candidate_dirs:
            ext_dir = Path(raw_dir).expanduser()
            if not ext_dir.is_dir():
                continue
            for subdir in ext_dir.iterdir():
                if not subdir.is_dir():
                    continue
                pkg_json = subdir / "package.json"
                if not pkg_json.is_file():
                    continue
                install_path_str = str(subdir.resolve())
                if install_path_str in seen_install_paths:
                    continue
                manifest = parse_manifest(pkg_json, client)
                if manifest is not None:
                    seen_install_paths.add(install_path_str)
                    results.append(manifest)

    return results


def parse_manifest(
    package_json_path: Path,
    client_name: str,
) -> ExtensionManifest | None:
    """Parse a single extension ``package.json`` into an :class:`ExtensionManifest`.

    Returns ``None`` on any parse error (missing required fields, invalid JSON,
    Pydantic validation failure).  Never raises.

    Extension ID is constructed as ``"{publisher}.{name}"`` from the manifest
    fields.  Falls back to the parent directory name when those fields are
    absent.
    """
    try:
        raw = package_json_path.read_text(encoding="utf-8")
        data = json.loads(raw)
    except Exception:  # noqa: BLE001
        return None

    if not isinstance(data, dict):
        return None

    # Derive extension_id
    publisher = data.get("publisher", "")
    name = data.get("name", "")
    if publisher and name:
        extension_id = f"{publisher}.{name}"
    else:
        # Fallback: use the directory name (e.g. "publisher.name-1.0.0")
        dir_name = package_json_path.parent.name
        # Strip trailing "-<version>" if present
        parts = dir_name.rsplit("-", 1)
        extension_id = parts[0] if len(parts) == 2 else dir_name
        if not publisher:
            publisher = extension_id.split(".")[0] if "." in extension_id else "unknown"
        if not name:
            name = (
                extension_id.split(".", 1)[1] if "." in extension_id else extension_id
            )

    if not data.get("version"):
        return None

    # mtime → ISO string
    try:
        mtime = package_json_path.stat().st_mtime
        last_updated: str | None = datetime.fromtimestamp(mtime, tz=UTC).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
    except Exception:  # noqa: BLE001
        last_updated = None

    try:
        return ExtensionManifest(
            extension_id=extension_id,
            name=name,
            display_name=data.get("displayName"),
            publisher=publisher,
            version=str(data.get("version", "")),
            description=data.get("description"),
            engines=(
                data.get("engines") if isinstance(data.get("engines"), dict) else {}
            ),
            activation_events=(
                data.get("activationEvents", [])
                if isinstance(data.get("activationEvents"), list)
                else []
            ),
            contributes=(
                data.get("contributes")
                if isinstance(data.get("contributes"), dict)
                else {}
            ),
            extension_dependencies=data.get("extensionDependencies", [])
            if isinstance(data.get("extensionDependencies"), list)
            else [],
            keywords=data.get("keywords", [])
            if isinstance(data.get("keywords"), list)
            else [],
            categories=data.get("categories", [])
            if isinstance(data.get("categories"), list)
            else [],
            client_name=client_name,
            manifest_path=str(package_json_path.resolve()),
            install_path=str(package_json_path.parent.resolve()),
            last_updated=last_updated,
        )
    except Exception:  # noqa: BLE001
        return None
