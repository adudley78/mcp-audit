"""Data models for the IDE extension scanner."""

from __future__ import annotations

from pydantic import BaseModel, Field


class ExtensionManifest(BaseModel):
    """Parsed from an extension's package.json."""

    extension_id: str  # "{publisher}.{name}" — VS Code canonical ID
    name: str
    display_name: str | None = None
    publisher: str
    version: str
    description: str | None = None
    engines: dict[str, str] = Field(default_factory=dict)
    activation_events: list[str] = Field(default_factory=list)
    contributes: dict = Field(default_factory=dict)
    extension_dependencies: list[str] = Field(default_factory=list)
    keywords: list[str] = Field(default_factory=list)
    categories: list[str] = Field(default_factory=list)

    # Populated by discovery, not from manifest
    client_name: str = ""  # "vscode", "cursor", "windsurf", etc.
    manifest_path: str = ""  # absolute path to package.json
    install_path: str = ""  # parent directory of package.json
    last_updated: str | None = None  # mtime of manifest file, ISO format


class ExtensionVulnEntry(BaseModel):
    """Entry in known-extension-vulns.json."""

    extension_id: str  # "{publisher}.{name}"
    affected_versions: str  # semver range, e.g. "<1.2.3" or "*"
    cve: str | None = None
    severity: str  # "critical", "high", "medium", "low"
    title: str
    description: str
    reference: str | None = None
    reported_date: str | None = None
