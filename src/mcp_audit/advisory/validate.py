"""Validation of advisory records against the vendored OSV 1.6.0 JSON schema.

The schema is vendored (``advisory/osv_schema/osv-1.6.0.json``) rather than fetched,
so validation works offline, inside the PyInstaller binary, and — most importantly —
against a fixed version. A feed that silently starts failing because upstream edited
their schema in place is worse than one that fails loudly when we bump the pin.

``jsonschema`` is a dev dependency, not a runtime one: publishing a feed does not
require it, only checking one does. :func:`validate_osv` raises a clear
:class:`ValidationUnavailableError` rather than crashing when it is absent.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from mcp_audit._paths import resolve_bundled_resource

__all__ = [
    "OSV_SCHEMA_VERSION",
    "ValidationUnavailableError",
    "load_osv_schema",
    "osv_schema_path",
    "validate_osv",
]

OSV_SCHEMA_VERSION = "1.6.0"
_SCHEMA_FILENAME = f"osv-{OSV_SCHEMA_VERSION}.json"

_DEV_FALLBACK = Path(__file__).parent / "osv_schema" / _SCHEMA_FILENAME


class ValidationUnavailableError(RuntimeError):
    """The ``jsonschema`` package is not installed, so validation cannot run."""


def osv_schema_path() -> Path:
    """Return the path to the vendored OSV schema.

    Raises:
        FileNotFoundError: The schema is missing from this installation.
    """
    resolved = resolve_bundled_resource(
        package="mcp_audit.advisory",
        subdir=f"osv_schema/{_SCHEMA_FILENAME}",
        frozen_subpath=f"mcp_audit/advisory/osv_schema/{_SCHEMA_FILENAME}",
        dev_fallback=_DEV_FALLBACK,
    )
    if resolved is None:
        raise FileNotFoundError(
            f"Vendored OSV schema {_SCHEMA_FILENAME} not found in this installation"
        )
    return resolved


@lru_cache(maxsize=1)
def load_osv_schema() -> dict:
    """Return the parsed OSV 1.6.0 JSON schema."""
    return json.loads(osv_schema_path().read_text(encoding="utf-8"))


def validate_osv(record: dict) -> None:
    """Validate one OSV record against the vendored schema.

    Args:
        record: The output of :meth:`~mcp_audit.advisory.schema.Advisory.to_osv`.

    Raises:
        ValidationUnavailableError: ``jsonschema`` is not installed.
        jsonschema.ValidationError: The record does not conform.
    """
    try:
        import jsonschema  # noqa: PLC0415 — optional dev dependency, imported lazily
    except ModuleNotFoundError as exc:  # pragma: no cover - depends on install extras
        raise ValidationUnavailableError(
            "OSV validation requires the 'jsonschema' package: "
            "pip install 'mcp-audit-scanner[dev]'"
        ) from exc

    jsonschema.validate(instance=record, schema=load_osv_schema())
