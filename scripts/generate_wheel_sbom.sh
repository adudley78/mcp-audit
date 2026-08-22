#!/usr/bin/env bash
# Generate mcp-audit-scanner-wheel.cdx.json from a built wheel.
#
# Installs the wheel into a throwaway venv so the SBOM is the default extra
# set (not --all-extras, not the PyInstaller PYZ). Filename contains "wheel"
# so it cannot be mistaken for a binary SBOM.
#
# Usage (repo root):
#   scripts/generate_wheel_sbom.sh dist/mcp_audit_scanner-*.whl dist/mcp-audit-scanner-wheel.cdx.json
set -euo pipefail

if [ "$#" -lt 2 ]; then
  echo "usage: $0 <wheel.whl> <output.cdx.json>" >&2
  exit 2
fi

WHEEL=$1
OUT=$2
ROOT=$(cd "$(dirname "$0")/.." && pwd)
SCHEMA="$ROOT/tests/fixtures/cyclonedx-1.5.schema.json"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

uv venv --python "${UV_PYTHON:-3.12.14}" "$TMP/venv"
if [ -x "$TMP/venv/bin/python" ]; then
  PY="$TMP/venv/bin/python"
else
  PY="$TMP/venv/Scripts/python.exe"
fi
uv pip install "$WHEEL" --python "$PY"
"$PY" "$ROOT/scripts/generate_release_sbom.py" \
  --from-environment \
  --name mcp-audit-scanner \
  --output "$OUT" \
  --require reportlab,pydantic,typer
uv run --with jsonschema python "$ROOT/scripts/generate_release_sbom.py" \
  --check "$OUT" \
  --schema "$SCHEMA" \
  --require reportlab,pydantic,typer
