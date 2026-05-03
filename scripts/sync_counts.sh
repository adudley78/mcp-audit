#!/usr/bin/env bash
# Pre-commit wrapper: run update_test_count.py inside the uv-managed project
# venv so that pytest and pyyaml are always available.
#
# Include the [attestation] extra so the collected test count matches the
# CI "test-all-extras" job, which installs [dev,sbom,attestation,mcp].
# Without [attestation] uv collects 1682 tests; with it the count is 1716.
set -e
exec uv run --extra dev --extra attestation python scripts/update_test_count.py "$@"
