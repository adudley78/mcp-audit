#!/usr/bin/env bash
# Pre-commit wrapper: run update_test_count.py inside the uv-managed project
# venv so that pytest and pyyaml are always available.
set -e
exec uv run python scripts/update_test_count.py "$@"
