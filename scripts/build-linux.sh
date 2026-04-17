#!/usr/bin/env bash
# Build a standalone Linux x86_64 mcp-audit binary using Docker + PyInstaller.
#
# Usage:  bash scripts/build-linux.sh
# Output: dist/mcp-audit-linux-x86_64
#
# Requirements: Docker must be installed and the daemon must be running.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="python:3.11-slim"
BINARY_NAME="mcp-audit-linux-x86_64"
BINARY_PATH="${REPO_ROOT}/dist/${BINARY_NAME}"

# ── helpers ──────────────────────────────────────────────────────────────────

die() {
    echo ""
    echo "ERROR: $*" >&2
    exit 1
}

step() {
    echo ""
    echo "==> $*"
}

# ── preflight checks ─────────────────────────────────────────────────────────

command -v docker &>/dev/null \
    || die "Docker is not installed or not in PATH"

docker info &>/dev/null 2>&1 \
    || die "Docker daemon is not running — start Docker and retry"

# ── pull base image ───────────────────────────────────────────────────────────

step "Pulling ${IMAGE} (no-op if already cached)"
docker pull "${IMAGE}" \
    || die "Failed to pull ${IMAGE}"

# ── build inside container ────────────────────────────────────────────────────

step "Building ${BINARY_NAME} inside Docker (linux/amd64)"
docker run --rm \
    --platform linux/amd64 \
    -v "${REPO_ROOT}:/app" \
    -w /app \
    "${IMAGE}" \
    bash -c '
        set -euo pipefail

        echo "--- Installing system dependencies ---"
        apt-get update -qq \
            && apt-get install -y --no-install-recommends binutils \
            && rm -rf /var/lib/apt/lists/* \
            || { echo "ERROR: apt-get install failed" >&2; exit 1; }

        echo "--- Installing build toolchain ---"
        pip install --quiet --no-cache-dir pyinstaller \
            || { echo "ERROR: pip install pyinstaller failed" >&2; exit 1; }

        echo "--- Installing project dependencies ---"
        pip install --quiet --no-cache-dir -e /app \
            || { echo "ERROR: pip install -e /app failed" >&2; exit 1; }

        echo "--- Running PyInstaller build ---"
        python /app/build.py \
            || { echo "ERROR: build.py failed" >&2; exit 1; }
    ' || die "Docker build step failed"

# ── verify output ─────────────────────────────────────────────────────────────

[[ -f "${BINARY_PATH}" ]] \
    || die "Expected binary not found at ${BINARY_PATH} — check Docker build logs above"

step "Build complete"
echo "    Binary : ${BINARY_PATH}"

# File size — du -sh works on macOS and Linux
SIZE=$(du -sh "${BINARY_PATH}" | cut -f1)
echo "    Size   : ${SIZE}"

# SHA-256 — sha256sum on Linux, shasum on macOS
if command -v sha256sum &>/dev/null; then
    SHA256=$(sha256sum "${BINARY_PATH}" | awk '{print $1}')
else
    SHA256=$(shasum -a 256 "${BINARY_PATH}" | awk '{print $1}')
fi
echo "    SHA-256: ${SHA256}"
