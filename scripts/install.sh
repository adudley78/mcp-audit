#!/bin/bash
set -euo pipefail

VERSION="0.1.0"
BASE_URL="https://github.com/adudley78/mcp-audit/releases/download/v${VERSION}"

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

# Normalize arch names to match PyInstaller output naming
case "$ARCH" in
    aarch64) ARCH="arm64" ;;
    amd64)   ARCH="x86_64" ;;
esac

BINARY="mcp-audit-${OS}-${ARCH}"
DEST="/usr/local/bin/mcp-audit"

echo "Downloading mcp-audit ${VERSION} for ${OS}/${ARCH}..."
curl -sSL "${BASE_URL}/${BINARY}" -o "${DEST}"
chmod +x "${DEST}"

echo "Installed mcp-audit to ${DEST}"
mcp-audit version
