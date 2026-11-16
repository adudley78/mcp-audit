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
DEST="/usr/local/bin/credenzo"

echo "Downloading Credenzo ${VERSION} for ${OS}/${ARCH}..."
curl -sSL "${BASE_URL}/${BINARY}" -o "${DEST}"
chmod +x "${DEST}"

# The old command name continues to work.
ln -sf "${DEST}" /usr/local/bin/mcp-audit

echo "Installed credenzo to ${DEST}"
credenzo version
