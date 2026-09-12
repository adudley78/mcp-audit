#!/bin/bash
# demo/lock/run.sh — reproducible demo of `mcp-audit lock`:
#   lock -> one-line drift -> `lock --verify` fails (LOCK-001) -> `lock --accept`
#   -> `lock --verify` passes.
#
# Requires network: `mcp-audit lock` resolves each server's package version
# against the npm registry. Run with MCP_AUDIT_DEMO_NETWORK=1 in CI
# (tests/test_demo_lock.py gates on the same variable). See docs/lock.md.
#
# Exit codes are asserted at every step below, not eyeballed.

set -euo pipefail

DEMO_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG="$DEMO_DIR/.cursor/mcp.json"
LOCK_FILE="$DEMO_DIR/mcp-lock.json"
BACKUP_CONFIG="$(mktemp)"

# Detect how to invoke mcp-audit (installed globally vs. development venv).
if command -v mcp-audit >/dev/null 2>&1; then
    MCP_AUDIT="mcp-audit"
elif command -v uv >/dev/null 2>&1 && uv run mcp-audit --help >/dev/null 2>&1; then
    MCP_AUDIT="uv run mcp-audit"
else
    echo "Error: mcp-audit not found."
    echo "  Install globally: pip install mcp-audit-scanner"
    echo "  Dev mode:         uv sync --all-extras  (then re-run this script)"
    exit 1
fi

cp "$CONFIG" "$BACKUP_CONFIG"

# ALWAYS restore the fixture and remove the generated lock file, on any exit
# path (success, assertion failure, or the early "needs network" exit).
cleanup() {
    cp "$BACKUP_CONFIG" "$CONFIG"
    rm -f "$BACKUP_CONFIG" "$LOCK_FILE"
}
trap cleanup EXIT

echo "=== a. mcp-audit lock demo/lock ==="
$MCP_AUDIT lock "$DEMO_DIR"

if [ ! -f "$LOCK_FILE" ]; then
    echo "FAIL: $LOCK_FILE was not written by 'mcp-audit lock'" >&2
    exit 1
fi

# An offline (or network-degraded) resolution writes package.source ==
# "unresolved" instead of "registry"/"known_hashes". Asserting drift on an
# unresolved lock would lie about what the demo is showing (R56 makes an
# unresolved entry fail --verify for a *different* reason than drift) — so
# stop here with a distinct, honest message instead of continuing to step b.
if python3 -c "
import json, sys
with open('$LOCK_FILE') as f:
    doc = json.load(f)
unresolved = any(
    (entry.get('package') or {}).get('source') == 'unresolved'
    for entry in doc.get('servers', {}).values()
)
sys.exit(0 if unresolved else 1)
"; then
    echo "demo/lock needs network to resolve package versions"
    exit 2
fi

echo ""
echo "=== b. edit demo/lock/.cursor/mcp.json (notion package spec) ==="
# python3, not sed -i: identical behavior on macOS (BSD sed) and Linux (GNU sed).
python3 - "$CONFIG" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as f:
    data = json.load(f)
data["mcpServers"]["notion"]["args"][-1] += "@1.0.0"
with open(path, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)
    f.write("\n")
PY
cat "$CONFIG"

echo ""
echo "=== c. mcp-audit lock --verify demo/lock (expect exit 1 on drift) ==="
set +e
VERIFY_OUTPUT="$($MCP_AUDIT lock --verify "$DEMO_DIR" 2>&1)"
VERIFY_EXIT=$?
set -e
echo "$VERIFY_OUTPUT"

if [ "$VERIFY_EXIT" -ne 1 ]; then
    echo "FAIL: expected exit 1 from 'lock --verify' after drift, got $VERIFY_EXIT" >&2
    exit 1
fi

LOCK001_COUNT=$(printf '%s\n' "$VERIFY_OUTPUT" | grep -o "LOCK-001" | wc -l | tr -d ' ')
if [ "$LOCK001_COUNT" -ne 1 ]; then
    echo "FAIL: expected exactly one LOCK-001, found $LOCK001_COUNT" >&2
    exit 1
fi
if printf '%s\n' "$VERIFY_OUTPUT" | grep -q "LOCK-002"; then
    echo "FAIL: unexpected LOCK-002 in output" >&2
    exit 1
fi
if printf '%s\n' "$VERIFY_OUTPUT" | grep -q "LOCK-005"; then
    echo "FAIL: unexpected LOCK-005 in output" >&2
    exit 1
fi

echo ""
echo "=== d. mcp-audit lock --accept demo/lock (expect exit 0) ==="
$MCP_AUDIT lock --accept "$DEMO_DIR"

echo ""
echo "=== e. mcp-audit lock --verify demo/lock (expect exit 0) ==="
$MCP_AUDIT lock --verify "$DEMO_DIR"

echo ""
echo "demo/lock: PASS"
