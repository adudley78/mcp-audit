#!/bin/bash
# mcp-audit demo — runs every command against the demo config directory
# and writes SARIF, JSON, and Nucleus output to demo/output/.
#
# mcp-audit scan exits with code 1 when findings are found, so each scan
# command is followed by "|| true" to let the script continue.

DEMO_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIGS="$DEMO_DIR/configs"
OUTPUT="$DEMO_DIR/output"

mkdir -p "$OUTPUT"

# Detect how to invoke mcp-audit (installed globally vs. development venv).
if command -v mcp-audit >/dev/null 2>&1; then
    MCP_AUDIT="mcp-audit"
elif command -v uv >/dev/null 2>&1 && uv run mcp-audit --help >/dev/null 2>&1; then
    MCP_AUDIT="uv run mcp-audit"
else
    echo "Error: mcp-audit not found."
    echo "  Install globally: pip install mcp-audit"
    echo "  Dev mode:         uv sync --all-extras  (then re-run this script)"
    exit 1
fi

echo "========================================"
echo "  mcp-audit Demo Environment"
echo "========================================"
echo ""
echo "Config directory: $CONFIGS"
echo "Invoking via:     $MCP_AUDIT"
echo ""

# ── 1. Discover ───────────────────────────────────────────────────────────────
echo "--- 1. Discover configs ---"
$MCP_AUDIT discover --path "$CONFIGS"
echo ""

# ── 2. Full scan (terminal output) ───────────────────────────────────────────
echo "--- 2. Full scan (terminal output) ---"
$MCP_AUDIT scan --path "$CONFIGS" || true
echo ""

# ── 3. Pin baseline ───────────────────────────────────────────────────────────
echo "--- 3. Pin baseline ---"
$MCP_AUDIT pin --path "$CONFIGS"
echo ""

# ── 4. Diff (should show no changes on first run) ────────────────────────────
echo "--- 4. Diff (no changes expected) ---"
$MCP_AUDIT diff --path "$CONFIGS"
echo ""

# ── 5. JSON output ────────────────────────────────────────────────────────────
echo "--- 5. JSON output ---"
$MCP_AUDIT scan --path "$CONFIGS" --format json --output "$OUTPUT/results.json" || true
echo "Written to $OUTPUT/results.json"
echo ""

# ── 6. SARIF output ───────────────────────────────────────────────────────────
echo "--- 6. SARIF output ---"
$MCP_AUDIT scan --path "$CONFIGS" --format sarif --output "$OUTPUT/results.sarif" || true
echo "Written to $OUTPUT/results.sarif"
echo ""

# ── 7. Nucleus FlexConnect output ─────────────────────────────────────────────
echo "--- 7. Nucleus FlexConnect output ---"
$MCP_AUDIT scan --path "$CONFIGS" --format nucleus --output "$OUTPUT/results.nucleus.json" || true
echo "Written to $OUTPUT/results.nucleus.json"
echo ""

# ── 8. CI mode (HIGH+ only, no fancy output) ──────────────────────────────────
echo "--- 8. CI mode (HIGH and CRITICAL findings only) ---"
$MCP_AUDIT scan --path "$CONFIGS" --ci --severity-threshold HIGH || true
echo ""

echo "========================================"
echo "  Demo complete."
echo "  Generated files in $OUTPUT/"
echo "========================================"
