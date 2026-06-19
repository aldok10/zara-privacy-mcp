#!/usr/bin/env bash
set -euo pipefail

# Zara Privacy MCP — Install & Integrate with OpenCode
#
# Usage:
#   ./scripts/install.sh              # Build + install binary
#   ./scripts/install.sh --http       # Launch HTTP server for testing
#   ./scripts/install.sh --check      # Verify installation
#
# This script:
#   1. Builds the zara-privacy-mcp binary
#   2. Installs it to /usr/local/bin
#   3. Creates the DB directory ~/.zara/privacymcp/
#   4. Offers to add MCP config to opencode.json

BINARY="zara-privacy-mcp"
INSTALL_DIR="/usr/local/bin"
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OPCODE_CONFIG="${PROJECT_DIR}/../../zara-agent-opc/opencode.json"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

info()  { echo -e "${GREEN}✓${NC} $1"; }
warn()  { echo -e "${YELLOW}⚠${NC} $1"; }
error() { echo -e "${RED}✗${NC} $1"; }

# ─── Build ──────────────────────────────────────────────────────────────────

build() {
    echo "🔨 Building ${BINARY}..."
    cd "$PROJECT_DIR"
    go build -ldflags="-s -w" -o "$BINARY" ./cmd/server/
    info "Build complete"
}

# ─── Install ────────────────────────────────────────────────────────────────

install_binary() {
    echo "📦 Installing to ${INSTALL_DIR}/${BINARY}..."
    install -d "$INSTALL_DIR"
    install -m 755 "$PROJECT_DIR/$BINARY" "${INSTALL_DIR}/${BINARY}"
    info "Installed ${BINARY} to ${INSTALL_DIR}/${BINARY}"

    # Create DB directory
    mkdir -p "$HOME/.zara/privacymcp"
    chmod 700 "$HOME/.zara/privacymcp"
    info "DB directory: $HOME/.zara/privacymcp/"
}

# ─── Check ──────────────────────────────────────────────────────────────────

check() {
    echo "🔍 Checking installation..."
    if command -v "${BINARY}" &>/dev/null; then
        info "${BINARY} found in PATH"
    else
        error "${BINARY} not found in PATH"
        return 1
    fi

    # Smoke test via stdio
    if echo '{"jsonrpc":"2.0","id":1,"method":"list_tools"}' | \
       "${BINARY}" --stdio 2>/dev/null | grep -q scan_context; then
        info "Stdio smoke test passed — tools responding"
    else
        error "Stdio smoke test failed"
        return 1
    fi

    info "Installation verified"
}

# ─── HTTP mode (for testing with Postman) ──────────────────────────────────

run_http() {
    echo "🌐 Starting HTTP server on 127.0.0.1:8530..."
    echo "   Postman → POST http://127.0.0.1:8530/mcp"
    echo "   Health  → GET  http://127.0.0.1:8530/health"
    echo ""
    export ZARA_ENCRYPTION_KEY="${ZARA_ENCRYPTION_KEY:-dev-key-32-bytes-long-for-testing!!}"
    "${BINARY}"
}

# ─── Main ───────────────────────────────────────────────────────────────────

main() {
    case "${1:-}" in
        --http)
            build
            install_binary
            run_http
            ;;
        --check)
            check
            ;;
        *)
            build
            install_binary
            check
            echo ""
            echo "─" 
            echo " Next steps:"
            echo "   1. Set ZARA_ENCRYPTION_KEY in your shell profile:"
            echo "      export ZARA_ENCRYPTION_KEY=\"your-strong-passphrase\""
            echo ""
            echo "   2. Add MCP config to opencode.json (see scripts/opencode-integration.md)"
            echo ""
            echo "   3. Test with Postman:"
            echo "      make run-dev"
            echo "      → POST http://127.0.0.1:8530/mcp"
            ;;
    esac
}

main "$@"
