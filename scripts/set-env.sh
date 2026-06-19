#!/usr/bin/env bash
# Source this file to set up environment for Zara Privacy MCP:
#   source scripts/set-env.sh

export ZARA_ENCRYPTION_KEY="${ZARA_ENCRYPTION_KEY:-your-strong-passphrase-change-me}"
export ZARA_DB_PATH="${ZARA_DB_PATH:-$HOME/.zara/privacymcp/mappings.db}"
export ZARA_LOG_LEVEL="${ZARA_LOG_LEVEL:-info}"
export ZARA_MCP_PORT="${ZARA_MCP_PORT:-8530}"
export ZARA_MCP_HOST="${ZARA_MCP_HOST:-127.0.0.1}"

echo "✓ Zara Privacy MCP environment set"
echo "  ZARA_ENCRYPTION_KEY=${ZARA_ENCRYPTION_KEY:0:8}... (${#ZARA_ENCRYPTION_KEY} chars)"
echo "  ZARA_DB_PATH=${ZARA_DB_PATH}"
echo "  ZARA_MCP_PORT=${ZARA_MCP_PORT}"
