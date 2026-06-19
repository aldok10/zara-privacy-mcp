#!/usr/bin/env bash
#
# install-skill.sh — Install Zara Secure MCP skill for OpenCode/Claude agents
#
# Usage:
#   ./scripts/install-skill.sh              # Install to all agent dirs
#   ./scripts/install-skill.sh --uninstall  # Remove from all agent dirs
#   ./scripts/install-skill.sh --list       # Show current installation status
#   ./scripts/install-skill.sh --check      # Verify all agent dirs have the skill
#
# This script copies the skill definition so any AI agent (OpenCode, Claude, etc.)
# can discover and load it via the `skill()` tool.

set -euo pipefail

SKILL_NAME="zara-secure-mcp"
SKILL_SRC=".opencode/skills/${SKILL_NAME}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Target directories (in priority order for agent discovery)
TARGET_DIRS=(
  "${HOME}/.agents/skills/${SKILL_NAME}"
  "${HOME}/.claude/skills/${SKILL_NAME}"
)

# === Functions ===

info()  { printf "  \033[1;34m➜\033[0m %s\n" "$*"; }
ok()    { printf "  \033[1;32m✓\033[0m %s\n" "$*"; }
fail()  { printf "  \033[1;31m✗\033[0m %s\n" "$*"; }
header(){ printf "\n\033[1;36m%s\033[0m\n" "$*"; }

check_prereqs() {
  local missing=0
  if [ ! -f "${PROJECT_DIR}/${SKILL_SRC}/SKILL.md" ]; then
    fail "Skill source not found: ${PROJECT_DIR}/${SKILL_SRC}/SKILL.md"
    info  "Run this script from the project root or via Makefile"
    missing=1
  fi
  return "${missing}"
}

install_skill() {
  header "Installing skill: ${SKILL_NAME}"

  for dir in "${TARGET_DIRS[@]}"; do
    mkdir -p "${dir}"
    if [ -f "${dir}/SKILL.md" ]; then
      local existing_checksum checksum
      existing_checksum=$(md5 -q "${dir}/SKILL.md" 2>/dev/null || true)
      checksum=$(md5 -q "${PROJECT_DIR}/${SKILL_SRC}/SKILL.md" 2>/dev/null || true)
      if [ "${existing_checksum}" = "${checksum}" ]; then
        ok "${dir}/SKILL.md  (up to date)"
        continue
      fi
    fi
    cp "${PROJECT_DIR}/${SKILL_SRC}/SKILL.md" "${dir}/SKILL.md"
    ok "${dir}/SKILL.md  (installed)"
  done

  header "Done!"
  info "Skill '${SKILL_NAME}' is now available for all agents."
  info "Load it in agent context via:  skill(\"${SKILL_NAME}\")"
}

uninstall_skill() {
  header "Uninstalling skill: ${SKILL_NAME}"

  for dir in "${TARGET_DIRS[@]}"; do
    if [ -d "${dir}" ]; then
      rm -rf "${dir}"
      ok "Removed ${dir}"
    else
      info "Not found: ${dir} (skipping)"
    fi
  done

  header "Done!"
  info "Skill '${SKILL_NAME}' removed from all agent directories."
}

list_status() {
  header "Skill status: ${SKILL_NAME}"

  for dir in "${TARGET_DIRS[@]}"; do
    if [ -f "${dir}/SKILL.md" ]; then
      local size
      size=$(wc -c < "${dir}/SKILL.md" | tr -d ' ')
      ok "${dir}/SKILL.md  (${size} bytes)"
    else
      fail "${dir}/SKILL.md  (not installed)"
    fi
  done
}

check_install() {
  header "Verifying skill installation: ${SKILL_NAME}"
  local all_ok=0

  for dir in "${TARGET_DIRS[@]}"; do
    if [ -f "${dir}/SKILL.md" ]; then
      local src_checksum dst_checksum
      src_checksum=$(md5 -q "${PROJECT_DIR}/${SKILL_SRC}/SKILL.md" 2>/dev/null || true)
      dst_checksum=$(md5 -q "${dir}/SKILL.md" 2>/dev/null || true)
      if [ "${src_checksum}" = "${dst_checksum}" ]; then
        ok "${dir}/SKILL.md  (in sync)"
      else
        fail "${dir}/SKILL.md  (out of date — re-run install-skill)"
        all_ok=1
      fi
    else
      fail "${dir}/SKILL.md  (not installed)"
      all_ok=1
    fi
  done

  if [ "${all_ok}" -eq 0 ]; then
    header "✓ Skill is fully installed and up to date."
  else
    header "⚠ Some locations need attention."
    info "Run: ./scripts/install-skill.sh"
  fi
}

# === Main ===

cd "${PROJECT_DIR}"

case "${1:-}" in
  --uninstall|-u)
    check_prereqs
    uninstall_skill
    ;;
  --list|-l)
    check_prereqs
    list_status
    ;;
  --check|-c)
    check_prereqs
    check_install
    ;;
  --help|-h)
    echo "Usage: $0 [--uninstall|--list|--check|--help]"
    echo ""
    echo "  (no flag)   Install skill to all agent directories"
    echo "  --uninstall Remove skill from all agent directories"
    echo "  --list      Show current installation status"
    echo "  --check     Verify all locations are in sync"
    echo "  --help      Show this help"
    ;;
  *)
    check_prereqs
    install_skill
    ;;
esac
