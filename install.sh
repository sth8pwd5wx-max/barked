#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
# install.sh — Barked installer for macOS / Linux
# Usage: curl -fsSL https://raw.githubusercontent.com/OWNER/REPO/main/install.sh | sudo bash
# ═══════════════════════════════════════════════════════════════════
set -euo pipefail

GITHUB_REPO="OWNER/REPO"
INSTALL_DIR="/usr/local/bin"
BINARY_NAME="barked"

# ═══════════════════════════════════════════════════════════════════
# COLORS
# ═══════════════════════════════════════════════════════════════════
RED='\033[0;31m'
GREEN='\033[0;32m'
BROWN='\033[0;33m'
NC='\033[0m'

# ═══════════════════════════════════════════════════════════════════
# HEADER
# ═══════════════════════════════════════════════════════════════════
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║${NC}             Barked Installer                     ${GREEN}║${NC}"
echo -e "${GREEN}║${NC}             macOS / Linux                        ${GREEN}║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════╝${NC}"
echo ""

# ═══════════════════════════════════════════════════════════════════
# PREFLIGHT CHECKS
# ═══════════════════════════════════════════════════════════════════
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Error: This installer must be run as root (use sudo).${NC}" >&2
    exit 1
fi

if ! command -v curl &>/dev/null; then
    echo -e "${RED}Error: curl is required but not found. Please install curl first.${NC}" >&2
    exit 1
fi

# ═══════════════════════════════════════════════════════════════════
# DETECT OS & ARCH
# ═══════════════════════════════════════════════════════════════════
KERNEL="$(uname -s)"
ARCH="$(uname -m)"

case "$KERNEL" in
    Darwin) OS="macOS" ;;
    Linux)  OS="Linux" ;;
    *)
        echo -e "${RED}Error: Unsupported OS '${KERNEL}'. Windows users: use install.ps1 instead.${NC}" >&2
        exit 1
        ;;
esac

echo -e "  Detected OS:   ${GREEN}${OS}${NC}"
echo -e "  Detected Arch: ${GREEN}${ARCH}${NC}"
echo ""

# ═══════════════════════════════════════════════════════════════════
# DOWNLOAD
# ═══════════════════════════════════════════════════════════════════
DOWNLOAD_URL="https://github.com/${GITHUB_REPO}/releases/latest/download/barked.sh"
TMP_FILE="$(mktemp /tmp/barked-install-XXXXXX.sh)"
trap 'rm -f "$TMP_FILE"' EXIT

echo -e "${BROWN}Fetching latest release...${NC}"
echo "  ${DOWNLOAD_URL}"
echo ""

if ! curl -fsSL --connect-timeout 10 --max-time 60 -o "$TMP_FILE" "$DOWNLOAD_URL"; then
    echo -e "${RED}Error: Failed to download barked from ${DOWNLOAD_URL}${NC}" >&2
    exit 1
fi

# ═══════════════════════════════════════════════════════════════════
# VALIDATE
# ═══════════════════════════════════════════════════════════════════
if ! bash -n "$TMP_FILE"; then
    echo -e "${RED}Error: Downloaded script has syntax errors. Aborting.${NC}" >&2
    exit 1
fi

# ═══════════════════════════════════════════════════════════════════
# INSTALL
# ═══════════════════════════════════════════════════════════════════
mkdir -p "$INSTALL_DIR"
mv "$TMP_FILE" "${INSTALL_DIR}/${BINARY_NAME}"
chmod +x "${INSTALL_DIR}/${BINARY_NAME}"

# ═══════════════════════════════════════════════════════════════════
# VERIFY
# ═══════════════════════════════════════════════════════════════════
INSTALLED_VERSION="$(${INSTALL_DIR}/${BINARY_NAME} --version 2>/dev/null || echo "unknown")"

echo ""
echo -e "${GREEN}Barked installed successfully!${NC}"
echo -e "  Version:  ${GREEN}${INSTALLED_VERSION}${NC}"
echo -e "  Location: ${GREEN}${INSTALL_DIR}/${BINARY_NAME}${NC}"
echo ""
echo "Usage:"
echo "  sudo barked            # Run hardening wizard"
echo "  sudo barked --clean    # Run system cleaner"
echo "  sudo barked --update   # Update to latest version"
echo ""
