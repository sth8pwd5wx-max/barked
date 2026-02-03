#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
# install.sh — Barked installer for macOS / Linux
# Usage:
#   bash install.sh              # Install to ~/.local/bin (recommended)
#   sudo bash install.sh         # Install to /usr/local/bin (system-wide)
# ═══════════════════════════════════════════════════════════════════
set -euo pipefail

GITHUB_REPO="sth8pwd5wx-max/barked"
BINARY_NAME="barked"

# Determine install location based on privileges
if [[ $EUID -eq 0 ]]; then
    INSTALL_DIR="/usr/local/bin"
    INSTALL_TYPE="system-wide"
else
    INSTALL_DIR="${HOME}/.local/bin"
    INSTALL_TYPE="user"
fi

# ═══════════════════════════════════════════════════════════════════
# COLORS
# ═══════════════════════════════════════════════════════════════════
RED='\033[0;31m'
GREEN='\033[0;32m'
BROWN='\033[0;33m'
CYAN='\033[0;36m'
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

echo -e "  Detected OS:     ${GREEN}${OS}${NC}"
echo -e "  Detected Arch:   ${GREEN}${ARCH}${NC}"
echo -e "  Install type:    ${CYAN}${INSTALL_TYPE}${NC}"
echo -e "  Install path:    ${CYAN}${INSTALL_DIR}${NC}"
echo ""

# barked requires Bash 4+ for associative arrays
BASH4=""
if ((BASH_VERSINFO[0] >= 4)); then
    BASH4="$(command -v bash)"
elif [[ -x /opt/homebrew/bin/bash ]]; then
    BASH4="/opt/homebrew/bin/bash"
elif [[ -x /usr/local/bin/bash ]]; then
    BASH4="/usr/local/bin/bash"
fi

if [[ -z "$BASH4" ]]; then
    echo ""
    echo -e "${RED}Error: barked requires Bash 4.0+ (system has ${BASH_VERSION}).${NC}"
    if [[ "$OS" == "macOS" ]]; then
        echo -e "  Install it:  ${GREEN}brew install bash${NC}"
        echo "  Then re-run this installer."
    else
        echo "  Install bash 4+: sudo apt install bash (or equivalent)"
    fi
    exit 1
fi

echo -e "  Bash 4+:         ${GREEN}${BASH4}${NC}"
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

# Download and verify checksum
CHECKSUM_URL="https://github.com/${GITHUB_REPO}/releases/latest/download/barked.sh.sha256"
EXPECTED_HASH="$(curl -fsSL --connect-timeout 10 --max-time 30 "$CHECKSUM_URL" 2>/dev/null | awk '{print $1}')"
if [[ -z "$EXPECTED_HASH" ]]; then
    echo -e "${RED}Error: Failed to download checksum for verification${NC}" >&2
    exit 1
fi

ACTUAL_HASH="$(shasum -a 256 "$TMP_FILE" | awk '{print $1}')"
if [[ "$ACTUAL_HASH" != "$EXPECTED_HASH" ]]; then
    echo -e "${RED}Error: Checksum verification failed. Aborting installation.${NC}" >&2
    echo -e "${RED}Expected: ${EXPECTED_HASH}${NC}" >&2
    echo -e "${RED}Got:      ${ACTUAL_HASH}${NC}" >&2
    exit 1
fi

echo -e "${GREEN}Checksum verified${NC}"

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
cp "$TMP_FILE" "${INSTALL_DIR}/${BINARY_NAME}"
chmod 755 "${INSTALL_DIR}/${BINARY_NAME}"

# ═══════════════════════════════════════════════════════════════════
# VERIFY
# ═══════════════════════════════════════════════════════════════════
INSTALLED_VERSION="$(${INSTALL_DIR}/${BINARY_NAME} --version 2>/dev/null || echo "unknown")"

echo ""
echo -e "${GREEN}✓ Barked installed successfully!${NC}"
echo -e "  Version:  ${GREEN}${INSTALLED_VERSION}${NC}"
echo -e "  Location: ${GREEN}${INSTALL_DIR}/${BINARY_NAME}${NC}"
echo ""

# ═══════════════════════════════════════════════════════════════════
# PATH SETUP (userspace installs only)
# ═══════════════════════════════════════════════════════════════════
if [[ "$INSTALL_TYPE" == "user" ]]; then
    # Check if already in PATH
    if ! echo "$PATH" | grep -q "${INSTALL_DIR}"; then
        echo -e "${BROWN}Note: ${INSTALL_DIR} is not in your PATH.${NC}"
        echo ""
        echo "Add it to your shell profile:"
        echo ""

        # Detect shell and show appropriate command
        if [[ -n "${BASH_VERSION:-}" ]] || [[ "$SHELL" == *"bash"* ]]; then
            echo -e "  ${CYAN}echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.bashrc${NC}"
            echo -e "  ${CYAN}source ~/.bashrc${NC}"
        elif [[ -n "${ZSH_VERSION:-}" ]] || [[ "$SHELL" == *"zsh"* ]]; then
            echo -e "  ${CYAN}echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.zshrc${NC}"
            echo -e "  ${CYAN}source ~/.zshrc${NC}"
        else
            echo -e "  ${CYAN}export PATH=\"\$HOME/.local/bin:\$PATH\"${NC}"
        fi
        echo ""
        echo "Or run directly:"
        echo -e "  ${CYAN}${INSTALL_DIR}/${BINARY_NAME}${NC}"
        echo ""
    fi
fi

echo "Usage:"
echo "  barked                 # Run hardening wizard"
echo "  barked --clean         # Run system cleaner"
echo "  barked --audit         # Security audit without changes"
echo "  barked --update        # Update to latest version"
echo ""
