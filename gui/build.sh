#!/bin/bash
# Build Barked.app bundle from Swift Package
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PKG_DIR="${SCRIPT_DIR}/Barked"
APP_NAME="Barked"
BUILD_DIR="${PKG_DIR}/.build/release"
APP_BUNDLE="${SCRIPT_DIR}/${APP_NAME}.app"

echo "Building ${APP_NAME}..."
cd "$PKG_DIR" && swift build -c release 2>&1

echo "Creating app bundle..."
rm -rf "$APP_BUNDLE"
mkdir -p "${APP_BUNDLE}/Contents/MacOS"
mkdir -p "${APP_BUNDLE}/Contents/Resources"

# Copy binary
cp "${BUILD_DIR}/${APP_NAME}" "${APP_BUNDLE}/Contents/MacOS/${APP_NAME}"

# Copy Info.plist
cp "${PKG_DIR}/Sources/Barked/Info.plist" "${APP_BUNDLE}/Contents/"

# Bundle barked.sh so the app works standalone
if [[ -f "${SCRIPT_DIR}/../scripts/barked.sh" ]]; then
    cp "${SCRIPT_DIR}/../scripts/barked.sh" "${APP_BUNDLE}/Contents/Resources/barked.sh"
    chmod +x "${APP_BUNDLE}/Contents/Resources/barked.sh"
fi

# Create PkgInfo
echo -n "APPL????" > "${APP_BUNDLE}/Contents/PkgInfo"

echo ""
echo "Built: ${APP_BUNDLE}"
echo "Size:  $(du -sh "$APP_BUNDLE" | cut -f1)"
echo ""
echo "To install:"
echo "  cp -r \"${APP_BUNDLE}\" /Applications/"
echo "  open /Applications/${APP_NAME}.app"
