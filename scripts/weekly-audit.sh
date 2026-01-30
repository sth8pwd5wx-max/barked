#!/bin/bash
# Weekly Security Audit Script
# Run manually or via launchd on a weekly schedule
# Output: ~/Projects/secure/audits/audit-YYYY-MM-DD.md

set -euo pipefail

AUDIT_DIR="$HOME/Projects/secure/audits"
BASELINE_DIR="$HOME/Projects/secure/baseline"
DATE=$(date +%Y-%m-%d)
REPORT="$AUDIT_DIR/audit-$DATE.md"

mkdir -p "$AUDIT_DIR"

exec > "$REPORT" 2>&1

echo "# Security Audit Report — $DATE"
echo ""
echo "Generated: $(date)"
echo ""

# ============================================================
echo "## 1. System Protection Status"
echo ""
echo '```'
echo "SIP: $(csrutil status 2>/dev/null || echo 'UNKNOWN')"
echo "FileVault: $(fdesetup status 2>/dev/null || echo 'UNKNOWN')"
echo "Gatekeeper: $(/usr/sbin/spctl --status 2>/dev/null || echo 'UNKNOWN')"
echo "Firewall state: $(sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null || echo 'UNKNOWN')"
echo "Stealth mode: $(sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>/dev/null || echo 'UNKNOWN')"
echo "Block all incoming: $(sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getblockall 2>/dev/null || echo 'UNKNOWN')"
echo '```'
echo ""

# ============================================================
echo "## 2. macOS Updates Available"
echo ""
echo '```'
softwareupdate -l 2>/dev/null || echo "Could not check for updates"
echo '```'
echo ""

# ============================================================
echo "## 3. Network Status"
echo ""
echo '```'
echo "DNS servers (Wi-Fi): $(networksetup -getdnsservers Wi-Fi 2>/dev/null)"
echo ""
echo "Active network services:"
networksetup -listallnetworkservices 2>/dev/null
echo ""
echo "Listening ports:"
lsof -i -P -n 2>/dev/null | grep LISTEN | awk '{print $1, $2, $9}' | sort -u || echo "Could not check ports"
echo ""
echo "Mullvad VPN status:"
mullvad status 2>/dev/null || echo "Mullvad CLI not available — check GUI"
echo '```'
echo ""

# ============================================================
echo "## 4. LaunchDaemons (system)"
echo ""
echo '```'
ls /Library/LaunchDaemons/ 2>/dev/null || echo "None"
echo '```'
echo ""

echo "## 5. LaunchAgents (system)"
echo ""
echo '```'
ls /Library/LaunchAgents/ 2>/dev/null || echo "None"
echo '```'
echo ""

echo "## 6. LaunchAgents (user)"
echo ""
echo '```'
ls ~/Library/LaunchAgents/ 2>/dev/null || echo "None"
echo '```'
echo ""

# ============================================================
echo "## 7. Login Items & Background Items"
echo ""
echo '```'
sfltool dumpbtm 2>/dev/null | head -100 || echo "Could not dump background items"
echo '```'
echo ""

# ============================================================
echo "## 8. Installed Applications"
echo ""
echo '```'
ls /Applications/ 2>/dev/null
echo ""
echo "--- User Applications ---"
ls ~/Applications/ 2>/dev/null || echo "None"
echo '```'
echo ""

# ============================================================
echo "## 9. Homebrew Packages"
echo ""
echo "### Formulae"
echo '```'
brew list --formula 2>/dev/null || echo "Homebrew not available"
echo '```'
echo ""
echo "### Casks"
echo '```'
brew list --cask 2>/dev/null || echo "Homebrew not available"
echo '```'
echo ""

# ============================================================
echo "## 10. Running Processes Without Sandbox"
echo ""
echo '```'
# List processes and check for sandbox status
ps -eo pid,comm 2>/dev/null | tail -20
echo ""
echo "(Full sandbox audit: use Activity Monitor > View > Columns > Sandbox)"
echo '```'
echo ""

# ============================================================
echo "## 11. Unsigned or Ad-hoc Signed Applications"
echo ""
echo '```'
for app in /Applications/*.app; do
    sig=$(codesign -dv "$app" 2>&1 | grep "Signature=" || true)
    if echo "$sig" | grep -q "adhoc"; then
        echo "AD-HOC: $app"
    fi
done
echo "(Any ad-hoc signed apps listed above should be investigated)"
echo '```'
echo ""

# ============================================================
echo "## 12. Hostname Check"
echo ""
echo '```'
echo "ComputerName: $(scutil --get ComputerName 2>/dev/null)"
echo "LocalHostName: $(scutil --get LocalHostName 2>/dev/null)"
echo "HostName: $(scutil --get HostName 2>/dev/null)"
echo '```'
echo ""

# ============================================================
echo "## 13. Baseline Comparison"
echo ""
if [ -f "$BASELINE_DIR/brew-formulae.txt" ]; then
    NEW_FORMULAE=$(comm -13 "$BASELINE_DIR/brew-formulae.txt" <(brew list --formula 2>/dev/null | sort) || true)
    REMOVED_FORMULAE=$(comm -23 "$BASELINE_DIR/brew-formulae.txt" <(brew list --formula 2>/dev/null | sort) || true)
    if [ -n "$NEW_FORMULAE" ]; then
        echo "### New Homebrew formulae since baseline:"
        echo '```'
        echo "$NEW_FORMULAE"
        echo '```'
    fi
    if [ -n "$REMOVED_FORMULAE" ]; then
        echo "### Removed Homebrew formulae since baseline:"
        echo '```'
        echo "$REMOVED_FORMULAE"
        echo '```'
    fi
    if [ -z "$NEW_FORMULAE" ] && [ -z "$REMOVED_FORMULAE" ]; then
        echo "Homebrew formulae unchanged from baseline."
    fi
else
    echo "No baseline found. Run baseline snapshot first."
fi
echo ""

if [ -f "$BASELINE_DIR/brew-casks.txt" ]; then
    NEW_CASKS=$(comm -13 "$BASELINE_DIR/brew-casks.txt" <(brew list --cask 2>/dev/null | sort) || true)
    REMOVED_CASKS=$(comm -23 "$BASELINE_DIR/brew-casks.txt" <(brew list --cask 2>/dev/null | sort) || true)
    if [ -n "$NEW_CASKS" ]; then
        echo "### New Homebrew casks since baseline:"
        echo '```'
        echo "$NEW_CASKS"
        echo '```'
    fi
    if [ -n "$REMOVED_CASKS" ]; then
        echo "### Removed Homebrew casks since baseline:"
        echo '```'
        echo "$REMOVED_CASKS"
        echo '```'
    fi
    if [ -z "$NEW_CASKS" ] && [ -z "$REMOVED_CASKS" ]; then
        echo "Homebrew casks unchanged from baseline."
    fi
else
    echo "No cask baseline found."
fi
echo ""

if [ -f "$BASELINE_DIR/launch-daemons.txt" ]; then
    NEW_DAEMONS=$(comm -13 "$BASELINE_DIR/launch-daemons.txt" <(ls /Library/LaunchDaemons/ 2>/dev/null | sort) || true)
    if [ -n "$NEW_DAEMONS" ]; then
        echo "### NEW LaunchDaemons since baseline (INVESTIGATE):"
        echo '```'
        echo "$NEW_DAEMONS"
        echo '```'
    else
        echo "LaunchDaemons unchanged from baseline."
    fi
else
    echo "No LaunchDaemons baseline found."
fi
echo ""

if [ -f "$BASELINE_DIR/applications.txt" ]; then
    NEW_APPS=$(comm -13 "$BASELINE_DIR/applications.txt" <(ls /Applications/ 2>/dev/null | sort) || true)
    if [ -n "$NEW_APPS" ]; then
        echo "### New applications since baseline:"
        echo '```'
        echo "$NEW_APPS"
        echo '```'
    else
        echo "Applications unchanged from baseline."
    fi
else
    echo "No applications baseline found."
fi
echo ""

# ============================================================
echo "---"
echo ""
echo "**Audit complete.** Review flagged items above."
echo "Next audit scheduled in 7 days."
