#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
# harden.sh — Cross-platform security hardening wizard (macOS/Linux)
# Idempotent, interactive, profile-based system hardening
# ═══════════════════════════════════════════════════════════════════
set -uo pipefail

readonly VERSION="1.0.0"
readonly SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
readonly DATE="$(date +%Y-%m-%d)"
readonly TIMESTAMP="$(date '+%Y-%m-%d %H:%M:%S')"
readonly LOG_FILE="${SCRIPT_DIR}/../audits/hardening-log-${DATE}.txt"

# ═══════════════════════════════════════════════════════════════════
# COLORS & FORMATTING
# ═══════════════════════════════════════════════════════════════════
if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[0;33m'
    BLUE='\033[0;34m'
    MAGENTA='\033[0;35m'
    CYAN='\033[0;36m'
    WHITE='\033[1;37m'
    DIM='\033[2m'
    BOLD='\033[1m'
    NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' BLUE='' MAGENTA='' CYAN='' WHITE='' DIM='' BOLD='' NC=''
fi

# ═══════════════════════════════════════════════════════════════════
# GLOBALS
# ═══════════════════════════════════════════════════════════════════
OS=""                    # "macos" or "linux"
DISTRO=""                # linux distro family: "debian", "fedora", "arch"
PKG_MGR=""               # package manager command
PROFILE=""               # "standard", "high", "paranoid", "advanced"
OUTPUT_MODE=""           # "checklist", "pause", "report"
TOTAL_MODULES=0
CURRENT_MODULE=0
COUNT_APPLIED=0
COUNT_SKIPPED=0
COUNT_FAILED=0
COUNT_MANUAL=0

declare -a ENABLED_MODULES=()
declare -a LOG_ENTRIES=()
declare -a MANUAL_STEPS=()

# Advanced questionnaire answers
Q_THREAT=""
Q_USECASE=""
Q_TRAVEL=""
Q_ECOSYSTEM=""
Q_NETWORK=""
Q_AUTH=""
Q_TRAFFIC=""
Q_MAINTENANCE=""

# ═══════════════════════════════════════════════════════════════════
# LOGGING & OUTPUT UTILITIES
# ═══════════════════════════════════════════════════════════════════
log_entry() {
    local module="$1" action="$2" result="$3" message="$4"
    local entry="[$(date '+%H:%M:%S')] [$module] [$action] [$result] $message"
    LOG_ENTRIES+=("$entry")
}

print_header() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}${BOLD}        SYSTEM HARDENING WIZARD v${VERSION}           ${NC}${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}        macOS / Linux                             ${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════╝${NC}"
    echo ""
}

print_section() {
    echo ""
    echo -e "${BOLD}${WHITE}═══ $1 ═══${NC}"
    echo ""
}

print_status() {
    local num="$1" total="$2" desc="$3" status="$4"
    case "$status" in
        applied)  echo -e "  ${GREEN}✓${NC} [${num}/${total}] ${desc} ${DIM}(applied)${NC}" ;;
        skipped)  echo -e "  ${GREEN}○${NC} [${num}/${total}] ${desc} ${DIM}(already applied)${NC}" ;;
        failed)   echo -e "  ${RED}✗${NC} [${num}/${total}] ${desc} ${RED}(failed)${NC}" ;;
        manual)   echo -e "  ${YELLOW}☐${NC} [${num}/${total}] ${desc} ${YELLOW}(manual)${NC}" ;;
        skipped_unsupported) echo -e "  ${DIM}–${NC} [${num}/${total}] ${desc} ${DIM}(not available on ${OS})${NC}" ;;
    esac
}

print_progress() {
    local desc="$1"
    echo -ne "  ${YELLOW}⟳${NC} [${CURRENT_MODULE}/${TOTAL_MODULES}] ${desc}..."
}

clear_progress() {
    echo -ne "\r\033[K"
}

prompt_choice() {
    local prompt="$1"
    shift
    local options=("$@")
    echo -e "${BOLD}${prompt}${NC}"
    echo ""
    for i in "${!options[@]}"; do
        echo -e "  ${CYAN}[$((i+1))]${NC} ${options[$i]}"
    done
    echo ""
    while true; do
        echo -ne "  ${BOLD}Choice:${NC} "
        read -r choice
        if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#options[@]} )); then
            return $((choice - 1))
        elif [[ "${choice,,}" == "q" ]]; then
            echo "Exiting."
            exit 0
        fi
        echo -e "  ${RED}Invalid choice. Enter 1-${#options[@]} or Q to quit.${NC}"
    done
}

prompt_yn() {
    local prompt="$1"
    echo -ne "  ${BOLD}${prompt}${NC} [Y/n]: "
    read -r yn
    [[ "${yn,,}" != "n" ]]
}

pause_guide() {
    local message="$1"
    if [[ "$OUTPUT_MODE" == "pause" ]]; then
        echo ""
        echo -e "  ${YELLOW}☐ MANUAL STEP:${NC} ${message}"
        echo -ne "  ${DIM}Press Enter when done (or S to skip)...${NC} "
        read -r response
        if [[ "${response,,}" == "s" ]]; then
            return 1
        fi
        return 0
    else
        MANUAL_STEPS+=("$message")
        return 1
    fi
}

# ═══════════════════════════════════════════════════════════════════
# OS DETECTION
# ═══════════════════════════════════════════════════════════════════
detect_os() {
    local uname_out
    uname_out="$(uname -s)"
    case "$uname_out" in
        Darwin*)
            OS="macos"
            PKG_MGR="brew"
            ;;
        Linux*)
            OS="linux"
            if command -v apt-get &>/dev/null; then
                DISTRO="debian"
                PKG_MGR="apt-get"
            elif command -v dnf &>/dev/null; then
                DISTRO="fedora"
                PKG_MGR="dnf"
            elif command -v pacman &>/dev/null; then
                DISTRO="arch"
                PKG_MGR="pacman"
            else
                DISTRO="unknown"
                PKG_MGR=""
            fi
            ;;
        *)
            echo -e "${RED}Unsupported OS: ${uname_out}. Use harden.ps1 for Windows.${NC}"
            exit 1
            ;;
    esac
    echo -e "  Detected: ${BOLD}${OS}${NC}$([ -n "$DISTRO" ] && echo " (${DISTRO})")"
}

# ═══════════════════════════════════════════════════════════════════
# PRIVILEGE CHECK
# ═══════════════════════════════════════════════════════════════════
check_privileges() {
    if [[ $EUID -ne 0 ]]; then
        echo ""
        echo -e "${YELLOW}This script requires root/sudo privileges to apply system changes.${NC}"
        echo -e "Please re-run: ${BOLD}sudo $0${NC}"
        echo ""
        exit 1
    fi
    # Preserve the real user for user-level configs
    if [[ -n "${SUDO_USER:-}" ]]; then
        REAL_USER="$SUDO_USER"
        REAL_HOME=$(eval echo "~$SUDO_USER")
    else
        REAL_USER="$(whoami)"
        REAL_HOME="$HOME"
    fi
    export REAL_USER REAL_HOME
}

run_as_user() {
    if [[ -n "${SUDO_USER:-}" ]]; then
        sudo -u "$SUDO_USER" "$@"
    else
        "$@"
    fi
}

# ═══════════════════════════════════════════════════════════════════
# PACKAGE INSTALL HELPERS
# ═══════════════════════════════════════════════════════════════════
pkg_install() {
    local pkg="$1"
    case "$OS" in
        macos)
            run_as_user brew install "$pkg" 2>/dev/null
            ;;
        linux)
            case "$DISTRO" in
                debian) DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg" 2>/dev/null ;;
                fedora) dnf install -y "$pkg" 2>/dev/null ;;
                arch)   pacman -S --noconfirm "$pkg" 2>/dev/null ;;
            esac
            ;;
    esac
}

pkg_install_cask() {
    if [[ "$OS" == "macos" ]]; then
        run_as_user brew install --cask "$1" 2>/dev/null
    fi
}

pkg_installed() {
    local pkg="$1"
    case "$OS" in
        macos)  brew list "$pkg" &>/dev/null ;;
        linux)
            case "$DISTRO" in
                debian) dpkg -l "$pkg" 2>/dev/null | grep -q "^ii" ;;
                fedora) rpm -q "$pkg" &>/dev/null ;;
                arch)   pacman -Q "$pkg" &>/dev/null ;;
            esac
            ;;
    esac
}

cask_installed() {
    [[ "$OS" == "macos" ]] && brew list --cask "$1" &>/dev/null
}

# ═══════════════════════════════════════════════════════════════════
# WIZARD: PROFILE SELECTION
# ═══════════════════════════════════════════════════════════════════
select_profile() {
    print_section "Profile Selection"

    prompt_choice "Select a hardening profile:" \
        "Standard  — Encrypted disk, firewall, secure DNS, auto-updates, basic browser hardening" \
        "High      — Standard + outbound firewall, hostname scrubbing, monitoring tools, SSH hardening, telemetry disabled" \
        "Paranoid  — High + MAC rotation, traffic obfuscation, VPN kill switch, full audit system, metadata stripping, border crossing prep" \
        "Advanced  — Custom questionnaire (choose per-category)"
    local choice=$?

    case $choice in
        0) PROFILE="standard" ;;
        1) PROFILE="high" ;;
        2) PROFILE="paranoid" ;;
        3) PROFILE="advanced"; run_questionnaire ;;
    esac

    echo ""
    echo -e "  Profile: ${BOLD}${PROFILE}${NC}"
}

# ═══════════════════════════════════════════════════════════════════
# WIZARD: ADVANCED QUESTIONNAIRE
# ═══════════════════════════════════════════════════════════════════
run_questionnaire() {
    print_section "Advanced Questionnaire"
    echo -e "  ${DIM}Answer 8 questions to build a custom hardening profile.${NC}"
    echo ""

    # Q1: Threat model
    prompt_choice "1. What is your primary threat model?" \
        "Targeted adversary (nation-state, mercenary spyware)" \
        "Mass surveillance (corporate tracking, ISP monitoring, data brokers)" \
        "Physical theft/access (theft, border crossing, evil maid)" \
        "All of the above"
    case $? in
        0) Q_THREAT="targeted" ;; 1) Q_THREAT="mass" ;;
        2) Q_THREAT="physical" ;; 3) Q_THREAT="all" ;;
    esac
    echo ""

    # Q2: Use case
    prompt_choice "2. How do you primarily use this machine?" \
        "Software development only" \
        "Dev + light personal use" \
        "Dev + media/creative work" \
        "Dedicated security machine"
    case $? in
        0) Q_USECASE="dev" ;; 1) Q_USECASE="dev-personal" ;;
        2) Q_USECASE="dev-media" ;; 3) Q_USECASE="dedicated" ;;
    esac
    echo ""

    # Q3: Travel
    prompt_choice "3. Do you travel internationally with this machine?" \
        "Frequently" \
        "Occasionally" \
        "Rarely or never"
    case $? in
        0) Q_TRAVEL="frequent" ;; 1) Q_TRAVEL="occasional" ;;
        2) Q_TRAVEL="rarely" ;;
    esac
    echo ""

    # Q4: Ecosystem
    prompt_choice "4. Vendor ecosystem preference?" \
        "Minimize vendor dependence (reduce Apple/Microsoft/Google reliance)" \
        "Strategic use (leverage vendor security features, lock them down)" \
        "Full ecosystem (multiple devices, want them secured as a unit)"
    case $? in
        0) Q_ECOSYSTEM="minimize" ;; 1) Q_ECOSYSTEM="strategic" ;;
        2) Q_ECOSYSTEM="full" ;;
    esac
    echo ""

    # Q5: Network monitoring
    prompt_choice "5. Network monitoring preference?" \
        "I want to see everything (per-app alerts on every connection)" \
        "Block and forget (strict rules, silent, no prompts)" \
        "DNS-level filtering is enough"
    case $? in
        0) Q_NETWORK="full-visibility" ;; 1) Q_NETWORK="block-forget" ;;
        2) Q_NETWORK="dns-only" ;;
    esac
    echo ""

    # Q6: Authentication
    prompt_choice "6. Current authentication setup?" \
        "Hardware security keys (YubiKey, FIDO2)" \
        "Password manager + TOTP codes" \
        "OS built-in (Apple Passwords, Windows Hello, etc.)" \
        "Mixed or inconsistent"
    case $? in
        0) Q_AUTH="hardware" ;; 1) Q_AUTH="manager-totp" ;;
        2) Q_AUTH="builtin" ;; 3) Q_AUTH="mixed" ;;
    esac
    echo ""

    # Q7: Traffic
    prompt_choice "7. Traffic obfuscation preference?" \
        "Route everything through Tor/VPN" \
        "VPN always on, Tor for sensitive tasks" \
        "Situational (speed matters)"
    case $? in
        0) Q_TRAFFIC="full-tor" ;; 1) Q_TRAFFIC="vpn-plus-tor" ;;
        2) Q_TRAFFIC="situational" ;;
    esac
    echo ""

    # Q8: Maintenance
    prompt_choice "8. Maintenance overhead tolerance?" \
        "Set and forget (automate everything)" \
        "Weekly check-ins (periodic review, daily automation)" \
        "Active management (regular log review, key rotation)"
    case $? in
        0) Q_MAINTENANCE="set-forget" ;; 1) Q_MAINTENANCE="weekly" ;;
        2) Q_MAINTENANCE="active" ;;
    esac
    echo ""
}

# ═══════════════════════════════════════════════════════════════════
# WIZARD: OUTPUT MODE
# ═══════════════════════════════════════════════════════════════════
select_output_mode() {
    print_section "Output Mode"

    prompt_choice "How should manual steps be handled?" \
        "Print checklist at the end" \
        "Pause and guide me through each step" \
        "Generate a report file"
    case $? in
        0) OUTPUT_MODE="checklist" ;;
        1) OUTPUT_MODE="pause" ;;
        2) OUTPUT_MODE="report" ;;
    esac

    echo ""
    echo -e "  Output mode: ${BOLD}${OUTPUT_MODE}${NC}"
}

# ═══════════════════════════════════════════════════════════════════
# PROFILE BUILDER — MAP PROFILE/ANSWERS TO MODULES
# ═══════════════════════════════════════════════════════════════════
build_module_list() {
    # Standard modules (always included)
    ENABLED_MODULES=(
        "disk-encrypt"
        "firewall-inbound"
        "dns-secure"
        "auto-updates"
        "guest-disable"
        "lock-screen"
        "browser-basic"
    )

    if [[ "$PROFILE" == "high" || "$PROFILE" == "paranoid" ]]; then
        ENABLED_MODULES+=(
            "firewall-stealth"
            "firewall-outbound"
            "hostname-scrub"
            "ssh-harden"
            "git-harden"
            "telemetry-disable"
            "monitoring-tools"
            "permissions-audit"
        )
    fi

    if [[ "$PROFILE" == "paranoid" ]]; then
        ENABLED_MODULES+=(
            "mac-rotate"
            "vpn-killswitch"
            "traffic-obfuscation"
            "browser-fingerprint"
            "metadata-strip"
            "dev-isolation"
            "audit-script"
            "backup-guidance"
            "border-prep"
            "bluetooth-disable"
        )
    fi

    if [[ "$PROFILE" == "advanced" ]]; then
        # Map questionnaire answers to modules
        # Always include standard
        # Add high-tier based on answers
        if [[ "$Q_THREAT" == "all" || "$Q_THREAT" == "targeted" || "$Q_THREAT" == "mass" ]]; then
            ENABLED_MODULES+=("firewall-stealth" "firewall-outbound" "hostname-scrub" "telemetry-disable")
        fi
        ENABLED_MODULES+=("ssh-harden" "git-harden" "monitoring-tools" "permissions-audit")

        # Add paranoid-tier based on answers
        if [[ "$Q_THREAT" == "all" || "$Q_THREAT" == "targeted" ]]; then
            ENABLED_MODULES+=("mac-rotate" "vpn-killswitch" "browser-fingerprint" "bluetooth-disable")
        fi
        if [[ "$Q_TRAFFIC" == "full-tor" || "$Q_TRAFFIC" == "vpn-plus-tor" ]]; then
            ENABLED_MODULES+=("vpn-killswitch" "traffic-obfuscation")
        fi
        if [[ "$Q_USECASE" == "dev" || "$Q_USECASE" == "dev-personal" || "$Q_USECASE" == "dev-media" ]]; then
            ENABLED_MODULES+=("dev-isolation")
        fi
        if [[ "$Q_MAINTENANCE" == "weekly" || "$Q_MAINTENANCE" == "active" ]]; then
            ENABLED_MODULES+=("audit-script")
        fi
        if [[ "$Q_TRAVEL" == "frequent" || "$Q_TRAVEL" == "occasional" ]]; then
            ENABLED_MODULES+=("border-prep")
        fi
        if [[ "$Q_THREAT" == "all" || "$Q_THREAT" == "mass" ]]; then
            ENABLED_MODULES+=("metadata-strip")
        fi
        ENABLED_MODULES+=("backup-guidance")

        # Deduplicate
        local -A seen
        local deduped=()
        for mod in "${ENABLED_MODULES[@]}"; do
            if [[ -z "${seen[$mod]:-}" ]]; then
                seen[$mod]=1
                deduped+=("$mod")
            fi
        done
        ENABLED_MODULES=("${deduped[@]}")
    fi

    TOTAL_MODULES=${#ENABLED_MODULES[@]}
}

# ═══════════════════════════════════════════════════════════════════
# MODULE FRAMEWORK
# ═══════════════════════════════════════════════════════════════════
# Each module is a function: mod_<name>
# Returns via global: MODULE_RESULT ("applied", "skipped", "failed", "manual", "skipped_unsupported")
MODULE_RESULT=""

run_module() {
    local mod_id="$1"
    local mod_func="mod_${mod_id//-/_}"
    CURRENT_MODULE=$((CURRENT_MODULE + 1))

    if declare -f "$mod_func" &>/dev/null; then
        "$mod_func"
    else
        MODULE_RESULT="skipped_unsupported"
    fi

    case "$MODULE_RESULT" in
        applied)  ((COUNT_APPLIED++)) ;;
        skipped)  ((COUNT_SKIPPED++)) ;;
        failed)   ((COUNT_FAILED++)) ;;
        manual)   ((COUNT_MANUAL++)) ;;
        skipped_unsupported) ((COUNT_SKIPPED++)) ;;
    esac
}

run_all_modules() {
    print_section "Applying Hardening (${TOTAL_MODULES} modules)"

    for mod_id in "${ENABLED_MODULES[@]}"; do
        run_module "$mod_id"
    done
}

# ═══════════════════════════════════════════════════════════════════
# MODULE: disk-encrypt
# ═══════════════════════════════════════════════════════════════════
mod_disk_encrypt() {
    local desc="Verify disk encryption"
    if [[ "$OS" == "macos" ]]; then
        if fdesetup status 2>/dev/null | grep -q "On"; then
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc (FileVault)" "skipped"
            log_entry "disk-encrypt" "check" "skip" "FileVault already enabled"
            MODULE_RESULT="skipped"
        else
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc (FileVault)" "manual"
            log_entry "disk-encrypt" "check" "manual" "FileVault not enabled"
            pause_guide "Enable FileVault: System Settings > Privacy & Security > FileVault > Turn On"
            MODULE_RESULT="manual"
        fi
    elif [[ "$OS" == "linux" ]]; then
        if lsblk -o NAME,TYPE,FSTYPE 2>/dev/null | grep -q "crypt"; then
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc (LUKS)" "skipped"
            log_entry "disk-encrypt" "check" "skip" "LUKS encryption detected"
            MODULE_RESULT="skipped"
        else
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc (LUKS)" "manual"
            log_entry "disk-encrypt" "check" "manual" "No LUKS encryption detected"
            pause_guide "Disk encryption must be set up during OS installation. Consider reinstalling with LUKS full-disk encryption enabled."
            MODULE_RESULT="manual"
        fi
    fi
}

# ═══════════════════════════════════════════════════════════════════
# MODULE: firewall-inbound
# ═══════════════════════════════════════════════════════════════════
mod_firewall_inbound() {
    local desc="Enable inbound firewall"
    if [[ "$OS" == "macos" ]]; then
        local state
        state=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null)
        if echo "$state" | grep -q "enabled\|State = 1\|State = 2"; then
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "skipped"
            log_entry "firewall-inbound" "check" "skip" "Firewall already enabled"
            MODULE_RESULT="skipped"
            return
        fi
        /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on &>/dev/null
        /usr/libexec/ApplicationFirewall/socketfilterfw --setblockall on &>/dev/null
        /usr/libexec/ApplicationFirewall/socketfilterfw --setallowsigned off &>/dev/null
        /usr/libexec/ApplicationFirewall/socketfilterfw --setallowsignedapp off &>/dev/null
        if /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null | grep -q "enabled\|State = 1\|State = 2"; then
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "applied"
            log_entry "firewall-inbound" "apply" "ok" "Firewall enabled, block all incoming"
            MODULE_RESULT="applied"
        else
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "failed"
            log_entry "firewall-inbound" "apply" "fail" "Could not enable firewall"
            MODULE_RESULT="failed"
        fi
    elif [[ "$OS" == "linux" ]]; then
        if command -v ufw &>/dev/null; then
            local ufw_status
            ufw_status=$(ufw status 2>/dev/null)
            if echo "$ufw_status" | grep -q "Status: active"; then
                print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc (ufw)" "skipped"
                log_entry "firewall-inbound" "check" "skip" "ufw already active"
                MODULE_RESULT="skipped"
                return
            fi
            ufw --force enable &>/dev/null
            ufw default deny incoming &>/dev/null
            if ufw status 2>/dev/null | grep -q "Status: active"; then
                print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc (ufw)" "applied"
                log_entry "firewall-inbound" "apply" "ok" "ufw enabled, default deny incoming"
                MODULE_RESULT="applied"
            else
                print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc (ufw)" "failed"
                log_entry "firewall-inbound" "apply" "fail" "Could not enable ufw"
                MODULE_RESULT="failed"
            fi
        else
            pkg_install ufw
            if command -v ufw &>/dev/null; then
                ufw --force enable &>/dev/null
                ufw default deny incoming &>/dev/null
                print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc (ufw)" "applied"
                log_entry "firewall-inbound" "apply" "ok" "Installed and enabled ufw"
                MODULE_RESULT="applied"
            else
                print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "failed"
                log_entry "firewall-inbound" "apply" "fail" "Could not install ufw"
                MODULE_RESULT="failed"
            fi
        fi
    fi
}

# ═══════════════════════════════════════════════════════════════════
# MODULE: dns-secure
# ═══════════════════════════════════════════════════════════════════
mod_dns_secure() {
    local desc="Configure encrypted DNS (Quad9)"
    if [[ "$OS" == "macos" ]]; then
        local current_dns
        current_dns=$(networksetup -getdnsservers Wi-Fi 2>/dev/null || echo "")
        if echo "$current_dns" | grep -q "9.9.9.9"; then
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "skipped"
            log_entry "dns-secure" "check" "skip" "Quad9 DNS already configured"
            MODULE_RESULT="skipped"
            return
        fi
        networksetup -setdnsservers Wi-Fi 9.9.9.9 149.112.112.112 &>/dev/null
        if networksetup -getdnsservers Wi-Fi 2>/dev/null | grep -q "9.9.9.9"; then
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "applied"
            log_entry "dns-secure" "apply" "ok" "Set DNS to Quad9 on Wi-Fi"
            MODULE_RESULT="applied"
        else
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "failed"
            log_entry "dns-secure" "apply" "fail" "Could not set DNS"
            MODULE_RESULT="failed"
        fi
    elif [[ "$OS" == "linux" ]]; then
        if command -v resolvectl &>/dev/null; then
            local current
            current=$(resolvectl dns 2>/dev/null || echo "")
            if echo "$current" | grep -q "9.9.9.9"; then
                print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "skipped"
                log_entry "dns-secure" "check" "skip" "Quad9 already configured"
                MODULE_RESULT="skipped"
                return
            fi
            # Configure systemd-resolved
            mkdir -p /etc/systemd/resolved.conf.d
            cat > /etc/systemd/resolved.conf.d/quad9.conf << 'DNSEOF'
[Resolve]
DNS=9.9.9.9#dns.quad9.net 149.112.112.112#dns.quad9.net
DNSOverTLS=yes
DNSSEC=yes
DNSEOF
            systemctl restart systemd-resolved &>/dev/null
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc (systemd-resolved)" "applied"
            log_entry "dns-secure" "apply" "ok" "Configured Quad9 DNS-over-TLS"
            MODULE_RESULT="applied"
        elif [[ -f /etc/resolv.conf ]]; then
            if grep -q "9.9.9.9" /etc/resolv.conf; then
                print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "skipped"
                log_entry "dns-secure" "check" "skip" "Quad9 in resolv.conf"
                MODULE_RESULT="skipped"
                return
            fi
            cp /etc/resolv.conf /etc/resolv.conf.bak
            echo -e "nameserver 9.9.9.9\nnameserver 149.112.112.112" > /etc/resolv.conf
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc (resolv.conf)" "applied"
            log_entry "dns-secure" "apply" "ok" "Set resolv.conf to Quad9"
            MODULE_RESULT="applied"
        else
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "failed"
            log_entry "dns-secure" "apply" "fail" "No supported DNS configuration method found"
            MODULE_RESULT="failed"
        fi
    fi
}

# ═══════════════════════════════════════════════════════════════════
# MODULE: auto-updates
# ═══════════════════════════════════════════════════════════════════
mod_auto_updates() {
    local desc="Enable automatic security updates"
    if [[ "$OS" == "macos" ]]; then
        local check
        check=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled 2>/dev/null || echo "0")
        if [[ "$check" == "1" ]]; then
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "skipped"
            log_entry "auto-updates" "check" "skip" "Auto-updates already enabled"
            MODULE_RESULT="skipped"
            return
        fi
        defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -bool true
        defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload -bool true
        defaults write /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall -bool true
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "applied"
        log_entry "auto-updates" "apply" "ok" "Enabled automatic updates"
        MODULE_RESULT="applied"
    elif [[ "$OS" == "linux" ]]; then
        if [[ "$DISTRO" == "debian" ]]; then
            if dpkg -l unattended-upgrades 2>/dev/null | grep -q "^ii"; then
                print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "skipped"
                log_entry "auto-updates" "check" "skip" "unattended-upgrades already installed"
                MODULE_RESULT="skipped"
                return
            fi
            DEBIAN_FRONTEND=noninteractive apt-get install -y unattended-upgrades &>/dev/null
            dpkg-reconfigure -plow unattended-upgrades &>/dev/null
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc (unattended-upgrades)" "applied"
            log_entry "auto-updates" "apply" "ok" "Installed unattended-upgrades"
            MODULE_RESULT="applied"
        elif [[ "$DISTRO" == "fedora" ]]; then
            if rpm -q dnf-automatic &>/dev/null; then
                print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "skipped"
                log_entry "auto-updates" "check" "skip" "dnf-automatic already installed"
                MODULE_RESULT="skipped"
                return
            fi
            dnf install -y dnf-automatic &>/dev/null
            systemctl enable --now dnf-automatic-install.timer &>/dev/null
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc (dnf-automatic)" "applied"
            log_entry "auto-updates" "apply" "ok" "Installed dnf-automatic"
            MODULE_RESULT="applied"
        else
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "manual"
            log_entry "auto-updates" "check" "manual" "Unknown distro, manual config needed"
            pause_guide "Configure automatic security updates for your distribution manually."
            MODULE_RESULT="manual"
        fi
    fi
}

# ═══════════════════════════════════════════════════════════════════
# MODULE: guest-disable
# ═══════════════════════════════════════════════════════════════════
mod_guest_disable() {
    local desc="Disable guest account"
    if [[ "$OS" == "macos" ]]; then
        local guest
        guest=$(defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled 2>/dev/null || echo "1")
        if [[ "$guest" == "0" ]]; then
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "skipped"
            log_entry "guest-disable" "check" "skip" "Guest account already disabled"
            MODULE_RESULT="skipped"
            return
        fi
        defaults write /Library/Preferences/com.apple.loginwindow GuestEnabled -bool false
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "applied"
        log_entry "guest-disable" "apply" "ok" "Disabled guest account"
        MODULE_RESULT="applied"
    elif [[ "$OS" == "linux" ]]; then
        if id guest &>/dev/null; then
            usermod -L guest &>/dev/null 2>&1 || true
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "applied"
            log_entry "guest-disable" "apply" "ok" "Locked guest account"
            MODULE_RESULT="applied"
        else
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "skipped"
            log_entry "guest-disable" "check" "skip" "No guest account exists"
            MODULE_RESULT="skipped"
        fi
    fi
}

# ═══════════════════════════════════════════════════════════════════
# MODULE: lock-screen
# ═══════════════════════════════════════════════════════════════════
mod_lock_screen() {
    local desc="Configure lock screen (password, timeout)"
    if [[ "$OS" == "macos" ]]; then
        local delay
        delay=$(run_as_user defaults read com.apple.screensaver askForPasswordDelay 2>/dev/null || echo "999")
        if [[ "$delay" == "0" ]]; then
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "skipped"
            log_entry "lock-screen" "check" "skip" "Lock screen already configured"
            MODULE_RESULT="skipped"
            return
        fi
        run_as_user defaults write com.apple.screensaver askForPassword -int 1
        run_as_user defaults write com.apple.screensaver askForPasswordDelay -int 0
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "applied"
        log_entry "lock-screen" "apply" "ok" "Set password required immediately"
        MODULE_RESULT="applied"
    elif [[ "$OS" == "linux" ]]; then
        # Try GNOME settings
        if command -v gsettings &>/dev/null; then
            local lock_enabled
            lock_enabled=$(run_as_user gsettings get org.gnome.desktop.screensaver lock-enabled 2>/dev/null || echo "")
            if [[ "$lock_enabled" == "true" ]]; then
                print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "skipped"
                log_entry "lock-screen" "check" "skip" "GNOME lock screen already enabled"
                MODULE_RESULT="skipped"
                return
            fi
            run_as_user gsettings set org.gnome.desktop.screensaver lock-enabled true 2>/dev/null
            run_as_user gsettings set org.gnome.desktop.screensaver lock-delay 0 2>/dev/null
            run_as_user gsettings set org.gnome.desktop.session idle-delay 300 2>/dev/null
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc (GNOME)" "applied"
            log_entry "lock-screen" "apply" "ok" "Configured GNOME lock screen"
            MODULE_RESULT="applied"
        else
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "manual"
            log_entry "lock-screen" "check" "manual" "No supported DE detected"
            pause_guide "Configure your desktop environment's lock screen: require password immediately after lock, timeout 5 minutes or less."
            MODULE_RESULT="manual"
        fi
    fi
}

# ═══════════════════════════════════════════════════════════════════
# MODULE: browser-basic
# ═══════════════════════════════════════════════════════════════════
mod_browser_basic() {
    local desc="Basic browser hardening (Firefox)"
    local ff_profile=""

    if [[ "$OS" == "macos" ]]; then
        ff_profile=$(find "${REAL_HOME}/Library/Application Support/Firefox/Profiles" -maxdepth 1 -name "*.default-release" -type d 2>/dev/null | head -1)
    elif [[ "$OS" == "linux" ]]; then
        ff_profile=$(find "${REAL_HOME}/.mozilla/firefox" -maxdepth 1 -name "*.default-release" -type d 2>/dev/null | head -1)
    fi

    if [[ -z "$ff_profile" ]]; then
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "manual"
        log_entry "browser-basic" "check" "manual" "Firefox profile not found"
        pause_guide "Install Firefox and run it once to create a profile, then re-run this script."
        MODULE_RESULT="manual"
        return
    fi

    if [[ -f "${ff_profile}/user.js" ]] && grep -q "toolkit.telemetry.enabled" "${ff_profile}/user.js" 2>/dev/null; then
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "skipped"
        log_entry "browser-basic" "check" "skip" "user.js already configured"
        MODULE_RESULT="skipped"
        return
    fi

    cat > "${ff_profile}/user.js" << 'FFEOF'
// Firefox Hardening — Basic Profile
// Telemetry & Data Collection
user_pref("toolkit.telemetry.enabled", false);
user_pref("toolkit.telemetry.unified", false);
user_pref("toolkit.telemetry.archive.enabled", false);
user_pref("datareporting.healthreport.uploadEnabled", false);
user_pref("datareporting.policy.dataSubmissionEnabled", false);
user_pref("browser.ping-centre.telemetry", false);
user_pref("browser.newtabpage.activity-stream.feeds.telemetry", false);
user_pref("browser.newtabpage.activity-stream.telemetry", false);
user_pref("app.shield.optoutstudies.enabled", false);
user_pref("app.normandy.enabled", false);
// Privacy
user_pref("privacy.trackingprotection.enabled", true);
user_pref("privacy.trackingprotection.socialtracking.enabled", true);
// Security
user_pref("dom.security.https_only_mode", true);
user_pref("dom.security.https_only_mode_ever_enabled", true);
user_pref("browser.safebrowsing.malware.enabled", true);
user_pref("browser.safebrowsing.phishing.enabled", true);
// Disable risky features
user_pref("media.peerconnection.enabled", false);
user_pref("geo.enabled", false);
// Disable Pocket & Sponsored
user_pref("extensions.pocket.enabled", false);
user_pref("browser.newtabpage.activity-stream.showSponsored", false);
user_pref("browser.newtabpage.activity-stream.showSponsoredTopSites", false);
FFEOF
    chown "${REAL_USER}" "${ff_profile}/user.js" 2>/dev/null
    print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "applied"
    log_entry "browser-basic" "apply" "ok" "Created Firefox user.js with basic hardening"
    MODULE_RESULT="applied"
}

# ═══════════════════════════════════════════════════════════════════
# MODULE: firewall-stealth
# ═══════════════════════════════════════════════════════════════════
mod_firewall_stealth() {
    local desc="Enable firewall stealth mode"
    if [[ "$OS" == "macos" ]]; then
        local stealth
        stealth=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>/dev/null)
        if echo "$stealth" | grep -q "on"; then
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "skipped"
            log_entry "firewall-stealth" "check" "skip" "Stealth mode already on"
            MODULE_RESULT="skipped"
            return
        fi
        /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on &>/dev/null
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "applied"
        log_entry "firewall-stealth" "apply" "ok" "Stealth mode enabled"
        MODULE_RESULT="applied"
    elif [[ "$OS" == "linux" ]]; then
        # Drop ICMP echo requests
        if iptables -C INPUT -p icmp --icmp-type echo-request -j DROP &>/dev/null 2>&1; then
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc (drop ICMP)" "skipped"
            log_entry "firewall-stealth" "check" "skip" "ICMP drop rule already exists"
            MODULE_RESULT="skipped"
            return
        fi
        iptables -A INPUT -p icmp --icmp-type echo-request -j DROP &>/dev/null
        # Persist if possible
        if command -v iptables-save &>/dev/null; then
            iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
        fi
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc (drop ICMP)" "applied"
        log_entry "firewall-stealth" "apply" "ok" "Added iptables ICMP drop rule"
        MODULE_RESULT="applied"
    fi
}

# ═══════════════════════════════════════════════════════════════════
# MODULE: firewall-outbound
# ═══════════════════════════════════════════════════════════════════
mod_firewall_outbound() {
    local desc="Install outbound firewall"
    if [[ "$OS" == "macos" ]]; then
        if cask_installed lulu; then
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc (LuLu)" "skipped"
            log_entry "firewall-outbound" "check" "skip" "LuLu already installed"
            MODULE_RESULT="skipped"
            return
        fi
        pkg_install_cask lulu
        if cask_installed lulu; then
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc (LuLu)" "applied"
            log_entry "firewall-outbound" "apply" "ok" "Installed LuLu"
            pause_guide "Open LuLu from /Applications and grant system extension + network filter permissions."
            MODULE_RESULT="applied"
        else
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc (LuLu)" "failed"
            log_entry "firewall-outbound" "apply" "fail" "Could not install LuLu"
            MODULE_RESULT="failed"
        fi
    elif [[ "$OS" == "linux" ]]; then
        if command -v ufw &>/dev/null; then
            local outbound
            outbound=$(ufw status verbose 2>/dev/null | grep "Default:" | grep -o "deny (outgoing)" || echo "")
            if [[ -n "$outbound" ]]; then
                print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc (ufw deny outgoing)" "skipped"
                log_entry "firewall-outbound" "check" "skip" "ufw deny outgoing already set"
                MODULE_RESULT="skipped"
                return
            fi
            ufw default deny outgoing &>/dev/null
            # Allow essential outbound
            ufw allow out 53 &>/dev/null   # DNS
            ufw allow out 80 &>/dev/null   # HTTP
            ufw allow out 443 &>/dev/null  # HTTPS
            ufw allow out 853 &>/dev/null  # DNS-over-TLS
            ufw allow out 22 &>/dev/null   # SSH
            ufw reload &>/dev/null
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc (ufw deny outgoing)" "applied"
            log_entry "firewall-outbound" "apply" "ok" "Set default deny outgoing with essential ports allowed"
            MODULE_RESULT="applied"
        else
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "failed"
            log_entry "firewall-outbound" "apply" "fail" "ufw not available"
            MODULE_RESULT="failed"
        fi
    fi
}

# ═══════════════════════════════════════════════════════════════════
# MODULE: hostname-scrub
# ═══════════════════════════════════════════════════════════════════
mod_hostname_scrub() {
    local desc="Set generic hostname"
    local generic="localhost"
    if [[ "$OS" == "macos" ]]; then
        generic="MacBook"
        local current
        current=$(scutil --get ComputerName 2>/dev/null || echo "")
        if [[ "$current" == "$generic" ]]; then
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "skipped"
            log_entry "hostname-scrub" "check" "skip" "Hostname already generic"
            MODULE_RESULT="skipped"
            return
        fi
        scutil --set ComputerName "$generic"
        scutil --set LocalHostName "$generic"
        scutil --set HostName "$generic"
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc ($generic)" "applied"
        log_entry "hostname-scrub" "apply" "ok" "Hostname set to $generic"
        MODULE_RESULT="applied"
    elif [[ "$OS" == "linux" ]]; then
        generic="linux"
        local current
        current=$(hostname 2>/dev/null || echo "")
        if [[ "$current" == "$generic" ]]; then
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "skipped"
            log_entry "hostname-scrub" "check" "skip" "Hostname already generic"
            MODULE_RESULT="skipped"
            return
        fi
        hostnamectl set-hostname "$generic" &>/dev/null 2>&1 || hostname "$generic" 2>/dev/null
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc ($generic)" "applied"
        log_entry "hostname-scrub" "apply" "ok" "Hostname set to $generic"
        MODULE_RESULT="applied"
    fi
}

# ═══════════════════════════════════════════════════════════════════
# MODULE: ssh-harden
# ═══════════════════════════════════════════════════════════════════
mod_ssh_harden() {
    local desc="Harden SSH configuration"
    local ssh_dir="${REAL_HOME}/.ssh"
    local ssh_config="${ssh_dir}/config"

    if [[ -f "$ssh_config" ]] && grep -q "IdentitiesOnly yes" "$ssh_config" 2>/dev/null; then
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "skipped"
        log_entry "ssh-harden" "check" "skip" "SSH config already hardened"
        MODULE_RESULT="skipped"
        return
    fi

    mkdir -p "$ssh_dir"
    chmod 700 "$ssh_dir"

    # Generate Ed25519 key if none exists
    if [[ ! -f "${ssh_dir}/id_ed25519" ]]; then
        run_as_user ssh-keygen -t ed25519 -f "${ssh_dir}/id_ed25519" -N "" -q
    fi

    cat > "$ssh_config" << 'SSHEOF'
Host *
    IdentitiesOnly yes
    AddKeysToAgent yes
    HashKnownHosts yes
    PasswordAuthentication no
    StrictHostKeyChecking ask
    IdentityFile ~/.ssh/id_ed25519
    ServerAliveInterval 60
    ServerAliveCountMax 3
SSHEOF

    # macOS-specific: UseKeychain
    if [[ "$OS" == "macos" ]]; then
        sed -i '' '2a\
    UseKeychain yes
' "$ssh_config" 2>/dev/null || true
    fi

    chmod 600 "$ssh_config"
    chown -R "${REAL_USER}" "$ssh_dir" 2>/dev/null

    print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "applied"
    log_entry "ssh-harden" "apply" "ok" "SSH config hardened with Ed25519"
    MODULE_RESULT="applied"
}

# ═══════════════════════════════════════════════════════════════════
# MODULE: git-harden
# ═══════════════════════════════════════════════════════════════════
mod_git_harden() {
    local desc="Harden Git configuration"
    if ! command -v git &>/dev/null; then
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "skipped_unsupported"
        log_entry "git-harden" "check" "skip" "Git not installed"
        MODULE_RESULT="skipped_unsupported"
        return
    fi

    local signing
    signing=$(run_as_user git config --global --get commit.gpgsign 2>/dev/null || echo "")
    if [[ "$signing" == "true" ]]; then
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "skipped"
        log_entry "git-harden" "check" "skip" "Git signing already configured"
        MODULE_RESULT="skipped"
        return
    fi

    run_as_user git config --global gpg.format ssh
    if [[ -f "${REAL_HOME}/.ssh/id_ed25519.pub" ]]; then
        run_as_user git config --global user.signingkey "${REAL_HOME}/.ssh/id_ed25519.pub"
    fi
    run_as_user git config --global commit.gpgsign true
    run_as_user git config --global tag.gpgsign true

    if [[ "$OS" == "macos" ]]; then
        run_as_user git config --global credential.helper osxkeychain
    elif [[ "$OS" == "linux" ]]; then
        run_as_user git config --global credential.helper store
    fi

    print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "applied"
    log_entry "git-harden" "apply" "ok" "Git SSH signing + credential helper configured"
    MODULE_RESULT="applied"
}

# ═══════════════════════════════════════════════════════════════════
# MODULE: telemetry-disable
# ═══════════════════════════════════════════════════════════════════
mod_telemetry_disable() {
    local desc="Disable OS telemetry"
    if [[ "$OS" == "macos" ]]; then
        # Disable Siri analytics, diagnostic submissions
        defaults write com.apple.assistant.support "Assistant Enabled" -bool false 2>/dev/null
        defaults write com.apple.Siri StatusMenuVisible -bool false 2>/dev/null
        defaults write com.apple.CrashReporter DialogType -string "none" 2>/dev/null
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "applied"
        log_entry "telemetry-disable" "apply" "ok" "Disabled Siri, crash reporter dialog"
        MODULE_RESULT="applied"
    elif [[ "$OS" == "linux" ]]; then
        local changed=false
        # Ubuntu/GNOME telemetry
        if command -v gsettings &>/dev/null; then
            run_as_user gsettings set org.gnome.desktop.privacy report-technical-problems false 2>/dev/null && changed=true
            run_as_user gsettings set org.gnome.desktop.privacy send-software-usage-stats false 2>/dev/null && changed=true
        fi
        # Disable apport (Ubuntu crash reporter)
        if [[ -f /etc/default/apport ]]; then
            sed -i 's/enabled=1/enabled=0/' /etc/default/apport 2>/dev/null && changed=true
            systemctl stop apport.service &>/dev/null 2>&1 || true
            systemctl disable apport.service &>/dev/null 2>&1 || true
        fi
        if $changed; then
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "applied"
            log_entry "telemetry-disable" "apply" "ok" "Disabled OS telemetry"
            MODULE_RESULT="applied"
        else
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "skipped"
            log_entry "telemetry-disable" "check" "skip" "No telemetry settings found to disable"
            MODULE_RESULT="skipped"
        fi
    fi
}

# ═══════════════════════════════════════════════════════════════════
# MODULE: monitoring-tools
# ═══════════════════════════════════════════════════════════════════
mod_monitoring_tools() {
    local desc="Install security monitoring tools"
    if [[ "$OS" == "macos" ]]; then
        local tools_installed=0
        local tools_total=4
        for tool in oversight blockblock knockknock ransomwhere; do
            if cask_installed "$tool"; then
                ((tools_installed++))
            fi
        done
        if [[ $tools_installed -eq $tools_total ]]; then
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc (Objective-See)" "skipped"
            log_entry "monitoring-tools" "check" "skip" "All Objective-See tools installed"
            MODULE_RESULT="skipped"
            return
        fi
        for tool in oversight blockblock knockknock ransomwhere; do
            if ! cask_installed "$tool"; then
                pkg_install_cask "$tool"
            fi
        done
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc (Objective-See)" "applied"
        log_entry "monitoring-tools" "apply" "ok" "Installed Objective-See tools"
        MODULE_RESULT="applied"
    elif [[ "$OS" == "linux" ]]; then
        local installed_any=false
        # auditd
        if ! command -v auditd &>/dev/null && ! command -v auditctl &>/dev/null; then
            case "$DISTRO" in
                debian) pkg_install auditd && installed_any=true ;;
                fedora) pkg_install audit && installed_any=true ;;
                arch)   pkg_install audit && installed_any=true ;;
            esac
            systemctl enable --now auditd &>/dev/null 2>&1 || true
        fi
        # aide (file integrity)
        if ! command -v aide &>/dev/null; then
            pkg_install aide && installed_any=true
            aide --init &>/dev/null 2>&1 || true
            cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db &>/dev/null 2>&1 || true
        fi
        # rkhunter
        if ! command -v rkhunter &>/dev/null; then
            pkg_install rkhunter && installed_any=true
            rkhunter --update &>/dev/null 2>&1 || true
            rkhunter --propupd &>/dev/null 2>&1 || true
        fi
        # fail2ban
        if ! command -v fail2ban-client &>/dev/null; then
            pkg_install fail2ban && installed_any=true
            systemctl enable --now fail2ban &>/dev/null 2>&1 || true
        fi
        if $installed_any; then
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc (auditd, aide, rkhunter, fail2ban)" "applied"
            log_entry "monitoring-tools" "apply" "ok" "Installed Linux monitoring tools"
            MODULE_RESULT="applied"
        else
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "skipped"
            log_entry "monitoring-tools" "check" "skip" "Monitoring tools already installed"
            MODULE_RESULT="skipped"
        fi
    fi
}

# ═══════════════════════════════════════════════════════════════════
# MODULE: permissions-audit
# ═══════════════════════════════════════════════════════════════════
mod_permissions_audit() {
    local desc="Audit privacy/security permissions"
    if [[ "$OS" == "macos" ]]; then
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "manual"
        log_entry "permissions-audit" "check" "manual" "Requires GUI review"
        pause_guide "Review System Settings > Privacy & Security. Check: Full Disk Access, Accessibility, Input Monitoring, Screen Recording, Camera, Microphone. Remove anything unnecessary."
        MODULE_RESULT="manual"
    elif [[ "$OS" == "linux" ]]; then
        # Check SUID binaries
        local suid_count
        suid_count=$(find / -perm -4000 -type f 2>/dev/null | wc -l)
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc (${suid_count} SUID binaries)" "applied"
        log_entry "permissions-audit" "check" "ok" "Found ${suid_count} SUID binaries on system"
        MODULE_RESULT="applied"
    fi
}

# ═══════════════════════════════════════════════════════════════════
# MODULE: mac-rotate
# ═══════════════════════════════════════════════════════════════════
mod_mac_rotate() {
    local desc="Verify MAC address rotation"
    if [[ "$OS" == "macos" ]]; then
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "manual"
        log_entry "mac-rotate" "check" "manual" "Requires GUI verification"
        pause_guide "System Settings > Wi-Fi > click (i) on each saved network > set 'Private Wi-Fi address' to 'Rotating'. Also delete unused saved networks."
        MODULE_RESULT="manual"
    elif [[ "$OS" == "linux" ]]; then
        if command -v nmcli &>/dev/null; then
            local randomized
            randomized=$(nmcli general 2>/dev/null | grep -i "wifi" || echo "")
            # Set MAC randomization for NetworkManager
            local nm_conf="/etc/NetworkManager/conf.d/mac-randomize.conf"
            if [[ -f "$nm_conf" ]]; then
                print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "skipped"
                log_entry "mac-rotate" "check" "skip" "MAC randomization config exists"
                MODULE_RESULT="skipped"
                return
            fi
            mkdir -p /etc/NetworkManager/conf.d
            cat > "$nm_conf" << 'MACEOF'
[device]
wifi.scan-rand-mac-address=yes

[connection]
wifi.cloned-mac-address=random
ethernet.cloned-mac-address=random
MACEOF
            systemctl restart NetworkManager &>/dev/null 2>&1 || true
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc (NetworkManager)" "applied"
            log_entry "mac-rotate" "apply" "ok" "Enabled MAC randomization"
            MODULE_RESULT="applied"
        else
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "manual"
            log_entry "mac-rotate" "check" "manual" "NetworkManager not found"
            pause_guide "Configure MAC address randomization for your network manager manually."
            MODULE_RESULT="manual"
        fi
    fi
}

# ═══════════════════════════════════════════════════════════════════
# MODULE: vpn-killswitch
# ═══════════════════════════════════════════════════════════════════
mod_vpn_killswitch() {
    local desc="Configure VPN kill switch"
    if command -v mullvad &>/dev/null; then
        local always
        always=$(mullvad always-require-vpn get 2>/dev/null || echo "")
        if echo "$always" | grep -qi "enabled\|on"; then
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc (Mullvad)" "skipped"
            log_entry "vpn-killswitch" "check" "skip" "Mullvad kill switch already enabled"
            MODULE_RESULT="skipped"
            return
        fi
        mullvad always-require-vpn set on &>/dev/null 2>&1 || true
        mullvad dns set default --block-ads --block-trackers --block-malware &>/dev/null 2>&1 || true
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc (Mullvad)" "applied"
        log_entry "vpn-killswitch" "apply" "ok" "Mullvad always-require-vpn + DNS blocking enabled"
        MODULE_RESULT="applied"
    else
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "manual"
        log_entry "vpn-killswitch" "check" "manual" "Mullvad CLI not found"
        pause_guide "Install Mullvad VPN and enable: Always require VPN (kill switch), Block ads/trackers/malware in DNS settings, DAITA traffic analysis protection."
        MODULE_RESULT="manual"
    fi
}

# ═══════════════════════════════════════════════════════════════════
# MODULE: traffic-obfuscation
# ═══════════════════════════════════════════════════════════════════
mod_traffic_obfuscation() {
    local desc="Traffic obfuscation guidance"
    print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "manual"
    log_entry "traffic-obfuscation" "check" "manual" "Guidance-only module"
    pause_guide "For traffic analysis resistance: (1) Enable Mullvad DAITA in VPN settings. (2) Use Mullvad Browser or Tor Browser for sensitive browsing. (3) Consider Tor for metadata-sensitive tasks."
    MODULE_RESULT="manual"
}

# ═══════════════════════════════════════════════════════════════════
# MODULE: browser-fingerprint
# ═══════════════════════════════════════════════════════════════════
mod_browser_fingerprint() {
    local desc="Advanced browser fingerprint resistance"
    local ff_profile=""

    if [[ "$OS" == "macos" ]]; then
        ff_profile=$(find "${REAL_HOME}/Library/Application Support/Firefox/Profiles" -maxdepth 1 -name "*.default-release" -type d 2>/dev/null | head -1)
    elif [[ "$OS" == "linux" ]]; then
        ff_profile=$(find "${REAL_HOME}/.mozilla/firefox" -maxdepth 1 -name "*.default-release" -type d 2>/dev/null | head -1)
    fi

    if [[ -z "$ff_profile" ]]; then
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "manual"
        log_entry "browser-fingerprint" "check" "manual" "Firefox profile not found"
        MODULE_RESULT="manual"
        return
    fi

    if [[ -f "${ff_profile}/user.js" ]] && grep -q "privacy.resistFingerprinting" "${ff_profile}/user.js" 2>/dev/null; then
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "skipped"
        log_entry "browser-fingerprint" "check" "skip" "Fingerprint resistance already configured"
        MODULE_RESULT="skipped"
        return
    fi

    # Append advanced settings to existing user.js
    cat >> "${ff_profile}/user.js" << 'FPEOF'

// Advanced Fingerprint Resistance
user_pref("privacy.firstparty.isolate", true);
user_pref("privacy.resistFingerprinting", true);
user_pref("privacy.clearOnShutdown.cookies", true);
user_pref("privacy.clearOnShutdown.history", true);
user_pref("privacy.clearOnShutdown.offlineApps", true);
user_pref("privacy.clearOnShutdown.sessions", true);
user_pref("privacy.clearOnShutdown.cache", true);
user_pref("privacy.sanitize.sanitizeOnShutdown", true);
// DNS over HTTPS (Quad9)
user_pref("network.trr.mode", 2);
user_pref("network.trr.uri", "https://dns.quad9.net/dns-query");
// TLS hardening
user_pref("security.ssl.require_safe_negotiation", true);
user_pref("security.tls.version.min", 3);
user_pref("security.mixed_content.block_active_content", true);
user_pref("security.mixed_content.block_display_content", true);
// Disable prefetch
user_pref("network.prefetch-next", false);
user_pref("network.dns.disablePrefetch", true);
user_pref("network.http.speculative-parallel-limit", 0);
user_pref("browser.urlbar.speculativeConnect.enabled", false);
FPEOF
    chown "${REAL_USER}" "${ff_profile}/user.js" 2>/dev/null
    print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "applied"
    log_entry "browser-fingerprint" "apply" "ok" "Added fingerprint resistance + clear-on-shutdown"
    MODULE_RESULT="applied"
}

# ═══════════════════════════════════════════════════════════════════
# MODULE: metadata-strip
# ═══════════════════════════════════════════════════════════════════
mod_metadata_strip() {
    local desc="Install metadata stripping tools"
    if command -v exiftool &>/dev/null; then
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "skipped"
        log_entry "metadata-strip" "check" "skip" "exiftool already installed"
        MODULE_RESULT="skipped"
        return
    fi

    if [[ "$OS" == "macos" ]]; then
        pkg_install exiftool
    elif [[ "$OS" == "linux" ]]; then
        case "$DISTRO" in
            debian) pkg_install libimage-exiftool-perl ;;
            fedora) pkg_install perl-Image-ExifTool ;;
            arch)   pkg_install perl-image-exiftool ;;
        esac
        # Also install mat2 if available
        pkg_install mat2 2>/dev/null || true
    fi

    if command -v exiftool &>/dev/null; then
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc (exiftool)" "applied"
        log_entry "metadata-strip" "apply" "ok" "Installed exiftool"
        MODULE_RESULT="applied"
    else
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "failed"
        log_entry "metadata-strip" "apply" "fail" "Could not install exiftool"
        MODULE_RESULT="failed"
    fi
}

# ═══════════════════════════════════════════════════════════════════
# MODULE: dev-isolation
# ═══════════════════════════════════════════════════════════════════
mod_dev_isolation() {
    local desc="Development environment isolation"
    if [[ "$OS" == "macos" ]]; then
        local docker_ok=false utm_ok=false
        if command -v docker &>/dev/null; then docker_ok=true; fi
        if [[ -d "/Applications/UTM.app" ]]; then utm_ok=true; fi

        if $docker_ok && $utm_ok; then
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "skipped"
            log_entry "dev-isolation" "check" "skip" "Docker and UTM already available"
            MODULE_RESULT="skipped"
            return
        fi
        if ! $utm_ok; then
            pkg_install_cask utm
        fi
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "applied"
        log_entry "dev-isolation" "apply" "ok" "Dev isolation tools available"
        MODULE_RESULT="applied"
    elif [[ "$OS" == "linux" ]]; then
        local docker_ok=false
        if command -v docker &>/dev/null; then docker_ok=true; fi

        if $docker_ok; then
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc (Docker)" "skipped"
            log_entry "dev-isolation" "check" "skip" "Docker already installed"
            MODULE_RESULT="skipped"
            return
        fi
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "manual"
        log_entry "dev-isolation" "check" "manual" "Docker not installed"
        pause_guide "Install Docker for container-based dev isolation: https://docs.docker.com/engine/install/ — Avoid --privileged and --net=host flags. Bind-mount only specific project directories."
        MODULE_RESULT="manual"
    fi
}

# ═══════════════════════════════════════════════════════════════════
# MODULE: audit-script
# ═══════════════════════════════════════════════════════════════════
mod_audit_script() {
    local desc="Set up weekly security audit"
    local audit_dir="${SCRIPT_DIR}/../audits"
    local baseline_dir="${SCRIPT_DIR}/../baseline"

    mkdir -p "$audit_dir" "$baseline_dir" 2>/dev/null

    if [[ "$OS" == "macos" ]]; then
        local plist="${REAL_HOME}/Library/LaunchAgents/com.secure.weekly-audit.plist"
        if [[ -f "$plist" ]]; then
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "skipped"
            log_entry "audit-script" "check" "skip" "Audit launchd agent already exists"
            MODULE_RESULT="skipped"
            return
        fi
        # Create audit script
        cat > "${SCRIPT_DIR}/weekly-audit-generated.sh" << 'AUDITEOF'
#!/bin/bash
set -euo pipefail
AUDIT_DIR="$(dirname "$0")/../audits"
BASELINE_DIR="$(dirname "$0")/../baseline"
DATE=$(date +%Y-%m-%d)
REPORT="$AUDIT_DIR/audit-$DATE.md"
mkdir -p "$AUDIT_DIR"
exec > "$REPORT" 2>&1
echo "# Security Audit — $DATE"
echo ""
echo "## System Protection"
echo '```'
echo "SIP: $(csrutil status 2>/dev/null)"
echo "FileVault: $(fdesetup status 2>/dev/null)"
echo "Gatekeeper: $(/usr/sbin/spctl --status 2>/dev/null)"
echo "Firewall: $(sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null)"
echo '```'
echo ""
echo "## Network"
echo '```'
echo "DNS: $(networksetup -getdnsservers Wi-Fi 2>/dev/null)"
echo "VPN: $(mullvad status 2>/dev/null || echo 'Check manually')"
echo '```'
echo ""
echo "## LaunchDaemons"
echo '```'
ls /Library/LaunchDaemons/ 2>/dev/null
echo '```'
echo ""
echo "## Applications"
echo '```'
ls /Applications/ 2>/dev/null
echo '```'
echo ""
echo "## Homebrew"
echo '```'
brew list --formula 2>/dev/null
echo "---"
brew list --cask 2>/dev/null
echo '```'
echo ""
echo "## Hostname"
echo '```'
echo "$(scutil --get ComputerName 2>/dev/null)"
echo '```'
echo ""
echo "---"
echo "Audit complete."
AUDITEOF
        chmod +x "${SCRIPT_DIR}/weekly-audit-generated.sh"
        # Create launchd plist
        cat > "$plist" << PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.secure.weekly-audit</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>${SCRIPT_DIR}/weekly-audit-generated.sh</string>
    </array>
    <key>StartCalendarInterval</key>
    <dict>
        <key>Weekday</key>
        <integer>1</integer>
        <key>Hour</key>
        <integer>10</integer>
    </dict>
    <key>RunAtLoad</key>
    <false/>
</dict>
</plist>
PLISTEOF
        chown "${REAL_USER}" "$plist"
        run_as_user launchctl load "$plist" &>/dev/null 2>&1 || true
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc (launchd, Mondays 10 AM)" "applied"
        log_entry "audit-script" "apply" "ok" "Weekly audit scheduled"
        MODULE_RESULT="applied"

    elif [[ "$OS" == "linux" ]]; then
        local cron_check
        cron_check=$(crontab -u "${REAL_USER}" -l 2>/dev/null | grep "weekly-audit" || echo "")
        if [[ -n "$cron_check" ]]; then
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "skipped"
            log_entry "audit-script" "check" "skip" "Cron audit job already exists"
            MODULE_RESULT="skipped"
            return
        fi
        # Create Linux audit script
        cat > "${SCRIPT_DIR}/weekly-audit-linux.sh" << 'LAUDITEOF'
#!/bin/bash
set -euo pipefail
AUDIT_DIR="$(dirname "$0")/../audits"
DATE=$(date +%Y-%m-%d)
REPORT="$AUDIT_DIR/audit-$DATE.md"
mkdir -p "$AUDIT_DIR"
exec > "$REPORT" 2>&1
echo "# Security Audit — $DATE"
echo ""
echo "## Firewall"
echo '```'
ufw status verbose 2>/dev/null || iptables -L -n 2>/dev/null || echo "No firewall info"
echo '```'
echo ""
echo "## DNS"
echo '```'
resolvectl dns 2>/dev/null || cat /etc/resolv.conf 2>/dev/null
echo '```'
echo ""
echo "## Listening Ports"
echo '```'
ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null
echo '```'
echo ""
echo "## Hostname"
echo '```'
hostname
echo '```'
echo ""
echo "## Failed Login Attempts"
echo '```'
journalctl -u sshd --since "1 week ago" 2>/dev/null | grep -i "failed" | tail -20 || echo "N/A"
echo '```'
echo ""
echo "---"
echo "Audit complete."
LAUDITEOF
        chmod +x "${SCRIPT_DIR}/weekly-audit-linux.sh"
        # Schedule via cron (Monday 10 AM)
        (crontab -u "${REAL_USER}" -l 2>/dev/null; echo "0 10 * * 1 /bin/bash ${SCRIPT_DIR}/weekly-audit-linux.sh # weekly-audit") | crontab -u "${REAL_USER}" -
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc (cron, Mondays 10 AM)" "applied"
        log_entry "audit-script" "apply" "ok" "Weekly audit cron job added"
        MODULE_RESULT="applied"
    fi

    # Take baseline snapshot
    if [[ "$OS" == "macos" ]]; then
        brew list --formula 2>/dev/null | sort > "${baseline_dir}/brew-formulae.txt" 2>/dev/null || true
        brew list --cask 2>/dev/null | sort > "${baseline_dir}/brew-casks.txt" 2>/dev/null || true
        ls /Library/LaunchDaemons/ 2>/dev/null | sort > "${baseline_dir}/launch-daemons.txt" 2>/dev/null || true
        ls /Applications/ 2>/dev/null | sort > "${baseline_dir}/applications.txt" 2>/dev/null || true
    elif [[ "$OS" == "linux" ]]; then
        case "$DISTRO" in
            debian) dpkg --get-selections 2>/dev/null | sort > "${baseline_dir}/packages.txt" || true ;;
            fedora) rpm -qa 2>/dev/null | sort > "${baseline_dir}/packages.txt" || true ;;
            arch)   pacman -Qqe 2>/dev/null | sort > "${baseline_dir}/packages.txt" || true ;;
        esac
        systemctl list-unit-files --state=enabled 2>/dev/null | sort > "${baseline_dir}/enabled-services.txt" || true
    fi
}

# ═══════════════════════════════════════════════════════════════════
# MODULE: backup-guidance
# ═══════════════════════════════════════════════════════════════════
mod_backup_guidance() {
    local desc="Encrypted backup strategy"
    print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "manual"
    log_entry "backup-guidance" "check" "manual" "Guidance-only module"

    if [[ "$OS" == "macos" ]]; then
        pause_guide "Backup checklist: (1) Enable encrypted Time Machine to an external drive. (2) Back up SSH keys, 2FA recovery codes to encrypted USB stored offsite. (3) Use Proton Drive or similar E2E encrypted cloud for critical documents. (4) Store FileVault + Apple ID recovery keys on paper in a separate physical location."
    elif [[ "$OS" == "linux" ]]; then
        pause_guide "Backup checklist: (1) Set up encrypted backups with Borgbackup or restic to external drive. (2) Back up SSH keys, GPG keys, 2FA recovery codes to encrypted USB stored offsite. (3) Use E2E encrypted cloud storage for critical documents. (4) Store LUKS recovery passphrase on paper in a separate physical location."
    fi
    MODULE_RESULT="manual"
}

# ═══════════════════════════════════════════════════════════════════
# MODULE: border-prep
# ═══════════════════════════════════════════════════════════════════
mod_border_prep() {
    local desc="Border crossing preparation"
    print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "manual"
    log_entry "border-prep" "check" "manual" "Guidance-only module"
    pause_guide "Border crossing protocol: (1) Back up everything before travel. (2) Power off completely before checkpoints (flushes keys from memory, forces password-only unlock). (3) Consider a clean travel user account with minimal data. (4) If device is seized: remote wipe via Find My (macOS) or similar. (5) Have a credential rotation checklist ready."
    MODULE_RESULT="manual"
}

# ═══════════════════════════════════════════════════════════════════
# MODULE: bluetooth-disable
# ═══════════════════════════════════════════════════════════════════
mod_bluetooth_disable() {
    local desc="Bluetooth management"
    if [[ "$OS" == "macos" ]]; then
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "manual"
        log_entry "bluetooth-disable" "check" "manual" "User preference required"
        pause_guide "Disable Bluetooth via Control Center when not actively using peripherals. Bluetooth beacons leak device identifiers even with Lockdown Mode."
        MODULE_RESULT="manual"
    elif [[ "$OS" == "linux" ]]; then
        if systemctl is-active bluetooth &>/dev/null 2>&1; then
            if prompt_yn "Disable Bluetooth service? (You can re-enable later)"; then
                systemctl disable --now bluetooth &>/dev/null 2>&1
                print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "applied"
                log_entry "bluetooth-disable" "apply" "ok" "Bluetooth service disabled"
                MODULE_RESULT="applied"
            else
                print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "skipped"
                log_entry "bluetooth-disable" "check" "skip" "User chose to keep Bluetooth"
                MODULE_RESULT="skipped"
            fi
        else
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "skipped"
            log_entry "bluetooth-disable" "check" "skip" "Bluetooth already disabled"
            MODULE_RESULT="skipped"
        fi
    fi
}

# ═══════════════════════════════════════════════════════════════════
# OUTPUT: SUMMARY & REPORTS
# ═══════════════════════════════════════════════════════════════════
print_summary() {
    echo ""
    echo -e "${BOLD}${WHITE}═══════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${WHITE}  Hardening Complete${NC}"
    echo -e "${BOLD}${WHITE}═══════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${GREEN}✓${NC} Applied:    ${BOLD}${COUNT_APPLIED}${NC}"
    echo -e "  ${GREEN}○${NC} Skipped:    ${BOLD}${COUNT_SKIPPED}${NC} ${DIM}(already applied)${NC}"
    echo -e "  ${RED}✗${NC} Failed:     ${BOLD}${COUNT_FAILED}${NC}$([ $COUNT_FAILED -gt 0 ] && echo -e " ${RED}(see log)${NC}")"
    echo -e "  ${YELLOW}☐${NC} Manual:     ${BOLD}${COUNT_MANUAL}${NC}$([ $COUNT_MANUAL -gt 0 ] && echo -e " ${YELLOW}(see below)${NC}")"
    echo ""
    echo -e "  Profile: ${BOLD}${PROFILE}${NC} | OS: ${BOLD}${OS}${NC} | Date: ${BOLD}${DATE}${NC}"
    echo ""
}

print_manual_checklist() {
    if [[ ${#MANUAL_STEPS[@]} -gt 0 ]]; then
        print_section "Manual Steps Remaining"
        for i in "${!MANUAL_STEPS[@]}"; do
            echo -e "  ${YELLOW}☐${NC} $((i+1)). ${MANUAL_STEPS[$i]}"
            echo ""
        done
    fi
}

write_report() {
    local report_file="${SCRIPT_DIR}/../audits/hardening-report-${DATE}.md"
    {
        echo "# Hardening Report — ${DATE}"
        echo ""
        echo "**Profile:** ${PROFILE}"
        echo "**OS:** ${OS} $([ -n "$DISTRO" ] && echo "(${DISTRO})")"
        echo "**Generated:** ${TIMESTAMP}"
        echo ""
        echo "## Summary"
        echo ""
        echo "| Status | Count |"
        echo "|--------|-------|"
        echo "| Applied | ${COUNT_APPLIED} |"
        echo "| Skipped (already done) | ${COUNT_SKIPPED} |"
        echo "| Failed | ${COUNT_FAILED} |"
        echo "| Manual steps | ${COUNT_MANUAL} |"
        echo ""
        echo "## Log"
        echo ""
        echo '```'
        for entry in "${LOG_ENTRIES[@]}"; do
            echo "$entry"
        done
        echo '```'
        echo ""
        if [[ ${#MANUAL_STEPS[@]} -gt 0 ]]; then
            echo "## Manual Steps"
            echo ""
            for i in "${!MANUAL_STEPS[@]}"; do
                echo "- [ ] ${MANUAL_STEPS[$i]}"
            done
            echo ""
        fi
        echo "---"
        echo "Generated by harden.sh v${VERSION}"
    } > "$report_file"
    echo -e "  ${GREEN}Report written to:${NC} ${report_file}"
}

write_log() {
    mkdir -p "$(dirname "$LOG_FILE")"
    {
        echo "# Hardening Log — ${TIMESTAMP}"
        echo "Profile: ${PROFILE} | OS: ${OS}"
        echo ""
        for entry in "${LOG_ENTRIES[@]}"; do
            echo "$entry"
        done
    } > "$LOG_FILE"
    echo -e "  ${DIM}Log written to: ${LOG_FILE}${NC}"
}

# ═══════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════
main() {
    print_header
    detect_os
    check_privileges

    select_profile
    select_output_mode

    build_module_list

    echo ""
    echo -e "  Modules to apply: ${BOLD}${TOTAL_MODULES}${NC}"
    echo ""
    if ! prompt_yn "Proceed with hardening?"; then
        echo "Aborted."
        exit 0
    fi

    run_all_modules

    # Output
    print_summary

    case "$OUTPUT_MODE" in
        checklist) print_manual_checklist ;;
        pause)     ;; # Already guided through
        report)    write_report ;;
    esac

    write_log

    echo ""
    echo -e "  ${DIM}Re-run this script anytime — it's safe to repeat.${NC}"
    echo ""
}

main "$@"
