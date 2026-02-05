#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
# barked.sh — Cross-platform security hardening wizard (macOS/Linux)
# Idempotent, interactive, profile-based system hardening
# ═══════════════════════════════════════════════════════════════════
set -uo pipefail

# Bash 4+ required for associative arrays
if ((BASH_VERSINFO[0] < 4)); then
    echo "Error: barked requires Bash 4.0 or later (found ${BASH_VERSION})."
    echo ""
    if [[ "$(uname -s)" == "Darwin" ]]; then
        echo "  macOS ships Bash 3.2. Install a newer version:"
        echo "    brew install bash"
        echo "  Then run:  /opt/homebrew/bin/bash $(basename "$0") $*"
        echo "  Or add /opt/homebrew/bin/bash to /etc/shells and chsh."
    else
        echo "  Install bash 4+: sudo apt install bash  (or equivalent)"
    fi
    exit 1
fi

readonly VERSION="2.5.0"
readonly GITHUB_REPO="sth8pwd5wx-max/barked"
readonly SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
readonly DATE="$(date +%Y-%m-%d)"
readonly TIMESTAMP="$(date '+%Y-%m-%d %H:%M:%S')"
if [[ -d "${SCRIPT_DIR}/../audits" ]]; then
    LOG_FILE="${SCRIPT_DIR}/../audits/hardening-log-${DATE}.txt"
else
    mkdir -p "${HOME}/.config/barked/logs"
    LOG_FILE="${HOME}/.config/barked/logs/hardening-log-${DATE}.txt"
fi

# ═══════════════════════════════════════════════════════════════════
# COLORS & FORMATTING
# ═══════════════════════════════════════════════════════════════════
if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    BROWN='\033[0;33m'
    YELLOW='\033[0;33m'
    BLUE='\033[0;34m'
    MAGENTA='\033[0;35m'
    CYAN='\033[0;36m'
    WHITE='\033[1;37m'
    DIM='\033[2m'
    BOLD='\033[1m'
    NC='\033[0m'
else
    RED='' GREEN='' BROWN='' YELLOW='' BLUE='' MAGENTA='' CYAN='' WHITE='' DIM='' BOLD='' NC=''
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

# Run mode: "harden", "uninstall", "modify"
RUN_MODE="harden"
MODULE_MODE="apply"          # "apply" or "revert"
REMOVE_PACKAGES=false        # whether to remove packages during uninstall
COUNT_REVERTED=0

# Modes
DRY_RUN=false
AUTO_MODE=false
AUDIT_MODE=false
QUIET_MODE=false
ACCEPT_ADVANCED=false
AUTO_PROFILE=""              # profile name for --auto mode

# Clean mode
CLEAN_MODE=false
CLEAN_FORCE=false
CLEAN_SCHEDULED=false
CLEAN_SCHEDULE_SETUP=false
CLEAN_UNSCHEDULE=false

# Scheduled clean config (loaded from config file)
SCHED_ENABLED=""
SCHED_SCHEDULE=""
SCHED_NOTIFY=""
declare -a SCHED_CATEGORIES=()

# Two-phase execution state
NO_SUDO_MODE=false               # --no-sudo flag
declare -a USERSPACE_MODULES=()  # Modules that don't need root
declare -a ROOT_MODULES_LIST=()  # Modules that need root (ordered)
declare -A ROOT_COMMANDS=()      # module -> newline-separated commands
declare -A ROOT_COMMAND_DESCS=() # module -> human description
ROOT_BATCH_ABORTED=false         # Set true if root batch fails
ROOT_BATCH_FAIL_CMD=""           # Command that failed
ROOT_BATCH_FAIL_EXIT=0           # Exit code of failed command
ROOT_BATCH_FAIL_MODULE=""        # Module that failed

# Clean log
if [[ -d "${SCRIPT_DIR}/../audits" ]]; then
    CLEAN_LOG_FILE="${SCRIPT_DIR}/../audits/clean-log-${DATE}.txt"
else
    mkdir -p "${HOME}/.config/barked/logs"
    CLEAN_LOG_FILE="${HOME}/.config/barked/logs/clean-log-${DATE}.txt"
fi

# ═══════════════════════════════════════════════════════════════════
# MONITOR MODE GLOBALS
# ═══════════════════════════════════════════════════════════════════
MONITOR_MODE=false
MONITOR_INIT=false
MONITOR_BASELINE=false
MONITOR_TEST_ALERT=false
MONITOR_INTERVAL=300           # seconds between checks (default: 5 min)
MONITOR_PID_FILE="${HOME}/.config/barked/monitor.pid"
MONITOR_LOG_FILE="${HOME}/.config/barked/monitor.log"
MONITOR_CONFIG_FILE="${HOME}/.config/barked/monitor.conf"
MONITOR_STATE_DIR="${HOME}/.config/barked/state"
MONITOR_BASELINE_DIR="${HOME}/.config/barked/baselines"

# Alert configuration (loaded from config file)
ALERT_WEBHOOK_URL=""
ALERT_SLACK_URL=""
ALERT_DISCORD_URL=""
ALERT_MACOS_NOTIFY=true
ALERT_EMAIL_ENABLED=false
ALERT_EMAIL_API_URL=""
ALERT_EMAIL_API_KEY=""
ALERT_EMAIL_TO=""
ALERT_COOLDOWN=3600
ALERT_SEVERITY_MIN="warning"

# Monitor categories to check
MONITOR_CATEGORIES="supply-chain,cloud-sync,network,dev-env"

# Alert deduplication tracking
declare -A MONITOR_LAST_ALERT=()

# Daemon installation state
MONITOR_DAEMON_MODE=false        # Running as installed daemon
MONITOR_INSTALL=false            # --install flag
MONITOR_UNINSTALL=false          # --uninstall flag
MONITOR_ENABLE=false             # --enable flag
MONITOR_DISABLE=false            # --disable flag
MONITOR_RESTART=false            # --restart flag
MONITOR_STATUS=false             # --status flag
MONITOR_LOGS=false               # --logs flag
MONITOR_LOGS_FOLLOW=false        # --logs -f flag
MONITOR_ALERTS=false             # --alerts flag
MONITOR_HEALTH=false             # --health flag
MONITOR_CONFIG=false             # --config flag

# Daemon config (loaded from monitor.conf)
DAEMON_ENABLED=true
DAEMON_START_MODE="always"       # "always" | "ac_power" | "manual"
DAEMON_INSTALLED=false

# Notification detail config
NOTIFY_SHOW_IMPACT=true
NOTIFY_SHOW_REMEDIATION=true
NOTIFY_MACOS_CLICK_ACTION="log"

# Clean category toggles (1=selected, 0=not)
declare -A CLEAN_CATEGORIES=(
    [system-caches]=0
    [user-caches]=0
    [browser-data]=0
    [privacy-traces]=0
    [dev-cruft]=0
    [trash-downloads]=0
    [mail-messages]=0
)

# Clean target toggles (1=selected, 0=not)
declare -A CLEAN_TARGETS=()

# Clean results tracking
declare -A CLEAN_SCAN_FILES=()    # target -> file count
declare -A CLEAN_SCAN_BYTES=()    # target -> byte count
declare -A CLEAN_RESULT_FILES=()  # target -> files removed
declare -A CLEAN_RESULT_BYTES=()  # target -> bytes freed
declare -A CLEAN_RESULT_STATUS=() # target -> pass|fail|skip|partial
declare -a CLEAN_LOG=()           # log lines for clean-log file

# Cleanliness severity map
declare -A CLEAN_SEVERITY=(
    [system-cache]="MEDIUM"
    [system-logs]="MEDIUM"
    [diagnostic-reports]="LOW"
    [dns-cache]="MEDIUM"
    [user-cache]="HIGH"
    [user-logs]="HIGH"
    [saved-app-state]="HIGH"
    [safari]="CRITICAL"
    [chrome]="CRITICAL"
    [firefox]="CRITICAL"
    [arc]="CRITICAL"
    [edge]="CRITICAL"
    [recent-items]="CRITICAL"
    [quicklook-thumbs]="HIGH"
    [ds-store]="LOW"
    [clipboard]="CRITICAL"
    [search-metadata]="CRITICAL"
    [xcode-derived]="MEDIUM"
    [homebrew-cache]="MEDIUM"
    [npm-cache]="MEDIUM"
    [yarn-cache]="MEDIUM"
    [pip-cache]="MEDIUM"
    [cargo-cache]="MEDIUM"
    [go-cache]="MEDIUM"
    [cocoapods-cache]="MEDIUM"
    [docker-cruft]="MEDIUM"
    [ide-caches]="MEDIUM"
    [trash]="LOW"
    [old-downloads]="LOW"
    [mail-cache]="HIGH"
    [messages-attachments]="HIGH"
)

# Category -> targets mapping
declare -A CLEAN_CAT_TARGETS=(
    [system-caches]="system-cache system-logs diagnostic-reports dns-cache"
    [user-caches]="user-cache user-logs saved-app-state"
    [browser-data]="safari chrome firefox arc edge"
    [privacy-traces]="recent-items quicklook-thumbs ds-store clipboard search-metadata"
    [dev-cruft]="xcode-derived homebrew-cache npm-cache yarn-cache pip-cache cargo-cache go-cache cocoapods-cache docker-cruft ide-caches"
    [trash-downloads]="trash old-downloads"
    [mail-messages]="mail-cache messages-attachments"
)

# Display names
declare -A CLEAN_CAT_NAMES=(
    [system-caches]="System Caches & Logs"
    [user-caches]="User Caches & Logs"
    [browser-data]="Browser Data"
    [privacy-traces]="Privacy Traces"
    [dev-cruft]="Developer Cruft"
    [trash-downloads]="Trash & Downloads"
    [mail-messages]="Mail & Messages"
)

declare -A CLEAN_TARGET_NAMES=(
    [system-cache]="System cache"
    [system-logs]="System logs"
    [diagnostic-reports]="Diagnostic reports"
    [dns-cache]="DNS cache"
    [user-cache]="User cache"
    [user-logs]="User logs"
    [saved-app-state]="Saved application state"
    [safari]="Safari cache & data"
    [chrome]="Chrome cache & data"
    [firefox]="Firefox cache & data"
    [arc]="Arc cache & data"
    [edge]="Edge cache & data"
    [recent-items]="Recent items"
    [quicklook-thumbs]="QuickLook thumbnails"
    [ds-store]=".DS_Store files"
    [clipboard]="Clipboard"
    [search-metadata]="Search metadata"
    [xcode-derived]="Xcode derived data"
    [homebrew-cache]="Homebrew cache"
    [npm-cache]="npm cache"
    [yarn-cache]="yarn cache"
    [pip-cache]="pip cache"
    [cargo-cache]="Cargo cache"
    [go-cache]="Go cache"
    [cocoapods-cache]="CocoaPods cache"
    [docker-cruft]="Docker cruft"
    [ide-caches]="IDE caches"
    [trash]="Trash"
    [old-downloads]="Old downloads (30+ days)"
    [mail-cache]="Mail attachment cache"
    [messages-attachments]="Messages attachments"
)

# Ordered category keys (for display order)
CLEAN_CAT_ORDER=(system-caches user-caches browser-data privacy-traces dev-cruft trash-downloads mail-messages)

# State file locations
STATE_FILE_USER="${HOME}/.config/barked/state.json"
STATE_FILE_PROJECT="${SCRIPT_DIR}/../state/hardening-state.json"
STATE_FILE_LEGACY="/etc/hardening-state.json"
STATE_EXISTS=false

# Scheduled clean config locations
SCHED_CLEAN_CONFIG_USER="${HOME}/.config/barked/scheduled-clean.json"
SCHED_CLEAN_CONFIG_PROJECT="${SCRIPT_DIR}/../state/scheduled-clean.json"

declare -A STATE_MODULES=()     # module_id -> status
declare -A STATE_PREVIOUS=()    # module_id -> previous_value
declare -A STATE_TIMESTAMPS=()  # module_id -> applied_at
declare -a STATE_PACKAGES=()    # packages installed by script
STATE_PROFILE=""
STATE_LAST_RUN=""

# Findings table (populated by check_module_state / record_finding)
declare -a FINDINGS_STATUS=()   # pass|fail|manual|skip|partial
declare -a FINDINGS_MODULE=()   # module id
declare -a FINDINGS_MESSAGE=()  # human-readable finding

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
    echo -e "${GREEN}╔══════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║${NC}${BOLD}          BARKED HARDENING WIZARD v${VERSION}          ${NC}${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}                  macOS / Linux                   ${GREEN}║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════╝${NC}"
    echo ""
}

print_section() {
    echo ""
    echo -e "${BOLD}${GREEN}═══ $1 ═══${NC}"
    echo ""
}

print_status() {
    local num="$1" total="$2" desc="$3" status="$4"
    case "$status" in
        applied)  echo -e "  ${GREEN}✓${NC} [${num}/${total}] ${desc} ${BROWN}(applied)${NC}" ;;
        reverted) echo -e "  ${GREEN}✓${NC} [${num}/${total}] ${desc} ${BROWN}(reverted)${NC}" ;;
        skipped)  echo -e "  ${GREEN}○${NC} [${num}/${total}] ${desc} ${BROWN}(already applied)${NC}" ;;
        failed)   echo -e "  ${RED}✗${NC} [${num}/${total}] ${desc} ${RED}(failed)${NC}" ;;
        manual)   echo -e "  ${RED}☐${NC} [${num}/${total}] ${desc} ${RED}(manual)${NC}" ;;
        skipped_unsupported) echo -e "  ${BROWN}–${NC} [${num}/${total}] ${desc} ${BROWN}(not available on ${OS})${NC}" ;;
    esac
}

print_progress() {
    local desc="$1"
    echo -ne "  ${BROWN}⟳${NC} [${CURRENT_MODULE}/${TOTAL_MODULES}] ${desc}..."
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
        echo -e "  ${GREEN}[$((i+1))]${NC} ${options[$i]}"
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
        echo -e "  ${RED}☐ MANUAL STEP:${NC} ${message}"
        echo -ne "  ${BROWN}Press Enter when done (or S to skip)...${NC} "
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
            echo -e "${RED}Unsupported OS: ${uname_out}. Use barked.ps1 for Windows.${NC}"
            exit 1
            ;;
    esac
    echo -e "  Detected: ${BOLD}${OS}${NC}$([ -n "$DISTRO" ] && echo " (${DISTRO})")"
}

# ═══════════════════════════════════════════════════════════════════
# PRIVILEGE MANAGEMENT
# ═══════════════════════════════════════════════════════════════════

setup_privileges() {
    REAL_USER="$(whoami)"
    REAL_HOME="$HOME"
    export REAL_USER REAL_HOME
}

acquire_sudo() {
    # Already root (e.g., running in container or as root user)
    if [[ $EUID -eq 0 ]]; then
        return 0
    fi

    # --no-sudo mode never acquires
    if [[ "$NO_SUDO_MODE" == true ]]; then
        return 1
    fi

    echo ""
    echo -e "  ${BROWN}Root privileges required for the following operations.${NC}"
    if ! sudo -v 2>/dev/null; then
        echo -e "  ${RED}Failed to acquire sudo.${NC}"
        return 1
    fi
    return 0
}

cleanup_sudo() {
    # No longer needed - keepalive removed
    # Kept for compatibility with any existing trap references
    :
}

run_as_root() {
    if [[ $EUID -eq 0 ]]; then
        "$@"
    else
        sudo "$@"
    fi
}

# Modules that require root for at least one command
declare -A ROOT_MODULES=(
    [firewall-inbound]=1 [firewall-stealth]=1 [dns-secure]=1
    [auto-updates]=1 [guest-disable]=1 [hostname-scrub]=1
    [telemetry-disable]=1 [kernel-sysctl]=1 [apparmor-enforce]=1
    [bluetooth-disable]=1 [boot-security]=1 [mac-rotate]=1
)

needs_sudo() {
    # --no-sudo flag bypasses all root operations
    if [[ "$NO_SUDO_MODE" == true ]]; then
        return 1
    fi

    # Clean mode with system targets needs root
    if [[ "$CLEAN_MODE" == true ]]; then
        if [[ "${CLEAN_CATEGORIES[system-caches]}" == "1" ]]; then
            return 0
        fi
        return 1
    fi

    # Check if any enabled module needs root
    for mod in "${ENABLED_MODULES[@]}"; do
        if [[ -n "${ROOT_MODULES[$mod]:-}" ]]; then
            return 0
        fi
    done

    # Linux package installs need root
    if [[ "$OS" == "linux" ]]; then
        for mod in "${ENABLED_MODULES[@]}"; do
            case "$mod" in
                firewall-outbound|monitoring-tools|metadata-strip) return 0 ;;
            esac
        done
    fi

    return 1
}

# ═══════════════════════════════════════════════════════════════════
# TWO-PHASE EXECUTION: MODULE CLASSIFICATION
# ═══════════════════════════════════════════════════════════════════
classify_modules() {
    USERSPACE_MODULES=()
    ROOT_MODULES_LIST=()

    for mod in "${ENABLED_MODULES[@]}"; do
        local needs_root=false

        # Check if in ROOT_MODULES associative array
        if [[ -n "${ROOT_MODULES[$mod]:-}" ]]; then
            needs_root=true
        fi

        # Linux package installs need root
        if [[ "$OS" == "linux" && "$needs_root" == false ]]; then
            case "$mod" in
                firewall-outbound|monitoring-tools|metadata-strip)
                    needs_root=true
                    ;;
            esac
        fi

        if [[ "$needs_root" == true ]]; then
            if [[ "$NO_SUDO_MODE" == true ]]; then
                log_entry "$mod" "skip" "no-sudo" "Skipped (--no-sudo mode)"
            else
                ROOT_MODULES_LIST+=("$mod")
            fi
        else
            USERSPACE_MODULES+=("$mod")
        fi
    done
}

# Queue a root command for later batch execution
queue_root_command() {
    local module="$1"
    local cmd="$2"
    if [[ -z "${ROOT_COMMANDS[$module]:-}" ]]; then
        ROOT_COMMANDS[$module]="$cmd"
    else
        ROOT_COMMANDS[$module]+=$'\n'"$cmd"
    fi
}

# Set description for a module's root operations
set_root_description() {
    local module="$1"
    local desc="$2"
    ROOT_COMMAND_DESCS[$module]="$desc"
}

# Count total root commands queued
count_root_commands() {
    local total=0
    for mod in "${ROOT_MODULES_LIST[@]}"; do
        if [[ -n "${ROOT_COMMANDS[$mod]:-}" ]]; then
            local count
            count=$(echo "${ROOT_COMMANDS[$mod]}" | grep -c .)
            total=$((total + count))
        fi
    done
    echo "$total"
}

# Count modules with queued commands
count_root_modules() {
    local count=0
    for mod in "${ROOT_MODULES_LIST[@]}"; do
        if [[ -n "${ROOT_COMMANDS[$mod]:-}" ]]; then
            ((count++))
        fi
    done
    echo "$count"
}

# ═══════════════════════════════════════════════════════════════════
# TWO-PHASE EXECUTION: ROOT COMMAND PREVIEW
# ═══════════════════════════════════════════════════════════════════
show_root_preview_summary() {
    local total_cmds
    total_cmds=$(count_root_commands)
    local total_mods
    total_mods=$(count_root_modules)

    if [[ $total_cmds -eq 0 ]]; then
        echo ""
        echo -e "  ${GREEN}No root commands needed.${NC}"
        return 1
    fi

    echo ""
    echo -e "══════════════════════════════════════════════════════════"
    echo -e "  ${BOLD}The following modules require sudo:${NC}"
    echo -e "══════════════════════════════════════════════════════════"
    echo ""

    for mod in "${ROOT_MODULES_LIST[@]}"; do
        if [[ -n "${ROOT_COMMANDS[$mod]:-}" ]]; then
            local cmd_count
            cmd_count=$(echo "${ROOT_COMMANDS[$mod]}" | grep -c .)
            local desc="${ROOT_COMMAND_DESCS[$mod]:-No description}"
            local cmd_word="command"
            [[ $cmd_count -gt 1 ]] && cmd_word="commands"
            printf "  ${BOLD}%-20s${NC} %d %s   %s\n" "$mod" "$cmd_count" "$cmd_word" "$desc"
        fi
    done

    echo ""
    echo -e "  Total: ${BOLD}${total_cmds}${NC} root commands across ${BOLD}${total_mods}${NC} modules"
    echo ""
    echo -e "──────────────────────────────────────────────────────────"
    echo -e "  [P] Preview full commands   [Enter] Continue   [Ctrl+C] Abort"
    echo -e "──────────────────────────────────────────────────────────"

    return 0
}

show_root_preview_full() {
    echo ""
    echo -e "══════════════════════════════════════════════════════════"
    echo -e "  ${BOLD}Full root command list:${NC}"
    echo -e "══════════════════════════════════════════════════════════"
    echo ""

    for mod in "${ROOT_MODULES_LIST[@]}"; do
        if [[ -n "${ROOT_COMMANDS[$mod]:-}" ]]; then
            echo -e "  ${BOLD}${mod}:${NC}"
            while IFS= read -r cmd; do
                echo -e "    ${DIM}${cmd}${NC}"
            done <<< "${ROOT_COMMANDS[$mod]}"
            echo ""
        fi
    done

    echo -e "──────────────────────────────────────────────────────────"
    echo -e "  [Enter] Continue with sudo   [Ctrl+C] Abort"
    echo -e "──────────────────────────────────────────────────────────"
}

prompt_root_preview() {
    show_root_preview_summary || return 1

    while true; do
        read -r -n1 -s choice
        case "$choice" in
            p|P)
                show_root_preview_full
                read -r -n1 -s
                return 0
                ;;
            "")
                return 0
                ;;
        esac
    done
}

# ═══════════════════════════════════════════════════════════════════
# TWO-PHASE EXECUTION: BATCHED ROOT EXECUTION
# ═══════════════════════════════════════════════════════════════════
execute_root_batch() {
    local total_cmds
    total_cmds=$(count_root_commands)

    if [[ $total_cmds -eq 0 ]]; then
        return 0
    fi

    echo ""
    echo -e "══════════════════════════════════════════════════════════"
    echo -e "  ${BOLD}Executing root commands...${NC}"
    echo -e "══════════════════════════════════════════════════════════"
    echo ""

    # Log section header
    log_entry "ROOT-BATCH" "start" "info" "Beginning root command batch ($total_cmds commands)"

    local cmd_num=0
    for mod in "${ROOT_MODULES_LIST[@]}"; do
        if [[ -z "${ROOT_COMMANDS[$mod]:-}" ]]; then
            continue
        fi

        local mod_cmd_count
        mod_cmd_count=$(echo "${ROOT_COMMANDS[$mod]}" | grep -c .)
        local mod_cmd_num=0

        while IFS= read -r cmd; do
            ((cmd_num++))
            ((mod_cmd_num++))

            # Log the command before execution
            log_entry "$mod" "root-cmd" "exec" "$cmd"

            # Execute
            local exit_code=0
            if [[ $EUID -eq 0 ]]; then
                eval "$cmd" &>/dev/null || exit_code=$?
            else
                sudo bash -c "$cmd" &>/dev/null || exit_code=$?
            fi

            # Log result
            log_entry "$mod" "root-cmd" "exit" "Exit code: $exit_code"

            if [[ $exit_code -eq 0 ]]; then
                echo -e "  ${GREEN}[✓]${NC} ${mod} (${mod_cmd_num}/${mod_cmd_count})"
            else
                echo -e "  ${RED}[✗]${NC} ${mod} (${mod_cmd_num}/${mod_cmd_count})"
                echo ""
                echo -e "══════════════════════════════════════════════════════════"
                echo -e "  ${RED}${BOLD}ROOT BATCH ABORTED${NC}"
                echo -e "══════════════════════════════════════════════════════════"
                echo ""
                echo -e "  ${BOLD}Failed command:${NC}"
                echo -e "    ${cmd}"
                echo ""
                echo -e "  ${BOLD}Exit code:${NC} ${exit_code}"
                echo ""

                # Count skipped
                local skipped=0
                local remaining_in_mod=$((mod_cmd_count - mod_cmd_num))
                skipped=$((skipped + remaining_in_mod))

                local found_current=false
                for skip_mod in "${ROOT_MODULES_LIST[@]}"; do
                    if [[ "$skip_mod" == "$mod" ]]; then
                        found_current=true
                        continue
                    fi
                    if [[ "$found_current" == true && -n "${ROOT_COMMANDS[$skip_mod]:-}" ]]; then
                        local skip_count
                        skip_count=$(echo "${ROOT_COMMANDS[$skip_mod]}" | grep -c .)
                        skipped=$((skipped + skip_count))
                    fi
                done

                if [[ $skipped -gt 0 ]]; then
                    echo -e "  ${BOLD}Skipped (not executed):${NC} ${skipped} commands"
                fi
                echo ""
                echo -e "  ${BROWN}Recommendation: Investigate the failure, then re-run barked.${NC}"
                echo ""

                ROOT_BATCH_ABORTED=true
                ROOT_BATCH_FAIL_CMD="$cmd"
                ROOT_BATCH_FAIL_EXIT=$exit_code
                ROOT_BATCH_FAIL_MODULE="$mod"

                log_entry "ROOT-BATCH" "abort" "fail" "Aborted after $cmd_num commands, $skipped skipped"
                return 1
            fi
        done <<< "${ROOT_COMMANDS[$mod]}"
    done

    echo ""
    echo -e "  ${GREEN}All ${total_cmds} root commands completed successfully.${NC}"
    log_entry "ROOT-BATCH" "complete" "ok" "All $total_cmds commands executed"
    return 0
}

# ═══════════════════════════════════════════════════════════════════
# TWO-PHASE EXECUTION: PHASE RUNNERS
# ═══════════════════════════════════════════════════════════════════
run_userspace_modules() {
    if [[ ${#USERSPACE_MODULES[@]} -eq 0 ]]; then
        return 0
    fi

    log_entry "PHASE" "userspace" "start" "Beginning user-space modules (${#USERSPACE_MODULES[@]} modules)"

    if [[ "$DRY_RUN" == true ]]; then
        print_section "Dry Run Preview — User-Space (${#USERSPACE_MODULES[@]} modules)"
    else
        print_section "User-Space Modules (${#USERSPACE_MODULES[@]} modules)"
    fi

    TOTAL_MODULES=${#USERSPACE_MODULES[@]}
    CURRENT_MODULE=0

    for mod_id in "${USERSPACE_MODULES[@]}"; do
        run_module "$mod_id" "apply"
    done

    log_entry "PHASE" "userspace" "complete" "User-space phase complete"
}

collect_root_commands() {
    if [[ ${#ROOT_MODULES_LIST[@]} -eq 0 ]]; then
        return 0
    fi

    log_entry "PHASE" "root-collect" "start" "Collecting root commands (${#ROOT_MODULES_LIST[@]} modules)"

    # Clear any previous state
    ROOT_COMMANDS=()
    ROOT_COMMAND_DESCS=()

    for mod_id in "${ROOT_MODULES_LIST[@]}"; do
        check_module "$mod_id"
        if [[ "$CHECK_STATUS" != "PASS" ]]; then
            # Module needs changes - collect its commands
            collect_root_commands_for_module "$mod_id"
        fi
    done

    log_entry "PHASE" "root-collect" "complete" "Collected $(count_root_commands) commands"
}

# ═══════════════════════════════════════════════════════════════════
# TWO-PHASE EXECUTION: MODULE COMMAND COLLECTORS
# ═══════════════════════════════════════════════════════════════════
collect_root_commands_for_module() {
    local mod_id="$1"
    local collector_func="collect_${mod_id//-/_}"

    if declare -f "$collector_func" &>/dev/null; then
        "$collector_func"
    else
        # Fallback: mark as needing manual review
        log_entry "$mod_id" "collect" "warn" "No command collector - will run directly"
    fi
}

collect_firewall_inbound() {
    if [[ "$OS" == "macos" ]]; then
        queue_root_command "firewall-inbound" "/usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on"
        queue_root_command "firewall-inbound" "/usr/libexec/ApplicationFirewall/socketfilterfw --setblockall on"
        queue_root_command "firewall-inbound" "/usr/libexec/ApplicationFirewall/socketfilterfw --setallowsigned off"
        queue_root_command "firewall-inbound" "/usr/libexec/ApplicationFirewall/socketfilterfw --setallowsignedapp off"
        set_root_description "firewall-inbound" "Enable firewall, block incoming"
    elif [[ "$OS" == "linux" ]]; then
        queue_root_command "firewall-inbound" "ufw --force enable"
        queue_root_command "firewall-inbound" "ufw default deny incoming"
        set_root_description "firewall-inbound" "Enable ufw, deny incoming"
    fi
}

collect_firewall_stealth() {
    if [[ "$OS" == "macos" ]]; then
        queue_root_command "firewall-stealth" "/usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on"
        set_root_description "firewall-stealth" "Enable stealth mode"
    elif [[ "$OS" == "linux" ]]; then
        queue_root_command "firewall-stealth" "iptables -A INPUT -p icmp --icmp-type echo-request -j DROP"
        set_root_description "firewall-stealth" "Drop ICMP echo requests"
    fi
}

collect_dns_secure() {
    if [[ "$OS" == "macos" ]]; then
        queue_root_command "dns-secure" "networksetup -setdnsservers Wi-Fi 9.9.9.9 149.112.112.112"
        set_root_description "dns-secure" "Set DNS to Quad9"
    elif [[ "$OS" == "linux" ]]; then
        if [[ -d /etc/systemd/resolved.conf.d ]]; then
            queue_root_command "dns-secure" "mkdir -p /etc/systemd/resolved.conf.d && cat > /etc/systemd/resolved.conf.d/quad9.conf << 'EOF'
[Resolve]
DNS=9.9.9.9 149.112.112.112
DNSOverTLS=yes
EOF"
            queue_root_command "dns-secure" "systemctl restart systemd-resolved"
        else
            queue_root_command "dns-secure" "cp /etc/resolv.conf /etc/resolv.conf.bak"
            queue_root_command "dns-secure" "echo -e 'nameserver 9.9.9.9\nnameserver 149.112.112.112' > /etc/resolv.conf"
        fi
        set_root_description "dns-secure" "Set DNS to Quad9"
    fi
}

collect_guest_disable() {
    if [[ "$OS" == "macos" ]]; then
        queue_root_command "guest-disable" "defaults write /Library/Preferences/com.apple.loginwindow GuestEnabled -bool false"
        set_root_description "guest-disable" "Disable guest account"
    elif [[ "$OS" == "linux" ]]; then
        queue_root_command "guest-disable" "usermod -L guest 2>/dev/null || true"
        set_root_description "guest-disable" "Lock guest account"
    fi
}

collect_auto_updates() {
    if [[ "$OS" == "macos" ]]; then
        queue_root_command "auto-updates" "defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -bool true"
        queue_root_command "auto-updates" "defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload -bool true"
        queue_root_command "auto-updates" "defaults write /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall -bool true"
        set_root_description "auto-updates" "Enable automatic security updates"
    elif [[ "$OS" == "linux" ]]; then
        case "$DISTRO" in
            debian)
                queue_root_command "auto-updates" "DEBIAN_FRONTEND=noninteractive apt-get install -y unattended-upgrades"
                queue_root_command "auto-updates" "dpkg-reconfigure -plow unattended-upgrades"
                ;;
            fedora)
                queue_root_command "auto-updates" "dnf install -y dnf-automatic"
                queue_root_command "auto-updates" "systemctl enable --now dnf-automatic-install.timer"
                ;;
        esac
        set_root_description "auto-updates" "Enable automatic security updates"
    fi
}

collect_hostname_scrub() {
    local generic="workstation-$(head -c 4 /dev/urandom | xxd -p)"
    if [[ "$OS" == "macos" ]]; then
        queue_root_command "hostname-scrub" "scutil --set ComputerName '$generic'"
        queue_root_command "hostname-scrub" "scutil --set LocalHostName '$generic'"
        queue_root_command "hostname-scrub" "scutil --set HostName '$generic'"
        set_root_description "hostname-scrub" "Set generic hostname"
    elif [[ "$OS" == "linux" ]]; then
        queue_root_command "hostname-scrub" "hostnamectl set-hostname '$generic' || hostname '$generic'"
        set_root_description "hostname-scrub" "Set generic hostname"
    fi
}

collect_telemetry_disable() {
    if [[ "$OS" == "linux" ]]; then
        if [[ -f /etc/default/apport ]]; then
            queue_root_command "telemetry-disable" "sed -i 's/enabled=1/enabled=0/' /etc/default/apport"
            queue_root_command "telemetry-disable" "systemctl stop apport.service"
            queue_root_command "telemetry-disable" "systemctl disable apport.service"
            set_root_description "telemetry-disable" "Disable crash reporting"
        fi
    fi
    # macOS telemetry uses user-space defaults, handled separately
}

collect_bluetooth_disable() {
    if [[ "$OS" == "linux" ]]; then
        queue_root_command "bluetooth-disable" "systemctl disable --now bluetooth"
        set_root_description "bluetooth-disable" "Disable Bluetooth service"
    fi
    # macOS bluetooth uses different approach
}

collect_mac_rotate() {
    if [[ "$OS" == "linux" ]]; then
        queue_root_command "mac-rotate" "mkdir -p /etc/NetworkManager/conf.d"
        queue_root_command "mac-rotate" "cat > /etc/NetworkManager/conf.d/mac-randomize.conf << 'EOF'
[device]
wifi.scan-rand-mac-address=yes
[connection]
wifi.cloned-mac-address=random
ethernet.cloned-mac-address=random
EOF"
        queue_root_command "mac-rotate" "systemctl restart NetworkManager"
        set_root_description "mac-rotate" "Enable MAC address randomization"
    fi
}

collect_kernel_sysctl() {
    if [[ "$OS" == "linux" ]]; then
        queue_root_command "kernel-sysctl" "cat > /etc/sysctl.d/99-hardening.conf << 'EOF'
kernel.kptr_restrict=2
kernel.dmesg_restrict=1
kernel.unprivileged_bpf_disabled=1
net.core.bpf_jit_harden=2
kernel.yama.ptrace_scope=2
EOF"
        queue_root_command "kernel-sysctl" "sysctl --system"
        set_root_description "kernel-sysctl" "Apply kernel hardening sysctls"
    fi
}

collect_apparmor_enforce() {
    if [[ "$OS" == "linux" ]]; then
        queue_root_command "apparmor-enforce" "aa-enforce /etc/apparmor.d/*"
        set_root_description "apparmor-enforce" "Enforce AppArmor profiles"
    fi
}

collect_boot_security() {
    if [[ "$OS" == "linux" ]]; then
        queue_root_command "boot-security" "cat >> /etc/grub.d/40_custom << 'EOF'
set superusers=\"root\"
password_pbkdf2 root grub.pbkdf2.sha512.PLACEHOLDER
EOF"
        queue_root_command "boot-security" "update-grub || grub-mkconfig -o /boot/grub/grub.cfg"
        set_root_description "boot-security" "Add GRUB password protection"
    fi
}

# ═══════════════════════════════════════════════════════════════════
# TWO-PHASE EXECUTION: REVERT COMMAND COLLECTORS
# ═══════════════════════════════════════════════════════════════════
collect_revert_firewall_inbound() {
    if [[ "$OS" == "macos" ]]; then
        queue_root_command "firewall-inbound" "/usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate off"
        queue_root_command "firewall-inbound" "/usr/libexec/ApplicationFirewall/socketfilterfw --setblockall off"
        queue_root_command "firewall-inbound" "/usr/libexec/ApplicationFirewall/socketfilterfw --setallowsigned on"
        queue_root_command "firewall-inbound" "/usr/libexec/ApplicationFirewall/socketfilterfw --setallowsignedapp on"
        set_root_description "firewall-inbound" "Disable firewall restrictions"
    elif [[ "$OS" == "linux" ]]; then
        queue_root_command "firewall-inbound" "ufw --force disable"
        set_root_description "firewall-inbound" "Disable ufw"
    fi
}

collect_revert_firewall_stealth() {
    if [[ "$OS" == "macos" ]]; then
        queue_root_command "firewall-stealth" "/usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode off"
        set_root_description "firewall-stealth" "Disable stealth mode"
    elif [[ "$OS" == "linux" ]]; then
        queue_root_command "firewall-stealth" "iptables -D INPUT -p icmp --icmp-type echo-request -j DROP 2>/dev/null || true"
        set_root_description "firewall-stealth" "Allow ICMP echo requests"
    fi
}

collect_revert_dns_secure() {
    local prev="${STATE_PREVIOUS[dns-secure]:-}"
    if [[ "$OS" == "macos" ]]; then
        if [[ -n "$prev" ]]; then
            queue_root_command "dns-secure" "networksetup -setdnsservers Wi-Fi $prev"
        else
            queue_root_command "dns-secure" "networksetup -setdnsservers Wi-Fi Empty"
        fi
        set_root_description "dns-secure" "Restore previous DNS"
    elif [[ "$OS" == "linux" ]]; then
        if [[ -f /etc/resolv.conf.bak ]]; then
            queue_root_command "dns-secure" "cp /etc/resolv.conf.bak /etc/resolv.conf"
        fi
        set_root_description "dns-secure" "Restore previous DNS"
    fi
}

collect_revert_guest_disable() {
    if [[ "$OS" == "macos" ]]; then
        queue_root_command "guest-disable" "defaults write /Library/Preferences/com.apple.loginwindow GuestEnabled -bool true"
        set_root_description "guest-disable" "Re-enable guest account"
    elif [[ "$OS" == "linux" ]]; then
        queue_root_command "guest-disable" "usermod -U guest 2>/dev/null || true"
        set_root_description "guest-disable" "Unlock guest account"
    fi
}

# ═══════════════════════════════════════════════════════════════════
# TWO-PHASE EXECUTION: MAIN ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════
run_all_modules_twophase() {
    # Classify modules into user-space and root
    classify_modules

    log_entry "EXECUTION" "mode" "info" "Two-phase execution: ${#USERSPACE_MODULES[@]} user-space, ${#ROOT_MODULES_LIST[@]} root"

    # ══════════════════════════════════════════════════════════════
    # PHASE 1: User-space modules (no sudo)
    # ══════════════════════════════════════════════════════════════
    run_userspace_modules

    # If --no-sudo or no root modules, we're done
    if [[ "$NO_SUDO_MODE" == true ]]; then
        log_entry "EXECUTION" "complete" "info" "Completed in --no-sudo mode"
        return 0
    fi

    if [[ ${#ROOT_MODULES_LIST[@]} -eq 0 ]]; then
        log_entry "EXECUTION" "complete" "info" "No root modules to execute"
        return 0
    fi

    # ══════════════════════════════════════════════════════════════
    # PHASE 2: Collect and preview root commands
    # ══════════════════════════════════════════════════════════════
    collect_root_commands

    local total_cmds
    total_cmds=$(count_root_commands)

    if [[ $total_cmds -eq 0 ]]; then
        echo ""
        echo -e "  ${GREEN}All root modules already configured. No changes needed.${NC}"
        log_entry "EXECUTION" "complete" "info" "Root modules already configured"
        return 0
    fi

    # Show preview and get confirmation
    if ! prompt_root_preview; then
        return 0
    fi

    # Log that user reviewed the preview
    log_entry "PREVIEW" "review" "ok" "User reviewed $total_cmds commands across $(count_root_modules) modules"

    # ══════════════════════════════════════════════════════════════
    # PHASE 3: Acquire sudo and execute batch
    # ══════════════════════════════════════════════════════════════
    if ! acquire_sudo; then
        echo -e "  ${RED}Cannot proceed without sudo. Root modules skipped.${NC}"
        log_entry "EXECUTION" "abort" "fail" "Sudo acquisition failed"
        return 1
    fi

    execute_root_batch
    local batch_result=$?

    # ══════════════════════════════════════════════════════════════
    # PHASE 4: Verify and update state
    # ══════════════════════════════════════════════════════════════
    if [[ $batch_result -eq 0 ]]; then
        # Verify and update state for each root module
        TOTAL_MODULES=${#ROOT_MODULES_LIST[@]}
        CURRENT_MODULE=0

        print_section "Verifying Root Modules"

        for mod_id in "${ROOT_MODULES_LIST[@]}"; do
            ((CURRENT_MODULE++))
            check_module "$mod_id"
            if [[ "$CHECK_STATUS" == "PASS" ]]; then
                print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$mod_id" "applied"
                log_entry "$mod_id" "verify" "ok" "Verified"
                state_set_module "$mod_id" "applied"
                ((COUNT_APPLIED++))
            else
                print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$mod_id" "failed"
                log_entry "$mod_id" "verify" "fail" "Verification failed"
                ((COUNT_FAILED++))
            fi
        done
    fi

    return $batch_result
}

# ═══════════════════════════════════════════════════════════════════
# PACKAGE INSTALL HELPERS
# ═══════════════════════════════════════════════════════════════════
pkg_install() {
    local pkg="$1"
    case "$OS" in
        macos)
            brew install "$pkg" 2>/dev/null
            ;;
        linux)
            case "$DISTRO" in
                debian) run_as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg" 2>/dev/null ;;
                fedora) run_as_root dnf install -y "$pkg" 2>/dev/null ;;
                arch)   run_as_root pacman -S --noconfirm "$pkg" 2>/dev/null ;;
            esac
            ;;
    esac
}

pkg_install_cask() {
    if [[ "$OS" == "macos" ]]; then
        brew install --cask "$1" 2>/dev/null
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

pkg_uninstall() {
    local pkg="$1"
    case "$OS" in
        macos)  brew uninstall "$pkg" 2>/dev/null ;;
        linux)
            case "$DISTRO" in
                debian) run_as_root apt-get remove -y "$pkg" 2>/dev/null ;;
                fedora) run_as_root dnf remove -y "$pkg" 2>/dev/null ;;
                arch)   run_as_root pacman -R --noconfirm "$pkg" 2>/dev/null ;;
            esac
            ;;
    esac
}

cask_uninstall() {
    [[ "$OS" == "macos" ]] && brew uninstall --cask "$1" 2>/dev/null
}

# ═══════════════════════════════════════════════════════════════════
# STATE FILE MANAGEMENT
# ═══════════════════════════════════════════════════════════════════
state_read() {
    local state_file=""
    if [[ -f "$STATE_FILE_USER" ]]; then
        state_file="$STATE_FILE_USER"
    elif [[ -f "$STATE_FILE_PROJECT" ]]; then
        state_file="$STATE_FILE_PROJECT"
    elif [[ -f "$STATE_FILE_LEGACY" ]]; then
        state_file="$STATE_FILE_LEGACY"
    else
        return 1
    fi

    if ! command -v python3 &>/dev/null; then
        echo -e "  ${RED}Warning: python3 required for state file. Using live detection.${NC}"
        return 1
    fi

    local tmp
    tmp=$(mktemp)
    python3 - "$state_file" << 'PYREAD' > "$tmp" 2>/dev/null
import json, sys, shlex
try:
    with open(sys.argv[1]) as f:
        state = json.load(f)
    for mid, mdata in state.get("modules", {}).items():
        s = mdata.get("status", "")
        p = str(mdata.get("previous_value", "") or "")
        t = mdata.get("applied_at", "")
        print(f'STATE_MODULES[{mid}]={shlex.quote(s)}')
        print(f'STATE_PREVIOUS[{mid}]={shlex.quote(p)}')
        print(f'STATE_TIMESTAMPS[{mid}]={shlex.quote(t)}')
    pkgs = " ".join(shlex.quote(p) for p in state.get("packages_installed", []))
    print(f'STATE_PACKAGES=({pkgs})')
    print(f'STATE_PROFILE={shlex.quote(state.get("profile", ""))}')
    print(f'STATE_LAST_RUN={shlex.quote(state.get("last_run", ""))}')
except Exception as e:
    print(f'# Error: {e}', file=sys.stderr)
    sys.exit(1)
PYREAD

    if [[ -s "$tmp" ]]; then
        # Use file descriptor to prevent symlink race (TOCTOU)
        exec 3<"$tmp"
        source /dev/fd/3
        exec 3<&-
        rm -f "$tmp"
        STATE_EXISTS=true
        return 0
    fi
    rm -f "$tmp"
    return 1
}

state_migrate_legacy() {
    # Migrate from /etc/hardening-state.json to user space
    if [[ -f "$STATE_FILE_LEGACY" ]] && [[ ! -f "$STATE_FILE_USER" ]]; then
        mkdir -p "$(dirname "$STATE_FILE_USER")" 2>/dev/null
        cp "$STATE_FILE_LEGACY" "$STATE_FILE_USER" 2>/dev/null
        if [[ -f "$STATE_FILE_USER" ]]; then
            echo -e "  ${BROWN}Migrated state file to ${STATE_FILE_USER}${NC}"
            # Use sudo -n (non-interactive) so this never prompts;
            # if credentials aren't cached the old file just stays
            sudo -n rm -f "$STATE_FILE_LEGACY" 2>/dev/null || true
        fi
    fi
}

state_write() {
    if ! command -v python3 &>/dev/null; then
        echo -e "  ${RED}Warning: python3 required for state file. State not saved.${NC}"
        return 1
    fi

    mkdir -p "$(dirname "$STATE_FILE_PROJECT")" 2>/dev/null

    local mod_lines=""
    for mod_id in "${!STATE_MODULES[@]}"; do
        local status="${STATE_MODULES[$mod_id]}"
        local prev="${STATE_PREVIOUS[$mod_id]:-}"
        local ts="${STATE_TIMESTAMPS[$mod_id]:-}"
        mod_lines+="MOD:${mod_id}|${status}|${ts}|${prev}"$'\n'
    done

    local pkg_lines=""
    for pkg in "${STATE_PACKAGES[@]}"; do
        pkg_lines+="PKG:${pkg}"$'\n'
    done

    mkdir -p "$(dirname "$STATE_FILE_USER")" 2>/dev/null
    local write_targets=("$STATE_FILE_USER" "$STATE_FILE_PROJECT")

    python3 - "${write_targets[@]}" << PYWRITE 2>/dev/null
import json, sys, os
state = {
    "version": "${VERSION}",
    "last_run": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "os": "${OS}",
    "profile": "${PROFILE:-${STATE_PROFILE:-unknown}}",
    "modules": {},
    "packages_installed": []
}
data = """${mod_lines}${pkg_lines}"""
for line in data.strip().split('\n'):
    line = line.strip()
    if not line:
        continue
    if line.startswith('MOD:'):
        parts = line[4:].split('|')
        if len(parts) >= 2:
            prev = parts[3] if len(parts) > 3 and parts[3] else None
            state['modules'][parts[0]] = {
                'status': parts[1],
                'applied_at': parts[2] if len(parts) > 2 else '',
                'previous_value': prev
            }
    elif line.startswith('PKG:'):
        state['packages_installed'].append(line[4:])
for path in sys.argv[1:]:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, 'w') as f:
        json.dump(state, f, indent=2)
PYWRITE

    echo ""
    echo -e "  ${BROWN}State file written to:${NC}"
    for t in "${write_targets[@]}"; do
        echo -e "    ${BROWN}${t}${NC}"
    done
}

state_set_module() {
    local mod_id="$1" status="$2"
    local prev="${3:-}"
    STATE_MODULES[$mod_id]="$status"
    STATE_TIMESTAMPS[$mod_id]="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    if [[ -n "$prev" ]]; then
        STATE_PREVIOUS[$mod_id]="$prev"
    fi
}

state_add_package() {
    local pkg="$1"
    for p in "${STATE_PACKAGES[@]}"; do
        [[ "$p" == "$pkg" ]] && return
    done
    STATE_PACKAGES+=("$pkg")
}

state_remove_package() {
    local pkg="$1"
    local new=()
    for p in "${STATE_PACKAGES[@]}"; do
        [[ "$p" != "$pkg" ]] && new+=("$p")
    done
    STATE_PACKAGES=("${new[@]}")
}

state_get_applied_modules() {
    local applied=()
    for mod_id in "${!STATE_MODULES[@]}"; do
        if [[ "${STATE_MODULES[$mod_id]}" == "applied" ]]; then
            applied+=("$mod_id")
        fi
    done
    echo "${applied[@]}"
}

state_count_applied() {
    local count=0
    for mod_id in "${!STATE_MODULES[@]}"; do
        [[ "${STATE_MODULES[$mod_id]}" == "applied" ]] && ((count++))
    done
    echo "$count"
}

# ═══════════════════════════════════════════════════════════════════
# SCHEDULED CLEAN: CONFIG MANAGEMENT
# ═══════════════════════════════════════════════════════════════════
load_scheduled_config() {
    local config_file=""

    if [[ -f "$SCHED_CLEAN_CONFIG_USER" ]]; then
        config_file="$SCHED_CLEAN_CONFIG_USER"
    elif [[ -f "$SCHED_CLEAN_CONFIG_PROJECT" ]]; then
        config_file="$SCHED_CLEAN_CONFIG_PROJECT"
    else
        return 1
    fi

    # Parse JSON once and extract all values safely using sys.argv
    local parse_output
    parse_output=$(python3 - "$config_file" 2>/dev/null << 'PYEOF'
import sys, json
try:
    with open(sys.argv[1]) as f:
        config = json.load(f)
    # Print booleans as lowercase for bash compatibility
    print(str(config['enabled']).lower())
    print(config['schedule'])
    print(str(config['notify']).lower())
    # Print categories one per line to handle spaces correctly
    for cat in config['categories']:
        print(cat)
except (FileNotFoundError, KeyError, json.JSONDecodeError) as e:
    sys.exit(1)
PYEOF
    ) || {
        clean_log "ERROR" "Invalid config JSON at $config_file"
        return 1
    }

    # Extract values from output (one per line)
    local line_num=0
    SCHED_CATEGORIES=()  # Clear array before populating
    while IFS= read -r line; do
        case $line_num in
            0) SCHED_ENABLED="$line" ;;
            1) SCHED_SCHEDULE="$line" ;;
            2) SCHED_NOTIFY="$line" ;;
            *) SCHED_CATEGORIES+=("$line") ;;
        esac
        ((line_num++))
    done <<< "$parse_output"

    return 0
}

save_scheduled_config() {
    local enabled="$1"
    local schedule="$2"
    local custom_interval="$3"
    local notify="$4"
    shift 4
    local categories=("$@")

    mkdir -p "$(dirname "$SCHED_CLEAN_CONFIG_USER")" 2>/dev/null
    chmod 700 "$(dirname "$SCHED_CLEAN_CONFIG_USER")" 2>/dev/null || true

    # Use Python json.dump() for safe JSON generation with error handling
    if ! python3 - "$SCHED_CLEAN_CONFIG_USER" "$enabled" "$schedule" "$custom_interval" "$notify" "${categories[@]}" 2>/dev/null << 'PYEOF'
import sys, json

config_file = sys.argv[1]
enabled = sys.argv[2] == "true"
schedule = sys.argv[3]
custom_interval = sys.argv[4]
notify = sys.argv[5] == "true"
categories = list(sys.argv[6:]) if len(sys.argv) > 6 else []

config = {
    "enabled": enabled,
    "schedule": schedule,
    "custom_interval": custom_interval,
    "categories": categories,
    "notify": notify,
    "last_run": "",
    "version": "1.0"
}

with open(config_file, 'w') as f:
    json.dump(config, f, indent=2)
PYEOF
    then
        clean_log "ERROR" "Failed to save scheduled clean config"
        return 1
    fi
    chmod 600 "$SCHED_CLEAN_CONFIG_USER" 2>/dev/null || true

    # Also save to project directory as backup
    mkdir -p "$(dirname "$SCHED_CLEAN_CONFIG_PROJECT")" 2>/dev/null
    cp "$SCHED_CLEAN_CONFIG_USER" "$SCHED_CLEAN_CONFIG_PROJECT" 2>/dev/null || true
}

setup_scheduled_clean() {
    print_section "Scheduled Cleaning Setup"

    echo -e "  ${BOLD}Configure automatic system cleaning${NC}"
    echo ""

    # Step 1: Category selection
    echo -e "  ${BOLD}Step 1/3: Select categories to clean automatically${NC}"
    echo ""
    clean_picker

    # Capture selected categories
    local selected_cats=()
    for cat in "${CLEAN_CAT_ORDER[@]}"; do
        if [[ "${CLEAN_CATEGORIES[$cat]}" == "1" ]]; then
            selected_cats+=("$cat")
        fi
    done

    if [[ ${#selected_cats[@]} -eq 0 ]]; then
        echo -e "  ${RED}No categories selected. Setup cancelled.${NC}"
        return 1
    fi

    echo ""
    echo -e "  ${GREEN}Selected ${#selected_cats[@]} categories${NC}"
    echo ""

    # Step 2: Schedule frequency
    echo -e "  ${BOLD}Step 2/3: How often should automated cleaning run?${NC}"
    echo ""
    echo -e "  ${GREEN}[1]${NC} Daily (every day at 2:00 AM)"
    echo -e "  ${GREEN}[2]${NC} Weekly (Sunday at 2:00 AM)"
    # Custom cron schedules only supported on Linux (launchd uses StartCalendarInterval)
    if [[ "$OS" == "linux" ]]; then
        echo -e "  ${GREEN}[3]${NC} Custom (specify cron schedule)"
    fi
    echo ""

    local schedule="" custom_interval="" max_choice=2
    [[ "$OS" == "linux" ]] && max_choice=3
    while true; do
        echo -ne "  ${BOLD}Choice:${NC} "
        read -r sched_choice
        case "${sched_choice}" in
            1) schedule="daily"; break ;;
            2) schedule="weekly"; break ;;
            3)
                if [[ "$OS" != "linux" ]]; then
                    echo -e "  ${RED}Invalid choice. Enter 1-${max_choice}.${NC}"
                    continue
                fi
                schedule="custom"
                echo ""
                echo -e "  ${BOLD}Enter cron schedule (e.g., '0 3 * * *' for daily at 3am):${NC}"
                echo -ne "  ${BOLD}Cron:${NC} "
                read -r custom_interval
                if [[ -z "$custom_interval" ]]; then
                    echo -e "  ${RED}Invalid cron schedule${NC}"
                    continue
                fi
                # Validate 5-field cron format with valid characters
                if [[ $(echo "$custom_interval" | wc -w) -ne 5 ]]; then
                    echo -e "  ${RED}Invalid cron format (must be 5 fields: minute hour day month weekday)${NC}"
                    continue
                fi
                local cron_valid=true
                for field in $custom_interval; do
                    if ! [[ "$field" =~ ^[0-9*,/\-]+$ ]]; then
                        cron_valid=false
                        break
                    fi
                done
                if [[ "$cron_valid" != "true" ]]; then
                    echo -e "  ${RED}Invalid cron field values (use digits, *, /, -, and , only)${NC}"
                    continue
                fi
                break
                ;;
            *) echo -e "  ${RED}Invalid choice. Enter 1-${max_choice}.${NC}" ;;
        esac
    done

    echo ""

    # Step 3: Notification preference
    echo -e "  ${BOLD}Step 3/3: Show notification when cleaning completes?${NC}"
    echo -ne "  ${BOLD}[Y/n]:${NC} "
    read -r notify_input
    local notify=true
    [[ "${notify_input,,}" == "n" ]] && notify=false

    echo ""

    # Confirmation summary
    local sched_display="$schedule"
    [[ "$schedule" == "daily" ]] && sched_display="Daily at 2:00 AM"
    [[ "$schedule" == "weekly" ]] && sched_display="Weekly (Sunday 2:00 AM)"
    [[ "$schedule" == "custom" ]] && sched_display="Custom: $custom_interval"

    # Truncate schedule display if too long
    if [[ ${#sched_display} -gt 41 ]]; then
        sched_display="${sched_display:0:38}..."
    fi

    local cat_names=""
    for cat in "${selected_cats[@]}"; do
        cat_names+="${CLEAN_CAT_NAMES[$cat]}, "
    done
    cat_names="${cat_names%, }"

    # Truncate if too long to fit in box
    if [[ ${#cat_names} -gt 41 ]]; then
        cat_names="${cat_names:0:38}..."
    fi

    local notify_display="Yes"
    [[ "$notify" == false ]] && notify_display="No"

    echo -e "  ${BOLD}${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "  ${BOLD}${GREEN}║${NC}      SCHEDULED CLEANING CONFIGURED                       ${BOLD}${GREEN}║${NC}"
    echo -e "  ${BOLD}${GREEN}╠══════════════════════════════════════════════════════════╣${NC}"
    printf "  ${GREEN}║${NC} %-56s ${GREEN}║${NC}\n" "Categories: $cat_names"
    printf "  ${GREEN}║${NC} %-56s ${GREEN}║${NC}\n" "Schedule:   $sched_display"
    printf "  ${GREEN}║${NC} %-56s ${GREEN}║${NC}\n" "Notify:     $notify_display"
    echo -e "  ${BOLD}${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""

    # Save config
    save_scheduled_config "true" "$schedule" "$custom_interval" "$notify" "${selected_cats[@]}"

    # Install scheduler
    install_scheduler "$schedule" "$custom_interval"

    echo ""
    echo -e "  ${GREEN}✓ Scheduled cleaning configured${NC}"
    echo ""
}

# Stub for Task 4
install_scheduler() {
    local schedule="$1"
    local custom_interval="$2"

    echo ""
    echo -e "  ${BOLD}Installing scheduler...${NC}"

    # Get barked path once
    local barked_path
    barked_path="$(command -v barked 2>/dev/null || echo "$0")"
    barked_path="$(cd "$(dirname "$barked_path")" && pwd)/$(basename "$barked_path")"

    # Detect OS and call appropriate installer
    case "$OS" in
        macos)
            install_scheduler_macos "$schedule" "$custom_interval" "$barked_path"
            ;;
        linux)
            install_scheduler_linux "$schedule" "$custom_interval" "$barked_path"
            ;;
        windows)
            echo -e "  ${BROWN}Windows scheduler not implemented in this script${NC}"
            return 1
            ;;
        *)
            echo -e "  ${RED}Unsupported OS: $OS${NC}"
            return 1
            ;;
    esac
}

install_scheduler_macos() {
    local schedule="$1"
    local custom_interval="$2"
    local barked_path="$3"

    # Plist path
    local plist_path="$HOME/Library/LaunchAgents/com.barked.scheduled-clean.plist"

    # Create LaunchAgents directory if needed
    mkdir -p "$HOME/Library/LaunchAgents"

    # Escape XML entities in barked_path
    local barked_path_xml="${barked_path//&/&amp;}"
    barked_path_xml="${barked_path_xml//</&lt;}"
    barked_path_xml="${barked_path_xml//>/&gt;}"
    barked_path_xml="${barked_path_xml//\"/&quot;}"
    barked_path_xml="${barked_path_xml//\'/&apos;}"

    # Determine schedule interval
    local interval_xml=""
    case "$schedule" in
        daily)
            interval_xml="    <dict>
      <key>Hour</key>
      <integer>2</integer>
      <key>Minute</key>
      <integer>0</integer>
    </dict>"
            ;;
        weekly)
            interval_xml="    <dict>
      <key>Weekday</key>
      <integer>0</integer>
      <key>Hour</key>
      <integer>2</integer>
      <key>Minute</key>
      <integer>0</integer>
    </dict>"
            ;;
        custom)
            # Custom cron schedules should not reach macOS (blocked in setup wizard)
            echo -e "  ${RED}Custom schedules not supported on macOS${NC}"
            return 1
            ;;
    esac

    # Create plist
    cat > "$plist_path" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.barked.scheduled-clean</string>
  <key>ProgramArguments</key>
  <array>
    <string>$barked_path_xml</string>
    <string>--clean-scheduled</string>
  </array>
  <key>StartCalendarInterval</key>
$interval_xml
  <key>RunAtLoad</key>
  <false/>
  <key>StandardOutPath</key>
  <string>\$HOME/Library/Logs/barked-clean.log</string>
  <key>StandardErrorPath</key>
  <string>\$HOME/Library/Logs/barked-clean-error.log</string>
</dict>
</plist>
EOF

    # Check if plist was created successfully
    if [[ ! -f "$plist_path" ]]; then
        echo -e "  ${RED}✗ Failed to create plist file${NC}"
        return 1
    fi

    # Unload existing job if present, then load
    launchctl unload "$plist_path" 2>/dev/null || true
    if launchctl load "$plist_path" 2>/dev/null; then
        echo -e "  ${GREEN}✓ macOS launchd job installed${NC}"
        echo "    Job: $plist_path"
    else
        echo -e "  ${RED}✗ Failed to load launchd job${NC}"
        return 1
    fi
}

install_scheduler_linux() {
    local schedule="$1"
    local custom_interval="$2"
    local barked_path="$3"

    # Determine cron schedule
    local cron_schedule
    case "$schedule" in
        daily)
            cron_schedule="0 2 * * *"
            ;;
        weekly)
            cron_schedule="0 2 * * 0"
            ;;
        custom)
            cron_schedule="$custom_interval"
            ;;
    esac

    # Build cron line
    local cron_line
    printf -v cron_line '%s %s --clean-scheduled' "$cron_schedule" "$barked_path"

    # Check if cron job already exists
    if crontab -l 2>/dev/null | grep -F "$barked_path --clean-scheduled" >/dev/null; then
        # Remove existing entry
        crontab -l 2>/dev/null | grep -vF "$barked_path --clean-scheduled" | crontab -
    fi

    # Add new cron job
    if (crontab -l 2>/dev/null; echo "$cron_line") | crontab -; then
        echo -e "  ${GREEN}✓ Cron job installed${NC}"
        echo "    Schedule: $cron_schedule"
    else
        echo -e "  ${RED}✗ Failed to install cron job${NC}"
        return 1
    fi
}

unschedule_clean() {
    print_section "Remove Scheduled Cleaning"

    if ! load_scheduled_config; then
        echo -e "  ${BROWN}No scheduled cleaning configured${NC}"
        return 0
    fi

    case "$OS" in
        macos)
            local plist_path="${HOME}/Library/LaunchAgents/com.barked.scheduled-clean.plist"
            if [[ -f "$plist_path" ]]; then
                launchctl unload "$plist_path" 2>/dev/null || true
                rm -f "$plist_path"
                echo -e "  ${GREEN}✓ Removed LaunchAgent${NC}"
            fi
            ;;
        linux)
            # Get barked path to match install pattern
            local barked_path
            barked_path="$(command -v barked 2>/dev/null || echo "$0")"
            barked_path="$(cd "$(dirname "$barked_path")" && pwd)/$(basename "$barked_path")"

            # Use full path in grep
            (crontab -l 2>/dev/null | grep -vF "$barked_path --clean-scheduled") | crontab - 2>/dev/null || true
            echo -e "  ${GREEN}✓ Removed from crontab${NC}"
            ;;
    esac

    # Disable in config
    if [[ -f "$SCHED_CLEAN_CONFIG_USER" ]]; then
        if ! python3 - "$SCHED_CLEAN_CONFIG_USER" 2>/dev/null << 'PYEOF'
import sys, json
try:
    with open(sys.argv[1], 'r') as f:
        config = json.load(f)
    config['enabled'] = False
    with open(sys.argv[1], 'w') as f:
        json.dump(config, f, indent=2)
except (FileNotFoundError, json.JSONDecodeError, IOError) as e:
    print(f'Error: {e}', file=sys.stderr)
    sys.exit(1)
PYEOF
        then
            echo -e "  ${RED}✗ Failed to update config${NC}"
            # Continue anyway - scheduler was removed successfully
        else
            echo -e "  ${GREEN}✓ Disabled scheduled cleaning${NC}"
        fi
    fi

    echo ""
}

# ───────────────────────────────────────────────────────────────────
# run_scheduled_clean: Execute automatic cleaning (invoked by scheduler)
# ───────────────────────────────────────────────────────────────────
run_scheduled_clean() {
    local lock_file="${HOME}/.config/barked/clean.lock"
    local lock_timeout=7200  # 2 hours in seconds
    local min_disk_gb=5
    local min_battery_pct=20
    local available_gb disk_used_pct battery_pct is_charging

    # 1. Load config and validate enabled status
    if ! load_scheduled_config; then
        clean_log "ERROR" "Failed to load scheduled clean config"
        return 1
    fi

    if [[ "${SCHED_ENABLED:-false}" != "true" ]]; then
        clean_log "INFO" "Scheduled cleaning is disabled, skipping run"
        return 0
    fi

    # 2. Pre-flight checks: disk space
    if command -v df &>/dev/null; then
        available_gb=$(df -h / | awk 'NR==2 {print $4}' | sed 's/[^0-9.]//g')
        if (( $(echo "$available_gb < $min_disk_gb" | bc -l 2>/dev/null || echo 0) )); then
            clean_log "WARN" "Low disk space (${available_gb}GB), skipping scheduled clean"
            return 0
        fi
    fi

    # 2b. Pre-flight checks: battery (macOS only)
    if [[ "$OS" == "macos" ]] && command -v pmset &>/dev/null; then
        battery_pct=$(pmset -g batt | grep -Eo "\d+%" | tr -d '%' | head -n1)
        is_charging=$(pmset -g batt | grep -q "AC Power" && echo "yes" || echo "no")

        if [[ "$is_charging" != "yes" ]] && [[ -n "$battery_pct" ]] && (( battery_pct < min_battery_pct )); then
            clean_log "WARN" "Low battery (${battery_pct}%), skipping scheduled clean"
            return 0
        fi
    fi

    # 3. Acquire lock file (prevent concurrent runs)
    # Use atomic lock creation to prevent race conditions
    (set -C; echo $$ > "$lock_file") 2>/dev/null || {
        # Lock exists, check if stale
        if [[ -f "$lock_file" ]]; then
            local lock_age=$(($(date +%s) - $(stat -f %m "$lock_file" 2>/dev/null || stat -c %Y "$lock_file" 2>/dev/null || echo 0)))
            if (( lock_age < lock_timeout )); then
                clean_log "INFO" "Another clean is already running (lock age: ${lock_age}s), exiting"
                return 0
            else
                clean_log "WARN" "Stale lock file detected (age: ${lock_age}s), removing"
                rm -f "$lock_file"
                # Try to acquire lock again atomically
                (set -C; echo $$ > "$lock_file") 2>/dev/null || {
                    clean_log "INFO" "Another clean acquired the lock first, exiting"
                    return 0
                }
            fi
        else
            clean_log "INFO" "Another clean is already running, exiting"
            return 0
        fi
    }
    # Append lock cleanup to existing EXIT trap (preserves cleanup_sudo if set)
    local existing_trap
    existing_trap=$(trap -p EXIT | sed "s/^trap -- '//;s/' EXIT$//") || true
    if [[ -n "$existing_trap" ]]; then
        trap "${existing_trap}; rm -f \"$lock_file\"" EXIT
    else
        trap 'rm -f "$lock_file"' EXIT
    fi

    # 4. Set categories from config
    if [[ ${#SCHED_CATEGORIES[@]} -eq 0 ]]; then
        clean_log "ERROR" "No categories configured for scheduled clean"
        return 1
    fi

    # Set all categories to 0, then enable only scheduled ones
    for cat in "${CLEAN_CAT_ORDER[@]}"; do
        CLEAN_CATEGORIES[$cat]=0
    done
    for cat in "${SCHED_CATEGORIES[@]}"; do
        CLEAN_CATEGORIES[$cat]=1
    done

    # Populate CLEAN_TARGETS from enabled categories
    for cat in "${CLEAN_CAT_ORDER[@]}"; do
        if [[ "${CLEAN_CATEGORIES[$cat]}" == "1" ]]; then
            for target in ${CLEAN_CAT_TARGETS[$cat]}; do
                if clean_target_available "$target"; then
                    CLEAN_TARGETS[$target]=1
                fi
            done
        fi
    done

    clean_log "INFO" "Starting scheduled clean: categories=${SCHED_CATEGORIES[*]}"

    # 5. Run clean_execute (with FORCE flag to skip confirmation)
    CLEAN_FORCE=true
    if ! clean_execute; then
        clean_log "ERROR" "Scheduled clean failed"
        return 1
    fi

    # 6. Calculate totals
    local total_files=0
    local total_bytes=0

    if [[ -v CLEAN_RESULT_FILES[@] ]]; then
        for count in "${CLEAN_RESULT_FILES[@]}"; do
            total_files=$((total_files + count))
        done
    fi

    if [[ -v CLEAN_RESULT_BYTES[@] ]]; then
        for bytes in "${CLEAN_RESULT_BYTES[@]}"; do
            total_bytes=$((total_bytes + bytes))
        done
    fi

    local total_size_fmt
    total_size_fmt=$(format_bytes "$total_bytes")

    clean_log "INFO" "Scheduled clean completed: $total_files files, $total_size_fmt freed"

    # 7. Send notification (if enabled)
    if [[ "${SCHED_NOTIFY:-false}" == "true" ]]; then
        send_clean_notification "$total_files" "$total_bytes"
    fi

    # 8. Update last_run timestamp in config
    # Check if config file is writable before attempting update
    if [[ ! -w "$SCHED_CLEAN_CONFIG_USER" ]]; then
        clean_log "WARN" "Cannot write to config file (permission denied), skipping timestamp update"
    else
        # Use sys.argv pattern to prevent shell injection
        if python3 - "$SCHED_CLEAN_CONFIG_USER" 2>/dev/null << 'PYEOF'
import sys, json
from datetime import datetime
try:
    with open(sys.argv[1], 'r') as f:
        config = json.load(f)
    config['last_run'] = datetime.utcnow().isoformat() + 'Z'
    with open(sys.argv[1], 'w') as f:
        json.dump(config, f, indent=2)
except (IOError, OSError, json.JSONDecodeError) as e:
    sys.exit(1)
PYEOF
        then
            clean_log "INFO" "Updated last_run timestamp"
        else
            clean_log "WARN" "Failed to update last_run timestamp"
        fi
    fi

    return 0
}

# ───────────────────────────────────────────────────────────────────
# send_clean_notification: Send notification about clean results
# ───────────────────────────────────────────────────────────────────
send_clean_notification() {
    local file_count=$1
    local bytes_freed=$2

    # Validate inputs are numeric
    if ! [[ "$file_count" =~ ^[0-9]+$ ]]; then
        clean_log "WARN" "Invalid file_count for notification: $file_count"
        return 0  # Non-critical, just skip notification
    fi

    if ! [[ "$bytes_freed" =~ ^[0-9]+$ ]]; then
        clean_log "WARN" "Invalid bytes_freed for notification: $bytes_freed"
        return 0
    fi

    # Skip notification if nothing was cleaned
    if [[ $file_count -eq 0 ]] && [[ $bytes_freed -eq 0 ]]; then
        clean_log "INFO" "No files cleaned, skipping notification"
        return 0
    fi

    # Convert bytes to human-readable format
    local size_str
    size_str=$(format_bytes "$bytes_freed")

    # Platform-specific notification
    case "$OS" in
        macos)
            # macOS: Use osascript for native notifications
            if ! osascript -e "display notification \"Cleaned ${size_str} from ${file_count} files\" with title \"Barked Cleaner\" subtitle \"Scheduled cleaning complete\"" 2>/dev/null; then
                # Notification failed - log but don't error out
                clean_log "INFO" "Notification system unavailable (osascript failed)"
            fi
            ;;
        linux)
            # Linux: Use notify-send if available
            if command -v notify-send &>/dev/null; then
                if ! notify-send "Barked Cleaner" "Cleaned ${size_str} from ${file_count} files" 2>/dev/null; then
                    clean_log "INFO" "Notification failed (notify-send error)"
                fi
            else
                # notify-send not available - just log
                clean_log "INFO" "Notification system unavailable (notify-send not found)"
            fi
            ;;
        *)
            # Windows or unknown platform - not yet implemented
            # TODO: Windows notification support
            clean_log "INFO" "Notifications not supported on this platform"
            ;;
    esac
}

# ═══════════════════════════════════════════════════════════════════
# SEVERITY MAP & SCORING
# ═══════════════════════════════════════════════════════════════════

# Fixed severity weights: CRITICAL=10, HIGH=7, MEDIUM=4, LOW=2
declare -A MODULE_SEVERITY=(
    [disk-encrypt]="CRITICAL"
    [firewall-inbound]="CRITICAL"
    [auto-updates]="CRITICAL"
    [lock-screen]="CRITICAL"
    [firewall-stealth]="HIGH"
    [firewall-outbound]="HIGH"
    [dns-secure]="HIGH"
    [ssh-harden]="HIGH"
    [guest-disable]="HIGH"
    [telemetry-disable]="HIGH"
    [kernel-sysctl]="HIGH"
    [hostname-scrub]="MEDIUM"
    [git-harden]="MEDIUM"
    [browser-basic]="MEDIUM"
    [monitoring-tools]="MEDIUM"
    [permissions-audit]="MEDIUM"
    [apparmor-enforce]="MEDIUM"
    [boot-security]="MEDIUM"
    [browser-fingerprint]="LOW"
    [mac-rotate]="LOW"
    [vpn-killswitch]="LOW"
    [traffic-obfuscation]="LOW"
    [metadata-strip]="LOW"
    [dev-isolation]="LOW"
    [audit-script]="LOW"
    [backup-guidance]="LOW"
    [border-prep]="LOW"
    [bluetooth-disable]="LOW"
)

declare -A SEVERITY_WEIGHT=(
    [CRITICAL]=10
    [HIGH]=7
    [MEDIUM]=4
    [LOW]=2
)

# Advanced modules requiring vetting
declare -A ADVANCED_MODULES=(
    [kernel-sysctl]=1
    [apparmor-enforce]=1
    [boot-security]=1
)

severity_weight() {
    local mod_id="$1"
    local sev="${MODULE_SEVERITY[$mod_id]:-LOW}"
    echo "${SEVERITY_WEIGHT[$sev]}"
}

# Get a brief description of what action a module would take in dry-run mode
dry_run_description() {
    local mod_id="$1"
    # Look up the label from ALL_MODULE_LABELS and extract the description after " — "
    for label in "${ALL_MODULE_LABELS[@]}"; do
        if [[ "$label" == "${mod_id} "* ]]; then
            echo "${BROWN}Will apply: ${label#*— }${NC}"
            return
        fi
    done
    # Fallback if module not found in labels
    echo "${BROWN}Will apply hardening${NC}"
}

# Calculate hardening score for a set of modules
# Args: $1 = name of array with all module IDs, $2 = name of array with applied module IDs
# Outputs: "applied_weight total_weight percentage applied_count total_count"
calculate_score() {
    local -n _all_mods=$1
    local -n _applied_mods=$2
    local total_weight=0
    local applied_weight=0
    local total_count=0
    local applied_count=0

    local -A _applied_set=()
    for m in "${_applied_mods[@]}"; do
        _applied_set[$m]=1
    done

    for mod_id in "${_all_mods[@]}"; do
        local w
        w=$(severity_weight "$mod_id")
        total_weight=$((total_weight + w))
        ((total_count++))
        if [[ -n "${_applied_set[$mod_id]:-}" ]]; then
            applied_weight=$((applied_weight + w))
            ((applied_count++))
        fi
    done

    local pct=0
    if [[ $total_weight -gt 0 ]]; then
        pct=$(( (applied_weight * 100) / total_weight ))
    fi
    echo "$applied_weight $total_weight $pct $applied_count $total_count"
}

# Print a progress bar: [████████░░]
print_score_bar() {
    local pct="$1"
    local width=20
    local filled=$(( (pct * width) / 100 ))
    local empty=$(( width - filled ))
    local bar=""
    for ((i=0; i<filled; i++)); do bar+="█"; done
    for ((i=0; i<empty; i++)); do bar+="░"; done

    local color="$RED"
    if [[ $pct -ge 80 ]]; then color="$GREEN"
    elif [[ $pct -ge 50 ]]; then color="$BROWN"
    fi

    echo -e "  ${BOLD}Hardening Score: ${color}${pct}/100${NC} [${color}${bar}${NC}]"
}

# Print severity-rated findings table
# Takes associative array name: mod_id -> "STATUS|FINDING"
# STATUS: PASS, FAIL, MANUAL, SKIP, N/A
print_findings_table() {
    local -n _findings=$1
    local -n _mod_list=$2

    local sev_order=("CRITICAL" "HIGH" "MEDIUM" "LOW")

    if [[ "$QUIET_MODE" != true ]]; then
        echo ""
        printf "  ${BOLD}%-8s %-10s %-22s %s${NC}\n" "Status" "Severity" "Module" "Finding"
        printf "  ${BROWN}%-8s %-10s %-22s %s${NC}\n" "------" "--------" "--------------------" "-------"
    fi

    for sev in "${sev_order[@]}"; do
        for mod_id in "${_mod_list[@]}"; do
            [[ "${MODULE_SEVERITY[$mod_id]:-}" != "$sev" ]] && continue
            local entry="${_findings[$mod_id]:-}"
            [[ -z "$entry" ]] && continue

            local status="${entry%%|*}"
            local finding="${entry#*|}"

            local icon="" color=""
            case "$status" in
                PASS)   icon="✓"; color="$GREEN" ;;
                FAIL)   icon="✗"; color="$RED" ;;
                MANUAL) icon="~"; color="$RED" ;;
                SKIP)   icon="○"; color="$BROWN" ;;
                N/A)    icon="—"; color="$BROWN" ;;
            esac

            if [[ "$QUIET_MODE" != true ]]; then
                printf "  ${color}%-8s${NC} %-10s %-22s %s\n" \
                    "${icon} ${status}" "$sev" "$mod_id" "$finding"
            fi
        done
    done
    echo ""
}

# Record a single module finding into the findings table
record_finding() {
    local status="$1" mod_id="$2" message="$3"
    FINDINGS_STATUS+=("$status")
    FINDINGS_MODULE+=("$mod_id")
    FINDINGS_MESSAGE+=("$message")
}

# ═══════════════════════════════════════════════════════════════════
# AUDIT MODE — SCORE & REPORT WITHOUT CHANGES
# ═══════════════════════════════════════════════════════════════════
run_audit() {
    local -a audit_mods=()

    # Determine which modules to audit
    if [[ -n "$AUTO_PROFILE" ]]; then
        # Profile explicitly specified on command line
        PROFILE="$AUTO_PROFILE"
        build_module_list
        audit_mods=("${ENABLED_MODULES[@]}")
    elif [[ -n "$STATE_PROFILE" ]]; then
        # Use profile from state file (previously applied hardening)
        PROFILE="$STATE_PROFILE"
        build_module_list
        audit_mods=("${ENABLED_MODULES[@]}")
        if [[ "$QUIET_MODE" != true ]]; then
            echo -e "  ${BROWN}Using profile from state: ${PROFILE}${NC}"
        fi
    else
        # No profile specified and no state exists - audit all modules
        audit_mods=("${ALL_MODULE_IDS[@]}")
        if [[ "$QUIET_MODE" != true ]]; then
            echo -e "  ${BROWN}No profile found - auditing all modules${NC}"
        fi
    fi

    # Clear findings arrays
    FINDINGS_STATUS=()
    FINDINGS_MODULE=()
    FINDINGS_MESSAGE=()

    # Run check on each module
    for mod_id in "${audit_mods[@]}"; do
        check_module_state "$mod_id"
    done

    # Build associative array for findings table
    local -A findings_map=()
    for i in "${!FINDINGS_MODULE[@]}"; do
        local status="${FINDINGS_STATUS[$i]}"
        local mod_id="${FINDINGS_MODULE[$i]}"
        local msg="${FINDINGS_MESSAGE[$i]}"
        local mapped_status
        case "$status" in
            pass)    mapped_status="PASS" ;;
            fail)    mapped_status="FAIL" ;;
            manual)  mapped_status="MANUAL" ;;
            skip)    mapped_status="SKIP" ;;
            partial) mapped_status="MANUAL" ;;
            *)       mapped_status="SKIP" ;;
        esac
        findings_map[$mod_id]="${mapped_status}|${msg}"
    done

    # Calculate score: only count applicable modules (exclude "skip")
    # applied_mods = modules that PASS
    # applicable_mods = modules that are not SKIP (i.e., relevant to this OS)
    local -a applied_mods=()
    local -a applicable_mods=()
    for i in "${!FINDINGS_MODULE[@]}"; do
        local mod="${FINDINGS_MODULE[$i]}"
        local status="${FINDINGS_STATUS[$i]}"
        # Skip modules not applicable to this OS
        if [[ "$status" != "skip" ]]; then
            applicable_mods+=("$mod")
            [[ "$status" == "pass" ]] && applied_mods+=("$mod")
        fi
    done

    local score_output
    score_output=$(calculate_score applicable_mods applied_mods)
    read -r _aw _tw pct _ac _tc <<< "$score_output"

    if [[ "$QUIET_MODE" != true ]]; then
        print_section "Security Audit Report"
        print_findings_table findings_map audit_mods
        print_score_bar "$pct"
        echo -e "  ${BROWN}${_ac} of ${_tc} modules passing${NC}"
        echo ""
    fi

    # Save audit report
    write_audit_report audit_mods findings_map "$pct" "$_ac" "$_tc"
}

write_audit_report() {
    local -n _rpt_mods=$1
    local -n _rpt_findings=$2
    local pct="$3" ac="$4" tc="$5"

    local report_dir="${SCRIPT_DIR}/../audits"
    mkdir -p "$report_dir"
    local report_file="${report_dir}/audit-${DATE}.md"

    local sev_order=("CRITICAL" "HIGH" "MEDIUM" "LOW")

    {
        echo "# Security Audit Report — ${DATE}"
        echo ""
        echo "**Hardening Score:** ${pct}/100 — ${ac} of ${tc} modules passing"
        echo "**OS:** ${OS}$([ -n "$DISTRO" ] && echo " (${DISTRO})")"
        echo "**Profile scope:** ${AUTO_PROFILE:-all}"
        echo "**Generated:** ${TIMESTAMP}"
        echo ""
        echo "## Findings"
        echo ""
        echo "| Status | Severity | Module | Finding |"
        echo "|--------|----------|--------|---------|"
        for sev in "${sev_order[@]}"; do
            for mod_id in "${_rpt_mods[@]}"; do
                [[ "${MODULE_SEVERITY[$mod_id]:-}" != "$sev" ]] && continue
                local entry="${_rpt_findings[$mod_id]:-}"
                [[ -z "$entry" ]] && continue
                local status="${entry%%|*}" finding="${entry#*|}"
                local icon
                case "$status" in
                    PASS) icon="PASS" ;; FAIL) icon="FAIL" ;;
                    MANUAL) icon="MANUAL" ;; *) icon="SKIP" ;;
                esac
                echo "| ${icon} | ${sev} | ${mod_id} | ${finding} |"
            done
        done
        echo ""
        echo "---"
        echo "Generated by barked.sh v${VERSION}"
    } > "$report_file"

    if [[ "$QUIET_MODE" != true ]]; then
        echo -e "  ${GREEN}Audit report saved:${NC} ${report_file}"
    fi
}

# ═══════════════════════════════════════════════════════════════════
# DRY-RUN REPORT
# ═══════════════════════════════════════════════════════════════════
write_dry_run_report() {
    local report_dir="${SCRIPT_DIR}/../audits"
    mkdir -p "$report_dir"
    local report_file="${report_dir}/dry-run-${DATE}.md"

    {
        echo "# Dry Run Report — ${DATE}"
        echo ""
        echo "**Profile:** ${PROFILE:-interactive}"
        echo "**OS:** ${OS}$([ -n "$DISTRO" ] && echo " (${DISTRO})")"
        echo "**Generated:** ${TIMESTAMP}"
        echo ""
        echo "## Summary"
        echo ""
        echo "| Status | Count |"
        echo "|--------|-------|"
        echo "| Would apply | ${COUNT_APPLIED} |"
        echo "| Already applied (skip) | ${COUNT_SKIPPED} |"
        echo "| Would fail | ${COUNT_FAILED} |"
        echo "| Manual steps | ${COUNT_MANUAL} |"
        echo ""
        echo "## Module Details"
        echo ""
        echo '```'
        for entry in "${LOG_ENTRIES[@]}"; do
            echo "$entry"
        done
        echo '```'
        echo ""
        echo "---"
        echo "Generated by barked.sh v${VERSION} (dry-run mode)"
    } > "$report_file"

    if [[ "$QUIET_MODE" != true ]]; then
        echo ""
        echo -e "  ${BOLD}Dry Run Summary:${NC}"
        echo -e "    Would apply: ${BOLD}${COUNT_APPLIED}${NC}"
        echo -e "    Already done: ${COUNT_SKIPPED}"
        echo ""
        echo -e "  ${GREEN}Dry run report saved:${NC} ${report_file}"
    fi
}

# ═══════════════════════════════════════════════════════════════════
# PRE-CHANGE ANALYSIS — SMART SKIP & PROJECTED SCORE
# ═══════════════════════════════════════════════════════════════════
# Runs check_module_state on all enabled modules before applying.
# Shows what will be skipped, what needs work, and projected score.
# Returns 0 to proceed, 1 to abort.
pre_change_analysis() {
    FINDINGS_STATUS=()
    FINDINGS_MODULE=()
    FINDINGS_MESSAGE=()

    for mod_id in "${ENABLED_MODULES[@]}"; do
        check_module_state "$mod_id"
    done

    local already_applied=0 not_applicable=0 to_apply=0 partial=0
    local -a already_ids=() apply_ids=() applicable_mods=()

    for i in "${!FINDINGS_MODULE[@]}"; do
        local mod_id="${FINDINGS_MODULE[$i]}"
        case "${FINDINGS_STATUS[$i]}" in
            pass)    ((already_applied++)); already_ids+=("$mod_id"); applicable_mods+=("$mod_id") ;;
            skip)    ((not_applicable++)) ;;  # Don't add to applicable_mods
            manual|partial)  ((partial++)); apply_ids+=("$mod_id"); applicable_mods+=("$mod_id") ;;
            fail)    ((to_apply++)); apply_ids+=("$mod_id"); applicable_mods+=("$mod_id") ;;
        esac
    done

    # Calculate current and projected scores (only count applicable modules)
    local current_score projected_score
    current_score=$(calculate_score applicable_mods already_ids)
    read -r _aw1 _tw1 cur_pct _ac1 _tc1 <<< "$current_score"

    # Projected: assume all apply_ids + already_ids will pass
    local -a projected_applied=("${already_ids[@]}" "${apply_ids[@]}")
    projected_score=$(calculate_score applicable_mods projected_applied)
    read -r _aw2 _tw2 proj_pct _ac2 _tc2 <<< "$projected_score"

    if [[ "$QUIET_MODE" != true ]]; then
        echo ""
        echo -e "  ${BOLD}Pre-change analysis complete.${NC}"
        echo ""
        echo -e "    Already applied:   ${GREEN}${already_applied}${NC} modules (skipping)"
        echo -e "    Not applicable:    ${BROWN}${not_applicable}${NC} modules (skipping)"
        if [[ $partial -gt 0 ]]; then
            echo -e "    Partially applied: ${RED}${partial}${NC} modules (will complete)"
        fi
        echo -e "    To apply:          ${BOLD}${to_apply}${NC} modules"
        echo ""
        echo -e "    Current score:     ${cur_pct}/100"
        echo -e "    Projected score:   ${BOLD}${proj_pct}/100${NC}"
        echo ""
    fi

    # In auto mode, don't prompt
    if [[ "$AUTO_MODE" == true ]]; then
        if [[ $to_apply -eq 0 && $partial -eq 0 ]]; then
            echo -e "  ${GREEN}Nothing to do — all modules already applied.${NC}"
            return 2
        fi
        return 0
    fi

    # Interactive: ask to proceed
    if [[ $to_apply -eq 0 && $partial -eq 0 ]]; then
        echo -e "  ${GREEN}All modules already applied. Nothing to do.${NC}"
        return 2
    fi

    if ! prompt_yn "Proceed with hardening?"; then
        echo "Aborted."
        return 1
    fi
    return 0
}

# ═══════════════════════════════════════════════════════════════════
# MODULE CHECK FUNCTIONS — AUDIT ONLY (no changes)
# ═══════════════════════════════════════════════════════════════════

# Dispatcher: check any module's current security state without making
# changes and record the result via record_finding().
# Usage: check_module_state <module-id>
check_module_state() {
    local mod_id="$1"

    case "$mod_id" in

    # ── Disk Encryption ──────────────────────────────────────────
    disk-encrypt)
        if [[ "$OS" == "macos" ]]; then
            if fdesetup status 2>/dev/null | grep -q "On"; then
                record_finding "pass" "$mod_id" "FileVault enabled"
            else
                record_finding "fail" "$mod_id" "FileVault not enabled"
            fi
        elif [[ "$OS" == "linux" ]]; then
            if lsblk -o NAME,TYPE,FSTYPE 2>/dev/null | grep -q "crypt"; then
                record_finding "pass" "$mod_id" "LUKS encryption detected"
            else
                record_finding "fail" "$mod_id" "No disk encryption detected"
            fi
        fi
        ;;

    # ── Inbound Firewall ─────────────────────────────────────────
    firewall-inbound)
        if [[ "$OS" == "macos" ]]; then
            if /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null | grep -qE "enabled|State = 1|State = 2"; then
                record_finding "pass" "$mod_id" "Firewall active"
            else
                record_finding "fail" "$mod_id" "Firewall not enabled"
            fi
        elif [[ "$OS" == "linux" ]]; then
            if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
                record_finding "pass" "$mod_id" "ufw active"
            else
                record_finding "fail" "$mod_id" "Firewall not active"
            fi
        fi
        ;;

    # ── Stealth Mode ─────────────────────────────────────────────
    firewall-stealth)
        if [[ "$OS" == "macos" ]]; then
            if /usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>/dev/null | grep -q "enabled"; then
                record_finding "pass" "$mod_id" "Stealth mode enabled"
            else
                record_finding "fail" "$mod_id" "Stealth mode not enabled"
            fi
        elif [[ "$OS" == "linux" ]]; then
            if iptables -C INPUT -p icmp --icmp-type echo-request -j DROP 2>/dev/null; then
                record_finding "pass" "$mod_id" "ICMP echo-request dropped"
            else
                record_finding "fail" "$mod_id" "ICMP echo-request not blocked"
            fi
        fi
        ;;

    # ── Outbound Firewall ────────────────────────────────────────
    firewall-outbound)
        if [[ "$OS" == "macos" ]]; then
            if cask_installed lulu; then
                record_finding "pass" "$mod_id" "LuLu installed"
            else
                record_finding "fail" "$mod_id" "No outbound firewall"
            fi
        elif [[ "$OS" == "linux" ]]; then
            if command -v ufw &>/dev/null && ufw status verbose 2>/dev/null | grep -q "deny (outgoing)"; then
                record_finding "pass" "$mod_id" "ufw denies outgoing by default"
            else
                record_finding "fail" "$mod_id" "Outbound traffic not restricted"
            fi
        fi
        ;;

    # ── Secure DNS ───────────────────────────────────────────────
    dns-secure)
        if [[ "$OS" == "macos" ]]; then
            if networksetup -getdnsservers Wi-Fi 2>/dev/null | grep -q "9.9.9.9"; then
                record_finding "pass" "$mod_id" "Quad9 DNS configured"
            else
                record_finding "fail" "$mod_id" "DNS not set to Quad9"
            fi
        elif [[ "$OS" == "linux" ]]; then
            if (command -v resolvectl &>/dev/null && resolvectl dns 2>/dev/null | grep -q "9.9.9.9") || \
               ([[ -f /etc/resolv.conf ]] && grep -q "9.9.9.9" /etc/resolv.conf 2>/dev/null); then
                record_finding "pass" "$mod_id" "Quad9 DNS configured"
            else
                record_finding "fail" "$mod_id" "DNS not set to Quad9"
            fi
        fi
        ;;

    # ── Automatic Updates ────────────────────────────────────────
    auto-updates)
        if [[ "$OS" == "macos" ]]; then
            if [[ "$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled 2>/dev/null)" == "1" ]]; then
                record_finding "pass" "$mod_id" "Automatic updates enabled"
            else
                record_finding "fail" "$mod_id" "Automatic updates not enabled"
            fi
        elif [[ "$OS" == "linux" ]]; then
            if command -v unattended-upgrades &>/dev/null || systemctl is-active dnf-automatic.timer &>/dev/null 2>&1; then
                record_finding "pass" "$mod_id" "Automatic updates configured"
            else
                record_finding "fail" "$mod_id" "Automatic updates not configured"
            fi
        fi
        ;;

    # ── Guest Account ────────────────────────────────────────────
    guest-disable)
        if [[ "$OS" == "macos" ]]; then
            if [[ "$(defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled 2>/dev/null)" == "0" ]]; then
                record_finding "pass" "$mod_id" "Guest account disabled"
            else
                record_finding "fail" "$mod_id" "Guest account enabled"
            fi
        elif [[ "$OS" == "linux" ]]; then
            record_finding "pass" "$mod_id" "No guest account by default"
        fi
        ;;

    # ── Lock Screen ──────────────────────────────────────────────
    lock-screen)
        if [[ "$OS" == "macos" ]]; then
            if [[ "$(defaults read com.apple.screensaver askForPasswordDelay 2>/dev/null)" == "0" ]]; then
                record_finding "pass" "$mod_id" "Immediate password on lock"
            else
                record_finding "fail" "$mod_id" "Password delay on lock screen"
            fi
        elif [[ "$OS" == "linux" ]]; then
            if command -v gsettings &>/dev/null && [[ "$(gsettings get org.gnome.desktop.screensaver lock-enabled 2>/dev/null)" == "true" ]]; then
                record_finding "pass" "$mod_id" "Screen lock enabled"
            else
                record_finding "fail" "$mod_id" "Screen lock not configured"
            fi
        fi
        ;;

    # ── Hostname Scrub ───────────────────────────────────────────
    hostname-scrub)
        if [[ "$OS" == "macos" ]]; then
            local cname
            cname="$(scutil --get ComputerName 2>/dev/null)"
            if [[ "$cname" == "MacBook" || "$cname" == "Mac" ]]; then
                record_finding "pass" "$mod_id" "Hostname is generic (${cname})"
            else
                record_finding "fail" "$mod_id" "Hostname reveals identity (${cname})"
            fi
        elif [[ "$OS" == "linux" ]]; then
            local hname
            hname="$(hostname 2>/dev/null)"
            if [[ "$hname" == "linux" || "$hname" == "localhost" ]]; then
                record_finding "pass" "$mod_id" "Hostname is generic"
            else
                record_finding "fail" "$mod_id" "Hostname may reveal identity (${hname})"
            fi
        fi
        ;;

    # ── SSH Hardening ────────────────────────────────────────────
    ssh-harden)
        if [[ -f "${REAL_HOME}/.ssh/config" ]] && grep -q "IdentitiesOnly yes" "${REAL_HOME}/.ssh/config" 2>/dev/null; then
            record_finding "pass" "$mod_id" "SSH config has IdentitiesOnly yes"
        else
            record_finding "fail" "$mod_id" "SSH config not hardened"
        fi
        ;;

    # ── Git Hardening ────────────────────────────────────────────
    git-harden)
        if [[ "$(git config --global --get commit.gpgsign 2>/dev/null)" == "true" ]]; then
            record_finding "pass" "$mod_id" "Git commit signing enabled"
        else
            record_finding "fail" "$mod_id" "Git commit signing not enabled"
        fi
        ;;

    # ── Telemetry ────────────────────────────────────────────────
    telemetry-disable)
        if [[ "$OS" == "macos" ]]; then
            if [[ "$(defaults read com.apple.CrashReporter DialogType 2>/dev/null)" == "none" ]]; then
                record_finding "pass" "$mod_id" "Crash reporter telemetry disabled"
            else
                record_finding "fail" "$mod_id" "Crash reporter telemetry active"
            fi
        elif [[ "$OS" == "linux" ]]; then
            record_finding "manual" "$mod_id" "Verify telemetry services manually"
        fi
        ;;

    # ── Monitoring Tools ─────────────────────────────────────────
    monitoring-tools)
        if [[ "$OS" == "macos" ]]; then
            if cask_installed oversight && cask_installed blockblock; then
                record_finding "pass" "$mod_id" "OverSight and BlockBlock installed"
            else
                record_finding "fail" "$mod_id" "Monitoring tools not installed"
            fi
        elif [[ "$OS" == "linux" ]]; then
            if command -v auditctl &>/dev/null && command -v aide &>/dev/null; then
                record_finding "pass" "$mod_id" "auditd + aide installed"
            else
                record_finding "fail" "$mod_id" "auditd/aide not installed"
            fi
        fi
        ;;

    # ── Permissions Audit ────────────────────────────────────────
    permissions-audit)
        record_finding "manual" "$mod_id" "Requires manual review of permissions"
        ;;

    # ── Browser Basic ────────────────────────────────────────────
    browser-basic)
        local ff_profile=""
        if [[ "$OS" == "macos" ]]; then
            ff_profile=$(find "${REAL_HOME}/Library/Application Support/Firefox/Profiles" -maxdepth 1 -name "*.default-release" -type d 2>/dev/null | head -1)
        elif [[ "$OS" == "linux" ]]; then
            ff_profile=$(find "${REAL_HOME}/.mozilla/firefox" -maxdepth 1 -name "*.default-release" -type d 2>/dev/null | head -1)
        fi
        if [[ -n "$ff_profile" ]] && [[ -f "${ff_profile}/user.js" ]] && grep -q "toolkit.telemetry.enabled" "${ff_profile}/user.js" 2>/dev/null; then
            record_finding "pass" "$mod_id" "Firefox telemetry hardened via user.js"
        else
            record_finding "fail" "$mod_id" "Firefox not hardened"
        fi
        ;;

    # ── Browser Fingerprint ──────────────────────────────────────
    browser-fingerprint)
        local ff_profile=""
        if [[ "$OS" == "macos" ]]; then
            ff_profile=$(find "${REAL_HOME}/Library/Application Support/Firefox/Profiles" -maxdepth 1 -name "*.default-release" -type d 2>/dev/null | head -1)
        elif [[ "$OS" == "linux" ]]; then
            ff_profile=$(find "${REAL_HOME}/.mozilla/firefox" -maxdepth 1 -name "*.default-release" -type d 2>/dev/null | head -1)
        fi
        if [[ -n "$ff_profile" ]] && [[ -f "${ff_profile}/user.js" ]] && grep -q "privacy.resistFingerprinting" "${ff_profile}/user.js" 2>/dev/null; then
            record_finding "pass" "$mod_id" "Fingerprint resistance enabled"
        else
            record_finding "fail" "$mod_id" "Fingerprint resistance not enabled"
        fi
        ;;

    # ── MAC Address Rotation ─────────────────────────────────────
    mac-rotate)
        if [[ "$OS" == "linux" ]]; then
            if [[ -f /etc/NetworkManager/conf.d/mac-randomize.conf ]]; then
                record_finding "pass" "$mod_id" "MAC randomization configured"
            else
                record_finding "fail" "$mod_id" "MAC randomization not configured"
            fi
        elif [[ "$OS" == "macos" ]]; then
            record_finding "manual" "$mod_id" "Verify MAC rotation in Network settings"
        fi
        ;;

    # ── VPN Kill Switch ──────────────────────────────────────────
    vpn-killswitch)
        if command -v mullvad &>/dev/null; then
            if mullvad always-require-vpn get 2>/dev/null | grep -qi "enabled\|on"; then
                record_finding "pass" "$mod_id" "Mullvad kill switch enabled"
            else
                record_finding "fail" "$mod_id" "Mullvad installed but kill switch off"
            fi
        else
            record_finding "fail" "$mod_id" "Mullvad VPN not installed"
        fi
        ;;

    # ── Traffic Obfuscation ──────────────────────────────────────
    traffic-obfuscation)
        record_finding "manual" "$mod_id" "Requires manual verification of DAITA/Tor"
        ;;

    # ── Metadata Strip ───────────────────────────────────────────
    metadata-strip)
        if command -v exiftool &>/dev/null; then
            record_finding "pass" "$mod_id" "exiftool installed"
        else
            record_finding "fail" "$mod_id" "exiftool not installed"
        fi
        ;;

    # ── Dev Isolation ────────────────────────────────────────────
    dev-isolation)
        if [[ "$OS" == "macos" ]] && [[ -d "/Applications/UTM.app" ]]; then
            record_finding "pass" "$mod_id" "UTM installed for VM isolation"
        elif command -v docker &>/dev/null; then
            record_finding "pass" "$mod_id" "Docker available for isolation"
        else
            record_finding "fail" "$mod_id" "No isolation tools detected"
        fi
        ;;

    # ── Audit Script ─────────────────────────────────────────────
    audit-script)
        if [[ "$OS" == "macos" ]] && [[ -f "${REAL_HOME}/Library/LaunchAgents/com.secure.weekly-audit.plist" ]]; then
            record_finding "pass" "$mod_id" "Weekly audit LaunchAgent scheduled"
        elif [[ "$OS" == "linux" ]] && crontab -u "${REAL_USER}" -l 2>/dev/null | grep -q "weekly-audit"; then
            record_finding "pass" "$mod_id" "Weekly audit in crontab"
        else
            record_finding "fail" "$mod_id" "No weekly audit scheduled"
        fi
        ;;

    # ── Backup Guidance ──────────────────────────────────────────
    backup-guidance)
        record_finding "manual" "$mod_id" "Requires manual verification of backup strategy"
        ;;

    # ── Border Prep ──────────────────────────────────────────────
    border-prep)
        record_finding "manual" "$mod_id" "Requires manual verification of travel protocol"
        ;;

    # ── Bluetooth Disable ────────────────────────────────────────
    bluetooth-disable)
        if [[ "$OS" == "linux" ]]; then
            if ! systemctl is-active bluetooth &>/dev/null 2>&1; then
                record_finding "pass" "$mod_id" "Bluetooth service disabled"
            else
                record_finding "fail" "$mod_id" "Bluetooth service active"
            fi
        elif [[ "$OS" == "macos" ]]; then
            record_finding "manual" "$mod_id" "Verify Bluetooth off in System Settings"
        fi
        ;;

    # ── Kernel Sysctl (Linux only) ───────────────────────────────
    kernel-sysctl)
        if [[ "$OS" != "linux" ]]; then
            record_finding "skip" "$mod_id" "Linux only — not applicable"
        elif [[ -f /etc/sysctl.d/99-hardening.conf ]]; then
            record_finding "pass" "$mod_id" "Hardening sysctl config present"
        else
            local all_ok=true
            for param in "kernel.randomize_va_space=2" "fs.suid_dumpable=0" \
                         "net.ipv4.conf.all.rp_filter=1" "net.ipv4.tcp_syncookies=1" \
                         "net.ipv4.conf.all.accept_redirects=0" "net.ipv4.conf.all.accept_source_route=0"; do
                local key="${param%%=*}" expected="${param#*=}"
                local current
                current="$(sysctl -n "$key" 2>/dev/null)"
                if [[ "$current" != "$expected" ]]; then
                    all_ok=false
                    break
                fi
            done
            if $all_ok; then
                record_finding "pass" "$mod_id" "All sysctl parameters hardened"
            else
                record_finding "fail" "$mod_id" "Kernel parameters not fully hardened"
            fi
        fi
        ;;

    # ── AppArmor Enforce ─────────────────────────────────────────
    apparmor-enforce)
        if [[ "$OS" == "linux" ]]; then
            if command -v aa-status &>/dev/null && aa-status 2>/dev/null | grep -q "enforce"; then
                record_finding "pass" "$mod_id" "AppArmor profiles enforcing"
            else
                record_finding "fail" "$mod_id" "AppArmor not in enforce mode"
            fi
        elif [[ "$OS" == "macos" ]]; then
            record_finding "manual" "$mod_id" "Check App Sandbox entitlements manually"
        fi
        ;;

    # ── Boot Security ────────────────────────────────────────────
    boot-security)
        if [[ "$OS" == "macos" ]]; then
            if csrutil status 2>/dev/null | grep -q "enabled"; then
                record_finding "pass" "$mod_id" "SIP enabled"
            else
                record_finding "fail" "$mod_id" "SIP disabled"
            fi
        elif [[ "$OS" == "linux" ]]; then
            if mokutil --sb-state 2>/dev/null | grep -qi "SecureBoot enabled"; then
                record_finding "pass" "$mod_id" "Secure Boot enabled"
            else
                record_finding "fail" "$mod_id" "Secure Boot not enabled"
            fi
        fi
        ;;

    # ── Unknown module ───────────────────────────────────────────
    *)
        record_finding "skip" "$mod_id" "Unknown module"
        ;;
    esac
}

# ═══════════════════════════════════════════════════════════════════
# MODULE CHECK — NON-DESTRUCTIVE STATE ASSESSMENT
# ═══════════════════════════════════════════════════════════════════
# Returns via globals: CHECK_STATUS ("PASS"|"FAIL"|"MANUAL"|"N/A")
#                      CHECK_FINDING (human-readable string)
CHECK_STATUS=""
CHECK_FINDING=""

check_module() {
    local mod_id="$1"
    local check_func="check_${mod_id//-/_}"
    CHECK_STATUS="FAIL"
    CHECK_FINDING="Not checked"
    if declare -f "$check_func" &>/dev/null; then
        "$check_func"
    else
        CHECK_STATUS="N/A"
        CHECK_FINDING="No check function available"
    fi
}

check_disk_encrypt() {
    if [[ "$OS" == "macos" ]]; then
        if fdesetup status 2>/dev/null | grep -q "On"; then
            CHECK_STATUS="PASS"; CHECK_FINDING="FileVault enabled"
        else
            CHECK_STATUS="FAIL"; CHECK_FINDING="FileVault not enabled"
        fi
    elif [[ "$OS" == "linux" ]]; then
        if lsblk -o NAME,TYPE,FSTYPE 2>/dev/null | grep -q "crypt"; then
            CHECK_STATUS="PASS"; CHECK_FINDING="LUKS encryption detected"
        else
            CHECK_STATUS="FAIL"; CHECK_FINDING="No disk encryption detected"
        fi
    fi
}

check_firewall_inbound() {
    if [[ "$OS" == "macos" ]]; then
        if /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null | grep -q "enabled\|State = 1\|State = 2"; then
            CHECK_STATUS="PASS"; CHECK_FINDING="Firewall active"
        else
            CHECK_STATUS="FAIL"; CHECK_FINDING="Firewall not enabled"
        fi
    elif [[ "$OS" == "linux" ]]; then
        if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
            CHECK_STATUS="PASS"; CHECK_FINDING="ufw active"
        else
            CHECK_STATUS="FAIL"; CHECK_FINDING="Firewall not active"
        fi
    fi
}

check_firewall_stealth() {
    if [[ "$OS" == "macos" ]]; then
        if /usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>/dev/null | grep -q "on"; then
            CHECK_STATUS="PASS"; CHECK_FINDING="Stealth mode on"
        else
            CHECK_STATUS="FAIL"; CHECK_FINDING="Stealth mode off"
        fi
    elif [[ "$OS" == "linux" ]]; then
        if iptables -C INPUT -p icmp --icmp-type echo-request -j DROP &>/dev/null 2>&1; then
            CHECK_STATUS="PASS"; CHECK_FINDING="ICMP echo dropped"
        else
            CHECK_STATUS="FAIL"; CHECK_FINDING="ICMP echo not blocked"
        fi
    fi
}

check_firewall_outbound() {
    if [[ "$OS" == "macos" ]]; then
        if cask_installed lulu; then
            CHECK_STATUS="PASS"; CHECK_FINDING="LuLu installed"
        else
            CHECK_STATUS="FAIL"; CHECK_FINDING="No outbound firewall"
        fi
    elif [[ "$OS" == "linux" ]]; then
        if command -v ufw &>/dev/null && ufw status verbose 2>/dev/null | grep -q "deny (outgoing)"; then
            CHECK_STATUS="PASS"; CHECK_FINDING="ufw outbound deny active"
        else
            CHECK_STATUS="FAIL"; CHECK_FINDING="Outbound not restricted"
        fi
    fi
}

check_dns_secure() {
    if [[ "$OS" == "macos" ]]; then
        if networksetup -getdnsservers Wi-Fi 2>/dev/null | grep -q "9.9.9.9"; then
            CHECK_STATUS="PASS"; CHECK_FINDING="Quad9 DNS configured"
        else
            CHECK_STATUS="FAIL"; CHECK_FINDING="DNS not set to Quad9"
        fi
    elif [[ "$OS" == "linux" ]]; then
        if (command -v resolvectl &>/dev/null && resolvectl dns 2>/dev/null | grep -q "9.9.9.9") || \
           ([[ -f /etc/resolv.conf ]] && grep -q "9.9.9.9" /etc/resolv.conf 2>/dev/null); then
            CHECK_STATUS="PASS"; CHECK_FINDING="Quad9 DNS configured"
        else
            CHECK_STATUS="FAIL"; CHECK_FINDING="DNS not set to Quad9"
        fi
    fi
}

check_auto_updates() {
    if [[ "$OS" == "macos" ]]; then
        if [[ "$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled 2>/dev/null)" == "1" ]]; then
            CHECK_STATUS="PASS"; CHECK_FINDING="Automatic updates enabled"
        else
            CHECK_STATUS="FAIL"; CHECK_FINDING="Automatic updates not enabled"
        fi
    elif [[ "$OS" == "linux" ]]; then
        if command -v unattended-upgrades &>/dev/null || systemctl is-active dnf-automatic.timer &>/dev/null 2>&1; then
            CHECK_STATUS="PASS"; CHECK_FINDING="Automatic updates configured"
        else
            CHECK_STATUS="FAIL"; CHECK_FINDING="Automatic updates not configured"
        fi
    fi
}

check_guest_disable() {
    if [[ "$OS" == "macos" ]]; then
        if [[ "$(defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled 2>/dev/null)" == "0" ]]; then
            CHECK_STATUS="PASS"; CHECK_FINDING="Guest account disabled"
        else
            CHECK_STATUS="FAIL"; CHECK_FINDING="Guest account enabled"
        fi
    elif [[ "$OS" == "linux" ]]; then
        if ! id guest &>/dev/null 2>&1; then
            CHECK_STATUS="PASS"; CHECK_FINDING="No guest account"
        else
            CHECK_STATUS="FAIL"; CHECK_FINDING="Guest account exists"
        fi
    fi
}

check_lock_screen() {
    if [[ "$OS" == "macos" ]]; then
        if [[ "$(defaults read com.apple.screensaver askForPasswordDelay 2>/dev/null)" == "0" ]]; then
            CHECK_STATUS="PASS"; CHECK_FINDING="Immediate password on lock"
        else
            CHECK_STATUS="FAIL"; CHECK_FINDING="Password delay on lock screen"
        fi
    elif [[ "$OS" == "linux" ]]; then
        if command -v gsettings &>/dev/null && [[ "$(gsettings get org.gnome.desktop.screensaver lock-enabled 2>/dev/null)" == "true" ]]; then
            CHECK_STATUS="PASS"; CHECK_FINDING="Screen lock enabled"
        else
            CHECK_STATUS="FAIL"; CHECK_FINDING="Screen lock not configured"
        fi
    fi
}

check_hostname_scrub() {
    if [[ "$OS" == "macos" ]]; then
        local name; name="$(scutil --get ComputerName 2>/dev/null)"
        if [[ "$name" == "MacBook" || "$name" == "Mac" ]]; then
            CHECK_STATUS="PASS"; CHECK_FINDING="Hostname generic (${name})"
        else
            CHECK_STATUS="FAIL"; CHECK_FINDING="Hostname reveals identity (${name})"
        fi
    elif [[ "$OS" == "linux" ]]; then
        local name; name="$(hostname 2>/dev/null)"
        if [[ "$name" == "linux" || "$name" == "localhost" ]]; then
            CHECK_STATUS="PASS"; CHECK_FINDING="Hostname generic"
        else
            CHECK_STATUS="FAIL"; CHECK_FINDING="Hostname may reveal identity (${name})"
        fi
    fi
}

check_ssh_harden() {
    if [[ -f "${REAL_HOME}/.ssh/config" ]] && grep -q "IdentitiesOnly yes" "${REAL_HOME}/.ssh/config" 2>/dev/null; then
        CHECK_STATUS="PASS"; CHECK_FINDING="SSH hardened (IdentitiesOnly)"
    else
        CHECK_STATUS="FAIL"; CHECK_FINDING="SSH config not hardened"
    fi
}

check_git_harden() {
    if [[ "$(git config --global --get commit.gpgsign 2>/dev/null)" == "true" ]]; then
        CHECK_STATUS="PASS"; CHECK_FINDING="Git commit signing enabled"
    else
        CHECK_STATUS="FAIL"; CHECK_FINDING="Git commit signing not enabled"
    fi
}

check_telemetry_disable() {
    if [[ "$OS" == "macos" ]]; then
        if [[ "$(defaults read com.apple.CrashReporter DialogType 2>/dev/null)" == "none" ]]; then
            CHECK_STATUS="PASS"; CHECK_FINDING="Crash reporter telemetry disabled"
        else
            CHECK_STATUS="FAIL"; CHECK_FINDING="Crash reporter telemetry active"
        fi
    elif [[ "$OS" == "linux" ]]; then
        if ! systemctl is-active apport &>/dev/null 2>&1; then
            CHECK_STATUS="PASS"; CHECK_FINDING="Telemetry disabled"
        else
            CHECK_STATUS="FAIL"; CHECK_FINDING="Telemetry services active"
        fi
    fi
}

check_monitoring_tools() {
    if [[ "$OS" == "macos" ]]; then
        if cask_installed oversight && cask_installed blockblock; then
            CHECK_STATUS="PASS"; CHECK_FINDING="Objective-See tools installed"
        else
            CHECK_STATUS="FAIL"; CHECK_FINDING="Monitoring tools not installed"
        fi
    elif [[ "$OS" == "linux" ]]; then
        if command -v auditctl &>/dev/null && command -v aide &>/dev/null; then
            CHECK_STATUS="PASS"; CHECK_FINDING="auditd + aide installed"
        else
            CHECK_STATUS="FAIL"; CHECK_FINDING="auditd/aide not installed"
        fi
    fi
}

check_permissions_audit() {
    CHECK_STATUS="MANUAL"; CHECK_FINDING="Requires manual review"
}

check_browser_basic() {
    local ff_profile=""
    if [[ "$OS" == "macos" ]]; then
        ff_profile=$(find "${REAL_HOME}/Library/Application Support/Firefox/Profiles" -maxdepth 1 -name "*.default-release" -type d 2>/dev/null | head -1)
    elif [[ "$OS" == "linux" ]]; then
        ff_profile=$(find "${REAL_HOME}/.mozilla/firefox" -maxdepth 1 -name "*.default-release" -type d 2>/dev/null | head -1)
    fi
    if [[ -n "$ff_profile" ]] && [[ -f "${ff_profile}/user.js" ]] && grep -q "toolkit.telemetry.enabled" "${ff_profile}/user.js" 2>/dev/null; then
        CHECK_STATUS="PASS"; CHECK_FINDING="Firefox hardened"
    else
        CHECK_STATUS="FAIL"; CHECK_FINDING="Firefox not hardened"
    fi
}

check_browser_fingerprint() {
    local ff_profile=""
    if [[ "$OS" == "macos" ]]; then
        ff_profile=$(find "${REAL_HOME}/Library/Application Support/Firefox/Profiles" -maxdepth 1 -name "*.default-release" -type d 2>/dev/null | head -1)
    elif [[ "$OS" == "linux" ]]; then
        ff_profile=$(find "${REAL_HOME}/.mozilla/firefox" -maxdepth 1 -name "*.default-release" -type d 2>/dev/null | head -1)
    fi
    if [[ -n "$ff_profile" ]] && [[ -f "${ff_profile}/user.js" ]] && grep -q "privacy.resistFingerprinting" "${ff_profile}/user.js" 2>/dev/null; then
        CHECK_STATUS="PASS"; CHECK_FINDING="Fingerprint resistance enabled"
    else
        CHECK_STATUS="FAIL"; CHECK_FINDING="Fingerprint resistance not enabled"
    fi
}

check_mac_rotate() {
    if [[ "$OS" == "linux" ]]; then
        if [[ -f /etc/NetworkManager/conf.d/mac-randomize.conf ]]; then
            CHECK_STATUS="PASS"; CHECK_FINDING="MAC randomization configured"
        else
            CHECK_STATUS="FAIL"; CHECK_FINDING="MAC randomization not configured"
        fi
    elif [[ "$OS" == "macos" ]]; then
        CHECK_STATUS="MANUAL"; CHECK_FINDING="Verify MAC rotation in Network settings"
    fi
}

check_vpn_killswitch() {
    if command -v mullvad &>/dev/null; then
        if mullvad always-require-vpn get 2>/dev/null | grep -qi "enabled\|on"; then
            CHECK_STATUS="PASS"; CHECK_FINDING="Mullvad kill switch enabled"
        else
            CHECK_STATUS="FAIL"; CHECK_FINDING="Mullvad installed, kill switch off"
        fi
    else
        CHECK_STATUS="FAIL"; CHECK_FINDING="Mullvad VPN not installed"
    fi
}

check_traffic_obfuscation() {
    CHECK_STATUS="MANUAL"; CHECK_FINDING="Requires manual verification of DAITA/Tor"
}

check_metadata_strip() {
    if command -v exiftool &>/dev/null; then
        CHECK_STATUS="PASS"; CHECK_FINDING="exiftool installed"
    else
        CHECK_STATUS="FAIL"; CHECK_FINDING="exiftool not installed"
    fi
}

check_dev_isolation() {
    if [[ "$OS" == "macos" ]] && [[ -d "/Applications/UTM.app" ]]; then
        CHECK_STATUS="PASS"; CHECK_FINDING="UTM installed"
    elif command -v docker &>/dev/null; then
        CHECK_STATUS="PASS"; CHECK_FINDING="Docker available"
    else
        CHECK_STATUS="FAIL"; CHECK_FINDING="No isolation tools detected"
    fi
}

check_audit_script() {
    if [[ "$OS" == "macos" ]] && [[ -f "${REAL_HOME}/Library/LaunchAgents/com.secure.weekly-audit.plist" ]]; then
        CHECK_STATUS="PASS"; CHECK_FINDING="Weekly audit scheduled"
    elif [[ "$OS" == "linux" ]] && crontab -u "${REAL_USER}" -l 2>/dev/null | grep -q "weekly-audit"; then
        CHECK_STATUS="PASS"; CHECK_FINDING="Weekly audit in crontab"
    else
        CHECK_STATUS="FAIL"; CHECK_FINDING="No weekly audit scheduled"
    fi
}

check_backup_guidance() {
    CHECK_STATUS="MANUAL"; CHECK_FINDING="Requires manual verification of backup strategy"
}

check_border_prep() {
    CHECK_STATUS="MANUAL"; CHECK_FINDING="Requires manual verification of travel protocol"
}

check_bluetooth_disable() {
    if [[ "$OS" == "linux" ]]; then
        if ! systemctl is-active bluetooth &>/dev/null 2>&1; then
            CHECK_STATUS="PASS"; CHECK_FINDING="Bluetooth service disabled"
        else
            CHECK_STATUS="FAIL"; CHECK_FINDING="Bluetooth service active"
        fi
    elif [[ "$OS" == "macos" ]]; then
        CHECK_STATUS="MANUAL"; CHECK_FINDING="Verify Bluetooth off in System Settings"
    fi
}

check_kernel_sysctl() {
    if [[ "$OS" != "linux" ]]; then
        CHECK_STATUS="N/A"; CHECK_FINDING="Linux only"; return
    fi
    local all_ok=true
    for param in "kernel.randomize_va_space=2" "fs.suid_dumpable=0" "net.ipv4.conf.all.rp_filter=1" \
                 "net.ipv4.tcp_syncookies=1" "net.ipv4.conf.all.accept_redirects=0" "net.ipv4.conf.all.accept_source_route=0"; do
        local key="${param%%=*}" expected="${param#*=}"
        local current; current="$(sysctl -n "$key" 2>/dev/null)"
        [[ "$current" != "$expected" ]] && all_ok=false && break
    done
    if $all_ok; then
        CHECK_STATUS="PASS"; CHECK_FINDING="All sysctl parameters hardened"
    else
        CHECK_STATUS="FAIL"; CHECK_FINDING="Kernel parameters not fully hardened"
    fi
}

check_apparmor_enforce() {
    if [[ "$OS" == "linux" ]]; then
        if command -v aa-status &>/dev/null && aa-status 2>/dev/null | grep -q "enforce"; then
            CHECK_STATUS="PASS"; CHECK_FINDING="AppArmor profiles enforcing"
        else
            CHECK_STATUS="FAIL"; CHECK_FINDING="AppArmor not in enforce mode"
        fi
    elif [[ "$OS" == "macos" ]]; then
        CHECK_STATUS="MANUAL"; CHECK_FINDING="Check App Sandbox entitlements manually"
    fi
}

check_boot_security() {
    if [[ "$OS" == "macos" ]]; then
        if csrutil status 2>/dev/null | grep -q "enabled"; then
            CHECK_STATUS="PASS"; CHECK_FINDING="SIP enabled"
        else
            CHECK_STATUS="FAIL"; CHECK_FINDING="SIP disabled"
        fi
    elif [[ "$OS" == "linux" ]]; then
        if mokutil --sb-state 2>/dev/null | grep -qi "SecureBoot enabled"; then
            CHECK_STATUS="PASS"; CHECK_FINDING="Secure Boot enabled"
        else
            CHECK_STATUS="FAIL"; CHECK_FINDING="Secure Boot not enabled"
        fi
    fi
}

# ═══════════════════════════════════════════════════════════════════
# LIVE DETECTION — FALLBACK WHEN NO STATE FILE
# ═══════════════════════════════════════════════════════════════════
detect_applied_modules() {
    # Check each module's current state via live detection
    local -a detected=()

    # disk-encrypt
    if [[ "$OS" == "macos" ]] && fdesetup status 2>/dev/null | grep -q "On"; then
        detected+=("disk-encrypt")
    elif [[ "$OS" == "linux" ]] && lsblk -o NAME,TYPE,FSTYPE 2>/dev/null | grep -q "crypt"; then
        detected+=("disk-encrypt")
    fi

    # firewall-inbound
    if [[ "$OS" == "macos" ]]; then
        /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null | grep -q "enabled\|State = 1\|State = 2" && detected+=("firewall-inbound")
    elif command -v ufw &>/dev/null; then
        ufw status 2>/dev/null | grep -q "Status: active" && detected+=("firewall-inbound")
    fi

    # firewall-stealth
    if [[ "$OS" == "macos" ]]; then
        /usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>/dev/null | grep -q "on" && detected+=("firewall-stealth")
    elif iptables -C INPUT -p icmp --icmp-type echo-request -j DROP &>/dev/null 2>&1; then
        detected+=("firewall-stealth")
    fi

    # firewall-outbound
    if [[ "$OS" == "macos" ]] && cask_installed lulu; then
        detected+=("firewall-outbound")
    elif command -v ufw &>/dev/null && ufw status verbose 2>/dev/null | grep -q "deny (outgoing)"; then
        detected+=("firewall-outbound")
    fi

    # dns-secure
    if [[ "$OS" == "macos" ]]; then
        networksetup -getdnsservers Wi-Fi 2>/dev/null | grep -q "9.9.9.9" && detected+=("dns-secure")
    elif command -v resolvectl &>/dev/null && resolvectl dns 2>/dev/null | grep -q "9.9.9.9"; then
        detected+=("dns-secure")
    elif [[ -f /etc/resolv.conf ]] && grep -q "9.9.9.9" /etc/resolv.conf 2>/dev/null; then
        detected+=("dns-secure")
    fi

    # auto-updates
    if [[ "$OS" == "macos" ]]; then
        [[ "$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled 2>/dev/null)" == "1" ]] && detected+=("auto-updates")
    fi

    # guest-disable
    if [[ "$OS" == "macos" ]]; then
        [[ "$(defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled 2>/dev/null)" == "0" ]] && detected+=("guest-disable")
    fi

    # lock-screen
    if [[ "$OS" == "macos" ]]; then
        [[ "$(defaults read com.apple.screensaver askForPasswordDelay 2>/dev/null)" == "0" ]] && detected+=("lock-screen")
    elif command -v gsettings &>/dev/null; then
        [[ "$(gsettings get org.gnome.desktop.screensaver lock-enabled 2>/dev/null)" == "true" ]] && detected+=("lock-screen")
    fi

    # hostname-scrub
    if [[ "$OS" == "macos" ]]; then
        [[ "$(scutil --get ComputerName 2>/dev/null)" == "MacBook" ]] && detected+=("hostname-scrub")
    elif [[ "$(hostname 2>/dev/null)" == "linux" ]]; then
        detected+=("hostname-scrub")
    fi

    # ssh-harden
    if [[ -f "${REAL_HOME}/.ssh/config" ]] && grep -q "IdentitiesOnly yes" "${REAL_HOME}/.ssh/config" 2>/dev/null; then
        detected+=("ssh-harden")
    fi

    # git-harden
    if [[ "$(git config --global --get commit.gpgsign 2>/dev/null)" == "true" ]]; then
        detected+=("git-harden")
    fi

    # telemetry-disable
    if [[ "$OS" == "macos" ]]; then
        [[ "$(defaults read com.apple.CrashReporter DialogType 2>/dev/null)" == "none" ]] && detected+=("telemetry-disable")
    fi

    # monitoring-tools
    if [[ "$OS" == "macos" ]]; then
        cask_installed oversight && cask_installed blockblock && detected+=("monitoring-tools")
    elif command -v auditctl &>/dev/null && command -v aide &>/dev/null; then
        detected+=("monitoring-tools")
    fi

    # browser-basic
    local ff_profile=""
    if [[ "$OS" == "macos" ]]; then
        ff_profile=$(find "${REAL_HOME}/Library/Application Support/Firefox/Profiles" -maxdepth 1 -name "*.default-release" -type d 2>/dev/null | head -1)
    elif [[ "$OS" == "linux" ]]; then
        ff_profile=$(find "${REAL_HOME}/.mozilla/firefox" -maxdepth 1 -name "*.default-release" -type d 2>/dev/null | head -1)
    fi
    if [[ -n "$ff_profile" ]] && [[ -f "${ff_profile}/user.js" ]] && grep -q "toolkit.telemetry.enabled" "${ff_profile}/user.js" 2>/dev/null; then
        detected+=("browser-basic")
    fi

    # browser-fingerprint
    if [[ -n "$ff_profile" ]] && [[ -f "${ff_profile}/user.js" ]] && grep -q "privacy.resistFingerprinting" "${ff_profile}/user.js" 2>/dev/null; then
        detected+=("browser-fingerprint")
    fi

    # mac-rotate (linux only — macos is manual)
    if [[ "$OS" == "linux" ]] && [[ -f /etc/NetworkManager/conf.d/mac-randomize.conf ]]; then
        detected+=("mac-rotate")
    fi

    # vpn-killswitch
    if command -v mullvad &>/dev/null && mullvad always-require-vpn get 2>/dev/null | grep -qi "enabled\|on"; then
        detected+=("vpn-killswitch")
    fi

    # metadata-strip
    command -v exiftool &>/dev/null && detected+=("metadata-strip")

    # dev-isolation
    if [[ "$OS" == "macos" ]] && [[ -d "/Applications/UTM.app" ]]; then
        detected+=("dev-isolation")
    fi

    # audit-script
    if [[ "$OS" == "macos" ]] && [[ -f "${REAL_HOME}/Library/LaunchAgents/com.secure.weekly-audit.plist" ]]; then
        detected+=("audit-script")
    elif [[ "$OS" == "linux" ]] && crontab -u "${REAL_USER}" -l 2>/dev/null | grep -q "weekly-audit"; then
        detected+=("audit-script")
    fi

    # bluetooth-disable (linux only)
    if [[ "$OS" == "linux" ]] && ! systemctl is-active bluetooth &>/dev/null 2>&1; then
        detected+=("bluetooth-disable")
    fi

    # Set state from detected modules
    for mod_id in "${detected[@]}"; do
        STATE_MODULES[$mod_id]="applied"
    done
}

# ═══════════════════════════════════════════════════════════════════
# INTERACTIVE PICKER — ARROW KEYS + SPACEBAR
# ═══════════════════════════════════════════════════════════════════

# All 25 modules grouped by category for the picker
ALL_MODULE_IDS=(
    disk-encrypt
    firewall-inbound firewall-stealth firewall-outbound
    dns-secure vpn-killswitch hostname-scrub
    mac-rotate telemetry-disable traffic-obfuscation metadata-strip
    browser-basic browser-fingerprint
    guest-disable lock-screen bluetooth-disable
    git-harden dev-isolation
    ssh-harden
    monitoring-tools permissions-audit audit-script
    auto-updates backup-guidance border-prep
    kernel-sysctl apparmor-enforce boot-security
)

ALL_MODULE_LABELS=(
    "disk-encrypt        — FileVault / LUKS / BitLocker verification"
    "firewall-inbound    — Block all incoming connections"
    "firewall-stealth    — Stealth mode / drop ICMP"
    "firewall-outbound   — Outbound firewall (LuLu / ufw / WF)"
    "dns-secure          — Encrypted DNS (Quad9)"
    "vpn-killswitch      — VPN always-on, block non-VPN traffic"
    "hostname-scrub      — Generic hostname"
    "mac-rotate          — MAC address rotation"
    "telemetry-disable   — OS and browser telemetry off"
    "traffic-obfuscation — DAITA, Tor guidance"
    "metadata-strip      — exiftool / mat2"
    "browser-basic       — Block trackers, HTTPS-only"
    "browser-fingerprint — Resist fingerprinting, clear-on-quit"
    "guest-disable       — Disable guest account"
    "lock-screen         — Screensaver password, zero delay"
    "bluetooth-disable   — Disable when unused"
    "git-harden          — SSH signing, credential helper"
    "dev-isolation       — Docker hardening, VM guidance"
    "ssh-harden          — Ed25519 keys, strict config"
    "monitoring-tools    — Objective-See / auditd+aide / Sysmon"
    "permissions-audit   — List granted permissions"
    "audit-script        — Weekly automated audit"
    "auto-updates        — Automatic security updates"
    "backup-guidance     — Encrypted backup strategy"
    "border-prep         — Travel protocol, nuke checklist"
    "kernel-sysctl       — ⚠ Kernel parameter hardening (Advanced)"
    "apparmor-enforce    — ⚠ AppArmor / App Sandbox (Advanced)"
    "boot-security       — ⚠ Secure Boot / SIP verification (Advanced)"
)

# Category headers: index in ALL_MODULE_IDS where each group starts
ALL_MODULE_GROUPS=(
    "0:DISK & BOOT"
    "1:FIREWALL"
    "4:NETWORK & DNS"
    "7:PRIVACY & OBFUSCATION"
    "11:BROWSER"
    "13:ACCESS CONTROL"
    "16:DEV TOOLS"
    "18:AUTH & SSH"
    "19:MONITORING"
    "22:MAINTENANCE"
    "25:⚠ ADVANCED"
)

interactive_picker() {
    # Build display list: interleave group headers and module items
    local -a display_lines=()    # what to print
    local -a display_modids=()   # module id or "" for headers
    local -a display_states=()   # "on", "off", or "header"
    local -a group_starts=()

    # Parse group start indices
    local -A group_at=()
    for g in "${ALL_MODULE_GROUPS[@]}"; do
        local idx="${g%%:*}"
        local name="${g#*:}"
        group_at[$idx]="$name"
    done

    for i in "${!ALL_MODULE_IDS[@]}"; do
        # Insert group header if this index starts a group
        if [[ -n "${group_at[$i]:-}" ]]; then
            display_lines+=("${group_at[$i]}")
            display_modids+=("")
            display_states+=("header")
        fi

        local mod_id="${ALL_MODULE_IDS[$i]}"
        local label="${ALL_MODULE_LABELS[$i]}"
        local state="off"
        if [[ "${STATE_MODULES[$mod_id]:-}" == "applied" ]]; then
            state="on"
        fi
        display_lines+=("$label")
        display_modids+=("$mod_id")
        display_states+=("$state")
    done

    local total=${#display_lines[@]}
    local cursor=0

    # Move cursor to first non-header line
    while [[ "${display_states[$cursor]}" == "header" ]] && (( cursor < total - 1 )); do
        ((cursor++))
    done

    # Save original states for change detection
    local -a orig_states=("${display_states[@]}")

    # Hide cursor
    tput civis 2>/dev/null || true

    # Draw function
    _picker_draw() {
        # Move to top of drawn area and clear
        if [[ "${1:-}" == "redraw" ]]; then
            echo -ne "\033[${total}A"
        fi
        for i in "${!display_lines[@]}"; do
            echo -ne "\033[2K"  # clear line
            if [[ "${display_states[$i]}" == "header" ]]; then
                echo -e "  ${BOLD}${GREEN}${display_lines[$i]}${NC}"
            else
                local check=" "
                [[ "${display_states[$i]}" == "on" ]] && check="${GREEN}✓${NC}"
                local prefix="   "
                if [[ $i -eq $cursor ]]; then
                    prefix="${GREEN} ▸ ${NC}"
                fi
                echo -e "${prefix}[${check}] ${display_lines[$i]}"
            fi
        done
    }

    echo ""
    echo -e "  ${BOLD}Use ↑↓ to navigate, SPACE to toggle, ENTER to apply, Q to cancel${NC}"
    echo ""
    _picker_draw "initial"

    while true; do
        IFS= read -rsn1 key
        case "$key" in
            $'\x1b')  # Escape sequence
                read -rsn2 key2
                case "$key2" in
                    '[A')  # Up arrow
                        local prev=$cursor
                        while true; do
                            (( cursor > 0 )) && ((cursor--)) || break
                            [[ "${display_states[$cursor]}" != "header" ]] && break
                        done
                        # If we landed on a header, revert
                        [[ "${display_states[$cursor]}" == "header" ]] && cursor=$prev
                        ;;
                    '[B')  # Down arrow
                        local prev=$cursor
                        while true; do
                            (( cursor < total - 1 )) && ((cursor++)) || break
                            [[ "${display_states[$cursor]}" != "header" ]] && break
                        done
                        [[ "${display_states[$cursor]}" == "header" ]] && cursor=$prev
                        ;;
                esac
                ;;
            ' ')  # Space — toggle
                if [[ "${display_states[$cursor]}" != "header" ]]; then
                    if [[ "${display_states[$cursor]}" == "on" ]]; then
                        display_states[$cursor]="off"
                    else
                        display_states[$cursor]="on"
                    fi
                fi
                ;;
            ''|$'\n')  # Enter — confirm
                break
                ;;
            'q'|'Q')
                tput cnorm 2>/dev/null || true
                echo ""
                echo "  Cancelled."
                return 1
                ;;
        esac
        _picker_draw "redraw"
    done

    tput cnorm 2>/dev/null || true
    echo ""

    # Determine what changed: modules to add and modules to remove
    PICKER_ADD=()
    PICKER_REMOVE=()
    for i in "${!display_modids[@]}"; do
        local mod_id="${display_modids[$i]}"
        [[ -z "$mod_id" ]] && continue
        if [[ "${orig_states[$i]}" == "off" ]] && [[ "${display_states[$i]}" == "on" ]]; then
            PICKER_ADD+=("$mod_id")
        elif [[ "${orig_states[$i]}" == "on" ]] && [[ "${display_states[$i]}" == "off" ]]; then
            PICKER_REMOVE+=("$mod_id")
        fi
    done
    return 0
}

# ═══════════════════════════════════════════════════════════════════
# WIZARD: PROFILE SELECTION
# ═══════════════════════════════════════════════════════════════════
select_profile() {
    print_section "Profile Selection"

    echo -e "${BOLD}Select a hardening profile:${NC}"
    echo ""
    echo -e "  ${GREEN}[1]${NC} Standard  — Encrypted disk, firewall, secure DNS, auto-updates, basic browser hardening"
    echo -e "  ${GREEN}[2]${NC} High      — Standard + outbound firewall, hostname scrubbing, monitoring tools, SSH hardening, telemetry disabled"
    echo -e "  ${GREEN}[3]${NC} Paranoid  — High + MAC rotation, traffic obfuscation, VPN kill switch, full audit system, metadata stripping, border crossing prep"
    echo -e "  ${GREEN}[4]${NC} Advanced  — Custom questionnaire (choose per-category)"
    echo ""
    echo -e "  ${MAGENTA}[M]${NC} Modify    — Add or remove individual modules"
    echo -e "  ${CYAN}[C]${NC} Clean     — System cleaner (caches, logs, privacy traces)"

    # Check if schedule exists and show status
    local schedule_text="Schedule — Set up automated cleaning schedule"
    if [[ -f "$SCHED_CLEAN_CONFIG_USER" ]] || [[ -f "$SCHED_CLEAN_CONFIG_PROJECT" ]]; then
        # Try to read the schedule
        if load_scheduled_config 2>/dev/null; then
            if [[ "$SCHED_ENABLED" == "true" ]]; then
                # Convert schedule to display format
                local sched_display=""
                case "$SCHED_SCHEDULE" in
                    daily) sched_display="Daily" ;;
                    weekly) sched_display="Weekly" ;;
                    custom) sched_display="Custom" ;;
                    *) sched_display="$SCHED_SCHEDULE" ;;
                esac
                schedule_text="Schedule — Manage automated cleaning (currently: ${sched_display})"
            fi
        fi
    fi
    echo -e "  ${CYAN}[S]${NC} ${schedule_text}"
    echo -e "  ${YELLOW}[O]${NC} Monitor   — Continuous security monitoring (VPN, supply chain, network)"

    echo -e "  ${RED}[U]${NC} Uninstall — Remove all hardening changes"
    echo -e "  ${BROWN}[Q] Quit${NC}"
    echo ""

    while true; do
        echo -ne "  ${BOLD}Choice:${NC} "
        read -r choice
        case "${choice,,}" in
            1) PROFILE="standard"; break ;;
            2) PROFILE="high"; break ;;
            3) PROFILE="paranoid"; break ;;
            4) PROFILE="advanced"; run_questionnaire; break ;;
            m) RUN_MODE="modify"; break ;;
            c) CLEAN_MODE=true; break ;;
            s) setup_scheduled_clean; select_profile; return ;;
            o) monitor_menu; select_profile; return ;;
            u) RUN_MODE="uninstall"; break ;;
            q) echo "Exiting."; exit 0 ;;
            *) echo -e "  ${RED}Invalid choice.${NC}" ;;
        esac
    done

    if [[ "$RUN_MODE" == "harden" ]]; then
        echo ""
        echo -e "  Profile: ${BOLD}${PROFILE}${NC}"
    fi
}

# ═══════════════════════════════════════════════════════════════════
# WIZARD: ADVANCED QUESTIONNAIRE
# ═══════════════════════════════════════════════════════════════════
run_questionnaire() {
    print_section "Advanced Questionnaire"
    echo -e "  ${BROWN}Answer 8 questions to build a custom hardening profile.${NC}"
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
            "kernel-sysctl"
            "apparmor-enforce"
            "boot-security"
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
    local mode="${2:-apply}"
    local mod_func="mod_${mod_id//-/_}"
    CURRENT_MODULE=$((CURRENT_MODULE + 1))

    # Dry-run guard: show preview instead of applying
    if [[ "$DRY_RUN" == true && "$mode" == "apply" ]]; then
        check_module "$mod_id"
        local sev="${MODULE_SEVERITY[$mod_id]:-LOW}"
        if [[ "$QUIET_MODE" != true ]]; then
            echo ""
            echo -e "  ${GREEN}[DRY RUN]${NC} ${BOLD}${mod_id}${NC}"
            echo -e "    Current:  ${CHECK_FINDING}"
            if [[ "$CHECK_STATUS" == "PASS" ]]; then
                echo -e "    Planned:  ${BROWN}No change needed${NC}"
            else
                echo -e "    Planned:  $(dry_run_description "$mod_id")"
            fi
            echo -e "    Severity: ${sev}"
            if [[ -n "${ADVANCED_MODULES[$mod_id]:-}" ]]; then
                echo -e "    ${RED}Advanced — requires confirmation in live run${NC}"
            fi
        fi
        log_entry "$mod_id" "dry-run" "$CHECK_STATUS" "$CHECK_FINDING"
        if [[ "$CHECK_STATUS" == "PASS" ]]; then
            MODULE_RESULT="skipped"
        else
            MODULE_RESULT="applied"  # would be applied
        fi
        case "$MODULE_RESULT" in
            applied)  ((COUNT_APPLIED++)) ;;
            skipped)  ((COUNT_SKIPPED++)) ;;
        esac
        return
    fi

    if [[ "$mode" == "revert" ]]; then
        local rev_func="revert_${mod_id//-/_}"
        if declare -f "$rev_func" &>/dev/null; then
            "$rev_func"
        else
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "Revert ${mod_id}" "skipped"
            log_entry "$mod_id" "revert" "skip" "No revert function"
            MODULE_RESULT="skipped"
        fi
    else
        if declare -f "$mod_func" &>/dev/null; then
            "$mod_func"
        else
            MODULE_RESULT="skipped_unsupported"
        fi
    fi

    case "$MODULE_RESULT" in
        applied)  ((COUNT_APPLIED++)) ;;
        reverted) ((COUNT_REVERTED++)) ;;
        skipped)  ((COUNT_SKIPPED++)) ;;
        failed)   ((COUNT_FAILED++)) ;;
        manual)   ((COUNT_MANUAL++)) ;;
        skipped_unsupported) ((COUNT_SKIPPED++)) ;;
    esac

    # Update state tracking
    if [[ "$mode" == "apply" && "$MODULE_RESULT" == "applied" ]]; then
        state_set_module "$mod_id" "applied"
    elif [[ "$mode" == "revert" && "$MODULE_RESULT" == "reverted" ]]; then
        state_set_module "$mod_id" "reverted"
    fi
}

run_all_modules() {
    if [[ "$DRY_RUN" == true ]]; then
        print_section "Dry Run Preview (${TOTAL_MODULES} modules)"
    else
        print_section "Applying Hardening (${TOTAL_MODULES} modules)"
    fi

    for mod_id in "${ENABLED_MODULES[@]}"; do
        run_module "$mod_id" "apply"
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
        run_as_root /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on &>/dev/null
        run_as_root /usr/libexec/ApplicationFirewall/socketfilterfw --setblockall on &>/dev/null
        run_as_root /usr/libexec/ApplicationFirewall/socketfilterfw --setallowsigned off &>/dev/null
        run_as_root /usr/libexec/ApplicationFirewall/socketfilterfw --setallowsignedapp off &>/dev/null
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
            run_as_root ufw --force enable &>/dev/null
            run_as_root ufw default deny incoming &>/dev/null
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
                run_as_root ufw --force enable &>/dev/null
                run_as_root ufw default deny incoming &>/dev/null
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
        # Save previous DNS for revert
        STATE_PREVIOUS[dns-secure]="$current_dns"
        run_as_root networksetup -setdnsservers Wi-Fi 9.9.9.9 149.112.112.112 &>/dev/null
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
            run_as_root mkdir -p /etc/systemd/resolved.conf.d
            run_as_root tee /etc/systemd/resolved.conf.d/quad9.conf >/dev/null << 'DNSEOF'
[Resolve]
DNS=9.9.9.9#dns.quad9.net 149.112.112.112#dns.quad9.net
DNSOverTLS=yes
DNSSEC=yes
DNSEOF
            run_as_root systemctl restart systemd-resolved &>/dev/null
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
            run_as_root cp /etc/resolv.conf /etc/resolv.conf.bak
            echo -e "nameserver 9.9.9.9\nnameserver 149.112.112.112" | run_as_root tee /etc/resolv.conf >/dev/null
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
        run_as_root defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -bool true
        run_as_root defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload -bool true
        run_as_root defaults write /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall -bool true
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
            run_as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y unattended-upgrades &>/dev/null
            run_as_root dpkg-reconfigure -plow unattended-upgrades &>/dev/null
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
            run_as_root dnf install -y dnf-automatic &>/dev/null
            run_as_root systemctl enable --now dnf-automatic-install.timer &>/dev/null
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
        run_as_root defaults write /Library/Preferences/com.apple.loginwindow GuestEnabled -bool false
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "applied"
        log_entry "guest-disable" "apply" "ok" "Disabled guest account"
        MODULE_RESULT="applied"
    elif [[ "$OS" == "linux" ]]; then
        if id guest &>/dev/null; then
            run_as_root usermod -L guest &>/dev/null 2>&1 || true
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
        delay=$(defaults read com.apple.screensaver askForPasswordDelay 2>/dev/null || echo "999")
        if [[ "$delay" == "0" ]]; then
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "skipped"
            log_entry "lock-screen" "check" "skip" "Lock screen already configured"
            MODULE_RESULT="skipped"
            return
        fi
        STATE_PREVIOUS[lock-screen]="$delay"
        defaults write com.apple.screensaver askForPassword -int 1
        defaults write com.apple.screensaver askForPasswordDelay -int 0
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "applied"
        log_entry "lock-screen" "apply" "ok" "Set password required immediately"
        MODULE_RESULT="applied"
    elif [[ "$OS" == "linux" ]]; then
        # Try GNOME settings
        if command -v gsettings &>/dev/null; then
            local lock_enabled
            lock_enabled=$(gsettings get org.gnome.desktop.screensaver lock-enabled 2>/dev/null || echo "")
            if [[ "$lock_enabled" == "true" ]]; then
                print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "skipped"
                log_entry "lock-screen" "check" "skip" "GNOME lock screen already enabled"
                MODULE_RESULT="skipped"
                return
            fi
            gsettings set org.gnome.desktop.screensaver lock-enabled true 2>/dev/null
            gsettings set org.gnome.desktop.screensaver lock-delay 0 2>/dev/null
            gsettings set org.gnome.desktop.session idle-delay 300 2>/dev/null
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
        run_as_root /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on &>/dev/null
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "applied"
        log_entry "firewall-stealth" "apply" "ok" "Stealth mode enabled"
        MODULE_RESULT="applied"
    elif [[ "$OS" == "linux" ]]; then
        # Drop ICMP echo requests
        if run_as_root iptables -C INPUT -p icmp --icmp-type echo-request -j DROP &>/dev/null 2>&1; then
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc (drop ICMP)" "skipped"
            log_entry "firewall-stealth" "check" "skip" "ICMP drop rule already exists"
            MODULE_RESULT="skipped"
            return
        fi
        run_as_root iptables -A INPUT -p icmp --icmp-type echo-request -j DROP &>/dev/null
        # Persist if possible
        if command -v iptables-save &>/dev/null; then
            run_as_root bash -c 'iptables-save > /etc/iptables/rules.v4' 2>/dev/null || true
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
            state_add_package "lulu"
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
            run_as_root ufw default deny outgoing &>/dev/null
            # Allow essential outbound
            run_as_root ufw allow out 53 &>/dev/null   # DNS
            run_as_root ufw allow out 80 &>/dev/null   # HTTP
            run_as_root ufw allow out 443 &>/dev/null  # HTTPS
            run_as_root ufw allow out 853 &>/dev/null  # DNS-over-TLS
            run_as_root ufw allow out 22 &>/dev/null   # SSH
            run_as_root ufw reload &>/dev/null
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
        # Save previous hostname for revert
        STATE_PREVIOUS[hostname-scrub]="$current"
        run_as_root scutil --set ComputerName "$generic"
        run_as_root scutil --set LocalHostName "$generic"
        run_as_root scutil --set HostName "$generic"
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
        STATE_PREVIOUS[hostname-scrub]="$current"
        run_as_root hostnamectl set-hostname "$generic" &>/dev/null 2>&1 || run_as_root hostname "$generic" 2>/dev/null
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
        ssh-keygen -t ed25519 -f "${ssh_dir}/id_ed25519" -N "" -q
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
    signing=$(git config --global --get commit.gpgsign 2>/dev/null || echo "")
    if [[ "$signing" == "true" ]]; then
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "skipped"
        log_entry "git-harden" "check" "skip" "Git signing already configured"
        MODULE_RESULT="skipped"
        return
    fi

    git config --global gpg.format ssh
    if [[ -f "${REAL_HOME}/.ssh/id_ed25519.pub" ]]; then
        git config --global user.signingkey "${REAL_HOME}/.ssh/id_ed25519.pub"
    fi
    git config --global commit.gpgsign true
    git config --global tag.gpgsign true

    if [[ "$OS" == "macos" ]]; then
        git config --global credential.helper osxkeychain
    elif [[ "$OS" == "linux" ]]; then
        git config --global credential.helper store
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
            gsettings set org.gnome.desktop.privacy report-technical-problems false 2>/dev/null && changed=true
            gsettings set org.gnome.desktop.privacy send-software-usage-stats false 2>/dev/null && changed=true
        fi
        # Disable apport (Ubuntu crash reporter)
        if [[ -f /etc/default/apport ]]; then
            run_as_root sed -i 's/enabled=1/enabled=0/' /etc/default/apport 2>/dev/null && changed=true
            run_as_root systemctl stop apport.service &>/dev/null 2>&1 || true
            run_as_root systemctl disable apport.service &>/dev/null 2>&1 || true
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
                state_add_package "$tool"
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
            run_as_root systemctl enable --now auditd &>/dev/null 2>&1 || true
        fi
        # aide (file integrity)
        if ! command -v aide &>/dev/null; then
            pkg_install aide && installed_any=true
            run_as_root aide --init &>/dev/null 2>&1 || true
            run_as_root cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db &>/dev/null 2>&1 || true
        fi
        # rkhunter
        if ! command -v rkhunter &>/dev/null; then
            pkg_install rkhunter && installed_any=true
            run_as_root rkhunter --update &>/dev/null 2>&1 || true
            run_as_root rkhunter --propupd &>/dev/null 2>&1 || true
        fi
        # fail2ban
        if ! command -v fail2ban-client &>/dev/null; then
            pkg_install fail2ban && installed_any=true
            run_as_root systemctl enable --now fail2ban &>/dev/null 2>&1 || true
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
            run_as_root mkdir -p /etc/NetworkManager/conf.d
            run_as_root tee "$nm_conf" >/dev/null << 'MACEOF'
[device]
wifi.scan-rand-mac-address=yes

[connection]
wifi.cloned-mac-address=random
ethernet.cloned-mac-address=random
MACEOF
            run_as_root systemctl restart NetworkManager &>/dev/null 2>&1 || true
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
        state_add_package "exiftool"
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
echo "Firewall: $(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null)"
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
        launchctl load "$plist" &>/dev/null 2>&1 || true
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
                run_as_root systemctl disable --now bluetooth &>/dev/null 2>&1
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
# ADVANCED MODULE VETTING
# ═══════════════════════════════════════════════════════════════════
vet_advanced_module() {
    local title="$1" risk_desc="$2" preview_func="$3"

    if [[ "$DRY_RUN" == true ]]; then return 0; fi
    if [[ "$AUTO_MODE" == true && "$ACCEPT_ADVANCED" != true ]]; then return 1; fi

    # Box width = 64 chars total, 60 chars usable between borders
    local title_text="⚠  ADVANCED MODULE: ${title}"
    local title_len=${#title_text}
    local desc_len=${#risk_desc}

    echo ""
    echo -e "${RED}╔══════════════════════════════════════════════════════════════╗${NC}"
    printf "${RED}║${NC}  ${BOLD}%-58s${NC}${RED}║${NC}\n" "$title_text"
    echo -e "${RED}║${NC}                                                              ${RED}║${NC}"
    printf "${RED}║${NC}  %-58s${RED}║${NC}\n" "$risk_desc"
    echo -e "${RED}║${NC}                                                              ${RED}║${NC}"
    printf "${RED}║${NC}  ${BROWN}%-58s${NC}${RED}║${NC}\n" "This module requires explicit confirmation to apply."
    echo -e "${RED}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${GREEN}Running mandatory dry-run preview...${NC}"
    echo ""
    if declare -f "$preview_func" &>/dev/null; then "$preview_func"; fi
    echo ""
    echo -ne "  ${BOLD}Type YES to apply these changes:${NC} "
    read -r confirm
    [[ "$confirm" == "YES" ]]
}

# ═══════════════════════════════════════════════════════════════════
# MODULE: kernel-sysctl (ADVANCED — Linux only)
# ═══════════════════════════════════════════════════════════════════
SYSCTL_PARAMS=(
    "kernel.randomize_va_space=2"
    "fs.suid_dumpable=0"
    "net.ipv4.conf.all.rp_filter=1"
    "net.ipv4.tcp_syncookies=1"
    "net.ipv4.conf.all.accept_redirects=0"
    "net.ipv4.conf.all.accept_source_route=0"
)

preview_kernel_sysctl() {
    local changes=0 correct=0
    printf "  %-44s %-10s %s\n" "Parameter" "Current" "Proposed"
    printf "  %-44s %-10s %s\n" "---------" "-------" "--------"
    for param in "${SYSCTL_PARAMS[@]}"; do
        local key="${param%%=*}" expected="${param#*=}"
        local current; current="$(sysctl -n "$key" 2>/dev/null || echo "?")"
        if [[ "$current" == "$expected" ]]; then
            printf "  %-44s %-10s %s\n" "$key" "$current" "${expected} (no change)"
            ((correct++))
        else
            printf "  ${RED}%-44s %-10s %s${NC}\n" "$key" "$current" "$expected"
            ((changes++))
        fi
    done
    echo ""
    echo -e "  ${changes} parameters will change. ${correct} already correct."
}

mod_kernel_sysctl() {
    local desc="Kernel sysctl hardening"
    if [[ "$OS" != "linux" ]]; then
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "skipped_unsupported"
        log_entry "kernel-sysctl" "check" "skip" "Linux only"
        MODULE_RESULT="skipped_unsupported"
        return
    fi
    check_kernel_sysctl
    if [[ "$CHECK_STATUS" == "PASS" ]]; then
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "skipped"
        log_entry "kernel-sysctl" "check" "skip" "Already hardened"
        MODULE_RESULT="skipped"
        return
    fi
    if ! vet_advanced_module "Kernel Sysctl Hardening" \
        "Modifies kernel parameters. Risk: network failures, broken containers." \
        "preview_kernel_sysctl"; then
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "skipped"
        log_entry "kernel-sysctl" "apply" "skip" "User declined"
        MODULE_RESULT="skipped"
        return
    fi
    local prev_values="" conf_file="/etc/sysctl.d/99-hardening.conf"
    for param in "${SYSCTL_PARAMS[@]}"; do
        local key="${param%%=*}"
        local current; current="$(sysctl -n "$key" 2>/dev/null || echo "")"
        prev_values+="${key}=${current};"
    done
    {
        echo "# Security hardening — applied by barked.sh v${VERSION}"
        for param in "${SYSCTL_PARAMS[@]}"; do
            echo "${param%%=*} = ${param#*=}"
        done
    } | run_as_root tee "$conf_file" >/dev/null
    run_as_root sysctl --system &>/dev/null
    state_set_module "kernel-sysctl" "applied" "$prev_values"
    print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "applied"
    log_entry "kernel-sysctl" "apply" "applied" "Sysctl parameters hardened"
    MODULE_RESULT="applied"
}

# ═══════════════════════════════════════════════════════════════════
# MODULE: apparmor-enforce (ADVANCED — Linux enforce, macOS audit)
# ═══════════════════════════════════════════════════════════════════
preview_apparmor_enforce() {
    if [[ "$OS" == "linux" ]] && command -v aa-status &>/dev/null; then
        local enforce_count; enforce_count=$(aa-status 2>/dev/null | grep -c "enforce" || echo "0")
        local complain_count; complain_count=$(aa-status 2>/dev/null | grep -c "complain" || echo "0")
        echo -e "  Enforce mode:  ${enforce_count} profiles"
        echo -e "  Complain mode: ${RED}${complain_count}${NC} profiles"
        echo -e "  Planned: Set all complain → enforce"
    elif [[ "$OS" == "macos" ]]; then
        echo -e "  macOS: Will audit apps for Sandbox entitlements"
        echo -e "  ${BROWN}Informational only — no system changes${NC}"
    fi
}

mod_apparmor_enforce() {
    local desc="AppArmor / App Sandbox enforcement"
    if [[ "$OS" == "macos" ]]; then
        if ! vet_advanced_module "App Sandbox Audit" \
            "Audits apps for Sandbox entitlements. Informational only." \
            "preview_apparmor_enforce"; then
            MODULE_RESULT="skipped"; return
        fi
        local non_hardened=0
        while IFS= read -r app; do
            if ! codesign -d --entitlements - "$app" 2>/dev/null | grep -q "com.apple.security.app-sandbox"; then
                ((non_hardened++))
            fi
        done < <(find /Applications -maxdepth 2 -name "*.app" -type d 2>/dev/null)
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc (${non_hardened} non-sandboxed)" "applied"
        log_entry "apparmor-enforce" "audit" "applied" "${non_hardened} non-sandboxed apps"
        MODULE_RESULT="applied"
        return
    fi
    if [[ "$OS" != "linux" ]]; then
        MODULE_RESULT="skipped_unsupported"; return
    fi
    if ! command -v aa-status &>/dev/null; then
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc (not installed)" "failed"
        log_entry "apparmor-enforce" "check" "failed" "AppArmor not installed"
        MODULE_RESULT="failed"; return
    fi
    check_apparmor_enforce
    if [[ "$CHECK_STATUS" == "PASS" ]]; then
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "skipped"
        MODULE_RESULT="skipped"; return
    fi
    if ! vet_advanced_module "AppArmor Enforce Mode" \
        "Sets all profiles to enforce. Risk: may block legitimate apps." \
        "preview_apparmor_enforce"; then
        MODULE_RESULT="skipped"; return
    fi
    local complain_profiles; complain_profiles=$(aa-status 2>/dev/null | awk '/complain/{ print $1 }')
    state_set_module "apparmor-enforce" "applied" "$complain_profiles"
    run_as_root aa-enforce /etc/apparmor.d/* &>/dev/null
    print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "applied"
    log_entry "apparmor-enforce" "apply" "applied" "All profiles set to enforce"
    MODULE_RESULT="applied"
}

# ═══════════════════════════════════════════════════════════════════
# MODULE: boot-security (ADVANCED — Linux + macOS)
# ═══════════════════════════════════════════════════════════════════
preview_boot_security() {
    if [[ "$OS" == "macos" ]]; then
        echo -e "  SIP Status: $(csrutil status 2>/dev/null || echo 'Unknown')"
        echo -e "  ${BROWN}macOS: Verification only — no changes${NC}"
    elif [[ "$OS" == "linux" ]]; then
        echo -e "  Secure Boot: $(mokutil --sb-state 2>/dev/null || echo 'Cannot determine')"
        if grep -q "set superusers" /etc/grub.d/40_custom 2>/dev/null; then
            echo -e "  GRUB password: ${GREEN}Configured${NC}"
        else
            echo -e "  GRUB password: ${RED}Not set${NC} — will configure"
        fi
    fi
}

mod_boot_security() {
    local desc="Boot security verification"
    if [[ "$OS" == "macos" ]]; then
        if ! vet_advanced_module "Boot Security Verification" \
            "Verifies SIP and authenticated root. Informational only on macOS." \
            "preview_boot_security"; then
            MODULE_RESULT="skipped"; return
        fi
        if csrutil status 2>/dev/null | grep -q "enabled"; then
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc (SIP enabled)" "applied"
            log_entry "boot-security" "check" "applied" "SIP verified"
            MODULE_RESULT="applied"
        else
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc (SIP disabled)" "manual"
            log_entry "boot-security" "check" "manual" "SIP disabled"
            pause_guide "Enable SIP: Restart in Recovery Mode > Terminal > csrutil enable"
            MODULE_RESULT="manual"
        fi
        return
    fi
    if [[ "$OS" != "linux" ]]; then
        MODULE_RESULT="skipped_unsupported"; return
    fi
    if grep -q "set superusers" /etc/grub.d/40_custom 2>/dev/null; then
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc (GRUB password set)" "skipped"
        MODULE_RESULT="skipped"; return
    fi
    if ! vet_advanced_module "Boot Security Hardening" \
        "Sets GRUB password. Risk: required at boot menu." \
        "preview_boot_security"; then
        MODULE_RESULT="skipped"; return
    fi
    echo -ne "  ${BOLD}Enter GRUB boot password:${NC} "
    read -rs grub_pass; echo ""
    local grub_hash; grub_hash=$(echo -e "${grub_pass}\n${grub_pass}" | grub-mkpasswd-pbkdf2 2>/dev/null | grep "grub.pbkdf2" | awk '{print $NF}')
    if [[ -n "$grub_hash" ]]; then
        [[ -f /etc/grub.d/40_custom ]] && run_as_root cp /etc/grub.d/40_custom /etc/grub.d/40_custom.bak.hardening
        run_as_root tee -a /etc/grub.d/40_custom >/dev/null << GRUBEOF
# Added by barked.sh v${VERSION}
set superusers="admin"
password_pbkdf2 admin ${grub_hash}
GRUBEOF
        run_as_root update-grub &>/dev/null || run_as_root grub-mkconfig -o /boot/grub/grub.cfg &>/dev/null
        state_set_module "boot-security" "applied" "grub-password-set"
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc (GRUB password set)" "applied"
        log_entry "boot-security" "apply" "applied" "GRUB password configured"
        MODULE_RESULT="applied"
    else
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "failed"
        log_entry "boot-security" "apply" "failed" "Could not generate GRUB hash"
        MODULE_RESULT="failed"
    fi
}

# ═══════════════════════════════════════════════════════════════════
# REVERT FUNCTIONS
# ═══════════════════════════════════════════════════════════════════
# Each revert_<module> function undoes the corresponding mod_<module>.
# Sets MODULE_RESULT to "reverted", "skipped", "failed", or "manual".

revert_disk_encrypt() {
    local desc="Revert disk encryption"
    print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "manual"
    log_entry "disk-encrypt" "revert" "manual" "Decrypting disk requires manual action"
    pause_guide "Disk decryption is a major decision. If needed: System Settings > Privacy & Security > FileVault > Turn Off (macOS) or cryptsetup luksClose (Linux)."
    MODULE_RESULT="manual"
}

revert_firewall_inbound() {
    local desc="Disable inbound firewall"
    if [[ "$OS" == "macos" ]]; then
        run_as_root /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate off &>/dev/null
        run_as_root /usr/libexec/ApplicationFirewall/socketfilterfw --setblockall off &>/dev/null
        run_as_root /usr/libexec/ApplicationFirewall/socketfilterfw --setallowsigned on &>/dev/null
        run_as_root /usr/libexec/ApplicationFirewall/socketfilterfw --setallowsignedapp on &>/dev/null
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "reverted"
        log_entry "firewall-inbound" "revert" "ok" "Firewall disabled"
        MODULE_RESULT="reverted"
    elif [[ "$OS" == "linux" ]]; then
        if command -v ufw &>/dev/null; then
            run_as_root ufw --force disable &>/dev/null
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc (ufw)" "reverted"
            log_entry "firewall-inbound" "revert" "ok" "ufw disabled"
            MODULE_RESULT="reverted"
        else
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "skipped"
            MODULE_RESULT="skipped"
        fi
    fi
}

revert_dns_secure() {
    local desc="Revert DNS to default"
    local prev="${STATE_PREVIOUS[dns-secure]:-}"
    if [[ "$OS" == "macos" ]]; then
        if [[ -n "$prev" && "$prev" != "null" ]]; then
            run_as_root networksetup -setdnsservers Wi-Fi $prev &>/dev/null
        else
            run_as_root networksetup -setdnsservers Wi-Fi Empty &>/dev/null
        fi
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "reverted"
        log_entry "dns-secure" "revert" "ok" "DNS reset${prev:+ to $prev}"
        MODULE_RESULT="reverted"
    elif [[ "$OS" == "linux" ]]; then
        if [[ -f /etc/systemd/resolved.conf.d/quad9.conf ]]; then
            run_as_root rm -f /etc/systemd/resolved.conf.d/quad9.conf
            run_as_root systemctl restart systemd-resolved &>/dev/null 2>&1 || true
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc (systemd-resolved)" "reverted"
            log_entry "dns-secure" "revert" "ok" "Removed Quad9 config"
            MODULE_RESULT="reverted"
        elif [[ -f /etc/resolv.conf.bak ]]; then
            run_as_root cp /etc/resolv.conf.bak /etc/resolv.conf
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc (resolv.conf)" "reverted"
            log_entry "dns-secure" "revert" "ok" "Restored resolv.conf backup"
            MODULE_RESULT="reverted"
        else
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "skipped"
            MODULE_RESULT="skipped"
        fi
    fi
}

revert_auto_updates() {
    local desc="Revert auto-updates to default"
    if [[ "$OS" == "macos" ]]; then
        # macOS default is auto-updates enabled, so this is typically a no-op
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "reverted"
        log_entry "auto-updates" "revert" "ok" "Auto-updates left at OS default (enabled)"
        MODULE_RESULT="reverted"
    elif [[ "$OS" == "linux" ]]; then
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "reverted"
        log_entry "auto-updates" "revert" "ok" "Auto-updates packages left installed"
        MODULE_RESULT="reverted"
    fi
}

revert_guest_disable() {
    local desc="Re-enable guest account"
    if [[ "$OS" == "macos" ]]; then
        run_as_root defaults write /Library/Preferences/com.apple.loginwindow GuestEnabled -bool true
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "reverted"
        log_entry "guest-disable" "revert" "ok" "Guest account re-enabled"
        MODULE_RESULT="reverted"
    elif [[ "$OS" == "linux" ]]; then
        if id guest &>/dev/null; then
            run_as_root usermod -U guest &>/dev/null 2>&1 || true
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "reverted"
            log_entry "guest-disable" "revert" "ok" "Guest account unlocked"
            MODULE_RESULT="reverted"
        else
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "skipped"
            MODULE_RESULT="skipped"
        fi
    fi
}

revert_lock_screen() {
    local desc="Revert lock screen settings"
    if [[ "$OS" == "macos" ]]; then
        local prev="${STATE_PREVIOUS[lock-screen]:-}"
        local delay="${prev:-5}"
        defaults write com.apple.screensaver askForPasswordDelay -int "$delay"
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "reverted"
        log_entry "lock-screen" "revert" "ok" "Screensaver delay reset to ${delay}s"
        MODULE_RESULT="reverted"
    elif [[ "$OS" == "linux" ]]; then
        if command -v gsettings &>/dev/null; then
            gsettings reset org.gnome.desktop.screensaver lock-enabled 2>/dev/null
            gsettings reset org.gnome.desktop.screensaver lock-delay 2>/dev/null
            gsettings reset org.gnome.desktop.session idle-delay 2>/dev/null
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc (GNOME)" "reverted"
            log_entry "lock-screen" "revert" "ok" "GNOME lock screen reset to defaults"
            MODULE_RESULT="reverted"
        else
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "skipped"
            MODULE_RESULT="skipped"
        fi
    fi
}

revert_browser_basic() {
    local desc="Remove Firefox basic hardening"
    local ff_profile=""
    if [[ "$OS" == "macos" ]]; then
        ff_profile=$(find "${REAL_HOME}/Library/Application Support/Firefox/Profiles" -maxdepth 1 -name "*.default-release" -type d 2>/dev/null | head -1)
    elif [[ "$OS" == "linux" ]]; then
        ff_profile=$(find "${REAL_HOME}/.mozilla/firefox" -maxdepth 1 -name "*.default-release" -type d 2>/dev/null | head -1)
    fi

    if [[ -n "$ff_profile" ]] && [[ -f "${ff_profile}/user.js" ]]; then
        rm -f "${ff_profile}/user.js"
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "reverted"
        log_entry "browser-basic" "revert" "ok" "Removed user.js"
        MODULE_RESULT="reverted"
    else
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "skipped"
        log_entry "browser-basic" "revert" "skip" "No user.js found"
        MODULE_RESULT="skipped"
    fi
}

revert_firewall_stealth() {
    local desc="Disable firewall stealth mode"
    if [[ "$OS" == "macos" ]]; then
        run_as_root /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode off &>/dev/null
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "reverted"
        log_entry "firewall-stealth" "revert" "ok" "Stealth mode disabled"
        MODULE_RESULT="reverted"
    elif [[ "$OS" == "linux" ]]; then
        if run_as_root iptables -C INPUT -p icmp --icmp-type echo-request -j DROP &>/dev/null 2>&1; then
            run_as_root iptables -D INPUT -p icmp --icmp-type echo-request -j DROP &>/dev/null
            if command -v iptables-save &>/dev/null; then
                run_as_root bash -c 'iptables-save > /etc/iptables/rules.v4' 2>/dev/null || true
            fi
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc (ICMP)" "reverted"
            log_entry "firewall-stealth" "revert" "ok" "Removed ICMP drop rule"
            MODULE_RESULT="reverted"
        else
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "skipped"
            MODULE_RESULT="skipped"
        fi
    fi
}

revert_firewall_outbound() {
    local desc="Remove outbound firewall"
    if [[ "$OS" == "macos" ]]; then
        if $REMOVE_PACKAGES && cask_installed lulu; then
            cask_uninstall lulu
            state_remove_package "lulu"
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc (LuLu removed)" "reverted"
            log_entry "firewall-outbound" "revert" "ok" "Uninstalled LuLu"
        else
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "manual"
            pause_guide "LuLu was kept installed. Uninstall manually from /Applications if desired."
            log_entry "firewall-outbound" "revert" "manual" "LuLu kept, manual removal if needed"
            MODULE_RESULT="manual"
            return
        fi
        MODULE_RESULT="reverted"
    elif [[ "$OS" == "linux" ]]; then
        if command -v ufw &>/dev/null; then
            run_as_root ufw default allow outgoing &>/dev/null
            run_as_root ufw delete allow out 53 &>/dev/null 2>&1 || true
            run_as_root ufw delete allow out 80 &>/dev/null 2>&1 || true
            run_as_root ufw delete allow out 443 &>/dev/null 2>&1 || true
            run_as_root ufw delete allow out 853 &>/dev/null 2>&1 || true
            run_as_root ufw delete allow out 22 &>/dev/null 2>&1 || true
            run_as_root ufw reload &>/dev/null
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc (ufw)" "reverted"
            log_entry "firewall-outbound" "revert" "ok" "ufw default allow outgoing restored"
            MODULE_RESULT="reverted"
        else
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "skipped"
            MODULE_RESULT="skipped"
        fi
    fi
}

revert_hostname_scrub() {
    local desc="Restore original hostname"
    local prev="${STATE_PREVIOUS[hostname-scrub]:-}"
    if [[ -z "$prev" || "$prev" == "null" ]]; then
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "manual"
        log_entry "hostname-scrub" "revert" "manual" "No previous hostname stored"
        pause_guide "Set your hostname manually: scutil --set ComputerName 'YourName' (macOS) or hostnamectl set-hostname 'YourName' (Linux)."
        MODULE_RESULT="manual"
        return
    fi
    if [[ "$OS" == "macos" ]]; then
        run_as_root scutil --set ComputerName "$prev"
        run_as_root scutil --set LocalHostName "$prev"
        run_as_root scutil --set HostName "$prev"
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc ($prev)" "reverted"
        log_entry "hostname-scrub" "revert" "ok" "Hostname restored to $prev"
        MODULE_RESULT="reverted"
    elif [[ "$OS" == "linux" ]]; then
        run_as_root hostnamectl set-hostname "$prev" &>/dev/null 2>&1 || run_as_root hostname "$prev" 2>/dev/null
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc ($prev)" "reverted"
        log_entry "hostname-scrub" "revert" "ok" "Hostname restored to $prev"
        MODULE_RESULT="reverted"
    fi
}

revert_ssh_harden() {
    local desc="Revert SSH configuration"
    local ssh_config="${REAL_HOME}/.ssh/config"
    if [[ -f "$ssh_config" ]] && grep -q "IdentitiesOnly yes" "$ssh_config" 2>/dev/null; then
        # Remove the hardened config entries added by this script
        # Keep any user-added Host blocks that don't match our Host * block
        local tmp
        tmp=$(mktemp)
        python3 -c "
import sys
lines = open(sys.argv[1]).readlines()
# Remove the Host * block added by the script
in_block = False
for line in lines:
    if line.strip() == 'Host *':
        in_block = True
        continue
    if in_block:
        if line.startswith('    ') or line.strip() == '':
            continue
        else:
            in_block = False
    if not in_block:
        sys.stdout.write(line)
" "$ssh_config" > "$tmp" 2>/dev/null
        if [[ -s "$tmp" ]]; then
            mv "$tmp" "$ssh_config"
        else
            rm -f "$ssh_config" "$tmp"
        fi
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "reverted"
        log_entry "ssh-harden" "revert" "ok" "Removed hardened SSH config entries"
        MODULE_RESULT="reverted"
    else
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "skipped"
        MODULE_RESULT="skipped"
    fi
}

revert_git_harden() {
    local desc="Revert Git hardening"
    if ! command -v git &>/dev/null; then
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "skipped"
        MODULE_RESULT="skipped"
        return
    fi
    git config --global --unset gpg.format 2>/dev/null || true
    git config --global --unset user.signingkey 2>/dev/null || true
    git config --global --unset commit.gpgsign 2>/dev/null || true
    git config --global --unset tag.gpgsign 2>/dev/null || true
    print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "reverted"
    log_entry "git-harden" "revert" "ok" "Git signing config removed"
    MODULE_RESULT="reverted"
}

revert_telemetry_disable() {
    local desc="Re-enable OS telemetry"
    if [[ "$OS" == "macos" ]]; then
        defaults delete com.apple.assistant.support "Assistant Enabled" 2>/dev/null || true
        defaults delete com.apple.Siri StatusMenuVisible 2>/dev/null || true
        defaults delete com.apple.CrashReporter DialogType 2>/dev/null || true
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "reverted"
        log_entry "telemetry-disable" "revert" "ok" "Reset telemetry settings to defaults"
        MODULE_RESULT="reverted"
    elif [[ "$OS" == "linux" ]]; then
        if command -v gsettings &>/dev/null; then
            gsettings reset org.gnome.desktop.privacy report-technical-problems 2>/dev/null
            gsettings reset org.gnome.desktop.privacy send-software-usage-stats 2>/dev/null
        fi
        if [[ -f /etc/default/apport ]]; then
            run_as_root sed -i 's/enabled=0/enabled=1/' /etc/default/apport 2>/dev/null || true
            run_as_root systemctl enable apport.service &>/dev/null 2>&1 || true
            run_as_root systemctl start apport.service &>/dev/null 2>&1 || true
        fi
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "reverted"
        log_entry "telemetry-disable" "revert" "ok" "Re-enabled telemetry"
        MODULE_RESULT="reverted"
    fi
}

revert_monitoring_tools() {
    local desc="Remove monitoring tools"
    if $REMOVE_PACKAGES; then
        if [[ "$OS" == "macos" ]]; then
            for tool in oversight blockblock knockknock ransomwhere; do
                if cask_installed "$tool"; then
                    cask_uninstall "$tool"
                    state_remove_package "$tool"
                fi
            done
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc (Objective-See)" "reverted"
            log_entry "monitoring-tools" "revert" "ok" "Uninstalled Objective-See tools"
        elif [[ "$OS" == "linux" ]]; then
            for tool in aide rkhunter fail2ban; do
                pkg_uninstall "$tool" 2>/dev/null || true
            done
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "reverted"
            log_entry "monitoring-tools" "revert" "ok" "Removed monitoring tools"
        fi
        MODULE_RESULT="reverted"
    else
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "manual"
        log_entry "monitoring-tools" "revert" "manual" "Tools kept, manual removal if needed"
        pause_guide "Monitoring tools were kept installed. Uninstall manually if desired."
        MODULE_RESULT="manual"
    fi
}

revert_permissions_audit() {
    local desc="Revert permissions audit"
    # Read-only module — nothing to revert
    print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "reverted"
    log_entry "permissions-audit" "revert" "ok" "Nothing to revert (read-only audit)"
    MODULE_RESULT="reverted"
}

revert_mac_rotate() {
    local desc="Revert MAC address rotation"
    if [[ "$OS" == "macos" ]]; then
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "manual"
        log_entry "mac-rotate" "revert" "manual" "GUI setting on macOS"
        pause_guide "To disable MAC rotation: System Settings > Wi-Fi > click (i) on each network > set 'Private Wi-Fi address' to 'Off' or 'Fixed'."
        MODULE_RESULT="manual"
    elif [[ "$OS" == "linux" ]]; then
        if [[ -f /etc/NetworkManager/conf.d/mac-randomize.conf ]]; then
            run_as_root rm -f /etc/NetworkManager/conf.d/mac-randomize.conf
            run_as_root systemctl restart NetworkManager &>/dev/null 2>&1 || true
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc (NetworkManager)" "reverted"
            log_entry "mac-rotate" "revert" "ok" "Removed MAC randomization config"
            MODULE_RESULT="reverted"
        else
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "skipped"
            MODULE_RESULT="skipped"
        fi
    fi
}

revert_vpn_killswitch() {
    local desc="Revert VPN kill switch"
    if command -v mullvad &>/dev/null; then
        mullvad always-require-vpn set off &>/dev/null 2>&1 || true
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc (Mullvad)" "reverted"
        log_entry "vpn-killswitch" "revert" "ok" "Disabled always-require-vpn"
        MODULE_RESULT="reverted"
    else
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "manual"
        log_entry "vpn-killswitch" "revert" "manual" "Mullvad CLI not found"
        pause_guide "Disable VPN kill switch in your VPN application settings."
        MODULE_RESULT="manual"
    fi
}

revert_traffic_obfuscation() {
    local desc="Revert traffic obfuscation"
    # Guidance-only module
    print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "reverted"
    log_entry "traffic-obfuscation" "revert" "ok" "Nothing to revert (guidance-only)"
    MODULE_RESULT="reverted"
}

revert_browser_fingerprint() {
    local desc="Remove Firefox fingerprint resistance"
    local ff_profile=""
    if [[ "$OS" == "macos" ]]; then
        ff_profile=$(find "${REAL_HOME}/Library/Application Support/Firefox/Profiles" -maxdepth 1 -name "*.default-release" -type d 2>/dev/null | head -1)
    elif [[ "$OS" == "linux" ]]; then
        ff_profile=$(find "${REAL_HOME}/.mozilla/firefox" -maxdepth 1 -name "*.default-release" -type d 2>/dev/null | head -1)
    fi

    if [[ -n "$ff_profile" ]] && [[ -f "${ff_profile}/user.js" ]] && grep -q "privacy.resistFingerprinting" "${ff_profile}/user.js" 2>/dev/null; then
        # Remove the fingerprint resistance block from user.js
        local tmp
        tmp=$(mktemp)
        sed '/Advanced Fingerprint Resistance/,$ d' "${ff_profile}/user.js" > "$tmp" 2>/dev/null
        if [[ -s "$tmp" ]]; then
            mv "$tmp" "${ff_profile}/user.js"
        else
            # If nothing left, remove the whole file
            rm -f "${ff_profile}/user.js" "$tmp"
        fi
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "reverted"
        log_entry "browser-fingerprint" "revert" "ok" "Removed fingerprint resistance settings"
        MODULE_RESULT="reverted"
    else
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "skipped"
        MODULE_RESULT="skipped"
    fi
}

revert_metadata_strip() {
    local desc="Remove metadata tools"
    if $REMOVE_PACKAGES; then
        if command -v exiftool &>/dev/null; then
            if [[ "$OS" == "macos" ]]; then
                pkg_uninstall exiftool
            elif [[ "$OS" == "linux" ]]; then
                case "$DISTRO" in
                    debian) pkg_uninstall libimage-exiftool-perl ;;
                    fedora) pkg_uninstall perl-Image-ExifTool ;;
                    arch)   pkg_uninstall perl-image-exiftool ;;
                esac
                pkg_uninstall mat2 2>/dev/null || true
            fi
            state_remove_package "exiftool"
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "reverted"
            log_entry "metadata-strip" "revert" "ok" "Uninstalled exiftool"
            MODULE_RESULT="reverted"
        else
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "skipped"
            MODULE_RESULT="skipped"
        fi
    else
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "manual"
        log_entry "metadata-strip" "revert" "manual" "Tools kept"
        pause_guide "Metadata tools were kept installed. Uninstall manually if desired."
        MODULE_RESULT="manual"
    fi
}

revert_dev_isolation() {
    local desc="Revert dev isolation"
    # Don't remove Docker or UTM — just note it
    print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "reverted"
    log_entry "dev-isolation" "revert" "ok" "Docker/UTM left installed (user tools)"
    MODULE_RESULT="reverted"
}

revert_audit_script() {
    local desc="Remove weekly audit schedule"
    if [[ "$OS" == "macos" ]]; then
        local plist="${REAL_HOME}/Library/LaunchAgents/com.secure.weekly-audit.plist"
        if [[ -f "$plist" ]]; then
            launchctl unload "$plist" &>/dev/null 2>&1 || true
            rm -f "$plist"
        fi
        rm -f "${SCRIPT_DIR}/weekly-audit-generated.sh"
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc (launchd)" "reverted"
        log_entry "audit-script" "revert" "ok" "Removed launchd agent and generated audit script"
        MODULE_RESULT="reverted"
    elif [[ "$OS" == "linux" ]]; then
        if crontab -u "${REAL_USER}" -l 2>/dev/null | grep -q "weekly-audit"; then
            crontab -u "${REAL_USER}" -l 2>/dev/null | grep -v "weekly-audit" | crontab -u "${REAL_USER}" - 2>/dev/null
        fi
        rm -f "${SCRIPT_DIR}/weekly-audit-linux.sh"
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc (cron)" "reverted"
        log_entry "audit-script" "revert" "ok" "Removed cron job and generated audit script"
        MODULE_RESULT="reverted"
    fi
}

revert_backup_guidance() {
    local desc="Revert backup guidance"
    # Guidance-only module
    print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "reverted"
    log_entry "backup-guidance" "revert" "ok" "Nothing to revert (guidance-only)"
    MODULE_RESULT="reverted"
}

revert_border_prep() {
    local desc="Revert border prep"
    # Guidance-only module
    print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "reverted"
    log_entry "border-prep" "revert" "ok" "Nothing to revert (guidance-only)"
    MODULE_RESULT="reverted"
}

revert_bluetooth_disable() {
    local desc="Re-enable Bluetooth"
    if [[ "$OS" == "macos" ]]; then
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "manual"
        log_entry "bluetooth-disable" "revert" "manual" "GUI setting on macOS"
        pause_guide "Re-enable Bluetooth via Control Center or System Settings > Bluetooth."
        MODULE_RESULT="manual"
    elif [[ "$OS" == "linux" ]]; then
        run_as_root systemctl enable --now bluetooth &>/dev/null 2>&1
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "reverted"
        log_entry "bluetooth-disable" "revert" "ok" "Bluetooth service re-enabled"
        MODULE_RESULT="reverted"
    fi
}

revert_kernel_sysctl() {
    local desc="Revert kernel sysctl hardening"
    if [[ "$OS" != "linux" ]]; then
        MODULE_RESULT="skipped"; return
    fi
    local conf_file="/etc/sysctl.d/99-hardening.conf"
    if [[ -f "$conf_file" ]]; then
        run_as_root rm -f "$conf_file"
        run_as_root sysctl --system &>/dev/null
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "reverted"
        log_entry "kernel-sysctl" "revert" "ok" "Removed sysctl hardening config"
        MODULE_RESULT="reverted"
    else
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "skipped"
        MODULE_RESULT="skipped"
    fi
}

revert_apparmor_enforce() {
    local desc="Revert AppArmor to complain mode"
    if [[ "$OS" == "macos" ]]; then
        # Audit-only on macOS — nothing to revert
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "reverted"
        log_entry "apparmor-enforce" "revert" "ok" "Nothing to revert (macOS audit-only)"
        MODULE_RESULT="reverted"
        return
    fi
    if [[ "$OS" != "linux" ]]; then
        MODULE_RESULT="skipped"; return
    fi
    if ! command -v aa-complain &>/dev/null; then
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "skipped"
        MODULE_RESULT="skipped"; return
    fi
    run_as_root aa-complain /etc/apparmor.d/* &>/dev/null
    print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "reverted"
    log_entry "apparmor-enforce" "revert" "ok" "All profiles set to complain"
    MODULE_RESULT="reverted"
}

revert_boot_security() {
    local desc="Revert boot security"
    if [[ "$OS" == "macos" ]]; then
        # Verification-only on macOS — nothing to revert
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "reverted"
        log_entry "boot-security" "revert" "ok" "Nothing to revert (macOS verification-only)"
        MODULE_RESULT="reverted"
        return
    fi
    if [[ "$OS" != "linux" ]]; then
        MODULE_RESULT="skipped"; return
    fi
    if [[ -f /etc/grub.d/40_custom.bak.hardening ]]; then
        run_as_root mv /etc/grub.d/40_custom.bak.hardening /etc/grub.d/40_custom
        run_as_root update-grub &>/dev/null || run_as_root grub-mkconfig -o /boot/grub/grub.cfg &>/dev/null
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc (GRUB password removed)" "reverted"
        log_entry "boot-security" "revert" "ok" "Restored GRUB config backup"
        MODULE_RESULT="reverted"
    else
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "skipped"
        MODULE_RESULT="skipped"
    fi
}

# ═══════════════════════════════════════════════════════════════════
# UNINSTALL FLOW
# ═══════════════════════════════════════════════════════════════════
run_uninstall_twophase() {
    print_section "Full Uninstall (Two-Phase)"

    # Load state and identify applied modules
    local applied_mods=()
    if state_read; then
        for mod in "${!STATE_MODULES[@]}"; do
            if [[ "${STATE_MODULES[$mod]}" == "applied" ]]; then
                applied_mods+=("$mod")
            fi
        done
    else
        detect_applied_modules
        for mod in "${!STATE_MODULES[@]}"; do
            if [[ "${STATE_MODULES[$mod]}" == "applied" ]]; then
                applied_mods+=("$mod")
            fi
        done
    fi

    if [[ ${#applied_mods[@]} -eq 0 ]]; then
        echo -e "  ${GREEN}No hardening changes detected. Nothing to uninstall.${NC}"
        return 0
    fi

    # Classify into user-space and root
    local userspace_reverts=()
    local root_reverts=()

    for mod in "${applied_mods[@]}"; do
        if [[ -n "${ROOT_MODULES[$mod]:-}" ]]; then
            root_reverts+=("$mod")
        else
            userspace_reverts+=("$mod")
        fi
    done

    # Phase 1: Revert user-space modules
    if [[ ${#userspace_reverts[@]} -gt 0 ]]; then
        print_section "Reverting User-Space Modules (${#userspace_reverts[@]})"
        TOTAL_MODULES=${#userspace_reverts[@]}
        CURRENT_MODULE=0
        for mod in "${userspace_reverts[@]}"; do
            run_module "$mod" "revert"
        done
    fi

    # Phase 2: Preview root reverts
    if [[ ${#root_reverts[@]} -gt 0 && "$NO_SUDO_MODE" != true ]]; then
        ROOT_MODULES_LIST=("${root_reverts[@]}")
        ROOT_COMMANDS=()
        ROOT_COMMAND_DESCS=()

        for mod in "${root_reverts[@]}"; do
            local collector="collect_revert_${mod//-/_}"
            if declare -f "$collector" &>/dev/null; then
                "$collector"
            fi
        done

        if [[ $(count_root_commands) -gt 0 ]]; then
            prompt_root_preview || return 0
            acquire_sudo || return 1
            execute_root_batch
        fi
    fi

    state_write
    echo -e "  ${GREEN}Uninstall complete.${NC}"
}

run_uninstall() {
    # Use two-phase uninstall
    run_uninstall_twophase
    return

    # --- Original implementation below (kept for reference, now unreachable) ---
    print_section "Full Uninstall"

    # Remove scheduled cleaner if configured
    if [[ -f "$SCHED_CLEAN_CONFIG_USER" ]] || [[ -f "$SCHED_CLEAN_CONFIG_PROJECT" ]]; then
        echo -e "  ${BROWN}Removing scheduled cleaner...${NC}"
        if unschedule_clean 2>/dev/null; then
            echo -e "  ${GREEN}✓ Scheduled cleaner removed${NC}"
        else
            echo -e "  ${RED}✗ Failed to remove scheduler - may need manual cleanup${NC}"
        fi
    fi

    # Load state
    local applied_count=0
    if state_read; then
        applied_count=$(state_count_applied)
        echo -e "  State file found: ${BOLD}${STATE_FILE_USER}${NC}"
        echo -e "  Applied modules: ${BOLD}${applied_count}${NC}"
        echo -e "  Last run: ${BOLD}${STATE_LAST_RUN}${NC}"
    else
        echo -e "  ${RED}No state file found. Using live detection...${NC}"
        detect_applied_modules
        applied_count=$(state_count_applied)
        echo -e "  Detected modules: ${BOLD}${applied_count}${NC}"
    fi

    if [[ $applied_count -eq 0 ]]; then
        echo ""
        echo -e "  ${GREEN}No hardening changes detected. Nothing to uninstall.${NC}"
        return
    fi

    echo ""

    # Ask about package removal
    if [[ ${#STATE_PACKAGES[@]} -gt 0 ]]; then
        echo -e "  The following tools were installed by the hardening script:"
        echo -e "    ${BOLD}${STATE_PACKAGES[*]}${NC}"
        echo ""
        echo -e "  Remove installed tools as well?"
        echo -e "    ${GREEN}[Y]${NC} Yes — uninstall all tools listed above"
        echo -e "    ${GREEN}[N]${NC} No  — keep tools, only revert settings"
        echo -e "    ${BROWN}[Q] Quit${NC}"
        echo ""
        while true; do
            echo -ne "  ${BOLD}Choice:${NC} "
            read -r yn
            case "${yn,,}" in
                y|yes) REMOVE_PACKAGES=true; break ;;
                n|no)  REMOVE_PACKAGES=false; break ;;
                q)     echo "Aborted."; exit 0 ;;
                *)     echo -e "  ${RED}Enter Y, N, or Q.${NC}" ;;
            esac
        done
    fi

    echo ""
    local pkg_msg=""
    $REMOVE_PACKAGES && pkg_msg=" and remove ${#STATE_PACKAGES[@]} packages"
    echo -e "  ${RED}⚠  This will revert ${applied_count} modules${pkg_msg}.${NC}"
    if ! prompt_yn "Proceed?"; then
        echo "Aborted."
        exit 0
    fi

    # Build list of applied modules in reverse order
    local -a to_revert=()
    for mod_id in "${!STATE_MODULES[@]}"; do
        if [[ "${STATE_MODULES[$mod_id]}" == "applied" ]]; then
            to_revert+=("$mod_id")
        fi
    done

    # Reverse the array
    local -a reversed=()
    for (( i=${#to_revert[@]}-1; i>=0; i-- )); do
        reversed+=("${to_revert[$i]}")
    done

    TOTAL_MODULES=${#reversed[@]}
    CURRENT_MODULE=0

    print_section "Reverting (${TOTAL_MODULES} modules)"

    for mod_id in "${reversed[@]}"; do
        run_module "$mod_id" "revert"
    done

    # Update state file
    state_write

    # Print summary
    print_uninstall_summary
}

# ═══════════════════════════════════════════════════════════════════
# MODIFY FLOW
# ═══════════════════════════════════════════════════════════════════
run_modify() {
    print_section "Modify Hardening"

    # Load current state
    if state_read; then
        echo -e "  State file loaded: ${BOLD}$(state_count_applied)${NC} modules currently applied."
    else
        echo -e "  ${RED}No state file found. Using live detection...${NC}"
        detect_applied_modules
        echo -e "  Detected: ${BOLD}$(state_count_applied)${NC} modules currently applied."
    fi
    echo ""

    # Select output mode for any manual steps
    select_output_mode

    # Launch interactive picker
    if ! interactive_picker; then
        return
    fi

    local add_count=${#PICKER_ADD[@]}
    local remove_count=${#PICKER_REMOVE[@]}

    if [[ $add_count -eq 0 && $remove_count -eq 0 ]]; then
        echo -e "  ${GREEN}No changes selected.${NC}"
        return
    fi

    echo -e "  Changes to apply:"
    if [[ $add_count -gt 0 ]]; then
        echo -e "    ${GREEN}+${NC} Add: ${PICKER_ADD[*]}"
    fi
    if [[ $remove_count -gt 0 ]]; then
        echo -e "    ${RED}-${NC} Remove: ${PICKER_REMOVE[*]}"
    fi
    echo ""

    if ! prompt_yn "Apply these changes?"; then
        echo "Cancelled."
        return
    fi

    # Ask about package removal if removing modules with packages
    if [[ $remove_count -gt 0 ]]; then
        local has_pkg_modules=false
        for mod_id in "${PICKER_REMOVE[@]}"; do
            case "$mod_id" in
                firewall-outbound|monitoring-tools|metadata-strip) has_pkg_modules=true ;;
            esac
        done
        if $has_pkg_modules; then
            echo ""
            if prompt_yn "Also remove packages installed by removed modules?"; then
                REMOVE_PACKAGES=true
            fi
        fi
    fi

    TOTAL_MODULES=$((add_count + remove_count))
    CURRENT_MODULE=0

    # Apply additions
    if [[ $add_count -gt 0 ]]; then
        print_section "Adding Modules"
        for mod_id in "${PICKER_ADD[@]}"; do
            run_module "$mod_id" "apply"
        done
    fi

    # Apply removals
    if [[ $remove_count -gt 0 ]]; then
        print_section "Removing Modules"
        for mod_id in "${PICKER_REMOVE[@]}"; do
            run_module "$mod_id" "revert"
        done
    fi

    # Update state
    state_write
}

# ═══════════════════════════════════════════════════════════════════
# OUTPUT: SUMMARY & REPORTS
# ═══════════════════════════════════════════════════════════════════
print_summary() {
    echo ""
    echo -e "${BOLD}${GREEN}═══════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${GREEN}  Hardening Complete${NC}"
    echo -e "${BOLD}${GREEN}═══════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${GREEN}✓${NC} Applied:    ${BOLD}${COUNT_APPLIED}${NC}"
    echo -e "  ${GREEN}○${NC} Skipped:    ${BOLD}${COUNT_SKIPPED}${NC} ${BROWN}(already applied)${NC}"
    echo -e "  ${RED}✗${NC} Failed:     ${BOLD}${COUNT_FAILED}${NC}$([ $COUNT_FAILED -gt 0 ] && echo -e " ${RED}(see log)${NC}")"
    echo -e "  ${RED}☐${NC} Manual:     ${BOLD}${COUNT_MANUAL}${NC}$([ $COUNT_MANUAL -gt 0 ] && echo -e " ${RED}(see below)${NC}")"
    echo ""

    # Post-run score: count applied modules, exclude OS-incompatible modules
    local -a applicable_mods=()
    local -a applied_mods=()
    for mod_id in "${ENABLED_MODULES[@]}"; do
        # Only count modules that were applicable to this OS
        # (modules with no state entry were skipped_unsupported)
        if [[ -n "${STATE_MODULES[$mod_id]:-}" ]]; then
            applicable_mods+=("$mod_id")
            if [[ "${STATE_MODULES[$mod_id]}" == "applied" ]]; then
                applied_mods+=("$mod_id")
            fi
        fi
    done
    local score_output
    score_output=$(calculate_score applicable_mods applied_mods)
    local _aw _tw pct _ac _tc
    read -r _aw _tw pct _ac _tc <<< "$score_output"
    print_score_bar "$pct"
    echo -e "  ${BROWN}${_ac} of ${_tc} modules applied${NC}"
    echo ""

    echo -e "  Profile: ${BOLD}${PROFILE}${NC} | OS: ${BOLD}${OS}${NC} | Date: ${BOLD}${DATE}${NC}"
    echo ""
}

print_uninstall_summary() {
    echo ""
    echo -e "${BOLD}${GREEN}═══════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${GREEN}  Uninstall Complete${NC}"
    echo -e "${BOLD}${GREEN}═══════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${GREEN}✓${NC} Reverted:   ${BOLD}${COUNT_REVERTED}${NC}"
    echo -e "  ${GREEN}○${NC} Skipped:    ${BOLD}${COUNT_SKIPPED}${NC}"
    echo -e "  ${RED}✗${NC} Failed:     ${BOLD}${COUNT_FAILED}${NC}$([ $COUNT_FAILED -gt 0 ] && echo -e " ${RED}(see log)${NC}")"
    echo -e "  ${RED}☐${NC} Manual:     ${BOLD}${COUNT_MANUAL}${NC}$([ $COUNT_MANUAL -gt 0 ] && echo -e " ${RED}(see below)${NC}")"
    echo ""
    echo -e "  OS: ${BOLD}${OS}${NC} | Date: ${BOLD}${DATE}${NC}"
    echo ""
}

print_modify_summary() {
    echo ""
    echo -e "${BOLD}${GREEN}═══════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${GREEN}  Modify Complete${NC}"
    echo -e "${BOLD}${GREEN}═══════════════════════════════════════════════════${NC}"
    echo ""
    if [[ $COUNT_APPLIED -gt 0 ]]; then
        echo -e "  ${GREEN}✓${NC} Added:      ${BOLD}${COUNT_APPLIED}${NC}"
    fi
    if [[ $COUNT_REVERTED -gt 0 ]]; then
        echo -e "  ${GREEN}✓${NC} Removed:    ${BOLD}${COUNT_REVERTED}${NC}"
    fi
    echo -e "  ${GREEN}○${NC} Skipped:    ${BOLD}${COUNT_SKIPPED}${NC}"
    echo -e "  ${RED}✗${NC} Failed:     ${BOLD}${COUNT_FAILED}${NC}$([ $COUNT_FAILED -gt 0 ] && echo -e " ${RED}(see log)${NC}")"
    echo -e "  ${RED}☐${NC} Manual:     ${BOLD}${COUNT_MANUAL}${NC}$([ $COUNT_MANUAL -gt 0 ] && echo -e " ${RED}(see below)${NC}")"
    echo ""
    echo -e "  OS: ${BOLD}${OS}${NC} | Date: ${BOLD}${DATE}${NC}"
    echo ""
}

print_manual_checklist() {
    if [[ ${#MANUAL_STEPS[@]} -gt 0 ]]; then
        print_section "Manual Steps Remaining"
        for i in "${!MANUAL_STEPS[@]}"; do
            echo -e "  ${RED}☐${NC} $((i+1)). ${MANUAL_STEPS[$i]}"
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
        echo "Generated by barked.sh v${VERSION}"
    } > "$report_file"
    echo -e "  ${GREEN}Report written to:${NC} ${report_file}"
}

write_log() {
    mkdir -p "$(dirname "$LOG_FILE")"
    {
        echo "══════════════════════════════════════════════════════════════════"
        echo "BARKED HARDENING LOG — ${TIMESTAMP}"
        echo "Profile: ${PROFILE:-none} | Mode: ${RUN_MODE} | OS: ${OS}"
        if [[ "$NO_SUDO_MODE" == true ]]; then
            echo "[MODE] --no-sudo: root modules skipped"
        fi
        echo "══════════════════════════════════════════════════════════════════"
        echo ""

        # Group entries by phase
        local in_root_section=false
        for entry in "${LOG_ENTRIES[@]}"; do
            # Detect phase transitions
            if [[ "$entry" == *"[PHASE]"*"[root-collect]"* && "$in_root_section" == false ]]; then
                echo ""
                echo "═══ ROOT MODULES (sudo) ═══"
                in_root_section=true
            elif [[ "$entry" == *"[PHASE]"*"[userspace]"*"[start]"* ]]; then
                echo "═══ USER-SPACE MODULES ═══"
            fi

            # Format [ROOT] entries specially
            if [[ "$entry" == *"[root-cmd]"*"[exec]"* ]]; then
                local cmd="${entry##*] }"
                echo "[ROOT] $cmd"
            elif [[ "$entry" == *"[root-cmd]"*"[exit]"* ]]; then
                local code="${entry##*: }"
                echo "[ROOT] EXIT $code"
            else
                echo "$entry"
            fi
        done

        echo ""
        echo "═══ SUMMARY ═══"
        echo "Applied: ${COUNT_APPLIED} | Skipped: ${COUNT_SKIPPED} | Failed: ${COUNT_FAILED}"
        if [[ "$ROOT_BATCH_ABORTED" == true ]]; then
            echo "Root batch: ABORTED at ${ROOT_BATCH_FAIL_MODULE}"
        fi
    } > "$LOG_FILE"
    echo -e "  ${BROWN}Log written to: ${LOG_FILE}${NC}"
}

# ═══════════════════════════════════════════════════════════════════
# MONITOR MODE — ALERT MESSAGE CATALOG
# ═══════════════════════════════════════════════════════════════════

# Alert titles (severity emoji added dynamically)
declare -A ALERT_TITLES=(
    # Network
    [vpn_disconnected]="VPN Disconnected"
    [dns_changed]="DNS Servers Changed"
    [dns_leak_detected]="DNS Leak Detected"
    [firewall_disabled]="Firewall Disabled"
    [stealth_mode_off]="Stealth Mode Disabled"
    [new_listener]="New Network Listener"
    [suspicious_listener]="Suspicious Port Open"
    # Supply chain
    [brew_new_package]="New Homebrew Package"
    [brew_untrusted_tap]="Non-Default Tap Added"
    [app_unsigned]="Unsigned App Detected"
    [app_signature_changed]="App Signature Changed"
    [npm_global_new]="New Global npm Package"
    [pip_global_new]="New Global pip Package"
    # Cloud sync
    [sync_sensitive_file]="Sensitive File in Sync Folder"
    [icloud_documents_sync]="Desktop/Documents Syncing"
    [token_in_history]="Token in Shell History"
    [token_file_permissions]="Credential File Exposed"
    [netrc_exists]="Plaintext Credentials File"
    # Dev environment
    [git_credentials_file]="Git Credentials File"
    [git_credential_exposed]="Token in Git Config"
    [ssh_key_permissions]="SSH Key Permissions"
    [ssh_key_no_passphrase]="SSH Key Unprotected"
    [ssh_key_weak]="Weak SSH Key"
    [docker_privileged]="Privileged Container"
    [docker_host_network]="Container Host Network"
    [ide_new_extension]="New IDE Extension"
    # Test
    [test]="Test Alert"
)

# Impact explanations (why this matters)
declare -A ALERT_IMPACTS=(
    # Network
    [vpn_disconnected]="Your real IP is visible to websites and your ISP can monitor all traffic"
    [dns_changed]="DNS queries may be logged by untrusted resolvers; potential for DNS spoofing"
    [dns_leak_detected]="ISP DNS resolver in use despite VPN; your browsing destinations are exposed"
    [firewall_disabled]="Inbound connections now allowed; system exposed to network attacks"
    [stealth_mode_off]="System responds to probes; visible to network scanners"
    [new_listener]="New process accepting network connections"
    [suspicious_listener]="Process listening on known-malicious port (common RAT/backdoor)"
    # Supply chain
    [brew_new_package]="Package installed outside baseline; supply chain change"
    [brew_untrusted_tap]="Third-party tap added; packages not vetted by Homebrew"
    [app_unsigned]="App has no code signature; could be tampered or malicious"
    [app_signature_changed]="App signature differs from baseline; possible tampering"
    [npm_global_new]="Global npm package installed; supply chain addition"
    [pip_global_new]="Global pip package installed; supply chain addition"
    # Cloud sync
    [sync_sensitive_file]="Credentials syncing to cloud; exposure risk"
    [icloud_documents_sync]="Files auto-upload to iCloud; sensitive local files may be cloud-stored"
    [token_in_history]="API token/key persisted to disk in shell history"
    [token_file_permissions]="Credential file world-readable; other users/processes can access"
    [netrc_exists]="Plaintext credentials in legacy auth file"
    # Dev environment
    [git_credentials_file]="Plaintext tokens stored; high-value target"
    [git_credential_exposed]="Hardcoded token visible to processes"
    [ssh_key_permissions]="Private key readable by others"
    [ssh_key_no_passphrase]="Stolen key = immediate access"
    [ssh_key_weak]="Cryptographically weak key algorithm"
    [docker_privileged]="Container has full host access"
    [docker_host_network]="Container has no network isolation"
    [ide_new_extension]="Extension can access files and network"
    # Test
    [test]="This is a test alert"
)

# Remediation steps (how to fix)
declare -A ALERT_REMEDIATIONS=(
    # Network
    [vpn_disconnected]="Run 'mullvad connect' or open Mullvad app"
    [dns_changed]="Review new servers. Restore with: networksetup -setdnsservers Wi-Fi <your-dns>"
    [dns_leak_detected]="Check VPN DNS settings. Mullvad: enable 'Block DNS not from Mullvad'"
    [firewall_disabled]="Re-enable: System Settings → Network → Firewall → On"
    [stealth_mode_off]="Re-enable: sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on"
    [new_listener]="Verify with 'lsof -i :<port>'. If unexpected: kill <pid>"
    [suspicious_listener]="Investigate: lsof -i :<port> then kill -9 <pid>"
    # Supply chain
    [brew_new_package]="Verify: brew info <name>. If expected: barked --monitor --baseline"
    [brew_untrusted_tap]="Review: brew tap-info <tap>. Remove if unknown: brew untap <tap>"
    [app_unsigned]="Verify source. Re-download from official site or remove app"
    [app_signature_changed]="Compare versions. Re-download from official source"
    [npm_global_new]="Verify: npm info <package>. If expected, update baseline"
    [pip_global_new]="Verify: pip show <package>. If expected, update baseline"
    # Cloud sync
    [sync_sensitive_file]="Move file outside sync folder or add to sync exclusions"
    [icloud_documents_sync]="System Settings → Apple ID → iCloud → Drive → disable Desktop/Documents"
    [token_in_history]="Clear: history -c && rm ~/.<shell>_history. Rotate exposed token"
    [token_file_permissions]="Fix: chmod 600 <file>"
    [netrc_exists]="Migrate to credential helpers. Remove: rm ~/.netrc after updating auth"
    # Dev environment
    [git_credentials_file]="Switch to osxkeychain: git config --global credential.helper osxkeychain"
    [git_credential_exposed]="Remove from config. Use credential helper or environment variables"
    [ssh_key_permissions]="Fix: chmod 600 <key>"
    [ssh_key_no_passphrase]="Add passphrase: ssh-keygen -p -f <key>"
    [ssh_key_weak]="Generate stronger: ssh-keygen -t ed25519"
    [docker_privileged]="Stop: docker stop <name>. Restart without --privileged"
    [docker_host_network]="Restart with bridge: docker run --network bridge ..."
    [ide_new_extension]="Review in IDE. Remove if unknown: Extensions → Uninstall"
    # Test
    [test]="No action needed"
)

# ═══════════════════════════════════════════════════════════════════
# MONITOR MODE — CONFIG FILE MANAGEMENT
# ═══════════════════════════════════════════════════════════════════
monitor_load_config() {
    if [[ -f "$MONITOR_CONFIG_FILE" ]]; then
        # Source the config file (it's shell key=value format)
        # shellcheck source=/dev/null
        source "$MONITOR_CONFIG_FILE"
    fi
}

monitor_write_default_config() {
    mkdir -p "$(dirname "$MONITOR_CONFIG_FILE")"
    cat > "$MONITOR_CONFIG_FILE" << 'EOFCONFIG'
# Barked Monitor Configuration
# Generated: $(date)

# Monitor settings
MONITOR_INTERVAL=300          # seconds between checks (default: 5 min)
MONITOR_CATEGORIES="supply-chain,cloud-sync,network,dev-env"

# Alert channels (configure one or more)
ALERT_WEBHOOK_URL=""          # Generic webhook endpoint
ALERT_SLACK_URL=""            # Slack incoming webhook
ALERT_DISCORD_URL=""          # Discord webhook
ALERT_MACOS_NOTIFY=true       # macOS notification center

# Email via SMTP API (optional)
ALERT_EMAIL_ENABLED=false
ALERT_EMAIL_API_URL=""        # SendGrid/Mailgun API endpoint
ALERT_EMAIL_API_KEY=""        # API key
ALERT_EMAIL_TO=""             # Recipient address

# Alert behavior
ALERT_COOLDOWN=3600           # Re-alert after N seconds if issue persists
ALERT_SEVERITY_MIN="warning"  # "warning" or "critical" only
EOFCONFIG
    chmod 600 "$MONITOR_CONFIG_FILE"
    echo -e "  ${GREEN}✓${NC} Created default config: ${MONITOR_CONFIG_FILE}"
}

monitor_menu() {
    print_section "Monitor Mode"

    echo -e "${BOLD}Continuous security monitoring for VPN, supply chain, and network changes.${NC}"
    echo ""

    # Check if already initialized
    local init_status="not configured"
    if [[ -f "$MONITOR_CONFIG_FILE" ]]; then
        init_status="${GREEN}configured${NC}"
    fi

    # Check if baseline exists
    local baseline_status="not created"
    if [[ -d "$MONITOR_BASELINE_DIR" ]] && [[ -n "$(ls -A "$MONITOR_BASELINE_DIR" 2>/dev/null)" ]]; then
        baseline_status="${GREEN}exists${NC}"
    fi

    # Check if running
    local running_status="not running"
    if [[ -f "$MONITOR_PID_FILE" ]]; then
        local pid
        pid="$(cat "$MONITOR_PID_FILE" 2>/dev/null)"
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            running_status="${GREEN}running (PID: $pid)${NC}"
        fi
    fi

    echo -e "  Status: config=${init_status}, baseline=${baseline_status}, daemon=${running_status}"
    echo ""
    echo -e "  ${GREEN}[1]${NC} Setup     — Initialize monitor configuration"
    echo -e "  ${GREEN}[2]${NC} Baseline  — Snapshot current system state"
    echo -e "  ${GREEN}[3]${NC} Start     — Start monitoring daemon"
    echo -e "  ${GREEN}[4]${NC} Test      — Send a test alert"
    echo -e "  ${BROWN}[B]${NC} Back      — Return to main menu"
    echo ""

    while true; do
        echo -ne "  ${BOLD}Choice:${NC} "
        read -r choice
        case "${choice,,}" in
            1) monitor_init_interactive; monitor_menu; return ;;
            2) monitor_take_baseline; monitor_menu; return ;;
            3) run_monitor ;;
            4) monitor_test_alert; monitor_menu; return ;;
            b) return ;;
            *) echo -e "  ${RED}Invalid choice.${NC}" ;;
        esac
    done
}

monitor_init_interactive() {
    print_section "Monitor Mode Setup"

    # Create directories
    mkdir -p "$MONITOR_STATE_DIR"
    mkdir -p "$MONITOR_BASELINE_DIR"
    mkdir -p "$(dirname "$MONITOR_LOG_FILE")"

    # Write default config if doesn't exist
    if [[ ! -f "$MONITOR_CONFIG_FILE" ]]; then
        monitor_write_default_config
    else
        echo -e "  ${BROWN}Config already exists: ${MONITOR_CONFIG_FILE}${NC}"
    fi

    echo ""
    echo -e "  ${BOLD}Configure alert channels:${NC}"
    echo ""

    # macOS notifications
    if [[ "$OS" == "macos" ]]; then
        if prompt_yn "Enable macOS notification center alerts?"; then
            if [[ "$OS" == "macos" ]]; then
                sed -i '' 's#^ALERT_MACOS_NOTIFY=.*#ALERT_MACOS_NOTIFY=true#' "$MONITOR_CONFIG_FILE"
            else
                sed -i 's#^ALERT_MACOS_NOTIFY=.*#ALERT_MACOS_NOTIFY=true#' "$MONITOR_CONFIG_FILE"
            fi
            echo -e "  ${GREEN}✓${NC} macOS notifications enabled"
        fi
    fi

    # Webhook
    echo ""
    echo -ne "  Webhook URL (blank to skip): "
    read -r webhook_url
    if [[ -n "$webhook_url" ]]; then
        if [[ "$OS" == "macos" ]]; then
            sed -i '' "s#^ALERT_WEBHOOK_URL=.*#ALERT_WEBHOOK_URL=\"${webhook_url}\"#" "$MONITOR_CONFIG_FILE"
        else
            sed -i "s#^ALERT_WEBHOOK_URL=.*#ALERT_WEBHOOK_URL=\"${webhook_url}\"#" "$MONITOR_CONFIG_FILE"
        fi
        echo -e "  ${GREEN}✓${NC} Webhook configured"
    fi

    # Slack
    echo -ne "  Slack webhook URL (blank to skip): "
    read -r slack_url
    if [[ -n "$slack_url" ]]; then
        if [[ "$OS" == "macos" ]]; then
            sed -i '' "s#^ALERT_SLACK_URL=.*#ALERT_SLACK_URL=\"${slack_url}\"#" "$MONITOR_CONFIG_FILE"
        else
            sed -i "s#^ALERT_SLACK_URL=.*#ALERT_SLACK_URL=\"${slack_url}\"#" "$MONITOR_CONFIG_FILE"
        fi
        echo -e "  ${GREEN}✓${NC} Slack configured"
    fi

    echo ""
    echo -e "  ${GREEN}Setup complete.${NC} Edit ${MONITOR_CONFIG_FILE} for more options."
    echo ""
    echo -e "  Next steps:"
    echo -e "    ${CYAN}barked --monitor --baseline${NC}  # Snapshot current state"
    echo -e "    ${CYAN}barked --monitor${NC}             # Start monitoring"
}

# ═══════════════════════════════════════════════════════════════════
# MONITOR MODE — ALERT SYSTEM
# ═══════════════════════════════════════════════════════════════════

# build_alert_message: Assemble detailed alert message based on severity
# Args: $1=alert_key, $2=severity, $3=dynamic_details (optional substitutions)
# Sets: BUILT_TITLE, BUILT_IMPACT, BUILT_DETAILS, BUILT_REMEDIATION
build_alert_message() {
    local alert_key="$1"
    local severity="$2"
    local dynamic_details="${3:-}"

    # Get base messages from catalog
    local base_title="${ALERT_TITLES[$alert_key]:-$alert_key}"
    local base_impact="${ALERT_IMPACTS[$alert_key]:-}"
    local base_remediation="${ALERT_REMEDIATIONS[$alert_key]:-}"

    # Add severity emoji
    local emoji="🟡"
    [[ "$severity" == "critical" ]] && emoji="🔴"

    # Build title with severity
    if [[ "$severity" == "critical" ]]; then
        BUILT_TITLE="${emoji} CRITICAL: ${base_title}"
    else
        BUILT_TITLE="${emoji} ${base_title}"
    fi

    # Impact (critical gets full, warning gets abbreviated)
    if [[ "$NOTIFY_SHOW_IMPACT" == "true" ]]; then
        if [[ "$severity" == "critical" ]]; then
            BUILT_IMPACT="$base_impact"
        else
            # Truncate impact for warnings
            BUILT_IMPACT="${base_impact:0:80}"
            [[ ${#base_impact} -gt 80 ]] && BUILT_IMPACT="${BUILT_IMPACT}..."
        fi
    else
        BUILT_IMPACT=""
    fi

    # Details (passed in dynamically)
    BUILT_DETAILS="$dynamic_details"

    # Remediation
    if [[ "$NOTIFY_SHOW_REMEDIATION" == "true" ]]; then
        BUILT_REMEDIATION="$base_remediation"
    else
        BUILT_REMEDIATION=""
    fi
}

monitor_send_alert() {
    local severity="$1"    # warning|critical
    local category="$2"    # supply-chain|cloud-sync|network|dev-env
    local alert_key="$3"   # key for message catalog
    local details="$4"     # dynamic details

    local timestamp
    timestamp="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

    # Check severity threshold
    if [[ "$ALERT_SEVERITY_MIN" == "critical" && "$severity" != "critical" ]]; then
        return 0
    fi

    # Check deduplication cooldown
    local cooldown_key="${category}_${alert_key}"
    local last_alert="${MONITOR_LAST_ALERT[$cooldown_key]:-0}"
    local now
    now="$(date +%s)"
    if (( now - last_alert < ALERT_COOLDOWN )); then
        return 0
    fi
    MONITOR_LAST_ALERT[$cooldown_key]="$now"

    # Build detailed message
    build_alert_message "$alert_key" "$severity" "$details"

    # Get title for logging (without emoji for log)
    local log_title="${ALERT_TITLES[$alert_key]:-$alert_key}"

    # Log the alert
    monitor_log "ALERT" "[$severity] $category: $log_title - $details"

    # Send to configured channels
    [[ -n "$ALERT_WEBHOOK_URL" ]] && monitor_send_webhook "" "$severity" "$category"
    [[ -n "$ALERT_SLACK_URL" ]] && monitor_send_slack "$severity" "$BUILT_TITLE" "$details"
    [[ -n "$ALERT_DISCORD_URL" ]] && monitor_send_discord "$severity" "$BUILT_TITLE" "$details"
    [[ "$ALERT_MACOS_NOTIFY" == "true" && "$OS" == "macos" ]] && monitor_send_macos "$severity" "$BUILT_TITLE" "$details"
    [[ "$ALERT_EMAIL_ENABLED" == "true" ]] && monitor_send_email "$severity" "$BUILT_TITLE" "$details"
}

monitor_send_webhook() {
    local payload="$1"
    local severity="$2"
    local category="$3"

    # Extended payload with impact/remediation
    local hostname
    hostname="$(scutil --get ComputerName 2>/dev/null || hostname)"
    local timestamp
    timestamp="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

    local extended_payload
    extended_payload=$(cat << EOFJSON
{
  "severity": "${severity}",
  "category": "${category}",
  "title": "${BUILT_TITLE}",
  "impact": "${BUILT_IMPACT}",
  "details": "${BUILT_DETAILS}",
  "remediation": "${BUILT_REMEDIATION}",
  "hostname": "${hostname}",
  "timestamp": "${timestamp}"
}
EOFJSON
)
    curl -s -X POST \
        -H "Content-Type: application/json" \
        -d "$extended_payload" \
        "$ALERT_WEBHOOK_URL" >/dev/null 2>&1 || true
}

monitor_send_slack() {
    local severity="$1" title="$2" details="$3"
    local color="#ffcc00"
    [[ "$severity" == "critical" ]] && color="#ff0000"

    local hostname
    hostname="$(scutil --get ComputerName 2>/dev/null || hostname)"
    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M')"

    # Build blocks array
    local blocks="["

    # Header block
    blocks+="{\"type\":\"header\",\"text\":{\"type\":\"plain_text\",\"text\":\"${BUILT_TITLE}\"}},"

    # Impact section (if available and critical)
    if [[ -n "$BUILT_IMPACT" && "$severity" == "critical" ]]; then
        blocks+="{\"type\":\"section\",\"text\":{\"type\":\"mrkdwn\",\"text\":\"${BUILT_IMPACT}\"}},"
    fi

    # Details with context fields
    blocks+="{\"type\":\"section\",\"fields\":["
    blocks+="{\"type\":\"mrkdwn\",\"text\":\"*Details:*\n${details}\"},"
    blocks+="{\"type\":\"mrkdwn\",\"text\":\"*Host:* ${hostname}\n*Time:* ${timestamp}\"}"
    blocks+="]},"

    # Remediation section (if available)
    if [[ -n "$BUILT_REMEDIATION" ]]; then
        blocks+="{\"type\":\"section\",\"text\":{\"type\":\"mrkdwn\",\"text\":\"*Fix:* \`${BUILT_REMEDIATION}\`\"}},"
    fi

    # Context footer
    blocks+="{\"type\":\"context\",\"elements\":[{\"type\":\"mrkdwn\",\"text\":\"barked monitor\"}]}"
    blocks+="]"

    local slack_payload
    slack_payload=$(cat << EOFJSON
{
  "attachments": [{
    "color": "${color}",
    "blocks": ${blocks}
  }]
}
EOFJSON
)
    curl -s -X POST \
        -H "Content-Type: application/json" \
        -d "$slack_payload" \
        "$ALERT_SLACK_URL" >/dev/null 2>&1 || true
}

monitor_send_discord() {
    local severity="$1" title="$2" details="$3"
    local color="16776960"  # yellow
    [[ "$severity" == "critical" ]] && color="16711680"  # red

    local hostname
    hostname="$(scutil --get ComputerName 2>/dev/null || hostname)"
    local timestamp
    timestamp="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

    # Build description with impact
    local description="$details"
    if [[ -n "$BUILT_IMPACT" && "$severity" == "critical" ]]; then
        description="${BUILT_IMPACT}\n\n**Details:** ${details}"
    fi

    # Build fields array
    local fields="["
    fields+="{\"name\":\"Host\",\"value\":\"${hostname}\",\"inline\":true},"
    fields+="{\"name\":\"Severity\",\"value\":\"${severity}\",\"inline\":true}"
    fields+="]"

    # Build footer with remediation
    local footer_text="barked monitor"
    if [[ -n "$BUILT_REMEDIATION" ]]; then
        footer_text="Fix: ${BUILT_REMEDIATION}"
    fi

    local discord_payload
    discord_payload=$(cat << EOFJSON
{
  "embeds": [{
    "color": ${color},
    "title": "${BUILT_TITLE}",
    "description": "${description}",
    "fields": ${fields},
    "footer": {"text": "${footer_text}"},
    "timestamp": "${timestamp}"
  }]
}
EOFJSON
)
    curl -s -X POST \
        -H "Content-Type: application/json" \
        -d "$discord_payload" \
        "$ALERT_DISCORD_URL" >/dev/null 2>&1 || true
}

monitor_send_macos() {
    local severity="$1" title="$2" details="$3"

    # macOS notification center has ~200 char limit
    # Build concise message with remediation hint
    local short_details="${details:0:120}"
    [[ ${#details} -gt 120 ]] && short_details="${short_details}..."

    # Add remediation hint if available
    local body="$short_details"
    if [[ -n "$BUILT_REMEDIATION" ]]; then
        local short_fix="${BUILT_REMEDIATION:0:60}"
        [[ ${#BUILT_REMEDIATION} -gt 60 ]] && short_fix="${short_fix}..."
        body="${short_details}\n\nFix: ${short_fix}"
    fi

    # Sound based on severity
    local sound="Basso"
    [[ "$severity" == "critical" ]] && sound="Sosumi"

    # Build AppleScript with click action
    local script
    if [[ "$NOTIFY_MACOS_CLICK_ACTION" == "log" ]]; then
        # Notification that opens log file when clicked
        script="display notification \"${body}\" with title \"${title}\" sound name \"${sound}\""
    else
        script="display notification \"${body}\" with title \"${title}\" sound name \"${sound}\""
    fi

    osascript -e "$script" 2>/dev/null || true
}

monitor_send_email() {
    local severity="$1" title="$2" details="$3"

    local hostname
    hostname="$(scutil --get ComputerName 2>/dev/null || hostname)"

    # Build HTML body
    local html_body="<h2>${BUILT_TITLE}</h2>"

    if [[ -n "$BUILT_IMPACT" ]]; then
        html_body+="<p><strong>Impact:</strong> ${BUILT_IMPACT}</p>"
    fi

    html_body+="<p><strong>Details:</strong> ${details}</p>"
    html_body+="<p><strong>Host:</strong> ${hostname}</p>"

    if [[ -n "$BUILT_REMEDIATION" ]]; then
        html_body+="<h3>How to Fix</h3>"
        html_body+="<p><code>${BUILT_REMEDIATION}</code></p>"
    fi

    html_body+="<hr><p style=\"color:#666;font-size:12px\">Sent by barked monitor</p>"

    # Subject line
    local subject="[Barked ${severity^}] ${title} on ${hostname}"

    # SendGrid API format
    local email_payload
    email_payload=$(cat << EOFJSON
{
  "personalizations": [{"to": [{"email": "${ALERT_EMAIL_TO}"}]}],
  "from": {"email": "barked@localhost", "name": "Barked Security Monitor"},
  "subject": "${subject}",
  "content": [{"type": "text/html", "value": "${html_body}"}]
}
EOFJSON
)
    curl -s -X POST \
        -H "Authorization: Bearer ${ALERT_EMAIL_API_KEY}" \
        -H "Content-Type: application/json" \
        -d "$email_payload" \
        "$ALERT_EMAIL_API_URL" >/dev/null 2>&1 || true
}

monitor_test_alert() {
    monitor_load_config
    echo -e "  ${BROWN}Sending test alert to configured channels...${NC}"

    # Temporarily disable cooldown for test
    local old_cooldown="$ALERT_COOLDOWN"
    ALERT_COOLDOWN=0

    monitor_send_alert "warning" "test" "test" "This is a test alert from barked monitor mode."

    ALERT_COOLDOWN="$old_cooldown"
    echo -e "  ${GREEN}✓${NC} Test alert sent"
}

# ═══════════════════════════════════════════════════════════════════
# MONITOR MODE — LOGGING & STATE
# ═══════════════════════════════════════════════════════════════════
monitor_log() {
    local level="$1"
    local message="$2"
    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    echo "[$timestamp] [$level] $message" >> "$MONITOR_LOG_FILE"
}

monitor_state_read() {
    local category="$1"
    local state_file="${MONITOR_STATE_DIR}/${category}.state"
    if [[ -f "$state_file" ]]; then
        cat "$state_file"
    fi
}

monitor_state_write() {
    local category="$1"
    local content="$2"
    local state_file="${MONITOR_STATE_DIR}/${category}.state"
    mkdir -p "$MONITOR_STATE_DIR"
    echo "$content" > "$state_file"
}

monitor_state_get() {
    local category="$1"
    local key="$2"
    local state_file="${MONITOR_STATE_DIR}/${category}.state"
    if [[ -f "$state_file" ]]; then
        grep "^${key}=" "$state_file" 2>/dev/null | cut -d'=' -f2- | head -1
    fi
}

monitor_state_set() {
    local category="$1"
    local key="$2"
    local value="$3"
    local state_file="${MONITOR_STATE_DIR}/${category}.state"
    mkdir -p "$MONITOR_STATE_DIR"

    if [[ -f "$state_file" ]]; then
        # Remove old key if exists
        grep -v "^${key}=" "$state_file" > "${state_file}.tmp" 2>/dev/null || true
        mv "${state_file}.tmp" "$state_file"
    fi
    echo "${key}=${value}" >> "$state_file"
}

monitor_baseline_read() {
    local name="$1"
    local baseline_file="${MONITOR_BASELINE_DIR}/${name}.txt"
    if [[ -f "$baseline_file" ]]; then
        cat "$baseline_file"
    fi
}

monitor_baseline_write() {
    local name="$1"
    local content="$2"
    mkdir -p "$MONITOR_BASELINE_DIR"
    echo "$content" > "${MONITOR_BASELINE_DIR}/${name}.txt"
}

monitor_check_pid() {
    if [[ -f "$MONITOR_PID_FILE" ]]; then
        local pid
        pid="$(cat "$MONITOR_PID_FILE")"
        if kill -0 "$pid" 2>/dev/null; then
            echo -e "${RED}Monitor already running (PID: ${pid})${NC}"
            echo -e "  Stop it with: kill $pid"
            return 1
        else
            # Stale PID file
            rm -f "$MONITOR_PID_FILE"
        fi
    fi
    return 0
}

monitor_write_pid() {
    echo $$ > "$MONITOR_PID_FILE"
}

monitor_cleanup() {
    rm -f "$MONITOR_PID_FILE"
    monitor_log "INFO" "Monitor stopped"
}

# ═══════════════════════════════════════════════════════════════════
# MONITOR MODE — NETWORK CHECKS
# ═══════════════════════════════════════════════════════════════════
monitor_check_network() {
    monitor_check_vpn
    monitor_check_dns
    monitor_check_firewall
    monitor_check_listeners
}

monitor_check_vpn() {
    local vpn_status="disconnected"

    # Try Mullvad CLI first
    if command -v mullvad &>/dev/null; then
        if mullvad status 2>/dev/null | grep -q "Connected"; then
            vpn_status="connected"
        fi
    else
        # Fallback: check for utun interfaces (VPN tunnels)
        if ifconfig 2>/dev/null | grep -q "^utun"; then
            # Check if Mullvad daemon is running
            if pgrep -x "mullvad-daemon" &>/dev/null; then
                vpn_status="connected"
            fi
        fi
    fi

    local prev_status
    prev_status="$(monitor_state_get "network" "vpn_status")"

    if [[ "$vpn_status" != "$prev_status" ]]; then
        monitor_state_set "network" "vpn_status" "$vpn_status"
        if [[ "$vpn_status" == "disconnected" && "$prev_status" == "connected" ]]; then
            monitor_send_alert "critical" "network" "vpn_disconnected" \
                "Mullvad VPN is no longer connected"
        fi
    fi
}

monitor_check_dns() {
    local current_dns=""

    if [[ "$OS" == "macos" ]]; then
        current_dns="$(networksetup -getdnsservers Wi-Fi 2>/dev/null | tr '\n' ',' | sed 's/,$//')"
    else
        current_dns="$(grep "^nameserver" /etc/resolv.conf 2>/dev/null | awk '{print $2}' | tr '\n' ',' | sed 's/,$//')"
    fi

    local baseline_dns
    baseline_dns="$(monitor_baseline_read "dns-servers")"

    if [[ -n "$baseline_dns" && "$current_dns" != "$baseline_dns" ]]; then
        local prev_dns
        prev_dns="$(monitor_state_get "network" "dns_servers")"
        if [[ "$current_dns" != "$prev_dns" ]]; then
            monitor_state_set "network" "dns_servers" "$current_dns"
            monitor_send_alert "critical" "network" "dns_changed" \
                "DNS servers changed from ${baseline_dns} to ${current_dns}"
        fi
    fi
}

monitor_check_firewall() {
    if [[ "$OS" != "macos" ]]; then
        return 0
    fi

    local fw_state
    fw_state="$(sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null | grep -o "enabled\|disabled" || echo "unknown")"

    local stealth_state
    stealth_state="$(sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>/dev/null | grep -o "enabled\|disabled" || echo "unknown")"

    local prev_fw
    prev_fw="$(monitor_state_get "network" "firewall_state")"
    local prev_stealth
    prev_stealth="$(monitor_state_get "network" "stealth_mode")"

    if [[ "$fw_state" != "$prev_fw" ]]; then
        monitor_state_set "network" "firewall_state" "$fw_state"
        if [[ "$fw_state" == "disabled" && "$prev_fw" == "enabled" ]]; then
            monitor_send_alert "critical" "network" "firewall_disabled" \
                "Firewall changed from enabled to disabled"
        fi
    fi

    if [[ "$stealth_state" != "$prev_stealth" ]]; then
        monitor_state_set "network" "stealth_mode" "$stealth_state"
        if [[ "$stealth_state" == "disabled" && "$prev_stealth" == "enabled" ]]; then
            monitor_send_alert "critical" "network" "stealth_mode_off" \
                "Stealth mode changed from on to off"
        fi
    fi
}

monitor_check_listeners() {
    local current_listeners
    current_listeners="$(lsof -i -P -n 2>/dev/null | grep LISTEN | awk '{print $1 ":" $9}' | sort -u | tr '\n' '|' | sed 's/|$//')"

    local baseline_listeners
    baseline_listeners="$(monitor_baseline_read "listeners")"

    if [[ -z "$baseline_listeners" ]]; then
        return 0
    fi

    # Check for new listeners
    local current_procs
    current_procs="$(echo "$current_listeners" | tr '|' '\n')"
    local baseline_procs
    baseline_procs="$(echo "$baseline_listeners" | tr '|' '\n')"

    local new_listeners
    new_listeners="$(comm -23 <(echo "$current_procs" | sort) <(echo "$baseline_procs" | sort))"

    if [[ -n "$new_listeners" ]]; then
        # Check for suspicious ports
        local suspicious_ports="4444 5555 6666 1337 31337 12345"
        for listener in $new_listeners; do
            local port
            port="$(echo "$listener" | grep -oE ':[0-9]+$' | tr -d ':')"
            if echo "$suspicious_ports" | grep -qw "$port"; then
                monitor_send_alert "critical" "network" "suspicious_listener" \
                    "Process listening on suspicious port: ${listener}"
            else
                monitor_send_alert "warning" "network" "new_listener" \
                    "New process listening: ${listener}"
            fi
        done
    fi
}

# ═══════════════════════════════════════════════════════════════════
# MONITOR MODE — SUPPLY CHAIN CHECKS
# ═══════════════════════════════════════════════════════════════════
monitor_check_supply_chain() {
    monitor_check_brew_packages
    monitor_check_app_signatures
    monitor_check_global_packages
}

monitor_check_brew_packages() {
    if ! command -v brew &>/dev/null; then
        return 0
    fi

    local current_formulae
    current_formulae="$(brew list --formula 2>/dev/null | sort | tr '\n' '|' | sed 's/|$//')"
    local current_casks
    current_casks="$(brew list --cask 2>/dev/null | sort | tr '\n' '|' | sed 's/|$//')"

    local baseline_formulae
    baseline_formulae="$(monitor_baseline_read "brew-formulae")"
    local baseline_casks
    baseline_casks="$(monitor_baseline_read "brew-casks")"

    if [[ -n "$baseline_formulae" ]]; then
        local new_formulae
        new_formulae="$(comm -23 <(echo "$current_formulae" | tr '|' '\n' | sort) <(echo "$baseline_formulae" | tr '|' '\n' | sort))"
        for pkg in $new_formulae; do
            [[ -z "$pkg" ]] && continue
            monitor_send_alert "warning" "supply-chain" "brew_new_package" \
                "New formula installed: ${pkg}"
        done
    fi

    if [[ -n "$baseline_casks" ]]; then
        local new_casks
        new_casks="$(comm -23 <(echo "$current_casks" | tr '|' '\n' | sort) <(echo "$baseline_casks" | tr '|' '\n' | sort))"
        for pkg in $new_casks; do
            [[ -z "$pkg" ]] && continue
            monitor_send_alert "warning" "supply-chain" "brew_new_package" \
                "New cask installed: ${pkg}"
        done
    fi

    # Check for untrusted taps
    local current_taps
    current_taps="$(brew tap 2>/dev/null | sort)"
    local default_taps="homebrew/cask|homebrew/core|homebrew/services"

    for tap in $current_taps; do
        if ! echo "$tap" | grep -qE "^(homebrew/|$default_taps)"; then
            local prev_warned
            prev_warned="$(monitor_state_get "supply-chain" "warned_tap_${tap//\//_}")"
            if [[ -z "$prev_warned" ]]; then
                monitor_state_set "supply-chain" "warned_tap_${tap//\//_}" "1"
                monitor_send_alert "warning" "supply-chain" "brew_untrusted_tap" \
                    "Third-party tap detected: ${tap}"
            fi
        fi
    done
}

monitor_check_app_signatures() {
    if [[ "$OS" != "macos" ]]; then
        return 0
    fi

    local baseline_sigs
    baseline_sigs="$(monitor_baseline_read "app-signatures")"

    for app in /Applications/*.app; do
        [[ ! -d "$app" ]] && continue
        local app_name
        app_name="$(basename "$app")"

        local sig_info
        sig_info="$(codesign -dv "$app" 2>&1 || echo "UNSIGNED")"
        local sig_status="signed"

        if echo "$sig_info" | grep -q "not signed\|UNSIGNED"; then
            sig_status="unsigned"
        elif echo "$sig_info" | grep -q "adhoc"; then
            sig_status="adhoc"
        fi

        # Check against baseline
        if [[ -n "$baseline_sigs" ]]; then
            local baseline_status
            baseline_status="$(echo "$baseline_sigs" | grep "^${app_name}=" | cut -d'=' -f2)"

            if [[ -n "$baseline_status" && "$sig_status" != "$baseline_status" ]]; then
                if [[ "$sig_status" == "unsigned" && "$baseline_status" == "signed" ]]; then
                    monitor_send_alert "critical" "supply-chain" "app_signature_changed" \
                        "${app_name} was signed but is now unsigned"
                fi
            elif [[ -z "$baseline_status" && "$sig_status" == "unsigned" ]]; then
                monitor_send_alert "critical" "supply-chain" "app_unsigned" \
                    "New unsigned application: ${app_name}"
            fi
        fi
    done
}

monitor_check_global_packages() {
    # npm global packages
    if command -v npm &>/dev/null; then
        local npm_globals
        npm_globals="$(npm list -g --depth=0 2>/dev/null | tail -n +2 | awk '{print $2}' | cut -d'@' -f1 | sort | tr '\n' '|' | sed 's/|$//')"
        local baseline_npm
        baseline_npm="$(monitor_baseline_read "npm-globals")"

        if [[ -n "$baseline_npm" ]]; then
            local new_npm
            new_npm="$(comm -23 <(echo "$npm_globals" | tr '|' '\n' | sort) <(echo "$baseline_npm" | tr '|' '\n' | sort))"
            for pkg in $new_npm; do
                [[ -z "$pkg" ]] && continue
                monitor_send_alert "warning" "supply-chain" "npm_global_new" \
                    "New global npm package: ${pkg}"
            done
        fi
    fi

    # pip global packages
    if command -v pip3 &>/dev/null || command -v pip &>/dev/null; then
        local pip_cmd="pip3"
        command -v pip3 &>/dev/null || pip_cmd="pip"

        local pip_globals
        pip_globals="$($pip_cmd list --user 2>/dev/null | tail -n +3 | awk '{print $1}' | sort | tr '\n' '|' | sed 's/|$//')"
        local baseline_pip
        baseline_pip="$(monitor_baseline_read "pip-globals")"

        if [[ -n "$baseline_pip" ]]; then
            local new_pip
            new_pip="$(comm -23 <(echo "$pip_globals" | tr '|' '\n' | sort) <(echo "$baseline_pip" | tr '|' '\n' | sort))"
            for pkg in $new_pip; do
                [[ -z "$pkg" ]] && continue
                monitor_send_alert "warning" "supply-chain" "pip_global_new" \
                    "New global pip package: ${pkg}"
            done
        fi
    fi
}

# ═══════════════════════════════════════════════════════════════════
# MONITOR MODE — CLOUD & SYNC CHECKS
# ═══════════════════════════════════════════════════════════════════
monitor_check_cloud_sync() {
    monitor_check_sync_sensitive_files
    monitor_check_token_exposure
}

monitor_check_sync_sensitive_files() {
    # Sensitive file patterns
    local sensitive_patterns=(".env" "*.pem" "*.key" "id_rsa" "id_ed25519" "credentials.json" "*.p12" "secrets.yaml" ".aws/credentials")

    # Sync folder locations
    local -a sync_dirs=()

    if [[ "$OS" == "macos" ]]; then
        # iCloud
        [[ -d "$HOME/Library/Mobile Documents/com~apple~CloudDocs" ]] && \
            sync_dirs+=("$HOME/Library/Mobile Documents/com~apple~CloudDocs")
        # iCloud Desktop & Documents
        [[ -d "$HOME/Desktop" ]] && sync_dirs+=("$HOME/Desktop")
        [[ -d "$HOME/Documents" ]] && sync_dirs+=("$HOME/Documents")
    fi

    # Dropbox
    [[ -d "$HOME/Dropbox" ]] && sync_dirs+=("$HOME/Dropbox")
    # Google Drive
    [[ -d "$HOME/Google Drive" ]] && sync_dirs+=("$HOME/Google Drive")
    [[ -d "$HOME/My Drive" ]] && sync_dirs+=("$HOME/My Drive")
    # OneDrive
    [[ -d "$HOME/OneDrive" ]] && sync_dirs+=("$HOME/OneDrive")

    for sync_dir in "${sync_dirs[@]}"; do
        for pattern in "${sensitive_patterns[@]}"; do
            local found
            found="$(find "$sync_dir" -maxdepth 3 -name "$pattern" -type f 2>/dev/null | head -5)"
            if [[ -n "$found" ]]; then
                local dir_name
                dir_name="$(basename "$sync_dir")"
                local alert_key="sync_${dir_name}_${pattern}"
                local prev_warned
                prev_warned="$(monitor_state_get "cloud-sync" "$alert_key")"
                if [[ -z "$prev_warned" ]]; then
                    monitor_state_set "cloud-sync" "$alert_key" "1"
                    monitor_send_alert "critical" "cloud-sync" "sync_sensitive_file" \
                        "Found ${pattern} files in ${dir_name}"
                fi
            fi
        done
    done
}

monitor_check_token_exposure() {
    # Check .netrc
    if [[ -f "$HOME/.netrc" ]]; then
        local prev_warned
        prev_warned="$(monitor_state_get "cloud-sync" "netrc_warning")"
        if [[ -z "$prev_warned" ]]; then
            monitor_state_set "cloud-sync" "netrc_warning" "1"
            monitor_send_alert "warning" "cloud-sync" "netrc_exists" \
                "~/.netrc exists with plaintext credentials"
        fi
    fi

    # Check shell history for tokens
    local -a history_files=("$HOME/.bash_history" "$HOME/.zsh_history")
    for hist_file in "${history_files[@]}"; do
        if [[ -f "$hist_file" ]]; then
            # Look for token patterns (be careful not to log the actual tokens)
            if grep -qE "(export.*TOKEN|export.*KEY|curl.*Authorization)" "$hist_file" 2>/dev/null; then
                local prev_warned
                prev_warned="$(monitor_state_get "cloud-sync" "history_token_$(basename "$hist_file")")"
                if [[ -z "$prev_warned" ]]; then
                    monitor_state_set "cloud-sync" "history_token_$(basename "$hist_file")" "1"
                    monitor_send_alert "critical" "cloud-sync" "token_in_history" \
                        "Potential API token found in $(basename "$hist_file")"
                fi
            fi
        fi
    done

    # Check credential file permissions
    local -a cred_files=("$HOME/.config/gh/hosts.yml" "$HOME/.docker/config.json" "$HOME/.aws/credentials")
    for cred_file in "${cred_files[@]}"; do
        if [[ -f "$cred_file" ]]; then
            local perms
            perms="$(stat -f "%OLp" "$cred_file" 2>/dev/null || stat -c "%a" "$cred_file" 2>/dev/null)"
            if [[ "$perms" =~ [0-7][4-7][4-7] ]]; then
                local prev_warned
                prev_warned="$(monitor_state_get "cloud-sync" "perms_$(basename "$cred_file")")"
                if [[ -z "$prev_warned" ]]; then
                    monitor_state_set "cloud-sync" "perms_$(basename "$cred_file")" "1"
                    monitor_send_alert "warning" "cloud-sync" "token_file_permissions" \
                        "$(basename "$cred_file") is world/group readable (${perms})"
                fi
            fi
        fi
    done
}

# ═══════════════════════════════════════════════════════════════════
# MONITOR MODE — DEV ENVIRONMENT CHECKS
# ═══════════════════════════════════════════════════════════════════
monitor_check_dev_env() {
    monitor_check_git_credentials
    monitor_check_ssh_keys
    monitor_check_docker
    monitor_check_ide_extensions
}

monitor_check_git_credentials() {
    # Check for .git-credentials file
    if [[ -f "$HOME/.git-credentials" ]]; then
        local prev_warned
        prev_warned="$(monitor_state_get "dev-env" "git_credentials_file")"
        if [[ -z "$prev_warned" ]]; then
            monitor_state_set "dev-env" "git_credentials_file" "1"
            monitor_send_alert "critical" "dev-env" "git_credentials_file" \
                "~/.git-credentials exists with plaintext credentials"
        fi
    fi

    # Check gitconfig for embedded tokens
    if [[ -f "$HOME/.gitconfig" ]]; then
        if grep -qE "(token|password)\s*=" "$HOME/.gitconfig" 2>/dev/null; then
            local prev_warned
            prev_warned="$(monitor_state_get "dev-env" "gitconfig_token")"
            if [[ -z "$prev_warned" ]]; then
                monitor_state_set "dev-env" "gitconfig_token" "1"
                monitor_send_alert "critical" "dev-env" "git_credential_exposed" \
                    "Potential credential found in ~/.gitconfig"
            fi
        fi
    fi
}

monitor_check_ssh_keys() {
    local ssh_dir="$HOME/.ssh"
    [[ ! -d "$ssh_dir" ]] && return 0

    for key_file in "$ssh_dir"/id_*; do
        [[ ! -f "$key_file" ]] && continue
        [[ "$key_file" == *.pub ]] && continue

        local key_name
        key_name="$(basename "$key_file")"

        # Check permissions
        local perms
        perms="$(stat -f "%OLp" "$key_file" 2>/dev/null || stat -c "%a" "$key_file" 2>/dev/null)"
        if [[ "$perms" != "600" ]]; then
            local prev_warned
            prev_warned="$(monitor_state_get "dev-env" "ssh_perms_${key_name}")"
            if [[ -z "$prev_warned" ]]; then
                monitor_state_set "dev-env" "ssh_perms_${key_name}" "1"
                monitor_send_alert "warning" "dev-env" "ssh_key_permissions" \
                    "${key_name} has permissions ${perms} (should be 600)"
            fi
        fi

        # Check for passphrase (attempt to load with empty passphrase)
        if ssh-keygen -y -P "" -f "$key_file" &>/dev/null; then
            local prev_warned
            prev_warned="$(monitor_state_get "dev-env" "ssh_nopass_${key_name}")"
            if [[ -z "$prev_warned" ]]; then
                monitor_state_set "dev-env" "ssh_nopass_${key_name}" "1"
                monitor_send_alert "warning" "dev-env" "ssh_key_no_passphrase" \
                    "${key_name} has no passphrase protection"
            fi
        fi

        # Check key type
        local key_type
        key_type="$(ssh-keygen -l -f "$key_file" 2>/dev/null | awk '{print $NF}' | tr -d '()')"
        if [[ "$key_type" == "DSA" ]]; then
            monitor_send_alert "warning" "dev-env" "ssh_key_weak" \
                "${key_name} uses deprecated DSA algorithm"
        elif [[ "$key_type" == "RSA" ]]; then
            local key_bits
            key_bits="$(ssh-keygen -l -f "$key_file" 2>/dev/null | awk '{print $1}')"
            if [[ "$key_bits" -lt 4096 ]]; then
                local prev_warned
                prev_warned="$(monitor_state_get "dev-env" "ssh_weak_${key_name}")"
                if [[ -z "$prev_warned" ]]; then
                    monitor_state_set "dev-env" "ssh_weak_${key_name}" "1"
                    monitor_send_alert "warning" "dev-env" "ssh_key_weak" \
                        "${key_name} is RSA with only ${key_bits} bits (recommend 4096+)"
                fi
            fi
        fi
    done
}

monitor_check_docker() {
    if ! command -v docker &>/dev/null; then
        return 0
    fi

    # Check for privileged containers
    local privileged
    privileged="$(docker ps --format '{{.Names}}' --filter "status=running" 2>/dev/null | while read -r name; do
        docker inspect "$name" 2>/dev/null | grep -q '"Privileged": true' && echo "$name"
    done)"

    if [[ -n "$privileged" ]]; then
        for container in $privileged; do
            local prev_warned
            prev_warned="$(monitor_state_get "dev-env" "docker_priv_${container}")"
            if [[ -z "$prev_warned" ]]; then
                monitor_state_set "dev-env" "docker_priv_${container}" "1"
                monitor_send_alert "critical" "dev-env" "docker_privileged" \
                    "Container '${container}' running with --privileged flag"
            fi
        done
    fi

    # Check for host network mode
    local host_net
    host_net="$(docker ps --format '{{.Names}}' --filter "status=running" 2>/dev/null | while read -r name; do
        docker inspect "$name" 2>/dev/null | grep -q '"NetworkMode": "host"' && echo "$name"
    done)"

    if [[ -n "$host_net" ]]; then
        for container in $host_net; do
            local prev_warned
            prev_warned="$(monitor_state_get "dev-env" "docker_hostnet_${container}")"
            if [[ -z "$prev_warned" ]]; then
                monitor_state_set "dev-env" "docker_hostnet_${container}" "1"
                monitor_send_alert "warning" "dev-env" "docker_host_network" \
                    "Container '${container}' using host network mode"
            fi
        done
    fi
}

monitor_check_ide_extensions() {
    if [[ "$OS" != "macos" ]]; then
        return 0
    fi

    # VS Code / Cursor extensions
    local -a ext_dirs=("$HOME/.vscode/extensions" "$HOME/.cursor/extensions")

    for ext_dir in "${ext_dirs[@]}"; do
        [[ ! -d "$ext_dir" ]] && continue

        local ide_name="vscode"
        [[ "$ext_dir" == *cursor* ]] && ide_name="cursor"

        local current_exts
        current_exts="$(ls -1 "$ext_dir" 2>/dev/null | sort | tr '\n' '|' | sed 's/|$//')"
        local baseline_exts
        baseline_exts="$(monitor_baseline_read "${ide_name}-extensions")"

        if [[ -n "$baseline_exts" ]]; then
            local new_exts
            new_exts="$(comm -23 <(echo "$current_exts" | tr '|' '\n' | sort) <(echo "$baseline_exts" | tr '|' '\n' | sort))"
            for ext in $new_exts; do
                [[ -z "$ext" ]] && continue
                monitor_send_alert "warning" "dev-env" "ide_new_extension" \
                    "New ${ide_name} extension: ${ext}"
            done
        fi
    done
}

# ═══════════════════════════════════════════════════════════════════
# MONITOR MODE — BASELINE SNAPSHOT
# ═══════════════════════════════════════════════════════════════════
monitor_take_baseline() {
    print_section "Creating Security Baseline"

    mkdir -p "$MONITOR_BASELINE_DIR"

    echo -e "  Capturing current state as known-good baseline..."
    echo ""

    # Network baselines
    echo -ne "  ${BROWN}⟳${NC} DNS servers..."
    if [[ "$OS" == "macos" ]]; then
        local dns
        dns="$(networksetup -getdnsservers Wi-Fi 2>/dev/null | tr '\n' ',' | sed 's/,$//')"
        monitor_baseline_write "dns-servers" "$dns"
    else
        local dns
        dns="$(grep "^nameserver" /etc/resolv.conf 2>/dev/null | awk '{print $2}' | tr '\n' ',' | sed 's/,$//')"
        monitor_baseline_write "dns-servers" "$dns"
    fi
    echo -e "\r  ${GREEN}✓${NC} DNS servers"

    echo -ne "  ${BROWN}⟳${NC} Network listeners..."
    local listeners
    listeners="$(lsof -i -P -n 2>/dev/null | grep LISTEN | awk '{print $1 ":" $9}' | sort -u | tr '\n' '|' | sed 's/|$//')"
    monitor_baseline_write "listeners" "$listeners"
    echo -e "\r  ${GREEN}✓${NC} Network listeners"

    # Homebrew baselines
    if command -v brew &>/dev/null; then
        echo -ne "  ${BROWN}⟳${NC} Homebrew packages..."
        local formulae
        formulae="$(brew list --formula 2>/dev/null | sort | tr '\n' '|' | sed 's/|$//')"
        monitor_baseline_write "brew-formulae" "$formulae"
        local casks
        casks="$(brew list --cask 2>/dev/null | sort | tr '\n' '|' | sed 's/|$//')"
        monitor_baseline_write "brew-casks" "$casks"
        echo -e "\r  ${GREEN}✓${NC} Homebrew packages"
    fi

    # App signatures baseline (macOS)
    if [[ "$OS" == "macos" ]]; then
        echo -ne "  ${BROWN}⟳${NC} Application signatures..."
        local app_sigs=""
        for app in /Applications/*.app; do
            [[ ! -d "$app" ]] && continue
            local app_name
            app_name="$(basename "$app")"
            local sig_info
            sig_info="$(codesign -dv "$app" 2>&1 || echo "UNSIGNED")"
            local sig_status="signed"
            if echo "$sig_info" | grep -q "not signed\|UNSIGNED"; then
                sig_status="unsigned"
            elif echo "$sig_info" | grep -q "adhoc"; then
                sig_status="adhoc"
            fi
            app_sigs+="${app_name}=${sig_status}\n"
        done
        echo -e "$app_sigs" > "${MONITOR_BASELINE_DIR}/app-signatures.txt"
        echo -e "\r  ${GREEN}✓${NC} Application signatures"
    fi

    # npm globals
    if command -v npm &>/dev/null; then
        echo -ne "  ${BROWN}⟳${NC} npm global packages..."
        local npm_globals
        npm_globals="$(npm list -g --depth=0 2>/dev/null | tail -n +2 | awk '{print $2}' | cut -d'@' -f1 | sort | tr '\n' '|' | sed 's/|$//')"
        monitor_baseline_write "npm-globals" "$npm_globals"
        echo -e "\r  ${GREEN}✓${NC} npm global packages"
    fi

    # pip globals
    if command -v pip3 &>/dev/null || command -v pip &>/dev/null; then
        echo -ne "  ${BROWN}⟳${NC} pip global packages..."
        local pip_cmd="pip3"
        command -v pip3 &>/dev/null || pip_cmd="pip"
        local pip_globals
        pip_globals="$($pip_cmd list --user 2>/dev/null | tail -n +3 | awk '{print $1}' | sort | tr '\n' '|' | sed 's/|$//')"
        monitor_baseline_write "pip-globals" "$pip_globals"
        echo -e "\r  ${GREEN}✓${NC} pip global packages"
    fi

    # IDE extensions
    for ext_dir in "$HOME/.vscode/extensions" "$HOME/.cursor/extensions"; do
        if [[ -d "$ext_dir" ]]; then
            local ide_name="vscode"
            [[ "$ext_dir" == *cursor* ]] && ide_name="cursor"
            echo -ne "  ${BROWN}⟳${NC} ${ide_name} extensions..."
            local exts
            exts="$(ls -1 "$ext_dir" 2>/dev/null | sort | tr '\n' '|' | sed 's/|$//')"
            monitor_baseline_write "${ide_name}-extensions" "$exts"
            echo -e "\r  ${GREEN}✓${NC} ${ide_name} extensions"
        fi
    done

    echo ""
    echo -e "  ${GREEN}Baseline captured.${NC} Saved to: ${MONITOR_BASELINE_DIR}"
    echo ""
    echo -e "  Next: ${CYAN}barked --monitor${NC} to start monitoring"
}

# ═══════════════════════════════════════════════════════════════════
# MONITOR MODE — MAIN LOOP
# ═══════════════════════════════════════════════════════════════════
monitor_run_checks() {
    local categories
    IFS=',' read -ra categories <<< "$MONITOR_CATEGORIES"

    for category in "${categories[@]}"; do
        case "$category" in
            network)       monitor_check_network ;;
            supply-chain)  monitor_check_supply_chain ;;
            cloud-sync)    monitor_check_cloud_sync ;;
            dev-env)       monitor_check_dev_env ;;
        esac
    done
}

run_monitor() {
    # Check for existing instance
    if ! monitor_check_pid; then
        exit 1
    fi

    # Load config
    monitor_load_config

    # Setup signal handlers
    trap monitor_cleanup EXIT INT TERM

    # Write PID file
    monitor_write_pid

    print_section "Security Monitor"
    echo -e "  Monitoring every ${MONITOR_INTERVAL} seconds"
    echo -e "  Categories: ${MONITOR_CATEGORIES}"
    echo -e "  Press Ctrl+C to stop"
    echo ""

    monitor_log "INFO" "Monitor started (interval: ${MONITOR_INTERVAL}s, categories: ${MONITOR_CATEGORIES})"

    # Initial check
    echo -e "  ${BROWN}Running initial security check...${NC}"
    monitor_run_checks
    echo -e "  ${GREEN}✓${NC} Initial check complete"
    echo ""

    # Main loop
    while true; do
        sleep "$MONITOR_INTERVAL"
        monitor_log "INFO" "Running scheduled check"
        monitor_run_checks
    done
}

# ═══════════════════════════════════════════════════════════════════
# ARGUMENT PARSING
# ═══════════════════════════════════════════════════════════════════
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --uninstall|-u)
                RUN_MODE="uninstall"
                ;;
            --modify|-m)
                RUN_MODE="modify"
                ;;
            --audit)
                AUDIT_MODE=true
                ;;
            --dry-run)
                DRY_RUN=true
                ;;
            --no-sudo|--user-only)
                NO_SUDO_MODE=true
                ;;
            --auto)
                AUTO_MODE=true
                ;;
            --profile)
                if [[ -z "${2:-}" ]]; then
                    echo -e "${RED}--profile requires a value (standard|high|paranoid)${NC}"
                    exit 1
                fi
                AUTO_PROFILE="$2"
                shift
                ;;
            --quiet|-q)
                QUIET_MODE=true
                ;;
            --accept-advanced)
                ACCEPT_ADVANCED=true
                ;;
            --clean|-c)
                CLEAN_MODE=true
                ;;
            --force)
                CLEAN_FORCE=true
                ;;
            --clean-scheduled)
                CLEAN_SCHEDULED=true
                ;;
            --clean-schedule)
                CLEAN_SCHEDULE_SETUP=true
                ;;
            --clean-unschedule)
                CLEAN_UNSCHEDULE=true
                ;;
            --monitor)
                MONITOR_MODE=true
                ;;
            --init)
                MONITOR_INIT=true
                ;;
            --baseline)
                MONITOR_BASELINE=true
                ;;
            --test-alert)
                MONITOR_TEST_ALERT=true
                ;;
            --interval)
                if [[ -z "${2:-}" ]]; then
                    echo -e "${RED}--interval requires a value in seconds${NC}"
                    exit 1
                fi
                if ! [[ "$2" =~ ^[0-9]+$ ]]; then
                    echo -e "${RED}--interval requires a positive integer value in seconds${NC}"
                    exit 1
                fi
                MONITOR_INTERVAL="$2"
                shift
                ;;
            --install)
                MONITOR_INSTALL=true
                ;;
            --uninstall)
                # Check if this is monitor --uninstall or standalone --uninstall
                if [[ "$MONITOR_MODE" == true ]]; then
                    MONITOR_UNINSTALL=true
                else
                    RUN_MODE="uninstall"
                fi
                ;;
            --enable)
                MONITOR_ENABLE=true
                ;;
            --disable)
                MONITOR_DISABLE=true
                ;;
            --restart)
                MONITOR_RESTART=true
                ;;
            --status)
                MONITOR_STATUS=true
                ;;
            --logs)
                MONITOR_LOGS=true
                ;;
            -f)
                MONITOR_LOGS_FOLLOW=true
                ;;
            --alerts)
                MONITOR_ALERTS=true
                ;;
            --health)
                MONITOR_HEALTH=true
                ;;
            --config)
                MONITOR_CONFIG=true
                ;;
            --daemon)
                MONITOR_DAEMON_MODE=true
                ;;
            --update)
                run_update
                ;;
            --uninstall-self)
                run_uninstall_self
                ;;
            --version|-v)
                echo "barked v${VERSION}"
                exit 0
                ;;
            --help|-h)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --uninstall, -u        Revert all hardening changes"
                echo "  --modify, -m           Add or remove individual modules"
                echo "  --audit                Score system security without making changes"
                echo "  --clean, -c            Run system cleaner"
                echo "  --dry-run              Show what would be changed without applying"
                echo "  --no-sudo              Skip modules requiring root (user-level only)"
                echo "  --auto                 Run non-interactively (requires --profile)"
                echo "  --profile <name>       Set security profile: standard, high, paranoid"
                echo "  --quiet, -q            Suppress interactive output (requires --auto or --audit)"
                echo "  --accept-advanced      Accept all advanced hardening prompts"
                echo "  --force                Skip confirmation prompt (use with --clean)"
                echo "  --clean-scheduled      Execute a scheduled clean run"
                echo "  --clean-schedule       Set up scheduled cleaning"
                echo "  --clean-unschedule     Remove scheduled cleaning"
                echo "  --monitor              Start continuous security monitoring"
                echo "    --install            Install monitor as system daemon (interactive)"
                echo "    --uninstall          Remove monitor daemon"
                echo "    --enable             Enable daemon (starts on boot)"
                echo "    --disable            Disable daemon"
                echo "    --restart            Restart running daemon"
                echo "    --status             Show daemon status"
                echo "    --logs [-f]          Show recent log (or follow with -f)"
                echo "    --alerts             Show alerts from last 24 hours"
                echo "    --health             Check daemon health"
                echo "    --config             Edit configuration"
                echo "    --init               Initialize configuration only"
                echo "    --baseline           Snapshot current state"
                echo "    --test-alert         Send test notification"
                echo "    --interval <secs>    Set check interval (default: 300)"
                echo "  --version, -v          Show version and exit"
                echo "  --update               Update barked to the latest version"
                echo "  --uninstall-self       Remove barked from system PATH"
                echo "  --help, -h             Show this help"
                echo ""
                echo "Examples:"
                echo "  $0                                  Interactive wizard"
                echo "  $0 --audit                          Score current security posture"
                echo "  $0 --dry-run --profile high         Preview high-profile changes"
                echo "  $0 --auto --profile standard        Apply standard profile non-interactively"
                echo "  $0 --auto --profile paranoid -q     Silent paranoid hardening"
                echo "  $0 --uninstall                      Revert all changes"
                echo "  $0 --clean                          Interactive system cleaner"
                echo "  $0 --clean --dry-run                Preview what would be cleaned"
                echo "  $0 --version                          Show version"
                echo "  $0 --clean --force                  Clean without confirmation"
                exit 0
                ;;
            *)
                echo -e "${RED}Unknown option: $1${NC}"
                echo "Use --help for usage."
                exit 1
                ;;
        esac
        shift
    done

    # Validation: --auto requires --profile
    if [[ "$AUTO_MODE" == true && -z "$AUTO_PROFILE" ]]; then
        echo -e "${RED}Error: --auto requires --profile <name>${NC}"
        exit 1
    fi

    # Validation: --profile value must be standard, high, or paranoid
    if [[ -n "$AUTO_PROFILE" ]]; then
        case "$AUTO_PROFILE" in
            standard|high|paranoid) ;;
            *)
                echo -e "${RED}Error: --profile must be one of: standard, high, paranoid (got '${AUTO_PROFILE}')${NC}"
                exit 1
                ;;
        esac
    fi

    # Validation: --quiet requires --auto or --audit
    if [[ "$QUIET_MODE" == true && "$AUTO_MODE" != true && "$AUDIT_MODE" != true ]]; then
        echo -e "${RED}Error: --quiet requires --auto or --audit${NC}"
        exit 1
    fi

    # Validation: --force requires --clean
    if [[ "$CLEAN_FORCE" == true && "$CLEAN_MODE" != true ]]; then
        echo -e "${RED}Error: --force requires --clean${NC}"
        exit 1
    fi
}

# ═══════════════════════════════════════════════════════════════════
# SYSTEM CLEANER — TARGET AVAILABILITY
# ═══════════════════════════════════════════════════════════════════
clean_target_available() {
    local target="$1"
    case "$target" in
        safari|saved-app-state|quicklook-thumbs|ds-store|xcode-derived|cocoapods-cache|messages-attachments)
            [[ "$OS" == "macos" ]] ;;
        chrome)
            if [[ "$OS" == "macos" ]]; then
                [[ -d "$HOME/Library/Caches/Google/Chrome" ]]
            else
                [[ -d "$HOME/.cache/google-chrome" ]]
            fi ;;
        firefox)
            if [[ "$OS" == "macos" ]]; then
                [[ -d "$HOME/Library/Caches/Firefox" || -d "$HOME/Library/Application Support/Firefox" ]]
            else
                [[ -d "$HOME/.cache/mozilla/firefox" || -d "$HOME/.mozilla/firefox" ]]
            fi ;;
        arc)
            [[ "$OS" == "macos" && -d "$HOME/Library/Caches/Arc" ]] ;;
        edge)
            if [[ "$OS" == "macos" ]]; then
                [[ -d "$HOME/Library/Caches/Microsoft Edge" ]]
            else
                [[ -d "$HOME/.cache/microsoft-edge" ]]
            fi ;;
        homebrew-cache) command -v brew &>/dev/null ;;
        npm-cache) command -v npm &>/dev/null ;;
        yarn-cache) command -v yarn &>/dev/null ;;
        pip-cache) command -v pip &>/dev/null || command -v pip3 &>/dev/null ;;
        cargo-cache) [[ -d "$HOME/.cargo" ]] ;;
        go-cache) command -v go &>/dev/null ;;
        docker-cruft) command -v docker &>/dev/null ;;
        ide-caches)
            [[ -d "$HOME/Library/Application Support/Code" ]] || \
            [[ -d "$HOME/.config/Code" ]] || \
            [[ -d "$HOME/Library/Caches/JetBrains" ]] || \
            [[ -d "$HOME/.cache/JetBrains" ]] ;;
        mail-cache)
            if [[ "$OS" == "macos" ]]; then
                [[ -d "$HOME/Library/Containers/com.apple.mail" ]]
            else
                [[ -d "$HOME/.thunderbird" ]]
            fi ;;
        *) return 0 ;;
    esac
}

# ═══════════════════════════════════════════════════════════════════
# SYSTEM CLEANER — PICKER UI
# ═══════════════════════════════════════════════════════════════════
clean_picker() {
    print_section "Select Categories"
    echo -e "  ${BROWN}Toggle categories, then press Enter to continue.${NC}"
    echo ""

    # Start with all selected
    for cat in "${CLEAN_CAT_ORDER[@]}"; do
        CLEAN_CATEGORIES[$cat]=1
    done

    local first_display=true
    while true; do
        # Add visual separator between iterations (except first time)
        if [[ "$first_display" != true ]]; then
            echo ""
            echo -e "${BROWN}────────────────────────────────────────────────────${NC}"
            echo ""
        fi
        first_display=false

        for i in "${!CLEAN_CAT_ORDER[@]}"; do
            local cat="${CLEAN_CAT_ORDER[$i]}"
            local num=$((i + 1))
            local mark=" "
            [[ "${CLEAN_CATEGORIES[$cat]}" == "1" ]] && mark="*"
            echo -e "  ${GREEN}[$num]${NC} [${mark}] ${CLEAN_CAT_NAMES[$cat]}"
        done
        echo ""
        echo -e "  ${GREEN}[A]${NC} Select All    ${GREEN}[N]${NC} Select None"
        echo ""
        echo -ne "  ${BOLD}Toggle (1-7, A, N) or Enter to continue:${NC} "
        read -r input

        if [[ -z "$input" ]]; then
            local any=0
            for cat in "${CLEAN_CAT_ORDER[@]}"; do
                [[ "${CLEAN_CATEGORIES[$cat]}" == "1" ]] && any=1 && break
            done
            if [[ $any -eq 0 ]]; then
                echo -e "  ${RED}Select at least one category.${NC}"
                echo ""
                sleep 1
                continue
            fi
            # Show confirmation before proceeding
            echo ""
            echo -e "  ${GREEN}✓ Categories selected. Proceeding...${NC}"
            echo ""
            break
        fi

        case "${input,,}" in
            a)
                for cat in "${CLEAN_CAT_ORDER[@]}"; do
                    CLEAN_CATEGORIES[$cat]=1
                done
                echo ""
                echo -e "  ${GREEN}✓ All categories selected${NC}"
                echo ""
                echo -ne "  ${BOLD}${GREEN}Press Enter to continue (or toggle more):${NC} "
                read -r continue_input
                if [[ -z "$continue_input" ]]; then
                    echo ""
                    echo -e "  ${GREEN}✓ Categories selected. Proceeding...${NC}"
                    echo ""
                    break
                fi
                continue
                ;;
            n)
                for cat in "${CLEAN_CAT_ORDER[@]}"; do
                    CLEAN_CATEGORIES[$cat]=0
                done
                echo -e "  ${BROWN}All categories deselected${NC}"
                ;;
            [1-7])
                local cat="${CLEAN_CAT_ORDER[$((input - 1))]}"
                if [[ "${CLEAN_CATEGORIES[$cat]}" == "1" ]]; then
                    CLEAN_CATEGORIES[$cat]=0
                    echo -e "  ${BROWN}Deselected: ${CLEAN_CAT_NAMES[$cat]}${NC}"
                else
                    CLEAN_CATEGORIES[$cat]=1
                    echo -e "  ${GREEN}Selected: ${CLEAN_CAT_NAMES[$cat]}${NC}"
                fi ;;
            *)
                echo -e "  ${RED}Invalid input.${NC}" ;;
        esac
    done

    # Populate CLEAN_TARGETS
    for cat in "${CLEAN_CAT_ORDER[@]}"; do
        if [[ "${CLEAN_CATEGORIES[$cat]}" == "1" ]]; then
            for target in ${CLEAN_CAT_TARGETS[$cat]}; do
                if clean_target_available "$target"; then
                    CLEAN_TARGETS[$target]=1
                fi
            done
        fi
    done
}

clean_drilldown() {
    print_section "Fine-Tune Selection"
    echo -e "  ${BROWN}Optionally drill into categories to toggle individual targets.${NC}"
    echo ""
    echo -ne "  ${BOLD}Drill into individual targets? (y/N):${NC} "
    read -r drill
    if [[ "${drill,,}" != "y" ]]; then
        echo ""
        echo -e "  ${GREEN}Proceeding with category-level selection...${NC}"
        echo ""
        return
    fi

    for cat in "${CLEAN_CAT_ORDER[@]}"; do
        [[ "${CLEAN_CATEGORIES[$cat]}" != "1" ]] && continue

        local -a avail=()
        for target in ${CLEAN_CAT_TARGETS[$cat]}; do
            if clean_target_available "$target"; then
                avail+=("$target")
            fi
        done
        [[ ${#avail[@]} -eq 0 ]] && continue

        echo ""
        echo -e "  ${BOLD}── ${CLEAN_CAT_NAMES[$cat]} ──${NC}"

        while true; do
            for i in "${!avail[@]}"; do
                local t="${avail[$i]}"
                local num=$((i + 1))
                local mark=" "
                [[ "${CLEAN_TARGETS[$t]:-0}" == "1" ]] && mark="*"
                echo -e "    ${GREEN}[$num]${NC} [${mark}] ${CLEAN_TARGET_NAMES[$t]}"
            done
            echo ""
            echo -ne "    ${BOLD}Toggle (1-${#avail[@]}) or Enter to keep:${NC} "
            read -r input

            [[ -z "$input" ]] && break

            if [[ "$input" =~ ^[0-9]+$ ]] && (( input >= 1 && input <= ${#avail[@]} )); then
                local t="${avail[$((input - 1))]}"
                if [[ "${CLEAN_TARGETS[$t]:-0}" == "1" ]]; then
                    CLEAN_TARGETS[$t]=0
                else
                    CLEAN_TARGETS[$t]=1
                fi
            else
                echo -e "    ${RED}Invalid input.${NC}"
            fi
            echo ""
        done
    done
}

# ═══════════════════════════════════════════════════════════════════
# SYSTEM CLEANER — SCAN HELPERS
# ═══════════════════════════════════════════════════════════════════
format_bytes() {
    local bytes="$1"
    if [[ $bytes -ge 1073741824 ]]; then
        echo "$(( bytes / 1073741824 )).$(( (bytes % 1073741824) * 10 / 1073741824 )) GB"
    elif [[ $bytes -ge 1048576 ]]; then
        echo "$(( bytes / 1048576 )) MB"
    elif [[ $bytes -ge 1024 ]]; then
        echo "$(( bytes / 1024 )) KB"
    else
        echo "${bytes} B"
    fi
}

scan_directory() {
    local dir="$1"
    SCAN_FILE_COUNT=0
    SCAN_BYTE_COUNT=0
    if [[ -d "$dir" ]]; then
        local result
        if [[ "$OS" == "macos" ]]; then
            result=$(find "$dir" -not -type l -type f -print0 2>/dev/null | xargs -0 stat -f '%z' 2>/dev/null | awk '{s+=$1; c++} END {printf "%d %d", c, s}')
        else
            result=$(find "$dir" -not -type l -type f -printf '%s\n' 2>/dev/null | awk '{s+=$1; c++} END {printf "%d %d", c, s}')
        fi
        SCAN_FILE_COUNT=$(echo "$result" | awk '{print $1}')
        SCAN_BYTE_COUNT=$(echo "$result" | awk '{print $2}')
        SCAN_FILE_COUNT=${SCAN_FILE_COUNT:-0}
        SCAN_BYTE_COUNT=${SCAN_BYTE_COUNT:-0}
    fi
}

scan_find() {
    local dir="$1"; shift
    SCAN_FILE_COUNT=0
    SCAN_BYTE_COUNT=0
    if [[ -d "$dir" ]]; then
        local result
        if [[ "$OS" == "macos" ]]; then
            result=$(find "$dir" "$@" -not -type l -type f -print0 2>/dev/null | xargs -0 stat -f '%z' 2>/dev/null | awk '{s+=$1; c++} END {printf "%d %d", c, s}')
        else
            result=$(find "$dir" "$@" -not -type l -type f -printf '%s\n' 2>/dev/null | awk '{s+=$1; c++} END {printf "%d %d", c, s}')
        fi
        SCAN_FILE_COUNT=$(echo "$result" | awk '{print $1}')
        SCAN_BYTE_COUNT=$(echo "$result" | awk '{print $2}')
        SCAN_FILE_COUNT=${SCAN_FILE_COUNT:-0}
        SCAN_BYTE_COUNT=${SCAN_BYTE_COUNT:-0}
    fi
}

# ═══════════════════════════════════════════════════════════════════
# SYSTEM CLEANER — PER-TARGET SCAN FUNCTIONS
# ═══════════════════════════════════════════════════════════════════
scan_system_cache() {
    if [[ "$OS" == "macos" ]]; then
        scan_directory "/Library/Caches"
    else
        local total_f=0 total_b=0
        for d in /var/cache/apt/archives /var/cache/dnf /var/cache/pacman/pkg; do
            if [[ -d "$d" ]]; then
                scan_directory "$d"
                total_f=$((total_f + SCAN_FILE_COUNT))
                total_b=$((total_b + SCAN_BYTE_COUNT))
            fi
        done
        SCAN_FILE_COUNT=$total_f
        SCAN_BYTE_COUNT=$total_b
    fi
    CLEAN_SCAN_FILES[system-cache]=$SCAN_FILE_COUNT
    CLEAN_SCAN_BYTES[system-cache]=$SCAN_BYTE_COUNT
}

scan_system_logs() {
    if [[ "$OS" == "macos" ]]; then
        local total_f=0 total_b=0
        for d in /Library/Logs /var/log/asl; do
            if [[ -d "$d" ]]; then
                scan_directory "$d"
                total_f=$((total_f + SCAN_FILE_COUNT))
                total_b=$((total_b + SCAN_BYTE_COUNT))
            fi
        done
        SCAN_FILE_COUNT=$total_f
        SCAN_BYTE_COUNT=$total_b
    else
        SCAN_FILE_COUNT=0
        SCAN_BYTE_COUNT=0
        if command -v journalctl &>/dev/null; then
            local usage
            usage=$(journalctl --disk-usage 2>/dev/null | grep -oE '[0-9.]+ [KMGT]' | head -1)
            if [[ -n "$usage" ]]; then
                local num unit
                num=$(echo "$usage" | awk '{print $1}')
                unit=$(echo "$usage" | awk '{print $2}')
                case "$unit" in
                    G) SCAN_BYTE_COUNT=$(echo "$num * 1073741824" | bc 2>/dev/null | cut -d. -f1) ;;
                    M) SCAN_BYTE_COUNT=$(echo "$num * 1048576" | bc 2>/dev/null | cut -d. -f1) ;;
                    K) SCAN_BYTE_COUNT=$(echo "$num * 1024" | bc 2>/dev/null | cut -d. -f1) ;;
                esac
                SCAN_BYTE_COUNT=${SCAN_BYTE_COUNT:-0}
            fi
        fi
    fi
    CLEAN_SCAN_FILES[system-logs]=$SCAN_FILE_COUNT
    CLEAN_SCAN_BYTES[system-logs]=$SCAN_BYTE_COUNT
}

scan_diagnostic_reports() {
    if [[ "$OS" == "macos" ]]; then
        scan_directory "/Library/Logs/DiagnosticReports"
    else
        scan_directory "/var/crash"
    fi
    CLEAN_SCAN_FILES[diagnostic-reports]=$SCAN_FILE_COUNT
    CLEAN_SCAN_BYTES[diagnostic-reports]=$SCAN_BYTE_COUNT
}

scan_dns_cache() {
    CLEAN_SCAN_FILES[dns-cache]=0
    CLEAN_SCAN_BYTES[dns-cache]=0
}

scan_user_cache() {
    if [[ "$OS" == "macos" ]]; then
        scan_directory "$HOME/Library/Caches"
    else
        scan_directory "$HOME/.cache"
    fi
    CLEAN_SCAN_FILES[user-cache]=$SCAN_FILE_COUNT
    CLEAN_SCAN_BYTES[user-cache]=$SCAN_BYTE_COUNT
}

scan_user_logs() {
    if [[ "$OS" == "macos" ]]; then
        scan_directory "$HOME/Library/Logs"
    else
        scan_directory "$HOME/.local/share/logs"
    fi
    CLEAN_SCAN_FILES[user-logs]=$SCAN_FILE_COUNT
    CLEAN_SCAN_BYTES[user-logs]=$SCAN_BYTE_COUNT
}

scan_saved_app_state() {
    scan_directory "$HOME/Library/Saved Application State"
    CLEAN_SCAN_FILES[saved-app-state]=$SCAN_FILE_COUNT
    CLEAN_SCAN_BYTES[saved-app-state]=$SCAN_BYTE_COUNT
}

scan_safari() {
    local total_f=0 total_b=0
    for d in "$HOME/Library/Caches/com.apple.Safari" \
             "$HOME/Library/Safari/LocalStorage" \
             "$HOME/Library/Safari/Databases" \
             "$HOME/Library/Cookies"; do
        scan_directory "$d"
        total_f=$((total_f + SCAN_FILE_COUNT))
        total_b=$((total_b + SCAN_BYTE_COUNT))
    done
    CLEAN_SCAN_FILES[safari]=$total_f
    CLEAN_SCAN_BYTES[safari]=$total_b
}

scan_chrome() {
    if [[ "$OS" == "macos" ]]; then
        scan_directory "$HOME/Library/Caches/Google/Chrome"
    else
        scan_directory "$HOME/.cache/google-chrome"
    fi
    CLEAN_SCAN_FILES[chrome]=$SCAN_FILE_COUNT
    CLEAN_SCAN_BYTES[chrome]=$SCAN_BYTE_COUNT
}

scan_firefox() {
    if [[ "$OS" == "macos" ]]; then
        scan_directory "$HOME/Library/Caches/Firefox"
    else
        scan_directory "$HOME/.cache/mozilla/firefox"
    fi
    CLEAN_SCAN_FILES[firefox]=$SCAN_FILE_COUNT
    CLEAN_SCAN_BYTES[firefox]=$SCAN_BYTE_COUNT
}

scan_arc() {
    scan_directory "$HOME/Library/Caches/Arc"
    CLEAN_SCAN_FILES[arc]=$SCAN_FILE_COUNT
    CLEAN_SCAN_BYTES[arc]=$SCAN_BYTE_COUNT
}

scan_edge() {
    if [[ "$OS" == "macos" ]]; then
        scan_directory "$HOME/Library/Caches/Microsoft Edge"
    else
        scan_directory "$HOME/.cache/microsoft-edge"
    fi
    CLEAN_SCAN_FILES[edge]=$SCAN_FILE_COUNT
    CLEAN_SCAN_BYTES[edge]=$SCAN_BYTE_COUNT
}

scan_recent_items() {
    if [[ "$OS" == "macos" ]]; then
        scan_directory "$HOME/Library/Application Support/com.apple.sharedfilelist"
    else
        SCAN_FILE_COUNT=0; SCAN_BYTE_COUNT=0
        if [[ -f "$HOME/.local/share/recently-used.xbel" ]]; then
            SCAN_FILE_COUNT=1
            SCAN_BYTE_COUNT=$(stat -c '%s' "$HOME/.local/share/recently-used.xbel" 2>/dev/null || echo 0)
        fi
    fi
    CLEAN_SCAN_FILES[recent-items]=$SCAN_FILE_COUNT
    CLEAN_SCAN_BYTES[recent-items]=$SCAN_BYTE_COUNT
}

scan_quicklook_thumbs() {
    scan_directory "$HOME/Library/Caches/com.apple.QuickLook.thumbnailcache"
    CLEAN_SCAN_FILES[quicklook-thumbs]=$SCAN_FILE_COUNT
    CLEAN_SCAN_BYTES[quicklook-thumbs]=$SCAN_BYTE_COUNT
}

scan_ds_store() {
    scan_find "$HOME" -name ".DS_Store" -maxdepth 10
    CLEAN_SCAN_FILES[ds-store]=$SCAN_FILE_COUNT
    CLEAN_SCAN_BYTES[ds-store]=$SCAN_BYTE_COUNT
}

scan_clipboard() {
    CLEAN_SCAN_FILES[clipboard]=0
    CLEAN_SCAN_BYTES[clipboard]=0
}

scan_search_metadata() {
    CLEAN_SCAN_FILES[search-metadata]=0
    CLEAN_SCAN_BYTES[search-metadata]=0
}

scan_xcode_derived() {
    scan_directory "$HOME/Library/Developer/Xcode/DerivedData"
    CLEAN_SCAN_FILES[xcode-derived]=$SCAN_FILE_COUNT
    CLEAN_SCAN_BYTES[xcode-derived]=$SCAN_BYTE_COUNT
}

scan_homebrew_cache() {
    if command -v brew &>/dev/null; then
        local cache_dir
        cache_dir=$(brew --cache 2>/dev/null)
        scan_directory "$cache_dir"
    else
        SCAN_FILE_COUNT=0; SCAN_BYTE_COUNT=0
    fi
    CLEAN_SCAN_FILES[homebrew-cache]=$SCAN_FILE_COUNT
    CLEAN_SCAN_BYTES[homebrew-cache]=$SCAN_BYTE_COUNT
}

scan_npm_cache() {
    if command -v npm &>/dev/null; then
        local cache_dir
        cache_dir=$(npm config get cache 2>/dev/null)
        scan_directory "$cache_dir"
    else
        SCAN_FILE_COUNT=0; SCAN_BYTE_COUNT=0
    fi
    CLEAN_SCAN_FILES[npm-cache]=$SCAN_FILE_COUNT
    CLEAN_SCAN_BYTES[npm-cache]=$SCAN_BYTE_COUNT
}

scan_yarn_cache() {
    if command -v yarn &>/dev/null; then
        local cache_dir
        cache_dir=$(yarn cache dir 2>/dev/null)
        scan_directory "$cache_dir"
    else
        SCAN_FILE_COUNT=0; SCAN_BYTE_COUNT=0
    fi
    CLEAN_SCAN_FILES[yarn-cache]=$SCAN_FILE_COUNT
    CLEAN_SCAN_BYTES[yarn-cache]=$SCAN_BYTE_COUNT
}

scan_pip_cache() {
    local pip_cmd="pip3"
    command -v pip3 &>/dev/null || pip_cmd="pip"
    if command -v "$pip_cmd" &>/dev/null; then
        local cache_dir
        cache_dir=$($pip_cmd cache dir 2>/dev/null)
        scan_directory "$cache_dir"
    else
        SCAN_FILE_COUNT=0; SCAN_BYTE_COUNT=0
    fi
    CLEAN_SCAN_FILES[pip-cache]=$SCAN_FILE_COUNT
    CLEAN_SCAN_BYTES[pip-cache]=$SCAN_BYTE_COUNT
}

scan_cargo_cache() {
    scan_directory "$HOME/.cargo/registry/cache"
    CLEAN_SCAN_FILES[cargo-cache]=$SCAN_FILE_COUNT
    CLEAN_SCAN_BYTES[cargo-cache]=$SCAN_BYTE_COUNT
}

scan_go_cache() {
    if command -v go &>/dev/null; then
        local cache_dir
        cache_dir=$(go env GOCACHE 2>/dev/null)
        scan_directory "$cache_dir"
    else
        SCAN_FILE_COUNT=0; SCAN_BYTE_COUNT=0
    fi
    CLEAN_SCAN_FILES[go-cache]=$SCAN_FILE_COUNT
    CLEAN_SCAN_BYTES[go-cache]=$SCAN_BYTE_COUNT
}

scan_cocoapods_cache() {
    scan_directory "$HOME/Library/Caches/CocoaPods"
    CLEAN_SCAN_FILES[cocoapods-cache]=$SCAN_FILE_COUNT
    CLEAN_SCAN_BYTES[cocoapods-cache]=$SCAN_BYTE_COUNT
}

scan_docker_cruft() {
    SCAN_FILE_COUNT=0
    SCAN_BYTE_COUNT=0
    if command -v docker &>/dev/null; then
        local usage
        usage=$(docker system df --format '{{.Size}}' 2>/dev/null | head -1)
        SCAN_FILE_COUNT=0
        SCAN_BYTE_COUNT=0
    fi
    CLEAN_SCAN_FILES[docker-cruft]=$SCAN_FILE_COUNT
    CLEAN_SCAN_BYTES[docker-cruft]=$SCAN_BYTE_COUNT
}

scan_ide_caches() {
    local total_f=0 total_b=0
    for d in "$HOME/Library/Application Support/Code/Cache" \
             "$HOME/.config/Code/Cache" \
             "$HOME/Library/Caches/JetBrains" \
             "$HOME/.cache/JetBrains"; do
        if [[ -d "$d" ]]; then
            scan_directory "$d"
            total_f=$((total_f + SCAN_FILE_COUNT))
            total_b=$((total_b + SCAN_BYTE_COUNT))
        fi
    done
    CLEAN_SCAN_FILES[ide-caches]=$total_f
    CLEAN_SCAN_BYTES[ide-caches]=$total_b
}

scan_trash() {
    if [[ "$OS" == "macos" ]]; then
        scan_directory "$HOME/.Trash"
    else
        scan_directory "$HOME/.local/share/Trash"
    fi
    CLEAN_SCAN_FILES[trash]=$SCAN_FILE_COUNT
    CLEAN_SCAN_BYTES[trash]=$SCAN_BYTE_COUNT
}

scan_old_downloads() {
    scan_find "$HOME/Downloads" -mtime +30 -maxdepth 1
    CLEAN_SCAN_FILES[old-downloads]=$SCAN_FILE_COUNT
    CLEAN_SCAN_BYTES[old-downloads]=$SCAN_BYTE_COUNT
}

scan_mail_cache() {
    if [[ "$OS" == "macos" ]]; then
        scan_directory "$HOME/Library/Containers/com.apple.mail/Data/Library/Caches"
    else
        scan_directory "$HOME/.thunderbird"
    fi
    CLEAN_SCAN_FILES[mail-cache]=$SCAN_FILE_COUNT
    CLEAN_SCAN_BYTES[mail-cache]=$SCAN_BYTE_COUNT
}

scan_messages_attachments() {
    scan_directory "$HOME/Library/Messages/Attachments"
    CLEAN_SCAN_FILES[messages-attachments]=$SCAN_FILE_COUNT
    CLEAN_SCAN_BYTES[messages-attachments]=$SCAN_BYTE_COUNT
}

# ═══════════════════════════════════════════════════════════════════
# SYSTEM CLEANER — SCAN DISPATCHER & PREVIEW
# ═══════════════════════════════════════════════════════════════════
scan_target() {
    local target="$1"
    local func="scan_${target//-/_}"
    if declare -f "$func" &>/dev/null; then
        "$func"
    else
        CLEAN_SCAN_FILES[$target]=0
        CLEAN_SCAN_BYTES[$target]=0
    fi
}

clean_preview() {
    print_section "Scanning..."

    local -a ordered_targets=()
    for cat in "${CLEAN_CAT_ORDER[@]}"; do
        for target in ${CLEAN_CAT_TARGETS[$cat]}; do
            if [[ "${CLEAN_TARGETS[$target]:-0}" == "1" ]]; then
                ordered_targets+=("$target")
            fi
        done
    done

    for target in "${ordered_targets[@]}"; do
        echo -ne "  ${BROWN}⟳${NC} Scanning ${CLEAN_TARGET_NAMES[$target]}...\r"
        scan_target "$target"
        echo -ne "\033[K"
    done

    local total_files=0 total_bytes=0
    echo ""
    echo -e "  ${BOLD}${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
    printf "  ${BOLD}${GREEN}║${NC}%-58s${BOLD}${GREEN}║${NC}\n" "                   CLEANING PREVIEW"
    echo -e "  ${BOLD}${GREEN}╠══════════════════════════════════════════════════════════╣${NC}"
    printf "  ${BOLD}${GREEN}║${NC} %-33s %7s %9s %7s ${BOLD}${GREEN}║${NC}\n" "Target" "Files" "Size" "Status"
    printf "  ${BROWN}${GREEN}║${NC} %-56s ${GREEN}║${NC}\n" "────────────────────────────────────────────────────────"

    for target in "${ordered_targets[@]}"; do
        local files="${CLEAN_SCAN_FILES[$target]:-0}"
        local bytes="${CLEAN_SCAN_BYTES[$target]:-0}"
        local status="Ready"
        local size_str
        if [[ $bytes -gt 0 ]]; then
            size_str=$(format_bytes "$bytes")
        elif [[ $files -gt 0 ]]; then
            size_str="—"
        else
            case "$target" in
                dns-cache|clipboard|search-metadata) size_str="—"; status="Ready" ;;
                *) status="Empty"; size_str="—" ;;
            esac
        fi

        local file_str="$files"
        [[ $files -eq 0 ]] && file_str="—"

        local color="$NC"
        [[ "$status" == "Empty" ]] && color="$BROWN"

        printf "  ${GREEN}║${NC}${color} %-33s %7s %9s %7s ${NC}${GREEN}║${NC}\n" \
            "${CLEAN_TARGET_NAMES[$target]}" "$file_str" "$size_str" "$status"

        total_files=$((total_files + files))
        total_bytes=$((total_bytes + bytes))
    done

    printf "  ${BROWN}${GREEN}║${NC} %-56s ${GREEN}║${NC}\n" "────────────────────────────────────────────────────────"
    printf "  ${BOLD}${GREEN}║${NC} %-33s %7s %9s ${BOLD}${GREEN}║${NC}\n" "TOTAL" "$total_files" "$(format_bytes $total_bytes)"
    echo -e "  ${BOLD}${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"

    CLEAN_TOTAL_SCAN_FILES=$total_files
    CLEAN_TOTAL_SCAN_BYTES=$total_bytes
}

# ═══════════════════════════════════════════════════════════════════
# SYSTEM CLEANER — CLEAN HELPERS & SAFETY
# ═══════════════════════════════════════════════════════════════════

clean_log() {
    local action="$1" message="$2"
    local entry="$(date '+%Y-%m-%d %H:%M:%S') [$action] $message"
    CLEAN_LOG+=("$entry")
}

browser_running() {
    local process_name="$1"
    pgrep -x "$process_name" &>/dev/null
}

safe_rm_contents() {
    local dir="$1"
    local use_root="${2:-false}"
    if [[ ! -d "$dir" ]]; then return 1; fi
    local real_dir
    real_dir=$(cd "$dir" 2>/dev/null && pwd -P)
    if [[ -z "$real_dir" ]]; then return 1; fi

    local files_removed=0 bytes_freed=0 files_processed=0
    while IFS= read -r -d '' file; do
        ((files_processed++))

        # Show progress every 100 files
        if (( files_processed % 100 == 0 )); then
            echo -ne "\r  ⟳ Cleaning... ($files_processed files processed)\033[K"
        fi

        local mod_time
        if [[ "$OS" == "macos" ]]; then
            mod_time=$(stat -f '%m' "$file" 2>/dev/null)
        else
            mod_time=$(stat -c '%Y' "$file" 2>/dev/null)
        fi
        local now
        now=$(date +%s)
        if [[ -n "$mod_time" && $(( now - mod_time )) -lt 60 ]]; then
            clean_log "SKIP" "$file (modified < 60s ago)"
            continue
        fi

        local fsize
        if [[ "$OS" == "macos" ]]; then
            fsize=$(stat -f '%z' "$file" 2>/dev/null || echo 0)
        else
            fsize=$(stat -c '%s' "$file" 2>/dev/null || echo 0)
        fi

        local rm_ok=false
        if [[ "$use_root" == true ]]; then
            run_as_root rm -f "$file" 2>/dev/null && rm_ok=true
        else
            rm -f "$file" 2>/dev/null && rm_ok=true
        fi

        if $rm_ok; then
            bytes_freed=$((bytes_freed + fsize))
            ((files_removed++))
            clean_log "CLEAN" "Removed $file ($(format_bytes "$fsize"))"
        else
            clean_log "FAIL" "$file (permission denied)"
        fi
    done < <(find "$real_dir" -not -type l -type f -print0 2>/dev/null)

    # Clear progress line
    echo -ne "\r\033[K"

    if [[ "$use_root" == true ]]; then
        run_as_root find "$real_dir" -mindepth 1 -type d -empty -delete 2>/dev/null
    else
        find "$real_dir" -mindepth 1 -type d -empty -delete 2>/dev/null
    fi

    SAFE_RM_FILES=$files_removed
    SAFE_RM_BYTES=$bytes_freed
}

# ═══════════════════════════════════════════════════════════════════
# SYSTEM CLEANER — PER-TARGET CLEAN FUNCTIONS
# ═══════════════════════════════════════════════════════════════════

clean_system_cache() {
    if [[ "$OS" == "macos" ]]; then
        safe_rm_contents "/Library/Caches" true
    else
        local total_f=0 total_b=0
        for d in /var/cache/apt/archives /var/cache/dnf /var/cache/pacman/pkg; do
            if [[ -d "$d" ]]; then
                safe_rm_contents "$d" true
                total_f=$((total_f + SAFE_RM_FILES))
                total_b=$((total_b + SAFE_RM_BYTES))
            fi
        done
        SAFE_RM_FILES=$total_f; SAFE_RM_BYTES=$total_b
    fi
    CLEAN_RESULT_FILES[system-cache]=$SAFE_RM_FILES
    CLEAN_RESULT_BYTES[system-cache]=$SAFE_RM_BYTES
    [[ $SAFE_RM_FILES -gt 0 ]] && CLEAN_RESULT_STATUS[system-cache]="pass" || CLEAN_RESULT_STATUS[system-cache]="skip"
}

clean_system_logs() {
    if [[ "$OS" == "macos" ]]; then
        local total_f=0 total_b=0
        for d in /Library/Logs /var/log/asl; do
            if [[ -d "$d" ]]; then
                safe_rm_contents "$d" true
                total_f=$((total_f + SAFE_RM_FILES))
                total_b=$((total_b + SAFE_RM_BYTES))
            fi
        done
        SAFE_RM_FILES=$total_f; SAFE_RM_BYTES=$total_b
    else
        SAFE_RM_FILES=0; SAFE_RM_BYTES=0
        if command -v journalctl &>/dev/null; then
            journalctl --vacuum-time=7d &>/dev/null && clean_log "CLEAN" "Vacuumed journald logs (7d retention)"
        fi
    fi
    CLEAN_RESULT_FILES[system-logs]=$SAFE_RM_FILES
    CLEAN_RESULT_BYTES[system-logs]=$SAFE_RM_BYTES
    CLEAN_RESULT_STATUS[system-logs]="pass"
}

clean_diagnostic_reports() {
    if [[ "$OS" == "macos" ]]; then
        safe_rm_contents "/Library/Logs/DiagnosticReports" true
    else
        safe_rm_contents "/var/crash" true
    fi
    CLEAN_RESULT_FILES[diagnostic-reports]=$SAFE_RM_FILES
    CLEAN_RESULT_BYTES[diagnostic-reports]=$SAFE_RM_BYTES
    [[ $SAFE_RM_FILES -gt 0 ]] && CLEAN_RESULT_STATUS[diagnostic-reports]="pass" || CLEAN_RESULT_STATUS[diagnostic-reports]="skip"
}

clean_dns_cache() {
    if [[ "$OS" == "macos" ]]; then
        run_as_root dscacheutil -flushcache 2>/dev/null && run_as_root killall -HUP mDNSResponder 2>/dev/null
        clean_log "CLEAN" "Flushed DNS cache (dscacheutil + mDNSResponder)"
    else
        if command -v systemd-resolve &>/dev/null; then
            systemd-resolve --flush-caches 2>/dev/null
        elif command -v resolvectl &>/dev/null; then
            resolvectl flush-caches 2>/dev/null
        fi
        clean_log "CLEAN" "Flushed DNS cache"
    fi
    CLEAN_RESULT_FILES[dns-cache]=0
    CLEAN_RESULT_BYTES[dns-cache]=0
    CLEAN_RESULT_STATUS[dns-cache]="pass"
}

clean_user_cache() {
    if [[ "$OS" == "macos" ]]; then
        safe_rm_contents "$HOME/Library/Caches"
    else
        safe_rm_contents "$HOME/.cache"
    fi
    CLEAN_RESULT_FILES[user-cache]=$SAFE_RM_FILES
    CLEAN_RESULT_BYTES[user-cache]=$SAFE_RM_BYTES
    [[ $SAFE_RM_FILES -gt 0 ]] && CLEAN_RESULT_STATUS[user-cache]="pass" || CLEAN_RESULT_STATUS[user-cache]="skip"
}

clean_user_logs() {
    if [[ "$OS" == "macos" ]]; then
        safe_rm_contents "$HOME/Library/Logs"
    else
        safe_rm_contents "$HOME/.local/share/logs"
    fi
    CLEAN_RESULT_FILES[user-logs]=$SAFE_RM_FILES
    CLEAN_RESULT_BYTES[user-logs]=$SAFE_RM_BYTES
    [[ $SAFE_RM_FILES -gt 0 ]] && CLEAN_RESULT_STATUS[user-logs]="pass" || CLEAN_RESULT_STATUS[user-logs]="skip"
}

clean_saved_app_state() {
    safe_rm_contents "$HOME/Library/Saved Application State"
    CLEAN_RESULT_FILES[saved-app-state]=$SAFE_RM_FILES
    CLEAN_RESULT_BYTES[saved-app-state]=$SAFE_RM_BYTES
    [[ $SAFE_RM_FILES -gt 0 ]] && CLEAN_RESULT_STATUS[saved-app-state]="pass" || CLEAN_RESULT_STATUS[saved-app-state]="skip"
}

clean_safari() {
    if browser_running "Safari"; then
        echo -e "  ${RED}⚠${NC}  Safari is running — close it first to clean"
        clean_log "SKIP" "Safari (browser running)"
        CLEAN_RESULT_FILES[safari]=0; CLEAN_RESULT_BYTES[safari]=0; CLEAN_RESULT_STATUS[safari]="fail"
        return
    fi
    local total_f=0 total_b=0
    for d in "$HOME/Library/Caches/com.apple.Safari" \
             "$HOME/Library/Safari/LocalStorage" \
             "$HOME/Library/Safari/Databases" \
             "$HOME/Library/Cookies"; do
        safe_rm_contents "$d"
        total_f=$((total_f + SAFE_RM_FILES))
        total_b=$((total_b + SAFE_RM_BYTES))
    done
    CLEAN_RESULT_FILES[safari]=$total_f
    CLEAN_RESULT_BYTES[safari]=$total_b
    [[ $total_f -gt 0 ]] && CLEAN_RESULT_STATUS[safari]="pass" || CLEAN_RESULT_STATUS[safari]="skip"
}

clean_chrome() {
    if browser_running "Google Chrome"; then
        echo -e "  ${RED}⚠${NC}  Chrome is running — close it first to clean"
        clean_log "SKIP" "Chrome (browser running)"
        CLEAN_RESULT_FILES[chrome]=0; CLEAN_RESULT_BYTES[chrome]=0; CLEAN_RESULT_STATUS[chrome]="fail"
        return
    fi
    if [[ "$OS" == "macos" ]]; then
        safe_rm_contents "$HOME/Library/Caches/Google/Chrome"
    else
        safe_rm_contents "$HOME/.cache/google-chrome"
    fi
    CLEAN_RESULT_FILES[chrome]=$SAFE_RM_FILES
    CLEAN_RESULT_BYTES[chrome]=$SAFE_RM_BYTES
    [[ $SAFE_RM_FILES -gt 0 ]] && CLEAN_RESULT_STATUS[chrome]="pass" || CLEAN_RESULT_STATUS[chrome]="skip"
}

clean_firefox() {
    if browser_running "firefox"; then
        echo -e "  ${RED}⚠${NC}  Firefox is running — close it first to clean"
        clean_log "SKIP" "Firefox (browser running)"
        CLEAN_RESULT_FILES[firefox]=0; CLEAN_RESULT_BYTES[firefox]=0; CLEAN_RESULT_STATUS[firefox]="fail"
        return
    fi
    if [[ "$OS" == "macos" ]]; then
        safe_rm_contents "$HOME/Library/Caches/Firefox"
    else
        safe_rm_contents "$HOME/.cache/mozilla/firefox"
    fi
    CLEAN_RESULT_FILES[firefox]=$SAFE_RM_FILES
    CLEAN_RESULT_BYTES[firefox]=$SAFE_RM_BYTES
    [[ $SAFE_RM_FILES -gt 0 ]] && CLEAN_RESULT_STATUS[firefox]="pass" || CLEAN_RESULT_STATUS[firefox]="skip"
}

clean_arc() {
    if browser_running "Arc"; then
        echo -e "  ${RED}⚠${NC}  Arc is running — close it first to clean"
        clean_log "SKIP" "Arc (browser running)"
        CLEAN_RESULT_FILES[arc]=0; CLEAN_RESULT_BYTES[arc]=0; CLEAN_RESULT_STATUS[arc]="fail"
        return
    fi
    safe_rm_contents "$HOME/Library/Caches/Arc"
    CLEAN_RESULT_FILES[arc]=$SAFE_RM_FILES
    CLEAN_RESULT_BYTES[arc]=$SAFE_RM_BYTES
    [[ $SAFE_RM_FILES -gt 0 ]] && CLEAN_RESULT_STATUS[arc]="pass" || CLEAN_RESULT_STATUS[arc]="skip"
}

clean_edge() {
    if browser_running "Microsoft Edge"; then
        echo -e "  ${RED}⚠${NC}  Edge is running — close it first to clean"
        clean_log "SKIP" "Edge (browser running)"
        CLEAN_RESULT_FILES[edge]=0; CLEAN_RESULT_BYTES[edge]=0; CLEAN_RESULT_STATUS[edge]="fail"
        return
    fi
    if [[ "$OS" == "macos" ]]; then
        safe_rm_contents "$HOME/Library/Caches/Microsoft Edge"
    else
        safe_rm_contents "$HOME/.cache/microsoft-edge"
    fi
    CLEAN_RESULT_FILES[edge]=$SAFE_RM_FILES
    CLEAN_RESULT_BYTES[edge]=$SAFE_RM_BYTES
    [[ $SAFE_RM_FILES -gt 0 ]] && CLEAN_RESULT_STATUS[edge]="pass" || CLEAN_RESULT_STATUS[edge]="skip"
}

clean_recent_items() {
    if [[ "$OS" == "macos" ]]; then
        safe_rm_contents "$HOME/Library/Application Support/com.apple.sharedfilelist"
    else
        if [[ -f "$HOME/.local/share/recently-used.xbel" ]]; then
            rm -f "$HOME/.local/share/recently-used.xbel" 2>/dev/null
            clean_log "CLEAN" "Removed recently-used.xbel"
        fi
    fi
    CLEAN_RESULT_FILES[recent-items]=${SAFE_RM_FILES:-1}
    CLEAN_RESULT_BYTES[recent-items]=${SAFE_RM_BYTES:-0}
    CLEAN_RESULT_STATUS[recent-items]="pass"
}

clean_quicklook_thumbs() {
    safe_rm_contents "$HOME/Library/Caches/com.apple.QuickLook.thumbnailcache"
    qlmanage -r cache &>/dev/null
    clean_log "CLEAN" "Reset QuickLook thumbnail cache"
    CLEAN_RESULT_FILES[quicklook-thumbs]=$SAFE_RM_FILES
    CLEAN_RESULT_BYTES[quicklook-thumbs]=$SAFE_RM_BYTES
    CLEAN_RESULT_STATUS[quicklook-thumbs]="pass"
}

clean_ds_store() {
    local count=0 bytes=0
    while IFS= read -r -d '' file; do
        local fsize
        fsize=$(stat -f '%z' "$file" 2>/dev/null || echo 0)
        if rm -f "$file" 2>/dev/null; then
            bytes=$((bytes + fsize))
            ((count++))
        fi
    done < <(find "$HOME" -name ".DS_Store" -maxdepth 10 -not -type l -print0 2>/dev/null)
    clean_log "CLEAN" "Removed $count .DS_Store files"
    CLEAN_RESULT_FILES[ds-store]=$count
    CLEAN_RESULT_BYTES[ds-store]=$bytes
    [[ $count -gt 0 ]] && CLEAN_RESULT_STATUS[ds-store]="pass" || CLEAN_RESULT_STATUS[ds-store]="skip"
}

clean_clipboard() {
    if [[ "$OS" == "macos" ]]; then
        pbcopy </dev/null 2>/dev/null
    else
        if command -v xclip &>/dev/null; then
            echo -n | xclip -selection clipboard 2>/dev/null
        elif command -v xsel &>/dev/null; then
            xsel --clipboard --clear 2>/dev/null
        fi
    fi
    clean_log "CLEAN" "Cleared clipboard"
    CLEAN_RESULT_FILES[clipboard]=0
    CLEAN_RESULT_BYTES[clipboard]=0
    CLEAN_RESULT_STATUS[clipboard]="pass"
}

clean_search_metadata() {
    if [[ "$OS" == "macos" ]]; then
        echo -e "  ${RED}☐${NC}  Spotlight: To rebuild, run: sudo mdutil -E /"
        clean_log "MANUAL" "Spotlight rebuild guidance shown"
    else
        if command -v tracker3 &>/dev/null; then
            tracker3 reset -s &>/dev/null
            clean_log "CLEAN" "Reset GNOME Tracker index"
        elif command -v tracker &>/dev/null; then
            tracker reset --hard &>/dev/null
            clean_log "CLEAN" "Reset Tracker index"
        fi
    fi
    CLEAN_RESULT_FILES[search-metadata]=0
    CLEAN_RESULT_BYTES[search-metadata]=0
    CLEAN_RESULT_STATUS[search-metadata]="pass"
}

clean_xcode_derived() {
    safe_rm_contents "$HOME/Library/Developer/Xcode/DerivedData"
    CLEAN_RESULT_FILES[xcode-derived]=$SAFE_RM_FILES
    CLEAN_RESULT_BYTES[xcode-derived]=$SAFE_RM_BYTES
    [[ $SAFE_RM_FILES -gt 0 ]] && CLEAN_RESULT_STATUS[xcode-derived]="pass" || CLEAN_RESULT_STATUS[xcode-derived]="skip"
}

clean_homebrew_cache() {
    if command -v brew &>/dev/null; then
        brew cleanup --prune=all -s &>/dev/null
        clean_log "CLEAN" "Ran brew cleanup --prune=all"
    fi
    CLEAN_RESULT_FILES[homebrew-cache]=0
    CLEAN_RESULT_BYTES[homebrew-cache]=0
    CLEAN_RESULT_STATUS[homebrew-cache]="pass"
}

clean_npm_cache() {
    if command -v npm &>/dev/null; then
        npm cache clean --force &>/dev/null
        clean_log "CLEAN" "Ran npm cache clean --force"
    fi
    CLEAN_RESULT_FILES[npm-cache]=0
    CLEAN_RESULT_BYTES[npm-cache]=0
    CLEAN_RESULT_STATUS[npm-cache]="pass"
}

clean_yarn_cache() {
    if command -v yarn &>/dev/null; then
        yarn cache clean &>/dev/null
        clean_log "CLEAN" "Ran yarn cache clean"
    fi
    CLEAN_RESULT_FILES[yarn-cache]=0
    CLEAN_RESULT_BYTES[yarn-cache]=0
    CLEAN_RESULT_STATUS[yarn-cache]="pass"
}

clean_pip_cache() {
    local pip_cmd="pip3"
    command -v pip3 &>/dev/null || pip_cmd="pip"
    if command -v "$pip_cmd" &>/dev/null; then
        $pip_cmd cache purge &>/dev/null
        clean_log "CLEAN" "Ran $pip_cmd cache purge"
    fi
    CLEAN_RESULT_FILES[pip-cache]=0
    CLEAN_RESULT_BYTES[pip-cache]=0
    CLEAN_RESULT_STATUS[pip-cache]="pass"
}

clean_cargo_cache() {
    safe_rm_contents "$HOME/.cargo/registry/cache"
    CLEAN_RESULT_FILES[cargo-cache]=$SAFE_RM_FILES
    CLEAN_RESULT_BYTES[cargo-cache]=$SAFE_RM_BYTES
    [[ $SAFE_RM_FILES -gt 0 ]] && CLEAN_RESULT_STATUS[cargo-cache]="pass" || CLEAN_RESULT_STATUS[cargo-cache]="skip"
}

clean_go_cache() {
    if command -v go &>/dev/null; then
        go clean -cache &>/dev/null
        clean_log "CLEAN" "Ran go clean -cache"
    fi
    CLEAN_RESULT_FILES[go-cache]=0
    CLEAN_RESULT_BYTES[go-cache]=0
    CLEAN_RESULT_STATUS[go-cache]="pass"
}

clean_cocoapods_cache() {
    safe_rm_contents "$HOME/Library/Caches/CocoaPods"
    CLEAN_RESULT_FILES[cocoapods-cache]=$SAFE_RM_FILES
    CLEAN_RESULT_BYTES[cocoapods-cache]=$SAFE_RM_BYTES
    [[ $SAFE_RM_FILES -gt 0 ]] && CLEAN_RESULT_STATUS[cocoapods-cache]="pass" || CLEAN_RESULT_STATUS[cocoapods-cache]="skip"
}

clean_docker_cruft() {
    if command -v docker &>/dev/null; then
        docker system prune -f &>/dev/null
        clean_log "CLEAN" "Ran docker system prune -f"
    fi
    CLEAN_RESULT_FILES[docker-cruft]=0
    CLEAN_RESULT_BYTES[docker-cruft]=0
    CLEAN_RESULT_STATUS[docker-cruft]="pass"
}

clean_ide_caches() {
    local total_f=0 total_b=0
    for d in "$HOME/Library/Application Support/Code/Cache" \
             "$HOME/.config/Code/Cache" \
             "$HOME/Library/Caches/JetBrains" \
             "$HOME/.cache/JetBrains"; do
        if [[ -d "$d" ]]; then
            safe_rm_contents "$d"
            total_f=$((total_f + SAFE_RM_FILES))
            total_b=$((total_b + SAFE_RM_BYTES))
        fi
    done
    CLEAN_RESULT_FILES[ide-caches]=$total_f
    CLEAN_RESULT_BYTES[ide-caches]=$total_b
    [[ $total_f -gt 0 ]] && CLEAN_RESULT_STATUS[ide-caches]="pass" || CLEAN_RESULT_STATUS[ide-caches]="skip"
}

clean_trash() {
    if [[ "$OS" == "macos" ]]; then
        safe_rm_contents "$HOME/.Trash"
    else
        safe_rm_contents "$HOME/.local/share/Trash"
    fi
    CLEAN_RESULT_FILES[trash]=$SAFE_RM_FILES
    CLEAN_RESULT_BYTES[trash]=$SAFE_RM_BYTES
    [[ $SAFE_RM_FILES -gt 0 ]] && CLEAN_RESULT_STATUS[trash]="pass" || CLEAN_RESULT_STATUS[trash]="skip"
}

clean_old_downloads() {
    SAFE_RM_FILES=0; SAFE_RM_BYTES=0
    while IFS= read -r -d '' file; do
        local fsize
        if [[ "$OS" == "macos" ]]; then
            fsize=$(stat -f '%z' "$file" 2>/dev/null || echo 0)
        else
            fsize=$(stat -c '%s' "$file" 2>/dev/null || echo 0)
        fi
        if rm -f "$file" 2>/dev/null; then
            SAFE_RM_BYTES=$((SAFE_RM_BYTES + fsize))
            ((SAFE_RM_FILES++))
            clean_log "CLEAN" "Removed $file ($(format_bytes "$fsize"))"
        fi
    done < <(find "$HOME/Downloads" -maxdepth 1 -not -type l -type f -mtime +30 -print0 2>/dev/null)
    CLEAN_RESULT_FILES[old-downloads]=$SAFE_RM_FILES
    CLEAN_RESULT_BYTES[old-downloads]=$SAFE_RM_BYTES
    [[ $SAFE_RM_FILES -gt 0 ]] && CLEAN_RESULT_STATUS[old-downloads]="pass" || CLEAN_RESULT_STATUS[old-downloads]="skip"
}

clean_mail_cache() {
    if [[ "$OS" == "macos" ]]; then
        safe_rm_contents "$HOME/Library/Containers/com.apple.mail/Data/Library/Caches"
    else
        if [[ -d "$HOME/.thunderbird" ]]; then
            find "$HOME/.thunderbird" -name "*.msf" -delete 2>/dev/null
            clean_log "CLEAN" "Removed Thunderbird index files"
        fi
        SAFE_RM_FILES=0; SAFE_RM_BYTES=0
    fi
    CLEAN_RESULT_FILES[mail-cache]=${SAFE_RM_FILES:-0}
    CLEAN_RESULT_BYTES[mail-cache]=${SAFE_RM_BYTES:-0}
    CLEAN_RESULT_STATUS[mail-cache]="pass"
}

clean_messages_attachments() {
    safe_rm_contents "$HOME/Library/Messages/Attachments"
    CLEAN_RESULT_FILES[messages-attachments]=$SAFE_RM_FILES
    CLEAN_RESULT_BYTES[messages-attachments]=$SAFE_RM_BYTES
    [[ $SAFE_RM_FILES -gt 0 ]] && CLEAN_RESULT_STATUS[messages-attachments]="pass" || CLEAN_RESULT_STATUS[messages-attachments]="skip"
}

# ═══════════════════════════════════════════════════════════════════
# SYSTEM CLEANER — EXECUTION ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════

clean_execute() {
    print_section "Cleaning ($(date '+%H:%M:%S'))"

    local -a ordered_targets=()
    for cat in "${CLEAN_CAT_ORDER[@]}"; do
        for target in ${CLEAN_CAT_TARGETS[$cat]}; do
            if [[ "${CLEAN_TARGETS[$target]:-0}" == "1" ]]; then
                ordered_targets+=("$target")
            fi
        done
    done

    local total=${#ordered_targets[@]}
    local current=0

    for target in "${ordered_targets[@]}"; do
        ((current++))
        echo -ne "  ${BROWN}⟳${NC} [${current}/${total}] ${CLEAN_TARGET_NAMES[$target]}..."

        local func="clean_${target//-/_}"
        if declare -f "$func" &>/dev/null; then
            "$func"
        else
            CLEAN_RESULT_STATUS[$target]="fail"
            clean_log "FAIL" "$target — no clean function"
        fi

        echo -ne "\r\033[K"
        local status="${CLEAN_RESULT_STATUS[$target]:-skip}"
        local freed="${CLEAN_RESULT_BYTES[$target]:-0}"
        local freed_str=""
        [[ $freed -gt 0 ]] && freed_str=" ($(format_bytes $freed))"

        case "$status" in
            pass)    echo -e "  ${GREEN}✓${NC} [${current}/${total}] ${CLEAN_TARGET_NAMES[$target]}${freed_str}" ;;
            skip)    echo -e "  ${GREEN}○${NC} [${current}/${total}] ${CLEAN_TARGET_NAMES[$target]} ${BROWN}(nothing to clean)${NC}" ;;
            fail)    echo -e "  ${RED}✗${NC} [${current}/${total}] ${CLEAN_TARGET_NAMES[$target]} ${RED}(failed)${NC}" ;;
            partial) echo -e "  ${BROWN}◐${NC} [${current}/${total}] ${CLEAN_TARGET_NAMES[$target]}${freed_str} ${BROWN}(partial)${NC}" ;;
        esac
    done
}

# ═══════════════════════════════════════════════════════════════════
# SYSTEM CLEANER — SCORE, SUMMARY, AND LOG
# ═══════════════════════════════════════════════════════════════════

calculate_clean_score() {
    local earned=0 possible=0

    for target in "${!CLEAN_TARGETS[@]}"; do
        [[ "${CLEAN_TARGETS[$target]}" != "1" ]] && continue
        local sev="${CLEAN_SEVERITY[$target]:-LOW}"
        local weight="${SEVERITY_WEIGHT[$sev]}"
        possible=$((possible + weight))

        local status="${CLEAN_RESULT_STATUS[$target]:-skip}"
        case "$status" in
            pass|skip) earned=$((earned + weight)) ;;
            partial)   earned=$((earned + weight / 2)) ;;
            fail)      ;;
        esac
    done

    local pct=0
    [[ $possible -gt 0 ]] && pct=$(( (earned * 100) / possible ))
    echo "$earned $possible $pct"
}

print_clean_summary() {
    local -a ordered_targets=()
    for cat in "${CLEAN_CAT_ORDER[@]}"; do
        for target in ${CLEAN_CAT_TARGETS[$cat]}; do
            if [[ "${CLEAN_TARGETS[$target]:-0}" == "1" ]]; then
                ordered_targets+=("$target")
            fi
        done
    done

    local total_files=0 total_bytes=0

    echo ""
    echo -e "  ${BOLD}${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "  ${BOLD}${GREEN}║                  CLEANING SUMMARY                        ║${NC}"
    echo -e "  ${BOLD}${GREEN}╠══════════════════════════════════════════════════════════╣${NC}"
    printf "  ${BOLD}${GREEN}║${NC} %-33s %7s %9s %7s ${BOLD}${GREEN}║${NC}\n" "Target" "Removed" "Freed" "Status"
    echo -e "  ${GREEN}║${NC}${BROWN}────────────────────────────────────────────────────────${NC}${GREEN}║${NC}"

    for target in "${ordered_targets[@]}"; do
        local files="${CLEAN_RESULT_FILES[$target]:-0}"
        local bytes="${CLEAN_RESULT_BYTES[$target]:-0}"
        local status="${CLEAN_RESULT_STATUS[$target]:-skip}"

        local file_str="$files"
        [[ $files -eq 0 ]] && file_str="—"
        local size_str="—"
        [[ $bytes -gt 0 ]] && size_str=$(format_bytes "$bytes")

        local status_str color
        case "$status" in
            pass)    status_str="PASS";    color="$GREEN" ;;
            skip)    status_str="SKIP";    color="$BROWN" ;;
            fail)    status_str="FAIL";    color="$RED" ;;
            partial) status_str="PARTIAL"; color="$BROWN" ;;
        esac

        printf "  ${GREEN}║${NC}${color} %-33s %7s %9s %7s ${NC}${GREEN}║${NC}\n" \
            "${CLEAN_TARGET_NAMES[$target]}" "$file_str" "$size_str" "$status_str"

        total_files=$((total_files + files))
        total_bytes=$((total_bytes + bytes))
    done

    echo -e "  ${GREEN}║${NC}${BROWN}────────────────────────────────────────────────────────${NC}${GREEN}║${NC}"
    printf "  ${BOLD}${GREEN}║${NC} %-33s %7s %9s         ${BOLD}${GREEN}║${NC}\n" "TOTAL" "$total_files" "$(format_bytes $total_bytes)"
    echo -e "  ${BOLD}${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""

    local score_output
    score_output=$(calculate_clean_score)
    local earned possible pct
    read -r earned possible pct <<< "$score_output"

    local color="$RED"
    if [[ $pct -ge 80 ]]; then color="$GREEN"
    elif [[ $pct -ge 50 ]]; then color="$BROWN"
    fi

    local width=20
    local filled=$(( (pct * width) / 100 ))
    local empty=$(( width - filled ))
    local bar=""
    for ((i=0; i<filled; i++)); do bar+="█"; done
    for ((i=0; i<empty; i++)); do bar+="░"; done

    echo -e "  ${BOLD}Cleanliness Score: ${color}${pct}/100${NC} [${color}${bar}${NC}]"
    echo ""
}

write_clean_log() {
    mkdir -p "$(dirname "$CLEAN_LOG_FILE")"
    {
        if [[ -f "$CLEAN_LOG_FILE" ]]; then
            echo ""
            echo "────────────────────────────────────────"
            echo ""
        fi
        echo "# System Cleaner Log — $(date '+%Y-%m-%d %H:%M:%S')"
        echo "OS: ${OS} | Date: ${DATE}"
        echo ""
        for entry in "${CLEAN_LOG[@]}"; do
            echo "$entry"
        done
    } >> "$CLEAN_LOG_FILE"
    echo -e "  ${BROWN}Log: ${CLEAN_LOG_FILE}${NC}"
}

# ═══════════════════════════════════════════════════════════════════
# SYSTEM CLEANER — MAIN ENTRY
# ═══════════════════════════════════════════════════════════════════
run_clean() {
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════╗${NC}"
    printf "${GREEN}║${NC}${BOLD}%-50s${NC}${GREEN}║${NC}\n" "          BARKED SYSTEM CLEANER v${VERSION}"
    printf "${GREEN}║${NC}%-50s${GREEN}║${NC}\n" "                  macOS / Linux"
    echo -e "${GREEN}╚══════════════════════════════════════════════════╝${NC}"

    clean_picker
    clean_drilldown
    needs_sudo && acquire_sudo
    clean_preview

    # Dry-run: show preview and exit
    if [[ "$DRY_RUN" == true ]]; then
        echo ""
        echo -e "  ${GREEN}[DRY RUN]${NC} Preview only — no files deleted."
        return
    fi

    # Confirmation
    if [[ "$CLEAN_FORCE" != true ]]; then
        echo ""
        echo -ne "  ${BOLD}Proceed with cleaning? (y/N):${NC} "
        read -r confirm
        if [[ "${confirm,,}" != "y" ]]; then
            echo -e "  ${BROWN}Cancelled.${NC}"
            return
        fi
    fi

    clean_execute
    print_clean_summary
    write_clean_log

    echo ""
    echo -e "  ${BROWN}Re-run with --clean anytime — safe to repeat.${NC}"
    echo ""
}

# ═══════════════════════════════════════════════════════════════════
# UPDATE SYSTEM
# ═══════════════════════════════════════════════════════════════════
version_gt() {
    local IFS='.'
    local i v1=($1) v2=($2)
    for ((i = 0; i < 3; i++)); do
        local a="${v1[i]:-0}" b="${v2[i]:-0}"
        if ((a > b)); then return 0; fi
        if ((a < b)); then return 1; fi
    done
    return 1
}

fetch_latest_version() {
    local api_url="https://api.github.com/repos/${GITHUB_REPO}/releases/latest"
    local response
    response="$(curl -fsSL --connect-timeout 5 --max-time 10 "$api_url" 2>/dev/null)" || return 1
    local tag
    tag="$(echo "$response" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')" || return 1
    [[ -z "$tag" ]] && return 1
    echo "${tag#v}"
}

run_update() {
    echo -e "${BROWN}Checking for updates...${NC}"

    local install_path
    install_path="$(command -v barked 2>/dev/null)" || install_path="$0"

    local latest
    latest="$(fetch_latest_version)" || {
        echo -e "${RED}Could not reach GitHub to check for updates.${NC}"
        exit 1
    }

    if ! version_gt "$latest" "$VERSION"; then
        echo -e "${GREEN}Already up to date (v${VERSION}).${NC}"
        exit 0
    fi

    # Check if we need root for the update
    local need_root=false
    if [[ ! -w "$install_path" ]]; then
        need_root=true
        acquire_sudo || {
            echo -e "${RED}Cannot update ${install_path} without admin privileges.${NC}"
            exit 1
        }
    fi

    local tmp_file
    tmp_file="$(mktemp /tmp/barked-new-XXXXXX.sh)" || {
        echo -e "${RED}Failed to create temp file.${NC}"
        exit 1
    }
    local download_url="https://github.com/${GITHUB_REPO}/releases/latest/download/barked.sh"

    echo -e "  Downloading v${latest}..."
    curl -fsSL --connect-timeout 5 --max-time 30 "$download_url" -o "$tmp_file" 2>/dev/null || {
        echo -e "${RED}Failed to download update.${NC}"
        rm -f "$tmp_file"
        exit 1
    }

    # Download and verify checksum
    local checksum_url="https://github.com/${GITHUB_REPO}/releases/latest/download/barked.sh.sha256"
    local expected_hash
    expected_hash="$(curl -fsSL --connect-timeout 5 --max-time 10 "$checksum_url" 2>/dev/null | awk '{print $1}')" || {
        echo -e "${RED}Failed to download checksum for verification.${NC}"
        rm -f "$tmp_file"
        exit 1
    }
    if [[ -z "$expected_hash" ]]; then
        echo -e "${RED}Failed to download checksum for verification.${NC}"
        rm -f "$tmp_file"
        exit 1
    fi

    local actual_hash
    actual_hash="$(shasum -a 256 "$tmp_file" | awk '{print $1}')"
    if [[ "$actual_hash" != "$expected_hash" ]]; then
        echo -e "${RED}Checksum verification failed — aborting update.${NC}"
        echo -e "${RED}Expected: ${expected_hash}${NC}"
        echo -e "${RED}Got:      ${actual_hash}${NC}"
        rm -f "$tmp_file"
        exit 1
    fi

    if ! bash -n "$tmp_file" 2>/dev/null; then
        echo -e "${RED}Downloaded file has syntax errors — aborting update.${NC}"
        rm -f "$tmp_file"
        exit 1
    fi

    chmod 755 "$tmp_file"

    # Install using appropriate privileges
    if [[ "$need_root" == true ]]; then
        run_as_root mv "$tmp_file" "$install_path" 2>/dev/null || {
            run_as_root cp "$tmp_file" "$install_path" 2>/dev/null || {
                echo -e "${RED}Failed to replace ${install_path}.${NC}"
                rm -f "$tmp_file"
                exit 1
            }
            rm -f "$tmp_file"
        }
    else
        mv "$tmp_file" "$install_path" 2>/dev/null || {
            cp "$tmp_file" "$install_path" 2>/dev/null || {
                echo -e "${RED}Failed to replace ${install_path}.${NC}"
                rm -f "$tmp_file"
                exit 1
            }
            rm -f "$tmp_file"
        }
    fi

    echo -e "${GREEN}Updated to v${latest}.${NC}"
    exit 0
}

check_update_passive() {
    [[ "${QUIET_MODE:-}" == true ]] && return
    command -v curl &>/dev/null || return 0

    local cache_file="${TMPDIR:-/tmp}/barked-update-check-$(id -u)"
    local cache_max=86400
    local now
    now="$(date +%s)" || return 0

    if [[ -f "$cache_file" ]]; then
        local cached_epoch cached_version
        cached_epoch="$(sed -n '1p' "$cache_file" 2>/dev/null)" || return 0
        cached_version="$(sed -n '2p' "$cache_file" 2>/dev/null)" || return 0

        if [[ -n "$cached_epoch" ]] && (( now - cached_epoch < cache_max )); then
            if [[ -n "$cached_version" ]] && version_gt "$cached_version" "$VERSION"; then
                echo -e "${GREEN}A new version is available (v${cached_version}). Run: barked --update${NC}"
            fi
            return 0
        fi
    fi

    local latest
    latest="$(fetch_latest_version 2>/dev/null)" || return 0

    printf '%s\n%s\n' "$now" "$latest" > "$cache_file" 2>/dev/null || true

    if version_gt "$latest" "$VERSION"; then
        echo -e "${GREEN}A new version is available (v${latest}). Run: barked --update${NC}"
    fi

    return 0
}

run_uninstall_self() {
    local install_path
    install_path="$(command -v barked 2>/dev/null)" || {
        echo -e "${RED}barked not found in PATH. Nothing to uninstall.${NC}"
        exit 1
    }

    if [[ ! -w "$install_path" ]]; then
        acquire_sudo || {
            echo -e "${RED}Cannot remove ${install_path} without admin privileges.${NC}"
            exit 1
        }
    fi

    run_as_root rm -f "$install_path"
    rm -f "${TMPDIR:-/tmp}/barked-update-check-$(id -u)"
    echo -e "${GREEN}barked has been removed from ${install_path}.${NC}"
    exit 0
}

# ═══════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════
main() {
    parse_args "$@"

    # ── Scheduled clean mode (non-interactive, invoked by launchd/cron) ──
    if [[ "$CLEAN_SCHEDULED" == true ]]; then
        detect_os
        run_scheduled_clean
        local rc=$?
        write_clean_log
        exit $rc
    fi

    # ── Monitor mode subcommands ──
    if [[ "$MONITOR_INIT" == true ]]; then
        detect_os
        monitor_init_interactive
        exit 0
    fi

    if [[ "$MONITOR_BASELINE" == true ]]; then
        detect_os
        print_header
        monitor_take_baseline
        exit 0
    fi

    if [[ "$MONITOR_TEST_ALERT" == true ]]; then
        detect_os
        print_header
        monitor_test_alert
        exit 0
    fi

    if [[ "$MONITOR_MODE" == true ]]; then
        detect_os
        print_header
        run_monitor
        exit 0
    fi

    print_header
    detect_os
    setup_privileges
    state_migrate_legacy

    # ── Audit-only mode: score and exit ──
    if [[ "$AUDIT_MODE" == true ]]; then
        run_audit
        check_update_passive
        exit 0
    fi

    # ── Clean mode: system cleaner ──
    if [[ "$CLEAN_MODE" == true ]]; then
        run_clean
        check_update_passive
        exit 0
    fi

    # ── Schedule setup mode ──
    if [[ "$CLEAN_SCHEDULE_SETUP" == true ]]; then
        setup_scheduled_clean
        local setup_rc=$?
        check_update_passive
        exit $setup_rc
    fi

    # ── Unschedule mode ──
    if [[ "$CLEAN_UNSCHEDULE" == true ]]; then
        unschedule_clean
        local unsched_rc=$?
        check_update_passive
        exit $unsched_rc
    fi

    # ── Auto (non-interactive) mode ──
    if [[ "$AUTO_MODE" == true ]]; then
        PROFILE="$AUTO_PROFILE"
        build_module_list
        # Pre-change analysis (smart-skip)
        local pca_rc=0
        pre_change_analysis || pca_rc=$?
        if [[ $pca_rc -eq 2 ]]; then
            write_log
            exit 2
        fi

        if [[ "$DRY_RUN" == true ]]; then
            run_all_modules_twophase
            write_dry_run_report
            write_log
            exit 0
        fi

        run_all_modules_twophase
        state_write
        print_summary
        write_log
        local exit_code=0
        [[ $COUNT_FAILED -gt 0 ]] && exit_code=1
        exit "$exit_code"
    fi

    # ── Interactive modes ──
    case "$RUN_MODE" in
        uninstall)
            acquire_sudo
            run_uninstall
            write_log
            print_manual_checklist
            ;;
        modify)
            acquire_sudo
            run_modify
            print_modify_summary
            print_manual_checklist
            write_log
            ;;
        harden)
            select_profile

            # Profile selection may have switched mode
            if [[ "$RUN_MODE" == "uninstall" ]]; then
                acquire_sudo
                run_uninstall
                write_log
                print_manual_checklist
                return
            elif [[ "$RUN_MODE" == "modify" ]]; then
                acquire_sudo
                run_modify
                print_modify_summary
                print_manual_checklist
                write_log
                return
            elif [[ "$CLEAN_MODE" == true ]]; then
                run_clean
                check_update_passive
                return
            fi

            select_output_mode
            build_module_list

            # Pre-change analysis replaces the old "Proceed?" prompt
            local pca_rc=0
            pre_change_analysis || pca_rc=$?
            if [[ $pca_rc -eq 1 ]]; then
                exit 0
            elif [[ $pca_rc -eq 2 ]]; then
                write_log
                return
            fi

            if [[ "$DRY_RUN" == true ]]; then
                run_all_modules_twophase
                write_dry_run_report
                write_log
                return
            fi

            run_all_modules_twophase

            # Track state for applied modules
            state_write

            # Output
            print_summary

            case "$OUTPUT_MODE" in
                checklist) print_manual_checklist ;;
                pause)     ;; # Already guided through
                report)    write_report ;;
            esac

            write_log
            ;;
    esac

    # Passive update check (runs after all work is done)
    check_update_passive

    echo ""
    echo -e "  ${BROWN}Re-run this script anytime — it's safe to repeat.${NC}"
    echo ""
}

main "$@"
