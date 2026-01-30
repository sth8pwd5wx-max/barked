# Audit, Scoring, Modes & Advanced Hardening — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add hardening score, severity ratings, audit mode, dry-run mode, non-interactive mode, pre-change analysis, and three advanced hardening modules with mandatory vetting to `scripts/barked.sh`.

**Architecture:** All changes go into the single `scripts/barked.sh` file (~3164 lines). New globals and severity map are added near existing globals (line ~35). New functions slot into existing sections. The module runner gains a dry-run guard. Three new modules + reverts are added after the existing 25 modules. The argument parser and main flow are extended.

**Tech Stack:** Pure Bash (no external dependencies). Python3 for JSON state I/O (already used). No new files except runtime audit output.

**Key file:** `scripts/barked.sh`

---

### Task 1: Add New Globals and Severity Map

**Files:**
- Modify: `scripts/barked.sh:35-66` (GLOBALS section)

**Step 1: Add new mode globals after line 55 (after `COUNT_REVERTED=0`)**

Add these globals in the GLOBALS section, after the existing `COUNT_REVERTED=0` line and before the state file locations block:

```bash
# New modes
DRY_RUN=false
AUTO_MODE=false
AUDIT_MODE=false
QUIET_MODE=false
ACCEPT_ADVANCED=false
CLI_PROFILE=""               # profile passed via --profile flag
```

**Step 2: Add severity map after the state arrays (after line 67)**

Add the severity weight map as an associative array, after `STATE_LAST_RUN=""`:

```bash
# Severity weights: Critical=10, High=7, Medium=4, Low=2
declare -A MODULE_SEVERITY=(
    [disk-encrypt]=10     [firewall-inbound]=10  [auto-updates]=10     [lock-screen]=10
    [firewall-stealth]=7  [firewall-outbound]=7  [dns-secure]=7        [ssh-harden]=7
    [guest-disable]=7     [telemetry-disable]=7  [kernel-sysctl]=7
    [hostname-scrub]=4    [git-harden]=4         [browser-basic]=4     [monitoring-tools]=4
    [permissions-audit]=4 [apparmor-enforce]=4   [boot-security]=4
    [browser-fingerprint]=2 [mac-rotate]=2       [vpn-killswitch]=2    [traffic-obfuscation]=2
    [metadata-strip]=2    [dev-isolation]=2      [audit-script]=2      [backup-guidance]=2
    [border-prep]=2       [bluetooth-disable]=2
)

# Advanced modules requiring vetting
declare -a ADVANCED_MODULES=("kernel-sysctl" "apparmor-enforce" "boot-security")

# Findings storage for audit/scoring
declare -a FINDINGS_STATUS=()    # "pass", "fail", "manual", "skip", "partial"
declare -a FINDINGS_MODULE=()    # module id
declare -a FINDINGS_MESSAGE=()   # human-readable finding
```

**Step 3: Verify the script still parses**

Run: `bash -n scripts/barked.sh`
Expected: No output (clean parse)

**Step 4: Commit**

```bash
git add scripts/barked.sh
git commit -m "feat: add severity map, mode globals, and findings storage"
```

---

### Task 2: Extend Argument Parser

**Files:**
- Modify: `scripts/barked.sh:3060-3088` (parse_args function)

**Step 1: Replace the parse_args function**

Replace the existing `parse_args()` (lines 3060-3088) with this expanded version:

```bash
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
                RUN_MODE="audit"
                ;;
            --dry-run)
                DRY_RUN=true
                ;;
            --auto)
                AUTO_MODE=true
                RUN_MODE="harden"
                ;;
            --profile)
                shift
                if [[ $# -eq 0 ]]; then
                    echo -e "${RED}--profile requires a value (standard, high, paranoid)${NC}"
                    exit 1
                fi
                CLI_PROFILE="$1"
                case "$CLI_PROFILE" in
                    standard|high|paranoid) ;;
                    *) echo -e "${RED}Invalid profile: $CLI_PROFILE (use standard, high, or paranoid)${NC}"; exit 1 ;;
                esac
                ;;
            --quiet|-q)
                QUIET_MODE=true
                ;;
            --accept-advanced)
                ACCEPT_ADVANCED=true
                ;;
            --help|-h)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Modes:"
                echo "  (default)              Interactive hardening wizard"
                echo "  --audit                Audit-only: scan and score, no changes"
                echo "  --dry-run              Preview what would change, no changes"
                echo "  --auto --profile NAME  Non-interactive: apply profile without prompts"
                echo "  --uninstall, -u        Revert all hardening changes"
                echo "  --modify, -m           Add or remove individual modules"
                echo ""
                echo "Options:"
                echo "  --profile NAME         Set profile (standard, high, paranoid)"
                echo "  --quiet, -q            Suppress terminal output (log file still written)"
                echo "  --accept-advanced      Include advanced modules in --auto mode"
                echo "  --help, -h             Show this help"
                echo ""
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

    # Validate flag combinations
    if $AUTO_MODE && [[ -z "$CLI_PROFILE" ]]; then
        echo -e "${RED}--auto requires --profile (standard, high, or paranoid)${NC}"
        exit 1
    fi
    if $QUIET_MODE && ! $AUTO_MODE && ! $AUDIT_MODE; then
        echo -e "${RED}--quiet requires --auto or --audit${NC}"
        exit 1
    fi
}
```

**Step 2: Verify the script still parses**

Run: `bash -n scripts/barked.sh`
Expected: No output (clean parse)

**Step 3: Commit**

```bash
git add scripts/barked.sh
git commit -m "feat: extend argument parser with audit, dry-run, auto, quiet, accept-advanced flags"
```

---

### Task 3: Add Scoring and Findings Table Functions

**Files:**
- Modify: `scripts/barked.sh` — insert new section after LOGGING & OUTPUT UTILITIES (after line ~170, before OS DETECTION)

**Step 1: Add the scoring and findings functions**

Insert a new section between the logging utilities (ends ~line 169) and OS detection (starts ~line 171):

```bash
# ═══════════════════════════════════════════════════════════════════
# SCORING & FINDINGS
# ═══════════════════════════════════════════════════════════════════

# Record a finding for the findings table
record_finding() {
    local status="$1" mod_id="$2" message="$3"
    FINDINGS_STATUS+=("$status")
    FINDINGS_MODULE+=("$mod_id")
    FINDINGS_MESSAGE+=("$message")
}

# Check if a module is applicable on the current OS
module_applicable() {
    local mod_id="$1"
    case "$mod_id" in
        kernel-sysctl)     [[ "$OS" == "linux" ]] ;;
        apparmor-enforce)  return 0 ;;  # linux: enforce, macos: audit-only
        boot-security)     return 0 ;;  # both platforms supported
        *)                 return 0 ;;
    esac
}

# Check if a module is an advanced module
is_advanced_module() {
    local mod_id="$1"
    for adv in "${ADVANCED_MODULES[@]}"; do
        [[ "$adv" == "$mod_id" ]] && return 0
    done
    return 1
}

# Get severity label from weight
severity_label() {
    local weight="${MODULE_SEVERITY[$1]:-0}"
    case "$weight" in
        10) echo "CRITICAL" ;;
        7)  echo "HIGH" ;;
        4)  echo "MEDIUM" ;;
        2)  echo "LOW" ;;
        *)  echo "UNKNOWN" ;;
    esac
}

# Calculate hardening score from findings
# Sets SCORE_CURRENT (0-100) and SCORE_APPLIED/SCORE_TOTAL counts
SCORE_CURRENT=0
SCORE_APPLIED_COUNT=0
SCORE_TOTAL_COUNT=0

calculate_score() {
    local earned=0 possible=0 applied_count=0 total_count=0
    for i in "${!FINDINGS_MODULE[@]}"; do
        local mod_id="${FINDINGS_MODULE[$i]}"
        local status="${FINDINGS_STATUS[$i]}"
        local weight="${MODULE_SEVERITY[$mod_id]:-0}"

        if [[ "$status" == "skip" ]]; then
            continue  # N/A modules excluded from denominator
        fi

        possible=$((possible + weight))
        total_count=$((total_count + 1))

        if [[ "$status" == "pass" ]]; then
            earned=$((earned + weight))
            applied_count=$((applied_count + 1))
        fi
    done

    if [[ $possible -gt 0 ]]; then
        SCORE_CURRENT=$(( (earned * 100) / possible ))
    else
        SCORE_CURRENT=0
    fi
    SCORE_APPLIED_COUNT=$applied_count
    SCORE_TOTAL_COUNT=$total_count
}

# Print a progress bar: [████████░░]
print_score_bar() {
    local score=$1
    local filled=$((score / 10))
    local empty=$((10 - filled))
    local bar=""
    for ((i=0; i<filled; i++)); do bar+="█"; done
    for ((i=0; i<empty; i++)); do bar+="░"; done

    local color="$RED"
    if [[ $score -ge 80 ]]; then color="$GREEN"
    elif [[ $score -ge 50 ]]; then color="$YELLOW"
    fi

    echo -e "  ${BOLD}Hardening Score: ${color}${score}/100${NC} [${color}${bar}${NC}] — ${SCORE_APPLIED_COUNT} of ${SCORE_TOTAL_COUNT} modules applied"
}

# Print the severity-rated findings table
print_findings_table() {
    echo ""
    printf "  ${BOLD}%-8s %-10s %-24s %s${NC}\n" "Status" "Severity" "Module" "Finding"
    printf "  ${DIM}%-8s %-10s %-24s %s${NC}\n" "------" "--------" "------" "-------"

    for i in "${!FINDINGS_MODULE[@]}"; do
        local mod_id="${FINDINGS_MODULE[$i]}"
        local status="${FINDINGS_STATUS[$i]}"
        local message="${FINDINGS_MESSAGE[$i]}"
        local sev
        sev=$(severity_label "$mod_id")

        local status_icon="" status_label="" color=""
        case "$status" in
            pass)    status_icon="✓" status_label="PASS"    color="$GREEN" ;;
            fail)    status_icon="✗" status_label="FAIL"    color="$RED" ;;
            manual)  status_icon="~" status_label="MANUAL"  color="$YELLOW" ;;
            skip)    status_icon="—" status_label="N/A"     color="$DIM" ;;
            partial) status_icon="◐" status_label="PARTIAL" color="$MAGENTA" ;;
        esac

        printf "  ${color}%-8s${NC} %-10s %-24s %s\n" "${status_icon} ${status_label}" "${sev}" "${mod_id}" "${message}"
    done
    echo ""
}

# Write findings to a markdown report file
write_findings_report() {
    local report_file="$1"
    mkdir -p "$(dirname "$report_file")"
    {
        echo "# Security Audit Report — ${DATE}"
        echo ""
        echo "**OS:** ${OS} $([ -n "$DISTRO" ] && echo "(${DISTRO})")"
        echo "**Profile:** ${PROFILE:-all}"
        echo "**Generated:** ${TIMESTAMP}"
        echo "**Hardening Score:** ${SCORE_CURRENT}/100 (${SCORE_APPLIED_COUNT}/${SCORE_TOTAL_COUNT} modules)"
        echo ""
        echo "## Findings"
        echo ""
        echo "| Status | Severity | Module | Finding |"
        echo "|--------|----------|--------|---------|"
        for i in "${!FINDINGS_MODULE[@]}"; do
            local mod_id="${FINDINGS_MODULE[$i]}"
            local status="${FINDINGS_STATUS[$i]}"
            local message="${FINDINGS_MESSAGE[$i]}"
            local sev
            sev=$(severity_label "$mod_id")
            local icon=""
            case "$status" in
                pass) icon="PASS" ;; fail) icon="FAIL" ;; manual) icon="MANUAL" ;;
                skip) icon="N/A" ;; partial) icon="PARTIAL" ;;
            esac
            echo "| ${icon} | ${sev} | ${mod_id} | ${message} |"
        done
        echo ""
        echo "---"
        echo "Generated by barked.sh v${VERSION}"
    } > "$report_file"
}
```

**Step 2: Verify the script still parses**

Run: `bash -n scripts/barked.sh`
Expected: No output

**Step 3: Commit**

```bash
git add scripts/barked.sh
git commit -m "feat: add scoring engine, findings table, and report writer"
```

---

### Task 4: Add Module Check Functions for Audit

**Files:**
- Modify: `scripts/barked.sh` — insert after the scoring section, before OS detection

Each existing module already has check logic inside its `mod_*` function. We need standalone check functions that only detect state without applying changes. These call `record_finding()` to populate the findings table.

**Step 1: Add the check functions**

```bash
# ═══════════════════════════════════════════════════════════════════
# MODULE CHECK FUNCTIONS — AUDIT ONLY (no changes)
# ═══════════════════════════════════════════════════════════════════

check_module_state() {
    local mod_id="$1"

    # Check OS applicability first
    if ! module_applicable "$mod_id"; then
        record_finding "skip" "$mod_id" "Not applicable on ${OS}"
        return
    fi

    case "$mod_id" in
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
        firewall-inbound)
            if [[ "$OS" == "macos" ]]; then
                if /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null | grep -q "enabled\|State = 1\|State = 2"; then
                    record_finding "pass" "$mod_id" "Firewall enabled"
                else
                    record_finding "fail" "$mod_id" "Firewall not enabled"
                fi
            elif command -v ufw &>/dev/null; then
                if ufw status 2>/dev/null | grep -q "Status: active"; then
                    record_finding "pass" "$mod_id" "UFW active"
                else
                    record_finding "fail" "$mod_id" "UFW not active"
                fi
            else
                record_finding "fail" "$mod_id" "No firewall found"
            fi
            ;;
        firewall-stealth)
            if [[ "$OS" == "macos" ]]; then
                if /usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>/dev/null | grep -q "enabled"; then
                    record_finding "pass" "$mod_id" "Stealth mode enabled"
                else
                    record_finding "fail" "$mod_id" "Stealth mode disabled"
                fi
            elif iptables -C INPUT -p icmp --icmp-type echo-request -j DROP &>/dev/null 2>&1; then
                record_finding "pass" "$mod_id" "ICMP echo drop rule active"
            else
                record_finding "fail" "$mod_id" "Stealth mode not configured"
            fi
            ;;
        firewall-outbound)
            if [[ "$OS" == "macos" ]]; then
                if cask_installed lulu; then
                    record_finding "pass" "$mod_id" "LuLu installed"
                else
                    record_finding "fail" "$mod_id" "No outbound firewall"
                fi
            elif command -v ufw &>/dev/null && ufw status verbose 2>/dev/null | grep -q "deny (outgoing)"; then
                record_finding "pass" "$mod_id" "UFW outgoing deny active"
            else
                record_finding "fail" "$mod_id" "No outbound firewall rules"
            fi
            ;;
        dns-secure)
            if [[ "$OS" == "macos" ]]; then
                if networksetup -getdnsservers Wi-Fi 2>/dev/null | grep -q "9.9.9.9"; then
                    record_finding "pass" "$mod_id" "Quad9 DNS configured"
                else
                    record_finding "fail" "$mod_id" "Secure DNS not configured"
                fi
            elif command -v resolvectl &>/dev/null && resolvectl dns 2>/dev/null | grep -q "9.9.9.9"; then
                record_finding "pass" "$mod_id" "Quad9 DNS configured"
            elif [[ -f /etc/resolv.conf ]] && grep -q "9.9.9.9" /etc/resolv.conf 2>/dev/null; then
                record_finding "pass" "$mod_id" "Quad9 DNS in resolv.conf"
            else
                record_finding "fail" "$mod_id" "Secure DNS not configured"
            fi
            ;;
        auto-updates)
            if [[ "$OS" == "macos" ]]; then
                if [[ "$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled 2>/dev/null)" == "1" ]]; then
                    record_finding "pass" "$mod_id" "Auto-updates enabled"
                else
                    record_finding "fail" "$mod_id" "Auto-updates not enabled"
                fi
            elif [[ "$OS" == "linux" ]]; then
                if command -v unattended-upgrades &>/dev/null || systemctl is-active dnf-automatic.timer &>/dev/null 2>&1; then
                    record_finding "pass" "$mod_id" "Auto-updates configured"
                else
                    record_finding "fail" "$mod_id" "Auto-updates not configured"
                fi
            fi
            ;;
        guest-disable)
            if [[ "$OS" == "macos" ]]; then
                if [[ "$(defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled 2>/dev/null)" == "0" ]]; then
                    record_finding "pass" "$mod_id" "Guest account disabled"
                else
                    record_finding "fail" "$mod_id" "Guest account enabled"
                fi
            else
                record_finding "pass" "$mod_id" "N/A on Linux (no guest by default)"
            fi
            ;;
        lock-screen)
            if [[ "$OS" == "macos" ]]; then
                if [[ "$(run_as_user defaults read com.apple.screensaver askForPasswordDelay 2>/dev/null)" == "0" ]]; then
                    record_finding "pass" "$mod_id" "Immediate password on lock"
                else
                    record_finding "fail" "$mod_id" "Lock screen delay not zero"
                fi
            elif command -v gsettings &>/dev/null; then
                if [[ "$(run_as_user gsettings get org.gnome.desktop.screensaver lock-enabled 2>/dev/null)" == "true" ]]; then
                    record_finding "pass" "$mod_id" "Screen lock enabled"
                else
                    record_finding "fail" "$mod_id" "Screen lock not enabled"
                fi
            else
                record_finding "manual" "$mod_id" "Cannot detect lock screen config"
            fi
            ;;
        hostname-scrub)
            if [[ "$OS" == "macos" ]]; then
                local hn
                hn="$(scutil --get ComputerName 2>/dev/null)"
                if [[ "$hn" == "MacBook" || "$hn" == "Mac" ]]; then
                    record_finding "pass" "$mod_id" "Generic hostname set ($hn)"
                else
                    record_finding "fail" "$mod_id" "Hostname reveals identity ($hn)"
                fi
            else
                local hn
                hn="$(hostname 2>/dev/null)"
                if [[ "$hn" == "linux" || "$hn" == "localhost" ]]; then
                    record_finding "pass" "$mod_id" "Generic hostname set"
                else
                    record_finding "fail" "$mod_id" "Hostname may reveal identity ($hn)"
                fi
            fi
            ;;
        ssh-harden)
            if [[ -f "${REAL_HOME}/.ssh/config" ]] && grep -q "IdentitiesOnly yes" "${REAL_HOME}/.ssh/config" 2>/dev/null; then
                record_finding "pass" "$mod_id" "SSH strict config present"
            else
                record_finding "fail" "$mod_id" "SSH not hardened"
            fi
            ;;
        git-harden)
            if [[ "$(run_as_user git config --global --get commit.gpgsign 2>/dev/null)" == "true" ]]; then
                record_finding "pass" "$mod_id" "Git commit signing enabled"
            else
                record_finding "fail" "$mod_id" "Git commit signing not enabled"
            fi
            ;;
        telemetry-disable)
            if [[ "$OS" == "macos" ]]; then
                if [[ "$(defaults read com.apple.CrashReporter DialogType 2>/dev/null)" == "none" ]]; then
                    record_finding "pass" "$mod_id" "Crash reporting disabled"
                else
                    record_finding "fail" "$mod_id" "Telemetry still active"
                fi
            else
                record_finding "manual" "$mod_id" "Manual verification needed"
            fi
            ;;
        monitoring-tools)
            if [[ "$OS" == "macos" ]]; then
                if cask_installed oversight && cask_installed blockblock; then
                    record_finding "pass" "$mod_id" "Objective-See tools installed"
                elif cask_installed oversight || cask_installed blockblock; then
                    record_finding "partial" "$mod_id" "Some monitoring tools installed"
                else
                    record_finding "fail" "$mod_id" "No monitoring tools"
                fi
            elif command -v auditctl &>/dev/null && command -v aide &>/dev/null; then
                record_finding "pass" "$mod_id" "auditd + aide installed"
            else
                record_finding "fail" "$mod_id" "Monitoring tools not installed"
            fi
            ;;
        permissions-audit)
            record_finding "manual" "$mod_id" "Requires manual review"
            ;;
        browser-basic)
            local ff_profile=""
            if [[ "$OS" == "macos" ]]; then
                ff_profile=$(find "${REAL_HOME}/Library/Application Support/Firefox/Profiles" -maxdepth 1 -name "*.default-release" -type d 2>/dev/null | head -1)
            elif [[ "$OS" == "linux" ]]; then
                ff_profile=$(find "${REAL_HOME}/.mozilla/firefox" -maxdepth 1 -name "*.default-release" -type d 2>/dev/null | head -1)
            fi
            if [[ -n "$ff_profile" ]] && [[ -f "${ff_profile}/user.js" ]] && grep -q "toolkit.telemetry.enabled" "${ff_profile}/user.js" 2>/dev/null; then
                record_finding "pass" "$mod_id" "Firefox hardened (user.js present)"
            else
                record_finding "fail" "$mod_id" "Browser not hardened"
            fi
            ;;
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
                record_finding "fail" "$mod_id" "Fingerprint resistance not configured"
            fi
            ;;
        mac-rotate)
            if [[ "$OS" == "linux" ]] && [[ -f /etc/NetworkManager/conf.d/mac-randomize.conf ]]; then
                record_finding "pass" "$mod_id" "MAC randomization configured"
            elif [[ "$OS" == "macos" ]]; then
                record_finding "manual" "$mod_id" "macOS: manual verification (Wi-Fi settings)"
            else
                record_finding "fail" "$mod_id" "MAC rotation not configured"
            fi
            ;;
        vpn-killswitch)
            if command -v mullvad &>/dev/null && mullvad always-require-vpn get 2>/dev/null | grep -qi "enabled\|on"; then
                record_finding "pass" "$mod_id" "Mullvad always-on VPN active"
            elif command -v mullvad &>/dev/null; then
                record_finding "partial" "$mod_id" "Mullvad installed but kill switch not verified"
            else
                record_finding "manual" "$mod_id" "VPN kill switch requires manual setup"
            fi
            ;;
        traffic-obfuscation)
            record_finding "manual" "$mod_id" "Requires manual configuration (DAITA/Tor)"
            ;;
        metadata-strip)
            if command -v exiftool &>/dev/null; then
                record_finding "pass" "$mod_id" "exiftool installed"
            else
                record_finding "fail" "$mod_id" "No metadata stripping tools"
            fi
            ;;
        dev-isolation)
            if [[ "$OS" == "macos" ]] && [[ -d "/Applications/UTM.app" ]]; then
                record_finding "pass" "$mod_id" "UTM installed for VM isolation"
            elif command -v docker &>/dev/null; then
                record_finding "pass" "$mod_id" "Docker available for isolation"
            else
                record_finding "manual" "$mod_id" "No isolation tools detected"
            fi
            ;;
        audit-script)
            if [[ "$OS" == "macos" ]] && [[ -f "${REAL_HOME}/Library/LaunchAgents/com.secure.weekly-audit.plist" ]]; then
                record_finding "pass" "$mod_id" "Weekly audit scheduled"
            elif [[ "$OS" == "linux" ]] && crontab -u "${REAL_USER}" -l 2>/dev/null | grep -q "weekly-audit"; then
                record_finding "pass" "$mod_id" "Weekly audit cron active"
            else
                record_finding "fail" "$mod_id" "No automated audit schedule"
            fi
            ;;
        backup-guidance)
            record_finding "manual" "$mod_id" "Requires manual verification"
            ;;
        border-prep)
            record_finding "manual" "$mod_id" "Requires manual verification"
            ;;
        bluetooth-disable)
            if [[ "$OS" == "linux" ]] && ! systemctl is-active bluetooth &>/dev/null 2>&1; then
                record_finding "pass" "$mod_id" "Bluetooth service disabled"
            elif [[ "$OS" == "macos" ]]; then
                record_finding "manual" "$mod_id" "macOS: manual check (System Settings)"
            else
                record_finding "fail" "$mod_id" "Bluetooth still active"
            fi
            ;;
        kernel-sysctl)
            if [[ "$OS" != "linux" ]]; then
                record_finding "skip" "$mod_id" "Not applicable on ${OS}"
                return
            fi
            if [[ -f /etc/sysctl.d/99-hardening.conf ]]; then
                record_finding "pass" "$mod_id" "Kernel hardening sysctl active"
            elif [[ "$(cat /proc/sys/kernel/randomize_va_space 2>/dev/null)" == "2" ]] && \
                 [[ "$(cat /proc/sys/net/ipv4/tcp_syncookies 2>/dev/null)" == "1" ]]; then
                record_finding "partial" "$mod_id" "Some kernel params hardened"
            else
                record_finding "fail" "$mod_id" "Kernel not hardened"
            fi
            ;;
        apparmor-enforce)
            if [[ "$OS" == "linux" ]]; then
                if command -v aa-status &>/dev/null && aa-status 2>/dev/null | grep -q "enforce"; then
                    record_finding "pass" "$mod_id" "AppArmor profiles enforcing"
                elif command -v aa-status &>/dev/null; then
                    record_finding "partial" "$mod_id" "AppArmor loaded but not all enforcing"
                else
                    record_finding "fail" "$mod_id" "AppArmor not available"
                fi
            elif [[ "$OS" == "macos" ]]; then
                record_finding "manual" "$mod_id" "macOS: audit-only (Sandbox/Hardened Runtime)"
            fi
            ;;
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
                    record_finding "fail" "$mod_id" "Secure Boot not verified"
                fi
            fi
            ;;
        *)
            record_finding "skip" "$mod_id" "Unknown module"
            ;;
    esac
}
```

**Step 2: Verify the script still parses**

Run: `bash -n scripts/barked.sh`
Expected: No output

**Step 3: Commit**

```bash
git add scripts/barked.sh
git commit -m "feat: add per-module check functions for audit mode"
```

---

### Task 5: Add Audit Mode Flow

**Files:**
- Modify: `scripts/barked.sh` — add `run_audit()` function before the MAIN section (~line 3090), and update `main()` to route to it

**Step 1: Add run_audit() function**

Insert before the MAIN section:

```bash
# ═══════════════════════════════════════════════════════════════════
# AUDIT MODE
# ═══════════════════════════════════════════════════════════════════
run_audit() {
    # Determine which modules to audit
    local -a audit_modules=()
    if [[ -n "$CLI_PROFILE" ]]; then
        PROFILE="$CLI_PROFILE"
        build_module_list
        audit_modules=("${ENABLED_MODULES[@]}")
        # Also add advanced modules if they're applicable
        for adv in "${ADVANCED_MODULES[@]}"; do
            audit_modules+=("$adv")
        done
    else
        # Audit all modules
        audit_modules=("${ALL_MODULE_IDS[@]}")
        # Add new advanced modules
        for adv in "${ADVANCED_MODULES[@]}"; do
            audit_modules+=("$adv")
        done
    fi

    # Deduplicate
    local -A seen
    local -a deduped=()
    for mod in "${audit_modules[@]}"; do
        if [[ -z "${seen[$mod]:-}" ]]; then
            seen[$mod]=1
            deduped+=("$mod")
        fi
    done
    audit_modules=("${deduped[@]}")

    if ! $QUIET_MODE; then
        print_section "Security Audit${CLI_PROFILE:+ (${CLI_PROFILE} profile)}"
        echo -e "  Scanning ${#audit_modules[@]} modules..."
        echo ""
    fi

    # Run checks
    for mod_id in "${audit_modules[@]}"; do
        check_module_state "$mod_id"
    done

    # Calculate score
    calculate_score

    # Display
    if ! $QUIET_MODE; then
        print_findings_table
        print_score_bar "$SCORE_CURRENT"
        echo ""
    fi

    # Save report
    local report_file="${SCRIPT_DIR}/../audits/audit-${DATE}.md"
    write_findings_report "$report_file"
    if ! $QUIET_MODE; then
        echo -e "  ${GREEN}Report saved to:${NC} ${report_file}"
    fi

    # Exit code based on score
    if [[ $SCORE_CURRENT -ge 80 ]]; then
        exit 0
    else
        exit 1
    fi
}
```

**Step 2: Update main() to route audit mode**

In the `main()` function (line ~3093), add the audit case to the routing switch. Insert before the `uninstall)` case:

```bash
        audit)
            run_audit
            ;;
```

**Step 3: Verify the script still parses**

Run: `bash -n scripts/barked.sh`
Expected: No output

**Step 4: Commit**

```bash
git add scripts/barked.sh
git commit -m "feat: add audit mode with scoring, findings table, and report output"
```

---

### Task 6: Add Pre-Change Analysis to Wizard Flow

**Files:**
- Modify: `scripts/barked.sh` — update `main()` harden flow (lines ~3130-3141)

**Step 1: Add pre_change_analysis() function**

Insert near `run_audit()`:

```bash
# Run pre-change analysis inline during wizard
pre_change_analysis() {
    local -a modules_to_check=("${ENABLED_MODULES[@]}")

    # Reset findings
    FINDINGS_STATUS=()
    FINDINGS_MODULE=()
    FINDINGS_MESSAGE=()

    # Check all selected modules
    for mod_id in "${modules_to_check[@]}"; do
        check_module_state "$mod_id"
    done

    calculate_score
    local current_score=$SCORE_CURRENT

    # Count categories
    local already=0 na=0 partial=0 to_apply=0
    for i in "${!FINDINGS_STATUS[@]}"; do
        case "${FINDINGS_STATUS[$i]}" in
            pass)    ((already++)) ;;
            skip)    ((na++)) ;;
            partial) ((partial++)) ;;
            fail|manual) ((to_apply++)) ;;
        esac
    done

    # Project score assuming all fail/manual/partial become pass
    local projected_earned=0 projected_possible=0
    for i in "${!FINDINGS_MODULE[@]}"; do
        local mod_id="${FINDINGS_MODULE[$i]}"
        local status="${FINDINGS_STATUS[$i]}"
        local weight="${MODULE_SEVERITY[$mod_id]:-0}"
        [[ "$status" == "skip" ]] && continue
        projected_possible=$((projected_possible + weight))
        # All non-skip modules count as earned in projection
        projected_earned=$((projected_earned + weight))
    done
    local projected_score=0
    if [[ $projected_possible -gt 0 ]]; then
        projected_score=$(( (projected_earned * 100) / projected_possible ))
    fi

    echo ""
    echo -e "  ${BOLD}Pre-change analysis complete.${NC}"
    echo ""
    echo -e "    Already applied:   ${GREEN}${already}${NC} modules (skipping)"
    echo -e "    Not applicable:    ${DIM}${na}${NC} modules (skipping)"
    echo -e "    Partially applied: ${MAGENTA}${partial}${NC} modules (will complete)"
    echo -e "    To apply:          ${BOLD}${to_apply}${NC} modules"
    echo ""
    echo -e "    Current score:   ${BOLD}${current_score}/100${NC}"
    echo -e "    Projected score: ${BOLD}${projected_score}/100${NC}"
    echo ""
}
```

**Step 2: Insert pre_change_analysis call in main()**

Replace the block in `main()` that shows "Modules to apply" and prompts (lines ~3133-3139) with:

```bash
            # Pre-change analysis
            pre_change_analysis

            if ! prompt_yn "Proceed with hardening?"; then
                echo "Aborted."
                exit 0
            fi
```

**Step 3: Verify the script still parses**

Run: `bash -n scripts/barked.sh`
Expected: No output

**Step 4: Commit**

```bash
git add scripts/barked.sh
git commit -m "feat: add pre-change analysis with projected score to wizard flow"
```

---

### Task 7: Add Dry-Run Mode

**Files:**
- Modify: `scripts/barked.sh` — update `run_module()` and add dry-run report logic

**Step 1: Update run_module() to support dry-run**

Modify the `run_module()` function (line ~1055). Add a dry-run guard at the top of the apply branch. Replace the apply branch (lines ~1070-1076):

```bash
    else
        if declare -f "$mod_func" &>/dev/null; then
            if $DRY_RUN; then
                # Dry-run: check state and report what would happen
                check_module_state "$mod_id"
                local sev
                sev=$(severity_label "$mod_id")
                local last_status="${FINDINGS_STATUS[-1]:-}"
                local last_msg="${FINDINGS_MESSAGE[-1]:-}"
                echo ""
                echo -e "  ${CYAN}[DRY RUN]${NC} ${BOLD}${mod_id}${NC}"
                echo -e "    Current:  ${last_msg}"
                echo -e "    Planned:  $(dry_run_description "$mod_id")"
                echo -e "    Severity: ${sev}$(is_advanced_module "$mod_id" && echo " (Advanced — requires confirmation in live run)")"
                if [[ "$last_status" == "pass" ]]; then
                    MODULE_RESULT="skipped"
                else
                    MODULE_RESULT="applied"  # would be applied
                fi
            else
                "$mod_func"
            fi
        else
            MODULE_RESULT="skipped_unsupported"
        fi
    fi
```

**Step 2: Add dry_run_description() helper**

Insert near the scoring functions:

```bash
# Human-readable description of what a module would do
dry_run_description() {
    local mod_id="$1"
    case "$mod_id" in
        disk-encrypt)       echo "Verify disk encryption (manual)" ;;
        firewall-inbound)   echo "Enable system firewall, block all incoming" ;;
        firewall-stealth)   echo "Enable stealth mode / drop ICMP probes" ;;
        firewall-outbound)  echo "Install/enable outbound firewall (LuLu/ufw)" ;;
        dns-secure)         echo "Set DNS to Quad9 (9.9.9.9)" ;;
        auto-updates)       echo "Enable automatic security updates" ;;
        guest-disable)      echo "Disable guest account" ;;
        lock-screen)        echo "Set immediate password on lock, zero delay" ;;
        hostname-scrub)     echo "Set generic hostname" ;;
        ssh-harden)         echo "Configure Ed25519 keys, strict SSH config" ;;
        git-harden)         echo "Enable SSH commit signing" ;;
        telemetry-disable)  echo "Disable OS telemetry and crash reporting" ;;
        monitoring-tools)   echo "Install monitoring tools (Objective-See/auditd+aide)" ;;
        permissions-audit)  echo "Audit granted privacy permissions" ;;
        browser-basic)      echo "Harden Firefox (disable telemetry, trackers, HTTPS-only)" ;;
        browser-fingerprint) echo "Enable fingerprint resistance, clear-on-quit" ;;
        mac-rotate)         echo "Configure MAC address rotation" ;;
        vpn-killswitch)     echo "Enable Mullvad always-on VPN" ;;
        traffic-obfuscation) echo "Configure DAITA/Tor (manual guidance)" ;;
        metadata-strip)     echo "Install exiftool/mat2" ;;
        dev-isolation)      echo "Configure Docker hardening / VM guidance" ;;
        audit-script)       echo "Schedule weekly automated audit" ;;
        backup-guidance)    echo "Review encrypted backup strategy (manual)" ;;
        border-prep)        echo "Review border crossing protocol (manual)" ;;
        bluetooth-disable)  echo "Disable Bluetooth service" ;;
        kernel-sysctl)      echo "Harden kernel parameters via sysctl.d" ;;
        apparmor-enforce)   echo "Set AppArmor profiles to enforce mode" ;;
        boot-security)      echo "Verify Secure Boot / SIP, set GRUB password" ;;
        *)                  echo "Unknown action" ;;
    esac
}
```

**Step 3: Add dry-run report writing at end of main flow**

In `main()`, after `run_all_modules` and before `state_write`, add:

```bash
            # Dry-run: write report and exit
            if $DRY_RUN; then
                calculate_score
                if ! $QUIET_MODE; then
                    echo ""
                    print_findings_table
                    print_score_bar "$SCORE_CURRENT"
                fi
                local dryrun_file="${SCRIPT_DIR}/../audits/dry-run-${DATE}.md"
                write_findings_report "$dryrun_file"
                if ! $QUIET_MODE; then
                    echo ""
                    echo -e "  ${GREEN}Dry-run report saved to:${NC} ${dryrun_file}"
                fi
                write_log
                if [[ $COUNT_FAILED -gt 0 ]]; then exit 1; else exit 0; fi
            fi
```

**Step 4: Verify the script still parses**

Run: `bash -n scripts/barked.sh`
Expected: No output

**Step 5: Commit**

```bash
git add scripts/barked.sh
git commit -m "feat: add dry-run mode with per-module preview and report output"
```

---

### Task 8: Add Non-Interactive (Auto) Mode

**Files:**
- Modify: `scripts/barked.sh` — update `main()` harden flow

**Step 1: Add auto-mode branch in main()**

In the `main()` function, inside the `harden)` case, add an auto-mode branch before the interactive wizard. After `if [[ "$RUN_MODE" == "harden" ]]; then` routing, and before `select_profile`:

```bash
            # Auto mode: non-interactive
            if $AUTO_MODE; then
                PROFILE="$CLI_PROFILE"
                OUTPUT_MODE="checklist"
                build_module_list

                # Filter out advanced modules unless --accept-advanced
                if ! $ACCEPT_ADVANCED; then
                    local -a filtered=()
                    for mod in "${ENABLED_MODULES[@]}"; do
                        if ! is_advanced_module "$mod"; then
                            filtered+=("$mod")
                        else
                            if ! $QUIET_MODE; then
                                echo -e "  ${DIM}Skipping advanced module: ${mod} (use --accept-advanced to include)${NC}"
                            fi
                        fi
                    done
                    ENABLED_MODULES=("${filtered[@]}")
                    TOTAL_MODULES=${#ENABLED_MODULES[@]}
                fi

                if ! $QUIET_MODE; then
                    echo -e "  Profile: ${BOLD}${PROFILE}${NC} | Modules: ${BOLD}${TOTAL_MODULES}${NC}"
                    echo ""
                fi

                # Load existing state for smart-skip
                state_read || detect_applied_modules

                run_all_modules

                if ! $DRY_RUN; then
                    state_write
                fi

                if ! $QUIET_MODE; then
                    print_summary
                    print_manual_checklist
                fi
                write_log

                # Exit codes: 0=applied, 1=failures, 2=nothing to do
                if [[ $COUNT_FAILED -gt 0 ]]; then
                    exit 1
                elif [[ $COUNT_APPLIED -eq 0 ]]; then
                    exit 2
                else
                    exit 0
                fi
            fi
```

**Step 2: Verify the script still parses**

Run: `bash -n scripts/barked.sh`
Expected: No output

**Step 3: Commit**

```bash
git add scripts/barked.sh
git commit -m "feat: add non-interactive auto mode with --auto --profile flags"
```

---

### Task 9: Add Advanced Module Vetting Flow

**Files:**
- Modify: `scripts/barked.sh` — add `vet_advanced_module()` and integrate into module runner

**Step 1: Add the vetting function**

Insert near the scoring section:

```bash
# ═══════════════════════════════════════════════════════════════════
# ADVANCED MODULE VETTING
# ═══════════════════════════════════════════════════════════════════

# Vet an advanced module: warning + mandatory dry-run preview + YES confirmation
# Returns 0 if approved, 1 if rejected
vet_advanced_module() {
    local mod_id="$1"

    # In dry-run mode, show preview without confirmation
    if $DRY_RUN; then
        return 0
    fi

    # In auto mode without --accept-advanced, skip
    if $AUTO_MODE && ! $ACCEPT_ADVANCED; then
        return 1
    fi

    local title="" risk=""
    case "$mod_id" in
        kernel-sysctl)
            title="Kernel Sysctl Hardening"
            risk="This module modifies kernel parameters that can affect\n  system stability, networking, and application behavior.\n\n  Risk: Misconfigured sysctl can cause network failures,\n  break containerized workloads, or prevent boot."
            ;;
        apparmor-enforce)
            title="AppArmor Enforcement"
            risk="This module switches AppArmor profiles from complain\n  to enforce mode, which will block policy violations.\n\n  Risk: Enforcing untested profiles can break applications\n  that rely on currently-permitted behaviors."
            ;;
        boot-security)
            title="Boot Security Hardening"
            risk="This module modifies boot configuration including\n  GRUB passwords and Secure Boot verification.\n\n  Risk: Incorrect GRUB configuration can prevent system\n  boot. Ensure you have recovery media available."
            ;;
    esac

    echo ""
    echo -e "  ${RED}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "  ${RED}║${NC}  ${YELLOW}⚠${NC}  ${BOLD}ADVANCED MODULE: ${title}${NC}"
    echo -e "  ${RED}║${NC}"
    echo -e "  ${RED}║${NC}  ${risk}"
    echo -e "  ${RED}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    # Mandatory dry-run preview
    echo -e "  ${BOLD}Running mandatory dry-run preview...${NC}"
    echo ""

    # Run the module-specific preview
    case "$mod_id" in
        kernel-sysctl)
            _preview_kernel_sysctl
            ;;
        apparmor-enforce)
            _preview_apparmor
            ;;
        boot-security)
            _preview_boot_security
            ;;
    esac

    echo ""
    echo -ne "  ${BOLD}Type YES to apply these changes:${NC} "
    read -r confirm
    if [[ "$confirm" == "YES" ]]; then
        return 0
    else
        echo -e "  ${YELLOW}Skipped (user declined).${NC}"
        return 1
    fi
}

_preview_kernel_sysctl() {
    local -a params=(
        "kernel.randomize_va_space:2"
        "fs.suid_dumpable:0"
        "net.ipv4.conf.all.rp_filter:1"
        "net.ipv4.tcp_syncookies:1"
        "net.ipv4.conf.all.accept_redirects:0"
        "net.ipv4.conf.all.accept_source_route:0"
    )
    local changes=0 correct=0
    printf "    %-44s %-10s %s\n" "Parameter" "Current" "Proposed"
    printf "    %-44s %-10s %s\n" "---------" "-------" "--------"
    for entry in "${params[@]}"; do
        local param="${entry%%:*}"
        local proposed="${entry#*:}"
        local current
        current="$(cat /proc/sys/${param//\.//} 2>/dev/null || echo "?")"
        if [[ "$current" == "$proposed" ]]; then
            printf "    %-44s %-10s %s\n" "$param" "$current" "$proposed (no change)"
            ((correct++))
        else
            printf "    %-44s %-10s %s\n" "$param" "$current" "$proposed"
            ((changes++))
        fi
    done
    echo ""
    echo -e "    ${BOLD}${changes} parameters will change. ${correct} already correct.${NC}"
}

_preview_apparmor() {
    if [[ "$OS" == "linux" ]] && command -v aa-status &>/dev/null; then
        local enforce_count complain_count
        enforce_count=$(aa-status 2>/dev/null | grep -c "enforce" || echo 0)
        complain_count=$(aa-status 2>/dev/null | grep -c "complain" || echo 0)
        echo -e "    Profiles in enforce mode:  ${enforce_count}"
        echo -e "    Profiles in complain mode: ${complain_count}"
        echo ""
        echo -e "    ${BOLD}${complain_count} profiles will be switched to enforce mode.${NC}"
    elif [[ "$OS" == "macos" ]]; then
        echo -e "    macOS: Will audit App Sandbox and Hardened Runtime status"
        echo -e "    (informational only — no system changes on macOS)"
    fi
}

_preview_boot_security() {
    if [[ "$OS" == "linux" ]]; then
        local sb_status="unknown"
        if mokutil --sb-state 2>/dev/null | grep -qi "enabled"; then
            sb_status="enabled"
        else
            sb_status="disabled/unknown"
        fi
        local grub_pw="not set"
        if [[ -f /etc/grub.d/40_custom ]] && grep -q "password_pbkdf2" /etc/grub.d/40_custom 2>/dev/null; then
            grub_pw="set"
        fi
        echo -e "    Secure Boot: ${sb_status}"
        echo -e "    GRUB password: ${grub_pw}"
        echo ""
        if [[ "$grub_pw" == "not set" ]]; then
            echo -e "    ${BOLD}Will set GRUB password to protect boot configuration.${NC}"
        else
            echo -e "    ${BOLD}GRUB password already set. No boot changes needed.${NC}"
        fi
    elif [[ "$OS" == "macos" ]]; then
        local sip_status="unknown"
        if csrutil status 2>/dev/null | grep -q "enabled"; then
            sip_status="enabled"
        else
            sip_status="disabled"
        fi
        echo -e "    SIP: ${sip_status}"
        echo ""
        if [[ "$sip_status" == "enabled" ]]; then
            echo -e "    ${BOLD}SIP already enabled. Will verify authenticated-root.${NC}"
        else
            echo -e "    ${BOLD}SIP is disabled — manual re-enable required (Recovery Mode).${NC}"
        fi
    fi
}
```

**Step 2: Integrate vetting into run_module()**

In the `run_module()` function, add a vetting check before calling the module function. Inside the apply branch, before `"$mod_func"`, add:

```bash
                # Advanced module vetting
                if is_advanced_module "$mod_id" && ! $DRY_RUN; then
                    if ! vet_advanced_module "$mod_id"; then
                        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$(echo "$mod_id" | tr '-' ' ')" "skipped"
                        log_entry "$mod_id" "vet" "skip" "User declined advanced module"
                        MODULE_RESULT="skipped"
                        return
                    fi
                fi
```

**Step 3: Verify the script still parses**

Run: `bash -n scripts/barked.sh`
Expected: No output

**Step 4: Commit**

```bash
git add scripts/barked.sh
git commit -m "feat: add advanced module vetting with warning, preview, and YES confirmation"
```

---

### Task 10: Add Three Advanced Hardening Modules

**Files:**
- Modify: `scripts/barked.sh` — add modules after `mod_bluetooth_disable` (~line 2253), add reverts after existing reverts (~line 2766)

**Step 1: Add mod_kernel_sysctl()**

Insert after `mod_bluetooth_disable`:

```bash
# ═══════════════════════════════════════════════════════════════════
# MODULE: kernel-sysctl (Linux only — ADVANCED)
# ═══════════════════════════════════════════════════════════════════
mod_kernel_sysctl() {
    local desc="Kernel sysctl hardening"
    if [[ "$OS" != "linux" ]]; then
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "skipped_unsupported"
        log_entry "kernel-sysctl" "check" "skip" "Not applicable on ${OS}"
        MODULE_RESULT="skipped_unsupported"
        return
    fi

    if [[ -f /etc/sysctl.d/99-hardening.conf ]]; then
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "skipped"
        log_entry "kernel-sysctl" "check" "skip" "Sysctl hardening already applied"
        MODULE_RESULT="skipped"
        return
    fi

    print_progress "$desc"

    # Save current values
    local prev_values=""
    for param in kernel.randomize_va_space fs.suid_dumpable net.ipv4.conf.all.rp_filter net.ipv4.tcp_syncookies net.ipv4.conf.all.accept_redirects net.ipv4.conf.all.accept_source_route; do
        local val
        val="$(sysctl -n "$param" 2>/dev/null || echo "?")"
        prev_values+="${param}=${val};"
    done

    # Write sysctl config
    cat > /etc/sysctl.d/99-hardening.conf << 'SYSCTL'
# Security hardening — applied by barked.sh
kernel.randomize_va_space = 2
fs.suid_dumpable = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
SYSCTL

    # Apply immediately
    sysctl --system &>/dev/null

    clear_progress
    print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "applied"
    log_entry "kernel-sysctl" "apply" "applied" "Sysctl hardening config written"
    state_set_module "kernel-sysctl" "applied" "$prev_values"
    MODULE_RESULT="applied"
}
```

**Step 2: Add mod_apparmor_enforce()**

```bash
# ═══════════════════════════════════════════════════════════════════
# MODULE: apparmor-enforce (Linux: enforce, macOS: audit-only — ADVANCED)
# ═══════════════════════════════════════════════════════════════════
mod_apparmor_enforce() {
    local desc="AppArmor / Sandbox enforcement"
    if [[ "$OS" == "macos" ]]; then
        # macOS: informational audit only
        print_progress "$desc (audit)"
        local non_sandboxed=0
        while IFS= read -r app; do
            if ! codesign -d --entitlements - "$app" 2>/dev/null | grep -q "com.apple.security.app-sandbox"; then
                ((non_sandboxed++))
            fi
        done < <(find /Applications -maxdepth 2 -name "*.app" -type d 2>/dev/null)
        clear_progress
        if [[ $non_sandboxed -gt 0 ]]; then
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc — ${non_sandboxed} apps without sandbox" "manual"
            log_entry "apparmor-enforce" "audit" "manual" "${non_sandboxed} apps without App Sandbox"
            MODULE_RESULT="manual"
        else
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "skipped"
            log_entry "apparmor-enforce" "audit" "skip" "All apps sandboxed"
            MODULE_RESULT="skipped"
        fi
        return
    fi

    # Linux: AppArmor enforcement
    if ! command -v aa-enforce &>/dev/null; then
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "failed"
        log_entry "apparmor-enforce" "check" "failed" "AppArmor tools not installed"
        MODULE_RESULT="failed"
        return
    fi

    # Check if already all enforcing
    local complain_count
    complain_count=$(aa-status 2>/dev/null | grep -c "complain" || echo 0)
    if [[ "$complain_count" -eq 0 ]]; then
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "skipped"
        log_entry "apparmor-enforce" "check" "skip" "All profiles already enforcing"
        MODULE_RESULT="skipped"
        return
    fi

    print_progress "$desc"

    # Save list of complain-mode profiles
    local prev_profiles
    prev_profiles="$(aa-status 2>/dev/null | grep "complain" | awk '{print $1}' | tr '\n' ';')"

    # Enforce all profiles
    aa-enforce /etc/apparmor.d/* &>/dev/null

    clear_progress
    print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc — ${complain_count} profiles enforced" "applied"
    log_entry "apparmor-enforce" "apply" "applied" "Switched ${complain_count} profiles to enforce"
    state_set_module "apparmor-enforce" "applied" "$prev_profiles"
    MODULE_RESULT="applied"
}
```

**Step 3: Add mod_boot_security()**

```bash
# ═══════════════════════════════════════════════════════════════════
# MODULE: boot-security (Linux + macOS — ADVANCED)
# ═══════════════════════════════════════════════════════════════════
mod_boot_security() {
    local desc="Boot security verification"
    if [[ "$OS" == "macos" ]]; then
        # Check SIP
        if csrutil status 2>/dev/null | grep -q "enabled"; then
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc (SIP enabled)" "skipped"
            log_entry "boot-security" "check" "skip" "SIP already enabled"
            MODULE_RESULT="skipped"
        else
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc (SIP disabled)" "manual"
            log_entry "boot-security" "check" "manual" "SIP is disabled — re-enable in Recovery Mode"
            pause_guide "Re-enable SIP: Boot to Recovery Mode (hold Cmd+R), open Terminal, run: csrutil enable"
            MODULE_RESULT="manual"
        fi
        return
    fi

    # Linux: Secure Boot + GRUB password
    print_progress "$desc"

    local applied_something=false

    # Check Secure Boot
    if mokutil --sb-state 2>/dev/null | grep -qi "SecureBoot enabled"; then
        log_entry "boot-security" "check" "skip" "Secure Boot already enabled"
    else
        log_entry "boot-security" "check" "manual" "Secure Boot not enabled — enable in BIOS/UEFI"
        MANUAL_STEPS+=("Enable Secure Boot in your BIOS/UEFI firmware settings")
    fi

    # Check/set GRUB password
    if [[ -f /etc/grub.d/40_custom ]] && grep -q "password_pbkdf2" /etc/grub.d/40_custom 2>/dev/null; then
        log_entry "boot-security" "check" "skip" "GRUB password already set"
    else
        # Generate a GRUB password
        echo -e "\n  ${YELLOW}GRUB boot password setup:${NC}"
        echo -e "  This prevents unauthorized boot parameter changes."
        echo -ne "  Enter GRUB password: "
        read -rs grub_pw
        echo ""
        echo -ne "  Confirm password: "
        read -rs grub_pw2
        echo ""

        if [[ "$grub_pw" != "$grub_pw2" ]]; then
            clear_progress
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "failed"
            log_entry "boot-security" "apply" "failed" "GRUB passwords did not match"
            MODULE_RESULT="failed"
            return
        fi

        # Generate PBKDF2 hash
        local grub_hash
        grub_hash=$(echo -e "${grub_pw}\n${grub_pw}" | grub-mkpasswd-pbkdf2 2>/dev/null | grep "grub.pbkdf2" | awk '{print $NF}')
        if [[ -z "$grub_hash" ]]; then
            clear_progress
            print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "failed"
            log_entry "boot-security" "apply" "failed" "Failed to generate GRUB hash"
            MODULE_RESULT="failed"
            return
        fi

        # Backup and write
        cp /etc/grub.d/40_custom /etc/grub.d/40_custom.bak 2>/dev/null
        cat >> /etc/grub.d/40_custom << GRUBPW

# Security hardening — added by barked.sh
set superusers="admin"
password_pbkdf2 admin ${grub_hash}
GRUBPW

        # Update GRUB
        update-grub &>/dev/null || grub-mkconfig -o /boot/grub/grub.cfg &>/dev/null
        applied_something=true
    fi

    # Check for unsigned kernel modules
    local unsigned_count=0
    while IFS= read -r mod; do
        if ! modinfo "$mod" 2>/dev/null | grep -q "sig_id"; then
            ((unsigned_count++))
        fi
    done < <(lsmod 2>/dev/null | tail -n+2 | awk '{print $1}')

    if [[ $unsigned_count -gt 0 ]]; then
        log_entry "boot-security" "audit" "manual" "${unsigned_count} unsigned kernel modules detected"
        MANUAL_STEPS+=("Review ${unsigned_count} unsigned kernel modules (run: lsmod | while read mod _; do modinfo \$mod 2>/dev/null | grep -q sig_id || echo \$mod; done)")
    fi

    clear_progress
    if $applied_something; then
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "applied"
        log_entry "boot-security" "apply" "applied" "GRUB password set"
        state_set_module "boot-security" "applied" "grub-password"
        MODULE_RESULT="applied"
    else
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "skipped"
        log_entry "boot-security" "check" "skip" "Boot security already configured"
        MODULE_RESULT="skipped"
    fi
}
```

**Step 4: Add revert functions for all three**

Insert after the existing revert functions:

```bash
revert_kernel_sysctl() {
    local desc="Revert kernel sysctl hardening"
    if [[ "$OS" != "linux" ]]; then
        MODULE_RESULT="skipped"
        return
    fi
    if [[ ! -f /etc/sysctl.d/99-hardening.conf ]]; then
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "skipped"
        MODULE_RESULT="skipped"
        return
    fi

    # Restore previous values if available
    local prev="${STATE_PREVIOUS[kernel-sysctl]:-}"
    if [[ -n "$prev" ]]; then
        IFS=';' read -ra pairs <<< "$prev"
        for pair in "${pairs[@]}"; do
            [[ -z "$pair" ]] && continue
            local param="${pair%%=*}"
            local val="${pair#*=}"
            sysctl -w "${param}=${val}" &>/dev/null
        done
    fi

    rm -f /etc/sysctl.d/99-hardening.conf
    sysctl --system &>/dev/null
    print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "reverted"
    log_entry "kernel-sysctl" "revert" "reverted" "Removed sysctl hardening"
    MODULE_RESULT="reverted"
}

revert_apparmor_enforce() {
    local desc="Revert AppArmor enforcement"
    if [[ "$OS" != "linux" ]] || ! command -v aa-complain &>/dev/null; then
        MODULE_RESULT="skipped"
        return
    fi

    local prev="${STATE_PREVIOUS[apparmor-enforce]:-}"
    if [[ -n "$prev" ]]; then
        IFS=';' read -ra profiles <<< "$prev"
        for profile in "${profiles[@]}"; do
            [[ -z "$profile" ]] && continue
            aa-complain "$profile" &>/dev/null
        done
    else
        aa-complain /etc/apparmor.d/* &>/dev/null
    fi

    print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "reverted"
    log_entry "apparmor-enforce" "revert" "reverted" "Profiles returned to complain mode"
    MODULE_RESULT="reverted"
}

revert_boot_security() {
    local desc="Revert boot security"
    if [[ "$OS" == "macos" ]]; then
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "skipped"
        log_entry "boot-security" "revert" "skip" "macOS SIP cannot be reverted via script"
        MODULE_RESULT="skipped"
        return
    fi

    # Restore GRUB config
    if [[ -f /etc/grub.d/40_custom.bak ]]; then
        cp /etc/grub.d/40_custom.bak /etc/grub.d/40_custom
        rm -f /etc/grub.d/40_custom.bak
        update-grub &>/dev/null || grub-mkconfig -o /boot/grub/grub.cfg &>/dev/null
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "reverted"
        log_entry "boot-security" "revert" "reverted" "GRUB password removed"
        MODULE_RESULT="reverted"
    else
        print_status "$CURRENT_MODULE" "$TOTAL_MODULES" "$desc" "skipped"
        log_entry "boot-security" "revert" "skip" "No backup to restore"
        MODULE_RESULT="skipped"
    fi
}
```

**Step 5: Update ALL_MODULE_IDS and ALL_MODULE_LABELS arrays**

Add the three new modules to the `ALL_MODULE_IDS` array (line ~606) and `ALL_MODULE_LABELS` array (line ~619). Add them at the end of their respective groups:

In `ALL_MODULE_IDS`, add after `border-prep`:
```bash
    kernel-sysctl apparmor-enforce boot-security
```

In `ALL_MODULE_LABELS`, add after the border-prep label:
```bash
    "kernel-sysctl      — ⚠ Kernel parameter hardening (Advanced)"
    "apparmor-enforce    — ⚠ AppArmor / App Sandbox enforcement (Advanced)"
    "boot-security       — ⚠ Secure Boot / SIP / GRUB protection (Advanced)"
```

Add a new group header in `ALL_MODULE_GROUPS`:
```bash
    "25:ADVANCED (requires vetting)"
```

**Step 6: Update build_module_list() for paranoid profile**

In `build_module_list()`, the paranoid profile should include the advanced modules. Add to the paranoid block (after line ~1000):

```bash
        ENABLED_MODULES+=(
            "kernel-sysctl"
            "apparmor-enforce"
            "boot-security"
        )
```

**Step 7: Verify the script still parses**

Run: `bash -n scripts/barked.sh`
Expected: No output

**Step 8: Commit**

```bash
git add scripts/barked.sh
git commit -m "feat: add kernel-sysctl, apparmor-enforce, boot-security modules with reverts"
```

---

### Task 11: Update Summary Display with Findings Table and Score

**Files:**
- Modify: `scripts/barked.sh` — update `print_summary()` (line ~2944)

**Step 1: Enhance print_summary() to include score**

Replace the existing `print_summary()` with:

```bash
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

    # Show score if findings were collected
    if [[ ${#FINDINGS_MODULE[@]} -gt 0 ]]; then
        calculate_score
        print_score_bar "$SCORE_CURRENT"
        echo ""
    fi

    echo -e "  Profile: ${BOLD}${PROFILE}${NC} | OS: ${BOLD}${OS}${NC} | Date: ${BOLD}${DATE}${NC}"
    echo ""
}
```

**Step 2: Collect findings during run_all_modules**

In `run_all_modules()` (line ~1095), add a post-run findings collection. After the `for` loop, add:

```bash
    # Collect findings for scoring
    FINDINGS_STATUS=()
    FINDINGS_MODULE=()
    FINDINGS_MESSAGE=()
    for mod_id in "${ENABLED_MODULES[@]}"; do
        check_module_state "$mod_id"
    done
```

**Step 3: Verify the script still parses**

Run: `bash -n scripts/barked.sh`
Expected: No output

**Step 4: Commit**

```bash
git add scripts/barked.sh
git commit -m "feat: show hardening score in summary after wizard run"
```

---

### Task 12: Update Help Text and Final Integration

**Files:**
- Modify: `scripts/barked.sh` — update header comment, version

**Step 1: Update the version number**

Change line 8 from `readonly VERSION="1.0.0"` to:

```bash
readonly VERSION="2.0.0"
```

**Step 2: Update the header comment**

Update lines 2-5:

```bash
# ═══════════════════════════════════════════════════════════════════
# barked.sh — Cross-platform security hardening wizard (macOS/Linux)
# Idempotent, interactive, profile-based system hardening
# Supports: audit, dry-run, non-interactive, and advanced modules
# ═══════════════════════════════════════════════════════════════════
```

**Step 3: Verify the complete script parses**

Run: `bash -n scripts/barked.sh`
Expected: No output

**Step 4: Final commit**

```bash
git add scripts/barked.sh
git commit -m "feat: bump to v2.0.0, update header for new capabilities"
```

---

## Implementation Order Summary

| Task | Description | Dependencies |
|------|-------------|--------------|
| 1 | Add globals and severity map | None |
| 2 | Extend argument parser | Task 1 |
| 3 | Add scoring and findings functions | Task 1 |
| 4 | Add module check functions | Task 3 |
| 5 | Add audit mode flow | Tasks 3, 4 |
| 6 | Add pre-change analysis | Tasks 3, 4 |
| 7 | Add dry-run mode | Tasks 3, 4 |
| 8 | Add non-interactive mode | Tasks 1, 2 |
| 9 | Add advanced module vetting | Task 1 |
| 10 | Add three advanced modules + reverts | Task 9 |
| 11 | Update summary with score | Tasks 3, 10 |
| 12 | Version bump and final integration | All |

Note: Since this is a single-file project, TDD is not applicable in the traditional sense (no test framework for Bash). Instead, each task ends with `bash -n` syntax validation. Full functional testing requires running the script on a live system.
