# System Cleaner Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a `--clean` mode to `harden.sh` (macOS/Linux) and `harden.ps1` (Windows) that provides interactive system cleaning with a two-level picker, size-estimated preview, safety guardrails, and cleanliness scoring.

**Architecture:** The cleaner is a new run mode inside the existing scripts. It reuses OS detection, privilege checks, colors, and logging, but has its own globals, picker UI, scan/clean/verify cycle, and scoring system. Each cleaning target is a self-contained module with `scan_`, `clean_`, and `verify_` functions. The picker, preview, execution, and summary are orchestrated by a `run_clean()` entry point dispatched from `main()`.

**Tech Stack:** Bash (macOS/Linux), PowerShell (Windows), no external dependencies.

**Design doc:** `docs/plans/2026-01-30-system-cleaner-design.md`

---

## Task 1: Add `--clean` flag and clean mode globals (harden.sh)

**Files:**
- Modify: `scripts/harden.sh` — globals section (~line 35-90), parse_args (~line 4590), main (~line 4681)

**Step 1: Add clean mode globals after line 62 (below `ACCEPT_ADVANCED`)**

Add these globals in the GLOBALS section, after the existing mode flags:

```bash
# Clean mode
CLEAN_MODE=false
CLEAN_FORCE=false

# Clean log
CLEAN_LOG_FILE="${SCRIPT_DIR}/../audits/clean-log-${DATE}.txt"

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
```

**Step 2: Add `--clean` and `--force` to parse_args**

In `parse_args()`, add these cases before the `--help` case:

```bash
            --clean|-c)
                CLEAN_MODE=true
                ;;
            --force)
                CLEAN_FORCE=true
                ;;
```

Update the help text to include:

```bash
                echo "  --clean, -c            Run system cleaner"
                echo "  --force                Skip confirmation prompt (use with --clean)"
```

Add validation after existing validations:

```bash
    # Validation: --force requires --clean
    if [[ "$CLEAN_FORCE" == true && "$CLEAN_MODE" != true ]]; then
        echo -e "${RED}Error: --force requires --clean${NC}"
        exit 1
    fi
```

**Step 3: Add clean mode dispatch in main()**

In `main()`, after the audit mode block (~line 4692) and before the auto mode block, add:

```bash
    # ── Clean mode: system cleaner ──
    if [[ "$CLEAN_MODE" == true ]]; then
        run_clean
        exit 0
    fi
```

**Step 4: Add stub `run_clean()` function**

Add before `main()`:

```bash
# ═══════════════════════════════════════════════════════════════════
# SYSTEM CLEANER
# ═══════════════════════════════════════════════════════════════════
run_clean() {
    echo -e "${CYAN}╔══════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}${BOLD}          SYSTEM CLEANER v${VERSION}                 ${NC}${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}          macOS / Linux                           ${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  ${DIM}(coming soon)${NC}"
}
```

**Step 5: Commit**

```bash
git add scripts/harden.sh
git commit -m "feat(clean): add --clean flag, globals, and mode dispatch"
```

---

## Task 2: Build the two-level picker UI (harden.sh)

**Files:**
- Modify: `scripts/harden.sh` — add `clean_picker()` and `clean_drilldown()` functions

**Step 1: Add target-to-category mapping and display names**

Add after the `CLEAN_SEVERITY` map:

```bash
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
```

**Step 2: Add `clean_target_available()` detection function**

This checks whether a target is relevant on the current OS and whether the software is installed:

```bash
clean_target_available() {
    local target="$1"
    case "$target" in
        # macOS only
        safari|saved-app-state|quicklook-thumbs|ds-store|xcode-derived|cocoapods-cache|messages-attachments)
            [[ "$OS" == "macos" ]] ;;
        # Linux only (none currently — all linux targets share IDs with cross-platform)
        # Browser detection
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
        # Dev tool detection
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
        # Mail detection
        mail-cache)
            if [[ "$OS" == "macos" ]]; then
                [[ -d "$HOME/Library/Containers/com.apple.mail" ]]
            else
                [[ -d "$HOME/.thunderbird" ]]
            fi ;;
        # Everything else is always available
        *) return 0 ;;
    esac
}
```

**Step 3: Add `clean_picker()` — Level 1 category selection**

```bash
clean_picker() {
    print_section "Select Categories"
    echo -e "  ${DIM}Toggle categories, then press Enter to continue.${NC}"
    echo ""

    # Start with all selected
    for cat in "${CLEAN_CAT_ORDER[@]}"; do
        CLEAN_CATEGORIES[$cat]=1
    done

    while true; do
        for i in "${!CLEAN_CAT_ORDER[@]}"; do
            local cat="${CLEAN_CAT_ORDER[$i]}"
            local num=$((i + 1))
            local mark=" "
            [[ "${CLEAN_CATEGORIES[$cat]}" == "1" ]] && mark="*"
            echo -e "  ${CYAN}[$num]${NC} [${mark}] ${CLEAN_CAT_NAMES[$cat]}"
        done
        echo ""
        echo -e "  ${CYAN}[A]${NC} Select All    ${CYAN}[N]${NC} Select None"
        echo ""
        echo -ne "  ${BOLD}Toggle (1-7, A, N) or Enter to continue:${NC} "
        read -r input

        if [[ -z "$input" ]]; then
            # Check at least one selected
            local any=0
            for cat in "${CLEAN_CAT_ORDER[@]}"; do
                [[ "${CLEAN_CATEGORIES[$cat]}" == "1" ]] && any=1 && break
            done
            if [[ $any -eq 0 ]]; then
                echo -e "  ${RED}Select at least one category.${NC}"
                continue
            fi
            break
        fi

        case "${input,,}" in
            a)
                for cat in "${CLEAN_CAT_ORDER[@]}"; do
                    CLEAN_CATEGORIES[$cat]=1
                done ;;
            n)
                for cat in "${CLEAN_CAT_ORDER[@]}"; do
                    CLEAN_CATEGORIES[$cat]=0
                done ;;
            [1-7])
                local cat="${CLEAN_CAT_ORDER[$((input - 1))]}"
                if [[ "${CLEAN_CATEGORIES[$cat]}" == "1" ]]; then
                    CLEAN_CATEGORIES[$cat]=0
                else
                    CLEAN_CATEGORIES[$cat]=1
                fi ;;
            *)
                echo -e "  ${RED}Invalid input.${NC}" ;;
        esac
        # Clear and redraw
        echo ""
    done

    # Populate CLEAN_TARGETS: enable all available targets in selected categories
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
```

**Step 4: Add `clean_drilldown()` — Level 2 target selection**

```bash
clean_drilldown() {
    echo ""
    echo -ne "  ${BOLD}Drill into individual targets? (y/N):${NC} "
    read -r drill
    [[ "${drill,,}" != "y" ]] && return

    for cat in "${CLEAN_CAT_ORDER[@]}"; do
        [[ "${CLEAN_CATEGORIES[$cat]}" != "1" ]] && continue

        # Collect available targets for this category
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
                echo -e "    ${CYAN}[$num]${NC} [${mark}] ${CLEAN_TARGET_NAMES[$t]}"
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
```

**Step 5: Wire picker into `run_clean()`**

Update `run_clean()` to call the picker:

```bash
run_clean() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}${BOLD}          SYSTEM CLEANER v${VERSION}                 ${NC}${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}          macOS / Linux                           ${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════╝${NC}"

    clean_picker
    clean_drilldown

    # Count selected targets
    local count=0
    for t in "${!CLEAN_TARGETS[@]}"; do
        [[ "${CLEAN_TARGETS[$t]}" == "1" ]] && ((count++))
    done

    if [[ $count -eq 0 ]]; then
        echo -e "  ${YELLOW}No targets selected. Exiting.${NC}"
        return
    fi

    echo ""
    echo -e "  ${DIM}Selected ${count} cleaning target(s).${NC}"
    echo -e "  ${DIM}(scan, preview, and clean steps coming soon)${NC}"
}
```

**Step 6: Commit**

```bash
git add scripts/harden.sh
git commit -m "feat(clean): add two-level picker with auto-detection"
```

---

## Task 3: Add scan functions and preview table (harden.sh)

**Files:**
- Modify: `scripts/harden.sh` — add scan functions + preview display

**Step 1: Add helper functions for size formatting and safe scanning**

```bash
# Format byte count to human-readable
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

# Scan a directory: count files and total bytes (no symlink following)
# Sets SCAN_FILE_COUNT and SCAN_BYTE_COUNT
scan_directory() {
    local dir="$1"
    SCAN_FILE_COUNT=0
    SCAN_BYTE_COUNT=0
    if [[ -d "$dir" ]]; then
        local result
        result=$(find "$dir" -not -type l -type f -print0 2>/dev/null | xargs -0 stat -f '%z' 2>/dev/null | awk '{s+=$1; c++} END {printf "%d %d", c, s}')
        if [[ "$OS" == "linux" ]]; then
            result=$(find "$dir" -not -type l -type f -printf '%s\n' 2>/dev/null | awk '{s+=$1; c++} END {printf "%d %d", c, s}')
        fi
        SCAN_FILE_COUNT=$(echo "$result" | awk '{print $1}')
        SCAN_BYTE_COUNT=$(echo "$result" | awk '{print $2}')
        # Default to 0 if empty
        SCAN_FILE_COUNT=${SCAN_FILE_COUNT:-0}
        SCAN_BYTE_COUNT=${SCAN_BYTE_COUNT:-0}
    fi
}

# Scan files matching a find pattern under a root directory
# Args: root_dir, find_args...
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
```

**Step 2: Add per-target scan functions**

Each `scan_<target>()` sets `CLEAN_SCAN_FILES[$target]` and `CLEAN_SCAN_BYTES[$target]`. Here are the scan functions for all targets:

```bash
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
        # For journald, estimate from disk usage
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
    # DNS cache is a command, not files — always "ready"
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
        # Docker reports are complex; just mark as available
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
```

**Step 3: Add the scan dispatcher and preview table**

```bash
# Dispatch scan for a target
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

# Run all scans and display preview
clean_preview() {
    print_section "Scanning..."

    local -a selected_targets=()
    for t in "${!CLEAN_TARGETS[@]}"; do
        [[ "${CLEAN_TARGETS[$t]}" == "1" ]] && selected_targets+=("$t")
    done

    # Sort targets by category order for display
    local -a ordered_targets=()
    for cat in "${CLEAN_CAT_ORDER[@]}"; do
        for target in ${CLEAN_CAT_TARGETS[$cat]}; do
            if [[ "${CLEAN_TARGETS[$target]:-0}" == "1" ]]; then
                ordered_targets+=("$target")
            fi
        done
    done

    # Scan each target
    for target in "${ordered_targets[@]}"; do
        echo -ne "  ${YELLOW}⟳${NC} Scanning ${CLEAN_TARGET_NAMES[$target]}...\r"
        scan_target "$target"
        echo -ne "\033[K"
    done

    # Display preview table
    local total_files=0 total_bytes=0
    echo ""
    echo -e "  ${BOLD}${WHITE}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "  ${BOLD}${WHITE}║                   CLEANING PREVIEW                       ║${NC}"
    echo -e "  ${BOLD}${WHITE}╠══════════════════════════════════════════════════════════╣${NC}"
    printf "  ${BOLD}  %-32s %8s %10s %8s${NC}\n" "Target" "Files" "Size" "Status"
    echo -e "  ${DIM}  ────────────────────────────────────────────────────────${NC}"

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
            # Command-based targets (dns, clipboard) or empty
            case "$target" in
                dns-cache|clipboard|search-metadata) size_str="—"; status="Ready" ;;
                *) status="Empty"; size_str="—" ;;
            esac
        fi

        local file_str="$files"
        [[ $files -eq 0 ]] && file_str="—"

        local color="$NC"
        [[ "$status" == "Empty" ]] && color="$DIM"

        printf "  ${color}  %-32s %8s %10s %8s${NC}\n" \
            "${CLEAN_TARGET_NAMES[$target]}" "$file_str" "$size_str" "$status"

        total_files=$((total_files + files))
        total_bytes=$((total_bytes + bytes))
    done

    echo -e "  ${DIM}  ────────────────────────────────────────────────────────${NC}"
    printf "  ${BOLD}  %-32s %8s %10s${NC}\n" "TOTAL" "$total_files" "$(format_bytes $total_bytes)"
    echo -e "  ${BOLD}${WHITE}╚══════════════════════════════════════════════════════════╝${NC}"

    # Store totals for summary
    CLEAN_TOTAL_SCAN_FILES=$total_files
    CLEAN_TOTAL_SCAN_BYTES=$total_bytes
}
```

**Step 4: Wire preview into `run_clean()` with dry-run and confirmation**

Update `run_clean()`:

```bash
run_clean() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}${BOLD}          SYSTEM CLEANER v${VERSION}                 ${NC}${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}          macOS / Linux                           ${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════╝${NC}"

    clean_picker
    clean_drilldown
    clean_preview

    # Dry-run: show preview and exit
    if [[ "$DRY_RUN" == true ]]; then
        echo ""
        echo -e "  ${CYAN}[DRY RUN]${NC} Preview only — no files deleted."
        return
    fi

    # Confirmation
    if [[ "$CLEAN_FORCE" != true ]]; then
        echo ""
        echo -ne "  ${BOLD}Proceed with cleaning? (y/N):${NC} "
        read -r confirm
        if [[ "${confirm,,}" != "y" ]]; then
            echo -e "  ${DIM}Cancelled.${NC}"
            return
        fi
    fi

    echo ""
    echo -e "  ${DIM}(cleaning execution coming in next task)${NC}"
}
```

**Step 5: Commit**

```bash
git add scripts/harden.sh
git commit -m "feat(clean): add scan functions and preview table"
```

---

## Task 4: Add clean and verify functions + execution loop (harden.sh)

**Files:**
- Modify: `scripts/harden.sh` — add clean/verify functions and execution orchestration

**Step 1: Add clean logging helper**

```bash
clean_log() {
    local action="$1" message="$2"
    local entry="$(date '+%Y-%m-%d %H:%M:%S') [$action] $message"
    CLEAN_LOG+=("$entry")
}
```

**Step 2: Add safety check helpers**

```bash
# Check if a browser process is running
browser_running() {
    local process_name="$1"
    pgrep -x "$process_name" &>/dev/null
}

# Safely remove directory contents (not the directory itself)
safe_rm_contents() {
    local dir="$1"
    if [[ ! -d "$dir" ]]; then return 1; fi
    # Don't follow symlinks — resolve and verify
    local real_dir
    real_dir=$(cd "$dir" 2>/dev/null && pwd -P)
    if [[ -z "$real_dir" ]]; then return 1; fi

    local files_removed=0 bytes_freed=0
    while IFS= read -r -d '' file; do
        # Skip files modified in last 60 seconds
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
        if rm -f "$file" 2>/dev/null; then
            bytes_freed=$((bytes_freed + fsize))
            ((files_removed++))
            clean_log "CLEAN" "Removed $file ($(format_bytes "$fsize"))"
        else
            clean_log "FAIL" "$file (permission denied)"
        fi
    done < <(find "$real_dir" -not -type l -type f -print0 2>/dev/null)

    # Clean empty subdirectories
    find "$real_dir" -mindepth 1 -type d -empty -delete 2>/dev/null

    SAFE_RM_FILES=$files_removed
    SAFE_RM_BYTES=$bytes_freed
}
```

**Step 3: Add per-target clean functions**

Each `clean_<target>()` sets `CLEAN_RESULT_FILES`, `CLEAN_RESULT_BYTES`, and `CLEAN_RESULT_STATUS` for its target. Here are all clean functions:

```bash
clean_system_cache() {
    if [[ "$OS" == "macos" ]]; then
        safe_rm_contents "/Library/Caches"
    else
        local total_f=0 total_b=0
        for d in /var/cache/apt/archives /var/cache/dnf /var/cache/pacman/pkg; do
            if [[ -d "$d" ]]; then
                safe_rm_contents "$d"
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
                safe_rm_contents "$d"
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
        safe_rm_contents "/Library/Logs/DiagnosticReports"
    else
        safe_rm_contents "/var/crash"
    fi
    CLEAN_RESULT_FILES[diagnostic-reports]=$SAFE_RM_FILES
    CLEAN_RESULT_BYTES[diagnostic-reports]=$SAFE_RM_BYTES
    [[ $SAFE_RM_FILES -gt 0 ]] && CLEAN_RESULT_STATUS[diagnostic-reports]="pass" || CLEAN_RESULT_STATUS[diagnostic-reports]="skip"
}

clean_dns_cache() {
    if [[ "$OS" == "macos" ]]; then
        dscacheutil -flushcache 2>/dev/null && sudo killall -HUP mDNSResponder 2>/dev/null
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
        echo -e "  ${YELLOW}⚠${NC}  Safari is running — close it first to clean"
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
        echo -e "  ${YELLOW}⚠${NC}  Chrome is running — close it first to clean"
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
        echo -e "  ${YELLOW}⚠${NC}  Firefox is running — close it first to clean"
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
        echo -e "  ${YELLOW}⚠${NC}  Arc is running — close it first to clean"
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
        echo -e "  ${YELLOW}⚠${NC}  Edge is running — close it first to clean"
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
        echo -e "  ${YELLOW}☐${NC}  Spotlight: To rebuild, run: sudo mdutil -E /"
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
```

**Step 4: Add execution orchestrator**

```bash
clean_execute() {
    print_section "Cleaning ($(date '+%H:%M:%S'))"

    # Build ordered target list
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
        echo -ne "  ${YELLOW}⟳${NC} [${current}/${total}] ${CLEAN_TARGET_NAMES[$target]}..."

        local func="clean_${target//-/_}"
        if declare -f "$func" &>/dev/null; then
            "$func"
        else
            CLEAN_RESULT_STATUS[$target]="fail"
            clean_log "FAIL" "$target — no clean function"
        fi

        # Clear progress line and print result
        echo -ne "\r\033[K"
        local status="${CLEAN_RESULT_STATUS[$target]:-skip}"
        local freed="${CLEAN_RESULT_BYTES[$target]:-0}"
        local freed_str=""
        [[ $freed -gt 0 ]] && freed_str=" ($(format_bytes $freed))"

        case "$status" in
            pass)    echo -e "  ${GREEN}✓${NC} [${current}/${total}] ${CLEAN_TARGET_NAMES[$target]}${freed_str}" ;;
            skip)    echo -e "  ${GREEN}○${NC} [${current}/${total}] ${CLEAN_TARGET_NAMES[$target]} ${DIM}(nothing to clean)${NC}" ;;
            fail)    echo -e "  ${RED}✗${NC} [${current}/${total}] ${CLEAN_TARGET_NAMES[$target]} ${RED}(failed)${NC}" ;;
            partial) echo -e "  ${YELLOW}◐${NC} [${current}/${total}] ${CLEAN_TARGET_NAMES[$target]}${freed_str} ${YELLOW}(partial)${NC}" ;;
        esac
    done
}
```

**Step 5: Wire execution into `run_clean()`**

Replace the placeholder in `run_clean()` after the confirmation block:

```bash
    clean_execute
    # (summary and logging coming next task)
```

**Step 6: Commit**

```bash
git add scripts/harden.sh
git commit -m "feat(clean): add clean/verify functions and execution loop"
```

---

## Task 5: Add cleanliness score, summary, and log writing (harden.sh)

**Files:**
- Modify: `scripts/harden.sh` — add scoring, summary table, and log output

**Step 1: Add cleanliness score calculator**

```bash
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
            fail)      ;; # zero
        esac
    done

    local pct=0
    [[ $possible -gt 0 ]] && pct=$(( (earned * 100) / possible ))
    echo "$earned $possible $pct"
}
```

**Step 2: Add cleaning summary display**

```bash
print_clean_summary() {
    # Build ordered target list
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
    echo -e "  ${BOLD}${WHITE}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "  ${BOLD}${WHITE}║                  CLEANING SUMMARY                        ║${NC}"
    echo -e "  ${BOLD}${WHITE}╠══════════════════════════════════════════════════════════╣${NC}"
    printf "  ${BOLD}  %-32s %8s %10s %8s${NC}\n" "Target" "Removed" "Freed" "Status"
    echo -e "  ${DIM}  ────────────────────────────────────────────────────────${NC}"

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
            skip)    status_str="SKIP";    color="$DIM" ;;
            fail)    status_str="FAIL";    color="$RED" ;;
            partial) status_str="PARTIAL"; color="$YELLOW" ;;
        esac

        printf "  ${color}  %-32s %8s %10s %8s${NC}\n" \
            "${CLEAN_TARGET_NAMES[$target]}" "$file_str" "$size_str" "$status_str"

        total_files=$((total_files + files))
        total_bytes=$((total_bytes + bytes))
    done

    echo -e "  ${DIM}  ────────────────────────────────────────────────────────${NC}"
    printf "  ${BOLD}  %-32s %8s %10s${NC}\n" "TOTAL" "$total_files" "$(format_bytes $total_bytes)"
    echo -e "  ${BOLD}${WHITE}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""

    # Score
    local score_output
    score_output=$(calculate_clean_score)
    local earned possible pct
    read -r earned possible pct <<< "$score_output"

    local color="$RED"
    if [[ $pct -ge 80 ]]; then color="$GREEN"
    elif [[ $pct -ge 50 ]]; then color="$YELLOW"
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
```

**Step 3: Add clean log writing**

```bash
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
    echo -e "  ${DIM}Log: ${CLEAN_LOG_FILE}${NC}"
}
```

**Step 4: Complete `run_clean()` with summary and logging**

Final version of `run_clean()`:

```bash
run_clean() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}${BOLD}          SYSTEM CLEANER v${VERSION}                 ${NC}${CYAN}║${NC}"
    echo -e "${CYAN}║${NC}          macOS / Linux                           ${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════╝${NC}"

    clean_picker
    clean_drilldown
    clean_preview

    # Dry-run: show preview and exit
    if [[ "$DRY_RUN" == true ]]; then
        echo ""
        echo -e "  ${CYAN}[DRY RUN]${NC} Preview only — no files deleted."
        return
    fi

    # Confirmation
    if [[ "$CLEAN_FORCE" != true ]]; then
        echo ""
        echo -ne "  ${BOLD}Proceed with cleaning? (y/N):${NC} "
        read -r confirm
        if [[ "${confirm,,}" != "y" ]]; then
            echo -e "  ${DIM}Cancelled.${NC}"
            return
        fi
    fi

    clean_execute
    print_clean_summary
    write_clean_log

    echo ""
    echo -e "  ${DIM}Re-run with --clean anytime — safe to repeat.${NC}"
    echo ""
}
```

**Step 5: Commit**

```bash
git add scripts/harden.sh
git commit -m "feat(clean): add cleanliness score, summary, and log writing"
```

---

## Task 6: Add `--clean` mode to harden.ps1 (Windows)

**Files:**
- Modify: `scripts/harden.ps1` — add clean mode for Windows

**Step 1: Add `-Clean` and `-Force` parameters**

Add to the `param()` block at the top of `harden.ps1`:

```powershell
    [switch]$Clean,
    [switch]$Force,
    [switch]$DryRun
```

**Step 2: Add Windows clean globals, severity map, category/target data**

Add after the existing globals section, mirroring the Bash structure:

```powershell
# ═══════════════════════════════════════════════════════════════════
# CLEAN MODE GLOBALS
# ═══════════════════════════════════════════════════════════════════
$script:CleanLogFile = Join-Path $script:AuditDir "clean-log-$($script:DATE).txt"
$script:CleanCategories = @{
    'system-caches' = $false; 'user-caches' = $false; 'browser-data' = $false
    'privacy-traces' = $false; 'dev-cruft' = $false; 'trash-downloads' = $false
    'mail-messages' = $false
}
$script:CleanTargets = @{}
$script:CleanScanFiles = @{}
$script:CleanScanBytes = @{}
$script:CleanResultFiles = @{}
$script:CleanResultBytes = @{}
$script:CleanResultStatus = @{}
$script:CleanLogEntries = @()

$script:CleanCatOrder = @('system-caches','user-caches','browser-data','privacy-traces','dev-cruft','trash-downloads','mail-messages')

$script:CleanCatNames = @{
    'system-caches' = 'System Caches & Logs'; 'user-caches' = 'User Caches & Logs'
    'browser-data' = 'Browser Data'; 'privacy-traces' = 'Privacy Traces'
    'dev-cruft' = 'Developer Cruft'; 'trash-downloads' = 'Trash & Downloads'
    'mail-messages' = 'Mail & Messages'
}

$script:CleanCatTargets = @{
    'system-caches' = @('system-cache','system-logs','diagnostic-reports','dns-cache')
    'user-caches' = @('user-cache','user-logs')
    'browser-data' = @('chrome','firefox','edge')
    'privacy-traces' = @('recent-items','clipboard','thumbnails')
    'dev-cruft' = @('npm-cache','yarn-cache','pip-cache','cargo-cache','go-cache','docker-cruft','ide-caches')
    'trash-downloads' = @('recycle-bin','old-downloads')
    'mail-messages' = @('outlook-cache')
}

$script:CleanTargetNames = @{
    'system-cache' = 'System cache (Windows\Temp)'
    'system-logs' = 'System event logs'
    'diagnostic-reports' = 'Windows Error Reports'
    'dns-cache' = 'DNS cache'
    'user-cache' = 'User temp files'
    'user-logs' = 'Crash dumps'
    'chrome' = 'Chrome cache & data'
    'firefox' = 'Firefox cache & data'
    'edge' = 'Edge cache & data'
    'recent-items' = 'Recent items'
    'clipboard' = 'Clipboard'
    'thumbnails' = 'Thumbnail cache'
    'npm-cache' = 'npm cache'
    'yarn-cache' = 'yarn cache'
    'pip-cache' = 'pip cache'
    'cargo-cache' = 'Cargo cache'
    'go-cache' = 'Go cache'
    'docker-cruft' = 'Docker cruft'
    'ide-caches' = 'IDE caches'
    'recycle-bin' = 'Recycle Bin'
    'old-downloads' = 'Old downloads (30+ days)'
    'outlook-cache' = 'Outlook cache'
}

$script:CleanSeverity = @{
    'system-cache' = 'MEDIUM'; 'system-logs' = 'MEDIUM'; 'diagnostic-reports' = 'LOW'
    'dns-cache' = 'MEDIUM'; 'user-cache' = 'HIGH'; 'user-logs' = 'HIGH'
    'chrome' = 'CRITICAL'; 'firefox' = 'CRITICAL'; 'edge' = 'CRITICAL'
    'recent-items' = 'CRITICAL'; 'clipboard' = 'CRITICAL'; 'thumbnails' = 'HIGH'
    'npm-cache' = 'MEDIUM'; 'yarn-cache' = 'MEDIUM'; 'pip-cache' = 'MEDIUM'
    'cargo-cache' = 'MEDIUM'; 'go-cache' = 'MEDIUM'; 'docker-cruft' = 'MEDIUM'
    'ide-caches' = 'MEDIUM'; 'recycle-bin' = 'LOW'; 'old-downloads' = 'LOW'
    'outlook-cache' = 'HIGH'
}

$script:SeverityWeight = @{ 'CRITICAL' = 10; 'HIGH' = 7; 'MEDIUM' = 4; 'LOW' = 2 }
```

**Step 3: Add Windows picker, scan, clean, summary, and log functions**

Implement the same flow as the Bash version using PowerShell idioms. The functions follow the same pattern: `Show-CleanPicker`, `Show-CleanDrilldown`, `Invoke-CleanScan`, `Show-CleanPreview`, `Invoke-CleanExecute`, `Show-CleanSummary`, `Write-CleanLog`.

Windows-specific paths:
- System cache: `C:\Windows\Temp`
- User cache: `$env:LOCALAPPDATA\Temp`
- System logs: `wevtutil cl System; wevtutil cl Application`
- Diagnostic reports: `C:\ProgramData\Microsoft\Windows\WER`
- DNS: `ipconfig /flushdns`
- Chrome: `$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache`
- Firefox: `$env:LOCALAPPDATA\Mozilla\Firefox\Profiles`
- Edge: `$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache`
- Recent items: `$env:APPDATA\Microsoft\Windows\Recent`
- Thumbnails: `$env:LOCALAPPDATA\Microsoft\Windows\Explorer\thumbcache_*`
- Clipboard: `Set-Clipboard -Value $null`
- Recycle Bin: `Clear-RecycleBin -Force`
- Old downloads: `$env:USERPROFILE\Downloads` (files > 30 days)
- Outlook: `$env:LOCALAPPDATA\Microsoft\Outlook\RoamCache`

The PowerShell implementations mirror the Bash versions but use `Get-ChildItem`, `Remove-Item`, `Measure-Object` for scanning/cleaning.

**Step 4: Add dispatch in main block**

Add before the existing mode dispatch:

```powershell
if ($Clean) {
    Invoke-Clean
    exit 0
}
```

**Step 5: Commit**

```bash
git add scripts/harden.ps1
git commit -m "feat(clean): add --clean mode for Windows (harden.ps1)"
```

---

## Task 7: Update README and help text

**Files:**
- Modify: `README.md` — add system cleaner section
- Modify: `scripts/harden.sh` — update help examples
- Modify: `scripts/harden.ps1` — update help examples

**Step 1: Add System Cleaner section to README**

Add a new section after the existing "Modules" section:

```markdown
## System Cleaner

Built-in system cleaner for privacy and disk hygiene. Run alongside hardening or independently.

```bash
sudo ./harden.sh --clean              # Interactive cleaning wizard
sudo ./harden.sh --clean --dry-run    # Preview what would be cleaned
sudo ./harden.sh --clean --force      # Skip confirmation prompt
```

**Categories:** System Caches & Logs, User Caches & Logs, Browser Data, Privacy Traces, Developer Cruft, Trash & Downloads, Mail & Messages

**Features:**
- Two-level picker: select categories, then optionally drill into individual targets
- Auto-detects installed browsers and dev tools
- Size-estimated preview before any deletion
- Safety guardrails: no symlink following, skips in-use files, warns about running browsers
- Cleanliness score with severity-weighted scoring
- Full logging to `audits/clean-log-YYYY-MM-DD.txt`
```

**Step 2: Update help text in both scripts to include clean examples**

Add to the examples section in `parse_args()`:

```
  $0 --clean                          Interactive system cleaner
  $0 --clean --dry-run                Preview what would be cleaned
  $0 --clean --force                  Clean without confirmation
```

**Step 3: Commit**

```bash
git add README.md scripts/harden.sh scripts/harden.ps1
git commit -m "docs: add system cleaner to README and help text"
```

---

## Summary

| Task | Description | Key Output |
|------|-------------|------------|
| 1 | CLI flag + globals + dispatch | `--clean` parsed, `run_clean()` stub |
| 2 | Two-level picker UI | Category and target selection with auto-detection |
| 3 | Scan functions + preview | Per-target size estimation and preview table |
| 4 | Clean functions + execution | Per-target cleaning with safety guardrails |
| 5 | Score + summary + logging | Cleanliness score, summary table, log file |
| 6 | Windows PowerShell port | Full `--clean` mode in `harden.ps1` |
| 7 | README + help text | Documentation and usage examples |
