# Sudo-Per-Command Escalation Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Refactor barked to run as the normal user and only escalate to sudo for specific commands that require root.

**Architecture:** Remove the root-at-startup gate. Add `run_as_root()` wrapper and sudo keepalive. Replace all `run_as_user` calls with direct calls. Wrap root-requiring commands with `run_as_root`. Migrate state file to user space. Apply same pattern to PowerShell.

**Tech Stack:** Bash 4+, PowerShell 5.1+

---

### Task 1: Replace Privilege System in barked.sh

**Files:**
- Modify: `scripts/barked.sh:362-387` (check_privileges + run_as_user)
- Modify: `scripts/barked.sh:206-207` (STATE_FILE paths)
- Modify: `scripts/barked.sh:28` (LOG_FILE path)
- Modify: `scripts/barked.sh:87` (CLEAN_LOG_FILE path)

**Context:** The script currently requires `EUID -eq 0` at startup (line 362-369), preserves the real user via SUDO_USER (lines 370-378), and uses `run_as_user()` (lines 381-387) to drop privileges for user-level commands. We need to flip this: run as normal user, escalate per-command.

**Step 1: Replace check_privileges() and run_as_user() with new privilege system**

Replace lines 359-387 with:

```bash
# ═══════════════════════════════════════════════════════════════════
# PRIVILEGE MANAGEMENT
# ═══════════════════════════════════════════════════════════════════
SUDO_KEEPALIVE_PID=""

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
    echo ""
    echo -e "  ${BROWN}Some hardening steps need admin privileges.${NC}"
    if ! sudo -v 2>/dev/null; then
        echo -e "  ${RED}Failed to acquire sudo. Some modules may fail.${NC}"
        return 1
    fi
    # Keep sudo alive in the background
    (while true; do sudo -n -v 2>/dev/null; sleep 50; done) &
    SUDO_KEEPALIVE_PID=$!
    trap 'cleanup_sudo' EXIT
    return 0
}

cleanup_sudo() {
    if [[ -n "$SUDO_KEEPALIVE_PID" ]]; then
        kill "$SUDO_KEEPALIVE_PID" 2>/dev/null
        wait "$SUDO_KEEPALIVE_PID" 2>/dev/null
        SUDO_KEEPALIVE_PID=""
    fi
}

run_as_root() {
    if [[ $EUID -eq 0 ]]; then
        "$@"
    else
        sudo "$@"
    fi
}
```

**Step 2: Update state file paths**

Change line 206-207 from:
```bash
STATE_FILE_SYSTEM="/etc/hardening-state.json"
STATE_FILE_PROJECT="${SCRIPT_DIR}/../state/hardening-state.json"
```
To:
```bash
STATE_FILE_USER="${HOME}/.config/barked/state.json"
STATE_FILE_PROJECT="${SCRIPT_DIR}/../state/hardening-state.json"
STATE_FILE_LEGACY="/etc/hardening-state.json"
```

**Step 3: Update LOG_FILE and CLEAN_LOG_FILE paths**

Change line 28 from:
```bash
readonly LOG_FILE="${SCRIPT_DIR}/../audits/hardening-log-${DATE}.txt"
```
To:
```bash
if [[ -d "${SCRIPT_DIR}/../audits" ]]; then
    LOG_FILE="${SCRIPT_DIR}/../audits/hardening-log-${DATE}.txt"
else
    mkdir -p "${HOME}/.config/barked/logs"
    LOG_FILE="${HOME}/.config/barked/logs/hardening-log-${DATE}.txt"
fi
```

Apply the same pattern to CLEAN_LOG_FILE on line 87:
```bash
if [[ -d "${SCRIPT_DIR}/../audits" ]]; then
    CLEAN_LOG_FILE="${SCRIPT_DIR}/../audits/clean-log-${DATE}.txt"
else
    mkdir -p "${HOME}/.config/barked/logs"
    CLEAN_LOG_FILE="${HOME}/.config/barked/logs/clean-log-${DATE}.txt"
fi
```

Note: These can't be `readonly` anymore since they're set conditionally. Remove `readonly` from the LOG_FILE line.

**Step 4: Update main() to use new privilege system**

In `main()` (line 6281+), replace `check_privileges` call:

Change line 6286 from:
```bash
    check_privileges
```
To:
```bash
    setup_privileges
```

The `acquire_sudo` call will be added in Task 3 after modules are resolved.

**Step 5: Test manually**

Run from the worktree without sudo:
```bash
./scripts/barked.sh --version
```
Expected: prints version without requiring sudo.

Run:
```bash
./scripts/barked.sh --help
```
Expected: works without sudo.

**Step 6: Commit**

```bash
git add scripts/barked.sh
git commit -m "refactor: replace root-at-startup with per-command sudo escalation"
```

---

### Task 2: Update State File Management in barked.sh

**Files:**
- Modify: `scripts/barked.sh:453-565` (state_read, state_write)
- Modify: `scripts/barked.sh:524` (EUID check in state_write)

**Context:** State was at `/etc/hardening-state.json` (needs root). Now primary is `~/.config/barked/state.json`. Need to update `state_read()` to check new location first, `state_write()` to write to user space, and add migration from old location.

**Step 1: Update state_read()**

Replace the file selection logic in `state_read()` (lines 453-461). Change from:
```bash
    local state_file=""
    if [[ -f "$STATE_FILE_SYSTEM" ]]; then
        state_file="$STATE_FILE_SYSTEM"
    elif [[ -f "$STATE_FILE_PROJECT" ]]; then
        state_file="$STATE_FILE_PROJECT"
    else
        return 1
    fi
```
To:
```bash
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
```

**Step 2: Update state_write()**

Replace the write targets logic (lines 522-526). Change from:
```bash
    local write_targets=("$STATE_FILE_PROJECT")
    # Try system path, might fail without write permission
    if [[ -w "$(dirname "$STATE_FILE_SYSTEM")" ]] || [[ $EUID -eq 0 ]]; then
        write_targets+=("$STATE_FILE_SYSTEM")
    fi
```
To:
```bash
    mkdir -p "$(dirname "$STATE_FILE_USER")" 2>/dev/null
    local write_targets=("$STATE_FILE_USER" "$STATE_FILE_PROJECT")
```

**Step 3: Add state migration function**

Add after `state_read()` (after line 499):

```bash
state_migrate_legacy() {
    # Migrate from /etc/hardening-state.json to user space
    if [[ -f "$STATE_FILE_LEGACY" ]] && [[ ! -f "$STATE_FILE_USER" ]]; then
        mkdir -p "$(dirname "$STATE_FILE_USER")" 2>/dev/null
        cp "$STATE_FILE_LEGACY" "$STATE_FILE_USER" 2>/dev/null
        if [[ -f "$STATE_FILE_USER" ]]; then
            echo -e "  ${BROWN}Migrated state file to ${STATE_FILE_USER}${NC}"
            run_as_root rm -f "$STATE_FILE_LEGACY" 2>/dev/null || true
        fi
    fi
}
```

This gets called in main() right after `setup_privileges`.

**Step 4: Test manually**

If `/etc/hardening-state.json` exists, run:
```bash
./scripts/barked.sh --version
```
Then check `~/.config/barked/state.json` exists.

**Step 5: Commit**

```bash
git add scripts/barked.sh
git commit -m "refactor: migrate state file to user space (~/.config/barked/)"
```

---

### Task 3: Add Sudo Acquisition After Module Resolution in barked.sh

**Files:**
- Modify: `scripts/barked.sh` — main() function (lines 6281-6405)
- Modify: `scripts/barked.sh` — add `needs_sudo()` helper

**Context:** We need to detect whether the selected modules/mode need root, and only prompt for sudo if they do. This must happen after profile selection and module list building, but before module execution.

**Step 1: Add needs_sudo() function**

Add near the privilege management section (after `run_as_root`):

```bash
# Modules that require root for at least one command
declare -A ROOT_MODULES=(
    [firewall-inbound]=1 [firewall-stealth]=1 [dns-secure]=1
    [auto-updates]=1 [guest-disable]=1 [hostname-scrub]=1
    [telemetry-disable]=1 [kernel-sysctl]=1 [apparmor-enforce]=1
    [bluetooth-disable]=1
)

needs_sudo() {
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
```

**Step 2: Insert acquire_sudo calls in main()**

In `main()`, after `build_module_list` is called and before `run_all_modules`, add sudo acquisition. There are multiple code paths:

**Auto mode (after line 6305 `build_module_list`):**
```bash
        needs_sudo && acquire_sudo
```

**Interactive harden mode (after line 6362 `build_module_list`):**
```bash
            needs_sudo && acquire_sudo
```

**Uninstall mode (before line 6334 `run_uninstall`):**
```bash
            acquire_sudo
```

**Modify mode (before line 6339 `run_modify`):**
```bash
            acquire_sudo
```

**Audit mode (line 6289-6292):** No sudo needed — audit is read-only.

**Clean mode (line 6296-6299):** Sudo acquired inside `run_clean` after category selection, since we don't know if system targets are selected until then. Add to `run_clean()` after the category picker returns:
```bash
    needs_sudo && acquire_sudo
```

**Step 3: Test manually**

Run without sudo, pick a user-only profile or module set:
```bash
./scripts/barked.sh --audit
```
Expected: no sudo prompt.

Run with a root-requiring module:
```bash
./scripts/barked.sh --auto standard --dry-run
```
Expected: prompts for sudo once.

**Step 4: Commit**

```bash
git add scripts/barked.sh
git commit -m "feat: acquire sudo only when selected modules require root"
```

---

### Task 4: Convert All Modules to Use run_as_root / Direct Calls in barked.sh

**Files:**
- Modify: `scripts/barked.sh` — every `run_as_user` call site (40+ occurrences)
- Modify: `scripts/barked.sh` — every root-requiring command in modules (socketfilterfw, networksetup, scutil, /Library/Preferences defaults, ufw, systemctl, etc.)
- Modify: `scripts/barked.sh` — package helpers (lines 392-448)

**Context:** This is the bulk of the work. Every `run_as_user` call becomes a direct call (the script is already the user). Every root-requiring system command gets wrapped with `run_as_root`. The package helpers change: macOS brew calls lose their wrapper, Linux pkg calls gain `run_as_root`.

**Step 1: Update package helpers (lines 392-448)**

Replace `pkg_install()`:
```bash
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
```

Replace `pkg_install_cask()`:
```bash
pkg_install_cask() {
    if [[ "$OS" == "macos" ]]; then
        brew install --cask "$1" 2>/dev/null
    fi
}
```

Replace `pkg_uninstall()`:
```bash
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
```

Replace `cask_uninstall()`:
```bash
cask_uninstall() {
    [[ "$OS" == "macos" ]] && brew uninstall --cask "$1" 2>/dev/null
}
```

**Step 2: Replace all `run_as_user` calls with direct calls**

Every remaining `run_as_user` call in the script becomes a direct call. These are all user-space operations (user defaults, git config, gsettings, ssh-keygen, launchctl, etc.). There are ~40 occurrences.

Find them all with: `grep -n "run_as_user" scripts/barked.sh`

For each, remove the `run_as_user` prefix. Examples:

```bash
# Before:
run_as_user defaults write com.apple.screensaver askForPassword -int 1
# After:
defaults write com.apple.screensaver askForPassword -int 1

# Before:
run_as_user git config --global gpg.format ssh
# After:
git config --global gpg.format ssh

# Before:
run_as_user ssh-keygen -t ed25519 -f "${ssh_dir}/id_ed25519" -N "" -q
# After:
ssh-keygen -t ed25519 -f "${ssh_dir}/id_ed25519" -N "" -q
```

**Step 3: Add run_as_root to root-requiring commands in modules**

Wrap these specific commands (these currently run fine because the whole script is root — now they need explicit escalation):

**mod_firewall_inbound (lines ~2497-2542):**
- All `/usr/libexec/ApplicationFirewall/socketfilterfw` calls → `run_as_root /usr/libexec/ApplicationFirewall/socketfilterfw ...`
- All `ufw` calls → `run_as_root ufw ...`

**mod_firewall_stealth (lines ~2821-2853):**
- All `socketfilterfw` calls → `run_as_root ...`
- All `iptables` calls → `run_as_root ...`

**mod_dns_secure (lines ~2558-2621):**
- `networksetup -setdnsservers` → `run_as_root networksetup -setdnsservers ...`
- `networksetup -getdnsservers` can stay direct (read-only, doesn't need root)
- Linux: writing to `/etc/systemd/resolved.conf.d/` and `systemctl restart` → `run_as_root`

**mod_auto_updates (lines ~2626-2675):**
- `defaults write /Library/Preferences/...` → `run_as_root defaults write /Library/Preferences/...`
- `defaults read /Library/Preferences/...` can stay direct (read doesn't need root)
- Linux: `apt-get install`, `systemctl enable` → `run_as_root`

**mod_guest_disable (lines ~2680-2707):**
- `defaults write /Library/Preferences/com.apple.loginwindow ...` → `run_as_root defaults write ...`
- `defaults read /Library/Preferences/...` can stay direct
- Linux: `usermod` → `run_as_root usermod ...`

**mod_hostname_scrub (lines ~2911-2948):**
- `scutil --set` → `run_as_root scutil --set ...`
- Linux: `hostnamectl` → `run_as_root hostnamectl ...`

**mod_telemetry_disable (lines ~3042-3075):**
- macOS system defaults (`defaults write` for Siri, CrashReporter, etc.) → `run_as_root defaults write ...`
- Linux: writing `/etc/default/apport`, `systemctl` → `run_as_root`
- Linux: `gsettings` calls stay direct (already user-space)

**mod_bluetooth_disable (lines ~3558-3585):**
- Linux: `systemctl disable bluetooth` → `run_as_root systemctl ...`

**mod_kernel_sysctl (lines ~3587-3618):**
- Writing `/etc/sysctl.d/`, running `sysctl -p` → `run_as_root`

**mod_apparmor_enforce (lines ~3620-3655):**
- `aa-enforce` → `run_as_root aa-enforce ...`

**All revert_* functions** that correspond to root modules: apply the same `run_as_root` wrapping for the reverse operations (socketfilterfw, networksetup, scutil, /Library/Preferences defaults, ufw, systemctl, etc.).

**All check_* audit functions** that read system state: most reads don't need root (defaults read, socketfilterfw --get, ufw status work without root). Leave these as direct calls.

**Step 4: Remove chown calls that are no longer needed**

Lines like `chown "${REAL_USER}" "${ff_profile}/user.js"` (line 2812) and `chown -R "${REAL_USER}" "$ssh_dir"` (line 2993) were needed because the script ran as root and created files owned by root. Since the script now runs as the user, these files are already owned by the user. Remove these chown calls.

**Step 5: Remove REAL_USER/REAL_HOME where $USER/$HOME suffice**

Since the script runs as the actual user, `REAL_USER` == `$USER` and `REAL_HOME` == `$HOME`. However, keep the `REAL_USER` and `REAL_HOME` variables as aliases (set in `setup_privileges`) for minimal diff and in case someone runs the script as root directly. Don't do a mass rename — just keep using them.

**Step 6: Test manually**

Run a dry-run that includes root modules:
```bash
./scripts/barked.sh --auto high --dry-run
```
Expected: prompts for sudo, shows dry-run without errors.

Run audit mode (no root needed):
```bash
./scripts/barked.sh --audit
```
Expected: no sudo prompt, audit completes.

**Step 7: Commit**

```bash
git add scripts/barked.sh
git commit -m "refactor: convert all modules to run_as_root / direct calls"
```

---

### Task 5: Update Clean Mode for Per-Command Sudo in barked.sh

**Files:**
- Modify: `scripts/barked.sh` — clean mode functions (lines ~4850-6145)

**Context:** Clean mode has system-level targets (/Library/Caches, /var/log, DNS flush) that need root, and user-level targets (~/Library/Caches, browser data, trash) that don't. We need to add `run_as_root` to system-level delete operations and sudo acquisition after category selection.

**Step 1: Add sudo acquisition to run_clean()**

Find where category selection completes in `run_clean()` and add sudo acquisition after it. Look for where the script transitions from category picking to scanning/deleting. Insert:

```bash
    needs_sudo && acquire_sudo
```

**Step 2: Wrap system-level operations with run_as_root**

In the clean execution functions, any `rm -rf` or deletion targeting:
- `/Library/Caches/...`
- `/Library/Logs/...`
- `/var/log/...`
- `/var/cache/...`

Must use `run_as_root rm -rf ...` instead of plain `rm -rf`.

DNS cache flush (`dscacheutil -flushcache` on macOS) → `run_as_root dscacheutil -flushcache`.

User-space targets (`$HOME/Library/Caches/...`, `~/.cache/...`, browser profiles, trash, downloads) stay as direct `rm -rf` — no `run_as_root`.

**Step 3: Test manually**

Run clean with only user targets (uncheck system caches):
```bash
./scripts/barked.sh --clean --dry-run
```
Expected: no sudo prompt when only user targets selected.

**Step 4: Commit**

```bash
git add scripts/barked.sh
git commit -m "refactor: add per-command sudo to clean mode system targets"
```

---

### Task 6: Update Update/Uninstall-Self for Per-Command Sudo in barked.sh

**Files:**
- Modify: `scripts/barked.sh:6171-6276` (run_update, run_uninstall_self)

**Context:** These functions need root when barked is installed to a root-owned path like `/usr/local/bin/`. Currently they check write permission and tell the user to re-run with sudo. Instead, they should acquire sudo and use `run_as_root` for the file operations.

**Step 1: Update run_update()**

Replace the write permission check (lines 6188-6191):
```bash
    if [[ ! -w "$install_path" ]]; then
        echo -e "${RED}No write permission to ${install_path}. Try: sudo barked --update${NC}"
        exit 1
    fi
```
With:
```bash
    if [[ ! -w "$install_path" ]]; then
        acquire_sudo || {
            echo -e "${RED}Cannot update ${install_path} without admin privileges.${NC}"
            exit 1
        }
    fi
```

Then wrap the file operations (mv/cp at lines 6213-6219) with `run_as_root`:
```bash
    run_as_root mv "$tmp_file" "$install_path" 2>/dev/null || {
        run_as_root cp "$tmp_file" "$install_path" 2>/dev/null || {
            echo -e "${RED}Failed to replace ${install_path}.${NC}"
            rm -f "$tmp_file"
            exit 1
        }
        rm -f "$tmp_file"
    }
```

Also wrap `chmod` with `run_as_root`:
```bash
    run_as_root chmod +x "$install_path"
```

Wait — actually `chmod +x` on the temp file should happen before the move. The temp file is owned by the user, so `chmod +x "$tmp_file"` stays direct. The `mv` into a root-owned directory needs `run_as_root`.

**Step 2: Update run_uninstall_self()**

Replace the write permission check (lines 6267-6269):
```bash
    if [[ ! -w "$install_path" ]]; then
        echo -e "${RED}No write permission to ${install_path}. Try: sudo barked --uninstall-self${NC}"
        exit 1
    fi
```
With:
```bash
    if [[ ! -w "$install_path" ]]; then
        acquire_sudo || {
            echo -e "${RED}Cannot remove ${install_path} without admin privileges.${NC}"
            exit 1
        }
    fi
```

Wrap the rm (line 6272):
```bash
    run_as_root rm -f "$install_path"
```

**Step 3: Test manually**

```bash
./scripts/barked.sh --version
```
Expected: works without sudo.

**Step 4: Commit**

```bash
git add scripts/barked.sh
git commit -m "refactor: update/uninstall-self acquire sudo only when needed"
```

---

### Task 7: Apply Same Changes to barked.ps1

**Files:**
- Modify: `scripts/barked.ps1:1` (remove `#Requires -RunAsAdministrator`)
- Modify: `scripts/barked.ps1:5` (update comment)
- Modify: `scripts/barked.ps1:688-701` (Check-Privileges function)
- Modify: `scripts/barked.ps1:3766-3770` (update admin check)
- Modify: `scripts/barked.ps1:3850-3854` (uninstall admin check)
- Modify: `scripts/barked.ps1` — state file paths

**Context:** Windows can't cache UAC like sudo. Design says: detect if any enabled modules need admin, if yes, re-launch the script elevated via `Start-Process -Verb RunAs`. Package managers (winget, choco, scoop) generally work without admin.

**Step 1: Remove #Requires -RunAsAdministrator**

Delete line 1 (`#Requires -RunAsAdministrator`) and update the comment on line 5.

**Step 2: Replace Check-Privileges with self-elevation logic**

Replace `Check-Privileges` function (lines 691-701) with:

```powershell
function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Request-Elevation {
    if (Test-IsAdmin) { return }
    Write-ColorLine "Some hardening steps need Administrator privileges. Requesting elevation..." DarkYellow
    $argList = @()
    if ($Uninstall) { $argList += '-Uninstall' }
    if ($Modify) { $argList += '-Modify' }
    if ($Audit) { $argList += '-Audit' }
    if ($Clean) { $argList += '-Clean' }
    if ($DryRun) { $argList += '-DryRun' }
    if ($Auto) { $argList += "-Auto"; $argList += $Auto }
    if ($Quiet) { $argList += '-Quiet' }
    if ($Version) { $argList += '-Version' }
    if ($Update) { $argList += '-Update' }
    if ($UninstallSelf) { $argList += '-UninstallSelf' }
    $argList += '-Elevated'
    try {
        Start-Process -FilePath "powershell.exe" -ArgumentList "-ExecutionPolicy Bypass -File `"$PSCommandPath`" $($argList -join ' ')" -Verb RunAs -Wait
        exit $LASTEXITCODE
    } catch {
        Write-ColorLine "Failed to acquire Administrator privileges." Red
        exit 1
    }
}
```

Add `-Elevated` switch to the param block (line 8+):
```powershell
    [switch]$Elevated
```

**Step 3: Add elevation call after module resolution in Main**

In the Main function, after modules are resolved (after `Build-ModuleList` equivalent), add:

```powershell
if (-not (Test-IsAdmin) -and -not $Elevated) {
    # Check if any enabled module needs admin
    $needsAdmin = $false
    $adminModules = @('firewall-inbound','firewall-stealth','dns-secure','auto-updates',
                      'guest-disable','hostname-scrub','telemetry-disable')
    foreach ($mod in $script:EnabledModules) {
        if ($adminModules -contains $mod) { $needsAdmin = $true; break }
    }
    if ($needsAdmin) { Request-Elevation }
}
```

**Step 4: Update state file path**

Change the state file primary location from `C:\ProgramData\hardening-state.json` to `$env:APPDATA\barked\state.json`. Keep project copy as backup.

**Step 5: Update update/uninstall admin checks**

In `Invoke-Update` (line ~3766) and `Invoke-UninstallSelf` (line ~3850), replace the hard admin check with self-elevation:

```powershell
if (-not (Test-IsAdmin)) {
    Request-Elevation
}
```

**Step 6: Test**

Open a normal (non-admin) PowerShell and run:
```powershell
.\scripts\barked.ps1 -Version
```
Expected: prints version without elevation.

**Step 7: Commit**

```bash
git add scripts/barked.ps1
git commit -m "refactor: remove admin requirement, self-elevate only when needed (Windows)"
```

---

### Task 8: Update Documentation and Install Scripts

**Files:**
- Modify: `README.md` — all `sudo barked` → `barked`, all `sudo ./scripts/barked.sh` → `./scripts/barked.sh`
- Modify: `install.sh` — update usage messages (lines 127-131)
- Modify: `install.ps1` — update usage messages
- Modify: `docs/plans/2026-01-29-hardening-wizard-design.md` — if it references `sudo`

**Step 1: Update README.md**

Replace all instances of:
- `sudo barked` → `barked`
- `sudo ./scripts/barked.sh` → `./scripts/barked.sh`
- `sudo ./barked.sh` → `./barked.sh`
- Keep `sudo` in the install one-liner (`curl ... | sudo bash`) — the installer itself still needs root

Update the "Get Barked" section usage examples.

**Step 2: Update install.sh usage messages**

Change lines 127-131:
```bash
echo "Usage:"
echo "  barked                # Run hardening wizard"
echo "  barked --clean        # Run system cleaner"
echo "  barked --update       # Update to latest version"
```

**Step 3: Update install.ps1 usage messages**

Same pattern — remove "as Administrator" from the usage examples.

**Step 4: Commit**

```bash
git add README.md install.sh install.ps1 docs/plans/
git commit -m "docs: update all references to remove sudo requirement"
```

---

### Task 9: Final Verification

**Step 1: Syntax check both scripts**

```bash
bash -n scripts/barked.sh && echo "barked.sh: OK"
pwsh -c "& { [System.Management.Automation.Language.Parser]::ParseFile('scripts/barked.ps1', [ref]\$null, [ref]\$null) | Out-Null; Write-Host 'barked.ps1: OK' }" 2>/dev/null || echo "pwsh not available, skip PS1 check"
```

**Step 2: Run barked.sh smoke tests**

```bash
# Version (no sudo)
./scripts/barked.sh --version

# Help (no sudo)
./scripts/barked.sh --help

# Audit mode (no sudo needed)
./scripts/barked.sh --audit

# Dry-run standard profile (will prompt for sudo)
./scripts/barked.sh --auto standard --dry-run
```

**Step 3: Verify no remaining run_as_user references**

```bash
grep -n "run_as_user" scripts/barked.sh
```
Expected: 0 results.

**Step 4: Verify no remaining old state path references**

```bash
grep -n "STATE_FILE_SYSTEM" scripts/barked.sh
```
Expected: 0 results (replaced with STATE_FILE_USER and STATE_FILE_LEGACY).

**Step 5: Commit any fixes, then final commit**

```bash
git add -A
git commit -m "chore: final verification and cleanup for sudo escalation refactor"
```
