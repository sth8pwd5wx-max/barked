# Install & Update System Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add install scripts (curl/PowerShell one-liner), self-update via GitHub releases, passive update notifications, and `--version`/`--update`/`--uninstall-self` flags to both barked.sh and barked.ps1.

**Architecture:** Two new installer scripts at repo root (`install.sh`, `install.ps1`) handle first-time installation. Update/version/uninstall-self logic is added directly into the main scripts. A GitHub repo variable (`GITHUB_REPO`) is set at the top of each script. Passive update check runs after every main operation with 24-hour caching.

**Tech Stack:** Bash, PowerShell, GitHub Releases API, curl, `Invoke-RestMethod`

---

## Task 1: Add `--version` flag and `GITHUB_REPO` constant (barked.sh)

**Files:**
- Modify: `scripts/barked.sh:8` (add GITHUB_REPO constant after VERSION)
- Modify: `scripts/barked.sh:4714-4787` (parse_args — add --version case)

**Step 1: Add GITHUB_REPO constant**

After line 8 (`readonly VERSION="2.0.0"`), add:

```bash
readonly GITHUB_REPO="sth8pwd5wx-max/barked"
```

**Step 2: Add --version flag to parse_args**

In the `case "$1"` block, before the `--help|-h)` case, add:

```bash
            --version|-v)
                echo "barked v${VERSION}"
                exit 0
                ;;
```

**Step 3: Add --version to help text**

In the `--help|-h)` case, add this line after the `--force` line:

```bash
                echo "  --version, -v          Show version and exit"
```

And add an example:

```bash
                echo "  $0 --version                          Show version"
```

**Step 4: Verify**

Run: `bash -n scripts/barked.sh`
Expected: No errors

**Step 5: Commit**

```bash
git add scripts/barked.sh
git commit -m "feat: add --version flag and GITHUB_REPO constant (barked.sh)"
```

---

## Task 2: Add update functions (barked.sh)

**Files:**
- Modify: `scripts/barked.sh` — add new section before MAIN (before line 6120)

**Step 1: Add version comparison function**

Insert a new section `# UPDATE SYSTEM` before the `# MAIN` section. Add:

```bash
# ═══════════════════════════════════════════════════════════════════
# UPDATE SYSTEM
# ═══════════════════════════════════════════════════════════════════

# Compare two semver strings. Returns 0 if $1 > $2, 1 otherwise.
version_gt() {
    local IFS='.'
    local i
    local -a v1=($1) v2=($2)
    for ((i=0; i<3; i++)); do
        local a="${v1[i]:-0}" b="${v2[i]:-0}"
        if ((a > b)); then return 0; fi
        if ((a < b)); then return 1; fi
    done
    return 1
}

fetch_latest_version() {
    local api_url="https://api.github.com/repos/${GITHUB_REPO}/releases/latest"
    local response
    response=$(curl -fsSL --connect-timeout 5 --max-time 10 "$api_url" 2>/dev/null) || return 1
    # Extract tag_name, strip leading 'v'
    local tag
    tag=$(echo "$response" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name"[[:space:]]*:[[:space:]]*"v\{0,1\}\([^"]*\)".*/\1/')
    [[ -z "$tag" ]] && return 1
    echo "$tag"
}

run_update() {
    echo ""
    echo -e "  ${BROWN}Checking for updates...${NC}"

    # Check permissions
    local install_path
    install_path=$(command -v barked 2>/dev/null || echo "")
    if [[ -z "$install_path" ]]; then
        install_path="$(readlink -f "$0" 2>/dev/null || echo "$0")"
    fi

    local latest
    latest=$(fetch_latest_version) || {
        echo -e "  ${RED}Could not reach GitHub. Check your connection.${NC}"
        exit 1
    }

    if ! version_gt "$latest" "$VERSION"; then
        echo -e "  ${GREEN}Already up to date (v${VERSION})${NC}"
        exit 0
    fi

    echo -e "  ${GREEN}New version available: v${latest} (current: v${VERSION})${NC}"

    # Check write permissions
    if [[ ! -w "$install_path" ]]; then
        echo -e "  ${RED}Update requires sudo. Run: sudo barked --update${NC}"
        exit 1
    fi

    # Download to temp file
    local tmp_file="/tmp/barked-new-$$.sh"
    local download_url="https://github.com/${GITHUB_REPO}/releases/latest/download/barked.sh"
    echo -e "  ${BROWN}Downloading v${latest}...${NC}"
    curl -fsSL --connect-timeout 10 --max-time 60 -o "$tmp_file" "$download_url" || {
        echo -e "  ${RED}Download failed.${NC}"
        rm -f "$tmp_file"
        exit 1
    }

    # Validate syntax
    if ! bash -n "$tmp_file" 2>/dev/null; then
        echo -e "  ${RED}Downloaded file failed syntax check. Update aborted.${NC}"
        rm -f "$tmp_file"
        exit 1
    fi

    # Atomic replace
    chmod +x "$tmp_file"
    mv "$tmp_file" "$install_path" || {
        # Cross-filesystem fallback
        cp "$tmp_file" "$install_path" && rm -f "$tmp_file" || {
            echo -e "  ${RED}Failed to replace script. Update aborted.${NC}"
            rm -f "$tmp_file"
            exit 1
        }
    }

    echo -e "  ${GREEN}Updated to v${latest}${NC}"
    exit 0
}

check_update_passive() {
    # Skip if no internet tool
    command -v curl >/dev/null 2>&1 || return

    local cache_file="/tmp/barked-update-check"
    local cache_max=86400  # 24 hours

    # Check cache freshness
    if [[ -f "$cache_file" ]]; then
        local cache_age
        local now
        now=$(date +%s)
        local cache_time
        cache_time=$(head -1 "$cache_file" 2>/dev/null || echo "0")
        cache_age=$((now - cache_time))
        if ((cache_age < cache_max)); then
            # Read cached version
            local cached_version
            cached_version=$(tail -1 "$cache_file" 2>/dev/null || echo "")
            if [[ -n "$cached_version" ]] && version_gt "$cached_version" "$VERSION"; then
                echo ""
                echo -e "  ${GREEN}A new version is available (v${cached_version}). Run: ${BOLD}barked --update${NC}"
            fi
            return
        fi
    fi

    # Fetch in background-safe way
    local latest
    latest=$(fetch_latest_version 2>/dev/null) || return

    # Write cache
    echo "$(date +%s)" > "$cache_file" 2>/dev/null
    echo "$latest" >> "$cache_file" 2>/dev/null

    if version_gt "$latest" "$VERSION"; then
        echo ""
        echo -e "  ${GREEN}A new version is available (v${latest}). Run: ${BOLD}barked --update${NC}"
    fi
}

run_uninstall_self() {
    local install_path
    install_path=$(command -v barked 2>/dev/null || echo "")

    if [[ -z "$install_path" ]]; then
        echo -e "  ${RED}barked is not installed in PATH. Nothing to remove.${NC}"
        exit 1
    fi

    if [[ ! -w "$install_path" ]]; then
        echo -e "  ${RED}Uninstall requires sudo. Run: sudo barked --uninstall-self${NC}"
        exit 1
    fi

    echo -e "  Removing ${install_path}..."
    rm -f "$install_path"
    echo -e "  ${GREEN}barked has been removed from your system.${NC}"

    # Clean up cache
    rm -f /tmp/barked-update-check

    exit 0
}
```

**Step 2: Add --update and --uninstall-self to parse_args**

In the `case "$1"` block, before `--version|-v)`, add:

```bash
            --update)
                run_update
                ;;
            --uninstall-self)
                run_uninstall_self
                ;;
```

And in the help text section, add:

```bash
                echo "  --update               Update barked to the latest version"
                echo "  --uninstall-self       Remove barked from system PATH"
```

**Step 3: Add passive check to main()**

In the `main()` function, just before the final `echo ""` / re-run message block at the bottom (line ~6236), add:

```bash
    # Passive update check (runs after all work is done)
    check_update_passive
```

Also add the same call after `run_audit` exits and after `run_clean` exits — but since those call `exit 0`, add the passive check just before each `exit 0`:

In the audit block:
```bash
    if [[ "$AUDIT_MODE" == true ]]; then
        run_audit
        check_update_passive
        exit 0
    fi
```

In the clean block:
```bash
    if [[ "$CLEAN_MODE" == true ]]; then
        run_clean
        check_update_passive
        exit 0
    fi
```

**Step 4: Verify**

Run: `bash -n scripts/barked.sh`
Expected: No errors

**Step 5: Commit**

```bash
git add scripts/barked.sh
git commit -m "feat: add --update, --uninstall-self, and passive update check (barked.sh)"
```

---

## Task 3: Add version, update, and uninstall-self to barked.ps1

**Files:**
- Modify: `scripts/barked.ps1:8-15` (param block — add switches)
- Modify: `scripts/barked.ps1:20` (add GITHUB_REPO after VERSION)
- Modify: `scripts/barked.ps1` — add update functions section before MAIN
- Modify: `scripts/barked.ps1:3728-3748` (Print-Help — add new flags)
- Modify: `scripts/barked.ps1:3750-3831` (Main — add routing + passive check)

**Step 1: Update param block**

Replace the param block (lines 8-15) with:

```powershell
param(
    [switch]$Uninstall,
    [switch]$Modify,
    [switch]$Clean,
    [switch]$Force,
    [switch]$DryRun,
    [switch]$Help,
    [switch]$Version,
    [switch]$Update,
    [switch]$UninstallSelf
)
```

**Step 2: Add GITHUB_REPO constant**

After line 20 (`$script:VERSION = "1.0.0"`), add:

```powershell
$script:GITHUB_REPO = "sth8pwd5wx-max/barked"
```

**Step 3: Add update functions**

Insert a new section before `# MAIN`. Add:

```powershell
# ═══════════════════════════════════════════════════════════════════
# UPDATE SYSTEM
# ═══════════════════════════════════════════════════════════════════

function Test-VersionGt {
    param([string]$New, [string]$Current)
    try {
        return ([version]$New -gt [version]$Current)
    } catch {
        return $false
    }
}

function Get-LatestVersion {
    $apiUrl = "https://api.github.com/repos/$($script:GITHUB_REPO)/releases/latest"
    try {
        $response = Invoke-RestMethod -Uri $apiUrl -TimeoutSec 10 -ErrorAction Stop
        $tag = $response.tag_name -replace '^v', ''
        if ([string]::IsNullOrEmpty($tag)) { return $null }
        return $tag
    } catch {
        return $null
    }
}

function Invoke-Update {
    Write-Host ""
    Write-Host "  Checking for updates..." -ForegroundColor DarkYellow

    $latest = Get-LatestVersion
    if ($null -eq $latest) {
        Write-Host "  Could not reach GitHub. Check your connection." -ForegroundColor Red
        exit 1
    }

    if (-not (Test-VersionGt -New $latest -Current $script:VERSION)) {
        Write-Host "  Already up to date (v$($script:VERSION))" -ForegroundColor Green
        exit 0
    }

    Write-Host "  New version available: v$latest (current: v$($script:VERSION))" -ForegroundColor Green

    # Determine install path
    $installDir = "C:\Program Files\Barked"
    $installPath = Join-Path $installDir "barked.ps1"

    # Check admin
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Host "  Update requires Administrator. Run PowerShell as Administrator." -ForegroundColor Red
        exit 1
    }

    # Download to temp
    $tmpFile = Join-Path $env:TEMP "barked-new-$PID.ps1"
    $downloadUrl = "https://github.com/$($script:GITHUB_REPO)/releases/latest/download/barked.ps1"
    Write-Host "  Downloading v$latest..." -ForegroundColor DarkYellow
    try {
        Invoke-WebRequest -Uri $downloadUrl -OutFile $tmpFile -TimeoutSec 60 -ErrorAction Stop
    } catch {
        Write-Host "  Download failed." -ForegroundColor Red
        Remove-Item -Path $tmpFile -ErrorAction SilentlyContinue
        exit 1
    }

    # Validate syntax
    $errors = $null
    [System.Management.Automation.Language.Parser]::ParseFile($tmpFile, [ref]$null, [ref]$errors) | Out-Null
    if ($errors.Count -gt 0) {
        Write-Host "  Downloaded file failed syntax check. Update aborted." -ForegroundColor Red
        Remove-Item -Path $tmpFile -ErrorAction SilentlyContinue
        exit 1
    }

    # Replace
    if (-not (Test-Path $installDir)) {
        New-Item -ItemType Directory -Path $installDir -Force | Out-Null
    }
    Move-Item -Path $tmpFile -Destination $installPath -Force

    Write-Host "  Updated to v$latest" -ForegroundColor Green
    exit 0
}

function Invoke-PassiveUpdateCheck {
    $cacheFile = Join-Path $env:TEMP "barked-update-check"
    $cacheMax = 86400  # 24 hours in seconds

    # Check cache
    if (Test-Path $cacheFile) {
        $lines = Get-Content $cacheFile -ErrorAction SilentlyContinue
        if ($lines -and $lines.Count -ge 2) {
            $cacheTime = [int64]$lines[0]
            $now = [int64](Get-Date -UFormat %s)
            if (($now - $cacheTime) -lt $cacheMax) {
                $cachedVersion = $lines[1]
                if (Test-VersionGt -New $cachedVersion -Current $script:VERSION) {
                    Write-Host ""
                    Write-Host "  A new version is available (v$cachedVersion). Run: " -ForegroundColor Green -NoNewline
                    Write-Host "barked -Update" -ForegroundColor Green
                }
                return
            }
        }
    }

    # Fetch
    $latest = Get-LatestVersion
    if ($null -eq $latest) { return }

    # Write cache
    $now = [int64](Get-Date -UFormat %s)
    @($now, $latest) | Set-Content $cacheFile -ErrorAction SilentlyContinue

    if (Test-VersionGt -New $latest -Current $script:VERSION) {
        Write-Host ""
        Write-Host "  A new version is available (v$latest). Run: " -ForegroundColor Green -NoNewline
        Write-Host "barked -Update" -ForegroundColor Green
    }
}

function Invoke-UninstallSelf {
    $installDir = "C:\Program Files\Barked"
    $installPath = Join-Path $installDir "barked.ps1"
    $cmdPath = Join-Path $installDir "barked.cmd"

    if (-not (Test-Path $installPath)) {
        Write-Host "  barked is not installed. Nothing to remove." -ForegroundColor Red
        exit 1
    }

    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Host "  Uninstall requires Administrator. Run PowerShell as Administrator." -ForegroundColor Red
        exit 1
    }

    Remove-Item -Path $installPath -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $cmdPath -Force -ErrorAction SilentlyContinue

    # Remove from PATH if present
    $machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    if ($machinePath -like "*$installDir*") {
        $newPath = ($machinePath -split ";" | Where-Object { $_ -ne $installDir }) -join ";"
        [Environment]::SetEnvironmentVariable("Path", $newPath, "Machine")
    }

    # Remove dir if empty
    if ((Test-Path $installDir) -and @(Get-ChildItem $installDir).Count -eq 0) {
        Remove-Item -Path $installDir -Force
    }

    # Clean cache
    Remove-Item -Path (Join-Path $env:TEMP "barked-update-check") -Force -ErrorAction SilentlyContinue

    Write-Host "  barked has been removed from your system." -ForegroundColor Green
    exit 0
}
```

**Step 4: Update Print-Help**

Add these lines to Print-Help after the `-Help` line:

```powershell
    Write-Host "  -Version      Show version and exit"
    Write-Host "  -Update       Update barked to the latest version"
    Write-Host "  -UninstallSelf  Remove barked from system PATH"
```

**Step 5: Update Main function**

Add early exits at the top of `Main`, after the `$Help` check:

```powershell
    if ($Version) {
        Write-Host "barked v$($script:VERSION)"
        exit 0
    }
    if ($Update) {
        Invoke-Update
    }
    if ($UninstallSelf) {
        Invoke-UninstallSelf
    }
```

Add `Invoke-PassiveUpdateCheck` before each final `return` or exit in the Main function — at the end of the uninstall branch, modify branch, clean branch, and default harden branch. Specifically, add it just before the `Write-ColorLine "  Re-run..."` lines in the clean function exit and at the end of the default harden block, and before the `return` in uninstall/modify blocks.

For the Clean block, change:
```powershell
    if ($Clean) {
        Invoke-Clean
        Invoke-PassiveUpdateCheck
        exit 0
    }
```

At the end of the Main function's default block, before the final re-run message:
```powershell
            Invoke-PassiveUpdateCheck

            Write-Host ""
            Write-ColorLine "  Re-run this script anytime — it's safe to repeat." DarkYellow
```

**Step 6: Verify**

Run: `bash -n scripts/barked.sh` (shouldn't have changed, but sanity check)

**Step 7: Commit**

```bash
git add scripts/barked.ps1
git commit -m "feat: add -Version, -Update, -UninstallSelf, and passive update check (barked.ps1)"
```

---

## Task 4: Create install.sh (macOS/Linux installer)

**Files:**
- Create: `install.sh`

**Step 1: Write the installer**

```bash
#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
# Barked installer — macOS / Linux
# Usage: curl -fsSL https://raw.githubusercontent.com/sth8pwd5wx-max/barked/main/install.sh | sudo bash
# ═══════════════════════════════════════════════════════════════════
set -euo pipefail

GITHUB_REPO="sth8pwd5wx-max/barked"
INSTALL_DIR="/usr/local/bin"
BINARY_NAME="barked"

RED='\033[0;31m'
GREEN='\033[0;32m'
BROWN='\033[0;33m'
NC='\033[0m'

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║${NC}          Barked Installer                        ${GREEN}║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════╝${NC}"
echo ""

# Check root
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}This installer must be run as root.${NC}"
    echo "  Run: curl -fsSL <url> | sudo bash"
    exit 1
fi

# Check curl
if ! command -v curl >/dev/null 2>&1; then
    echo -e "${RED}curl is required but not found.${NC}"
    exit 1
fi

# Detect OS
OS="$(uname -s)"
case "$OS" in
    Darwin) OS_NAME="macOS" ;;
    Linux)  OS_NAME="Linux" ;;
    *)
        echo -e "${RED}Unsupported OS: ${OS}. Use install.ps1 for Windows.${NC}"
        exit 1
        ;;
esac
echo -e "  Detected: ${GREEN}${OS_NAME}${NC} ($(uname -m))"

# Get latest release version
echo -e "  ${BROWN}Fetching latest release...${NC}"
DOWNLOAD_URL="https://github.com/${GITHUB_REPO}/releases/latest/download/barked.sh"

# Download
TMP_FILE=$(mktemp /tmp/barked-install-XXXXXX.sh)
trap 'rm -f "$TMP_FILE"' EXIT

curl -fsSL --connect-timeout 10 --max-time 60 -o "$TMP_FILE" "$DOWNLOAD_URL" || {
    echo -e "${RED}Download failed. Check your connection and that the repo exists.${NC}"
    exit 1
}

# Validate syntax
if ! bash -n "$TMP_FILE" 2>/dev/null; then
    echo -e "${RED}Downloaded file failed syntax check. Install aborted.${NC}"
    exit 1
fi

# Install
mkdir -p "$INSTALL_DIR"
mv "$TMP_FILE" "${INSTALL_DIR}/${BINARY_NAME}"
chmod +x "${INSTALL_DIR}/${BINARY_NAME}"

# Verify
INSTALLED_VERSION=$("${INSTALL_DIR}/${BINARY_NAME}" --version 2>/dev/null || echo "unknown")
echo ""
echo -e "  ${GREEN}Installed: ${INSTALLED_VERSION}${NC}"
echo -e "  ${GREEN}Location:  ${INSTALL_DIR}/${BINARY_NAME}${NC}"
echo ""
echo -e "  Run ${GREEN}sudo barked${NC} to start the hardening wizard."
echo -e "  Run ${GREEN}sudo barked --clean${NC} to clean your system."
echo -e "  Run ${GREEN}sudo barked --update${NC} to update later."
echo ""
```

**Step 2: Make executable**

```bash
chmod +x install.sh
```

**Step 3: Verify**

Run: `bash -n install.sh`
Expected: No errors

**Step 4: Commit**

```bash
git add install.sh
git commit -m "feat: add install.sh for macOS/Linux curl one-liner"
```

---

## Task 5: Create install.ps1 (Windows installer)

**Files:**
- Create: `install.ps1`

**Step 1: Write the installer**

```powershell
# ═══════════════════════════════════════════════════════════════════
# Barked installer — Windows
# Usage: irm https://raw.githubusercontent.com/sth8pwd5wx-max/barked/main/install.ps1 | iex
# ═══════════════════════════════════════════════════════════════════

$GithubRepo = "sth8pwd5wx-max/barked"
$InstallDir = "C:\Program Files\Barked"
$BinaryName = "barked.ps1"
$CmdWrapper = "barked.cmd"

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║" -ForegroundColor Green -NoNewline
Write-Host "          Barked Installer                        " -NoNewline
Write-Host "║" -ForegroundColor Green
Write-Host "╚══════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""

# Check admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "  This installer must be run as Administrator." -ForegroundColor Red
    Write-Host "  Right-click PowerShell > Run as Administrator, then re-run."
    exit 1
}

Write-Host "  Detected: Windows $([Environment]::OSVersion.Version.Major)" -ForegroundColor Green

# Download
Write-Host "  Fetching latest release..." -ForegroundColor DarkYellow
$downloadUrl = "https://github.com/$GithubRepo/releases/latest/download/barked.ps1"
$tmpFile = Join-Path $env:TEMP "barked-install-$PID.ps1"

try {
    Invoke-WebRequest -Uri $downloadUrl -OutFile $tmpFile -TimeoutSec 60 -ErrorAction Stop
} catch {
    Write-Host "  Download failed. Check your connection and that the repo exists." -ForegroundColor Red
    exit 1
}

# Validate syntax
$errors = $null
[System.Management.Automation.Language.Parser]::ParseFile($tmpFile, [ref]$null, [ref]$errors) | Out-Null
if ($errors.Count -gt 0) {
    Write-Host "  Downloaded file failed syntax check. Install aborted." -ForegroundColor Red
    Remove-Item -Path $tmpFile -ErrorAction SilentlyContinue
    exit 1
}

# Install
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}
Move-Item -Path $tmpFile -Destination (Join-Path $InstallDir $BinaryName) -Force

# Create cmd wrapper for cmd.exe users
$cmdContent = "@echo off`r`npowershell.exe -ExecutionPolicy Bypass -File `"$InstallDir\$BinaryName`" %*"
Set-Content -Path (Join-Path $InstallDir $CmdWrapper) -Value $cmdContent

# Add to PATH if not present
$machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
if ($machinePath -notlike "*$InstallDir*") {
    [Environment]::SetEnvironmentVariable("Path", "$machinePath;$InstallDir", "Machine")
    Write-Host "  Added $InstallDir to system PATH." -ForegroundColor DarkYellow
}

# Verify
Write-Host ""
$installedVersion = & (Join-Path $InstallDir $BinaryName) -Version 2>$null
if ($installedVersion) {
    Write-Host "  Installed: $installedVersion" -ForegroundColor Green
} else {
    Write-Host "  Installed: barked.ps1" -ForegroundColor Green
}
Write-Host "  Location:  $InstallDir\$BinaryName" -ForegroundColor Green
Write-Host ""
Write-Host "  Run " -NoNewline; Write-Host "barked" -ForegroundColor Green -NoNewline; Write-Host " to start the hardening wizard."
Write-Host "  Run " -NoNewline; Write-Host "barked -Clean" -ForegroundColor Green -NoNewline; Write-Host " to clean your system."
Write-Host "  Run " -NoNewline; Write-Host "barked -Update" -ForegroundColor Green -NoNewline; Write-Host " to update later."
Write-Host ""
Write-Host "  Note: Restart your terminal for PATH changes to take effect." -ForegroundColor DarkYellow
Write-Host ""
```

**Step 2: Commit**

```bash
git add install.ps1
git commit -m "feat: add install.ps1 for Windows PowerShell one-liner"
```

---

## Task 6: Update README and create GitHub repo

**Files:**
- Modify: `README.md` — replace Quick Start, add Install section
- Run: `gh repo create` and `gh release create`

**Step 1: Update README Quick Start**

Replace the existing Quick Start section (lines 13-30) with:

```markdown
## Install

**macOS / Linux:**
```bash
curl -fsSL https://raw.githubusercontent.com/sth8pwd5wx-max/barked/main/install.sh | sudo bash
```

**Windows (PowerShell as Administrator):**
```powershell
irm https://raw.githubusercontent.com/sth8pwd5wx-max/barked/main/install.ps1 | iex
```

Once installed, run `barked` from anywhere. The wizard guides you from there.

### Update

```bash
sudo barked --update              # macOS / Linux
barked -Update                    # Windows (as Administrator)
```

Barked also checks for updates after each run and notifies you if a new version is available.

### Uninstall Barked

To remove barked itself from your system (not to revert hardening changes):
```bash
sudo barked --uninstall-self      # macOS / Linux
barked -UninstallSelf             # Windows (as Administrator)
```

### Manual Install (from source)

```bash
git clone https://github.com/sth8pwd5wx-max/barked secure
cd secure
chmod +x scripts/barked.sh
sudo ./scripts/barked.sh
```

Windows:
```powershell
git clone https://github.com/sth8pwd5wx-max/barked secure
cd secure
.\scripts\barked.ps1
```
```

**Step 2: Update File Structure in README**

Update the file structure section to include the new files:

```markdown
## File Structure

```
secure/
├── install.sh                # macOS/Linux installer
├── install.ps1               # Windows installer
├── scripts/
│   ├── barked.sh              # macOS + Linux wizard
│   ├── barked.ps1             # Windows wizard
│   └── weekly-audit.sh        # macOS weekly audit
├── docs/plans/                # Design documents
├── audits/                    # Audit reports
├── baseline/                  # Known-good system snapshots
└── state/                     # Hardening state files
```
```

**Step 3: Create GitHub repo and push**

```bash
gh repo create barked --public --source=. --push --remote=origin --description "Cross-platform security hardening wizard for macOS, Linux, and Windows"
```

If the repo already exists or the remote is already set, just push:

```bash
git push -u origin main
```

**Step 4: Replace sth8pwd5wx-max/barked placeholders**

After the repo is created, get the actual owner/repo path from `gh repo view --json nameWithOwner -q .nameWithOwner` and replace all `sth8pwd5wx-max/barked` placeholders in:
- `scripts/barked.sh`
- `scripts/barked.ps1`
- `install.sh`
- `install.ps1`
- `README.md`
- `docs/plans/2026-01-30-install-update-design.md`

**Step 5: Create initial release**

```bash
gh release create v2.0.0 scripts/barked.sh scripts/barked.ps1 --title "v2.0.0" --notes "Initial release with hardening wizard, system cleaner, audit mode, and install/update system."
```

**Step 6: Commit**

```bash
git add README.md install.sh install.ps1 scripts/barked.sh scripts/barked.ps1 docs/plans/2026-01-30-install-update-design.md
git commit -m "docs: update README with install instructions and repo URLs"
```

---

## Summary

| Task | Description | Key Output |
|------|-------------|------------|
| 1 | --version flag + GITHUB_REPO | barked.sh prints version |
| 2 | Update functions (barked.sh) | --update, --uninstall-self, passive check |
| 3 | Update functions (barked.ps1) | -Update, -UninstallSelf, passive check |
| 4 | install.sh | curl one-liner installer for macOS/Linux |
| 5 | install.ps1 | PowerShell one-liner installer for Windows |
| 6 | README + GitHub repo + release | Repo created, v2.0.0 released, README updated |
