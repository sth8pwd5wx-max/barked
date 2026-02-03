# ═══════════════════════════════════════════════════════════════════
# install.ps1 — Barked installer for Windows
# Usage: irm https://raw.githubusercontent.com/sth8pwd5wx-max/barked/main/install.ps1 | iex
# ═══════════════════════════════════════════════════════════════════

$GithubRepo  = "sth8pwd5wx-max/barked"
$InstallDir  = "C:\Program Files\Barked"
$BinaryName  = "barked.ps1"
$CmdWrapper  = "barked.cmd"

# ═══════════════════════════════════════════════════════════════════
# HEADER
# ═══════════════════════════════════════════════════════════════════
Write-Host ""
Write-Host "╔══════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║" -ForegroundColor Green -NoNewline
Write-Host "             Barked Installer                     " -NoNewline
Write-Host "║" -ForegroundColor Green
Write-Host "║" -ForegroundColor Green -NoNewline
Write-Host "             Windows                              " -NoNewline
Write-Host "║" -ForegroundColor Green
Write-Host "╚══════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""

# ═══════════════════════════════════════════════════════════════════
# PREFLIGHT CHECKS
# ═══════════════════════════════════════════════════════════════════
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)
if (-not $isAdmin) {
    Write-Host "  Error: This installer must be run as Administrator." -ForegroundColor Red
    Write-Host "  Right-click PowerShell > Run as Administrator, then re-run."
    exit 1
}

Write-Host "  Detected: Windows $([Environment]::OSVersion.Version)" -ForegroundColor Green
Write-Host ""

# ═══════════════════════════════════════════════════════════════════
# DOWNLOAD
# ═══════════════════════════════════════════════════════════════════
Write-Host "  Fetching latest release..." -ForegroundColor DarkYellow
$downloadUrl = "https://github.com/$GithubRepo/releases/latest/download/barked.ps1"
Write-Host "  $downloadUrl"
Write-Host ""

$tmpFile = Join-Path $env:TEMP "barked-install-$(Get-Random).ps1"

try {
    Invoke-WebRequest -Uri $downloadUrl -OutFile $tmpFile -TimeoutSec 60 -ErrorAction Stop
} catch {
    Write-Host "  Error: Download failed. Check your connection and that the repo exists." -ForegroundColor Red
    Remove-Item -Path $tmpFile -ErrorAction SilentlyContinue
    exit 1
}

# Download and verify checksum
$checksumUrl = "https://github.com/$GithubRepo/releases/latest/download/barked.ps1.sha256"
try {
    $expectedHash = (Invoke-WebRequest -Uri $checksumUrl -TimeoutSec 30 -ErrorAction Stop).Content.Trim().Split()[0]
} catch {
    Write-Host "  Error: Failed to download checksum for verification" -ForegroundColor Red
    Remove-Item -Path $tmpFile -ErrorAction SilentlyContinue
    exit 1
}

$actualHash = (Get-FileHash -Path $tmpFile -Algorithm SHA256).Hash
if ($actualHash -ne $expectedHash.ToUpper()) {
    Write-Host "  Error: Checksum verification failed. Install aborted." -ForegroundColor Red
    Write-Host "  Expected: $expectedHash" -ForegroundColor Red
    Write-Host "  Got:      $actualHash" -ForegroundColor Red
    Remove-Item -Path $tmpFile -ErrorAction SilentlyContinue
    exit 1
}

Write-Host "  Checksum verified" -ForegroundColor Green

# ═══════════════════════════════════════════════════════════════════
# VALIDATE
# ═══════════════════════════════════════════════════════════════════
$errors = $null
[System.Management.Automation.Language.Parser]::ParseFile($tmpFile, [ref]$null, [ref]$errors) | Out-Null
if ($errors.Count -gt 0) {
    Write-Host "  Error: Downloaded file failed syntax check. Install aborted." -ForegroundColor Red
    Remove-Item -Path $tmpFile -ErrorAction SilentlyContinue
    exit 1
}

# ═══════════════════════════════════════════════════════════════════
# INSTALL
# ═══════════════════════════════════════════════════════════════════
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}
Move-Item -Path $tmpFile -Destination (Join-Path $InstallDir $BinaryName) -Force

# Create cmd wrapper so barked works from cmd.exe and PowerShell alike
$cmdContent = "@echo off`r`npowershell.exe -ExecutionPolicy Bypass -File `"$InstallDir\$BinaryName`" %*"
Set-Content -Path (Join-Path $InstallDir $CmdWrapper) -Value $cmdContent

# Add to system PATH if not already present
$machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
if ($machinePath -notlike "*$InstallDir*") {
    [Environment]::SetEnvironmentVariable("Path", "$machinePath;$InstallDir", "Machine")
    Write-Host "  Added $InstallDir to system PATH." -ForegroundColor DarkYellow
}

# ═══════════════════════════════════════════════════════════════════
# VERIFY
# ═══════════════════════════════════════════════════════════════════
Write-Host ""
$installedVersion = $null
try {
    $installedVersion = & (Join-Path $InstallDir $BinaryName) -Version 2>$null
} catch { }

if ($installedVersion) {
    Write-Host "  Installed: $installedVersion" -ForegroundColor Green
} else {
    Write-Host "  Installed: barked.ps1" -ForegroundColor Green
}
Write-Host "  Location:  $InstallDir\$BinaryName" -ForegroundColor Green
Write-Host ""

# ═══════════════════════════════════════════════════════════════════
# USAGE HINTS
# ═══════════════════════════════════════════════════════════════════
Write-Host "Usage:"
Write-Host "  Run " -NoNewline
Write-Host "barked" -ForegroundColor Green -NoNewline
Write-Host "          to start the hardening wizard."
Write-Host "  Run " -NoNewline
Write-Host "barked -Clean" -ForegroundColor Green -NoNewline
Write-Host "   to clean your system."
Write-Host "  Run " -NoNewline
Write-Host "barked -Update" -ForegroundColor Green -NoNewline
Write-Host "  to update later."
Write-Host ""
Write-Host "  Note: Restart your terminal for PATH changes to take effect." -ForegroundColor DarkYellow
Write-Host ""
