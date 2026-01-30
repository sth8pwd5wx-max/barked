#Requires -RunAsAdministrator
# ═══════════════════════════════════════════════════════════════════
# harden.ps1 — Windows security hardening wizard
# Idempotent, interactive, profile-based system hardening
# Run: Right-click PowerShell > Run as Administrator > .\harden.ps1
# ═══════════════════════════════════════════════════════════════════

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

$script:VERSION = "1.0.0"
$script:DATE = Get-Date -Format "yyyy-MM-dd"
$script:TIMESTAMP = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$script:ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$script:AuditDir = Join-Path (Split-Path $script:ScriptDir) "audits"
$script:BaselineDir = Join-Path (Split-Path $script:ScriptDir) "baseline"
$script:LogFile = Join-Path $script:AuditDir "hardening-log-$($script:DATE).txt"

# ═══════════════════════════════════════════════════════════════════
# GLOBALS
# ═══════════════════════════════════════════════════════════════════
$script:Profile = ""
$script:OutputMode = ""
$script:TotalModules = 0
$script:CurrentModule = 0
$script:CountApplied = 0
$script:CountSkipped = 0
$script:CountFailed = 0
$script:CountManual = 0
$script:EnabledModules = @()
$script:LogEntries = @()
$script:ManualSteps = @()
$script:ModuleResult = ""

# Questionnaire answers
$script:QThreat = ""
$script:QUsecase = ""
$script:QTravel = ""
$script:QEcosystem = ""
$script:QNetwork = ""
$script:QAuth = ""
$script:QTraffic = ""
$script:QMaintenance = ""

# Real user home (for user-level configs under admin elevation)
$script:RealHome = $env:USERPROFILE
$script:RealUser = $env:USERNAME

# ═══════════════════════════════════════════════════════════════════
# OUTPUT UTILITIES
# ═══════════════════════════════════════════════════════════════════
function Write-Color {
    param([string]$Text, [ConsoleColor]$Color = "White")
    Write-Host $Text -ForegroundColor $Color -NoNewline
}

function Write-ColorLine {
    param([string]$Text, [ConsoleColor]$Color = "White")
    Write-Host $Text -ForegroundColor $Color
}

function Log-Entry {
    param([string]$Module, [string]$Action, [string]$Result, [string]$Message)
    $entry = "[$(Get-Date -Format 'HH:mm:ss')] [$Module] [$Action] [$Result] $Message"
    $script:LogEntries += $entry
}

function Print-Header {
    Write-Host ""
    Write-ColorLine "╔══════════════════════════════════════════════════╗" Cyan
    Write-Host "║" -ForegroundColor Cyan -NoNewline
    Write-Host "        SYSTEM HARDENING WIZARD v$($script:VERSION)           " -ForegroundColor White -NoNewline
    Write-ColorLine "║" Cyan
    Write-Host "║" -ForegroundColor Cyan -NoNewline
    Write-Host "        Windows                                    " -NoNewline
    Write-ColorLine "║" Cyan
    Write-ColorLine "╚══════════════════════════════════════════════════╝" Cyan
    Write-Host ""
}

function Print-Section {
    param([string]$Title)
    Write-Host ""
    Write-ColorLine "═══ $Title ═══" White
    Write-Host ""
}

function Print-Status {
    param([int]$Num, [int]$Total, [string]$Desc, [string]$Status)
    switch ($Status) {
        "applied"  { Write-Host "  " -NoNewline; Write-Color "✓" Green; Write-Host " [$Num/$Total] $Desc " -NoNewline; Write-ColorLine "(applied)" DarkGray }
        "skipped"  { Write-Host "  " -NoNewline; Write-Color "○" Green; Write-Host " [$Num/$Total] $Desc " -NoNewline; Write-ColorLine "(already applied)" DarkGray }
        "failed"   { Write-Host "  " -NoNewline; Write-Color "✗" Red;   Write-Host " [$Num/$Total] $Desc " -NoNewline; Write-ColorLine "(failed)" Red }
        "manual"   { Write-Host "  " -NoNewline; Write-Color "☐" Yellow; Write-Host " [$Num/$Total] $Desc " -NoNewline; Write-ColorLine "(manual)" Yellow }
        "skipped_unsupported" { Write-Host "  " -NoNewline; Write-Color "–" DarkGray; Write-Host " [$Num/$Total] $Desc " -NoNewline; Write-ColorLine "(not available on Windows)" DarkGray }
    }
}

function Prompt-Choice {
    param([string]$Prompt, [string[]]$Options)
    Write-ColorLine $Prompt White
    Write-Host ""
    for ($i = 0; $i -lt $Options.Count; $i++) {
        Write-Host "  " -NoNewline
        Write-Color "[$($i+1)]" Cyan
        Write-Host " $($Options[$i])"
    }
    Write-Host ""
    while ($true) {
        Write-Host "  Choice: " -NoNewline -ForegroundColor White
        $choice = Read-Host
        if ($choice -eq "Q" -or $choice -eq "q") { Write-Host "Exiting."; exit 0 }
        $num = 0
        if ([int]::TryParse($choice, [ref]$num) -and $num -ge 1 -and $num -le $Options.Count) {
            return ($num - 1)
        }
        Write-ColorLine "  Invalid choice. Enter 1-$($Options.Count) or Q to quit." Red
    }
}

function Prompt-YN {
    param([string]$Prompt)
    Write-Host "  $Prompt [Y/n]: " -NoNewline -ForegroundColor White
    $response = Read-Host
    return ($response -ne "n" -and $response -ne "N")
}

function Pause-Guide {
    param([string]$Message)
    if ($script:OutputMode -eq "pause") {
        Write-Host ""
        Write-Host "  " -NoNewline; Write-Color "☐ MANUAL STEP:" Yellow; Write-Host " $Message"
        Write-Host "  Press Enter when done (or S to skip)... " -NoNewline -ForegroundColor DarkGray
        $response = Read-Host
        return ($response -ne "s" -and $response -ne "S")
    } else {
        $script:ManualSteps += $Message
        return $false
    }
}

# ═══════════════════════════════════════════════════════════════════
# PRIVILEGE CHECK
# ═══════════════════════════════════════════════════════════════════
function Check-Privileges {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-ColorLine "This script requires Administrator privileges." Yellow
        Write-ColorLine "Right-click PowerShell > Run as Administrator, then re-run this script." Yellow
        exit 1
    }
    Write-Host "  Detected: " -NoNewline
    Write-ColorLine "Windows $(([System.Environment]::OSVersion.Version))" White
}

# ═══════════════════════════════════════════════════════════════════
# PACKAGE HELPERS (winget / choco / scoop)
# ═══════════════════════════════════════════════════════════════════
function Get-PkgManager {
    if (Get-Command winget -ErrorAction SilentlyContinue) { return "winget" }
    if (Get-Command choco -ErrorAction SilentlyContinue) { return "choco" }
    if (Get-Command scoop -ErrorAction SilentlyContinue) { return "scoop" }
    return ""
}

function Install-Pkg {
    param([string]$WingetId, [string]$ChocoName, [string]$ScoopName)
    $mgr = Get-PkgManager
    switch ($mgr) {
        "winget" { winget install --id $WingetId --accept-source-agreements --accept-package-agreements --silent 2>$null }
        "choco"  { choco install $ChocoName -y 2>$null }
        "scoop"  { scoop install $ScoopName 2>$null }
        default  { return $false }
    }
    return $true
}

# ═══════════════════════════════════════════════════════════════════
# WIZARD: PROFILE SELECTION
# ═══════════════════════════════════════════════════════════════════
function Select-Profile {
    Print-Section "Profile Selection"
    $choice = Prompt-Choice "Select a hardening profile:" @(
        "Standard  — Encrypted disk, firewall, secure DNS, auto-updates, basic browser hardening"
        "High      — Standard + outbound firewall, hostname scrubbing, monitoring tools, SSH hardening, telemetry disabled"
        "Paranoid  — High + MAC rotation, traffic obfuscation, VPN kill switch, full audit system, metadata stripping, border crossing prep"
        "Advanced  — Custom questionnaire (choose per-category)"
    )
    switch ($choice) {
        0 { $script:Profile = "standard" }
        1 { $script:Profile = "high" }
        2 { $script:Profile = "paranoid" }
        3 { $script:Profile = "advanced"; Run-Questionnaire }
    }
    Write-Host ""
    Write-Host "  Profile: " -NoNewline; Write-ColorLine $script:Profile White
}

# ═══════════════════════════════════════════════════════════════════
# WIZARD: ADVANCED QUESTIONNAIRE
# ═══════════════════════════════════════════════════════════════════
function Run-Questionnaire {
    Print-Section "Advanced Questionnaire"
    Write-ColorLine "  Answer 8 questions to build a custom hardening profile." DarkGray
    Write-Host ""

    $c = Prompt-Choice "1. What is your primary threat model?" @(
        "Targeted adversary (nation-state, mercenary spyware)"
        "Mass surveillance (corporate tracking, ISP monitoring, data brokers)"
        "Physical theft/access (theft, border crossing, evil maid)"
        "All of the above"
    )
    $script:QThreat = @("targeted","mass","physical","all")[$c]
    Write-Host ""

    $c = Prompt-Choice "2. How do you primarily use this machine?" @(
        "Software development only"
        "Dev + light personal use"
        "Dev + media/creative work"
        "Dedicated security machine"
    )
    $script:QUsecase = @("dev","dev-personal","dev-media","dedicated")[$c]
    Write-Host ""

    $c = Prompt-Choice "3. Do you travel internationally with this machine?" @(
        "Frequently"
        "Occasionally"
        "Rarely or never"
    )
    $script:QTravel = @("frequent","occasional","rarely")[$c]
    Write-Host ""

    $c = Prompt-Choice "4. Vendor ecosystem preference?" @(
        "Minimize vendor dependence"
        "Strategic use (leverage vendor security features, lock them down)"
        "Full ecosystem (multiple devices, secured as a unit)"
    )
    $script:QEcosystem = @("minimize","strategic","full")[$c]
    Write-Host ""

    $c = Prompt-Choice "5. Network monitoring preference?" @(
        "I want to see everything (per-app alerts on every connection)"
        "Block and forget (strict rules, silent, no prompts)"
        "DNS-level filtering is enough"
    )
    $script:QNetwork = @("full-visibility","block-forget","dns-only")[$c]
    Write-Host ""

    $c = Prompt-Choice "6. Current authentication setup?" @(
        "Hardware security keys (YubiKey, FIDO2)"
        "Password manager + TOTP codes"
        "OS built-in (Windows Hello, etc.)"
        "Mixed or inconsistent"
    )
    $script:QAuth = @("hardware","manager-totp","builtin","mixed")[$c]
    Write-Host ""

    $c = Prompt-Choice "7. Traffic obfuscation preference?" @(
        "Route everything through Tor/VPN"
        "VPN always on, Tor for sensitive tasks"
        "Situational (speed matters)"
    )
    $script:QTraffic = @("full-tor","vpn-plus-tor","situational")[$c]
    Write-Host ""

    $c = Prompt-Choice "8. Maintenance overhead tolerance?" @(
        "Set and forget (automate everything)"
        "Weekly check-ins (periodic review, daily automation)"
        "Active management (regular log review, key rotation)"
    )
    $script:QMaintenance = @("set-forget","weekly","active")[$c]
    Write-Host ""
}

# ═══════════════════════════════════════════════════════════════════
# WIZARD: OUTPUT MODE
# ═══════════════════════════════════════════════════════════════════
function Select-OutputMode {
    Print-Section "Output Mode"
    $choice = Prompt-Choice "How should manual steps be handled?" @(
        "Print checklist at the end"
        "Pause and guide me through each step"
        "Generate a report file"
    )
    switch ($choice) {
        0 { $script:OutputMode = "checklist" }
        1 { $script:OutputMode = "pause" }
        2 { $script:OutputMode = "report" }
    }
    Write-Host ""
    Write-Host "  Output mode: " -NoNewline; Write-ColorLine $script:OutputMode White
}

# ═══════════════════════════════════════════════════════════════════
# PROFILE BUILDER
# ═══════════════════════════════════════════════════════════════════
function Build-ModuleList {
    $script:EnabledModules = @(
        "disk-encrypt"
        "firewall-inbound"
        "dns-secure"
        "auto-updates"
        "guest-disable"
        "lock-screen"
        "browser-basic"
    )

    if ($script:Profile -eq "high" -or $script:Profile -eq "paranoid") {
        $script:EnabledModules += @(
            "firewall-stealth"
            "firewall-outbound"
            "hostname-scrub"
            "ssh-harden"
            "git-harden"
            "telemetry-disable"
            "monitoring-tools"
            "permissions-audit"
        )
    }

    if ($script:Profile -eq "paranoid") {
        $script:EnabledModules += @(
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
    }

    if ($script:Profile -eq "advanced") {
        if ($script:QThreat -eq "all" -or $script:QThreat -eq "targeted" -or $script:QThreat -eq "mass") {
            $script:EnabledModules += @("firewall-stealth","firewall-outbound","hostname-scrub","telemetry-disable")
        }
        $script:EnabledModules += @("ssh-harden","git-harden","monitoring-tools","permissions-audit")

        if ($script:QThreat -eq "all" -or $script:QThreat -eq "targeted") {
            $script:EnabledModules += @("mac-rotate","vpn-killswitch","browser-fingerprint","bluetooth-disable")
        }
        if ($script:QTraffic -eq "full-tor" -or $script:QTraffic -eq "vpn-plus-tor") {
            $script:EnabledModules += @("vpn-killswitch","traffic-obfuscation")
        }
        if ($script:QUsecase -match "dev") {
            $script:EnabledModules += "dev-isolation"
        }
        if ($script:QMaintenance -eq "weekly" -or $script:QMaintenance -eq "active") {
            $script:EnabledModules += "audit-script"
        }
        if ($script:QTravel -eq "frequent" -or $script:QTravel -eq "occasional") {
            $script:EnabledModules += "border-prep"
        }
        if ($script:QThreat -eq "all" -or $script:QThreat -eq "mass") {
            $script:EnabledModules += "metadata-strip"
        }
        $script:EnabledModules += "backup-guidance"

        # Deduplicate
        $script:EnabledModules = $script:EnabledModules | Select-Object -Unique
    }

    $script:TotalModules = $script:EnabledModules.Count
}

# ═══════════════════════════════════════════════════════════════════
# MODULE RUNNER
# ═══════════════════════════════════════════════════════════════════
function Run-Module {
    param([string]$ModId)
    $script:CurrentModule++
    $funcName = "Mod-$($ModId)"

    if (Get-Command $funcName -ErrorAction SilentlyContinue) {
        & $funcName
    } else {
        $script:ModuleResult = "skipped_unsupported"
    }

    switch ($script:ModuleResult) {
        "applied"  { $script:CountApplied++ }
        "skipped"  { $script:CountSkipped++ }
        "failed"   { $script:CountFailed++ }
        "manual"   { $script:CountManual++ }
        "skipped_unsupported" { $script:CountSkipped++ }
    }
}

function Run-AllModules {
    Print-Section "Applying Hardening ($($script:TotalModules) modules)"
    foreach ($mod in $script:EnabledModules) {
        Run-Module $mod
    }
}

# ═══════════════════════════════════════════════════════════════════
# MODULE: disk-encrypt (BitLocker)
# ═══════════════════════════════════════════════════════════════════
function Mod-disk-encrypt {
    $desc = "Verify disk encryption (BitLocker)"
    try {
        $bl = Get-BitLockerVolume -MountPoint "C:" -ErrorAction Stop
        if ($bl.ProtectionStatus -eq "On") {
            Print-Status $script:CurrentModule $script:TotalModules $desc "skipped"
            Log-Entry "disk-encrypt" "check" "skip" "BitLocker already enabled on C:"
            $script:ModuleResult = "skipped"
            return
        }
        # Attempt to enable BitLocker
        Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256 -RecoveryPasswordProtector -ErrorAction Stop | Out-Null
        Print-Status $script:CurrentModule $script:TotalModules $desc "applied"
        Log-Entry "disk-encrypt" "apply" "ok" "BitLocker enabled on C: with XTS-AES-256"
        $script:ModuleResult = "applied"
    } catch {
        Print-Status $script:CurrentModule $script:TotalModules $desc "manual"
        Log-Entry "disk-encrypt" "check" "manual" "BitLocker requires TPM or Group Policy config: $_"
        Pause-Guide "Enable BitLocker: Settings > Privacy & Security > Device encryption, or use manage-bde from an elevated prompt. Save recovery key to a secure location." | Out-Null
        $script:ModuleResult = "manual"
    }
}

# ═══════════════════════════════════════════════════════════════════
# MODULE: firewall-inbound (Windows Defender Firewall)
# ═══════════════════════════════════════════════════════════════════
function Mod-firewall-inbound {
    $desc = "Enable Windows Defender Firewall (all profiles)"
    $profiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
    $allEnabled = ($profiles | Where-Object { $_.Enabled -eq $false }).Count -eq 0

    if ($allEnabled -and $profiles.Count -gt 0) {
        $blockInbound = ($profiles | Where-Object { $_.DefaultInboundAction -eq "Block" }).Count -eq $profiles.Count
        if ($blockInbound) {
            Print-Status $script:CurrentModule $script:TotalModules $desc "skipped"
            Log-Entry "firewall-inbound" "check" "skip" "Firewall enabled, inbound blocked on all profiles"
            $script:ModuleResult = "skipped"
            return
        }
    }

    try {
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -DefaultInboundAction Block -ErrorAction Stop
        Print-Status $script:CurrentModule $script:TotalModules $desc "applied"
        Log-Entry "firewall-inbound" "apply" "ok" "Firewall enabled, default inbound block on all profiles"
        $script:ModuleResult = "applied"
    } catch {
        Print-Status $script:CurrentModule $script:TotalModules $desc "failed"
        Log-Entry "firewall-inbound" "apply" "fail" "Could not configure firewall: $_"
        $script:ModuleResult = "failed"
    }
}

# ═══════════════════════════════════════════════════════════════════
# MODULE: dns-secure (Quad9)
# ═══════════════════════════════════════════════════════════════════
function Mod-dns-secure {
    $desc = "Configure encrypted DNS (Quad9)"
    $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }

    $alreadySet = $true
    foreach ($adapter in $adapters) {
        $dns = Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
        if ($dns.ServerAddresses -notcontains "9.9.9.9") {
            $alreadySet = $false
            break
        }
    }

    if ($alreadySet -and $adapters.Count -gt 0) {
        Print-Status $script:CurrentModule $script:TotalModules $desc "skipped"
        Log-Entry "dns-secure" "check" "skip" "Quad9 DNS already set on all active adapters"
        $script:ModuleResult = "skipped"
        return
    }

    try {
        foreach ($adapter in $adapters) {
            Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses @("9.9.9.9","149.112.112.112") -ErrorAction Stop
        }
        # Enable DNS-over-HTTPS if available (Windows 11+)
        try {
            $dohServers = Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue
            if (-not ($dohServers | Where-Object { $_.ServerAddress -eq "9.9.9.9" })) {
                Add-DnsClientDohServerAddress -ServerAddress "9.9.9.9" -DohTemplate "https://dns.quad9.net/dns-query" -AllowFallbackToUdp $false -AutoUpgrade $true -ErrorAction SilentlyContinue
                Add-DnsClientDohServerAddress -ServerAddress "149.112.112.112" -DohTemplate "https://dns.quad9.net/dns-query" -AllowFallbackToUdp $false -AutoUpgrade $true -ErrorAction SilentlyContinue
            }
        } catch { }
        Print-Status $script:CurrentModule $script:TotalModules $desc "applied"
        Log-Entry "dns-secure" "apply" "ok" "Set Quad9 DNS on all active adapters"
        $script:ModuleResult = "applied"
    } catch {
        Print-Status $script:CurrentModule $script:TotalModules $desc "failed"
        Log-Entry "dns-secure" "apply" "fail" "Could not set DNS: $_"
        $script:ModuleResult = "failed"
    }
}

# ═══════════════════════════════════════════════════════════════════
# MODULE: auto-updates (Windows Update)
# ═══════════════════════════════════════════════════════════════════
function Mod-auto-updates {
    $desc = "Enable automatic Windows updates"
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
    try {
        $current = Get-ItemProperty -Path $regPath -Name "NoAutoUpdate" -ErrorAction SilentlyContinue
        if ($null -eq $current -or $current.NoAutoUpdate -eq 0) {
            Print-Status $script:CurrentModule $script:TotalModules $desc "skipped"
            Log-Entry "auto-updates" "check" "skip" "Auto-updates not disabled by policy"
            $script:ModuleResult = "skipped"
            return
        }
        Set-ItemProperty -Path $regPath -Name "NoAutoUpdate" -Value 0 -ErrorAction Stop
        Print-Status $script:CurrentModule $script:TotalModules $desc "applied"
        Log-Entry "auto-updates" "apply" "ok" "Enabled automatic updates"
        $script:ModuleResult = "applied"
    } catch {
        # Registry path may not exist — updates are on by default
        Print-Status $script:CurrentModule $script:TotalModules $desc "skipped"
        Log-Entry "auto-updates" "check" "skip" "Auto-updates enabled (default)"
        $script:ModuleResult = "skipped"
    }
}

# ═══════════════════════════════════════════════════════════════════
# MODULE: guest-disable
# ═══════════════════════════════════════════════════════════════════
function Mod-guest-disable {
    $desc = "Disable Guest account"
    try {
        $guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
        if ($null -eq $guest -or $guest.Enabled -eq $false) {
            Print-Status $script:CurrentModule $script:TotalModules $desc "skipped"
            Log-Entry "guest-disable" "check" "skip" "Guest account already disabled"
            $script:ModuleResult = "skipped"
            return
        }
        Disable-LocalUser -Name "Guest" -ErrorAction Stop
        Print-Status $script:CurrentModule $script:TotalModules $desc "applied"
        Log-Entry "guest-disable" "apply" "ok" "Guest account disabled"
        $script:ModuleResult = "applied"
    } catch {
        Print-Status $script:CurrentModule $script:TotalModules $desc "failed"
        Log-Entry "guest-disable" "apply" "fail" "Could not disable Guest: $_"
        $script:ModuleResult = "failed"
    }
}

# ═══════════════════════════════════════════════════════════════════
# MODULE: lock-screen
# ═══════════════════════════════════════════════════════════════════
function Mod-lock-screen {
    $desc = "Configure lock screen (timeout, password)"
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    try {
        # Screen saver timeout (5 minutes) + password on resume
        $ssRegPath = "HKCU:\Control Panel\Desktop"
        $currentTimeout = (Get-ItemProperty -Path $ssRegPath -Name "ScreenSaveTimeOut" -ErrorAction SilentlyContinue).ScreenSaveTimeOut
        $currentLock = (Get-ItemProperty -Path $ssRegPath -Name "ScreenSaverIsSecure" -ErrorAction SilentlyContinue).ScreenSaverIsSecure

        if ($currentLock -eq "1" -and $null -ne $currentTimeout -and [int]$currentTimeout -le 300) {
            Print-Status $script:CurrentModule $script:TotalModules $desc "skipped"
            Log-Entry "lock-screen" "check" "skip" "Lock screen already configured"
            $script:ModuleResult = "skipped"
            return
        }

        Set-ItemProperty -Path $ssRegPath -Name "ScreenSaveTimeOut" -Value "300" -ErrorAction Stop
        Set-ItemProperty -Path $ssRegPath -Name "ScreenSaverIsSecure" -Value "1" -ErrorAction Stop
        Set-ItemProperty -Path $ssRegPath -Name "ScreenSaveActive" -Value "1" -ErrorAction Stop

        # Also set machine inactivity limit via security policy
        $inactivityPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        if (-not (Test-Path $inactivityPath)) { New-Item -Path $inactivityPath -Force | Out-Null }
        Set-ItemProperty -Path $inactivityPath -Name "InactivityTimeoutSecs" -Value 300 -ErrorAction SilentlyContinue

        Print-Status $script:CurrentModule $script:TotalModules $desc "applied"
        Log-Entry "lock-screen" "apply" "ok" "Screen timeout 5min, password required"
        $script:ModuleResult = "applied"
    } catch {
        Print-Status $script:CurrentModule $script:TotalModules $desc "failed"
        Log-Entry "lock-screen" "apply" "fail" "Could not configure lock screen: $_"
        $script:ModuleResult = "failed"
    }
}

# ═══════════════════════════════════════════════════════════════════
# MODULE: browser-basic (Firefox user.js + Edge/Chrome registry)
# ═══════════════════════════════════════════════════════════════════
function Mod-browser-basic {
    $desc = "Basic browser hardening"
    $applied = $false

    # Firefox user.js
    $ffProfileRoot = Join-Path $script:RealHome "AppData\Roaming\Mozilla\Firefox\Profiles"
    $ffProfile = Get-ChildItem -Path $ffProfileRoot -Filter "*.default-release" -Directory -ErrorAction SilentlyContinue | Select-Object -First 1

    if ($ffProfile) {
        $userJs = Join-Path $ffProfile.FullName "user.js"
        if (Test-Path $userJs) {
            $content = Get-Content $userJs -Raw
            if ($content -match "toolkit.telemetry.enabled") {
                # Already hardened
            } else {
                $applied = $true
            }
        } else {
            $applied = $true
        }

        if ($applied -or -not (Test-Path $userJs)) {
            $ffConfig = @"
// Firefox Hardening — Basic Profile
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
user_pref("privacy.trackingprotection.enabled", true);
user_pref("privacy.trackingprotection.socialtracking.enabled", true);
user_pref("dom.security.https_only_mode", true);
user_pref("dom.security.https_only_mode_ever_enabled", true);
user_pref("browser.safebrowsing.malware.enabled", true);
user_pref("browser.safebrowsing.phishing.enabled", true);
user_pref("media.peerconnection.enabled", false);
user_pref("geo.enabled", false);
user_pref("extensions.pocket.enabled", false);
user_pref("browser.newtabpage.activity-stream.showSponsored", false);
user_pref("browser.newtabpage.activity-stream.showSponsoredTopSites", false);
"@
            Set-Content -Path $userJs -Value $ffConfig -Encoding UTF8
            $applied = $true
        }
    }

    # Edge hardening via registry
    $edgePath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    if (-not (Test-Path $edgePath)) { New-Item -Path $edgePath -Force | Out-Null }
    Set-ItemProperty -Path $edgePath -Name "TrackingPrevention" -Value 3 -ErrorAction SilentlyContinue  # Strict
    Set-ItemProperty -Path $edgePath -Name "AutomaticHttpsDefault" -Value 2 -ErrorAction SilentlyContinue  # Always upgrade
    Set-ItemProperty -Path $edgePath -Name "SmartScreenEnabled" -Value 1 -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $edgePath -Name "PasswordManagerEnabled" -Value 0 -ErrorAction SilentlyContinue
    $applied = $true

    # Chrome hardening via registry
    $chromePath = "HKLM:\SOFTWARE\Policies\Google\Chrome"
    if (-not (Test-Path $chromePath)) { New-Item -Path $chromePath -Force | Out-Null }
    Set-ItemProperty -Path $chromePath -Name "AutomaticHttpsDefault" -Value 2 -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $chromePath -Name "SafeBrowsingProtectionLevel" -Value 1 -ErrorAction SilentlyContinue

    if ($applied) {
        Print-Status $script:CurrentModule $script:TotalModules $desc "applied"
        Log-Entry "browser-basic" "apply" "ok" "Hardened Firefox user.js + Edge/Chrome registry policies"
        $script:ModuleResult = "applied"
    } else {
        Print-Status $script:CurrentModule $script:TotalModules $desc "skipped"
        Log-Entry "browser-basic" "check" "skip" "Browsers already hardened"
        $script:ModuleResult = "skipped"
    }
}

# ═══════════════════════════════════════════════════════════════════
# MODULE: firewall-stealth (drop ICMP)
# ═══════════════════════════════════════════════════════════════════
function Mod-firewall-stealth {
    $desc = "Enable firewall stealth mode (drop ICMP)"
    $existing = Get-NetFirewallRule -DisplayName "Harden-Block-ICMPv4-In" -ErrorAction SilentlyContinue
    if ($existing) {
        Print-Status $script:CurrentModule $script:TotalModules $desc "skipped"
        Log-Entry "firewall-stealth" "check" "skip" "ICMP block rule already exists"
        $script:ModuleResult = "skipped"
        return
    }
    try {
        New-NetFirewallRule -DisplayName "Harden-Block-ICMPv4-In" -Direction Inbound -Protocol ICMPv4 -Action Block -Profile Any -ErrorAction Stop | Out-Null
        New-NetFirewallRule -DisplayName "Harden-Block-ICMPv6-In" -Direction Inbound -Protocol ICMPv6 -Action Block -Profile Any -ErrorAction Stop | Out-Null
        # Disable multicast name resolution (LLMNR)
        $llmnrPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
        if (-not (Test-Path $llmnrPath)) { New-Item -Path $llmnrPath -Force | Out-Null }
        Set-ItemProperty -Path $llmnrPath -Name "EnableMulticast" -Value 0 -ErrorAction SilentlyContinue

        Print-Status $script:CurrentModule $script:TotalModules $desc "applied"
        Log-Entry "firewall-stealth" "apply" "ok" "Blocked inbound ICMP + disabled LLMNR"
        $script:ModuleResult = "applied"
    } catch {
        Print-Status $script:CurrentModule $script:TotalModules $desc "failed"
        Log-Entry "firewall-stealth" "apply" "fail" "Could not create ICMP block rules: $_"
        $script:ModuleResult = "failed"
    }
}

# ═══════════════════════════════════════════════════════════════════
# MODULE: firewall-outbound (default deny outbound)
# ═══════════════════════════════════════════════════════════════════
function Mod-firewall-outbound {
    $desc = "Configure outbound firewall (default deny)"
    $profiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
    $allDenyOut = ($profiles | Where-Object { $_.DefaultOutboundAction -eq "Block" }).Count -eq $profiles.Count

    if ($allDenyOut) {
        Print-Status $script:CurrentModule $script:TotalModules $desc "skipped"
        Log-Entry "firewall-outbound" "check" "skip" "Outbound already default-deny"
        $script:ModuleResult = "skipped"
        return
    }

    try {
        Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Block -ErrorAction Stop
        # Allow essential outbound
        $essentialPorts = @(53, 80, 443, 853, 22)
        foreach ($port in $essentialPorts) {
            $ruleName = "Harden-Allow-Out-TCP-$port"
            if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
                New-NetFirewallRule -DisplayName $ruleName -Direction Outbound -Protocol TCP -RemotePort $port -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null
            }
        }
        # Allow DNS UDP
        if (-not (Get-NetFirewallRule -DisplayName "Harden-Allow-Out-UDP-53" -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -DisplayName "Harden-Allow-Out-UDP-53" -Direction Outbound -Protocol UDP -RemotePort 53 -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null
        }
        Print-Status $script:CurrentModule $script:TotalModules $desc "applied"
        Log-Entry "firewall-outbound" "apply" "ok" "Default outbound deny + essential ports allowed"
        $script:ModuleResult = "applied"
    } catch {
        Print-Status $script:CurrentModule $script:TotalModules $desc "failed"
        Log-Entry "firewall-outbound" "apply" "fail" "Could not set outbound policy: $_"
        $script:ModuleResult = "failed"
    }
}

# ═══════════════════════════════════════════════════════════════════
# MODULE: hostname-scrub
# ═══════════════════════════════════════════════════════════════════
function Mod-hostname-scrub {
    $desc = "Set generic hostname"
    $generic = "DESKTOP-PC"
    $current = $env:COMPUTERNAME
    if ($current -eq $generic) {
        Print-Status $script:CurrentModule $script:TotalModules $desc "skipped"
        Log-Entry "hostname-scrub" "check" "skip" "Hostname already generic"
        $script:ModuleResult = "skipped"
        return
    }
    try {
        Rename-Computer -NewName $generic -Force -ErrorAction Stop
        Print-Status $script:CurrentModule $script:TotalModules "$desc ($generic — reboot required)" "applied"
        Log-Entry "hostname-scrub" "apply" "ok" "Hostname set to $generic (reboot required)"
        $script:ModuleResult = "applied"
    } catch {
        Print-Status $script:CurrentModule $script:TotalModules $desc "failed"
        Log-Entry "hostname-scrub" "apply" "fail" "Could not rename computer: $_"
        $script:ModuleResult = "failed"
    }
}

# ═══════════════════════════════════════════════════════════════════
# MODULE: ssh-harden
# ═══════════════════════════════════════════════════════════════════
function Mod-ssh-harden {
    $desc = "Harden SSH configuration"
    $sshDir = Join-Path $script:RealHome ".ssh"
    $sshConfig = Join-Path $sshDir "config"

    if ((Test-Path $sshConfig) -and (Select-String -Path $sshConfig -Pattern "IdentitiesOnly yes" -Quiet)) {
        Print-Status $script:CurrentModule $script:TotalModules $desc "skipped"
        Log-Entry "ssh-harden" "check" "skip" "SSH config already hardened"
        $script:ModuleResult = "skipped"
        return
    }

    if (-not (Test-Path $sshDir)) { New-Item -ItemType Directory -Path $sshDir -Force | Out-Null }

    # Generate Ed25519 key if missing
    $keyPath = Join-Path $sshDir "id_ed25519"
    if (-not (Test-Path $keyPath)) {
        if (Get-Command ssh-keygen -ErrorAction SilentlyContinue) {
            & ssh-keygen -t ed25519 -f $keyPath -N '""' -q 2>$null
        }
    }

    $config = @"
Host *
    IdentitiesOnly yes
    HashKnownHosts yes
    PasswordAuthentication no
    StrictHostKeyChecking ask
    IdentityFile ~/.ssh/id_ed25519
    ServerAliveInterval 60
    ServerAliveCountMax 3
"@
    Set-Content -Path $sshConfig -Value $config -Encoding UTF8
    Print-Status $script:CurrentModule $script:TotalModules $desc "applied"
    Log-Entry "ssh-harden" "apply" "ok" "SSH config hardened with Ed25519"
    $script:ModuleResult = "applied"
}

# ═══════════════════════════════════════════════════════════════════
# MODULE: git-harden
# ═══════════════════════════════════════════════════════════════════
function Mod-git-harden {
    $desc = "Harden Git configuration"
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
        Print-Status $script:CurrentModule $script:TotalModules $desc "skipped_unsupported"
        Log-Entry "git-harden" "check" "skip" "Git not installed"
        $script:ModuleResult = "skipped_unsupported"
        return
    }

    $signing = & git config --global --get commit.gpgsign 2>$null
    if ($signing -eq "true") {
        Print-Status $script:CurrentModule $script:TotalModules $desc "skipped"
        Log-Entry "git-harden" "check" "skip" "Git signing already configured"
        $script:ModuleResult = "skipped"
        return
    }

    & git config --global gpg.format ssh
    $pubKey = Join-Path $script:RealHome ".ssh\id_ed25519.pub"
    if (Test-Path $pubKey) {
        & git config --global user.signingkey $pubKey
    }
    & git config --global commit.gpgsign true
    & git config --global tag.gpgsign true
    & git config --global credential.helper manager

    Print-Status $script:CurrentModule $script:TotalModules $desc "applied"
    Log-Entry "git-harden" "apply" "ok" "Git SSH signing + credential manager configured"
    $script:ModuleResult = "applied"
}

# ═══════════════════════════════════════════════════════════════════
# MODULE: telemetry-disable
# ═══════════════════════════════════════════════════════════════════
function Mod-telemetry-disable {
    $desc = "Disable Windows telemetry"
    try {
        # Telemetry level: 0 = Security (Enterprise only), 1 = Basic
        $telPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
        if (-not (Test-Path $telPath)) { New-Item -Path $telPath -Force | Out-Null }
        Set-ItemProperty -Path $telPath -Name "AllowTelemetry" -Value 0 -ErrorAction SilentlyContinue

        # Disable Connected User Experience
        Stop-Service -Name "DiagTrack" -Force -ErrorAction SilentlyContinue
        Set-Service -Name "DiagTrack" -StartupType Disabled -ErrorAction SilentlyContinue

        # Disable WAP Push
        Stop-Service -Name "dmwappushservice" -Force -ErrorAction SilentlyContinue
        Set-Service -Name "dmwappushservice" -StartupType Disabled -ErrorAction SilentlyContinue

        # Disable Advertising ID
        $adIdPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo"
        if (-not (Test-Path $adIdPath)) { New-Item -Path $adIdPath -Force | Out-Null }
        Set-ItemProperty -Path $adIdPath -Name "DisabledByGroupPolicy" -Value 1

        # Disable activity history
        $actPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
        if (-not (Test-Path $actPath)) { New-Item -Path $actPath -Force | Out-Null }
        Set-ItemProperty -Path $actPath -Name "EnableActivityFeed" -Value 0 -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $actPath -Name "PublishUserActivities" -Value 0 -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $actPath -Name "UploadUserActivities" -Value 0 -ErrorAction SilentlyContinue

        # Disable Cortana
        $cortanaPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
        if (-not (Test-Path $cortanaPath)) { New-Item -Path $cortanaPath -Force | Out-Null }
        Set-ItemProperty -Path $cortanaPath -Name "AllowCortana" -Value 0 -ErrorAction SilentlyContinue

        Print-Status $script:CurrentModule $script:TotalModules $desc "applied"
        Log-Entry "telemetry-disable" "apply" "ok" "Disabled telemetry, DiagTrack, advertising ID, activity history, Cortana"
        $script:ModuleResult = "applied"
    } catch {
        Print-Status $script:CurrentModule $script:TotalModules $desc "failed"
        Log-Entry "telemetry-disable" "apply" "fail" "Could not disable telemetry: $_"
        $script:ModuleResult = "failed"
    }
}

# ═══════════════════════════════════════════════════════════════════
# MODULE: monitoring-tools (Sysmon + audit policy)
# ═══════════════════════════════════════════════════════════════════
function Mod-monitoring-tools {
    $desc = "Install security monitoring tools (Sysmon + audit policy)"

    # Check if Sysmon is running
    $sysmon = Get-Service -Name "Sysmon*" -ErrorAction SilentlyContinue
    $auditConfigured = $false
    try {
        $audit = & auditpol /get /category:* 2>$null
        if ($audit -match "Success and Failure") { $auditConfigured = $true }
    } catch { }

    if ($sysmon -and $sysmon.Status -eq "Running" -and $auditConfigured) {
        Print-Status $script:CurrentModule $script:TotalModules $desc "skipped"
        Log-Entry "monitoring-tools" "check" "skip" "Sysmon running + audit policies configured"
        $script:ModuleResult = "skipped"
        return
    }

    # Configure audit policies
    try {
        & auditpol /set /subcategory:"Logon" /success:enable /failure:enable 2>$null
        & auditpol /set /subcategory:"Logoff" /success:enable 2>$null
        & auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable 2>$null
        & auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable 2>$null
        & auditpol /set /subcategory:"Process Creation" /success:enable 2>$null
        & auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable 2>$null

        # Enable command-line auditing in process creation events
        $auditPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
        if (-not (Test-Path $auditPath)) { New-Item -Path $auditPath -Force | Out-Null }
        Set-ItemProperty -Path $auditPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -ErrorAction SilentlyContinue
    } catch { }

    if (-not $sysmon -or $sysmon.Status -ne "Running") {
        Print-Status $script:CurrentModule $script:TotalModules $desc "manual"
        Log-Entry "monitoring-tools" "apply" "manual" "Audit policies set. Sysmon requires manual install."
        Pause-Guide "Install Sysmon from Microsoft Sysinternals: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon — Download, extract, run: sysmon -accepteula -i sysmonconfig.xml (use SwiftOnSecurity config from GitHub)." | Out-Null
        $script:ModuleResult = "manual"
    } else {
        Print-Status $script:CurrentModule $script:TotalModules $desc "applied"
        Log-Entry "monitoring-tools" "apply" "ok" "Audit policies configured"
        $script:ModuleResult = "applied"
    }
}

# ═══════════════════════════════════════════════════════════════════
# MODULE: permissions-audit
# ═══════════════════════════════════════════════════════════════════
function Mod-permissions-audit {
    $desc = "Audit security permissions and services"
    try {
        # List services running as SYSTEM with non-default paths
        $services = Get-WmiObject Win32_Service | Where-Object {
            $_.StartMode -eq "Auto" -and $_.State -eq "Running"
        } | Select-Object Name, PathName, StartName | Sort-Object Name

        # Check for unquoted service paths (vulnerability)
        $unquoted = $services | Where-Object {
            $_.PathName -and $_.PathName -notmatch '^"' -and $_.PathName -match '\s'
        }

        if ($unquoted.Count -gt 0) {
            Log-Entry "permissions-audit" "check" "warn" "Found $($unquoted.Count) services with unquoted paths"
        }

        Print-Status $script:CurrentModule $script:TotalModules "$desc ($($services.Count) auto-start services)" "applied"
        Log-Entry "permissions-audit" "check" "ok" "Audited $($services.Count) services, $($unquoted.Count) unquoted paths"
        $script:ModuleResult = "applied"
    } catch {
        Print-Status $script:CurrentModule $script:TotalModules $desc "failed"
        Log-Entry "permissions-audit" "check" "fail" "Could not audit services: $_"
        $script:ModuleResult = "failed"
    }
}

# ═══════════════════════════════════════════════════════════════════
# MODULE: mac-rotate (Wi-Fi MAC randomization)
# ═══════════════════════════════════════════════════════════════════
function Mod-mac-rotate {
    $desc = "Enable Wi-Fi MAC address randomization"
    # Windows 10/11 supports random hardware addresses
    $regPath = "HKLM:\SOFTWARE\Microsoft\WlanSvc\Interfaces"
    Print-Status $script:CurrentModule $script:TotalModules $desc "manual"
    Log-Entry "mac-rotate" "check" "manual" "Requires per-network GUI setting"
    Pause-Guide "Settings > Network & Internet > Wi-Fi > Random hardware addresses: set to 'On' or 'Change daily' for each saved network." | Out-Null
    $script:ModuleResult = "manual"
}

# ═══════════════════════════════════════════════════════════════════
# MODULE: vpn-killswitch
# ═══════════════════════════════════════════════════════════════════
function Mod-vpn-killswitch {
    $desc = "Configure VPN kill switch"
    $mullvad = Get-Command mullvad -ErrorAction SilentlyContinue
    if ($mullvad) {
        try {
            $status = & mullvad always-require-vpn get 2>$null
            if ($status -match "enabled|on") {
                Print-Status $script:CurrentModule $script:TotalModules "$desc (Mullvad)" "skipped"
                Log-Entry "vpn-killswitch" "check" "skip" "Mullvad kill switch already on"
                $script:ModuleResult = "skipped"
                return
            }
            & mullvad always-require-vpn set on 2>$null
            & mullvad dns set default --block-ads --block-trackers --block-malware 2>$null
            Print-Status $script:CurrentModule $script:TotalModules "$desc (Mullvad)" "applied"
            Log-Entry "vpn-killswitch" "apply" "ok" "Mullvad always-require-vpn + DNS blocking"
            $script:ModuleResult = "applied"
        } catch {
            Print-Status $script:CurrentModule $script:TotalModules $desc "failed"
            Log-Entry "vpn-killswitch" "apply" "fail" "Mullvad CLI error: $_"
            $script:ModuleResult = "failed"
        }
    } else {
        Print-Status $script:CurrentModule $script:TotalModules $desc "manual"
        Log-Entry "vpn-killswitch" "check" "manual" "Mullvad CLI not found"
        Pause-Guide "Install Mullvad VPN and enable: Always require VPN (kill switch), Block ads/trackers/malware DNS, DAITA traffic analysis protection." | Out-Null
        $script:ModuleResult = "manual"
    }
}

# ═══════════════════════════════════════════════════════════════════
# MODULE: traffic-obfuscation
# ═══════════════════════════════════════════════════════════════════
function Mod-traffic-obfuscation {
    $desc = "Traffic obfuscation guidance"
    Print-Status $script:CurrentModule $script:TotalModules $desc "manual"
    Log-Entry "traffic-obfuscation" "check" "manual" "Guidance-only module"
    Pause-Guide "For traffic analysis resistance: (1) Enable Mullvad DAITA in VPN settings. (2) Use Mullvad Browser or Tor Browser for sensitive browsing. (3) Consider Tor for metadata-sensitive tasks." | Out-Null
    $script:ModuleResult = "manual"
}

# ═══════════════════════════════════════════════════════════════════
# MODULE: browser-fingerprint
# ═══════════════════════════════════════════════════════════════════
function Mod-browser-fingerprint {
    $desc = "Advanced browser fingerprint resistance"
    $ffProfileRoot = Join-Path $script:RealHome "AppData\Roaming\Mozilla\Firefox\Profiles"
    $ffProfile = Get-ChildItem -Path $ffProfileRoot -Filter "*.default-release" -Directory -ErrorAction SilentlyContinue | Select-Object -First 1

    if (-not $ffProfile) {
        Print-Status $script:CurrentModule $script:TotalModules $desc "manual"
        Log-Entry "browser-fingerprint" "check" "manual" "Firefox profile not found"
        $script:ModuleResult = "manual"
        return
    }

    $userJs = Join-Path $ffProfile.FullName "user.js"
    if ((Test-Path $userJs) -and (Select-String -Path $userJs -Pattern "privacy.resistFingerprinting" -Quiet)) {
        Print-Status $script:CurrentModule $script:TotalModules $desc "skipped"
        Log-Entry "browser-fingerprint" "check" "skip" "Fingerprint resistance already configured"
        $script:ModuleResult = "skipped"
        return
    }

    $fpConfig = @"

// Advanced Fingerprint Resistance
user_pref("privacy.firstparty.isolate", true);
user_pref("privacy.resistFingerprinting", true);
user_pref("privacy.clearOnShutdown.cookies", true);
user_pref("privacy.clearOnShutdown.history", true);
user_pref("privacy.clearOnShutdown.offlineApps", true);
user_pref("privacy.clearOnShutdown.sessions", true);
user_pref("privacy.clearOnShutdown.cache", true);
user_pref("privacy.sanitize.sanitizeOnShutdown", true);
user_pref("network.trr.mode", 2);
user_pref("network.trr.uri", "https://dns.quad9.net/dns-query");
user_pref("security.ssl.require_safe_negotiation", true);
user_pref("security.tls.version.min", 3);
user_pref("security.mixed_content.block_active_content", true);
user_pref("security.mixed_content.block_display_content", true);
user_pref("network.prefetch-next", false);
user_pref("network.dns.disablePrefetch", true);
user_pref("network.http.speculative-parallel-limit", 0);
user_pref("browser.urlbar.speculativeConnect.enabled", false);
"@
    Add-Content -Path $userJs -Value $fpConfig -Encoding UTF8
    Print-Status $script:CurrentModule $script:TotalModules $desc "applied"
    Log-Entry "browser-fingerprint" "apply" "ok" "Added fingerprint resistance + clear-on-shutdown"
    $script:ModuleResult = "applied"
}

# ═══════════════════════════════════════════════════════════════════
# MODULE: metadata-strip
# ═══════════════════════════════════════════════════════════════════
function Mod-metadata-strip {
    $desc = "Install metadata stripping tools (exiftool)"
    if (Get-Command exiftool -ErrorAction SilentlyContinue) {
        Print-Status $script:CurrentModule $script:TotalModules $desc "skipped"
        Log-Entry "metadata-strip" "check" "skip" "exiftool already installed"
        $script:ModuleResult = "skipped"
        return
    }

    $installed = Install-Pkg "OliverBetz.ExifTool" "exiftool" "exiftool"
    if ($installed -and (Get-Command exiftool -ErrorAction SilentlyContinue)) {
        Print-Status $script:CurrentModule $script:TotalModules $desc "applied"
        Log-Entry "metadata-strip" "apply" "ok" "Installed exiftool"
        $script:ModuleResult = "applied"
    } else {
        Print-Status $script:CurrentModule $script:TotalModules $desc "manual"
        Log-Entry "metadata-strip" "apply" "manual" "Could not auto-install exiftool"
        Pause-Guide "Install exiftool manually: https://exiftool.org — or via winget: winget install OliverBetz.ExifTool" | Out-Null
        $script:ModuleResult = "manual"
    }
}

# ═══════════════════════════════════════════════════════════════════
# MODULE: dev-isolation
# ═══════════════════════════════════════════════════════════════════
function Mod-dev-isolation {
    $desc = "Development environment isolation"
    $docker = Get-Command docker -ErrorAction SilentlyContinue
    $wsl = Get-Command wsl -ErrorAction SilentlyContinue

    if ($docker -and $wsl) {
        Print-Status $script:CurrentModule $script:TotalModules $desc "skipped"
        Log-Entry "dev-isolation" "check" "skip" "Docker + WSL already available"
        $script:ModuleResult = "skipped"
        return
    }

    Print-Status $script:CurrentModule $script:TotalModules $desc "manual"
    Log-Entry "dev-isolation" "check" "manual" "Docker/WSL setup needed"
    $msg = "Install for dev isolation: "
    if (-not $wsl) { $msg += "(1) WSL2: wsl --install from elevated PowerShell. " }
    if (-not $docker) { $msg += "(2) Docker Desktop: https://www.docker.com/products/docker-desktop/ " }
    $msg += "Avoid --privileged and --net=host flags. Bind-mount only specific project directories."
    Pause-Guide $msg | Out-Null
    $script:ModuleResult = "manual"
}

# ═══════════════════════════════════════════════════════════════════
# MODULE: audit-script (Task Scheduler weekly audit)
# ═══════════════════════════════════════════════════════════════════
function Mod-audit-script {
    $desc = "Set up weekly security audit"

    # Check if scheduled task exists
    $task = Get-ScheduledTask -TaskName "SecurityWeeklyAudit" -ErrorAction SilentlyContinue
    if ($task) {
        Print-Status $script:CurrentModule $script:TotalModules $desc "skipped"
        Log-Entry "audit-script" "check" "skip" "Weekly audit task already exists"
        $script:ModuleResult = "skipped"
        return
    }

    # Create audit script
    $auditScript = Join-Path $script:ScriptDir "weekly-audit.ps1"
    $auditContent = @'
# Weekly Security Audit — Windows
$AuditDir = Join-Path (Split-Path (Split-Path $MyInvocation.MyCommand.Path)) "audits"
$Date = Get-Date -Format "yyyy-MM-dd"
$Report = Join-Path $AuditDir "audit-$Date.md"
New-Item -ItemType Directory -Path $AuditDir -Force | Out-Null

$output = @()
$output += "# Security Audit — $Date"
$output += ""
$output += "## System Protection"
$output += '```'
$output += "BitLocker: $((Get-BitLockerVolume -MountPoint 'C:' -ErrorAction SilentlyContinue).ProtectionStatus)"
$output += "Firewall Domain: $((Get-NetFirewallProfile -Name Domain).Enabled)"
$output += "Firewall Private: $((Get-NetFirewallProfile -Name Private).Enabled)"
$output += "Firewall Public: $((Get-NetFirewallProfile -Name Public).Enabled)"
$output += "Defender Status: $((Get-MpComputerStatus -ErrorAction SilentlyContinue).AntivirusEnabled)"
$output += "Defender Signatures: $((Get-MpComputerStatus -ErrorAction SilentlyContinue).AntivirusSignatureLastUpdated)"
$output += '```'
$output += ""
$output += "## DNS"
$output += '```'
$adapters = Get-NetAdapter | Where-Object Status -eq Up
foreach ($a in $adapters) {
    $dns = (Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4).ServerAddresses -join ", "
    $output += "$($a.Name): $dns"
}
$output += '```'
$output += ""
$output += "## Listening Ports"
$output += '```'
$listeners = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Select-Object LocalPort, OwningProcess | Sort-Object LocalPort -Unique
foreach ($l in $listeners) {
    $proc = (Get-Process -Id $l.OwningProcess -ErrorAction SilentlyContinue).ProcessName
    $output += "Port $($l.LocalPort) — $proc"
}
$output += '```'
$output += ""
$output += "## Hostname"
$output += '```'
$output += $env:COMPUTERNAME
$output += '```'
$output += ""
$output += "## Recent Failed Logons"
$output += '```'
$failed = Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625} -MaxEvents 20 -ErrorAction SilentlyContinue
if ($failed) { $failed | ForEach-Object { $output += $_.TimeCreated.ToString() + " " + $_.Message.Substring(0, [Math]::Min(100, $_.Message.Length)) } }
else { $output += "None found" }
$output += '```'
$output += ""
$output += "---"
$output += "Audit complete."

$output | Out-File -FilePath $Report -Encoding UTF8
'@
    Set-Content -Path $auditScript -Value $auditContent -Encoding UTF8

    try {
        # Schedule weekly task (Monday 10 AM)
        $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -File `"$auditScript`""
        $trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 10am
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
        Register-ScheduledTask -TaskName "SecurityWeeklyAudit" -Action $action -Trigger $trigger -Settings $settings -Description "Weekly security audit" -ErrorAction Stop | Out-Null

        Print-Status $script:CurrentModule $script:TotalModules "$desc (Task Scheduler, Mondays 10 AM)" "applied"
        Log-Entry "audit-script" "apply" "ok" "Weekly audit task scheduled"
        $script:ModuleResult = "applied"
    } catch {
        Print-Status $script:CurrentModule $script:TotalModules $desc "failed"
        Log-Entry "audit-script" "apply" "fail" "Could not schedule task: $_"
        $script:ModuleResult = "failed"
    }

    # Take baseline
    New-Item -ItemType Directory -Path $script:BaselineDir -Force | Out-Null
    Get-Service | Where-Object { $_.StartType -eq "Automatic" -and $_.Status -eq "Running" } |
        Select-Object -ExpandProperty Name | Sort-Object | Out-File (Join-Path $script:BaselineDir "services.txt") -Encoding UTF8
    Get-NetFirewallRule -Enabled True | Select-Object DisplayName, Direction, Action |
        Sort-Object DisplayName | Out-File (Join-Path $script:BaselineDir "firewall-rules.txt") -Encoding UTF8
}

# ═══════════════════════════════════════════════════════════════════
# MODULE: backup-guidance
# ═══════════════════════════════════════════════════════════════════
function Mod-backup-guidance {
    $desc = "Encrypted backup strategy"
    Print-Status $script:CurrentModule $script:TotalModules $desc "manual"
    Log-Entry "backup-guidance" "check" "manual" "Guidance-only"
    Pause-Guide "Backup checklist: (1) Enable Windows Backup or use a tool like Veeam/Macrium to an encrypted external drive. (2) Store BitLocker recovery key + 2FA codes on paper in separate physical location. (3) Back up SSH/GPG keys to encrypted USB stored offsite. (4) Use E2E encrypted cloud (Proton Drive, Tresorit) for critical documents." | Out-Null
    $script:ModuleResult = "manual"
}

# ═══════════════════════════════════════════════════════════════════
# MODULE: border-prep
# ═══════════════════════════════════════════════════════════════════
function Mod-border-prep {
    $desc = "Border crossing preparation"
    Print-Status $script:CurrentModule $script:TotalModules $desc "manual"
    Log-Entry "border-prep" "check" "manual" "Guidance-only"
    Pause-Guide "Border crossing protocol: (1) Full backup before travel. (2) Shut down completely before checkpoints (flushes BitLocker keys from memory). (3) Consider a separate local account with minimal data for travel. (4) If device seized: remote wipe via Microsoft Find My Device. (5) Have credential rotation checklist ready." | Out-Null
    $script:ModuleResult = "manual"
}

# ═══════════════════════════════════════════════════════════════════
# MODULE: bluetooth-disable
# ═══════════════════════════════════════════════════════════════════
function Mod-bluetooth-disable {
    $desc = "Bluetooth management"
    $btService = Get-Service -Name "bthserv" -ErrorAction SilentlyContinue
    if ($btService -and $btService.Status -eq "Stopped" -and $btService.StartType -eq "Disabled") {
        Print-Status $script:CurrentModule $script:TotalModules $desc "skipped"
        Log-Entry "bluetooth-disable" "check" "skip" "Bluetooth service already disabled"
        $script:ModuleResult = "skipped"
        return
    }

    if (Prompt-YN "Disable Bluetooth service? (You can re-enable later)") {
        try {
            Stop-Service -Name "bthserv" -Force -ErrorAction SilentlyContinue
            Set-Service -Name "bthserv" -StartupType Disabled -ErrorAction Stop
            Print-Status $script:CurrentModule $script:TotalModules $desc "applied"
            Log-Entry "bluetooth-disable" "apply" "ok" "Bluetooth service disabled"
            $script:ModuleResult = "applied"
        } catch {
            Print-Status $script:CurrentModule $script:TotalModules $desc "failed"
            Log-Entry "bluetooth-disable" "apply" "fail" "Could not disable Bluetooth: $_"
            $script:ModuleResult = "failed"
        }
    } else {
        Print-Status $script:CurrentModule $script:TotalModules $desc "skipped"
        Log-Entry "bluetooth-disable" "check" "skip" "User chose to keep Bluetooth"
        $script:ModuleResult = "skipped"
    }
}

# ═══════════════════════════════════════════════════════════════════
# OUTPUT: SUMMARY & REPORTS
# ═══════════════════════════════════════════════════════════════════
function Print-Summary {
    Write-Host ""
    Write-ColorLine "═══════════════════════════════════════════════════" White
    Write-ColorLine "  Hardening Complete" White
    Write-ColorLine "═══════════════════════════════════════════════════" White
    Write-Host ""
    Write-Host "  " -NoNewline; Write-Color "✓" Green; Write-Host " Applied:    $($script:CountApplied)"
    Write-Host "  " -NoNewline; Write-Color "○" Green; Write-Host " Skipped:    $($script:CountSkipped) " -NoNewline; Write-ColorLine "(already applied)" DarkGray
    Write-Host "  " -NoNewline; Write-Color "✗" Red;   Write-Host " Failed:     $($script:CountFailed)" -NoNewline
    if ($script:CountFailed -gt 0) { Write-ColorLine " (see log)" Red } else { Write-Host "" }
    Write-Host "  " -NoNewline; Write-Color "☐" Yellow; Write-Host " Manual:     $($script:CountManual)" -NoNewline
    if ($script:CountManual -gt 0) { Write-ColorLine " (see below)" Yellow } else { Write-Host "" }
    Write-Host ""
    Write-Host "  Profile: $($script:Profile) | OS: Windows | Date: $($script:DATE)"
    Write-Host ""
}

function Print-ManualChecklist {
    if ($script:ManualSteps.Count -gt 0) {
        Print-Section "Manual Steps Remaining"
        for ($i = 0; $i -lt $script:ManualSteps.Count; $i++) {
            Write-Host "  " -NoNewline; Write-Color "☐" Yellow; Write-Host " $($i+1). $($script:ManualSteps[$i])"
            Write-Host ""
        }
    }
}

function Write-Report {
    $reportFile = Join-Path $script:AuditDir "hardening-report-$($script:DATE).md"
    New-Item -ItemType Directory -Path $script:AuditDir -Force | Out-Null
    $report = @()
    $report += "# Hardening Report — $($script:DATE)"
    $report += ""
    $report += "**Profile:** $($script:Profile)"
    $report += "**OS:** Windows $([System.Environment]::OSVersion.Version)"
    $report += "**Generated:** $($script:TIMESTAMP)"
    $report += ""
    $report += "## Summary"
    $report += ""
    $report += "| Status | Count |"
    $report += "|--------|-------|"
    $report += "| Applied | $($script:CountApplied) |"
    $report += "| Skipped (already done) | $($script:CountSkipped) |"
    $report += "| Failed | $($script:CountFailed) |"
    $report += "| Manual steps | $($script:CountManual) |"
    $report += ""
    $report += "## Log"
    $report += ""
    $report += '```'
    $report += $script:LogEntries
    $report += '```'
    $report += ""
    if ($script:ManualSteps.Count -gt 0) {
        $report += "## Manual Steps"
        $report += ""
        foreach ($step in $script:ManualSteps) {
            $report += "- [ ] $step"
        }
        $report += ""
    }
    $report += "---"
    $report += "Generated by harden.ps1 v$($script:VERSION)"
    $report | Out-File -FilePath $reportFile -Encoding UTF8
    Write-Host "  " -NoNewline; Write-Color "Report written to: " Green; Write-Host $reportFile
}

function Write-Log {
    New-Item -ItemType Directory -Path (Split-Path $script:LogFile) -Force | Out-Null
    $log = @()
    $log += "# Hardening Log — $($script:TIMESTAMP)"
    $log += "Profile: $($script:Profile) | OS: Windows"
    $log += ""
    $log += $script:LogEntries
    $log | Out-File -FilePath $script:LogFile -Encoding UTF8
    Write-ColorLine "  Log written to: $($script:LogFile)" DarkGray
}

# ═══════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════
function Main {
    Print-Header
    Check-Privileges

    Select-Profile
    Select-OutputMode
    Build-ModuleList

    Write-Host ""
    Write-Host "  Modules to apply: " -NoNewline; Write-ColorLine $script:TotalModules White
    Write-Host ""
    if (-not (Prompt-YN "Proceed with hardening?")) {
        Write-Host "Aborted."
        exit 0
    }

    Run-AllModules
    Print-Summary

    switch ($script:OutputMode) {
        "checklist" { Print-ManualChecklist }
        "pause"     { } # Already guided
        "report"    { Write-Report }
    }

    Write-Log

    Write-Host ""
    Write-ColorLine "  Re-run this script anytime — it's safe to repeat." DarkGray
    Write-Host ""
}

Main
