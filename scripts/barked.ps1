# ═══════════════════════════════════════════════════════════════════
# barked.ps1 — Windows security hardening wizard
# Idempotent, interactive, profile-based system hardening
# Run: .\barked.ps1 (self-elevates when admin modules are needed)
# ═══════════════════════════════════════════════════════════════════

param(
    [switch]$Uninstall,
    [switch]$Modify,
    [switch]$Clean,
    [switch]$Force,
    [switch]$DryRun,
    [switch]$Help,
    [switch]$Version,
    [switch]$Update,
    [switch]$UninstallSelf,
    [switch]$Elevated,
    [switch]$Audit,
    [switch]$CleanSchedule,
    [switch]$CleanUnschedule,
    [switch]$CleanScheduled,
    [switch]$Auto,
    [string]$Profile,
    [switch]$Quiet
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

$script:VERSION = "1.3.0"
$script:GITHUB_REPO = "sth8pwd5wx-max/barked"
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
$script:CountReverted = 0
$script:EnabledModules = @()
$script:LogEntries = @()
$script:ManualSteps = @()
$script:ModuleResult = ""

# Run mode: harden, uninstall, modify
$script:RunMode = "harden"
$script:ModuleMode = "apply"
$script:RemovePackages = $false
$script:QuietMode = $false

# Audit mode globals
$script:FindingsStatus = @()
$script:FindingsModule = @()
$script:FindingsMessage = @()

# State file paths
$script:StateFileUser = Join-Path $env:APPDATA "barked\state.json"
$script:StateFileProject = Join-Path (Split-Path $script:ScriptDir) "state\hardening-state.json"
$script:StateFileLegacy = "C:\ProgramData\hardening-state.json"
$script:StateData = @{
    version = "1.0.0"
    last_run = ""
    os = "windows"
    profile = ""
    modules = @{}
    packages_installed = @()
}

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
# Scheduled clean config paths
$script:SchedConfigUser = Join-Path $env:APPDATA "barked\scheduled-clean.json"
$script:SchedConfigProject = Join-Path (Split-Path $script:ScriptDir) "state\scheduled-clean.json"
$script:SchedTaskName = "BarkedScheduledClean"
$script:CleanForce = $false
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

# ═══════════════════════════════════════════════════════════════════
# SCHEDULED CLEAN: CONFIG
# ═══════════════════════════════════════════════════════════════════

function Load-ScheduledConfig {
    $configFile = $null
    if (Test-Path $script:SchedConfigUser) {
        $configFile = $script:SchedConfigUser
    } elseif (Test-Path $script:SchedConfigProject) {
        $configFile = $script:SchedConfigProject
    } else {
        return $null
    }
    try {
        $config = Get-Content $configFile -Raw | ConvertFrom-Json
        return $config
    } catch {
        return $null
    }
}

function Save-ScheduledConfig {
    param([bool]$Enabled, [string]$Schedule, [bool]$Notify, [string[]]$Categories)
    $config = @{
        enabled = $Enabled
        schedule = $Schedule
        categories = $Categories
        notify = $Notify
        last_run = ""
        version = "1.0"
    }
    try {
        $dir = Split-Path $script:SchedConfigUser
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        $config | ConvertTo-Json | Out-File -FilePath $script:SchedConfigUser -Encoding UTF8 -ErrorAction Stop

        # Backup to project directory
        $projDir = Split-Path $script:SchedConfigProject
        if (Test-Path (Split-Path $projDir)) {
            New-Item -ItemType Directory -Path $projDir -Force | Out-Null
            Copy-Item $script:SchedConfigUser $script:SchedConfigProject -Force -ErrorAction SilentlyContinue
        }
    } catch {
        Write-Host "  ERROR: Failed to save scheduled clean config" -ForegroundColor Red
    }
}

# ═══════════════════════════════════════════════════════════════════
# SCHEDULED CLEAN: SETUP WIZARD
# ═══════════════════════════════════════════════════════════════════

function Install-CleanScheduledTask {
    param([string]$Schedule)

    $scriptPath = $MyInvocation.ScriptName
    if (-not $scriptPath) { $scriptPath = $PSCommandPath }
    if (-not $scriptPath) { $scriptPath = Join-Path $script:ScriptDir "barked.ps1" }

    # Find pwsh or powershell
    $pwshPath = (Get-Command pwsh -ErrorAction SilentlyContinue).Source
    if (-not $pwshPath) { $pwshPath = (Get-Command powershell -ErrorAction SilentlyContinue).Source }
    if (-not $pwshPath) { $pwshPath = "powershell.exe" }

    $action = New-ScheduledTaskAction -Execute $pwshPath -Argument "-NonInteractive -NoProfile -File `"$scriptPath`" -CleanScheduled"

    if ($Schedule -eq "daily") {
        $trigger = New-ScheduledTaskTrigger -Daily -At "2:00AM"
    } else {
        $trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At "2:00AM"
    }

    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

    try {
        # Remove existing task if present
        Unregister-ScheduledTask -TaskName $script:SchedTaskName -Confirm:$false -ErrorAction SilentlyContinue
        Register-ScheduledTask -TaskName $script:SchedTaskName -Action $action -Trigger $trigger -Settings $settings -Description "Barked automated system cleaning" -ErrorAction Stop | Out-Null
        Write-Host "  " -NoNewline; Write-ColorLine "Task Scheduler entry created" Green
    } catch {
        Write-Host "  ERROR: Failed to register scheduled task: $_" -ForegroundColor Red
        Write-Host "  Try running as Administrator to register scheduled tasks." -ForegroundColor DarkYellow
    }
}

function Setup-ScheduledClean {
    Print-Section "Scheduled Cleaning Setup"

    Write-Host "  Configure automatic system cleaning" -ForegroundColor White
    Write-Host ""

    # Step 1: Category selection (reuse existing picker)
    Write-Host "  Step 1/3: Select categories to clean automatically" -ForegroundColor White
    Write-Host ""
    Show-CleanPicker

    # Capture selected categories
    $selectedCats = @()
    foreach ($cat in $script:CleanCatOrder) {
        if ($script:CleanCategories[$cat]) {
            $selectedCats += $cat
        }
    }

    if ($selectedCats.Count -eq 0) {
        Write-Host "  No categories selected. Setup cancelled." -ForegroundColor Red
        return
    }

    Write-Host ""
    Write-Host "  Selected $($selectedCats.Count) categories" -ForegroundColor Green
    Write-Host ""

    # Step 2: Schedule frequency
    Write-Host "  Step 2/3: How often should automated cleaning run?" -ForegroundColor White
    Write-Host ""
    Write-Host "  " -NoNewline; Write-Color "[1]" Green; Write-Host " Daily (every day at 2:00 AM)"
    Write-Host "  " -NoNewline; Write-Color "[2]" Green; Write-Host " Weekly (Sunday at 2:00 AM)"
    Write-Host ""

    $schedule = ""
    while ($true) {
        Write-Host "  Choice: " -NoNewline -ForegroundColor White
        $schedChoice = Read-Host
        switch ($schedChoice) {
            "1" { $schedule = "daily"; break }
            "2" { $schedule = "weekly"; break }
            default { Write-Host "  Invalid choice. Enter 1-2." -ForegroundColor Red }
        }
        if ($schedule) { break }
    }

    Write-Host ""

    # Step 3: Notification preference
    Write-Host "  Step 3/3: Show notification when cleaning completes?" -ForegroundColor White
    Write-Host "  [Y/n]: " -NoNewline -ForegroundColor White
    $notifyInput = Read-Host
    $notify = $notifyInput.ToLower() -ne "n"

    Write-Host ""

    # Confirmation summary
    $schedDisplay = if ($schedule -eq "daily") { "Daily at 2:00 AM" } else { "Weekly (Sunday 2:00 AM)" }
    $catNames = ($selectedCats | ForEach-Object { $script:CleanCatNames[$_] }) -join ", "
    if ($catNames.Length -gt 41) { $catNames = $catNames.Substring(0, 38) + "..." }
    $notifyDisplay = if ($notify) { "Yes" } else { "No" }

    Write-ColorLine "  ╔══════════════════════════════════════════════════════════╗" Green
    Write-Host "  " -NoNewline; Write-Color "║" Green; Write-Host "      SCHEDULED CLEANING CONFIGURED                       " -NoNewline; Write-ColorLine "║" Green
    Write-ColorLine "  ╠══════════════════════════════════════════════════════════╣" Green
    Write-Host "  " -NoNewline; Write-Color "║" Green; Write-Host (" Categories: {0,-44}" -f $catNames) -NoNewline; Write-ColorLine "║" Green
    Write-Host "  " -NoNewline; Write-Color "║" Green; Write-Host (" Schedule:   {0,-44}" -f $schedDisplay) -NoNewline; Write-ColorLine "║" Green
    Write-Host "  " -NoNewline; Write-Color "║" Green; Write-Host (" Notify:     {0,-44}" -f $notifyDisplay) -NoNewline; Write-ColorLine "║" Green
    Write-ColorLine "  ╚══════════════════════════════════════════════════════════╝" Green
    Write-Host ""

    # Save config
    Save-ScheduledConfig -Enabled $true -Schedule $schedule -Notify $notify -Categories $selectedCats

    # Install scheduler
    Install-CleanScheduledTask -Schedule $schedule

    Write-Host ""
    Write-Host "  Scheduled cleaning configured" -ForegroundColor Green
    Write-Host ""
}

function Unschedule-ScheduledClean {
    Print-Section "Remove Scheduled Cleaning"

    $config = Load-ScheduledConfig
    if (-not $config) {
        Write-Host "  No scheduled cleaning configured" -ForegroundColor DarkYellow
        return
    }

    # Remove Task Scheduler entry
    try {
        $task = Get-ScheduledTask -TaskName $script:SchedTaskName -ErrorAction SilentlyContinue
        if ($task) {
            Unregister-ScheduledTask -TaskName $script:SchedTaskName -Confirm:$false -ErrorAction Stop
            Write-Host "  Removed scheduled task" -ForegroundColor Green
        } else {
            Write-Host "  No scheduled task found" -ForegroundColor DarkYellow
        }
    } catch {
        Write-Host "  ERROR: Failed to remove scheduled task: $_" -ForegroundColor Red
    }

    # Disable in config
    if (Test-Path $script:SchedConfigUser) {
        try {
            $config = Get-Content $script:SchedConfigUser -Raw | ConvertFrom-Json
            $config.enabled = $false
            $config | ConvertTo-Json | Out-File -FilePath $script:SchedConfigUser -Encoding UTF8 -ErrorAction Stop
            Write-Host "  Disabled scheduled cleaning" -ForegroundColor Green
        } catch {
            Write-Host "  ERROR: Failed to update config" -ForegroundColor Red
        }
    }

    Write-Host ""
}

# ═══════════════════════════════════════════════════════════════════
# SCHEDULED CLEAN: EXECUTION (invoked by Task Scheduler)
# ═══════════════════════════════════════════════════════════════════

function Send-CleanNotification {
    param([int]$FileCount, [long]$BytesFreed)

    if ($FileCount -eq 0 -and $BytesFreed -eq 0) { return }

    $sizeStr = Format-CleanBytes $BytesFreed
    $message = "Cleaned $sizeStr from $FileCount files"

    # Try BurntToast module first
    if (Get-Module -ListAvailable -Name BurntToast -ErrorAction SilentlyContinue) {
        try {
            Import-Module BurntToast -ErrorAction Stop
            New-BurntToastNotification -Text "Barked Cleaner", $message -ErrorAction Stop
            return
        } catch { }
    }

    # Fallback: Windows Forms MessageBox (non-blocking via job)
    try {
        Start-Job -ScriptBlock {
            Add-Type -AssemblyName System.Windows.Forms
            [System.Windows.Forms.MessageBox]::Show($using:message, "Barked Cleaner", "OK", "Information") | Out-Null
        } | Out-Null
    } catch { }
}

function Run-ScheduledClean {
    $lockFile = Join-Path $env:TEMP "barked-clean.lock"
    $lockTimeout = 7200  # 2 hours in seconds

    # 1. Load config and validate
    $config = Load-ScheduledConfig
    if (-not $config) {
        Write-CleanLogEntry "ERROR" "Failed to load scheduled clean config"
        return
    }
    if (-not $config.enabled) {
        Write-CleanLogEntry "INFO" "Scheduled cleaning is disabled, skipping"
        return
    }

    # 2. Pre-flight: disk space
    try {
        $drive = Get-PSDrive C -ErrorAction Stop
        $freeGB = [math]::Round($drive.Free / 1GB, 1)
        if ($freeGB -lt 5) {
            Write-CleanLogEntry "WARN" "Low disk space (${freeGB}GB), skipping scheduled clean"
            return
        }
    } catch { }

    # 3. Pre-flight: battery
    try {
        $battery = Get-WmiObject Win32_Battery -ErrorAction SilentlyContinue
        if ($battery -and $battery.EstimatedChargeRemaining -lt 20 -and $battery.BatteryStatus -ne 2) {
            Write-CleanLogEntry "WARN" "Low battery ($($battery.EstimatedChargeRemaining)%), skipping scheduled clean"
            return
        }
    } catch { }

    # 4. Lock file
    if (Test-Path $lockFile) {
        $lockAge = ((Get-Date) - (Get-Item $lockFile).LastWriteTime).TotalSeconds
        if ($lockAge -lt $lockTimeout) {
            Write-CleanLogEntry "INFO" "Another clean is already running (lock age: ${lockAge}s), exiting"
            return
        }
        Remove-Item $lockFile -Force -ErrorAction SilentlyContinue
    }
    try {
        [IO.File]::Open($lockFile, 'CreateNew', 'Write').Close()
    } catch {
        Write-CleanLogEntry "INFO" "Another clean acquired the lock first, exiting"
        return
    }

    try {
        # 5. Set categories from config
        if (-not $config.categories -or $config.categories.Count -eq 0) {
            Write-CleanLogEntry "ERROR" "No categories configured for scheduled clean"
            return
        }

        foreach ($cat in $script:CleanCatOrder) {
            $script:CleanCategories[$cat] = $false
        }
        foreach ($cat in $config.categories) {
            if ($script:CleanCategories.ContainsKey($cat)) {
                $script:CleanCategories[$cat] = $true
            }
        }

        # Populate clean targets from enabled categories
        $script:CleanTargets = @{}
        foreach ($cat in $script:CleanCatOrder) {
            if ($script:CleanCategories[$cat]) {
                foreach ($target in $script:CleanCatTargets[$cat]) {
                    $script:CleanTargets[$target] = $true
                }
            }
        }

        Write-CleanLogEntry "INFO" "Starting scheduled clean: categories=$($config.categories -join ',')"

        # 6. Run clean (force mode — no confirmation)
        $script:CleanForce = $true
        Invoke-CleanExecute

        # 7. Calculate totals
        $totalFiles = 0
        $totalBytes = [long]0
        foreach ($count in $script:CleanResultFiles.Values) { $totalFiles += $count }
        foreach ($bytes in $script:CleanResultBytes.Values) { $totalBytes += $bytes }

        $totalSizeFmt = Format-CleanBytes $totalBytes
        Write-CleanLogEntry "INFO" "Scheduled clean completed: $totalFiles files, $totalSizeFmt freed"

        # 8. Notify if enabled
        if ($config.notify) {
            Send-CleanNotification -FileCount $totalFiles -BytesFreed $totalBytes
        }

        # 9. Update last_run timestamp
        if (Test-Path $script:SchedConfigUser) {
            try {
                $cfg = Get-Content $script:SchedConfigUser -Raw | ConvertFrom-Json
                $cfg.last_run = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
                $cfg | ConvertTo-Json | Out-File -FilePath $script:SchedConfigUser -Encoding UTF8 -ErrorAction Stop
            } catch {
                Write-CleanLogEntry "WARN" "Failed to update last_run timestamp"
            }
        }
    } finally {
        # Always remove lock file
        Remove-Item $lockFile -Force -ErrorAction SilentlyContinue
    }

    Write-CleanLog
}

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
    if ($script:QuietMode) { return }
    Write-Host ""
    Write-ColorLine "╔══════════════════════════════════════════════════╗" Green
    Write-Host "║" -ForegroundColor Green -NoNewline
    Write-Host "          BARKED HARDENING WIZARD v$($script:VERSION)          " -ForegroundColor Green -NoNewline
    Write-ColorLine "║" Green
    Write-Host "║" -ForegroundColor Green -NoNewline
    Write-Host "                     Windows                       " -NoNewline
    Write-ColorLine "║" Green
    Write-ColorLine "╚══════════════════════════════════════════════════╝" Green
    Write-Host ""
}

function Print-Section {
    param([string]$Title)
    Write-Host ""
    Write-ColorLine "═══ $Title ═══" Green
    Write-Host ""
}

function Print-Status {
    param([int]$Num, [int]$Total, [string]$Desc, [string]$Status)
    if ($script:QuietMode) { return }
    switch ($Status) {
        "applied"  { Write-Host "  " -NoNewline; Write-Color "✓" Green; Write-Host " [$Num/$Total] $Desc " -NoNewline; Write-ColorLine "(applied)" DarkYellow }
        "skipped"  { Write-Host "  " -NoNewline; Write-Color "○" Green; Write-Host " [$Num/$Total] $Desc " -NoNewline; Write-ColorLine "(already applied)" DarkYellow }
        "failed"   { Write-Host "  " -NoNewline; Write-Color "✗" Red;   Write-Host " [$Num/$Total] $Desc " -NoNewline; Write-ColorLine "(failed)" Red }
        "manual"   { Write-Host "  " -NoNewline; Write-Color "☐" Red; Write-Host " [$Num/$Total] $Desc " -NoNewline; Write-ColorLine "(manual)" Red }
        "reverted"  { Write-Host "  " -NoNewline; Write-Color "✓" Green; Write-Host " [$Num/$Total] $Desc " -NoNewline; Write-ColorLine "(reverted)" DarkYellow }
        "skipped_unsupported" { Write-Host "  " -NoNewline; Write-Color "–" DarkYellow; Write-Host " [$Num/$Total] $Desc " -NoNewline; Write-ColorLine "(not available on Windows)" DarkYellow }
    }
}

function Prompt-Choice {
    param([string]$Prompt, [string[]]$Options)
    Write-ColorLine $Prompt Green
    Write-Host ""
    for ($i = 0; $i -lt $Options.Count; $i++) {
        Write-Host "  " -NoNewline
        Write-Color "[$($i+1)] Green
        Write-Host " $($Options[$i])"
    }
    Write-Host ""
    while ($true) {
        Write-Host "  Choice: " -NoNewline -ForegroundColor Green
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
    Write-Host "  $Prompt [Y/n]: " -NoNewline -ForegroundColor Green
    $response = Read-Host
    return ($response -ne "n" -and $response -ne "N")
}

function Pause-Guide {
    param([string]$Message)
    if ($script:OutputMode -eq "pause") {
        Write-Host ""
        Write-Host "  " -NoNewline; Write-Color "☐ MANUAL STEP:" Red; Write-Host " $Message"
        Write-Host "  Press Enter when done (or S to skip)... " -NoNewline -ForegroundColor DarkYellow
        $response = Read-Host
        return ($response -ne "s" -and $response -ne "S")
    } else {
        $script:ManualSteps += $Message
        return $false
    }
}

# ═══════════════════════════════════════════════════════════════════
# STATE FILE I/O
# ═══════════════════════════════════════════════════════════════════
function Read-State {
    $loaded = $false
    foreach ($path in @($script:StateFileUser, $script:StateFileProject, $script:StateFileLegacy)) {
        if (Test-Path $path) {
            try {
                $json = Get-Content $path -Raw | ConvertFrom-Json
                $script:StateData.version = if ($json.version) { $json.version } else { "1.0.0" }
                $script:StateData.last_run = if ($json.last_run) { $json.last_run } else { "" }
                $script:StateData.os = if ($json.os) { $json.os } else { "windows" }
                $script:StateData.profile = if ($json.profile) { $json.profile } else { "" }
                $script:StateData.modules = @{}
                if ($json.modules) {
                    $json.modules.PSObject.Properties | ForEach-Object {
                        $script:StateData.modules[$_.Name] = @{
                            status = $_.Value.status
                            applied_at = $_.Value.applied_at
                            previous_value = $_.Value.previous_value
                        }
                    }
                }
                $script:StateData.packages_installed = @()
                if ($json.packages_installed) {
                    $script:StateData.packages_installed = @($json.packages_installed)
                }
                $loaded = $true
                break
            } catch {
                Log-Entry "state" "read" "warn" "Could not parse state file $path"
            }
        }
    }
    return $loaded
}

function Write-State {
    $script:StateData.last_run = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
    $script:StateData.profile = $script:Profile

    # Build output object
    $output = [ordered]@{
        version = $script:StateData.version
        last_run = $script:StateData.last_run
        os = $script:StateData.os
        profile = $script:StateData.profile
        modules = [ordered]@{}
        packages_installed = $script:StateData.packages_installed
    }
    foreach ($key in ($script:StateData.modules.Keys | Sort-Object)) {
        $mod = $script:StateData.modules[$key]
        $output.modules[$key] = [ordered]@{
            status = $mod.status
            applied_at = $mod.applied_at
            previous_value = $mod.previous_value
        }
    }

    $json = $output | ConvertTo-Json -Depth 4

    # Write to user location
    try {
        $userDir = Split-Path $script:StateFileUser
        if (-not (Test-Path $userDir)) { New-Item -ItemType Directory -Path $userDir -Force | Out-Null }
        $json | Out-File -FilePath $script:StateFileUser -Encoding UTF8 -Force
    } catch {
        Log-Entry "state" "write" "warn" "Could not write user state: $_"
    }

    # Write to project location
    try {
        $stateDir = Split-Path $script:StateFileProject
        if (-not (Test-Path $stateDir)) { New-Item -ItemType Directory -Path $stateDir -Force | Out-Null }
        $json | Out-File -FilePath $script:StateFileProject -Encoding UTF8 -Force
    } catch {
        Log-Entry "state" "write" "warn" "Could not write project state: $_"
    }
}

function Set-ModuleState {
    param([string]$ModId, [string]$Status, [string]$PreviousValue = $null)
    $script:StateData.modules[$ModId] = @{
        status = $Status
        applied_at = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
        previous_value = $PreviousValue
    }
}

function Add-StatePackage {
    param([string]$PkgName)
    if ($script:StateData.packages_installed -notcontains $PkgName) {
        $script:StateData.packages_installed += $PkgName
    }
}

function Remove-StatePackage {
    param([string]$PkgName)
    $script:StateData.packages_installed = @($script:StateData.packages_installed | Where-Object { $_ -ne $PkgName })
}

function Get-AppliedModules {
    $applied = @()
    foreach ($key in $script:StateData.modules.Keys) {
        if ($script:StateData.modules[$key].status -eq "applied") {
            $applied += $key
        }
    }
    return $applied
}

function Get-AppliedCount {
    return @(Get-AppliedModules).Count
}

# ═══════════════════════════════════════════════════════════════════
# LIVE DETECTION (fallback when no state file)
# ═══════════════════════════════════════════════════════════════════
function Detect-AppliedModules {
    $detected = @{}

    # disk-encrypt
    try {
        $bl = Get-BitLockerVolume -MountPoint "C:" -ErrorAction Stop
        if ($bl.ProtectionStatus -eq "On") { $detected["disk-encrypt"] = $true }
    } catch {}

    # firewall-inbound
    $profiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
    if ($profiles) {
        $allEnabled = ($profiles | Where-Object { $_.Enabled -eq $false }).Count -eq 0
        $allBlock = ($profiles | Where-Object { $_.DefaultInboundAction -eq "Block" }).Count -eq $profiles.Count
        if ($allEnabled -and $allBlock) { $detected["firewall-inbound"] = $true }
    }

    # firewall-stealth
    if (Get-NetFirewallRule -DisplayName "Harden-Block-ICMPv4-In" -ErrorAction SilentlyContinue) {
        $detected["firewall-stealth"] = $true
    }

    # firewall-outbound
    if ($profiles) {
        $allDenyOut = ($profiles | Where-Object { $_.DefaultOutboundAction -eq "Block" }).Count -eq $profiles.Count
        if ($allDenyOut) { $detected["firewall-outbound"] = $true }
    }

    # dns-secure
    $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } -ErrorAction SilentlyContinue
    if ($adapters) {
        $allQuad9 = $true
        foreach ($a in $adapters) {
            $dns = Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
            if ($dns.ServerAddresses -notcontains "9.9.9.9") { $allQuad9 = $false; break }
        }
        if ($allQuad9) { $detected["dns-secure"] = $true }
    }

    # auto-updates
    try {
        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
        $current = Get-ItemProperty -Path $regPath -Name "NoAutoUpdate" -ErrorAction SilentlyContinue
        if ($null -eq $current -or $current.NoAutoUpdate -eq 0) { $detected["auto-updates"] = $true }
    } catch { $detected["auto-updates"] = $true }

    # guest-disable
    try {
        $guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
        if ($null -eq $guest -or $guest.Enabled -eq $false) { $detected["guest-disable"] = $true }
    } catch {}

    # lock-screen
    $ssRegPath = "HKCU:\Control Panel\Desktop"
    $lock = (Get-ItemProperty -Path $ssRegPath -Name "ScreenSaverIsSecure" -ErrorAction SilentlyContinue).ScreenSaverIsSecure
    $timeout = (Get-ItemProperty -Path $ssRegPath -Name "ScreenSaveTimeOut" -ErrorAction SilentlyContinue).ScreenSaveTimeOut
    if ($lock -eq "1" -and $null -ne $timeout -and [int]$timeout -le 300) { $detected["lock-screen"] = $true }

    # browser-basic
    $edgePath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    $edgeTP = (Get-ItemProperty -Path $edgePath -Name "TrackingPrevention" -ErrorAction SilentlyContinue).TrackingPrevention
    if ($edgeTP -eq 3) { $detected["browser-basic"] = $true }

    # hostname-scrub
    if ($env:COMPUTERNAME -eq "DESKTOP-PC") { $detected["hostname-scrub"] = $true }

    # ssh-harden
    $sshConfig = Join-Path $script:RealHome ".ssh\config"
    if ((Test-Path $sshConfig) -and (Select-String -Path $sshConfig -Pattern "IdentitiesOnly yes" -Quiet -ErrorAction SilentlyContinue)) {
        $detected["ssh-harden"] = $true
    }

    # git-harden
    if (Get-Command git -ErrorAction SilentlyContinue) {
        $signing = & git config --global --get commit.gpgsign 2>$null
        if ($signing -eq "true") { $detected["git-harden"] = $true }
    }

    # telemetry-disable
    $diagTrack = Get-Service -Name "DiagTrack" -ErrorAction SilentlyContinue
    if ($diagTrack -and $diagTrack.StartType -eq "Disabled") { $detected["telemetry-disable"] = $true }

    # monitoring-tools
    $sysmon = Get-Service -Name "Sysmon*" -ErrorAction SilentlyContinue
    if ($sysmon -and $sysmon.Status -eq "Running") { $detected["monitoring-tools"] = $true }

    # permissions-audit — read-only, skip detection

    # browser-fingerprint
    $ffProfileRoot = Join-Path $script:RealHome "AppData\Roaming\Mozilla\Firefox\Profiles"
    $ffProfile = Get-ChildItem -Path $ffProfileRoot -Filter "*.default-release" -Directory -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($ffProfile) {
        $userJs = Join-Path $ffProfile.FullName "user.js"
        if ((Test-Path $userJs) -and (Select-String -Path $userJs -Pattern "privacy.resistFingerprinting" -Quiet -ErrorAction SilentlyContinue)) {
            $detected["browser-fingerprint"] = $true
        }
    }

    # metadata-strip
    if (Get-Command exiftool -ErrorAction SilentlyContinue) { $detected["metadata-strip"] = $true }

    # audit-script
    $task = Get-ScheduledTask -TaskName "SecurityWeeklyAudit" -ErrorAction SilentlyContinue
    if ($task) { $detected["audit-script"] = $true }

    # bluetooth-disable
    $btService = Get-Service -Name "bthserv" -ErrorAction SilentlyContinue
    if ($btService -and $btService.Status -eq "Stopped" -and $btService.StartType -eq "Disabled") {
        $detected["bluetooth-disable"] = $true
    }

    # Populate state from detection
    foreach ($modId in $detected.Keys) {
        if (-not $script:StateData.modules.ContainsKey($modId)) {
            $script:StateData.modules[$modId] = @{
                status = "applied"
                applied_at = "unknown"
                previous_value = $null
            }
        }
    }
}

# ═══════════════════════════════════════════════════════════════════
# AUDIT: SEVERITY & SCORING
# ═══════════════════════════════════════════════════════════════════
$script:ModuleSeverity = @{
    'disk-encrypt' = 'CRITICAL'; 'firewall-inbound' = 'CRITICAL'
    'auto-updates' = 'CRITICAL'; 'lock-screen' = 'CRITICAL'
    'firewall-stealth' = 'HIGH'; 'firewall-outbound' = 'HIGH'
    'dns-secure' = 'HIGH'; 'ssh-harden' = 'HIGH'
    'guest-disable' = 'HIGH'; 'telemetry-disable' = 'HIGH'
    'hostname-scrub' = 'MEDIUM'; 'git-harden' = 'MEDIUM'
    'browser-basic' = 'MEDIUM'; 'monitoring-tools' = 'MEDIUM'
    'permissions-audit' = 'MEDIUM'
    'browser-fingerprint' = 'LOW'; 'mac-rotate' = 'LOW'
    'vpn-killswitch' = 'LOW'; 'traffic-obfuscation' = 'LOW'
    'metadata-strip' = 'LOW'; 'dev-isolation' = 'LOW'
    'audit-script' = 'LOW'; 'backup-guidance' = 'LOW'
    'border-prep' = 'LOW'; 'bluetooth-disable' = 'LOW'
}

$script:ModuleSeverityWeight = @{
    'CRITICAL' = 10; 'HIGH' = 7; 'MEDIUM' = 4; 'LOW' = 2
}

function Get-SeverityWeight {
    param([string]$ModId)
    $sev = $script:ModuleSeverity[$ModId]
    if (-not $sev) { $sev = 'LOW' }
    return $script:ModuleSeverityWeight[$sev]
}

function Calculate-Score {
    param([string[]]$AllMods, [string[]]$PassingMods)
    $totalWeight = 0; $appliedWeight = 0
    $totalCount = 0; $appliedCount = 0
    $passSet = @{}
    foreach ($m in $PassingMods) { $passSet[$m] = $true }
    foreach ($modId in $AllMods) {
        $w = Get-SeverityWeight $modId
        $totalWeight += $w
        $totalCount++
        if ($passSet.ContainsKey($modId)) {
            $appliedWeight += $w
            $appliedCount++
        }
    }
    $pct = 0
    if ($totalWeight -gt 0) { $pct = [math]::Floor(($appliedWeight * 100) / $totalWeight) }
    return @{
        AppliedWeight = $appliedWeight; TotalWeight = $totalWeight
        Percentage = $pct; AppliedCount = $appliedCount; TotalCount = $totalCount
    }
}

function Record-Finding {
    param([string]$Status, [string]$ModId, [string]$Message)
    $script:FindingsStatus += $Status
    $script:FindingsModule += $ModId
    $script:FindingsMessage += $Message
}

# ═══════════════════════════════════════════════════════════════════
# AUDIT: CHECK FUNCTIONS (non-destructive)
# ═══════════════════════════════════════════════════════════════════

function Check-disk-encrypt {
    try {
        $bl = Get-BitLockerVolume -MountPoint "C:" -ErrorAction Stop
        if ($bl.ProtectionStatus -eq "On") {
            Record-Finding "PASS" "disk-encrypt" "BitLocker enabled on C:"
        } else {
            Record-Finding "FAIL" "disk-encrypt" "BitLocker not enabled"
        }
    } catch {
        Record-Finding "MANUAL" "disk-encrypt" "BitLocker status unknown (requires admin or TPM)"
    }
}

function Check-firewall-inbound {
    $profiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
    if (-not $profiles) {
        Record-Finding "SKIP" "firewall-inbound" "Cannot query firewall profiles"
        return
    }
    $allEnabled = ($profiles | Where-Object { $_.Enabled -eq $false }).Count -eq 0
    $allBlock = ($profiles | Where-Object { $_.DefaultInboundAction -eq "Block" }).Count -eq $profiles.Count
    if ($allEnabled -and $allBlock) {
        Record-Finding "PASS" "firewall-inbound" "Firewall enabled, inbound blocked on all profiles"
    } elseif ($allEnabled) {
        Record-Finding "FAIL" "firewall-inbound" "Firewall enabled but inbound not blocked"
    } else {
        Record-Finding "FAIL" "firewall-inbound" "Firewall not enabled on all profiles"
    }
}

function Check-firewall-stealth {
    if (Get-NetFirewallRule -DisplayName "Harden-Block-ICMPv4-In" -ErrorAction SilentlyContinue) {
        Record-Finding "PASS" "firewall-stealth" "ICMP block rule active"
    } else {
        Record-Finding "FAIL" "firewall-stealth" "No ICMP block rule found"
    }
}

function Check-firewall-outbound {
    $profiles = Get-NetFirewallProfile -ErrorAction SilentlyContinue
    if (-not $profiles) {
        Record-Finding "SKIP" "firewall-outbound" "Cannot query firewall profiles"
        return
    }
    $allDenyOut = ($profiles | Where-Object { $_.DefaultOutboundAction -eq "Block" }).Count -eq $profiles.Count
    if ($allDenyOut) {
        Record-Finding "PASS" "firewall-outbound" "Default outbound blocked on all profiles"
    } else {
        Record-Finding "FAIL" "firewall-outbound" "Outbound traffic not blocked by default"
    }
}

function Check-dns-secure {
    $adapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Up" }
    if (-not $adapters) {
        Record-Finding "SKIP" "dns-secure" "No active network adapters"
        return
    }
    $allQuad9 = $true
    foreach ($a in $adapters) {
        $dns = Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
        if ($dns.ServerAddresses -notcontains "9.9.9.9") { $allQuad9 = $false; break }
    }
    if ($allQuad9) {
        Record-Finding "PASS" "dns-secure" "Quad9 DNS configured on all adapters"
    } else {
        Record-Finding "FAIL" "dns-secure" "DNS not set to Quad9 on all adapters"
    }
}

function Check-vpn-killswitch {
    $rules = Get-NetFirewallRule -DisplayName "Harden-VPN-*" -ErrorAction SilentlyContinue
    if ($rules) {
        Record-Finding "PASS" "vpn-killswitch" "VPN killswitch firewall rules found"
    } else {
        Record-Finding "MANUAL" "vpn-killswitch" "VPN killswitch requires manual verification"
    }
}

function Check-hostname-scrub {
    if ($env:COMPUTERNAME -eq "DESKTOP-PC") {
        Record-Finding "PASS" "hostname-scrub" "Generic hostname set (DESKTOP-PC)"
    } else {
        Record-Finding "FAIL" "hostname-scrub" "Hostname is '$($env:COMPUTERNAME)' (not generic)"
    }
}

function Check-mac-rotate {
    $adapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Up" }
    $spoofed = $false
    foreach ($a in $adapters) {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}"
        $subKeys = Get-ChildItem $regPath -ErrorAction SilentlyContinue
        foreach ($key in $subKeys) {
            $na = Get-ItemProperty -Path $key.PSPath -Name "NetworkAddress" -ErrorAction SilentlyContinue
            if ($na -and $na.NetworkAddress) { $spoofed = $true; break }
        }
        if ($spoofed) { break }
    }
    if ($spoofed) {
        Record-Finding "PASS" "mac-rotate" "MAC address override detected in registry"
    } else {
        Record-Finding "MANUAL" "mac-rotate" "No MAC spoofing detected (may use third-party tool)"
    }
}

function Check-telemetry-disable {
    $diagTrack = Get-Service -Name "DiagTrack" -ErrorAction SilentlyContinue
    if ($diagTrack -and $diagTrack.StartType -eq "Disabled") {
        Record-Finding "PASS" "telemetry-disable" "DiagTrack service disabled"
    } elseif ($diagTrack) {
        Record-Finding "FAIL" "telemetry-disable" "DiagTrack service is $($diagTrack.StartType)"
    } else {
        Record-Finding "SKIP" "telemetry-disable" "DiagTrack service not found"
    }
}

function Check-traffic-obfuscation {
    if (Get-Command tor -ErrorAction SilentlyContinue) {
        Record-Finding "PASS" "traffic-obfuscation" "Tor binary found in PATH"
    } else {
        Record-Finding "MANUAL" "traffic-obfuscation" "Traffic obfuscation requires manual setup (Tor/VPN with DAITA)"
    }
}

function Check-metadata-strip {
    if (Get-Command exiftool -ErrorAction SilentlyContinue) {
        Record-Finding "PASS" "metadata-strip" "exiftool available"
    } else {
        Record-Finding "FAIL" "metadata-strip" "exiftool not found in PATH"
    }
}

function Check-browser-basic {
    $edgePath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    $edgeTP = (Get-ItemProperty -Path $edgePath -Name "TrackingPrevention" -ErrorAction SilentlyContinue).TrackingPrevention
    if ($edgeTP -eq 3) {
        Record-Finding "PASS" "browser-basic" "Edge tracking prevention set to Strict"
    } else {
        Record-Finding "FAIL" "browser-basic" "Edge tracking prevention not configured"
    }
}

function Check-browser-fingerprint {
    $ffProfileRoot = Join-Path $script:RealHome "AppData\Roaming\Mozilla\Firefox\Profiles"
    $ffProfile = Get-ChildItem -Path $ffProfileRoot -Filter "*.default-release" -Directory -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $ffProfile) {
        Record-Finding "SKIP" "browser-fingerprint" "No Firefox profile found"
        return
    }
    $userJs = Join-Path $ffProfile.FullName "user.js"
    if ((Test-Path $userJs) -and (Select-String -Path $userJs -Pattern "privacy.resistFingerprinting" -Quiet -ErrorAction SilentlyContinue)) {
        Record-Finding "PASS" "browser-fingerprint" "Firefox resistFingerprinting enabled"
    } else {
        Record-Finding "FAIL" "browser-fingerprint" "Firefox resistFingerprinting not set"
    }
}

function Check-guest-disable {
    try {
        $guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
        if ($null -eq $guest -or $guest.Enabled -eq $false) {
            Record-Finding "PASS" "guest-disable" "Guest account disabled"
        } else {
            Record-Finding "FAIL" "guest-disable" "Guest account is enabled"
        }
    } catch {
        Record-Finding "PASS" "guest-disable" "Guest account not found"
    }
}

function Check-lock-screen {
    $ssRegPath = "HKCU:\Control Panel\Desktop"
    $lock = (Get-ItemProperty -Path $ssRegPath -Name "ScreenSaverIsSecure" -ErrorAction SilentlyContinue).ScreenSaverIsSecure
    $timeout = (Get-ItemProperty -Path $ssRegPath -Name "ScreenSaveTimeOut" -ErrorAction SilentlyContinue).ScreenSaveTimeOut
    if ($lock -eq "1" -and $null -ne $timeout -and [int]$timeout -le 300) {
        Record-Finding "PASS" "lock-screen" "Screen locks after $([math]::Floor([int]$timeout/60)) min with password"
    } else {
        Record-Finding "FAIL" "lock-screen" "Screen lock not configured (timeout or password missing)"
    }
}

function Check-bluetooth-disable {
    $btService = Get-Service -Name "bthserv" -ErrorAction SilentlyContinue
    if (-not $btService) {
        Record-Finding "SKIP" "bluetooth-disable" "Bluetooth service not found"
        return
    }
    if ($btService.Status -eq "Stopped" -and $btService.StartType -eq "Disabled") {
        Record-Finding "PASS" "bluetooth-disable" "Bluetooth service disabled"
    } else {
        Record-Finding "FAIL" "bluetooth-disable" "Bluetooth service is $($btService.Status) ($($btService.StartType))"
    }
}

function Check-git-harden {
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
        Record-Finding "SKIP" "git-harden" "Git not installed"
        return
    }
    $signing = & git config --global --get commit.gpgsign 2>$null
    if ($signing -eq "true") {
        Record-Finding "PASS" "git-harden" "Git commit signing enabled"
    } else {
        Record-Finding "FAIL" "git-harden" "Git commit signing not enabled"
    }
}

function Check-dev-isolation {
    $wslInstalled = Get-Command wsl -ErrorAction SilentlyContinue
    $dockerDesktop = Get-Process "Docker Desktop" -ErrorAction SilentlyContinue
    if ($wslInstalled -or $dockerDesktop) {
        Record-Finding "MANUAL" "dev-isolation" "WSL/Docker present — verify isolation settings manually"
    } else {
        Record-Finding "SKIP" "dev-isolation" "WSL and Docker not detected"
    }
}

function Check-ssh-harden {
    $sshConfig = Join-Path $script:RealHome ".ssh\config"
    if (-not (Test-Path $sshConfig)) {
        Record-Finding "FAIL" "ssh-harden" "No SSH config file found"
        return
    }
    if (Select-String -Path $sshConfig -Pattern "IdentitiesOnly yes" -Quiet -ErrorAction SilentlyContinue) {
        Record-Finding "PASS" "ssh-harden" "SSH config has IdentitiesOnly yes"
    } else {
        Record-Finding "FAIL" "ssh-harden" "SSH config missing IdentitiesOnly yes"
    }
}

function Check-monitoring-tools {
    $sysmon = Get-Service -Name "Sysmon*" -ErrorAction SilentlyContinue
    if ($sysmon -and $sysmon.Status -eq "Running") {
        Record-Finding "PASS" "monitoring-tools" "Sysmon is running"
    } elseif ($sysmon) {
        Record-Finding "FAIL" "monitoring-tools" "Sysmon installed but not running"
    } else {
        Record-Finding "FAIL" "monitoring-tools" "Sysmon not installed"
    }
}

function Check-permissions-audit {
    Record-Finding "MANUAL" "permissions-audit" "Run permissions audit manually to review granted access"
}

function Check-audit-script {
    $task = Get-ScheduledTask -TaskName "SecurityWeeklyAudit" -ErrorAction SilentlyContinue
    if ($task) {
        Record-Finding "PASS" "audit-script" "Weekly audit task scheduled"
    } else {
        Record-Finding "FAIL" "audit-script" "Weekly audit task not found"
    }
}

function Check-auto-updates {
    try {
        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
        $current = Get-ItemProperty -Path $regPath -Name "NoAutoUpdate" -ErrorAction SilentlyContinue
        if ($null -eq $current -or $current.NoAutoUpdate -eq 0) {
            Record-Finding "PASS" "auto-updates" "Automatic updates enabled"
        } else {
            Record-Finding "FAIL" "auto-updates" "Automatic updates disabled via policy"
        }
    } catch {
        Record-Finding "PASS" "auto-updates" "No update restriction policy found"
    }
}

function Check-backup-guidance {
    Record-Finding "MANUAL" "backup-guidance" "Verify encrypted backup strategy is in place"
}

function Check-border-prep {
    Record-Finding "MANUAL" "border-prep" "Review travel protocol and nuke checklist"
}

# ═══════════════════════════════════════════════════════════════════
# AUDIT: DISPLAY
# ═══════════════════════════════════════════════════════════════════

function Print-FindingsTable {
    param([string[]]$ModList)
    if ($script:QuietMode) { return }

    Write-Host ""
    Write-Host ("  {0,-10} {1,-10} {2,-22} {3}" -f "Status", "Severity", "Module", "Finding") -ForegroundColor White
    Write-Host ("  {0,-10} {1,-10} {2,-22} {3}" -f "------", "--------", "--------------------", "-------") -ForegroundColor DarkYellow

    $sevOrder = @("CRITICAL", "HIGH", "MEDIUM", "LOW")

    foreach ($sev in $sevOrder) {
        foreach ($modId in $ModList) {
            if ($script:ModuleSeverity[$modId] -ne $sev) { continue }

            # Find this module's finding
            $idx = -1
            for ($i = 0; $i -lt $script:FindingsModule.Count; $i++) {
                if ($script:FindingsModule[$i] -eq $modId) { $idx = $i; break }
            }
            if ($idx -eq -1) { continue }

            $status = $script:FindingsStatus[$idx]
            $finding = $script:FindingsMessage[$idx]

            switch ($status) {
                "PASS"   { $icon = "✓"; $color = "Green" }
                "FAIL"   { $icon = "✗"; $color = "Red" }
                "MANUAL" { $icon = "~"; $color = "Red" }
                "SKIP"   { $icon = "○"; $color = "DarkYellow" }
                default  { $icon = "○"; $color = "DarkYellow" }
            }

            Write-Host "  " -NoNewline
            Write-Host ("{0,-10}" -f "$icon $status") -ForegroundColor $color -NoNewline
            Write-Host ("{0,-10} {1,-22} {2}" -f $sev, $modId, $finding)
        }
    }
    Write-Host ""
}

function Print-ScoreBar {
    param([int]$Pct)
    if ($script:QuietMode) { return }
    $width = 20
    $filled = [math]::Floor(($Pct * $width) / 100)
    $empty = $width - $filled
    $bar = ("█" * $filled) + ("░" * $empty)

    if ($Pct -ge 80) { $color = "Green" }
    elseif ($Pct -ge 50) { $color = "DarkYellow" }
    else { $color = "Red" }

    Write-Host "  Hardening Score: " -NoNewline -ForegroundColor White
    Write-Host "$Pct/100" -ForegroundColor $color -NoNewline
    Write-Host " [" -NoNewline
    Write-Host $bar -ForegroundColor $color -NoNewline
    Write-Host "]"
}

# ═══════════════════════════════════════════════════════════════════
# AUDIT: REPORT & ORCHESTRATION
# ═══════════════════════════════════════════════════════════════════

function Write-AuditReport {
    param([string[]]$ModList, [int]$Pct, [int]$AC, [int]$TC)
    New-Item -ItemType Directory -Path $script:AuditDir -Force | Out-Null
    $reportFile = Join-Path $script:AuditDir "audit-$($script:DATE).md"
    $sevOrder = @("CRITICAL", "HIGH", "MEDIUM", "LOW")

    $report = @()
    $report += "# Security Audit Report — $($script:DATE)"
    $report += ""
    $report += "**Hardening Score:** $Pct/100 — $AC of $TC modules passing"
    $report += "**OS:** Windows $([System.Environment]::OSVersion.Version)"
    $report += "**Profile scope:** all"
    $report += "**Generated:** $($script:TIMESTAMP)"
    $report += ""
    $report += "## Findings"
    $report += ""
    $report += "| Status | Severity | Module | Finding |"
    $report += "|--------|----------|--------|---------|"

    foreach ($sev in $sevOrder) {
        foreach ($modId in $ModList) {
            if ($script:ModuleSeverity[$modId] -ne $sev) { continue }
            $idx = -1
            for ($i = 0; $i -lt $script:FindingsModule.Count; $i++) {
                if ($script:FindingsModule[$i] -eq $modId) { $idx = $i; break }
            }
            if ($idx -eq -1) { continue }
            $status = $script:FindingsStatus[$idx]
            $finding = $script:FindingsMessage[$idx] -replace '\|', '\|'
            $report += "| $status | $sev | $modId | $finding |"
        }
    }

    $report += ""
    $report += "---"
    $report += "Generated by barked.ps1 v$($script:VERSION)"
    try {
        $report | Out-File -FilePath $reportFile -Encoding UTF8 -ErrorAction Stop
        Write-Host "  " -NoNewline
        Write-Color "Audit report saved: " Green
        Write-Host $reportFile
    } catch {
        Write-Host "  ERROR: Failed to write audit report to $reportFile" -ForegroundColor Red
    }
}

function Write-DryRunReport {
    New-Item -ItemType Directory -Path $script:AuditDir -Force | Out-Null
    $reportFile = Join-Path $script:AuditDir "dry-run-$($script:DATE).md"

    $report = @()
    $report += "# Dry Run Report — $($script:DATE)"
    $report += ""
    $report += "**Profile:** $($script:Profile)"
    $report += "**OS:** Windows $([System.Environment]::OSVersion.Version)"
    $report += "**Generated:** $($script:TIMESTAMP)"
    $report += ""
    $report += "## Summary"
    $report += ""
    $report += "| Status | Count |"
    $report += "|--------|-------|"
    $report += "| Would apply | $($script:CountApplied) |"
    $report += "| Already applied (skip) | $($script:CountSkipped) |"
    $report += "| Would fail | $($script:CountFailed) |"
    $report += "| Manual steps | $($script:CountManual) |"
    $report += ""
    $report += "## Module Details"
    $report += ""
    $report += '```'
    foreach ($entry in $script:LogEntries) {
        $report += $entry
    }
    $report += '```'
    $report += ""
    $report += "---"
    $report += "Generated by barked.ps1 v$($script:VERSION) (dry-run mode)"

    try {
        $report | Out-File -FilePath $reportFile -Encoding UTF8 -ErrorAction Stop
        if (-not $script:QuietMode) {
            Write-Host ""
            Write-Host "  " -NoNewline
            Write-Color "Dry Run Summary:" White
            Write-Host ""
            Write-Host "    Would apply:  " -NoNewline
            Write-ColorLine "$($script:CountApplied)" White
            Write-Host "    Already done: $($script:CountSkipped)"
            Write-Host ""
            Write-Host "  " -NoNewline
            Write-Color "Dry run report saved: " Green
            Write-Host $reportFile
        }
    } catch {
        Write-Host "  ERROR: Failed to write dry-run report to $reportFile" -ForegroundColor Red
    }
}

function Run-Audit {
    $auditMods = $script:AllModuleIds

    # Clear findings
    $script:FindingsStatus = @()
    $script:FindingsModule = @()
    $script:FindingsMessage = @()

    # Run check on each module
    foreach ($modId in $auditMods) {
        $fnName = "Check-$modId"
        if (Get-Command $fnName -ErrorAction SilentlyContinue) {
            & $fnName
        } else {
            Record-Finding "SKIP" $modId "No check function available"
        }
    }

    # Separate applicable from skipped, and passing from rest
    $applicableMods = @()
    $passingMods = @()
    for ($i = 0; $i -lt $script:FindingsModule.Count; $i++) {
        $status = $script:FindingsStatus[$i]
        $mod = $script:FindingsModule[$i]
        if ($status -ne "SKIP") {
            $applicableMods += $mod
            if ($status -eq "PASS") { $passingMods += $mod }
        }
    }

    # Calculate score
    $score = Calculate-Score $applicableMods $passingMods

    # Display
    Print-Section "Security Audit Report"
    Print-FindingsTable $auditMods
    Print-ScoreBar $score.Percentage
    Write-Host "  $($score.AppliedCount) of $($score.TotalCount) modules passing" -ForegroundColor DarkYellow
    Write-Host ""

    # Write report
    Write-AuditReport $auditMods $score.Percentage $score.AppliedCount $score.TotalCount
}

# ═══════════════════════════════════════════════════════════════════
# PACKAGE UNINSTALL HELPER
# ═══════════════════════════════════════════════════════════════════
function Uninstall-Pkg {
    param([string]$WingetId, [string]$ChocoName, [string]$ScoopName)
    $mgr = Get-PkgManager
    switch ($mgr) {
        "winget" { winget uninstall --id $WingetId --silent 2>$null }
        "choco"  { choco uninstall $ChocoName -y 2>$null }
        "scoop"  { scoop uninstall $ScoopName 2>$null }
        default  { return $false }
    }
    return $true
}

# ═══════════════════════════════════════════════════════════════════
# INTERACTIVE MODULE PICKER (arrow-key / spacebar)
# ═══════════════════════════════════════════════════════════════════
$script:AllModuleIds = @(
    "disk-encrypt", "firewall-inbound", "firewall-stealth", "firewall-outbound",
    "dns-secure", "vpn-killswitch", "hostname-scrub",
    "mac-rotate", "telemetry-disable", "traffic-obfuscation", "metadata-strip",
    "browser-basic", "browser-fingerprint",
    "guest-disable", "lock-screen", "bluetooth-disable",
    "git-harden", "dev-isolation",
    "ssh-harden",
    "monitoring-tools", "permissions-audit", "audit-script",
    "auto-updates", "backup-guidance", "border-prep"
)

$script:AllModuleLabels = @(
    "disk-encrypt        - BitLocker verification"
    "firewall-inbound    - Block all incoming connections"
    "firewall-stealth    - Stealth mode / drop ICMP"
    "firewall-outbound   - Outbound firewall (WF rules)"
    "dns-secure          - Encrypted DNS (Quad9)"
    "vpn-killswitch      - VPN always-on, block non-VPN traffic"
    "hostname-scrub      - Generic hostname"
    "mac-rotate          - MAC address randomization"
    "telemetry-disable   - OS and browser telemetry off"
    "traffic-obfuscation - DAITA, Tor guidance"
    "metadata-strip      - exiftool"
    "browser-basic       - Block trackers, HTTPS-only"
    "browser-fingerprint - Resist fingerprinting, clear-on-quit"
    "guest-disable       - Disable guest account"
    "lock-screen         - Screen timeout, password required"
    "bluetooth-disable   - Disable when unused"
    "git-harden          - SSH signing, credential helper"
    "dev-isolation       - Docker/WSL hardening"
    "ssh-harden          - Ed25519 keys, strict config"
    "monitoring-tools    - Sysmon / audit policy"
    "permissions-audit   - List granted permissions"
    "audit-script        - Weekly automated audit"
    "auto-updates        - Automatic security updates"
    "backup-guidance     - Encrypted backup strategy"
    "border-prep         - Travel protocol, nuke checklist"
)

# Category groups: name, startIndex, count
$script:AllModuleGroups = @(
    @{ name = "DISK & BOOT";           start = 0;  count = 1 }
    @{ name = "FIREWALL";              start = 1;  count = 3 }
    @{ name = "NETWORK & DNS";         start = 4;  count = 3 }
    @{ name = "PRIVACY & OBFUSCATION"; start = 7;  count = 4 }
    @{ name = "BROWSER";               start = 11; count = 2 }
    @{ name = "ACCESS CONTROL";        start = 13; count = 3 }
    @{ name = "DEV TOOLS";             start = 16; count = 2 }
    @{ name = "AUTH & SSH";            start = 18; count = 1 }
    @{ name = "MONITORING";            start = 19; count = 3 }
    @{ name = "MAINTENANCE";           start = 22; count = 3 }
)

function Interactive-Picker {
    # Build display list: items with category headers
    # Returns two arrays: $script:PickerAdd (modules to add) and $script:PickerRemove (modules to remove)
    $script:PickerAdd = @()
    $script:PickerRemove = @()

    $total = $script:AllModuleIds.Count
    $checked = @{}
    $originalState = @{}

    # Initialize from current state
    for ($i = 0; $i -lt $total; $i++) {
        $modId = $script:AllModuleIds[$i]
        $isApplied = $script:StateData.modules.ContainsKey($modId) -and $script:StateData.modules[$modId].status -eq "applied"
        $checked[$i] = $isApplied
        $originalState[$i] = $isApplied
    }

    # Build display lines (headers + items)
    $displayLines = @()   # Each: @{ type="header"|"item"; text="..."; itemIndex=-1|N }
    foreach ($group in $script:AllModuleGroups) {
        $displayLines += @{ type = "header"; text = "  $($group.name)"; itemIndex = -1 }
        for ($j = $group.start; $j -lt ($group.start + $group.count); $j++) {
            $displayLines += @{ type = "item"; text = $script:AllModuleLabels[$j]; itemIndex = $j }
        }
    }

    $cursorPos = 0
    # Find first selectable item
    while ($cursorPos -lt $displayLines.Count -and $displayLines[$cursorPos].type -ne "item") { $cursorPos++ }

    # Print header
    Write-Host ""
    Write-ColorLine "═══ Modify Hardening ═══" Green
    Write-Host ""
    Write-ColorLine "  Use ↑↓ to navigate, SPACE to toggle, ENTER to apply changes, Q to cancel." DarkYellow
    Write-ColorLine "  Modules marked [✓] are currently applied." DarkYellow
    Write-Host ""

    $startRow = [Console]::CursorTop

    # Draw initial list
    function Draw-List {
        [Console]::SetCursorPosition(0, $startRow)
        for ($d = 0; $d -lt $displayLines.Count; $d++) {
            $line = $displayLines[$d]
            if ($line.type -eq "header") {
                Write-Host ""
                $isSelected = ($d -eq $cursorPos)
                if ($isSelected) {
                    Write-Host "  " -NoNewline
                    Write-ColorLine $line.text Green
                } else {
                    Write-Host "  " -NoNewline
                    Write-ColorLine $line.text Red
                }
            } else {
                $idx = $line.itemIndex
                $isSelected = ($d -eq $cursorPos)
                $mark = if ($checked[$idx]) { "[✓]" } else { "[ ]" }
                $markColor = if ($checked[$idx]) { "Green" } else { "DarkYellow" }

                if ($isSelected) {
                    Write-Host "  > " -NoNewline -ForegroundColor Green
                    Write-Color $mark $markColor
                    Write-Host " $($line.text)" -ForegroundColor Green
                } else {
                    Write-Host "    " -NoNewline
                    Write-Color $mark $markColor
                    Write-Host " $($line.text)" -ForegroundColor Gray
                }
            }
        }
        Write-Host ""
        Write-Host "                                                                              "
    }

    Draw-List

    # Input loop
    while ($true) {
        $key = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

        if ($key.VirtualKeyCode -eq 38) {
            # Up arrow
            $prev = $cursorPos - 1
            while ($prev -ge 0 -and $displayLines[$prev].type -ne "item") { $prev-- }
            if ($prev -ge 0) { $cursorPos = $prev }
            Draw-List
        }
        elseif ($key.VirtualKeyCode -eq 40) {
            # Down arrow
            $next = $cursorPos + 1
            while ($next -lt $displayLines.Count -and $displayLines[$next].type -ne "item") { $next++ }
            if ($next -lt $displayLines.Count) { $cursorPos = $next }
            Draw-List
        }
        elseif ($key.Character -eq ' ') {
            # Space — toggle
            if ($displayLines[$cursorPos].type -eq "item") {
                $idx = $displayLines[$cursorPos].itemIndex
                $checked[$idx] = -not $checked[$idx]
            }
            Draw-List
        }
        elseif ($key.VirtualKeyCode -eq 13) {
            # Enter — apply changes
            break
        }
        elseif ($key.Character -eq 'q' -or $key.Character -eq 'Q') {
            # Cancel
            Write-Host ""
            Write-ColorLine "  Cancelled." Red
            return $false
        }
    }

    # Compute adds and removes
    for ($i = 0; $i -lt $total; $i++) {
        if ($checked[$i] -and -not $originalState[$i]) {
            $script:PickerAdd += $script:AllModuleIds[$i]
        }
        elseif (-not $checked[$i] -and $originalState[$i]) {
            $script:PickerRemove += $script:AllModuleIds[$i]
        }
    }
    return $true
}

# ═══════════════════════════════════════════════════════════════════
# PRIVILEGE MANAGEMENT
# ═══════════════════════════════════════════════════════════════════
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
    if ($Clean) { $argList += '-Clean' }
    if ($Force) { $argList += '-Force' }
    if ($DryRun) { $argList += '-DryRun' }
    if ($Help) { $argList += '-Help' }
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
    Write-ColorLine "Select a hardening profile:" Green
    Write-Host ""
    Write-Host "  " -NoNewline; Write-Color "[1] Green; Write-Host " Standard  — Encrypted disk, firewall, secure DNS, auto-updates, basic browser hardening"
    Write-Host "  " -NoNewline; Write-Color "[2] Green; Write-Host " High      — Standard + outbound firewall, hostname scrubbing, monitoring tools, SSH hardening, telemetry disabled"
    Write-Host "  " -NoNewline; Write-Color "[3] Green; Write-Host " Paranoid  — High + MAC rotation, traffic obfuscation, VPN kill switch, full audit system, metadata stripping, border crossing prep"
    Write-Host "  " -NoNewline; Write-Color "[4] Green; Write-Host " Advanced  — Custom questionnaire (choose per-category)"
    Write-Host ""
    Write-Host "  " -NoNewline; Write-Color "[M]" Magenta; Write-Host " Modify    — Add or remove individual modules"
    Write-Host "  " -NoNewline; Write-Color "[U]" Red;     Write-Host " Uninstall — Remove all hardening changes"
    Write-Host "  " -NoNewline; Write-Color "[Q]" DarkYellow; Write-Host " Quit"
    Write-Host ""
    while ($true) {
        Write-Host "  Choice: " -NoNewline -ForegroundColor Green
        $choice = Read-Host
        switch ($choice) {
            "1" { $script:Profile = "standard"; break }
            "2" { $script:Profile = "high"; break }
            "3" { $script:Profile = "paranoid"; break }
            "4" { $script:Profile = "advanced"; Run-Questionnaire; break }
            { $_ -eq "M" -or $_ -eq "m" } { $script:RunMode = "modify"; return }
            { $_ -eq "U" -or $_ -eq "u" } { $script:RunMode = "uninstall"; return }
            { $_ -eq "Q" -or $_ -eq "q" } { Write-Host "Exiting."; exit 0 }
            default { Write-ColorLine "  Invalid choice. Enter 1-4, M, U, or Q." Red; continue }
        }
        break
    }
    Write-Host ""
    Write-Host "  Profile: " -NoNewline; Write-ColorLine $script:Profile Green
}

# ═══════════════════════════════════════════════════════════════════
# WIZARD: ADVANCED QUESTIONNAIRE
# ═══════════════════════════════════════════════════════════════════
function Run-Questionnaire {
    Print-Section "Advanced Questionnaire"
    Write-ColorLine "  Answer 8 questions to build a custom hardening profile." DarkYellow
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
    Write-Host "  Output mode: " -NoNewline; Write-ColorLine $script:OutputMode Green
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
    param([string]$ModId, [string]$Mode = "apply")
    $script:CurrentModule++
    $script:ModuleMode = $Mode

    # Dry-run guard: run check instead of apply
    if ($DryRun -and $Mode -eq "apply") {
        $checkFunc = "Check-$ModId"
        if (Get-Command $checkFunc -ErrorAction SilentlyContinue) {
            & $checkFunc
        }
        # Find this module's finding
        $idx = -1
        for ($i = 0; $i -lt $script:FindingsModule.Count; $i++) {
            if ($script:FindingsModule[$i] -eq $ModId) { $idx = $i; break }
        }
        $status = if ($idx -ge 0) { $script:FindingsStatus[$idx] } else { "SKIP" }
        $finding = if ($idx -ge 0) { $script:FindingsMessage[$idx] } else { "No check function" }
        $sev = if ($script:ModuleSeverity[$ModId]) { $script:ModuleSeverity[$ModId] } else { "LOW" }

        if (-not $script:QuietMode) {
            Write-Host ""
            Write-Host "  " -NoNewline
            Write-Color "[DRY RUN]" Green
            Write-Host " $ModId" -ForegroundColor White
            Write-Host "    Current:  $finding"
            if ($status -eq "PASS") {
                Write-Host "    Planned:  " -NoNewline
                Write-ColorLine "No change needed" DarkYellow
            } else {
                Write-Host "    Planned:  " -NoNewline
                Write-ColorLine "Would apply hardening" DarkYellow
            }
            Write-Host "    Severity: $sev"
        }

        Log-Entry $ModId "dry-run" $status $finding

        if ($status -eq "PASS") {
            $script:ModuleResult = "skipped"
        } else {
            $script:ModuleResult = "applied"
        }
        switch ($script:ModuleResult) {
            "applied" { $script:CountApplied++ }
            "skipped" { $script:CountSkipped++ }
        }
        return
    }

    if ($Mode -eq "revert") {
        $funcName = "Revert-$($ModId)"
        if (Get-Command $funcName -ErrorAction SilentlyContinue) {
            & $funcName
        } else {
            Print-Status $script:CurrentModule $script:TotalModules $ModId "skipped"
            $script:ModuleResult = "skipped"
        }
    } else {
        $funcName = "Mod-$($ModId)"
        if (Get-Command $funcName -ErrorAction SilentlyContinue) {
            & $funcName
        } else {
            $script:ModuleResult = "skipped_unsupported"
        }
    }

    switch ($script:ModuleResult) {
        "applied"  {
            $script:CountApplied++
            if ($Mode -eq "apply") {
                # Only set state if the module didn't already set it (with previous_value)
                if (-not $script:StateData.modules.ContainsKey($ModId) -or $script:StateData.modules[$ModId].status -ne "applied") {
                    Set-ModuleState $ModId "applied"
                }
            }
        }
        "reverted" { $script:CountReverted++; Set-ModuleState $ModId "reverted" }
        "skipped"  { $script:CountSkipped++ }
        "failed"   { $script:CountFailed++ }
        "manual"   { $script:CountManual++ }
        "skipped_unsupported" { $script:CountSkipped++ }
    }
}

function Run-AllModules {
    if (-not $script:QuietMode) {
        if ($DryRun) {
            Print-Section "Dry Run Preview ($($script:TotalModules) modules)"
        } else {
            Print-Section "Applying Hardening ($($script:TotalModules) modules)"
        }
    }
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
        # Capture previous DNS for state
        $prevDns = @()
        foreach ($adapter in $adapters) {
            $dns = Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
            if ($dns.ServerAddresses) { $prevDns += ($dns.ServerAddresses -join ",") }
        }
        $prevDnsStr = ($prevDns | Select-Object -Unique) -join ";"
        Set-ModuleState "dns-secure" "applied" $prevDnsStr

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

        $prevTimeout = if ($currentTimeout) { $currentTimeout } else { "600" }
        $prevLock = if ($currentLock) { $currentLock } else { "0" }
        Set-ModuleState "lock-screen" "applied" "$prevTimeout,$prevLock"

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
        Set-ModuleState "hostname-scrub" "applied" $current
        Rename-Computer -NewName $generic -Force -ErrorAction Stop
        Print-Status $script:CurrentModule $script:TotalModules "$desc ($generic — reboot required)" "applied"
        Log-Entry "hostname-scrub" "apply" "ok" "Hostname set to $generic (was: $current, reboot required)"
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
        Add-StatePackage "exiftool"
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
# REVERT FUNCTIONS
# ═══════════════════════════════════════════════════════════════════
function Revert-disk-encrypt {
    $desc = "Revert disk encryption"
    Print-Status $script:CurrentModule $script:TotalModules $desc "manual"
    Log-Entry "disk-encrypt" "revert" "manual" "Disk decryption is a major decision — not auto-reverted"
    $script:ManualSteps += "Disable BitLocker: manage-bde -off C: (this will decrypt the entire drive)"
    $script:ModuleResult = "manual"
}

function Revert-firewall-inbound {
    $desc = "Revert inbound firewall"
    try {
        Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Allow -ErrorAction Stop
        Print-Status $script:CurrentModule $script:TotalModules $desc "reverted"
        Log-Entry "firewall-inbound" "revert" "ok" "Default inbound set to Allow"
        $script:ModuleResult = "reverted"
    } catch {
        Print-Status $script:CurrentModule $script:TotalModules $desc "failed"
        Log-Entry "firewall-inbound" "revert" "fail" "Could not revert firewall: $_"
        $script:ModuleResult = "failed"
    }
}

function Revert-firewall-stealth {
    $desc = "Revert firewall stealth mode"
    try {
        Remove-NetFirewallRule -DisplayName "Harden-Block-ICMPv4-In" -ErrorAction SilentlyContinue
        Remove-NetFirewallRule -DisplayName "Harden-Block-ICMPv6-In" -ErrorAction SilentlyContinue
        # Re-enable LLMNR
        $llmnrPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
        Remove-ItemProperty -Path $llmnrPath -Name "EnableMulticast" -ErrorAction SilentlyContinue
        Print-Status $script:CurrentModule $script:TotalModules $desc "reverted"
        Log-Entry "firewall-stealth" "revert" "ok" "Removed ICMP block rules + re-enabled LLMNR"
        $script:ModuleResult = "reverted"
    } catch {
        Print-Status $script:CurrentModule $script:TotalModules $desc "failed"
        Log-Entry "firewall-stealth" "revert" "fail" "Could not revert stealth: $_"
        $script:ModuleResult = "failed"
    }
}

function Revert-firewall-outbound {
    $desc = "Revert outbound firewall"
    try {
        Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Allow -ErrorAction Stop
        # Remove Harden-Allow-Out rules
        Get-NetFirewallRule -DisplayName "Harden-Allow-Out-*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
        Print-Status $script:CurrentModule $script:TotalModules $desc "reverted"
        Log-Entry "firewall-outbound" "revert" "ok" "Default outbound set to Allow, removed allow rules"
        $script:ModuleResult = "reverted"
    } catch {
        Print-Status $script:CurrentModule $script:TotalModules $desc "failed"
        Log-Entry "firewall-outbound" "revert" "fail" "Could not revert outbound firewall: $_"
        $script:ModuleResult = "failed"
    }
}

function Revert-dns-secure {
    $desc = "Revert DNS settings"
    try {
        $prev = $null
        if ($script:StateData.modules.ContainsKey("dns-secure")) {
            $prev = $script:StateData.modules["dns-secure"].previous_value
        }
        $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
        foreach ($adapter in $adapters) {
            if ($prev -and $prev -ne "") {
                # Restore previous DNS
                $dnsServers = ($prev -split ";")[0] -split ","
                Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses $dnsServers -ErrorAction Stop
            } else {
                # Reset to DHCP
                Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ResetServerAddresses -ErrorAction Stop
            }
        }
        # Remove DoH entries
        try {
            Remove-DnsClientDohServerAddress -ServerAddress "9.9.9.9" -ErrorAction SilentlyContinue
            Remove-DnsClientDohServerAddress -ServerAddress "149.112.112.112" -ErrorAction SilentlyContinue
        } catch {}
        $detail = if ($prev) { "to $prev" } else { "to DHCP" }
        Print-Status $script:CurrentModule $script:TotalModules "$desc ($detail)" "reverted"
        Log-Entry "dns-secure" "revert" "ok" "DNS reverted $detail"
        $script:ModuleResult = "reverted"
    } catch {
        Print-Status $script:CurrentModule $script:TotalModules $desc "failed"
        Log-Entry "dns-secure" "revert" "fail" "Could not revert DNS: $_"
        $script:ModuleResult = "failed"
    }
}

function Revert-auto-updates {
    $desc = "Revert automatic updates"
    # Windows auto-updates are on by default; reverting means removing any policy we set
    try {
        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
        Remove-ItemProperty -Path $regPath -Name "NoAutoUpdate" -ErrorAction SilentlyContinue
        Print-Status $script:CurrentModule $script:TotalModules $desc "reverted"
        Log-Entry "auto-updates" "revert" "ok" "Removed update policy override (default behavior restored)"
        $script:ModuleResult = "reverted"
    } catch {
        Print-Status $script:CurrentModule $script:TotalModules $desc "reverted"
        Log-Entry "auto-updates" "revert" "ok" "No policy to remove"
        $script:ModuleResult = "reverted"
    }
}

function Revert-guest-disable {
    $desc = "Re-enable Guest account"
    try {
        Enable-LocalUser -Name "Guest" -ErrorAction Stop
        Print-Status $script:CurrentModule $script:TotalModules $desc "reverted"
        Log-Entry "guest-disable" "revert" "ok" "Guest account re-enabled"
        $script:ModuleResult = "reverted"
    } catch {
        Print-Status $script:CurrentModule $script:TotalModules $desc "failed"
        Log-Entry "guest-disable" "revert" "fail" "Could not re-enable Guest: $_"
        $script:ModuleResult = "failed"
    }
}

function Revert-lock-screen {
    $desc = "Revert lock screen settings"
    try {
        $ssRegPath = "HKCU:\Control Panel\Desktop"
        $prev = $null
        if ($script:StateData.modules.ContainsKey("lock-screen")) {
            $prev = $script:StateData.modules["lock-screen"].previous_value
        }
        if ($prev -and $prev -match ",") {
            $parts = $prev -split ","
            Set-ItemProperty -Path $ssRegPath -Name "ScreenSaveTimeOut" -Value $parts[0] -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $ssRegPath -Name "ScreenSaverIsSecure" -Value $parts[1] -ErrorAction SilentlyContinue
        } else {
            # OS defaults
            Set-ItemProperty -Path $ssRegPath -Name "ScreenSaveTimeOut" -Value "600" -ErrorAction SilentlyContinue
            Set-ItemProperty -Path $ssRegPath -Name "ScreenSaverIsSecure" -Value "0" -ErrorAction SilentlyContinue
        }
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "InactivityTimeoutSecs" -ErrorAction SilentlyContinue
        Print-Status $script:CurrentModule $script:TotalModules $desc "reverted"
        Log-Entry "lock-screen" "revert" "ok" "Lock screen settings restored"
        $script:ModuleResult = "reverted"
    } catch {
        Print-Status $script:CurrentModule $script:TotalModules $desc "failed"
        Log-Entry "lock-screen" "revert" "fail" "Could not revert lock screen: $_"
        $script:ModuleResult = "failed"
    }
}

function Revert-browser-basic {
    $desc = "Revert basic browser hardening"
    try {
        # Remove Firefox user.js (basic prefs)
        $ffProfileRoot = Join-Path $script:RealHome "AppData\Roaming\Mozilla\Firefox\Profiles"
        $ffProfile = Get-ChildItem -Path $ffProfileRoot -Filter "*.default-release" -Directory -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($ffProfile) {
            $userJs = Join-Path $ffProfile.FullName "user.js"
            if (Test-Path $userJs) {
                # Remove only if it starts with our marker
                $content = Get-Content $userJs -Raw -ErrorAction SilentlyContinue
                if ($content -match "Firefox Hardening") {
                    Remove-Item $userJs -Force -ErrorAction SilentlyContinue
                }
            }
        }
        # Remove Edge policies
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "TrackingPrevention" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "AutomaticHttpsDefault" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "SmartScreenEnabled" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "PasswordManagerEnabled" -ErrorAction SilentlyContinue
        # Remove Chrome policies
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "AutomaticHttpsDefault" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "SafeBrowsingProtectionLevel" -ErrorAction SilentlyContinue
        Print-Status $script:CurrentModule $script:TotalModules $desc "reverted"
        Log-Entry "browser-basic" "revert" "ok" "Removed Firefox user.js + Edge/Chrome policies"
        $script:ModuleResult = "reverted"
    } catch {
        Print-Status $script:CurrentModule $script:TotalModules $desc "failed"
        Log-Entry "browser-basic" "revert" "fail" "Could not revert browser: $_"
        $script:ModuleResult = "failed"
    }
}

function Revert-hostname-scrub {
    $desc = "Revert hostname"
    $prev = $null
    if ($script:StateData.modules.ContainsKey("hostname-scrub")) {
        $prev = $script:StateData.modules["hostname-scrub"].previous_value
    }
    if (-not $prev -or $prev -eq "") {
        Print-Status $script:CurrentModule $script:TotalModules "$desc (no previous hostname stored)" "manual"
        Log-Entry "hostname-scrub" "revert" "manual" "No previous hostname in state"
        $script:ManualSteps += "Rename computer back to desired hostname: Rename-Computer -NewName 'YOUR-NAME' -Force"
        $script:ModuleResult = "manual"
        return
    }
    try {
        Rename-Computer -NewName $prev -Force -ErrorAction Stop
        Print-Status $script:CurrentModule $script:TotalModules "$desc (to $prev — reboot required)" "reverted"
        Log-Entry "hostname-scrub" "revert" "ok" "Hostname set to $prev (reboot required)"
        $script:ModuleResult = "reverted"
    } catch {
        Print-Status $script:CurrentModule $script:TotalModules $desc "failed"
        Log-Entry "hostname-scrub" "revert" "fail" "Could not rename computer: $_"
        $script:ModuleResult = "failed"
    }
}

function Revert-ssh-harden {
    $desc = "Revert SSH configuration"
    try {
        $sshConfig = Join-Path $script:RealHome ".ssh\config"
        if (Test-Path $sshConfig) {
            Remove-Item $sshConfig -Force -ErrorAction Stop
        }
        Print-Status $script:CurrentModule $script:TotalModules $desc "reverted"
        Log-Entry "ssh-harden" "revert" "ok" "Removed hardened SSH config"
        $script:ModuleResult = "reverted"
    } catch {
        Print-Status $script:CurrentModule $script:TotalModules $desc "failed"
        Log-Entry "ssh-harden" "revert" "fail" "Could not revert SSH config: $_"
        $script:ModuleResult = "failed"
    }
}

function Revert-git-harden {
    $desc = "Revert Git configuration"
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
        Print-Status $script:CurrentModule $script:TotalModules $desc "skipped"
        $script:ModuleResult = "skipped"
        return
    }
    try {
        & git config --global --unset gpg.format 2>$null
        & git config --global --unset user.signingkey 2>$null
        & git config --global --unset commit.gpgsign 2>$null
        & git config --global --unset tag.gpgsign 2>$null
        Print-Status $script:CurrentModule $script:TotalModules $desc "reverted"
        Log-Entry "git-harden" "revert" "ok" "Removed Git signing + credential config"
        $script:ModuleResult = "reverted"
    } catch {
        Print-Status $script:CurrentModule $script:TotalModules $desc "failed"
        Log-Entry "git-harden" "revert" "fail" "Could not revert Git config: $_"
        $script:ModuleResult = "failed"
    }
}

function Revert-telemetry-disable {
    $desc = "Re-enable Windows telemetry"
    try {
        # Remove telemetry policy
        $telPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
        Remove-ItemProperty -Path $telPath -Name "AllowTelemetry" -ErrorAction SilentlyContinue
        # Re-enable DiagTrack
        Set-Service -Name "DiagTrack" -StartupType Automatic -ErrorAction SilentlyContinue
        Start-Service -Name "DiagTrack" -ErrorAction SilentlyContinue
        # Re-enable WAP Push
        Set-Service -Name "dmwappushservice" -StartupType Automatic -ErrorAction SilentlyContinue
        Start-Service -Name "dmwappushservice" -ErrorAction SilentlyContinue
        # Re-enable Advertising ID
        $adIdPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo"
        Remove-ItemProperty -Path $adIdPath -Name "DisabledByGroupPolicy" -ErrorAction SilentlyContinue
        # Re-enable activity history
        $actPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
        Remove-ItemProperty -Path $actPath -Name "EnableActivityFeed" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $actPath -Name "PublishUserActivities" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $actPath -Name "UploadUserActivities" -ErrorAction SilentlyContinue
        # Re-enable Cortana
        $cortanaPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
        Remove-ItemProperty -Path $cortanaPath -Name "AllowCortana" -ErrorAction SilentlyContinue
        Print-Status $script:CurrentModule $script:TotalModules $desc "reverted"
        Log-Entry "telemetry-disable" "revert" "ok" "Re-enabled telemetry, DiagTrack, advertising, Cortana"
        $script:ModuleResult = "reverted"
    } catch {
        Print-Status $script:CurrentModule $script:TotalModules $desc "failed"
        Log-Entry "telemetry-disable" "revert" "fail" "Could not re-enable telemetry: $_"
        $script:ModuleResult = "failed"
    }
}

function Revert-monitoring-tools {
    $desc = "Revert monitoring tools"
    try {
        # Revert audit policies to defaults
        & auditpol /set /subcategory:"Logon" /success:disable /failure:disable 2>$null
        & auditpol /set /subcategory:"Logoff" /success:disable 2>$null
        & auditpol /set /subcategory:"Account Lockout" /success:disable /failure:disable 2>$null
        & auditpol /set /subcategory:"Other Logon/Logoff Events" /success:disable /failure:disable 2>$null
        & auditpol /set /subcategory:"Process Creation" /success:disable 2>$null
        & auditpol /set /subcategory:"Credential Validation" /success:disable /failure:disable 2>$null
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -ErrorAction SilentlyContinue
        # Sysmon removal is manual
        $sysmon = Get-Service -Name "Sysmon*" -ErrorAction SilentlyContinue
        if ($sysmon) {
            $script:ManualSteps += "Uninstall Sysmon: sysmon -u from an elevated prompt"
        }
        Print-Status $script:CurrentModule $script:TotalModules $desc "reverted"
        Log-Entry "monitoring-tools" "revert" "ok" "Reverted audit policies"
        $script:ModuleResult = "reverted"
    } catch {
        Print-Status $script:CurrentModule $script:TotalModules $desc "failed"
        Log-Entry "monitoring-tools" "revert" "fail" "Could not revert monitoring: $_"
        $script:ModuleResult = "failed"
    }
}

function Revert-permissions-audit {
    $desc = "Revert permissions audit"
    Print-Status $script:CurrentModule $script:TotalModules "$desc (read-only, nothing to revert)" "skipped"
    Log-Entry "permissions-audit" "revert" "skip" "Read-only audit, nothing to revert"
    $script:ModuleResult = "skipped"
}

function Revert-mac-rotate {
    $desc = "Revert MAC address randomization"
    Print-Status $script:CurrentModule $script:TotalModules $desc "manual"
    Log-Entry "mac-rotate" "revert" "manual" "GUI setting, not script-managed"
    $script:ManualSteps += "Disable MAC randomization: Settings > Network & Internet > Wi-Fi > Random hardware addresses: set to Off"
    $script:ModuleResult = "manual"
}

function Revert-vpn-killswitch {
    $desc = "Revert VPN kill switch"
    $mullvad = Get-Command mullvad -ErrorAction SilentlyContinue
    if ($mullvad) {
        try {
            & mullvad always-require-vpn set off 2>$null
            Print-Status $script:CurrentModule $script:TotalModules "$desc (Mullvad)" "reverted"
            Log-Entry "vpn-killswitch" "revert" "ok" "Mullvad always-require-vpn disabled"
            $script:ModuleResult = "reverted"
        } catch {
            Print-Status $script:CurrentModule $script:TotalModules $desc "failed"
            Log-Entry "vpn-killswitch" "revert" "fail" "Mullvad CLI error: $_"
            $script:ModuleResult = "failed"
        }
    } else {
        Print-Status $script:CurrentModule $script:TotalModules $desc "manual"
        Log-Entry "vpn-killswitch" "revert" "manual" "VPN app configuration, not script-managed"
        $script:ManualSteps += "Disable VPN kill switch in your VPN application settings"
        $script:ModuleResult = "manual"
    }
}

function Revert-traffic-obfuscation {
    $desc = "Revert traffic obfuscation"
    Print-Status $script:CurrentModule $script:TotalModules "$desc (guidance-only, nothing to revert)" "skipped"
    Log-Entry "traffic-obfuscation" "revert" "skip" "Guidance-only module"
    $script:ModuleResult = "skipped"
}

function Revert-browser-fingerprint {
    $desc = "Revert browser fingerprint resistance"
    try {
        $ffProfileRoot = Join-Path $script:RealHome "AppData\Roaming\Mozilla\Firefox\Profiles"
        $ffProfile = Get-ChildItem -Path $ffProfileRoot -Filter "*.default-release" -Directory -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($ffProfile) {
            $userJs = Join-Path $ffProfile.FullName "user.js"
            if (Test-Path $userJs) {
                $content = Get-Content $userJs -Raw
                # Remove fingerprint resistance block
                $content = $content -replace "(?s)// Advanced Fingerprint Resistance.*?$", ""
                if ($content.Trim() -eq "") {
                    Remove-Item $userJs -Force -ErrorAction SilentlyContinue
                } else {
                    Set-Content -Path $userJs -Value $content.TrimEnd() -Encoding UTF8
                }
            }
        }
        Print-Status $script:CurrentModule $script:TotalModules $desc "reverted"
        Log-Entry "browser-fingerprint" "revert" "ok" "Removed fingerprint resistance from user.js"
        $script:ModuleResult = "reverted"
    } catch {
        Print-Status $script:CurrentModule $script:TotalModules $desc "failed"
        Log-Entry "browser-fingerprint" "revert" "fail" "Could not revert fingerprint settings: $_"
        $script:ModuleResult = "failed"
    }
}

function Revert-metadata-strip {
    $desc = "Revert metadata stripping tools"
    if ($script:RemovePackages -and (Get-Command exiftool -ErrorAction SilentlyContinue)) {
        Uninstall-Pkg "OliverBetz.ExifTool" "exiftool" "exiftool"
        Remove-StatePackage "exiftool"
        Print-Status $script:CurrentModule $script:TotalModules "$desc (exiftool removed)" "reverted"
        Log-Entry "metadata-strip" "revert" "ok" "Uninstalled exiftool"
        $script:ModuleResult = "reverted"
    } else {
        Print-Status $script:CurrentModule $script:TotalModules "$desc (kept exiftool)" "reverted"
        Log-Entry "metadata-strip" "revert" "ok" "Settings reverted, tools kept"
        $script:ModuleResult = "reverted"
    }
}

function Revert-dev-isolation {
    $desc = "Revert development isolation"
    Print-Status $script:CurrentModule $script:TotalModules "$desc (guidance-only, nothing to revert)" "skipped"
    Log-Entry "dev-isolation" "revert" "skip" "Guidance-only module"
    $script:ModuleResult = "skipped"
}

function Revert-audit-script {
    $desc = "Revert weekly security audit"
    try {
        Unregister-ScheduledTask -TaskName "SecurityWeeklyAudit" -Confirm:$false -ErrorAction SilentlyContinue
        $auditScript = Join-Path $script:ScriptDir "weekly-audit.ps1"
        if (Test-Path $auditScript) {
            Remove-Item $auditScript -Force -ErrorAction SilentlyContinue
        }
        Print-Status $script:CurrentModule $script:TotalModules $desc "reverted"
        Log-Entry "audit-script" "revert" "ok" "Removed scheduled task + audit script"
        $script:ModuleResult = "reverted"
    } catch {
        Print-Status $script:CurrentModule $script:TotalModules $desc "failed"
        Log-Entry "audit-script" "revert" "fail" "Could not remove audit task: $_"
        $script:ModuleResult = "failed"
    }
}

function Revert-backup-guidance {
    $desc = "Revert backup guidance"
    Print-Status $script:CurrentModule $script:TotalModules "$desc (guidance-only, nothing to revert)" "skipped"
    Log-Entry "backup-guidance" "revert" "skip" "Guidance-only module"
    $script:ModuleResult = "skipped"
}

function Revert-border-prep {
    $desc = "Revert border crossing prep"
    Print-Status $script:CurrentModule $script:TotalModules "$desc (guidance-only, nothing to revert)" "skipped"
    Log-Entry "border-prep" "revert" "skip" "Guidance-only module"
    $script:ModuleResult = "skipped"
}

function Revert-bluetooth-disable {
    $desc = "Re-enable Bluetooth"
    try {
        Set-Service -Name "bthserv" -StartupType Manual -ErrorAction Stop
        Start-Service -Name "bthserv" -ErrorAction SilentlyContinue
        Print-Status $script:CurrentModule $script:TotalModules $desc "reverted"
        Log-Entry "bluetooth-disable" "revert" "ok" "Bluetooth service re-enabled"
        $script:ModuleResult = "reverted"
    } catch {
        Print-Status $script:CurrentModule $script:TotalModules $desc "failed"
        Log-Entry "bluetooth-disable" "revert" "fail" "Could not re-enable Bluetooth: $_"
        $script:ModuleResult = "failed"
    }
}

# ═══════════════════════════════════════════════════════════════════
# UNINSTALL & MODIFY FLOWS
# ═══════════════════════════════════════════════════════════════════
function Run-Uninstall {
    Print-Section "Full Uninstall"

    # Load state
    $hasState = Read-State
    if (-not $hasState) {
        Write-ColorLine "  No state file found. Detecting applied modules..." Red
        Detect-AppliedModules
    }

    $applied = @(Get-AppliedModules)
    if ($applied.Count -eq 0) {
        Write-ColorLine "  No hardening changes detected. Nothing to uninstall." Green
        return
    }

    # Show status
    if ($hasState) {
        Write-Host "  State file found: " -NoNewline; Write-ColorLine $script:StateFileUser Green
    }
    Write-Host "  Applied modules: " -NoNewline; Write-ColorLine $applied.Count Green
    if ($script:StateData.last_run) {
        Write-Host "  Last run: " -NoNewline; Write-ColorLine $script:StateData.last_run Green
    }
    Write-Host ""

    # Package question
    if ($script:StateData.packages_installed.Count -gt 0) {
        Write-ColorLine "  The following tools were installed by the hardening script:" Green
        Write-Host "    " -NoNewline
        Write-ColorLine ($script:StateData.packages_installed -join ", ") Green
        Write-Host ""
        Write-Host "  Remove installed tools as well?" -ForegroundColor Green
        Write-Host "  " -NoNewline; Write-Color "[Y] Green; Write-Host " Yes — uninstall all tools listed above"
        Write-Host "  " -NoNewline; Write-Color "[N] Green; Write-Host " No  — keep tools, only revert settings"
        Write-Host "  " -NoNewline; Write-Color "[Q]" DarkYellow; Write-Host " Quit"
        Write-Host ""
        while ($true) {
            Write-Host "  Choice: " -NoNewline -ForegroundColor Green
            $pkgChoice = Read-Host
            switch ($pkgChoice) {
                { $_ -eq "Y" -or $_ -eq "y" } { $script:RemovePackages = $true; break }
                { $_ -eq "N" -or $_ -eq "n" } { $script:RemovePackages = $false; break }
                { $_ -eq "Q" -or $_ -eq "q" } { Write-Host "Aborted."; return }
                default { Write-ColorLine "  Enter Y, N, or Q." Red; continue }
            }
            break
        }
        Write-Host ""
    }

    # Final confirmation
    $pkgMsg = if ($script:RemovePackages -and $script:StateData.packages_installed.Count -gt 0) {
        " and remove $($script:StateData.packages_installed.Count) packages"
    } else { "" }
    Write-Host "  " -NoNewline; Write-Color "⚠" Red
    Write-Host "  This will revert $($applied.Count) modules$pkgMsg."
    if (-not (Prompt-YN "Proceed?")) {
        Write-Host "  Aborted."
        return
    }
    Write-Host ""

    # Revert in reverse order
    [array]::Reverse($applied)
    $script:TotalModules = $applied.Count
    $script:CurrentModule = 0

    foreach ($modId in $applied) {
        Run-Module $modId "revert"
    }

    # Update state
    Write-State

    Print-UninstallSummary
}

function Run-Modify {
    Print-Section "Modify Hardening"

    # Load state
    $hasState = Read-State
    if (-not $hasState) {
        Write-ColorLine "  No state file found. Detecting applied modules..." Red
        Detect-AppliedModules
    }

    $result = Interactive-Picker
    if (-not $result) { return }

    $addCount = $script:PickerAdd.Count
    $removeCount = $script:PickerRemove.Count

    if ($addCount -eq 0 -and $removeCount -eq 0) {
        Write-Host ""
        Write-ColorLine "  No changes selected." DarkYellow
        return
    }

    Write-Host ""
    if ($addCount -gt 0) {
        Write-Host "  Adding: " -NoNewline; Write-ColorLine ($script:PickerAdd -join ", ") Green
    }
    if ($removeCount -gt 0) {
        Write-Host "  Removing: " -NoNewline; Write-ColorLine ($script:PickerRemove -join ", ") Red
    }
    Write-Host ""
    if (-not (Prompt-YN "Apply changes?")) {
        Write-Host "  Aborted."
        return
    }
    Write-Host ""

    $script:TotalModules = $addCount + $removeCount
    $script:CurrentModule = 0

    # Select output mode for apply operations
    if ($addCount -gt 0) {
        Select-OutputMode
    }

    # Apply new modules
    foreach ($modId in $script:PickerAdd) {
        Run-Module $modId "apply"
    }

    # Remove modules
    foreach ($modId in $script:PickerRemove) {
        Run-Module $modId "revert"
    }

    # Update state
    Write-State

    Print-ModifySummary
}

function Print-UninstallSummary {
    Write-Host ""
    Write-ColorLine "═══════════════════════════════════════════════════" Green
    Write-ColorLine "  Uninstall Complete" Green
    Write-ColorLine "═══════════════════════════════════════════════════" Green
    Write-Host ""
    Write-Host "  " -NoNewline; Write-Color "✓" Green; Write-Host " Reverted:   $($script:CountReverted)"
    Write-Host "  " -NoNewline; Write-Color "○" Green; Write-Host " Skipped:    $($script:CountSkipped) " -NoNewline; Write-ColorLine "(nothing to revert)" DarkYellow
    Write-Host "  " -NoNewline; Write-Color "✗" Red;   Write-Host " Failed:     $($script:CountFailed)" -NoNewline
    if ($script:CountFailed -gt 0) { Write-ColorLine " (see log)" Red } else { Write-Host "" }
    Write-Host "  " -NoNewline; Write-Color "☐" Red; Write-Host " Manual:     $($script:CountManual)" -NoNewline
    if ($script:CountManual -gt 0) { Write-ColorLine " (see below)" Red } else { Write-Host "" }
    Write-Host ""
    Write-Host "  State files:"
    Write-Host "    User:    " -NoNewline; Write-ColorLine $script:StateFileUser DarkYellow
    Write-Host "    Project: " -NoNewline; Write-ColorLine $script:StateFileProject DarkYellow
    Write-Host ""

    if ($script:ManualSteps.Count -gt 0) {
        Print-ManualChecklist
    }
}

function Print-ModifySummary {
    Write-Host ""
    Write-ColorLine "═══════════════════════════════════════════════════" Green
    Write-ColorLine "  Modify Complete" Green
    Write-ColorLine "═══════════════════════════════════════════════════" Green
    Write-Host ""
    if ($script:CountApplied -gt 0) {
        Write-Host "  " -NoNewline; Write-Color "✓" Green; Write-Host " Applied:    $($script:CountApplied)"
    }
    if ($script:CountReverted -gt 0) {
        Write-Host "  " -NoNewline; Write-Color "✓" Green; Write-Host " Reverted:   $($script:CountReverted)"
    }
    if ($script:CountSkipped -gt 0) {
        Write-Host "  " -NoNewline; Write-Color "○" Green; Write-Host " Skipped:    $($script:CountSkipped)"
    }
    if ($script:CountFailed -gt 0) {
        Write-Host "  " -NoNewline; Write-Color "✗" Red;   Write-Host " Failed:     $($script:CountFailed)"
    }
    if ($script:CountManual -gt 0) {
        Write-Host "  " -NoNewline; Write-Color "☐" Red; Write-Host " Manual:     $($script:CountManual)"
    }
    Write-Host ""
    Write-Host "  State files:"
    Write-Host "    User:    " -NoNewline; Write-ColorLine $script:StateFileUser DarkYellow
    Write-Host "    Project: " -NoNewline; Write-ColorLine $script:StateFileProject DarkYellow
    Write-Host ""

    if ($script:ManualSteps.Count -gt 0) {
        Print-ManualChecklist
    }
}

# ═══════════════════════════════════════════════════════════════════
# OUTPUT: SUMMARY & REPORTS
# ═══════════════════════════════════════════════════════════════════
function Print-Summary {
    if ($script:QuietMode) { return }
    Write-Host ""
    Write-ColorLine "═══════════════════════════════════════════════════" Green
    Write-ColorLine "  Hardening Complete" Green
    Write-ColorLine "═══════════════════════════════════════════════════" Green
    Write-Host ""
    Write-Host "  " -NoNewline; Write-Color "✓" Green; Write-Host " Applied:    $($script:CountApplied)"
    Write-Host "  " -NoNewline; Write-Color "○" Green; Write-Host " Skipped:    $($script:CountSkipped) " -NoNewline; Write-ColorLine "(already applied)" DarkYellow
    Write-Host "  " -NoNewline; Write-Color "✗" Red;   Write-Host " Failed:     $($script:CountFailed)" -NoNewline
    if ($script:CountFailed -gt 0) { Write-ColorLine " (see log)" Red } else { Write-Host "" }
    Write-Host "  " -NoNewline; Write-Color "☐" Red; Write-Host " Manual:     $($script:CountManual)" -NoNewline
    if ($script:CountManual -gt 0) { Write-ColorLine " (see below)" Red } else { Write-Host "" }
    Write-Host ""
    Write-Host "  Profile: $($script:Profile) | OS: Windows | Date: $($script:DATE)"
    Write-Host ""
    Write-Host "  State files:"
    Write-Host "    User:    " -NoNewline; Write-ColorLine $script:StateFileUser DarkYellow
    Write-Host "    Project: " -NoNewline; Write-ColorLine $script:StateFileProject DarkYellow
    Write-Host ""
}

function Print-ManualChecklist {
    if ($script:ManualSteps.Count -gt 0) {
        Print-Section "Manual Steps Remaining"
        for ($i = 0; $i -lt $script:ManualSteps.Count; $i++) {
            Write-Host "  " -NoNewline; Write-Color "☐" Red; Write-Host " $($i+1). $($script:ManualSteps[$i])"
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
    $report += "Generated by barked.ps1 v$($script:VERSION)"
    $report | Out-File -FilePath $reportFile -Encoding UTF8
    Write-Host "  " -NoNewline; Write-Color "Report written to: " Green; Write-Host $reportFile
}

function Write-Log {
    New-Item -ItemType Directory -Path (Split-Path $script:LogFile) -Force | Out-Null
    $log = @()
    $log += "# Hardening Log — $($script:TIMESTAMP)"
    $log += "Mode: $($script:RunMode) | Profile: $($script:Profile) | OS: Windows"
    $log += ""
    $log += $script:LogEntries
    $log | Out-File -FilePath $script:LogFile -Encoding UTF8
    Write-ColorLine "  Log written to: $($script:LogFile)" DarkYellow
}

# ═══════════════════════════════════════════════════════════════════
# SYSTEM CLEANER — AVAILABILITY CHECK
# ═══════════════════════════════════════════════════════════════════
function Test-CleanTargetAvailable {
    param([string]$Target)
    switch ($Target) {
        'system-cache'        { return (Test-Path "C:\Windows\Temp") }
        'system-logs'         { return $true }
        'diagnostic-reports'  { return (Test-Path "C:\ProgramData\Microsoft\Windows\WER") }
        'dns-cache'           { return $true }
        'user-cache'          { return (Test-Path "$env:LOCALAPPDATA\Temp") }
        'user-logs'           { return $true }
        'chrome'              { return (Test-Path "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache") }
        'firefox'             { return (Test-Path "$env:LOCALAPPDATA\Mozilla\Firefox\Profiles") }
        'edge'                { return (Test-Path "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache") }
        'recent-items'        { return (Test-Path "$env:APPDATA\Microsoft\Windows\Recent") }
        'clipboard'           { return $true }
        'thumbnails' {
            $thumbDir = "$env:LOCALAPPDATA\Microsoft\Windows\Explorer"
            if (Test-Path $thumbDir) {
                return @(Get-ChildItem -Path $thumbDir -Filter "thumbcache_*" -ErrorAction SilentlyContinue).Count -gt 0
            }
            return $false
        }
        'npm-cache'           { return ($null -ne (Get-Command npm -ErrorAction SilentlyContinue)) }
        'yarn-cache'          { return ($null -ne (Get-Command yarn -ErrorAction SilentlyContinue)) }
        'pip-cache'           { return ($null -ne (Get-Command pip -ErrorAction SilentlyContinue)) -or ($null -ne (Get-Command pip3 -ErrorAction SilentlyContinue)) }
        'cargo-cache'         { return (Test-Path "$env:USERPROFILE\.cargo") }
        'go-cache'            { return ($null -ne (Get-Command go -ErrorAction SilentlyContinue)) }
        'docker-cruft'        { return ($null -ne (Get-Command docker -ErrorAction SilentlyContinue)) }
        'ide-caches' {
            return (Test-Path "$env:APPDATA\Code\Cache") -or
                   (Test-Path "$env:LOCALAPPDATA\JetBrains")
        }
        'recycle-bin'         { return $true }
        'old-downloads'       { return (Test-Path "$env:USERPROFILE\Downloads") }
        'outlook-cache'       { return (Test-Path "$env:LOCALAPPDATA\Microsoft\Outlook\RoamCache") }
        default               { return $true }
    }
}

# ═══════════════════════════════════════════════════════════════════
# SYSTEM CLEANER — PICKER UI
# ═══════════════════════════════════════════════════════════════════
function Show-CleanPicker {
    Print-Section "Select Categories"
    Write-ColorLine "  Toggle categories, then press Enter to continue." DarkYellow
    Write-Host ""

    # Start with all selected
    foreach ($cat in $script:CleanCatOrder) {
        $script:CleanCategories[$cat] = $true
    }

    while ($true) {
        for ($i = 0; $i -lt $script:CleanCatOrder.Count; $i++) {
            $cat = $script:CleanCatOrder[$i]
            $num = $i + 1
            $mark = " "
            if ($script:CleanCategories[$cat]) { $mark = "*" }
            Write-Host "  " -NoNewline
            Write-Color "[$num] Green
            Write-Host " [$mark] $($script:CleanCatNames[$cat])"
        }
        Write-Host ""
        Write-Host "  " -NoNewline; Write-Color "[A] Green; Write-Host " Select All    " -NoNewline
        Write-Color "[N] Green; Write-Host " Select None"
        Write-Host ""
        Write-Host "  Toggle (1-7, A, N) or Enter to continue: " -NoNewline -ForegroundColor Green
        $input = Read-Host

        if ([string]::IsNullOrEmpty($input)) {
            $any = $false
            foreach ($cat in $script:CleanCatOrder) {
                if ($script:CleanCategories[$cat]) { $any = $true; break }
            }
            if (-not $any) {
                Write-ColorLine "  Select at least one category." Red
                continue
            }
            break
        }

        switch ($input.ToLower()) {
            'a' {
                foreach ($cat in $script:CleanCatOrder) {
                    $script:CleanCategories[$cat] = $true
                }
            }
            'n' {
                foreach ($cat in $script:CleanCatOrder) {
                    $script:CleanCategories[$cat] = $false
                }
            }
            default {
                $num = 0
                if ([int]::TryParse($input, [ref]$num) -and $num -ge 1 -and $num -le 7) {
                    $cat = $script:CleanCatOrder[$num - 1]
                    $script:CleanCategories[$cat] = -not $script:CleanCategories[$cat]
                } else {
                    Write-ColorLine "  Invalid input." Red
                }
            }
        }
        Write-Host ""
    }

    # Populate CleanTargets from selected categories
    foreach ($cat in $script:CleanCatOrder) {
        if ($script:CleanCategories[$cat]) {
            foreach ($target in $script:CleanCatTargets[$cat]) {
                if (Test-CleanTargetAvailable $target) {
                    $script:CleanTargets[$target] = $true
                }
            }
        }
    }
}

# ═══════════════════════════════════════════════════════════════════
# SYSTEM CLEANER — DRILLDOWN UI
# ═══════════════════════════════════════════════════════════════════
function Show-CleanDrilldown {
    Write-Host ""
    Write-Host "  Drill into individual targets? (y/N): " -NoNewline -ForegroundColor Green
    $drill = Read-Host
    if ($drill.ToLower() -ne 'y') { return }

    foreach ($cat in $script:CleanCatOrder) {
        if (-not $script:CleanCategories[$cat]) { continue }

        $avail = @()
        foreach ($target in $script:CleanCatTargets[$cat]) {
            if (Test-CleanTargetAvailable $target) {
                $avail += $target
            }
        }
        if ($avail.Count -eq 0) { continue }

        Write-Host ""
        Write-ColorLine "  -- $($script:CleanCatNames[$cat]) --" Green

        while ($true) {
            for ($i = 0; $i -lt $avail.Count; $i++) {
                $t = $avail[$i]
                $num = $i + 1
                $mark = " "
                if ($script:CleanTargets.ContainsKey($t) -and $script:CleanTargets[$t]) { $mark = "*" }
                Write-Host "    " -NoNewline
                Write-Color "[$num] Green
                Write-Host " [$mark] $($script:CleanTargetNames[$t])"
            }
            Write-Host ""
            Write-Host "    Toggle (1-$($avail.Count)) or Enter to keep: " -NoNewline -ForegroundColor Green
            $input = Read-Host

            if ([string]::IsNullOrEmpty($input)) { break }

            $num = 0
            if ([int]::TryParse($input, [ref]$num) -and $num -ge 1 -and $num -le $avail.Count) {
                $t = $avail[$num - 1]
                if ($script:CleanTargets.ContainsKey($t) -and $script:CleanTargets[$t]) {
                    $script:CleanTargets[$t] = $false
                } else {
                    $script:CleanTargets[$t] = $true
                }
            } else {
                Write-ColorLine "    Invalid input." Red
            }
            Write-Host ""
        }
    }
}

# ═══════════════════════════════════════════════════════════════════
# SYSTEM CLEANER — BYTE FORMATTING
# ═══════════════════════════════════════════════════════════════════
function Format-CleanBytes {
    param([long]$Bytes)
    if ($Bytes -ge 1GB) {
        return "{0:N1} GB" -f ($Bytes / 1GB)
    } elseif ($Bytes -ge 1MB) {
        return "{0:N0} MB" -f ($Bytes / 1MB)
    } elseif ($Bytes -ge 1KB) {
        return "{0:N0} KB" -f ($Bytes / 1KB)
    } else {
        return "$Bytes B"
    }
}

# ═══════════════════════════════════════════════════════════════════
# SYSTEM CLEANER — SCAN HELPERS
# ═══════════════════════════════════════════════════════════════════
function Invoke-ScanDirectory {
    param([string]$Path)
    $script:ScanFileCount = 0
    $script:ScanByteCount = 0
    if (Test-Path $Path) {
        try {
            $items = Get-ChildItem -Path $Path -Recurse -File -Force -ErrorAction SilentlyContinue |
                Where-Object { -not $_.Attributes.HasFlag([System.IO.FileAttributes]::ReparsePoint) }
            if ($items) {
                $measure = $items | Measure-Object -Property Length -Sum
                $script:ScanFileCount = [int]$measure.Count
                $script:ScanByteCount = [long]$measure.Sum
            }
        } catch {
            # Permission errors, etc.
        }
    }
}

# ═══════════════════════════════════════════════════════════════════
# SYSTEM CLEANER — PER-TARGET SCAN FUNCTIONS
# ═══════════════════════════════════════════════════════════════════
function Invoke-ScanSystemCache {
    Invoke-ScanDirectory "C:\Windows\Temp"
    $script:CleanScanFiles['system-cache'] = $script:ScanFileCount
    $script:CleanScanBytes['system-cache'] = $script:ScanByteCount
}

function Invoke-ScanSystemLogs {
    # Event logs cannot be easily measured by file size; report as 0
    $script:CleanScanFiles['system-logs'] = 0
    $script:CleanScanBytes['system-logs'] = 0
}

function Invoke-ScanDiagnosticReports {
    Invoke-ScanDirectory "C:\ProgramData\Microsoft\Windows\WER"
    $script:CleanScanFiles['diagnostic-reports'] = $script:ScanFileCount
    $script:CleanScanBytes['diagnostic-reports'] = $script:ScanByteCount
}

function Invoke-ScanDnsCache {
    $script:CleanScanFiles['dns-cache'] = 0
    $script:CleanScanBytes['dns-cache'] = 0
}

function Invoke-ScanUserCache {
    Invoke-ScanDirectory "$env:LOCALAPPDATA\Temp"
    $script:CleanScanFiles['user-cache'] = $script:ScanFileCount
    $script:CleanScanBytes['user-cache'] = $script:ScanByteCount
}

function Invoke-ScanUserLogs {
    $totalF = 0; $totalB = 0
    foreach ($d in @("$env:LOCALAPPDATA\CrashDumps", "$env:LOCALAPPDATA\Microsoft\Windows\WER")) {
        if (Test-Path $d) {
            Invoke-ScanDirectory $d
            $totalF += $script:ScanFileCount
            $totalB += $script:ScanByteCount
        }
    }
    $script:CleanScanFiles['user-logs'] = $totalF
    $script:CleanScanBytes['user-logs'] = $totalB
}

function Invoke-ScanChrome {
    Invoke-ScanDirectory "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache"
    $script:CleanScanFiles['chrome'] = $script:ScanFileCount
    $script:CleanScanBytes['chrome'] = $script:ScanByteCount
}

function Invoke-ScanFirefox {
    Invoke-ScanDirectory "$env:LOCALAPPDATA\Mozilla\Firefox\Profiles"
    $script:CleanScanFiles['firefox'] = $script:ScanFileCount
    $script:CleanScanBytes['firefox'] = $script:ScanByteCount
}

function Invoke-ScanEdge {
    Invoke-ScanDirectory "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache"
    $script:CleanScanFiles['edge'] = $script:ScanFileCount
    $script:CleanScanBytes['edge'] = $script:ScanByteCount
}

function Invoke-ScanRecentItems {
    Invoke-ScanDirectory "$env:APPDATA\Microsoft\Windows\Recent"
    $script:CleanScanFiles['recent-items'] = $script:ScanFileCount
    $script:CleanScanBytes['recent-items'] = $script:ScanByteCount
}

function Invoke-ScanClipboard {
    $script:CleanScanFiles['clipboard'] = 0
    $script:CleanScanBytes['clipboard'] = 0
}

function Invoke-ScanThumbnails {
    $totalF = 0; $totalB = 0
    $thumbDir = "$env:LOCALAPPDATA\Microsoft\Windows\Explorer"
    if (Test-Path $thumbDir) {
        $thumbFiles = Get-ChildItem -Path $thumbDir -Filter "thumbcache_*" -File -Force -ErrorAction SilentlyContinue |
            Where-Object { -not $_.Attributes.HasFlag([System.IO.FileAttributes]::ReparsePoint) }
        if ($thumbFiles) {
            $measure = $thumbFiles | Measure-Object -Property Length -Sum
            $totalF = [int]$measure.Count
            $totalB = [long]$measure.Sum
        }
    }
    $script:CleanScanFiles['thumbnails'] = $totalF
    $script:CleanScanBytes['thumbnails'] = $totalB
}

function Invoke-ScanNpmCache {
    $script:ScanFileCount = 0; $script:ScanByteCount = 0
    if (Get-Command npm -ErrorAction SilentlyContinue) {
        try {
            $cacheDir = (npm config get cache 2>$null)
            if ($cacheDir -and (Test-Path $cacheDir)) {
                Invoke-ScanDirectory $cacheDir
            }
        } catch {}
    }
    $script:CleanScanFiles['npm-cache'] = $script:ScanFileCount
    $script:CleanScanBytes['npm-cache'] = $script:ScanByteCount
}

function Invoke-ScanYarnCache {
    $script:ScanFileCount = 0; $script:ScanByteCount = 0
    if (Get-Command yarn -ErrorAction SilentlyContinue) {
        try {
            $cacheDir = (yarn cache dir 2>$null)
            if ($cacheDir -and (Test-Path $cacheDir)) {
                Invoke-ScanDirectory $cacheDir
            }
        } catch {}
    }
    $script:CleanScanFiles['yarn-cache'] = $script:ScanFileCount
    $script:CleanScanBytes['yarn-cache'] = $script:ScanByteCount
}

function Invoke-ScanPipCache {
    $script:ScanFileCount = 0; $script:ScanByteCount = 0
    $pipCmd = $null
    if (Get-Command pip3 -ErrorAction SilentlyContinue) { $pipCmd = 'pip3' }
    elseif (Get-Command pip -ErrorAction SilentlyContinue) { $pipCmd = 'pip' }
    if ($pipCmd) {
        try {
            $cacheDir = (& $pipCmd cache dir 2>$null)
            if ($cacheDir -and (Test-Path $cacheDir)) {
                Invoke-ScanDirectory $cacheDir
            }
        } catch {}
    }
    $script:CleanScanFiles['pip-cache'] = $script:ScanFileCount
    $script:CleanScanBytes['pip-cache'] = $script:ScanByteCount
}

function Invoke-ScanCargoCache {
    Invoke-ScanDirectory "$env:USERPROFILE\.cargo\registry\cache"
    $script:CleanScanFiles['cargo-cache'] = $script:ScanFileCount
    $script:CleanScanBytes['cargo-cache'] = $script:ScanByteCount
}

function Invoke-ScanGoCache {
    $script:ScanFileCount = 0; $script:ScanByteCount = 0
    if (Get-Command go -ErrorAction SilentlyContinue) {
        try {
            $cacheDir = (go env GOCACHE 2>$null)
            if ($cacheDir -and (Test-Path $cacheDir)) {
                Invoke-ScanDirectory $cacheDir
            }
        } catch {}
    }
    $script:CleanScanFiles['go-cache'] = $script:ScanFileCount
    $script:CleanScanBytes['go-cache'] = $script:ScanByteCount
}

function Invoke-ScanDockerCruft {
    $script:CleanScanFiles['docker-cruft'] = 0
    $script:CleanScanBytes['docker-cruft'] = 0
}

function Invoke-ScanIdeCaches {
    $totalF = 0; $totalB = 0
    foreach ($d in @("$env:APPDATA\Code\Cache",
                     "$env:LOCALAPPDATA\JetBrains")) {
        if (Test-Path $d) {
            Invoke-ScanDirectory $d
            $totalF += $script:ScanFileCount
            $totalB += $script:ScanByteCount
        }
    }
    $script:CleanScanFiles['ide-caches'] = $totalF
    $script:CleanScanBytes['ide-caches'] = $totalB
}

function Invoke-ScanRecycleBin {
    # Recycle Bin size is not easily measured via filesystem
    $script:CleanScanFiles['recycle-bin'] = 0
    $script:CleanScanBytes['recycle-bin'] = 0
}

function Invoke-ScanOldDownloads {
    $script:ScanFileCount = 0; $script:ScanByteCount = 0
    $dlPath = "$env:USERPROFILE\Downloads"
    if (Test-Path $dlPath) {
        $cutoff = (Get-Date).AddDays(-30)
        $oldFiles = Get-ChildItem -Path $dlPath -File -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -lt $cutoff -and -not $_.Attributes.HasFlag([System.IO.FileAttributes]::ReparsePoint) }
        if ($oldFiles) {
            $measure = $oldFiles | Measure-Object -Property Length -Sum
            $script:ScanFileCount = [int]$measure.Count
            $script:ScanByteCount = [long]$measure.Sum
        }
    }
    $script:CleanScanFiles['old-downloads'] = $script:ScanFileCount
    $script:CleanScanBytes['old-downloads'] = $script:ScanByteCount
}

function Invoke-ScanOutlookCache {
    Invoke-ScanDirectory "$env:LOCALAPPDATA\Microsoft\Outlook\RoamCache"
    $script:CleanScanFiles['outlook-cache'] = $script:ScanFileCount
    $script:CleanScanBytes['outlook-cache'] = $script:ScanByteCount
}

# ═══════════════════════════════════════════════════════════════════
# SYSTEM CLEANER — SCAN DISPATCHER
# ═══════════════════════════════════════════════════════════════════
function Invoke-ScanTarget {
    param([string]$Target)
    $funcMap = @{
        'system-cache'       = { Invoke-ScanSystemCache }
        'system-logs'        = { Invoke-ScanSystemLogs }
        'diagnostic-reports' = { Invoke-ScanDiagnosticReports }
        'dns-cache'          = { Invoke-ScanDnsCache }
        'user-cache'         = { Invoke-ScanUserCache }
        'user-logs'          = { Invoke-ScanUserLogs }
        'chrome'             = { Invoke-ScanChrome }
        'firefox'            = { Invoke-ScanFirefox }
        'edge'               = { Invoke-ScanEdge }
        'recent-items'       = { Invoke-ScanRecentItems }
        'clipboard'          = { Invoke-ScanClipboard }
        'thumbnails'         = { Invoke-ScanThumbnails }
        'npm-cache'          = { Invoke-ScanNpmCache }
        'yarn-cache'         = { Invoke-ScanYarnCache }
        'pip-cache'          = { Invoke-ScanPipCache }
        'cargo-cache'        = { Invoke-ScanCargoCache }
        'go-cache'           = { Invoke-ScanGoCache }
        'docker-cruft'       = { Invoke-ScanDockerCruft }
        'ide-caches'         = { Invoke-ScanIdeCaches }
        'recycle-bin'        = { Invoke-ScanRecycleBin }
        'old-downloads'      = { Invoke-ScanOldDownloads }
        'outlook-cache'      = { Invoke-ScanOutlookCache }
    }
    if ($funcMap.ContainsKey($Target)) {
        & $funcMap[$Target]
    } else {
        $script:CleanScanFiles[$Target] = 0
        $script:CleanScanBytes[$Target] = 0
    }
}

# ═══════════════════════════════════════════════════════════════════
# SYSTEM CLEANER — PREVIEW TABLE
# ═══════════════════════════════════════════════════════════════════
function Show-CleanPreview {
    Print-Section "Scanning..."

    $orderedTargets = @()
    foreach ($cat in $script:CleanCatOrder) {
        foreach ($target in $script:CleanCatTargets[$cat]) {
            if ($script:CleanTargets.ContainsKey($target) -and $script:CleanTargets[$target]) {
                $orderedTargets += $target
            }
        }
    }

    foreach ($target in $orderedTargets) {
        Write-Host "  " -NoNewline
        Write-Color ([char]0x27F3).ToString() Red
        Write-Host " Scanning $($script:CleanTargetNames[$target])..." -NoNewline
        Invoke-ScanTarget $target
        Write-Host "`r" -NoNewline
        Write-Host ("  " + (" " * 60)) -NoNewline
        Write-Host "`r" -NoNewline
    }

    $totalFiles = 0; $totalBytes = [long]0
    Write-Host ""
    Write-ColorLine "  +----------------------------------------------------------+" Green
    Write-ColorLine "  |                   CLEANING PREVIEW                        |" Green
    Write-ColorLine "  +----------------------------------------------------------+" Green
    Write-Host ("  {0,-34} {1,8} {2,10} {3,8}" -f "  Target","Files","Size","Status") -ForegroundColor Green
    Write-ColorLine "  ----  --------------------------------  --------  ----------  --------" DarkYellow

    foreach ($target in $orderedTargets) {
        $files = if ($script:CleanScanFiles.ContainsKey($target)) { $script:CleanScanFiles[$target] } else { 0 }
        $bytes = if ($script:CleanScanBytes.ContainsKey($target)) { [long]$script:CleanScanBytes[$target] } else { [long]0 }
        $status = "Ready"
        $sizeStr = [string]::Empty

        if ($bytes -gt 0) {
            $sizeStr = Format-CleanBytes $bytes
        } elseif ($files -gt 0) {
            $sizeStr = [char]0x2014 # em-dash
        } else {
            switch ($target) {
                { $_ -in @('dns-cache','clipboard') } { $sizeStr = [char]0x2014; $status = "Ready" }
                default { $status = "Empty"; $sizeStr = [char]0x2014 }
            }
        }

        $fileStr = if ($files -eq 0) { [string]([char]0x2014) } else { "$files" }

        $color = "White"
        if ($status -eq "Empty") { $color = "DarkYellow" }

        Write-Host ("  {0,-34} {1,8} {2,10} {3,8}" -f "  $($script:CleanTargetNames[$target])",$fileStr,$sizeStr,$status) -ForegroundColor $color

        $totalFiles += $files
        $totalBytes += $bytes
    }

    Write-ColorLine "  ----  --------------------------------  --------  ----------  --------" DarkYellow
    Write-Host ("  {0,-34} {1,8} {2,10}" -f "  TOTAL","$totalFiles","$(Format-CleanBytes $totalBytes)") -ForegroundColor Green
    Write-ColorLine "  +----------------------------------------------------------+" Green

    $script:CleanTotalScanFiles = $totalFiles
    $script:CleanTotalScanBytes = $totalBytes
}

# ═══════════════════════════════════════════════════════════════════
# SYSTEM CLEANER — CLEAN LOG ENTRY
# ═══════════════════════════════════════════════════════════════════
function Write-CleanLogEntry {
    param([string]$Action, [string]$Message)
    $entry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Action] $Message"
    $script:CleanLogEntries += $entry
}

# ═══════════════════════════════════════════════════════════════════
# SYSTEM CLEANER — SAFE DIRECTORY REMOVAL
# ═══════════════════════════════════════════════════════════════════
function Remove-DirectoryContents {
    param([string]$Path)
    $script:SafeRmFiles = 0
    $script:SafeRmBytes = [long]0

    if (-not (Test-Path $Path)) { return }

    # Resolve to physical path (no symlink following)
    try {
        $realPath = (Resolve-Path $Path -ErrorAction Stop).Path
    } catch {
        return
    }

    $now = Get-Date
    $files = Get-ChildItem -Path $realPath -Recurse -File -Force -ErrorAction SilentlyContinue |
        Where-Object { -not $_.Attributes.HasFlag([System.IO.FileAttributes]::ReparsePoint) }

    if (-not $files) { return }

    foreach ($file in $files) {
        # Skip files modified less than 60 seconds ago
        if (($now - $file.LastWriteTime).TotalSeconds -lt 60) {
            Write-CleanLogEntry "SKIP" "$($file.FullName) (modified < 60s ago)"
            continue
        }

        $fsize = $file.Length
        try {
            Remove-Item -Path $file.FullName -Force -ErrorAction Stop
            $script:SafeRmBytes += $fsize
            $script:SafeRmFiles++
            Write-CleanLogEntry "CLEAN" "Removed $($file.FullName) ($(Format-CleanBytes $fsize))"
        } catch {
            Write-CleanLogEntry "FAIL" "$($file.FullName) (permission denied)"
        }
    }

    # Remove empty directories
    Get-ChildItem -Path $realPath -Recurse -Directory -Force -ErrorAction SilentlyContinue |
        Sort-Object { $_.FullName.Length } -Descending |
        ForEach-Object {
            if (@(Get-ChildItem -Path $_.FullName -Force -ErrorAction SilentlyContinue).Count -eq 0) {
                Remove-Item -Path $_.FullName -Force -ErrorAction SilentlyContinue
            }
        }
}

# ═══════════════════════════════════════════════════════════════════
# SYSTEM CLEANER — BROWSER RUNNING CHECK
# ═══════════════════════════════════════════════════════════════════
function Test-BrowserRunning {
    param([string]$ProcessName)
    return @(Get-Process -Name $ProcessName -ErrorAction SilentlyContinue).Count -gt 0
}

# ═══════════════════════════════════════════════════════════════════
# SYSTEM CLEANER — PER-TARGET CLEAN FUNCTIONS
# ═══════════════════════════════════════════════════════════════════
function Invoke-CleanSystemCache {
    Remove-DirectoryContents "C:\Windows\Temp"
    $script:CleanResultFiles['system-cache'] = $script:SafeRmFiles
    $script:CleanResultBytes['system-cache'] = $script:SafeRmBytes
    $script:CleanResultStatus['system-cache'] = if ($script:SafeRmFiles -gt 0) { "pass" } else { "skip" }
}

function Invoke-CleanSystemLogs {
    try {
        wevtutil cl System 2>$null
        wevtutil cl Application 2>$null
        Write-CleanLogEntry "CLEAN" "Cleared System and Application event logs"
    } catch {
        Write-CleanLogEntry "FAIL" "Could not clear event logs: $_"
    }
    $script:CleanResultFiles['system-logs'] = 0
    $script:CleanResultBytes['system-logs'] = 0
    $script:CleanResultStatus['system-logs'] = "pass"
}

function Invoke-CleanDiagnosticReports {
    Remove-DirectoryContents "C:\ProgramData\Microsoft\Windows\WER"
    $script:CleanResultFiles['diagnostic-reports'] = $script:SafeRmFiles
    $script:CleanResultBytes['diagnostic-reports'] = $script:SafeRmBytes
    $script:CleanResultStatus['diagnostic-reports'] = if ($script:SafeRmFiles -gt 0) { "pass" } else { "skip" }
}

function Invoke-CleanDnsCache {
    try {
        ipconfig /flushdns 2>$null | Out-Null
        Write-CleanLogEntry "CLEAN" "Flushed DNS cache (ipconfig /flushdns)"
    } catch {
        Write-CleanLogEntry "FAIL" "Could not flush DNS cache: $_"
    }
    $script:CleanResultFiles['dns-cache'] = 0
    $script:CleanResultBytes['dns-cache'] = 0
    $script:CleanResultStatus['dns-cache'] = "pass"
}

function Invoke-CleanUserCache {
    Remove-DirectoryContents "$env:LOCALAPPDATA\Temp"
    $script:CleanResultFiles['user-cache'] = $script:SafeRmFiles
    $script:CleanResultBytes['user-cache'] = $script:SafeRmBytes
    $script:CleanResultStatus['user-cache'] = if ($script:SafeRmFiles -gt 0) { "pass" } else { "skip" }
}

function Invoke-CleanUserLogs {
    $totalF = 0; $totalB = [long]0
    foreach ($d in @("$env:LOCALAPPDATA\CrashDumps", "$env:LOCALAPPDATA\Microsoft\Windows\WER")) {
        if (Test-Path $d) {
            Remove-DirectoryContents $d
            $totalF += $script:SafeRmFiles
            $totalB += $script:SafeRmBytes
        }
    }
    $script:CleanResultFiles['user-logs'] = $totalF
    $script:CleanResultBytes['user-logs'] = $totalB
    $script:CleanResultStatus['user-logs'] = if ($totalF -gt 0) { "pass" } else { "skip" }
}

function Invoke-CleanChrome {
    if (Test-BrowserRunning "chrome") {
        Write-Host "  " -NoNewline; Write-Color ([char]0x26A0).ToString() Red; Write-Host "  Chrome is running -- close it first to clean"
        Write-CleanLogEntry "SKIP" "Chrome (browser running)"
        $script:CleanResultFiles['chrome'] = 0; $script:CleanResultBytes['chrome'] = 0; $script:CleanResultStatus['chrome'] = "fail"
        return
    }
    Remove-DirectoryContents "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache"
    $script:CleanResultFiles['chrome'] = $script:SafeRmFiles
    $script:CleanResultBytes['chrome'] = $script:SafeRmBytes
    $script:CleanResultStatus['chrome'] = if ($script:SafeRmFiles -gt 0) { "pass" } else { "skip" }
}

function Invoke-CleanFirefox {
    if (Test-BrowserRunning "firefox") {
        Write-Host "  " -NoNewline; Write-Color ([char]0x26A0).ToString() Red; Write-Host "  Firefox is running -- close it first to clean"
        Write-CleanLogEntry "SKIP" "Firefox (browser running)"
        $script:CleanResultFiles['firefox'] = 0; $script:CleanResultBytes['firefox'] = 0; $script:CleanResultStatus['firefox'] = "fail"
        return
    }
    # Clean cache subdirectories within all profiles
    $profilesDir = "$env:LOCALAPPDATA\Mozilla\Firefox\Profiles"
    $totalF = 0; $totalB = [long]0
    if (Test-Path $profilesDir) {
        Get-ChildItem -Path $profilesDir -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $cacheDir = Join-Path $_.FullName "cache2"
            if (Test-Path $cacheDir) {
                Remove-DirectoryContents $cacheDir
                $totalF += $script:SafeRmFiles
                $totalB += $script:SafeRmBytes
            }
        }
    }
    $script:CleanResultFiles['firefox'] = $totalF
    $script:CleanResultBytes['firefox'] = $totalB
    $script:CleanResultStatus['firefox'] = if ($totalF -gt 0) { "pass" } else { "skip" }
}

function Invoke-CleanEdge {
    if (Test-BrowserRunning "msedge") {
        Write-Host "  " -NoNewline; Write-Color ([char]0x26A0).ToString() Red; Write-Host "  Edge is running -- close it first to clean"
        Write-CleanLogEntry "SKIP" "Edge (browser running)"
        $script:CleanResultFiles['edge'] = 0; $script:CleanResultBytes['edge'] = 0; $script:CleanResultStatus['edge'] = "fail"
        return
    }
    Remove-DirectoryContents "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache"
    $script:CleanResultFiles['edge'] = $script:SafeRmFiles
    $script:CleanResultBytes['edge'] = $script:SafeRmBytes
    $script:CleanResultStatus['edge'] = if ($script:SafeRmFiles -gt 0) { "pass" } else { "skip" }
}

function Invoke-CleanRecentItems {
    Remove-DirectoryContents "$env:APPDATA\Microsoft\Windows\Recent"
    $script:CleanResultFiles['recent-items'] = $script:SafeRmFiles
    $script:CleanResultBytes['recent-items'] = $script:SafeRmBytes
    $script:CleanResultStatus['recent-items'] = "pass"
}

function Invoke-CleanClipboard {
    try {
        Set-Clipboard -Value $null
        Write-CleanLogEntry "CLEAN" "Cleared clipboard"
    } catch {
        Write-CleanLogEntry "FAIL" "Could not clear clipboard: $_"
    }
    $script:CleanResultFiles['clipboard'] = 0
    $script:CleanResultBytes['clipboard'] = 0
    $script:CleanResultStatus['clipboard'] = "pass"
}

function Invoke-CleanThumbnails {
    $thumbDir = "$env:LOCALAPPDATA\Microsoft\Windows\Explorer"
    $totalF = 0; $totalB = [long]0
    if (Test-Path $thumbDir) {
        $thumbFiles = Get-ChildItem -Path $thumbDir -Filter "thumbcache_*" -File -Force -ErrorAction SilentlyContinue |
            Where-Object { -not $_.Attributes.HasFlag([System.IO.FileAttributes]::ReparsePoint) }
        if ($thumbFiles) {
            foreach ($file in $thumbFiles) {
                $fsize = $file.Length
                try {
                    Remove-Item -Path $file.FullName -Force -ErrorAction Stop
                    $totalF++
                    $totalB += $fsize
                    Write-CleanLogEntry "CLEAN" "Removed $($file.FullName) ($(Format-CleanBytes $fsize))"
                } catch {
                    Write-CleanLogEntry "FAIL" "$($file.FullName) (in use or permission denied)"
                }
            }
        }
    }
    $script:CleanResultFiles['thumbnails'] = $totalF
    $script:CleanResultBytes['thumbnails'] = $totalB
    $script:CleanResultStatus['thumbnails'] = if ($totalF -gt 0) { "pass" } else { "skip" }
}

function Invoke-CleanNpmCache {
    if (Get-Command npm -ErrorAction SilentlyContinue) {
        try {
            npm cache clean --force 2>$null | Out-Null
            Write-CleanLogEntry "CLEAN" "Ran npm cache clean --force"
        } catch {}
    }
    $script:CleanResultFiles['npm-cache'] = 0
    $script:CleanResultBytes['npm-cache'] = 0
    $script:CleanResultStatus['npm-cache'] = "pass"
}

function Invoke-CleanYarnCache {
    if (Get-Command yarn -ErrorAction SilentlyContinue) {
        try {
            yarn cache clean 2>$null | Out-Null
            Write-CleanLogEntry "CLEAN" "Ran yarn cache clean"
        } catch {}
    }
    $script:CleanResultFiles['yarn-cache'] = 0
    $script:CleanResultBytes['yarn-cache'] = 0
    $script:CleanResultStatus['yarn-cache'] = "pass"
}

function Invoke-CleanPipCache {
    $pipCmd = $null
    if (Get-Command pip3 -ErrorAction SilentlyContinue) { $pipCmd = 'pip3' }
    elseif (Get-Command pip -ErrorAction SilentlyContinue) { $pipCmd = 'pip' }
    if ($pipCmd) {
        try {
            & $pipCmd cache purge 2>$null | Out-Null
            Write-CleanLogEntry "CLEAN" "Ran $pipCmd cache purge"
        } catch {}
    }
    $script:CleanResultFiles['pip-cache'] = 0
    $script:CleanResultBytes['pip-cache'] = 0
    $script:CleanResultStatus['pip-cache'] = "pass"
}

function Invoke-CleanCargoCache {
    Remove-DirectoryContents "$env:USERPROFILE\.cargo\registry\cache"
    $script:CleanResultFiles['cargo-cache'] = $script:SafeRmFiles
    $script:CleanResultBytes['cargo-cache'] = $script:SafeRmBytes
    $script:CleanResultStatus['cargo-cache'] = if ($script:SafeRmFiles -gt 0) { "pass" } else { "skip" }
}

function Invoke-CleanGoCache {
    if (Get-Command go -ErrorAction SilentlyContinue) {
        try {
            go clean -cache 2>$null | Out-Null
            Write-CleanLogEntry "CLEAN" "Ran go clean -cache"
        } catch {}
    }
    $script:CleanResultFiles['go-cache'] = 0
    $script:CleanResultBytes['go-cache'] = 0
    $script:CleanResultStatus['go-cache'] = "pass"
}

function Invoke-CleanDockerCruft {
    if (Get-Command docker -ErrorAction SilentlyContinue) {
        try {
            docker system prune -f 2>$null | Out-Null
            Write-CleanLogEntry "CLEAN" "Ran docker system prune -f"
        } catch {}
    }
    $script:CleanResultFiles['docker-cruft'] = 0
    $script:CleanResultBytes['docker-cruft'] = 0
    $script:CleanResultStatus['docker-cruft'] = "pass"
}

function Invoke-CleanIdeCaches {
    $totalF = 0; $totalB = [long]0
    foreach ($d in @("$env:APPDATA\Code\Cache",
                     "$env:LOCALAPPDATA\JetBrains")) {
        if (Test-Path $d) {
            Remove-DirectoryContents $d
            $totalF += $script:SafeRmFiles
            $totalB += $script:SafeRmBytes
        }
    }
    $script:CleanResultFiles['ide-caches'] = $totalF
    $script:CleanResultBytes['ide-caches'] = $totalB
    $script:CleanResultStatus['ide-caches'] = if ($totalF -gt 0) { "pass" } else { "skip" }
}

function Invoke-CleanRecycleBin {
    try {
        Clear-RecycleBin -Force -ErrorAction SilentlyContinue
        Write-CleanLogEntry "CLEAN" "Cleared Recycle Bin"
    } catch {
        Write-CleanLogEntry "FAIL" "Could not clear Recycle Bin: $_"
    }
    $script:CleanResultFiles['recycle-bin'] = 0
    $script:CleanResultBytes['recycle-bin'] = 0
    $script:CleanResultStatus['recycle-bin'] = "pass"
}

function Invoke-CleanOldDownloads {
    $totalF = 0; $totalB = [long]0
    $dlPath = "$env:USERPROFILE\Downloads"
    if (Test-Path $dlPath) {
        $cutoff = (Get-Date).AddDays(-30)
        $oldFiles = Get-ChildItem -Path $dlPath -File -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -lt $cutoff -and -not $_.Attributes.HasFlag([System.IO.FileAttributes]::ReparsePoint) }
        if ($oldFiles) {
            foreach ($file in $oldFiles) {
                $fsize = $file.Length
                try {
                    Remove-Item -Path $file.FullName -Force -ErrorAction Stop
                    $totalF++
                    $totalB += $fsize
                    Write-CleanLogEntry "CLEAN" "Removed $($file.FullName) ($(Format-CleanBytes $fsize))"
                } catch {
                    Write-CleanLogEntry "FAIL" "$($file.FullName) (permission denied)"
                }
            }
        }
    }
    $script:CleanResultFiles['old-downloads'] = $totalF
    $script:CleanResultBytes['old-downloads'] = $totalB
    $script:CleanResultStatus['old-downloads'] = if ($totalF -gt 0) { "pass" } else { "skip" }
}

function Invoke-CleanOutlookCache {
    Remove-DirectoryContents "$env:LOCALAPPDATA\Microsoft\Outlook\RoamCache"
    $script:CleanResultFiles['outlook-cache'] = $script:SafeRmFiles
    $script:CleanResultBytes['outlook-cache'] = $script:SafeRmBytes
    $script:CleanResultStatus['outlook-cache'] = if ($script:SafeRmFiles -gt 0) { "pass" } else { "skip" }
}

# ═══════════════════════════════════════════════════════════════════
# SYSTEM CLEANER — EXECUTION ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════
function Invoke-CleanExecute {
    Print-Section "Cleaning ($(Get-Date -Format 'HH:mm:ss'))"

    $orderedTargets = @()
    foreach ($cat in $script:CleanCatOrder) {
        foreach ($target in $script:CleanCatTargets[$cat]) {
            if ($script:CleanTargets.ContainsKey($target) -and $script:CleanTargets[$target]) {
                $orderedTargets += $target
            }
        }
    }

    $total = $orderedTargets.Count
    $current = 0

    $cleanFuncMap = @{
        'system-cache'       = { Invoke-CleanSystemCache }
        'system-logs'        = { Invoke-CleanSystemLogs }
        'diagnostic-reports' = { Invoke-CleanDiagnosticReports }
        'dns-cache'          = { Invoke-CleanDnsCache }
        'user-cache'         = { Invoke-CleanUserCache }
        'user-logs'          = { Invoke-CleanUserLogs }
        'chrome'             = { Invoke-CleanChrome }
        'firefox'            = { Invoke-CleanFirefox }
        'edge'               = { Invoke-CleanEdge }
        'recent-items'       = { Invoke-CleanRecentItems }
        'clipboard'          = { Invoke-CleanClipboard }
        'thumbnails'         = { Invoke-CleanThumbnails }
        'npm-cache'          = { Invoke-CleanNpmCache }
        'yarn-cache'         = { Invoke-CleanYarnCache }
        'pip-cache'          = { Invoke-CleanPipCache }
        'cargo-cache'        = { Invoke-CleanCargoCache }
        'go-cache'           = { Invoke-CleanGoCache }
        'docker-cruft'       = { Invoke-CleanDockerCruft }
        'ide-caches'         = { Invoke-CleanIdeCaches }
        'recycle-bin'        = { Invoke-CleanRecycleBin }
        'old-downloads'      = { Invoke-CleanOldDownloads }
        'outlook-cache'      = { Invoke-CleanOutlookCache }
    }

    foreach ($target in $orderedTargets) {
        $current++
        Write-Host "  " -NoNewline
        Write-Color ([char]0x27F3).ToString() Red
        Write-Host " [$current/$total] $($script:CleanTargetNames[$target])..." -NoNewline

        if ($cleanFuncMap.ContainsKey($target)) {
            & $cleanFuncMap[$target]
        } else {
            $script:CleanResultStatus[$target] = "fail"
            Write-CleanLogEntry "FAIL" "$target -- no clean function"
        }

        # Clear progress line
        Write-Host "`r" -NoNewline
        Write-Host ("  " + (" " * 70)) -NoNewline
        Write-Host "`r" -NoNewline

        $status = if ($script:CleanResultStatus.ContainsKey($target)) { $script:CleanResultStatus[$target] } else { "skip" }
        $freed = if ($script:CleanResultBytes.ContainsKey($target)) { [long]$script:CleanResultBytes[$target] } else { [long]0 }
        $freedStr = ""
        if ($freed -gt 0) { $freedStr = " ($(Format-CleanBytes $freed))" }

        switch ($status) {
            "pass" {
                Write-Host "  " -NoNewline; Write-Color ([char]0x2713).ToString() Green
                Write-Host " [$current/$total] $($script:CleanTargetNames[$target])$freedStr"
            }
            "skip" {
                Write-Host "  " -NoNewline; Write-Color ([char]0x25CB).ToString() Green
                Write-Host " [$current/$total] $($script:CleanTargetNames[$target]) " -NoNewline
                Write-ColorLine "(nothing to clean)" DarkYellow
            }
            "fail" {
                Write-Host "  " -NoNewline; Write-Color ([char]0x2717).ToString() Red
                Write-Host " [$current/$total] $($script:CleanTargetNames[$target]) " -NoNewline
                Write-ColorLine "(failed)" Red
            }
            "partial" {
                Write-Host "  " -NoNewline; Write-Color ([char]0x25D0).ToString() Red
                Write-Host " [$current/$total] $($script:CleanTargetNames[$target])$freedStr " -NoNewline
                Write-ColorLine "(partial)" Red
            }
        }
    }
}

# ═══════════════════════════════════════════════════════════════════
# SYSTEM CLEANER — CLEANLINESS SCORE
# ═══════════════════════════════════════════════════════════════════
function Get-CleanScore {
    $earned = 0; $possible = 0

    foreach ($target in $script:CleanTargets.Keys) {
        if (-not $script:CleanTargets[$target]) { continue }
        $sev = if ($script:CleanSeverity.ContainsKey($target)) { $script:CleanSeverity[$target] } else { "LOW" }
        $weight = $script:SeverityWeight[$sev]
        $possible += $weight

        $status = if ($script:CleanResultStatus.ContainsKey($target)) { $script:CleanResultStatus[$target] } else { "skip" }
        switch ($status) {
            "pass"    { $earned += $weight }
            "skip"    { $earned += $weight }
            "partial" { $earned += [int]($weight / 2) }
            "fail"    { }
        }
    }

    $pct = 0
    if ($possible -gt 0) { $pct = [int](($earned * 100) / $possible) }
    return @{ Earned = $earned; Possible = $possible; Percent = $pct }
}

# ═══════════════════════════════════════════════════════════════════
# SYSTEM CLEANER — SUMMARY TABLE
# ═══════════════════════════════════════════════════════════════════
function Show-CleanSummary {
    $orderedTargets = @()
    foreach ($cat in $script:CleanCatOrder) {
        foreach ($target in $script:CleanCatTargets[$cat]) {
            if ($script:CleanTargets.ContainsKey($target) -and $script:CleanTargets[$target]) {
                $orderedTargets += $target
            }
        }
    }

    $totalFiles = 0; $totalBytes = [long]0

    Write-Host ""
    Write-ColorLine "  +----------------------------------------------------------+" Green
    Write-ColorLine "  |                  CLEANING SUMMARY                         |" Green
    Write-ColorLine "  +----------------------------------------------------------+" Green
    Write-Host ("  {0,-34} {1,8} {2,10} {3,8}" -f "  Target","Removed","Freed","Status") -ForegroundColor Green
    Write-ColorLine "  ----  --------------------------------  --------  ----------  --------" DarkYellow

    foreach ($target in $orderedTargets) {
        $files = if ($script:CleanResultFiles.ContainsKey($target)) { $script:CleanResultFiles[$target] } else { 0 }
        $bytes = if ($script:CleanResultBytes.ContainsKey($target)) { [long]$script:CleanResultBytes[$target] } else { [long]0 }
        $status = if ($script:CleanResultStatus.ContainsKey($target)) { $script:CleanResultStatus[$target] } else { "skip" }

        $fileStr = if ($files -eq 0) { [string]([char]0x2014) } else { "$files" }
        $sizeStr = if ($bytes -gt 0) { Format-CleanBytes $bytes } else { [string]([char]0x2014) }

        $statusStr = ""; $color = "White"
        switch ($status) {
            "pass"    { $statusStr = "PASS";    $color = "Green" }
            "skip"    { $statusStr = "SKIP";    $color = "DarkYellow" }
            "fail"    { $statusStr = "FAIL";    $color = "Red" }
            "partial" { $statusStr = "PARTIAL"; $color = "DarkYellow" }
        }

        Write-Host ("  {0,-34} {1,8} {2,10} {3,8}" -f "  $($script:CleanTargetNames[$target])",$fileStr,$sizeStr,$statusStr) -ForegroundColor $color

        $totalFiles += $files
        $totalBytes += $bytes
    }

    Write-ColorLine "  ----  --------------------------------  --------  ----------  --------" DarkYellow
    Write-Host ("  {0,-34} {1,8} {2,10}" -f "  TOTAL","$totalFiles","$(Format-CleanBytes $totalBytes)") -ForegroundColor Green
    Write-ColorLine "  +----------------------------------------------------------+" Green
    Write-Host ""

    # Score bar
    $scoreResult = Get-CleanScore
    $pct = $scoreResult.Percent

    $color = "Red"
    if ($pct -ge 80) { $color = "Green" }
    elseif ($pct -ge 50) { $color = "DarkYellow" }

    $width = 20
    $filled = [int](($pct * $width) / 100)
    $empty = $width - $filled
    $barFull = [string]::new([char]0x2588, $filled)
    $barEmpty = [string]::new([char]0x2591, $empty)

    Write-Host "  Cleanliness Score: " -NoNewline -ForegroundColor Green
    Write-Color "$pct/100" $color
    Write-Host " [" -NoNewline
    Write-Color $barFull $color
    Write-Color $barEmpty $color
    Write-Host "]"
    Write-Host ""
}

# ═══════════════════════════════════════════════════════════════════
# SYSTEM CLEANER — WRITE LOG FILE
# ═══════════════════════════════════════════════════════════════════
function Write-CleanLog {
    New-Item -ItemType Directory -Path (Split-Path $script:CleanLogFile) -Force | Out-Null

    $logContent = @()
    if (Test-Path $script:CleanLogFile) {
        $logContent += ""
        $logContent += [string]::new([char]0x2500, 40)
        $logContent += ""
    }
    $logContent += "# System Cleaner Log -- $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $logContent += "OS: Windows | Date: $($script:DATE)"
    $logContent += ""
    foreach ($entry in $script:CleanLogEntries) {
        $logContent += $entry
    }

    $logContent | Out-File -FilePath $script:CleanLogFile -Encoding UTF8 -Append
    Write-ColorLine "  Log: $($script:CleanLogFile)" DarkYellow
}

# ═══════════════════════════════════════════════════════════════════
# SYSTEM CLEANER — MAIN ENTRY POINT
# ═══════════════════════════════════════════════════════════════════
function Invoke-Clean {
    Write-Host ""
    Write-ColorLine "╔══════════════════════════════════════════════════╗" Green
    Write-Host "║" -ForegroundColor Green -NoNewline
    Write-Host "          BARKED SYSTEM CLEANER v$($script:VERSION)           " -ForegroundColor Green -NoNewline
    Write-ColorLine "║" Green
    Write-Host "║" -ForegroundColor Green -NoNewline
    Write-Host "                     Windows                       " -NoNewline
    Write-ColorLine "║" Green
    Write-ColorLine "╚══════════════════════════════════════════════════╝" Green

    Show-CleanPicker
    Show-CleanDrilldown
    Show-CleanPreview

    # Dry-run: show preview and exit
    if ($DryRun) {
        Write-Host ""
        Write-Host "  " -NoNewline; Write-Color "[DRY RUN] Green; Write-Host " Preview only -- no files deleted."
        return
    }

    # Confirmation
    if (-not $Force) {
        Write-Host ""
        Write-Host "  Proceed with cleaning? (y/N): " -NoNewline -ForegroundColor Green
        $confirm = Read-Host
        if ($confirm.ToLower() -ne 'y') {
            Write-ColorLine "  Cancelled." DarkYellow
            return
        }
    }

    Invoke-CleanExecute
    Show-CleanSummary
    Write-CleanLog

    Write-Host ""
    Write-ColorLine "  Re-run with -Clean anytime -- safe to repeat." DarkYellow
    Write-Host ""
}

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
    try {
        $response = Invoke-RestMethod -Uri "https://api.github.com/repos/$($script:GITHUB_REPO)/releases/latest" -TimeoutSec 10
        $tag = $response.tag_name
        if (-not $tag) { return $null }
        return $tag -replace '^v', ''
    } catch {
        return $null
    }
}

function Invoke-Update {
    Write-ColorLine "Checking for updates..." DarkYellow

    $latest = Get-LatestVersion
    if (-not $latest) {
        Write-ColorLine "Could not reach GitHub to check for updates." Red
        exit 1
    }

    if (-not (Test-VersionGt -New $latest -Current $script:VERSION)) {
        Write-ColorLine "Already up to date (v$($script:VERSION))." Green
        exit 0
    }

    # Elevate if needed
    if (-not (Test-IsAdmin)) { Request-Elevation }

    $installDir = "C:\Program Files\Barked"
    $installPath = Join-Path $installDir "barked.ps1"
    $tmpFile = Join-Path $env:TEMP "barked-new-$(Get-Random).ps1"
    $downloadUrl = "https://github.com/$($script:GITHUB_REPO)/releases/latest/download/barked.ps1"

    try {
        Invoke-WebRequest -Uri $downloadUrl -OutFile $tmpFile -TimeoutSec 30 -ErrorAction Stop
    } catch {
        Write-ColorLine "Failed to download update." Red
        Remove-Item -Path $tmpFile -Force -ErrorAction SilentlyContinue
        exit 1
    }

    # Validate syntax
    $errors = $null
    [System.Management.Automation.Language.Parser]::ParseFile($tmpFile, [ref]$null, [ref]$errors) | Out-Null
    if ($errors.Count -gt 0) {
        Write-ColorLine "Downloaded file has syntax errors — aborting update." Red
        Remove-Item -Path $tmpFile -Force -ErrorAction SilentlyContinue
        exit 1
    }

    # Create install directory if needed
    if (-not (Test-Path $installDir)) {
        New-Item -ItemType Directory -Path $installDir -Force | Out-Null
    }

    Move-Item -Path $tmpFile -Destination $installPath -Force
    Write-ColorLine "Updated to v${latest}." Green
    exit 0
}

function Invoke-PassiveUpdateCheck {
    $cacheFile = Join-Path $env:TEMP "barked-update-check"
    $cacheMax = 86400
    $now = [int][double]::Parse((Get-Date -UFormat %s))

    try {
        if (Test-Path $cacheFile) {
            $lines = Get-Content $cacheFile -ErrorAction Stop
            if ($lines.Count -ge 2) {
                $cachedEpoch = [int]$lines[0]
                $cachedVersion = $lines[1]

                if (($now - $cachedEpoch) -lt $cacheMax) {
                    if ($cachedVersion -and (Test-VersionGt -New $cachedVersion -Current $script:VERSION)) {
                        Write-ColorLine "A new version is available (v${cachedVersion}). Run: barked -Update" Green
                    }
                    return
                }
            }
        }

        $latest = Get-LatestVersion
        if (-not $latest) { return }

        @($now, $latest) | Set-Content $cacheFile -ErrorAction SilentlyContinue

        if (Test-VersionGt -New $latest -Current $script:VERSION) {
            Write-ColorLine "A new version is available (v${latest}). Run: barked -Update" Green
        }
    } catch {
        return
    }
}

function Invoke-UninstallSelf {
    $installDir = "C:\Program Files\Barked"
    $installPath = Join-Path $installDir "barked.ps1"
    $cmdPath = Join-Path $installDir "barked.cmd"

    if (-not (Test-Path $installPath)) {
        Write-ColorLine "barked not found at ${installPath}. Nothing to uninstall." Red
        exit 1
    }

    # Elevate if needed
    if (-not (Test-IsAdmin)) { Request-Elevation }

    # Remove barked files
    Remove-Item -Path $installPath -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $cmdPath -Force -ErrorAction SilentlyContinue

    # Remove from system PATH
    $machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    if ($machinePath -and $machinePath.Contains($installDir)) {
        $newPath = ($machinePath -split ';' | Where-Object { $_ -ne $installDir }) -join ';'
        [Environment]::SetEnvironmentVariable("Path", $newPath, "Machine")
    }

    # Remove empty directory
    if ((Test-Path $installDir) -and @(Get-ChildItem $installDir -Force).Count -eq 0) {
        Remove-Item -Path $installDir -Force -ErrorAction SilentlyContinue
    }

    # Clean cache
    $cacheFile = Join-Path $env:TEMP "barked-update-check"
    Remove-Item -Path $cacheFile -Force -ErrorAction SilentlyContinue

    Write-ColorLine "barked has been removed from ${installDir}." Green
    exit 0
}

# ═══════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════
function Print-Help {
    Write-Host ""
    Write-Host "Usage: barked.ps1 [options]"
    Write-Host ""
    Write-Host "Options:"
    Write-Host "  -Uninstall    Full uninstall — revert all hardening changes"
    Write-Host "  -Modify       Interactive module picker — add or remove individual modules"
    Write-Host "  -Audit        Score system security without making changes"
    Write-Host "  -Clean        System cleaner — remove caches, logs, browser data, and more"
    Write-Host "  -CleanSchedule    Set up scheduled cleaning"
    Write-Host "  -CleanUnschedule  Remove scheduled cleaning"
    Write-Host "  -Force        Skip confirmation prompts (use with -Clean)"
    Write-Host "  -DryRun       Preview changes without applying them (use with -Clean)"
    Write-Host "  -Auto         Run non-interactively (requires -Profile)"
    Write-Host "  -Profile <name> Set security profile: standard, high, paranoid"
    Write-Host "  -Quiet        Suppress console output (requires -Auto or -Audit)"
    Write-Host "  -Help         Show this help message"
    Write-Host "  -Version        Show version and exit"
    Write-Host "  -Update         Update barked to the latest version"
    Write-Host "  -UninstallSelf  Remove barked from system PATH"
    Write-Host ""
    Write-Host "Examples:"
    Write-Host "  .\barked.ps1                        Interactive wizard"
    Write-Host "  .\barked.ps1 -Audit                 Security audit (read-only)"
    Write-Host "  .\barked.ps1 -Clean                 Interactive system cleaner"
    Write-Host "  .\barked.ps1 -Clean -DryRun         Preview what would be cleaned"
    Write-Host "  .\barked.ps1 -Clean -Force          Clean without confirmation"
    Write-Host "  .\barked.ps1 -CleanSchedule          Set up recurring clean"
    Write-Host "  .\barked.ps1 -Auto -Profile standard  Non-interactive hardening"
    Write-Host ""
    Write-Host "No options: launch the interactive hardening wizard."
    Write-Host ""
}

function Main {
    # Parse params
    if ($Help) {
        Print-Help
        exit 0
    }
    if ($Version) {
        Write-Host "barked v$($script:VERSION)"
        exit 0
    }
    # Validate flag combinations
    if ($Auto -and -not $Profile) {
        Write-Host "Error: -Auto requires -Profile <name>" -ForegroundColor Red
        exit 1
    }
    if ($Profile -and $Profile -notin @("standard", "high", "paranoid")) {
        Write-Host "Error: -Profile must be one of: standard, high, paranoid (got '$Profile')" -ForegroundColor Red
        exit 1
    }
    if ($Quiet -and -not $Auto -and -not $Audit) {
        Write-Host "Error: -Quiet requires -Auto or -Audit" -ForegroundColor Red
        exit 1
    }
    if ($Quiet) {
        $script:QuietMode = $true
    }
    if ($Update) {
        Invoke-Update
    }
    if ($UninstallSelf) {
        Invoke-UninstallSelf
    }
    if ($Uninstall) {
        $script:RunMode = "uninstall"
    }
    if ($Modify) {
        $script:RunMode = "modify"
    }

    if ($CleanScheduled) {
        Run-ScheduledClean
        exit 0
    }

    if ($CleanSchedule) {
        Print-Header
        Setup-ScheduledClean
        Invoke-PassiveUpdateCheck
        exit 0
    }

    if ($CleanUnschedule) {
        Print-Header
        Unschedule-ScheduledClean
        Invoke-PassiveUpdateCheck
        exit 0
    }

    if ($Clean) {
        Invoke-Clean
        Invoke-PassiveUpdateCheck
        exit 0
    }

    if ($Audit) {
        Print-Header
        Write-Host "  Detected: " -NoNewline
        Write-ColorLine "Windows $(([System.Environment]::OSVersion.Version))" Green
        Run-Audit
        Invoke-PassiveUpdateCheck
        exit 0
    }

    if ($Auto) {
        if (-not $script:QuietMode) {
            Print-Header
            Write-Host "  Detected: " -NoNewline
            Write-ColorLine "Windows $(([System.Environment]::OSVersion.Version))" Green
        }

        $script:Profile = $Profile
        Build-ModuleList

        # Check if elevation is needed
        if (-not (Test-IsAdmin) -and -not $Elevated) {
            $adminModules = @('firewall-inbound','firewall-stealth','dns-secure','auto-updates',
                              'guest-disable','hostname-scrub','telemetry-disable')
            $needsAdmin = $false
            foreach ($mod in $script:EnabledModules) {
                if ($adminModules -contains $mod) { $needsAdmin = $true; break }
            }
            if ($needsAdmin) { Request-Elevation }
        }

        Run-AllModules
        if ($DryRun) {
            Write-DryRunReport
        } else {
            Write-State
            Print-Summary
        }
        Write-Log
        $exitCode = 0
        if (-not $DryRun -and $script:CountFailed -gt 0) { $exitCode = 1 }
        exit $exitCode
    }

    Print-Header
    Write-Host "  Detected: " -NoNewline
    Write-ColorLine "Windows $(([System.Environment]::OSVersion.Version))" Green

    switch ($script:RunMode) {
        "uninstall" {
            if (-not (Test-IsAdmin)) { Request-Elevation }
            Run-Uninstall
            Write-Log
            Invoke-PassiveUpdateCheck
            return
        }
        "modify" {
            if (-not (Test-IsAdmin)) { Request-Elevation }
            Run-Modify
            Write-Log
            Invoke-PassiveUpdateCheck
            return
        }
        default {
            # Normal hardening flow
            Select-Profile

            # Menu may have changed RunMode
            if ($script:RunMode -eq "uninstall") {
                if (-not (Test-IsAdmin)) { Request-Elevation }
                Run-Uninstall
                Write-Log
                Invoke-PassiveUpdateCheck
                return
            }
            if ($script:RunMode -eq "modify") {
                if (-not (Test-IsAdmin)) { Request-Elevation }
                Run-Modify
                Write-Log
                Invoke-PassiveUpdateCheck
                return
            }

            Select-OutputMode
            Build-ModuleList

            # Check if elevation is needed
            if (-not (Test-IsAdmin) -and -not $Elevated) {
                $adminModules = @('firewall-inbound','firewall-stealth','dns-secure','auto-updates',
                                  'guest-disable','hostname-scrub','telemetry-disable')
                $needsAdmin = $false
                foreach ($mod in $script:EnabledModules) {
                    if ($adminModules -contains $mod) { $needsAdmin = $true; break }
                }
                if ($needsAdmin) { Request-Elevation }
            }

            Write-Host ""
            Write-Host "  Modules to apply: " -NoNewline; Write-ColorLine $script:TotalModules Green
            Write-Host ""
            if (-not (Prompt-YN "Proceed with hardening?")) {
                Write-Host "Aborted."
                exit 0
            }

            Run-AllModules

            if ($DryRun) {
                Write-DryRunReport
            } else {
                # Write state after hardening
                Write-State

                Print-Summary

                switch ($script:OutputMode) {
                    "checklist" { Print-ManualChecklist }
                    "pause"     { } # Already guided
                    "report"    { Write-Report }
                }
            }

            Write-Log

            Invoke-PassiveUpdateCheck
            Write-Host ""
            Write-ColorLine "  Re-run this script anytime — it's safe to repeat." DarkYellow
            Write-Host ""
        }
    }
}

Main
