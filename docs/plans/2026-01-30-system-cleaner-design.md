# System Cleaner Design

**Date:** 2026-01-30
**Status:** Draft
**Version:** 1.0

## Overview

A system cleaner feature integrated into `barked.sh` (macOS/Linux) and `barked.ps1` (Windows), invoked via `--clean`. Provides privacy-focused cleaning and disk space recovery with a two-level interactive picker, size-estimated preview, and cleanliness scoring. Cross-platform from day one.

## CLI Interface

```
sudo ./barked.sh --clean              # Interactive cleaning wizard
sudo ./barked.sh --clean --dry-run    # Preview only, no deletions
sudo ./barked.sh --clean --force      # Skip confirmation after preview
sudo ./barked.sh --clean --quiet      # Minimal output, log to file only
```

Windows equivalent:
```
.\barked.ps1 --clean
.\barked.ps1 --clean --dry-run
.\barked.ps1 --clean --force
.\barked.ps1 --clean --quiet
```

## Flow

1. OS detection (reuse existing)
2. Privilege check (reuse existing)
3. Two-level picker: select categories, optionally drill into individual targets
4. Scan selected targets and calculate size estimates
5. Display preview table with per-target sizes and total reclaimable space
6. Ask for confirmation (unless `--force`)
7. Execute cleaning, logging each deletion
8. Display summary table with files removed, space freed, pass/fail per target
9. Calculate and display cleanliness score
10. Write detailed log to `audits/clean-log-YYYY-MM-DD.txt`

State: Unlike hardening modules, cleaning doesn't write to `hardening-state.json` — there's nothing to undo. Each run logs results to the audit log for history.

## Cleaning Categories & Targets

### 1. System Caches & Logs

| Target | macOS | Linux | Windows |
|--------|-------|-------|---------|
| System cache | `/Library/Caches` | `/var/cache/apt`, `/var/cache/dnf` | `C:\Windows\Temp` |
| System logs | `/Library/Logs`, `/var/log/asl` | `journalctl --vacuum-time=7d` | `wevtutil cl System` |
| Diagnostic reports | `/Library/Logs/DiagnosticReports` | `/var/crash` | `C:\ProgramData\Microsoft\Windows\WER` |
| DNS cache | `dscacheutil -flushcache` | `systemd-resolve --flush-caches` | `ipconfig /flushdns` |

### 2. User Caches & Logs

| Target | macOS | Linux | Windows |
|--------|-------|-------|---------|
| User cache | `~/Library/Caches` | `~/.cache` | `%LOCALAPPDATA%\Temp` |
| User logs | `~/Library/Logs` | `~/.local/share/logs` | `%LOCALAPPDATA%\CrashDumps` |
| Saved application state | `~/Library/Saved Application State` | n/a | n/a |

### 3. Browser Data

Per-browser targets (cache, cookies, history, local storage, session data). Users toggle per-browser, not per-data-type.

| Browser | macOS | Linux | Windows |
|---------|-------|-------|---------|
| Safari | `~/Library/Caches/com.apple.Safari` + related | n/a | n/a |
| Chrome | `~/Library/Caches/Google/Chrome` | `~/.cache/google-chrome` | `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cache` |
| Firefox | `~/Library/Caches/Firefox` | `~/.cache/mozilla/firefox` | `%LOCALAPPDATA%\Mozilla\Firefox\Profiles` |
| Arc | `~/Library/Caches/Arc` | n/a | n/a |
| Edge | n/a (unless installed) | n/a (unless installed) | `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Cache` |

The picker auto-detects installed browsers and only shows relevant targets.

### 4. Privacy Traces

| Target | macOS | Linux | Windows |
|--------|-------|-------|---------|
| Recent items | `~/Library/Application Support/com.apple.sharedfilelist` | `~/.local/share/recently-used.xbel` | `%APPDATA%\Microsoft\Windows\Recent` |
| QuickLook thumbnails | `~/Library/Caches/com.apple.QuickLook.thumbnailcache` | n/a | `%LOCALAPPDATA%\Microsoft\Windows\Explorer\thumbcache_*` |
| `.DS_Store` files | Recursive from `$HOME` | n/a | n/a |
| Clipboard | `pbcopy </dev/null` | `xclip -selection clipboard /dev/null` | `echo.\|clip` |
| Search metadata | Spotlight rebuild guidance | Tracker cleanup | Windows Search index guidance |

### 5. Developer Cruft

| Target | macOS | Linux | Windows |
|--------|-------|-------|---------|
| Xcode derived data | `~/Library/Developer/Xcode/DerivedData` | n/a | n/a |
| Homebrew cache | `brew cleanup` | `brew cleanup` (if installed) | n/a |
| npm cache | `npm cache clean --force` | Same | Same |
| yarn cache | `yarn cache clean` | Same | Same |
| pip cache | `pip cache purge` | Same | Same |
| Cargo cache | `~/.cargo/registry/cache` | Same | `%USERPROFILE%\.cargo\registry\cache` |
| Go cache | `go clean -cache` | Same | Same |
| CocoaPods cache | `~/Library/Caches/CocoaPods` | n/a | n/a |
| Docker cruft | `docker system prune` (dangling images, build cache, stopped containers) | Same | Same |
| IDE caches | VS Code, JetBrains caches | Same | Same |

Developer targets auto-detect installed tools and hide targets that don't apply.

### 6. Trash & Downloads

| Target | macOS | Linux | Windows |
|--------|-------|-------|---------|
| Trash | `~/.Trash` | `~/.local/share/Trash` | `Clear-RecycleBin` |
| Old downloads | `~/Downloads` files older than 30 days | Same | Same |

The downloads age threshold (30 days) is user-configurable.

### 7. Mail & Messages

| Target | macOS | Linux | Windows |
|--------|-------|-------|---------|
| Mail attachment cache | `~/Library/Containers/com.apple.mail` | Thunderbird cache | Outlook cache |
| Messages attachments | `~/Library/Messages/Attachments` | n/a | n/a |

## Two-Level Picker UI

### Level 1 — Category Selection

```
╔══════════════════════════════════════╗
║         SYSTEM CLEANER              ║
╠══════════════════════════════════════╣
║  Select categories to clean:        ║
║                                     ║
║  [1] System Caches & Logs           ║
║  [2] User Caches & Logs             ║
║  [3] Browser Data                   ║
║  [4] Privacy Traces                 ║
║  [5] Developer Cruft                ║
║  [6] Trash & Downloads              ║
║  [7] Mail & Messages                ║
║                                     ║
║  [A] Select All                     ║
║  [N] Select None / Reset            ║
╚══════════════════════════════════════╝
Toggle (1-7, A, N) then press Enter to continue:
```

Users type numbers to toggle categories on/off (shown with `[*]` when selected). Press Enter with no input to proceed.

### Level 2 — Target Drill-Down

After confirming categories, the picker asks: `Drill into individual targets? (y/N)`

If yes, each selected category expands:

```
── Browser Data ──────────────────────
  [1] Safari cache & data        [*]
  [2] Chrome cache & data        [*]
  [3] Firefox cache & data       [*]
  [4] Arc cache & data           [ ]
  Enter to keep, or toggle (1-4):
```

Only targets relevant to the detected OS are shown. Targets auto-detect installed software (browsers, dev tools) and hide those that don't apply. If drill-down is skipped, all targets within selected categories are included.

## Scan, Preview & Confirmation

### Scanning

Each target has a `scan_<target>()` function that calculates file count and disk usage without deleting anything. Uses `du -sh` (macOS/Linux) or PowerShell `Measure-Object` (Windows). Targets that don't exist or are empty are marked "Nothing to clean" and skipped.

### Preview Table

```
╔══════════════════════════════════════════════════════════╗
║                   CLEANING PREVIEW                       ║
╠══════════════════════════════════════════════════════════╣
║  Target                        Files    Size    Status   ║
║  ─────────────────────────────────────────────────────   ║
║  System cache                  1,204    2.3 GB  Ready    ║
║  System logs                     847    640 MB  Ready    ║
║  Diagnostic reports               23     12 MB  Ready    ║
║  Safari cache & data             312    890 MB  Ready    ║
║  Chrome cache & data           2,108    1.7 GB  Ready    ║
║  QuickLook thumbnails            156    210 MB  Ready    ║
║  .DS_Store files               4,891    4.8 MB  Ready    ║
║  Clipboard                         -       -   Ready    ║
║  Xcode derived data              89     8.1 GB  Ready    ║
║  Docker build cache               -    3.2 GB  Ready    ║
║  Trash                           412    5.6 GB  Ready    ║
║  ─────────────────────────────────────────────────────   ║
║  TOTAL                        10,042   22.7 GB           ║
╚══════════════════════════════════════════════════════════╝

Proceed with cleaning? (y/N):
```

- `--dry-run`: Display preview and exit without prompting
- `--force`: Skip prompt, begin cleaning immediately

### Safety Guardrails

- Never follow symlinks outside the target path
- Never delete files modified in the last 60 seconds (in-use protection)
- Skip targets that require root if not running with `sudo`
- Browser targets check if the browser is running and warn the user to close it first

## Module Pattern

Each cleaning target is implemented with four functions:

```
scan_<target>()   — Calculate file count and size, return estimates
clean_<target>()  — Delete files, log each deletion
verify_<target>() — Confirm target directory is clean/reduced
score_<target>()  — Return weighted score contribution
```

### Execution per target

1. Call `clean_<target>()` which iterates files/directories
2. Each deletion is logged: timestamp, path, size, success/fail
3. Call `verify_<target>()` to confirm cleanup worked
4. Record result (files removed, bytes freed, pass/fail)

### Deletion strategy by target type

- **Directory contents** (caches, logs): Remove contents but preserve the directory itself. Uses `rm -rf` on contents, not the parent. Recreate empty dirs if needed for app stability.
- **Individual files** (`.DS_Store`, thumbnails): `find` + `rm` with depth limits to avoid runaway recursion.
- **System commands** (DNS flush, clipboard clear, Docker prune): Execute the platform-specific command directly.
- **Package manager caches** (`brew cleanup`, `npm cache clean`, `pip cache purge`): Delegate to the tool's own cleanup command when available, fall back to manual deletion only if the tool isn't installed.

### Error handling

- Permission denied: Log and skip, don't abort the run
- File in use: Skip with warning, continue to next file
- Target not found: Mark as "Skipped — not present" in results
- Partial failure: Report per-target pass/partial/fail status

## Cleanliness Score

Each target has a fixed weight based on its privacy/hygiene impact:

| Weight | Targets |
|--------|---------|
| CRITICAL (10) | Browser data, privacy traces, clipboard |
| HIGH (7) | User caches, mail/messages attachments, QuickLook thumbnails |
| MEDIUM (4) | System caches, system logs, developer cruft, DNS cache |
| LOW (2) | Trash, old downloads, `.DS_Store` files, diagnostic reports |

### Calculation

```
earned  = sum of weights for targets successfully cleaned
possible = sum of weights for all selected targets
score   = (earned / possible) * 100
```

- Targets skipped due to "nothing to clean" count as earned (already clean)
- Targets that failed count as zero

## Summary Report

```
╔══════════════════════════════════════════════════════════╗
║                  CLEANING SUMMARY                        ║
╠══════════════════════════════════════════════════════════╣
║  Target                     Removed    Freed    Status   ║
║  ──────────────────────────────────────────────────────  ║
║  System cache                 1,204    2.3 GB   PASS     ║
║  Safari cache & data            312    890 MB   PASS     ║
║  Docker build cache               -    3.2 GB   PASS     ║
║  Clipboard                        -       -     PASS     ║
║  Spotify cache                    -       -     SKIP     ║
║  ──────────────────────────────────────────────────────  ║
║  TOTAL                        8,941   21.2 GB            ║
║                                                          ║
║  Cleanliness Score: 94/100                               ║
║  Log: audits/clean-log-2026-01-30.txt                    ║
╚══════════════════════════════════════════════════════════╝
```

## Logging

Every deletion writes a line to `audits/clean-log-YYYY-MM-DD.txt`:

```
2026-01-30 14:23:01 [CLEAN] Removed ~/Library/Caches/com.apple.Safari (890 MB)
2026-01-30 14:23:01 [SKIP]  ~/Library/Caches/com.spotify.client (in use)
2026-01-30 14:23:02 [FAIL]  /Library/Logs/DiagnosticReports (permission denied)
```

Repeated runs on the same day append to the same log file with a separator line between runs.

## Implementation Split

- `barked.sh`: macOS + Linux targets (Bash, following existing multi-platform patterns with `case $OS_TYPE`)
- `barked.ps1`: Windows targets (PowerShell, matching existing Windows module style)

Both scripts share the same CLI flags, picker UI design, scoring weights, and log format.
