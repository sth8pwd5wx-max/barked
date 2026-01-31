# Install & Update System Design

**Date:** 2026-01-30
**Status:** Draft
**Version:** 1.0

## Overview

Add a system install mechanism and self-update system for barked. Users install via a curl one-liner (macOS/Linux) or PowerShell one-liner (Windows), which downloads the latest release from GitHub. Once installed, `barked --update` pulls new versions, and a passive check notifies users of available updates after each run.

## Install System

### macOS/Linux

Users run:

```
curl -fsSL https://raw.githubusercontent.com/sth8pwd5wx-max/barked/main/install.sh | sudo bash
```

`install.sh` does:

1. Detect OS (macOS vs Linux) and architecture
2. Download the latest `barked.sh` from the newest GitHub release
3. Copy to `/usr/local/bin/barked` with `chmod +x`
4. Verify it runs (`barked --version`)
5. Print success message with version installed

### Windows

Users run:

```powershell
irm https://raw.githubusercontent.com/sth8pwd5wx-max/barked/main/install.ps1 | iex
```

`install.ps1` does:

1. Download latest `barked.ps1` from the newest GitHub release
2. Copy to `C:\Program Files\Barked\barked.ps1`
3. Add that directory to the system PATH (if not already there)
4. Create a wrapper `barked.cmd` so users can type `barked` from cmd.exe
5. Print success message

### Uninstall

`barked --uninstall-self` removes the binary and PATH entry. Separate from `--uninstall` which reverts hardening changes.

## Update System

### Manual Update (`barked --update`)

Built into both `barked.sh` and `barked.ps1`:

1. Query GitHub releases API: `https://api.github.com/repos/sth8pwd5wx-max/barked/releases/latest`
2. Extract the latest version tag (e.g., `v2.1.0`)
3. Compare against local `VERSION` using semver comparison
4. If newer: download new script from release assets, validate syntax, atomic replace
5. If current: print "Already up to date (vX.Y.Z)"

Requires `curl` (macOS/Linux) or `Invoke-RestMethod` (Windows, built-in).

### Passive Update Check

Runs after every barked invocation (harden, audit, clean) completes:

1. Query the same GitHub API endpoint
2. If newer version exists, print: `A new version is available (v2.1.0). Run: barked --update`
3. If API call fails (no internet, rate-limited), silently skip
4. Cache result in `/tmp/barked-update-check` with timestamp. Re-check only if cache is older than 24 hours

The passive check runs after the main work, never before. It never delays or blocks the actual task.

## GitHub Release Workflow

### Release Process

1. Bump `VERSION` in both `barked.sh` and `barked.ps1`
2. Commit and tag: `git tag vX.Y.Z`
3. Create GitHub release: `gh release create vX.Y.Z` with `barked.sh` and `barked.ps1` as release assets

Install and update scripts download from release assets (not raw repo files), so users always get a tagged, stable version.

### New CLI Flags

- `--version` / `-Version`: Print version and exit (`barked v2.0.0`)
- `--update` / `-Update`: Check for and apply updates
- `--uninstall-self`: Remove barked from system PATH

### Version Comparison

- Bash: split on dots, compare major/minor/patch numerically
- PowerShell: cast to `[version]`, use `-gt`
- No external dependencies needed

## Safety & Edge Cases

### Self-Replacement

`--update` never overwrites the running script directly:

1. Download to temp file (`/tmp/barked-new.sh`)
2. Validate syntax (`bash -n` / PowerShell parse check)
3. Compare checksums to confirm download integrity
4. Atomic replace via `mv` (same filesystem) or copy-then-remove
5. If any step fails, old version stays untouched

### Permissions

`--update` requires sudo (macOS/Linux) or admin (Windows). Without privileges: `Update requires sudo. Run: sudo barked --update`

### No Internet

- Passive check: silent skip
- `--update`: print "Could not reach GitHub. Check your connection."

### Rate Limiting

GitHub allows 60 unauthenticated requests/hour. The 24-hour cache on the passive check keeps typical usage well within limits.

### Rollback

Not included. Syntax validation guards against broken updates. If an update causes issues, re-run the install one-liner or `--update` once a fix is published.

## File Layout

```
├── install.sh          # macOS/Linux installer (new, repo root)
├── install.ps1         # Windows installer (new, repo root)
├── scripts/
│   ├── barked.sh       # +update functions, +--version, +--update, +--uninstall-self
│   └── barked.ps1      # +update functions, +-Version, +-Update, +uninstall-self
```

Installers live at repo root for short, clean raw GitHub URLs. Update logic lives inside the main scripts since they self-replace.
