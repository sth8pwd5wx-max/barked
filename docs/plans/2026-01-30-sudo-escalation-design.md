# Sudo-Per-Command Escalation Design

**Goal:** Refactor barked to run as the normal user by default and only escalate to sudo for specific commands that require root — fixing Homebrew failures and improving UX.

**Architecture:** Replace the current "run entire script as root, drop to user for brew" model with "run as user, escalate to root per-command." Cache sudo credentials once at startup with a keepalive loop.

## Core Changes

### Startup

Remove the `EUID -eq 0` gate. Replace with:

1. Detect if any enabled modules need root (firewall, DNS, system defaults, etc.)
2. If yes, run `sudo -v` once with message: `"Some hardening steps need admin privileges."`
3. Start background keepalive: `while true; do sudo -n -v; sleep 50; done &`
4. Trap EXIT to kill the keepalive process

### Helper Functions

- **Delete** `run_as_user()` — no longer needed, script is already the user
- **Add** `run_as_root()` — wrapper that calls `sudo "$@"`
- All `run_as_user` call sites become direct calls
- Root-requiring commands get wrapped with `run_as_root`

### Package Helpers

- macOS: `pkg_install()` and `pkg_install_cask()` call brew directly (no wrapper)
- Linux: `pkg_install()` uses `run_as_root apt-get` / `run_as_root dnf` / etc.

## Module Classification

### User-space (no sudo needed)

- `lock-screen` — user defaults
- `browser-basic`, `browser-fingerprint` — user's Firefox profile
- `ssh-harden` — user's `~/.ssh/config`
- `git-harden` — user's git config
- `vpn-killswitch` — mullvad CLI
- `audit-script` — user's LaunchAgent/crontab
- `firewall-outbound` (macOS) — brew install LuLu
- `monitoring-tools` (macOS) — brew install Objective-See tools
- `metadata-strip` (macOS) — brew install exiftool
- `dev-isolation` (macOS) — brew install UTM
- Manual modules (disk-encrypt, backup-guidance, border-prep, traffic-obfuscation)

### Root-required (wrap specific commands with run_as_root)

- `firewall-inbound` — socketfilterfw
- `firewall-stealth` — socketfilterfw
- `dns-secure` — networksetup -setdnsservers
- `auto-updates` — defaults write /Library/Preferences/
- `guest-disable` — defaults write /Library/Preferences/com.apple.loginwindow
- `hostname-scrub` — scutil --set
- `telemetry-disable` — defaults write (system domains only)

### Mixed (some commands root, some user)

- `firewall-outbound` (Linux) — ufw needs root
- `monitoring-tools` (Linux) — apt-get, systemctl need root
- `telemetry-disable` — system defaults need root, user gsettings don't
- `bluetooth-disable` (Linux) — systemctl needs root
- `kernel-sysctl`, `apparmor-enforce` — Linux root-only

## State File Migration

- Primary: `~/.config/barked/state.json` (user-writable, no root needed)
- Backup: `state/hardening-state.json` in project directory (unchanged)
- Migration: On first run, if `/etc/hardening-state.json` exists but user config doesn't, copy it over and remove the old one via `run_as_root rm`

## Log and Audit Files

- When running from source: `audits/` in project directory (unchanged)
- When installed to `/usr/local/bin/`: `~/.config/barked/logs/` instead of relative `../audits/`

## Clean Mode

- User-space targets (user caches, browser data, trash): direct
- System-space targets (system caches, system logs, DNS flush): `run_as_root`

## Install / Update / Uninstall-Self

- `install.sh` still requires `sudo` (writes to `/usr/local/bin/`)
- `barked --update` and `--uninstall-self` detect if binary is in a root-owned path and use `run_as_root` for file operations

## PowerShell (barked.ps1)

Windows can't cache UAC prompts like sudo. Approach:

1. Script starts as normal user
2. During module resolution, detect if any enabled modules need admin
3. If yes, re-launch the script elevated via `Start-Process -Verb RunAs` with all original arguments
4. If no admin modules needed, run entirely without elevation

## UX Change

```bash
# Before
sudo barked
sudo barked --clean

# After
barked                  # prompts for password when needed
barked --clean
```

Update README, help text, install script usage messages, and all documentation.
