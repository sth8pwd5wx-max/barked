# Barked

**Tough outer layer for your system.**

Cross-platform security hardening for macOS, Linux, and Windows.
One script. No dependencies. Every change reversible.

![macOS](https://img.shields.io/badge/macOS-supported-blue) ![Linux](https://img.shields.io/badge/Linux-supported-blue) ![Windows](https://img.shields.io/badge/Windows-supported-blue)

## What This Does

Barked wraps your system in a tough, protective layer. Pick a preset profile — Standard, High, or Paranoid — for fast deployment, or answer a short questionnaire to build a config matched to your threat model.

Under the bark:
- **Idempotent** — checks before changing, skips what's already applied
- **Reversible** — every change can be undone, previous values saved to state
- **Zero dependencies** — just Bash (macOS/Linux) or PowerShell (Windows)

## Get Barked

**macOS / Linux:**
```bash
curl -fsSL https://raw.githubusercontent.com/sth8pwd5wx-max/barked/main/install.sh | bash
```

Installs to `~/.local/bin`. No sudo needed for install or updates.

**Windows (PowerShell as Administrator):**
```powershell
irm https://raw.githubusercontent.com/sth8pwd5wx-max/barked/main/install.ps1 | iex
```

Run `barked` from anywhere. The wizard takes it from there.

### Update

```bash
barked --update                   # macOS / Linux
barked -Update                    # Windows
```

Barked also checks for updates after each run and notifies you if a new version is available.

### Uninstall Barked

To remove barked itself from your system (not to revert hardening changes):
```bash
barked --uninstall-self            # macOS / Linux
barked -UninstallSelf             # Windows
```

### Manual Install (from source)

```bash
git clone https://github.com/sth8pwd5wx-max/barked
cd barked
chmod +x scripts/barked.sh
./scripts/barked.sh
```

Windows:
```powershell
git clone https://github.com/sth8pwd5wx-max/barked
cd barked
.\scripts\barked.ps1
```

## How It Works

Every module follows four rings of protection:

```
check_state ──→ apply ──→ verify ──→ (revert)
     │                       │
     │ already applied       │ failed
     ▼                       ▼
  [SKIP]                 [LOG ERROR]
```

1. **Check** — Already applied? Skip.
2. **Apply** — Make the change. Save previous value to state.
3. **Verify** — Confirm it took effect.
4. **Revert** — Undo it, restore previous value.

All actions logged to `audits/hardening-log-YYYY-MM-DD.txt`.

## Profiles

**Standard** — Essential baseline security.
Disk encryption verification, inbound firewall, encrypted DNS (Quad9), automatic security updates, guest account disabled, lock screen hardening, basic browser hardening.

**High** — Standard + active defense.
Stealth mode firewall, outbound firewall (LuLu / ufw / WF), generic hostname, SSH hardening, Git commit signing, telemetry disabled, monitoring tools (Objective-See / auditd+aide / Sysmon), privacy permissions audit.

**Paranoid** — High + obfuscation and operational security.
MAC address rotation, VPN kill switch, traffic obfuscation (DAITA/Tor), browser fingerprint resistance, metadata stripping, dev environment isolation, weekly automated audits, encrypted backup guidance, border crossing prep, Bluetooth disabled when unused.

**Advanced** — Custom questionnaire that maps your threat model, use case, travel habits, and maintenance preferences to the right set of modules.

## Modules

### Disk & Boot
- `disk-encrypt` — FileVault / LUKS / BitLocker verification

### Firewall
- `firewall-inbound` — Block all incoming connections
- `firewall-stealth` — Stealth mode / drop ICMP
- `firewall-outbound` — Outbound firewall (LuLu / ufw / WF)

### Network & DNS
- `dns-secure` — Encrypted DNS (Quad9)
- `vpn-killswitch` — VPN always-on, block non-VPN traffic
- `hostname-scrub` — Generic hostname

### Privacy & Obfuscation
- `mac-rotate` — MAC address rotation
- `telemetry-disable` — OS and browser telemetry off
- `traffic-obfuscation` — DAITA, Tor guidance
- `metadata-strip` — exiftool / mat2

### Browser
- `browser-basic` — Block trackers, HTTPS-only, disable safe-open
- `browser-fingerprint` — Resist fingerprinting, clear-on-quit

### Access Control
- `guest-disable` — Disable guest account
- `lock-screen` — Screensaver password, zero delay, timeout
- `bluetooth-disable` — Disable when unused

### Dev Tools
- `git-harden` — SSH signing, credential helper
- `dev-isolation` — Docker hardening, VM setup guidance

### Auth & SSH
- `ssh-harden` — Ed25519 keys, strict config

### Monitoring
- `monitoring-tools` — Objective-See / auditd+aide / Sysmon
- `permissions-audit` — List granted privacy/security permissions
- `audit-script` — Weekly automated audit + baseline snapshot

### Maintenance
- `auto-updates` — Automatic security updates
- `backup-guidance` — Encrypted backup strategy
- `border-prep` — Travel protocol, nuke checklist

For platform-specific implementation details, see [docs/plans/2026-01-29-hardening-wizard-design.md](docs/plans/2026-01-29-hardening-wizard-design.md).

## System Cleaner

Shed the dead wood. Built-in system cleaner for privacy and disk hygiene.

```bash
barked --clean                   # Interactive cleaning wizard
barked --clean --dry-run         # Preview what would be cleaned
barked --clean --force           # Skip confirmation prompt
```

Windows:
```powershell
.\barked.ps1 -Clean              # Interactive cleaning wizard
.\barked.ps1 -Clean -DryRun     # Preview what would be cleaned
.\barked.ps1 -Clean -Force      # Skip confirmation prompt
```

**Categories:** System Caches & Logs, User Caches & Logs, Browser Data, Privacy Traces, Developer Cruft, Trash & Downloads, Mail & Messages

**Features:**
- Two-level picker: select categories, then optionally drill into individual targets
- Auto-detects installed browsers and dev tools
- Size-estimated preview before any deletion
- Safety guardrails: no symlink following, skips in-use files, warns about running browsers
- Cleanliness score with severity-weighted scoring
- Full logging to `audits/clean-log-YYYY-MM-DD.txt`

## Automated Scheduled Cleaning

Set up automated cleaning to run on a schedule (daily, weekly, or custom).

```bash
barked --clean-schedule          # macOS / Linux
```

**Setup wizard:**
1. Select cleaning categories
2. Choose schedule frequency (Daily, Weekly, Custom)
3. Enable/disable notifications
4. Review and confirm

The schedule is installed to run automatically:
- **macOS**: launchd (`~/Library/LaunchAgents/com.barked.scheduled-clean.plist`)
- **Linux**: cron (`crontab -l` to view)

**Remove schedule:**
```bash
barked --clean-unschedule        # macOS / Linux
```

**Manage from menu:**
In the wizard, select `[S] Schedule` to set up or modify automated cleaning.

## Peel It Back

**Full uninstall** — revert all changes:
```bash
barked --uninstall               # macOS / Linux
.\barked.ps1 -Uninstall          # Windows
```

**Modify** — add or remove individual modules:
```bash
barked --modify                  # macOS / Linux
.\barked.ps1 -Modify             # Windows
```

Both options are also available from the wizard menu (`[U]` Uninstall, `[M]` Modify).

## User-Space Only (No Sudo)

Run only modules that don't require root privileges:

```bash
barked --no-sudo                 # Skip all root-requiring modules
barked --auto standard --no-sudo # Combine with profiles
```

Useful for:
- Managed machines where you don't have sudo
- Quick partial hardening without elevation
- Testing user-space modules in isolation

The scripts track applied changes in a state file:
| Platform | User (primary) | Project (copy) |
|---|---|---|
| macOS / Linux | `~/.config/barked/state.json` | `state/hardening-state.json` |
| Windows | `%LOCALAPPDATA%\barked\state.json` | `state\hardening-state.json` |

Legacy state files (`/etc/hardening-state.json`, `C:\ProgramData\hardening-state.json`) are automatically migrated to userspace on first run. If no state file is found, the scripts detect applied hardening from live system state.

## File Structure

```
barked/
├── install.sh                # macOS/Linux installer
├── install.ps1               # Windows installer
├── scripts/
│   ├── barked.sh              # macOS + Linux wizard
│   ├── barked.ps1             # Windows wizard
│   └── weekly-audit.sh        # macOS weekly audit
├── gui/
│   ├── Barked/                # SwiftUI macOS menubar app (macOS 13+)
│   └── build.sh               # Build Barked.app bundle
├── docs/plans/                # Design documents
├── audits/                    # Audit reports
├── baseline/                  # Known-good system snapshots
└── state/                     # Hardening state files
```

## Releasing

Both scripts and their SHA256 checksums must be published together. The update and install flows verify downloads against these checksums.

```bash
# 1. Bump versions
#    scripts/barked.sh  → readonly VERSION="X.Y.Z"
#    scripts/barked.ps1 → $script:VERSION = "X.Y.Z"

# 2. Commit and push
git add scripts/barked.sh scripts/barked.ps1
git commit -m "chore: bump versions to vX.Y.Z (bash) and vX.Y.Z (ps1)"
git push

# 3. Generate checksums
shasum -a 256 scripts/barked.sh > barked.sh.sha256
shasum -a 256 scripts/barked.ps1 > barked.ps1.sha256

# 4. Create release with all four assets
gh release create vX.Y.Z \
  scripts/barked.sh \
  scripts/barked.ps1 \
  barked.sh.sha256 \
  barked.ps1.sha256 \
  --title "Barked vX.Y.Z" \
  --notes "Release notes here"
```

The release **must** include all four files. Without the `.sha256` files, update and install will fail checksum verification and abort.

## License

TBD
