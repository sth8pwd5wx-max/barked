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
curl -fsSL https://raw.githubusercontent.com/sth8pwd5wx-max/barked/main/install.sh | sudo bash
```

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

The scripts track applied changes in a state file:
| Platform | System (primary) | Project (copy) |
|---|---|---|
| macOS / Linux | `/etc/hardening-state.json` | `state/hardening-state.json` |
| Windows | `C:\ProgramData\hardening-state.json` | `state\hardening-state.json` |

If the state file is missing, the scripts detect applied hardening from live system state.

## File Structure

```
barked/
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

## License

TBD
