# Hardening Wizard Design

**Date:** 2026-01-29
**Type:** Cross-platform security hardening wizard with interactive questionnaire

## Overview

Two self-contained scripts — `barked.sh` (macOS + Linux) and `barked.ps1` (Windows) — that walk a user through security hardening with a wizard interface. Quick profile selection for fast deployment, advanced questionnaire for custom configuration.

## Design Decisions

- **Language:** Bash (macOS/Linux), PowerShell (Windows). Native, zero dependencies.
- **Profiles:** Standard / High / Paranoid presets + Advanced custom questionnaire
- **Output modes:** Print checklist at end, pause-and-guide, or generate report file
- **Idempotent:** Checks state before every change, skips what's already applied, safe to re-run
- **Error handling:** Log and continue. Failed steps appear in summary/report.
- **Interactive only:** No silent/unattended mode. Human in the loop for security decisions.
- **Feature parity:** All three platforms cover equivalent hardening categories.

## Script Architecture

```
barked.sh / barked.ps1
├── OS detection (macOS / Linux)  [Bash only]
├── Privilege check (sudo / admin)
├── Wizard
│   ├── Profile select (Standard / High / Paranoid)
│   └── Advanced questionnaire (8 questions)
├── Output mode select (checklist / pause-guide / report)
├── Profile builder (maps answers → enabled modules)
├── Module runner (loops through enabled modules)
│   ├── check_state() — is this already applied?
│   ├── apply()       — make the change
│   └── verify()      — confirm it worked
├── Output handler
│   ├── Print checklist
│   ├── Pause and guide
│   └── Generate report file
└── Summary (applied / skipped / failed / manual counts)
```

## Wizard Interface

### Profile Selection Screen
```
╔══════════════════════════════════════════╗
║       SYSTEM HARDENING WIZARD            ║
║       macOS / Linux / Windows            ║
╚══════════════════════════════════════════╝

Select a hardening profile:

  [1] Standard    — Encrypted disk, firewall, secure DNS,
                    auto-updates, basic browser hardening
  [2] High        — Standard + outbound firewall, hostname
                    scrubbing, monitoring tools, SSH hardening,
                    telemetry disabled
  [3] Paranoid    — High + MAC rotation, traffic obfuscation,
                    VPN kill switch, full audit system,
                    metadata stripping, border crossing prep
  [4] Advanced    — Custom questionnaire (choose per-category)

  [Q] Quit
```

### Advanced Questionnaire (8 questions)
1. Threat model: targeted / mass surveillance / physical / all
2. Use case: dev only / dev + personal / dev + media / dedicated security machine
3. Travel: frequent international / occasional / rarely
4. Ecosystem: minimize vendor / strategic use / full ecosystem
5. Network monitoring: see everything / block and forget / DNS-level only
6. Authentication: hardware keys / password manager + TOTP / OS built-in / mixed
7. Traffic: route all through Tor/VPN / VPN always + Tor situational / situational
8. Maintenance: set and forget / weekly check-ins / active management

### Output Mode Selection
```
How should manual steps be handled?

  [1] Print checklist at the end
  [2] Pause and guide me through each step
  [3] Generate a report file
```

## Module Map

### Standard Profile (7 modules)
| Module ID         | Description                                      |
|-------------------|--------------------------------------------------|
| `disk-encrypt`    | FileVault / LUKS / BitLocker verification        |
| `firewall-inbound`| Enable firewall, block all incoming              |
| `dns-secure`      | Set encrypted DNS (Quad9)                        |
| `auto-updates`    | Enable automatic security updates                |
| `guest-disable`   | Disable guest account                            |
| `lock-screen`     | Screensaver password, zero delay, timeout        |
| `browser-basic`   | Block trackers, HTTPS-only, disable safe-open    |

### High Profile (Standard + 8 modules)
| Module ID          | Description                                     |
|--------------------|--------------------------------------------------|
| `firewall-stealth` | Stealth mode / drop ICMP                        |
| `firewall-outbound`| LuLu / UFW deny-out / WF outbound rules        |
| `hostname-scrub`   | Set generic hostname                            |
| `ssh-harden`       | Ed25519 keys, strict config                     |
| `git-harden`       | SSH signing, credential helper                  |
| `telemetry-disable`| OS and browser telemetry off                    |
| `monitoring-tools` | Objective-See / auditd+aide / Sysmon            |
| `permissions-audit`| List granted privacy/security permissions       |

### Paranoid Profile (High + 10 modules)
| Module ID             | Description                                  |
|-----------------------|----------------------------------------------|
| `mac-rotate`          | Verify/enable MAC address rotation           |
| `vpn-killswitch`      | Enforce VPN always-on, block non-VPN traffic |
| `traffic-obfuscation` | DAITA, Tor guidance                          |
| `browser-fingerprint` | Resist fingerprinting, clear-on-quit         |
| `metadata-strip`      | Install exiftool / mat2                      |
| `dev-isolation`       | Docker hardening, VM setup guidance          |
| `audit-script`        | Weekly automated audit + baseline snapshot   |
| `backup-guidance`     | Encrypted backup strategy                    |
| `border-prep`         | Travel protocol, nuke checklist              |
| `bluetooth-disable`   | Disable when unused                          |

**Total: 25 modules**

## Platform Equivalence

| Module              | macOS                          | Linux                              | Windows                                  |
|---------------------|--------------------------------|------------------------------------|------------------------------------------|
| `disk-encrypt`      | `fdesetup` / FileVault        | `cryptsetup` / LUKS               | `Get-BitLockerVolume` / BitLocker        |
| `firewall-inbound`  | `socketfilterfw`              | `ufw` / `nftables`                | `Set-NetFirewallProfile`                 |
| `firewall-stealth`  | `socketfilterfw --stealth`    | `iptables` drop ICMP              | `netsh` ICMP rules                       |
| `firewall-outbound` | LuLu (brew cask)             | `ufw default deny outgoing`       | WF `DefaultOutboundAction Block`         |
| `dns-secure`        | `networksetup -setdnsservers` | `resolved.conf` / `resolvconf`    | `Set-DnsClientServerAddress`             |
| `hostname-scrub`    | `scutil --set`                | `hostnamectl set-hostname`         | `Rename-Computer`                        |
| `auto-updates`      | `softwareupdate` defaults     | `unattended-upgrades` / `dnf-auto`| `Windows Update` registry/GPO            |
| `guest-disable`     | `defaults write` loginwindow  | remove/lock guest user             | `net user Guest /active:no`              |
| `lock-screen`       | `defaults write` screensaver  | gsettings / xdg-screensaver       | `registry` screen saver policies         |
| `ssh-harden`        | `~/.ssh/config`               | `~/.ssh/config`                    | `$env:USERPROFILE\.ssh\config`           |
| `git-harden`        | `git config --global`         | `git config --global`              | `git config --global`                    |
| `monitoring-tools`  | Objective-See suite           | auditd + aide + rkhunter + fail2ban| Sysmon + Defender ATP + auditpol         |
| `browser-basic`     | Firefox `user.js` + Safari    | Firefox `user.js`                  | Firefox `user.js` + Edge/Chrome registry |
| `browser-fingerprint`| Firefox `user.js` advanced   | Firefox `user.js` advanced         | Firefox `user.js` advanced               |
| `telemetry-disable` | defaults + Firefox prefs      | systemd services + Firefox         | registry + GPO + Firefox                 |
| `metadata-strip`    | exiftool (brew)               | exiftool / mat2 (apt/dnf)          | exiftool (choco/scoop)                   |
| `audit-script`      | launchd weekly agent          | cron weekly job                    | Task Scheduler weekly task               |
| `vpn-killswitch`    | Mullvad + pf rules            | Mullvad + ufw/nftables             | Mullvad + WF rules                       |

## Idempotency Pattern

Every module follows:

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│ check_state  │────▶│   apply     │────▶│   verify    │
│ (is it done?)│     │ (make change)│     │ (did it work?)│
└─────────────┘     └─────────────┘     └─────────────┘
      │                                        │
      │ already applied                        │ failed
      ▼                                        ▼
   [SKIP]                                  [LOG ERROR]
   green ✓                                  red ✗
```

- `check_state` returns: `applied`, `partial`, `not_applied`, `unsupported`
- `unsupported` → silently skipped (e.g., LuLu on Linux)
- `partial` → apply only touches what's missing
- All actions logged: timestamp, module ID, action, result, message
- Log always written to `hardening-log-YYYY-MM-DD.txt`

## Privilege Handling

Script checks for elevated privileges at startup. If not elevated:
1. Lists which modules need root/admin
2. Asks user to re-run with `sudo` (Bash) or "Run as Administrator" (PowerShell)
3. Exits cleanly

No partial-privilege runs.

## Summary Display

```
═══ Hardening Complete ═══
  ✓ Applied:    18
  ○ Skipped:    4 (already applied)
  ✗ Failed:     2 (see report)
  ☐ Manual:     6 (see checklist)
```

## File Structure

```
secure/
├── scripts/
│   ├── barked.sh              # macOS + Linux wizard
│   ├── barked.ps1             # Windows wizard
│   ├── weekly-audit.sh        # macOS audit (existing)
│   ├── weekly-audit-linux.sh  # Linux audit (generated by wizard)
│   └── weekly-audit.ps1       # Windows audit (generated by wizard)
├── docs/plans/
├── audits/
├── baseline/
└── README.md
```

Scripts are self-contained single files. No external dependencies, no module directories. Functions inside the script act as modules, separated by comment blocks.

Distribution: clone repo or download single script file. `chmod +x barked.sh && sudo ./barked.sh`.

## Sources

- [drduh/macOS-Security-and-Privacy-Guide](https://github.com/drduh/macOS-Security-and-Privacy-Guide)
- [beerisgood/macOS_Hardening](https://github.com/beerisgood/macOS_Hardening)
- [Objective-See Tools](https://objective-see.org/tools.html)
- [CIS Apple macOS Benchmarks](https://www.cisecurity.org/benchmark/apple_os)
- [macOS Security Compliance Project](https://support.apple.com/guide/certifications/macos-security-compliance-project-apc322685bb2/web)
- [EFF Surveillance Self-Defense](https://ssd.eff.org/)
