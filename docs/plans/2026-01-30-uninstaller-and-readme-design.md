# Uninstaller, Modify Feature & README Design

**Date:** 2026-01-30
**Type:** Reversibility features for hardening scripts + project README

## Overview

Add uninstall and modify capabilities to the existing hardening scripts (`barked.sh` / `barked.ps1`), plus a project README. Users can fully revert all hardening changes, or selectively add/remove individual modules through an interactive category-grouped picker with arrow-key navigation.

## Design Decisions

- **Built-in, not separate scripts:** Uninstall and modify logic lives inside `barked.sh` / `barked.ps1`. Module revert functions sit alongside apply functions. CLI flags (`--uninstall`, `--modify` / `-Uninstall`, `-Modify`) and wizard menu entries (`[U]`, `[M]`) provide entry points.
- **State file + live detection:** A JSON state file records what was applied. Falls back to live `check_state` detection if the file is missing.
- **State file in two locations:** System path (primary) and project directory (copy). User informed of both paths after every run.
- **Interactive module picker:** Arrow-key/spacebar navigation for the modify screen. Built in pure Bash / PowerShell with no dependencies.
- **Package removal opt-in:** Full uninstall asks once whether to remove packages installed by the script. Settings always revert.
- **Reverse order uninstall:** Modules revert in reverse application order to avoid dependency issues.

## 1. State File & Tracking

### Locations

| Platform      | System (primary)                        | Project (copy)                     |
|---------------|-----------------------------------------|------------------------------------|
| macOS / Linux | `/etc/hardening-state.json`             | `secure/state/hardening-state.json`|
| Windows       | `C:\ProgramData\hardening-state.json`   | `secure\state\hardening-state.json`|

### Schema

```json
{
  "version": "1.0.0",
  "last_run": "2026-01-30T14:30:00Z",
  "os": "macos",
  "profile": "high",
  "modules": {
    "firewall-inbound": {
      "status": "applied",
      "applied_at": "2026-01-30T14:30:12Z",
      "previous_value": null
    },
    "dns-secure": {
      "status": "applied",
      "applied_at": "2026-01-30T14:30:15Z",
      "previous_value": "192.168.1.1"
    }
  },
  "packages_installed": ["lulu", "exiftool", "oversight", "blockblock", "knockknock", "ransomwhere"]
}
```

- `previous_value`: Captures original setting before hardening (old DNS, old hostname, etc.). Enables precise revert. Null for modules with no prior value.
- `packages_installed`: Only packages the script installed (not pre-existing). Used during uninstall to determine what to remove.
- `status`: Per-module — `applied`, `reverted`, `failed`.

### Write Behavior

- State file written after every hardening run, modify operation, and uninstall.
- Both copies updated simultaneously. User informed of paths at end of run.
- Apply step in each module saves pre-change values to state before making changes.
- Existing `check_state` logic serves as fallback when no state file exists.

## 2. Entry Points

### CLI Flags

```bash
# Bash
sudo ./barked.sh --uninstall    # Full uninstall
sudo ./barked.sh --modify       # Interactive module picker

# PowerShell
.\barked.ps1 -Uninstall         # Full uninstall
.\barked.ps1 -Modify            # Interactive module picker
```

### Wizard Menu

```
Select a hardening profile:

  [1] Standard    — Encrypted disk, firewall, secure DNS, ...
  [2] High        — Standard + outbound firewall, hostname scrubbing, ...
  [3] Paranoid    — High + MAC rotation, traffic obfuscation, ...
  [4] Advanced    — Custom questionnaire (choose per-category)

  [M] Modify      — Add or remove individual modules
  [U] Uninstall   — Remove all hardening changes
  [Q] Quit
```

### Behavior

- `--uninstall` / `-Uninstall` skips wizard, goes straight to uninstall flow with confirmation prompt.
- `--modify` / `-Modify` skips profile selection, goes straight to category picker.
- Wizard `[M]` and `[U]` behave identically to flags.
- All paths require elevated privileges.
- If no state file exists and live detection finds nothing applied, script says so and exits.

## 3. Modify — Category-Grouped Module Picker

### Interactive Picker

Arrow-key navigation with spacebar to toggle. Built in pure Bash (raw terminal input via `read -rsn1`, cursor repositioning) and PowerShell (`$Host.UI.RawUI.ReadKey()`).

### Layout

```
═══ Modify Hardening ═══

Use ↑↓ to navigate, SPACE to toggle, ENTER to apply changes, Q to cancel.
Modules marked [✓] are currently applied.

  DISK & BOOT
    [✓] disk-encrypt        — FileVault / LUKS / BitLocker verification

  FIREWALL
    [✓] firewall-inbound    — Block all incoming connections
    [✓] firewall-stealth    — Stealth mode / drop ICMP
    [✓] firewall-outbound   — Outbound firewall (LuLu / ufw / WF)

  NETWORK & DNS
    [✓] dns-secure          — Encrypted DNS (Quad9)
    [ ] vpn-killswitch      — VPN always-on, block non-VPN traffic
    [✓] hostname-scrub      — Generic hostname

  PRIVACY & OBFUSCATION
    [ ] mac-rotate           — MAC address rotation
    [✓] telemetry-disable   — OS and browser telemetry off
    [ ] traffic-obfuscation — DAITA, Tor guidance
    [ ] metadata-strip      — exiftool / mat2

  BROWSER
    [✓] browser-basic        — Block trackers, HTTPS-only
    [ ] browser-fingerprint  — Resist fingerprinting, clear-on-quit

  ACCESS CONTROL
    [✓] guest-disable        — Disable guest account
    [✓] lock-screen          — Screensaver password, zero delay
    [ ] bluetooth-disable    — Disable when unused

  DEV TOOLS
    [✓] git-harden           — SSH signing, credential helper
    [ ] dev-isolation        — Docker hardening, VM guidance

  AUTH & SSH
    [✓] ssh-harden           — Ed25519 keys, strict config

  MONITORING
    [✓] monitoring-tools     — Objective-See / auditd+aide / Sysmon
    [✓] permissions-audit    — List granted permissions
    [ ] audit-script         — Weekly automated audit

  MAINTENANCE
    [ ] auto-updates         — Automatic security updates
    [ ] backup-guidance      — Encrypted backup strategy
    [ ] border-prep          — Travel protocol, nuke checklist
```

- Modules unsupported on current platform are hidden.
- Status read from state file first, fallback to live `check_state`.
- Toggling on → runs `apply()`. Toggling off → runs `revert()`.
- State file updated after all changes applied.

## 4. Full Uninstall Flow

### Sequence

```
═══ Full Uninstall ═══

This will revert all hardening changes made by this script.

State file found: /etc/hardening-state.json
  Applied modules: 15
  Last run: 2026-01-30

The following tools were installed by the hardening script:
  lulu, oversight, blockblock, knockknock, ransomwhere, exiftool

Remove installed tools as well?
  [Y] Yes — uninstall all tools listed above
  [N] No  — keep tools, only revert settings
  [Q] Quit
```

Then a final confirmation:

```
⚠  This will revert 15 modules and remove 6 packages.
   Proceed? [y/N]
```

### Execution

- Modules revert in **reverse application order** (last applied first) to avoid dependency issues.
- Same status output pattern as hardening:

```
  ✓ [1/15] firewall-outbound (reverted)
  ✓ [2/15] dns-secure (reverted to 192.168.1.1)
  ✗ [3/15] telemetry-disable (revert failed)
```

- After completion, state file updated: cleared if everything reverted, or reflects remaining modules if some failed.
- Both state file copies (system + project) updated.
- Summary: reverted / skipped / failed counts.

## 5. Module Revert Categories

### Settings Revert — Restore previous value or OS default

| Module | Revert Action |
|--------|---------------|
| `dns-secure` | Restore original DNS servers or reset to DHCP |
| `hostname-scrub` | Restore original hostname from state |
| `firewall-inbound` | Disable firewall / remove rules |
| `firewall-stealth` | Disable stealth mode |
| `lock-screen` | Reset screensaver delay to OS default |
| `auto-updates` | Reset to OS default |
| `guest-disable` | Re-enable guest account |
| `ssh-harden` | Remove script-added entries from `~/.ssh/config` |
| `git-harden` | Unset global config keys the script added |
| `telemetry-disable` | Re-enable telemetry settings |
| `browser-basic` | Remove script-created `user.js` or script-added lines |
| `browser-fingerprint` | Remove script-created `user.js` or script-added lines |
| `bluetooth-disable` | Re-enable Bluetooth |

### Package Removal — Only if user opts in during uninstall

| Module | Packages |
|--------|----------|
| `firewall-outbound` | LuLu (macOS) / ufw deny-outgoing rule (Linux) / WF rules (Windows) |
| `monitoring-tools` | Objective-See suite (macOS) / auditd+aide (Linux) / Sysmon (Windows) |
| `metadata-strip` | exiftool / mat2 |
| `dev-isolation` | Remove Docker hardening config (not Docker itself) |

### Guidance-Only — Print manual revert instructions

| Module | Why manual |
|--------|-----------|
| `disk-encrypt` | Decrypting disk is a major decision, not auto-reverted |
| `vpn-killswitch` | VPN app configuration, not script-managed |
| `traffic-obfuscation` | Tor/DAITA are app settings |
| `backup-guidance` | Backup strategy is informational |
| `border-prep` | Travel protocol is informational |
| `mac-rotate` | OS-level setting verified, not always script-applied |
| `permissions-audit` | Read-only audit, nothing to revert |

## 6. README Structure

File: `secure/README.md`

### Sections

1. **Header** — Project name, one-line description, platform badges (macOS, Linux, Windows).

2. **What This Does** — Two paragraphs: what the wizard does, philosophy (interactive, idempotent, reversible). Single-file scripts, zero dependencies.

3. **Quick Start** — Three code blocks: macOS, Linux, Windows. Clone and run.

4. **Profiles** — Standard / High / Paranoid tier summaries showing what each includes.

5. **Modules by Category** — Grouped list matching modify picker categories:
   - Disk & Boot
   - Firewall
   - Network & DNS
   - Privacy & Obfuscation
   - Browser
   - Access Control
   - Dev Tools
   - Auth & SSH
   - Monitoring
   - Maintenance

   One-line description per module. Link to design doc for platform details.

6. **Uninstall & Modify** — CLI flags, wizard menu options, state file locations, live-detection fallback explanation.

7. **File Structure** — Repo tree view.

8. **How It Works** — Check → apply → verify → revert pattern. State file purpose.

9. **License** — Placeholder.

## Implementation Notes

- Each module function gains a `revert` action alongside `check` and `apply`. The `run_module` function accepts a mode parameter: `apply` (default) or `revert`.
- State file I/O: Bash uses `python3 -c` for JSON (available on macOS and most Linux). PowerShell uses `ConvertTo-Json` / `ConvertFrom-Json` natively.
- Interactive picker: ~80-100 lines of Bash utility code for terminal cursor control. PowerShell equivalent using `RawUI.ReadKey()`.
- `previous_value` capture: Each module's apply path reads current value before overwriting and passes it to the state writer.
