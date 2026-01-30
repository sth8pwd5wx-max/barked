# Audit, Scoring, Modes & Advanced Hardening Design

**Date:** 2026-01-30
**Status:** Approved

## Overview

Add audit scoring, new CLI modes (dry-run, non-interactive, audit-only), pre-change analysis, and three new advanced hardening modules with mandatory vetting. All changes go into `scripts/barked.sh` — single-file architecture preserved.

## 1. Audit & Scoring System

### Hardening Score Model

- Each module gets a **fixed severity weight**: Critical (10), High (7), Medium (4), Low (2)
- Score = `(sum of applied module weights / sum of all applicable module weights) × 100`
- Modules not applicable to the current OS are excluded from the denominator
- Display format: `Hardening Score: 74/100 [████████░░] — 18 of 25 modules applied`

### Severity Assignments

| Severity | Points | Modules |
|----------|--------|---------|
| Critical | 10 | disk-encrypt, firewall-inbound, auto-updates, lock-screen |
| High | 7 | firewall-stealth, firewall-outbound, dns-secure, ssh-harden, guest-disable, telemetry-disable, kernel-sysctl |
| Medium | 4 | hostname-scrub, git-harden, browser-basic, monitoring-tools, permissions-audit, apparmor-enforce, boot-security |
| Low | 2 | browser-fingerprint, mac-rotate, vpn-killswitch, traffic-obfuscation, metadata-strip, dev-isolation, audit-script, backup-guidance, border-prep, bluetooth-disable |

### Severity-Rated Findings Table

Shown during `--audit` and after wizard runs:

```
 Status   Severity  Module              Finding
 ✗ FAIL   CRITICAL  disk-encrypt        FileVault not enabled
 ✓ PASS   CRITICAL  firewall-inbound    Firewall active, stealth on
 ~ MANUAL HIGH      firewall-outbound   LuLu installed but not verified
 — SKIP   MEDIUM    apparmor-enforce    Not applicable on macOS
```

## 2. Pre-Change Analysis

### Standalone Audit Mode (`--audit`)

- Runs all module `check_state()` functions without changing anything
- Produces the severity-rated findings table
- Calculates and displays the hardening score
- Saves report to `audits/audit-YYYY-MM-DD.md`
- Exits without prompting for changes
- Scoped with `--profile`: `sudo ./barked.sh --audit --profile high`

### Smart-Skip Inline (Normal Wizard Flow)

Before presenting the module list, run `check_state()` on all selected modules:

- Auto-skip already-applied modules: `[SKIP] ssh-harden — already applied`
- Auto-skip OS-irrelevant modules: `[N/A] apparmor-enforce — not applicable on macOS`
- Flag partial modules: `[PARTIAL] firewall-inbound — firewall active but stealth mode off`

Pre-run summary before any changes:

```
Pre-change analysis complete.

  Already applied:  8 modules (skipping)
  Not applicable:   3 modules (skipping)
  Partially applied: 2 modules (will complete)
  To apply:         7 modules

  Current score: 52/100
  Projected score after run: 81/100

  Proceed? [Y/n]
```

## 3. Dry-Run Mode (`--dry-run`)

- Runs the full wizard or `--auto` flow but replaces every `apply()` with a no-op
- Per-module preview:

```
[DRY RUN] firewall-stealth
  Current:  Stealth mode disabled
  Planned:  Enable stealth mode via socketfilterfw --setstealthmode on
  Severity: HIGH

[DRY RUN] kernel-sysctl
  Current:  net.ipv4.conf.all.rp_filter = 0
  Planned:  Set to 1 (enable reverse path filtering)
  Severity: HIGH (Advanced — requires confirmation in live run)
```

- Prints terminal summary table at the end
- Saves full report to `audits/dry-run-YYYY-MM-DD.md`
- `--quiet` suppresses terminal output (file still saved)
- Exit codes: `0` all would succeed, `1` any would fail/unsupported

## 4. Non-Interactive Mode (`--auto --profile <name>`)

- No prompts, no interactive picker, no questionnaire
- Applies all modules for the given profile in sequence
- Smart-skip still runs (already-applied modules skipped)
- Advanced modules **skipped unless `--accept-advanced`** is also passed
- Output to stdout as running log + saved to `audits/hardening-log-YYYY-MM-DD.txt`
- Exit codes: `0` all applied, `1` any failures, `2` nothing to do

## 5. Advanced Hardening Modules

All three gated behind mandatory vetting flow. Skipped in `--auto` unless `--accept-advanced`.

### `mod_kernel_sysctl` (Linux only)

Hardens kernel parameters via `/etc/sysctl.d/99-hardening.conf`:

| Parameter | Value | Purpose |
|-----------|-------|---------|
| `kernel.randomize_va_space` | `2` | Full ASLR randomization |
| `fs.suid_dumpable` | `0` | Disable core dumps for SUID |
| `net.ipv4.conf.all.rp_filter` | `1` | IP spoofing protection |
| `net.ipv4.tcp_syncookies` | `1` | SYN flood defense |
| `net.ipv4.conf.all.accept_redirects` | `0` | Disable ICMP redirects |
| `net.ipv4.conf.all.accept_source_route` | `0` | Disable source routing |

Revert: restore previous values from state file, remove config file.

### `mod_apparmor_enforce` (Linux; macOS: audit-only)

- Linux: check AppArmor status, set all loaded profiles to enforce mode
- macOS: audit apps for Sandbox and Hardened Runtime entitlements, report non-sandboxed apps (informational only)
- Revert (Linux): return profiles to complain mode

### `mod_boot_security` (Linux + macOS)

- Linux: verify Secure Boot, set GRUB password if not present, check for unsigned kernel modules
- macOS: verify SIP enabled, check `csrutil authenticated-root`, check Kernel Extension allowlist
- Revert (Linux): remove GRUB password, restore config

### Mandatory Vetting Flow

Applies to all three advanced modules during interactive runs:

```
╔══════════════════════════════════════════════════════════════╗
║  ⚠  ADVANCED MODULE: Kernel Sysctl Hardening               ║
║                                                              ║
║  This module modifies kernel parameters that can affect      ║
║  system stability, networking, and application behavior.     ║
║                                                              ║
║  Risk: Misconfigured sysctl can cause network failures,      ║
║  break containerized workloads, or prevent boot.             ║
╚══════════════════════════════════════════════════════════════╝

Running mandatory dry-run preview...

  Parameter                              Current    Proposed
  kernel.randomize_va_space              2          2 (no change)
  fs.suid_dumpable                       1          0
  net.ipv4.conf.all.rp_filter            0          1

  3 parameters will change. 3 already correct.

Type YES to apply these changes: _
```

- Anything other than exact `YES` aborts that module only
- In `--auto` mode: skipped unless `--accept-advanced`
- In `--dry-run` mode: preview shown, no confirmation asked

## 6. CLI Flags Summary

```
sudo ./barked.sh                                    # Interactive wizard (existing)
sudo ./barked.sh --uninstall                         # Full uninstall (existing)
sudo ./barked.sh --modify                            # Module picker (existing)
sudo ./barked.sh --audit                             # Audit-only, no changes
sudo ./barked.sh --audit --profile <name>            # Audit scoped to profile
sudo ./barked.sh --dry-run                           # Preview wizard interactively
sudo ./barked.sh --dry-run --auto --profile <name>   # Preview automated run
sudo ./barked.sh --auto --profile <name>             # Non-interactive apply
sudo ./barked.sh --auto --profile <name> --quiet     # Silent CI mode
sudo ./barked.sh --auto --profile <name> --accept-advanced  # Include advanced modules
```

## 7. Implementation Summary

### New Functions

| Function | Purpose |
|----------|---------|
| `calculate_score()` | Sum weights of applied modules, return percentage |
| `print_findings_table()` | Render the severity-rated status table |
| `run_audit()` | Execute all `check_state()`, score, display, save report |
| `run_dry_run()` | Execute wizard flow with no-op applies, show preview per module |
| `parse_args()` | Handle new CLI flags, set globals |
| `vet_advanced_module()` | Warning box + mandatory dry-run + YES confirmation |
| `mod_kernel_sysctl()` | New module: sysctl hardening |
| `mod_apparmor_enforce()` | New module: AppArmor/Sandbox enforcement |
| `mod_boot_security()` | New module: Secure Boot/SIP/GRUB verification |

### Changes to Existing Code

- Module runner: add dry-run guard (`$DRY_RUN` flag → call `preview()` not `apply()`)
- Summary display: replace pass/fail counts with findings table + score
- State file schema: add `severity` field per module
- Argument parser: add new CLI flags

### Unchanged

- Interactive wizard flow, profile questionnaire, module picker
- All 25 existing modules and revert functions
- State file location and JSON format (one new field only)
- Weekly audit script
- PowerShell script (port later)

### File Changes

- `scripts/barked.sh` — all changes (single-file preserved)
- Runtime outputs to `audits/` directory
