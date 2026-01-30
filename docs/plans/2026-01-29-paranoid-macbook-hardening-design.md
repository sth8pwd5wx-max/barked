# Paranoid MacBook Hardening Design

**Date:** 2026-01-29
**Device:** MacBook Air M2, 24GB RAM, macOS 26.2
**Threat model:** All — targeted, mass surveillance, physical access/theft, border crossing

## Security Profile

- **Use case:** Daily driver — development, personal, media
- **Travel:** Occasional international, border crossing prep needed
- **Apple ecosystem:** Full (iPhone, etc.), leverage strategically with Advanced Data Protection
- **Network posture:** Silent strict outbound blocking, full visibility on demand
- **Auth:** Apple Passwords (hardened), hardware security keys for critical accounts
- **Traffic:** Mullvad VPN always-on, Tor/Mullvad Browser for sensitive tasks
- **Dev environment:** Isolated in Docker containers and UTM VMs, host stays clean
- **Maintenance:** Weekly automated audits, monthly manual reviews

## Current State (pre-hardening)

**Already solid:**
- FileVault: ON
- System Integrity Protection: ON
- Gatekeeper: ON
- Activation Lock: ON
- Lockdown Mode: ON
- Guest account: disabled
- Privacy-aware software: Mullvad VPN + Browser, Proton Mail + Drive, Signal, Tailscale

**Gaps identified:**
- No custom DNS (falling back to ISP)
- Firewall not configured (state 0)
- No application-layer outbound firewall
- Hostname leaking identity via mDNS/Bonjour
- No MAC address rotation verification
- No Objective-See monitoring tools
- No automated audit process
- No hardware security keys
- Screensaver password delay not verified
- Thunderbolt Bridge active (unnecessary attack surface)
- No dev isolation strategy in place
- No backup strategy documented

---

## Section 1: OS Foundation & Access Control

### Hostname and identity scrubbing
```bash
sudo scutil --set ComputerName MacBook
sudo scutil --set LocalHostName MacBook
sudo scutil --set HostName MacBook
```
Machine name currently leaks identity on local networks and Bluetooth. Generic names prevent passive identification.

### Firmware and boot security
- Verify Full Security mode in Startup Security Utility (default on M2, confirm)
- FileVault already on — move recovery key to physical safe or safety deposit box, remove from iCloud
- Enable Advanced Data Protection for iCloud across all devices

### Auto-updates
```bash
sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -bool true
sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload -bool true
sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall -bool true
```

---

## Section 2: Firewall & Network Hardening

### macOS Application Firewall — stealth mode
```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setallowsigned off
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setallowsignedapp off
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setblockall on
```
Blocks all incoming connections. Stealth mode drops ICMP ping and probe traffic silently.

### LuLu — outbound firewall
Install [LuLu](https://objective-see.org/products/lulu.html) (free, open-source by Objective-See). Default mode: silent blocking with per-app rules learned on first connection. Switch to "block all and ask" mode for full investigative visibility.

### pf kernel firewall
For advanced packet filtering: block known telemetry IPs, restrict outbound to VPN-only, drop all traffic if VPN tunnel goes down (OS-level kill switch complementing Mullvad's).

### DNS — encrypted and filtered
- Configure NextDNS or Quad9 (9.9.9.9) as DNS resolver
- Set via System Settings > Wi-Fi > Details > DNS, or use a DNS configuration profile for persistence
- Current state: no DNS configured, ISP sees every domain resolved

### Mullvad VPN — always-on
- Enable "Always require VPN" — OS-level kill switch blocks all traffic if tunnel drops
- Enable "Block ads, trackers, malware" DNS toggles
- Disable "Local network sharing" unless actively needed
- Enable DAITA (Defense Against AI-guided Traffic Analysis) for packet padding and cover traffic

### MAC address rotation
Verify: System Settings > Wi-Fi > [network] > Details > "Private Wi-Fi address" set to "Rotating" for all saved networks.

### Disable unnecessary network services
Disable Thunderbolt Bridge — each active interface is an attack surface.

---

## Section 3: Obfuscation & Anti-Fingerprinting

### Browser fingerprint reduction
- **Mullvad Browser** as default — hardened Firefox fork, all users look identical (same window size, fonts, WebGL, timezone)
- Firefox and Safari for sites that break in Mullvad Browser — understand those sessions are more fingerprintable

### Network traffic obfuscation
- Mullvad VPN encrypts and tunnels all traffic, hiding content from ISP
- For metadata-sensitive tasks: Tor via Mullvad Browser or standalone Tor Browser
- DAITA feature pads packets and adds cover traffic to defeat traffic analysis

### Bluetooth discipline
Disable Bluetooth when not actively using peripherals. Lockdown Mode blocks unknown accessory connections, but the radio still broadcasts identifiers.

### iCloud metadata reduction
- Advanced Data Protection encrypts data E2E, but metadata (contacts, timing, device info) remains visible to Apple
- Disable unused iCloud features: Siri, Diagnostics & Usage sharing, Location Services for non-essential apps, "Improve Siri & Dictation"
- Safari and Mail: enable "Hide IP Address" and "Mail Privacy Protection"

### Hostile network protocol (airports, hotels, conferences)
Combine: rotating MAC address + Mullvad VPN + generic hostname = different anonymous device each session.

---

## Section 4: Application Security & Dev Isolation

### App installation policy
- Prefer Mac App Store (sandboxed, reviewed)
- Non-App Store: verify code signatures: `codesign -dv --verbose=4 /Applications/AppName.app`
- Avoid Electron apps where native or web alternatives exist
- Audit via Activity Monitor: enable "Sandbox" and "Restricted" columns

### Docker containers for development
- Run code, dependencies, build tools inside containers
- Bind-mount only specific project directories, not home directory
- Avoid `--privileged` and `--net=host`
- Reduce Docker VM resource limits to contain blast radius

### UTM virtual machines for heavy isolation
Install [UTM](https://mac.getutm.app/) (free, Apple Virtualization framework):
- Full Linux dev environments completely isolated from macOS
- Test untrusted software before allowing on host
- Disposable VMs for border crossing prep

### SSH hardening
```
# ~/.ssh/config
Host *
    IdentitiesOnly yes
    AddKeysToAgent yes
    UseKeychain yes
    HashKnownHosts yes
    PasswordAuthentication no
    StrictHostKeyChecking ask
```
Ed25519 keys only (`ssh-keygen -t ed25519`). Never reuse keys across services. Store in Apple Keychain (biometric auth required).

### Git hardening
- Sign commits with SSH keys: `git config --global gpg.format ssh`
- Credential helper: `git config --global credential.helper osxkeychain`
- Audit `.gitconfig` for embedded tokens or secrets

### Homebrew hygiene
Runs without sandbox, installs to `/opt/homebrew` with user permissions. Supply chain risk. Audit regularly (`brew list`), remove unused packages, prefer App Store or direct-download alternatives.

---

## Section 5: Authentication & Physical Security

### Apple Passwords / Keychain hardening
- Advanced Data Protection E2E-encrypts Keychain sync
- Strong alphanumeric login password (not 6-digit PIN)
- All critical accounts: unique generated passwords + 2FA via built-in TOTP

### Hardware security keys
Two YubiKey 5C keys for Apple ID, email, GitHub, financial accounts. Phishing-resistant — immune to SIM swaps, TOTP theft, session hijacking. One carried, one stored offsite.

### Lock screen discipline
```bash
defaults write com.apple.screensaver askForPassword -int 1
defaults write com.apple.screensaver askForPasswordDelay -int 0
```
- Lock after 2-5 minutes inactivity
- Hot Corner for instant screensaver/lock
- Muscle memory: `Ctrl+Cmd+Q` before walking away

### Touch ID
Keep enabled for low-friction locking. Limitation: law enforcement may compel biometric unlock. For border crossings: power off completely before checkpoint — forces password-only unlock, flushes keys from memory.

### Find My
Keep enabled. Remote lock, wipe, location tracking if stolen. Activation Lock makes stolen Mac a brick.

### Physical tamper detection
- Tamper-evident stickers or glitter nail polish over bottom case screws — detects evil maid attacks
- Unattended laptop: power off completely (sleeping Mac has keys in memory)

### Border crossing protocol
1. Back up to encrypted external drive or Proton Drive before travel
2. Power off completely before checkpoint
3. If compelled to unlock: standard user account shows nothing unusual, sensitive data in encrypted containers or cloud-only
4. Consider travel profile: clean macOS user account with minimal data

---

## Section 6: Monitoring, Logging & Weekly Audit Automation

### Objective-See security tools (free, open-source)
- **LuLu** — outbound firewall (covered in Section 2)
- **OverSight** — alerts on microphone/camera activation, shows triggering process
- **BlockBlock** — monitors persistence locations (LaunchDaemons, LaunchAgents, login items), alerts on install
- **KnockKnock** — on-demand scan of all persistent software
- **RansomWhere?** — detects rapid file encryption (ransomware), halts process

### OpenBSM audit logging
```bash
sudo touch /etc/security/audit_control
```
Forensic-grade logs of process execution, file access, privilege escalation.

### Automated weekly audit script
Runs via `launchd`, outputs report for review:
- List all LaunchDaemons and LaunchAgents (compare against baseline)
- List login items and background items
- Check for unsigned/ad-hoc signed processes
- Verify SIP, FileVault, Gatekeeper, firewall status
- List apps with Full Disk Access, Accessibility, Input Monitoring permissions
- Show new network listening ports
- Verify Mullvad VPN connected
- Check for macOS updates
- List Homebrew packages, flag new additions since last audit

### Privacy permission audit
System Settings > Privacy & Security — review every category. Remove unused. Revisit monthly.

### Baseline snapshot
After hardening: export all installed apps, brew packages, LaunchAgents/Daemons, privacy permissions. Hash critical system files. Store in Proton Drive. Future audits compare against baseline.

---

## Section 7: Communication Security & Data Hygiene

### Messaging hierarchy (by sensitivity)
1. **Signal** — default for private conversations. Enable disappearing messages (≤1 week), registration lock PIN, screen security
2. **Proton Mail** — PGP for external recipients. Use aliases for service signups
3. **iMessage** — casual Apple-to-Apple with ADP. Metadata visible to Apple
4. **Avoid SMS/MMS** — plaintext, interceptable via SS7, accessible to carriers/law enforcement

### Email operational security
- Proton Mail aliases or SimpleLogin for unique-per-service addresses
- Never use primary email for signups, newsletters, commerce
- Disable remote image loading (blocks tracking pixels)

### File and metadata hygiene
- Strip EXIF from photos before sharing: `exiftool -all= filename.jpg`
- Clean PDF/Office document metadata before sharing
- Proton Drive for sensitive cloud storage (E2E encrypted)

### Clipboard security
Universal Clipboard syncs across Apple devices through Apple servers (encrypted with ADP). For sensitive copy-paste: temporarily disable Handoff in System Settings > General > AirDrop & Handoff.

### Secure deletion
SSDs with TRIM: traditional secure erase doesn't work. FileVault encryption is the secure deletion — deleted encrypted blocks are unreadable without key. Full wipe: erase via Recovery Mode (destroys encryption keys).

### Browser session hygiene
- Mullvad Browser clears state on exit (keep default)
- Firefox/Safari: clear cookies and site data on quit
- Never stay logged into tracking-heavy services (Google, Facebook) in general browsing browser

---

## Section 8: Backup Strategy & Disaster Recovery

### 3-2-1 encrypted backups
- **Local:** Encrypted Time Machine to external drive. Don't leave permanently connected (ransomware risk)
- **Cloud:** Proton Drive for critical documents and configs (selective sync)
- **Offsite:** Clone encrypted backup or APFS disk image at separate physical location

### Beyond files
- Export Apple Passwords to encrypted archive periodically
- Back up SSH keys, GPG keys, 2FA recovery codes to encrypted USB, stored separately
- Document security configuration (firewall rules, DNS, LuLu rules, permissions) for rebuild

### Recovery key management
Critical secrets to store on paper/stamped metal, never on the device they protect:
- FileVault recovery key
- Apple ID recovery key
- 2FA recovery codes for critical accounts
- Hardware security key backup

Split storage: one copy at home, one offsite.

### Nuke protocol (compromise or seizure)
- Remote wipe via Find My
- If physical access: Recovery Mode > erase volume > reinstall > restore selectively (never full Time Machine restore of compromised system)
- Credential rotation checklist: Apple ID, email, GitHub, financial, VPN

---

## Section 9: Implementation Roadmap

### Phase 1 — Immediate (today)
- [ ] Set hostname to generic name (`MacBook`)
- [ ] Enable macOS application firewall with stealth mode
- [ ] Configure DNS (NextDNS or Quad9) on Wi-Fi
- [ ] Enable Mullvad "Always require VPN" + kill switch + DNS blocking
- [ ] Verify MAC address rotation on all saved Wi-Fi networks
- [ ] Set screensaver password delay to 0 seconds
- [ ] Set up Hot Corner for instant screen lock
- [ ] Disable Thunderbolt Bridge
- [ ] Disable Bluetooth when not in use
- [ ] Review and strip Privacy & Security permissions

### Phase 2 — This week
- [ ] Install LuLu and configure baseline rules
- [ ] Install Objective-See tools: OverSight, BlockBlock, KnockKnock, RansomWhere?
- [ ] Enable Advanced Data Protection for iCloud on all devices
- [ ] Enable Apple ID recovery key, store on paper offsite
- [ ] Move FileVault recovery key to physical offsite storage
- [ ] Configure SSH hardening (`~/.ssh/config`)
- [ ] Switch Git to SSH-key commit signing
- [ ] Harden Firefox/Safari: clear on quit, disable telemetry
- [ ] Set up Proton Mail aliases via SimpleLogin
- [ ] Enable disappearing messages in Signal

### Phase 3 — This month
- [ ] Set up encrypted Time Machine backup
- [ ] Create offsite backup of recovery keys, SSH keys, 2FA codes
- [ ] Install UTM for VM-based dev isolation
- [ ] Configure Docker: minimal bind mounts, no privileged containers
- [ ] Write and schedule weekly audit script via `launchd`
- [ ] Take baseline snapshot, store in Proton Drive
- [ ] Install `exiftool` for metadata stripping
- [ ] Purchase and register two YubiKey 5C keys

### Phase 4 — Ongoing practices
- [ ] Weekly: run audit script, review report, check for updates
- [ ] Monthly: review Privacy & Security permissions, audit Homebrew
- [ ] Before travel: full backup, power-off protocol, consider travel user account
- [ ] Per-incident: remote wipe, credential rotation checklist
- [ ] Quarterly: review threat model, update firewall rules, rotate credentials

---

## Sources

- [drduh/macOS-Security-and-Privacy-Guide](https://github.com/drduh/macOS-Security-and-Privacy-Guide)
- [beerisgood/macOS_Hardening](https://github.com/beerisgood/macOS_Hardening)
- [Objective-See Tools](https://objective-see.org/tools.html)
- [CIS Apple macOS Benchmarks](https://www.cisecurity.org/benchmark/apple_os)
- [macOS Security Compliance Project (Apple)](https://support.apple.com/guide/certifications/macos-security-compliance-project-apc322685bb2/web)
- [EFF Surveillance Self-Defense](https://ssd.eff.org/)
- [Hardening macOS (Bejarano)](https://www.bejarano.io/hardening-macos/)
- [Apple Lockdown Mode](https://support.apple.com/en-us/105120)
