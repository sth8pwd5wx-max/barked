import Foundation

struct HardenModule: Identifiable, Hashable {
    let id: String
    let displayName: String
    let group: String

    static let all: [HardenModule] = [
        HardenModule(id: "disk-encrypt", displayName: "Disk Encryption", group: "Disk & Boot"),
        HardenModule(id: "firewall-inbound", displayName: "Inbound Firewall", group: "Firewall"),
        HardenModule(id: "firewall-stealth", displayName: "Stealth Mode", group: "Firewall"),
        HardenModule(id: "firewall-outbound", displayName: "Outbound Firewall", group: "Firewall"),
        HardenModule(id: "dns-secure", displayName: "Encrypted DNS (Quad9)", group: "Network & DNS"),
        HardenModule(id: "vpn-killswitch", displayName: "VPN Kill Switch", group: "Network & DNS"),
        HardenModule(id: "hostname-scrub", displayName: "Hostname Scrub", group: "Network & DNS"),
        HardenModule(id: "mac-rotate", displayName: "MAC Rotation", group: "Privacy"),
        HardenModule(id: "telemetry-disable", displayName: "Telemetry Disable", group: "Privacy"),
        HardenModule(id: "traffic-obfuscation", displayName: "Traffic Obfuscation", group: "Privacy"),
        HardenModule(id: "metadata-strip", displayName: "Metadata Stripping", group: "Privacy"),
        HardenModule(id: "browser-basic", displayName: "Basic Browser Hardening", group: "Browser"),
        HardenModule(id: "browser-fingerprint", displayName: "Fingerprint Resistance", group: "Browser"),
        HardenModule(id: "guest-disable", displayName: "Disable Guest Account", group: "Access Control"),
        HardenModule(id: "lock-screen", displayName: "Lock Screen", group: "Access Control"),
        HardenModule(id: "bluetooth-disable", displayName: "Disable Bluetooth", group: "Access Control"),
        HardenModule(id: "git-harden", displayName: "Git Hardening", group: "Dev Tools"),
        HardenModule(id: "dev-isolation", displayName: "Dev Isolation", group: "Dev Tools"),
        HardenModule(id: "ssh-harden", displayName: "SSH Hardening", group: "Auth & SSH"),
        HardenModule(id: "monitoring-tools", displayName: "Monitoring Tools", group: "Monitoring"),
        HardenModule(id: "permissions-audit", displayName: "Permissions Audit", group: "Monitoring"),
        HardenModule(id: "audit-script", displayName: "Weekly Audit Script", group: "Monitoring"),
        HardenModule(id: "auto-updates", displayName: "Auto Updates", group: "Maintenance"),
        HardenModule(id: "backup-guidance", displayName: "Backup Guidance", group: "Maintenance"),
        HardenModule(id: "border-prep", displayName: "Border Crossing Prep", group: "Maintenance"),
        HardenModule(id: "kernel-sysctl", displayName: "Kernel Hardening", group: "Advanced"),
        HardenModule(id: "apparmor-enforce", displayName: "App Sandbox Enforce", group: "Advanced"),
        HardenModule(id: "boot-security", displayName: "Secure Boot / SIP", group: "Advanced"),
    ]

    static var grouped: [(String, [HardenModule])] {
        let groups = Dictionary(grouping: all) { $0.group }
        let order = ["Disk & Boot", "Firewall", "Network & DNS", "Privacy", "Browser",
                     "Access Control", "Dev Tools", "Auth & SSH", "Monitoring", "Maintenance", "Advanced"]
        return order.compactMap { key in
            groups[key].map { (key, $0) }
        }
    }
}
