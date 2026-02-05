import Foundation

enum Profile: String, CaseIterable, Identifiable {
    case standard, high, paranoid

    var id: String { rawValue }

    var displayName: String {
        rawValue.capitalized
    }

    var description: String {
        switch self {
        case .standard:
            "Encrypted disk, firewall, secure DNS, auto-updates, basic browser hardening"
        case .high:
            "Standard + outbound firewall, hostname scrubbing, monitoring tools, SSH hardening, telemetry disabled"
        case .paranoid:
            "High + MAC rotation, traffic obfuscation, VPN kill switch, full audit system, metadata stripping, border crossing prep"
        }
    }

    var cliFlag: [String] { ["--profile", rawValue, "--auto", "--yes"] }
}
