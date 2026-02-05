import Foundation

struct CleanCategory: Identifiable, Hashable {
    let id: String
    let displayName: String
    let targets: [String]

    static let all: [CleanCategory] = [
        CleanCategory(id: "system-caches", displayName: "System Caches & Logs",
                      targets: ["system-cache", "system-logs", "diagnostic-reports", "dns-cache"]),
        CleanCategory(id: "user-caches", displayName: "User Caches & Logs",
                      targets: ["user-cache", "user-logs", "saved-app-state"]),
        CleanCategory(id: "browser-data", displayName: "Browser Data",
                      targets: ["safari", "chrome", "firefox", "arc", "edge"]),
        CleanCategory(id: "privacy-traces", displayName: "Privacy Traces",
                      targets: ["recent-items", "quicklook-thumbs", "ds-store", "clipboard", "search-metadata"]),
        CleanCategory(id: "dev-cruft", displayName: "Developer Cruft",
                      targets: ["xcode-derived", "homebrew-cache", "npm-cache", "yarn-cache", "pip-cache",
                                "cargo-cache", "go-cache", "cocoapods-cache", "docker-cruft", "ide-caches"]),
        CleanCategory(id: "trash-downloads", displayName: "Trash & Downloads",
                      targets: ["trash", "old-downloads"]),
        CleanCategory(id: "mail-messages", displayName: "Mail & Messages",
                      targets: ["mail-cache", "messages-attachments"]),
    ]
}
