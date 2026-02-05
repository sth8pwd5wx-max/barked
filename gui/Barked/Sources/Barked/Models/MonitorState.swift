import Foundation

enum DaemonStatus: String {
    case notInstalled = "Not Installed"
    case running = "Running"
    case stopped = "Stopped"
    case unknown = "Unknown"
}

struct MonitorState {
    var status: DaemonStatus = .unknown
    var lastRun: Date?
}
