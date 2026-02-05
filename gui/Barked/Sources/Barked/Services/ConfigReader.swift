import Foundation

struct ScheduleConfig {
    var enabled: Bool = false
    var schedule: String = ""
    var categories: [String] = []
}

class ConfigReader {
    private let userConfigDir = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent(".config/barked")

    var scheduledCleanPath: URL {
        userConfigDir.appendingPathComponent("scheduled-clean.json")
    }

    func readScheduleConfig() -> ScheduleConfig? {
        guard let data = try? Data(contentsOf: scheduledCleanPath),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return nil
        }

        var config = ScheduleConfig()
        config.enabled = json["enabled"] as? Bool ?? false
        config.schedule = json["schedule"] as? String ?? ""
        config.categories = json["categories"] as? [String] ?? []
        return config
    }

    var scheduleDisplayText: String {
        guard let config = readScheduleConfig(), config.enabled else {
            return "No schedule configured"
        }
        switch config.schedule {
        case "daily": return "Scheduled: Daily"
        case "weekly": return "Scheduled: Weekly"
        case "custom": return "Scheduled: Custom"
        default: return "Scheduled: \(config.schedule)"
        }
    }
}
