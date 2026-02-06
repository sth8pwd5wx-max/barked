import SwiftUI

struct CleanView: View {
    @StateObject private var runner = ScriptRunner()
    @State private var selectedCategories: Set<String> = []
    @State private var previewOutput: String = ""
    @State private var showingPreview = false
    @State private var tab: CleanTab = .clean

    enum CleanTab: String, CaseIterable {
        case clean = "Clean"
        case schedule = "Schedule"
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Picker("", selection: $tab) {
                ForEach(CleanTab.allCases, id: \.self) { Text($0.rawValue) }
            }
            .pickerStyle(.segmented)
            .frame(width: 200)

            switch tab {
            case .clean:
                cleanContent
            case .schedule:
                ScheduleContent(runner: runner)
            }
        }
        .padding()
    }

    private var catsArg: String {
        selectedCategories.joined(separator: ",")
    }

    @ViewBuilder
    private var cleanContent: some View {
        Text("System Cleaner")
            .font(.title2.bold())

        Text("Select categories to clean:")
            .foregroundStyle(.secondary)

        ForEach(CleanCategory.all) { cat in
            Toggle(cat.displayName, isOn: Binding(
                get: { selectedCategories.contains(cat.id) },
                set: { on in
                    if on { selectedCategories.insert(cat.id) }
                    else { selectedCategories.remove(cat.id) }
                }
            ))
        }

        HStack(spacing: 12) {
            Button("Preview") {
                Task {
                    await runner.run(["--clean", "--dry-run", "--clean-cats", catsArg])
                    previewOutput = runner.output
                    showingPreview = true
                }
            }
            .disabled(selectedCategories.isEmpty || runner.isRunning)

            Button("Clean Now") {
                Task {
                    _ = await runner.runPrivileged(["--clean", "--force", "--clean-cats", catsArg])
                }
            }
            .buttonStyle(.borderedProminent)
            .disabled(selectedCategories.isEmpty || runner.isRunning)

            if runner.isRunning {
                ProgressView().controlSize(.small)
            }
        }

        if !runner.output.isEmpty {
            OutputLogView(
                output: runner.output,
                statusLine: runner.exitCode == 0 ? "Clean complete" : "Clean finished with errors"
            )
        }

        Spacer()
    }
}

// MARK: - Schedule Tab

private struct ScheduleContent: View {
    @ObservedObject var runner: ScriptRunner
    @State private var schedCategories: Set<String> = []
    @State private var frequency: Frequency = .daily
    @State private var editing = false
    @State private var statusMessage: String?

    private let config = ConfigReader()

    enum Frequency: String, CaseIterable {
        case daily = "Daily"
        case weekly = "Weekly"
    }

    var body: some View {
        Text("Scheduled Cleaning")
            .font(.title2.bold())

        if editing {
            editingForm
        } else {
            currentStatus
        }

        if !runner.output.isEmpty {
            OutputLogView(
                output: runner.output,
                statusLine: runner.exitCode == 0 ? "Schedule removed" : "Failed to remove schedule"
            )
        }

        Spacer()
    }

    @ViewBuilder
    private var currentStatus: some View {
        let schedConfig = config.readScheduleConfig()

        if let sched = schedConfig, sched.enabled {
            Label("Active: \(sched.schedule.capitalized)", systemImage: "clock.badge.checkmark")
                .foregroundStyle(.green)

            Text("Categories: \(sched.categories.joined(separator: ", "))")
                .foregroundStyle(.secondary)
        } else {
            Label("No schedule configured", systemImage: "clock")
                .foregroundStyle(.secondary)
        }

        HStack(spacing: 12) {
            Button("Configure Schedule...") {
                loadExisting()
                editing = true
            }

            if let sched = schedConfig, sched.enabled {
                Button("Remove Schedule") {
                    Task { await runner.run(["--clean-unschedule"]) }
                }
                .foregroundStyle(.red)
            }
        }
    }

    @ViewBuilder
    private var editingForm: some View {
        Text("Select categories:")
            .foregroundStyle(.secondary)

        ForEach(CleanCategory.all) { cat in
            Toggle(cat.displayName, isOn: Binding(
                get: { schedCategories.contains(cat.id) },
                set: { on in
                    if on { schedCategories.insert(cat.id) }
                    else { schedCategories.remove(cat.id) }
                }
            ))
        }

        Picker("Frequency", selection: $frequency) {
            ForEach(Frequency.allCases, id: \.self) { Text($0.rawValue) }
        }
        .pickerStyle(.segmented)
        .frame(width: 200)

        if let msg = statusMessage {
            Text(msg)
                .font(.caption)
                .foregroundStyle(msg.hasPrefix("Error") ? .red : .green)
        }

        HStack(spacing: 12) {
            Button("Save Schedule") {
                save()
            }
            .buttonStyle(.borderedProminent)
            .disabled(schedCategories.isEmpty)

            Button("Cancel") {
                editing = false
                statusMessage = nil
            }
        }
    }

    private func loadExisting() {
        if let sched = config.readScheduleConfig(), sched.enabled {
            schedCategories = Set(sched.categories)
            frequency = sched.schedule == "weekly" ? .weekly : .daily
        } else {
            schedCategories = []
            frequency = .daily
        }
    }

    private func save() {
        let configDir = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".config/barked")
        let configPath = configDir.appendingPathComponent("scheduled-clean.json")
        let cats = CleanCategory.all.map(\.id).filter { schedCategories.contains($0) }

        // Write config JSON
        let json: [String: Any] = [
            "enabled": true,
            "schedule": frequency.rawValue.lowercased(),
            "custom_interval": "",
            "categories": cats,
            "notify": true,
            "last_run": "",
            "version": "1.0"
        ]

        do {
            try FileManager.default.createDirectory(at: configDir, withIntermediateDirectories: true)
            let data = try JSONSerialization.data(withJSONObject: json, options: .prettyPrinted)
            try data.write(to: configPath)
        } catch {
            statusMessage = "Error: \(error.localizedDescription)"
            return
        }

        // Install launchd plist
        if installLaunchAgent() {
            statusMessage = "Schedule saved"
            editing = false
            DispatchQueue.main.asyncAfter(deadline: .now() + 2) { statusMessage = nil }
        }
    }

    private func installLaunchAgent() -> Bool {
        let scriptRunner = ScriptRunner()
        let barkedPath = scriptRunner.scriptPath
        let plistDir = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/LaunchAgents")
        let plistPath = plistDir.appendingPathComponent("com.barked.scheduled-clean.plist")

        var intervalXML: String
        switch frequency {
        case .daily:
            intervalXML = """
                <dict>
                  <key>Hour</key>
                  <integer>2</integer>
                  <key>Minute</key>
                  <integer>0</integer>
                </dict>
            """
        case .weekly:
            intervalXML = """
                <dict>
                  <key>Weekday</key>
                  <integer>0</integer>
                  <key>Hour</key>
                  <integer>2</integer>
                  <key>Minute</key>
                  <integer>0</integer>
                </dict>
            """
        }

        let escapedPath = barkedPath
            .replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")

        let home = FileManager.default.homeDirectoryForCurrentUser.path

        let plist = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
          <key>Label</key>
          <string>com.barked.scheduled-clean</string>
          <key>ProgramArguments</key>
          <array>
            <string>\(escapedPath)</string>
            <string>--clean-scheduled</string>
          </array>
          <key>StartCalendarInterval</key>
        \(intervalXML)
          <key>RunAtLoad</key>
          <false/>
          <key>StandardOutPath</key>
          <string>\(home)/Library/Logs/barked-clean.log</string>
          <key>StandardErrorPath</key>
          <string>\(home)/Library/Logs/barked-clean-error.log</string>
        </dict>
        </plist>
        """

        do {
            try FileManager.default.createDirectory(at: plistDir, withIntermediateDirectories: true)
            // Unload existing job
            let unload = Process()
            unload.executableURL = URL(fileURLWithPath: "/bin/launchctl")
            unload.arguments = ["unload", plistPath.path]
            unload.standardInput = FileHandle.nullDevice
            unload.standardOutput = FileHandle.nullDevice
            unload.standardError = FileHandle.nullDevice
            try? unload.run()
            unload.waitUntilExit()

            try plist.write(to: plistPath, atomically: true, encoding: .utf8)

            let load = Process()
            load.executableURL = URL(fileURLWithPath: "/bin/launchctl")
            load.arguments = ["load", plistPath.path]
            load.standardInput = FileHandle.nullDevice
            load.standardOutput = FileHandle.nullDevice
            load.standardError = FileHandle.nullDevice
            try load.run()
            load.waitUntilExit()

            if load.terminationStatus != 0 {
                statusMessage = "Error: launchctl load failed"
                return false
            }
            return true
        } catch {
            statusMessage = "Error: \(error.localizedDescription)"
            return false
        }
    }
}
