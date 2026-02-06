import SwiftUI

struct MonitorView: View {
    @StateObject private var runner = ScriptRunner()
    @State private var daemonStatus: DaemonStatus = .unknown

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Security Monitor")
                .font(.title2.bold())

            switch daemonStatus {
            case .notInstalled:
                MonitorInstallForm(runner: runner) { await checkStatus() }
            case .running:
                managementView(running: true)
            case .stopped:
                managementView(running: false)
            case .unknown:
                ProgressView("Checking daemon status...")
            }

            if !runner.output.isEmpty {
                OutputLogView(
                    output: runner.output,
                    statusLine: "Monitor output"
                )
            }

            Spacer()
        }
        .padding()
        .task { await checkStatus() }
    }

    @ViewBuilder
    private func managementView(running: Bool) -> some View {
        Label(running ? "Daemon is running" : "Daemon is stopped",
              systemImage: running ? "checkmark.circle.fill" : "pause.circle")
        .foregroundStyle(running ? .green : .orange)

        HStack(spacing: 12) {
            if running {
                Button("Stop") {
                    Task { await runner.run(["--monitor", "--disable"]) ; await checkStatus() }
                }
                Button("Restart") {
                    Task { await runner.run(["--monitor", "--restart"]) ; await checkStatus() }
                }
            } else {
                Button("Start") {
                    Task { await runner.run(["--monitor", "--enable"]) ; await checkStatus() }
                }
            }

            Button("View Logs") {
                Task { await runner.run(["--monitor", "--logs"]) }
            }

            Button("Health Check") {
                Task { await runner.run(["--monitor", "--health"]) }
            }
        }

        Divider()

        Button("Uninstall Monitor") {
            uninstallMonitor()
        }
        .foregroundStyle(.red)
    }

    private func uninstallMonitor() {
        let home = FileManager.default.homeDirectoryForCurrentUser
        let plistPath = home.appendingPathComponent("Library/LaunchAgents/com.barked.monitor.plist")
        let configPath = home.appendingPathComponent(".config/barked/monitor.conf")

        // Unload launchd job
        let unload = Process()
        unload.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        unload.arguments = ["unload", plistPath.path]
        unload.standardInput = FileHandle.nullDevice
        unload.standardOutput = FileHandle.nullDevice
        unload.standardError = FileHandle.nullDevice
        try? unload.run()
        unload.waitUntilExit()

        // Remove plist
        try? FileManager.default.removeItem(at: plistPath)

        // Update config to mark uninstalled
        if FileManager.default.fileExists(atPath: configPath.path),
           var contents = try? String(contentsOf: configPath, encoding: .utf8) {
            contents = contents.replacingOccurrences(of: "DAEMON_INSTALLED=true", with: "DAEMON_INSTALLED=false")
            try? contents.write(to: configPath, atomically: true, encoding: .utf8)
        }

        daemonStatus = .notInstalled
    }

    func checkStatus() async {
        let plistPath = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/LaunchAgents/com.barked.monitor.plist")

        guard FileManager.default.fileExists(atPath: plistPath.path) else {
            daemonStatus = .notInstalled
            return
        }

        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        proc.arguments = ["list", "com.barked.monitor"]
        let pipe = Pipe()
        proc.standardOutput = pipe
        proc.standardError = Pipe()

        do {
            try proc.run()
            proc.waitUntilExit()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: data, encoding: .utf8) ?? ""
            let firstLine = output.components(separatedBy: "\n").first ?? ""
            if firstLine.contains("PID") || (proc.terminationStatus == 0 && !output.contains("\"PID\" = 0;")) {
                daemonStatus = .running
            } else {
                daemonStatus = .stopped
            }
        } catch {
            daemonStatus = .unknown
        }
    }
}

// MARK: - Monitor Install Form

private struct MonitorInstallForm: View {
    @ObservedObject var runner: ScriptRunner
    var onComplete: () async -> Void

    @State private var startMode: StartMode = .always
    @State private var interval: IntervalChoice = .fiveMinutes
    @State private var severity: SeverityChoice = .warningAndCritical
    @State private var createBaseline = true
    @State private var statusMessage: String?
    @State private var installing = false

    enum StartMode: String, CaseIterable {
        case always = "Always on login"
        case acPower = "Only on AC power"
        case manual = "Manual control"
    }

    enum IntervalChoice: String, CaseIterable {
        case oneMinute = "Every 1 minute"
        case fiveMinutes = "Every 5 minutes"
        case fifteenMinutes = "Every 15 minutes"

        var seconds: Int {
            switch self {
            case .oneMinute: 60
            case .fiveMinutes: 300
            case .fifteenMinutes: 900
            }
        }
    }

    enum SeverityChoice: String, CaseIterable {
        case warningAndCritical = "Warning + Critical"
        case criticalOnly = "Critical only"

        var configValue: String {
            switch self {
            case .warningAndCritical: "warning"
            case .criticalOnly: "critical"
            }
        }
    }

    var body: some View {
        Label("Monitor daemon is not installed", systemImage: "exclamationmark.triangle")
            .foregroundStyle(.orange)

        Text("Install the monitor daemon for continuous security checks.")
            .foregroundStyle(.secondary)

        GroupBox("Configuration") {
            VStack(alignment: .leading, spacing: 12) {
                Picker("Startup", selection: $startMode) {
                    ForEach(StartMode.allCases, id: \.self) { Text($0.rawValue) }
                }

                Picker("Check interval", selection: $interval) {
                    ForEach(IntervalChoice.allCases, id: \.self) { Text($0.rawValue) }
                }

                Picker("Alert threshold", selection: $severity) {
                    ForEach(SeverityChoice.allCases, id: \.self) { Text($0.rawValue) }
                }

                Toggle("Create security baseline", isOn: $createBaseline)
            }
            .padding(.vertical, 4)
        }

        if let msg = statusMessage {
            Text(msg)
                .font(.caption)
                .foregroundStyle(msg.hasPrefix("Error") ? .red : .green)
        }

        Button("Install Monitor") {
            install()
        }
        .buttonStyle(.borderedProminent)
        .disabled(installing)
    }

    private func install() {
        installing = true
        statusMessage = nil

        let home = FileManager.default.homeDirectoryForCurrentUser
        let configDir = home.appendingPathComponent(".config/barked")
        let configPath = configDir.appendingPathComponent("monitor.conf")
        let stateDir = configDir.appendingPathComponent("state")
        let baselineDir = configDir.appendingPathComponent("baselines")
        let plistDir = home.appendingPathComponent("Library/LaunchAgents")
        let plistPath = plistDir.appendingPathComponent("com.barked.monitor.plist")

        let scriptRunner = ScriptRunner()
        let barkedPath = scriptRunner.scriptPath
        let bashPath = scriptRunner.bashPath

        do {
            // Create directories
            for dir in [configDir, stateDir, baselineDir, plistDir] {
                try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            }

            // Write monitor config
            let startModeValue: String
            switch startMode {
            case .always: startModeValue = "always"
            case .acPower: startModeValue = "ac_power"
            case .manual: startModeValue = "manual"
            }

            let config = """
            # Barked Monitor Configuration
            # Generated: \(ISO8601DateFormatter().string(from: Date()))

            # Daemon settings
            DAEMON_ENABLED=true
            DAEMON_START_MODE="\(startModeValue)"
            DAEMON_INSTALLED=true

            # Monitor settings
            MONITOR_INTERVAL=\(interval.seconds)
            MONITOR_CATEGORIES="network,supply-chain,cloud-sync,dev-env"

            # Alert channels
            ALERT_MACOS_NOTIFY=true
            ALERT_LINUX_NOTIFY=true
            ALERT_WEBHOOK_URL=""

            # Email (configure manually if needed)
            ALERT_EMAIL_ENABLED=false
            ALERT_EMAIL_API_URL=""
            ALERT_EMAIL_API_KEY=""
            ALERT_EMAIL_TO=""

            # Alert behavior
            ALERT_COOLDOWN=3600
            ALERT_SEVERITY_MIN="\(severity.configValue)"

            # Notification detail
            NOTIFY_SHOW_IMPACT=true
            NOTIFY_SHOW_REMEDIATION=true
            NOTIFY_MACOS_CLICK_ACTION="log"
            """
            try config.write(to: configPath, atomically: true, encoding: .utf8)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: configPath.path)

            // Create baseline if requested
            if createBaseline {
                let baselineProc = Process()
                baselineProc.executableURL = URL(fileURLWithPath: bashPath)
                baselineProc.arguments = [barkedPath, "--monitor", "--baseline"]
                baselineProc.standardInput = FileHandle.nullDevice
                baselineProc.standardOutput = FileHandle.nullDevice
                baselineProc.standardError = FileHandle.nullDevice
                try? baselineProc.run()
                baselineProc.waitUntilExit()
            }

            // Build plist
            let runAtLoad = startMode != .manual
            let escapedBash = bashPath
                .replacingOccurrences(of: "&", with: "&amp;")
                .replacingOccurrences(of: "<", with: "&lt;")
            let escapedBarked = barkedPath
                .replacingOccurrences(of: "&", with: "&amp;")
                .replacingOccurrences(of: "<", with: "&lt;")

            let plist = """
            <?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
            <plist version="1.0">
            <dict>
              <key>Label</key>
              <string>com.barked.monitor</string>
              <key>ProgramArguments</key>
              <array>
                <string>\(escapedBash)</string>
                <string>\(escapedBarked)</string>
                <string>--monitor</string>
                <string>--daemon</string>
              </array>
              <key>RunAtLoad</key>
              <\(runAtLoad)/>
              <key>KeepAlive</key>
              <true/>
              <key>ThrottleInterval</key>
              <integer>60</integer>
              <key>StandardOutPath</key>
              <string>\(home.path)/.config/barked/monitor-stdout.log</string>
              <key>StandardErrorPath</key>
              <string>\(home.path)/.config/barked/monitor-stderr.log</string>
            </dict>
            </plist>
            """

            // Unload existing, write new, load
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
                installing = false
                return
            }

            statusMessage = "Monitor installed"
            installing = false
            Task { await onComplete() }
        } catch {
            statusMessage = "Error: \(error.localizedDescription)"
            installing = false
        }
    }
}
