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
                notInstalledView
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
    private var notInstalledView: some View {
        Label("Monitor daemon is not installed", systemImage: "exclamationmark.triangle")
            .foregroundStyle(.orange)

        Text("Install the monitor daemon to enable continuous security checks for VPN status, supply chain integrity, and network anomalies.")
            .foregroundStyle(.secondary)

        Button("Install Monitor...") {
            Task {
                await runner.run(["--monitor", "--install"])
                await checkStatus()
            }
        }
        .buttonStyle(.borderedProminent)
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
            Task { await runner.run(["--monitor", "--uninstall"]) ; await checkStatus() }
        }
        .foregroundStyle(.red)
    }

    private func checkStatus() async {
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
