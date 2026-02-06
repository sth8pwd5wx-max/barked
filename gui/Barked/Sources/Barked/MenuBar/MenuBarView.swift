import SwiftUI

struct MenuBarView: View {
    @StateObject private var runner = ScriptRunner()
    @Environment(\.openWindow) private var openWindow
    private let configReader = ConfigReader()

    var body: some View {
        Button("Quick Clean") {
            let allCats = CleanCategory.all.map(\.id).joined(separator: ",")
            Task { await runner.run(["--clean", "--force", "--clean-cats", allCats]) }
        }
        .disabled(runner.isRunning)

        if runner.isRunning {
            Text("Cleaning...").foregroundStyle(.secondary)
        }

        Divider()

        Button("Open Barked...") {
            openWindow(id: "main")
            NSApplication.shared.activate(ignoringOtherApps: true)
        }

        Divider()

        Text(configReader.scheduleDisplayText)
            .foregroundStyle(.secondary)

        Button("Check for Updates...") {
            Task {
                await runner.run(["--update-app"])
                let output = runner.output

                if output.contains("__BARKED_RELAUNCH__") {
                    showAlert(
                        title: "Update Installed",
                        message: "Barked has been updated. The app will now relaunch.",
                        style: .informational
                    )
                    let proc = Process()
                    proc.executableURL = URL(fileURLWithPath: "/usr/bin/open")
                    proc.arguments = ["-n", "/Applications/Barked.app"]
                    try? proc.run()
                    DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
                        NSApplication.shared.terminate(nil)
                    }
                } else if output.contains("Already up to date") {
                    showAlert(
                        title: "No Updates Available",
                        message: "You're already running the latest version of Barked.",
                        style: .informational
                    )
                } else {
                    showAlert(
                        title: "Update Failed",
                        message: output.isEmpty ? "Could not check for updates." : output,
                        style: .critical
                    )
                }
            }
        }
        .disabled(runner.isRunning)

        Divider()

        Button("Quit") {
            NSApplication.shared.terminate(nil)
        }
    }

    private func showAlert(title: String, message: String, style: NSAlert.Style) {
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = message
        alert.alertStyle = style
        alert.addButton(withTitle: "OK")
        NSApplication.shared.activate(ignoringOtherApps: true)
        alert.runModal()
    }
}
