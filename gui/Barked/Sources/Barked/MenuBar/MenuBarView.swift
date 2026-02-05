import SwiftUI

struct MenuBarView: View {
    @StateObject private var runner = ScriptRunner()
    private let configReader = ConfigReader()

    var body: some View {
        Button("Quick Clean") {
            Task { await runner.run(["--clean", "--force"]) }
        }
        .disabled(runner.isRunning)

        if runner.isRunning {
            Text("Cleaning...").foregroundStyle(.secondary)
        }

        Divider()

        Button("Open Barked...") {
            openMainWindow()
        }

        Divider()

        Text(configReader.scheduleDisplayText)
            .foregroundStyle(.secondary)

        Divider()

        Button("Quit") {
            NSApplication.shared.terminate(nil)
        }
    }

    private func openMainWindow() {
        if let window = NSApplication.shared.windows.first(where: { $0.identifier?.rawValue == "main" }) {
            window.makeKeyAndOrderFront(nil)
        }
        NSApplication.shared.activate(ignoringOtherApps: true)
        NSApp.sendAction(#selector(NSWindow.makeKeyAndOrderFront(_:)), to: nil, from: nil)
    }
}
