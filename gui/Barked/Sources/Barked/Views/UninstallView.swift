import SwiftUI

struct UninstallView: View {
    @StateObject private var runner = ScriptRunner()
    @EnvironmentObject private var mascot: MascotState
    @State private var confirmed = false

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Uninstall Hardening")
                .font(.title2.bold())

            Label("This will revert all hardening changes applied by Barked.", systemImage: "exclamationmark.triangle.fill")
                .foregroundStyle(.red)

            Text("""
                This includes:
                - Firewall rules
                - DNS configuration
                - Hostname changes
                - Browser hardening
                - SSH configuration
                - All other applied modules
                """)
                .foregroundStyle(.secondary)
                .padding(.leading, 4)

            Toggle("I understand this will revert all hardening changes", isOn: $confirmed)

            Button("Uninstall") {
                Task {
                    mascot.startActivity()
                    _ = await runner.runPrivileged(["--uninstall", "--yes"])
                    if runner.exitCode == 0 { mascot.succeed() } else { mascot.reset() }
                }
            }
            .buttonStyle(.borderedProminent)
            .tint(.red)
            .disabled(!confirmed || runner.isRunning)

            if runner.isRunning {
                ProgressView("Reverting changes...")
            }

            if !runner.output.isEmpty {
                OutputLogView(
                    output: runner.output,
                    statusLine: runner.exitCode == 0 ? "Uninstall complete" : "Uninstall finished with errors"
                )
            }

            Spacer()
        }
        .padding()
    }
}
