import SwiftUI

struct ModifyView: View {
    @StateObject private var runner = ScriptRunner()
    @State private var enabledModules: Set<String> = []

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Text("Modify Modules")
                    .font(.title2.bold())
                Spacer()
                Button("Select All") {
                    enabledModules = Set(HardenModule.all.map(\.id))
                }
                .buttonStyle(.borderless)
                .font(.caption)
                Button("Deselect All") {
                    enabledModules = []
                }
                .buttonStyle(.borderless)
                .font(.caption)
            }

            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    ForEach(HardenModule.grouped, id: \.0) { group, modules in
                        Section {
                            ForEach(modules) { mod in
                                Toggle(mod.displayName, isOn: Binding(
                                    get: { enabledModules.contains(mod.id) },
                                    set: { enabled in
                                        if enabled { enabledModules.insert(mod.id) }
                                        else { enabledModules.remove(mod.id) }
                                    }
                                ))
                            }
                        } header: {
                            Text(group)
                                .font(.headline)
                                .padding(.top, 4)
                        }
                    }
                }
            }

            HStack {
                Button("Apply \(enabledModules.count) Modules") {
                    Task {
                        _ = await runner.runPrivileged(["--auto", "--modify"], reason: "Modifying security modules requires administrator access to change firewall, network, and system configuration.")
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(enabledModules.isEmpty || runner.isRunning)

                if runner.isRunning {
                    ProgressView().controlSize(.small)
                }
            }

            if !runner.output.isEmpty {
                OutputLogView(
                    output: runner.output,
                    statusLine: runner.exitCode == 0 ? "Modules applied" : "Finished with errors"
                )
            }
        }
        .padding()
    }
}
