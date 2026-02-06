import SwiftUI

struct ModifyView: View {
    @StateObject private var runner = ScriptRunner()
    @EnvironmentObject private var mascot: MascotState
    @State private var enabledModules: Set<String> = []

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Modify Modules")
                .font(.title2.bold())

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
                    let modules = enabledModules.joined(separator: ",")
                    Task {
                        mascot.startActivity()
                        _ = await runner.runPrivileged(["--modify", "--modules", modules, "--yes"])
                        if runner.exitCode == 0 { mascot.succeed() } else { mascot.reset() }
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(enabledModules.isEmpty || runner.isRunning)

                if runner.isRunning {
                    ProgressView().controlSize(.small)
                }
            }

            if !runner.output.isEmpty {
                if !runner.isRunning && runner.exitCode == 0 {
                    SuccessBanner(message: "Modules applied")
                }

                OutputLogView(
                    output: runner.output,
                    statusLine: runner.exitCode == 0 ? "Modules applied" : "Finished with errors"
                )
            }
        }
        .padding()
    }
}
