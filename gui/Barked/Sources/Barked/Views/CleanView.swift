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
                scheduleContent
            }
        }
        .padding()
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
                    await runner.run(["--clean", "--dry-run"])
                    previewOutput = runner.output
                    showingPreview = true
                }
            }
            .disabled(selectedCategories.isEmpty || runner.isRunning)

            Button("Clean Now") {
                Task { await runner.run(["--clean", "--force"]) }
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

    @ViewBuilder
    private var scheduleContent: some View {
        Text("Scheduled Cleaning")
            .font(.title2.bold())

        let config = ConfigReader()
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

        Button("Configure Schedule...") {
            Task { await runner.run(["--clean-schedule"]) }
        }

        Button("Remove Schedule") {
            Task { await runner.run(["--clean-unschedule"]) }
        }
        .foregroundStyle(.red)

        Spacer()
    }
}
