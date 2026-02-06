import SwiftUI

struct HardenView: View {
    @StateObject private var runner = ScriptRunner()
    @State private var selectedProfile: Profile?

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Hardening Profile")
                .font(.title2.bold())

            ForEach(Profile.allCases) { profile in
                ProfileCard(profile: profile, isSelected: selectedProfile == profile) {
                    selectedProfile = profile
                }
            }

            if let profile = selectedProfile {
                HStack {
                    Button("Apply \(profile.displayName) Profile") {
                        Task {
                            _ = await runner.runPrivileged(profile.cliFlag)
                        }
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(runner.isRunning)

                    if runner.isRunning {
                        ProgressView()
                            .controlSize(.small)
                    }
                }
            }

            if !runner.output.isEmpty {
                OutputLogView(
                    output: runner.output,
                    statusLine: runner.exitCode == 0 ? "Hardening complete" : "Hardening finished with errors"
                )
            }

            Spacer()
        }
        .padding()
    }
}

struct ProfileCard: View {
    let profile: Profile
    let isSelected: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            VStack(alignment: .leading, spacing: 4) {
                Text(profile.displayName)
                    .font(.headline)
                Text(profile.description)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(12)
            .background(isSelected ? Color.accentColor.opacity(0.1) : Color(.controlBackgroundColor))
            .clipShape(RoundedRectangle(cornerRadius: 8))
            .overlay(
                RoundedRectangle(cornerRadius: 8)
                    .stroke(isSelected ? Color.accentColor : Color.clear, lineWidth: 2)
            )
        }
        .buttonStyle(.plain)
    }
}
