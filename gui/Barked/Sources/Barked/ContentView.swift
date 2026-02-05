import SwiftUI

struct ContentView: View {
    var body: some View {
        NavigationSplitView {
            List {
                Label("Harden", systemImage: "lock.shield")
                Label("Modify", systemImage: "slider.horizontal.3")
                Label("Clean", systemImage: "trash")
                Label("Monitor", systemImage: "eye")
                Label("Uninstall", systemImage: "xmark.circle")
            }
            .navigationTitle("Barked")
        } detail: {
            Text("Select an option")
                .foregroundStyle(.secondary)
        }
    }
}
