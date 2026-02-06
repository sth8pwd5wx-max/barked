import SwiftUI

enum SidebarItem: String, CaseIterable, Identifiable {
    case harden = "Harden"
    case modify = "Modify"
    case clean = "Clean"
    case monitor = "Monitor"
    case uninstall = "Uninstall"

    var id: String { rawValue }

    var icon: String {
        switch self {
        case .harden: "lock.shield"
        case .modify: "slider.horizontal.3"
        case .clean: "trash"
        case .monitor: "eye"
        case .uninstall: "xmark.circle"
        }
    }
}

struct ContentView: View {
    @State private var selection: SidebarItem? = .harden

    var body: some View {
        NavigationSplitView {
            List(SidebarItem.allCases, selection: $selection) { item in
                Label(item.rawValue, systemImage: item.icon)
                    .tag(item)
            }
            .listStyle(.sidebar)
        } detail: {
            switch selection {
            case .harden: HardenView()
            case .modify: ModifyView()
            case .clean: CleanView()
            case .monitor: MonitorView()
            case .uninstall: UninstallView()
            case nil: welcomeView
            }
        }
    }

    private var welcomeView: some View {
        VStack(spacing: 12) {
            Spacer()
            Text("Welcome to Barked")
                .font(.title2.bold())
            Text("Tough outer layer for your system.\nPick a section from the sidebar to get started.")
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)
                .font(.callout)
            Spacer()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}
