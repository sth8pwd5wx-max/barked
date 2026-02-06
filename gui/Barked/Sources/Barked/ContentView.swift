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
    @StateObject private var mascotState = MascotState()

    var body: some View {
        NavigationSplitView {
            VStack {
                List(SidebarItem.allCases, selection: $selection) { item in
                    Label(item.rawValue, systemImage: item.icon)
                        .tag(item)
                }
                .listStyle(.sidebar)

                Spacer()

                MascotView(mood: mascotState.mood, pixelSize: 5)
                    .padding(.bottom, 32)
                    .opacity(0.85)
            }
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
        .environmentObject(mascotState)
    }

    private var welcomeView: some View {
        VStack(spacing: 12) {
            Spacer()
            MascotView(mood: .idle, pixelSize: 6)
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
