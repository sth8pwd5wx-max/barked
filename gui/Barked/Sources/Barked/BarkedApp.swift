import SwiftUI

@main
struct BarkedApp: App {
    @NSApplicationDelegateAdaptor private var appDelegate: AppDelegate

    var body: some Scene {
        MenuBarExtra("Barked", systemImage: "shield.checkmark") {
            MenuBarView()
        }

        Window("Barked", id: "main") {
            ContentView()
                .frame(minWidth: 700, minHeight: 500)
        }
    }
}

class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        // Open main window on launch so the app feels responsive
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) {
            NSApplication.shared.activate(ignoringOtherApps: true)
            NSApp.sendAction(#selector(NSWindow.makeKeyAndOrderFront(_:)), to: nil, from: nil)
        }
    }
}
