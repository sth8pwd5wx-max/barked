import SwiftUI

@main
struct BarkedApp: App {
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
