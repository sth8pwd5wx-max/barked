import SwiftUI
import AppKit

@main
struct BarkedApp: App {
    @NSApplicationDelegateAdaptor private var appDelegate: AppDelegate

    var body: some Scene {
        MenuBarExtra {
            MenuBarView()
        } label: {
            Image(nsImage: Self.menuBarIconGreen)
        }

        Window("Barked", id: "main") {
            ContentView()
                .frame(minWidth: 700, minHeight: 500)
                .onAppear {
                    NSApplication.shared.activate(ignoringOtherApps: true)
                }
        }
        .defaultPosition(.center)
    }

    /// Green tree — normal state
    static let menuBarIconGreen: NSImage = makeTreeIcon(
        fill: NSColor(red: 0.322, green: 0.718, blue: 0.533, alpha: 1), // #52b788
        trunk: NSColor(red: 0.545, green: 0.369, blue: 0.235, alpha: 1), // #8B5E3C
        mark: .none
    )

    /// Red tree with X — alert state
    static let menuBarIconRed: NSImage = makeTreeIcon(
        fill: NSColor(red: 0.906, green: 0.298, blue: 0.235, alpha: 1), // #e74c3c
        trunk: NSColor(red: 0.42, green: 0.247, blue: 0.165, alpha: 1), // #6B3F2A
        mark: .xmark
    )

    enum TreeMark { case none, xmark }

    private static func makeTreeIcon(fill: NSColor, trunk: NSColor, mark: TreeMark) -> NSImage {
        let size = NSSize(width: 18, height: 18)
        let image = NSImage(size: size, flipped: true) { rect in
            let w = rect.width
            let h = rect.height
            let cx = w / 2

            // Three-tier pine tree silhouette
            // Top tier
            let top = NSBezierPath()
            top.move(to: NSPoint(x: cx, y: 0.5))
            top.line(to: NSPoint(x: cx - 4.5, y: h * 0.35))
            top.line(to: NSPoint(x: cx + 4.5, y: h * 0.35))
            top.close()

            // Middle tier
            let mid = NSBezierPath()
            mid.move(to: NSPoint(x: cx, y: h * 0.18))
            mid.line(to: NSPoint(x: cx - 6.5, y: h * 0.58))
            mid.line(to: NSPoint(x: cx + 6.5, y: h * 0.58))
            mid.close()

            // Bottom tier
            let bot = NSBezierPath()
            bot.move(to: NSPoint(x: cx, y: h * 0.38))
            bot.line(to: NSPoint(x: cx - 8, y: h * 0.78))
            bot.line(to: NSPoint(x: cx + 8, y: h * 0.78))
            bot.close()

            fill.setFill()
            bot.fill()
            mid.fill()
            top.fill()

            // Trunk
            let trunkRect = NSRect(x: cx - 1.5, y: h * 0.78, width: 3, height: h * 0.18)
            trunk.setFill()
            NSBezierPath(rect: trunkRect).fill()

            // X mark overlay
            if mark == .xmark {
                NSColor.white.setStroke()
                let stroke = NSBezierPath()
                stroke.lineWidth = 1.8
                stroke.lineCapStyle = .round
                stroke.move(to: NSPoint(x: cx - 3.5, y: h * 0.3))
                stroke.line(to: NSPoint(x: cx + 3.5, y: h * 0.6))
                stroke.move(to: NSPoint(x: cx + 3.5, y: h * 0.3))
                stroke.line(to: NSPoint(x: cx - 3.5, y: h * 0.6))
                stroke.stroke()
            }
            return true
        }
        image.isTemplate = false
        return image
    }
}

class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) {
            if let window = NSApplication.shared.windows.first(where: { $0.title == "Barked" }) {
                window.makeKeyAndOrderFront(nil)
            }
            NSApplication.shared.activate(ignoringOtherApps: true)
        }
    }
}
