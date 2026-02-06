import SwiftUI

/// Pixel art pine tree mascot rendered natively in SwiftUI.
/// 24x24 pixel grid — each pixel maps to `pixelSize x pixelSize` points.
enum MascotMood {
    case idle
    case cheer
    case windy
}

struct MascotView: View {
    var mood: MascotMood = .idle
    var pixelSize: CGFloat = 4

    // Animation state
    @State private var bounceOffset: CGFloat = 0
    @State private var showSparkles = false
    @State private var pupilOffsetX: CGFloat = 0
    @State private var pupilOffsetY: CGFloat = 0
    @State private var isBlinking = false
    @State private var swayOffset: CGFloat = 0
    @State private var leafParticles: [LeafParticle] = []

    struct LeafParticle: Identifiable {
        let id = UUID()
        var x: CGFloat
        var y: CGFloat
        var opacity: Double
        let color: Color
    }

    private var gridSize: CGFloat { 24 * pixelSize }

    var body: some View {
        ZStack(alignment: .topLeading) {
            // Sparkles (cheer only)
            if mood == .cheer {
                sparkles
            }

            // Blown needles (windy only)
            if mood == .windy {
                ForEach(leafParticles) { leaf in
                    leaf.color
                        .frame(width: pixelSize, height: pixelSize)
                        .opacity(leaf.opacity)
                        .offset(x: leaf.x * pixelSize, y: leaf.y * pixelSize)
                }
            }

            // Ground (static — no sway/bounce)
            groundPixels

            // Tree (crown + eyes + mouth + trunk) — animated
            treePixels
                .offset(x: swayOffset, y: bounceOffset)
        }
        .frame(width: gridSize, height: gridSize)
        .onAppear { startAnimations() }
        .onChange(of: mood) { _ in startAnimations() }
    }

    // MARK: - Tree pixels (everything that sways/bounces)

    private var treePixels: some View {
        ZStack(alignment: .topLeading) {
            // Star/tip
            pixel(x: 11, y: 0, w: 2, h: 1, color: Color(hex: 0x6fcf97))

            // Top tier
            pixel(x: 10, y: 1, w: 4, h: 1, color: Color(hex: 0x52b788))
            pixel(x: 9, y: 2, w: 6, h: 1, color: Color(hex: 0x40916c))
            pixel(x: 8, y: 3, w: 8, h: 1, color: Color(hex: 0x2d6a4f))

            // Middle tier
            pixel(x: 9, y: 4, w: 6, h: 1, color: Color(hex: 0x52b788))
            pixel(x: 8, y: 5, w: 8, h: 1, color: Color(hex: 0x6fcf97))
            pixel(x: 7, y: 6, w: 10, h: 1, color: Color(hex: 0x52b788))
            pixel(x: 6, y: 7, w: 12, h: 1, color: Color(hex: 0x40916c))
            pixel(x: 5, y: 8, w: 14, h: 1, color: Color(hex: 0x2d6a4f))

            // Bottom tier (face area)
            pixel(x: 7, y: 9, w: 10, h: 1, color: Color(hex: 0x52b788))
            pixel(x: 6, y: 10, w: 12, h: 1, color: Color(hex: 0x6fcf97))
            pixel(x: 5, y: 11, w: 14, h: 1, color: Color(hex: 0x52b788))
            pixel(x: 4, y: 12, w: 16, h: 1, color: Color(hex: 0x40916c))
            pixel(x: 3, y: 13, w: 18, h: 1, color: Color(hex: 0x52b788))
            pixel(x: 3, y: 14, w: 18, h: 1, color: Color(hex: 0x40916c))
            pixel(x: 4, y: 15, w: 16, h: 1, color: Color(hex: 0x2d6a4f))

            // Eyes
            if mood == .windy && isBlinking {
                pixel(x: 7, y: 10, w: 2, h: 1, color: Color(hex: 0x2d6a4f))
                pixel(x: 14, y: 10, w: 2, h: 1, color: Color(hex: 0x2d6a4f))
            } else if mood == .windy {
                pixel(x: 7, y: 10, w: 2, h: 1, color: .white)
                pixel(x: 14, y: 10, w: 2, h: 1, color: .white)
                pixel(x: 8, y: 10, w: 1, h: 1, color: Color(hex: 0x111111))
                pixel(x: 15, y: 10, w: 1, h: 1, color: Color(hex: 0x111111))
            } else if isBlinking {
                pixel(x: 7, y: 11, w: 2, h: 1, color: .white)
                pixel(x: 14, y: 11, w: 2, h: 1, color: .white)
            } else {
                pixel(x: 7, y: 10, w: 2, h: 2, color: .white)
                pixel(x: 14, y: 10, w: 2, h: 2, color: .white)
                pixel(x: 8 + Int(pupilOffsetX), y: 10 + Int(pupilOffsetY), w: 1, h: 1, color: Color(hex: 0x111111))
                pixel(x: 15 + Int(pupilOffsetX), y: 10 + Int(pupilOffsetY), w: 1, h: 1, color: Color(hex: 0x111111))
            }

            // Mouth
            if mood == .cheer {
                pixel(x: 10, y: 12, w: 4, h: 1, color: Color(hex: 0x1a4d2e))
                pixel(x: 11, y: 13, w: 2, h: 1, color: Color(hex: 0x1a4d2e))
            } else if mood == .windy {
                pixel(x: 11, y: 13, w: 2, h: 1, color: Color(hex: 0x1a4d2e))
            } else {
                pixel(x: 10, y: 12, w: 4, h: 1, color: Color(hex: 0x1a4d2e))
            }

            // Trunk with bark texture
            pixel(x: 10, y: 16, w: 4, h: 1, color: Color(hex: 0x8B5E3C))
            pixel(x: 11, y: 16, w: 1, h: 1, color: Color(hex: 0x6B3F2A))
            pixel(x: 10, y: 17, w: 4, h: 1, color: Color(hex: 0x6B3F2A))
            pixel(x: 10, y: 18, w: 4, h: 1, color: Color(hex: 0x8B5E3C))
            pixel(x: 12, y: 18, w: 1, h: 1, color: Color(hex: 0x6B3F2A))
            pixel(x: 9, y: 19, w: 6, h: 1, color: Color(hex: 0x6B3F2A))
        }
    }

    // MARK: - Ground (static, stays put)

    private var groundPixels: some View {
        ZStack(alignment: .topLeading) {
            pixel(x: 6, y: 20, w: 12, h: 1, color: Color(hex: 0x5C4033))
            pixel(x: 5, y: 21, w: 14, h: 1, color: Color(hex: 0x4a3728))
            // Roots
            pixel(x: 8, y: 20, w: 1, h: 1, color: Color(hex: 0x6B3F2A))
            pixel(x: 15, y: 20, w: 1, h: 1, color: Color(hex: 0x6B3F2A))
        }
    }

    private var sparkles: some View {
        ZStack(alignment: .topLeading) {
            pixel(x: 1, y: 4, w: 1, h: 1, color: Color(hex: 0xffd166)).opacity(showSparkles ? 1 : 0)
            pixel(x: 22, y: 3, w: 1, h: 1, color: Color(hex: 0xffd166)).opacity(showSparkles ? 1 : 0)
            pixel(x: 2, y: 1, w: 1, h: 1, color: Color(hex: 0xffd166)).opacity(showSparkles ? 0.7 : 0)
            pixel(x: 21, y: 6, w: 1, h: 1, color: Color(hex: 0xffd166)).opacity(showSparkles ? 0.7 : 0)
            pixel(x: 0, y: 8, w: 1, h: 1, color: Color(hex: 0x52b788)).opacity(showSparkles ? 1 : 0)
            pixel(x: 23, y: 1, w: 1, h: 1, color: Color(hex: 0x52b788)).opacity(showSparkles ? 1 : 0)
        }
    }

    // MARK: - Pixel helper

    private func pixel(x: Int, y: Int, w: Int, h: Int, color: Color) -> some View {
        color
            .frame(width: CGFloat(w) * pixelSize, height: CGFloat(h) * pixelSize)
            .offset(x: CGFloat(x) * pixelSize, y: CGFloat(y) * pixelSize)
    }

    // MARK: - Animations

    private func startAnimations() {
        switch mood {
        case .idle:
            startIdleAnimations()
        case .cheer:
            startCheerAnimations()
        case .windy:
            startWindyAnimations()
        }
    }

    private func startIdleAnimations() {
        Timer.scheduledTimer(withTimeInterval: 4.0, repeats: true) { _ in
            withAnimation(.easeInOut(duration: 0.08)) { isBlinking = true }
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.15) {
                withAnimation(.easeInOut(duration: 0.08)) { isBlinking = false }
            }
        }

        func scanLoop() {
            DispatchQueue.main.asyncAfter(deadline: .now() + 2.0) {
                withAnimation(.easeInOut(duration: 0.2)) { pupilOffsetX = -1 }
            }
            DispatchQueue.main.asyncAfter(deadline: .now() + 3.5) {
                withAnimation(.easeInOut(duration: 0.2)) { pupilOffsetX = 0; pupilOffsetY = 1 }
            }
            DispatchQueue.main.asyncAfter(deadline: .now() + 5.0) {
                withAnimation(.easeInOut(duration: 0.2)) { pupilOffsetY = 0 }
            }
            DispatchQueue.main.asyncAfter(deadline: .now() + 7.0) {
                scanLoop()
            }
        }
        scanLoop()
    }

    private func startCheerAnimations() {
        func bounceLoop() {
            withAnimation(.easeOut(duration: 0.2)) { bounceOffset = -pixelSize }
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.2) {
                withAnimation(.easeIn(duration: 0.2)) { bounceOffset = 0 }
            }
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.6) {
                withAnimation(.easeOut(duration: 0.15)) { bounceOffset = -pixelSize * 0.5 }
            }
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.75) {
                withAnimation(.easeIn(duration: 0.15)) { bounceOffset = 0 }
            }
            DispatchQueue.main.asyncAfter(deadline: .now() + 2.0) { bounceLoop() }
        }
        bounceLoop()

        Timer.scheduledTimer(withTimeInterval: 0.5, repeats: true) { _ in
            withAnimation(.easeInOut(duration: 0.25)) { showSparkles.toggle() }
        }
    }

    private func startWindyAnimations() {
        func swayLoop() {
            withAnimation(.easeInOut(duration: 0.3)) { swayOffset = -pixelSize * 0.5 }
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) {
                withAnimation(.easeInOut(duration: 0.3)) { swayOffset = -pixelSize * 0.7 }
            }
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.6) {
                withAnimation(.easeInOut(duration: 0.3)) { swayOffset = -pixelSize * 0.4 }
            }
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.9) {
                withAnimation(.easeInOut(duration: 0.3)) { swayOffset = -pixelSize * 0.7 }
            }
            DispatchQueue.main.asyncAfter(deadline: .now() + 1.2) { swayLoop() }
        }
        swayLoop()

        Timer.scheduledTimer(withTimeInterval: 3.0, repeats: true) { _ in
            DispatchQueue.main.asyncAfter(deadline: .now() + 1.05) {
                withAnimation(.easeInOut(duration: 0.05)) { isBlinking = true }
            }
            DispatchQueue.main.asyncAfter(deadline: .now() + 1.65) {
                withAnimation(.easeInOut(duration: 0.05)) { isBlinking = false }
            }
        }

        let needleColors: [Color] = [Color(hex: 0x52b788), Color(hex: 0x40916c), Color(hex: 0x2d6a4f)]
        Timer.scheduledTimer(withTimeInterval: 0.4, repeats: true) { _ in
            let startX = CGFloat(25)
            let startY = CGFloat.random(in: 2...16)
            let needle = LeafParticle(x: startX, y: startY, opacity: 0.8, color: needleColors.randomElement()!)
            leafParticles.append(needle)

            if let idx = leafParticles.firstIndex(where: { $0.id == needle.id }) {
                withAnimation(.easeOut(duration: 1.4)) {
                    leafParticles[idx].x -= CGFloat.random(in: 20...26)
                    leafParticles[idx].y -= CGFloat.random(in: 1...4)
                    leafParticles[idx].opacity = 0
                }
                DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
                    leafParticles.removeAll { $0.id == needle.id }
                }
            }
        }
    }
}

// MARK: - Color hex helper

extension Color {
    init(hex: UInt32) {
        self.init(
            red: Double((hex >> 16) & 0xFF) / 255,
            green: Double((hex >> 8) & 0xFF) / 255,
            blue: Double(hex & 0xFF) / 255
        )
    }
}
