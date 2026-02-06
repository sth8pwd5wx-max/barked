import SwiftUI

@MainActor
class MascotState: ObservableObject {
    @Published var mood: MascotMood = .idle

    func startActivity() { mood = .windy }
    func succeed() { mood = .cheer }
    func reset() { mood = .idle }
}
