// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "Barked",
    platforms: [.macOS(.v13)],
    targets: [
        .executableTarget(
            name: "Barked",
            path: "Sources/Barked",
            exclude: ["Info.plist"]
        )
    ]
)
