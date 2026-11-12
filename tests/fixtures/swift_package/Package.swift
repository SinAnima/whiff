// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "HarbourTides",
    platforms: [.macOS(.v13), .iOS(.v16)],
    products: [
        .library(name: "HarbourTides", targets: ["HarbourTides"]),
        .executable(name: "tides", targets: ["TidesCLI"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser", from: "1.5.0"),
        .package(path: "../HarbourModel"),
    ],
    targets: [
        .target(name: "HarbourTides"),
        .executableTarget(name: "TidesCLI", dependencies: ["HarbourTides"]),
        .testTarget(name: "HarbourTidesTests", dependencies: ["HarbourTides"]),
    ]
)
