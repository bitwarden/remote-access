// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "ApUniffiExample",
    platforms: [.macOS(.v13)],
    targets: [
        .systemLibrary(
            name: "CApUniffi",
            path: "Sources/CApUniffi"
        ),
        .target(
            name: "ApUniffi",
            dependencies: ["CApUniffi"],
            path: "Sources/ApUniffi",
            linkerSettings: [
                .unsafeFlags(["-L", "../../target/debug"]),
                .linkedLibrary("ap_uniffi"),
            ]
        ),
        .executableTarget(
            name: "ApUniffiExample",
            dependencies: ["ApUniffi"],
            path: "Sources/ApUniffiExample"
        ),
    ]
)
