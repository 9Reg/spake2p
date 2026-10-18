// swift-tools-version: 6.0
import PackageDescription

// CSpake2p.xcframework is built by ../scripts/build-xcframework.sh (it is not checked in).
let package = Package(
    name: "Spake2p",
    platforms: [.iOS(.v18), .macOS(.v14)],
    products: [
        .library(name: "Spake2p", targets: ["Spake2p"]),
        .executable(name: "spake2p-interop-driver", targets: ["spake2p-interop-driver"]),
    ],
    targets: [
        .binaryTarget(name: "CSpake2p", path: "CSpake2p.xcframework"),
        .target(name: "Spake2p", dependencies: ["CSpake2p"]),
        .executableTarget(name: "spake2p-interop-driver", dependencies: ["Spake2p"]),
        .testTarget(name: "Spake2pTests", dependencies: ["Spake2p"]),
    ]
)
