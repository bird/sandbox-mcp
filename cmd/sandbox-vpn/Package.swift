// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "sandbox-vpn",
    platforms: [
        .macOS(.v15)
    ],
    products: [
        .executable(name: "sandbox-vpn", targets: ["SandboxVPN"])
    ],
    dependencies: [],
    targets: [
        .executableTarget(
            name: "SandboxVPN",
            linkerSettings: [
                .linkedFramework("Virtualization")
            ]
        )
    ]
)
