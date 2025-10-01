// swift-tools-version: 6.2
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "EnclaveLocker",
    platforms: [
        .macOS(.v12),
        .iOS(.v15)
    ],
    products: [
        .library(
            name: "EnclaveLocker",
            targets: ["EnclaveLocker"]
        ),
    ],
    dependencies: [
        .package(
            url: "https://github.com/kishikawakatsumi/KeychainAccess.git", from: "4.2.2"
        )
    ],
    targets: [
        .target(
            name: "EnclaveLocker",
            dependencies: ["KeychainAccess"]
        ),
        .testTarget(
            name: "EnclaveLockerTests",
            dependencies: ["EnclaveLocker"]
        )
    ]
)
