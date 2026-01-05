// swift-tools-version: 5.9
// SPDX-FileCopyrightText: Copyright 2025 gematik GmbH
//
// SPDX-License-Identifier: Apache-2.0
//
// *******
//
// For additional notes and disclaimer from gematik and in case of changes by gematik,
// find details in the "Readme" file.

import PackageDescription

let package = Package(
    name: "OpenHealthHealthcard",
    platforms: [
        .iOS(.v13),
        .macOS(.v11),
    ],
    products: [
        .library(name: "OpenHealthHealthcard", targets: ["OpenHealthHealthcard"]),
    ],
    targets: [
        .binaryTarget(
            name: "OpenHealthHealthcardFFI",
            path: "./OpenHealthHealthcardFFI.xcframework"
        ),
        .target(
            name: "OpenHealthHealthcard",
            dependencies: ["OpenHealthHealthcardFFI"],
            path: "Sources/OpenHealthHealthcard"
        ),
    ]
)
