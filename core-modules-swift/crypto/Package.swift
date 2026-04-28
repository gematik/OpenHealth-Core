// swift-tools-version: 5.9
// SPDX-FileCopyrightText: Copyright 2026 gematik GmbH
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// *******
//
// For additional notes and disclaimer from gematik and in case of changes by gematik,
// find details in the "Readme" file.

import PackageDescription

let package = Package(
    name: "OpenHealthCrypto",
    platforms: [
        .iOS(.v13),
        .macOS(.v11),
    ],
    products: [
        .library(name: "OpenHealthCrypto", targets: ["OpenHealthCrypto"]),
    ],
    dependencies: [
        .package(path: "../asn1"),
    ],
    targets: [
        .binaryTarget(
            name: "OpenHealthCryptoFFI",
            path: "OpenHealthCryptoFFI.xcframework"
        ),
        .target(
            name: "OpenHealthCrypto",
            dependencies: [
                "OpenHealthCryptoFFI",
                .product(name: "OpenHealthAsn1", package: "asn1"),
            ],
            path: "Sources/OpenHealthCrypto"
        ),
        .testTarget(
            name: "OpenHealthCryptoTests",
            dependencies: ["OpenHealthCrypto"],
            path: "Tests/OpenHealthCryptoTests"
        ),
    ]
)
