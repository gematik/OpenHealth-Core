// swift-tools-version: 5.9
// SPDX-FileCopyrightText: Copyright 2025 - 2026 gematik GmbH
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
    name: "OpenHealthHealthcard",
    platforms: [
        .iOS(.v13),
        .macOS(.v11),
    ],
    products: [
        .library(name: "OpenHealthHealthcard", targets: ["OpenHealthHealthcard"]),
        .library(name: "OpenHealthAsn1", targets: ["OpenHealthAsn1"]),
        .library(name: "OpenHealthCrypto", targets: ["OpenHealthCrypto"]),
    ],
    targets: [
        .binaryTarget(
            name: "OpenHealthHealthcardFFI",
            url: "https://github.com/gematik/OpenHealth-Core/releases/download/0.4.0-alpha1/OpenHealthHealthcardFFI.xcframework.zip", checksum: "8b64ceb582f2050233157f4e7459876f792084fcd7ad65fcea81b8adb8c076a8"
        ),
        .target(
            name: "OpenHealthHealthcard",
            dependencies: ["OpenHealthHealthcardFFI"],
            path: "core-modules-swift/healthcard/Sources/OpenHealthHealthcard"
        ),
        .testTarget(
            name: "OpenHealthHealthcardTests",
            dependencies: ["OpenHealthHealthcard"],
            path: "core-modules-swift/healthcard/Tests/OpenHealthHealthcardTests"
        ),
        .binaryTarget(
            name: "OpenHealthAsn1FFI",
            url: "https://github.com/gematik/OpenHealth-Core/releases/download/0.4.0-alpha1/OpenHealthAsn1FFI.xcframework.zip", checksum: "a1ba0c87f1a1a4927a06ddc5d1df0baf426f99f60be537aa01ddad7e03f925d7"
        ),
        .target(
            name: "OpenHealthAsn1",
            dependencies: ["OpenHealthAsn1FFI"],
            path: "core-modules-swift/asn1/Sources/OpenHealthAsn1"
        ),
        .binaryTarget(
            name: "OpenHealthCryptoFFI",
            url: "https://github.com/gematik/OpenHealth-Core/releases/download/0.4.0-alpha1/OpenHealthCryptoFFI.xcframework.zip", checksum: "9810ae70853441fca0a5e2003af5bf1f74498378b0cb1b12e8566d5d687e5d22"
        ),
        .target(
            name: "OpenHealthCrypto",
            dependencies: ["OpenHealthCryptoFFI", "OpenHealthAsn1"],
            path: "core-modules-swift/crypto/Sources/OpenHealthCrypto"
        ),
        .testTarget(
            name: "OpenHealthCryptoTests",
            dependencies: ["OpenHealthCrypto"],
            path: "core-modules-swift/crypto/Tests/OpenHealthCryptoTests"
        ),
    ]
)
