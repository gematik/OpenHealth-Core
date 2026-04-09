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
    ],
    targets: [
        .binaryTarget(
            name: "OpenHealthHealthcardFFI",
            url: "https://github.com/gematik/OpenHealth-Core/releases/download/0.2.0-alpha2/OpenHealthHealthcardFFI.xcframework.zip", checksum: "b8273ba198b2be2acb16e3f0108411435962b311b160ddadb88280582bee1e67"
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
            url: "https://github.com/gematik/OpenHealth-Core/releases/download/0.2.0-alpha2/OpenHealthAsn1FFI.xcframework.zip", checksum: "a725232b68c39e024d966b301404cf08ab9c377056274fc17e41bd6390210efb"
        ),
        .target(
            name: "OpenHealthAsn1",
            dependencies: ["OpenHealthAsn1FFI"],
            path: "core-modules-swift/asn1/Sources/OpenHealthAsn1"
        ),
    ]
)
