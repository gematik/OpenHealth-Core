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
            url: "https://github.com/gematik/OpenHealth-Core/releases/download/0.3.0-alpha1/OpenHealthHealthcardFFI.xcframework.zip", checksum: "67eae49117ae717a937c6dc4f659956c61e9e3cab7b6d78214820bf473597caa"
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
            url: "https://github.com/gematik/OpenHealth-Core/releases/download/0.3.0-alpha1/OpenHealthAsn1FFI.xcframework.zip", checksum: "7a80e457cc8608c6b5c18111e7e51be101f61f3acdf1d4580ab352a8e62d886d"
        ),
        .target(
            name: "OpenHealthAsn1",
            dependencies: ["OpenHealthAsn1FFI"],
            path: "core-modules-swift/asn1/Sources/OpenHealthAsn1"
        ),
    ]
)
