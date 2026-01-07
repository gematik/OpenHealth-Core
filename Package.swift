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
    ],
    targets: [
        .binaryTarget(
            name: "OpenHealthHealthcardFFI",
            url: "https://github.com/gematik/OpenHealth-Core/releases/download/0.0.1-alpha2/OpenHealthHealthcardFFI.xcframework.zip", checksum: "5a42470de0c11f0ca2fb29b03d4d93903e727621d702cdbfe5f49b02c1e7291b"
        ),
        .target(
            name: "OpenHealthHealthcard",
            dependencies: ["OpenHealthHealthcardFFI"],
            path: "core-modules-swift/healthcard/Sources/OpenHealthHealthcard"
        ),
    ]
)
