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
            url: "https://github.com/gematik/OpenHealth-Core/releases/download/0.1.1-alpha1/OpenHealthHealthcardFFI.xcframework.zip", checksum: "d3546e252bd211b1ee7a3ae28b519c2b70e22e5a554cf074adf9939a34822a9b"
        ),
        .target(
            name: "OpenHealthHealthcard",
            dependencies: ["OpenHealthHealthcardFFI"],
            path: "core-modules-swift/healthcard/Sources/OpenHealthHealthcard"
        ),
    ]
)
