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
            url: "https://github.com/gematik/OpenHealth-Core/releases/download/0.0.1-alpha1/OpenHealthHealthcardFFI.xcframework.zip", checksum: "1755d33b9ba5a70b432e2ce3c7d855df8cf7dd600af3632d2f1f06e57b893fa2"
        ),
        .target(
            name: "OpenHealthHealthcard",
            dependencies: ["OpenHealthHealthcardFFI"],
            path: "Sources/OpenHealthHealthcard"
        ),
    ]
)
