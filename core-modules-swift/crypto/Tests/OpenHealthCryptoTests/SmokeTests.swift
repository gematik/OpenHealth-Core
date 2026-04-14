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

import Foundation
import OpenHealthCrypto
import XCTest

final class SmokeTests: XCTestCase {
    func testGenerateElcEphemeralPublicKey_smoke() throws {
        let cvc = try Data(contentsOf: cvcFixture(named: "DEGXX820214.cvc"))

        let publicKey = try generateElcEphemeralPublicKey(cvc: cvc)

        XCTAssertFalse(publicKey.isEmpty)
    }

    func testGenerateElcEphemeralPublicKey_rejectsInvalidInput() {
        XCTAssertThrowsError(try generateElcEphemeralPublicKey(cvc: Data()))
    }
}

private func cvcFixture(named name: String) -> URL {
    repositoryRoot()
        .appendingPathComponent("test-vectors")
        .appendingPathComponent("cvc-chain")
        .appendingPathComponent("pki_cvc_g2_input")
        .appendingPathComponent("Atos_CVC-Root-CA")
        .appendingPathComponent(name)
}

private func repositoryRoot() -> URL {
    var url = URL(fileURLWithPath: #filePath)
    for _ in 0..<5 {
        url.deleteLastPathComponent()
    }
    return url
}
