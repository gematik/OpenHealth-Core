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
import OpenHealthAsn1
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

    func testValidateCvcChain_acceptsAsn1Certificate() throws {
        let cvc = try Data(contentsOf: cvcFixture(named: "DEGXX820214.cvc"))
        let cert = try parseCvCertificate(data: cvc)
        let anchor = try CvcTrustAnchor.fromCertificate(certificate: cert)
        let validationTime = try XCTUnwrap(DateComponents(
            calendar: Calendar(identifier: .gregorian),
            timeZone: TimeZone(secondsFromGMT: 0),
            year: 2020,
            month: 1,
            day: 1,
            hour: 12
        ).date)

        let result = try validateCvcChain(chain: [cert], trustAnchors: [anchor], validationTime: validationTime)

        XCTAssertEqual(result.validatedCertificates(), 1)
        XCTAssertEqual(result.endEntityChr().hexEncodedString(), "4445475858820214")
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

private extension Data {
    func hexEncodedString() -> String {
        map { String(format: "%02x", $0) }.joined()
    }
}
