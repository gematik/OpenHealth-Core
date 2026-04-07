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

import XCTest
import Foundation
import OpenHealthAsn1

final class SmokeTests: XCTestCase {
    func testParseCvCertificate_smoke() throws {
        let hexData = """
        7f2181da7f4e81935f290170420844454758581102237f494b06062b24030503
        018641045e7ae614740e7012e350de71c10021ec668f21d6859591b4f709c4c7
        3cce91c5a7fb0be1327e59ff1d0cb402b9c2bb0dc0432fa566bd4ff5f532258c
        7364aecd5f200c0009802768831100001565497f4c1306082a8214004c048118
        5307000000000000005f25060204000400025f24060209000400015f37409d24
        4d497832172304f298bd49f91f45bf346cb306adeb44b0742017a074902146cc
        cbdbb35426c2eb602d38253d92ebe1ac6905f388407398a474c4ea612d84
        """

        let data = try Data(hex: hexData)
        let cert = try parseCvCertificate(data: data)
        let body = cert.body()
        let effectiveDate = body.certificateEffectiveDate()

        XCTAssertEqual(body.profileIdentifier(), UInt8(0x70))
        XCTAssertEqual(body.publicKey().keyOid(), "1.3.36.3.5.3.1")
        XCTAssertEqual(body.certificateHolderAuthorizationTemplate().terminalTypeOid(), "1.2.276.0.76.4.152")
        XCTAssertEqual(effectiveDate.year(), UInt8(24))
        XCTAssertEqual(effectiveDate.month(), UInt8(4))
        XCTAssertEqual(effectiveDate.day(), UInt8(2))
    }
}

private extension Data {
    init(hex: String) throws {
        let cleaned = hex.filter { !$0.isWhitespace }
        guard cleaned.count % 2 == 0 else {
            throw NSError(domain: "OpenHealthAsn1Tests", code: 1, userInfo: [NSLocalizedDescriptionKey: "hex length must be even"])
        }

        var bytes: [UInt8] = []
        bytes.reserveCapacity(cleaned.count / 2)

        var i = cleaned.startIndex
        while i < cleaned.endIndex {
            let j = cleaned.index(i, offsetBy: 2)
            let chunk = cleaned[i..<j]
            guard let b = UInt8(chunk, radix: 16) else {
                throw NSError(domain: "OpenHealthAsn1Tests", code: 2, userInfo: [NSLocalizedDescriptionKey: "invalid hex byte: \(chunk)"])
            }
            bytes.append(b)
            i = j
        }

        self.init(bytes)
    }
}
