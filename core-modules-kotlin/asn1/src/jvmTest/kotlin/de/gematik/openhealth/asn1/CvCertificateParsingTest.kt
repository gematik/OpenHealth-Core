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

package de.gematik.openhealth.asn1

import kotlin.test.Test
import kotlin.test.assertEquals

val format = HexFormat {
    bytes {
        byteSeparator = ""
        bytesPerLine = 32
    }
}

class CvCertificateParsingTest {
    @Test
    fun parseCvCertificate_smoke() {
        val hexData =
            """
            7f2181da7f4e81935f290170420844454758581102237f494b06062b24030503
            018641045e7ae614740e7012e350de71c10021ec668f21d6859591b4f709c4c7
            3cce91c5a7fb0be1327e59ff1d0cb402b9c2bb0dc0432fa566bd4ff5f532258c
            7364aecd5f200c0009802768831100001565497f4c1306082a8214004c048118
            5307000000000000005f25060204000400025f24060209000400015f37409d24
            4d497832172304f298bd49f91f45bf346cb306adeb44b0742017a074902146cc
            cbdbb35426c2eb602d38253d92ebe1ac6905f388407398a474c4ea612d84
            """.trimIndent()
        val bytes = hexData.hexToByteArray(format)

        val cert = parseCvCertificate(bytes)
        val body = cert.body

        assertEquals(0x70.toUByte(), body.profileIdentifier)
        assertEquals("1.3.36.3.5.3.1", body.publicKey.keyOid)
        assertEquals("1.2.276.0.76.4.152", body.certificateHolderAuthorizationTemplate.terminalTypeOid)
        assertEquals(24.toUByte(), body.certificateEffectiveDate.year)
        assertEquals(4.toUByte(), body.certificateEffectiveDate.month)
        assertEquals(2.toUByte(), body.certificateEffectiveDate.day)
    }
}
