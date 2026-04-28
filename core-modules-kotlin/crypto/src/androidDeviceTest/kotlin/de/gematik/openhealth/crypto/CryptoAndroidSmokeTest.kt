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

package de.gematik.openhealth.crypto

import de.gematik.openhealth.asn1.parseCvCertificate
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals

class CryptoAndroidSmokeTest {
    @Test
    fun validateCvcChain_acceptsAsn1Certificate() {
        val cert = parseCvCertificate(DEGXX820214_CVC_HEX.hexToBytes())
        val anchor = CvcTrustAnchor.fromCertificate(cert)

        val result = validateCvcChain(
            chain = listOf(cert),
            trustAnchors = listOf(anchor),
            validationTime = Instant.parse("2020-01-01T12:00:00Z"),
        )

        assertEquals(1uL, result.validatedCertificates())
        assertEquals("4445475858820214", result.endEntityChr().toHex())
    }
}

private const val DEGXX820214_CVC_HEX =
    "7f2181d87f4e81915f290170420844454758588202147f494d06082a8648ce3d0403028641048534d8887f3c7ec18b50b91f09ef3979e86a6f4fc314f3a91ddcc0d271c8c2fd66f9399d7ad8de5fc7dc09435f2130585b6e7ed4fb2f599f5aea" +
        "4b4b15a44a405f200844454758588202147f4c1306082a8214004c0481185307ffffffffffffff5f25060104000202075f24060204000202065f374052512b58338a12935a10e93a118f765b3b16a7bffd35c933d8e210197ddf8f0ca8ed276e" +
        "f1345f2fd58c97b6780a3ed8135a1461fecfa09336287f215b91f27a"

private fun String.hexToBytes(): ByteArray =
    chunked(2)
        .map { it.toInt(16).toByte() }
        .toByteArray()

private fun ByteArray.toHex(): String = joinToString(separator = "") { "%02x".format(it) }
