/*
 * Copyright (c) 2025 gematik GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.openhealth.crypto.key

import com.ionspin.kotlin.bignum.integer.BigInteger
import de.gematik.openhealth.crypto.runTestWithProvider
import kotlin.test.Test
import kotlin.test.assertEquals

@Suppress("ktlint:standard:max-line-length")
class EcPointBrainpoolP256r1Test {
    private val curve = EcCurve.BrainpoolP256r1

    @Test
    fun `test vector - rfc6932`() = runTestWithProvider {
        // test vector according to https://datatracker.ietf.org/doc/html/rfc6932

        val dA = BigInteger.parseString("041EB8B1E2BC681BCE8E39963B2E9FC415B05283313DD1A8BCC055F11AE49699",16)
        val xQa = BigInteger.parseString("78028496B5ECAAB3C8B6C12E45DB1E02C9E4D26B4113BC4F015F60C5CCC0D206",16)
        val yQa = BigInteger.parseString("A2AE1762A3831C1D20F03F8D1E3C0C39AFE6F09B4D44BBE80CD100987B05F92B",16)

        val dB = BigInteger.parseString("06F5240EACDB9837BC96D48274C8AA834B6C87BA9CC3EEDD81F99A16B8D804D3",16)
        val xQb = BigInteger.parseString("8E07E219BA588916C5B06AA30A2F464C2F2ACFC1610A3BE2FB240B635341F0DB",16)
        val yQb = BigInteger.parseString("148EA1D7D1E7E54B9555B6C9AC90629C18B63BEE5D7AA6949EBBF47B24FDE40D",16)

        val expected_xZ = BigInteger.parseString("05E940915549E9F6A4A75693716E37466ABA79B4BF2919877A16DD2CC2E23708",16)
        val expected_yZ = BigInteger.parseString("6BC23B6702BC5A019438CEEA107DAAD8B94232FFBBC350F3B137628FE6FD134C",16)

        // Party A's public key
        val qA = curve.point(xQa, yQa)

        // Party B's public key
        val qB = curve.point(xQb, yQb)

        // Compute shared secret (A's perspective)
        val sharedSecretA = qB * dA

        // Compute shared secret (B's perspective)
        val sharedSecretB = qA * dB

        // Verify
        assertEquals(expected_xZ, sharedSecretA.x)
        assertEquals(expected_yZ, sharedSecretA.y)
        assertEquals(expected_xZ, sharedSecretB.x)
        assertEquals(expected_yZ, sharedSecretB.y)
        assertEquals(sharedSecretA, sharedSecretB)
    }
}