/*
 * Copyright 2025 gematik GmbH
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

package de.gematik.openhealth.smartcard.card

import de.gematik.openhealth.crypto.ExperimentalCryptoApi
import de.gematik.openhealth.crypto.key.EcCurve
import de.gematik.openhealth.crypto.key.toEcPublicKey
import de.gematik.openhealth.smartcard.card.Mode
import de.gematik.openhealth.smartcard.card.getAES128Key
import de.gematik.openhealth.smartcard.exchange.createAsn1AuthToken
import de.gematik.openhealth.smartcard.hexUppercaseFormat
import de.gematik.openhealth.smartcard.runTestWithProvider
import kotlin.test.Test
import kotlin.test.assertEquals

class PaceKeyTest {
    private val secretK =
        "2ECA74E72CD6C1E0DA235093569984987C34A9F4D34E4E60FB0AD87B983CDC62"
            .hexToByteArray()

    @Test
    fun shouldReturnValidAES128KeyModeEnc() =
        runTestWithProvider {
            val aes128Key = getAES128Key(secretK, Mode.ENC)
            assertEquals(
                "AB5541629D18E5F33EE2B13DBDCDBE84",
                aes128Key.toHexString(hexUppercaseFormat),
            )
        }

    @Test
    fun shouldReturnValidAES128KeyModeMac() =
        runTestWithProvider {
            val aes128Key = getAES128Key(secretK, Mode.MAC)
            assertEquals(
                "E13D3757C7D9073794A3D7CA94B22D30",
                aes128Key.toHexString(hexUppercaseFormat),
            )
        }

    @Test
    fun shouldReturnValidAES128KeyModePassword() =
        runTestWithProvider {
            val aes128Key = getAES128Key(secretK, Mode.PASSWORD)
            assertEquals(
                "74C1F5E712B53BAAA3B02B182E0961B9",
                aes128Key.toHexString(hexUppercaseFormat),
            )
        }

    @OptIn(ExperimentalCryptoApi::class)
    @Test
    fun `create asn1 auth token`() =
        runTestWithProvider {
            val point =
                EcCurve.BrainpoolP256r1.point(
                    EcCurve.BrainpoolP256r1.x,
                    EcCurve.BrainpoolP256r1.y,
                )
            val asn1AuthToken =
                createAsn1AuthToken(
                    point.toEcPublicKey(),
                    "1.2.3.4.5",
                ).toHexString(hexUppercaseFormat)
            assertEquals(
                "7F494906042A0304058641048BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE" +
                    "27E1E3BD23C23A4453BD9ACE3262547EF835C3DAC4FD97F8461A14611DC9C" +
                    "27745132DED8E545C1D54C72F046997",
                asn1AuthToken,
            )
        }
}
