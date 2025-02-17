/*
 * Copyright (c) 2024 gematik GmbH
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

package de.gematik.openhealth.smartcard.model.exchange

import de.gematik.openhealth.smartcard.exchange.parsePaceInfo
import de.gematik.openhealth.smartcard.hexSpaceFormat
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals

class PaceInfoTest {
    @Test
    fun `PACE info extraction - validate protocol ID and protocol bytes with spaces`() =
        runTest {
            val cardAccessBytes =
                "31 14 30 12 06 0A 04 00 7F 00 07" +
                    "02 02 04 02 02 02 01 02 02 01 0D"
            val expectedProtocolId = "0.4.0.127.0.7.2.2.4.2.2"
            val expectedPaceInfoProtocolBytes = "04 00 7F 00 07 02 02 04 02 02"

            val paceInfo = parsePaceInfo(cardAccessBytes.hexToByteArray(hexSpaceFormat))

            assertEquals(expectedProtocolId, paceInfo.protocolId)
            assertEquals(
                expectedPaceInfoProtocolBytes,
                paceInfo.protocolIdBytes.toHexString(hexSpaceFormat),
            )
        }
}
