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

package de.gematik.openhealth.smartcard.command

import de.gematik.openhealth.crypto.secureRandom
import de.gematik.openhealth.smartcard.runTestWithProvider
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ApduTest {
    @Test
    fun `test apdu command creation`() =
        runTestWithProvider {
            val lengths = listOf(null, 42, 0x81, 255, 256, 4242, 0x8181, 65535, 65536)
            lengths.forEach { nc ->
                // Data length must be less than 65536 if data is provided.
                if (nc == 65536) return@forEach
                lengths.forEach { ne ->
                    testApdu(nc, ne)
                }
            }
        }

    private fun testApdu(
        nc: Int?,
        ne: Int?,
    ) {
        val random = secureRandom()

        val data =
            nc?.let {
                ByteArray(nc).apply { random.nextBytes(this) }
            }

        val apdu = CardCommandApdu.ofOptions(0, 0, 0, 0, data, ne)
        assertEquals(nc ?: 0, apdu.dataLength)
        assertTrue(data.contentEquals(apdu.data))
        assertEquals(ne, apdu.ne)

        val apduBytes = apdu.apdu
        val apdu2 = CardCommandApdu.ofApdu(apduBytes)
        assertTrue(apduBytes.contentEquals(apdu2.apdu))
        assertEquals(nc ?: 0, apdu2.dataLength)
        assertEquals(data?.toHexString(), apdu2.data?.toHexString())
        assertEquals(ne, apdu2.ne)
    }
}
