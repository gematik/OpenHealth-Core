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

package de.gematik.openhealth.crypto

import kotlin.test.Test
import kotlin.test.assertEquals

class SecureRandomTest {
    @Test
    fun `secure random - full 32 bits`() {
        val random = secureRandom()
        val values = buildSet { repeat(100) { add(random.nextBits(32)) } }
        assertEquals(100, values.size)
    }

    @Test
    fun `secure random - 28 bits`() {
        val random = secureRandom()
        val values =
            buildSet {
                repeat(100) {
                    val nextBits = random.nextBits(28)
                    add(nextBits)
                    assertEquals(0, nextBits shr 28 and 0x1111)
                }
            }
        assertEquals(100, values.size)
    }

    @Test
    fun `secure random - 27 bits`() {
        val random = secureRandom()
        val values =
            buildSet {
                repeat(100) {
                    val nextBits = random.nextBits(27)
                    add(nextBits)
                    assertEquals(0, nextBits shr 27 and 0x11111)
                }
            }
        assertEquals(100, values.size)
    }
}