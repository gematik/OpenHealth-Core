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

package de.gematik.openhealth.crypto

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

@OptIn(ExperimentalCryptoApi::class)
class ByteUnitTest {
    @Test
    fun `create ByteUnit from bytes`() {
        val byteUnit = 8.bytes
        assertEquals(8, byteUnit.value)
    }

    @Test
    fun `create ByteUnit from valid bits`() {
        val byteUnit = 16.bits
        assertEquals(2, byteUnit.value)
    }

    @Test
    fun `create ByteUnit from invalid bits throws error`() {
        assertFailsWith<IllegalStateException>("Value must be multiple of 8") {
            3.bits
        }
    }

    @Test
    fun `convert ByteUnit to bits`() {
        val byteUnit = ByteUnit(4)
        assertEquals(32, byteUnit.bits)
    }

    @Test
    fun `convert ByteUnit to bytes`() {
        val byteUnit = ByteUnit(4)
        assertEquals(4, byteUnit.bytes)
    }

    @Test
    fun `zero is valid for both bits and bytes`() {
        assertEquals(0, 0.bytes.value)
        assertEquals(0, 0.bits.value)
    }

    @Test
    fun `large numbers are handled correctly`() {
        val largeBytes = 1024.bytes
        assertEquals(1024, largeBytes.value)
        assertEquals(8192, largeBytes.bits)

        val largeBits = 8192.bits
        assertEquals(1024, largeBits.value)
        assertEquals(8192, largeBits.bits)
    }
}
