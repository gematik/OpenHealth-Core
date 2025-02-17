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

@file:OptIn(ExperimentalStdlibApi::class)

package de.gematik.openhealth.crypto

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

private val hexFormat =
    HexFormat {
        bytes.byteSeparator = " "
        upperCase = true
    }

class HashTest {
    @Test
    fun `hash with valid data - expected`() =
        runTestWithProvider {
            val hash = HashSpec(HashAlgorithm.Sha1).createHash()
            hash.update("Hello, World!".encodeToByteArray())
            val result = hash.digest()
            assertEquals(
                "0A 0A 9F 2A 67 72 94 25 57 AB 53 55 D7 6A F4 42 F8 F6 5E 01",
                result.toHexString(hexFormat),
            )
        }

    @Test
    fun `hash with empty data`() =
        runTestWithProvider {
            val hash = HashSpec(HashAlgorithm.Sha1).createHash()
            hash.update(ByteArray(0))
            val result = hash.digest()
            assertEquals(
                "DA 39 A3 EE 5E 6B 4B 0D 32 55 BF EF 95 60 18 90 AF D8 07 09",
                result.toHexString(hexFormat),
            )
        }

    @Test
    fun `hash with multiple updates`() =
        runTestWithProvider {
            val hash = HashSpec(HashAlgorithm.Sha1).createHash()
            hash.update("Hello, ".encodeToByteArray())
            hash.update("World!".encodeToByteArray())
            val result = hash.digest()
            assertEquals(
                "0A 0A 9F 2A 67 72 94 25 57 AB 53 55 D7 6A F4 42 F8 F6 5E 01",
                result.toHexString(hexFormat),
            )
        }

    @Test
    fun `digest can only be called once`() =
        runTestWithProvider {
            val hash = HashSpec(HashAlgorithm.Sha1).createHash()
            hash.update("Test data".encodeToByteArray())
            hash.digest()
            assertFailsWith<Throwable> {
                hash.digest()
            }
        }
}
