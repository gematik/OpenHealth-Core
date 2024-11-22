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

@file:OptIn(ExperimentalStdlibApi::class)

package de.gematik.kmp.crypto

import de.gematik.kmp.crypto.key.SecretKey
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

private val hexFormat =
    HexFormat {
        bytes.byteSeparator = " "
        upperCase = true
    }

class CmacTest {
    private val secret = SecretKey("67 AD A7 BE 54 75 0C 47 44 D0 E3 46 66 33 64 05".hexToByteArray(hexFormat))

    @Test
    fun `cmac with valid data - expected`() =
        runTest {
            val cmac = CmacSpec(CmacAlgorithm.Aes).createCmac(secret)
            cmac.update("Hello, World!".encodeToByteArray())
            val result = cmac.final()
            assertEquals(
                "6B 77 96 A8 0D E9 BB C2 0A B3 E9 95 96 DF EF 43",
                result.toHexString(hexFormat),
            )
        }

    @Test
    fun `cmac with empty data`() =
        runTest {
            val cmac = CmacSpec(CmacAlgorithm.Aes).createCmac(secret)
            cmac.update(ByteArray(0))
            val result = cmac.final()
            assertEquals(
                "4F 26 7F 72 08 20 4D 86 B1 AB A8 5A 4C 40 51 E5",
                result.toHexString(hexFormat),
            )
        }

    @Test
    fun `cmac with multiple updates`() =
        runTest {
            val cmac = CmacSpec(CmacAlgorithm.Aes).createCmac(secret)
            cmac.update("Hello, ".encodeToByteArray())
            cmac.update("World!".encodeToByteArray())
            val result = cmac.final()
            assertEquals(
                "6B 77 96 A8 0D E9 BB C2 0A B3 E9 95 96 DF EF 43",
                result.toHexString(hexFormat),
            )
        }

    @Test
    fun `cmac final can only be called once`() =
        runTest {
            val cmac = CmacSpec(CmacAlgorithm.Aes).createCmac(secret)
            cmac.update("Test data".encodeToByteArray())
            cmac.final()
            assertFailsWith<CmacException> {
                cmac.final()
            }
        }
}