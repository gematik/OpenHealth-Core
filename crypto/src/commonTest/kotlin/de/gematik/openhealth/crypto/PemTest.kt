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

import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertTrue

class PemTest {
    @Test
    fun `encode and decode PEM with short data`() {
        val type = "TEST CERTIFICATE"
        val data = "Hello World".encodeToByteArray()
        val pem = Pem(type, data)

        val encoded = pem.encodeToString()
        val decoded = encoded.decodeToPem()

        assertEquals(type, decoded.type)
        assertContentEquals(data, decoded.data)
    }

    @Test
    fun `encode and decode PEM with long data`() {
        val type = "LONG CERTIFICATE"
        val data = ByteArray(100) { it.toByte() }
        val pem = Pem(type, data)

        val encoded = pem.encodeToString()
        val decoded = encoded.decodeToPem()

        assertEquals(type, decoded.type)
        assertContentEquals(data, decoded.data)
        assertTrue(encoded.contains("\n"))
    }

    @Test
    fun `encode PEM respects line length limit`() {
        val type = "TEST"
        val data = ByteArray(100) { 65 } // 'A' bytes
        val pem = Pem(type, data)

        val encoded = pem.encodeToString()
        val lines = encoded.lines()

        lines.filter { it.isNotEmpty() && !it.startsWith("-----") }.forEach {
            assertTrue(it.length <= 64, "Line exceeds 64 characters: $it")
        }
    }

    @Test
    fun `decode invalid PEM format throws error`() {
        val invalidPem = "Not a PEM format"

        assertFails("Invalid PEM format") {
            invalidPem.decodeToPem()
        }
    }

    @Test
    fun `decode PEM with mismatched types throws error`() {
        val invalidPem =
            """
            -----BEGIN CERT-----
            SGVsbG8gV29ybGQ=
            -----END DIFFERENT-----
            """.trimIndent()

        assertFails("Invalid PEM type format") {
            invalidPem.decodeToPem()
        }
    }

    @OptIn(ExperimentalEncodingApi::class)
    @Test
    fun `decode PEM with whitespace and newlines`() {
        val type = "CERTIFICATE"
        val content = "Hello World"
        val pemString =
            """
            -----BEGIN $type-----
            ${Base64.encode(content.encodeToByteArray())}
            -----END $type-----
            
            """.trimIndent()

        val decoded = pemString.decodeToPem()
        assertEquals(type, decoded.type)
        assertEquals(content, decoded.data.decodeToString())
    }
}
