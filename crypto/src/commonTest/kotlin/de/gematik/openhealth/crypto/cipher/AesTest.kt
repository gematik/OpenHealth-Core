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

package de.gematik.openhealth.crypto.cipher

import de.gematik.openhealth.crypto.UnsafeCryptoApi
import de.gematik.openhealth.crypto.bytes
import de.gematik.openhealth.crypto.hexSpaceFormat
import de.gematik.openhealth.crypto.key.SecretKey
import de.gematik.openhealth.crypto.runTestWithProvider
import kotlin.test.Test
import kotlin.test.assertEquals

class AesTest {
    @OptIn(UnsafeCryptoApi::class)
    @Test
    fun `aes ecb - 128 bit encryption`() =
        runTestWithProvider {
            val cipher =
                AesEcbSpec(
                    16.bytes,
                ).createCipher(SecretKey("1234567890123456".encodeToByteArray()))
            var result = cipher.update("Hello World".encodeToByteArray())
            result += cipher.final()
            assertEquals(
                "C5 00 17 56 2E 76 83 EC 13 EF 1A 15 37 4F 2C B1",
                result.toHexString(hexSpaceFormat),
            )
        }

    @OptIn(UnsafeCryptoApi::class)
    @Test
    fun `aes ecb - 128 bit decryption`() =
        runTestWithProvider {
            val cipher =
                AesEcbSpec(
                    16.bytes,
                ).createDecipher(SecretKey("1234567890123456".encodeToByteArray()))
            var result =
                cipher.update(
                    "C5 00 17 56 2E 76 83 EC 13 EF 1A 15 37 4F 2C B1".hexToByteArray(
                        hexSpaceFormat,
                    ),
                )
            result += cipher.final()
            assertEquals("Hello World", result.decodeToString())
        }

    @OptIn(UnsafeCryptoApi::class)
    @Test
    fun `aes cbc - 128 bit encryption`() =
        runTestWithProvider {
            val cipher =
                AesCbcSpec(
                    16.bytes,
                    "1234567890123456".encodeToByteArray(),
                ).createCipher(SecretKey("1234567890123456".encodeToByteArray()))
            var result = cipher.update("Hello World".encodeToByteArray())
            result += cipher.final()
            assertEquals(
                "67 23 83 A2 43 37 DC 8A 35 64 A2 00 F2 1E E8 C0",
                result.toHexString(hexSpaceFormat),
            )
        }

    @OptIn(UnsafeCryptoApi::class)
    @Test
    fun `aes cbc - 128 bit decryption`() =
        runTestWithProvider {
            val cipher =
                AesCbcSpec(
                    16.bytes,
                    "1234567890123456".encodeToByteArray(),
                ).createDecipher(SecretKey("1234567890123456".encodeToByteArray()))
            var result =
                cipher.update(
                    "67 23 83 A2 43 37 DC 8A 35 64 A2 00 F2 1E E8 C0".hexToByteArray(
                        hexSpaceFormat,
                    ),
                )
            result += cipher.final()
            assertEquals("Hello World", result.decodeToString())
        }

    @Test
    fun `aes gcm - 128 bit encryption`() =
        runTestWithProvider {
            val cipher =
                AesGcmCipherSpec(
                    16.bytes,
                    "1234567890123456".encodeToByteArray(),
                    byteArrayOf(),
                    autoPadding = false,
                ).createCipher(
                    SecretKey("1234567890123456".encodeToByteArray()),
                )
            var result = cipher.update("Hello World".encodeToByteArray())
            result += cipher.final()
            assertEquals("CE C1 89 D0 E8 4D EC A8 E6 08 DD", result.toHexString(hexSpaceFormat))
            assertEquals(
                "0F 98 50 42 1A DA DC FF 64 5F 7E 79 79 E2 E6 8A",
                cipher.authTag().toHexString(hexSpaceFormat),
            )
        }

    @Test
    fun `aes gcm - 128 bit decryption`() =
        runTestWithProvider {
            val cipher =
                AesGcmDecipherSpec(
                    16.bytes,
                    "1234567890123456".encodeToByteArray(),
                    byteArrayOf(),
                    "0F 98 50 42 1A DA DC FF 64 5F 7E 79 79 E2 E6 8A".hexToByteArray(
                        hexSpaceFormat,
                    ),
                    autoPadding = false,
                ).createDecipher(
                    SecretKey("1234567890123456".encodeToByteArray()),
                )
            var result =
                cipher.update(
                    "CE C1 89 D0 E8 4D EC A8 E6 08 DD".hexToByteArray(hexSpaceFormat),
                )
            result += cipher.final()
            assertEquals("Hello World", result.decodeToString())
        }
}
