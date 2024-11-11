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

package de.gematik.openhealth.crypto.key

import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.Sign
import de.gematik.openhealth.crypto.runTestWithProvider
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals

class EcKeyTest {
    @Test
    fun `create ec key pair with different curves`() =
        runTestWithProvider {
            EcCurve.entries.forEach { curve ->
                val (publicKey, privateKey) = EcKeyPairSpec(curve).generateKeyPair()
                assertEquals(curve, publicKey.curve)
                assertEquals(curve, privateKey.curve)

                val pointSize =
                    when (curve) {
                        EcCurve.BrainpoolP256r1 -> 32
                        EcCurve.BrainpoolP384r1 -> 48
                        EcCurve.BrainpoolP512r1 -> 64
                    }
                val expectedSize = 1 + (2 * pointSize)

                assertEquals(
                    expectedSize,
                    publicKey.data.size,
                    "Invalid point size for curve $curve",
                )
                assertEquals(0x04, publicKey.data[0].toInt() and 0xFF)
            }
        }

    @Test
    fun `encode and decode ec public key from pem for each curve`() =
        runTestWithProvider {
            EcCurve.entries.forEach { curve ->
                val pointSize =
                    when (curve) {
                        EcCurve.BrainpoolP256r1 -> 32
                        EcCurve.BrainpoolP384r1 -> 48
                        EcCurve.BrainpoolP512r1 -> 64
                    }

                val ecPublicKey =
                    EcPublicKey.decodeFromUncompressedFormat(
                        curve,
                        byteArrayOf(0x04) + Random.nextBytes(pointSize) +
                            Random.nextBytes(pointSize),
                    )
                val ecPublicKeyResult = EcPublicKey.decodeFromAsn1(ecPublicKey.encodeToAsn1())

                assertEquals(ecPublicKey, ecPublicKeyResult)
            }
        }

    @Test
    fun `encode and decode ec private key from pem for each curve`() =
        runTestWithProvider {
            EcCurve.entries.forEach { curve ->
                val keySize =
                    when (curve) {
                        EcCurve.BrainpoolP256r1 -> 32
                        EcCurve.BrainpoolP384r1 -> 48
                        EcCurve.BrainpoolP512r1 -> 64
                    }

                val ecPrivateKey =
                    EcPrivateKey.fromScalar(
                        curve,
                        Random.nextBytes(keySize),
                    )
                val ecPrivateKeyResult = EcPrivateKey.decodeFromAsn1(ecPrivateKey.encodeToAsn1())

                assertEquals(ecPrivateKey, ecPrivateKeyResult)
            }
        }

    @Test
    fun `test public key PEM encoding and decoding`() {
        runTestWithProvider {
            EcCurve.entries.forEach { curve ->
                val keyPairSpec = EcKeyPairSpec(curve)
                val (publicKey, _) = keyPairSpec.generateKeyPair()

                val pem = publicKey.encodeToPem()
                val decoded = EcPublicKey.decodeFromPem(pem)

                assertEquals(publicKey, decoded)
            }
        }
    }

    @Test
    fun `test private key PEM encoding and decoding`() {
        runTestWithProvider {
            EcCurve.entries.forEach { curve ->
                val keyPairSpec = EcKeyPairSpec(curve)
                val (_, privateKey) = keyPairSpec.generateKeyPair()

                val pem = privateKey.encodeToPem()
                val decoded = EcPrivateKey.decodeFromPem(pem)

                assertEquals(privateKey, decoded)
            }
        }
    }

    @Test
    fun `test public key equality`() {
        runTestWithProvider {
            EcCurve.entries.forEach { curve ->
                val keyPairSpec = EcKeyPairSpec(curve)
                val (publicKey1, _) = keyPairSpec.generateKeyPair()
                val (publicKey2, _) = keyPairSpec.generateKeyPair()

                assertNotEquals(publicKey1, publicKey2)
                assertEquals(publicKey1, publicKey1)
            }
        }
    }

    @Test
    fun `test private key equality`() {
        runTestWithProvider {
            EcCurve.entries.forEach { curve ->
                val keyPairSpec = EcKeyPairSpec(curve)
                val (_, privateKey1) = keyPairSpec.generateKeyPair()
                val (_, privateKey2) = keyPairSpec.generateKeyPair()

                assertNotEquals(privateKey1, privateKey2)
                assertEquals(privateKey1, privateKey1)
            }
        }
    }

    @Test
    fun `test invalid public key length`() {
        runTestWithProvider {
            EcCurve.entries.forEach { curve ->
                val invalidData = ByteArray(64) { 0x04 }
                assertFailsWith<IllegalArgumentException> {
                    EcPublicKey(curve, invalidData)
                }
            }
        }
    }

    @Test
    fun `test invalid private key version`() {
        runTestWithProvider {
            val invalidData = ByteArray(32) { 0x01 }
            assertFailsWith<IllegalArgumentException> {
                EcPrivateKey.decodeFromAsn1(invalidData)
            }
        }
    }

    @Test
    fun `test public key to ec point`() {
        runTestWithProvider {
            EcCurve.entries.forEach { curve ->
                val keyPairSpec = EcKeyPairSpec(curve)
                val (publicKey, _) = keyPairSpec.generateKeyPair()

                val ecPoint = publicKey.toEcPoint()
                val pointSize =
                    when (curve) {
                        EcCurve.BrainpoolP256r1 -> 32
                        EcCurve.BrainpoolP384r1 -> 48
                        EcCurve.BrainpoolP512r1 -> 64
                    }

                assertEquals(curve, ecPoint.curve)
                assertEquals(
                    BigInteger.fromByteArray(
                        publicKey.data.sliceArray(1..pointSize),
                        Sign.POSITIVE,
                    ),
                    ecPoint.x,
                )
                assertEquals(
                    BigInteger.fromByteArray(
                        publicKey.data.sliceArray(pointSize + 1..2 * pointSize),
                        Sign.POSITIVE,
                    ),
                    ecPoint.y,
                )
            }
        }
    }
}
