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

package de.gematik.openhealth.crypto.key

import de.gematik.openhealth.crypto.runTestWithProvider
import kotlinx.coroutines.test.runTest
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals

class EcKeyTest {
    @Test
    fun `create ec key pair`() =
        runTestWithProvider {
            val (publicKeyResult, privateKeyResult) =
                EcKeyPairSpec(
                    EcCurve.BrainpoolP256r1,
                ).generateKeyPair()
            assertEquals(EcCurve.BrainpoolP256r1, publicKeyResult.curve)
            assertEquals(EcCurve.BrainpoolP256r1, privateKeyResult.curve)
        }

    @Test
    fun `encode and decode ec public key from pem`() = runTestWithProvider {
        val ecPublicKey =
            EcPublicKey.decodeFromUncompressedFormat(
                EcCurve.BrainpoolP256r1,
                byteArrayOf(0x04) + Random.nextBytes(32) + Random.nextBytes(32),
            )
        val ecPublicKeyResult = EcPublicKey.decodeFromAsn1(ecPublicKey.encodeToAsn1())

        assertEquals(ecPublicKey, ecPublicKeyResult)
    }

    @Test
    fun `encode and decode ec private key from pem`() = runTestWithProvider {
        val ecPrivateKey = EcPrivateKey.fromScalar(EcCurve.BrainpoolP256r1, Random.nextBytes(32))
        val ecPrivateKeyResult = EcPrivateKey.decodeFromAsn1(ecPrivateKey.encodeToAsn1())

        assertEquals(ecPrivateKey, ecPrivateKeyResult)
    }
}