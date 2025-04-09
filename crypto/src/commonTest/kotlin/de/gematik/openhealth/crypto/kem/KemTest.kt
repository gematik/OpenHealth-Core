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

package de.gematik.openhealth.crypto.kem

import de.gematik.openhealth.crypto.runTestWithProvider
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class KemTest {
    private val secret1 = byteArrayOf(1, 2, 3)
    private val secret2 = byteArrayOf(1, 2, 3)
    private val secret3 = byteArrayOf(4, 5, 6)
    private val wrapped1 = byteArrayOf(7, 8, 9)
    private val wrapped2 = byteArrayOf(7, 8, 9)
    private val wrapped3 = byteArrayOf(10, 11, 12)

    @Test
    fun `ml-kem-768 round trip`() =
        runTestWithProvider {
            val alice = KemSpec(KemAlgorithm.MlKem768).createDecapsulation()

            val bob = KemSpec(KemAlgorithm.MlKem768).createEncapsulation(alice.encapsulationKey())
            val bobEncapsulationResult = bob.encapsulate()

            val aliceDecapsulationResult = alice.decapsulate(bobEncapsulationResult.wrappedKey)

            assertTrue(aliceDecapsulationResult.isValid(bobEncapsulationResult))
        }

    @Test
    fun `kyber-768 round trip`() =
        runTestWithProvider {
            val alice = KemSpec(KemAlgorithm.Kyber768).createDecapsulation()

            val bob = KemSpec(KemAlgorithm.Kyber768).createEncapsulation(alice.encapsulationKey())
            val bobEncapsulationResult = bob.encapsulate()

            val aliceDecapsulationResult = alice.decapsulate(bobEncapsulationResult.wrappedKey)

            println(aliceDecapsulationResult.sharedSecret.toHexString())
            println(bobEncapsulationResult.sharedSecret.toHexString())

            assertTrue(aliceDecapsulationResult.isValid(bobEncapsulationResult))
        }

    @Test
    fun `KemEncapsulationResult equals should compare contents`() =
        runTestWithProvider {
            val result1 = KemEncapsulationResult(secret1, wrapped1)
            val result2 = KemEncapsulationResult(secret2, wrapped2)
            val result3 = KemEncapsulationResult(secret3, wrapped1)
            val result4 = KemEncapsulationResult(secret1, wrapped3)

            assertEquals(result1, result2)
            assertNotEquals(result1, result3)
            assertNotEquals(result1, result4)
        }

    @Test
    fun `KemDecapsulationResult equals should compare contents`() =
        runTestWithProvider {
            val result1 = KemDecapsulationResult(secret1)
            val result2 = KemDecapsulationResult(secret2)
            val result3 = KemDecapsulationResult(secret3)

            assertEquals(result1, result2)
            assertNotEquals(result1, result3)
        }

    @Test
    fun `KemDecapsulationResult isValid should compare shared secrets`() =
        runTestWithProvider {
            val decap = KemDecapsulationResult(secret1)
            val encap1 = KemEncapsulationResult(secret2, wrapped1)
            val encap2 = KemEncapsulationResult(secret3, wrapped1)

            assertTrue(decap.isValid(encap1))
            assertFalse(decap.isValid(encap2))
        }

    @Test
    fun `KemEncapsulationResult should handle reference equality`() =
        runTestWithProvider {
            val result = KemEncapsulationResult(secret1, wrapped1)
            val result2 = KemEncapsulationResult(secret1, wrapped1)
            assertEquals(result, result)
            assertEquals(result, result2)
        }

    @Test
    fun `KemEncapsulationResult hashCode should be consistent`() =
        runTestWithProvider {
            val result1 = KemEncapsulationResult(secret1, wrapped1)
            val result2 = KemEncapsulationResult(secret1, wrapped1)

            assertEquals(result1.hashCode(), result2.hashCode())
        }

    @Test
    fun `KemDecapsulationResult should handle reference equality`() =
        runTestWithProvider {
            val result = KemDecapsulationResult(secret1)
            assertEquals(result, result) // Same instance
        }

    @Test
    fun `KemDecapsulationResult hashCode should be consistent`() =
        runTestWithProvider {
            val result1 = KemDecapsulationResult(secret1)
            val result2 = KemDecapsulationResult(secret1)

            assertEquals(result1.hashCode(), result2.hashCode())
        }

    @Test
    fun `KemDecapsulationResult isValid should handle empty secrets`() =
        runTestWithProvider {
            val decap = KemDecapsulationResult(byteArrayOf())
            val encap = KemEncapsulationResult(secret1, wrapped1)
            assertFalse(decap.isValid(encap))

            val decap2 = KemDecapsulationResult(secret1)
            val encap2 = KemEncapsulationResult(byteArrayOf(), wrapped1)
            assertFalse(decap2.isValid(encap2))
        }
}
