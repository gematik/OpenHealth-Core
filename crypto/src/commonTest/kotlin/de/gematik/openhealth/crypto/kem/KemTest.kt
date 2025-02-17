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

package de.gematik.openhealth.crypto.kem

import de.gematik.openhealth.crypto.runTestWithProvider
import kotlin.test.Test
import kotlin.test.assertTrue

class KemTest {
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
}
