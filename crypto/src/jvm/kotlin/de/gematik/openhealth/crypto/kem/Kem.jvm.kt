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

import de.gematik.openhealth.crypto.CryptoScope
import de.gematik.openhealth.crypto.internal.interop.HashGenerator
import de.gematik.openhealth.crypto.internal.interop.MlkemDecapsulation
import de.gematik.openhealth.crypto.internal.interop.MlkemEncapsulation
import de.gematik.openhealth.crypto.internal.interop.Uint8Vector
import de.gematik.openhealth.crypto.wrapper.DeferScope
import de.gematik.openhealth.crypto.wrapper.deferScoped
import de.gematik.openhealth.crypto.wrapper.deferred
import de.gematik.openhealth.crypto.wrapper.lazyDeferred
import de.gematik.openhealth.crypto.wrapper.runWithProvider
import de.gematik.openhealth.crypto.wrapper.toUint8Vector

private fun KemAlgorithm.algorithmName() =
    when (this) {
        KemAlgorithm.MlKem768 -> "ML-KEM-768"
        KemAlgorithm.Kyber768 -> "ML-KEM-768"
    }

private fun KemAlgorithm.isKyber() =
    when (this) {
        KemAlgorithm.Kyber768 -> true
        else -> false
    }

private class JvmKemEncapsulation(
    override val spec: KemSpec,
    private val encapsulationKey: ByteArray,
    scope: CryptoScope,
) : KemEncapsulation,
    DeferScope by deferred(scope) {
    private val kem by lazyDeferred {
        deferScoped(true) {
            MlkemEncapsulation.create(
                spec.algorithm.algorithmName(),
                encapsulationKey.toUint8Vector().alsoDefer(),
            )
        }
    }

    override fun encapsulate(): KemEncapsulationResult =
        runWithProvider {
            deferScoped {
                val data = kem.encapsulate().alsoDefer()

                var sharedSecret = data.sharedSecret
                if (spec.algorithm.isKyber()) {
                    sharedSecret =
                        kyberSharedSecret(
                            encapsulationKey.toUint8Vector().alsoDefer(),
                            sharedSecret,
                        )
                }

                KemEncapsulationResult(
                    sharedSecret = sharedSecret.toByteArray(),
                    wrappedKey = data.wrappedKey.toByteArray(),
                )
            }
        }
}

private class JvmKemDecapsulation(
    override val spec: KemSpec,
    scope: CryptoScope,
) : KemDecapsulation,
    DeferScope by deferred(scope) {
    private val kem by lazyDeferred {
        MlkemDecapsulation.create(spec.algorithm.algorithmName())
    }

    override fun encapsulationKey(): ByteArray =
        runWithProvider {
            deferScoped {
                val key = kem.getEncapsulationKey().alsoDefer()
                key.toByteArray()
            }
        }

    override fun decapsulate(wrappedKey: ByteArray): KemDecapsulationResult =
        runWithProvider {
            deferScoped {
                val key = wrappedKey.toUint8Vector().alsoDefer()
                var sharedSecret = kem.decapsulate(key).alsoDefer()

                if (spec.algorithm.isKyber()) {
                    sharedSecret =
                        kyberSharedSecret(kem.getEncapsulationKey().alsoDefer(), sharedSecret)
                }

                KemDecapsulationResult(
                    sharedSecret = sharedSecret.toByteArray(),
                )
            }
        }
}

private fun DeferScope.kyberSharedSecret(
    encapsulationKey: Uint8Vector,
    sharedSecret: Uint8Vector,
) = runWithProvider {
    // Compute SHAKE-256(K || SHA3-256(c), 32) to match the shared secret of Kyber.
    // See https://words.filippo.io/mlkem768/#bonus-track-using-a-ml-kem-implementation-as-kyber-v3.

    val sha3 = HashGenerator.create("SHA3-256")
    sha3.update(encapsulationKey)
    val shaCiphertext = sha3._final().alsoDefer()

    val shake = HashGenerator.create("SHAKE256")
    shake.setFinalOutputLength(32)
    shake.update(sharedSecret)
    shake.update(shaCiphertext)
    shake._final().alsoDefer()
}

/**
 * JVM-specific implementation for creating KEM encapsulation instances.
 */
actual fun KemSpec.nativeCreateEncapsulation(
    scope: CryptoScope,
    encapsulationKey: ByteArray,
): KemEncapsulation = JvmKemEncapsulation(this, encapsulationKey, scope)

/**
 * JVM-specific implementation for creating KEM decapsulation instances.
 */
actual fun KemSpec.nativeCreateDecapsulation(scope: CryptoScope): KemDecapsulation =
    JvmKemDecapsulation(this, scope)
