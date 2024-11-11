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
import de.gematik.openhealth.crypto.ExperimentalCryptoApi
import de.gematik.openhealth.crypto.contentConstantTimeEquals

/**
 * Supported Key Encapsulation Mechanism algorithms.
 */
enum class KemAlgorithm {
    MlKem768,
    Kyber768,
}

/**
 * Result of a KEM encapsulation operation containing the shared secret and wrapped key.
 */
@ExperimentalCryptoApi
data class KemEncapsulationResult(
    val sharedSecret: ByteArray,
    val wrappedKey: ByteArray,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as KemEncapsulationResult

        if (!sharedSecret.contentConstantTimeEquals(other.sharedSecret)) return false
        if (!wrappedKey.contentConstantTimeEquals(other.wrappedKey)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = sharedSecret.contentHashCode()
        result = 31 * result + wrappedKey.contentHashCode()
        return result
    }
}

/**
 * Result of a KEM decapsulation operation containing the shared secret.
 */
@ExperimentalCryptoApi
data class KemDecapsulationResult(
    val sharedSecret: ByteArray,
) {
    /**
     * Returns `true` if both secrets are equal.
     */
    fun isValid(encapsulation: KemEncapsulationResult): Boolean =
        sharedSecret.isNotEmpty() &&
            encapsulation.sharedSecret.isNotEmpty() &&
            sharedSecret.contentConstantTimeEquals(encapsulation.sharedSecret)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as KemDecapsulationResult

        return sharedSecret.contentConstantTimeEquals(other.sharedSecret)
    }

    override fun hashCode(): Int = sharedSecret.contentHashCode()
}

/**
 * Interface for KEM encapsulation operations.
 */
@ExperimentalCryptoApi
interface KemEncapsulation {
    val spec: KemSpec

    fun encapsulate(): KemEncapsulationResult
}

/**
 * Interface for KEM decapsulation operations.
 */
@ExperimentalCryptoApi
interface KemDecapsulation {
    val spec: KemSpec

    fun encapsulationKey(): ByteArray

    fun decapsulate(wrappedKey: ByteArray): KemDecapsulationResult
}

/**
 * Specification for KEM operations.
 */
@ExperimentalCryptoApi
class KemSpec(
    val algorithm: KemAlgorithm,
)

/**
 * Creates a native KEM encapsulation instance.
 */
internal expect fun KemSpec.nativeCreateEncapsulation(
    scope: CryptoScope,
    encapsulationKey: ByteArray,
): KemEncapsulation

/**
 * Creates a native KEM decapsulation instance.
 */
internal expect fun KemSpec.nativeCreateDecapsulation(scope: CryptoScope): KemDecapsulation
