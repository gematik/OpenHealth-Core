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

import de.gematik.openhealth.crypto.CryptoScope
import de.gematik.openhealth.crypto.ExperimentalCryptoApi
import de.gematik.openhealth.crypto.contentConstantTimeEquals

enum class KemAlgorithm {
    MlKem768,
    Kyber768,
}

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

@ExperimentalCryptoApi
interface KemEncapsulation {
    val spec: KemSpec

    fun encapsulate(): KemEncapsulationResult
}

@ExperimentalCryptoApi
interface KemDecapsulation {
    val spec: KemSpec

    fun encapsulationKey(): ByteArray

    fun decapsulate(wrappedKey: ByteArray): KemDecapsulationResult
}

@ExperimentalCryptoApi
class KemSpec(
    val algorithm: KemAlgorithm,
)

internal expect fun KemSpec.nativeCreateEncapsulation(
    scope: CryptoScope,
    encapsulationKey: ByteArray,
): KemEncapsulation

internal expect fun KemSpec.nativeCreateDecapsulation(scope: CryptoScope): KemDecapsulation