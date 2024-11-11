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

import de.gematik.openhealth.crypto.key.SecretKey

/**
* Exception thrown when an error occurs during CMAC operations.
*/
@ExperimentalCryptoApi
class CmacException(
    override val message: String,
    override val cause: Throwable? = null,
) : Throwable(message, cause)

/**
* Enum representing the supported CMAC algorithms.
*/
@ExperimentalCryptoApi
enum class CmacAlgorithm {
    Aes,
}

/**
 * Interface representing a CMAC (Cipher-based Message Authentication Code) instance.
 */
@ExperimentalCryptoApi
interface Cmac {
    val spec: CmacSpec

    /**
     * Updates the CMAC with the given data.
     */
    fun update(data: ByteArray)

    /**
     * Finalizes the CMAC computation and returns the resulting MAC.
     */
    fun final(): ByteArray
}

/**
 * Specification for creating a CMAC instance.
 */
@ExperimentalCryptoApi
class CmacSpec(
    val algorithm: CmacAlgorithm,
)

/**
 * Creates a native CMAC instance based on the given specification and secret key.
 */
internal expect fun CmacSpec.nativeCreateCmac(
    scope: CryptoScope,
    secret: SecretKey,
): Cmac
