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

/**
 * Exception thrown when an error occurs during hash operations.
 */
@ExperimentalCryptoApi
class HashException(
    override val message: String,
    override val cause: Throwable? = null,
) : Throwable(message, cause)

/**
 * Supported hash algorithms.
 */
@ExperimentalCryptoApi
enum class HashAlgorithm {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
    Shake128,
    Shake256,
}

/**
 * Interface for cryptographic hash functions.
 */
@ExperimentalCryptoApi
interface Hash {
    val spec: HashSpec

    /**
     * Updates the hash computation with the given data.
     */
    fun update(data: ByteArray)

    /**
     * Completes the hash computation and returns the hash value.
     */
    fun digest(): ByteArray
}

/**
 * Specification for creating a hash function instance.
 */
@ExperimentalCryptoApi
class HashSpec(
    val algorithm: HashAlgorithm,
)

/**
 * Creates a native hash function instance based on the given specification.
 */
@ExperimentalCryptoApi
internal expect fun HashSpec.nativeCreateHash(scope: CryptoScope): Hash
