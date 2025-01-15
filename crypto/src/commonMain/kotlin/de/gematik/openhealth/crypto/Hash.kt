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

package de.gematik.openhealth.crypto

@ExperimentalCryptoApi
class HashException(
    override val message: String,
    override val cause: Throwable? = null,
) : Throwable(message, cause)

@ExperimentalCryptoApi
enum class HashAlgorithm {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
    Shake128,
    Shake256,
}

@ExperimentalCryptoApi
interface Hash {
    val spec: HashSpec

    fun update(data: ByteArray)

    fun digest(): ByteArray
}

@ExperimentalCryptoApi
class HashSpec(
    val algorithm: HashAlgorithm,
)

@ExperimentalCryptoApi
internal expect fun HashSpec.nativeCreateHash(scope: CryptoScope): Hash