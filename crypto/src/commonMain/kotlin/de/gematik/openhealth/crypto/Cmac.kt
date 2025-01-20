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

import de.gematik.openhealth.crypto.key.SecretKey

@ExperimentalCryptoApi
class CmacException(
    override val message: String,
    override val cause: Throwable? = null,
) : Throwable(message, cause)

@ExperimentalCryptoApi
enum class CmacAlgorithm {
    Aes,
}

@ExperimentalCryptoApi
interface Cmac {
    val spec: CmacSpec

    fun update(data: ByteArray)

    fun final(): ByteArray
}

@ExperimentalCryptoApi
class CmacSpec(
    val algorithm: CmacAlgorithm,
)

internal expect fun CmacSpec.nativeCreateCmac(
    scope: CryptoScope,
    secret: SecretKey,
): Cmac