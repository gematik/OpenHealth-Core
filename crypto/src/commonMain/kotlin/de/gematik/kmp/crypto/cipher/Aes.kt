/*
 * Copyright (c) 2024 gematik GmbH
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

package de.gematik.kmp.crypto.cipher

import de.gematik.kmp.crypto.ByteUnit
import de.gematik.kmp.crypto.ExperimentalCryptoApi
import de.gematik.kmp.crypto.UnsafeCryptoApi
import de.gematik.kmp.crypto.key.SecretKey

@ExperimentalCryptoApi
interface AesCipher : Cipher {
    val spec: AesCipherSpec

    fun authTag(): ByteArray
}

@ExperimentalCryptoApi
interface AesDecipher : Cipher {
    val spec: AesDecipherSpec
}

@ExperimentalCryptoApi
sealed interface AesCipherSpec {
    val tagLength: ByteUnit
}

@ExperimentalCryptoApi
sealed interface AesDecipherSpec {
    val tagLength: ByteUnit
}

@ExperimentalCryptoApi
@UnsafeCryptoApi
class AesEcbSpec(
    override val tagLength: ByteUnit,
) : AesCipherSpec,
    AesDecipherSpec

@ExperimentalCryptoApi
class AesGcmCipherSpec(
    override val tagLength: ByteUnit,
    val iv: ByteArray,
    val aad: ByteArray,
) : AesCipherSpec {
    init {
        require(iv.isNotEmpty()) { "IV must not be empty" }
    }
}

@ExperimentalCryptoApi
class AesGcmDecipherSpec(
    override val tagLength: ByteUnit,
    val iv: ByteArray,
    val aad: ByteArray,
    val authTag: ByteArray,
) : AesDecipherSpec {
    init {
        require(iv.isNotEmpty()) { "IV must not be empty" }
    }
}

@ExperimentalCryptoApi
expect fun AesCipherSpec.createCipher(key: SecretKey): AesCipher

@ExperimentalCryptoApi
expect fun AesDecipherSpec.createDecipher(key: SecretKey): AesDecipher