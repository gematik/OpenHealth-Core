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

package de.gematik.openhealth.crypto.cipher

import de.gematik.openhealth.crypto.ByteUnit
import de.gematik.openhealth.crypto.CryptoScope
import de.gematik.openhealth.crypto.ExperimentalCryptoApi
import de.gematik.openhealth.crypto.UnsafeCryptoApi
import de.gematik.openhealth.crypto.key.SecretKey

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
    val autoPadding: Boolean
}

@ExperimentalCryptoApi
sealed interface AesCipherIvSpec : AesCipherSpec {
    val iv: ByteArray
}

@ExperimentalCryptoApi
sealed interface AesDecipherSpec {
    val tagLength: ByteUnit
    val autoPadding: Boolean
}

@ExperimentalCryptoApi
sealed interface AesDecipherIvSpec : AesDecipherSpec {
    val iv: ByteArray
}

@ExperimentalCryptoApi
@UnsafeCryptoApi
class AesEcbSpec(
    override val tagLength: ByteUnit,
    override val autoPadding: Boolean = true,
) : AesCipherSpec,
    AesDecipherSpec

@ExperimentalCryptoApi
@UnsafeCryptoApi
class AesCbcSpec(
    override val tagLength: ByteUnit,
    override val iv: ByteArray,
    override val autoPadding: Boolean = true,
) : AesCipherIvSpec,
    AesDecipherIvSpec

@ExperimentalCryptoApi
class AesGcmCipherSpec(
    override val tagLength: ByteUnit,
    override val iv: ByteArray,
    val aad: ByteArray,
    override val autoPadding: Boolean = true,
) : AesCipherIvSpec {
    init {
        require(iv.isNotEmpty()) { "IV must not be empty" }
    }
}

@ExperimentalCryptoApi
class AesGcmDecipherSpec(
    override val tagLength: ByteUnit,
    override val iv: ByteArray,
    val aad: ByteArray,
    val authTag: ByteArray,
    override val autoPadding: Boolean = true,
) : AesDecipherIvSpec {
    init {
        require(iv.isNotEmpty()) { "IV must not be empty" }
    }
}

internal expect fun AesCipherSpec.nativeCreateCipher(
    scope: CryptoScope,
    key: SecretKey,
): AesCipher

internal expect fun AesDecipherSpec.nativeCreateDecipher(
    scope: CryptoScope,
    key: SecretKey,
): AesDecipher
