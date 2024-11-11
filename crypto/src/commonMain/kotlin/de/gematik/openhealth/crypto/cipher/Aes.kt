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

package de.gematik.openhealth.crypto.cipher

import de.gematik.openhealth.crypto.ByteUnit
import de.gematik.openhealth.crypto.CryptoScope
import de.gematik.openhealth.crypto.ExperimentalCryptoApi
import de.gematik.openhealth.crypto.UnsafeCryptoApi
import de.gematik.openhealth.crypto.key.SecretKey

/**
 * Interface for AES encryption operations.
 */
@ExperimentalCryptoApi
interface AesCipher : Cipher {
    val spec: AesCipherSpec

    /**
     * Returns the authentication tag for authenticated encryption modes.
     */
    fun authTag(): ByteArray
}

/**
 * Interface for AES decryption operations.
 */
@ExperimentalCryptoApi
interface AesDecipher : Cipher {
    val spec: AesDecipherSpec
}

/**
 * Base specification for AES encryption operations.
 */
@ExperimentalCryptoApi
sealed interface AesCipherSpec {
    val tagLength: ByteUnit
    val autoPadding: Boolean
}

/**
 * Specification for AES encryption operations requiring an initialization vector.
 */
@ExperimentalCryptoApi
sealed interface AesCipherIvSpec : AesCipherSpec {
    val iv: ByteArray
}

/**
 * Base specification for AES decryption operations.
 */
@ExperimentalCryptoApi
sealed interface AesDecipherSpec {
    val tagLength: ByteUnit
    val autoPadding: Boolean
}

/**
 * Specification for AES decryption operations requiring an initialization vector.
 */
@ExperimentalCryptoApi
sealed interface AesDecipherIvSpec : AesDecipherSpec {
    val iv: ByteArray
}

/**
 * Specification for AES ECB mode operations.
 */
@ExperimentalCryptoApi
@UnsafeCryptoApi
class AesEcbSpec(
    override val tagLength: ByteUnit,
    override val autoPadding: Boolean = true,
) : AesCipherSpec,
    AesDecipherSpec

/**
 * Specification for AES CBC mode operations.
 */
@ExperimentalCryptoApi
@UnsafeCryptoApi
class AesCbcSpec(
    override val tagLength: ByteUnit,
    override val iv: ByteArray,
    override val autoPadding: Boolean = true,
) : AesCipherIvSpec,
    AesDecipherIvSpec

/**
 * Specification for AES GCM mode encryption operations.
 */
@ExperimentalCryptoApi
class AesGcmCipherSpec(
    override val tagLength: ByteUnit,
    override val iv: ByteArray,
    val aad: ByteArray,
) : AesCipherIvSpec {
    override val autoPadding: Boolean = false

    init {
        require(iv.isNotEmpty()) { "IV must not be empty" }
    }
}

/**
 * Specification for AES GCM mode decryption operations.
 */
@ExperimentalCryptoApi
class AesGcmDecipherSpec(
    override val tagLength: ByteUnit,
    override val iv: ByteArray,
    val aad: ByteArray,
    val authTag: ByteArray,
) : AesDecipherIvSpec {
    override val autoPadding: Boolean = false

    init {
        require(iv.isNotEmpty()) { "IV must not be empty" }
    }
}

/**
 * Creates a native AES cipher instance.
 */
internal expect fun AesCipherSpec.nativeCreateCipher(
    scope: CryptoScope,
    key: SecretKey,
): AesCipher

/**
 * Creates a native AES decipher instance.
 */
internal expect fun AesDecipherSpec.nativeCreateDecipher(
    scope: CryptoScope,
    key: SecretKey,
): AesDecipher
