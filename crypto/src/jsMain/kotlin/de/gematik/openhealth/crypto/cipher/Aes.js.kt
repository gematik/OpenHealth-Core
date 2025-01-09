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
//
package de.gematik.openhealth.crypto.cipher
//
import de.gematik.openhealth.crypto.ByteUnit
import de.gematik.openhealth.crypto.UnsafeCryptoApi
import de.gematik.openhealth.crypto.bits
import de.gematik.openhealth.crypto.bytes
import de.gematik.openhealth.crypto.key.SecretKey
import de.gematik.openhealth.crypto.wrapper.lazyWithProvider
import de.gematik.openhealth.crypto.wrapper.runWithProvider
import de.gematik.openhealth.crypto.wrapper.toByteArray
import de.gematik.openhealth.crypto.wrapper.toUint8Vector

@OptIn(UnsafeCryptoApi::class)
private fun AesCipherSpec.algorithmName(keyLength: ByteUnit): String =
    when (this) {
        is AesEcbSpec -> "aes-${keyLength.bits}-ecb"
        is AesGcmCipherSpec -> "aes-${keyLength.bits}-gcm"
    }

@OptIn(UnsafeCryptoApi::class)
private fun AesDecipherSpec.algorithmName(keyLength: ByteUnit): String =
    when (this) {
        is AesEcbSpec -> "aes-${keyLength.bits}-ecb"
        is AesGcmDecipherSpec -> "aes-${keyLength.bits}-gcm"
    }

private class JsAesCipher(
    override val spec: AesCipherSpec,
    key: SecretKey,
) : AesCipher {
    init {
        require(spec.tagLength == key.length) { "Key must be ${spec.tagLength.bits} bits" }
    }

    private val cipher by lazyWithProvider {
            val cipher = AESCipher.createEncryptor(spec.algorithmName(key.length), key.data.toUint8Vector(), ((spec as? AesGcmCipherSpec)?.iv ?: byteArrayOf()).toUint8Vector())
            cipher.setAutoPadding(spec.autoPadding)
            if (spec is AesGcmCipherSpec) {
                if (spec.aad.isNotEmpty()) cipher.setAAD(spec.aad.toUint8Vector())
            }
            cipher
        }

    override  fun update(data: ByteArray): ByteArray =
        runWithProvider {
            cipher.update(data.toUint8Vector()).toByteArray()
        }

    override  fun final(): ByteArray =
        runWithProvider {
            cipher.final().toByteArray()
        }

    override  fun authTag(): ByteArray =
        runWithProvider {
            if (spec is AesGcmCipherSpec) {
                cipher.getAuthTag(spec.tagLength.bytes).toByteArray()
            } else {
                byteArrayOf()
            }
        }
}

private class JsAesDecipher(
    override val spec: AesDecipherSpec,
    key: SecretKey,
) : AesDecipher {
    init {
        require(spec.tagLength == key.length) { "Key must be ${spec.tagLength.bits} bits" }
    }

    private val cipher by
        lazyWithProvider {
            val cipher = AESCipher.createDecryptor(spec.algorithmName(key.length), key.data.toUint8Vector(), ((spec as? AesGcmDecipherSpec)?.iv ?: byteArrayOf()).toUint8Vector())
            cipher.setAutoPadding(spec.autoPadding)
            if (spec is AesGcmDecipherSpec) {
                if (spec.authTag.isNotEmpty()) cipher.setAuthTag(spec.authTag.toUint8Vector())
                if (spec.aad.isNotEmpty()) cipher.setAAD(spec.aad.toUint8Vector())
            }
            cipher
        }

    override  fun update(data: ByteArray): ByteArray =
        runWithProvider {
            cipher.update(data.toUint8Vector()).toByteArray()
        }

    override  fun final(): ByteArray =
        runWithProvider {
            cipher.final().toByteArray()
        }
}

actual fun AesCipherSpec.createCipher(key: SecretKey): AesCipher = JsAesCipher(this, key)
actual fun AesDecipherSpec.createDecipher(key: SecretKey): AesDecipher = JsAesDecipher(this, key)