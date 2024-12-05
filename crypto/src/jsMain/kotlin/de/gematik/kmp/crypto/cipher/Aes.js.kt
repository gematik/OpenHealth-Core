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
import de.gematik.kmp.crypto.UnsafeCryptoApi
import de.gematik.kmp.crypto.bits
import de.gematik.kmp.crypto.key.SecretKey
import de.gematik.kmp.crypto.runNodeCatching
import js.memory.FinalizationRegistry
import js.typedarrays.asInt8Array
import node.crypto.Cipher
import node.crypto.CipherGCM
import node.crypto.Decipher
import node.crypto.DecipherGCM
import node.crypto.createCipheriv
import node.crypto.createDecipheriv

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

private class NodeAesCipher(
    override val spec: AesCipherSpec,
    key: SecretKey,
) : AesCipher {
    init {
        require(spec.tagLength == key.length) { "Key must be ${spec.tagLength.bits} bits" }
    }

    private var cipher: Cipher =
        run {
            val cipher =
                createCipheriv(
                    spec.algorithmName(key.length),
                    key.data.asInt8Array(),
                    ((spec as? AesGcmCipherSpec)?.iv ?: byteArrayOf()).asInt8Array(),
                )
            cipher.setAutoPadding(spec.autoPadding)
            if (spec is AesGcmCipherSpec) {
                @Suppress("UNCHECKED_CAST_TO_EXTERNAL_INTERFACE")
                (cipher as CipherGCM).setAAD(spec.aad.asInt8Array())
            }
            cipher
        }

    override suspend fun update(data: ByteArray): ByteArray =
        cipher.update(data.asInt8Array()).toByteArray()

    override suspend fun final(): ByteArray = cipher.final().toByteArray()

    override fun authTag(): ByteArray =
        if (spec is AesGcmCipherSpec) {
            @Suppress("UNCHECKED_CAST_TO_EXTERNAL_INTERFACE")
            (cipher as CipherGCM).getAuthTag().toByteArray()
        } else {
            byteArrayOf()
        }
}

private class NodeAesDecipher(
    override val spec: AesDecipherSpec,
    key: SecretKey,
) : AesDecipher {
    init {
        require(spec.tagLength == key.length) { "Key must be ${spec.tagLength.bits} bits" }
    }

    private var cipher: Decipher =
        runNodeCatching {
            val cipher =
                createDecipheriv(
                    spec.algorithmName(key.length),
                    key.data.asInt8Array(),
                    ((spec as? AesGcmDecipherSpec)?.iv ?: byteArrayOf()).asInt8Array(),
                )
            cipher.setAutoPadding(spec.autoPadding)
            if (spec is AesGcmDecipherSpec) {
                @Suppress("UNCHECKED_CAST_TO_EXTERNAL_INTERFACE")
                val cipherGcm = (cipher as DecipherGCM)
                cipherGcm.setAuthTag(spec.authTag.asInt8Array())
                cipherGcm.setAAD(spec.aad.asInt8Array())
            }
            cipher
        }

    override suspend fun update(data: ByteArray): ByteArray =
        cipher.update(data.asInt8Array()).toByteArray()

    override suspend fun final(): ByteArray = cipher.final().toByteArray()
}

actual fun AesCipherSpec.createCipher(key: SecretKey): AesCipher = NodeAesCipher(this, key)

actual fun AesDecipherSpec.createDecipher(key: SecretKey): AesDecipher = NodeAesDecipher(this, key)