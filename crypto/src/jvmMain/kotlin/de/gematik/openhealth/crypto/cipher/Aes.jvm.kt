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
import de.gematik.openhealth.crypto.UnsafeCryptoApi
import de.gematik.openhealth.crypto.bits
import de.gematik.openhealth.crypto.bytes
import de.gematik.openhealth.crypto.key.SecretKey
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

@OptIn(UnsafeCryptoApi::class)
private fun AesCipherSpec.algorithmName(keyLength: ByteUnit): String =
    when (this) {
        is AesEcbSpec -> "AES/ECB/PKCS5Padding"
        is AesCbcSpec -> "AES/CBC/PKCS5Padding"
        is AesGcmCipherSpec -> "AES/GCM/NoPadding"
    }

@OptIn(UnsafeCryptoApi::class)
private fun AesDecipherSpec.algorithmName(keyLength: ByteUnit): String =
    when (this) {
        is AesEcbSpec -> "AES/ECB/PKCS5Padding"
        is AesCbcSpec -> "AES/CBC/PKCS5Padding"
        is AesGcmDecipherSpec -> "AES/GCM/NoPadding"
    }

private class JvmAesCipher(
    override val spec: AesCipherSpec,
    key: SecretKey,
) : AesCipher {
    private lateinit var authTag: ByteArray

    @OptIn(UnsafeCryptoApi::class)
    private val cipher: Cipher = Cipher.getInstance(spec.algorithmName(key.length)).apply {
        val secretKey = SecretKeySpec(key.data, "AES")
        when (spec) {
            is AesGcmCipherSpec -> {
                val gcmSpec = GCMParameterSpec(spec.tagLength.bits, spec.iv)
                init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec)
                updateAAD(spec.aad)
            }
            is AesCbcSpec ->{
                val ivSpec = IvParameterSpec(spec.iv)
                init(Cipher.DECRYPT_MODE, secretKey, ivSpec)
            }
            else -> init(Cipher.ENCRYPT_MODE, secretKey)
        }
    }

    override fun update(data: ByteArray): ByteArray = cipher.update(data)

    override fun final(): ByteArray = when (spec) {
        is AesGcmCipherSpec -> {
            val final = cipher.doFinal()
            authTag = final.copyOfRange(final.size - spec.tagLength.bytes, final.size)
            final.copyOfRange(0, final.size - spec.tagLength.bytes)
        }
        else -> cipher.doFinal()
    }

    override fun authTag(): ByteArray = authTag.copyOf()
}

private class JvmAesDecipher(
    override val spec: AesDecipherSpec,
    key: SecretKey,
) : AesDecipher {
    @OptIn(UnsafeCryptoApi::class)
    private val cipher: Cipher = Cipher.getInstance(spec.algorithmName(key.length)).apply {
        val secretKey = SecretKeySpec(key.data, "AES")
        when (spec) {
            is AesGcmDecipherSpec -> {
                val gcmSpec = GCMParameterSpec(spec.tagLength.bits, spec.iv)
                init(Cipher.DECRYPT_MODE, secretKey, gcmSpec)
                updateAAD(spec.aad)
            }
            is AesCbcSpec -> {
                val ivSpec = IvParameterSpec(spec.iv)
                init(Cipher.DECRYPT_MODE, secretKey, ivSpec)
            }
            else -> init(Cipher.DECRYPT_MODE, secretKey)
        }
    }

    override fun update(data: ByteArray): ByteArray = cipher.update(data)

    override fun final(): ByteArray = when (spec) {
        is AesGcmDecipherSpec -> cipher.doFinal(spec.authTag)
        else -> cipher.doFinal()
    }
}

internal actual fun AesCipherSpec.nativeCreateCipher(
    scope: CryptoScope,
    key: SecretKey,
): AesCipher = JvmAesCipher(this, key)

internal actual fun AesDecipherSpec.nativeCreateDecipher(
    scope: CryptoScope,
    key: SecretKey,
): AesDecipher = JvmAesDecipher(this, key)