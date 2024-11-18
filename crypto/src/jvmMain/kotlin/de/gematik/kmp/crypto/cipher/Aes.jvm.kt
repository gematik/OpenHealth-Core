package de.gematik.kmp.crypto.cipher

import de.gematik.kmp.crypto.UnsafeCryptoApi
import de.gematik.kmp.crypto.bits
import de.gematik.kmp.crypto.bytes
import de.gematik.kmp.crypto.key.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import javax.crypto.Cipher as JavaCipher

private class JvmAesCipher(
    override val spec: AesCipherSpec,
    key: SecretKey,
) : AesCipher {
    private lateinit var authTag: ByteArray

    @OptIn(UnsafeCryptoApi::class)
    private var cipher: JavaCipher =
        when (spec) {
            is AesEcbSpec -> {
                val secretKey = SecretKeySpec(key.data, "AES")
                val cipher = JavaCipher.getInstance("AES/ECB/PKCS5Padding")
                cipher.init(JavaCipher.ENCRYPT_MODE, secretKey)
                cipher
            }
            is AesGcmCipherSpec -> {
                val secretKey = SecretKeySpec(key.data, "AES")
                val gcmSpec = GCMParameterSpec(spec.tagLength.bits, spec.iv)
                val cipher = JavaCipher.getInstance("AES/GCM/NoPadding")
                cipher.init(JavaCipher.ENCRYPT_MODE, secretKey, gcmSpec)
                cipher.updateAAD(spec.aad)
                cipher
            }
        }

    override suspend fun update(data: ByteArray): ByteArray = cipher.update(data)

    @OptIn(UnsafeCryptoApi::class)
    override suspend fun final(): ByteArray =
        when (spec) {
            is AesEcbSpec -> {
                authTag = byteArrayOf()
                cipher.doFinal()
            }
            is AesGcmCipherSpec -> {
                val final = cipher.doFinal()
                authTag = final.copyOfRange(final.size - spec.tagLength.bytes, final.size)
                final.copyOfRange(0, final.size - spec.tagLength.bytes)
            }
        }

    override fun authTag(): ByteArray = authTag.copyOf()
}

private class JvmAesDecipher(
    override val spec: AesDecipherSpec,
    key: SecretKey,
) : AesDecipher {
    @OptIn(UnsafeCryptoApi::class)
    private var cipher: JavaCipher =
        when (spec) {
            is AesEcbSpec -> {
                val secretKey = SecretKeySpec(key.data, "AES")
                val cipher = JavaCipher.getInstance("AES/ECB/PKCS5Padding")
                cipher.init(JavaCipher.DECRYPT_MODE, secretKey)
                cipher
            }
            is AesGcmDecipherSpec -> {
                val secretKey = SecretKeySpec(key.data, "AES")
                val gcmSpec = GCMParameterSpec(spec.tagLength.bits, spec.iv)
                val cipher = JavaCipher.getInstance("AES/GCM/NoPadding")
                cipher.init(JavaCipher.DECRYPT_MODE, secretKey, gcmSpec)
                cipher.updateAAD(spec.aad)
                cipher
            }
        }

    override suspend fun update(data: ByteArray): ByteArray = cipher.update(data)

    @OptIn(UnsafeCryptoApi::class)
    override suspend fun final(): ByteArray =
        when (spec) {
            is AesEcbSpec -> cipher.doFinal()
            is AesGcmDecipherSpec -> cipher.doFinal(spec.authTag)
        }
}

actual fun AesCipherSpec.createCipher(key: SecretKey): AesCipher = JvmAesCipher(this, key)

actual fun AesDecipherSpec.createDecipher(key: SecretKey): AesDecipher = JvmAesDecipher(this, key)