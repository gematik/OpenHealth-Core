package de.gematik.kmp.crypto

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

class JvmCmac(override val algorithm: CmacAlgorithm, secret: ByteArray) : Cmac {
    private var final = false

    private val algorithmName = when(algorithm) {
        CmacAlgorithm.Aes -> "AESCMAC"
        else -> throw IllegalArgumentException("Unknown algorithm")
    }
    private val keyName = when(algorithm) {
        CmacAlgorithm.Aes -> "AES"
        else -> throw IllegalArgumentException("Unknown algorithm")
    }
    private val secretKey = SecretKeySpec(secret, keyName)
    private val mac = Mac.getInstance(algorithmName, BCProvider).apply { init(secretKey) };

    override fun update(data: ByteArray) {
        mac.update(data)
    }

    override suspend fun final(): ByteArray {
        if (final) throw CmacException("Final can only be called once")
        return mac.doFinal().also { final = true }
    }
}

actual fun createCmac(
    algorithm: CmacAlgorithm,
    secret: ByteArray
): Cmac = JvmCmac(algorithm, secret)