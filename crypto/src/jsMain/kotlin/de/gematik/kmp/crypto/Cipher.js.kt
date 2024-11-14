package de.gematik.kmp.crypto

import js.buffer.ArrayBufferView
import js.typedarrays.toUint8Array
import node.crypto.createCipheriv
import node.crypto.createDecipheriv
import node.crypto.getCipherInfo
import org.khronos.webgl.Uint8Array

private enum class ModeMapping {
    Ecb
}

private class NodeAesCipher(
    override val tagLength: Int,
    override val key: SecretKey,
    iv: ByteArray? = null,
    mode: String,
) : AesEcb {
    private var cipher = createCipheriv("aes-${tagLength * 8}-ecb", key.data, iv)

    override fun update(data: ByteArray) {
        cipher.update(data.toUint8Array())
    }

    override suspend fun final(): ByteArray {
        return cipher.final().toByteArray()
    }
}

private class NodeAesDecipher(
    override val tagLength: Int,
    override val key: SecretKey,
    iv: ByteArray? = null,
) : AesEcb {
    private var cipher = createDecipheriv("aes-${tagLength * 8}-ecb", key.data, iv)

    override fun update(data: ByteArray) {
        cipher.update(data.toUint8Array())
    }

    override suspend fun final(): ByteArray {
        return cipher.final().toByteArray()
    }
}

@ExperimentalCryptoApi
actual fun createAesEcbCipher(
    tagLength: Int,
    key: SecretKey,
    iv: ByteArray?
): AesEcb = NodeAesCipher(tagLength, key, iv)

@ExperimentalCryptoApi
actual fun createAesEcbDecipher(
    tagLength: Int,
    key: SecretKey,
    iv: ByteArray?
): AesEcb = NodeAesDecipher(tagLength, key, iv)