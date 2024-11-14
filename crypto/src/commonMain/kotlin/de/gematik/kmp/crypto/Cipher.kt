package de.gematik.kmp.crypto

@ExperimentalCryptoApi
interface Cipher {
    val key: Key

    fun update(data: ByteArray)
    suspend fun final(): ByteArray
}

@ExperimentalCryptoApi
interface AesEcb : Cipher {
    val tagLength: Int
}

@ExperimentalCryptoApi
interface AesGcm : Cipher {
    val iv: ByteArray
    val tagLength: Int
}

@ExperimentalCryptoApi
expect fun createAesEcbCipher(tagLength: Int, key: SecretKey): AesEcb

@ExperimentalCryptoApi
expect fun createAesEcbDecipher(tagLength: Int, key: SecretKey): AesEcb

@ExperimentalCryptoApi
expect fun createAesGcmCipher(tagLength: Int, key: SecretKey, iv: ByteArray? = null): AesGcm

@ExperimentalCryptoApi
expect fun createAesGcmDecipher(tagLength: Int, key: SecretKey, iv: ByteArray? = null): AesGcm

