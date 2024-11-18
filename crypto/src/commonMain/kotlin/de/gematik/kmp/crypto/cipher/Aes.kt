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