package de.gematik.kmp.crypto

@ExperimentalCryptoApi
class CmacException(
    override val message: String,
    override val cause: Throwable? = null,
) : Throwable(message, cause)

@ExperimentalCryptoApi
enum class CmacAlgorithm {
    Aes,
}

@ExperimentalCryptoApi
interface Cmac {
    val algorithm: CmacAlgorithm

    suspend fun update(data: ByteArray)

    suspend fun final(): ByteArray
}

@ExperimentalCryptoApi
expect fun createCmac(
    algorithm: CmacAlgorithm,
    secret: ByteArray,
): Cmac