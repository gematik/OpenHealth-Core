package de.gematik.kmp.crypto

@ExperimentalCryptoApi
class HashException(override val message: String, override val cause: Throwable? = null) : Throwable(message, cause)

@ExperimentalCryptoApi
enum class HashAlgorithm {
    Sha1
}

@ExperimentalCryptoApi
interface Hash {
    val algorithm: HashAlgorithm
    fun update(data: ByteArray)
    suspend fun digest(): ByteArray
}

@ExperimentalCryptoApi
expect fun createHash(algorithm: HashAlgorithm): Hash