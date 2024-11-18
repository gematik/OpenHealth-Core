package de.gematik.kmp.crypto

import java.security.MessageDigest

class JvmHash(
    override val algorithm: HashAlgorithm,
) : Hash {
    private var digested = false
    private val hash = MessageDigest.getInstance(algorithm.name, BCProvider)

    override suspend fun update(data: ByteArray) {
        hash.update(data)
    }

    override suspend fun digest(): ByteArray {
        if (digested) throw HashException("Digest can only be called once")
        return hash.digest().also { digested = true }
    }
}

actual fun createHash(algorithm: HashAlgorithm): Hash = JvmHash(algorithm)