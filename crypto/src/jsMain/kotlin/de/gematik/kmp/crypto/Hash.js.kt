package de.gematik.kmp.crypto

internal class NodeHash(
    override val algorithm: HashAlgorithm,
) : Hash {
    private val hash = node.crypto.createHash(algorithm.name)

    override suspend fun update(data: ByteArray) {
        hash.update(data)
    }

    override suspend fun digest(): ByteArray {
        val result = hash.digest()
        return result.toByteArray()
    }
}

actual fun createHash(algorithm: HashAlgorithm): Hash = NodeHash(algorithm)