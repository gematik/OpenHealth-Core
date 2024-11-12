package de.gematik.kmp.crypto

import kotlinx.coroutines.await
import kotlin.js.Promise

private val crypto = js("require('crypto')")

internal class NodeHash(override val algorithm: HashAlgorithm) : Hash {
    private val hash = crypto.createHash(algorithm.name)

    override fun update(data: ByteArray) {
        hash.update(data)
    }

    override suspend fun digest(): ByteArray {
        return Promise { resolve, reject ->
            try {
                val result = hash.digest()
                resolve(result.unsafeCast<ByteArray>())
            } catch (e: dynamic) {
                reject(HashException("Error during digest", NodeException(e)))
            }
        }.await()
    }
}

actual fun createHash(algorithm: HashAlgorithm): Hash = NodeHash(algorithm)