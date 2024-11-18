package de.gematik.kmp.crypto

import kotlinx.coroutines.await
import org.khronos.webgl.Uint8Array
import kotlin.js.Promise

@JsModule("aes-cmac")
@JsNonModule
external object aesCmac {
    class AesCmac(
        key: Uint8Array,
    ) {
        fun calculate(message: Uint8Array): Promise<Uint8Array>
    }
}

internal class NodeCmac(
    override val algorithm: CmacAlgorithm,
    secret: ByteArray,
) : Cmac {
    private var final = false

    private val cmac = runNodeCatching { aesCmac.AesCmac(js("Buffer").from(secret) as Uint8Array) }
    private var data = byteArrayOf()

    override suspend fun update(data: ByteArray) {
        this.data += data
    }

    override suspend fun final(): ByteArray {
        if (final) throw CmacException("Final can only be called once")
        return Promise { resolve, reject ->
            try {
                val result = cmac.calculate(js("Buffer").from(this.data) as Uint8Array)
                resolve(result.unsafeCast<ByteArray>())
            } catch (e: dynamic) {
                reject(CmacException("Error during digest", NodeException(e)))
            }
        }.await().also { final = true }
    }
}

actual fun createCmac(
    algorithm: CmacAlgorithm,
    secret: ByteArray,
): Cmac = NodeCmac(algorithm, secret)