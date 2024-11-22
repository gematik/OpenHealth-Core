/*
 * Copyright (c) 2024 gematik GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.kmp.crypto

import de.gematik.kmp.crypto.key.SecretKey
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

private class NodeCmac(
    override val spec: CmacSpec,
    secret: SecretKey,
) : Cmac {
    init {
        require(spec.algorithm == CmacAlgorithm.Aes) { "Only AES is supported" }
    }

    private var final = false

    private val cmac = runNodeCatching { aesCmac.AesCmac(js("Buffer").from(secret.data) as Uint8Array) }
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

actual fun CmacSpec.createCmac(
    secret: SecretKey,
): Cmac = NodeCmac(this, secret)