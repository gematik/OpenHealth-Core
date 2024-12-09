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
//import js.buffer.ArrayBuffer
//import js.typedarrays.Uint8Array
//import js.typedarrays.toUint8Array
import kotlinx.coroutines.await
import kotlin.js.Promise

//@JsModule("aes-cmac")
//@JsNonModule
//external object aesCmac {
//    class AesCmac(
//        key: Uint8Array<ArrayBuffer>,
//    ) {
//        fun calculate(message: Uint8Array<ArrayBuffer>): Promise<Uint8Array<ArrayBuffer>>
//    }
//}
//
//private class NodeCmac(
//    override val spec: CmacSpec,
//    secret: SecretKey,
//) : Cmac {
//    init {
//        require(spec.algorithm == CmacAlgorithm.Aes) { "Only AES is supported" }
//    }
//
//    private var final = false
//
//    private val cmac = runNodeCatching { aesCmac.AesCmac(secret.data.toUint8Array()) }
//    private var data = byteArrayOf()
//
//    override suspend fun update(data: ByteArray) {
//        this.data += data
//    }
//
//    override suspend fun final(): ByteArray {
//        if (final) throw CmacException("Final can only be called once")
//        val result = cmac.calculate(this.data.toUint8Array()).await()
//        final = true
//        return result.toByteArray()
//    }
//}

actual fun CmacSpec.createCmac(secret: SecretKey): Cmac = TODO() //NodeCmac(this, secret)