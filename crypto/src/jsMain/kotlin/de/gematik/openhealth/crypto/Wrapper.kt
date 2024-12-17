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

package de.gematik.openhealth.crypto

import js.buffer.ArrayBuffer
import js.typedarrays.Uint8Array
import kotlin.js.Promise

external interface RuntimeExports {
    var HEAPF32: dynamic
    var HEAPF64: dynamic
    var HEAP_DATA_VIEW: dynamic
    var HEAP8: dynamic
    var HEAPU8: dynamic
    var HEAP16: dynamic
    var HEAPU16: dynamic
    var HEAP32: dynamic
    var HEAPU32: dynamic
    var HEAP64: dynamic
    var HEAPU64: dynamic
}

external interface WasmModule

typealias EmbindString = Any // Represents ArrayBuffer, UUint8Array, Uint8Array, String, etc.
//
//external interface ClassHandle {
//    fun isAliasOf(other: ClassHandle): Boolean
//    fun delete()
//    fun deleteLater(): ClassHandle
//    fun isDeleted(): Boolean
//    fun clone(): ClassHandle
//}

//external interface OSSL_PARAM_vector : ClassHandle {
//    fun push_back(param: OSSL_PARAM)
//    fun resize(size: Int, param: OSSL_PARAM)
//    fun size(): Int
//    fun get(index: Int): OSSL_PARAM?
//    fun set(index: Int, param: OSSL_PARAM): Boolean
//}
//
//external interface BIGNUM : ClassHandle
//external interface OSSL_LIB_CTX : ClassHandle
//external interface OSSL_PARAM : ClassHandle
//external interface EVP_MAC : ClassHandle
//external interface EVP_MAC_CTX : ClassHandle
//external interface EVP_CIPHER_CTX : ClassHandle
//external interface EC_GROUP : ClassHandle
//external interface EC_POINT : ClassHandle
//
//external interface EmbindModule {
//    val OSSL_PARAM_vector: dynamic
//    val BIGNUM: dynamic
//    val OSSL_LIB_CTX: dynamic
//    val OSSL_PARAM: dynamic
//    fun OSSL_PARAM_construct_end(): OSSL_PARAM
//    val EVP_MAC: dynamic
//    val EVP_MAC_CTX: dynamic
//    fun EVP_MAC_CTX_new(mac: EVP_MAC): EVP_MAC_CTX
//    val EVP_CIPHER_CTX: dynamic
//    fun EVP_CIPHER_CTX_new(): EVP_CIPHER_CTX
//    val EC_GROUP: dynamic
//    val EC_POINT: dynamic
//    fun EC_POINT_new(group: EC_GROUP): EC_POINT
//    fun EC_GROUP_new_by_curve_name(name: Int): EC_GROUP
//    fun EC_POINT_mul(group: EC_GROUP, point: EC_POINT, scalar: BIGNUM?, basePoint: EC_POINT, coefficient: BIGNUM): Int
//    fun EVP_MAC_final(ctx: EVP_MAC_CTX): Uint8Array<ArrayBuffer>?
//    fun OSSL_PARAM_construct_utf8_string(key: String, value: String): OSSL_PARAM
//    fun EVP_MAC_fetch(ctx: OSSL_LIB_CTX?, name: String, properties: String): EVP_MAC
//    fun EVP_MAC_init(ctx: EVP_MAC_CTX, key: Uint8Array<ArrayBuffer>, params: OSSL_PARAM_vector): Int
//    fun EVP_MAC_update(ctx: EVP_MAC_CTX, data: Uint8Array<ArrayBuffer>): Int
//}

//fun EmbindModule.new_OSSL_PARAM_vector(): OSSL_PARAM_vector {
//    @Suppress("UNUSED_VARIABLE") val _this = this
//    return js("new _this.OSSL_PARAM_vector();").unsafeCast<OSSL_PARAM_vector>()
//}

external interface ClassHandle {
    fun isAliasOf(other: ClassHandle): Boolean
    fun delete()
    fun deleteLater(): ClassHandle
    fun isDeleted(): Boolean
    fun clone(): ClassHandle
}

external interface UCharVector : ClassHandle {
    fun push_back(value: Int)
    fun resize(size: Int, value: Int)
    fun size(): Int
    fun get(index: Int): Int?
    fun set(index: Int, value: Int): Boolean
}

external interface EmsCmac : ClassHandle {
    fun finalize(): UCharVector
    fun update(data: UCharVector)
    fun initialize(key: UCharVector, mode: String)
}

external interface EmbindModule {
    val UChar_vector: dynamic
    val Cmac: dynamic
    fun toTypedArray(_0: UCharVector): Uint8Array<ArrayBuffer>
    fun fromTypedArray(_0: Uint8Array<ArrayBuffer>): UCharVector;
}

fun EmbindModule.new_Cmac(): EmsCmac {
    @Suppress("UNUSED_VARIABLE") val _this = this
    return js("new _this.Cmac();").unsafeCast<EmsCmac>()
}

external interface MainModule : WasmModule, RuntimeExports, EmbindModule

@JsModule("gematik-ems-openssl")
@JsNonModule
external fun OpenSslModuleFactory(options: Any? = definedExternally): Promise<MainModule>