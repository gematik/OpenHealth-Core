/*
 * Copyright (c) 2025 gematik GmbH
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

@file:Suppress("ktlint", "detekt.all")

package de.gematik.openhealth.crypto.wrapper

import js.buffer.ArrayBuffer
import js.typedarrays.Int8Array
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

typealias EmbindString = Any // ArrayBuffer | Uint8Array | Uint8ClampedArray | Int8Array | String

external interface ClassHandle {
    fun isAliasOf(other: ClassHandle): Boolean

    fun delete()

    fun deleteLater(): ClassHandle

    fun isDeleted(): Boolean

    fun clone(): ClassHandle
}

external interface Int8Vector : ClassHandle {
    fun push_back(value: Number)

    fun resize(
        size: Number,
        value: Number,
    )

    fun size(): Number

    fun get(index: Number): Number?

    fun set(
        index: Number,
        value: Number,
    ): Boolean
}

external interface Uint8Vector : ClassHandle {
    fun push_back(value: Number)

    fun resize(
        size: Number,
        value: Number,
    )

    fun size(): Number

    fun get(index: Number): Number?

    fun set(
        index: Number,
        value: Number,
    ): Boolean

    fun create(value: EmbindString): CMAC
}

external interface CMAC : ClassHandle {
    fun final(): Uint8Vector

    fun update(vector: Uint8Vector)
}

external interface ECPoint : ClassHandle {
    fun times(signedInteger: Uint8Vector): ECPoint

    fun add(point: ECPoint): ECPoint

    fun uncompressed(): Uint8Vector
}

external interface MlKemEncapsulationData : ClassHandle {
    val wrappedKey: Uint8Vector
    val sharedSecret: Uint8Vector
}

external interface MlKemEncapsulation : ClassHandle {
    fun encapsulate(): MlKemEncapsulationData
}

external interface MlKemDecapsulation : ClassHandle {
    fun decapsulate(_0: Uint8Vector): Uint8Vector

    fun getEncapsulationKey(): Uint8Vector
}

external interface ECKeyPairGenerator : ClassHandle {
    fun getPublicKeyDER(): Uint8Vector

    fun getPrivateKeyDER(): Uint8Vector
}

external interface ECDH : ClassHandle {
    fun computeSecret(otherPublicKey: Uint8Vector): Uint8Vector
}

external interface HashGenerator : ClassHandle {
    fun update(vector: Uint8Vector)

    fun setFinalOutputLength(length: Int)

    fun final(): Uint8Vector
}

external interface AESCipher : ClassHandle {
    fun update(vector: Uint8Vector): Uint8Vector

    fun final(): Uint8Vector

    fun setAutoPadding(value: Boolean)

    fun setAAD(vector: Uint8Vector)

    fun setAuthTag(authTag: Uint8Vector): Uint8Vector

    fun getAuthTag(tagLength: Number): Uint8Vector
}

external interface EmbindModule {
    val CMAC: CMACFactory
    val ECPoint: ECPointFactory
    val ECKeyPairGenerator: ECKeyPairGeneratorFactory
    val MlKemEncapsulation: MlKemEncapsulationFactory
    val MlKemDecapsulation: MlKemDecapsulationFactory
    val ECDH: ECDHFactory
    val HashGenerator: HashGeneratorFactory
    val AESCipher: AESCipherFactory

    fun toInt8Array(vector: Int8Vector): Int8Array<ArrayBuffer>

    fun toUint8Array(vector: Uint8Vector): Uint8Array<ArrayBuffer>

    fun fromInt8Array(data: Int8Array<ArrayBuffer>): Int8Vector

    fun fromUint8Array(data: Uint8Array<ArrayBuffer>): Uint8Vector

    fun cryptoRandom(n: Int): Uint8Vector

    fun cryptoConstantTimeEquals(
        vecA: Uint8Vector,
        vecB: Uint8Vector,
    ): Boolean
}

external interface CMACFactory {
    fun create(
        key: Uint8Vector,
        algorithm: EmbindString,
    ): CMAC
}

external interface ECPointFactory {
    fun create(
        curveName: EmbindString,
        publicKey: Uint8Vector,
    ): ECPoint
}

external interface MlKemEncapsulationFactory {
    fun create(
        algorithm: EmbindString,
        encapsulationKey: Uint8Vector,
    ): MlKemEncapsulation
}

external interface MlKemDecapsulationFactory {
    fun create(algorithm: EmbindString): MlKemDecapsulation
}

external interface ECKeyPairGeneratorFactory {
    fun generateKeyPair(value: EmbindString): ECKeyPairGenerator
}

external interface ECDHFactory {
    fun create(privateKey: Uint8Vector): ECDH
}

external interface HashGeneratorFactory {
    fun create(algorithm: EmbindString): HashGenerator
}

external interface AESCipherFactory {
    fun createEncryptor(
        algorithm: EmbindString,
        key: Uint8Vector,
        iv: Uint8Vector,
    ): AESCipher

    fun createDecryptor(
        algorithm: EmbindString,
        key: Uint8Vector,
        iv: Uint8Vector,
    ): AESCipher
}

external interface OpenSslModule :
    WasmModule,
    EmbindModule,
    RuntimeExports

@JsModule("gematik-ems-openssl")
@JsNonModule
external fun OpenSslModuleFactory(options: Any? = definedExternally): Promise<OpenSslModule>