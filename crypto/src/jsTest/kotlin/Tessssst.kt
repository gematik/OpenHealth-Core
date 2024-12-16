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

import de.gematik.kmp.crypto.CmacAlgorithm
import de.gematik.kmp.crypto.CmacSpec
import de.gematik.kmp.crypto.createCmac
import kotlinx.coroutines.await
import kotlinx.coroutines.delay
import kotlinx.coroutines.test.runTest
import kotlin.js.Promise
import kotlin.test.Test
import kotlin.test.assertEquals

//@JsModule("gematik-ems-openssl")
//external val module: dynamic

external object RuntimeExports {
    val HEAPF32: dynamic
    val HEAPF64: dynamic
    val HEAP_DATA_VIEW: dynamic
    val HEAP8: dynamic
    val HEAPU8: dynamic
    val HEAP16: dynamic
    val HEAPU16: dynamic
    val HEAP32: dynamic
    val HEAPU32: dynamic
    val HEAP64: dynamic
    val HEAPU64: dynamic
}

external interface WasmModule

external class ems_EVP_CIPHER_CTX

external class ems_EC_GROUP

external class ems_EC_POINT

external class ems_BIGNUM

external class ems_BIGNUM_ref

external interface EmbindModule {
    fun ems_EVP_CIPHER_CTX_new(): ems_EVP_CIPHER_CTX
    fun ems_EC_POINT_new(_0: ems_EC_GROUP): ems_EC_POINT
    fun ems_EC_GROUP_new_by_curve_name(_0: Int): ems_EC_GROUP
    fun ems_EC_POINT_mul(
        _0: ems_EC_GROUP,
        _1: ems_EC_POINT,
        _2: ems_BIGNUM_ref?,
        _3: ems_EC_POINT,
        _4: ems_BIGNUM
    ): Int

    fun ems_ref(_0: Any?): Any?
}

external interface MainModule : WasmModule, EmbindModule

@JsModule("gematik-ems-openssl")
@JsNonModule
external fun MainModuleFactory(options: dynamic = definedExternally): Promise<MainModule>

class Tessssst {
    @Test
    fun `asdfasdf`() =
        runTest {
//            val sdaf = js("new URL(\"wasm_test.wasm\",import.meta.url).href")
//            println(sdaf)
//            println(sdaf)
//            val module = js("import('./wasm_test.js')")
//            val moduleImport = js("require('gematik-openssl-ems')")

//            js("console.log(vv)")
//            val module = (moduleImport as Promise<dynamic>).await().default
//            val module1 = module.default
//            js("console.log(module)")
            val module = MainModuleFactory().await()
//            js("console.log(module['ems_EC_GROUP_new_by_curve_name'](1));")



            val curve = module.ems_EC_GROUP_new_by_curve_name(1)

            js("module.ems_Abc_new(module.ems_ref(curve));")
            val point = module.ems_EC_POINT_new(curve)
            js("console.log(module.ems_Abc_new());")
            js("console.log(point)" )
//            js("console.l og(curve.isDeleted())")
//            js("curve.delete();")
//            js("console.log(curve.isDeleted())")


//            module().then {
//                println("asdfasdf")
//            }.catch {
//                println("asdfasdf")
//            }
//            js("console.log(mod)")
//
//            val BN_new_hex = mod.cwrap("BN_new_hex", "number", arrayOf("string"))
//            val BN_bn2hex = mod.cwrap("BN_bn2hex", "string", arrayOf("number"))
//            val r = BN_new_hex("041EB8B1E2BC681BCE8E39963B2E9FC415B05283313DD1A8BCC055F11AE49699")
//            println(BN_bn2hex(r))
        }
}