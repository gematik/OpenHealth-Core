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

import de.gematik.openhealth.crypto.EmbindModule
import de.gematik.openhealth.crypto.OpenSslModuleFactory
import de.gematik.openhealth.crypto.new_Cmac
import js.buffer.ArrayBuffer
import js.typedarrays.Int8Array
import js.typedarrays.Uint8Array
import js.typedarrays.asInt8Array
import js.typedarrays.toUint8Array
import kotlinx.coroutines.await
import kotlinx.coroutines.test.runTest
import kotlin.js.Promise
import kotlin.test.Test
import kotlin.test.assertEquals
//
//fun calculateCmac(module: EmbindModule, key: Uint8Array<ArrayBuffer>, data: Uint8Array<ArrayBuffer>): Uint8Array<ArrayBuffer> {
//    val mac = module.EVP_MAC_fetch(null, "CMAC", "")
//    val macCtx = module.EVP_MAC_CTX_new(mac)
//
//    js("console.log(mac);")
//    js("console.log(macCtx);")
//
//    // Construct parameters for cipher
//    val cipherParam = module.OSSL_PARAM_construct_utf8_string("cipher", "AES-128-CBC")
//    val params = module.new_OSSL_PARAM_vector()
//    params.push_back(cipherParam)
//    params.push_back(module.OSSL_PARAM_construct_end())
//
//    // Initialize MAC context with key and parameters
//    val initStatus = module.EVP_MAC_init(macCtx, key, params)
//    if (initStatus != 1) {
//        console.error("Error initializing MAC context.")
//    }
//
//    // Update MAC context with data
//    val updateStatus = module.EVP_MAC_update(macCtx, data)
//    if (updateStatus != 1) {
//        console.error("Error updating MAC context.")
//    }
//
//    // Finalize the MAC computation
//    val macResult = module.EVP_MAC_final(macCtx)
//    if (macResult == null) {
//        console.error("Error finalizing MAC.")
//    }
//
//    // Return the computed CMAC value
//    return macResult!!
//}

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
            val module = OpenSslModuleFactory().await()

//            js("module.sadfasd()")
//            js("console.log(module['ems_EC_GROUP_new_by_curve_name'](1));")

            // Assume `module` is an instance of `EmbindModule`

            val key = "0123456789abcdef".encodeToByteArray().toUint8Array()
            val data = "This is a test  message.".encodeToByteArray().toUint8Array()

            val cmac = module.new_Cmac();
//            js("console.log(module.fromTypedArray(key))")
            cmac.initialize(module.fromTypedArray(key), "AES-128-CBC2")
            cmac.update(module.fromTypedArray(data))
//            js("cmac.initialize(new module.UChar_vector(key), 'AES-128-CBC')")
            println(module.toTypedArray(cmac.finalize()).toByteArray().toHexString())

//            val cmacValue = calculateCmac(module, key, data)
//            if (cmacValue != null) {
//                console.log("CMAC: $cmacValue")
//            } else {
//                console.error("Failed to compute CMAC.")
//            }

            println(cmac)
//
//            val curve = module.ems_EC_GROUP_new_by_curve_name(1)
//
//            js("module.ems_Abc_new(module.ems_ref(curve));")
//            val point = module.ems_EC_POINT_new(curve)
//            js("console.log(module.ems_Abc_new());")
//            js("console.log(point)" )
//            EmbindModule.

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