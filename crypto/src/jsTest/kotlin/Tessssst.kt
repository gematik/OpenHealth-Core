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

//@JsModule("gematik-openssl-ems")
//external fun module(): Promise<Any>

class Tessssst {
    @Test
    fun `asdfasdf`() =
        runTest {
//            val sdaf = js("new URL(\"wasm_test.wasm\",import.meta.url).href")
//            println(sdaf)
//            println(sdaf)
//            val moduleImport = js("import('./wasm_test.js')")
            val moduleImport = js("import('gematik-openssl-ems')")

            js("console.log(moduleImport)")
            val module = (moduleImport as Promise<dynamic>).await().default
            js("console.log(module)")
            val module1 = (module() as Promise<dynamic>).await()
            js("console.log(module1)")
//            module().then {
//                println("asdfasdf")
//            }.catch {
//                println("asdfasdf")
//            }
//            js("console.log(mod)")
//
//            val BN_new_hex = mod.cwrap("BN_new_hex", "number", arrayOf("string"));
        }
}